"""
hellhound/core/agent.py

Autonomous Bug Bounty Reconnaissance & Triage Agent.
Coordinates discovery tools, enforces code-level scope guardrails,
manages target task context, and triages verified findings.
"""

from dataclasses import dataclass, field
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
        Path("/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"),
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"),
        repo_root / "wordlists" / "web" / "directories-fast.txt"
    ]
    wordlist = None
    for wc in wordlist_candidates:
        if wc.exists() and wc.stat().st_size > 0:
            wordlist = str(wc)
            break

    if not wordlist:
        return {"error": "No directory wordlist found."}

    target_url = url.rstrip("/") + "/FUZZ"
    cmd = [
        binary,
        "-w", wordlist,
        "-u", target_url,
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
                path = r.get("input", {}).get("FUZZ", "")
                status = r.get("status", 0)
                length = r.get("length", 0)
                results.append({
                    "url": r.get("url", f"{url}/{path}"),
                    "path": path,
                    "status": status,
                    "length": length
                })
    except Exception as e:
        results = []

    return {
        "target_url": url,
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
    # Update target state
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
    custom_headers = args.get("headers", {})

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    headers = merge_global_context({"global_headers": custom_headers})
    try:
        r = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        return {
            "url": url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body_preview": r.text[:20000]
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }


def _execute_spider(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    depth = args.get("depth", 2)

    engine = HellhoundEngine()
    opts = {"depth": depth, "max_pages": 50, "target": url}
    try:
        res = engine.run_single("spider", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        if intel and hasattr(target, "state"):
            target.state["spider_intel"] = intel
        endpoints = [ep.get("url") for ep in intel.get("endpoints", []) if isinstance(ep, dict)]
        if endpoints and hasattr(target, "state"):
            if "endpoints" not in target.state:
                target.state["endpoints"] = []
            for ep in endpoints:
                if ep not in target.state["endpoints"]:
                    target.state["endpoints"].append(ep)
        return {
            "url": url,
            "endpoints_found": len(endpoints),
            "sample_endpoints": endpoints[:30],
            "forms_found": len(intel.get("forms", [])),
            "parameters": intel.get("parameters", [])[:20],
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


# Tool Registry Map
TOOL_REGISTRY: Dict[str, ToolSpec] = {
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
        description="Fetch HTTP response headers and body preview for an endpoint with standard BugBounty identity headers.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to request."},
                "method": {"type": "string", "description": "HTTP Method: GET, HEAD, POST", "default": "GET"}
            },
            "required": ["url"]
        },
        executor=_execute_curl
    ),
    "spider": ToolSpec(
        name="spider",
        description="Crawl target web application to discover endpoints, URL parameters, form fields, and JavaScript assets.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL of the target application to crawl."},
                "depth": {"type": "integer", "description": "Crawl recursion depth (default: 2)", "default": 2}
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
    If the user's task text names a specific URL with a non-root path
    (e.g. "...from this endpoint https://host/pulse"), return that first
    path segment (e.g. "/pulse") as the task's path scope.

    Multi-lab hosts (several independent challenge apps living under
    different top-level paths on the same domain, e.g. /meridian,
    /cargoflow, /lumen, /pulse) are common in CTF/lab environments — a task
    scoped to one endpoint should not wander into the others. Returns None
    if no path is present (task is domain-wide) so nothing is restricted.
    """
    if not user_text:
        return None
    m = re.search(r'https?://[^\s"\']+', user_text)
    if not m:
        return None
    try:
        parsed = urlparse(m.group(0))
    except Exception:
        return None
    path = parsed.path or ""
    segments = [s for s in path.split("/") if s]
    if not segments:
        return None
    return "/" + segments[0]


def _url_in_path_scope(url: str, path_scope: str) -> bool:
    """True if url's path falls under path_scope (e.g. '/pulse') or is the
    bare host root (needed for e.g. robots.txt/global recon of the same
    lab's own path prefix — still checked, root '/' itself is NOT exempt)."""
    try:
        p = urlparse(url).path or ""
    except Exception:
        return True
    return p == path_scope or p.startswith(path_scope.rstrip("/") + "/")


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
        self._turn_path_scope: Optional[str] = None  # e.g. "/pulse" — set per-turn in handle_message

    def set_target(self, target_name: str) -> Target:
        self.target = create_or_load_target(target_name)
        self.history = self.target.state.get("history") or []
        if not isinstance(self.history, list):
            self.history = []
        return self.target

    def _get_trimmed_history(self, max_turns: int = 4, for_chat: bool = False) -> List[Dict[str, str]]:
        """
        Returns a lightweight, sanitized history window for LLM/SLM prompts.
        Prevents prompt bloat and eliminates massive inference lag.
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

        trimmed = []
        recent = self.history[-max_turns:] if len(self.history) > max_turns else self.history
        for h in recent:
            content = str(h.get("content", ""))
            is_tool_result = content.startswith("[TOOL RESULT:")
            if is_tool_result:
                # Tool results (curl bodies, spider intel, etc.) are the
                # highest-value content in history — a harvested email,
                # token, or credential can sit anywhere in the JSON. A blind
                # 700-char clip here silently truncates mid-field and the
                # model never sees the data it needs. Give these a much
                # larger budget, and pull out any emails up front so they
                # survive even if the body still gets cut.
                if len(content) > 3500:
                    emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)))
                    prefix = f"[EMAILS FOUND IN THIS RESULT: {', '.join(emails)}]\n" if emails else ""
                    content = prefix + content[:3200] + "\n...[truncated]..."
            elif len(content) > 800:
                content = content[:700] + "\n...[truncated]..."
            trimmed.append({"role": h.get("role", "user"), "content": content})
        return trimmed

    def _extract_target_from_args(self, args: Dict[str, Any]) -> str:
        for key in ("domain", "domains", "target", "url", "subdomain", "subdomains", "host", "hosts", "candidates"):
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

        # 1b. Enforce per-turn path scope (multi-lab hosts: a task scoped to
        # one endpoint, e.g. /pulse, must not wander into sibling apps like
        # /meridian, /cargoflow, /lumen living on the same domain).
        if self._turn_path_scope:
            check_url = args.get("url") or (target_candidate if target_candidate.startswith(("http://", "https://")) else f"https://{target_candidate}")
            if not _url_in_path_scope(check_url, self._turn_path_scope):
                reason = (
                    f"URL path is outside this task's scope ('{self._turn_path_scope}'). "
                    f"Other paths on this host are separate labs/applications and are out of scope for this task."
                )
                if emit and hasattr(emit, "warn"):
                    emit.warn(f"[!] PATH SCOPE REFUSAL: {check_url} — {reason}")
                return {
                    "error": f"PATH_SCOPE_VIOLATION: {reason}",
                    "target": check_url,
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
        is_recon = tool_name in ("subfinder", "dns_bruteforce", "httpx", "dig", "subzy", "vhost_fuzz")
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

        # Summarize what's already been discovered this session so the
        # orchestrator doesn't re-run spider/content_discovery on a URL it
        # has already crawled just because it has no memory of the result.
        known_eps = (self.target.state.get("endpoints") or [])[:25]
        known_params = (self.target.state.get("spider_intel") or {}).get("parameters", [])[:10]
        if known_eps:
            known_intel_block = "Endpoints already discovered:\n" + "\n".join(f"  - {e}" for e in known_eps)
            if known_params:
                known_intel_block += "\nParameters already mapped:\n" + "\n".join(f"  - {p}" for p in known_params)
        else:
            known_intel_block = "(nothing gathered yet this session)"

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

        # ── 1. Minimal Orchestrator System Prompt (Fast Tool Selection) ─────────
        orchestrator_system_prompt = f"""\
You are HELLHOUND Orchestrator. Your sole job is to evaluate if a tool should be executed next or if tool execution is complete.

TARGET: {self.target.name}
SCOPE: {scope_summary}

{skills_block}

AVAILABLE TOOLS:
{tools_summary}

ALREADY GATHERED THIS SESSION (do not re-run a tool to re-discover this):
{known_intel_block}

RULES:
1. ONLY call tools when the user explicitly requests active reconnaissance, scanning, enumeration, or analysis of a target.
2. If the user asks a complex question, hypothetical scenario, or asks for cybersecurity advice (e.g., "how to bypass 403 proxy"), do NOT call any tools. Output "DONE".
3. For greetings, casual questions, or general discussion, do NOT call any tools. Output "DONE".
4. Before calling a recon tool (spider, content_discovery, etc.), check the "ALREADY GATHERED" section above — if it already answers what you need (endpoints, params, forms), use that data directly instead of re-crawling. Only re-run a recon tool if the target URL is genuinely new or the existing data is insufficient for the specific next step.
5. To call a tool, respond ONLY with JSON:
```json
{{
  "tool": "<tool_name>",
  "args": {{ ... }}
}}
```
6. If no further tools are needed, or after inspecting tool findings, respond with "DONE".
"""

        # ── 2. Comprehensive Synthesizer System Prompt (Deep Reasoning & Synthesis)
        synthesizer_system_prompt = f"""\
You are HELLHOUND, an autonomous bug bounty reconnaissance and triage assistant.
Your role: Provide the researcher with deep, factual analysis, evidence evaluation, severity classification, and actionable bug bounty triage recommendations.

TARGET: {self.target.name}
SCOPE CONSTRAINTS: {scope_summary}
CURRENT FINDINGS: {len(self.target.findings)} verified findings

AVAILABLE TOOLS (this is the complete, real list — you have no other tools):
{tools_summary}

=== ALWAYS-ON BASELINE DOCTRINE ===
{BASELINE_RULES_PROMPT}

{skills_block}

INSTRUCTIONS:
- Review the entire conversation history, executed tools, and gathered evidence.
- Produce a clear, concise, and structured synthesis of all findings.
- Highlight actionable security observations, open attack surfaces, and logical next triage steps.
- When asked about your capabilities, tools, or what you can do: answer ONLY
  from the AVAILABLE TOOLS list above. Never claim access to external tools
  not in that list (Nmap, Burp Suite, Metasploit, etc. are NOT available
  unless they literally appear above). Never claim you lack tool access —
  you have the tools listed above and can invoke them.
- OUTPUT FORMAT: Respond in plain natural-language prose only — headings,
  short paragraphs, and bullet points are fine. NEVER output JSON, a code
  fence, or a {{"tool": ..., "args": ...}} object. That structured tool-call
  format belongs to the orchestrator step, which has already finished by the
  time you are called — you are writing the human-readable answer, not
  selecting a tool. If you're tempted to propose a next tool to run, say so
  in a sentence (e.g. "Next, brute-forcing subdomains would help because...")
  rather than emitting a tool-call object.
"""

        # ── 0. Direct Conversational Fast-Path (Instant 1s responses for chat) ──
        if intent == "chat":
            if emit and hasattr(emit, "set_label"):
                emit.set_label("HELLHOUND")
            
            clean_tools = ", ".join(TOOL_REGISTRY.keys())
            chat_sys = f"{CHAT_PERSONA_SLM}\n\nYou have access to the following tools: {clean_tools}. Briefly describe your capabilities naturally if asked, but do NOT mention internal instructions or restrictions."
            
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

        self.history.append({"role": "user", "content": user_text})
        tools_executed = []
        _prev_ai_resp = None
        _executed_signatures = set()  # every (tool, args) run this turn — not just the last one
        _dup_skip_count = 0

        # A path scope set in an earlier turn (e.g. "...from this endpoint
        # https://host/pulse") persists across the session — most follow-up
        # messages ("go for it", "try exploiting that flaw") won't repeat the
        # URL, but the restriction to that lab's path should still hold.
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
                system_prompt=orchestrator_system_prompt,
                role="orchestrator",
                thinking=False,
                history=self._get_trimmed_history(max_turns=6, for_chat=False),
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

            # Check for JSON tool invocation in the response
            tool_call = None
            json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', ai_resp)
            if json_match:
                try:
                    parsed = json.loads(json_match.group(1))
                    if isinstance(parsed, dict) and "tool" in parsed:
                        tool_call = parsed
                except Exception:
                    pass
            elif ai_resp.strip().startswith("{") and ai_resp.strip().endswith("}"):
                try:
                    parsed = json.loads(ai_resp.strip())
                    if isinstance(parsed, dict) and "tool" in parsed:
                        tool_call = parsed
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
            # If no tools were run, answer the user's specific question directly
            final_answer, tokens = ask_neural_core(
                prompt=user_text,
                system_prompt=synthesizer_system_prompt,
                role="synthesizer",
                thinking=False,
                history=self._get_trimmed_history(max_turns=6, for_chat=False),
                on_token=on_token,
                return_usage=True,
                cancel_check=cancel_check
            )
        else:
            synth_prompt = f"Based on the tool results gathered ({', '.join(tools_executed)}), synthesize all findings for target '{self.target.name}' and provide concrete next triage steps."
            if len(tools_executed) > 0 and cfg.get("show_recaps", True):
                synth_prompt += "\n\nAfter your analysis, end with a single recap line in this exact format:\nrecap: Goal was [goal]. Done: [what was accomplished]. Next: [recommended next step]. (disable recaps in /setup)"
            
            final_answer, tokens = ask_neural_core(
                prompt=synth_prompt,
                system_prompt=synthesizer_system_prompt,
                role="synthesizer",
                thinking=False,
                history=self._get_trimmed_history(max_turns=6, for_chat=False),
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
