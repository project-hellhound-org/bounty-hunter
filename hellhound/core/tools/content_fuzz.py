"""
hellhound/core/tools/content_fuzz.py - content-discovery / directory & param fuzzing.

Split slice 13. feroxbuster_content, ffuf_content (also exposed as the
content_discovery tool) and fuzz_hunter, with their cluster-private helpers
(rate-limit resolution, soft-404 baselining, live stdout parsers + their regexes).
All shell out via tool_shared's _run_cmd_with_heartbeat. agent.py re-imports the
executors; TOOL_REGISTRY wiring unchanged.
"""
import os
import re
import json
import logging
import subprocess
import tempfile
from pathlib import Path

import hellhound
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from hellhound.core.tool_shared import (
    _find_binary, _run_cmd_with_heartbeat, _bounded_request,
    _with_identity_bearer_header, _target_auth_options)
from hellhound.core.scope import is_in_scope, normalize_host
from hellhound.core.tasks import Target, save_target, sanitize_target_name
from hellhound.core.ai_utils import load_config
from hellhound.core.http_utils import merge_global_context, normalize_headers, normalize_cookies
from hellhound.core.toolcheck import ensure_tool, get_binary_path, is_available, pick_available, install_hint

logger = logging.getLogger("hellhound.agent")


_FEROXBUSTER_LIVE_HIT_RE = re.compile(r'^(\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(\S+)')


_FFUF_LIVE_HIT_RE = re.compile(r'^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)')


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
    # Identity-model extension: this fallback engine (no feroxbuster/ffuf
    # installed) used bare, unauthenticated requests.get() with no cookies
    # or headers at all — an auth-gated path tree (e.g. everything under
    # /admin/ once logged in) was invisible to it even with an active
    # swap_session identity. Same auth_cookies/auth_headers shape every
    # other HellhoundEngine-wrapped module already reads via
    # apply_session_config(); FUZZhunter.run() now applies both to its
    # requests.
    opts.update(_target_auth_options(target))
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

    repo_root = Path(hellhound.__file__).resolve().parent
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
    req_headers = _with_identity_bearer_header(req_headers, target)
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


# CAUGHT IN THE WILD (2026-10): a real sqlmap finding's auto-saved report
# showed nothing but the sqlmap startup banner/legal disclaimer as its
# "captured evidence" instead of the actual dumped data. Root cause: this
# regex was `\b(curl|wget|http|httpie)\b` with NO anchoring, so it matched
# the word "http" inside the URL SCHEME of ANY command that took a URL
# argument — `sqlmap -u 'http://host/login.php' ...` matches `\bhttp\b`
# at the "http" in "http://", nowhere near the actual invoked binary
# (sqlmap). That misrouted the whole command through
# _mirror_http_evidence_from_terminal, which captured sqlmap's raw
# stdout/stderr (mostly banner, since sqlmap's real dumped output often
# comes later / after the captured excerpt's head-only cap) and filed it
# as "curl evidence" under the login.php URL -- exactly the garbage the
# researcher flagged. Same false-positive would've fired for hydra, nmap,
# ffuf, gobuster, or literally any CLI tool invoked with a URL argument.
# Fixed by anchoring the match to actual COMMAND position (start of the
# command, or right after a shell separator/sudo/env prefix) instead of
# searching the whole string — "http://" appearing mid-argument no longer
# qualifies, only the invoked program name itself does.


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

    repo_root = Path(hellhound.__file__).resolve().parent
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
    req_headers = _with_identity_bearer_header(req_headers, target)

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
