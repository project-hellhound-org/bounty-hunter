"""
hellhound/core/tools/crawl_scan.py - crawling & external-scanner tools.

Split slice 12. katana (JS-aware crawler), gau_nuclei_sweep (archive URL harvest
+ nuclei templates), wpscan_scan (WordPress), and gowitness (headless screenshot
grid) — all shell-out tools pulling their shared plumbing from tool_shared. agent.py
re-imports every executor; TOOL_REGISTRY wiring unchanged.
"""
import os
import re
import json
import logging
import subprocess
import tempfile
from pathlib import Path
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
from hellhound.memory import update_from_spider

logger = logging.getLogger("hellhound.agent")


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
        screenshots_dir = Path(os.path.expanduser(f"~/.beast/targets/{target_safe_name}/screenshots")).resolve()

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


# CAUGHT IN THE WILD (VaultFi/localhost): a SQLi finding on /login.php's
# username parameter was confirmed via sqlmap, but request_ref was just
# the bare endpoint ("http://localhost:8081/login.php") -- and the SAME
# URL also got hit repeatedly afterward by completely unrelated, benign
# plain-login curl calls (testing the SSO flow). URL-containment matching
# alone can't tell those apart, so the two MOST RECENT /login.php curl
# entries -- plain "username=testuser&password=testpass123" logins with
# nothing injection-related in them -- won, and got attached to the
# finding as its "proof." A triager correctly called this out: both
# captured responses were identical 302s with no evidence of the actual
# SLEEP-based timing delay sqlmap used to confirm the bug. The real proof
# (sqlmap's own payload + timing output) existed in terminal_evidence_log
# the whole time, but _lookup_curl_evidence never got a chance to miss so
# the terminal fallback below never triggered. Fix: for vuln classes where
# the PoC is a specific payload (not just "any request to this URL"),
# only accept a curl-log match that actually contains a payload marker for
# that class -- returning nothing is correct here, since it's what makes
# record_finding fall through to _lookup_terminal_evidence next.


def _execute_nuclei_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Run nuclei's community templates against a URL (or all live hosts
    discovered so far) to catch known CVEs, misconfigurations, exposures,
    default creds, and takeovers — the single highest-ROI "is anything already
    broken here" check. ACTIVE scanner: gated by engagement rules like the other
    scanners (blocked where the program forbids automated scanning). Needs
    nuclei on PATH; install via /setup."""
    raw = args.get("url") or args.get("target")
    targets = raw if isinstance(raw, list) else ([raw] if raw else [])
    if not targets:
        st = target.state if isinstance(getattr(target, "state", None), dict) else {}
        live = st.get("live_hosts") or []
        urls = [h.get("url") for h in live if isinstance(h, dict) and h.get("url")]
        targets = urls or [target.name]

    rules = getattr(target, "scope_rules", None)
    gated = []
    for t in targets:
        u = str(t).strip()
        if not u:
            continue
        if not u.startswith(("http://", "https://")):
            u = f"https://{u}"
        ok, _r = is_in_scope(u, rules)
        if ok and u not in gated:
            gated.append(u)
    if not gated:
        return {"status": "no_in_scope_targets", "note": "No in-scope URL to scan with nuclei."}

    nuclei_bin = get_binary_path("nuclei")
    if not nuclei_bin:
        return {"error": "nuclei not installed", "hint": install_hint("nuclei")}

    severity = str(args.get("severity") or "low,medium,high,critical")
    in_fd, in_path = tempfile.mkstemp(suffix=".txt", prefix="hh_nuclei_")
    with os.fdopen(in_fd, "w") as f:
        f.write("\n".join(gated) + "\n")
    cmd = [nuclei_bin, "-l", in_path, "-jsonl", "-silent", "-severity", severity,
           "-timeout", "10", "-rate-limit", str(int(args.get("rate_limit", 50) or 50))]
    tags = args.get("tags")
    if tags:
        cmd += ["-tags", tags if isinstance(tags, str) else ",".join(tags)]

    findings = []
    try:
        proc = _run_cmd_with_heartbeat(cmd, timeout=int(args.get("max_runtime", 300) or 300),
                                       emit=emit, label="nuclei (template scan)")
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                it = json.loads(line)
                info = it.get("info", {}) if isinstance(it.get("info"), dict) else {}
                findings.append({
                    "template": it.get("template-id") or it.get("templateID"),
                    "name": info.get("name"),
                    "severity": (info.get("severity") or "unknown"),
                    "matched_at": it.get("matched-at") or it.get("matched_at") or it.get("host"),
                    "type": it.get("type"),
                })
            except Exception:
                pass
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.unlink(in_path)
        except Exception:
            pass

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    findings.sort(key=lambda f: order.get(str(f.get("severity")).lower(), 9))
    return {
        "status": "success",
        "targets_scanned": len(gated),
        "findings": findings,
        "finding_count": len(findings),
        "note": (f"nuclei flagged {len(findings)} issue(s) — VERIFY each (templates can false-positive) before recording."
                 if findings else "nuclei found nothing on the scanned targets."),
    }


def _execute_dalfox_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Run dalfox for XSS / parameter-injection on a URL. ACTIVE scanner, gated
    by engagement rules (and on programs where XSS is out of scope the gate
    blocks it). Needs dalfox on PATH; install via /setup."""
    url = str(args.get("url") or args.get("target") or target.name).strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    rules = getattr(target, "scope_rules", None)
    ok, reason = is_in_scope(url, rules)
    if not ok:
        return {"status": "out_of_scope", "note": f"{url} out of scope ({reason})."}

    dalfox_bin = get_binary_path("dalfox")
    if not dalfox_bin:
        return {"error": "dalfox not installed", "hint": install_hint("dalfox")}

    cmd = [dalfox_bin, "url", url, "--format", "json", "--silence", "--no-spinner"]
    if args.get("data"):
        cmd += ["--data", str(args["data"])]
    if args.get("cookie"):
        cmd += ["--cookie", str(args["cookie"])]

    findings = []
    try:
        proc = _run_cmd_with_heartbeat(cmd, timeout=int(args.get("max_runtime", 300) or 300),
                                       emit=emit, label="dalfox (XSS scan)")
        out = (proc.stdout or "").strip()
        try:
            data = json.loads(out)
            findings = data if isinstance(data, list) else [data]
        except Exception:
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass
    except subprocess.TimeoutExpired:
        pass

    pocs = []
    for f in findings:
        if isinstance(f, dict):
            pocs.append({
                "type": f.get("type"), "severity": f.get("severity"),
                "param": f.get("param"), "poc": f.get("data") or f.get("poc"),
                "cwe": f.get("cwe"), "evidence": f.get("evidence"),
            })
    return {
        "status": "success",
        "url": url,
        "findings": pocs or findings,
        "finding_count": len(findings),
        "note": (f"dalfox reported {len(findings)} XSS candidate(s) — VERIFY the PoC fires in a real browser before recording."
                 if findings else "dalfox found no XSS on this endpoint."),
    }
