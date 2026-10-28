import time
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from hellhound.core import http_utils

NAME = "cors_buster"
CATEGORY = "recon"
DESCRIPTION = "Active CORS misconfiguration detection (Origin reflection, Null trust, Arbitrary trust)"

def generate_poc(url, origin, credentials):
    """Generates a clean HTML/JS PoC for the CORS misconfiguration"""
    creds_js = "xhr.withCredentials = true;" if credentials else ""
    
    poc_html = f"""
<!DOCTYPE html>
<html>
<body>
    <h2>Hellhound CORS Exploit PoC</h2>
    <p>Target: {url}</p>
    <p>Reflected Origin: {origin}</p>
    <script>
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {{
            if (xhr.readyState == 4) {{
                alert("Exploit Success! Data: " + xhr.responseText.substring(0, 100));
            }}
        }};
        xhr.open("GET", "{url}", true);
        {creds_js}
        xhr.send();
    </script>
</body>
</html>
"""
    return poc_html.strip()

def test_cors(url, origin, session=None):
    headers = {"Origin": origin}
    try:
        if session:
            r = session.options(url, headers=headers, timeout=5)
            if "Access-Control-Allow-Origin" not in r.headers:
                r = session.get(url, headers=headers, timeout=5)
        else:
            r = requests.options(url, headers=headers, timeout=5)
            if "Access-Control-Allow-Origin" not in r.headers:
                r = requests.get(url, headers=headers, timeout=5)
            
        acao = r.headers.get("Access-Control-Allow-Origin")
        if not acao:
            return None

        acac = r.headers.get("Access-Control-Allow-Credentials", "false").lower() == "true"
        acam = r.headers.get("Access-Control-Allow-Methods", "")
        acah = r.headers.get("Access-Control-Allow-Headers", "")
        aceh = r.headers.get("Access-Control-Expose-Headers", "")

        # Risk multipliers for dangerous methods/headers
        dangerous_methods = [m.strip().upper() for m in acam.split(",") if m.strip().upper() in ("PUT", "DELETE", "PATCH")]
        sensitive_headers = [h.strip().lower() for h in acah.split(",") if h.strip().lower() in ("authorization", "x-api-key", "cookie")]
        exposed_headers = [h.strip().lower() for h in aceh.split(",") if h.strip().lower() in ("authorization", "set-cookie", "x-auth-token")]

        return {
            "origin": origin,
            "acao": acao,
            "credentials": acac,
            "allowed_methods": acam,
            "allowed_headers": acah,
            "dangerous_methods": dangerous_methods,
            "sensitive_headers": sensitive_headers,
            "exposed_headers": exposed_headers,
            # Kept so a confirmed finding can carry its OWN real
            # request/response as evidence instead of a report later
            # grabbing some unrelated earlier curl to the same URL (see
            # the evidence-mirroring in agent.py's _execute_cors_checker).
            "status_code": r.status_code,
            "method": r.request.method if getattr(r, "request", None) else "OPTIONS",
            "response_headers": dict(r.headers),
        }
    except Exception:
        pass
    return None


def run(target, emit, options=None):
    emit.info(f"[*] CORS Buster: Analyzing Origins for {target}")
    
    # Configure session with global proxy and headers
    session = requests.Session()
    http_utils.apply_session_config(session, options)
    
    base_url = target if target.startswith("http") else f"http://{target}"
    parsed = urllib.parse.urlparse(base_url)
    domain = parsed.netloc
    
    # Grab spider endpoints properly from options passed by console.py
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    urls_to_test = [base_url]
    for ep in endpoints:
        ep_url = ep.get("url")
        if ep_url:
            urls_to_test.append(ep_url)
        
    urls_to_test = list(set(urls_to_test))
    if len(urls_to_test) > 100:
        # If there are a massive number of endpoints, cap to 100 to save time
        urls_to_test = list(urls_to_test)[:100]
    
    payloads = [
        "https://evil.com",
        "null",
        f"https://{domain}.evil.com",    # Post-domain trust (subdomain of evil)
        f"https://evil{domain}",         # Pre-domain trust (joined word)
        f"https://{domain}evil.com",     # Post-domain trust (joined word)
        f"http://{domain}",              # HTTP trust on HTTPS
        f"https://sub.{domain}.evil.com", # Deep subdomain of evil
        f"https://{domain}.local",       # Local variant trust
        f"https://{domain.replace('.', '-')}.evil.com", # Hyphenated variant
        # Three classes folded in from Corsy (s0md3v/Corsy) — each one
        # catches a specific origin-validation IMPLEMENTATION bug, not just
        # "does it trust an arbitrary domain" like the payloads above:
        f"https://{domain}_.evil.com",   # Unrecognized-underscore bypass — a
        # validation regex anchored on the raw domain string sometimes
        # treats '_' as a normal hostname char it doesn't need to escape
        # against, so "target.com_.evil.com" slips past a check written to
        # stop at the real domain boundary.
        f"https://{domain}%60.evil.com", # Broken-parser / backtick bypass —
        # Origin header carries a literal '%60' in the host position; some
        # origin-checking code urldecodes before validating (header values
        # normally shouldn't be) and a raw backtick then confuses whatever
        # split/parse logic draws the trust boundary. Matched on substring
        # below, not equality, since what's being checked for is the
        # backtick showing up unescaped in the reflected ACAO value.
    ]
    if domain.count(".") > 1:
        # Unescaped-regex-dot bypass — only meaningful for a multi-label
        # domain (sub.example.com), same guard Corsy itself uses: replaces
        # the FIRST literal '.' with 'x'. If the origin-validation regex
        # was written as /sub.example.com$/ instead of /sub\.example\.com$/,
        # the unescaped '.' matches ANY character — including 'x' — so this
        # mutated origin gets reflected back as trusted even though it's
        # not the real domain. This is arguably the single most valuable
        # check in the whole list: it catches a specific, common regex-
        # authoring mistake that none of the payloads above would ever
        # trigger (they all either match exactly or clearly don't).
        payloads.append(f"https://{domain.replace('.', 'x', 1)}")

    findings = []
    signals = []
    risk_score = 0

    # CAUGHT IN THE WILD (2026-10): this was a plain serial double loop --
    # up to 100 URLs x ~12 payloads x up to 2 requests each (OPTIONS, then
    # a GET fallback), one at a time, with NO progress output between the
    # single "[*] Analyzing Origins..." line at the top and the final
    # result. Against a target with a large discovered-endpoint set (a
    # real-world recon haul easily has 200+), that's 1000+ sequential
    # HTTP round-trips -- a researcher watching this had no way to tell
    # "still working" from "hung," and it genuinely took 10+ minutes wall
    # clock on one real engagement. Fixed two ways: run the probes
    # concurrently (bounded worker pool -- Session handles concurrent use
    # fine, this is the same pattern requests-based tools commonly use),
    # and cap the whole sweep to a wall-clock budget so a slow/unreachable
    # target can't turn into an unbounded hang -- whatever's been tested
    # by the deadline is reported, same "partial beats nothing" principle
    # as the sqlmap/run_terminal_command timeout fixes elsewhere in this
    # codebase.
    tasks = [(url, payload) for url in urls_to_test for payload in payloads]
    total_tasks = len(tasks)
    _BUDGET_SECONDS = 90
    _MAX_WORKERS = 12
    deadline = time.time() + _BUDGET_SECONDS
    completed = 0
    timed_out_early = False

    if total_tasks > 20:
        emit.info(f"    [*] Testing {total_tasks} (url, origin) combinations across {len(urls_to_test)} URL(s), up to {_BUDGET_SECONDS}s budget...")

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        future_map = {pool.submit(test_cors, url, payload, session): (url, payload) for url, payload in tasks}
        for future in as_completed(future_map, timeout=_BUDGET_SECONDS + 10):
            url, payload = future_map[future]
            completed += 1
            if total_tasks > 20 and completed % 50 == 0:
                emit.info(f"    [*] CORS sweep: {completed}/{total_tasks} probes tested...")
            if time.time() > deadline:
                timed_out_early = True
                # Let already-finished futures be processed below (the
                # for-loop over as_completed still yields them), just stop
                # waiting on anything still pending -- cancel() is a no-op
                # for futures already running, but cleanly drops queued-
                # but-not-started ones instead of waiting out their timeout.
                for f in future_map:
                    if not f.done():
                        f.cancel()
                break

            try:
                result = future.result()
            except Exception:
                result = None
            if not result:
                continue

            acao = result["acao"]
            acac = result["credentials"]

            vuln_type = None
            risk_val = 0

            if "%60.evil.com" in payload and acao and "`.evil.com" in acao:
                # Substring match, not equality — the thing being confirmed
                # is that the server reflected an UNESCAPED backtick, not
                # that it echoed the payload verbatim.
                vuln_type = "Broken Origin Parser (Backtick)"
                risk_val = 4

            elif acao == payload:
                vuln_type = "Origin Reflection"
                if payload == "null": vuln_type = "Null Origin Trust"
                elif payload.endswith(f"{domain}_.evil.com"): vuln_type = "Unrecognized Underscore Bypass"
                elif domain.count(".") > 1 and payload == f"https://{domain.replace('.', 'x', 1)}":
                    vuln_type = "Unescaped Regex Validation (dot-as-wildcard)"
                    risk_val = 4
                elif "evil" in payload: vuln_type = "Arbitrary Origin Trust"
                elif payload == f"http://{domain}": vuln_type = "Insecure HTTP Trust"

                if not risk_val:
                    risk_val = 5 if acac else 3

            elif acao == "*" and acac:
                vuln_type = "Wildcard with Credentials"
                risk_val = 5

            elif acao == "*" and not acac:
                # Open CORS (Wildcard) is only a minor issue for public files
                # Don't flood the results if it's the same across many URLs
                vuln_type = "Open CORS (Wildcard)"
                risk_val = 1

            if vuln_type:
                # Deduplication: If many URLs have the same 'Open CORS' issue, only report it once for the base target
                is_repetitive = vuln_type == "Open CORS (Wildcard)"
                duplicate = any(f["type"] == vuln_type and (f["url"] == url or is_repetitive) for f in findings)
                
                if not duplicate:
                    finding = {
                        "url": url,
                        "type": vuln_type,
                        "payload": payload,
                        "credentials_allowed": acac,
                        "poc_html": generate_poc(url, payload, acac),
                        # Real captured response for THIS exact probe (the
                        # one that actually produced the reflected/trusted
                        # ACAO value) — not reconstructed, not guessed.
                        "status_code": result.get("status_code"),
                        "response_headers": result.get("response_headers") or {},
                        "repro_data": {
                            "method": result.get("method", "OPTIONS"),
                            "url": url,
                            "headers": {"Origin": payload}
                        }
                    }
                    findings.append(finding)
                    risk_score += risk_val
                    emit.warn(f"    [!] {vuln_type}: {url} matches Origin: {payload}")

    if timed_out_early:
        emit.warn(f"    [!] CORS sweep hit its {_BUDGET_SECONDS}s budget after {completed}/{total_tasks} probes — reporting what was found so far rather than hanging further; re-run with fewer discovered endpoints in spider_intel for full coverage.")

    if findings:
        signals.append("CORS_MISCONFIGURATION")
        emit.success(f"[+] Found {len(findings)} CORS misconfigurations.")
    else:
        emit.info("[-] No CORS misconfigurations detected.")

    return {
        "raw": f"CORS Misconfigs: {len(findings)}",
        "intel": {"cors_vulnerabilities": findings, "risk_score": risk_score, "probes_completed": completed, "probes_total": total_tasks, "timed_out_early": timed_out_early},
        "signals": signals
    }
