import asyncio
import aiohttp
import re
from urllib.parse import urlparse

NAME = "csrf_detector"
CATEGORY = "vuln"
DESCRIPTION = "Active & Passive CSRF Security Auditor"

OPTIONS = [
    {"name": "concurrency", "type": int, "default": 10, "help": "Concurrent audit threads"},
    {"name": "timeout", "type": int, "default": 8, "help": "Request timeout (seconds)"},
]

CSRF_TOKEN_PATTERNS = [
    r"csrf", r"xsrf", r"_token", r"authenticity_token",
    r"requestverificationtoken", r"nonce", r"__requestverificationtoken",
    r"csrfmiddlewaretoken", r"anti-forgery", r"antiforgery"
]

SAMESITE_KEYWORDS = ["samesite=strict", "samesite=lax"]

class CSRFAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.semaphore = asyncio.Semaphore(options.get("concurrency", 10))

    async def audit_endpoint(self, endpoint, cookies_info=None):
        """Analyzes an endpoint for CSRF protection — passive + active."""
        url = endpoint.get("url")
        method = endpoint.get("method", "GET").upper()
        params = endpoint.get("params", {})
        
        # Only care about state-changing requests
        if method not in ["POST", "PUT", "DELETE", "PATCH"]:
            return []

        findings = []
        flat_params = []
        if isinstance(params, dict):
            for p_items in params.values():
                if isinstance(p_items, list):
                    flat_params.extend(p_items)
        elif isinstance(params, list):
            flat_params = params

        # 1. Check for tokens in parameters
        found_token = False
        for p in flat_params:
            for pattern in CSRF_TOKEN_PATTERNS:
                if re.search(pattern, str(p), re.I):
                    found_token = True
                    break
            if found_token:
                break
        
        if not found_token:
            findings.append({
                "url": url,
                "method": method,
                "type": "MISSING_CSRF_TOKEN",
                "severity": "HIGH",
                "evidence": f"State-changing endpoint {method} {url} has no anti-CSRF token in its parameters.",
                "repro_data": {"url": url, "method": method, "headers": {}, "note": "Replay this request without Origin/Referer headers from a different domain."}
            })

        # 2. Active: Test if Origin header is validated
        async with self.semaphore:
            try:
                # Send request with a spoofed Origin
                headers = {"Origin": "https://evil-attacker.com", "Referer": "https://evil-attacker.com/exploit"}
                async with self.session.request(method, url, headers=headers, timeout=self.options.get("timeout")) as r:
                    if r.status in [200, 201, 204, 302]:
                        findings.append({
                            "url": url,
                            "method": method,
                            "type": "ORIGIN_NOT_VALIDATED",
                            "severity": "HIGH",
                            "evidence": f"Server accepted request with spoofed Origin 'evil-attacker.com' (Status: {r.status}).",
                        })
            except:
                pass

        # 3. Check SameSite cookie attribute
        if cookies_info:
            for cookie_name, cookie_val in cookies_info.items():
                cookie_str = str(cookie_val).lower()
                if not any(kw in cookie_str for kw in SAMESITE_KEYWORDS):
                    if not any(f["type"] == "MISSING_SAMESITE" for f in findings):
                        findings.append({
                            "url": url,
                            "method": method,
                            "type": "MISSING_SAMESITE",
                            "severity": "MEDIUM",
                            "evidence": f"Session cookie '{cookie_name}' lacks SameSite attribute.",
                        })

        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] CSRF_DETECTOR: Active & Passive CSRF audit for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    if not endpoints:
        emit.warn("No endpoints identified. Ensure Spider has run first.")
        return {"raw": "No targets", "signals": []}

    state_changing = [e for e in endpoints if e.get("method", "GET").upper() in ["POST", "PUT", "DELETE", "PATCH"]]
    
    if not state_changing:
        emit.info("No state-changing endpoints found for CSRF analysis.")
        return {"raw": "No state-changing targets", "signals": []}

    emit.info(f"    [i] Auditing {len(state_changing)} state-changing endpoints...")

    all_findings = []
    async with aiohttp.ClientSession() as session:
        auditor = CSRFAuditor(emit, session, options or {})
        tasks = [auditor.audit_endpoint(ep) for ep in state_changing]
        results = await asyncio.gather(*tasks)
        for res in results:
            all_findings.extend(res)

    if all_findings:
        emit.success(f"[+] CSRF_DETECTOR complete. Found {len(all_findings)} potential vulnerabilities.")
        for f in all_findings[:5]:
            emit.warn(f"    [!] {f['type']}: {f['method']} {f['url']}")
    else:
        emit.info("[-] No CSRF protection gaps detected.")

    return {
        "raw": f"Audited {len(state_changing)} endpoints. Found {len(all_findings)} potential CSRF issues.",
        "intel": {"vulnerabilities": all_findings},
        "signals": ["CSRF_POTENTIAL" if all_findings else "NO_CSRF"]
    }
