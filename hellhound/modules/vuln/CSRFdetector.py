import asyncio
import aiohttp
import re
from urllib.parse import urlparse

NAME = "csrf_detector"
CATEGORY = "vuln"
DESCRIPTION = "Passive CSRF Security Auditor"

class C:
    R   = "\033[91m"; RD  = "\033[31m"; G   = "\033[92m"; GD  = "\033[32m"; Y   = "\033[93m"; O   = "\033[38;5;208m"
    CY  = "\033[96m"; CYD = "\033[36m"; BL  = "\033[94m"; MG  = "\033[95m"; W   = "\033[97m"; GR  = "\033[90m"
    GL  = "\033[37m"; B   = "\033[1m"; DIM = "\033[2m"; RST = "\033[0m"

OPTIONS = [
    {"name": "concurrency", "type": int, "default": 10, "help": "Concurrent audit threads"},
]

CSRF_TOKEN_PATTERNS = [
    r"csrf", r"xsrf", r"token", r"_token", r"authenticity_token",
    r"requestverificationtoken", r"nonce", r"state"
]

class CSRFAuditor:
    def __init__(self, emit, options):
        self.emit = emit
        self.options = options

    async def audit_endpoint(self, endpoint):
        """Analyzes an endpoint for CSRF protection passively."""
        url = endpoint.get("url")
        method = endpoint.get("method", "GET").upper()
        params = endpoint.get("params", [])
        
        # We only care about state-changing requests
        if method not in ["POST", "PUT", "DELETE", "PATCH"]:
            return []

        findings = []
        
        # 1. Check for tokens in parameters (Query, Form, JS, etc)
        found_token = False
        for p in params:
            for pattern in CSRF_TOKEN_PATTERNS:
                if re.search(pattern, p, re.I):
                    found_token = True
                    break
            if found_token: break
        
        if not found_token:
            findings.append({
                "url": url,
                "method": method,
                "type": "MISSING_CSRF_TOKEN",
                "severity": "HIGH",
                "title": "Missing CSRF Protection Token",
                "evidence": f"State-changing endpoint {method} {url} does not appear to use anti-CSRF tokens in its parameters."
            })

        # 2. Check for SameSite cookie flags (via TransportAuditor intel if available, or just signal it)
        # Note: In a real flow, we'd check the spider_intel's cookie headers here.
        # For now, we signal that POST endpoints without tokens are high risk.
        
        return findings

async def run(target, emit, options=None):
    emit.always_info(f"Phase: Passive CSRF Audit for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    if not endpoints:
        emit.warn("No endpoints identified. Ensure Spider has run first.")
        return {"raw": "No targets", "signals": []}

    state_changing = [e for e in endpoints if e.get("method", "GET").upper() in ["POST", "PUT", "DELETE", "PATCH"]]
    
    if not state_changing:
        emit.info("No state-changing endpoints found for CSRF analysis.")
        return {"raw": "No state-changing targets", "signals": []}

    emit.info(f"Auditing {C.W}{len(state_changing)}{C.RST} state-changing endpoints...")

    all_findings = []
    auditor = CSRFAuditor(emit, options or {})
    
    for ep in state_changing:
        res = await auditor.audit_endpoint(ep)
        if res:
            all_findings.extend(res)
            for f in res:
                emit.info(f"  {C.R}●{C.RST} {C.RD}CSRF_VULN{C.RST} : {C.W}{f['method']}{C.RST} {C.DIM}{f['url']}{C.RST}")

    if all_findings:
        emit.always_success(f"CSRF_DETECTOR complete. Found {len(all_findings)} potential vulnerabilities.")
    else:
        emit.info(f"No obvious CSRF protection gaps detected.")

    return {"raw": f"Found {len(all_findings)} issues", "intel": {"vulnerabilities": all_findings}}

    return {
        "raw": f"Audited {len(state_changing)} endpoints. Found {len(all_findings)} potential CSRF issues.",
        "intel": {
            "vulnerabilities": all_findings
        },
        "signals": ["CSRF_POTENTIAL" if all_findings else "NO_CSRF"]
    }

