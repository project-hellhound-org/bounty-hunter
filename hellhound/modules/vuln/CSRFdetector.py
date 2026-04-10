import asyncio
import aiohttp
import re
from hellhound.core import http_utils

NAME = "csrf_detector"
CATEGORY = "vuln"
DESCRIPTION = "State-Changing Request CSRF Auditor"

OPTIONS = [
    {"name": "check_all_forms", "type": bool, "default": True, "help": "Audit all forms, not just those flagged as sensitive"},
    {"name": "concurrency", "type": int, "default": 5, "help": "Concurrent attack threads"},
]

CSRF_TOKEN_PATTENS = [
    r"csrf", r"xsrf", r"token", r"_token", r"authenticity_token"
]

class CSRFAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options

    async def audit_endpoint(self, endpoint):
        """Analyzes an endpoint for CSRF protection."""
        url = endpoint.get("url")
        method = endpoint.get("method", "GET").upper()
        params = endpoint.get("params", {})
        
        if method not in ["POST", "PUT", "DELETE", "PATCH"]:
            return None

        # 1. Check for tokens in parameters
        found_token = False
        for p_type, p_list in params.items():
            for p in p_list:
                for pattern in CSRF_TOKEN_PATTENS:
                    if re.search(pattern, p, re.I):
                        found_token = True
                        break
                if found_token: break
            if found_token: break
        
        findings = []
        if not found_token:
            findings.append({
                "url": url,
                "method": method,
                "type": "MISSING_TOKEN",
                "severity": "HIGH",
                "title": "Missing CSRF Token in State-Changing Request",
                "evidence": f"Endpoint {method} {url} has no visible CSRF protection tokens in parameters."
            })

        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] CSRF_DETECTOR: Auditing state-changing endpoints for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    if not endpoints:
        emit.warn("[!] No endpoints identified for CSRF testing. Ensure Spider has run.")
        return {"raw": "No targets", "signals": []}

    state_changing = [e for e in endpoints if e.get("method", "GET").upper() in ["POST", "PUT", "DELETE", "PATCH"]]
    
    if not state_changing:
        emit.info("[-] No state-changing endpoints found.")
        return {"raw": "No state-changing targets", "signals": []}

    emit.info(f"    [i] Auditing {len(state_changing)} state-changing endpoint(s)...")

    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = CSRFAuditor(emit, session, options or {})
        for ep in state_changing:
            res = await auditor.audit_endpoint(ep)
            if res:
                findings.extend(res)
                for f in res:
                    emit.warn(f"        [!] CSRF VULNERABILITY: {f['method']} {f['url']} ({f['type']})")

    if findings:
        emit.success(f"[+] CSRF_DETECTOR complete. Found {len(findings)} potential vulnerabilities!")
    else:
        emit.info("[-] No obvious CSRF vulnerabilities detected.")

    return {
        "raw": f"Audited {len(state_changing)} endpoints. Found {len(findings)} potential CSRF issues.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["CSRF_POTENTIAL" if findings else "NO_CSRF"]
    }
