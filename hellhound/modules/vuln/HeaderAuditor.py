import asyncio
import aiohttp

NAME = "header_auditor"
CATEGORY = "vuln"
DESCRIPTION = "HTTP Security Header Baseline Auditor"

OPTIONS = []

SECURITY_HEADERS = {
    "Content-Security-Policy": {"severity": "MEDIUM", "desc": "CSP missing (Risk of XSS/Injection)"},
    "Strict-Transport-Security": {"severity": "LOW", "desc": "HSTS missing (Risk of SSL stripping)"},
    "X-Frame-Options": {"severity": "LOW", "desc": "Clickjacking protection missing"},
    "X-Content-Type-Options": {"severity": "INFO", "desc": "MIME-sniffing protection missing"},
    "Referrer-Policy": {"severity": "INFO", "desc": "Referrer policy not set"},
}

class HeaderAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options

    async def audit_headers(self, url):
        """Checks for missing security headers."""
        findings = []
        try:
            async with self.session.get(url, timeout=5) as r:
                headers = r.headers
                for hname, info in SECURITY_HEADERS.items():
                    if hname not in headers:
                        findings.append({
                            "url": url,
                            "header": hname,
                            "type": "MISSING_HEADER",
                            "severity": info["severity"],
                            "description": info["desc"]
                        })
        except:
            pass
        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] HEADER_AUDITOR: Scanning security header baseline for {target}")
    
    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = HeaderAuditor(emit, session, options or {})
        res = await auditor.audit_headers(target)
        if res:
            findings.extend(res)
            for f in res:
                emit.warn(f"        [!] {f['header']} is missing on {target}")

    if findings:
        emit.success(f"[+] HEADER_AUDITOR complete. Identified {len(findings)} missing/misconfigured headers.")
    else:
        emit.info("[-] All baseline security headers are present.")

    return {
        "raw": f"Audited {target}. Found {len(findings)} header issues.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["HEADER_ISSUES" if findings else "NO_HEADER_ISSUES"]
    }
