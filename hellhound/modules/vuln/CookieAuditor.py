import asyncio
import aiohttp

NAME = "cookie_auditor"
CATEGORY = "vuln"
DESCRIPTION = "Session Cookie Attribute Security Auditor"

OPTIONS = []

class CookieAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options

    async def audit_cookies(self, url):
        """Analyzes cookie attributes."""
        findings = []
        try:
            async with self.session.get(url, timeout=5) as r:
                # aiohttp r.cookies is a CookieJar-like object
                for cookie in r.cookies.values():
                    cname = cookie.key
                    
                    if not cookie.get("httponly"):
                        findings.append({
                            "url": url,
                            "cookie": cname,
                            "type": "MISSING_HTTPONLY",
                            "severity": "MEDIUM",
                            "evidence": f"Cookie '{cname}' is missing the HttpOnly flag."
                        })
                    
                    if not cookie.get("secure") and url.startswith("https"):
                        findings.append({
                            "url": url,
                            "cookie": cname,
                            "type": "MISSING_SECURE",
                            "severity": "LOW",
                            "evidence": f"Cookie '{cname}' is missing the Secure flag over HTTPS."
                        })
                    
                    samesite = cookie.get("samesite")
                    if not samesite or samesite.lower() == "none":
                        findings.append({
                            "url": url,
                            "cookie": cname,
                            "type": "WEAK_SAMESITE",
                            "severity": "LOW",
                            "evidence": f"Cookie '{cname}' has weak or missing SameSite attribute."
                        })
        except:
            pass
        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] COOKIE_AUDITOR: Analyzing session cookie security for {target}")
    
    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = CookieAuditor(emit, session, options or {})
        res = await auditor.audit_cookies(target)
        if res:
            findings.extend(res)
            for f in res:
                emit.warn(f"        [!] {f['type']}: Cookie '{f['cookie']}' on {target}")

    if findings:
        emit.success(f"[+] COOKIE_AUDITOR complete. Identified {len(findings)} insecure cookie attributes.")
    else:
        emit.info("[-] All identified cookies have secure attributes.")

    return {
        "raw": f"Audited {target}. Found {len(findings)} cookie issues.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["COOKIE_ISSUES" if findings else "NO_COOKIE_ISSUES"]
    }
