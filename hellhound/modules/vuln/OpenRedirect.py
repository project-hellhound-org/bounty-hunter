import asyncio
import aiohttp
from urllib.parse import urlparse

NAME = "open_redirect"
CATEGORY = "vuln"
DESCRIPTION = "Open Redirection Auditor"

OPTIONS = [
    {"name": "timeout", "type": int, "default": 5, "help": "Request timeout (seconds)"},
]

REDIRECT_PAYLOADS = [
    "https://google.com",
    "//google.com",
    "https:google.com",
    "/\\google.com",
]

class RedirectAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options

    async def check_redirect(self, url, method, pname):
        """Checks for Open Redirect by monitoring Location header."""
        findings = []
        for payload in REDIRECT_PAYLOADS:
            try:
                # We use allow_redirects=False to catch the Location header ourselves
                async with self.session.request(method, url, params={pname: payload}, allow_redirects=False, timeout=self.options.get("timeout")) as r:
                    location = r.headers.get("Location", "")
                    if "google.com" in location.lower():
                        findings.append({
                            "url": url,
                            "parameter": pname,
                            "type": "OPEN_REDIRECT",
                            "severity": "MEDIUM",
                            "evidence": f"Redirected to: {location} using payload {payload}"
                        })
                        break
            except:
                continue
        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] OPEN_REDIRECT: Auditing redirection parameters for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    surfaces = []
    for ep in endpoints:
        for p_items in ep.get("params", {}).values():
            for p in p_items:
                if any(x in p.lower() for x in ["url", "redirect", "next", "dest", "to", "out", "view", "link"]):
                    surfaces.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not surfaces:
        emit.warn("[!] No redirection-likely parameters identified.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Auditing {len(surfaces)} potential redirection surface(s)...")

    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = RedirectAuditor(emit, session, options or {})
        for s in surfaces:
            res = await auditor.check_redirect(s["url"], s["method"], s["parameter"])
            if res:
                findings.extend(res)
                for f in res:
                    emit.warn(f"        [!] OPEN REDIRECT FOUND: {f['url']} via {f['parameter']}")

    if findings:
        emit.success(f"[+] OPEN_REDIRECT complete. Found {len(findings)} redirection vulnerabilities!")
    else:
        emit.info("[-] No open redirects detected.")

    return {
        "raw": f"Audited {len(surfaces)} surfaces. Found {len(findings)} Open Redirects.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["REDIRECT_FOUND" if findings else "NO_REDIRECT"]
    }
