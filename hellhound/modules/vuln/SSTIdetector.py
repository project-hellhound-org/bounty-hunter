import asyncio
import aiohttp
import re
from hellhound.core import oob_utils

NAME = "ssti_detector"
CATEGORY = "vuln"
DESCRIPTION = "Server-Side Template Injection (SSTI) Auditor"

OPTIONS = [
    {"name": "timeout", "type": int, "default": 10, "help": "Request timeout (seconds)"},
    {"name": "concurrency", "type": int, "default": 5, "help": "Concurrent attack threads"},
]

# ─────────────────────────────────────────────────────────────────────────────
# PROBES & ENGINES
# ─────────────────────────────────────────────────────────────────────────────

SSTI_PROBES = [
    {"engine": "Jinja2/Twig", "probe": "{{7*7}}", "pattern": r"49"},
    {"engine": "Mako", "probe": "${7*7}", "pattern": r"49"},
    {"engine": "ERB", "probe": "<%= 7*7 %>", "pattern": r"49"},
    {"engine": "Smarty", "probe": "{7*7}", "pattern": r"49"},
    {"engine": "Handlebars", "probe": "{{7*7}}", "pattern": r"49"}, # Handlebars often requires helpers, but simple math works in some setups
]

class SSTIAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options

    async def check_ssti(self, url, method, pname):
        """Checks for SSTI using math reflection."""
        findings = []
        for probe in SSTI_PROBES:
            try:
                params = {pname: probe["probe"]} if method == "GET" else {}
                data = {pname: probe["probe"]} if method == "POST" else {}
                
                async with self.session.request(method, url, params=params, data=data, timeout=self.options.get("timeout")) as r:
                    body = await r.text()
                    if re.search(probe["pattern"], body):
                        # Verify it's not a false positive by testing another math string
                        verify_probe = probe["probe"].replace("7*7", "8*8")
                        v_params = {pname: verify_probe} if method == "GET" else {}
                        v_data = {pname: verify_probe} if method == "POST" else {}
                        
                        async with self.session.request(method, url, params=v_params, data=v_data) as vr:
                            v_body = await vr.text()
                            if "64" in v_body and "49" not in v_body:
                                findings.append({
                                    "url": url,
                                    "parameter": pname,
                                    "type": "SSTI",
                                    "engine": probe["engine"],
                                    "severity": "CRITICAL",
                                    "evidence": f"Reflected math evaluation: 7*7=49 via {probe['engine']} syntax"
                                })
                                break # Found one, likely no need to check other engines for this param
            except:
                continue
        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] SSTI_DETECTOR: Probing for template injection on {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    # Priority: params flagged as SSTI_POTENTIAL or reflecting input
    surfaces = []
    for ep in endpoints:
        for p_items in ep.get("params", {}).values():
            for p in p_items:
                surfaces.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not surfaces:
        emit.warn("[!] No injection surfaces identified for SSTI testing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Auditing {len(surfaces)} potential SSTI surface(s)...")

    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = SSTIAuditor(emit, session, options or {})
        for s in surfaces:
            res = await auditor.check_ssti(s["url"], s["method"], s["parameter"])
            if res:
                findings.extend(res)
                for f in res:
                    emit.warn(f"        [!] SSTI CONFIRMED: {f['url']} ({f['engine']})")

    if findings:
        emit.success(f"[+] SSTI_DETECTOR complete. Found {len(findings)} confirmed SSTI vulnerabilities!")
    else:
        emit.info("[-] No SSTI vulnerabilities detected.")

    return {
        "raw": f"Audited {len(surfaces)} surfaces. Found {len(findings)} SSTI.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["SSTI_FOUND" if findings else "NO_SSTI"]
    }
