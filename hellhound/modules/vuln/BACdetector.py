import requests
import json
import re
import time
import difflib
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Any, Set
from hellhound.core import http_utils

NAME = "bacdetector"
CATEGORY = "vuln"
DESCRIPTION = "Universal Logic Matrix Auditor (Fidelity Success Detection)"

# Module Options
OPTIONS = [
    {"name": "cookie", "default": "", "required": False, "help": "Custom session cookie for UserA testing"},
    {"name": "token", "default": "", "required": False, "help": "Custom JWT token for UserA testing"},
    {"name": "threads", "default": 20, "required": False, "help": "Concurrency for the logic matrix"}
]

# ==========================================================
# PATTERNS & BYPASS MATRICES
# ==========================================================

ADMIN_KEYWORDS = {"admin", "manage", "config", "settings", "role", "permissions", "user", "staff"}
SENSITIVE_FIELDS = {"password", "token", "secret", "totp", "apiKey", "hash", "salt"}

BYPASS_HEADERS = [
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"}
]

# ==========================================================
# CORE ENGINES
# ==========================================================

class SessionMgr:
    def __init__(self, emit, options):
        self.emit = emit
        self.sessions = {
            "userA": requests.Session(), "userB": requests.Session(), "guest": requests.Session()
        }
        for s in self.sessions.values():
            s.verify = False; s.timeout = 10
            s.headers.update({"User-Agent": "Mozilla/5.0 (Hellhound-BAC/12.5)"})
        
        c, t = options.get("cookie", ""), options.get("token", "")
        if c:
            if "=" in c: k, v = c.split("=", 1); self.sessions["userA"].cookies.set(k.strip(), v.strip())
            else: self.sessions["userA"].cookies.set("token", c)
            self.emit.info(f"    [*] BAC: UserA session loaded via Cookie")
        if t:
            auth = t if t.startswith("Bearer ") else f"Bearer {t}"
            self.sessions["userA"].headers["Authorization"] = auth
            self.emit.info(f"    [*] BAC: UserA session loaded via JWT")

        # Apply Global Proxy & Headers
        proxy = options.get("proxy")
        global_headers = options.get("global_headers", {})
        enable_waf = options.get("enable_waf_bypass")

        for s in self.sessions.values():
            if proxy:
                http_utils.apply_proxy_to_session(s, proxy)
            if global_headers:
                s.headers.update(global_headers)
            if enable_waf:
                s.headers.update(http_utils.get_waf_bypass_header())

class FidelityAuditor:
    def __init__(self, base_url: str, sessions: Dict[str, requests.Session], emit):
        self.base_url = base_url
        self.sessions = sessions
        self.emit = emit
        self.findings: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._critical_urls = set()

    def audit(self, ep_url: str):
        # 1. Base check (Baseline response)
        session_a = self.sessions["userA"]
        try:
            r_a = session_a.get(ep_url, timeout=10, allow_redirects=False)
        except: return

        if r_a.status_code not in (200, 201, 204): return
        
        # Check for Exposure
        self._check_exposure(r_a, ep_url)

        # 2. Guest check (Auth Bypass)
        # Try both direct and bypass-header attempts
        for bypass_h in [None] + BYPASS_HEADERS:
            headers = bypass_h if bypass_h else {}
            r_g = self._req("guest", ep_url, headers=headers)
            if self._is_hit(r_g, r_a):
                method_name = f"(via {list(headers.keys())[0]})" if bypass_h else "(Direct)"
                repro = {
                    "url": ep_url,
                    "method": "GET",
                    "headers": dict(self.sessions["guest"].headers),
                    "body": None
                }
                self._add_finding("Missing Authentication", "Critical", ep_url, f"Guest accessed protected API {method_name}", repro_context=repro)
                self._critical_urls.add(ep_url); break

        # 3. RBAC/Vertical check
        is_admin_ep = any(k in ep_url.lower() for k in ADMIN_KEYWORDS)
        if is_admin_ep and ep_url not in self._critical_urls:
            r_b = self._req("userB", ep_url)
            if self._is_hit(r_b, r_a):
                repro = {
                    "url": ep_url,
                    "method": "GET",
                    "headers": dict(self.sessions["userB"].headers),
                    "body": None
                }
                self._add_finding("Vertical Privilege Escalation", "High", ep_url, "Low-priv session accessed administrative resource", repro_context=repro)

        # 4. UserB check (Horizontal Access Control)
        if ep_url not in self._critical_urls:
            r_b = self._req("userB", ep_url)
            if self._is_hit(r_b, r_a):
                repro = {
                    "url": ep_url,
                    "method": "GET",
                    "headers": dict(self.sessions["userB"].headers),
                    "body": None
                }
                self._add_finding("Horizontal Authorization Bypass", "High", ep_url, "UserB accessed UserA resource", repro_context=repro)

        # 5. Admin Action Validation (POST/PUT/DELETE)
        if ep_url not in self._critical_urls:
            if is_admin_ep:
                for method in ("POST", "PUT", "DELETE"):
                    payload = {"id": 1, "test": "logic-probe"}
                    try:
                        res = self.sessions["userA"].request(method, ep_url, json=payload, timeout=5)
                        if res.status_code in (200, 201, 204) and self._is_state_change_hit(res):
                            repro = {
                                "url": ep_url,
                                "method": method,
                                "headers": dict(self.sessions["userA"].headers),
                                "body": payload
                            }
                            self._add_finding(f"Unauthorized Admin Action — {method}", "Critical", ep_url, f"Non-admin performed state change via {method}", repro_context=repro)
                    except: pass

    def _is_hit(self, r_test, r_base):
        if r_test.status_code != r_base.status_code: return False
        # If response length is significantly different, it's likely a custom 403 or error page
        if abs(len(r_test.text) - len(r_base.text)) > 200: return False
        # Compare content similarity
        ratio = difflib.SequenceMatcher(None, r_test.text[:5000], r_base.text[:5000]).ratio()
        return ratio > 0.85

    def _is_state_change_hit(self, res):
        # A successful state change usually returns a JSON status or remains 2xx
        return res.status_code in (200, 201, 204)

    def _check_exposure(self, r, url):
        # Scan for sensitive field exposure in baseline
        leaks = [f for f in SENSITIVE_FIELDS if f in r.text]
        if leaks:
            self._add_finding("Excessive Data Exposure", "Medium", url, f"Endpoint returns sensitive fields: {', '.join(leaks)}")

    def _req(self, role, url, headers=None):
        try: return self.sessions[role].get(url, timeout=10, headers=headers, allow_redirects=False)
        except: return requests.Response()

    def _add_finding(self, name, severity, ep, details, repro_context=None):
        with self._lock:
            if ep in self._critical_urls and severity != "Critical": return
            if any(f["endpoint"] == ep and f["vulnerability"] == name for f in self.findings): return
            
            finding = {
                "vulnerability": name, 
                "severity": severity, 
                "endpoint": ep, 
                "details": details,
                "proof": details
            }
            if repro_context:
                finding["repro_data"] = repro_context
            self.findings.append(finding)
            self.emit.warn(f"    [!] Discovery: {severity} - {name} @ {ep.split('/')[-1]}")

def run(target: str, emit, options: Optional[Dict[str, Any]] = None):
    emit.info(f"[*] Logic Matrix v12.5 (Universal Mastery): {target}")
    opt = options or {}
    mgr = SessionMgr(emit, opt)
    
    spider_intel = opt.get("spider_intel", {})
    all_eps = spider_intel.get("endpoints", [])
    
    targets = {e.get("url") for e in all_eps if e.get("url")}
    prio_targets = sorted(list(targets), key=lambda x: any(k in x.lower() for k in ADMIN_KEYWORDS), reverse=True)
    
    auditor = FidelityAuditor(target, mgr.sessions, emit)
    with ThreadPoolExecutor(max_workers=int(opt.get("threads", 20))) as pool:
        pool.map(auditor.audit, prio_targets[:150])

    if not auditor.findings:
        emit.info("[-] No logic flaws discovered.")
        return {"raw": "0 findings", "intel": {}, "risk_score": 0}

    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in auditor.findings: summary[f["severity"]] += 1
    
    risk_score = sum(25 if f["severity"] == "Critical" else 15 if f["severity"] == "High" else 5 for f in auditor.findings)

    return {
        "raw": f"Discovered {len(auditor.findings)} logic flaws across the matrix.",
        "intel": {
            "vulnerabilities": auditor.findings,
            "bac": {"summary": summary, "risk_score": risk_score}
        },
        "risk_score": risk_score,
        "parameter_sensitive": True
    }