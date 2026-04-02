import requests
import re
import time
import difflib
import threading
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Any, Set
from hellhound.core import http_utils

NAME = "rbac"
CATEGORY = "vuln"
DESCRIPTION = "Universal Role-Based Access Control (RBAC) & Privilege Escalation Auditor"

# Module Options
OPTIONS = [
    {"name": "cookie_g", "default": "", "required": False, "help": "Session cookie for Guest role"},
    {"name": "token_g",  "default": "", "required": False, "help": "Auth token for Guest role"},
    {"name": "cookie_u", "default": "", "required": False, "help": "Session cookie for Standard User role"},
    {"name": "token_u",  "default": "", "required": False, "help": "Auth token for Standard User role"},
    {"name": "cookie_a", "default": "", "required": False, "help": "Session cookie for Admin role (Baseline)"},
    {"name": "token_a",  "default": "", "required": False, "help": "Auth token for Admin role (Baseline)"},
    {"name": "threads",  "default": 10, "required": False, "help": "Concurrency for the logic matrix"},
    {"name": "fidelity", "default": 0.85, "required": False, "help": "Success threshold ratio (0.1 to 1.0)"},
    {"name": "deep_scan", "type": bool, "default": False, "help": "Enable dynamic identity harvesting and IDOR swapping"}
]

# ==========================================================
# PATTERNS & BYPASS MATRICES
# ==========================================================

PRIVILEGED_KEYWORDS = [
    "admin", "manage", "config", "settings", "role", "permissions", 
    "user", "staff", "dashboard", "console", "accounting", "reports",
    "invoice", "order", "system", "internal", "debug", "root"
]

WHOAMI_ENDPOINTS = [
    "/rest/user/whoami", "/api/users/me", "/api/profile", "/api/v1/user",
    "/rest/admin/whoami", "/settings/profile", "/api/auth/session"
]

ID_PATTERN = re.compile(r'["\'](?:id|uid|userId|accountId|ownerId)["\']\s*[:=]\s*(\d+|[a-f0-9-]{32,36})', re.I)

# ==========================================================
# CORE ENGINES
# ==========================================================

class SessionMgr:
    def __init__(self, emit, options):
        self.emit = emit
        self.sessions = {
            "guest": requests.Session(), 
            "user": requests.Session(), 
            "admin": requests.Session()
        }
        for role, s in self.sessions.items():
            s.verify = False
            s.timeout = 10
            s.headers.update({"User-Agent": "Mozilla/5.0 (Hellhound-RBAC/1.0; Universal Auditor)"})
            
            # Use specific or global cookie/token
            suffix = "_g" if role == "guest" else "_u" if role == "user" else "_a"
            c = options.get(f"cookie{suffix}", options.get("cookie", ""))
            t = options.get(f"token{suffix}", options.get("token", ""))
            
            if c: self._apply_cookies(s, c)
            if t: self._apply_token(s, t)
            
            # Apply Global configurations (Proxy/WAF)
            http_utils.apply_session_config(s, options)

    def _apply_cookies(self, session, cookie_str):
        if not cookie_str: return
        try:
            for part in cookie_str.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    session.cookies.set(k.strip(), v.strip())
                else:
                    session.cookies.set("session", cookie_str.strip())
        except: pass

    def _apply_token(self, session, token_str):
        if not token_str: return
        auth = token_str if any(x in token_str for x in ["Bearer ", "Basic ", "Token "]) else f"Bearer {token_str}"
        session.headers["Authorization"] = auth

class IdentityHarvester:
    def __init__(self, sessions, emit):
        self.sessions = sessions
        self.emit = emit
        self.identities = {"admin": set(), "user": set(), "guest": set()}

    def harvest(self, base_url):
        for role, session in self.sessions.items():
            for ep in WHOAMI_ENDPOINTS:
                try:
                    url = f"{base_url.rstrip('/')}{ep}"
                    r = session.get(url, timeout=5)
                    if r.status_code == 200:
                        matches = ID_PATTERN.findall(r.text)
                        for m in matches:
                            self.identities[role].add(m)
                except: continue
            if self.identities[role]:
                self.emit.info(f"    [*] RBAC: Harvested IDs for {role}: {list(self.identities[role])}")

class RoleMatrixAuditor:
    def __init__(self, base_url: str, sessions: Dict[str, requests.Session], emit, options: Dict[str, Any] = None):
        self.base_url = base_url
        self.sessions = sessions
        self.emit = emit
        self.options = options or {}
        self.threshold = float(self.options.get("fidelity", 0.85))
        self.identities = {}
        self.findings: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._critical_eps = set()

    def audit(self, ep_data: Dict[str, Any]):
        ep_url = ep_data.get("url")
        if not ep_url: return
        
        # 1. Admin Baseline (Authorized check)
        try:
            r_admin = self.sessions["admin"].get(ep_url, timeout=10, allow_redirects=False)
        except: return

        # Only proceed if Admin actually has access (2xx)
        if r_admin.status_code not in (200, 201, 204): return

        # ==========================================================
        # RBAC MATRIX
        # ==========================================================

        # 2. Guest Privilege Escalation (Unauthorized: Guest, Expected: Admin)
        r_guest = self._req("guest", ep_url)
        if self._is_hit(r_guest, r_admin):
            repro_h = self._get_headers("guest")
            self._add_finding(
                name="Broken Role-Based Access Control",
                severity="Critical",
                ep=ep_url,
                details="Guest role accessed administrative resource",
                unauth_role="Guest",
                expected_role="Admin",
                repro={"url": ep_url, "method": "GET", "role": "guest", "headers": repro_h}
            )
            self._critical_eps.add(ep_url)

        # 3. User Privilege Escalation (Unauthorized: Member, Expected: Admin)
        if ep_url not in self._critical_eps:
            is_privileged_ep = any(k in ep_url.lower() for k in PRIVILEGED_KEYWORDS)
            if is_privileged_ep:
                r_user = self._req("user", ep_url)
                if self._is_hit(r_user, r_admin):
                    self._add_finding(
                        name="Vertical Privilege Escalation",
                        severity="High",
                        ep=ep_url,
                        details="Standard user accessed administrative resource",
                        unauth_role="Standard User",
                        expected_role="Admin",
                        repro={"url": ep_url, "method": "GET", "role": "user", "headers": self._get_headers("user")}
                    )

        # 4. Identity Swapping (Unauthorized: UserB, Expected: UserA)
        # Testing if UserB can access UserA's private resources via ID swapping
        if self.options.get("deep_scan") and self.identities.get("admin"):
            for admin_id in self.identities["admin"]:
                if re.search(r'/\d+|/[a-f0-9-]{32,36}', ep_url):
                    swapped_url = re.sub(r'/\d+|/[a-f0-9-]{32,36}', f"/{admin_id}", ep_url)
                    r_swap = self._req("user", swapped_url)
                    if r_swap.status_code == 200:
                        self._add_finding(
                            name="Insecure Direct Object Reference (RBAC)",
                            severity="High",
                            ep=swapped_url,
                            details="User accessed Admin identity object via ID swapping",
                            unauth_role="Standard User",
                            expected_role="Admin",
                            repro={"url": swapped_url, "method": "GET", "role": "user", "headers": self._get_headers("user")}
                        )

    def _is_hit(self, r_test, r_base):
        if r_test.status_code != r_base.status_code: return False
        if len(r_test.text) < 10: return False
        diff_limit = 200 if len(r_base.text) > 1000 else 50
        if abs(len(r_test.text) - len(r_base.text)) > diff_limit: return False
        ratio = difflib.SequenceMatcher(None, r_test.text[:5000], r_base.text[:5000]).ratio()
        return ratio >= self.threshold

    def _get_headers(self, role):
        s = self.sessions[role]
        headers = dict(s.headers)
        cookies = s.cookies.get_dict()
        if cookies: headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        return headers

    def _req(self, role, url, method="GET", data=None):
        try: return self.sessions[role].request(method, url, timeout=10, allow_redirects=False, json=data)
        except: return requests.Response()

    def _add_finding(self, name, severity, ep, details, unauth_role=None, expected_role=None, repro=None):
        with self._lock:
            if any(f["endpoint"] == ep and f["vulnerability"] == name for f in self.findings): return
            finding = {
                "vulnerability": name, 
                "severity": severity, 
                "endpoint": ep, 
                "details": details,
                "unauthorized_role": unauth_role,
                "expected_role": expected_role,
                "repro_data": repro
            }
            self.findings.append(finding)
            self.emit.warn(f"    [!] Discovery: {severity} - {name} @ {ep.split('/')[-1]}")

def run(target: str, emit, options: Optional[Dict[str, Any]] = None):
    emit.info(f"[*] RBAC Logic Matrix v2.0: {target}")
    opt = options or {}
    mgr = SessionMgr(emit, opt)
    
    if opt.get("deep_scan"):
        harvester = IdentityHarvester(mgr.sessions, emit)
        harvester.harvest(target)
    
    spider_intel = opt.get("spider_intel", {})
    all_eps = spider_intel.get("endpoints", [])
    
    ep_list = []
    seen = set()
    for ep in all_eps:
        url = ep.get("url")
        if url and url not in seen:
            ep_list.append(ep); seen.add(url)
    
    # Prioritize privileged keywords
    targets = sorted(ep_list, key=lambda x: any(k in x.get("url", "").lower() for k in PRIVILEGED_KEYWORDS), reverse=True)
    
    auditor = RoleMatrixAuditor(target, mgr.sessions, emit, options=opt)
    if opt.get("deep_scan"): auditor.identities = harvester.identities
    
    threads = int(opt.get("threads", 10))
    emit.info(f"    [i] Auditing {len(targets[:150])} endpoints using {threads} threads...")
    
    with ThreadPoolExecutor(max_workers=threads) as pool:
        pool.map(auditor.audit, targets[:150])

    if not auditor.findings:
        emit.info("[-] No RBAC flaws discovered.")
        return {"raw": "0 findings", "intel": {}, "risk_score": 0}

    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in auditor.findings: summary[f["severity"]] += 1
    
    risk_score = min(100, sum(30 if f["severity"] == "Critical" else 15 if f["severity"] == "High" else 5 for f in auditor.findings))

    return {
        "raw": f"Discovered {len(auditor.findings)} role-based logic flaws.",
        "intel": {"vulnerabilities": auditor.findings, "summary": summary, "risk_score": risk_score},
        "risk_score": risk_score
    }
