import asyncio
import aiohttp
import re
import difflib
from typing import Dict, List, Optional, Any
from hellhound.core import http_utils

NAME = "rbac"
CATEGORY = "vuln"
DESCRIPTION = "Apex-Grade Logic Matrix: Differential RBAC Auditor"

# Module Options
OPTIONS = [
    {"name": "cookie_g", "default": "", "required": False, "help": "Session cookie for Guest role"},
    {"name": "token_g",  "default": "", "required": False, "help": "Auth token for Guest role"},
    {"name": "cookie_u", "default": "", "required": False, "help": "Session cookie for Standard User role"},
    {"name": "token_u",  "default": "", "required": False, "help": "Auth token for Standard User role"},
    {"name": "cookie_a", "default": "", "required": False, "help": "Session cookie for Admin role (Baseline)"},
    {"name": "token_a",  "default": "", "required": False, "help": "Auth token for Admin role (Baseline)"},
    {"name": "concurrency", "type": int, "default": 5, "help": "Concurrent audit threads"},
    {"name": "fidelity", "default": 0.90, "required": False, "help": "Success threshold ratio (0.1 to 1.0)"},
]

PRIVILEGED_KEYWORDS = [
    "admin", "manage", "config", "settings", "role", "permissions", 
    "user", "staff", "dashboard", "console", "accounting", "reports",
    "invoice", "order", "system", "internal", "debug", "root"
]

class RoleMatrixAuditor:
    def __init__(self, emit, options):
        self.emit = emit
        self.options = options
        self.threshold = float(options.get("fidelity", 0.90))
        self.sessions: Dict[str, aiohttp.ClientSession] = {}
        self.findings = []
        self.semaphore = asyncio.Semaphore(options.get("concurrency", 5))

    async def setup_sessions(self):
        """Initializes specialized sessions for each role."""
        roles = ["guest", "user", "admin"]
        for role in roles:
            jar = aiohttp.CookieJar(unsafe=True)
            session = aiohttp.ClientSession(cookie_jar=jar)
            
            # Apply Role-Specific Auth
            suffix = "_g" if role == "guest" else "_u" if role == "user" else "_a"
            cookie = self.options.get(f"cookie{suffix}")
            token = self.options.get(f"token{suffix}")
            
            headers = {"User-Agent": "Mozilla/5.0 (Hellhound-RBAC/2.0; Apex-Grade)"}
            if token:
                auth = token if any(x in token for x in ["Bearer ", "Basic "]) else f"Bearer {token}"
                headers["Authorization"] = auth
            
            # Manual Cookie Setting to ensure visibility in proxy
            if cookie:
                for part in cookie.split(";"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        session.cookie_jar.update_cookies({k.strip(): v.strip()})
                    else:
                        session.cookie_jar.update_cookies({"session": cookie.strip()})

            # Apply Global Config (Proxy, etc.)
            http_utils.apply_session_config(session, self.options)
            session._default_headers.update(headers)
            self.sessions[role] = session

    async def audit_endpoint(self, ep_url, method="GET"):
        """Performs differential analysis across the role matrix."""
        try:
            async with self.semaphore:
                # 1. Admin Baseline
                async with self.sessions["admin"].request(method, ep_url, timeout=10, allow_redirects=False) as r_admin:
                    admin_status = r_admin.status
                    admin_text = await r_admin.text()
                    
                    # Only proceed if Admin has access (Baseline)
                    if admin_status not in [200, 201, 204]:
                        return

                # 2. Guest Analysis
                async with self.sessions["guest"].request(method, ep_url, timeout=10, allow_redirects=False) as r_guest:
                    guest_status = r_guest.status
                    guest_text = await r_guest.text()

                # 3. User Analysis
                async with self.sessions["user"].request(method, ep_url, timeout=10, allow_redirects=False) as r_user:
                    user_status = r_user.status
                    user_text = await r_user.text()

                # Differential Logic: A finding is valid if Guest/User matches Admin
                # but doesn't match the typical "Unauth" response of the app.
                if self._is_vulnerable(guest_status, guest_text, admin_status, admin_text):
                    self._add_finding(ep_url, method, "Guest", "Admin", "Broken Access Control (Guest -> Admin)")

                elif self._is_vulnerable(user_status, user_text, admin_status, admin_text):
                    self._add_finding(ep_url, method, "Standard User", "Admin", "Vertical Privilege Escalation")

        except Exception as e:
            pass

    def _is_vulnerable(self, test_status, test_text, base_status, base_text):
        """Determines vulnerability based on status and high-fidelity body similarity."""
        if test_status != base_status:
            return False
        
        # If both are 200, check body similarity
        if len(test_text) < 20 or len(base_text) < 20:
            return False
            
        # Use a higher threshold and ignore small variations (tokens, timestamps)
        ratio = difflib.SequenceMatcher(None, test_text[:10000], base_text[:10000]).ratio()
        return ratio >= self.threshold

    def _add_finding(self, url, method, unauth_role, expected_role, name):
        # Deduplicate
        if any(f["url"] == url and f["type"] == name for f in self.findings):
            return
            
        self.findings.append({
            "url": url,
            "method": method,
            "type": name,
            "severity": "CRITICAL" if unauth_role == "Guest" else "HIGH",
            "evidence": f"{unauth_role} accessed {expected_role} resource (Status: 200, Match: >{int(self.threshold*100)}%)",
            "repro_data": {
                "url": url,
                "method": method,
                "role": unauth_role,
                "headers": {"Referer": url} # Real headers come from session in repro engine
            }
        })
        self.emit.warn(f"        [!] RBAC DISCOVERY: {unauth_role} accessed {url.split('/')[-1]}")

async def run(target, emit, options=None):
    emit.info(f"[*] RBAC_MATRIX: Differential Logic Audit for {target}")
    
    auditor = RoleMatrixAuditor(emit, options or {})
    await auditor.setup_sessions()
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    # Filter and prioritize privileged endpoints
    targets = []
    seen = set()
    for ep in endpoints:
        url = ep.get("url")
        if url and url not in seen:
            targets.append(ep)
            seen.add(url)
            
    # Sort by privileged keywords
    targets.sort(key=lambda x: any(k in x.get("url", "").lower() for k in PRIVILEGED_KEYWORDS), reverse=True)
    
    if not targets:
        emit.warn("[!] No targets identified for RBAC auditing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Auditing top {min(100, len(targets))} endpoints for role-based logic flaws...")
    
    tasks = [auditor.audit_endpoint(t["url"], t.get("method", "GET")) for t in targets[:100]]
    await asyncio.gather(*tasks)

    # Cleanup
    for s in auditor.sessions.values():
        await s.close()

    if auditor.findings:
        emit.success(f"[+] RBAC_MATRIX complete. Found {len(auditor.findings)} logic flaws!")
    else:
        emit.info("[-] No RBAC vulnerabilities detected.")

    return {
        "raw": f"Audited {len(targets[:100])} endpoints. Found {len(auditor.findings)} logic flaws.",
        "intel": {"vulnerabilities": auditor.findings},
        "signals": ["RBAC_FLAW" if auditor.findings else "NO_RBAC"]
    }
