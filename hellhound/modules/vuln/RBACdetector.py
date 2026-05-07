import asyncio
import hmac
import aiohttp
import re
import difflib
import json
import base64
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from yarl import URL
from colorama import Fore, Style
from hellhound.core import http_utils

NAME = "rbacdetector"
CATEGORY = "vuln"
DESCRIPTION = "Universal Role-Based Access Control vulnerability detector"

OPTIONS = [
    {"name": "cookie_g", "default": "", "required": False, "help": "Guest session cookie"},
    {"name": "token_g",  "default": "", "required": False, "help": "Auth token for Guest"},
    {"name": "cookie_u", "default": "", "required": False, "help": "User A cookie (REQUIRED if token_u missing)"},
    {"name": "token_u",  "default": "", "required": False, "help": "User A token (REQUIRED if cookie_u missing)"},
    {"name": "cookie_a", "default": "", "required": False, "help": "Admin session cookie"},
    {"name": "token_a",  "default": "", "required": False, "help": "Admin auth token"},
    {"name": "expand_endpoints", "type": bool, "default": True, "help": "Intelligently expand spider endpoints"},
    {"name": "idor_depth", "type": int, "default": 2, "help": "Number of ID variations to test"},
    {"name": "fidelity", "default": 0.85, "required": True, "help": "Success threshold ratio"},
    {"name": "concurrency", "type": int, "default": 10, "required": True, "help": "Concurrent audit threads"},
]

PRIVILEGED_KEYWORDS = ["admin", "superadmin", "root", "sysadmin", "manage", "config", "setup", "dashboard", "console", "controlpanel"]

class RBACAuditor:
    def __init__(self, emit, options):
        self.emit = emit
        self.options = options
        self.target = options.get("target", "")
        self.threshold = float(options.get("fidelity", 0.85))
        self.sessions: Dict[str, List[aiohttp.ClientSession]] = {"guest": [], "user": [], "admin": []}
        self.findings = []
        self.semaphore = asyncio.Semaphore(options.get("concurrency", 10))
        self.mode = "guest_only"
        self.skip_patterns = [p.strip().lower() for p in options.get("skip_patterns", "").split(",") if p.strip()]

    async def setup_sessions(self):
        has_admin = any(self.options.get(x) for x in ["cookie_a", "token_a"])
        has_user = any(self.options.get(x) for x in ["cookie_u", "token_u"])
        self.mode = "full_differential" if has_admin else "vertical_escalation" if has_user else "guest_only"

        for role in ["guest", "user", "admin"]:
            role_cookies = []
            if role == "guest": role_cookies.append(self.options.get("cookie_g") or "")
            elif role == "user": role_cookies.append(self.options.get("cookie_u") or "")
            elif role == "admin": role_cookies.append(self.options.get("cookie_a") or "")

            for cookie_str in role_cookies:
                jar = aiohttp.CookieJar(unsafe=True)
                session = aiohttp.ClientSession(cookie_jar=jar)
                http_utils.apply_session_config(session, self.options)
                session._default_headers["User-Agent"] = "Mozilla/5.0 (Hellhound-RBACdetector/5.0)"
                
                suffix = "_g" if role == "guest" else "_u" if role == "user" else "_a"
                token = self.options.get(f"token{suffix}")
                if token:
                    auth = token if any(x in token for x in ["Bearer ", "Basic "]) else f"Bearer {token}"
                    session._default_headers["Authorization"] = auth
                
                if cookie_str:
                    c_dict = {}
                    for part in cookie_str.split(";"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            c_dict[k.strip()] = v.strip()
                    session.cookie_jar.update_cookies(c_dict, URL(self.target))
                self.sessions[role].append(session)

    def expand_endpoints(self, endpoints):
        """Intelligently expand discovered endpoints without full crawling"""
        expanded = []
        seen = set()
        idor_depth = self.options.get("idor_depth", 2)
        
        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            if url not in seen:
                expanded.append(ep)
                seen.add(f"{url}|{method}")
            
            # 1. Path-based ID Expansion
            path_match = re.search(r'/(\d+)(?:/|$)', url)
            if path_match:
                orig_id = path_match.group(1)
                for offset in range(-idor_depth, idor_depth + 1):
                    if offset == 0: continue
                    new_id = str(int(orig_id) + offset)
                    if new_id.isdigit() and int(new_id) > 0:
                        new_url = url.replace(f"/{orig_id}", f"/{new_id}", 1)
                        if f"{new_url}|{method}" not in seen:
                            expanded.append({"url": new_url, "method": method, "params": ep.get("params", {})})
                            seen.add(f"{new_url}|{method}")
            
            # 2. Query-based ID Mutation
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for p_name in ['id', 'userId', 'user_id', 'uid', 'customerId', 'basketId', 'accountId']:
                    if p_name in params:
                        for idx, val in enumerate(params[p_name]):
                            if val.isdigit():
                                for offset in range(-idor_depth, idor_depth + 1):
                                    if offset == 0: continue
                                    new_v = str(int(val) + offset)
                                    if new_v.isdigit() and int(new_v) > 0:
                                        new_p = params.copy()
                                        new_p[p_name] = [new_v]
                                        new_url = urlunparse(parsed._replace(query=urlencode(new_p, doseq=True)))
                                        if f"{new_url}|{method}" not in seen:
                                            expanded.append({"url": new_url, "method": method, "params": ep.get("params", {})})
                                            seen.add(f"{new_url}|{method}")
            
            # 3. Method Swapping (GET -> POST for actions)
            action_kw = ['delete', 'remove', 'update', 'change', 'create', 'add', 'set', 'enable', 'disable']
            if method == "GET" and any(kw in url.lower() for kw in action_kw):
                if f"{url}|POST" not in seen:
                    expanded.append({"url": url, "method": "POST", "params": ep.get("params", {})})
                    seen.add(f"{url}|POST")
            
            # 4. Singular/Plural Variant
            if '/api/' in url and url.endswith('s') and not url.endswith('ss'):
                sing_url = url[:-1]
                if f"{sing_url}|{method}" not in seen:
                    expanded.append({"url": sing_url, "method": method, "params": ep.get("params", {})})
                    seen.add(f"{sing_url}|{method}")
                    
        return expanded

    async def audit_endpoint(self, ep_url, method="GET"):
        if self.mode == "guest_only" or any(p in ep_url.lower() for p in self.skip_patterns): return

        try:
            async with self.semaphore:
                guest_resp = await self._req("guest", method, ep_url)
                if not guest_resp: return

                user_resp = await self._req("user", method, ep_url)
                if not user_resp: return

                # Logic A: Status Code Differential (Vertical)
                if guest_resp['status'] in [401, 403, 404] and user_resp['status'] in [200, 201, 204]:
                    if await self._is_meaningful(user_resp['text']):
                        self._add_finding(ep_url, method, "user", "Anonymous", f"Vertical Escalation: {method} access to restricted resource", severity="CRITICAL", confidence="HIGH")

                # Logic B: Content Ratio Differential
                elif guest_resp['status'] == 200 and user_resp['status'] == 200:
                    ratio = difflib.SequenceMatcher(None, guest_resp['text'][:2500], user_resp['text'][:2500]).ratio()
                    if ratio < self.threshold:
                        if self._contains_sensitive_data(user_resp['text']):
                            self._add_finding(ep_url, method, "user", "Anonymous", "Sensitive Data Leak: Privileged content mismatch", severity="HIGH", confidence="MEDIUM")

        except Exception: pass

    async def _req(self, role, method, url):
        if not self.sessions.get(role): return None
        session = self.sessions[role][0]
        try:
            async with session.request(method, url, timeout=10, allow_redirects=False) as r:
                text = await r.text()
                return {"status": r.status, "text": text, "len": len(text)}
        except Exception: return None

    async def _is_meaningful(self, text):
        text_l = text.lower()
        if any(k in text_l for k in PRIVILEGED_KEYWORDS): return True
        if (text.strip().startswith("{") or text.strip().startswith("[")) and len(text) > 50: return True
        return len(text) > 400

    def _contains_sensitive_data(self, text):
        patterns = [r'"email"', r'"password"', r'"token"', r'"secret"', r'"apiKey"', r'"creditCard"', r'"ssn"']
        for p in patterns:
            if re.search(p, text, re.I): return True
        return len(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)) > 1

    def _add_finding(self, url, method, role, target_role, name, severity="HIGH", confidence="MEDIUM"):
        if any(f['url'] == url and f['type'] == name for f in self.findings): return
        
        session = self.sessions[role.lower()][0]
        headers = dict(getattr(session, "_default_headers", {}))
        cookies = [f"{c.key}={c.value}" for c in session.cookie_jar]
        
        auth_h = f" -H 'Authorization: {headers['Authorization']}'" if headers.get("Authorization") else ""
        cook_h = f" -H 'Cookie: {'; '.join(cookies)}'" if cookies else ""
        poc_curl = f"curl -sk -X {method}{auth_h}{cook_h} '{url}'"
        
        c_sev = Fore.RED + Style.BRIGHT if severity == "CRITICAL" else Fore.YELLOW + Style.BRIGHT
        c_url = Fore.CYAN + Style.BRIGHT
        c_poc = Fore.YELLOW + Style.BRIGHT
        c_conf = Fore.CYAN
        c_type = Fore.WHITE + Style.BRIGHT
        
        finding = {
            "url": f"{c_url}{url}{Style.RESET_ALL}", 
            "method": f"{Fore.YELLOW}{method}{Style.RESET_ALL}", 
            "type": f"{c_type}{name}{Style.RESET_ALL}", 
            "severity": f"{c_sev}{severity}{Style.RESET_ALL}", 
            "confidence": f"{c_conf}{confidence}{Style.RESET_ALL}",
            "evidence": f"{c_url}{role.upper()} -> {target_role.upper()}{Style.RESET_ALL}", 
            "poc_curl": f"{c_poc}{poc_curl}{Style.RESET_ALL}",
            "repro_data": {"url": url, "method": method, "headers": headers}
        }
        self.findings.append(finding)
        self.emit.warn(f"{c_sev}[ {severity} ]{Style.RESET_ALL} {c_conf}({confidence}){Style.RESET_ALL} — {c_type}{name}{Style.RESET_ALL}")
        self.emit.print_always(f"        {Fore.WHITE}{method} {url.split('/')[-1]}{Style.RESET_ALL}")
        self.emit.print_always(f"        {c_poc}{poc_curl}{Style.RESET_ALL}")

async def run(target, emit, options=None):
    emit.info(f"[*] RBACdetector: Expansion Logic Matrix for {target}")
    auditor = RBACAuditor(emit, options or {})
    await auditor.setup_sessions()
    
    endpoints = (options or {}).get("spider_intel", {}).get("endpoints", [])
    if auditor.options.get("expand_endpoints", True):
        expanded = auditor.expand_endpoints(endpoints)
        emit.info(f"    [i] Expanded {len(endpoints)} endpoints to {len(expanded)} audit candidates...")
        endpoints = expanded

    tasks = [auditor.audit_endpoint(ep['url'], ep.get('method', 'GET')) for ep in endpoints[:250]]
    await asyncio.gather(*tasks)

    emit.info("-" * 50)
    emit.info(f"[*] {Fore.CYAN + Style.BRIGHT}RBAC TEST SUMMARY: Found {len(auditor.findings)} logic flaws.{Style.RESET_ALL}")
    for s in [s for role_sessions in auditor.sessions.values() for s in role_sessions]: await s.close()
    return {"intel": {"vulnerabilities": auditor.findings}}
