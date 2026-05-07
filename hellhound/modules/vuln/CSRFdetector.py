import asyncio
import aiohttp
import re
import secrets
import json
from colorama import Fore, Style
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

NAME = "csrf_detector"
CATEGORY = "vuln"
DESCRIPTION = "Universal Cross-Site Request Forgery vulnerability detector"

OPTIONS = [
    {"name": "concurrency", "type": int, "default": 10, "required": True, "help": "Concurrent audit threads"},
    {"name": "timeout", "type": int, "default": 8, "required": True, "help": "Request timeout (seconds)"},
    {"name": "expand_endpoints", "type": bool, "default": True, "help": "Intelligently expand spider endpoints"},
    {"name": "idor_depth", "type": int, "default": 2, "help": "Number of ID variations to test"},
    {"name": "test_token_validation", "type": bool, "default": True, "required": True, "help": "Verify if the server actually validates tokens"},
]

CSRF_TOKEN_PATTERNS = [
    r"csrf", r"xsrf", r"_token", r"authenticity_token",
    r"requestverificationtoken", r"nonce", r"__requestverificationtoken",
    r"csrfmiddlewaretoken", r"anti-forgery", r"antiforgery"
]

class CSRFAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.semaphore = asyncio.Semaphore(options.get("concurrency", 10))
        self.findings = []

    def expand_endpoints(self, endpoints):
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
            
            # 3. Method Swapping
            action_kw = ['delete', 'remove', 'update', 'change', 'create', 'add', 'set', 'enable', 'disable']
            if method == "GET" and any(kw in url.lower() for kw in action_kw):
                if f"{url}|POST" not in seen:
                    expanded.append({"url": url, "method": "POST", "params": ep.get("params", {})})
                    seen.add(f"{url}|POST")
                    
        return expanded

    def _generate_repro(self, url, method, params=None, headers=None):
        merged_headers = dict(getattr(self.session, "_default_headers", {}))
        if headers: merged_headers.update(headers)
        cookies = [f"{c.key}={c.value}" for c in self.session.cookie_jar]
        
        auth_h = f" -H 'Authorization: {merged_headers['Authorization']}'" if merged_headers.get("Authorization") else ""
        cook_h = f" -H 'Cookie: {'; '.join(cookies)}'" if cookies else ""
        
        poc_curl = f"curl -sk -X {method}{auth_h}{cook_h} '{url}'"
        if params and method != "GET":
            poc_curl += f" -d '{json.dumps(params) if isinstance(params, dict) else params}'"
            
        return {
            "poc_curl": poc_curl,
            "repro_data": {"url": url, "method": method, "headers": merged_headers, "body": params if method != "GET" else None}
        }

    async def audit_endpoint(self, endpoint, all_endpoints=None):
        url = endpoint.get("url")
        method = endpoint.get("method", "GET").upper()
        params = endpoint.get("params", {})
        
        if method not in ["POST", "PUT", "DELETE", "PATCH"]: return []

        token_param = None
        flat_params = []
        if isinstance(params, dict): flat_params = [str(k) for k in params.keys()]
        elif isinstance(params, list): flat_params = [str(p) for p in params]

        for p in flat_params:
            if any(re.search(pattern, p, re.I) for pattern in CSRF_TOKEN_PATTERNS):
                token_param = p
                break

        if not token_param:
            repro = self._generate_repro(url, method, params)
            self._add_finding({
                "url": url, "method": method, "type": "MISSING_CSRF_TOKEN", "severity": "HIGH", "confidence": "HIGH",
                "evidence": "Stateful endpoint lacks anti-CSRF token.",
                **repro
            })
        elif self.options.get("test_token_validation"):
            await self._test_token_validation(endpoint, token_param)

        return self.findings

    def _add_finding(self, f):
        c_sev = Fore.RED + Style.BRIGHT if f['severity'] == "CRITICAL" else Fore.YELLOW + Style.BRIGHT
        c_url = Fore.CYAN + Style.BRIGHT
        c_poc = Fore.YELLOW + Style.BRIGHT
        c_conf = Fore.CYAN
        c_type = Fore.WHITE + Style.BRIGHT
        
        finding = {
            "url": f"{c_url}{f['url']}{Style.RESET_ALL}", 
            "method": f"{Fore.YELLOW}{f['method']}{Style.RESET_ALL}", 
            "type": f"{c_type}{f['type']}{Style.RESET_ALL}", 
            "severity": f"{c_sev}{f['severity']}{Style.RESET_ALL}", 
            "confidence": f"{c_conf}{f['confidence']}{Style.RESET_ALL}",
            "evidence": f"{Fore.CYAN}{f['evidence']}{Style.RESET_ALL}", 
            "poc_curl": f"{c_poc}{f['poc_curl']}{Style.RESET_ALL}",
            "repro_data": f['repro_data']
        }
        self.findings.append(finding)
        self.emit.warn(f"{c_sev}[ {f['severity']} ]{Style.RESET_ALL} {c_conf}({f['confidence']}){Style.RESET_ALL} — {c_type}{f['type']}{Style.RESET_ALL}")
        self.emit.print_always(f"        {Fore.WHITE}{f['method']} {f['url'].split('/')[-1]}{Style.RESET_ALL}")
        self.emit.print_always(f"        {c_poc}{f['poc_curl']}{Style.RESET_ALL}")

    async def _test_token_validation(self, endpoint, token_name):
        url = endpoint["url"]
        method = endpoint["method"]
        async with self.semaphore:
            for t_type in ["random", "empty"]:
                val = secrets.token_hex(16) if t_type == "random" else ""
                test_params = endpoint.get("params", {}).copy()
                if isinstance(test_params, dict): test_params[token_name] = val
                try:
                    async with self.session.request(method, url, data=test_params, timeout=self.options.get("timeout")) as r:
                        if r.status in [200, 201, 204, 302]:
                            repro = self._generate_repro(url, method, test_params)
                            self._add_finding({
                                "url": url, "method": method, "type": "WEAK_TOKEN_VALIDATION", "severity": "CRITICAL", "confidence": "HIGH",
                                "evidence": f"Accepted {t_type} token.",
                                **repro
                            })
                            break
                except: pass

async def run(target, emit, options=None):
    emit.info(f"[*] CSRFdetector: Expansion Logic Matrix for {target}")
    endpoints = (options or {}).get("spider_intel", {}).get("endpoints", [])
    
    async with aiohttp.ClientSession() as session:
        from hellhound.core import http_utils
        http_utils.apply_session_config(session, options or {})
        auditor = CSRFAuditor(emit, session, options or {})
        
        if auditor.options.get("expand_endpoints", True):
            endpoints = auditor.expand_endpoints(endpoints)
            emit.info(f"    [i] Expanded audit surface to {len(endpoints)} candidates...")

        tasks = [auditor.audit_endpoint(ep, endpoints) for ep in endpoints if ep.get("method", "GET").upper() in ["POST", "PUT", "DELETE", "PATCH"]]
        await asyncio.gather(*tasks)
        
    emit.success(f"[+] {Fore.CYAN + Style.BRIGHT}CSRF_DETECTOR complete. Found {len(auditor.findings)} issues.{Style.RESET_ALL}")
    return {"intel": {"vulnerabilities": auditor.findings}}
