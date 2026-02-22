import requests
import requests.adapters
import json
import re
import time
import difflib
import urllib.parse
import logging
import string
import random
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from copy import deepcopy

try:
    from bs4 import BeautifulSoup
    BS4 = True
except ImportError:
    BS4 = False

# ==========================================================
# MODULE METADATA
# ==========================================================
NAME = "bacdetector"
CATEGORY = "vuln"
DESCRIPTION = "Advanced Access Control Scanner (IDOR, RBAC, Auth, Misconfig, Vuln Scan)"

# ==========================================================
# CONSTANTS & CONFIG
# ==========================================================

SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 5,
    "Medium": 3,
    "Low": 1,
    "Info": 0
}

COMMON_PATHS = [
    "/api/users", "/api/users/1", "/api/Users", "/api/Users/1",
    "/api/me", "/me", "/profile", "/account", "/api/profile",
    "/rest/user/whoami", "/api/whoami", "/api/auth/me",
    "/api/orders", "/api/orders/1", "/api/Orders", "/orders",
    "/api/products", "/api/products/1", "/api/Products", "/api/Products/1",
    "/rest/basket/1", "/rest/basket/2",
    "/api/BasketItems", "/api/BasketItems/1", "/api/cart", "/cart",
    "/api/feedbacks", "/api/Feedbacks", "/api/reviews", "/api/comments",
    "/api/Addresss", "/api/addresses", "/api/addresses/1",
    "/api/Cards", "/api/cards", "/api/Wallets", "/api/payments",
    "/admin", "/admin/users", "/admin/dashboard", "/administration",
    "/api/admin", "/api/admin/users", "/settings", "/api/settings", "/config",
    "/api/SecurityQuestions", "/api/SecurityAnswers", "/api/SecurityAnswers/1",
    "/api/Challenges", "/rest/memories", "/api/Deliverys", "/api/Deliverys/1",
    "/api/PrivacyRequests", "/api/Complaints", "/api/Recycles",
    "/search", "/api/search", "/rest/products/search?q=test",
    "/ftp/", "/ftp/acquisitions.md", "/ftp/package.json.bak",
    "/ftp/eastere.gg", "/ftp/coupons_2013.md.bak", "/ftp/suspicious_errors.yml",
    "/download?file=test.txt", "/swagger.json", "/openapi.json",
    "/api-docs", "/api/docs", "/metrics", "/health", "/status",
    "/actuator", "/actuator/env", "/actuator/mappings", "/debug", "/trace",
    "/.env", "/.git/config", "/package.json", "/config.json",
    "/phpinfo.php", "/server-status", "/.htpasswd", "/.htaccess",
    "/rest/admin/application-version", "/rest/admin/application-configuration",
    "/b2b/v2/orders", "/.well-known/security.txt",
]

PROTECTED_EPS = [
    "/api/users", "/api/Users", "/api/users/1", "/api/Users/1",
    "/api/users/2", "/api/Users/2", "/rest/user/whoami", "/api/me", "/me",
    "/api/orders", "/api/Orders", "/api/orders/1", "/rest/basket/1", "/rest/basket/2",
    "/api/BasketItems", "/api/BasketItems/1", "/api/Complaints", "/api/Recycles",
    "/api/Cards", "/api/Wallets", "/api/Addresss", "/api/Feedbacks", "/api/SecurityAnswers",
    "/administration", "/admin", "/admin/users", "/api/admin", "/api/admin/users",
    "/settings", "/profile", "/account",
]

ADMIN_EPS = [
    "/administration", "/admin", "/admin/users", "/admin/dashboard",
    "/api/admin", "/api/admin/users", "/api/admin/dashboard",
    "/api/Users", "/api/users", "/api/Challenges", "/api/Complaints", "/api/Recycles",
    "/api/Deliverys", "/api/PrivacyRequests", "/api/SecurityAnswers",
    "/rest/admin/application-version", "/rest/admin/application-configuration",
]

LOGIN_EPS = [
    ("/api/Users/login",    "email",    "password", "json"),
    ("/api/users/login",    "email",    "password", "json"),
    ("/api/auth/login",     "email",    "password", "json"),
    ("/api/auth/login",     "username", "password", "json"),
    ("/api/login",          "email",    "password", "json"),
    ("/api/login",          "username", "password", "json"),
    ("/auth/login",         "email",    "password", "json"),
    ("/auth/login",         "username", "password", "json"),
    ("/login",              "email",    "password", "json"),
    ("/login",              "username", "password", "json"),
    ("/login.php",          "username", "password", "form"),
    ("/users/sign_in",      "email",    "password", "json"),
    ("/session",            "email",    "password", "json"),
    ("/api/session",        "email",    "password", "json"),
    ("/api/v1/users/login", "email",    "password", "json"),
    ("/api/token",          "username", "password", "json"),
]

REG_EPS = [
    ("/api/Users/",         "email",    "password", "json"),
    ("/api/Users",          "email",    "password", "json"),
    ("/api/users",          "email",    "password", "json"),
    ("/api/auth/register",  "email",    "password", "json"),
    ("/api/auth/signup",    "email",    "password", "json"),
    ("/api/register",       "email",    "password", "json"),
    ("/api/register",       "username", "password", "json"),
    ("/api/signup",         "email",    "password", "json"),
    ("/register",           "email",    "password", "json"),
    ("/signup",             "email",    "password", "json"),
    ("/users",              "email",    "password", "json"),
    ("/api/v1/users",       "email",    "password", "json"),
]

TOKEN_NESTED = [
    ["authentication", "token"], ["data", "token"], ["data", "accessToken"],
    ["auth", "token"], ["result", "token"], ["response", "token"], ["user", "token"],
]
TOKEN_FLAT = [
    "token", "access_token", "accessToken", "jwt", "id_token",
    "authToken", "auth_token", "sessionToken", "bearer",
]

SENS_KW = [
    "password", "passwordhash", "secret", "api_key", "apikey",
    "ssn", "credit_card", "creditcard", "isadmin", "is_admin",
    "accesstoken", "refreshtoken", "jwt", "hash", "salt",
    "passhash", "encryptedpassword", "private_key", "bearer",
]

TRAV_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "../../../../windows/win.ini",
]
TRAV_SIGNS = [
    "root:x:0:0", "[boot loader]", "/bin/bash",
    "daemon:", "www-data:", "[extensions]",
]

# ==========================================================
# UTILITIES
# ==========================================================

class Dummy:
    status_code = 0
    text = ""
    headers = {}
    cookies = {}
    def json(self): raise ValueError("Dummy response")

def make_session(pool_size=10, ua="Mozilla/5.0 (Hellhound-BAC/8.0)"):
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=pool_size, pool_maxsize=pool_size,
        max_retries=requests.adapters.Retry(total=1, backoff_factor=0.1, status_forcelist=[500, 502, 503]),
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": ua, "Accept": "application/json, text/html, */*"})
    return s

def normalize_url(u):
    u = u.strip().rstrip("/").rstrip("#").rstrip("/")
    if not u.startswith("http"): u = "http://" + u
    if "#" in u: u = u[:u.index("#")]
    return u.rstrip("/")

def is_json_ct(resp):
    return "application/json" in resp.headers.get("Content-Type", "").lower()

def is_spa(resp):
    if resp.status_code not in (200, 201): return False
    if is_json_ct(resp): return False
    snip = resp.text[:2000].lower()
    return any(m.lower() in snip for m in ["<!doctype html", "<html", "<app-root", "ng-version", "__next_data__"])

def real_api_response(resp):
    if resp.status_code not in (200, 201, 204): return False
    if is_spa(resp): return False
    if not is_json_ct(resp): return False
    return len(resp.text.strip()) > 2

def fast_similar(a, b, threshold=0.95):
    if not a or not b: return a == b
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio() >= threshold

def has_kw(text, kws):
    lo = text.lower()
    return [k for k in kws if k in lo]

def evid(resp, n=400):
    try:
        body = resp.text[:n].replace("\n", " ").strip()
        return f"HTTP {resp.status_code} | {resp.headers.get('Content-Type','?')} | {body}"
    except Exception:
        return f"HTTP {resp.status_code}"

def nested_get(d, path):
    for k in path:
        if not isinstance(d, dict): return None
        d = d.get(k)
    return d

# ==========================================================
# CORE CLASSES
# ==========================================================

class Findings:
    def __init__(self, emit):
        self._lock = threading.Lock()
        self._list = []
        self._seen = set()
        self.emit = emit

    def add(self, name, severity, endpoint, parameter, evidence_str, impact, recommendation, confidence="High"):
        key = f"{name}|{endpoint}|{parameter}"
        with self._lock:
            if key in self._seen: return
            self._seen.add(key)
            self._list.append({
                "vulnerability": name, "severity": severity, "confidence": confidence,
                "endpoint": endpoint, "parameter": parameter, "evidence": (evidence_str or "")[:500],
                "impact": impact, "recommendation": recommendation, "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            # Minimal noise for console
            if severity in ["Critical", "High"]:
                self.emit.warn(f"Found {severity}: {name} @ {endpoint}")

    def all(self):
        with self._lock: return list(self._list)

class AutoRegistrar:
    def __init__(self, base, http, emit):
        self.base = base
        self.http = http
        self.emit = emit

    def _extract_token(self, body):
        if not isinstance(body, dict): return None
        for path in TOKEN_NESTED:
            v = nested_get(body, path)
            if isinstance(v, str) and len(v) > 10: return v
        for k in TOKEN_FLAT:
            v = body.get(k)
            if isinstance(v, str) and len(v) > 10: return v
        return None

    def _try_register(self, sess, ep, uf, pf, method, email, password):
        payloads = [
            {uf: email, pf: password},
            {uf: email, pf: password, "passwordRepeat": password},
            {uf: email, pf: password, "password_confirmation": password},
            {uf: email, pf: password, "confirmPassword": password},
        ]
        for pl in payloads:
            r = self.http.post(sess, ep, json_data=pl if method == "json" else None, form_data=pl if method == "form" else None)
            if r.status_code in (200, 201):
                try: tok = self._extract_token(r.json())
                except: tok = None
                if tok: return "TOKEN", tok
                return "OK", None
            if r.status_code == 409: return "EXISTS", None
        return None, None

    def _try_login(self, sess, ep, uf, pf, method, email, password):
        extras = [{}, {"rememberMe": False}, {"Login": "Login"}]
        for extra in extras:
            pl = {uf: email, pf: password, **extra}
            if method == "form" and BS4:
                try:
                    pre = sess.get(self.base + ep, timeout=8)
                    soup = BeautifulSoup(pre.text, "html.parser")
                    for fname in ["user_token", "_token", "csrf_token", "authenticity_token"]:
                        inp = soup.find("input", {"name": fname})
                        if inp: pl[fname] = inp.get("value", "")
                except: pass
            r = self.http.post(sess, ep, json_data=pl if method == "json" else None, form_data=pl if method == "form" else None)
            if r.status_code in (200, 201):
                try:
                    tok = self._extract_token(r.json())
                    if tok: return tok
                except: pass
                if r.cookies or sess.cookies: return "COOKIE"
        return None

    def _setup_user(self, role, email, password):
        probe_sess = make_session(pool_size=5)
        token = None
        login_cfg = None

        # Parallel Register
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = {pool.submit(self._try_register, probe_sess, ep, uf, pf, m, email, password): (ep, uf, pf, m) for ep, uf, pf, m in REG_EPS}
            for f in as_completed(futs):
                status, tok = f.result()
                if status in ("OK", "EXISTS", "TOKEN"):
                    if tok: token = tok
                    break

        if not token:
            # Parallel Login
            with ThreadPoolExecutor(max_workers=5) as pool:
                futs = {pool.submit(self._try_login, probe_sess, ep, uf, pf, m, email, password): (ep, uf, pf, m) for ep, uf, pf, m in LOGIN_EPS}
                for f in as_completed(futs):
                    tok = f.result()
                    if tok:
                        token = tok
                        ep, uf, pf, m = futs[f]
                        login_cfg = {"endpoint": ep, "user_field": uf, "pass_field": pf, "method": m}
                        break

        engine_sess = make_session(pool_size=5)
        if token and token not in ("COOKIE", "OK"):
            engine_sess.headers.update({"Authorization": f"Bearer {token}"})
            self.emit.info(f"Auth: {role} OK (JWT)")
        elif token in ("COOKIE",):
            for cookie in probe_sess.cookies: engine_sess.cookies.set(cookie.name, cookie.value)
            self.emit.info(f"Auth: {role} OK (Cookie)")
        else:
            self.emit.warn(f"Auth: {role} Failed")
        
        return {"session": engine_sess, "token": token, "authed": bool(token), "login_cfg": login_cfg}

    def register_users(self):
        self.emit.info("Auto-Registering Users...")
        emailA, passA = f"hh_a{random.randint(100,999)}@test.local", f"Pass{random.randint(10,99)}!"
        emailB, passB = f"hh_b{random.randint(100,999)}@test.local", f"Pass{random.randint(10,99)}!"
        
        with ThreadPoolExecutor(max_workers=2) as pool:
            fa = pool.submit(self._setup_user, "userA", emailA, passA)
            fb = pool.submit(self._setup_user, "userB", emailB, passB)
            userA = fa.result()
            userB = fb.result()

        guest = {"session": make_session(pool_size=5), "token": None, "authed": False}
        return {"userA": userA, "userB": userB, "guest": guest}

class Discovery:
    def __init__(self, http, sess, emit, external_endpoints_file=None):
        self.http = http
        self.sess = sess
        self.emit = emit
        self.found = set(COMMON_PATHS)
        self._lock = threading.Lock()

        if external_endpoints_file:
            try:
                with open(external_endpoints_file, "r") as f: data = json.load(f)
                spider_intel = data.get("spider", {}).get("intel", data)
                raw_endpoints = spider_intel.get("js_endpoints", [])
                blacklist_extensions = [".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".woff", ".woff2", ".ttf", ".ico", ".map"]
                for ep in raw_endpoints:
                    if any(ep.lower().endswith(ext) for ext in blacklist_extensions): continue
                    if "/assets/" in ep or "/static/" in ep: continue
                    if not ep.startswith("/"): ep = "/" + ep
                    self.found.add(ep)
                self.emit.info(f"Spider: Loaded {len(raw_endpoints)} routes")
            except Exception as e: self.emit.warn(f"Spider load failed: {e}")

    def _probe_one(self, path):
        r = self.http.get(self.sess, path)
        if r.status_code not in (404, 0, 400):
            with self._lock: self.found.add(path)

    def probe(self, workers=30):
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(self._probe_one, COMMON_PATHS))

    def crawl(self):
        if not BS4: return
        try:
            r = self.sess.get(self.http.base + "/", timeout=8)
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all(["a", "form", "script"]):
                href = (tag.get("href") or tag.get("action") or tag.get("src") or "")
                p = urllib.parse.urlparse(href)
                if p.scheme and p.netloc: continue
                rel = p.path
                if rel and len(rel) > 1 and not rel.startswith("#"):
                    with self._lock: self.found.add(rel)
        except: pass

    def endpoints(self):
        with self._lock: return sorted(self.found)

class HTTP:
    def __init__(self, base, timeout=10):
        self.base = base
        self.timeout = timeout
    def _url(self, path): return path if path.startswith("http") else self.base + path
    def get(self, sess, path, headers=None):
        try: return sess.get(self._url(path), timeout=self.timeout, allow_redirects=False, headers=headers or {})
        except: return Dummy()
    def post(self, sess, path, json_data=None, form_data=None, hdrs=None):
        try:
            if form_data: return sess.post(self._url(path), data=form_data, timeout=self.timeout, allow_redirects=True, headers=hdrs or {})
            return sess.post(self._url(path), json=json_data, timeout=self.timeout, allow_redirects=True, headers=hdrs or {})
        except: return Dummy()
    def method(self, m, sess, path, **kw):
        try: return sess.request(m, self._url(path), timeout=self.timeout, allow_redirects=False, **kw)
        except: return Dummy()

# ==========================================================
# BASE ENGINE
# ==========================================================

class BaseEngine:
    NAME = "Base"
    WORKERS = 20
    def __init__(self, http, users, findings, workers=20):
        self.http = http; self.users = users; self.F = findings; self.workers = workers
        self._sa = self._fresh_session("userA")
        self._sb = self._fresh_session("userB")
        self._sg = self._fresh_session("guest")

    def _fresh_session(self, role):
        src = self.users.get(role, {}).get("session")
        s = make_session(pool_size=self.workers + 5)
        if src:
            for k, v in src.headers.items():
                if k.lower() in ("authorization", "cookie", "x-auth-token"): s.headers[k] = v
            for cookie in src.cookies: s.cookies.set(cookie.name, cookie.value)
        return s

    def _run_parallel(self, tasks, label=None):
        if not tasks: return
        def wrapped(item):
            fn, args = item[0], item[1:]
            try: fn(*args)
            except: pass
        with ThreadPoolExecutor(max_workers=min(self.workers, len(tasks), 50)) as pool:
            list(pool.map(wrapped, tasks))

# ==========================================================
# ENGINE 1 — IDOR
# ==========================================================
class IDOREngine(BaseEngine):
    NAME = "IDOR"
    def run(self, endpoints):
        self.F.emit.info("Engine 1/10: IDOR scanning...")
        tasks = []
        seen_pairs = set()
        for ep in endpoints:
            parts = ep.split("?")[0].split("/")
            for i, seg in enumerate(parts):
                if not seg.isdigit(): continue
                n = int(seg)
                for alt in [n + 1, n - 1]:
                    if alt < 1: continue
                    own = "/".join(parts[:i] + [str(n)] + parts[i+1:])
                    alt_ep = "/".join(parts[:i] + [str(alt)] + parts[i+1:])
                    pair = tuple(sorted([own, alt_ep]))
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        tasks.append((self._check, own, alt_ep, f"path:{n}→{alt}"))
                break
            parsed = urllib.parse.urlparse(ep)
            for param, vals in urllib.parse.parse_qs(parsed.query).items():
                if vals and vals[0].isdigit():
                    v = int(vals[0])
                    own = f"{parsed.path}?{param}={v}"
                    alt_ep = f"{parsed.path}?{param}={v+1}"
                    tasks.append((self._check, own, alt_ep, f"query:{param}={v}→{v+1}"))
        self._run_parallel(tasks)

    def _check(self, ep_own, ep_alt, label):
        r_own = self.http.get(self._sa, ep_own)
        r_alt = self.http.get(self._sa, ep_alt)
        if not real_api_response(r_own): return
        if not real_api_response(r_alt): return
        if fast_similar(r_own.text, r_alt.text, 0.98): return
        sensitive = has_kw(r_alt.text, SENS_KW)
        r_cross = self.http.get(self._sb, ep_own)
        r_guest = self.http.get(self._sg, ep_own)
        cross = real_api_response(r_cross)
        guest = real_api_response(r_guest)
        self.F.add("IDOR — Unauthorized Object Access", "Critical", ep_alt, label, evid(r_alt),
            f"User can access another user's data at {ep_alt}. " + (f"Sensitive fields: {sensitive}. " if sensitive else "") + ("Cross-session confirmed. " if cross else "") + ("Guest access confirmed." if guest else ""),
            "Validate object ownership server-side.", "High" if (cross or guest) else "Medium")

# ==========================================================
# ENGINE 2 — MISSING AUTH
# ==========================================================
class MissingAuthEngine(BaseEngine):
    NAME = "MissingAuth"
    def run(self, endpoints):
        self.F.emit.info("Engine 2/10: Missing Auth scanning...")
        targets = list(set(PROTECTED_EPS + [ep for ep in endpoints if any(ep.startswith(p) for p in PROTECTED_EPS)]))
        tasks = [(self._check, ep) for ep in targets]
        self._run_parallel(tasks)

    def _check(self, ep):
        rg = self.http.get(self._sg, ep)
        if not real_api_response(rg): return
        sens = has_kw(rg.text, SENS_KW)
        if not sens and not is_json_ct(rg): return
        ra = self.http.get(self._sa, ep)
        if fast_similar(rg.text, ra.text, 0.97) and ra.status_code == rg.status_code: return
        self.F.add("Missing Authentication — Protected API Exposed", "Critical", ep, "No credentials", evid(rg),
            "Unauthenticated access to protected endpoint. " + (f"Sensitive fields: {sens}. " if sens else ""), "Require authentication.", "High")

# ==========================================================
# ENGINE 3 — RBAC
# ==========================================================
class RBACEngine(BaseEngine):
    NAME = "RBAC"
    def run(self, endpoints):
        self.F.emit.info("Engine 3/10: RBAC scanning...")
        targets = list(set(ADMIN_EPS + [ep for ep in endpoints if any(a in ep for a in ["/admin", "/manage", "/dashboard", "/api/Users", "/api/Challenges"])]))
        tasks = [(self._check, ep) for ep in targets]
        self._run_parallel(tasks)

    def _check(self, ep):
        ru = self.http.get(self._sa, ep)
        if not real_api_response(ru): return
        sens = has_kw(ru.text, SENS_KW)
        self.F.add("RBAC Flaw — Admin Accessible by User", "High", ep, "Regular User", evid(ru),
            "Regular user can access admin endpoint. " + (f"Sensitive data: {sens}. " if sens else ""), "Enforce server-side role checks.", "High" if sens else "Medium")

# ==========================================================
# ENGINE 4 — EXCESSIVE PRIVILEGES
# ==========================================================
class ExcessivePrivEngine(BaseEngine):
    NAME = "ExcessivePriv"
    METHODS = ["PUT", "DELETE", "PATCH"]
    def run(self, endpoints):
        self.F.emit.info("Engine 4/10: Excessive Privileges scanning...")
        api_endpoints = []
        def check_api(ep):
            if real_api_response(self.http.get(self._sa, ep)): api_endpoints.append(ep)
        with ThreadPoolExecutor(max_workers=self.workers) as pool: pool.map(check_api, endpoints)
        tasks = [(self._check, ep, m) for ep in api_endpoints for m in self.METHODS]
        self._run_parallel(tasks)

    def _check(self, ep, method):
        base_r = self.http.get(self._sa, ep)
        if not real_api_response(base_r): return
        resp = self.http.method(method, self._sa, ep, json={"_scanner_test": 1}, headers={"Content-Type": "application/json"})
        if resp.status_code not in (200, 201, 204): return
        if not is_json_ct(resp): return
        if fast_similar(base_r.text, resp.text, 0.95): return
        body_lo = resp.text.lower()
        if any(w in body_lo for w in ["error", "invalid", "unauthorized", "forbidden", "not allowed"]): return
        self.F.add(f"Excessive Privilege — {method} Allowed", "High", ep, f"HTTP {method}", evid(resp), "User allowed unsafe method.", "Enforce method-level ACL.", "High")

# ==========================================================
# ENGINE 5 — PATH TRAVERSAL
# ==========================================================
class PathTraversalEngine(BaseEngine):
    NAME = "PathTraversal"
    FILE_PARAMS = {"file", "filename", "path", "page", "include", "doc", "document", "dir", "folder", "load", "read", "view", "f"}
    FTP_TARGETS = ["/ftp/package.json.bak", "/ftp/coupons_2013.md.bak", "/ftp/eastere.gg", "/ftp/suspicious_errors.yml"]
    def run(self, endpoints):
        self.F.emit.info("Engine 5/10: Path Traversal scanning...")
        tasks = []
        for ep in endpoints:
            parsed = urllib.parse.urlparse(ep)
            qs = urllib.parse.parse_qs(parsed.query)
            for param in qs:
                if param.lower() in self.FILE_PARAMS:
                    for payload in TRAV_PAYLOADS:
                        test = f"{parsed.path}?{param}=" + urllib.parse.quote(payload, safe="./")
                        tasks.append((self._check_param, test, param, payload))
        for fp in self.FTP_TARGETS: tasks.append((self._check_ftp, fp))
        self._run_parallel(tasks)

    def _check_param(self, test_ep, param, payload):
        r = self.http.get(self._sa, test_ep)
        if r.status_code not in (200, 201): return
        if is_spa(r): return
        for sign in TRAV_SIGNS:
            if sign.lower() in r.text.lower():
                self.F.add("Path Traversal — Local File Read", "Critical", test_ep, f"{param}={payload}", evid(r), "Arbitrary file read.", "Sanitize path inputs.", "High")

    def _check_ftp(self, ftp_path):
        r = self.http.get(self._sa, ftp_path)
        if r.status_code == 403:
            rb = self.http.get(self._sa, ftp_path + "%2500.md")
            if rb.status_code == 200 and not is_spa(rb) and len(rb.text) > 10:
                self.F.add("Path Traversal — FTP Null-Byte Bypass", "Critical", ftp_path, "Null-byte", evid(rb), "Bypassed extension filter.", "Reject null bytes.", "High")
        elif r.status_code == 200 and not is_spa(r) and len(r.text) > 10:
            if r.text[:50].strip().startswith(("{", "---")) or r.text[:3] == "\xef\xbb\xbf":
                self.F.add("Sensitive File Accessible — FTP", "High", ftp_path, "Direct Access", evid(r), "Backup file exposed.", "Restrict FTP dir.", "High")

# ==========================================================
# ENGINE 6 — RATE LIMITING
# ==========================================================
class RateLimitEngine(BaseEngine):
    NAME = "RateLimit"
    BYPASS_HDRS = [{"X-Forwarded-For": "1.1.1.1"}, {"X-Real-IP": "1.1.1.1"}, {"CF-Connecting-IP": "1.1.1.1"}]
    def _pick_ep(self, endpoints):
        for pref in ["/api/Users/login", "/api/users/login", "/login", "/api/search"]:
            for ep in endpoints: 
                if pref in ep: return ep
        for ep in endpoints:
            if real_api_response(self.http.get(self._sg, ep)): return ep
        return endpoints[0] if endpoints else "/"

    def run(self, endpoints):
        self.F.emit.info("Engine 6/10: Rate Limit scanning...")
        ep = self._pick_ep(endpoints)
        url = self.http.base + ep
        burst_sess = make_session(pool_size=40)
        codes = []
        lock = threading.Lock()
        def do_req(_):
            try:
                r = burst_sess.get(url, timeout=self.http.timeout, allow_redirects=False)
                with lock: codes.append(r.status_code)
            except: 
                with lock: codes.append(0)
        
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=40) as pool: pool.map(do_req, range(40))
        elapsed = time.time() - t0
        n429 = codes.count(429); n200 = codes.count(200)
        
        if n429 == 0 and n200 >= 20:
            self.F.add("Missing Rate Limiting", "Medium", ep, "Burst Request", f"{40} reqs in {elapsed:.1f}s", "No throttling detected.", "Implement rate limiting.", "High")
            return

        if n429 > 0:
            for hdr in self.BYPASS_HDRS:
                bs = make_session(20); bs.headers.update(hdr)
                hits = sum(1 for _ in range(15) if bs.get(url, timeout=5).status_code == 200)
                if hits >= 10:
                    hn = list(hdr.keys())[0]
                    self.F.add("Rate Limit Bypass — Spoofed IP", "High", ep, hn, f"{hits}/15 succeeded", "Bypassed via header.", "Rate-limit by ID.", "High")

# ==========================================================
# ENGINE 7 — REFERRER BYPASS
# ==========================================================
class ReferrerEngine(BaseEngine):
    NAME = "ReferrerBypass"
    REFS = ["http://localhost/admin", "http://127.0.0.1/admin", "http://trusted.internal/"]
    def run(self, endpoints):
        self.F.emit.info("Engine 7/10: Referrer Bypass scanning...")
        targets = [ep for ep in endpoints if any(ep.startswith(p) for p in PROTECTED_EPS)]
        if not targets: targets = endpoints[:20]
        tasks = [(self._check, ep, ref) for ep in targets for ref in self.REFS]
        self._run_parallel(tasks)

    def _check(self, ep, ref):
        r = self.http.get(self._sg, ep, headers={"Referer": ref})
        if is_spa(r): return
        if r.status_code not in (200, 201, 204): return
        if not real_api_response(r): return
        self.F.add("Referrer Header Auth Bypass", "High", ep, f"Referer: {ref}", evid(r), "Bypassed auth via header.", "Validate session tokens.", "High")

# ==========================================================
# ENGINE 8 — HOST HEADER INJECTION
# ==========================================================
class HostHeaderEngine(BaseEngine):
    NAME = "HostHeader"
    HOSTS = ["evil.com", "attacker.com", "localhost", "127.0.0.1", "169.254.169.254"]
    def run(self, endpoints):
        self.F.emit.info("Engine 8/10: Host Header scanning...")
        targets = endpoints[:8]
        tasks = [(self._check, ep, hv) for ep in targets for hv in self.HOSTS]
        self._run_parallel(tasks)

    def _check(self, ep, hv):
        r = self.http.get(self._sg, ep, headers={"Host": hv})
        if is_spa(r): return
        if hv in r.text:
            self.F.add("Host Header Injection — Reflected", "Medium", ep, f"Host: {hv}", evid(r), "Host value reflected.", "Whitelist Host headers.", "High")
        elif r.status_code in (200, 201) and is_json_ct(r):
            self.F.add("Host Header — Arbitrary Accepted", "Low", ep, f"Host: {hv}", evid(r), "Arbitrary host accepted.", "Validate Host header.", "Medium")

# ==========================================================
# ENGINE 9 — SECURITY MISCONFIGURATION
# ==========================================================
class MisconfigEngine(BaseEngine):
    NAME = "Misconfig"
    INDICATORS = {
        "/.env": ["DB_", "SECRET_KEY", "PASSWORD=", "API_KEY"], "/.git/config": ["[core]", "[remote"],
        "/config.json": ["password", "secret", "database"], "/phpinfo.php": ["PHP Version", "phpinfo()"],
        "/actuator/env": ["activeProfiles", "propertySources"], "/swagger.json": ['"swagger"', '"openapi"'],
        "/metrics": ["jvm_", "# HELP"], "/ftp/": ["Index of /ftp", "Parent Directory"],
    }
    MISCONFIG_PATHS = list(set(list(INDICATORS.keys()) + ["/.htaccess", "/server-info", "/.well-known/security.txt", "/trace"]))

    def run(self, endpoints):
        self.F.emit.info("Engine 9/10: Misconfiguration scanning...")
        all_paths = list(set(self.MISCONFIG_PATHS + [ep for ep in endpoints if any(x in ep for x in [".env", ".git", "phpinfo", "actuator", "swagger", "ftp", "package.json"])]))
        tasks = [(self._check, path) for path in all_paths]
        self._run_parallel(tasks)

    def _check(self, path):
        for sess, sess_name in [(self._sg, "guest"), (self._sa, "user")]:
            r = self.http.get(sess, path)
            if r.status_code not in (200, 201): continue
            if is_spa(r): continue
            indicators = self.INDICATORS.get(path, [])
            matched = [i for i in indicators if i.lower() in r.text.lower()]
            generic = has_kw(r.text, SENS_KW)
            if not matched and not generic: continue
            sev = "Critical" if any(x in path for x in [".env", "phpinfo", "actuator"]) else "High"
            self.F.add(f"Security Misconfiguration — {path}", sev, path, f"Accessible as: {sess_name}", evid(r), f"Sensitive path exposed. Matched: {matched[:3]}", "Restrict path.", "High" if matched else "Medium")
            break

# ==========================================================
# ENGINE 10 — SENSITIVE DATA EXPOSURE
# ==========================================================
class SensitiveDataEngine(BaseEngine):
    NAME = "SensitiveData"
    HIGH_RISK = ["password", "passwordhash", "secret", "api_key", "ssn", "credit_card", "private_key"]
    MED_RISK = ["isadmin", "is_admin", "role", "permissions", "accesstoken", "jwt", "salt"]
    def run(self, endpoints):
        self.F.emit.info("Engine 10/10: Sensitive Data Exposure scanning...")
        tasks = [(self._check, ep) for ep in endpoints]
        self._run_parallel(tasks)

    def _check(self, ep):
        r = self.http.get(self._sa, ep)
        if not real_api_response(r): return
        lo = r.text.lower()
        high = [f for f in self.HIGH_RISK if f in lo]
        med = [f for f in self.MED_RISK if f in lo]
        if high:
            self.F.add("Sensitive Data Exposure — Critical Fields", "Critical", ep, f"Exposed: {high}", evid(r), "API returns sensitive fields.", "Whitelist safe fields.", "High")
        elif med:
            self.F.add("Sensitive Data Exposure — Privilege Fields", "High", ep, f"Exposed: {med}", evid(r), "API exposes roles/tokens.", "Exclude priv fields.", "Medium")

# ==========================================================
# MODULE ENTRY POINT
# ==========================================================

def run(target, emit, options=None, stop_check=None, pause_check=None):
    options = options or {}
    
    target = normalize_url(target)
    emit.info(f"BACDetector: Starting full suite against {target}")
    
    http = HTTP(base=target, timeout=10)
    findings_store = Findings(emit)
    
    # 1. Auth
    registrar = AutoRegistrar(target, http, emit)
    users = registrar.register_users()
    
    # 2. Discovery
    spider_file = options.get("spider_file")
    spider_intel = options.get("spider_intel")
    
    # Load spider file if intel not provided directly
    if spider_file and not spider_intel:
        try:
            with open(spider_file, 'r') as f:
                j = json.load(f)
                spider_intel = j.get("spider", {}).get("intel", j)
        except: pass

    disc_sess = make_session(10)
    if users["userA"].get("session"):
        for k,v in users["userA"]["session"].headers.items():
            if k.lower() == "authorization": disc_sess.headers[k] = v
            
    discovery = Discovery(http, disc_sess, emit, external_endpoints_file=None)
    if spider_intel:
        raw_eps = spider_intel.get("js_endpoints", [])
        for ep in raw_eps:
            if ep.startswith("http"):
                ep = urllib.parse.urlparse(ep).path
            if not ep.startswith("/"):
                ep = "/" + ep
            discovery.found.add(ep)
        
    discovery.probe(workers=20)
    endpoints = discovery.endpoints()
    emit.info(f"Discovery: {len(endpoints)} live endpoints found")

    # 3. Run Engines
    all_engines = [
        IDOREngine, MissingAuthEngine, RBACEngine, ExcessivePrivEngine,
        PathTraversalEngine, ReferrerEngine, HostHeaderEngine,
        MisconfigEngine, SensitiveDataEngine, RateLimitEngine
    ]
    
    # Skip RateLimit if explicitly requested (optional flag)
    if options.get("skip_ratelimit"):
        all_engines = [e for e in all_engines if e != RateLimitEngine]

    engine_args = (http, users, findings_store, 10) # 10 workers per engine

    for cls in all_engines:
        if stop_check and stop_check(): break
        try:
            cls(*engine_args).run(endpoints)
        except Exception as e:
            emit.warn(f"Engine {cls.NAME} error: {e}")

    findings = findings_store.all()
    
    # Risk Calc
    risk = 0
    for f in findings:
        risk += SEVERITY_WEIGHTS.get(f["severity"], 0)
        
    emit.success(f"BACDetector Complete. {len(findings)} findings. Risk: {risk}")
    
    return {
        "raw": f"{len(findings)} BAC findings identified",
        "intel": {
            "bac": {
                "findings": findings,
                "summary": {k: len([x for x in findings if x["severity"]==k]) for k in SEVERITY_WEIGHTS},
                "risk_score": risk
            }
        }
    }