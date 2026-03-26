#!/usr/bin/env python3
"""
hellhound/modules/vuln/IDORdetector.py

HELLHOUND — IDOR Detector  v1.3
Dual-session Insecure Direct Object Reference scanner.
Pipeline: auth → endpoint feed → surface analysis → ID harvest → dual-session test → report

Framework module — do not run directly.

v1.3 merge additions (from standalone Agent30 v1.3):
  - Full 8-signal ResponseAnalyser (value-level leak, HTML token diff, unauth probe)
  - IDHarvestPass._derive_get_child_urls (REST child URL derivation)
  - IDHarvestPass POST creation harvest + child URL tracking
  - Full Crawler class with BFS queue+pool, JS extraction, id_hints mining
  - JSExtractor — axios/fetch/XHR/router pattern extraction
  - PageParser — full HTML form/link/option parser with ID harvesting
  - SpiderBridge.load() — full Agent2/v12 bucketed param schema, QS harvest,
    synthetic IDOR hints for auth_required endpoints, smart singularization
  - SpiderBridge.export() — crawler → spider JSON export
  - IDORSurfaceAnalyser._PAGINATION_PARAMS blocklist (no false positives on page/limit)
  - IDORSurfaceAnalyser slug support, priority_params upgrade path
  - IDORTester._test_child_urls, _unauth_one, _all_param_variants
  - IDORTester numeric_value confidence penalty (fix #7)
  - IDORTester cluster-dedup for child URL findings
  - FieldClassifier full 50-category form filler
  - AutoRegistrar constraint-aware password generation
  - SessionBuilder username-aware own-ID extraction (all strategies A–D)
  - AuthEngine multi-attempt login (username/email × form/JSON)
  - _spider_intel_to_endpoints updated to use enriched SpiderBridge parsing
  - export_json with severity mapping
  - sys.exit() calls replaced with RuntimeError/return for framework compat
"""

import json
import queue
import random
import re
import string
import sys
import time
import threading
import urllib.parse
import urllib.request
import urllib.error
import ssl
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser

# ══════════════════════════════════════════════════════════════════════
# METADATA
# ══════════════════════════════════════════════════════════════════════

NAME        = "IDORdetector"
CATEGORY    = "vuln"
VERSION     = "1.3"
DESCRIPTION = "Dual-session IDOR detector — path segments, query params, body keys, unauth bypass"

# ══════════════════════════════════════════════════════════════════════
# OPTIONS
# ══════════════════════════════════════════════════════════════════════

OPTIONS = [
    {"name": "cookie_a",      "type": str,   "default": None,  "required": False,
     "help": "Session token for User A (cookie or Authorization header value)"},
    {"name": "cookie_b",      "type": str,   "default": None,  "required": False,
     "help": "Session token for User B (enables full dual-session IDOR)"},
    {"name": "header_a",      "type": str,   "default": None,  "required": False,
     "help": "Extra header for User A e.g. 'Authorization: Bearer TOKEN'"},
    {"name": "header_b",      "type": str,   "default": None,  "required": False,
     "help": "Extra header for User B"},
    {"name": "login_user_a",  "type": str,   "default": None,  "required": False,
     "help": "User A email/username for auto-login"},
    {"name": "login_pass_a",  "type": str,   "default": None,  "required": False,
     "help": "User A password for auto-login"},
    {"name": "login_user_b",  "type": str,   "default": None,  "required": False,
     "help": "User B email/username for auto-login"},
    {"name": "login_pass_b",  "type": str,   "default": None,  "required": False,
     "help": "User B password for auto-login"},
    {"name": "login_url_a",   "type": str,   "default": None,  "required": False,
     "help": "Explicit login URL override (User A)"},
    {"name": "auto_register", "type": bool,  "default": False, "required": False,
     "help": "Auto-create two test accounts if registration is open"},
    {"name": "invite_code",   "type": str,   "default": None,  "required": False,
     "help": "Invite/registration code required by the app's register form"},
    {"name": "timeout",       "type": int,   "default": 10,    "required": False,
     "help": "HTTP timeout per request (seconds)"},
    {"name": "threads",       "type": int,   "default": 8,     "required": False,
     "help": "Concurrent test threads"},
    {"name": "delay",         "type": float, "default": 0.0,   "required": False,
     "help": "Seconds to wait between requests"},
    {"name": "write_probe",   "type": bool,  "default": False, "required": False,
     "help": "Include POST/PUT write-probe tests (default: GET only)"},
    {"name": "no_unauth",     "type": bool,  "default": False, "required": False,
     "help": "Skip unauthenticated bypass checks"},
    {"name": "depth",         "type": int,   "default": 3,     "required": False,
     "help": "Crawler depth when no spider intel (default: 3)"},
    {"name": "max_pages",     "type": int,   "default": 200,   "required": False,
     "help": "Max pages for built-in crawler"},
    {"name": "verbose",       "type": bool,  "default": False, "required": False,
     "help": "Show per-request detail"},
]

# ══════════════════════════════════════════════════════════════════════
# GLOBALS
# ══════════════════════════════════════════════════════════════════════

VERBOSE = False

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE

# ══════════════════════════════════════════════════════════════════════
# TERMINAL HELPERS
# ══════════════════════════════════════════════════════════════════════

class C:
    RESET   = "\033[0m";  BOLD    = "\033[1m"; DIM     = "\033[2m"
    RED     = "\033[31m"; GREEN   = "\033[32m"; YELLOW  = "\033[33m"
    CYAN    = "\033[36m"; WHITE   = "\033[37m"
    BRED    = "\033[91m"; BGREEN  = "\033[92m"; BYELLOW = "\033[93m"
    BCYAN   = "\033[96m"; BWHITE  = "\033[97m"

def color(text, *codes):
    return "".join(codes) + str(text) + C.RESET

_tprint_lock = threading.Lock()
def tprint(*args, **kwargs):
    with _tprint_lock:
        print(*args, **kwargs)

def vprint(*a, **kw):
    if VERBOSE:
        tprint(*a, **kw)

def ok(msg):    return color(f"[+] {msg}", C.BGREEN, C.BOLD)
def warn(msg):  return color(f"[!] {msg}", C.BYELLOW, C.BOLD)
def info(msg):  return color(f"[*] {msg}", C.BCYAN)
def err(msg):   return color(f"[-] {msg}", C.BRED, C.BOLD)
def found(msg): return color(f"[IDOR] {msg}", C.BRED, C.BOLD)
def skp(msg):   return color(f"[SKIP] {msg}", C.DIM)

def section(title):
    bar = color("─" * 72, C.DIM + C.CYAN)
    tprint(f"\n{bar}")
    tprint(f"  {color('  ' + title + '  ', C.BOLD + C.BCYAN)}")
    tprint(f"{bar}")

# ══════════════════════════════════════════════════════════════════════
# SHARED REGEX CONSTANTS
# ══════════════════════════════════════════════════════════════════════

# Numeric path segment — excludes version strings like /v1, /v2
_PATH_NUMERIC_RE = re.compile(r'(?<![vV])(?<!/version)/(\d{1,12})(?=/|$)')

# UUID segment in path
_PATH_UUID_RE = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
    re.I
)

# Alphanumeric slug in path ≥8 chars
_PATH_SLUG_RE = re.compile(r'/([a-zA-Z0-9]{8,48})(?=/|$)')

# Pure numeric value
_NUMERIC_RE = re.compile(r'^\d{1,12}$')

# UUID value
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.I
)

# Slug value — alphanumeric+hyphens/underscores, must have both alpha and digit
_SLUG_RE = re.compile(r'^[a-zA-Z0-9_\-]{8,64}$')

def _is_slug(val):
    return (bool(_SLUG_RE.match(val))
            and bool(re.search(r'\d', val))
            and bool(re.search(r'[a-zA-Z]', val)))

# IDOR-signal parameter names
_IDOR_PARAM_NAME_RE = re.compile(
    r'^(?:'
    r'id|uid|user_?id|userid|user|account_?id|accountid|account'
    r'|profile_?id|profileid|profile'
    r'|doc(?:ument)?_?id|docid'
    r'|order_?id|orderid'
    r'|invoice_?id|invoiceid'
    r'|resource_?id|resourceid'
    r'|record_?id|recordid'
    r'|item_?id|itemid'
    r'|obj(?:ect)?_?id|objectid|oid'
    r'|uuid|guid'
    r'|ref|slug|handle'
    r'|to|from|with|recipient|sender|peer|contact|member|target'
    r'|receiver|receiver_?id|receiverid|sender_?id|senderid'
    r'|author|author_?id|authorid|owner|owner_?id|ownerid'
    r'|patient|patient_?id|patientid'
    r'|ticket|ticket_?id|ticketid'
    r'|thread|thread_?id|threadid|post_?id|postid|message_?id|messageid'
    r'|listing_?id|listingid|product_?id|productid|catalog_?id'
    r'|customer_?id|customerid|client_?id|clientid'
    r'|employee_?id|employeeid|staff_?id|staffid'
    r'|token|key|secret|hash'
    r')$',
    re.I
)

# Sensitive JSON response keys — indicate user-specific data
_SENSITIVE_KEYS_RE = re.compile(
    r'"(?:email|phone|mobile|address|dob|birth_?date|ssn|national_id|passport'
    r'|credit_card|card_number|bank|iban|salary|tax|medical|diagnosis'
    r'|password|secret|api_key|private_key|personal|permission'
    r'|username|full_?name|first_?name|last_?name|avatar|photo_url'
    r'|balance|subscription|plan|invoice|billing|payment'
    r'|secret_token|auth_token|access_token|session_token|token'
    r'|btc_address|xmr_address|eth_address|crypto|wallet'
    r'|pgp_key|pgp|encryption_key|private'
    r'|role|permission|admin|moderator|privilege|scope'
    r'|two_?fa|2fa|totp|mfa|recovery'
    r'|show_online|online_status|last_seen|location|geo'
    r'|prefs|preferences|settings|config|theme'
    r'|reputation|score|rank|level|points'
    r'|purchase|transaction|order|cart|checkout'
    r')"\s*:',
    re.I
)

# Static file extensions — skip in crawler
_STATIC_EXT_RE = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip|gz|tar|bz2|mp4|mp3|webm)$',
    re.I
)

# Auth param names — skip during injection
_AUTH_RE = re.compile(r'(?:password|passwd|pass|token|csrf|secret|auth|captcha|otp|pin)', re.I)

# SpiderBridge param bucket ordering
_BUCKET_ORDER     = ["runtime", "query", "openapi", "js", "form"]
_PRIORITY_BUCKETS = {"runtime", "query"}

# Strip sanitization suffixes
_STRIP_SFX_RE = re.compile(
    r'^(.+?)(?:_raw|_sanitized|_input|_clean|_safe|_encoded|_value)$', re.I)

def _strip_sfx(name):
    m = _STRIP_SFX_RE.match(str(name).strip())
    return m.group(1) if m else str(name).strip()

# ══════════════════════════════════════════════════════════════════════
# AUTH PATTERNS
# ══════════════════════════════════════════════════════════════════════

_LOGIN_URL_PATTERNS = re.compile(
    r'(?:^|/)(?:login|signin|sign-in|log-in|auth|authenticate'
    r'|session|account/login|user/login|users/login'
    r'|api/login|api/auth|api/signin|api/token|api/session'
    r'|oauth/token|v\d+/auth|v\d+/login)(?:/|$|\?)',
    re.I
)

_REGISTER_URL_PATTERNS = re.compile(
    r'(?:^|/)(?:register|signup|sign-up|create.?account|join'
    r'|account/register|user/register|users/register|new.?user'
    r'|api/register|api/signup|api/users|api/accounts|api/members'
    r'|api/auth/register|api/auth/signup|api/v\d+/users|api/v\d+/register'
    r'|v\d+/register|v\d+/signup|v\d+/users)(?:/|$|\?)',
    re.I
)

_LOGIN_LINK_TEXT    = re.compile(r'\b(?:log\s*in|sign\s*in|login|signin|authenticate|account\s*access)\b', re.I)
_REGISTER_LINK_TEXT = re.compile(r'\b(?:register|sign\s*up|signup|create\s*account|join|get\s*started)\b', re.I)
_POST_LOGIN_DESTINATIONS = re.compile(r'dashboard|home|profile|account|welcome|main|app|portal|overview', re.I)
_SUCCESS_BODY_SIGNALS    = re.compile(
    r'"(?:token|access_token|accessToken|jwt|user|account|profile|dashboard|'
    r'sessionId|session_id|auth_token|authToken|logged_in|loggedIn|'
    r'authenticated|success)"\s*:\s*(?:"[^"]{4,}"|true|\d+)', re.I
)

_USERNAME_FIELD_VARIANTS = [
    "username", "email", "user", "login", "email_address",
    "user_email", "identifier", "handle", "phone", "mobile",
    "user_name", "userName", "userEmail", "loginEmail",
    "account", "userId", "user_id",
]

_PASSWORD_FIELD_VARIANTS = [
    "password", "passwd", "pass", "secret", "pwd",
    "user_password", "userPassword", "account_password",
    "login_password", "pass_word",
]

_ME_ENDPOINTS = [
    "/api/me", "/api/user/me", "/api/users/me",
    "/api/current_user", "/api/currentuser", "/api/whoami",
    "/api/v1/me", "/api/v1/user/me", "/api/v1/users/me",
    "/api/v2/me", "/api/v2/user/me",
    "/user/me", "/users/me", "/me",
    "/api/account", "/api/profile", "/api/user/profile",
    "/api/auth/me", "/api/session/user",
    "/user", "/account", "/profile",
]

# ══════════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ══════════════════════════════════════════════════════════════════════

class HTTPClient:
    _login_redirect_re = re.compile(r'login|signin|auth|session|unauthorized', re.I)

    def __init__(self, timeout=12, cookie=None, extra_header=None,
                 login_url=None, login_user=None, login_pass=None,
                 login_user_field="username", login_pass_field="password",
                 user_agent=None):
        self.timeout           = timeout
        self._login_url        = login_url
        self._login_user       = login_user
        self._login_pass       = login_pass
        self._login_user_field = login_user_field
        self._login_pass_field = login_pass_field
        ua = user_agent or "Mozilla/5.0 (compatible; HELLHOUND-IDOR/1.3)"
        self.headers = {
            "User-Agent":      ua,
            "Accept":          "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection":      "close",
        }
        if cookie:
            cookie = cookie.strip()
            if cookie.lower().startswith("cookie:"):
                cookie = cookie[len("cookie:"):].strip()
            if re.match(r"(?:Bearer|Basic|Token)\s+\S", cookie, re.I):
                self.headers["Authorization"] = cookie
            elif re.match(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", cookie):
                self.headers["Authorization"] = f"Bearer {cookie}"
            else:
                self.headers["Cookie"] = cookie
        if extra_header:
            sep = ":" if ":" in extra_header else "="
            k, v = extra_header.split(sep, 1)
            self.headers[k.strip()] = v.strip()
        if login_url and login_user and login_pass:
            self._do_login()

    def _do_login(self):
        data = {self._login_user_field: self._login_user,
                self._login_pass_field: self._login_pass}
        resp = self.post_no_redirect(self._login_url, data)
        if self._extract_session(resp):
            return
        if resp.get("status", 0) not in range(200, 210):
            resp = self.post(self._login_url, data)
            if self._extract_session(resp):
                return
        if not self._extract_session(resp):
            tprint(f"  {warn('Login: no session token detected — may be unauthenticated')}")

    def _extract_session(self, resp):
        sc = resp.get("headers", {}).get("set-cookie", "")
        if sc:
            pairs = []
            for part in sc.split(","):
                frag = part.strip().split(";")[0].strip()
                if "=" in frag and not any(
                    frag.lower().startswith(k)
                    for k in ("path=", "domain=", "expires=", "max-age=",
                              "samesite=", "secure", "httponly")
                ):
                    pairs.append(frag)
            if pairs:
                self.headers["Cookie"] = "; ".join(pairs)
                tprint(f"  {ok(f'Login OK — {len(pairs)} cookie pair(s) captured')}")
                return True
        auth = resp.get("headers", {}).get("authorization", "")
        if auth:
            self.headers["Authorization"] = auth
            tprint(f"  {ok('Login OK — Authorization header captured')}")
            return True
        try:
            body = json.loads(resp.get("body", "{}") or "{}")
            candidates = [body]
            if isinstance(body.get("data"), dict):
                candidates.append(body["data"])
            for obj in candidates:
                for key in ("token", "access_token", "accessToken",
                            "jwt", "auth_token", "authToken", "id_token"):
                    if key in obj and isinstance(obj[key], str) and len(obj[key]) > 8:
                        self.headers["Authorization"] = f"Bearer {obj[key]}"
                        tprint(f"  {ok(f'Login OK — Bearer token [{key}]')}")
                        return True
        except Exception:
            pass
        return False

    def clone_no_auth(self):
        c = HTTPClient.__new__(HTTPClient)
        c.timeout           = self.timeout
        c._login_url        = None
        c._login_user       = None
        c._login_pass       = None
        c._login_user_field = "username"
        c._login_pass_field = "password"
        c.headers = {k: v for k, v in self.headers.items()
                     if k not in ("Cookie", "Authorization")}
        return c

    def get(self, url, params=None, extra_headers=None):
        hdrs = {**self.headers, **(extra_headers or {})}
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                qs  = urllib.parse.urlencode(filtered, quote_via=urllib.parse.quote)
                url = url + ("&" if "?" in url else "?") + qs
        return self._do(url, None, "GET", hdrs)

    def post(self, url, data=None, content_type=None, extra_headers=None):
        hdrs = {**self.headers, **(extra_headers or {})}
        body = None
        if data:
            if content_type == "json":
                body = json.dumps(data).encode()
                hdrs = {**hdrs, "Content-Type": "application/json"}
            else:
                body = urllib.parse.urlencode(
                    {k: v for k, v in data.items() if v is not None}
                ).encode()
                hdrs = {**hdrs, "Content-Type": "application/x-www-form-urlencoded"}
        return self._do(url, body, "POST", hdrs)

    def _do(self, url, body, method, hdrs):
        req    = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        t0     = time.time()
        result = [None]

        def _execute():
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL_CTX) as r:
                    text = r.read(512 * 1024).decode("utf-8", errors="replace")
                    result[0] = {"ok": True, "status": r.status, "body": text,
                                 "elapsed": time.time() - t0, "url": r.url,
                                 "headers": dict(r.headers), "error": None}
            except urllib.error.HTTPError as e:
                try:    text = e.read(256 * 1024).decode("utf-8", errors="replace")
                except: text = ""
                result[0] = {"ok": False, "status": e.code, "body": text,
                             "elapsed": time.time() - t0, "url": url,
                             "headers": dict(e.headers) if e.headers else {},
                             "error": str(e)}
            except Exception as ex:
                result[0] = {"ok": False, "status": 0, "body": "",
                             "elapsed": time.time() - t0, "url": url,
                             "headers": {}, "error": str(ex)}

        t = threading.Thread(target=_execute, daemon=True)
        t.start()
        t.join(timeout=self.timeout + 2)
        if result[0] is None:
            return {"ok": False, "status": 0, "body": "",
                    "elapsed": time.time() - t0, "url": url,
                    "headers": {}, "error": "hard_timeout"}
        return result[0]

    def post_no_redirect(self, url, data=None, content_type=None):
        hdrs = dict(self.headers)
        body = None
        if data:
            if content_type == "json":
                body = json.dumps(data).encode()
                hdrs["Content-Type"] = "application/json"
            else:
                body = urllib.parse.urlencode(
                    {k: v for k, v in data.items() if v is not None}
                ).encode()
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_SSL_CTX))
        req    = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        t0     = time.time()
        try:
            with opener.open(req, timeout=self.timeout) as r:
                text = r.read(256 * 1024).decode("utf-8", errors="replace")
                return {"ok": True, "status": r.status, "body": text,
                        "elapsed": time.time() - t0, "url": url,
                        "headers": dict(r.headers), "error": None}
        except urllib.error.HTTPError as e:
            try:    text = e.read(256 * 1024).decode("utf-8", errors="replace")
            except: text = ""
            return {"ok": e.code in range(200, 400), "status": e.code, "body": text,
                    "elapsed": time.time() - t0, "url": url,
                    "headers": dict(e.headers) if e.headers else {},
                    "error": None if e.code in range(300, 310) else str(e)}
        except Exception as ex:
            return {"ok": False, "status": 0, "body": "",
                    "elapsed": time.time() - t0, "url": url, "headers": {}, "error": str(ex)}

# ══════════════════════════════════════════════════════════════════════
# FORM PARSER (auth forms)
# ══════════════════════════════════════════════════════════════════════

class AuthFormParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url   = base_url
        self._base      = urllib.parse.urlparse(base_url)
        self.forms      = []
        self.auth_links = []
        self._form      = None
        self._in_a      = False
        self._a_href    = ""
        self._a_text    = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            href = (a.get("href") or "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "#")):
                self._in_a   = True
                self._a_href = urllib.parse.urljoin(self.base_url, href)
                self._a_text = ""
        elif tag == "form":
            action  = urllib.parse.urljoin(self.base_url, a.get("action") or self.base_url)
            method  = a.get("method", "POST").upper()
            enctype = a.get("enctype", "").lower()
            ct_hint = "json" if "json" in enctype else "form"
            self._form = {"action": action, "method": method, "content_type": ct_hint,
                          "fields": [], "hidden": {}}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name  = (a.get("name") or a.get("id") or "").strip()
            itype = a.get("type", "text").lower()
            value = a.get("value", "")
            if not name:
                return
            if itype == "hidden":
                self._form["hidden"][name] = value
            elif itype not in ("submit", "button", "reset", "image", "file"):
                self._form["fields"].append({"name": name, "type": itype, "value": value})

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            if self._looks_like_auth_form(self._form):
                self.forms.append(self._form)
            self._form = None
        elif tag == "a":
            if self._in_a and self._a_href:
                kind = self._classify_link(self._a_href, self._a_text)
                if kind:
                    self.auth_links.append((self._a_href, self._a_text.strip(), kind))
            self._in_a = False; self._a_href = ""; self._a_text = ""

    def handle_data(self, data):
        if self._in_a:
            self._a_text += data

    def _looks_like_auth_form(self, form):
        field_names = {f["name"].lower() for f in form.get("fields", [])}
        has_password = any(v in field_names for v in ("password", "passwd", "pass", "secret", "pwd"))
        action_looks_auth = bool(
            _LOGIN_URL_PATTERNS.search(form.get("action", "")) or
            _REGISTER_URL_PATTERNS.search(form.get("action", ""))
        )
        return has_password or action_looks_auth

    def _classify_link(self, href, text):
        if _LOGIN_URL_PATTERNS.search(href) or _LOGIN_LINK_TEXT.search(text):
            return "login"
        if _REGISTER_URL_PATTERNS.search(href) or _REGISTER_LINK_TEXT.search(text):
            return "register"
        return None

# ══════════════════════════════════════════════════════════════════════
# AUTH PROBE
# ══════════════════════════════════════════════════════════════════════

class AuthProbe:
    def __init__(self, client, base_url):
        self.client   = client
        self.base_url = base_url.rstrip("/")
        self._base    = urllib.parse.urlparse(base_url)

    def discover(self):
        result = {"login_url": None, "register_url": None, "login_form": None,
                  "register_form": None, "csrf_field": None, "content_type": "form"}
        candidate_pages    = self._collect_candidate_pages()
        login_candidates   = []
        register_candidates= []

        for url, page_type in candidate_pages:
            resp = self.client.get(url)
            if resp["status"] == 0 or resp["status"] >= 400:
                continue
            body = resp.get("body", "") or ""
            ct   = resp.get("headers", {}).get("content-type", "")
            if "html" in ct or body.strip().startswith("<"):
                parser = AuthFormParser(url)
                try: parser.feed(body)
                except Exception: pass
                for form in parser.forms:
                    kind = self._classify_form(form, url, page_type)
                    if kind == "login":    login_candidates.append((url, form))
                    elif kind == "register": register_candidates.append((url, form))
                for href, text, kind in parser.auth_links:
                    if kind == "login" and href not in [c[0] for c in candidate_pages]:
                        candidate_pages.append((href, "login"))
                    elif kind == "register" and href not in [c[0] for c in candidate_pages]:
                        candidate_pages.append((href, "register"))
            elif "json" in ct or body.strip().startswith("{"):
                if page_type == "login":
                    result["login_url"]    = url
                    result["content_type"] = "json"
                elif page_type == "register":
                    result["register_url"] = url

        if login_candidates:
            url, form = login_candidates[0]
            result["login_url"]    = form["action"]
            result["login_form"]   = form
            result["content_type"] = form.get("content_type", "form")
            result["csrf_field"]   = self._find_csrf_field(form)
        if register_candidates:
            url, form = register_candidates[0]
            result["register_url"]  = form["action"]
            result["register_form"] = form
            if not result["csrf_field"]:
                result["csrf_field"] = self._find_csrf_field(form)
        return result

    def _collect_candidate_pages(self):
        base = self.base_url
        candidates = [(base, "home")]
        for path in [
            "/login", "/signin", "/sign-in", "/auth", "/auth/login",
            "/user/login", "/users/login", "/account/login",
            "/api/login", "/api/auth", "/api/signin", "/api/token",
            "/api/v1/auth", "/api/v1/login", "/api/v1/token",
            "/api/v2/login", "/api/v2/auth",
            "/rest/user/login", "/rest/auth/login", "/rest/login",
            "/rest/session", "/api/session", "/api/users/login",
            "/api/auth/token", "/api/authenticate",
        ]:
            candidates.append((base + path, "login"))
        for path in [
            "/register", "/signup", "/sign-up", "/join",
            "/account/register", "/user/register", "/users/register",
            "/create-account", "/new-account",
            "/api/register", "/api/signup",
            "/api/v1/register", "/api/v1/signup", "/api/v1/users",
        ]:
            candidates.append((base + path, "register"))
        return candidates

    def _classify_form(self, form, page_url, page_type_hint):
        action   = form.get("action", "").lower()
        fields   = {f["name"].lower() for f in form.get("fields", [])}
        has_pass = bool(fields & {"password", "passwd", "pass", "pwd", "secret"})
        has_conf = bool(fields & {"password_confirmation", "confirm_password",
                                  "confirmpassword", "password2", "pass2",
                                  "repeat_password", "repassword"})
        if has_pass and has_conf: return "register"
        if _REGISTER_URL_PATTERNS.search(action) or page_type_hint == "register": return "register"
        if has_pass or _LOGIN_URL_PATTERNS.search(action) or page_type_hint == "login": return "login"
        return None

    def _find_csrf_field(self, form):
        for name in form.get("hidden", {}).keys():
            if re.search(r'csrf|xsrf|nonce|authenticity_token|_token|verify', name, re.I):
                return name
        return None

# ══════════════════════════════════════════════════════════════════════
# SESSION BUILDER
# ══════════════════════════════════════════════════════════════════════

class SessionBuilder:
    def __init__(self, client, base_url, timeout=12):
        self.client          = client
        self.base_url        = base_url.rstrip("/")
        self.timeout         = timeout
        self._login_url_hint = None
        self._own_username   = None

    def login(self, username, password, probe_result):
        login_url = probe_result.get("login_url")
        if not login_url:
            return False, {}, []
        self._login_url_hint = login_url
        self._own_username   = username
        csrf_name, csrf_value = self._fetch_csrf(login_url, probe_result.get("csrf_field"))
        content_type = probe_result.get("content_type", "form")
        form         = probe_result.get("login_form") or {}
        user_cands   = self._field_candidates(form, "user")
        pass_cands   = self._field_candidates(form, "pass")
        form_user    = user_cands[:3]
        form_pass    = pass_cands[:3]

        for uf in form_user:
            for pf in form_pass:
                if uf == pf: continue
                success, auth_hdrs, id_hints = self._attempt_login(
                    login_url, uf, username, pf, password,
                    csrf_name, csrf_value, content_type, form)
                if success: return True, auth_hdrs, id_hints

        form_fields = {f["name"].lower() for f in form.get("fields", [])}
        if len(form_fields) >= 2:
            return False, {}, []

        attempted = 0
        for uf in user_cands[:5]:
            for pf in pass_cands[:4]:
                if uf == pf or attempted >= 20: continue
                attempted += 1
                success, auth_hdrs, id_hints = self._attempt_login(
                    login_url, uf, username, pf, password,
                    csrf_name, csrf_value, content_type, form)
                if success: return True, auth_hdrs, id_hints
        return False, {}, []

    def _fetch_csrf(self, url, known_field):
        resp = self.client.get(url)
        if not resp["ok"]: return None, None
        body = resp.get("body", "") or ""
        csrf_re  = re.compile(r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']{8,})["\']', re.I)
        csrf_re2 = re.compile(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']{8,})["\']', re.I)
        for pattern in (csrf_re, csrf_re2):
            for m in pattern.finditer(body):
                fname, fval = m.group(1), m.group(2)
                if re.search(r'csrf|xsrf|nonce|authenticity|_token|verify', fname, re.I):
                    return fname, fval
                if known_field and fname.lower() == known_field.lower():
                    return fname, fval
        meta_m = re.search(r'<meta[^>]+name=["\']csrf-?token["\'][^>]*content=["\']([^"\']+)["\']', body, re.I)
        if meta_m: return "csrf_token", meta_m.group(1)
        js_csrf = re.search(r'(?:csrf|xsrf|_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']', body, re.I)
        if js_csrf: return known_field or "csrf_token", js_csrf.group(1)
        return known_field, None

    def _field_candidates(self, form, kind):
        variants = list(_USERNAME_FIELD_VARIANTS if kind == "user" else _PASSWORD_FIELD_VARIANTS)
        if not form: return variants
        form_names = [f["name"] for f in form.get("fields", []) if f.get("type") != "hidden"]
        ordered = []
        for fn in form_names:
            fn_lower = fn.lower()
            if kind == "user" and any(v in fn_lower for v in ("user","email","login","handle","phone","account","identifier")):
                ordered.insert(0, fn)
            elif kind == "pass" and any(v in fn_lower for v in ("pass","pwd","secret")):
                ordered.insert(0, fn)
        seen = set(ordered)
        for v in variants:
            if v not in seen: ordered.append(v); seen.add(v)
        return ordered

    def _attempt_login(self, url, user_field, username, pass_field, password,
                       csrf_name, csrf_value, content_type, form):
        payload = dict(form.get("hidden", {}))
        if csrf_name and csrf_value:   payload[csrf_name] = csrf_value
        elif csrf_name:
            _, fresh_csrf = self._fetch_csrf(url, csrf_name)
            if fresh_csrf: payload[csrf_name] = fresh_csrf
        payload[user_field] = username
        payload[pass_field] = password
        url_looks_rest = bool(re.search(r'/rest/|/api/|/auth/', url, re.I))
        effective_ct = "json" if url_looks_rest else content_type
        resp = self.client.post_no_redirect(url, payload, effective_ct)
        if effective_ct == "json" and resp.get("status", 0) in (400, 415, 422, 405):
            resp = self.client.post_no_redirect(url, payload, content_type)
        auth_hdrs = self._extract_auth(resp)
        if not auth_hdrs: return False, {}, []
        verified, id_hints = self._verify_and_harvest(auth_hdrs)
        if not verified: return False, {}, []
        return True, auth_hdrs, id_hints

    def _extract_auth(self, resp):
        status   = resp.get("status", 0)
        location = resp.get("headers", {}).get("location", "") or ""
        body     = (resp.get("body", "") or "")
        is_redirect_success = (
            status in range(301, 310) and
            (not location or _POST_LOGIN_DESTINATIONS.search(location) or
             not re.search(r'login|signin|error|fail', location, re.I))
        )
        sc = resp.get("headers", {}).get("set-cookie", "") or ""
        if sc:
            pairs = []
            for part in sc.split(","):
                frag = part.strip().split(";")[0].strip()
                if "=" in frag and not any(frag.lower().startswith(k)
                    for k in ("path=","domain=","expires=","max-age=","samesite=","secure","httponly")):
                    pairs.append(frag)
            if pairs: return {"Cookie": "; ".join(pairs)}
        if body:
            try:
                obj = json.loads(body)
                token, uid = self._dig_json(obj)
                if token: return {"Authorization": f"Bearer {token}", "_uid": uid}
            except Exception: pass
        for hname in ("x-auth-token","x-access-token","x-token","x-api-key","x-session-token"):
            hval = resp.get("headers", {}).get(hname, "")
            if hval and len(hval) > 8: return {"Authorization": f"Bearer {hval}"}
        if is_redirect_success and status in range(301, 310):
            return {"_redirect_only": True}
        return {}

    def _dig_json(self, obj, depth=0):
        if depth > 4 or not isinstance(obj, dict): return None, None
        token_keys = ("token","access_token","accessToken","jwt","auth_token",
                      "authToken","id_token","idToken","sessionToken","bearer")
        id_keys    = ("id","user_id","userId","uid","uuid","account_id","accountId")
        token = None; uid = None
        for k, v in obj.items():
            if k in token_keys and isinstance(v, str) and len(v) > 8: token = v
            if k in id_keys and v is not None: uid = str(v)
            if isinstance(v, dict):
                sub_tok, sub_uid = self._dig_json(v, depth + 1)
                if not token and sub_tok: token = sub_tok
                if not uid   and sub_uid: uid   = sub_uid
        return token, uid

    def _verify_and_harvest(self, auth_hdrs):
        if auth_hdrs.get("_redirect_only"): return True, []
        test_client = self.client.clone_no_auth()
        for k, v in auth_hdrs.items():
            if not k.startswith("_"): test_client.headers[k] = v
        uid_from_login = auth_hdrs.get("_uid")
        id_hints = []; verified = False
        if uid_from_login:
            id_hints.append({"id_val": uid_from_login,
                             "id_type": "uuid" if _UUID_RE.match(str(uid_from_login)) else "numeric",
                             "id_source": "login_response", "context_url": self.base_url})
            verified = True

        # Strategy A: /me endpoints
        for path in _ME_ENDPOINTS:
            url  = self.base_url + path
            resp = test_client.get(url)
            if resp["status"] in (200, 201):
                verified = True
                body  = resp.get("body", "") or ""
                hints = self._extract_ids_from_body(body, url)
                id_hints.extend(hints)
                if hints: return verified, self._dedup_hints(id_hints)
            elif resp["status"] not in (404, 0, 401, 403):
                verified = True

        # Strategy B: Session-only link diff
        if not id_hints:
            try:
                auth_resp = test_client.get(self.base_url)
                bare_resp = self.client.get(self.base_url)
                auth_body = auth_resp.get("body", "") or ""
                bare_body = bare_resp.get("body", "") or ""
                href_re    = re.compile(r'href=["\']([^"\'#?]{1,200})["\']', re.I)
                auth_hrefs = {m.group(1) for m in href_re.finditer(auth_body)}
                bare_hrefs = {m.group(1) for m in href_re.finditer(bare_body)}
                session_only = auth_hrefs - bare_hrefs
                for href in list(session_only)[:20]:
                    full_url = urllib.parse.urljoin(self.base_url, href)
                    if not full_url.startswith(self.base_url): continue
                    resp = test_client.get(full_url)
                    if resp["status"] not in (200, 201): continue
                    body = resp.get("body", "") or ""
                    if len(body) < 50: continue
                    verified = True
                    hints = self._extract_ids_from_body(body, full_url)
                    if not hints:
                        hints = self._extract_ids_from_html(body, full_url, self._own_username)
                    if hints:
                        id_hints.extend(hints); break
            except Exception: pass

        # Strategy C: Common session-specific pages
        if not id_hints:
            for page_path in ["/settings","/account/settings","/user/settings",
                               "/profile/edit","/account/edit","/account",
                               "/me","/my-account","/my-profile","/dashboard","/home",
                               "/notifications","/inbox","/messages",
                               "/api/settings","/api/account","/api/profile"]:
                url  = self.base_url + page_path
                resp = test_client.get(url)
                if resp["status"] not in (200, 201): continue
                body = resp.get("body", "") or ""
                if len(body) < 50: continue
                verified = True
                hints = self._extract_ids_from_body(body, url)
                if not hints:
                    hints = self._extract_ids_from_html(body, url, self._own_username)
                if hints:
                    id_hints.extend(hints); break

        # Strategy D: Login redirect destination
        if self._login_url_hint and not id_hints:
            resp = test_client.post_no_redirect(self._login_url_hint, {})
            loc  = resp.get("headers", {}).get("location", "") or ""
            if loc and loc not in ("/", ""):
                redir_url  = urllib.parse.urljoin(self.base_url, loc)
                redir_resp = test_client.get(redir_url)
                if redir_resp["status"] == 200:
                    verified = True
                    body  = redir_resp.get("body", "") or ""
                    hints = self._extract_ids_from_body(body, redir_url)
                    if not hints:
                        hints = self._extract_ids_from_html(body, redir_url, self._own_username)
                    id_hints.extend(hints)

        # Strategy E: Base URL verification only
        if not verified:
            resp = test_client.get(self.base_url)
            if resp["status"] == 200:
                body = (resp.get("body", "") or "")[:2000]
                if not re.search(r'login|signin|please\s+log\s*in|not\s+authenticated', body, re.I):
                    verified = True

        return verified, self._dedup_hints(id_hints)

    def _dedup_hints(self, hints):
        seen = set(); out = []
        for h in hints:
            k = (h["id_val"], h["id_type"])
            if k not in seen: seen.add(k); out.append(h)
        return out

    def _extract_ids_from_html(self, body, context_url, own_username=None):
        hints     = []
        own_hints = []
        if own_username:
            tagged_re = re.compile(
                r'href=["\']([^"\'#?]{1,200})["\'][^>]*(?:class=["\'][^"\']*'
                r'(?:active|current|self|me|own)[^"\']*["\'])?[^>]*>([^<]{0,200})</a>',
                re.I | re.S)
            for m in tagged_re.finditer(body[:32000]):
                href_val  = m.group(1); link_text = m.group(2).strip().lower()
                if own_username.lower() not in link_text:
                    class_m   = re.search(r'class=["\']([^"\']*)["\']', m.group(0), re.I)
                    css_class = (class_m.group(1) if class_m else "").lower()
                    if not any(k in css_class for k in ("active","current","self","me","own")):
                        continue
                segs = [s for s in href_val.rstrip("/").split("/") if s]
                for idx, seg in enumerate(segs):
                    if seg.isdigit() and int(seg) > 0:
                        parent = segs[idx-1].lower() if idx > 0 else ""
                        if not re.match(r'^v\d*$', parent):
                            own_hints.append({"id_val": seg, "id_type": "numeric",
                                              "id_source": "html:username_link",
                                              "context_url": context_url})
            if own_hints: return own_hints
            blocks = re.split(r'(?:</li>|</div>|</tr>|</td>|</nav>)', body[:32000], flags=re.I)
            for block in blocks:
                if own_username.lower() not in block.lower(): continue
                for m in re.finditer(r'href=["\']([^"\'#?]{1,200})["\']', block, re.I):
                    segs = [s for s in m.group(1).rstrip("/").split("/") if s]
                    for idx, seg in enumerate(segs):
                        if seg.isdigit() and int(seg) > 0:
                            parent = segs[idx-1].lower() if idx > 0 else ""
                            if not re.match(r'^v\d*$', parent):
                                own_hints.append({"id_val": seg, "id_type": "numeric",
                                                  "id_source": "html:username_block",
                                                  "context_url": context_url})
            if own_hints: return own_hints

        _STATIC_SKIP  = re.compile(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip)(\?|$)', re.I)
        _SEG_PAGI     = frozenset({"page","p","pg","step","chunk","batch","v","ver","version",
                                    "rev","ts","t","time","date","year","month","day","size",
                                    "limit","max","min","num","n","rows","index","start","end","pos"})
        href_re = re.compile(r'href=["\']([^"\'#?]{2,200})["\']', re.I)
        for m in href_re.finditer(body[:32000]):
            href = m.group(1)
            if _STATIC_SKIP.search(href): continue
            segs = [s for s in href.rstrip("/").split("/") if s]
            for idx, seg in enumerate(segs):
                if not seg.isdigit() or int(seg) == 0: continue
                parent = segs[idx-1].lower() if idx > 0 else ""
                if re.match(r'^v\d*$', parent): continue
                if parent in _SEG_PAGI: continue
                hints.append({"id_val": seg, "id_type": "numeric",
                               "id_source": "html:href_path", "context_url": context_url})
        for m in re.finditer(r'data-(?:user-?id|uid|author-?id|owner-?id|member-?id|profile-?id)\s*=\s*["\'](\d{1,8})["\']', body[:32000], re.I):
            hints.append({"id_val": m.group(1), "id_type": "numeric",
                           "id_source": "html:data_attr", "context_url": context_url})
        for m in re.finditer(r'(?:user_?id|userId|currentUser\.id|profile_?id|uid|loggedInId)\s*[=:]\s*["\']?(\d{1,8})["\']?', body[:32000], re.I):
            val = m.group(1)
            if val not in ("0",""):
                hints.append({"id_val": val, "id_type": "numeric",
                               "id_source": "html:js_var", "context_url": context_url})
        for m in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*name=["\'](?:user_?id|uid|profile_?id|author_?id)["\'][^>]*value=["\'](\d{1,8})["\']', body[:32000], re.I):
            hints.append({"id_val": m.group(1), "id_type": "numeric",
                           "id_source": "html:hidden_field", "context_url": context_url})
        seen = set(); deduped = []
        for h in hints:
            if h["id_val"] not in seen: seen.add(h["id_val"]); deduped.append(h)
        return deduped

    def _extract_ids_from_body(self, body, context_url):
        hints = []
        try:
            obj = json.loads(body)
            self._recurse_id_extract(obj, hints, context_url, 0)
        except Exception: pass
        return hints

    def _recurse_id_extract(self, obj, hints, ctx, depth):
        if depth > 4: return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _IDOR_PARAM_NAME_RE.match(str(k)):
                    val = str(v) if v is not None else ""
                    if _NUMERIC_RE.match(val):
                        hints.append({"id_val": val, "id_type": "numeric",
                                      "id_source": f"me_response:{k}", "context_url": ctx})
                    elif _UUID_RE.match(val):
                        hints.append({"id_val": val, "id_type": "uuid",
                                      "id_source": f"me_response:{k}", "context_url": ctx})
                if isinstance(v, dict): self._recurse_id_extract(v, hints, ctx, depth+1)
        elif isinstance(obj, list):
            for item in obj[:5]: self._recurse_id_extract(item, hints, ctx, depth+1)

# ══════════════════════════════════════════════════════════════════════
# FIELD CLASSIFIER
# ══════════════════════════════════════════════════════════════════════

class FieldClassifier:
    _NAME_MAP = [
        ("email",        ("email","mail","e_mail","emailaddress","email_address","email_addr")),
        ("username",     ("username","user_name","login","loginname","login_name","user_login",
                          "account_name","accountname","nickname","nick_name","screen_name",
                          "screenname","handle")),
        ("first_name",   ("firstname","first_name","fname","given_name","givenname","forename","first")),
        ("last_name",    ("lastname","last_name","lname","surname","family_name","familyname","last")),
        ("display_name", ("display","displayname","display_name","fullname","full_name","realname",
                          "real_name","your_name","yourname","first_last","firstname_lastname","name")),
        ("confirm_pass", ("confirm","confirmation","verify","retype","re_enter","reenter","repeat",
                          "password_confirm","confirm_password","confirmpassword","password_confirmation",
                          "password2","pass2","passwd2","re_password","repassword","repeat_password",
                          "confirm_pass","confirmpass","confirm_passphrase","passphrase_confirm")),
        ("password",     ("password","passwd","pass","pwd","secret","passphrase","pass_phrase",
                          "new_password","newpassword","create_password","createpassword",
                          "account_password","user_password","login_password")),
        ("phone",        ("phone","mobile","cell","telephone","tel","phonenumber","phone_number",
                          "mobile_number","cellphone","contact_number","contactnumber")),
        ("website",      ("website","url","web","homepage","site","blog","portfolio")),
        ("dob",          ("dob","birthday","birth_date","birthdate","date_of_birth","dateofbirth",
                          "born","birth","birthyear","birth_year")),
        ("gender",       ("gender","sex","pronouns")),
        ("country",      ("country","nation","country_code","nationality")),
        ("city",         ("city","town","locality")),
        ("address",      ("address","street","addr","location")),
        ("zip",          ("zip","zipcode","zip_code","postal","postcode","postal_code")),
        ("bio",          ("bio","about","description","about_me","aboutme","profile_text",
                          "summary","introduction","intro","blurb")),
        ("company",      ("company","organization","organisation","employer","workplace",
                          "corp","business","firm")),
        ("job_title",    ("title","job","jobtitle","job_title","position","role",
                          "occupation","profession")),
        ("invite_code",  ("invite","invitation","referral","ref_code","promo","coupon",
                          "voucher","access_code","invite_code","registration_code","signup_code")),
        ("secret_q",     ("security_question","secret_question","hint_question","sq")),
        ("secret_a",     ("security_answer","secret_answer","hint_answer","sa")),
        ("terms",        ("terms","tos","agree","accept","i_agree","terms_of_service",
                          "terms_and_conditions","privacy","consent","gdpr","newsletter",
                          "marketing","subscribe","optin","opt_in")),
        ("age_num",      ("age","years_old","how_old","your_age")),
        ("quantity",     ("qty","quantity","amount","count","number")),
    ]
    _TYPE_MAP = {"email":"email","tel":"phone","url":"website","date":"dob",
                 "number":"quantity","checkbox":"terms","radio":"gender","range":"quantity"}
    _FIRST_NAMES = ["Alex","Jordan","Morgan","Taylor","Casey","Riley","Cameron","Quinn","Avery","Blake"]
    _LAST_NAMES  = ["Smith","Johnson","Williams","Brown","Davis","Miller","Wilson","Moore","Taylor","Anderson"]
    _COMPANIES   = ["Acme Corp","Test Industries","Example Ltd","Sample Solutions","Demo Enterprises"]
    _JOB_TITLES  = ["Software Engineer","Developer","Analyst","Designer","Consultant","Manager"]
    _CITIES      = ["New York","London","Toronto","Sydney","Berlin"]
    _BIOS        = ["Security researcher and developer.",
                    "Software professional interested in web technologies.",
                    "Tech enthusiast building cool things."]
    _SEC_QUESTIONS = ["What is your mother's maiden name?",
                      "What was the name of your first pet?",
                      "What city were you born in?"]

    def classify(self, field):
        fname = (field.get("name") or "").lower().strip()
        ftype = (field.get("type") or "text").lower().strip()
        fph   = (field.get("placeholder") or "").lower()
        flab  = (field.get("label") or "").lower()
        if ftype in self._TYPE_MAP and ftype != "number":
            return self._TYPE_MAP[ftype]
        all_kws = []
        for category, keywords in self._NAME_MAP:
            for kw in keywords:
                all_kws.append((len(kw), category, kw))
        all_kws.sort(key=lambda x: -x[0])
        clean = re.sub(r'^(new_|re_|confirm_|user_|your_|my_)', '', fname)
        clean = re.sub(r'(_input|_field|_val|_value|_entry)$', '', clean)
        for _, category, kw in all_kws:
            if clean == kw or fname == kw: return category
        for _, category, kw in all_kws:
            if len(kw) >= 4 and (kw in clean or kw in fname): return category
        combined = fph + " " + flab
        for _, category, kw in all_kws:
            if len(kw) >= 4 and kw in combined: return category
        pattern = (field.get("pattern") or "").lower()
        if pattern:
            if re.search(r'\[0-9\].*\[0-9\]', pattern): return "phone"
            if "@" in pattern: return "email"
        return "unknown"

    def fill(self, field, credentials):
        category = self.classify(field)
        fname    = field.get("name", "")
        ftype    = (field.get("type") or "text").lower()
        c        = credentials
        if category == "email":        return c["email"]
        if category == "username":     return c["username"]
        if category == "display_name": return c["display_name"]
        if category == "first_name":   return c["first_name"]
        if category == "last_name":    return c["last_name"]
        if category in ("password", "confirm_pass"): return c["password"]
        if category == "phone":        return c["phone"]
        if category == "website":      return f"https://example.com/~{c['username']}"
        if category == "dob":
            if ftype == "date": return "1990-01-15"
            ph = (field.get("placeholder") or "").upper()
            if "MM/DD/YYYY" in ph: return "01/15/1990"
            if "DD/MM/YYYY" in ph: return "15/01/1990"
            return "1990-01-15"
        if category == "gender":  return field.get("value","other") if ftype == "radio" else "other"
        if category == "country": return "US"
        if category == "city":    return random.choice(self._CITIES)
        if category == "address": return "123 Test Street"
        if category == "zip":     return "10001"
        if category == "bio":     return random.choice(self._BIOS)
        if category == "company": return random.choice(self._COMPANIES)
        if category == "job_title": return random.choice(self._JOB_TITLES)
        if category == "invite_code": return ""
        if category == "secret_q":
            if field.get("type") == "select" or field.get("options"):
                opts = field.get("options") or []
                for opt in opts:
                    v = opt.get("value","") if isinstance(opt, dict) else str(opt)
                    if v and v not in ("","0","null","none","select"): return v
            return random.choice(self._SEC_QUESTIONS)
        if category == "secret_a": return "TestAnswer123"
        if category == "terms":    return field.get("value") or "1"
        if category in ("age_num", "quantity"): return "25" if category == "age_num" else (field.get("value") or "1")
        if ftype == "email": return c["email"]
        if ftype in ("text","search"):
            return c["display_name"] if any(x in fname.lower() for x in ("name","alias","display","nick")) else c["username"]
        if ftype in ("number","range"): return field.get("value") or "1"
        if ftype == "checkbox":   return field.get("value") or "1"
        if ftype == "textarea":   return "Test user profile."
        if ftype == "url":        return "https://example.com"
        return c["display_name"]

# ══════════════════════════════════════════════════════════════════════
# AUTO REGISTRAR
# ══════════════════════════════════════════════════════════════════════

class AutoRegistrar:
    _DOMAINS      = ["example.com","test.local","mailtest.dev","fakeuser.io"]
    _INVITE_CODES = ["TEST","INVITE","BETA","DEMO","FREE","test123","invite123","beta2024","welcome"]

    def __init__(self, client, base_url, probe_result):
        self.client       = client
        self.base_url     = base_url.rstrip("/")
        self.probe_result = probe_result
        self._classifier  = FieldClassifier()

    def _parse_password_constraints(self, reg_form):
        c = {"minlen":8,"maxlen":128,"pattern":None,
             "requires_upper":True,"requires_lower":True,"requires_digit":True,"requires_special":True}
        for field in reg_form.get("fields",[]):
            if self._classifier.classify(field) != "password": continue
            if field.get("minlength"):
                try: c["minlen"] = max(c["minlen"], int(field["minlength"]))
                except: pass
            if field.get("maxlength"):
                try: c["maxlen"] = min(c["maxlen"], int(field["maxlength"]))
                except: pass
            pat = field.get("pattern") or ""
            if pat:
                c["pattern"] = pat
                if "a-z" not in pat.lower(): c["requires_lower"]   = False
                if "A-Z" not in pat:          c["requires_upper"]   = False
                if "0-9" not in pat and r"\d" not in pat: c["requires_digit"] = False
                if not any(x in pat for x in ("!@#$%^&*",r"\W","special")): c["requires_special"] = False
            break
        return c

    def generate_credentials(self, label="a"):
        rand  = "".join(random.choices(string.ascii_lowercase, k=6))
        num   = random.randint(100, 999)
        first = random.choice(FieldClassifier._FIRST_NAMES)
        last  = random.choice(FieldClassifier._LAST_NAMES)
        uname = f"tuser_{rand}{num}"
        return {"label": label, "username": uname,
                "email": f"{uname}@{random.choice(self._DOMAINS)}",
                "password": self._generate_password(), "display_name": f"{first} {last}",
                "first_name": first, "last_name": last,
                "phone": f"+1555{random.randint(1000000, 9999999)}"}

    def _generate_password(self, constraints=None):
        if constraints is None:
            constraints = {"minlen":8,"maxlen":128,"requires_upper":True,"requires_lower":True,
                           "requires_digit":True,"requires_special":True}
        target_len = max(min(max(constraints["minlen"],16), constraints["maxlen"]), 8)
        specials = "@!#$"; parts = []
        if constraints["requires_upper"]:   parts += random.choices(string.ascii_uppercase, k=3)
        if constraints["requires_lower"]:   parts += random.choices(string.ascii_lowercase, k=3)
        if constraints["requires_digit"]:   parts += random.choices(string.digits, k=3)
        if constraints["requires_special"]: parts += random.choices(specials, k=2)
        remaining = target_len - len(parts)
        if remaining > 0:
            pool = string.ascii_letters + string.digits
            if constraints["requires_special"]: pool += specials
            parts += random.choices(pool, k=remaining)
        random.shuffle(parts)
        for i, c in enumerate(parts):
            if c.isalpha(): parts[0], parts[i] = parts[i], parts[0]; break
        return "".join(parts)

    def _build_payload(self, reg_form, credentials, invite_code=None):
        payload  = dict(reg_form.get("hidden", {}))
        csrf_name = self.probe_result.get("csrf_field")
        if csrf_name:
            reg_page = self.client.get(self.probe_result.get("register_url", ""))
            csrf_re  = re.compile(r'<input[^>]+name=["\']' + re.escape(csrf_name) +
                                  r'["\'][^>]*value=["\']([^"\']+)["\']', re.I)
            m = csrf_re.search(reg_page.get("body", "") or "")
            if m: payload[csrf_name] = m.group(1)
        label_map = self._extract_labels(reg_form)
        for field in reg_form.get("fields", []):
            fname    = field["name"]
            enriched = {**field, "label": label_map.get(fname, "")}
            category = self._classifier.classify(enriched)
            if category == "invite_code" and invite_code is not None:
                payload[fname] = invite_code; continue
            val = self._classifier.fill(enriched, credentials)
            if val != "": payload[fname] = val
        return payload

    def _extract_labels(self, reg_form):
        label_map = {}
        reg_url   = self.probe_result.get("register_url", "")
        try:
            resp = self.client.get(reg_url); body = resp.get("body","") or ""
            for m in re.finditer(r'<label[^>]*(?:for|id)=["\']([^"\']+)["\'][^>]*>(.*?)</label>', body, re.I|re.S):
                label_map[m.group(1).strip()] = re.sub(r'<[^>]+>','',m.group(2)).strip()
            for field in reg_form.get("fields",[]):
                if field.get("placeholder"): label_map.setdefault(field["name"], field["placeholder"])
        except Exception: pass
        return label_map

    def _is_registration_success(self, resp, credentials):
        status   = resp.get("status", 0)
        body     = (resp.get("body","") or "").lower()
        location = (resp.get("headers",{}).get("location","") or "").lower()
        failure_signals = ("invalid","error","failed","incorrect","already","exists","taken",
                           "too short","too long","weak","required","must contain","does not match",
                           "password must","username must")
        if any(s in body for s in failure_signals): return False
        if status in range(301,310) and any(s in location for s in ("register","signup","sign-up","error")): return False
        if status in range(200,300):
            return not any(s in body for s in failure_signals)
        return status in range(300,310)

    def register(self, credentials, retry_invite=True):
        reg_url  = self.probe_result.get("register_url")
        reg_form = self.probe_result.get("register_form") or {}
        if not reg_url: return False, {}
        ct          = self.probe_result.get("content_type", "form")
        constraints = self._parse_password_constraints(reg_form)
        if (len(credentials["password"]) < constraints["minlen"] or
                len(credentials["password"]) > constraints["maxlen"]):
            credentials = {**credentials, "password": self._generate_password(constraints)}
        user_supplied_code = self.probe_result.get("_invite_code_hint")
        payload = self._build_payload(reg_form, credentials, invite_code=user_supplied_code)
        resp    = self.client.post_no_redirect(reg_url, payload, ct)
        if self._is_registration_success(resp, credentials): return True, resp
        body = (resp.get("body","") or "").lower()
        if any(kw in body for kw in ("invite","invitation","referral","access code","promo","voucher","registration code")) and retry_invite:
            for code in self._INVITE_CODES:
                if code == user_supplied_code: continue
                payload = self._build_payload(reg_form, credentials, invite_code=code)
                resp    = self.client.post_no_redirect(reg_url, payload, ct)
                if self._is_registration_success(resp, credentials): return True, resp
        if ct != "json":
            resp_json = self.client.post_no_redirect(reg_url, payload, "json")
            if self._is_registration_success(resp_json, credentials): return True, resp_json
        return False, resp

    def register_two_users(self):
        reg_form    = self.probe_result.get("register_form") or {}
        constraints = self._parse_password_constraints(reg_form)
        creds_a     = self.generate_credentials("a"); creds_b = self.generate_credentials("b")
        creds_a["password"] = self._generate_password(constraints)
        creds_b["password"] = self._generate_password(constraints)
        ua_name = creds_a["username"]; ua_mail = creds_a["email"]
        tprint(f"  {info(f'Registering User A: {ua_name} / {ua_mail}')}")
        ok_a, resp_a = self.register(creds_a)
        if not ok_a:
            st_a = resp_a.get("status", "?"); bd_a = (resp_a.get("body","") or "")[:300]
            raise RuntimeError(f"Auto-registration of User A failed (HTTP {st_a}).\n  Server said: {bd_a}")
        tprint(f"  {ok(f'User A registered: {ua_name}')}")
        time.sleep(0.8)
        ub_name = creds_b["username"]; ub_mail = creds_b["email"]
        tprint(f"  {info(f'Registering User B: {ub_name} / {ub_mail}')}")
        ok_b, resp_b = self.register(creds_b)
        if not ok_b:
            st_b = resp_b.get("status", "?"); bd_b = (resp_b.get("body","") or "")[:300]
            raise RuntimeError(f"Auto-registration of User B failed (HTTP {st_b}).\n  Server said: {bd_b}")
        tprint(f"  {ok(f'User B registered: {ub_name}')}")
        return creds_a, creds_b

# ══════════════════════════════════════════════════════════════════════
# AUTH ENGINE
# ══════════════════════════════════════════════════════════════════════

class AuthResult:
    __slots__ = ("client_a","client_b","id_hints","probe","creds_a","creds_b")
    def __init__(self, client_a, client_b, id_hints, probe, creds_a, creds_b):
        self.client_a = client_a; self.client_b = client_b
        self.id_hints = id_hints; self.probe    = probe
        self.creds_a  = creds_a;  self.creds_b  = creds_b

class AuthEngine:
    def __init__(self, client, base_url, tprint_fn=None, invite_code_hint=None):
        self.client            = client
        self.base_url          = base_url.rstrip("/")
        self._tprint           = tprint_fn or print
        self._invite_code_hint = invite_code_hint

    def run(self, user_a=None, user_b=None, auto_register=False):
        self._tprint("  [AUTH] Probing app for auth endpoints...")
        probe     = AuthProbe(self.client, self.base_url).discover()
        login_url = probe.get("login_url")
        reg_url   = probe.get("register_url")
        self._tprint(f"  [AUTH] Login: {login_url or 'not found'}  Register: {reg_url or 'not found'}")

        creds_a = user_a; creds_b = user_b
        if not creds_a or not creds_b:
            if auto_register:
                if not reg_url:
                    raise RuntimeError("auto_register=True but no register endpoint found.")
                self._tprint("  [AUTH] Auto-registering two test accounts...")
                if self._invite_code_hint:
                    probe = {**probe, "_invite_code_hint": self._invite_code_hint}
                registrar = AutoRegistrar(self.client, self.base_url, probe)
                raw_a, raw_b = registrar.register_two_users()
                creds_a = (raw_a["username"], raw_a["password"], raw_a["email"])
                creds_b = (raw_b["username"], raw_b["password"], raw_b["email"])
            else:
                raise RuntimeError("No credentials and auto_register=False.")

        def _try_login(builder, creds_tuple, label):
            username = creds_tuple[0]; password = creds_tuple[1]
            email    = creds_tuple[2] if len(creds_tuple) > 2 else None
            self._tprint(f"  [AUTH] Logging in {label} as '{username}'...")
            ok_, hdrs, hints = builder.login(username, password, probe)
            if ok_: return True, hdrs, hints
            if email and email != username:
                ok_, hdrs, hints = builder.login(email, password, probe)
                if ok_: return True, hdrs, hints
            probe_json = {**probe, "content_type": "json"}
            ok_, hdrs, hints = builder.login(username, password, probe_json)
            if ok_: return True, hdrs, hints
            if email and email != username:
                ok_, hdrs, hints = builder.login(email, password, probe_json)
                if ok_: return True, hdrs, hints
            return False, {}, []

        builder_a = SessionBuilder(self.client, self.base_url)
        ok_a, hdrs_a, id_hints_a = _try_login(builder_a, creds_a, "User A")
        if not ok_a:
            raise RuntimeError(f"Login failed for User A ({creds_a[0]}).")
        self._tprint(f"  [AUTH] User A authenticated — {len(id_hints_a)} own ID(s)")

        builder_b = SessionBuilder(self.client, self.base_url)
        ok_b, hdrs_b, _ = _try_login(builder_b, creds_b, "User B")
        if not ok_b:
            raise RuntimeError(f"Login failed for User B ({creds_b[0]}).")
        self._tprint("  [AUTH] User B authenticated.")

        client_a = self.client.clone_no_auth()
        for k, v in hdrs_a.items():
            if not k.startswith("_"): client_a.headers[k] = v
        client_b = self.client.clone_no_auth()
        for k, v in hdrs_b.items():
            if not k.startswith("_"): client_b.headers[k] = v
        return AuthResult(client_a=client_a, client_b=client_b, id_hints=id_hints_a,
                          probe=probe, creds_a=creds_a, creds_b=creds_b)

# ══════════════════════════════════════════════════════════════════════
# JS ENDPOINT EXTRACTOR
# ══════════════════════════════════════════════════════════════════════

class JSExtractor:
    _REST = [
        re.compile(r'axios\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'fetch\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'\$\.(get|post|ajax)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'XMLHttpRequest[^;]{0,200}\.open\s*\(\s*["\']([A-Z]+)["\']\s*,\s*["\']([^"\']{3,80})["\']', re.I),
        re.compile(r'["\`](/(?:api|v\d+|rest|admin|user|account|profile|order|invoice|doc)[a-zA-Z0-9_\-\./]*)["\`]', re.I),
    ]
    _ROUTER = re.compile(r'(?:router|app|Route)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*["\']([^"\']{2,60})["\']', re.I)
    _QS     = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', re.I)
    _NOISE  = re.compile(r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$|^/static/|^/assets/|^/images/|^/fonts/|^/dist/', re.I)

    def _valid(self, p):
        if not p or not isinstance(p, str): return False
        p = p.split("?")[0].split("#")[0]
        return p.startswith("/") and 2 <= len(p) <= 120 and not self._NOISE.search(p)

    def _norm(self, p):
        return re.sub(r'//+', '/', p.split("#")[0].split("?")[0]).rstrip("/") or "/"

    def extract(self, js_content, base_url=""):
        results = {}
        def add(path, method, params):
            if not self._valid(path): return
            norm = self._norm(path)
            if norm not in results:
                results[norm] = {"path": norm, "method": method.upper(), "params": list(params), "base_url": base_url}
            else:
                results[norm]["params"] = sorted(set(results[norm]["params"] + list(params)))
        for pat in self._REST:
            for m in pat.finditer(js_content):
                g = m.groups()
                if len(g) == 1: path, method = g[0], "GET"
                else:
                    a, b = g[0], g[1]
                    if a.upper() in ("GET","POST","PUT","DELETE","PATCH"): method, path = a.upper(), b
                    elif b.upper() in ("GET","POST","PUT","DELETE","PATCH"): method, path = b.upper(), a
                    else: path, method = a, "GET"
                add(path.split("?")[0], method, self._QS.findall(path))
        for m in self._ROUTER.finditer(js_content):
            method, path = m.group(1), m.group(2)
            if method.lower() == "use": method = "GET"
            add(path, method, [])
        return list(results.values())

# ══════════════════════════════════════════════════════════════════════
# PAGE PARSER (HTML forms + links)
# ══════════════════════════════════════════════════════════════════════

class PageParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self._base    = urllib.parse.urlparse(base_url)
        self.links    = set()
        self.js_links = set()
        self.forms    = []
        self._form    = None
        self.id_links = []
        self._current_select = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            href = (a.get("href") or "").strip()
            if href and not href.startswith(("javascript:","mailto:","#","tel:","data:")):
                full   = urllib.parse.urljoin(self.base_url, href)
                parsed = urllib.parse.urlparse(full)
                if parsed.netloc == self._base.netloc:
                    self.links.add(full)
                    self._harvest_ids_from_url(full)
        elif tag == "script":
            src = (a.get("src") or "").strip()
            if src:
                full = urllib.parse.urljoin(self.base_url, src)
                if urllib.parse.urlparse(full).netloc == self._base.netloc:
                    self.js_links.add(full)
        elif tag == "form":
            action = urllib.parse.urljoin(self.base_url, a.get("action") or self.base_url)
            self._form = {"action": action, "method": a.get("method","GET").upper(),
                          "inputs": [], "hidden": {}, "fields": []}
            self._current_select = None
        elif tag in ("input","textarea","select") and self._form is not None:
            name  = (a.get("name") or a.get("id") or "").strip()
            itype = a.get("type","text").lower()
            value = a.get("value","")
            if not name: return
            if itype == "hidden":
                self._form["hidden"][name] = value
            elif itype not in ("submit","button","reset","image","file"):
                field_entry = {"name": name, "type": "select" if tag == "select" else itype,
                               "value": value, "options": []}
                self._form["inputs"].append({"name": name, "value": value})
                self._form["fields"].append(field_entry)
                if tag == "select": self._current_select = field_entry
        elif tag == "option" and self._form is not None:
            sel = self._current_select
            if sel is not None:
                val = a.get("value","")
                if val and val not in ("","0","null","none"):
                    sel["options"].append({"value": val})

    def handle_endtag(self, tag):
        if tag == "form" and self._form:
            if self._form["inputs"]: self.forms.append(self._form)
            self._form = None; self._current_select = None

    def _harvest_ids_from_url(self, url):
        parsed = urllib.parse.urlparse(url)
        for m in _PATH_NUMERIC_RE.finditer(parsed.path):
            self.id_links.append((url, m.group(1), "path_numeric"))
        for m in _PATH_UUID_RE.finditer(parsed.path):
            self.id_links.append((url, m.group(1), "path_uuid"))
        qs = urllib.parse.parse_qs(parsed.query)
        for k, vs in qs.items():
            if _IDOR_PARAM_NAME_RE.match(k) and vs:
                self.id_links.append((url, vs[0], f"param:{k}"))

# ══════════════════════════════════════════════════════════════════════
# CRAWLER
# ══════════════════════════════════════════════════════════════════════

class Crawler:
    def __init__(self, client, base_url, depth=4, threads=10, max_pages=200):
        self.client    = client
        self.base      = urllib.parse.urlparse(base_url)
        self.base_url  = base_url
        self.max_depth = depth
        self.max_pages = max_pages
        self.threads   = threads
        self._lock     = threading.Lock()
        self.visited   = set()
        self.js_visited= set()
        self.endpoints = []
        self.js_eps    = []
        self.id_hints  = []

    def _same_host(self, url):
        return urllib.parse.urlparse(url).netloc == self.base.netloc

    def _process_page(self, url):
        resp = self.client.get(url)
        if resp["status"] == 0: return [], []
        body = resp.get("body","") or ""
        ct   = resp.get("headers",{}).get("content-type","")
        if "json" in ct or body.strip().startswith(("{","[")):
            self._mine_json_ids(body, url)
        parser = PageParser(url)
        try: parser.feed(body)
        except Exception: pass
        with self._lock:
            for (full_url, id_val, id_src) in parser.id_links:
                if   _NUMERIC_RE.match(id_val): id_type = "numeric"
                elif _UUID_RE.match(id_val):    id_type = "uuid"
                elif _is_slug(id_val):          id_type = "slug"
                else: continue
                self.id_hints.append({"id_val":id_val,"id_type":id_type,
                                       "id_source":id_src,"context_url":url})
        for form in parser.forms:
            params = {i["name"]: i["value"] for i in form["inputs"]}
            with self._lock:
                self.endpoints.append({"url":form["action"],"method":form["method"],
                                        "params":params,"hidden":{},"source":f"form@{url}"})
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            qs = urllib.parse.parse_qs(parsed_url.query)
            with self._lock:
                self.endpoints.append({
                    "url":    parsed_url._replace(query="").geturl(),
                    "method": "GET",
                    "params": {k: v[0] for k, v in qs.items()},
                    "hidden": {}, "source": "url_query",
                })
        new_links = [l for l in parser.links if self._same_host(l) and not _STATIC_EXT_RE.search(l)]
        return new_links, list(parser.js_links)

    def _fetch_js(self, js_url):
        with self._lock:
            if js_url in self.js_visited: return
            self.js_visited.add(js_url)
        resp = self.client.get(js_url)
        if not resp["ok"] or not resp["body"]: return
        eps  = JSExtractor().extract(resp["body"], js_url)
        base = f"{self.base.scheme}://{self.base.netloc}"
        with self._lock:
            for e in eps:
                full = urllib.parse.urljoin(base, e["path"])
                self.js_eps.append({"url":full,"method":e["method"],
                                     "params":{p:"1" for p in e["params"]},
                                     "hidden":{},"source":f"js:{js_url}"})

    def _mine_json_ids(self, body, context_url):
        try:
            data = json.loads(body)
            self._recurse_json(data, context_url, 0)
        except Exception: pass

    def _recurse_json(self, obj, ctx, depth):
        if depth > 6: return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _IDOR_PARAM_NAME_RE.match(str(k)):
                    val = str(v)
                    if   _NUMERIC_RE.match(val): id_type = "numeric"
                    elif _UUID_RE.match(val):    id_type = "uuid"
                    elif _is_slug(val):          id_type = "slug"
                    else: id_type = None
                    if id_type:
                        with self._lock:
                            self.id_hints.append({"id_val":val,"id_type":id_type,
                                                   "id_source":f"json:{k}","context_url":ctx})
                self._recurse_json(v, ctx, depth+1)
        elif isinstance(obj, list):
            for item in obj[:30]: self._recurse_json(item, ctx, depth+1)

    def crawl(self):
        tprint(f"\n  {info(f'Crawling: {self.base_url}  depth={self.max_depth}  threads={self.threads}')}")
        work_q = queue.Queue(); js_q = queue.Queue()
        work_q.put((self.base_url, 0)); self.visited.add(self.base_url)

        def worker():
            while True:
                try: url, depth = work_q.get(timeout=2)
                except queue.Empty: return
                try:
                    with self._lock:
                        if len(self.visited) >= self.max_pages: return
                    new_links, new_js = self._process_page(url)
                    for js in new_js: js_q.put(js)
                    if depth < self.max_depth:
                        for link in new_links:
                            with self._lock:
                                if link not in self.visited and len(self.visited) < self.max_pages:
                                    self.visited.add(link); work_q.put((link, depth+1))
                except Exception: pass
                finally: work_q.task_done()

        def js_worker():
            while True:
                try: js_url = js_q.get(timeout=2)
                except queue.Empty: return
                try: self._fetch_js(js_url)
                except Exception: pass
                finally: js_q.task_done()

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            [pool.submit(worker) for _ in range(self.threads)]
            work_q.join()
            [pool.submit(js_worker) for _ in range(max(2, self.threads//2))]
            js_q.join()

        seen = set(); deduped = []
        for ep in self.endpoints + self.js_eps:
            key = (ep["url"], ep["method"])
            if key not in seen: seen.add(key); deduped.append(ep)
        self.endpoints = deduped

        seen_hints = set(); deduped_hints = []
        for h in self.id_hints:
            k = (h["id_val"], h["id_type"])
            if k not in seen_hints: seen_hints.add(k); deduped_hints.append(h)
        self.id_hints = deduped_hints

        tprint(f"  {ok(f'Crawl done — {len(self.visited)} pages, {len(self.js_visited)} JS, {len(self.endpoints)} endpoints, {len(self.id_hints)} ID hints')}")
        return self.endpoints

# ══════════════════════════════════════════════════════════════════════
# IDOR SURFACE ANALYSER
# ══════════════════════════════════════════════════════════════════════

class IDORSurfaceAnalyser:

    _PAGINATION_PARAMS = frozenset({
        "page","p","pg","pageno","page_no","pagenum","page_num",
        "offset","skip","start","begin","limit","size","per_page","perpage",
        "page_size","pagesize","count","max","num","n","rows","take",
        "step","chunk","batch","sort","order","dir","direction","asc","desc",
        "format","type","view","mode","tab","section",
        "v","ver","version","rev","revision","ts","timestamp","t","time","date",
        "lang","locale","currency",
    })

    def _path_targets(self, path):
        seen = set(); targets = []
        for m in _PATH_NUMERIC_RE.finditer(path):
            val = m.group(1)
            if val in seen: continue
            seen.add(val)
            targets.append({"location":"path","param_name":None,"sample_value":val,"id_type":"numeric"})
        for m in _PATH_UUID_RE.finditer(path):
            val = m.group(1).lower()
            if val in seen: continue
            seen.add(val)
            targets.append({"location":"path","param_name":None,"sample_value":val,"id_type":"uuid"})
        for m in _PATH_SLUG_RE.finditer(path):
            val = m.group(1)
            if val in seen or not _is_slug(val): continue
            seen.add(val)
            targets.append({"location":"path","param_name":None,"sample_value":val,"id_type":"slug"})
        return targets

    def _param_targets(self, params):
        seen = set(); targets = []
        for pname, pval in params.items():
            if pname in seen: continue
            if pname.lower() in self._PAGINATION_PARAMS: continue
            pval_str = str(pval)
            if _IDOR_PARAM_NAME_RE.match(pname):
                if   _NUMERIC_RE.match(pval_str): id_type = "numeric"
                elif _UUID_RE.match(pval_str):    id_type = "uuid"
                elif _is_slug(pval_str):          id_type = "slug"
                else:                             id_type = "param_name_signal"
                seen.add(pname)
                targets.append({"location":"param","param_name":pname,"sample_value":pval_str,"id_type":id_type})
            elif _NUMERIC_RE.match(pval_str):
                seen.add(pname)
                targets.append({"location":"param","param_name":pname,"sample_value":pval_str,"id_type":"numeric_value"})
        return targets

    def score_endpoint(self, ep):
        parsed  = urllib.parse.urlparse(ep["url"])
        targets = self._path_targets(parsed.path) + self._param_targets(ep.get("params",{}))
        priority = set(ep.get("priority_params") or [])
        if priority:
            for t in targets:
                if t["location"] == "param" and t["param_name"] in priority:
                    if t["id_type"] == "param_name_signal": t["id_type"] = "numeric"
        if not targets: return 0, []
        high_count = sum(1 for t in targets if t["id_type"] in ("numeric","uuid","slug"))
        score = 3 if high_count >= 2 else 2 if high_count == 1 else 1
        return score, targets

    def analyse(self, endpoints):
        scored = []
        for ep in endpoints:
            score, targets = self.score_endpoint(ep)
            if score > 0: scored.append((score, ep, targets))
        scored.sort(key=lambda x: -x[0])
        return scored

# ══════════════════════════════════════════════════════════════════════
# ID GENERATOR
# ══════════════════════════════════════════════════════════════════════

class IDGenerator:
    def neighbours(self, id_val, id_type, n=5):
        candidates = []
        if id_type == "numeric" and _NUMERIC_RE.match(id_val):
            base = int(id_val)
            for delta in range(1, n+1):
                if base - delta > 0: candidates.append(str(base - delta))
                candidates.append(str(base + delta))
            for anchor in ("1","2","100","1000","9999"):
                if anchor != id_val: candidates.append(anchor)
        elif id_type == "uuid" and _UUID_RE.match(id_val):
            parts = id_val.lower().split("-")
            for _ in range(n):
                last = "".join(random.choices("0123456789abcdef", k=len(parts[-1])))
                candidates.append("-".join(parts[:-1] + [last]))
            candidates += ["00000000-0000-0000-0000-000000000001",
                           "00000000-0000-0000-0000-000000000002"]
        elif id_type in ("slug","param_name_signal"):
            candidates.extend(["admin","test","guest","user1","user2",id_val+"1",id_val+"2"])
        else:
            try:
                base = int(id_val)
                for delta in range(1, n+1):
                    if base - delta > 0: candidates.append(str(base - delta))
                    candidates.append(str(base + delta))
            except ValueError: pass
        seen = {id_val}; out = []
        for c in candidates:
            if c not in seen: seen.add(c); out.append(c)
        return out

# ══════════════════════════════════════════════════════════════════════
# RESPONSE ANALYSER — 8 signals
# ══════════════════════════════════════════════════════════════════════

class ResponseAnalyser:
    _DENY_BODY_RE = re.compile(
        r'\b(?:forbidden|unauthorized|access\s+denied|not\s+authorized'
        r'|permission\s+denied|not\s+allowed|invalid\s+token'
        r'|session\s+expired|please\s+log\s+in|authentication\s+required)\b', re.I)

    _SENSITIVE_PLAINTEXT_RE = re.compile(
        r'\b(?:secret_token|auth_token|access_token|api_key|private_key'
        r'|btc_address|xmr_address|eth_address|wallet_address'
        r'|pgp_key|pgp.{0,5}block|begin.{0,5}pgp'
        r'|credit_card|card_number|cvv|ssn|passport'
        r'|password_hash|passwd|bcrypt|sha256.*:.*[a-f0-9]{32}'
        r'|admin_token|session_secret|signing_key)\b', re.I)

    def is_access_denied(self, resp):
        status = resp.get("status", 0)
        body   = (resp.get("body","") or "")[:2000]
        loc    = resp.get("headers",{}).get("location","")
        if status in (401, 403): return True
        if status in range(301,310) and re.search(r'login|signin|auth', loc, re.I): return True
        if status == 200 and self._DENY_BODY_RE.search(body): return True
        return False

    def has_sensitive_data(self, body):
        sample = body[:8000]
        return bool(_SENSITIVE_KEYS_RE.search(sample) or self._SENSITIVE_PLAINTEXT_RE.search(sample))

    def _json_keys(self, body):
        return set(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})"\s*:', body[:4000]))

    def _html_sensitive_tokens(self, body):
        tokens = set()
        tok_re = re.compile(
            r'(?:token|secret|api.?key|auth|wallet|btc|xmr|eth)[^:=>\n]{0,30}[:=>\s]+([a-zA-Z0-9_\-]{16,80})',
            re.I)
        for m in tok_re.finditer(body[:8000]): tokens.add(m.group(1))
        if re.search(r'BEGIN PGP', body, re.I): tokens.add("__pgp_key_present__")
        return tokens

    def _extract_sensitive_values(self, body):
        values = set()
        if not body: return values
        try: obj = json.loads(body[:16000])
        except Exception: return values
        _SF_RE = re.compile(
            r'^(?:email|phone|mobile|password|token|secret|api_key|private_key'
            r'|ssn|passport|credit_card|card_number|iban|salary'
            r'|auth_token|access_token|session_token|totp_secret|totpSecret'
            r'|role|admin|permission|scope|balance|wallet'
            r'|first_name|last_name|full_name|username|address|dob)$', re.I)
        def _recurse(o, depth=0):
            if depth > 4: return
            if isinstance(o, dict):
                for k, v in o.items():
                    if _SF_RE.match(str(k)):
                        if isinstance(v, str) and len(v) > 3: values.add(v)
                        elif isinstance(v, (int,float)) and v != 0: values.add(str(v))
                    if isinstance(v, (dict,list)): _recurse(v, depth+1)
            elif isinstance(o, list):
                for item in o[:10]: _recurse(item, depth+1)
        _recurse(obj)
        return values

    def compare(self, user_a_resp, user_b_own_resp, tampered_resp):
        if self.is_access_denied(tampered_resp):
            return False, None, "Access denied — properly protected"
        t_status = tampered_resp.get("status", 0)
        t_body   = (tampered_resp.get("body","") or "")
        if t_status == 0 or not t_body: return False, None, "No response / connection error"
        if t_status not in range(200,210): return False, None, f"Non-2xx status {t_status}"

        a_body = (user_a_resp or {}).get("body","") or ""
        b_body = (user_b_own_resp or {}).get("body","") or ""
        a_keys = self._json_keys(a_body); b_keys = self._json_keys(b_body); t_keys = self._json_keys(t_body)
        evidence = []

        # S1: sensitive data keys
        if self.has_sensitive_data(t_body): evidence.append("sensitive_data_keys_in_response")
        # S2: structure matches User A
        if a_keys and t_keys:
            a_overlap = len(a_keys & t_keys); b_overlap = len(b_keys & t_keys) if b_keys else 0
            if a_overlap >= 3 and a_overlap > b_overlap: evidence.append("response_structure_matches_user_a")
        # S3: body length within 15% of A (only with S1 or S2)
        if a_body and len(a_body) > 20:
            ratio = abs(len(t_body) - len(a_body)) / len(a_body)
            if ratio < 0.15 and ("sensitive_data_keys_in_response" in evidence or
                                  "response_structure_matches_user_a" in evidence):
                evidence.append("body_length_consistent_with_user_a_resource")
        # S4: differs from B baseline
        if b_body and t_body.strip() != b_body.strip(): evidence.append("response_differs_from_user_b_baseline")
        # S5: non-trivial body
        if len(t_body.strip()) > 20: evidence.append("non_trivial_response_body")
        # S6: unauth sensitive data
        is_unauth_probe = not b_body or len(b_body.strip()) < 30
        if is_unauth_probe and self.has_sensitive_data(t_body) and len(t_body.strip()) > 30:
            evidence.append("no_auth_sensitive_data_exposed")
        # S7: HTML token differential
        t_tokens = self._html_sensitive_tokens(t_body)
        a_tokens = self._html_sensitive_tokens(a_body) if a_body else set()
        b_tokens = self._html_sensitive_tokens(b_body) if b_body else set()
        if t_tokens:
            leaked = t_tokens - b_tokens
            if leaked and (not a_body or (a_tokens & leaked)):
                evidence.append("html_sensitive_tokens_exposed")
        # S8: value-level leak
        if a_body and t_body:
            a_values = self._extract_sensitive_values(a_body)
            t_values = self._extract_sensitive_values(t_body)
            b_values = self._extract_sensitive_values(b_body) if b_body else set()
            if (a_values & t_values) - b_values: evidence.append("user_a_field_values_in_tampered_response")

        if not evidence: return False, None, "No IDOR signals detected"

        has_a = bool(a_body and len(a_body) > 20)
        has_b = bool(b_body and len(b_body) > 20)
        if "no_auth_sensitive_data_exposed" in evidence: qual = True
        elif "html_sensitive_tokens_exposed" in evidence: qual = True
        elif "user_a_field_values_in_tampered_response" in evidence: qual = True
        elif has_a and has_b:
            qual = ("sensitive_data_keys_in_response" in evidence or
                    ("response_structure_matches_user_a" in evidence and
                     "body_length_consistent_with_user_a_resource" in evidence))
        elif has_a:
            qual = ("sensitive_data_keys_in_response" in evidence or
                    "response_structure_matches_user_a" in evidence or
                    "body_length_consistent_with_user_a_resource" in evidence)
        else:
            qual = "sensitive_data_keys_in_response" in evidence

        if not qual: return False, None, "Signals present but insufficient confidence"
        confidence = ("HIGH" if len(evidence) >= 3 else "MEDIUM" if len(evidence) == 2 else "LOW")
        return True, confidence, " | ".join(evidence)

# ══════════════════════════════════════════════════════════════════════
# ID HARVEST PASS
# ══════════════════════════════════════════════════════════════════════

class IDHarvestPass:
    def __init__(self, client_a, targets, threads=8, delay=0, client_b=None):
        self.client_a  = client_a; self.client_b = client_b
        self.targets   = targets;  self.threads  = threads
        self.delay     = delay;    self._lock    = threading.Lock()
        self.id_hints  = [];       self.child_urls = []

    def _mine(self, ep, idor_targets):
        if self.delay: time.sleep(self.delay)
        try:
            if ep["method"] == "GET": resp = self.client_a.get(ep["url"], ep.get("params") or {})
            else:                     resp = self.client_a.post(ep["url"], ep.get("params") or {})
        except Exception: return
        body = resp.get("body","") or ""
        if resp.get("status",0) == 0 or not body: return
        new_hints = []
        if body.strip().startswith(("{","[")):
            try:
                obj = json.loads(body)
                self._recurse(obj, ep["url"], new_hints, 0, owner="user_a")
            except Exception: pass
        loc = resp.get("headers",{}).get("location","") or ""
        if loc:
            for m in _PATH_NUMERIC_RE.finditer(urllib.parse.urlparse(loc).path):
                new_hints.append({"id_val":m.group(1),"id_type":"numeric",
                                   "id_source":"harvest:redirect_path","context_url":ep["url"],"owner":"user_a"})
        for t in idor_targets:
            val = t["sample_value"]
            if t["id_type"] == "numeric" and _NUMERIC_RE.match(val):
                new_hints.append({"id_val":val,"id_type":"numeric",
                                   "id_source":"harvest:surface_target","context_url":ep["url"],"owner":"unknown"})
            elif t["id_type"] == "uuid" and _UUID_RE.match(val):
                new_hints.append({"id_val":val,"id_type":"uuid",
                                   "id_source":"harvest:surface_target","context_url":ep["url"],"owner":"unknown"})
        with self._lock: self.id_hints.extend(new_hints)

    def _derive_get_child_urls(self):
        if not self.id_hints: return
        url_hints = defaultdict(list)
        for h in self.id_hints:
            ctx = h.get("context_url","")
            if ctx: url_hints[ctx].append(h)
        seen_child_urls = {c["url"] for c in self.child_urls}
        _OWNERSHIP_PATH_RE = re.compile(
            r'(?:user|account|profile|basket|cart|order|wallet|address'
            r'|card|complaint|invoice|subscription|session|notification'
            r'|message|inbox|ticket|payment|transaction|delivery'
            r'|security|auth|2fa|totp|mfa|password|token|key'
            r'|membership|privilege|role|permission|wishlist|favourite|favorite'
            r'|history|activity|log|audit|setting|preference|config)', re.I)
        for ctx_url, hints in url_hints.items():
            parsed   = urllib.parse.urlparse(ctx_url)
            last_seg = parsed.path.rstrip("/").rsplit("/",1)[-1]
            if _NUMERIC_RE.match(last_seg) or _UUID_RE.match(last_seg): continue
            if not _OWNERSHIP_PATH_RE.search(parsed.path):
                try:
                    bare_resp = HTTPClient(timeout=8).get(ctx_url, {})
                    if bare_resp.get("status",0) in range(200,210): continue
                except Exception: pass
            _is_public = False
            try:
                a_resp = self.client_a.get(ctx_url, {})
                b_resp = self.client_b.get(ctx_url, {}) if self.client_b else None
                if b_resp:
                    a_body = (a_resp.get("body","") or "").strip()
                    b_body = (b_resp.get("body","") or "").strip()
                    a_st   = a_resp.get("status",0); b_st = b_resp.get("status",0)
                    if (a_st in range(200,210) and b_st in range(200,210)
                            and a_body and b_body and a_body == b_body
                            and not ResponseAnalyser().has_sensitive_data(a_body)):
                        _is_public = True
                    elif a_st not in range(200,210) and a_st == b_st:
                        _is_public = True
            except Exception: _is_public = True
            if _is_public: continue
            base = ctx_url.rstrip("/")
            for h in hints:
                child_url = f"{base}/{h['id_val']}"
                if child_url in seen_child_urls: continue
                seen_child_urls.add(child_url)
                self.child_urls.append({"url":child_url,"method":"GET","id_val":h["id_val"],
                                         "id_type":h["id_type"],"owner":h.get("owner","unknown"),
                                         "source":f"get_harvest:{ctx_url}"})

    def _mine_post(self, ep):
        if self.delay: time.sleep(self.delay)
        try:
            resp = self.client_a.post(ep["url"], ep.get("params") or {}, "json")
            if resp.get("status",0) in (400,415,422):
                resp = self.client_a.post(ep["url"], ep.get("params") or {})
        except Exception: return
        body = resp.get("body","") or ""
        if resp.get("status",0) not in range(200,210) or not body: return
        new_hints = []
        try:
            obj = json.loads(body)
            self._recurse(obj, ep["url"], new_hints, 0, owner="user_a")
        except Exception: pass
        with self._lock:
            self.id_hints.extend(new_hints)
            for h in new_hints:
                child_url = ep["url"].rstrip("/") + "/" + h["id_val"]
                self.child_urls.append({"url":child_url,"method":"GET","id_val":h["id_val"],
                                         "id_type":h["id_type"],"owner":"user_a",
                                         "source":f"post_creation:{ep['url']}"})

    def _recurse(self, obj, ctx, out, depth, owner="unknown"):
        if depth > 5: return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _IDOR_PARAM_NAME_RE.match(str(k)):
                    val = str(v) if v is not None else ""
                    if   _NUMERIC_RE.match(val): out.append({"id_val":val,"id_type":"numeric","id_source":f"harvest:json:{k}","context_url":ctx,"owner":owner})
                    elif _UUID_RE.match(val):    out.append({"id_val":val,"id_type":"uuid","id_source":f"harvest:json:{k}","context_url":ctx,"owner":owner})
                if isinstance(v, (dict,list)): self._recurse(v, ctx, out, depth+1, owner)
        elif isinstance(obj, list):
            for item in obj[:20]: self._recurse(item, ctx, out, depth+1, owner)

    def run(self):
        if not self.targets: return []
        tprint(f"\n  {info(f'ID harvest: fetching {len(self.targets)} endpoints as User A...')}")
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = [pool.submit(self._mine, ep, tgts) for _, ep, tgts in self.targets]
            for f in as_completed(futs):
                try: f.result()
                except: pass
        self._derive_get_child_urls()
        if self.child_urls:
            tprint(f"  {ok(f'Derived {len(self.child_urls)} child URL(s) from GET harvest IDs')}")
        post_eps = [ep for _, ep, _ in self.targets if ep["method"] == "POST"]
        if post_eps:
            with ThreadPoolExecutor(max_workers=min(4, self.threads)) as pool:
                futs = [pool.submit(self._mine_post, ep) for ep in post_eps]
                for f in as_completed(futs):
                    try: f.result()
                    except: pass

        seen = set(); deduped = []
        for h in self.id_hints:
            k = (h["id_val"], h["id_type"])
            if k not in seen: seen.add(k); deduped.append(h)
        self.id_hints = deduped

        # Session page harvest for User A's own ID
        if self.targets:
            base   = urllib.parse.urlparse(self.targets[0][1]["url"])
            base_url = f"{base.scheme}://{base.netloc}"
            own_found = False
            for page_path in ["/settings","/account/settings","/user/settings",
                               "/profile/edit","/account/edit","/account",
                               "/me","/my-account","/my-profile","/dashboard","/home",
                               "/notifications","/inbox","/api/settings","/api/account",
                               "/api/profile","/api/me"]:
                if own_found: break
                try:
                    resp = self.client_a.get(base_url + page_path)
                    if resp["status"] not in (200,201): continue
                    body = resp.get("body","") or ""
                    if len(body) < 50: continue
                    page_hints = []
                    if body.strip().startswith(("{","[")):
                        try:
                            obj = json.loads(body)
                            self._recurse(obj, base_url + page_path, page_hints, 0, owner="user_a")
                        except Exception: pass
                    for pat in [
                        re.compile(r'data-(?:user-?id|uid|profile-?id|author-?id)\s*=\s*["\'](\d{1,8})["\']', re.I),
                        re.compile(r'(?:user_?id|userId|uid|profile_?id|currentUser\.id)\s*[=:]\s*["\']?(\d{1,8})["\']?', re.I),
                        re.compile(r'<input[^>]+name=["\'](?:user_id|uid|profile_id|author_id)["\'][^>]*value=["\'](\d{1,8})["\']', re.I),
                    ]:
                        for m in pat.finditer(body[:16000]):
                            val = m.group(1)
                            if val and int(val) > 0:
                                page_hints.append({"id_val":val,"id_type":"numeric",
                                                    "id_source":f"harvest:session_page:{page_path}",
                                                    "context_url":base_url+page_path})
                    if page_hints:
                        seen_vals = {h["id_val"] for h in self.id_hints}
                        new = [h for h in page_hints if h["id_val"] not in seen_vals]
                        if new: self.id_hints.extend(new); own_found = True
                except Exception: pass

        tprint(f"  {ok(f'ID harvest complete — {len(self.id_hints)} unique ID(s)')}")
        return self.id_hints

# ══════════════════════════════════════════════════════════════════════
# IDOR TESTER
# ══════════════════════════════════════════════════════════════════════

class IDORTester:
    def __init__(self, client_a, client_b, client_unauth, targets, id_hints,
                 child_urls=None, threads=6, delay=0, test_unauth=True,
                 write_probe=False, single_session=False):
        self.client_a       = client_a;    self.client_b      = client_b
        self.client_unauth  = client_unauth; self.targets     = targets
        self.id_hints       = id_hints;    self.child_urls    = child_urls or []
        self.threads        = threads;     self.delay         = delay
        self.test_unauth    = test_unauth; self.write_probe   = write_probe
        self.single_session = single_session
        self.findings       = [];          self._seen_findings = set()
        self._lock          = threading.Lock()
        self._id_gen        = IDGenerator(); self._analyser    = ResponseAnalyser()

    def _sleep(self):
        if self.delay: time.sleep(self.delay)

    def _fetch(self, client, ep, params_override=None):
        url    = ep["url"]; method = ep["method"]
        params = params_override if params_override is not None else ep.get("params",{})
        self._sleep()
        if method == "GET": return client.get(url, params)
        explicit_ct = ep.get("content_type")
        if explicit_ct: return client.post(url, params, explicit_ct)
        source = (ep.get("source","") or "").lower()
        if "json" in source or source.startswith("js:") or "api" in source:
            resp = client.post(url, params, "json")
            if resp.get("status",0) in (400,415,422): return client.post(url, params, None)
            return resp
        return client.post(url, params, None)

    def _substitute_path(self, url, old_seg, new_seg):
        parsed   = urllib.parse.urlparse(url)
        new_path = re.sub(r'(/)' + re.escape(str(old_seg)) + r'(/|$)',
                          r'\g<1>' + str(new_seg) + r'\g<2>', parsed.path, count=1)
        return parsed._replace(path=new_path).geturl()

    def _record_finding(self, finding):
        key = (finding["url"], finding.get("param_name"), finding["tampered_id"])
        cluster_key = None
        if (finding.get("location") == "path"
                and finding.get("source","").startswith("get_harvest:")
                and finding.get("finding_type") == "path_idor"):
            base = re.sub(r'/[^/]+$', '', finding["url"])
            cluster_key = f"child_cluster:{base}:path_idor"
        with self._lock:
            if key in self._seen_findings: return False
            if cluster_key and cluster_key in self._seen_findings: return False
            self._seen_findings.add(key)
            if cluster_key: self._seen_findings.add(cluster_key)
            self.findings.append(finding)
            return True

    def _build_candidates(self, orig_val, id_type, n=6):
        user_a_vals = []; other_vals = []
        for hint in self.id_hints:
            if hint["id_type"] != id_type or hint["id_val"] == orig_val: continue
            if hint.get("owner") == "user_a":
                if hint["id_val"] not in user_a_vals: user_a_vals.append(hint["id_val"])
            else:
                if hint["id_val"] not in other_vals:  other_vals.append(hint["id_val"])
        gen_count = n if id_type == "numeric" else max(n, 10)
        gen  = self._id_gen.neighbours(orig_val, id_type, n=gen_count)
        seen = {orig_val}; out = []
        for val in user_a_vals + other_vals + gen:
            if val not in seen: seen.add(val); out.append(val)
        return out[:30 if id_type == "numeric" else 20]

    def _test_one(self, score, ep, idor_targets):
        url = ep["url"]; method = ep["method"]
        if method in ("PUT","PATCH","DELETE") and not self.write_probe: return
        _parsed_url = urllib.parse.urlparse(url)
        if re.search(r'\.(bak|pyc|yml|yaml|json|xml|txt|md|log|cfg|conf|env|key|pem|crt|sql|gz|tar|zip|js|css|map)$', _parsed_url.path, re.I): return
        if re.search(r'socket\.io|websocket|ws://', url, re.I): return

        a_resp = self._fetch(self.client_a, ep)
        b_resp = self._fetch(self.client_b, ep)
        a_status = a_resp.get("status",0); b_status = b_resp.get("status",0)

        if (a_status not in range(200,210) and b_status not in range(200,210) and a_status == b_status):
            return
        if a_status in range(200,210) and b_status in range(200,210):
            a_body = (a_resp.get("body","") or "").strip()
            b_body = (b_resp.get("body","") or "").strip()
            if a_body and b_body and a_body == b_body and not self._analyser.has_sensitive_data(a_body):
                return

        _zero_streak = 0
        for target in idor_targets:
            loc = target["location"]; pname = target["param_name"]
            orig_val = target["sample_value"]; id_type = target["id_type"]
            candidates = self._build_candidates(orig_val, id_type)
            for tampered_id in candidates:
                if loc == "path":
                    t_url = self._substitute_path(url, orig_val, tampered_id)
                    t_ep  = {**ep, "url": t_url}; t_params = ep.get("params",{})
                else:
                    t_url = url; t_params = {**ep.get("params",{}), pname: tampered_id}
                    t_ep  = ep
                b_tampered = self._fetch(self.client_b, t_ep, t_params)
                if b_tampered.get("status",0) == 0:
                    _zero_streak += 1
                    if _zero_streak >= 3: break
                else: _zero_streak = 0
                a_tampered = self._fetch(self.client_a, t_ep, t_params)
                is_idor, conf, evidence = self._analyser.compare(a_tampered, b_resp, b_tampered)

                # Fix #7: numeric_value confidence penalty
                if (is_idor and id_type == "numeric_value" and conf == "HIGH"
                        and "sensitive_data_keys_in_response" not in evidence
                        and "user_a_field_values_in_tampered_response" not in evidence):
                    conf = "MEDIUM"; evidence = evidence + " | [penalized:numeric_value_type]"

                vprint(f"    [test] {method} {t_url}  b={b_tampered.get('status')} a={a_tampered.get('status')}  idor={is_idor}")
                if is_idor:
                    is_synthetic = bool(ep.get("synthetic_params"))
                    _evidence = evidence
                    param_effective = True
                    if is_synthetic and pname:
                        if b_tampered.get("status",0) == 0:
                            param_effective = False
                        else:
                            param_effective = self._param_is_effective(self.client_b, ep, pname, b_tampered)
                        _evidence += " | [param_not_observed:synthetic_spider_hint]"
                        if not param_effective: _evidence += " | [param_ignored_by_server:session_level_bac]"
                    if loc == "path": finding_type = "path_idor"
                    elif is_synthetic or not param_effective: finding_type = "session_isolation_bypass"
                    elif pname and not any(pname.endswith(s) for s in ("_id","Id","ID","uuid","guid")) and id_type == "numeric_value":
                        finding_type = "session_isolation_bypass"
                    else: finding_type = "param_idor"

                    _poc_label, _poc_cmd = self._build_poc_curl(t_url, method,
                        params=t_params if loc != "path" else None,
                        param_name=pname if loc != "path" else None,
                        tampered_id=tampered_id if loc != "path" else None)
                    finding = {
                        "url": t_url, "method": method, "location": loc,
                        "param_name": pname, "original_id": orig_val, "tampered_id": tampered_id,
                        "id_type": id_type, "finding_type": finding_type, "confidence": conf,
                        "evidence": _evidence, "status": b_tampered.get("status"),
                        "body_snippet": (b_tampered.get("body","") or "")[:300],
                        "source": ep.get("source",""), "session": "User B",
                        "poc_curl": _poc_cmd, "poc_session_label": _poc_label,
                        "severity": ("CRITICAL" if "unauthenticated" in _evidence.lower()
                                     else "High" if conf == "HIGH" else "Medium" if conf == "MEDIUM" else "Low"),
                        "vuln_type": "IDOR",
                    }
                    if self._record_finding(finding):
                        self._print_hit(finding)
                        break
                    if self.test_unauth and self.client_unauth:
                        unauth_resp = self._fetch(self.client_unauth, t_ep, t_params)
                        is_ua, ua_conf, ua_ev = self._analyser.compare(a_tampered, {}, unauth_resp)
                        if is_ua:
                            ua_finding = {**finding, "confidence": ua_conf,
                                          "evidence": ua_ev + " | UNAUTHENTICATED",
                                          "status": unauth_resp.get("status"),
                                          "body_snippet": (unauth_resp.get("body","") or "")[:300],
                                          "session": "unauthenticated", "severity": "CRITICAL"}
                            if self._record_finding(ua_finding):
                                tprint(f"\n  {found(color(f'[UNAUTH][{ua_conf}]  {method} {t_url}', C.BRED, C.BOLD))}")
                                tprint(f"    {color('⚠ Endpoint accessible with NO session!', C.BRED, C.BOLD)}")

    def _test_child_urls(self):
        if not self.child_urls: return
        tprint(f"\n  {info(f'Testing {len(self.child_urls)} ownership-based child URLs...')}")
        for child in self.child_urls:
            t_url = child["url"]; method = child.get("method","GET")
            id_val = child["id_val"]; id_type = child["id_type"]
            t_ep  = {"url":t_url,"method":method,"params":{},"source":child["source"],"synthetic_params":False}
            try:
                a_resp = self._fetch(self.client_a, t_ep)
                b_resp = self._fetch(self.client_b, t_ep)
                is_idor, conf, evidence = self._analyser.compare(a_resp, {}, b_resp)
                vprint(f"    [child] {method} {t_url}  a={a_resp.get('status')} b={b_resp.get('status')}  idor={is_idor}")
                if is_idor:
                    _poc_label, _poc_cmd = self._build_poc_curl(t_url, method)
                    finding = {
                        "url": t_url, "method": method, "location": "path",
                        "param_name": None, "original_id": id_val, "tampered_id": id_val,
                        "id_type": id_type, "finding_type": "path_idor", "confidence": conf,
                        "evidence": evidence + (" | [ownership:get_harvest_derived]"
                            if child["source"].startswith("get_harvest:") else " | [ownership:user_a_created_resource]"),
                        "status": b_resp.get("status"),
                        "body_snippet": (b_resp.get("body","") or "")[:300],
                        "source": child["source"], "session": "User B",
                        "poc_curl": _poc_cmd, "poc_session_label": _poc_label,
                        "severity": "High" if conf == "HIGH" else "Medium" if conf == "MEDIUM" else "Low",
                        "vuln_type": "IDOR",
                    }
                    if self._record_finding(finding): self._print_hit(finding)
            except Exception: pass

    def _param_is_effective(self, client, ep, pname, b_tampered):
        try:
            clean_ep  = {**ep, "params": {k:v for k,v in (ep.get("params") or {}).items() if k != pname}}
            base_resp = self._fetch(client, clean_ep)
            return (base_resp.get("body") or "").strip() != (b_tampered.get("body") or "").strip()
        except Exception: return True

    def _build_poc_curl(self, url, method, params=None, param_name=None, tampered_id=None):
        auth_client   = self.client_a if self.single_session else self.client_b
        session_label = "User A" if self.single_session else "User B"
        auth_part = ""
        try:
            hdrs = getattr(auth_client,"headers",{}) or {}
            if hdrs.get("Cookie"):         auth_part = f" -H 'Cookie: {hdrs['Cookie']}'"
            elif hdrs.get("Authorization"): auth_part = f" -H 'Authorization: {hdrs['Authorization']}'"
        except Exception:
            auth_part = f" -H 'Cookie: <{session_label.lower().replace(' ','-')}-token>'"
        if params and param_name and tampered_id:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param_name}={tampered_id}"
        else:
            test_url = url
        method_part = "" if method == "GET" else f" -X {method}"
        return session_label, f"curl -sk{method_part}{auth_part} '{test_url}'"

    def _print_hit(self, f):
        conf_col = C.BRED if f["confidence"] == "HIGH" else C.BYELLOW
        _conf = f["confidence"]; _meth = f["method"]; _url = f["url"]
        tprint(f"\n  {found(color(f'[{_conf}]  {_meth} {_url}', conf_col, C.BOLD))}")
        _loc  = f["location"]; _pname = f["param_name"] or "(path segment)"
        _orig = f["original_id"]; _tamp = f["tampered_id"]
        tprint(f"    {color('Location:', C.BYELLOW)} {_loc}  "
               f"{color('Param:', C.BYELLOW)} {_pname}  "
               f"{color('Original:', C.BYELLOW)} {_orig}  "
               f"{color('Tampered:', C.BRED)} {_tamp}")
        tprint(f"    {color('Evidence:', C.BYELLOW)} {f['evidence']}")
        snippet = (f.get("body_snippet") or "").replace("\n"," ")[:200]
        if snippet: tprint(f"    {color('Snippet:', C.DIM)} {snippet}")

    def _unauth_one(self, score, ep, idor_targets):
        ra = self._analyser; method = ep["method"]
        if method in ("PUT","PATCH","DELETE") and not self.write_probe: return
        for t_ep, t_params, t_url, orig_val, tampered_id, pname, loc, id_type in self._all_param_variants(ep, idor_targets):
            if self.delay: time.sleep(self.delay)
            try:
                ua_resp = self._fetch(self.client_unauth, t_ep, t_params)
                body = ua_resp.get("body","") or ""; status = ua_resp.get("status",0)
                if status not in range(200,210) or not body: continue
                if ra.is_access_denied(ua_resp): continue
                if not ra.has_sensitive_data(body): continue
                a_base = self._fetch(self.client_a, ep); b_base = self._fetch(self.client_b, ep)
                is_likely_public = (
                    a_base.get("status") in range(200,210) and b_base.get("status") in range(200,210)
                    and ra.has_sensitive_data(a_base.get("body","") or "")
                    and ra.has_sensitive_data(b_base.get("body","") or ""))
                finding = {
                    "method": method, "url": t_url, "location": loc, "param_name": pname,
                    "original_id": orig_val, "tampered_id": tampered_id, "id_type": id_type,
                    "confidence": "MEDIUM" if is_likely_public else "HIGH",
                    "evidence": ("no_auth_required | sensitive_data_in_response | possibly_intentional_public_endpoint"
                                 if is_likely_public else "no_auth_required | sensitive_data_in_response"),
                    "status": status, "body_snippet": body[:300], "source": ep.get("source",""),
                    "session": "unauthenticated", "severity": "CRITICAL", "vuln_type": "IDOR",
                    "poc_curl": f"curl -sk '{t_url}'", "poc_session_label": "No Session",
                }
                if self._record_finding(finding):
                    _uconf = finding["confidence"]
                    tprint(f"\n  {found(color(f'[UNAUTH][{_uconf}]  {method} {t_url}', C.BRED, C.BOLD))}")
                    tprint(f"    {color('Sensitive data returned with NO session!', C.BRED, C.BOLD)}")
                    break
            except Exception: pass

    def _all_param_variants(self, ep, idor_targets):
        variants = []; url = ep["url"]
        for target in idor_targets:
            loc = target["location"]; pname = target.get("param_name")
            orig_val = target["sample_value"]; id_type = target["id_type"]
            for tampered_id in self._build_candidates(orig_val, id_type):
                if loc == "path":
                    t_url = self._substitute_path(url, orig_val, tampered_id)
                    t_ep  = {**ep, "url": t_url}; t_params = ep.get("params") or {}
                else:
                    t_url = url; t_ep = ep
                    t_params = {**(ep.get("params") or {}), pname: tampered_id}
                variants.append((t_ep, t_params, t_url, orig_val, tampered_id, pname, loc, id_type))
        return variants

    def run(self):
        if not self.targets:
            tprint(f"  {warn('No IDOR surface found.')}")
            return []
        total = len(self.targets)
        tprint(f"\n  {info(f'Testing {total} IDOR-candidate endpoints...')}\n")
        if self.single_session:
            tprint(f"  {warn('Single-session mode — comparing User A vs unauthenticated baseline.')}")

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = {pool.submit(self._test_one, s, ep, tgts): ep["url"]
                    for s, ep, tgts in self.targets}
            _per_ep_budget = (self.threads + 1) * 30
            try:
                for fut in as_completed(futs, timeout=_per_ep_budget * total):
                    try: fut.result(timeout=_per_ep_budget)
                    except TimeoutError: pass
                    except Exception as ex:
                        if "_zero_streak" not in str(ex): vprint(f"  {warn(f'Worker error: {ex}')}")
            except Exception: pass

        if self.test_unauth and self.client_unauth:
            tprint(f"\n  {info('Unauth scan pass...')}")
            with ThreadPoolExecutor(max_workers=self.threads) as _upool:
                _ufuts = {_upool.submit(self._unauth_one, s, ep, tgts): ep["url"]
                          for s, ep, tgts in self.targets}
                try:
                    for _uf in as_completed(_ufuts, timeout=max(60, self.threads*20)):
                        try: _uf.result(timeout=30)
                        except Exception: pass
                except Exception: pass

        self._test_child_urls()
        return self.findings

# ══════════════════════════════════════════════════════════════════════
# SPIDER BRIDGE
# ══════════════════════════════════════════════════════════════════════

class SpiderBridge:
    _BUCKET_ORDER     = ["runtime","query","openapi","js","form"]
    _PRIORITY_BUCKETS = {"runtime","query"}
    _STRIP_SFX        = re.compile(r'^(.+?)(?:_raw|_sanitized|_input|_clean|_safe|_encoded|_value)$', re.I)
    _AUTH_RE          = re.compile(r'(?:password|passwd|pass|token|csrf|secret|auth)', re.I)

    def _strip(self, name):
        m = self._STRIP_SFX.match(str(name).strip())
        return m.group(1) if m else str(name).strip()

    def load(self, filepath_or_dict, cli_target=None):
        """Load from filepath (str) or pre-parsed dict. Returns (target, endpoints)."""
        if isinstance(filepath_or_dict, dict):
            raw = filepath_or_dict
        else:
            try:
                with open(filepath_or_dict, encoding="utf-8") as fh:
                    raw = json.load(fh)
            except FileNotFoundError:
                raise RuntimeError(f"Spider file not found: {filepath_or_dict}")
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Spider JSON parse error: {e}")

        if isinstance(raw, dict):
            file_target = raw.get("target") or raw.get("base_url") or raw.get("url") or ""
            entries     = raw.get("endpoints") or raw.get("urls") or raw.get("results") or []
        elif isinstance(raw, list):
            file_target = ""; entries = raw
        else:
            raise RuntimeError("Spider JSON: unrecognised structure")

        target     = cli_target or file_target or ""
        if target and not target.startswith(("http://","https://")):
            target = "http://" + target
        cli_parsed  = urllib.parse.urlparse(target) if target else None
        file_parsed = urllib.parse.urlparse(file_target) if file_target else None
        endpoints   = []; n_confirmed = 0; n_priority = 0

        for entry in entries:
            if not isinstance(entry, dict): continue
            ep_url = (entry.get("url") or entry.get("endpoint") or "").strip()
            if not ep_url: continue
            if not ep_url.startswith("http"):
                if target: ep_url = urllib.parse.urljoin(target.rstrip("/")+"/", ep_url.lstrip("/"))
                else: continue
            if cli_parsed and file_parsed and cli_parsed.netloc and cli_parsed.netloc != file_parsed.netloc:
                ep_parsed = urllib.parse.urlparse(ep_url)
                ep_url    = urllib.parse.urlunparse((cli_parsed.scheme, cli_parsed.netloc,
                    ep_parsed.path, ep_parsed.params, ep_parsed.query, ""))

            raw_methods = entry.get("methods") or entry.get("method") or ["GET"]
            if isinstance(raw_methods, str): raw_methods = [raw_methods]
            method = str(raw_methods[0]).upper() if raw_methods else "GET"
            if method not in ("GET","POST","PUT","PATCH","DELETE"): method = "GET"
            if method in ("PUT","PATCH","DELETE"): method = "POST"

            obs = entry.get("observed_status") or 0
            if isinstance(obs, list): obs = obs[0] if obs else 0
            baseline = entry.get("baseline") or {}
            if not obs and isinstance(baseline, dict): obs = baseline.get("status") or 0
            try: obs_int = int(obs or 0)
            except: obs_int = 0
            if obs_int in (404,410,400): continue

            raw_params = entry.get("params") or {}
            params = {}; priority_params = []; id_hints_ep = []

            if isinstance(raw_params, dict):
                is_bucketed = any(isinstance(v, list) for v in raw_params.values())
                if is_bucketed:
                    for bucket in self._BUCKET_ORDER:
                        for pname in (raw_params.get(bucket) or []):
                            pk = self._strip(pname)
                            if not pk or (self._AUTH_RE.search(pk) and bucket == "form"): continue
                            if pk not in params: params[pk] = "test"
                            if bucket in self._PRIORITY_BUCKETS and pk not in priority_params:
                                priority_params.append(pk)
                    for bucket, plist in raw_params.items():
                        if bucket not in self._BUCKET_ORDER and isinstance(plist, list):
                            for pname in plist:
                                pk = self._strip(pname)
                                if pk and pk not in params: params[pk] = "test"
                else:
                    for pk, pv in raw_params.items():
                        pk = self._strip(pk)
                        if not pk or self._AUTH_RE.search(pk): continue
                        params[pk] = str(pv) if pv is not None else "test"
                        if _IDOR_PARAM_NAME_RE.match(pk):
                            priority_params.append(pk)
                            pv_str = str(pv) if pv else ""
                            if _NUMERIC_RE.match(pv_str) or _UUID_RE.match(pv_str):
                                id_hints_ep.append({"id_val":pv_str,
                                    "id_type":"numeric" if _NUMERIC_RE.match(pv_str) else "uuid",
                                    "id_source":f"spider:param:{pk}","context_url":ep_url})
            elif isinstance(raw_params, list):
                for item in raw_params:
                    pk = self._strip(str(item))
                    if pk and pk not in params:
                        params[pk] = "test"
                        if _IDOR_PARAM_NAME_RE.match(pk): priority_params.append(pk)

            # Synthesize IDOR hint for auth_required endpoints with no params
            is_auth_ep  = bool(entry.get("auth_required")) or bool(entry.get("parameter_sensitive"))
            has_path_id = bool(_PATH_NUMERIC_RE.search(urllib.parse.urlparse(ep_url).path) or
                               _PATH_UUID_RE.search(urllib.parse.urlparse(ep_url).path))
            ep_synthetic = False
            if is_auth_ep and not params and not has_path_id:
                last_seg = [s for s in urllib.parse.urlparse(ep_url).path.split("/") if s]
                if last_seg:
                    raw_seg = last_seg[-1].lower()
                    if (raw_seg.endswith("s") and not raw_seg.endswith("ss")
                            and not raw_seg.endswith("us") and not raw_seg.endswith("is")
                            and len(raw_seg) > 3):
                        seg = raw_seg[:-1]
                    else: seg = raw_seg
                    synth_param = f"{seg}_id"
                else: synth_param = "id"
                params[synth_param] = "1"; priority_params.append(synth_param); ep_synthetic = True

            # QS params from URL
            ep_parsed_qs = urllib.parse.urlparse(ep_url)
            qs_params    = urllib.parse.parse_qs(ep_parsed_qs.query, keep_blank_values=True)
            for pk, pvlist in qs_params.items():
                pk = self._strip(pk)
                if pk and pk not in params:
                    params[pk] = pvlist[0] if pvlist else "test"
                    if pk not in priority_params: priority_params.append(pk)
                pv_str = pvlist[0] if pvlist else ""
                if _IDOR_PARAM_NAME_RE.match(pk) and (_NUMERIC_RE.match(pv_str) or _UUID_RE.match(pv_str)):
                    id_hints_ep.append({"id_val":pv_str,
                        "id_type":"numeric" if _NUMERIC_RE.match(pv_str) else "uuid",
                        "id_source":f"spider:qs:{pk}","context_url":ep_url})
            ep_url = urllib.parse.urlunparse(ep_parsed_qs._replace(query="",fragment=""))

            # Path segment ID hints
            ep_path = urllib.parse.urlparse(ep_url).path
            for m in _PATH_NUMERIC_RE.finditer(ep_path):
                id_hints_ep.append({"id_val":m.group(1),"id_type":"numeric",
                                     "id_source":"spider:path_segment","context_url":ep_url})
            for m in _PATH_UUID_RE.finditer(ep_path):
                id_hints_ep.append({"id_val":m.group(1).lower(),"id_type":"uuid",
                                     "id_source":"spider:path_segment","context_url":ep_url})

            # Fallback params
            if not params:
                segs = [s for s in urllib.parse.urlparse(ep_url).path.split("/") if s
                        and not _NUMERIC_RE.match(s) and not _UUID_RE.match(s)]
                for seg in segs[-2:]:
                    seg_lo = seg.lower()
                    if (seg_lo.endswith("s") and not seg_lo.endswith(("ss","us","is")) and len(seg_lo) > 3):
                        seg_clean = seg_lo[:-1]
                    else: seg_clean = seg_lo
                    for suffix in ("_id","Id","ID"): params[seg_clean+suffix] = "test"
                if not params: params = {"id": "test"}

            response_sig = None
            if isinstance(baseline, dict): response_sig = baseline.get("hash") or None
            confirmed = bool(priority_params) or bool(entry.get("parameter_sensitive"))
            if confirmed: n_confirmed += 1
            n_priority += len(priority_params)

            endpoints.append({
                "url": ep_url, "method": method, "params": params, "hidden": {},
                "source": "spider_json", "synthetic_params": ep_synthetic,
                "priority_params": list(dict.fromkeys(priority_params)),
                "parameter_sensitive": bool(entry.get("parameter_sensitive")),
                "response_sig": response_sig, "discovered_via": entry.get("discovered_via") or None,
                "_spider_id_hints": id_hints_ep,
            })

        tprint(f"  {ok(f'Spider loaded — {len(endpoints)} endpoints, {n_confirmed} confirmed, {n_priority} priority params')}")
        return target, endpoints

    def export(self, crawler, target, filepath):
        export_eps = []
        for ep in crawler.endpoints:
            params_bucketed = {"query":[],"form":[],"runtime":[]}
            src = ep.get("source","") or ""
            for pname in (ep.get("priority_params") or []):
                params_bucketed["runtime"].append(pname)
            for pname in ep.get("params",{}):
                if pname in (ep.get("priority_params") or []): continue
                bucket = "query" if "url_query" in src else "form" if "form" in src else "js" if src.startswith("js:") else "query"
                if pname not in params_bucketed.get(bucket,[]): params_bucketed.setdefault(bucket,[]).append(pname)
            export_eps.append({"url":ep["url"],"methods":[ep["method"]],
                                "params":{k:v for k,v in params_bucketed.items() if v},
                                "parameter_sensitive":bool(ep.get("priority_params")),
                                "source":src,"discovered_via":ep.get("discovered_via")})
        payload = {"agent":"HELLHOUND-IDORdetector","version":VERSION,"target":target,"endpoints":export_eps,
                   "id_hints":[{"id_val":h["id_val"],"id_type":h["id_type"],
                                 "id_source":h["id_source"],"context_url":h["context_url"]}
                                for h in crawler.id_hints],
                   "crawl_stats":{"pages":len(crawler.visited),"js_files":len(crawler.js_visited),
                                   "endpoints":len(crawler.endpoints),"id_hints":len(crawler.id_hints)}}
        with open(filepath,"w") as fh: json.dump(payload, fh, indent=2, default=str)
        tprint(f"  {ok(f'Spider export saved → {filepath}  ({len(export_eps)} endpoints)')}")

# ══════════════════════════════════════════════════════════════════════
# SPIDER INTEL → IDOR ENDPOINT CONVERSION
# ══════════════════════════════════════════════════════════════════════

def _spider_intel_to_endpoints(intel, target):
    """Convert framework spider_intel dict → IDOR endpoint list via SpiderBridge."""
    bridge  = SpiderBridge()
    # Wrap as a SpiderBridge-compatible dict and call .load()
    wrapped = {"target": target, "endpoints": intel.get("endpoints", [])}
    try:
        _, endpoints = bridge.load(wrapped, cli_target=target)
        return endpoints
    except RuntimeError:
        return []

# ══════════════════════════════════════════════════════════════════════
# REPORT HELPER
# ══════════════════════════════════════════════════════════════════════

def _print_report(findings, target, stats, single_session=False):
    section("IDOR DETECTION REPORT")
    tprint(f"  {color('Target:', C.BYELLOW)} {target}")
    tprint(f"  {color('Timestamp:', C.BYELLOW)} {stats.get('timestamp','?')}")
    tprint(f"  {color('Endpoints:', C.BYELLOW)} {stats.get('endpoints','?')}  "
           f"{color('IDOR surface:', C.BYELLOW)} {stats.get('idor_surface','?')}  "
           f"{color('ID hints:', C.BYELLOW)} {stats.get('id_hints','?')}")
    tprint()
    if not findings:
        tprint(f"  {ok('No IDOR vulnerabilities confirmed.')}")
        return
    seen_ep = {}
    for f in findings:
        key = (f["url"].split("?")[0], f.get("param_name"), f.get("location"))
        if key not in seen_ep: seen_ep[key] = f
        else:
            order = {"HIGH":3,"MEDIUM":2,"LOW":1}
            if order.get(f.get("confidence","LOW"),0) > order.get(seen_ep[key].get("confidence","LOW"),0):
                seen_ep[key] = f
    findings = list(seen_ep.values())
    user_b  = [f for f in findings if f.get("session","User B") != "unauthenticated"]
    unauth  = [f for f in findings if f.get("session") == "unauthenticated"]
    tprint(f"  {color(f'CONFIRMED IDOR FINDINGS', C.BRED, C.BOLD)}  "
           f"{color(f'[User B: {len(user_b)}  Unauthenticated: {len(unauth)}]', C.DIM)}\n")
    def _print_group(group, prefix):
        by_conf = {"HIGH":[],"MEDIUM":[],"LOW":[]}
        for f in group: by_conf.get(f.get("confidence","LOW"), by_conf["LOW"]).append(f)
        idx = 1
        for level in ("HIGH","MEDIUM","LOW"):
            for f in by_conf[level]:
                cc = C.BRED if level == "HIGH" else C.BYELLOW if level == "MEDIUM" else C.DIM
                tprint(f"  {color(f'[{idx}]', C.BOLD, C.BWHITE)} {color(f'[{level}]', cc, C.BOLD)} {color(prefix, C.DIM)}")
                tprint(f"      {color('Endpoint:', C.BYELLOW)} {f['method']} {f['url']}")
                tprint(f"      {color('Param:', C.BYELLOW)} {f.get('param_name') or '(path)'}  "
                       f"{color('Original:', C.BYELLOW)} {f['original_id']}  "
                       f"{color('Tampered:', C.BRED, C.BOLD)} {f['tampered_id']}")
                tprint(f"      {color('Evidence:', C.BYELLOW)} {f['evidence']}")
                snip = (f.get("body_snippet") or "").replace("\n"," ")[:180]
                if snip: tprint(f"      {color('Snippet:', C.DIM)} {snip}")
                poc = f.get("poc_curl",""); poc_label = f.get("poc_session_label","User B")
                if poc:
                    tprint(f"      {color(f'PoC ({poc_label}):', C.BRED, C.BOLD)} {color(poc, C.BYELLOW)}")
                tprint(); idx += 1
    if user_b:
        tprint(color(f"  ── {'Single-session BAC' if single_session else 'User B Session'} Findings ──", C.BYELLOW, C.BOLD))
        _print_group(user_b, "User A (BAC)" if single_session else "User B session")
    if unauth:
        tprint(color("  ── Unauthenticated Findings (Critical) ──", C.BRED, C.BOLD))
        _print_group(unauth, "No session")
    tprint(color("  REMEDIATION", C.BOLD + C.BYELLOW))
    tprint("  • Enforce server-side ownership checks on EVERY object access request.")
    tprint("  • Use cryptographically random, non-sequential object identifiers.")
    tprint("  • Apply row-level security at the data layer — not just the API.")
    return findings

# ══════════════════════════════════════════════════════════════════════
# FRAMEWORK ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def run(target, emit, options=None, stop_check=None, pause_check=None):
    """
    Hellhound module entry point.

    options keys (all optional — see OPTIONS block above):
      cookie_a/b           : pre-captured session tokens
      header_a/b           : extra auth headers
      login_user/pass_a/b  : credentials for auto-login
      login_url_a          : explicit login URL override
      auto_register        : create two test accounts automatically
      invite_code          : registration invite code
      timeout              : HTTP timeout per request (default 10)
      threads              : concurrent test threads (default 8)
      delay                : inter-request delay in seconds
      write_probe          : include POST/PUT endpoints
      no_unauth            : skip unauthenticated bypass checks
      depth                : crawler depth when no spider intel (default 3)
      max_pages            : max pages for built-in crawler (default 200)
      verbose              : per-request detail logging
      spider_intel         : auto-injected by console when Spider has run

    Returns:
      {"raw": str, "intel": dict}
    """
    opts    = options or {}
    global VERBOSE
    VERBOSE = bool(opts.get("verbose", False))

    if not target.startswith(("http://","https://")):
        target = "http://" + target
    target = target.rstrip("/")

    emit.section("IDOR Detector  v" + VERSION)

    ua          = None
    timeout     = opts.get("timeout", 10)
    bare_client = HTTPClient(timeout=timeout, user_agent=ua)

    # ── Phase 1: Session initialisation ───────────────────────────────
    emit.section("Session Initialisation")

    cookie_a = opts.get("cookie_a") or opts.get("cookie")
    cookie_b = opts.get("cookie_b")
    header_a = opts.get("header_a")
    header_b = opts.get("header_b")
    user_a   = opts.get("login_user_a")
    pass_a   = opts.get("login_pass_a")
    user_b   = opts.get("login_user_b")
    pass_b   = opts.get("login_pass_b")
    url_a    = opts.get("login_url_a")
    auto_reg = bool(opts.get("auto_register", False))
    invite   = opts.get("invite_code")

    auth_id_hints = []
    client_a      = None
    client_b      = None

    if cookie_a:
        client_a = HTTPClient(timeout=timeout, cookie=cookie_a, extra_header=header_a, user_agent=ua)
        emit.info("User A: token loaded directly")
        if cookie_b:
            client_b = HTTPClient(timeout=timeout, cookie=cookie_b, extra_header=header_b, user_agent=ua)
            emit.info("User B: token loaded — dual-session IDOR enabled")
        else:
            emit.warn("No User B token — running single-session mode")
            client_b = bare_client.clone_no_auth()

    elif user_a and url_a:
        emit.info(f"Logging in User A via {url_a}...")
        probe = AuthProbe(bare_client, target).discover()
        probe["login_url"] = url_a
        builder = SessionBuilder(bare_client, target)
        ok_a, hdrs_a, hints_a = builder.login(user_a, pass_a, probe)
        if not ok_a:
            ok_a, hdrs_a, hints_a = builder.login(user_a, pass_a, {**probe, "content_type": "json"})
        if ok_a:
            auth_id_hints.extend(hints_a)
            client_a = bare_client.clone_no_auth()
            for k, v in hdrs_a.items():
                if not k.startswith("_"): client_a.headers[k] = v
            emit.info(f"User A authenticated ({len(hints_a)} own ID(s) found)")
        else:
            emit.warn("User A login failed — continuing unauthenticated")
            client_a = bare_client.clone_no_auth()

        if user_b and pass_b:
            ok_b, hdrs_b, _ = builder.login(user_b, pass_b, probe)
            if ok_b:
                client_b = bare_client.clone_no_auth()
                for k, v in hdrs_b.items():
                    if not k.startswith("_"): client_b.headers[k] = v
                emit.info("User B authenticated")
            else:
                emit.warn("User B login failed"); client_b = bare_client.clone_no_auth()
        else:
            client_b = bare_client.clone_no_auth()

    elif user_a or auto_reg:
        emit.info("Adaptive auth — discovering login form...")
        engine = AuthEngine(bare_client, target, tprint_fn=lambda *a,**k: None,
                            invite_code_hint=invite)
        try:
            auth_result   = engine.run(
                user_a        = (user_a, pass_a) if user_a else None,
                user_b        = (user_b, pass_b) if user_b else None,
                auto_register = auto_reg,
            )
            client_a      = auth_result.client_a
            client_b      = auth_result.client_b
            auth_id_hints = auth_result.id_hints
            emit.info(f"Sessions ready — {len(auth_id_hints)} User A ID(s) harvested")
        except RuntimeError as e:
            emit.warn(f"Auth failed: {e} — running unauthenticated")
            client_a = bare_client.clone_no_auth()
            client_b = bare_client.clone_no_auth()

    else:
        emit.warn("No credentials — unauthenticated surface scan only")
        emit.info("Tip: set cookie_a, login_user_a/login_pass_a, or auto_register=true")
        client_a = bare_client.clone_no_auth()
        client_b = bare_client.clone_no_auth()

    client_unauth = None if opts.get("no_unauth") else bare_client.clone_no_auth()

    # ── Phase 2: Endpoint discovery ────────────────────────────────────
    emit.section("Endpoint Discovery")

    spider_intel  = opts.get("spider_intel")
    endpoints     = []
    extra_id_hints = []
    crawler        = None

    if spider_intel:
        emit.info("Spider intel detected — converting to IDOR endpoint list")
        endpoints = _spider_intel_to_endpoints(spider_intel, target)
        for ep in endpoints:
            hints = ep.pop("_spider_id_hints", [])
            extra_id_hints.extend(hints)
        if extra_id_hints:
            emit.info(f"{len(extra_id_hints)} live ID value(s) extracted from Spider params")
        emit.info(f"Loaded {len(endpoints)} endpoints from Spider")

    if not endpoints:
        emit.info("Running built-in crawler...")
        crawler   = Crawler(client_a, target,
                            depth=opts.get("depth", 3),
                            threads=opts.get("threads", 8),
                            max_pages=opts.get("max_pages", 200))
        endpoints = crawler.crawl()
        if not endpoints:
            emit.warn("No endpoints discovered — scan complete with no results")
            return {"raw": "No endpoints found", "intel": {"vulnerabilities":[], "risk_score":0}}

    # ── Phase 3: Surface analysis ──────────────────────────────────────
    emit.section("IDOR Surface Analysis")
    analyser     = IDORSurfaceAnalyser()
    targets_list = analyser.analyse(endpoints)

    high   = sum(1 for t in targets_list if t[0] == 3)
    medium = sum(1 for t in targets_list if t[0] == 2)
    low    = sum(1 for t in targets_list if t[0] == 1)
    emit.info(f"High-signal: {high} | Medium: {medium} | Low: {low} IDOR surface endpoints")

    if not targets_list:
        emit.warn("No IDOR surface detected — scan complete with no findings")
        return {"raw": "No IDOR surface found", "intel": {"vulnerabilities":[], "risk_score":0}}

    # ── ID Harvest Pass ────────────────────────────────────────────────
    has_real_session = bool(cookie_a or user_a or auto_reg)
    harvest_client   = client_a if has_real_session else bare_client
    harvest = IDHarvestPass(
        harvest_client, targets_list,
        threads=opts.get("threads", 8),
        delay=opts.get("delay", 0),
        client_b=client_b if has_real_session else None,
    )
    harvested_hints = harvest.run()

    _hint_seen   = set()
    all_id_hints = []
    for h in (harvested_hints + auth_id_hints + extra_id_hints +
              (crawler.id_hints if crawler else [])):
        k = (h["id_val"], h["id_type"])
        if k not in _hint_seen: _hint_seen.add(k); all_id_hints.append(h)
    emit.info(f"ID pool: {len(all_id_hints)} unique IDs for candidate generation")

    # ── Phase 4: Dual-session testing ─────────────────────────────────
    emit.section("Dual-Session IDOR Testing")
    single_session = not (cookie_b or (user_b and pass_b))
    tester = IDORTester(
        client_a      = client_a,
        client_b      = client_b,
        client_unauth = client_unauth,
        targets       = targets_list,
        id_hints      = all_id_hints,
        child_urls    = harvest.child_urls,
        threads       = opts.get("threads", 8),
        delay         = opts.get("delay", 0),
        test_unauth   = not opts.get("no_unauth", False),
        write_probe   = opts.get("write_probe", False),
        single_session= single_session,
    )
    findings = tester.run()

    # ── Phase 5: Report ────────────────────────────────────────────────
    stats = {
        "timestamp":    datetime.now().isoformat(),
        "pages":        len(crawler.visited)    if crawler else "n/a (spider)",
        "js_files":     len(crawler.js_visited) if crawler else "n/a (spider)",
        "endpoints":    len(endpoints),
        "idor_surface": len(targets_list),
        "id_hints":     len(all_id_hints),
        "findings":     len(findings),
        "source":       "spider_intel" if spider_intel else "crawler",
    }
    _print_report(findings, target, stats, single_session=single_session)

    # ── Severity scoring ───────────────────────────────────────────────
    def _severity(f):
        if f.get("session") == "unauthenticated": return "CRITICAL"
        if f.get("confidence") == "HIGH":         return "High"
        if f.get("confidence") == "MEDIUM":       return "Medium"
        return "Low"

    enriched = [{**f, "severity": _severity(f), "vuln_type": "IDOR"} for f in findings]
    risk     = sum(10 if f["severity"] in ("CRITICAL","High") else
                   3  if f["severity"] == "Medium" else 1
                   for f in enriched)

    emit.section("IDOR Summary")
    emit.always_success(f"Scan complete — {len(enriched)} finding(s) | risk score: {risk}")
    for f in enriched:
        emit.always_success(
            f"CONFIRMED: {f['vuln_type']} [{f['confidence']}] @ {f['url']} "
            f"(param: {f.get('param_name') or 'path'}, tampered: {f['tampered_id']})"
        )

    return {
        "raw": f"{len(enriched)} IDOR finding(s)",
        "intel": {
            "vulnerabilities":  enriched,
            "risk_score":       risk,
            "endpoints_tested": len(endpoints),
            "idor_surface":     len(targets_list),
            "id_pool":          len(all_id_hints),
            "scan_stats":       stats,
        }
    }