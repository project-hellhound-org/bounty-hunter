#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  HELLHOUND — IDOR_UserData_Detector  v1.2                                 ║
║  Insecure Direct Object Reference — User Data Variant                      ║
║                                                                             ║
║  Pipeline:                                                                  ║
║    1. Threaded crawler + JS/SPA endpoint extraction (shared)               ║
║    2. IDOR surface detection — URL path segments, query params, body keys  ║
║       carrying numeric/UUID/slug identifiers                                ║
║    3. Dual-user authentication (User A + User B)                           ║
║    4. Harvest User A's live object IDs from authenticated responses        ║
║    5. Replay User A's IDs in User B's session across all candidate EPs     ║
║    6. Differential response analysis — confirm unauthorized data access    ║
║    7. Neighbour ID enumeration — sequential ±N and UUID scrambling        ║
║    8. Unauthenticated bypass — replay with no session                      ║
║    9. Report: vulnerable EP · param · original ID · tampered ID · leak    ║
║                                                                             ║
║  v1.2 fixes:                                                                ║
║    - NameError: tampered_url scoped correctly for path vs param             ║
║    - Unauth block guarded — only runs after IDOR is confirmed               ║
║    - Crawler recursion uses queue+pool (no nested ThreadPoolExecutor)       ║
║    - ID hint type-matching (numeric→numeric, uuid→uuid)                    ║
║    - Slug filter excludes short version strings (/v1, /v2 etc.)            ║
║    - Dedup targets per endpoint (no double-entry for same param)            ║
║    - 404 NOT treated as access-denied (object absent ≠ forbidden)          ║
║    - Finding deduplication (url+param+tampered_id key)                     ║
║    - write_probe flag honoured — POST/PUT skipped unless --write-probe     ║
║    - clone_no_auth preserves timeout/UA                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import queue
import random
import re
import string
import sys
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser
from hellhound.core import http_utils

# ─────────────────────────────────────────────────────────────────────────────
# SSL — accept self-signed certs (test apps)
# ─────────────────────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET    = "\033[0m";  BOLD    = "\033[1m"; DIM     = "\033[2m"
    RED      = "\033[31m"; GREEN   = "\033[32m"; YELLOW  = "\033[33m"
    BLUE     = "\033[34m"; MAGENTA = "\033[35m"; CYAN    = "\033[36m"
    WHITE    = "\033[37m"
    BRED     = "\033[91m"; BGREEN  = "\033[92m"; BYELLOW = "\033[93m"
    BBLUE    = "\033[94m"; BMAGENTA= "\033[95m"; BCYAN   = "\033[96m"
    BWHITE   = "\033[97m"

def color(text, *styles): return "".join(styles) + str(text) + C.RESET
def label(tag, text, tc=C.BBLUE):
    return f"{color('[',C.DIM)}{color(tag,tc,C.BOLD)}{color(']',C.DIM)} {text}"

def ok(t):    return label("+",      t, C.BGREEN)
def warn(t):  return label("!",      t, C.BYELLOW)
def err(t):   return label("-",      t, C.BRED)
def info(t):  return label("*",      t, C.BCYAN)
def found(t): return label("IDOR",   t, C.BRED)
def skp(t):   return label("SKIP",   t, C.DIM)

_print_lock = threading.Lock()
def tprint(*a, **kw):
    with _print_lock:
        print(*a, **kw)

def section(title):
    bar = color("─" * 72, C.DIM + C.CYAN)
    tprint(f"\n{bar}")
    tprint(f"  {color('  ' + title + '  ', C.BOLD + C.BCYAN)}")
    tprint(f"{bar}")

VERBOSE = False
def vprint(*a, **kw):
    if VERBOSE: tprint(*a, **kw)

# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# HELLHOUND MODULE CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
NAME = "idordetector"
CATEGORY = "vuln"
DESCRIPTION = "Horizontal & Vertical Insecure Direct Object Reference Detector"
AUTHOR = "Hellhound Framework"

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


# ─────────────────────────────────────────────────────────────────────────────
# IDOR SURFACE PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

# Numeric path segment: /123  (1–12 digits, not a version string like /v1 /v2)
# Requires preceding context to NOT be "v" or "version"
_PATH_NUMERIC_RE = re.compile(r'(?<![vV])(?<!/version)/(\d{1,12})(?=/|$)')

# UUID in path
_PATH_UUID_RE = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
    re.I
)

# Opaque alphanumeric slug in path: ≥8 chars, mix of alpha+digit (not pure alpha = word)
_PATH_SLUG_RE = re.compile(
    r'/([a-zA-Z0-9]{8,48})(?=/|$)'
)

# Param names that are high-signal IDOR surface
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
    # Social / messaging params — commonly carry user IDs
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

# Value patterns
_NUMERIC_RE  = re.compile(r'^\d{1,12}$')
_UUID_RE     = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.I
)
_SLUG_RE     = re.compile(r'^[a-zA-Z0-9_\-]{8,64}$')

# Mixed alpha+digit check (slug must have at least one digit)
def _is_slug(val):
    return bool(_SLUG_RE.match(val)) and bool(re.search(r'\d', val)) and bool(re.search(r'[a-zA-Z]', val))

# JSON keys in response that indicate user-specific data
_SENSITIVE_KEYS_RE = re.compile(
    r'"(?:email|phone|mobile|address|dob|birth_?date|ssn|national_id|passport'
    r'|credit_card|card_number|bank|iban|salary|tax|medical|diagnosis'
    r'|password|secret|api_key|private_key|personal|permission'
    r'|username|full_?name|first_?name|last_?name|avatar|photo_url'
    r'|balance|subscription|plan|invoice|billing|payment'
    # Extended: crypto, tokens, settings — IDOR-relevant
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

# Static file extensions — skip these in crawler
_STATIC_EXT_RE = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip|gz|tar|bz2|mp4|mp3|webm)$',
    re.I
)

# ─────────────────────────────────────────────────────────────────────────────
# HTTP CLIENT
# ─────────────────────────────────────────────────────────────────────────────
class HTTPClient:
    _login_redirect_re = re.compile(r'login|signin|auth|session|unauthorized', re.I)

    def __init__(self, timeout=12, cookie=None, extra_header=None,
                 login_url=None, login_user=None, login_pass=None,
                 login_user_field="username", login_pass_field="password",
                 user_agent=None, options=None):
        options = options or {}
        self.timeout           = timeout
        self._login_url        = login_url
        self._login_user       = login_user
        self._login_pass       = login_pass
        self._login_user_field = login_user_field
        self._login_pass_field = login_pass_field
        ua = user_agent or "Mozilla/5.0 (compatible; HELLHOUND-IDOR/1.2)"
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
                # Raw JWT — auto-wrap as Bearer token
                self.headers["Authorization"] = f"Bearer {cookie}"
            else:
                self.headers["Cookie"] = cookie
        if extra_header:
            sep = ":" if ":" in extra_header else "="
            k, v = extra_header.split(sep, 1)
            self.headers[k.strip()] = v.strip()
        if login_url and login_user and login_pass:
            self._do_login()
        
        # apply global proxy
        self._proxy = options.get("proxy")
        self._opener = http_utils.get_urllib_opener(self._proxy)
        
        # merge global headers
        self.headers = http_utils.merge_global_context(options, self.headers)

# ── login ──────────────────────────────────────────────────────────────
    def _do_login(self):
        data = {
            self._login_user_field: self._login_user,
            self._login_pass_field: self._login_pass,
        }

        # Phase 1: try no-redirect POST first — captures Set-Cookie on 302
        # (most common pattern: POST /login → 302 /dashboard with Set-Cookie on the 302)
        resp = self.post_no_redirect(self._login_url, data)

        # If the no-redirect call itself returned a cookie, we're done
        if self._extract_session(resp):
            return

        # Phase 2: if no-redirect gave nothing useful (e.g. 200 JSON API),
        # fall back to the redirect-following POST to capture body tokens
        if resp.get("status", 0) not in range(200, 210):
            resp = self.post(self._login_url, data)
            if self._extract_session(resp):
                return

        # Final fallback: try body token extraction on whatever we got
        if not self._extract_session(resp):
            tprint(f"  {warn('Login: no session token detected in response — may be unauthenticated')}")

    def _extract_session(self, resp):
        """
        Try to extract a session credential from a login response.
        Returns True if a credential was captured, False otherwise.
        Checks: Set-Cookie → Authorization header → JSON body token.
        """
        # 1. Cookie
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

        # 2. Authorization header echoed back
        auth = resp.get("headers", {}).get("authorization", "")
        if auth:
            self.headers["Authorization"] = auth
            tprint(f"  {ok('Login OK — Authorization header captured')}")
            return True

        # 3. JSON body token
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
                        tprint(f"  {ok(f'Login OK — Bearer token captured [{key}]')}")
                        return True
        except Exception:
            pass

        return False

    def clone_no_auth(self, options=None):
        """Return a client copy with no auth headers (for unauthenticated checks)."""
        c = HTTPClient.__new__(HTTPClient)
        c.timeout           = self.timeout
        c._login_url        = None
        c._login_user       = None
        c._login_pass       = None
        c._login_user_field = "username"
        c._login_pass_field = "password"
        # Copy all headers EXCEPT auth
        c.headers = {k: v for k, v in self.headers.items()
                     if k not in ("Cookie", "Authorization")}
        
        # Apply proxy to clone
        c._proxy = self._proxy
        c._opener = self._opener
        return c

    # ── HTTP verbs ──────────────────────────────────────────────────────────
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
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        t0  = time.time()
        result = [None]

        def _execute():
            try:
                # Use the proxied opener
                with self._opener.open(req, timeout=self.timeout) as r:
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
        """
        POST without following redirects. Returns the raw 3xx response
        including its Set-Cookie header — essential for cookie-based login
        flows where the session is set on the redirect, not the final page.
        """
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

        # Build a custom opener that does NOT follow redirects
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None   # block redirect

        opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_SSL_CTX))
        req    = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        t0     = time.time()
        try:
            with opener.open(req, timeout=self.timeout) as r:
                elapsed = time.time() - t0
                text    = r.read(256 * 1024).decode("utf-8", errors="replace")
                return {"ok": True, "status": r.status, "body": text,
                        "elapsed": elapsed, "url": url,
                        "headers": dict(r.headers), "error": None}
        except urllib.error.HTTPError as e:
            elapsed = time.time() - t0
            try:    text = e.read(256 * 1024).decode("utf-8", errors="replace")
            except: text = ""
            # 3xx responses come here when redirect is blocked — this is what we want
            return {"ok": e.code in range(200, 400), "status": e.code, "body": text,
                    "elapsed": elapsed, "url": url,
                    "headers": dict(e.headers) if e.headers else {},
                    "error": None if e.code in range(300, 310) else str(e)}
        except Exception as ex:
            elapsed = time.time() - t0
            return {"ok": False, "status": 0, "body": "",
                    "elapsed": elapsed, "url": url, "headers": {}, "error": str(ex)}

# ─────────────────────────────────────────────────────────────────────────────
# AUTH ENGINE (adaptive login/register for any webapp)
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# KNOWN LOGIN / REGISTER URL PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
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

# Common login page link text
_LOGIN_LINK_TEXT = re.compile(
    r'\b(?:log\s*in|sign\s*in|login|signin|authenticate|account\s*access)\b',
    re.I
)
_REGISTER_LINK_TEXT = re.compile(
    r'\b(?:register|sign\s*up|signup|create\s*account|join|get\s*started)\b',
    re.I
)

# ─────────────────────────────────────────────────────────────────────────────
# FIELD NAME VARIANT TABLES
# Priority order: most common first
# ─────────────────────────────────────────────────────────────────────────────
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

_CONFIRM_PASS_VARIANTS = [
    "password_confirmation", "confirm_password", "confirmPassword",
    "password_confirm", "confirm_pass", "re_password", "repassword",
    "password2", "pass2", "repeat_password",
]

# Keys in JSON response body that indicate auth success and contain user identity
_IDENTITY_KEYS = [
    # token keys
    "token", "access_token", "accessToken", "jwt", "auth_token",
    "authToken", "id_token", "idToken", "bearer", "sessionToken",
    # nested
    "data.token", "data.access_token", "data.accessToken",
    "result.token", "auth.token", "user.token",
    # user ID keys — extracted for IDOR seed
    "id", "user_id", "userId", "uid", "uuid", "account_id",
    "accountId", "profile_id", "profileId",
    # nested user ID
    "user.id", "user.user_id", "user.uid", "user.uuid",
    "data.id", "data.user_id", "data.uid",
    "account.id", "profile.id",
]

# Response fields that confirm auth success
_SUCCESS_BODY_SIGNALS = re.compile(
    r'"(?:token|access_token|accessToken|jwt|user|account|profile|dashboard|'
    r'sessionId|session_id|auth_token|authToken|logged_in|loggedIn|'
    r'authenticated|success)"\s*:\s*(?:"[^"]{4,}"|true|\d+)',
    re.I
)

# Redirect destinations after successful login
_POST_LOGIN_DESTINATIONS = re.compile(
    r'dashboard|home|profile|account|welcome|main|app|portal|overview',
    re.I
)

# ─────────────────────────────────────────────────────────────────────────────
# "ME" / "CURRENT USER" ENDPOINT PATTERNS
# Hit after login to get User A's own ID
# ─────────────────────────────────────────────────────────────────────────────
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

# Patterns that match a user's own profile link in HTML pages
# e.g. href="/profile/32"  or  href="/api/users/32"  or  data-user-id="32"
# Works universally — does not rely on knowing the app's URL structure
_SELF_PROFILE_LINK_RE = re.compile(
    r'(?:href|src)=["\']([^"\']*(?:profile|user|account|member|u)[^"\']*?/(\d{1,8}))["\']'
    r'|data-(?:user|profile|author|owner|uid|user-id)["\']?\s*=\s*["\'](\d{1,8})["\']'
    r'|(?:user|profile|account)_?id["\']?\s*[:=]\s*["\']?(\d{1,8})',
    re.I
)

# ─────────────────────────────────────────────────────────────────────────────
# FORM PARSER  (specialised for auth forms)
# ─────────────────────────────────────────────────────────────────────────────
class AuthFormParser(HTMLParser):
    """
    Parses HTML to find login/register forms and auth-related links.
    After feed(), check:
      .forms      — list of dicts: {action, method, fields, hidden, content_type_hint}
      .auth_links — list of (href, link_text, kind) where kind='login'|'register'
    """

    def __init__(self, base_url):
        super().__init__()
        self.base_url   = base_url
        self._base      = urllib.parse.urlparse(base_url)
        self.forms      = []
        self.auth_links = []   # (href, text, kind)
        self._form      = None
        self._in_a      = False
        self._a_href    = ""
        self._a_text    = ""

    # ── Tag handlers ───────────────────────────────────────────────────────
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)

        if tag == "a":
            href = (a.get("href") or "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "#")):
                self._in_a   = True
                self._a_href = urllib.parse.urljoin(self.base_url, href)
                self._a_text = ""

        elif tag == "form":
            action  = urllib.parse.urljoin(
                self.base_url, a.get("action") or self.base_url)
            method  = a.get("method", "POST").upper()
            # Some SPAs POST JSON — check enctype
            enctype = a.get("enctype", "").lower()
            ct_hint = "json" if "json" in enctype else "form"
            self._form = {
                "action":       action,
                "method":       method,
                "content_type": ct_hint,
                "fields":       [],   # testable fields
                "hidden":       {},   # hidden fields (CSRF, nonces)
            }

        elif tag in ("input", "textarea", "select") and self._form is not None:
            name  = (a.get("name") or a.get("id") or "").strip()
            itype = a.get("type", "text").lower()
            value = a.get("value", "")

            if not name:
                return

            if itype == "hidden":
                self._form["hidden"][name] = value
            elif itype not in ("submit", "button", "reset", "image", "file"):
                self._form["fields"].append({
                    "name":  name,
                    "type":  itype,
                    "value": value,
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            # Only keep forms that look auth-related
            if self._looks_like_auth_form(self._form):
                self.forms.append(self._form)
            self._form = None

        elif tag == "a":
            if self._in_a and self._a_href:
                kind = self._classify_link(self._a_href, self._a_text)
                if kind:
                    self.auth_links.append((self._a_href, self._a_text.strip(), kind))
            self._in_a   = False
            self._a_href = ""
            self._a_text = ""

    def handle_data(self, data):
        if self._in_a:
            self._a_text += data

    # ── Helpers ────────────────────────────────────────────────────────────
    def _looks_like_auth_form(self, form):
        """True if the form has a password field or action URL looks auth-like."""
        field_names = {f["name"].lower() for f in form.get("fields", [])}
        has_password = any(
            v in field_names
            for v in ("password", "passwd", "pass", "secret", "pwd")
        )
        action_looks_auth = bool(
            _LOGIN_URL_PATTERNS.search(form.get("action", "")) or
            _REGISTER_URL_PATTERNS.search(form.get("action", ""))
        )
        return has_password or action_looks_auth

    def _classify_link(self, href, text):
        """Return 'login', 'register', or None."""
        combined = (href + " " + text).lower()
        if _LOGIN_URL_PATTERNS.search(href) or _LOGIN_LINK_TEXT.search(text):
            return "login"
        if _REGISTER_URL_PATTERNS.search(href) or _REGISTER_LINK_TEXT.search(text):
            return "register"
        return None


# ─────────────────────────────────────────────────────────────────────────────
# AUTH PROBE  — discovers login/register URLs and form shapes
# ─────────────────────────────────────────────────────────────────────────────
class AuthProbe:
    """
    Given a base URL and a bare HTTPClient, discovers:
      - login_url
      - register_url
      - form shape (field names, hidden/CSRF, content-type)
    """

    def __init__(self, client, base_url):
        self.client   = client
        self.base_url = base_url.rstrip("/")
        self._base    = urllib.parse.urlparse(base_url)

    # ── Public ─────────────────────────────────────────────────────────────
    def discover(self):
        """
        Returns a dict:
        {
          "login_url":    str | None,
          "register_url": str | None,
          "login_form":   {...} | None,
          "register_form":{...} | None,
          "csrf_field":   str | None,   # name of CSRF hidden field
          "content_type": "form"|"json",
        }
        """
        result = {
            "login_url":    None,
            "register_url": None,
            "login_form":   None,
            "register_form":None,
            "csrf_field":   None,
            "content_type": "form",
        }

        # Step 1: crawl homepage + common auth paths, collect links + forms
        candidate_pages = self._collect_candidate_pages()

        # Step 2: classify into login vs register
        login_candidates    = []
        register_candidates = []

        for url, page_type in candidate_pages:
            resp = self.client.get(url)
            if resp["status"] == 0 or resp["status"] >= 400:
                continue
            body = resp.get("body", "") or ""
            ct   = resp.get("headers", {}).get("content-type", "")

            # Parse the page for forms and links
            if "html" in ct or body.strip().startswith("<"):
                parser = AuthFormParser(url)
                try:
                    parser.feed(body)
                except Exception:
                    pass

                for form in parser.forms:
                    kind = self._classify_form(form, url, page_type)
                    if kind == "login":
                        login_candidates.append((url, form))
                    elif kind == "register":
                        register_candidates.append((url, form))

                # Follow auth links we haven't visited yet
                for href, text, kind in parser.auth_links:
                    if kind == "login" and href not in [c[0] for c in candidate_pages]:
                        candidate_pages.append((href, "login"))
                    elif kind == "register" and href not in [c[0] for c in candidate_pages]:
                        candidate_pages.append((href, "register"))

            # JSON API endpoint that looks like a login handler
            elif "json" in ct or body.strip().startswith("{"):
                if page_type == "login":
                    result["login_url"]    = url
                    result["content_type"] = "json"
                elif page_type == "register":
                    result["register_url"] = url

        # Step 3: pick best candidates
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

    # ── Internals ──────────────────────────────────────────────────────────
    def _collect_candidate_pages(self):
        """
        Returns list of (url, page_type_hint) to fetch and parse.
        page_type_hint: 'login' | 'register' | 'home'
        """
        base = self.base_url
        candidates = [(base, "home")]

# Common login paths — includes REST API patterns used by SPAs
        for path in [
            "/login", "/signin", "/sign-in", "/auth", "/auth/login",
            "/user/login", "/users/login", "/account/login",
            "/api/login", "/api/auth", "/api/signin", "/api/token",
            "/api/v1/auth", "/api/v1/login", "/api/v1/token",
            "/api/v2/login", "/api/v2/auth",
            # REST-style login endpoints common in SPAs (no HTML form)
            "/rest/user/login", "/rest/auth/login", "/rest/login",
            "/rest/session", "/api/session", "/api/users/login",
            "/api/auth/token", "/api/authenticate",
        ]:
            candidates.append((base + path, "login"))

        # Common register paths
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
        """Return 'login', 'register', or None."""
        action    = form.get("action", "").lower()
        fields    = {f["name"].lower() for f in form.get("fields", [])}
        has_pass  = bool(fields & {"password", "passwd", "pass", "pwd", "secret"})
        has_conf  = bool(fields & {
            "password_confirmation", "confirm_password", "confirmpassword",
            "password2", "pass2", "repeat_password", "repassword"
        })

        # Registration: has confirm-password field
        if has_pass and has_conf:
            return "register"
        # Registration: action/URL matches register pattern
        if _REGISTER_URL_PATTERNS.search(action) or page_type_hint == "register":
            return "register"
        # Login: has password but no confirm, or action/URL matches
        if has_pass or _LOGIN_URL_PATTERNS.search(action) or page_type_hint == "login":
            return "login"
        return None

    def _find_csrf_field(self, form):
        """Return CSRF hidden field name if present."""
        for name in form.get("hidden", {}).keys():
            if re.search(r'csrf|xsrf|nonce|authenticity_token|_token|verify', name, re.I):
                return name
        return None


# ─────────────────────────────────────────────────────────────────────────────
# SESSION BUILDER  — performs the actual login and verifies it worked
# ─────────────────────────────────────────────────────────────────────────────
class SessionBuilder:
    """
    Attempts to login with given credentials using a discovered probe result.
    Tries multiple field-name strategies until one works.
    Returns (success: bool, auth_headers: dict, own_ids: list[dict])
    """

    def __init__(self, client, base_url, timeout=12):
        self.client          = client
        self.base_url        = base_url.rstrip("/")
        self.timeout         = timeout
        self._login_url_hint = None   # set during login, used in _verify_and_harvest
        self._own_username   = None   # set during login for username-aware ID extraction

    # ── Public ─────────────────────────────────────────────────────────────
    def login(self, username, password, probe_result):
        """
        Try to login username+password using the probe_result from AuthProbe.
        Returns (success, auth_headers, user_id_hints)
        """
        login_url = probe_result.get("login_url")
        if not login_url:
            return False, {}, []

        self._login_url_hint = login_url   # used in _verify_and_harvest Strategy C
        self._own_username   = username    # used for username-aware ID extraction

        # Fetch the login page fresh to get a live CSRF token
        csrf_name, csrf_value = self._fetch_csrf(
            login_url, probe_result.get("csrf_field"))

        content_type = probe_result.get("content_type", "form")
        form         = probe_result.get("login_form") or {}

        # Build candidate field names — form-discovered names go first
        user_cands = self._field_candidates(form, "user")
        pass_cands = self._field_candidates(form, "pass")

        # Strategy: try form-discovered fields (top 3) × form-discovered fields (top 3) first
        # Then fall back to full variant list × form-discovered password (top 1)
        # This prevents the 150-attempt explosion while still covering edge cases
        form_user = user_cands[:3]   # only top 3 user field guesses
        form_pass = pass_cands[:3]   # only top 3 pass field guesses

        # Phase 1: cross product of top candidates (max 9 attempts)
        for uf in form_user:
            for pf in form_pass:
                if uf == pf:
                    continue
                success, auth_hdrs, id_hints = self._attempt_login(
                    login_url, uf, username, pf, password,
                    csrf_name, csrf_value, content_type, form
                )
                if success:
                    return True, auth_hdrs, id_hints

        # Phase 2: if form had actual field names, don't try more variants —
        # if the form field names failed, the credentials are wrong, not the field names
        form_fields = {f["name"].lower() for f in form.get("fields", [])}
        if len(form_fields) >= 2:
            # We had real form fields and they failed — credentials issue, not field names
            return False, {}, []

        # Phase 3: no form found — try wider variant list but capped at 20 attempts
        attempted = 0
        for uf in user_cands[:5]:
            for pf in pass_cands[:4]:
                if uf == pf or attempted >= 20:
                    continue
                attempted += 1
                success, auth_hdrs, id_hints = self._attempt_login(
                    login_url, uf, username, pf, password,
                    csrf_name, csrf_value, content_type, form
                )
                if success:
                    return True, auth_hdrs, id_hints

        return False, {}, []

    # ── Internals ──────────────────────────────────────────────────────────
    def _fetch_csrf(self, url, known_field):
        """
        GET the login page and extract the CSRF token value.
        Returns (field_name, value) or (None, None).
        """
        resp = self.client.get(url)
        if not resp["ok"]:
            return None, None
        body = resp.get("body", "") or ""

        # Pattern: <input type="hidden" name="csrf_token" value="XYZ">
        csrf_re = re.compile(
            r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*'
            r'value=["\']([^"\']{8,})["\']',
            re.I
        )
        # Also: name first, then value
        csrf_re2 = re.compile(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*'
            r'value=["\']([^"\']{8,})["\']',
            re.I
        )

        for pattern in (csrf_re, csrf_re2):
            for m in pattern.finditer(body):
                fname, fval = m.group(1), m.group(2)
                if re.search(r'csrf|xsrf|nonce|authenticity|_token|verify', fname, re.I):
                    return fname, fval
                if known_field and fname.lower() == known_field.lower():
                    return fname, fval

        # JSON meta tag pattern: <meta name="csrf-token" content="XYZ">
        meta_m = re.search(
            r'<meta[^>]+name=["\']csrf-?token["\'][^>]*content=["\']([^"\']+)["\']',
            body, re.I
        )
        if meta_m:
            return "csrf_token", meta_m.group(1)

        # window.__CSRF__ = "..." or similar JS global
        js_csrf = re.search(
            r'(?:csrf|xsrf|_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
            body, re.I
        )
        if js_csrf:
            field = known_field or "csrf_token"
            return field, js_csrf.group(1)

        return known_field, None

    def _field_candidates(self, form, kind):
        """
        Build ordered list of field name candidates for user or pass.
        Puts form-discovered name first, then common variants.
        """
        if kind == "user":
            variants = list(_USERNAME_FIELD_VARIANTS)
        else:
            variants = list(_PASSWORD_FIELD_VARIANTS)

        if not form:
            return variants

        # Put the actual form field names first
        form_names = [
            f["name"] for f in form.get("fields", [])
            if f.get("type") != "hidden"
        ]
        ordered = []
        for fn in form_names:
            fn_lower = fn.lower()
            if kind == "user" and any(v in fn_lower for v in
                    ("user", "email", "login", "handle", "phone", "account", "identifier")):
                ordered.insert(0, fn)
            elif kind == "pass" and any(v in fn_lower for v in
                    ("pass", "pwd", "secret")):
                ordered.insert(0, fn)
        # Append standard variants not already present
        seen = set(ordered)
        for v in variants:
            if v not in seen:
                ordered.append(v)
                seen.add(v)
        return ordered

    def _attempt_login(self, url, user_field, username,
                       pass_field, password,
                       csrf_name, csrf_value,
                       content_type, form):
        """
        POST the login form with one field-name attempt.
        Uses post_no_redirect so Set-Cookie on 302 responses is captured.
        Returns (success, auth_headers, id_hints).
        """
        # Build payload — start with hidden fields from form
        payload = dict(form.get("hidden", {}))

        # Inject fresh CSRF value
        if csrf_name and csrf_value:
            payload[csrf_name] = csrf_value
        elif csrf_name:
            _, fresh_csrf = self._fetch_csrf(url, csrf_name)
            if fresh_csrf:
                payload[csrf_name] = fresh_csrf

        payload[user_field] = username
        payload[pass_field] = password

# Try JSON first if URL looks like a REST/API endpoint,
        # then fall back to the probe's content_type.
        # Most SPAs use REST login endpoints that only accept JSON.
        url_looks_rest = bool(re.search(r'/rest/|/api/|/auth/', url, re.I))
        effective_ct = "json" if url_looks_rest else content_type
        resp = self.client.post_no_redirect(url, payload, effective_ct)

        # If REST-JSON attempt failed with 4xx, retry with probe's original ct
        if effective_ct == "json" and resp.get("status", 0) in (400, 415, 422, 405):
            resp = self.client.post_no_redirect(url, payload, content_type)

        # Check if we got a session back from the raw response
        auth_hdrs = self._extract_auth(resp)
        id_hints  = []

        if not auth_hdrs:
            return False, {}, []

        # Verify the session actually works
        verified, id_hints = self._verify_and_harvest(auth_hdrs)
        if not verified:
            return False, {}, []

        return True, auth_hdrs, id_hints

    def _extract_auth(self, resp):
        """
        Try to extract auth token from response.
        Checks: Set-Cookie, Authorization header, JSON body tokens.
        Returns dict of headers to add, or empty dict on failure.
        """
        # 1. Redirect to a post-login page (success signal even before token)
        status   = resp.get("status", 0)
        location = resp.get("headers", {}).get("location", "") or ""
        body     = (resp.get("body", "") or "")

        is_redirect_success = (
            status in range(301, 310) and
            (not location or _POST_LOGIN_DESTINATIONS.search(location) or
             not re.search(r'login|signin|error|fail', location, re.I))
        )

        # 2. Cookie
        sc = resp.get("headers", {}).get("set-cookie", "") or ""
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
                return {"Cookie": "; ".join(pairs)}

        # 3. JSON body token
        if body:
            try:
                obj = json.loads(body)
                token, uid = self._dig_json(obj)
                if token:
                    return {"Authorization": f"Bearer {token}",
                            "_uid": uid}
            except Exception:
                pass

        # 4. Custom auth headers
        for hname in ("x-auth-token", "x-access-token", "x-token",
                       "x-api-key", "x-session-token"):
            hval = resp.get("headers", {}).get(hname, "")
            if hval and len(hval) > 8:
                return {"Authorization": f"Bearer {hval}"}

        # 5. Accept redirect-only as success (session in cookie may follow)
        if is_redirect_success and status in range(301, 310):
            # Still no token but redirect went somewhere good — possible
            # session set in a follow-up redirect we didn't follow.
            # Return empty-but-truthy sentinel so caller knows to follow.
            return {"_redirect_only": True}

        return {}

    def _dig_json(self, obj, depth=0):
        """
        Recursively search a JSON object for a token and a user ID.
        Returns (token_str, uid_str).
        """
        if depth > 4 or not isinstance(obj, dict):
            return None, None

        token_keys = ("token", "access_token", "accessToken", "jwt",
                      "auth_token", "authToken", "id_token", "idToken",
                      "sessionToken", "bearer")
        id_keys    = ("id", "user_id", "userId", "uid", "uuid",
                      "account_id", "accountId")

        token = None
        uid   = None

        for k, v in obj.items():
            if k in token_keys and isinstance(v, str) and len(v) > 8:
                token = v
            if k in id_keys and v is not None:
                uid = str(v)
            if isinstance(v, dict):
                sub_tok, sub_uid = self._dig_json(v, depth + 1)
                if not token and sub_tok:
                    token = sub_tok
                if not uid and sub_uid:
                    uid = sub_uid

        return token, uid

    def _verify_and_harvest(self, auth_hdrs):
        """
        Apply auth_hdrs to a scratch client and extract User A's OWN object ID.

        The key challenge: a homepage shows ALL users' profile links.
        We need to find links/data that are SPECIFIC to the logged-in session.
        Strategy (in priority order):
          A. JSON /me endpoints → most reliable
          B. Settings / account pages → session-specific, contain YOUR id
          C. Notification / dashboard pages → session-specific
          D. Follow redirect after login → lands on user-specific page
          E. Confirm session validity via base URL
        """
        if auth_hdrs.get("_redirect_only"):
            return True, []

        test_client = self.client.clone_no_auth()
        for k, v in auth_hdrs.items():
            if not k.startswith("_"):
                test_client.headers[k] = v

        uid_from_login = auth_hdrs.get("_uid")
        id_hints = []
        verified = False

        if uid_from_login:
            id_hints.append({
                "id_val":     uid_from_login,
                "id_type":    "uuid" if _UUID_RE.match(str(uid_from_login))
                              else "numeric",
                "id_source":  "login_response",
                "context_url": self.base_url,
            })
            verified = True

        # Strategy A: JSON /me endpoints (most reliable — always try first)
        for path in _ME_ENDPOINTS:
            url  = self.base_url + path
            resp = test_client.get(url)
            if resp["status"] in (200, 201):
                verified = True
                body  = resp.get("body", "") or ""
                hints = self._extract_ids_from_body(body, url)
                id_hints.extend(hints)
                vprint(f"    [auth] /me endpoint {path}: {[h['id_val'] for h in hints]}")
                if hints:
                    return verified, self._dedup_hints(id_hints)
            elif resp["status"] not in (404, 0, 401, 403):
                verified = True

        # Strategy B: Compare authenticated vs unauthenticated homepage links.
        # Session-specific links — appear when logged in but NOT unauthenticated —
        # point to pages containing YOUR data (settings, profile, notifications).
        # This is the universal approach: works regardless of URL structure.
        if not id_hints:
            try:
                auth_resp = test_client.get(self.base_url)
                bare_resp = self.client.get(self.base_url)
                auth_body = auth_resp.get("body", "") or ""
                bare_body = bare_resp.get("body", "") or ""

                href_re    = re.compile(r'href=["\']([^"\'#?]{1,200})["\']', re.I)
                auth_hrefs = {m.group(1) for m in href_re.finditer(auth_body)}
                bare_hrefs = {m.group(1) for m in href_re.finditer(bare_body)}
                # Pages only visible when logged in = session-specific
                session_only = auth_hrefs - bare_hrefs
                vprint(f"    [auth] {len(session_only)} session-only links found vs unauthenticated")

                for href in list(session_only)[:20]:
                    full_url = urllib.parse.urljoin(self.base_url, href)
                    if not full_url.startswith(self.base_url):
                        continue
                    resp = test_client.get(full_url)
                    if resp["status"] not in (200, 201):
                        continue
                    body  = resp.get("body", "") or ""
                    if len(body) < 50:
                        continue
                    verified = True
                    hints = self._extract_ids_from_body(body, full_url)
                    if not hints:
                        hints = self._extract_ids_from_html(body, full_url, own_username=self._own_username)
                    if hints:
                        id_hints.extend(hints)
                        vprint(f"    [auth] Own IDs from session page {href}: "
                               f"{[h['id_val'] for h in hints]}")
                        break
            except Exception as e:
                vprint(f"    [auth] Session link diff error: {e}")

        # Strategy C: Common session-specific paths as fallback
        # (when auth-vs-unauth comparison finds nothing useful — e.g. same homepage)
        if not id_hints:
            session_pages = [
                "/settings", "/account/settings", "/user/settings",
                "/profile/edit", "/account/edit", "/account",
                "/me", "/my-account", "/my-profile",
                "/dashboard", "/home", "/app",
                "/notifications", "/inbox", "/messages",
                "/api/settings", "/api/account", "/api/profile",
            ]
            for page_path in session_pages:
                url  = self.base_url + page_path
                resp = test_client.get(url)
                if resp["status"] not in (200, 201):
                    continue
                body = resp.get("body", "") or ""
                if len(body) < 50:
                    continue
                verified = True
                hints = self._extract_ids_from_body(body, url)
                if not hints:
                    hints = self._extract_ids_from_html(body, url, own_username=self._own_username)
                if hints:
                    id_hints.extend(hints)
                    vprint(f"    [auth] Own IDs from {page_path}: {[h['id_val'] for h in hints]}")
                    break

        # Strategy D: Follow the login redirect destination (if non-trivial)
        login_url = self._login_url_hint
        if login_url and not id_hints:
            resp = test_client.post_no_redirect(login_url, {})
            loc  = resp.get("headers", {}).get("location", "") or ""
            if loc and loc not in ("/", ""):
                redir_url  = urllib.parse.urljoin(self.base_url, loc)
                redir_resp = test_client.get(redir_url)
                if redir_resp["status"] == 200:
                    verified = True
                    body  = redir_resp.get("body", "") or ""
                    hints = self._extract_ids_from_body(body, redir_url)
                    if not hints:
                        hints = self._extract_ids_from_html(body, redir_url, own_username=self._own_username)
                    if hints:
                        id_hints.extend(hints)
                        vprint(f"    [auth] Own IDs from login redirect {loc}: "
                               f"{[h['id_val'] for h in hints]}")

        # Strategy D: Base URL — only for verifying session, not ID harvest
        # (homepage has all users' IDs, not just ours — we don't harvest from it)
        if not verified:
            resp = test_client.get(self.base_url)
            if resp["status"] == 200:
                body = (resp.get("body", "") or "")[:2000]
                if not re.search(r'login|signin|please\s+log\s*in|not\s+authenticated',
                                 body, re.I):
                    verified = True

        return verified, self._dedup_hints(id_hints)

    def _dedup_hints(self, hints):
        seen = set()
        out  = []
        for h in hints:
            k = (h["id_val"], h["id_type"])
            if k not in seen:
                seen.add(k)
                out.append(h)
        return out

    def _extract_ids_from_html(self, body, context_url, own_username=None):
        """
        Extract the logged-in user's own ID from HTML pages.

        When own_username is provided, prioritises links whose surrounding
        text / link text matches the username — this pins the ID to the
        specific logged-in user rather than returning all users' IDs.

        Falls back to broad extraction when no username match found.
        """
        hints      = []
        own_hints  = []   # username-matched — highest confidence

        # Priority 0: Username-aware own-ID extraction
        # When we know the logged-in username, find href="/something/42" where:
        #   a) The link text contains the username, OR
        #   b) The link has class "active"/"current"/"self"/"me", OR
        #   c) A nearby element (same <li>, <div>) contains the username text
        # This identifies OUR profile link from a page full of other users' links.
        if own_username:
            uname_esc = re.escape(own_username.lower())
            # Pattern: <a href="PATH/42" ...>...username...</a>
            # or: <a href="PATH/42" class="active/current/self">
            tagged_re = re.compile(
                r'href=["\']([^"\'#?]{1,200})["\'][^>]*(?:class=["\'][^"\']*'
                r'(?:active|current|self|me|own)[^"\']*["\'])?[^>]*>'
                r'([^<]{0,200})</a>',
                re.I | re.S
            )
            for m in tagged_re.finditer(body[:32000]):
                href_val  = m.group(1)
                link_text = m.group(2).strip().lower()
                # Check if link text contains the username
                if own_username.lower() not in link_text:
                    # Check for active/current class instead
                    href_full = m.group(0)
                    class_m   = re.search(r'class=["\']([^"\']*)["\']', href_full, re.I)
                    css_class = (class_m.group(1) if class_m else "").lower()
                    if not any(k in css_class for k in ("active", "current", "self", "me", "own")):
                        continue
                # Extract numeric segments from the href
                segs = [s for s in href_val.rstrip("/").split("/") if s]
                for idx, seg in enumerate(segs):
                    if seg.isdigit() and int(seg) > 0:
                        parent = segs[idx-1].lower() if idx > 0 else ""
                        if re.match(r'^v\d*$', parent):
                            continue
                        own_hints.append({
                            "id_val":     seg,
                            "id_type":    "numeric",
                            "id_source":  "html:username_link",
                            "context_url": context_url,
                        })
            if own_hints:
                return own_hints   # high-confidence own-ID found — return immediately

            # Fallback: look for username in surrounding block then nearby href
            # Pattern: find the username text anywhere, then find the closest
            # preceding or following href with a numeric segment
            blocks = re.split(r'(?:</li>|</div>|</tr>|</td>|</nav>)', body[:32000], flags=re.I)
            for block in blocks:
                if own_username.lower() not in block.lower():
                    continue
                for m in re.finditer(r'href=["\']([^"\'#?]{1,200})["\']', block, re.I):
                    href_val = m.group(1)
                    segs = [s for s in href_val.rstrip("/").split("/") if s]
                    for idx, seg in enumerate(segs):
                        if seg.isdigit() and int(seg) > 0:
                            parent = segs[idx-1].lower() if idx > 0 else ""
                            if not re.match(r'^v\d*$', parent):
                                own_hints.append({
                                    "id_val":     seg,
                                    "id_type":    "numeric",
                                    "id_source":  "html:username_block",
                                    "context_url": context_url,
                                })
            if own_hints:
                return own_hints

        # Fallback generic extraction (used when no username match found,
        # or when called without own_username from non-session-specific pages)

        # 1. href links — scan ALL numeric segments in any path
        _STATIC_SKIP = re.compile(
            r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip)(\?|$)',
            re.I
        )
        _SEG_PAGINATION = frozenset({
            "page", "p", "pg", "step", "chunk", "batch",
            "v", "ver", "version", "rev", "revision",
            "ts", "t", "time", "date", "year", "month", "day",
            "size", "limit", "max", "min", "num", "n", "rows",
            "index", "start", "end", "pos", "position",
        })
        href_re = re.compile(r'href=["\']([^"\'#?]{2,200})["\']', re.I)
        for m in href_re.finditer(body[:32000]):
            href = m.group(1)
            if _STATIC_SKIP.search(href):
                continue
            segs = [s for s in href.rstrip("/").split("/") if s]
            for idx, seg in enumerate(segs):
                if not seg.isdigit() or int(seg) == 0:
                    continue
                parent = segs[idx - 1].lower() if idx > 0 else ""
                if re.match(r'^v\d*$', parent):
                    continue
                if parent in _SEG_PAGINATION:
                    continue
                if _NUMERIC_RE.match(seg):
                    hints.append({
                        "id_val":     seg,
                        "id_type":    "numeric",
                        "id_source":  "html:href_path",
                        "context_url": context_url,
                    })

        # 2. data-* attributes carrying user ID
        data_re = re.compile(
            r'data-(?:user-?id|uid|author-?id|owner-?id|member-?id|profile-?id)'
            r'\s*=\s*["\'](\d{1,8})["\']',
            re.I
        )
        for m in data_re.finditer(body[:32000]):
            hints.append({
                "id_val":     m.group(1),
                "id_type":    "numeric",
                "id_source":  "html:data_attr",
                "context_url": context_url,
            })

        # 3. JS variable assignments
        js_re = re.compile(
            r'(?:user_?id|userId|currentUser\.id|profile_?id|uid|loggedInId)'
            r'\s*[=:]\s*["\']?(\d{1,8})["\']?',
            re.I
        )
        for m in js_re.finditer(body[:32000]):
            val = m.group(1)
            if val not in ("0", ""):
                hints.append({
                    "id_val":     val,
                    "id_type":    "numeric",
                    "id_source":  "html:js_var",
                    "context_url": context_url,
                })

        # 4. Hidden form fields
        hidden_re = re.compile(
            r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']'
            r'(?:user_?id|uid|profile_?id|author_?id)["\'][^>]*value=["\'](\d{1,8})["\']',
            re.I
        )
        for m in hidden_re.finditer(body[:32000]):
            hints.append({
                "id_val":     m.group(1),
                "id_type":    "numeric",
                "id_source":  "html:hidden_field",
                "context_url": context_url,
            })

        # Dedup
        seen     = set()
        deduped  = []
        for h in hints:
            if h["id_val"] not in seen:
                seen.add(h["id_val"])
                deduped.append(h)
        return deduped

    def _extract_ids_from_body(self, body, context_url):
        """Extract user ID hints from a JSON /me response body."""
        hints = []
        try:
            obj = json.loads(body)
            self._recurse_id_extract(obj, hints, context_url, 0)
        except Exception:
            pass
        return hints

    def _recurse_id_extract(self, obj, hints, ctx, depth):
        if depth > 4:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _IDOR_PARAM_NAME_RE.match(str(k)):
                    val = str(v) if v is not None else ""
                    if _NUMERIC_RE.match(val):
                        hints.append({"id_val": val, "id_type": "numeric",
                                       "id_source": f"me_response:{k}",
                                       "context_url": ctx})
                    elif _UUID_RE.match(val):
                        hints.append({"id_val": val, "id_type": "uuid",
                                       "id_source": f"me_response:{k}",
                                       "context_url": ctx})
                if isinstance(v, dict):
                    self._recurse_id_extract(v, hints, ctx, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:5]:
                self._recurse_id_extract(item, hints, ctx, depth + 1)


# ─────────────────────────────────────────────────────────────────────────────
# FIELD CLASSIFIER
# Analyses any HTML form field and returns the most plausible fill value.
# Used by AutoRegistrar to handle unknown / unusual registration fields.
# ─────────────────────────────────────────────────────────────────────────────
class FieldClassifier:
    """
    Classifies a form field by name, type, placeholder, label, and pattern
    attributes, then generates a realistic value for it.

    Call:  value = FieldClassifier().fill(field_dict, credentials)
    Where field_dict has keys: name, type, value, placeholder, label, pattern
    and credentials has keys:  username, email, password, display_name, phone
    """

    # ── Category keyword maps (field name → category) ───────────────────────
    # Checked in priority order — first match wins
    _NAME_MAP = [
        # ── Identity — most specific first ──
        ("email",        ("email", "mail", "e_mail", "email_addr",
                          "emailaddress", "email_address")),
        ("username",     ("username", "user_name", "login", "loginname",
                          "login_name", "user_login", "account_name",
                          "accountname", "nickname", "nick_name",
                          "screen_name", "screenname", "handle")),
        # first/last BEFORE display_name — "firstname" must not match "name"
        ("first_name",   ("firstname", "first_name", "fname",
                          "given_name", "givenname", "forename",
                          "first")),
        ("last_name",    ("lastname", "last_name", "lname", "surname",
                          "family_name", "familyname", "last")),
        ("display_name", ("display", "displayname", "display_name",
                          "fullname", "full_name", "realname", "real_name",
                          "your_name", "yourname", "first_last",
                          "firstname_lastname",
                          "name")),          # "name" alone last in this group
        # ── Auth — confirm_pass BEFORE password so "confirm_password" matches correctly ──
        ("confirm_pass", ("confirm", "confirmation", "verify", "retype",
                          "re_enter", "reenter", "repeat",
                          "password_confirm", "confirm_password",
                          "confirmpassword", "password_confirmation",
                          "password2", "pass2", "passwd2",
                          "re_password", "repassword", "repeat_password",
                          "confirm_pass", "confirmpass",
                          "confirm_passphrase", "passphrase_confirm")),
        ("password",     ("password", "passwd", "pass", "pwd", "secret",
                          "passphrase", "pass_phrase",
                          "new_password", "newpassword", "create_password",
                          "createpassword", "account_password",
                          "user_password", "login_password")),
        # ── Contact ──
        ("phone",        ("phone", "mobile", "cell", "telephone", "tel",
                          "phonenumber", "phone_number", "mobile_number",
                          "cellphone", "contact_number", "contactnumber")),
        ("website",      ("website", "url", "web", "homepage", "site",
                          "blog", "portfolio")),
        # ── Personal ──
        ("dob",          ("dob", "birthday", "birth_date", "birthdate",
                          "date_of_birth", "dateofbirth", "born",
                          "birth", "birthyear", "birth_year")),
        ("gender",       ("gender", "sex", "pronouns")),
        ("country",      ("country", "nation", "country_code",
                          "nationality")),
        ("city",         ("city", "town", "locality")),
        ("address",      ("address", "street", "addr", "location")),
        ("zip",          ("zip", "zipcode", "zip_code", "postal",
                          "postcode", "postal_code")),
        # ── Profile ──
        ("bio",          ("bio", "about", "description", "about_me",
                          "aboutme", "profile_text", "summary",
                          "introduction", "intro", "blurb")),
        ("company",      ("company", "organization", "organisation",
                          "employer", "workplace", "corp", "business",
                          "firm")),
        ("job_title",    ("title", "job", "jobtitle", "job_title",
                          "position", "role", "occupation", "profession")),
        # ── Security ──
        ("invite_code",  ("invite", "invitation", "referral", "ref_code",
                          "promo", "coupon", "voucher", "access_code",
                          "invite_code", "registration_code",
                          "signup_code")),
        ("secret_q",     ("security_question", "secret_question",
                          "hint_question", "sq")),
        ("secret_a",     ("security_answer", "secret_answer", "hint_answer",
                          "sa")),
        # ── Agreements ──
        ("terms",        ("terms", "tos", "agree", "accept",
                          "i_agree", "terms_of_service",
                          "terms_and_conditions", "privacy",
                          "consent", "gdpr", "newsletter",
                          "marketing", "subscribe", "optin",
                          "opt_in")),
        # ── age BEFORE quantity so "age" doesn't fall through ──
        ("age_num",      ("age", "years_old", "how_old", "your_age")),
        ("quantity",     ("qty", "quantity", "amount", "count", "number")),
    ]

    # ── HTML input type → category ───────────────────────────────────────────
    _TYPE_MAP = {
        "email":    "email",
        "tel":      "phone",
        "url":      "website",
        "date":     "dob",
        "number":   "quantity",
        "checkbox": "terms",
        "radio":    "gender",
        "range":    "quantity",
    }

    # ── Plausible value generators per category ──────────────────────────────
    # Values are realistic-looking to pass common server-side validations

    _FIRST_NAMES  = ["Alex","Jordan","Morgan","Taylor","Casey","Riley",
                     "Cameron","Quinn","Avery","Blake"]
    _LAST_NAMES   = ["Smith","Johnson","Williams","Brown","Davis",
                     "Miller","Wilson","Moore","Taylor","Anderson"]
    _COMPANIES    = ["Acme Corp","Test Industries","Example Ltd",
                     "Sample Solutions","Demo Enterprises"]
    _JOB_TITLES   = ["Software Engineer","Developer","Analyst",
                     "Designer","Consultant","Manager"]
    _COUNTRIES    = ["US","GB","CA","AU","DE"]
    _CITIES       = ["New York","London","Toronto","Sydney","Berlin"]
    _BIOS         = [
        "Security researcher and developer.",
        "Software professional interested in web technologies.",
        "Tech enthusiast building cool things.",
    ]
    _SEC_QUESTIONS = [
        "What is your mother's maiden name?",
        "What was the name of your first pet?",
        "What city were you born in?",
    ]

    def classify(self, field):
        """
        Classify a field dict → return category string.
        Uses longest-keyword-first matching so 'firstname' matches first_name
        before display_name's generic 'name' keyword.
        """
        fname = (field.get("name") or "").lower().strip()
        ftype = (field.get("type") or "text").lower().strip()
        fph   = (field.get("placeholder") or "").lower()
        flab  = (field.get("label") or "").lower()

        # 1. Type-based classification (high confidence for specific types)
        # Exception: "number" type is too generic — check name first for age fields
        if ftype in self._TYPE_MAP and ftype != "number":
            return self._TYPE_MAP[ftype]

        # 2. Build flat keyword list sorted by length DESC
        #    so longer/more-specific keywords always win over short ones.
        #    e.g. "firstname" (9) beats "name" (4) for field "firstname"
        all_kws = []
        for category, keywords in self._NAME_MAP:
            for kw in keywords:
                all_kws.append((len(kw), category, kw))
        all_kws.sort(key=lambda x: -x[0])

        # Strip common prefixes/suffixes
        clean = re.sub(r'^(new_|re_|confirm_|user_|your_|my_)', '', fname)
        clean = re.sub(r'(_input|_field|_val|_value|_entry)$', '', clean)

        # Exact match pass
        for _, category, kw in all_kws:
            if clean == kw or fname == kw:
                return category

        # Contains match pass (longer keywords first prevents false substring hits)
        for _, category, kw in all_kws:
            if len(kw) >= 4:   # skip tiny keywords like "id", "re" in contains mode
                if kw in clean or kw in fname:
                    return category

        # 3. Placeholder / label text fallback
        combined = fph + " " + flab
        for _, category, kw in all_kws:
            if len(kw) >= 4 and kw in combined:
                return category

        # 4. Pattern attribute hints
        pattern = (field.get("pattern") or "").lower()
        if pattern:
            if re.search(r'\[0-9\].*\[0-9\]', pattern):
                return "phone"
            if "@" in pattern:
                return "email"

        return "unknown"

    def fill(self, field, credentials):
        """
        Return the most plausible value for a field given credentials dict.
        credentials keys: username, email, password, display_name, phone, label
        """
        category = self.classify(field)
        fname    = field.get("name", "")
        ftype    = (field.get("type") or "text").lower()
        label    = credentials.get("label", "a")  # "a" or "b" for two users

        c = credentials  # shorthand

        if category == "email":
            return c["email"]

        elif category == "username":
            return c["username"]

        elif category == "display_name":
            return c["display_name"]

        elif category == "first_name":
            return c["first_name"]

        elif category == "last_name":
            return c["last_name"]

        elif category == "password":
            return c["password"]

        elif category == "confirm_pass":
            return c["password"]

        elif category == "phone":
            return c["phone"]

        elif category == "website":
            return f"https://example.com/~{c['username']}"

        elif category == "dob":
            # Various date formats apps use
            if ftype == "date":
                return "1990-01-15"
            # Detect format from placeholder or pattern
            ph = (field.get("placeholder") or "").upper()
            if "MM/DD/YYYY" in ph or "MM-DD-YYYY" in ph:
                return "01/15/1990"
            if "DD/MM/YYYY" in ph or "DD-MM-YYYY" in ph:
                return "15/01/1990"
            if "YYYY-MM-DD" in ph:
                return "1990-01-15"
            return "1990-01-15"   # ISO default

        elif category == "gender":
            if ftype == "radio":
                return field.get("value", "other")
            return "other"

        elif category == "country":
            return "US"

        elif category == "city":
            return random.choice(self._CITIES)

        elif category == "address":
            return f"123 Test Street"

        elif category == "zip":
            return "10001"

        elif category == "bio":
            return random.choice(self._BIOS)

        elif category == "company":
            return random.choice(self._COMPANIES)

        elif category == "job_title":
            return random.choice(self._JOB_TITLES)

        elif category == "invite_code":
            # Leave blank — most invite codes are unknown.
            # If blank causes failure, caller retries without this field.
            return ""

        elif category == "secret_q":
                    # For <select> dropdowns, use the field's own value attr if present
                    # (set during form parsing), otherwise fall back to free text
                    if field.get("type") == "select" or field.get("options"):
                        opts = field.get("options") or []
                        if opts:
                            # Pick first non-empty option value
                            for opt in opts:
                                v = opt.get("value", "") if isinstance(opt, dict) else str(opt)
                                if v and v not in ("", "0", "null", "none", "select"):
                                    return v
                    return random.choice(self._SEC_QUESTIONS)

        elif category == "secret_a":
            return "TestAnswer123"

        elif category == "terms":
            # Checkboxes: return the field's own value attr or "1"/"true"
            if ftype == "checkbox":
                return field.get("value") or "1"
            return "1"

        elif category == "age_num":
            if ftype == "number":
                return "25"
            return "25"

        elif category == "quantity":
            return field.get("value") or "1"

        else:
            # Unknown field — best-effort based on input type
            if ftype == "email":
                return c["email"]
            if ftype in ("text", "search"):
                # If name looks like it wants a name, give display_name
                n = fname.lower()
                if any(x in n for x in ("name", "alias", "display", "nick")):
                    return c["display_name"]
                return c["username"]
            if ftype in ("number", "range"):
                return field.get("value") or "1"
            if ftype == "checkbox":
                return field.get("value") or "1"
            if ftype == "textarea":
                return "Test user profile."
            if ftype == "url":
                return "https://example.com"
            # Truly unknown — use display_name as safest generic value
            return c["display_name"]


# ─────────────────────────────────────────────────────────────────────────────
# AUTO-REGISTRAR  — creates two fresh accounts from scratch
# ─────────────────────────────────────────────────────────────────────────────
class AutoRegistrar:
    """
    Creates two fresh user accounts on the target when no credentials
    are supplied. Uses FieldClassifier to fill every registration field
    regardless of what the app calls them.

    Supports:
      - username / email / password / confirm-password
      - display_name / first_name / last_name
      - phone / dob / gender / country / bio / company
      - passphrase (treated as password)
      - invite_code (tried blank, then retried with common test codes)
      - terms/checkbox fields (auto-checked)
      - Any other field filled with a plausible default
    """

    _DOMAINS = ["example.com", "test.local", "mailtest.dev", "fakeuser.io"]

    # Common invite/promo codes to try when registration requires one
    _INVITE_CODES = ["TEST", "INVITE", "BETA", "DEMO", "FREE",
                     "test123", "invite123", "beta2024", "welcome"]

    def __init__(self, client, base_url, probe_result):
        self.client       = client
        self.base_url     = base_url.rstrip("/")
        self.probe_result = probe_result
        self._classifier  = FieldClassifier()

    def _parse_password_constraints(self, reg_form):
        """
        Read minlength, maxlength, pattern, and data-* attributes from
        the password field to generate a conforming password.
        Returns dict: {minlen, maxlen, pattern, requires_upper, requires_digit,
                       requires_special, requires_lower}
        """
        constraints = {
            "minlen":           8,
            "maxlen":           128,
            "pattern":          None,
            "requires_upper":   True,
            "requires_lower":   True,
            "requires_digit":   True,
            "requires_special": True,
        }
        for field in reg_form.get("fields", []):
            if self._classifier.classify(field) != "password":
                continue
            # minlength / maxlength HTML attributes
            if field.get("minlength"):
                try: constraints["minlen"] = max(constraints["minlen"], int(field["minlength"]))
                except: pass
            if field.get("maxlength"):
                try: constraints["maxlen"] = min(constraints["maxlen"], int(field["maxlength"]))
                except: pass
            # pattern attribute — parse requirements from it
            pat = field.get("pattern") or ""
            if pat:
                constraints["pattern"] = pat
                # Common patterns that restrict character classes
                if "a-z" not in pat.lower():
                    constraints["requires_lower"] = False
                if "A-Z" not in pat:
                    constraints["requires_upper"] = False
                if "0-9" not in pat and r"\d" not in pat:
                    constraints["requires_digit"] = False
                if not any(c in pat for c in ("!@#$%^&*", r"\W", "special")):
                    constraints["requires_special"] = False
            # data-password-strength or similar hints
            for attr in ("data-minlength", "data-min-length", "data-strength"):
                val = field.get(attr)
                if val:
                    try: constraints["minlen"] = max(constraints["minlen"], int(val))
                    except: pass
            break
        return constraints

    def generate_credentials(self, label="a"):
        """
        Generate a complete, realistic credential set.
        Password is generated to satisfy the broadest possible set of
        webapp password policies: length, uppercase, lowercase, digits, special.
        """
        rand   = "".join(random.choices(string.ascii_lowercase, k=6))
        num    = random.randint(100, 999)
        first  = random.choice(FieldClassifier._FIRST_NAMES)
        last   = random.choice(FieldClassifier._LAST_NAMES)
        uname  = f"tuser_{rand}{num}"
        email  = f"{uname}@{random.choice(self._DOMAINS)}"
        pwd    = self._generate_password()
        phone  = f"+1555{random.randint(1000000, 9999999)}"

        return {
            "label":        label,
            "username":     uname,
            "email":        email,
            "password":     pwd,
            "display_name": f"{first} {last}",
            "first_name":   first,
            "last_name":    last,
            "phone":        phone,
        }

    def _generate_password(self, constraints=None):
        """
        Generate a password that satisfies the given constraints dict.
        If no constraints, generates one that satisfies most common policies:
          - 16 characters (exceeds most minimums)
          - At least 2 uppercase, 2 lowercase, 2 digits, 2 special
          - Special chars limited to @!#$ (avoids apps that restrict to alphanum+@)
          - No spaces (many apps reject them)
          - Does not start with a special character (some apps reject this)
        """
        if constraints is None:
            constraints = {
                "minlen": 8, "maxlen": 128,
                "requires_upper": True, "requires_lower": True,
                "requires_digit": True, "requires_special": True,
            }

        target_len = max(constraints["minlen"], 16)
        target_len = min(target_len, constraints["maxlen"])

        # Safe special chars — accepted by virtually all apps
        specials = "@!#$"

        # Build guaranteed character pool
        parts = []
        if constraints["requires_upper"]:
            parts += random.choices(string.ascii_uppercase, k=3)
        if constraints["requires_lower"]:
            parts += random.choices(string.ascii_lowercase, k=3)
        if constraints["requires_digit"]:
            parts += random.choices(string.digits, k=3)
        if constraints["requires_special"]:
            parts += random.choices(specials, k=2)

        # Fill remaining length with mixed alphanumeric
        remaining = target_len - len(parts)
        if remaining > 0:
            pool = string.ascii_letters + string.digits
            if constraints["requires_special"]:
                pool += specials
            parts += random.choices(pool, k=remaining)

        # Shuffle but ensure first char is a letter (not special/digit)
        random.shuffle(parts)
        # Ensure first char is alpha
        for i, c in enumerate(parts):
            if c.isalpha():
                parts[0], parts[i] = parts[i], parts[0]
                break

        return "".join(parts)

    def _build_payload(self, reg_form, credentials, invite_code=None):
        """
        Build a POST payload for the registration form using FieldClassifier.
        Returns dict ready to POST.
        """
        payload = dict(reg_form.get("hidden", {}))

        # CSRF
        csrf_name = self.probe_result.get("csrf_field")
        if csrf_name:
            reg_page = self.client.get(self.probe_result["register_url"])
            csrf_re  = re.compile(
                r'<input[^>]+name=["\']' + re.escape(csrf_name) +
                r'["\'][^>]*value=["\']([^"\']+)["\']', re.I)
            m = csrf_re.search(reg_page.get("body", "") or "")
            if m:
                payload[csrf_name] = m.group(1)

        # Try to extract label text for each field from the page
        # so FieldClassifier has more context for ambiguous fields
        label_map = self._extract_labels(reg_form)

        for field in reg_form.get("fields", []):
            fname = field["name"]
            # Enrich field with label text if found
            enriched = {**field, "label": label_map.get(fname, "")}

            # Override invite_code if we're doing a retry with a known code
            category = self._classifier.classify(enriched)
            if category == "invite_code" and invite_code is not None:
                payload[fname] = invite_code
                continue

            val = self._classifier.fill(enriched, credentials)
            if val != "":   # don't send empty strings for required fields
                payload[fname] = val
            # If blank (invite_code unknown), omit the field entirely
            # so the server tells us whether it's required

        return payload

    def _extract_labels(self, reg_form):
        """
        Extract label text from the raw form HTML for input correlation.
        Maps field name → label text.
        Falls back to placeholder text.
        """
        label_map = {}
        reg_url = self.probe_result.get("register_url", "")
        try:
            resp = self.client.get(reg_url)
            body = resp.get("body", "") or ""
            # Match <label for="fname">First Name</label>
            for m in re.finditer(
                r'<label[^>]*(?:for|id)=["\']([^"\']+)["\'][^>]*>(.*?)</label>',
                body, re.I | re.S
            ):
                field_id   = m.group(1).strip()
                label_text = re.sub(r'<[^>]+>', '', m.group(2)).strip()
                label_map[field_id] = label_text
            # Also map placeholder → field name
            for field in reg_form.get("fields", []):
                if field.get("placeholder"):
                    label_map.setdefault(field["name"], field["placeholder"])
        except Exception:
            pass
        return label_map

    def _is_registration_success(self, resp, credentials):
        """
        Determine if a registration response indicates success or failure.
        A 302 to homepage is ambiguous — could be success OR failure.
        We check for failure signals in the response body/location.
        """
        status   = resp.get("status", 0)
        body     = (resp.get("body", "") or "").lower()
        location = (resp.get("headers", {}).get("location", "") or "").lower()

        # Clear failure signals
        failure_body_signals = (
            "invalid", "error", "failed", "incorrect", "already",
            "exists", "taken", "too short", "too long", "weak",
            "required", "must contain", "does not match",
            "password must", "username must",
        )
        if any(s in body for s in failure_body_signals):
            return False

        # If redirected back to register page — failure
        if status in range(301, 310) and any(
            s in location for s in ("register", "signup", "sign-up", "error")
        ):
            return False

        # 2xx → success
        if status in range(200, 300):
            # But check if the 200 body looks like an error page
            if any(s in body for s in failure_body_signals):
                return False
            return True

        # 3xx not to register/error → treat as success
        if status in range(300, 310):
            return True

        return False

    def register(self, credentials, retry_invite=True):
        """
        Attempt to register one user.
        Uses form constraints to generate a conforming password.
        Returns (success: bool, response: dict)
        """
        reg_url  = self.probe_result.get("register_url")
        reg_form = self.probe_result.get("register_form") or {}

        if not reg_url:
            return False, {}

        ct = self.probe_result.get("content_type", "form")

        # Read password constraints from form and regenerate password if needed
        constraints = self._parse_password_constraints(reg_form)
        if (len(credentials["password"]) < constraints["minlen"] or
                len(credentials["password"]) > constraints["maxlen"]):
            # Regenerate conforming password
            _minlen = constraints["minlen"]
            credentials = {
                **credentials,
                "password": self._generate_password(constraints)
            }
            tprint(f"  {info(f'Password regenerated to meet form constraints (min={_minlen})')}")

        # If invite code was supplied by operator, use it from first attempt
        # Don't wait for failure+retry — the form may 302→/ on missing invite
        # which _is_registration_success() mistakenly treats as success
        user_supplied_code = self.probe_result.get("_invite_code_hint")

        # Attempt 1 — with operator-supplied invite code (if any), blank otherwise
        payload = self._build_payload(reg_form, credentials,
                                      invite_code=user_supplied_code)
        resp    = self.client.post_no_redirect(reg_url, payload, ct)
        status  = resp.get("status", 0)

        vprint(f"    [reg] POST {reg_url} → {status}  fields={list(payload.keys())}")
        vprint(f"    [reg] body[:150] = {(resp.get('body','') or '')[:150]}")

        if self._is_registration_success(resp, credentials):
            return True, resp

        body = (resp.get("body", "") or "").lower()

        # Attempt 2 — invite code required but not supplied or wrong?
        needs_invite = any(kw in body for kw in (
            "invite", "invitation", "referral", "access code",
            "promo", "voucher", "registration code"
        ))
        if needs_invite and retry_invite:
            # Try generic codes — user_supplied_code already tried in Attempt 1
            for code in self._INVITE_CODES:
                if code == user_supplied_code:
                    continue
                payload = self._build_payload(reg_form, credentials, invite_code=code)
                resp    = self.client.post_no_redirect(reg_url, payload, ct)
                vprint(f"    [reg] invite retry '{code}' → {resp.get('status')}")
                if self._is_registration_success(resp, credentials):
                    tprint(f"  {info(f'Registration succeeded with invite code: {code}')}")
                    return True, resp

        # Attempt 3 — try JSON content type if form-encoded failed
        if ct != "json":
            resp_json = self.client.post_no_redirect(reg_url, payload, "json")
            vprint(f"    [reg] JSON retry → {resp_json.get('status')}")
            if self._is_registration_success(resp_json, credentials):
                return True, resp_json

        # Always print failure details — helps diagnose what went wrong
        tprint(f"  {warn(f'Registration attempt failed (HTTP {status})')}")
        fail_body = (resp.get("body", "") or "")[:300]
        if fail_body:
            tprint(f"  {color('Server response:', C.DIM)} {fail_body[:200]}")

        return False, resp

    def register_two_users(self):
        """
        Register User A and User B.
        Reads password constraints from the form before generating credentials
        so passwords always conform to the app's requirements.
        Returns (creds_a, creds_b) on success, raises RuntimeError on failure.
        """
        reg_form    = self.probe_result.get("register_form") or {}
        constraints = self._parse_password_constraints(reg_form)
        vprint(f"    [reg] password constraints: {constraints}")

        creds_a = self.generate_credentials("a")
        creds_b = self.generate_credentials("b")

        # Apply constraints to generated passwords
        creds_a["password"] = self._generate_password(constraints)
        creds_b["password"] = self._generate_password(constraints)

        _ua_name = creds_a["username"]; _ua_mail = creds_a["email"]
        tprint(f"  {info(f'Registering User A: {_ua_name} / {_ua_mail}')}")
        ok_a, resp_a = self.register(creds_a)
        if not ok_a:
            status_a = resp_a.get("status", "?")
            body_a   = (resp_a.get("body", "") or "")[:300]
            raise RuntimeError(
                f"Auto-registration of User A failed (HTTP {status_a}).\n"
                f"  Server said: {body_a}\n"
                f"  → Try --login-user-a/b with existing accounts\n"
                f"  → Or --cookie-a/b with captured session tokens"
            )

        _ua = creds_a["username"]; _ue = creds_a["email"]
        tprint(f"  {ok(f'User A registered: {_ua} ({_ue})')}")
        time.sleep(0.8)

        _ub_name = creds_b["username"]; _ub_mail = creds_b["email"]
        tprint(f"  {info(f'Registering User B: {_ub_name} / {_ub_mail}')}")
        ok_b, resp_b = self.register(creds_b)
        if not ok_b:
            status_b = resp_b.get("status", "?")
            body_b   = (resp_b.get("body", "") or "")[:300]
            raise RuntimeError(
                f"Auto-registration of User B failed (HTTP {status_b}).\n"
                f"  Server said: {body_b}\n"
                f"  → Try --login-user-a/b with existing accounts"
            )

        _ub = creds_b["username"]; _ubmail = creds_b["email"]
        tprint(f"  {ok(f'User B registered: {_ub} ({_ubmail})')}")
        return creds_a, creds_b


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ENGINE  — top-level orchestrator
# ─────────────────────────────────────────────────────────────────────────────
class AuthEngine:
    """
    Top-level orchestrator. Given a bare HTTPClient and target URL,
    plus optional credentials, returns two ready-to-use HTTPClient instances
    and a list of User A's own object ID hints.

    Usage:
        engine = AuthEngine(bare_client, target_url)
        result = engine.run(
            user_a=("alice", "pass1"),   # or None for auto-register
            user_b=("bob",   "pass2"),
        )
        # result.client_a  — authenticated session for User A
        # result.client_b  — authenticated session for User B
        # result.id_hints  — User A's known object IDs (for IDOR seeding)
        # result.probe     — full probe result (login_url etc.)
        # result.creds_a   — credentials used (useful when auto-registered)
        # result.creds_b
    """

    def __init__(self, client, base_url, tprint_fn=None, invite_code_hint=None):
        """
        client:             A bare (unauthenticated) HTTPClient instance
        base_url:           Target application base URL
        tprint_fn:          Optional print function (thread-safe). Defaults to print.
        invite_code_hint:   Optional invite/registration code (from --invite-code flag)
        """
        self.client              = client
        self.base_url            = base_url.rstrip("/")
        self._tprint             = tprint_fn or print
        self._invite_code_hint   = invite_code_hint

    # ── Public ─────────────────────────────────────────────────────────────
    def run(self, user_a=None, user_b=None, auto_register=False):
        """
        Main entry point.

        user_a / user_b: (username_or_email, password) tuples, or None
        auto_register:   If True and no creds supplied, register two fresh accounts

        Returns an AuthResult namedtuple-like object.
        """
        # Step 1: Probe the app for login/register form shape
        self._tprint(self._label("Probing app for auth endpoints..."))
        probe = AuthProbe(self.client, self.base_url).discover()

        login_url = probe.get("login_url")
        reg_url   = probe.get("register_url")

        self._tprint(
            self._label(
                f"Login URL: {login_url or 'not found'}  "
                f"Register URL: {reg_url or 'not found'}"
            )
        )

        # Step 2: If no credentials, auto-register or fail
        creds_a = user_a
        creds_b = user_b
        raw_a   = None
        raw_b   = None

        if not creds_a or not creds_b:
            if auto_register:
                if not reg_url:
                    raise RuntimeError(
                        "auto_register=True but no register endpoint found. "
                        "Provide --login-user-a/b credentials manually.")
                self._tprint(self._label("Auto-registering two test accounts..."))
                # Inject user-supplied invite code hint into probe
                if self._invite_code_hint:
                    probe = {**probe, "_invite_code_hint": self._invite_code_hint}
                registrar = AutoRegistrar(self.client, self.base_url, probe)
                raw_a, raw_b = registrar.register_two_users()
                # Store both username and email — try both on login
                creds_a = (raw_a["username"], raw_a["password"], raw_a["email"])
                creds_b = (raw_b["username"], raw_b["password"], raw_b["email"])
                self._tprint(self._label(
                    f"Registered: {raw_a['username']} / {raw_b['username']}"))
            else:
                raise RuntimeError(
                    "No credentials supplied and auto_register=False. "
                    "Provide credentials or pass auto_register=True.")

        def _try_login(builder, creds_tuple, label):
            """
            Try logging in with username, then email, then JSON content-type.
            creds_tuple: (username, password) or (username, password, email)
            """
            username = creds_tuple[0]
            password = creds_tuple[1]
            email    = creds_tuple[2] if len(creds_tuple) > 2 else None

            # Attempt 1: username + form encoding
            self._tprint(self._label(f"Logging in {label} as '{username}'..."))
            ok, hdrs, hints = builder.login(username, password, probe)
            if ok:
                return True, hdrs, hints

            # Attempt 2: email + form encoding (if we have an email)
            if email and email != username:
                self._tprint(self._label(f"Retrying {label} with email '{email}'..."))
                ok, hdrs, hints = builder.login(email, password, probe)
                if ok:
                    return True, hdrs, hints

            # Attempt 3: username + JSON body
            probe_json = {**probe, "content_type": "json"}
            self._tprint(self._label(f"Retrying {label} with JSON body..."))
            ok, hdrs, hints = builder.login(username, password, probe_json)
            if ok:
                return True, hdrs, hints

            # Attempt 4: email + JSON body
            if email and email != username:
                ok, hdrs, hints = builder.login(email, password, probe_json)
                if ok:
                    return True, hdrs, hints

            return False, {}, []

        # Step 3: Login User A
        builder_a = SessionBuilder(self.client, self.base_url)
        ok_a, hdrs_a, id_hints_a = _try_login(builder_a, creds_a, "User A")

        if not ok_a:
            raise RuntimeError(
                f"Login failed for User A ({creds_a[0]}).\n"
                f"  Registration succeeded but login failed — possible causes:\n"
                f"  • App requires email verification before login\n"
                f"  • Password was rejected at registration despite 302 response\n"
                f"  • Login form uses different field names than expected\n"
                f"  → Run with --verbose for detailed login attempt log\n"
                f"  → Or supply --cookie-a with a manually captured token"
            )

        self._tprint(self._label(
            f"User A authenticated — {len(id_hints_a)} own ID(s) harvested"))

        # Step 4: Login User B
        builder_b = SessionBuilder(self.client, self.base_url)
        ok_b, hdrs_b, _ = _try_login(builder_b, creds_b, "User B")

        if not ok_b:
            raise RuntimeError(
                f"Login failed for User B ({creds_b[0]}).\n"
                f"  → Run with --verbose for detailed login attempt log\n"
                f"  → Or supply --cookie-b with a manually captured token"
            )

        self._tprint(self._label("User B authenticated."))

        # Step 5: Build authenticated HTTPClient instances
        client_a = self.client.clone_no_auth()
        for k, v in hdrs_a.items():
            if not k.startswith("_"):
                client_a.headers[k] = v

        client_b = self.client.clone_no_auth()
        for k, v in hdrs_b.items():
            if not k.startswith("_"):
                client_b.headers[k] = v

        return AuthResult(
            client_a   = client_a,
            client_b   = client_b,
            id_hints   = id_hints_a,
            probe      = probe,
            creds_a    = creds_a,
            creds_b    = creds_b,
        )

    def _label(self, msg):
        return f"  [AUTH] {msg}"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH RESULT
# ─────────────────────────────────────────────────────────────────────────────
class AuthResult:
    """Container for AuthEngine output."""
    __slots__ = ("client_a", "client_b", "id_hints",
                 "probe", "creds_a", "creds_b")

    def __init__(self, client_a, client_b, id_hints, probe, creds_a, creds_b):
        self.client_a = client_a
        self.client_b = client_b
        self.id_hints = id_hints
        self.probe    = probe
        self.creds_a  = creds_a
        self.creds_b  = creds_b

# ─────────────────────────────────────────────────────────────────────────────
# JS ENDPOINT EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────
class JSExtractor:
    _REST = [
        re.compile(r'axios\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'fetch\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'\$\.(get|post|ajax)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'XMLHttpRequest[^;]{0,200}\.open\s*\(\s*["\']([A-Z]+)["\']\s*,\s*["\']([^"\']{3,80})["\']', re.I),
        re.compile(
            r'["\`](/(?:api|v\d+|rest|admin|user|account|profile|order|invoice|doc)'
            r'[a-zA-Z0-9_\-\./]*)["\`]', re.I),
    ]
    _ROUTER = re.compile(
        r'(?:router|app|Route)\s*\.\s*(get|post|put|delete|patch|use)'
        r'\s*\(\s*["\']([^"\']{2,60})["\']', re.I)
    _QS    = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', re.I)
    _NOISE = re.compile(
        r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$'
        r'|^/static/|^/assets/|^/images/|^/fonts/|^/dist/', re.I)

    def _valid(self, p):
        if not p or not isinstance(p, str): return False
        p = p.split("?")[0].split("#")[0]
        return p.startswith("/") and 2 <= len(p) <= 120 and not self._NOISE.search(p)

    def _norm(self, p):
        p = p.split("#")[0].split("?")[0]
        return re.sub(r'//+', '/', p).rstrip("/") or "/"

    def extract(self, js_content, base_url=""):
        results = {}
        def add(path, method, params):
            if not self._valid(path): return
            norm = self._norm(path)
            if norm not in results:
                results[norm] = {"path": norm, "method": method.upper(),
                                 "params": list(params), "base_url": base_url}
            else:
                results[norm]["params"] = sorted(
                    set(results[norm]["params"] + list(params)))

        for pat in self._REST:
            for m in pat.finditer(js_content):
                g = m.groups()
                if len(g) == 1:
                    path, method = g[0], "GET"
                else:
                    a, b = g[0], g[1]
                    if a.upper() in ("GET","POST","PUT","DELETE","PATCH"):
                        method, path = a.upper(), b
                    elif b.upper() in ("GET","POST","PUT","DELETE","PATCH"):
                        method, path = b.upper(), a
                    else:
                        path, method = a, "GET"
                add(path.split("?")[0], method, self._QS.findall(path))

        for m in self._ROUTER.finditer(js_content):
            method, path = m.group(1), m.group(2)
            if method.lower() == "use": method = "GET"
            add(path, method, [])

        return list(results.values())

# ─────────────────────────────────────────────────────────────────────────────
# HTML FORM / LINK PARSER
# ─────────────────────────────────────────────────────────────────────────────
class PageParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self._base    = urllib.parse.urlparse(base_url)
        self.links    = set()
        self.js_links = set()
        self.forms    = []
        self._form    = None
        self.id_links = []   # (full_url, id_val, id_source)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            href = (a.get("href") or "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "#", "tel:", "data:")):
                full = urllib.parse.urljoin(self.base_url, href)
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
            self._form = {"action": action, "method": a.get("method", "GET").upper(), "inputs": []}

        elif tag in ("input", "textarea", "select") and self._form is not None:
            name  = (a.get("name") or a.get("id") or "").strip()
            itype = a.get("type", "text").lower()
            value = a.get("value", "")

            if not name:
                return

            if itype == "hidden":
                self._form["hidden"][name] = value
            elif itype not in ("submit", "button", "reset", "image", "file"):
                field_entry = {
                    "name":  name,
                    "type":  "select" if tag == "select" else itype,
                    "value": value,
                    "options": [],
                }
                self._form["fields"].append(field_entry)
                # Track current select for option harvesting
                if tag == "select":
                    self._current_select = field_entry

        elif tag == "option" and self._form is not None:
            sel = getattr(self, "_current_select", None)
            if sel is not None:
                val  = a.get("value", "")
                # Skip placeholder options
                if val and val not in ("", "0", "null", "none"):
                    sel["options"].append({"value": val})

    def handle_endtag(self, tag):
        if tag == "form" and self._form:
            if self._form["inputs"]:
                self.forms.append(self._form)
            self._form = None

    def _harvest_ids_from_url(self, url):
        parsed = urllib.parse.urlparse(url)
        # Path segment IDs
        for m in _PATH_NUMERIC_RE.finditer(parsed.path):
            self.id_links.append((url, m.group(1), "path_numeric"))
        for m in _PATH_UUID_RE.finditer(parsed.path):
            self.id_links.append((url, m.group(1), "path_uuid"))
        # Query param IDs
        qs = urllib.parse.parse_qs(parsed.query)
        for k, vs in qs.items():
            if _IDOR_PARAM_NAME_RE.match(k) and vs:
                self.id_links.append((url, vs[0], f"param:{k}"))

# ─────────────────────────────────────────────────────────────────────────────
# CRAWLER  (BFS with a shared work queue — no nested ThreadPoolExecutors)
# ─────────────────────────────────────────────────────────────────────────────
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
        self.id_hints  = []   # [{id_val, id_type, id_source, context_url}]

    def _same_host(self, url):
        return urllib.parse.urlparse(url).netloc == self.base.netloc

    def _process_page(self, url):
        resp = self.client.get(url)
        if resp["status"] == 0:
            return [], []
        body = resp.get("body", "") or ""
        ct   = resp.get("headers", {}).get("content-type", "")

        # Mine IDs from JSON API responses
        if "json" in ct or body.strip().startswith(("{", "[")):
            self._mine_json_ids(body, url)

        parser = PageParser(url)
        try:
            parser.feed(body)
        except Exception:
            pass

        # Collect ID-bearing links
        with self._lock:
            for (full_url, id_val, id_src) in parser.id_links:
                if _NUMERIC_RE.match(id_val):
                    id_type = "numeric"
                elif _UUID_RE.match(id_val):
                    id_type = "uuid"
                elif _is_slug(id_val):
                    id_type = "slug"
                else:
                    continue
                self.id_hints.append({
                    "id_val":     id_val,
                    "id_type":    id_type,
                    "id_source":  id_src,
                    "context_url": url,
                })

        # Collect form endpoints
        for form in parser.forms:
            params = {i["name"]: i["value"] for i in form["inputs"]}
            with self._lock:
                self.endpoints.append({
                    "url":    form["action"],
                    "method": form["method"],
                    "params": params,
                    "hidden": {},
                    "source": f"form@{url}",
                })

        # Collect URL query-param endpoints
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            qs = urllib.parse.parse_qs(parsed_url.query)
            params = {k: v[0] for k, v in qs.items()}
            with self._lock:
                self.endpoints.append({
                    "url":    parsed_url._replace(query="").geturl(),
                    "method": "GET",
                    "params": params,
                    "hidden": {},
                    "source": "url_query",
                })

        # Return new links to crawl + JS URLs to fetch
        new_links = [
            l for l in parser.links
            if self._same_host(l) and not _STATIC_EXT_RE.search(l)
        ]
        return new_links, list(parser.js_links)

    def _fetch_js(self, js_url):
        with self._lock:
            if js_url in self.js_visited:
                return
            self.js_visited.add(js_url)
        resp = self.client.get(js_url)
        if not resp["ok"] or not resp["body"]:
            return
        eps  = JSExtractor().extract(resp["body"], js_url)
        base = f"{self.base.scheme}://{self.base.netloc}"
        with self._lock:
            for e in eps:
                full = urllib.parse.urljoin(base, e["path"])
                self.js_eps.append({
                    "url":    full,
                    "method": e["method"],
                    "params": {p: "1" for p in e["params"]},
                    "hidden": {},
                    "source": f"js:{js_url}",
                })

    def _mine_json_ids(self, body, context_url):
        try:
            data = json.loads(body)
        except Exception:
            return
        self._recurse_json(data, context_url, 0)

    def _recurse_json(self, obj, ctx, depth):
        if depth > 6:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _IDOR_PARAM_NAME_RE.match(str(k)):
                    val = str(v)
                    if _NUMERIC_RE.match(val):
                        id_type = "numeric"
                    elif _UUID_RE.match(val):
                        id_type = "uuid"
                    elif _is_slug(val):
                        id_type = "slug"
                    else:
                        id_type = None
                    if id_type:
                        with self._lock:
                            self.id_hints.append({
                                "id_val":     val,
                                "id_type":    id_type,
                                "id_source":  f"json:{k}",
                                "context_url": ctx,
                            })
                self._recurse_json(v, ctx, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:30]:
                self._recurse_json(item, ctx, depth + 1)

    def crawl(self):
        tprint(f"\n  {info(f'Starting crawl: {self.base_url}  depth={self.max_depth}  threads={self.threads}  max_pages={self.max_pages}')}")

        # BFS: work_queue items are (url, depth)
        work_q   = queue.Queue()
        work_q.put((self.base_url, 0))
        js_q     = queue.Queue()
        self.visited.add(self.base_url)

        def worker():
            while True:
                try:
                    url, depth = work_q.get(timeout=2)
                except queue.Empty:
                    return
                try:
                    with self._lock:
                        if len(self.visited) >= self.max_pages:
                            return
                    new_links, new_js = self._process_page(url)
                    for js in new_js:
                        js_q.put(js)
                    if depth < self.max_depth:
                        for link in new_links:
                            with self._lock:
                                if link not in self.visited and len(self.visited) < self.max_pages:
                                    self.visited.add(link)
                                    work_q.put((link, depth + 1))
                except Exception:
                    pass
                finally:
                    work_q.task_done()

        def js_worker():
            while True:
                try:
                    js_url = js_q.get(timeout=2)
                except queue.Empty:
                    return
                try:
                    self._fetch_js(js_url)
                except Exception:
                    pass
                finally:
                    js_q.task_done()

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            # Spawn page workers
            futs = [pool.submit(worker) for _ in range(self.threads)]
            # Drain work queue — join() blocks until all tasks done
            work_q.join()
            # Now drain JS queue
            js_futs = [pool.submit(js_worker) for _ in range(max(2, self.threads // 2))]
            js_q.join()

        # Dedup endpoints by (url, method)
        seen     = set()
        deduped  = []
        for ep in self.endpoints + self.js_eps:
            key = (ep["url"], ep["method"])
            if key not in seen:
                seen.add(key)
                deduped.append(ep)
        self.endpoints = deduped

        # Dedup id_hints by (id_val, id_type)
        seen_hints = set()
        deduped_hints = []
        for h in self.id_hints:
            k = (h["id_val"], h["id_type"])
            if k not in seen_hints:
                seen_hints.add(k)
                deduped_hints.append(h)
        self.id_hints = deduped_hints

        tprint(f"  {ok(f'Crawl done — {len(self.visited)} pages, {len(self.js_visited)} JS files, '
                       f'{len(self.endpoints)} endpoints, {len(self.id_hints)} ID hints')}")
        return self.endpoints

# ─────────────────────────────────────────────────────────────────────────────
# IDOR SURFACE ANALYSER
# ─────────────────────────────────────────────────────────────────────────────
class IDORSurfaceAnalyser:

    def _path_targets(self, path):
        """Extract all IDOR targets from a URL path. Deduped by (location, val)."""
        seen    = set()
        targets = []
        # Numeric segments
        for m in _PATH_NUMERIC_RE.finditer(path):
            val = m.group(1)
            if val in seen: continue
            seen.add(val)
            targets.append({
                "location":     "path",
                "param_name":   None,
                "sample_value": val,
                "id_type":      "numeric",
            })
        # UUID segments
        for m in _PATH_UUID_RE.finditer(path):
            val = m.group(1).lower()
            if val in seen: continue
            seen.add(val)
            targets.append({
                "location":     "path",
                "param_name":   None,
                "sample_value": val,
                "id_type":      "uuid",
            })
        # Slug segments
        for m in _PATH_SLUG_RE.finditer(path):
            val = m.group(1)
            if val in seen: continue
            if not _is_slug(val): continue
            seen.add(val)
            targets.append({
                "location":     "path",
                "param_name":   None,
                "sample_value": val,
                "id_type":      "slug",
            })
        return targets

    # Params that look numeric but are NOT IDOR surface — blocklist
    _PAGINATION_PARAMS = frozenset({
        "page", "p", "pg", "pageno", "page_no", "pagenum", "page_num",
        "offset", "skip", "start", "begin",
        "limit", "size", "per_page", "perpage", "page_size", "pagesize",
        "count", "max", "num", "n", "rows", "take",
        "step", "chunk", "batch",
        "sort", "order", "dir", "direction", "asc", "desc",
        "format", "type", "view", "mode", "tab", "section",
        "v", "ver", "version", "rev", "revision",
        "ts", "timestamp", "t", "time", "date",
        "lang", "locale", "currency",
        # NOTE: 'from' intentionally excluded — it's a valid IDOR param
        # (e.g. ?from=user_id in messaging endpoints)
    })

    def _param_targets(self, params):
        """Extract IDOR targets from param dict. Deduped by param_name."""
        seen    = set()
        targets = []
        for pname, pval in params.items():
            if pname in seen:
                continue
            # Skip pagination / control params — they carry numbers but not object IDs
            if pname.lower() in self._PAGINATION_PARAMS:
                continue
            pval_str = str(pval)
            # High-signal: param name matches IDOR pattern
            if _IDOR_PARAM_NAME_RE.match(pname):
                if _NUMERIC_RE.match(pval_str):
                    id_type = "numeric"
                elif _UUID_RE.match(pval_str):
                    id_type = "uuid"
                elif _is_slug(pval_str):
                    id_type = "slug"
                else:
                    id_type = "param_name_signal"
                seen.add(pname)
                targets.append({
                    "location":     "param",
                    "param_name":   pname,
                    "sample_value": pval_str,
                    "id_type":      id_type,
                })
            # Lower signal: any param with a numeric value ≥ 1 digit
            elif _NUMERIC_RE.match(pval_str):
                seen.add(pname)
                targets.append({
                    "location":     "param",
                    "param_name":   pname,
                    "sample_value": pval_str,
                    "id_type":      "numeric_value",
                })
        return targets

    def score_endpoint(self, ep):
        parsed  = urllib.parse.urlparse(ep["url"])
        targets = self._path_targets(parsed.path) + self._param_targets(ep.get("params", {}))

        # Upgrade param targets whose names appear in priority_params
        # (spider-confirmed params — treat as high-signal regardless of value)
        priority = set(ep.get("priority_params") or [])
        if priority:
            for t in targets:
                if t["location"] == "param" and t["param_name"] in priority:
                    # Promote to numeric if still param_name_signal
                    if t["id_type"] == "param_name_signal":
                        t["id_type"] = "numeric"  # best-effort: try numeric candidates

        if not targets:
            return 0, []
        high_count = sum(1 for t in targets if t["id_type"] in ("numeric", "uuid", "slug"))
        score = 3 if high_count >= 2 else 2 if high_count == 1 else 1
        return score, targets

    def analyse(self, endpoints):
        scored = []
        for ep in endpoints:
            score, targets = self.score_endpoint(ep)
            if score > 0:
                scored.append((score, ep, targets))
        scored.sort(key=lambda x: -x[0])
        return scored

# ─────────────────────────────────────────────────────────────────────────────
# ID GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
class IDGenerator:

    def neighbours(self, id_val, id_type, n=5):
        """
        Produce candidate tampered IDs. Type-matched — numeric hints only
        used against numeric IDs, UUID hints against UUID endpoints, etc.
        """
        candidates = []
        if id_type == "numeric" and _NUMERIC_RE.match(id_val):
            base = int(id_val)
            for delta in range(1, n + 1):
                if base - delta > 0:
                    candidates.append(str(base - delta))
                candidates.append(str(base + delta))
            for anchor in ("1", "2", "100", "1000", "9999"):
                if anchor != id_val:
                    candidates.append(anchor)
        elif id_type == "uuid" and _UUID_RE.match(id_val):
            parts = id_val.lower().split("-")
            for _ in range(n):
                last = "".join(random.choices("0123456789abcdef", k=len(parts[-1])))
                scrambled = parts[:-1] + [last]
                candidates.append("-".join(scrambled))
            candidates.append("00000000-0000-0000-0000-000000000001")
            candidates.append("00000000-0000-0000-0000-000000000002")
        elif id_type in ("slug", "param_name_signal"):
            # Try simple predictable slugs
            candidates.extend(["admin", "test", "guest", "user1", "user2",
                                id_val + "1", id_val + "2"])
        else:
            # numeric_value — same as numeric
            try:
                base = int(id_val)
                for delta in range(1, n + 1):
                    if base - delta > 0:
                        candidates.append(str(base - delta))
                    candidates.append(str(base + delta))
            except ValueError:
                pass

        # Deduplicate, preserve order, remove original
        seen = {id_val}
        out  = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

# ─────────────────────────────────────────────────────────────────────────────
# RESPONSE ANALYSER
# ─────────────────────────────────────────────────────────────────────────────
class ResponseAnalyser:

    # Body text patterns that indicate explicit access denial
    _DENY_BODY_RE = re.compile(
        r'\b(?:forbidden|unauthorized|access\s+denied|not\s+authorized'
        r'|permission\s+denied|not\s+allowed|invalid\s+token'
        r'|session\s+expired|please\s+log\s+in|authentication\s+required)\b',
        re.I
    )

    def is_access_denied(self, resp):
        """
        True only for unambiguous auth/authz denial.
        NOTE: 404 is NOT treated as denial — an app often returns 404 for
        objects that don't exist, which is different from forbidden access.
        We need to distinguish 'object not found' from 'access denied'.
        """
        status = resp.get("status", 0)
        body   = (resp.get("body", "") or "")[:2000]
        loc    = resp.get("headers", {}).get("location", "")

        if status in (401, 403):
            return True
        # Redirect to login page
        if status in range(301, 310) and re.search(r'login|signin|auth', loc, re.I):
            return True
        # Body explicitly says access denied
        if status == 200 and self._DENY_BODY_RE.search(body):
            return True
        return False

    # Plaintext sensitive terms — catches HTML pages and plain text responses
    # that contain sensitive data without JSON key formatting
    _SENSITIVE_PLAINTEXT_RE = re.compile(
        r'\b(?:secret_token|auth_token|access_token|api_key|private_key'
        r'|btc_address|xmr_address|eth_address|wallet_address'
        r'|pgp_key|pgp.{0,5}block|begin.{0,5}pgp'
        r'|credit_card|card_number|cvv|ssn|passport'
        r'|password_hash|passwd|bcrypt|sha256.*:.*[a-f0-9]{32}'
        r'|admin_token|session_secret|signing_key)\b',
        re.I
    )

    def has_sensitive_data(self, body):
        """Check if body contains sensitive data — handles both JSON and plaintext."""
        sample = body[:8000]
        return bool(_SENSITIVE_KEYS_RE.search(sample) or
                    self._SENSITIVE_PLAINTEXT_RE.search(sample))

    def _json_keys(self, body):
        return set(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})"\s*:', body[:4000]))

    def _html_sensitive_tokens(self, body):
        """
        Extract unique sensitive token values from HTML body.
        Used to compare if a response exposes the OWNER's private tokens
        vs what another user should see.
        Extracts: API tokens, secret keys, wallet addresses embedded in HTML.
        """
        tokens = set()
        # Hex/base58 tokens 16-80 chars after sensitive label
        tok_re = re.compile(
            r'(?:token|secret|api.?key|auth|wallet|btc|xmr|eth)[^:=>\n]{0,30}'
            r'[:=>\s]+([a-zA-Z0-9_\-]{16,80})',
            re.I
        )
        for m in tok_re.finditer(body[:8000]):
            tokens.add(m.group(1))
        # PGP key material
        if re.search(r'BEGIN PGP', body, re.I):
            tokens.add("__pgp_key_present__")
        return tokens
    def _extract_sensitive_values(self, body):
            """
            Extract actual values of sensitive fields from a JSON response body.
            Used to detect value-level leaks — User B receiving User A's actual
            email/token/role value, not just the same key name.
            Returns a set of non-trivial string values found under sensitive keys.
            """
            values = set()
            if not body:
                return values
            try:
                obj = json.loads(body[:16000])
            except Exception:
                return values

            _SENSITIVE_FIELD_RE = re.compile(
                r'^(?:email|phone|mobile|password|token|secret|api_key|private_key'
                r'|ssn|passport|credit_card|card_number|iban|salary'
                r'|auth_token|access_token|session_token|totp_secret|totpSecret'
                r'|role|admin|permission|scope|balance|wallet'
                r'|first_name|last_name|full_name|username|address|dob)$',
                re.I
            )

            def _recurse(o, depth=0):
                if depth > 4:
                    return
                if isinstance(o, dict):
                    for k, v in o.items():
                        if _SENSITIVE_FIELD_RE.match(str(k)):
                            if isinstance(v, str) and len(v) > 3:
                                values.add(v)
                            elif isinstance(v, (int, float)) and v != 0:
                                values.add(str(v))
                        if isinstance(v, (dict, list)):
                            _recurse(v, depth + 1)
                elif isinstance(o, list):
                    for item in o[:10]:
                        _recurse(item, depth + 1)

            _recurse(obj)
            return values

    def compare(self, user_a_resp, user_b_own_resp, tampered_resp):
        """
        Decide if tampered_resp indicates IDOR.
        Returns (is_idor: bool, confidence: str|None, evidence: str)

        Key insight: when an endpoint requires no auth, BOTH user A and user B
        get the same response for the same ID. The differential signals (signal 2,3,4)
        all fail. But this is still an IDOR — ANY user can access ANY user's data.
        We detect this via the 'no_auth_sensitive_data' signal.
        """
        if self.is_access_denied(tampered_resp):
            return False, None, "Access denied — properly protected"

        t_status = tampered_resp.get("status", 0)
        t_body   = (tampered_resp.get("body", "") or "")

        if t_status == 0 or not t_body:
            return False, None, "No response / connection error"

        if t_status not in range(200, 210):
            return False, None, f"Non-2xx status {t_status} (not a data leak)"

        a_body = (user_a_resp or {}).get("body", "") or ""
        b_body = (user_b_own_resp or {}).get("body", "") or ""
        a_keys = self._json_keys(a_body)
        b_keys = self._json_keys(b_body)
        t_keys = self._json_keys(t_body)

        evidence = []

        # Signal 1: sensitive data keys in tampered response
        if self.has_sensitive_data(t_body):
            evidence.append("sensitive_data_keys_in_response")

        # Signal 2: response JSON structure matches User A's
        if a_keys and t_keys:
            a_overlap = len(a_keys & t_keys)
            b_overlap = len(b_keys & t_keys) if b_keys else 0
            if a_overlap >= 3 and a_overlap > b_overlap:
                evidence.append("response_structure_matches_user_a")

        # Signal 3: body length within 40% of User A's
# Signal 3: body length within 15% of User A's — tighter threshold,
        # only counts when Signal 1 or 2 is also present (not standalone evidence)
        if a_body and len(a_body) > 20:
            ratio = abs(len(t_body) - len(a_body)) / len(a_body)
            if ratio < 0.15 and (
                "sensitive_data_keys_in_response" in evidence or
                "response_structure_matches_user_a" in evidence
            ):
                evidence.append("body_length_consistent_with_user_a_resource")

        # Signal 4: differs from User B's own baseline
        if b_body and t_body.strip() != b_body.strip():
            evidence.append("response_differs_from_user_b_baseline")

        # Signal 5: non-trivial response body
        if len(t_body.strip()) > 20:
            evidence.append("non_trivial_response_body")

        # Signal 6: no-auth endpoint leaking sensitive data
        # Fires when b_body is absent (unauth check) AND response has sensitive keys.
        # "Unauth probe" means _test_one called compare() with empty user_b_own_resp
        # — happens when client_unauth is the one being tested.
        is_unauth_probe = not b_body or len(b_body.strip()) < 30
        if is_unauth_probe and self.has_sensitive_data(t_body) and len(t_body.strip()) > 30:
            evidence.append("no_auth_sensitive_data_exposed")

        # Signal 7: HTML sensitive token differential
        # Detects IDOR in HTML responses by comparing extracted token values.
        # User A's profile shows secret_token: "tok_abc123"
        # User B accessing User A's profile also shows "tok_abc123" → IDOR
        # Detected because tampered response contains tokens that B's own page doesn't.
        t_tokens = self._html_sensitive_tokens(t_body)
        a_tokens = self._html_sensitive_tokens(a_body) if a_body else set()
        b_tokens = self._html_sensitive_tokens(b_body) if b_body else set()
        if t_tokens:
            # Tokens in tampered that B's own page doesn't have
            leaked = t_tokens - b_tokens
            if leaked:
                # If User A has those same tokens (or we have no A baseline), flag it
                if not a_body or (a_tokens & leaked):
                    evidence.append("html_sensitive_tokens_exposed")

        # Signal 8: value-level leak — User A's actual sensitive field values
        # appear in the tampered response that User B made.
        # This is stronger than key-presence: same key structure could be
        # coincidental, but same actual email/token value is definitive.
        if a_body and t_body:
            a_values = self._extract_sensitive_values(a_body)
            t_values = self._extract_sensitive_values(t_body)
            b_values = self._extract_sensitive_values(b_body) if b_body else set()
            # Values from A's response that appear in tampered but NOT in B's own baseline
            leaked_values = (a_values & t_values) - b_values
            if leaked_values:
                evidence.append("user_a_field_values_in_tampered_response")
        if not evidence:
            return False, None, "No IDOR signals detected"

        # Qualification — adaptive to available baseline data
        has_a = bool(a_body and len(a_body) > 20)
        has_b = bool(b_body and len(b_body) > 20)

        if "no_auth_sensitive_data_exposed" in evidence:
            qual = True
        elif "html_sensitive_tokens_exposed" in evidence:
            qual = True
        elif "user_a_field_values_in_tampered_response" in evidence:
            qual = True
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

        if not qual:
            return False, None, "Signals present but insufficient confidence"

        confidence = (
            "HIGH"   if len(evidence) >= 3
            else "MEDIUM" if len(evidence) == 2
            else "LOW"
        )
        return True, confidence, " | ".join(evidence)

# ─────────────────────────────────────────────────────────────────────────────
# ID HARVEST PASS
# After surface analysis, fetch every IDOR-candidate endpoint as User A
# and extract real object IDs from the live responses.
# This solves the "no ID hints" problem when using --spider-json without
# a prior authenticated crawl.
# ─────────────────────────────────────────────────────────────────────────────
class IDHarvestPass:
    """
    Fetches IDOR-surface endpoints as User A and mines their responses for
    real object IDs. Results are merged into the id_hints pool before testing.
    """

    def __init__(self, client_a, targets, threads=8, delay=0, client_b=None, options=None):
        self.options  = options or {}
        self.client_a = client_a
        self.client_b = client_b
        self.targets  = targets
        self.threads  = threads
        self.delay    = delay
        self._lock    = threading.Lock()
        self.id_hints = []
        self.child_urls = [] 

    def _mine(self, ep, idor_targets):
        """Fetch endpoint as User A and extract IDs — tagged as user_a_owned."""
        if self.delay:
            time.sleep(self.delay)
        try:
            if ep["method"] == "GET":
                resp = self.client_a.get(ep["url"], ep.get("params") or {})
            else:
                resp = self.client_a.post(ep["url"], ep.get("params") or {})
        except Exception:
            return

        body   = resp.get("body", "") or ""
        status = resp.get("status", 0)
        if status == 0 or not body:
            return

        new_hints = []

        # Mine JSON body for ID fields — tag as user_a_owned
        if body.strip().startswith(("{", "[")):
            try:
                obj = json.loads(body)
                self._recurse(obj, ep["url"], new_hints, 0, owner="user_a")
            except Exception:
                pass

        # Mine path segments from redirect Location header
        loc = resp.get("headers", {}).get("location", "") or ""
        if loc:
            for m in _PATH_NUMERIC_RE.finditer(urllib.parse.urlparse(loc).path):
                new_hints.append({
                    "id_val": m.group(1), "id_type": "numeric",
                    "id_source": "harvest:redirect_path",
                    "context_url": ep["url"],
                    "owner": "user_a",
                })

        # Mine IDs from IDOR targets themselves
        for t in idor_targets:
            val = t["sample_value"]
            if t["id_type"] == "numeric" and _NUMERIC_RE.match(val):
                new_hints.append({
                    "id_val": val, "id_type": "numeric",
                    "id_source": "harvest:surface_target",
                    "context_url": ep["url"],
                    "owner": "unknown",
                })
            elif t["id_type"] == "uuid" and _UUID_RE.match(val):
                new_hints.append({
                    "id_val": val, "id_type": "uuid",
                    "id_source": "harvest:surface_target",
                    "context_url": ep["url"],
                    "owner": "unknown",
                })

        with self._lock:
            self.id_hints.extend(new_hints)

    def _derive_get_child_urls(self):
        """
        Derive REST child URL candidates from GET harvest IDs.
        Pattern: harvested id=23 from GET /api/Users
              → construct GET /api/Users/23
        This gives _test_child_urls something to work with even when
        no POST creation endpoints exist in the spider JSON.
        Only constructs child URLs for collection-style endpoints
        (path ends in a resource name, not already an ID segment).
        """
        if not self.id_hints:
            return

        # Group hints by context_url — each unique source endpoint
        # gets its own set of candidate child URLs
        from collections import defaultdict
        url_hints = defaultdict(list)
        for h in self.id_hints:
            ctx = h.get("context_url", "")
            if ctx:
                url_hints[ctx].append(h)

        seen_child_urls = {c["url"] for c in self.child_urls}

        for ctx_url, hints in url_hints.items():
            # Skip if the context URL itself already looks like a child URL
            parsed = urllib.parse.urlparse(ctx_url)
            last_seg = parsed.path.rstrip("/").rsplit("/", 1)[-1]
            if _NUMERIC_RE.match(last_seg) or _UUID_RE.match(last_seg):
                continue

            # Universal ownership check — skip paths with no ownership semantics.
            # If the path contains none of these keywords it's catalogue/public data.
            # This is app-agnostic: same logic works on any REST API.
            _OWNERSHIP_PATH_RE = re.compile(
                r'(?:user|account|profile|basket|cart|order|wallet|address'
                r'|card|complaint|invoice|subscription|session|notification'
                r'|message|inbox|ticket|payment|transaction|delivery'
                r'|security|auth|2fa|totp|mfa|password|token|key'
                r'|membership|privilege|role|permission|wishlist|favourite|favorite'
                r'|history|activity|log|audit|setting|preference|config)',
                re.I
            )
            if not _OWNERSHIP_PATH_RE.search(parsed.path):
                # No ownership keywords — likely public catalogue data.
                # Confirm by checking if unauthenticated GET returns 200.
                try:
                    bare_resp = HTTPClient(timeout=8, options=self.options).get(ctx_url, {})
                    if bare_resp.get("status", 0) in range(200, 210):
                        vprint(f"    [harvest:derive] Skipping public catalogue path: {ctx_url}")
                        continue
                except Exception:
                    pass  # can't confirm — still apply _is_public check below

            # Skip public/non-sensitive endpoints.
            # Default to SKIP on any error — safer than false positives.
            _is_public = False
            try:
                a_resp   = self.client_a.get(ctx_url, {})
                b_resp   = self.client_b.get(ctx_url, {}) if self.client_b else None
                if b_resp:
                    a_body   = (a_resp.get("body", "") or "").strip()
                    b_body   = (b_resp.get("body", "") or "").strip()
                    a_status = a_resp.get("status", 0)
                    b_status = b_resp.get("status", 0)
                    if (a_status in range(200, 210) and b_status in range(200, 210)
                            and a_body and b_body and a_body == b_body
                            and not ResponseAnalyser().has_sensitive_data(a_body)):
                        _is_public = True
                    elif a_status not in range(200, 210) and a_status == b_status:
                        _is_public = True
            except Exception:
                _is_public = True  # skip on error — safer than false positives

            if _is_public:
                vprint(f"    [harvest:derive] Skipping public/uniform endpoint: {ctx_url}")
                continue

            # Only derive child URLs from collection endpoints
            # that returned 200 (skip endpoints that 404/500 on baseline)
            base = ctx_url.rstrip("/")

            for h in hints:
                id_val  = h["id_val"]
                id_type = h["id_type"]
                owner   = h.get("owner", "unknown")
                child_url = f"{base}/{id_val}"

                if child_url in seen_child_urls:
                    continue
                seen_child_urls.add(child_url)

                self.child_urls.append({
                    "url":    child_url,
                    "method": "GET",
                    "id_val": id_val,
                    "id_type": id_type,
                    "owner":  owner,
                    "source": f"get_harvest:{ctx_url}",
                })

        if self.child_urls:
            vprint(f"    [harvest:derive] {len(self.child_urls)} child URL(s) "
                   f"derived from GET harvest IDs")

    def _mine_post(self, ep):
        """
        Attempt single-step resource creation as User A via POST.
        Extracts returned ID and tags it user_a_owned — these are the
        highest-confidence IDOR seeds since we know User A created them.
        Also derives child URLs for path-based IDOR testing.
        """
        if self.delay:
            time.sleep(self.delay)
        try:
            resp = self.client_a.post(ep["url"], ep.get("params") or {}, "json")
            if resp.get("status", 0) in (400, 415, 422):
                resp = self.client_a.post(ep["url"], ep.get("params") or {})
        except Exception:
            return

        body   = resp.get("body", "") or ""
        status = resp.get("status", 0)
        if status not in range(200, 210) or not body:
            return

        new_hints = []
        try:
            obj = json.loads(body)
            self._recurse(obj, ep["url"], new_hints, 0, owner="user_a")
        except Exception:
            pass

        if new_hints:
            vprint(f"    [harvest:post] Created resource at {ep['url']} → "
                   f"IDs: {[h['id_val'] for h in new_hints]}")

        with self._lock:
            self.id_hints.extend(new_hints)
            # Store child URLs derived from creation: /api/Items + id=42 → /api/Items/42
            for h in new_hints:
                child_url = ep["url"].rstrip("/") + "/" + h["id_val"]
                self.child_urls.append({
                    "url":    child_url,
                    "method": "GET",
                    "id_val": h["id_val"],
                    "id_type": h["id_type"],
                    "owner":  "user_a",
                    "source": f"post_creation:{ep['url']}",
                })

    def _recurse(self, obj, ctx, out, depth, owner="unknown"):
        if depth > 5:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _IDOR_PARAM_NAME_RE.match(str(k)):
                    val = str(v) if v is not None else ""
                    if _NUMERIC_RE.match(val):
                        out.append({"id_val": val, "id_type": "numeric",
                                    "id_source": f"harvest:json:{k}",
                                    "context_url": ctx, "owner": owner})
                    elif _UUID_RE.match(val):
                        out.append({"id_val": val, "id_type": "uuid",
                                    "id_source": f"harvest:json:{k}",
                                    "context_url": ctx, "owner": owner})
                if isinstance(v, (dict, list)):
                    self._recurse(v, ctx, out, depth + 1, owner)
        elif isinstance(obj, list):
            for item in obj[:20]:
                self._recurse(item, ctx, out, depth + 1, owner)

    def run(self):
        """Run harvest pass. Returns list of new id_hints."""
        if not self.targets:
            return []

        tprint(f"\n  {info(f'ID harvest pass: fetching {len(self.targets)} endpoints as User A...')}")

        # Phase 1a: Mine IDOR-candidate GET endpoints as User A
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = [pool.submit(self._mine, ep, tgts)
                    for _, ep, tgts in self.targets]
            for f in as_completed(futs):
                try: f.result()
                except: pass
        # Phase 1b: Derive child URLs from GET harvest IDs
        # e.g. /api/Users + id=23 → /api/Users/23
        self._derive_get_child_urls()
        if self.child_urls:
            tprint(f"  {ok(f'Derived {len(self.child_urls)} child URL(s) from GET harvest IDs')}")
        
        # Phase 1b: Attempt POST creation on POST endpoints to get owned IDs
        post_eps = [ep for _, ep, _ in self.targets if ep["method"] == "POST"]
        if post_eps:
            tprint(f"  {info(f'POST creation harvest: trying {len(post_eps)} POST endpoints...')}")
            with ThreadPoolExecutor(max_workers=min(4, self.threads)) as pool:
                futs = [pool.submit(self._mine_post, ep) for ep in post_eps]
                for f in as_completed(futs):
                    try: f.result()
                    except: pass
            if self.child_urls:
                tprint(f"  {ok(f'Created {len(self.child_urls)} child URL(s) from POST responses')}")

        # Dedup by (id_val, id_type)
        seen    = set()
        deduped = []
        for h in self.id_hints:
            k = (h["id_val"], h["id_type"])
            if k not in seen:
                seen.add(k)
                deduped.append(h)
        self.id_hints = deduped

        # Phase 2: Crawl session-specific pages to find User A's OWN id
        # This is distinct from the endpoint harvest above — these are pages
        # that are unique to the logged-in session (settings, account, notifications)
        # and therefore contain YOUR id, not all other users' ids.
        session_pages = [
            "/settings", "/account/settings", "/user/settings",
            "/profile/edit", "/account/edit", "/account",
            "/me", "/my-account", "/my-profile",
            "/dashboard", "/home", "/app",
            "/notifications", "/inbox",
            "/api/settings", "/api/account", "/api/profile", "/api/me",
        ]
        # Infer base URL from first target
        if self.targets:
            base = urllib.parse.urlparse(self.targets[0][1]["url"])
            base_url = f"{base.scheme}://{base.netloc}"
            own_hints_found = False
            for page_path in session_pages:
                if own_hints_found:
                    break
                try:
                    resp = self.client_a.get(base_url + page_path)
                    if resp["status"] not in (200, 201):
                        continue
                    body = resp.get("body", "") or ""
                    if len(body) < 50:
                        continue
                    # Mine JSON
                    page_hints = []
                    if body.strip().startswith(("{", "[")):
                        try:
                            obj = json.loads(body)
                            self._recurse(obj, base_url + page_path, page_hints, 0, owner="user_a")
                        except Exception:
                            pass
                    # Mine HTML — but only data-* and JS vars (not href links
                    # since settings pages don't link to the user's own profile)
                    # Use targeted patterns for session pages
                    for pat in [
                        re.compile(r'data-(?:user-?id|uid|profile-?id|author-?id)\s*=\s*["\'](\d{1,8})["\']', re.I),
                        re.compile(r'(?:user_?id|userId|uid|profile_?id|currentUser\.id)\s*[=:]\s*["\']?(\d{1,8})["\']?', re.I),
                        re.compile(r'<input[^>]+name=["\'](?:user_id|uid|profile_id|author_id)["\'][^>]*value=["\'](\d{1,8})["\']', re.I),
                    ]:
                        for m in pat.finditer(body[:16000]):
                            val = m.group(1)
                            if val and int(val) > 0:
                                page_hints.append({
                                    "id_val": val, "id_type": "numeric",
                                    "id_source": f"harvest:session_page:{page_path}",
                                    "context_url": base_url + page_path,
                                })
                    if page_hints:
                        # Dedup
                        seen_vals = {h["id_val"] for h in self.id_hints}
                        new = [h for h in page_hints if h["id_val"] not in seen_vals]
                        if new:
                            self.id_hints.extend(new)
                            own_hints_found = True
                            vprint(f"    [harvest] Own IDs from {page_path}: {[h['id_val'] for h in new]}")
                except Exception:
                    pass

        tprint(f"  {ok(f'ID harvest complete — {len(self.id_hints)} unique ID(s) extracted from live responses')}")
        return self.id_hints


# ─────────────────────────────────────────────────────────────────────────────
# IDOR TESTER
# ─────────────────────────────────────────────────────────────────────────────
class IDORTester:

    def __init__(self, client_a, client_b, client_unauth,
                 targets, id_hints, child_urls=None,
                 threads=6, delay=0, test_unauth=True, write_probe=False,
                 single_session=False):
        self.client_a       = client_a
        self.client_b       = client_b
        self.client_unauth  = client_unauth
        self.targets        = targets
        self.id_hints       = id_hints
        self.child_urls     = child_urls or []
        self.threads        = threads
        self.delay          = delay
        self.test_unauth    = test_unauth
        self.write_probe    = write_probe
        self.single_session = single_session  # True = no User B, BAC scan only
        self.findings       = []
        self._seen_findings = set()
        self._lock          = threading.Lock()
        self._id_gen        = IDGenerator()
        self._analyser      = ResponseAnalyser()

    def _sleep(self):
        if self.delay:
            time.sleep(self.delay)

    def _fetch(self, client, ep, params_override=None):
            url    = ep["url"]
            method = ep["method"]
            params = params_override if params_override is not None else ep.get("params", {})
            self._sleep()
            if method == "GET":
                return client.get(url, params)

            # POST content-type resolution — priority order:
            # 1. Explicit ct stored on ep (set by spider bridge or prior probe)
            # 2. Source label hint (js: prefix → likely JSON API)
            # 3. Probe: try JSON first, fall back to form-encoded if 4xx
            explicit_ct = ep.get("content_type")
            if explicit_ct:
                return client.post(url, params, explicit_ct)

            source = (ep.get("source", "") or "").lower()
            if "json" in source or source.startswith("js:") or "api" in source:
                resp = client.post(url, params, "json")
                # If server rejects JSON with 4xx, retry as form-encoded
                if resp.get("status", 0) in (400, 415, 422):
                    return client.post(url, params, None)
                return resp

            # Default: form-encoded
            return client.post(url, params, None)

    def _substitute_path(self, url, old_seg, new_seg):
        """Replace first occurrence of /old_seg/ or /old_seg$ in path."""
        parsed   = urllib.parse.urlparse(url)
        new_path = re.sub(
            r'(/)' + re.escape(str(old_seg)) + r'(/|$)',
            r'\g<1>' + str(new_seg) + r'\g<2>',
            parsed.path,
            count=1,
        )
        return parsed._replace(path=new_path).geturl()

    def _record_finding(self, finding):
        # Primary dedup: exact (url, param, tampered_id)
        key = (finding["url"], finding.get("param_name"), finding["tampered_id"])
        # Cluster dedup: for child URL path findings, one finding per base endpoint
        # Prevents /api/Users/1, /api/Users/2 ... /api/Users/N all being reported
        cluster_key = None
        # Only cluster-dedup child URL path findings — never param findings
        # Param findings on /api/Users and path findings on /api/Users/1
        # are different vulnerabilities and must both be reported
        if (finding.get("location") == "path"
                and finding.get("source", "").startswith("get_harvest:")
                and finding.get("finding_type") == "path_idor"):
            base = re.sub(r'/[^/]+$', '', finding["url"])
            cluster_key = f"child_cluster:{base}:path_idor"
        with self._lock:
            if key in self._seen_findings:
                return False
            if cluster_key and cluster_key in self._seen_findings:
                return False
            self._seen_findings.add(key)
            if cluster_key:
                self._seen_findings.add(cluster_key)
            self.findings.append(finding)
            return True

    def _build_candidates(self, orig_val, id_type, n=6):
        """
        Build candidate tampered IDs.
        Priority order:
          1. user_a_owned IDs of matching type — highest confidence IDOR seeds
          2. Other harvested IDs of matching type
          3. Generated neighbours
        """
        user_a_vals = []
        other_vals  = []
        for hint in self.id_hints:
            if hint["id_type"] != id_type or hint["id_val"] == orig_val:
                continue
            if hint.get("owner") == "user_a":
                if hint["id_val"] not in user_a_vals:
                    user_a_vals.append(hint["id_val"])
            else:
                if hint["id_val"] not in other_vals:
                    other_vals.append(hint["id_val"])

        gen_count = n if id_type == "numeric" else max(n, 10)
        gen = self._id_gen.neighbours(orig_val, id_type, n=gen_count)

        # user_a owned first — these are confirmed real IDs belonging to User A
        seen = {orig_val}
        out  = []
        for val in user_a_vals + other_vals + gen:
            if val not in seen:
                seen.add(val)
                out.append(val)

        cap = 30 if id_type == "numeric" else 20
        return out[:cap]

    def _test_one(self, score, ep, idor_targets):
        url    = ep["url"]
        method = ep["method"]

        # Skip destructive verbs unless write_probe enabled
        if method in ("PUT", "PATCH", "DELETE") and not self.write_probe:
            vprint(skp(f"Skipping {method} {url} (use --write-probe to enable)"))
            return

        # Skip static files — never IDOR surface
        _parsed_url = urllib.parse.urlparse(url)
        if re.search(
            r'\.(bak|pyc|yml|yaml|json|xml|txt|md|log|cfg|conf|env|key|pem|crt|sql|gz|tar|zip|js|css|map)$',
            _parsed_url.path, re.I
        ):
            vprint(skp(f"Skipping static file: {url}"))
            return

        # Skip socket/websocket endpoints
        if re.search(r'socket\.io|websocket|ws://', url, re.I):
            vprint(skp(f"Skipping socket endpoint: {url}"))
            return

        # Baseline responses — what each user sees with the original ID
        a_resp = self._fetch(self.client_a, ep)
        b_resp = self._fetch(self.client_b, ep)

        # Assign status codes once — used by both early-exit checks below
        a_status = a_resp.get("status", 0)
        b_status = b_resp.get("status", 0)

        # Early-exit 1: both sessions same non-2xx — no candidates will succeed
        if (a_status not in range(200, 210) and
                b_status not in range(200, 210) and
                a_status == b_status):
            vprint(skp(f"Skipping {url} — baseline {a_status} for both sessions"))
            return

        # Early-exit 2: both sessions identical 200 AND no sensitive data
        # — same non-sensitive data for all users means no IDOR possible.
        # NOTE: if identical response DOES contain sensitive data, keep testing —
        # that means any user can see all users' data (broken access control).
        if a_status in range(200, 210) and b_status in range(200, 210):
            a_body = (a_resp.get("body", "") or "").strip()
            b_body = (b_resp.get("body", "") or "").strip()
            if (a_body and b_body and a_body == b_body
                    and not self._analyser.has_sensitive_data(a_body)):
                vprint(skp(f"Skipping {url} — identical non-sensitive 200 for both sessions"))
                return

        _zero_streak = 0  # consecutive status=0 responses
        for target in idor_targets:
            loc       = target["location"]
            pname     = target["param_name"]
            orig_val  = target["sample_value"]
            id_type   = target["id_type"]

            candidates = self._build_candidates(orig_val, id_type)

            for tampered_id in candidates:
                # Build tampered URL and params depending on location
                if loc == "path":
                    t_url    = self._substitute_path(url, orig_val, tampered_id)
                    t_params = ep.get("params", {})
                    t_ep     = {**ep, "url": t_url}
                else:
                    t_url    = url
                    t_params = {**ep.get("params", {}), pname: tampered_id}
                    t_ep     = ep

                # User B requests User A's resource
                b_tampered = self._fetch(self.client_b, t_ep, t_params)
                if b_tampered.get("status", 0) == 0:
                    _zero_streak += 1
                    if _zero_streak >= 3:
                        vprint(f"    [skip] {url} — 3 consecutive timeouts, abandoning")
                        break
                else:
                    _zero_streak = 0
                # User A requests same resource (as comparison baseline)
                a_tampered = self._fetch(self.client_a, t_ep, t_params)

                is_idor, conf, evidence = self._analyser.compare(
                    a_tampered, b_resp, b_tampered
                )

                # Fix #7: numeric_value type is low-signal — apply confidence penalty
                # unless a strong corroborating signal is present.
                # Rationale: any param with a number gets typed numeric_value,
                # which includes coincidental numbers (counts, timestamps, flags).
                # Require at least Signal 1 or Signal 8 to keep HIGH confidence.
                if (is_idor and id_type == "numeric_value"
                        and conf == "HIGH"
                        and "sensitive_data_keys_in_response" not in evidence
                        and "user_a_field_values_in_tampered_response" not in evidence):
                    conf = "MEDIUM"
                    evidence = evidence + " | [penalized:numeric_value_type]"

                vprint(
                    f"    [test] {method} {t_url}"
                    f"  b_status={b_tampered.get('status')} "
                    f"  a_status={a_tampered.get('status')} "
                    f"  idor={is_idor}  ev={evidence[:60]}"
                )

                if is_idor:
                    is_synthetic = bool(ep.get("synthetic_params"))

                    # For synthetic params: verify server actually uses the param.
                    # If response without param == response with param,
                    # the server ignores it — this is BAC not param IDOR.
                    _evidence = evidence
                    if is_synthetic and pname:
                        # Skip effectiveness check if endpoint is unreachable
                        if b_tampered.get("status", 0) == 0:
                            param_effective = False
                        else:
                            param_effective = self._param_is_effective(
                                self.client_b, ep, pname, b_tampered
                            )
                        _evidence = evidence + " | [param_not_observed:synthetic_spider_hint]"
                        if not param_effective:
                            _evidence += " | [param_ignored_by_server:session_level_bac]"
                    else:
                        param_effective = True

                    if loc == "path":
                        finding_type = "path_idor"
                    elif is_synthetic or not param_effective:
                        finding_type = "session_isolation_bypass"
                    elif pname and not any(
                        pname.endswith(sfx)
                        for sfx in ("_id", "Id", "ID", "uuid", "guid")
                    ) and id_type == "numeric_value":
                        finding_type = "session_isolation_bypass"
                    else:
                        finding_type = "param_idor"

                    _poc_label, _poc_cmd, _poc_browser = self._build_poc_curl(
                        t_url, method,
                        params=t_params if loc != "path" else None,
                        param_name=pname if loc != "path" else None,
                        tampered_id=tampered_id if loc != "path" else None,
                    )
                    finding = {
                        "url":               t_url,
                        "method":            method,
                        "location":          loc,
                        "param_name":        pname,
                        "original_id":       orig_val,
                        "tampered_id":       tampered_id,
                        "id_type":           id_type,
                        "finding_type":      finding_type,
                        "confidence":        conf,
                        "evidence":          _evidence,
                        "status":            b_tampered.get("status"),
                        "body_snippet":      (b_tampered.get("body", "") or "")[:300],
                        "source":            ep.get("source", ""),
                        "session":           "User B",
                        "poc_curl":          _poc_cmd,
                        "poc_browser":       _poc_browser,
                        "poc_session_label": _poc_label,
                        # [HELLHOUND] Reproduction Data
                        "repro_data": {
                            "url": t_url,
                            "method": method,
                            "headers": dict(self.client_b.headers if not self.single_session else self.client_a.headers),
                            "body": (t_params if method != "GET" else None)
                        }
                    }
                    if self._record_finding(finding):
                        self._print_hit(finding)
                        break
                # Unauthenticated check — only runs if IDOR confirmed first
                # This avoids flooding logs with unauth false positives
                if is_idor and self.test_unauth and self.client_unauth:
                    unauth_resp = self._fetch(self.client_unauth, t_ep, t_params)
                    is_ua, ua_conf, ua_ev = self._analyser.compare(
                        a_tampered, {}, unauth_resp
                    )
                    if is_ua:
                        ua_finding = {
                            **finding,
                            "confidence":   ua_conf,
                            "evidence":     ua_ev + " | UNAUTHENTICATED",
                            "status":       unauth_resp.get("status"),
                            "body_snippet": (unauth_resp.get("body", "") or "")[:300],
                            "session":      "unauthenticated",
                            # [HELLHOUND] Reproduction Data
                            "repro_data": {
                                "url": t_url,
                                "method": method,
                                "headers": dict(self.client_unauth.headers),
                                "body": (t_params if method != "GET" else None)
                            }
                        }
                        if self._record_finding(ua_finding):
                            tprint(
                                f"  {found(color(f'[UNAUTH][{ua_conf}]  {method} {t_url}', C.BRED, C.BOLD))}"
                            )
                            tprint(f"    {color('⚠ Endpoint accessible with NO session at all!', C.BRED, C.BOLD)}")
    def _test_child_urls(self):
        """
        Test REST child URLs derived from GET harvest IDs and POST creation.
        Pattern 1: GET /api/Users returned id=23 → test /api/Users/23 in User B session
        Pattern 2: POST /api/BasketItems returned id=42 → test /api/BasketItems/42
        This catches true path-based IDOR that param enumeration misses entirely.
        """
        if not self.child_urls:
            return
        tprint(f"\n  {info(f'Testing {len(self.child_urls)} ownership-based child URLs...')}")
        for child in self.child_urls:
            t_url  = child["url"]
            method = child.get("method", "GET")
            id_val = child["id_val"]
            id_type = child["id_type"]
            t_ep   = {"url": t_url, "method": method, "params": {},
                      "source": child["source"], "synthetic_params": False}
            try:
                a_resp     = self._fetch(self.client_a, t_ep)
                b_resp     = self._fetch(self.client_b, t_ep)
                is_idor, conf, evidence = self._analyser.compare(
                    a_resp, {}, b_resp
                )
                vprint(f"    [child] {method} {t_url}  "
                       f"a={a_resp.get('status')} b={b_resp.get('status')}  "
                       f"idor={is_idor}")
                if is_idor:
                    _poc_label, _poc_cmd, _poc_browser = self._build_poc_curl(t_url, method)
                    finding = {
                        "url":               t_url,
                        "method":            method,
                        "location":          "path",
                        "param_name":        None,
                        "original_id":       id_val,
                        "tampered_id":       id_val,
                        "id_type":           id_type,
                        "finding_type":      "path_idor",
                        "confidence":        conf,
                        "evidence":          evidence + (
                            " | [ownership:get_harvest_derived]"
                            if child["source"].startswith("get_harvest:")
                            else " | [ownership:user_a_created_resource]"
                        ),
                        "status":            b_resp.get("status"),
                        "body_snippet":      (b_resp.get("body", "") or "")[:300],
                        "source":            child["source"],
                        "session":           "User B",
                        "poc_curl":          _poc_cmd,
                        "poc_browser":       _poc_browser,
                        "poc_session_label": _poc_label,
                        # [HELLHOUND] Reproduction Data
                        "repro_data": {
                            "url": t_url,
                            "method": method,
                            "headers": dict(self.client_b.headers if not self.single_session else self.client_a.headers),
                            "body": None
                        }
                    }
                    if self._record_finding(finding):
                        self._print_hit(finding)
            except Exception:
                pass

    def _param_is_effective(self, client, ep, pname, b_tampered):
        """Check if param actually changes the response — if not, server ignores it."""
        try:
            clean_params = {k: v for k, v in (ep.get("params") or {}).items()
                            if k != pname}
            clean_ep = {**ep, "params": clean_params}
            base_resp = self._fetch(client, clean_ep)
            base_body = (base_resp.get("body") or "").strip()
            tampered_body = (b_tampered.get("body") or "").strip()
            return base_body != tampered_body
        except Exception:
            return True

    def _build_poc_curl(self, url, method, params=None, param_name=None, tampered_id=None):
        """
        Build a PoC curl command for the finding.
        Single-session mode: uses User A's token.
        Dual-session mode:   uses User B's token.
        Reads from client.headers — where HTTPClient stores all auth.
        """
        auth_client   = self.client_a if self.single_session else self.client_b
        session_label = "User A" if self.single_session else "User B"

        auth_part = ""
        try:
            hdrs = getattr(auth_client, "headers", {}) or {}
            if hdrs.get("Cookie"):
                auth_part = f" -H 'Cookie: {hdrs['Cookie']}'"
            elif hdrs.get("Authorization"):
                auth_part = f" -H 'Authorization: {hdrs['Authorization']}'"
        except Exception:
            auth_part = f" -H 'Cookie: <paste-{session_label.lower().replace(' ','-')}-token>'"

        if params and param_name and tampered_id:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param_name}={tampered_id}"
        else:
            test_url = url

        method_part = "" if method == "GET" else f" -X {method}"
        return session_label, f"curl -sk{method_part}{auth_part} '{test_url}'", test_url

    def _print_hit(self, f):
        conf_col = C.BRED if f["confidence"] == "HIGH" else C.BYELLOW
        _conf = f["confidence"]; _meth = f["method"]; _url = f["url"]
        tprint(
            f"\n  {found(color(f'[{_conf}]  {_meth} {_url}', conf_col, C.BOLD))}"
        )
        tprint(
            f"    {color('Location:', C.BYELLOW)} {f['location']}  "
            f"{color('Param:', C.BYELLOW)} {f['param_name'] or '(path segment)'}  "
            f"{color('Original:', C.BYELLOW)} {f['original_id']}  "
            f"{color('Tampered:', C.BRED)} {f['tampered_id']}"
        )
        tprint(f"    {color('Evidence:', C.BYELLOW)} {f['evidence']}")
        snippet = (f.get("body_snippet") or "").replace("\n", " ")[:200]
        if snippet:
            tprint(f"    {color('Snippet:', C.DIM)} {snippet}")

    def run(self):
        if not self.targets:
            tprint(f"  {warn('No IDOR surface found in discovered endpoints.')}")
            return []

        total = len(self.targets)
        tprint(f"\n  {info(f'Testing {total} IDOR-candidate endpoints...')}\n")
        if self.single_session:
            tprint(f"  {warn('Single-session mode — comparing User A vs unauthenticated baseline.')}")
            tprint(f"  {info('Findings indicate BAC/data-exposure; add --cookie-b for full IDOR testing.')}\n")

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = {
                pool.submit(self._test_one, s, ep, tgts): ep["url"]
                for s, ep, tgts in self.targets
            }
            done = 0
            # Per-endpoint wall-clock budget: timeout * max_candidates + buffer
            # Prevents a single hanging endpoint from blocking the entire scan
            _per_ep_budget = (self.threads + 1) * 30  # ~30s per endpoint max
            try:
                for fut in as_completed(futs, timeout=_per_ep_budget * len(self.targets)):
                    done += 1
                    try:
                        fut.result(timeout=_per_ep_budget)
                    except TimeoutError:
                        url = futs.get(fut, "?")
                        vprint(warn(f"Endpoint timed out — skipping: {url}"))
                    except Exception as ex:
                        if "_zero_streak" not in str(ex):
                            vprint(f"  {warn(f'Worker error: {ex}')}")
            except Exception:
                # as_completed internal error (Python <3.12 _zero_streak bug)
                # — collect any remaining results directly
                for fut in futs:
                    if not fut.done():
                        continue
                    done += 1
                    try:
                        fut.result(timeout=1)
                    except Exception:
                        pass
                sys.stdout.write(
                    f"\r  {color('Testing:', C.DIM)} {done}/{total}  "
                    f"{color(f'{len(self.findings)} finding(s) so far', C.BYELLOW)}   "
                )
                sys.stdout.flush()

        sys.stdout.write("\r" + " " * 64 + "\r")

        # Unauth-only pass: independently test all IDOR-surface endpoints
        # with NO session. Any endpoint that returns sensitive data to an
        # unauthenticated client is an IDOR/broken-auth finding in its own right —
        # even if the dual-session differential found nothing above.
        if self.test_unauth and self.client_unauth:
            tprint(f"\n  {info('Unauth scan pass...')}")
            _unauth_budget = max(60, self.threads * 20)
            with ThreadPoolExecutor(max_workers=self.threads) as _upool:
                _ufuts = {
                    _upool.submit(self._unauth_one, score, ep, tgts): ep["url"]
                    for score, ep, tgts in self.targets
                }
                try:
                    for _uf in as_completed(_ufuts, timeout=_unauth_budget):
                        try:
                            _uf.result(timeout=30)
                        except TimeoutError:
                            vprint(warn(f"Unauth probe timed out: {_ufuts.get(_uf, '?')}"))
                        except Exception:
                            pass
                except Exception:
                    pass
        # Test ownership-based child URLs from POST creation harvest
        self._test_child_urls()
        return self.findings

    def _unauth_one(self, score, ep, idor_targets):
        ra     = self._analyser
        method = ep["method"]
        if method in ("PUT", "PATCH", "DELETE") and not self.write_probe:
            return
        variants = self._all_param_variants(ep, idor_targets)
        for t_ep, t_params, t_url, orig_val, tampered_id, pname, loc, id_type in variants:
            if self.delay:
                time.sleep(self.delay)
            try:
                ua_resp = self._fetch(self.client_unauth, t_ep, t_params)
                body    = ua_resp.get("body", "") or ""
                status  = ua_resp.get("status", 0)
                if status not in range(200, 210) or not body:
                    continue
                if ra.is_access_denied(ua_resp):
                    continue
                if not ra.has_sensitive_data(body):
                    continue
                a_base = self._fetch(self.client_a, ep)
                b_base = self._fetch(self.client_b, ep)
                a_sens = ra.has_sensitive_data((a_base.get("body") or ""))
                b_sens = ra.has_sensitive_data((b_base.get("body") or ""))
                is_likely_public = (
                    a_base.get("status") in range(200, 210) and
                    b_base.get("status") in range(200, 210) and
                    a_sens and b_sens
                )
                unauth_confidence = "MEDIUM" if is_likely_public else "HIGH"
                unauth_evidence   = (
                    "no_auth_required | sensitive_data_in_response | possibly_intentional_public_endpoint"
                    if is_likely_public else
                    "no_auth_required | sensitive_data_in_response"
                )
                finding = {
                    "method":       method,
                    "url":          t_url,
                    "location":     loc,
                    "param_name":   pname,
                    "original_id":  orig_val,
                    "tampered_id":  tampered_id,
                    "id_type":      id_type,
                    "confidence":   unauth_confidence,
                    "evidence":     unauth_evidence,
                    "status":       status,
                    "body_snippet": body[:300],
                    "source":       ep.get("source", ""),
                    "session":      "unauthenticated",
                }
                if self._record_finding(finding):
                    tprint(f"\n  {found(color(f'[UNAUTH][{unauth_confidence}]  {method} {t_url}', C.BRED, C.BOLD))}")
                    tprint(f"    {color('⚠ Sensitive data returned with NO session!', C.BRED, C.BOLD)}")
                    tprint(f"    {color('Snippet:', C.DIM)} {body[:150]}")
                    break
            except Exception:
                pass

    def _run_unauth_scan(self):
        pass  # work moved to _unauth_one via thread pool in run()

    def _all_param_variants(self, ep, idor_targets):
        """
        Build all (tampered_ep, params, url, orig_val, tampered_id, param_name,
        location, id_type) tuples for an endpoint — same logic as _test_one
        but extracted so both _test_one and _run_unauth_scan can share it.
        """
        variants = []
        method = ep["method"]
        url    = ep["url"]

        for target in idor_targets:
            loc      = target["location"]
            pname    = target.get("param_name")
            orig_val = target["sample_value"]
            id_type  = target["id_type"]

            candidates = self._build_candidates(orig_val, id_type)
            _zero_streak = 0  # consecutive status=0 responses
            for tampered_id in candidates:
                if loc == "path":
                    t_url  = self._substitute_path(url, orig_val, tampered_id)
                    t_ep   = {**ep, "url": t_url}
                    t_params = ep.get("params") or {}
                else:
                    t_url  = url
                    t_ep   = ep
                    t_params = {**(ep.get("params") or {}), pname: tampered_id}

                variants.append((t_ep, t_params, t_url, orig_val,
                                 tampered_id, pname, loc, id_type))
        return variants

# ─────────────────────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────────────────────
def print_report(findings, target, stats, single_session=False):
    section("IDOR DETECTION REPORT")
    tprint(f"  {color('Target:',         C.BYELLOW)} {target}")
    tprint(f"  {color('Timestamp:',      C.BYELLOW)} {stats.get('timestamp', '?')}")
    tprint(f"  {color('Pages crawled:',  C.BYELLOW)} {stats.get('pages', '?')}"
           f"  {color('JS files:',       C.BYELLOW)} {stats.get('js_files', '?')}"
           f"  {color('Endpoints:',      C.BYELLOW)} {stats.get('endpoints', '?')}")
    tprint(f"  {color('IDOR surface:',   C.BYELLOW)} {stats.get('idor_surface', '?')}"
           f"  {color('ID hints:',       C.BYELLOW)} {stats.get('id_hints', '?')}")
    tprint()

    if not findings:
        tprint(f"  {ok('No IDOR vulnerabilities confirmed.')}")
        tprint(f"  {color('NOTE:', C.BYELLOW)} This does not guarantee absence.")
        tprint(f"  {color('TIP:', C.BYELLOW)}  Try --depth 3+, supply both user sessions, or pass a direct API URL.")
        return

# Dedup findings to one per (url, param_name) — keep highest confidence
    seen_ep = {}
    for f in findings:
        key = (f["url"].split("?")[0], f.get("param_name"), f.get("location"))
        if key not in seen_ep:
            seen_ep[key] = f
        else:
            order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
            if order.get(f.get("confidence","LOW"), 0) > order.get(seen_ep[key].get("confidence","LOW"), 0):
                seen_ep[key] = f
    findings = list(seen_ep.values())

    # Split by session type for ordering
    user_b  = [f for f in findings if f.get("session", "User B") != "unauthenticated"]
    unauth  = [f for f in findings if f.get("session") == "unauthenticated"]

    tprint(f"  {color(f'CONFIRMED IDOR FINDINGS', C.BRED, C.BOLD)}"
           f"  {color(f'[User B: {len(user_b)}  Unauthenticated: {len(unauth)}]', C.DIM)}\n")

    def _print_group(group, label_prefix):
        by_conf = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for f in group:
            by_conf.get(f.get("confidence", "LOW"), by_conf["LOW"]).append(f)
        idx = 1
        for level in ("HIGH", "MEDIUM", "LOW"):
            for f in by_conf[level]:
                cc = C.BRED if level == "HIGH" else C.BYELLOW if level == "MEDIUM" else C.DIM
                tprint(f"  {color(f'[{idx}]', C.BOLD, C.BWHITE)} "
                       f"{color(f'[{level}]', cc, C.BOLD)} "
                       f"{color(label_prefix, C.DIM)}")
                tprint(f"      {color('Endpoint:', C.BYELLOW)} {f['method']} {f['url']}")
                tprint(f"      {color('Location:', C.BYELLOW)} {f['location']}"
                       f"  {color('Param:', C.BYELLOW)} {f.get('param_name') or '(path segment)'}")
                tprint(f"      {color('ID Type:', C.BYELLOW)} {f['id_type']}"
                       f"  {color('Original:', C.BYELLOW)} {f['original_id']}"
                       f"  {color('Tampered:', C.BRED, C.BOLD)} {f['tampered_id']}")
                tprint(f"      {color('HTTP Status:', C.BYELLOW)} {f.get('status', '?')}")
                tprint(f"      {color('Evidence:', C.BYELLOW)} {f['evidence']}")
                tprint(f"      {color('Source:', C.DIM)} {f.get('source', '')}")
                snip = (f.get("body_snippet") or "").replace("\n", " ")[:180]
                if snip:
                    tprint(f"      {color('Snippet:', C.DIM)} {snip}")
                # PoC curl — colored, labeled with correct session
                poc       = f.get("poc_curl", "")
                poc_label = f.get("poc_session_label", "User B")
                if poc:
                    tprint(f"      {color(f'PoC ({poc_label}):', C.BRED, C.BOLD)} "
                           f"{color(poc, C.BYELLOW)}")
                    tprint(f"      {color(f'↑ Paste and run to reproduce — uses {poc_label} session', C.DIM)}")
                tprint()
                idx += 1

    if user_b:
        label = "Single-session BAC Findings" if single_session else "User B Session Findings"
        tprint(color(f"  ── {label} ──", C.BYELLOW, C.BOLD))
        group_label = "User A (single-session BAC)" if single_session else "User B session"
        _print_group(user_b, group_label)
    if unauth:
        tprint(color("  ── Unauthenticated Findings (Critical) ──", C.BRED, C.BOLD))
        _print_group(unauth, "No session (public access)")

    tprint(color("  REMEDIATION", C.BOLD + C.BYELLOW))
    tprint(f"  {color('─'*68, C.DIM)}")
    tprint("  • Enforce server-side authorization on EVERY object access request.")
    tprint("  • Validate ownership: authenticated user must own (or be granted")
    tprint("    access to) the specific object ID before returning any data.")
    tprint("  • Use cryptographically random, non-sequential object identifiers.")
    tprint("  • Apply row-level security at the data layer — not just at the API.")
    tprint()
    return findings

def export_json(findings, target, stats, out_path):

    def _severity(f):
        """Map finding fields to a CVSS-style severity tier."""
        session    = f.get("session", "")
        confidence = f.get("confidence", "LOW")
        evidence   = f.get("evidence", "")
        if session == "unauthenticated" and "no_auth_required" in evidence:
            return "CRITICAL"
        if confidence == "HIGH":
            return "HIGH"
        if confidence == "MEDIUM":
            return "MEDIUM"
        return "LOW"

    enriched = []
    for f in findings:
        enriched.append({**f, "severity": _severity(f)})

    stats = {**stats, "findings": len(enriched)}
    payload = {
        "agent":    "HELLHOUND-Agent30-IDOR_UserData_Detector",
        "version":  "1.3.0",
        "target":   target,
        "stats":    stats,
        "findings": enriched,
    }
    with open(out_path, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    tprint(f"\n  {ok(f'JSON report saved → {out_path}')}")

# ─────────────────────────────────────────────────────────────────────────────
# SPIDER BRIDGE
# Ingests Hellhound Spider / HELLHOUND spider JSON output and converts it to the
# standard internal endpoint list used throughout this agent.
#
# Accepted spider JSON schema (Hellhound Spider compatible):
#   {
#     "target":    "http://...",          # optional
#     "endpoints": [                      # or "urls" / "results"
#       {
#         "url":                "http://target/api/user/42",
#         "methods":            ["GET"],   # or "method": "GET"
#         "params": {
#           "query":   ["id","user_id"],   # highest IDOR signal
#           "runtime": ["uuid"],           # live-observed params
#           "form":    ["username"],
#           "js":      ["profile_id"],
#           "openapi": ["order_id"]
#         },
#         "parameter_sensitive": true,
#         "observed_status":     200,
#         "baseline":  {"status": 200, "hash": "abc123"},
#         "discovered_via": "/api/users"
#       }
#     ]
#   }
#
# Also accepts a flat list of endpoints at top level.
# Also accepts flat {name: value} params dict (non-bucketed).
# ─────────────────────────────────────────────────────────────────────────────
class SpiderBridge:
    def __init__(self, timeout=30, ua=None):
        self.timeout = timeout
        self.ua      = ua
        self.id_hints_ep = []
    
    # Param bucket priority order — higher buckets = higher IDOR confidence
    _BUCKET_ORDER    = ["runtime", "query", "openapi", "js", "form"]
    _PRIORITY_BUCKETS = {"runtime", "query"}
    # Strip common suffixes Hellhound Spider sometimes appends
    _STRIP_SFX = re.compile(
        r'^(.+?)(?:_raw|_sanitized|_input|_clean|_safe|_encoded|_value)$', re.I)
    # Auth params: skip injecting these (passwords, tokens, CSRF)
    _AUTH_RE   = re.compile(r'(?:password|passwd|pass|token|csrf|secret|auth)', re.I)

    def _strip(self, name):
        m = self._STRIP_SFX.match(str(name).strip())
        return m.group(1) if m else str(name).strip()

    def load(self, filepath, cli_target=None):
        """
        Load a spider JSON file and return (target_url, endpoints_list).
        target_url: base URL inferred from file or cli_target.
        endpoints_list: list of internal endpoint dicts, fully normalised.
        """
        try:
            with open(filepath, encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception as e:
            tprint(f"  {err(f'--spider-json/file error: {e}')}")
            return cli_target or "", []

        return self.parse(raw, cli_target)

    def parse(self, raw, cli_target=None):
        """
        Parse raw spider data (dict or list) and return (target_url, endpoints_list).
        This contains the core normalization logic.
        """
        # Normalise top-level structure
        if isinstance(raw, dict):
            file_target = (raw.get("target") or raw.get("base_url")
                           or raw.get("url") or "")
            entries     = (raw.get("endpoints") or raw.get("urls")
                           or raw.get("results") or [])
        elif isinstance(raw, list):
            file_target = ""
            entries     = raw
        else:
            return cli_target or "", []

        # Resolve authoritative target URL
        target = cli_target or file_target or ""
        if target and not target.startswith(("http://", "https://")):
            target = "http://" + target

        # Parse CLI target for potential URL rebasing
        cli_parsed  = urllib.parse.urlparse(target) if target else None
        file_parsed = urllib.parse.urlparse(file_target) if file_target else None

        endpoints = []
        n_confirmed  = 0
        n_priority   = 0
        self.id_hints_ep = [] # Temporary store for hints discovered in this pass

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            # ── URL ────────────────────────────────────────────────────────
            ep_url = (entry.get("url") or entry.get("endpoint") or "").strip()
            if not ep_url:
                continue
            if not ep_url.startswith("http"):
                if target:
                    ep_url = urllib.parse.urljoin(
                        target.rstrip("/") + "/", ep_url.lstrip("/"))
                else:
                    continue

            # Rebase URL if CLI target differs from spider's origin
            if (cli_parsed and file_parsed
                    and cli_parsed.netloc
                    and cli_parsed.netloc != file_parsed.netloc):
                ep_parsed = urllib.parse.urlparse(ep_url)
                ep_url    = urllib.parse.urlunparse((
                    cli_parsed.scheme, cli_parsed.netloc,
                    ep_parsed.path, ep_parsed.params,
                    ep_parsed.query, "",
                ))

            # ── Method ─────────────────────────────────────────────────────
            raw_methods = entry.get("methods") or entry.get("method") or ["GET"]
            if isinstance(raw_methods, str):
                raw_methods = [raw_methods]
            method = str(raw_methods[0]).upper() if raw_methods else "GET"
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                method = "GET"
            # Normalise destructive verbs to POST for testing purposes
            if method in ("PUT", "PATCH", "DELETE"):
                method = "POST"

            # ── Skip definitively failed endpoints ─────────────────────────
            obs_status = entry.get("observed_status") or 0
            if isinstance(obs_status, list):
                obs_status = obs_status[0] if obs_status else 0
            baseline   = entry.get("baseline") or {}
            if not obs_status and isinstance(baseline, dict):
                obs_status = baseline.get("status") or 0
            if int(obs_status or 0) in (404, 410, 400):
                continue

            # ── Params ─────────────────────────────────────────────────────
            raw_params     = entry.get("params") or {}
            params         = {}
            priority_params= []
            id_hints_ep    = []  # ID values extracted from spider data

            if isinstance(raw_params, dict):
                is_bucketed = any(isinstance(v, list)
                                  for v in raw_params.values())
                if is_bucketed:
                    # Hellhound Spider bucketed format
                    for bucket in self._BUCKET_ORDER:
                        for pname in (raw_params.get(bucket) or []):
                            pk = self._strip(pname)
                            if not pk:
                                continue
                            if self._AUTH_RE.search(pk) and bucket == "form":
                                continue   # skip auth params
                            if pk not in params:
                                params[pk] = "test"
                            if bucket in self._PRIORITY_BUCKETS and pk not in priority_params:
                                priority_params.append(pk)
                    # Non-standard buckets
                    for bucket, plist in raw_params.items():
                        if bucket not in self._BUCKET_ORDER and isinstance(plist, list):
                            for pname in plist:
                                pk = self._strip(pname)
                                if pk and pk not in params:
                                    params[pk] = "test"
                else:
                    # Flat {name: value} dict
                    for pk, pv in raw_params.items():
                        pk = self._strip(pk)
                        if not pk:
                            continue
                        if self._AUTH_RE.search(pk):
                            continue
                        params[pk] = str(pv) if pv is not None else "test"
                        if _IDOR_PARAM_NAME_RE.match(pk):
                            priority_params.append(pk)
                            # Harvest live ID value if it looks real
                            pv_str = str(pv) if pv else ""
                            if _NUMERIC_RE.match(pv_str) or _UUID_RE.match(pv_str):
                                id_hints_ep.append({
                                    "id_val":     pv_str,
                                    "id_type":    "numeric" if _NUMERIC_RE.match(pv_str) else "uuid",
                                    "id_source":  f"spider:param:{pk}",
                                    "context_url": ep_url,
                                })

            elif isinstance(raw_params, list):
                # List of param names
                for item in raw_params:
                    pk = self._strip(str(item))
                    if pk and pk not in params:
                        params[pk] = "test"
                        if _IDOR_PARAM_NAME_RE.match(pk):
                            priority_params.append(pk)
# ── Synthesize IDOR surface hint for auth-required endpoints ──
            # If an endpoint is auth_required or parameter_sensitive but has
            # no params and no numeric path segment, inject a synthetic "id"
            # param hint so the surface analyser scores it and the harvest
            # pass fetches it authenticated to find real IDs.
            # This covers REST APIs like /api/Users, /api/BasketItems etc.
            # where the spider saw a 401 and couldn't observe real param values.
            is_auth_ep = bool(entry.get("auth_required")) or bool(entry.get("parameter_sensitive"))
            has_path_id = bool(_PATH_NUMERIC_RE.search(urllib.parse.urlparse(ep_url).path) or
                               _PATH_UUID_RE.search(urllib.parse.urlparse(ep_url).path))
            if is_auth_ep and not params and not has_path_id:
                last_seg = [s for s in urllib.parse.urlparse(ep_url).path.split("/") if s]
                if last_seg:
                    raw_seg = last_seg[-1].lower()
                    # Smart singularization — only strip trailing 's' for clear plurals.
                    # Preserves: status→status, address→address, process→process
                    # Strips:    users→user, basketitems→basketitem, cards→card
                    if (raw_seg.endswith("s")
                            and not raw_seg.endswith("ss")
                            and not raw_seg.endswith("us")
                            and not raw_seg.endswith("is")
                            and len(raw_seg) > 3):
                        seg = raw_seg[:-1]
                    else:
                        seg = raw_seg
                    synth_param = f"{seg}_id"
                    params[synth_param] = "1"
                    priority_params.append(synth_param)
                else:
                    synth_param = "id"
                    params[synth_param] = "1"
                    priority_params.append(synth_param)
                # Tag endpoint so _test_one knows params weren't observed in traffic
                ep_synthetic = True
            else:
                ep_synthetic = False

            # QS params embedded in the URL itself
            ep_parsed_qs = urllib.parse.urlparse(ep_url)
            qs_params    = urllib.parse.parse_qs(
                ep_parsed_qs.query, keep_blank_values=True)
            for pk, pvlist in qs_params.items():
                pk = self._strip(pk)
                if pk and pk not in params:
                    params[pk] = pvlist[0] if pvlist else "test"
                    if pk not in priority_params:
                        priority_params.append(pk)
                # Harvest live ID value from QS
                pv_str = pvlist[0] if pvlist else ""
                if _IDOR_PARAM_NAME_RE.match(pk) and (
                        _NUMERIC_RE.match(pv_str) or _UUID_RE.match(pv_str)):
                    id_hints_ep.append({
                        "id_val":     pv_str,
                        "id_type":    "numeric" if _NUMERIC_RE.match(pv_str) else "uuid",
                        "id_source":  f"spider:qs:{pk}",
                        "context_url": ep_url,
                    })
            # Strip QS from URL (absorbed into params)
            ep_url = urllib.parse.urlunparse(
                ep_parsed_qs._replace(query="", fragment=""))

            # Harvest numeric/UUID path segments as ID hints
            # e.g. /profile/1  → id_val="1", /api/resource/550e8400-... → uuid
            # Works regardless of the app's URL structure or slug naming
            ep_path = urllib.parse.urlparse(ep_url).path
            for m in _PATH_NUMERIC_RE.finditer(ep_path):
                val = m.group(1)
                id_hints_ep.append({
                    "id_val":     val,
                    "id_type":    "numeric",
                    "id_source":  "spider:path_segment",
                    "context_url": ep_url,
                })
            for m in _PATH_UUID_RE.finditer(ep_path):
                val = m.group(1).lower()
                id_hints_ep.append({
                    "id_val":     val,
                    "id_type":    "uuid",
                    "id_source":  "spider:path_segment",
                    "context_url": ep_url,
                })

            # Fallback: path-hint params if nothing found
            if not params:
                segs = [s for s in urllib.parse.urlparse(ep_url).path.split("/") if s
                        and not _NUMERIC_RE.match(s) and not _UUID_RE.match(s)]
                for seg in segs[-2:]:
                    seg_lo = seg.lower()
                    if (seg_lo.endswith("s")
                            and not seg_lo.endswith("ss")
                            and not seg_lo.endswith("us")
                            and not seg_lo.endswith("is")
                            and len(seg_lo) > 3):
                        seg_clean = seg_lo[:-1]
                    else:
                        seg_clean = seg_lo
                    for suffix in ("_id", "Id", "ID"):
                        params[seg_clean + suffix] = "test"
                if not params:
                    params = {"id": "test"}

            # ── Metadata ───────────────────────────────────────────────────
            response_sig = None
            if isinstance(baseline, dict):
                response_sig = baseline.get("hash") or None

            confirmed = bool(priority_params) or bool(
                entry.get("parameter_sensitive"))
            if confirmed:
                n_confirmed += 1
            n_priority += len(priority_params)

            # ── Final normalization ────────────────────────────────────────
            endpoints.append({
                "url":                ep_url,
                "method":             method,
                "params":             params,
                "hidden":             {},
                "source":             "spider_intel",
                "synthetic_params":   ep_synthetic, 
                "priority_params":    list(dict.fromkeys(priority_params)),
                "parameter_sensitive":bool(entry.get("parameter_sensitive")),
                "auth_required":      bool(entry.get("auth_required")),
                "response_sig":       response_sig,
                "discovered_via":     entry.get("discovered_via") or None,
                "_spider_id_hints":   id_hints_ep,  # harvested live IDs
            })
            if ep_synthetic: n_priority += 1

        tprint(f"  {ok(f'Spider JSON loaded — {len(endpoints)} endpoints, '
                       f'{n_confirmed} confirmed, {n_priority} priority params')}")

        return target, endpoints

    def export(self, crawler, target, filepath):
        """
        Save built-in crawler output as a spider JSON file.
        Compatible with HELLHOUND's --spider-json format.
        Can be passed to subsequent agent runs or to HELLHOUND directly.
        """
        export_eps = []
        for ep in crawler.endpoints:
            # Convert flat params back to bucketed format
            params_bucketed = {
                "query":   [],
                "form":    [],
                "runtime": [],
            }
            src = ep.get("source", "") or ""
            for pname in (ep.get("priority_params") or []):
                params_bucketed["runtime"].append(pname)
            for pname, pval in ep.get("params", {}).items():
                bucket = (
                    "runtime" if pname in (ep.get("priority_params") or [])
                    else "query"  if "url_query" in src
                    else "form"   if "form" in src
                    else "js"     if src.startswith("js:")
                    else "query"
                )
                if pname not in params_bucketed.get(bucket, []):
                    params_bucketed.setdefault(bucket, []).append(pname)

            export_ep = {
                "url":                ep["url"],
                "methods":            [ep["method"]],
                "params":             {k: v for k, v in params_bucketed.items() if v},
                "parameter_sensitive":bool(ep.get("priority_params")),
                "source":             src,
                "discovered_via":     ep.get("discovered_via"),
            }
            export_eps.append(export_ep)

        # Also export ID hints as a separate key for downstream agents
        id_hints_export = [
            {
                "id_val":     h["id_val"],
                "id_type":    h["id_type"],
                "id_source":  h["id_source"],
                "context_url":h["context_url"],
            }
            for h in crawler.id_hints
        ]

        payload = {
            "agent":      "HELLHOUND-Agent30-IDOR_UserData_Detector",
            "version":    "1.3.0",
            "target":     target,
            "endpoints":  export_eps,
            "id_hints":   id_hints_export,
            "crawl_stats":{
                "pages":    len(crawler.visited),
                "js_files": len(crawler.js_visited),
                "endpoints":len(crawler.endpoints),
                "id_hints": len(crawler.id_hints),
            },
        }
        with open(filepath, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        tprint(f"  {ok(f'Spider export saved → {filepath}  ({len(export_eps)} endpoints)')}")

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="idor_agent30",
        description="HELLHOUND Agent 30 — IDOR_UserData_Detector v1.3",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("target", nargs="?", default=None,
                   help="Base URL of the target application\n"
                        "(optional when --spider-json is provided — URL inferred from file)")

    gs = p.add_argument_group("Spider integration")
    gs.add_argument("--spider-json",   metavar="FILE",
                    help="Load endpoints from an Hellhound Spider / HELLHOUND spider JSON file.\n"
                         "Skips the built-in crawler entirely.\n"
                         "Schema: {target, endpoints:[{url, methods, params:{query,form,js,...}}]}")
    gs.add_argument("--spider",        metavar="FILE",
                    help="Alias for --spider-json (legacy)")
    gs.add_argument("--spider-export", metavar="FILE",
                    help="Run built-in crawl AND save results as spider JSON for reuse\n"
                         "by subsequent agent runs or by HELLHOUND (--spider-json).")

    ga = p.add_argument_group("User A (resource owner — whose IDs are harvested)")
    ga.add_argument("--cookie-a",          metavar="COOKIE",
                    help="Cookie string for User A (e.g. 'session=abc123')")
    ga.add_argument("--header-a",          metavar="K:V",
                    help="Extra header for User A (e.g. 'Authorization: Bearer TOKEN')")
    ga.add_argument("--login-url-a",       metavar="URL",
                    help="Login endpoint URL for User A\n"
                         "(optional — AuthEngine auto-discovers it if omitted)")
    ga.add_argument("--login-user-a",      metavar="USER",
                    help="Username or email for User A")
    ga.add_argument("--login-pass-a",      metavar="PASS",
                    help="Password for User A")
    ga.add_argument("--login-user-field-a",metavar="FIELD", default="username",
                    help="Username field name override (default: auto-detected)")
    ga.add_argument("--login-pass-field-a",metavar="FIELD", default="password",
                    help="Password field name override (default: auto-detected)")
    ga.add_argument("--auto-register",     action="store_true",
                    help="Auto-create two test accounts via the app's register form.\n"
                         "Use when no existing accounts are available.\n"
                         "Agent discovers the register endpoint automatically.")

    gb = p.add_argument_group("User B (attacker session) — optional for single-session BAC mode")
    gb.add_argument("--cookie-b",          metavar="COOKIE",
                    help="Second session token. If omitted, runs single-session BAC scan "
                         "using User A only — finds endpoints returning data beyond your scope.")
    gb.add_argument("--header-b",          metavar="K:V")
    gb.add_argument("--login-url-b",       metavar="URL")
    gb.add_argument("--login-user-b",      metavar="USER")
    gb.add_argument("--login-pass-b",      metavar="PASS")
    gb.add_argument("--login-user-field-b",metavar="FIELD",default="username")
    gb.add_argument("--login-pass-field-b",metavar="FIELD",default="password")

    gc = p.add_argument_group("Crawler")
    gc.add_argument("--depth",     type=int, default=4,   metavar="N",
                    help="Crawl depth (default: 4 — autonomous mode)")
    gc.add_argument("--max-pages", type=int, default=200, metavar="N",
                    help="Max pages to crawl (default: 200)")
    gc.add_argument("--threads",   type=int, default=10,  metavar="N",
                    help="Worker threads (default: 10)")

    gp = p.add_argument_group("Probe")
    gp.add_argument("--delay",       type=float, default=0, metavar="SEC",
                    help="Delay between requests in seconds")
    gp.add_argument("--no-unauth",   action="store_true",
                    help="Skip unauthenticated endpoint checks")
    gp.add_argument("--write-probe", action="store_true",
                    help="Also test POST/PUT endpoints (default: GET only)")
    gp.add_argument("--invite-code", metavar="CODE",
                    help="Invite/registration code required by the app's register form.\n"
                         "Used automatically during --auto-register if the form has an\n"
                         "invite_code field. Also tried before the built-in code list.")
    gp.add_argument("--timeout",     type=int,   default=12, metavar="SEC",
                    help="HTTP timeout in seconds (default: 12)")
    gp.add_argument("--user-agent",  metavar="UA",
                    help="Custom User-Agent string")

    go = p.add_argument_group("Output")
    go.add_argument("--json",    metavar="FILE", help="Save JSON report to FILE")
    go.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    return p

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
class MockArgs:
    def __init__(self, **kwargs):
        self.cookie_a = None
        self.header_a = None
        self.login_url_a = None
        self.login_user_a = None
        self.login_pass_a = None
        self.login_user_field_a = "username"
        self.login_pass_field_a = "password"
        self.auto_register = False
        self.cookie_b = None
        self.header_b = None
        self.login_url_b = None
        self.login_user_b = None
        self.login_pass_b = None
        self.login_user_field_b = "username"
        self.login_pass_field_b = "password"
        self.depth = 3
        self.max_pages = 200
        self.threads = 8
        self.delay = 0.0
        self.no_unauth = False
        self.write_probe = False
        self.invite_code = None
        self.timeout = 10
        self.user_agent = None
        self.spider_intel = {}
        self.spider = None
        self.spider_export = None
        
        for k, v in kwargs.items():
            setattr(self, k, v)

def run(target, emit, options):
    global VERBOSE
    VERBOSE = options.get("verbose", False)

    # Use emit for printing if available
    global tprint
    if emit and hasattr(emit, "log"):
        tprint = emit.log

    # Build args object from options (cast to types)
    args = MockArgs(
        cookie_a           = options.get("cookie_a"),
        header_a           = options.get("header_a"),
        login_url_a        = options.get("login_url_a"),
        login_user_a       = options.get("login_user_a"),
        login_pass_a       = options.get("login_pass_a"),
        login_user_field_a = options.get("login_user_field_a", "username"),
        login_pass_field_a = options.get("login_pass_field_a", "password"),
        auto_register      = options.get("auto_register", False),
        cookie_b           = options.get("cookie_b"),
        header_b           = options.get("header_b"),
        login_url_b        = options.get("login_url_b"),
        login_user_b       = options.get("login_user_b"),
        login_pass_b       = options.get("login_pass_b"),
        login_user_field_b = options.get("login_user_field_b", "username"),
        login_pass_field_b = options.get("login_pass_field_b", "password"),
        depth              = int(options.get("depth", 3)),
        max_pages          = int(options.get("max_pages", 200)),
        threads            = int(options.get("threads", 8)),
        delay              = float(options.get("delay", 0.0)),
        no_unauth          = bool(options.get("no_unauth", False)),
        write_probe        = bool(options.get("write_probe", False)),
        invite_code        = options.get("invite_code"),
        timeout            = int(options.get("timeout", 10)),
        user_agent         = options.get("user_agent"),
        spider_intel       = options.get("spider_intel", {})
    )

    tprint("\n" + color("[*] IDORdetector: Validating target " + str(target), C.BBLUE))

    target = target.rstrip("/") if target else None
    if not target:
        tprint(err("No target URL provided to run()."))
        return None

    ua = args.user_agent

    # ── Phase 1: Sessions ─────────────────────────────────────────────────
    section("PHASE 1/5 — SESSION INITIALISATION")

    # Bare unauthenticated client used by AuthEngine for probing
    bare_client = HTTPClient(timeout=args.timeout, user_agent=ua, options=options)

    # Detect which auth mode the operator chose
    has_cookie_a = bool(args.cookie_a or args.header_a)
    has_cookie_b = bool(args.cookie_b or args.header_b)
    has_creds_a  = bool(args.login_user_a and args.login_pass_a)
    has_creds_b  = bool(args.login_user_b and args.login_pass_b)
    has_url_a    = bool(args.login_url_a)
    has_url_b    = bool(args.login_url_b)
    auto_reg     = getattr(args, "auto_register", False)

    auth_id_hints = []   # ID hints extracted during auth (User A's own IDs)

    # ── Mode 1: Pre-captured cookies/tokens — inject directly ─────────────
    if has_cookie_a or has_cookie_b:
        client_a = HTTPClient(
            timeout=args.timeout, cookie=args.cookie_a,
            extra_header=args.header_a, user_agent=ua,
            options=options
        )
        if has_cookie_b:
            tprint(f"  {info('Mode: dual-session IDOR scan (User A vs User B)')}")
            client_b = HTTPClient(
                timeout=args.timeout, cookie=args.cookie_b,
                extra_header=args.header_b, user_agent=ua,
                options=options
            )
            tprint(f"  {ok('User A: token injected directly')}")
            tprint(f"  {ok('User B: token injected directly')}")
        else:
            tprint(f"  {info('Mode: single-session BAC scan (User A only)')}")
            tprint(f"  {ok('User A: token injected directly')}")
            tprint(f"  {warn('No User B token — running single-session mode.')}")
            tprint(f"  {info('Tip: add --cookie-b <token> to enable full dual-session IDOR testing')}")
            client_b = bare_client.clone_no_auth()

    # ── Mode 2: Credentials supplied + explicit login URL ─────────────────
    elif has_creds_a and has_url_a:
        tprint(f"  {info('Mode: explicit login URL + credentials')}")
        # Use AuthEngine but with login_url pre-set in probe
        probe = AuthProbe(bare_client, target or "http://placeholder").discover()
        # Override with explicitly supplied login URL
        if has_url_a:
            probe["login_url"] = args.login_url_a
        if has_url_b:
            probe["register_url"] = args.login_url_b   # treated as same endpoint

        builder = SessionBuilder(bare_client, target or args.login_url_a)

        tprint(f"  {info(f'Logging in User A: {args.login_user_a}...')}")
        ok_a, hdrs_a, hints_a = builder.login(args.login_user_a, args.login_pass_a, probe)
        if not ok_a:
            probe_json = {**probe, "content_type": "json"}
            ok_a, hdrs_a, hints_a = builder.login(args.login_user_a, args.login_pass_a, probe_json)
        if not ok_a:
            tprint(f"  {err(f'Login failed for User A ({args.login_user_a}). Check credentials.')}")
            sys.exit(1)
        tprint(f"  {ok(f'User A authenticated — {len(hints_a)} own ID(s) found')}")
        auth_id_hints.extend(hints_a)

        client_a = bare_client.clone_no_auth()
        for k, v in hdrs_a.items():
            if not k.startswith("_"):
                client_a.headers[k] = v

        if has_creds_b:
            b_probe = {**probe}
            if has_url_b:
                b_probe["login_url"] = args.login_url_b
            tprint(f"  {info(f'Logging in User B: {args.login_user_b}...')}")
            ok_b, hdrs_b, _ = builder.login(args.login_user_b, args.login_pass_b, b_probe)
            if not ok_b:
                b_probe_json = {**b_probe, "content_type": "json"}
                ok_b, hdrs_b, _ = builder.login(args.login_user_b, args.login_pass_b, b_probe_json)
            if not ok_b:
                tprint(f"  {err(f'Login failed for User B ({args.login_user_b}). Check credentials.')}")
                sys.exit(1)
            tprint(f"  {ok('User B authenticated')}")
            client_b = bare_client.clone_no_auth()
            for k, v in hdrs_b.items():
                if not k.startswith("_"):
                    client_b.headers[k] = v
        else:
            tprint(f"  {warn('No User B credentials — unauthenticated checks only for User B side.')}")
            client_b = bare_client.clone_no_auth()

    # ── Mode 3: Credentials only — let AuthEngine discover login URL ───────
    elif has_creds_a:
        tprint(f"  {info('Mode: adaptive auth — discovering login form automatically...')}")
        if not target:
            tprint(f"  {err('Target URL required for adaptive auth mode.')}")
            return None
        _invite = getattr(args, "invite_code", None)
        engine = AuthEngine(bare_client, target, tprint_fn=tprint,
                            invite_code_hint=_invite)
        user_a_tuple = (args.login_user_a, args.login_pass_a)
        user_b_tuple = (args.login_user_b, args.login_pass_b) if has_creds_b else None

        try:
            auth_result = engine.run(
                user_a        = user_a_tuple,
                user_b        = user_b_tuple,
                auto_register = False,
            )
            client_a      = auth_result.client_a
            client_b      = auth_result.client_b
            auth_id_hints = auth_result.id_hints
            tprint(f"  {ok(f'Both sessions ready — {len(auth_id_hints)} User A ID(s) harvested')}")
        except RuntimeError as e:
            tprint(f"  {err(str(e))}")
            sys.exit(1)

    # ── Mode 4: Auto-register — no accounts exist ─────────────────────────
    elif auto_reg:
        tprint(f"  {info('Mode: auto-registration — creating two fresh test accounts...')}")
        if not target:
            tprint(f"  {err('Target URL required for auto-register mode.')}")
            return None
        _invite = getattr(args, "invite_code", None)
        engine = AuthEngine(bare_client, target, tprint_fn=tprint,
                            invite_code_hint=_invite)
        try:
            auth_result = engine.run(
                user_a        = None,
                user_b        = None,
                auto_register = True,
            )
            client_a      = auth_result.client_a
            client_b      = auth_result.client_b
            auth_id_hints = auth_result.id_hints
            tprint(f"  {ok(f'Auto-register done — sessions ready, {len(auth_id_hints)} own ID(s).')}")
        except RuntimeError as e:
            tprint(f"  {err(str(e))}")
            sys.exit(1)

    # ── Mode 5: No auth at all — unauthenticated surface scan only ─────────
    else:
        tprint(f"  {warn('No credentials supplied — running unauthenticated surface scan only.')}")
        tprint(f"  {color('TIP:', C.BYELLOW)} Use one of:")
        tprint(f"       --login-user-a alice --login-pass-a pass1  (auto-discovers login form)")
        tprint(f"       --login-url-a URL --login-user-a alice --login-pass-a pass1  (explicit)")
        tprint(f"       --cookie-a 'session=TOKEN'  (pre-captured token)")
        tprint(f"       --auto-register  (create two accounts if registration is open)")
        client_a = bare_client.clone_no_auth()
        client_b = bare_client.clone_no_auth()

    # Unauthenticated client for bypass checks
    client_unauth = None if args.no_unauth else bare_client.clone_no_auth()
    if client_unauth:
        tprint(f"  {info('Unauthenticated client ready for bypass checks.')}")

    # ── Phase 2: Discovery ────────────────────────────────────────────────
    endpoints = []
    crawler = None
    extra_id_hints = []
    discovery_source = "crawler"
    spider_bridge = SpiderBridge(args.timeout, ua)
    
    # Priority 1: Framework-injected spider_intel (dictionary)
    spider_intel = options.get("spider_intel", {})
    if spider_intel and spider_intel.get("endpoints"):
        section("PHASE 2/5 — LOADING SPIDER INTEL (Framework)")
        tprint(f"  {ok('Using internal spider intelligence for endpoint discovery')}")
        discovery_source = "spider_intel"
        
        target, endpoints = spider_bridge.parse(spider_intel, target)
        extra_id_hints.extend(getattr(spider_bridge, "id_hints_ep", []))
        if spider_intel.get("id_hints"):
             extra_id_hints.extend(spider_intel["id_hints"])

    # Priority 2: CLI-provided spider JSON file
    elif getattr(args, "spider", None):
        section("PHASE 2/5 — LOADING SPIDER INTEL (File)")
        spider_file = args.spider
        tprint(f"  [*] Loading: {color(spider_file, C.BWHITE)}")
        discovery_source = "spider_file"
        
        target, endpoints = spider_bridge.load(spider_file, target)
        extra_id_hints.extend(getattr(spider_bridge, "id_hints_ep", []))

    # Priority 3: Built-in Crawler
    if not endpoints:
        section("PHASE 2/5 — CRAWL + JS/SPA ENDPOINT DISCOVERY")
        max_pages = getattr(args, "max_pages", 200)
        crawler = Crawler(client_a, target, depth=args.depth,
                          threads=args.threads, max_pages=max_pages)
        endpoints = crawler.crawl()
        discovery_source = "crawler"

        if not endpoints:
            tprint(f"\n  {err('No endpoints discovered. Try --depth 3 or pass a specific API endpoint URL.')}")
            return None

        if getattr(args, "spider_export", None):
            bridge = SpiderBridge(args.timeout, ua)
            bridge.export(crawler, target, args.spider_export)

    if discovery_source != "crawler":
        tprint(f"  {info(f'Discovery complete: {len(endpoints)} endpoints, {len(extra_id_hints)} ID hints.')}")

    # ── Phase 3: Surface analysis ─────────────────────────────────────────
    section("PHASE 3/5 — IDOR SURFACE ANALYSIS")
    analyser = IDORSurfaceAnalyser()
    targets  = analyser.analyse(endpoints)

    high   = sum(1 for t in targets if t[0] == 3)
    medium = sum(1 for t in targets if t[0] == 2)
    low    = sum(1 for t in targets if t[0] == 1)

    # Pre-harvest hint count (from crawler + spider + auth — before active harvest)
    # Ensure spider_intel IDs are seeded even if harvest fails
    _hint_seen       = set()
    crawler_id_hints = []
    
    pre_harvest_hints = (
        (crawler.id_hints if crawler else [])
        + extra_id_hints
        + auth_id_hints
    )
    # Add spider discovered IDs to the pool
    for hint in pre_harvest_hints:
        k = (hint["id_val"], hint["id_type"])
        if k not in _hint_seen:
            _hint_seen.add(k)
            crawler_id_hints.append(hint)
    tprint(f"  {color('High-signal IDOR surface:', C.BRED,    C.BOLD)} {high} endpoints")
    tprint(f"  {color('Medium-signal:',            C.BYELLOW, C.BOLD)} {medium} endpoints")
    tprint(f"  {color('Low-signal:',               C.DIM)}    {low} endpoints")
    tprint(f"  {color('ID hints (pre-harvest):',   C.BCYAN,  C.BOLD)} {len(pre_harvest_hints)}")
    tprint()

    if targets:
        tprint(f"  {color('Top candidates:', C.BCYAN, C.BOLD)}")
        for score, ep, tgts in targets[:10]:
            sc_col  = C.BRED if score == 3 else C.BYELLOW if score == 2 else C.DIM
            tgt_str = ", ".join(
                t["param_name"] or f"path:{t['sample_value'][:12]}"
                for t in tgts[:4]
            )
            tprint(f"    {color(f'[{score}]', sc_col, C.BOLD)} "
                   f"{color(ep['method'], C.BYELLOW)} "
                   f"{color(ep['url'][:60], C.BWHITE)}"
                   f"  {color(f'[{tgt_str}]', C.DIM)}")
    else:
        tprint(f"  {warn('No IDOR surface detected. Try --depth 4+ or supply direct API URLs.')}")
        return None

    # ── ID Harvest Pass — fetch IDOR endpoints as User A, extract real IDs ──
    has_real_session = any([
        args.cookie_a, args.header_a,
        args.login_user_a, args.login_url_a,
        getattr(args, "auto_register", False)
    ])
    harvest_client = client_a if has_real_session else bare_client

    harvest = IDHarvestPass(
        harvest_client, targets,
        threads=args.threads, delay=args.delay,
        options=options
    )
    harvested_hints = harvest.run()

    # Merge all hint sources — trusted order: auth > harvested > spider > crawler
    for h in (harvested_hints + auth_id_hints + extra_id_hints +
              (crawler.id_hints if crawler else [])):
        k = (h["id_val"], h["id_type"])
        if k not in _hint_seen:
            _hint_seen.add(k)
            crawler_id_hints.append(h)

    tprint(f"  {info(f'ID pool: {len(crawler_id_hints)} unique IDs available for candidate generation')}")

    # ── Phase 4: Testing ──────────────────────────────────────────────────
    section("PHASE 4/5 — DUAL-SESSION IDOR TESTING")
    tester = IDORTester(
        client_a       = client_a,
        client_b       = client_b,
        client_unauth  = client_unauth,
        targets        = targets,
        id_hints       = crawler_id_hints,
        child_urls     = harvest.child_urls,
        threads        = args.threads,
        delay          = args.delay,
        test_unauth    = not args.no_unauth,
        write_probe    = args.write_probe,
        single_session = not has_cookie_b and not has_creds_b,
    )
    findings = tester.run()

    # ── Phase 5: Report ───────────────────────────────────────────────────
    section("PHASE 5/5 — REPORT")
    stats = {
        "timestamp":    datetime.now().isoformat(),
        "pages":        len(crawler.visited)    if crawler else "n/a (spider)",
        "js_files":     len(crawler.js_visited) if crawler else "n/a (spider)",
        "endpoints":    len(endpoints),
        "idor_surface": len(targets),
        "id_hints":     len(crawler_id_hints),
        "findings":     len(findings),
        "source":       discovery_source,
    }
    
    total_risk = 0
    signals = []
    if findings:
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev == "critical": total_risk += 40
            elif sev == "high": total_risk += 30
            elif sev == "medium": total_risk += 20
            elif sev == "low": total_risk += 10
            else: total_risk += 5
        signals.append("IDOR_VULNERABILITY")
        emit.success(f"[+] Found {len(findings)} IDOR vulnerabilities on {target}")
    else:
        emit.info("[-] No IDOR vulnerabilities detected.")

    return {
        "raw": f"IDOR Detector: {len(findings)} findings",
        "intel": {"vulnerabilities": findings, "risk_score": total_risk},
        "signals": signals
    }