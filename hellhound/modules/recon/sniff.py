import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import re
import threading

NAME = "sniff"
CATEGORY = "recon"
DESCRIPTION = "Advanced web attack surface intelligence (Deep crawl, JS analysis, APIs, Auth, Security posture)"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Hellhound Sniff Engine)"
}

SENSITIVE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/",
    "/admin/",
    "/backup/",
    "/config/",
    "/swagger",
]

RISK_KEYWORDS = {
    "id": "IDOR_POTENTIAL",
    "user_id": "IDOR_POTENTIAL",
    "token": "AUTH_BYPASS",
    "password": "AUTH_SURFACE",
    "file": "FILE_UPLOAD",
    "cmd": "COMMAND_INJECTION",
    "search": "SQLI_POTENTIAL",
}


# -------------------------------------------------
# Core Engine
# -------------------------------------------------

class SniffEngine:

    def __init__(self, base_url, emit, depth=3):
        self.base_url = self.normalize_url(base_url)
        self.base_domain = urlparse(self.base_url).netloc
        self.emit = emit
        self.max_depth = depth

        self.session = requests.Session()
        self.session.headers.update(HEADERS)

        self.visited = set()
        self.queue = deque([(self.base_url, 0)])

        self.lock = threading.Lock()

        self.intel = {
            "endpoints": [],
            "js_files": [],
            "api_endpoints": [],
            "auth_surfaces": [],
            "security_headers": {},
            "sensitive_paths": [],
            "tech_stack": [],
            "signals": [],
            "stats": {"get": 0, "post": 0, "total": 0}
        }

    # -------------------------
    # Utilities
    # -------------------------

    def normalize_url(self, url):
        if not url.startswith("http"):
            return "http://" + url
        return url.rstrip("/")

    def in_scope(self, url):
        return urlparse(url).netloc == self.base_domain

    def classify_risks(self, params):
        risks = []
        for p in params:
            name = p["name"].lower()
            if name in RISK_KEYWORDS:
                risks.append(RISK_KEYWORDS[name])
        return list(set(risks))

    # -------------------------
    # Crawl Logic
    # -------------------------

    def crawl(self):
        while self.queue:
            url, depth = self.queue.popleft()

            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)

            try:
                r = self.session.get(url, timeout=5)
            except Exception:
                continue

            self.analyze_headers(r)
            self.detect_tech(r)
            self.parse_html(r.text, url, depth)

    # -------------------------
    # HTML Parsing
    # -------------------------

    def parse_html(self, html, base_url, depth):
        soup = BeautifulSoup(html, "html.parser")

        # Links
        for tag in soup.find_all("a", href=True):
            link = urljoin(base_url, tag["href"])
            if self.in_scope(link):
                self.queue.append((link, depth + 1))

        # Forms
        for form in soup.find_all("form"):
            self.process_form(form, base_url)

        # JS Files
        for script in soup.find_all("script", src=True):
            js_url = urljoin(base_url, script["src"])
            if self.in_scope(js_url):
                self.intel["js_files"].append(js_url)
                self.analyze_js(js_url)

    # -------------------------
    # Form Processing
    # -------------------------

    def process_form(self, form, base_url):
        action = form.get("action")
        method = form.get("method", "POST").upper()

        if not action:
            return

        full_url = urljoin(base_url, action)

        params = []
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                params.append({
                    "name": name,
                    "type": inp.get("type", "text")
                })

        risks = self.classify_risks(params)

        endpoint = {
            "method": method,
            "url": full_url,
            "params": params,
            "risks": risks,
            "tags": ["FORM"]
        }

        if "password" in [p["name"].lower() for p in params]:
            self.intel["auth_surfaces"].append(full_url)
            self.intel["signals"].append("AUTH_SURFACE_DETECTED")

        self.intel["endpoints"].append(endpoint)

        if method == "GET":
            self.intel["stats"]["get"] += 1
        else:
            self.intel["stats"]["post"] += 1

        self.intel["stats"]["total"] += 1

    # -------------------------
    # JS Analysis
    # -------------------------

    def analyze_js(self, js_url):
        try:
            r = self.session.get(js_url, timeout=5)
            content = r.text
        except:
            return

        # Extract API patterns
        api_matches = re.findall(r"/api/[A-Za-z0-9/_\-]+", content)
        for api in api_matches:
            if api not in self.intel["api_endpoints"]:
                self.intel["api_endpoints"].append(api)

        # Detect JWT
        if re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", content):
            self.intel["signals"].append("JWT_DETECTED")

    # -------------------------
    # Security Headers
    # -------------------------

    def analyze_headers(self, response):
        headers = response.headers

        important = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]

        for h in important:
            if h not in headers:
                self.intel["signals"].append(f"MISSING_{h.upper()}")

        self.intel["security_headers"] = dict(headers)

    # -------------------------
    # Technology Detection
    # -------------------------

    def detect_tech(self, response):
        server = response.headers.get("Server", "")
        x_powered = response.headers.get("X-Powered-By", "")

        if "php" in x_powered.lower():
            self.intel["tech_stack"].append("PHP")
        if "express" in x_powered.lower():
            self.intel["tech_stack"].append("Node/Express")
        if "django" in server.lower():
            self.intel["tech_stack"].append("Django")

    # -------------------------
    # Sensitive Path Probing
    # -------------------------

    def probe_sensitive(self):
        for path in SENSITIVE_PATHS:
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    self.intel["sensitive_paths"].append(url)
                    self.intel["signals"].append("SENSITIVE_PATH_EXPOSED")
            except:
                continue

    # -------------------------
    # Run
    # -------------------------

    def run(self):
        self.emit("[*] Deep Sniff initiated...")
        self.crawl()
        self.probe_sensitive()

        self.intel["signals"] = list(set(self.intel["signals"]))
        self.intel["tech_stack"] = list(set(self.intel["tech_stack"]))

        raw_summary = (
            f"GET: {self.intel['stats']['get']} | "
            f"POST: {self.intel['stats']['post']} | "
            f"TOTAL: {self.intel['stats']['total']}"
        )

        return {
            "raw": raw_summary,
            "intel": self.intel
        }


# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):

    emit(f"[*] Sniffing attack surface: {target}")

    depth = 3
    if options and options.get("mode") == "deep":
        depth = 5

    engine = SniffEngine(target, emit, depth=depth)
    result = engine.run()

    emit("[✓] Deep Sniff complete.")
    emit(f"[+] {result['raw']}")

    return result
