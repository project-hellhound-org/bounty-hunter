import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import re
import threading
import time

NAME = "spider"
CATEGORY = "recon"
DESCRIPTION = "Advanced multi-threaded web intelligence crawler (Endpoints, JS APIs, Secrets, Auth, Tech stack, Security posture)"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Hellhound Spider v3.0)"
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
    "/api/docs",
    "/console"
]

RISK_KEYWORDS = {
    "id": "IDOR_POTENTIAL",
    "user_id": "IDOR_POTENTIAL",
    "token": "AUTH_BYPASS",
    "password": "AUTH_SURFACE",
    "file": "FILE_UPLOAD",
    "cmd": "COMMAND_INJECTION",
    "search": "SQLI_POTENTIAL",
    "redirect": "OPEN_REDIRECT"
}


# =================================================
# Spider Engine
# =================================================

class SpiderEngine:

    def __init__(self, base_url, emit, depth=3, threads=8):
        self.base_url = self.normalize(base_url)
        self.base_domain = urlparse(self.base_url).netloc
        self.emit = emit
        self.max_depth = depth
        self.max_threads = threads

        self.session = requests.Session()
        self.session.headers.update(HEADERS)

        self.queue = deque([(self.base_url, 0)])
        self.visited = set()
        self.lock = threading.Lock()
        self.running = True

        self.intel = {
            "endpoints": [],
            "js_files": [],
            "api_endpoints": [],
            "auth_surfaces": [],
            "security_headers": {},
            "sensitive_paths": [],
            "tech_stack": [],
            "secrets": [],
            "signals": [],
            "stats": {"get": 0, "post": 0, "total": 0, "links": 0}
        }

    # =================================================
    # Utilities
    # =================================================

    def normalize(self, url):
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

    # =================================================
    # Worker
    # =================================================

    def worker(self):
        while self.running:
            try:
                url, depth = self.queue.popleft()
            except IndexError:
                time.sleep(0.1)
                continue

            with self.lock:
                if url in self.visited or depth > self.max_depth:
                    continue
                self.visited.add(url)
                self.intel["stats"]["links"] += 1

            try:
                r = self.session.get(url, timeout=6)
            except:
                continue

            content_type = r.headers.get("Content-Type", "")

            if "text/html" in content_type:
                self.analyze_headers(r)
                self.detect_tech(r)
                self.parse_html(r.text, url, depth)
            elif "javascript" in content_type or url.endswith(".js"):
                self.analyze_js(r.text, url)

    # =================================================
    # HTML Parsing
    # =================================================

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

        # Query endpoints
        parsed = urlparse(base_url)
        if parsed.query:
            params = [{"name": k, "type": "query"} for k in parse_qs(parsed.query)]
            risks = self.classify_risks(params)

            self.add_endpoint("GET", base_url, params, risks, ["QUERY"])

        # JS Files
        for script in soup.find_all("script", src=True):
            js_url = urljoin(base_url, script["src"])
            if self.in_scope(js_url):
                with self.lock:
                    if js_url not in self.intel["js_files"]:
                        self.intel["js_files"].append(js_url)
                self.queue.append((js_url, depth + 1))

    # =================================================
    # Endpoint Handling
    # =================================================

    def add_endpoint(self, method, url, params, risks, tags):
        endpoint = {
            "method": method,
            "url": url,
            "params": params,
            "risks": risks,
            "tags": tags
        }

        with self.lock:
            if endpoint not in self.intel["endpoints"]:
                self.intel["endpoints"].append(endpoint)
                if method == "GET":
                    self.intel["stats"]["get"] += 1
                else:
                    self.intel["stats"]["post"] += 1
                self.intel["stats"]["total"] += 1

    def process_form(self, form, base_url):
        action = form.get("action")
        method = form.get("method", "POST").upper()

        if not action:
            return

        full_url = urljoin(base_url, action)

        params = []
        for inp in form.find_all(["input", "textarea"]):
            name = inp.get("name")
            if name:
                params.append({
                    "name": name,
                    "type": inp.get("type", "text")
                })

        risks = self.classify_risks(params)

        if any(p["name"].lower() == "password" for p in params):
            with self.lock:
                self.intel["auth_surfaces"].append(full_url)
                self.intel["signals"].append("AUTH_SURFACE_DETECTED")

        self.add_endpoint(method, full_url, params, risks, ["FORM"])

    # =================================================
    # JS Analysis
    # =================================================

    def analyze_js(self, content, source_url):

        # API discovery
        api_matches = re.findall(r"/api/[A-Za-z0-9/_\-]+", content)
        for api in api_matches:
            with self.lock:
                if api not in self.intel["api_endpoints"]:
                    self.intel["api_endpoints"].append(api)

        # JWT detection
        if re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", content):
            self.intel["signals"].append("JWT_DETECTED")

        # API key leakage detection
        if re.search(r"(?i)(api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9]{20,}", content):
            self.intel["signals"].append("POTENTIAL_API_KEY_LEAK")

    # =================================================
    # Headers & Tech
    # =================================================

    def analyze_headers(self, response):
        important = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]

        headers = response.headers

        with self.lock:
            self.intel["security_headers"] = dict(headers)

            for h in important:
                if h not in headers:
                    self.intel["signals"].append(f"MISSING_{h.upper().replace('-', '_')}")

    def detect_tech(self, response):
        server = response.headers.get("Server", "").lower()
        x_powered = response.headers.get("X-Powered-By", "").lower()

        tech = []

        if "php" in x_powered:
            tech.append("PHP")
        if "express" in x_powered:
            tech.append("Node/Express")
        if "django" in server:
            tech.append("Django")
        if "nginx" in server:
            tech.append("Nginx")

        with self.lock:
            self.intel["tech_stack"].extend(tech)

    # =================================================
    # Sensitive Paths
    # =================================================

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

    # =================================================
    # Run
    # =================================================

    def run(self):
        self.emit.info(f"Spider initialized ({self.max_threads} threads)")

        self.probe_sensitive()

        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        while True:
            time.sleep(1)
            if not self.queue:
                time.sleep(2)
                if not self.queue:
                    self.running = False
                    break

        for t in threads:
            t.join()

        self.intel["signals"] = list(set(self.intel["signals"]))
        self.intel["tech_stack"] = list(set(self.intel["tech_stack"]))

        raw_summary = (
            f"GET: {self.intel['stats']['get']} | "
            f"POST: {self.intel['stats']['post']} | "
            f"TOTAL: {self.intel['stats']['total']} | "
            f"LINKS: {self.intel['stats']['links']}"
        )

        return {
            "raw": raw_summary,
            "intel": self.intel
        }


# =================================================
# Framework Entry Point
# =================================================

def run(target, emit, options=None):

    emit.info(f"Spider crawling target: {target}")

    depth = 3
    threads = 8

    if options:
        if options.get("mode") == "deep":
            depth = 5
        if options.get("threads"):
            threads = int(options.get("threads"))

    engine = SpiderEngine(target, emit, depth=depth, threads=threads)
    result = engine.run()

    emit.success("Spider crawl complete.")
    emit.success(result["raw"])

    return result
