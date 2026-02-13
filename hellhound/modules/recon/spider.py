import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import re
import threading
import time

NAME = "spider"
CATEGORY = "recon"
DESCRIPTION = "Advanced intelligent crawler (Deep mapping, GET/POST extraction, JS APIs, Auth detection, Security posture)"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Hellhound Spider v4.0)"
}

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

    def __init__(self, base_url, emit, depth=3, threads=8, auth=False):
        self.base_url = self.normalize(base_url)
        self.base_domain = urlparse(self.base_url).netloc
        self.emit = emit
        self.max_depth = depth
        self.max_threads = threads
        self.auth_enabled = auth

        self.session = requests.Session()
        self.session.headers.update(HEADERS)

        self.queue = deque([(self.base_url, 0)])
        self.visited = set()
        self.lock = threading.Lock()
        self.running = True

        self.login_detected = False

        self.intel = {
            "endpoints": [],
            "js_files": [],
            "api_endpoints": [],
            "auth_surfaces": [],
            "security_headers": {},
            "tech_stack": [],
            "signals": [],
            "stats": {
                "get": 0,
                "post": 0,
                "total": 0,
                "links": 0
            }
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
    # Authentication
    # =================================================

    def attempt_login(self, login_url):
        self.emit.info("Attempting authentication bypass...")

        try:
            r = self.session.get(login_url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")

            form = soup.find("form")
            if not form:
                return False

            action = form.get("action")
            method = form.get("method", "POST").upper()
            target = urljoin(login_url, action)

            data = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue
                if name.lower() == "username":
                    data[name] = "admin"
                elif name.lower() == "password":
                    data[name] = "password"
                else:
                    data[name] = inp.get("value", "")

            if method == "POST":
                self.session.post(target, data=data, timeout=5)
            else:
                self.session.get(target, params=data, timeout=5)

            self.emit.success("Authentication attempt completed.")
            return True

        except:
            return False

    # =================================================
    # Worker Thread
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
                self.analyze_js(r.text)

    # =================================================
    # HTML Parsing
    # =================================================

    def parse_html(self, html, base_url, depth):
        soup = BeautifulSoup(html, "html.parser")

        # Detect login form
        if soup.find("input", {"type": "password"}):
            self.login_detected = True

        # Extract links
        for tag in soup.find_all("a", href=True):
            link = urljoin(base_url, tag["href"])
            if self.in_scope(link):
                self.queue.append((link, depth + 1))
                self.extract_get_params(link)

        # Extract forms
        for form in soup.find_all("form"):
            self.process_form(form, base_url)

        # Inline JS
        for script in soup.find_all("script"):
            if script.string:
                self.analyze_js(script.string)

    # =================================================
    # GET Parameter Extraction
    # =================================================

    def extract_get_params(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = [{"name": k, "type": "query"} for k in parse_qs(parsed.query)]
        risks = self.classify_risks(params)

        endpoint = {
            "method": "GET",
            "url": url,
            "params": params,
            "risks": risks,
            "tags": ["GET_PARAM"]
        }

        with self.lock:
            if endpoint not in self.intel["endpoints"]:
                self.intel["endpoints"].append(endpoint)
                self.intel["stats"]["get"] += 1
                self.intel["stats"]["total"] += 1

    # =================================================
    # Form Handling
    # =================================================

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
            self.intel["auth_surfaces"].append(full_url)
            self.intel["signals"].append("AUTH_SURFACE_DETECTED")

        endpoint = {
            "method": method,
            "url": full_url,
            "params": params,
            "risks": risks,
            "tags": ["FORM"]
        }

        with self.lock:
            if endpoint not in self.intel["endpoints"]:
                self.intel["endpoints"].append(endpoint)
                if method == "GET":
                    self.intel["stats"]["get"] += 1
                else:
                    self.intel["stats"]["post"] += 1
                self.intel["stats"]["total"] += 1

    # =================================================
    # JS Analysis
    # =================================================

    def analyze_js(self, content):

        # API discovery
        api_matches = re.findall(r"(\/api\/[A-Za-z0-9\/_\-]+)", content)
        versioned = re.findall(r"(\/v[0-9]+\/[A-Za-z0-9\/_\-]+)", content)

        for match in api_matches + versioned:
            if match not in self.intel["api_endpoints"]:
                self.intel["api_endpoints"].append(match)

        # Fetch / axios detection
        fetch_calls = re.findall(r"(fetch|axios)\(['\"]([^'\"]+)", content)
        for _, endpoint in fetch_calls:
            if endpoint.startswith("/"):
                self.intel["api_endpoints"].append(endpoint)

        # JWT detection
        if re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", content):
            self.intel["signals"].append("JWT_DETECTED")

    # =================================================
    # Headers & Tech
    # =================================================

    def analyze_headers(self, response):
        headers = response.headers
        self.intel["security_headers"] = dict(headers)

        important = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]

        for h in important:
            if h not in headers:
                self.intel["signals"].append(
                    f"MISSING_{h.upper().replace('-', '_')}"
                )

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

        self.intel["tech_stack"].extend(tech)

    # =================================================
    # Run
    # =================================================

    def run(self):

        if self.auth_enabled:
            self.attempt_login(self.base_url)

        self.emit.info(f"Spider initialized ({self.max_threads} threads)")

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

        # Login wall detection
        if self.login_detected and not self.auth_enabled and self.intel["stats"]["links"] < 3:
            self.intel["signals"].append("LOGIN_WALL_DETECTED")
            self.emit.warn("Authentication wall detected.")
            self.emit.warn("Re-run with: strike spider --auth")

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
# Framework Entry
# =================================================

def run(target, emit, options=None):

    emit.info(f"Spider crawling target: {target}")

    depth = 3
    threads = 8
    auth = False

    if options:
        if options.get("mode") == "deep":
            depth = 5
        if options.get("threads"):
            threads = int(options.get("threads"))
        if options.get("auth"):
            auth = True

    engine = SpiderEngine(target, emit, depth=depth, threads=threads, auth=auth)
    result = engine.run()

    emit.success("Spider crawl complete.")
    emit.success(result["raw"])

    return result
