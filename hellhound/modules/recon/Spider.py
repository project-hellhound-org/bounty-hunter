import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import re
import threading
import time
from colorama import Fore
import hashlib
from .utils.js_extractor import JSExtractor

NAME = "spider"
CATEGORY = "recon"
DESCRIPTION = "Advanced SPA-aware intelligent crawler"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Hellhound Spider v6.9)"
}

RISK_KEYWORDS = {
    "cmd": "COMMAND_INJECTION", "exec": "COMMAND_INJECTION", "system": "COMMAND_INJECTION", 
    "shell": "COMMAND_INJECTION", "bash": "COMMAND_INJECTION",
    # SPECIFIC FIX: Explicitly map host/ip/ping to Command Injection
    "ip": "COMMAND_INJECTION", 
    "host": "COMMAND_INJECTION", 
    "target": "COMMAND_INJECTION", 
    "ping": "COMMAND_INJECTION", 
    "traceroute": "COMMAND_INJECTION",
    "file": "FILE_OPERATION", "path": "FILE_OPERATION", "page": "LFI_RFI_POTENTIAL", 
    "document": "LFI_RFI_POTENTIAL", "root": "LFI_RFI_POTENTIAL",
    "id": "IDOR_POTENTIAL", "user": "IDOR_POTENTIAL", "uid": "IDOR_POTENTIAL", 
    "account": "IDOR_POTENTIAL",
    "token": "AUTH_BYPASS", "password": "AUTH_SURFACE", "pass": "AUTH_SURFACE", 
    "login": "AUTH_SURFACE", "auth": "AUTH_SURFACE",
    "redirect": "OPEN_REDIRECT", "url": "OPEN_REDIRECT", "next": "OPEN_REDIRECT", 
    "return": "OPEN_REDIRECT",
    "search": "SQLI_POTENTIAL", "query": "SQLI_POTENTIAL", "select": "SQLI_POTENTIAL", 
    "where": "SQLI_POTENTIAL",
}

# Comprehensive Junk Filter to clean up loot
JUNK_KEYWORDS = [
    # Licensing
    'copyright', 'license', 'mit license', 'apache license', 'bsd license', 'gpl',
    # Libraries/Frameworks
    'jquery', 'bootstrap', 'foundation', 'react', 'angular', 'vue', 'lodash', 'underscore',
    # Documentation & Support (Common noise)
    'developer.mozilla.org', 'developers.google.com', 'docs', 'documentation', 
    'support.google.com', 'stackoverflow.com', 'w3.org', 'w3schools',
    # Google & Tracking specific
    'google.com', 'googleapis.com', 'gstatic.com', 'googletagmanager.com', 
    'google-analytics.com', 'googleadservices.com', 'analytics', 'tracking',
    'tag manager', 'noscript', 'doubleclick', 'adwords',
    # UI & Styling (Generic comments)
    'component', 'style', 'button', 'hamburger', 'menu', 'search (hide', 
    'width', 'height', 'mobile', 'desktop', 'responsive', 'container',
    # Code Logic Noise
    'function(', 'return ', 'var ', 'let ', 'const ', '=>', '=> {', 'if (',
    'else {', 'catch(e)', 'console.log', 'window.', 'document.',
    # Conditional Comments (IE)
    '[if lte', 'ie 9', 'ie 8', 'ie 7',
    # Other
    'todo: surface', 'determine the', 'appropriate'
]

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
        self.content_hashes = set()
        self.js_hashes = set()
        self.extractor = JSExtractor()

        self.session = requests.Session()
        self.session.headers.update(HEADERS)

        self.queue = deque([(self.base_url, 0)])
        self.visited = set()
        self.lock = threading.Lock()
        self.running = True

        self.login_detected = False

        self.intel = {
            "endpoints": [],
            "api_endpoints": [],
            "js_files": [],
            "js_endpoints": [],
            "auth_surfaces": [],
            "security_headers": {},
            "tech_stack": [],
            "comments": [],
            "potential_keys": [],
            "robots_disallowed": [],
            "robots_raw": "",
            "signals": [],
            "graphql": [],
            "js_parameters": [],
            "stats": {
                "get": 0, "post": 0, "total": 0, "links": 0, "js_files": 0
            }
        }

    def normalize(self, url):
        if not url.startswith("http"):
            return "http://" + url
        return url.rstrip("/")

    def in_scope(self, url):
        parsed = urlparse(url)
        return not parsed.netloc or parsed.netloc == self.base_domain

    def is_junk(self, text):
        """Check if text looks like noise"""
        t = text.lower()
        if any(k in t for k in JUNK_KEYWORDS):
            return True
        # Filter out pure URLs
        if t.startswith("http://") or t.startswith("https://"):
            return True
        return False

    def is_code_like(self, text):
        """Check if comment is actually just leftover code logic"""
        # If it has operators and braces, it's likely code
        indicators = ['||', '&&', '=>', 'function', 'return ', 'catch', 'throw']
        t_lower = text.lower()
        if any(i in t_lower for i in indicators):
            # Allow if it has a specific interesting keyword mixed in
            interesting = ['flag', 'secret', 'admin', 'password', 'todo', 'bug']
            if any(k in t_lower for k in interesting):
                return False
            return True
        return False

    def classify_risks(self, params):
        risks = []
        for p in params:
            name = p["name"].lower()
            if name in RISK_KEYWORDS:
                risks.append(RISK_KEYWORDS[name])
                continue
            for key in RISK_KEYWORDS:
                if key in name:
                    risks.append(RISK_KEYWORDS[key])
                    break
        return list(set(risks))

    def calculate_priority(self, risks):
        score = 1
        if "COMMAND_INJECTION" in risks: score += 5
        if "SYSTEM_INTERACTION" in risks: score += 4
        if "SQLI_POTENTIAL" in risks: score += 3
        if "IDOR_POTENTIAL" in risks: score += 2
        return score

    def check_robots_txt(self):
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            self.emit.info(f"Checking for robots.txt at {robots_url}")
            r = self.session.get(robots_url, timeout=5)
            
            if r.status_code == 200:
                with self.lock:
                    self.intel["robots_raw"] = r.text

                disallows = []
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallows.append(path)
                
                if disallows:
                    with self.lock:
                        self.intel["robots_disallowed"] = disallows
                    
                    self.emit.success(f"Found {len(disallows)} disallowed entries in robots.txt")
                    self.emit.warn("Adding disallowed paths to crawl queue...")
                    for path in disallows:
                        target_url = urljoin(self.base_url, path)
                        if self.in_scope(target_url):
                            self.queue.append((target_url, 1))
                else:
                    self.emit.info("robots.txt found but no disallow rules present.")
            else:
                self.emit.info("robots.txt not found (Status: {0})".format(r.status_code))
        except Exception as e:
            pass

    def attempt_login(self, login_url):
        try:
            r = self.session.get(login_url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            form = soup.find("form")
            if not form: return False
            
            target = urljoin(login_url, form.get("action", ""))
            method = form.get("method", "POST").upper()
            data = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    data[name] = "admin" if "user" in name.lower() else ("password" if "pass" in name.lower() else inp.get("value", ""))
            
            if method == "POST": self.session.post(target, data=data, timeout=5)
            else: self.session.get(target, params=data, timeout=5)
            return True
        except: return False

    def worker(self):
        while self.running:
            try:
                url, depth = self.queue.popleft()
            except IndexError:
                time.sleep(0.05)
                continue

            url = self.normalize(url)
            with self.lock:
                if url in self.visited or depth > self.max_depth: continue
                self.visited.add(url)
                self.intel["stats"]["links"] += 1

            try:
                r = self.session.get(url, timeout=8)

                # Ignore obvious failures
                if r.status_code >= 400:
                    continue

                if "not found" in r.text.lower() and r.status_code == 200:
                    continue

            except: continue

            content_type = r.headers.get("Content-Type", "").lower()
            content_hash = hashlib.md5(r.text.encode()).hexdigest()

            with self.lock:
                if content_hash in self.content_hashes:
                    return
                self.content_hashes.add(content_hash)


            if "text/html" in content_type:
                self.analyze_headers(r)
                self.detect_tech(r)
                self.parse_html(r.text, url, depth)
            
            elif "javascript" in content_type or url.endswith(".js"):
                with self.lock:
                    self.intel["stats"]["js_files"] += 1
                    if url not in self.intel["js_files"]:
                        self.intel["js_files"].append(url)

                content_hash = hashlib.md5(r.text.encode()).hexdigest()

                with self.lock:
                    if content_hash in self.js_hashes:
                        continue
                    self.js_hashes.add(content_hash)

                # === NEW SPA EXTRACTION LOGIC ===
                extracted = self.extractor.extract(r.text)

                with self.lock:
                    # 1. Handle Rich Routes (Dictionaries)
                    for route_data in extracted.get("routes", []):
                        # route_data is now a dict: {'path': '/api/user', 'method': 'POST', ...}
                        route_path = route_data.get("path")
                        
                        if route_path and route_path not in self.intel["js_endpoints"]:
                            # Store the full rich data if you want, or just the path
                            self.intel["js_endpoints"].append(route_path)
                            
                            # Optional: Log the method found
                            # self.emit.success(f"Found {route_data.get('method')} endpoint: {route_path}")

                    # 2. Handle other data (Lists of strings)
                    for gql in extracted.get("graphql", []):
                        if "graphql" not in self.intel: self.intel["graphql"] = []
                        if gql not in self.intel["graphql"]: self.intel["graphql"].append(gql)

                    # 3. Handle Parameters (Filtered for quality)
                    for param in extracted.get("parameters", []):
                        if "js_parameters" not in self.intel: self.intel["js_parameters"] = []
                        if param not in self.intel["js_parameters"]: self.intel["js_parameters"].append(param)
                    
                    # 4. Handle Body Params (Crucial for NoSQLi)
                    for param in extracted.get("body_params", []): # Note: check if your extractor returns this key or if it's inside routes
                         # The provided extractor puts params inside the route dict, 
                         # but if you want a global list, you might need to aggregate them.
                         pass 

                # Optional surface expansion
                for route_data in extracted.get("routes", []):
                    route_path = route_data.get("path")
                    if route_path:
                        full = urljoin(self.base_url, route_path)
                        if self.in_scope(full):
                            self.queue.append((full, depth + 1))


    def parse_html(self, html, base_url, depth):
        soup = BeautifulSoup(html, "html.parser")

        if soup.find("input", {"type": "password"}): self.login_detected = True

        self.extract_get_params(base_url)
        self.extract_comments(soup) 

        for tag in soup.find_all("a", href=True):
            link = urljoin(base_url, tag["href"])
            if self.in_scope(link): self.queue.append((link, depth + 1))

        for script in soup.find_all("script", src=True):
            js_link = urljoin(base_url, script["src"])
            if self.in_scope(js_link): 
                self.queue.append((js_link, depth + 1))
            if script.string: self.analyze_js(script.string)

        for form in soup.find_all("form"): self.process_form(form, base_url)
        
        for iframe in soup.find_all("iframe", src=True):
            link = urljoin(base_url, iframe["src"])
            if self.in_scope(link): self.queue.append((link, depth + 1))

    def extract_comments(self, soup):
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        keywords = ['todo', 'fixme', 'bug', 'admin', 'hidden', 'secret', 'key', 'debug', 'pass', 
                    'flag', 'hint', 'ctf', 'config', 'env', 'stage', 'dev', 'backup', 'old', 'note']
        
        for c in comments:
            c_text = c.strip()
            if not c_text or len(c_text) < 3: continue
            
            if self.is_junk(c_text): continue

            if any(k in c_text.lower() for k in keywords):
                self.save_comment(f"[HTML] {c_text}")
                continue

            if re.search(r'^[/\.][a-z0-9_\-\.#]{3,}', c_text):
                self.save_comment(f"[HTML Path] {c_text}")
                continue
            
            # Heuristic: Long comments that aren't junk
            if len(c_text) > 25:
                self.save_comment(f"[HTML Suspicious] {c_text}")

    def extract_script_comments(self, soup):
        for script in soup.find_all("script"):
            if script.string:
                content = script.string
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith("//"):
                        self.check_js_comment(line[2:].strip())
                blocks = re.findall(r'/\*(.*?)\*/', content, re.DOTALL)
                for block in blocks:
                    self.check_js_comment(block.strip())

    def check_js_comment(self, text):
        if not text or len(text) < 3: return
        if self.is_junk(text): return
        if self.is_code_like(text): return

        keywords = ['todo', 'fixme', 'bug', 'admin', 'hidden', 'secret', 'key', 'debug', 'pass', 
                    'flag', 'hint', 'ctf', 'config', 'api', 'token']
        
        if any(k in text.lower() for k in keywords):
            self.save_comment(f"[JS] {text}")
        elif re.search(r'^[/\.][a-z0-9_\-\.#]{3,}', text):
            self.save_comment(f"[JS Path] {text}")

    def save_comment(self, text):
        with self.lock:
            if text not in self.intel["comments"]:
                self.intel["comments"].append(text)

    def parse_js_content(self, content, source_url):
        self.analyze_js(content)
        self.scan_text_for_urls(content)
        self.extract_comments_from_raw_js(content)

    def extract_comments_from_raw_js(self, content):
        for line in content.split('\n'):
            if '//' in line:
                parts = line.split('//')
                if len(parts) > 1:
                    self.check_js_comment(parts[1].strip())
        blocks = re.findall(r'/\*(.*?)\*/', content, re.DOTALL)
        for block in blocks:
            self.check_js_comment(block.strip())

    def analyze_js(self, content):
        api_matches = re.findall(r'["\']([/][A-Za-z0-9_\-\.\/]+(?:api|v1|v2|graphql|rest|admin|login|user)[A-Za-z0-9_\-\.\/]*)["\']', content, re.IGNORECASE)
        
        with self.lock:
            for match in api_matches:
                if match not in self.intel["js_endpoints"] and len(match) > 3:
                    self.intel["js_endpoints"].append(match)

        ips = re.findall(r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', content)
        if ips: self.emit.warn(f"Internal IP found in JS: {ips[0]}")

        keys = re.findall(r'["\']([A-Za-z0-9_\-]{20,})["\']', content)
        for key in keys:
            if len(key) > 25 and key.isalnum() and not key.startswith("http"):
                 with self.lock:
                    if key not in self.intel["potential_keys"]:
                        self.intel["potential_keys"].append(key)
            if "flag" in key.lower() or key.startswith("CTF"):
                 with self.lock:
                    if key not in self.intel["comments"]:
                        self.intel["comments"].append(f"[JS Potential Flag] {key}")

    def scan_text_for_urls(self, text):
        urls = re.findall(r'https?://[^\s<>"\'(){}|\\\^`[\]]+', text)
        for url in urls:
            clean_url = url.rstrip('.,;!?)\'"')
            if self.in_scope(clean_url):
                clean_url = self.normalize(clean_url)
                with self.lock:
                    if clean_url not in self.visited:
                        self.queue.append((clean_url, self.max_depth))

    def extract_get_params(self, url):
        parsed = urlparse(url)
        if not parsed.query: return
        params = [{"name": k, "type": "query"} for k in parse_qs(parsed.query)]
        risks = self.classify_risks(params)
        priority = self.calculate_priority(risks)
        normalized_url = parsed.scheme + "://" + parsed.netloc + parsed.path
        endpoint = {"method": "GET", "url": normalized_url, "params": params, "risks": risks, "priority": priority, "tags": ["GET_PARAM"]}
        with self.lock:
            if endpoint not in self.intel["endpoints"]:
                self.intel["endpoints"].append(endpoint)
                self.intel["stats"]["get"] += 1
                self.intel["stats"]["total"] += 1
                if risks: self.intel["signals"].append("HIGH_RISK_PARAMETERS_DETECTED")

    def process_form(self, form, base_url):
        action = form.get("action")
        method = form.get("method", "POST").upper()
        
        if not action: 
            action = base_url
        else:
            action = urljoin(base_url, action)

        params = []
        for inp in form.find_all(["input", "textarea", "button"]):
            name = inp.get("name")
            if name: params.append({"name": name, "type": inp.get("type", "text")})
        
        risks = self.classify_risks(params)
        priority = self.calculate_priority(risks)
        
        if any(p["name"].lower() in ["password", "pass", "pwd"] for p in params):
            self.intel["auth_surfaces"].append(action)
            self.intel["signals"].append("AUTH_SURFACE_DETECTED")

        endpoint = {"method": method, "url": action, "params": params, "risks": risks, "priority": priority, "tags": ["FORM"]}
        with self.lock:
            if endpoint not in self.intel["endpoints"]:
                self.intel["endpoints"].append(endpoint)
                if method == "GET": self.intel["stats"]["get"] += 1
                else: self.intel["stats"]["post"] += 1
                self.intel["stats"]["total"] += 1
                if risks: self.intel["signals"].append("HIGH_RISK_PARAMETERS_DETECTED")

    def analyze_headers(self, response):
        headers = response.headers
        self.intel["security_headers"] = dict(headers)
        important = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]
        for h in important:
            if h not in headers: self.intel["signals"].append(f"MISSING_{h.upper().replace('-', '_')}")

    def detect_tech(self, response):
        server = response.headers.get("Server", "").lower()
        x_powered = response.headers.get("X-Powered-By", "").lower()
        if "php" in x_powered: self.intel["tech_stack"].append("PHP")
        if "express" in x_powered: self.intel["tech_stack"].append("Node/Express")
        if "django" in server: self.intel["tech_stack"].append("Django")
        if "nginx" in server: self.intel["tech_stack"].append("Nginx")
        if "cloudflare" in server: self.intel["tech_stack"].append("Cloudflare")

    def run(self):
        if "signals" not in self.intel: self.intel["signals"] = []
        if self.auth_enabled: self.attempt_login(self.base_url)
        self.emit.info(f"Spider initialized...")
        self.emit.info("Extracting Comments...")
        self.check_robots_txt()
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
        
        for t in threads: t.join()
        if self.login_detected and not self.auth_enabled and self.intel["stats"]["links"] < 5:
            self.intel["signals"].append("LOGIN_WALL_DETECTED")
        
        self.intel["signals"] = list(set(self.intel["signals"]))
        self.intel["tech_stack"] = list(set(self.intel["tech_stack"]))

        raw_summary = (f"GET: {self.intel['stats']['get']} | POST: {self.intel['stats']['post']} | "
                       f"TOTAL: {self.intel['stats']['total']} | LINKS: {self.intel['stats']['links']} | "
                       f"JS_FILES: {self.intel['stats']['js_files']}")
        
        # ======================================================
        # UPDATED RISK CALCULATION LOGIC
        # ======================================================
        risk_score = 0

        # 1. Attack Surface Risk (Hidden Routes)
        # We combine JS Endpoints, GraphQL endpoints, and Robots.txt disallowed paths.
        # We add 1 point for every 3 hidden routes found.
        hidden_routes_count = (
            len(self.intel.get("js_endpoints", [])) +
            len(self.intel.get("graphql", [])) +
            len(self.intel.get("robots_disallowed", []))
        )
        risk_score += (hidden_routes_count // 3)

        # 2. Information Leakage Risk
        # We add points for potential keys/flags and suspicious developer comments.
        # 1 point for every 2 leaks found.
        intel_leaks = (
            len(self.intel.get("potential_keys", [])) +
            len(self.intel.get("comments", []))
        )
        risk_score += (intel_leaks // 2)

        # 3. Configuration & Vulnerability Risk (Signals)
        # Parse the signals list for specific security issues.
        for signal in self.intel["signals"]:
            signal_upper = signal.upper()
            
            if "AUTH_SURFACE_DETECTED" in signal_upper:
                risk_score += 2
            elif "HIGH_RISK_PARAMETERS_DETECTED" in signal_upper:
                risk_score += 3
            elif "LOGIN_WALL_DETECTED" in signal_upper:
                risk_score += 1
            elif "MISSING_CONTENT_SECURITY_POLICY" in signal_upper:
                risk_score += 2
            elif "MISSING_STRICT_TRANSPORT_SECURITY" in signal_upper:
                risk_score += 2
            elif "MISSING_" in signal_upper:
                # Any other missing security header (X-Frame-Options, etc.)
                risk_score += 1

        self.intel["risk_score"] = risk_score

        return {"raw": raw_summary, "intel": self.intel}


# =================================================
# Framework Entry
# =================================================

def run(target, emit, options=None):
    emit.info(f"Spider crawling target: {target}")
    depth = 3
    threads = 8
    auth = False
    if options:
        if options.get("mode") == "deep": depth = 5
        if options.get("threads"): threads = int(options.get("threads"))
        if options.get("auth"): auth = True
    engine = SpiderEngine(target, emit, depth=depth, threads=threads, auth=auth)
    result = engine.run()
    emit.success("Spider crawl complete.")
    emit.success(result["raw"])
    return result