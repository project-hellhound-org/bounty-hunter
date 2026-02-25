import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from collections import deque
import re
import threading
import time
import hashlib
import heapq
import json
from colorama import Fore, Style
from .utils.js_extractor import JSExtractor

NAME = "spider"
CATEGORY = "recon"
DESCRIPTION = "Advanced SPA-aware intelligent crawler with strict validation & injection prep"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Hellhound Spider v8.0)"
}

RISK_KEYWORDS = {
    "cmd": "COMMAND_INJECTION", "exec": "COMMAND_INJECTION", "system": "COMMAND_INJECTION", 
    "shell": "COMMAND_INJECTION", "bash": "COMMAND_INJECTION",
    "ip": "COMMAND_INJECTION", "host": "COMMAND_INJECTION", "target": "COMMAND_INJECTION", 
    "ping": "COMMAND_INJECTION", "traceroute": "COMMAND_INJECTION",
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

JUNK_KEYWORDS = [
    'copyright', 'license', 'mit license', 'apache license', 'bsd license', 'gpl',
    'jquery', 'bootstrap', 'foundation', 'react', 'angular', 'vue', 'lodash', 'underscore',
    'developer.mozilla.org', 'developers.google.com', 'docs', 'documentation', 
    'support.google.com', 'stackoverflow.com', 'w3.org', 'w3schools',
    'google.com', 'googleapis.com', 'gstatic.com', 'googletagmanager.com', 
    'google-analytics.com', 'googleadservices.com', 'analytics', 'tracking',
    'tag manager', 'noscript', 'doubleclick', 'adwords',
    'component', 'style', 'button', 'hamburger', 'menu', 'search (hide', 
    'width', 'height', 'mobile', 'desktop', 'responsive', 'container',
    'function(', 'return ', 'var ', 'let ', 'const ', '=>', '=> {', 'if (',
    'else {', 'catch(e)', 'console.log', 'window.', 'document.',
    '[if lte', 'ie 9', 'ie 8', 'ie 7',
    'todo: surface', 'determine the', 'appropriate'
]

# =================================================
# Priority Queue Implementation
# =================================================

class PriorityURL:
    """URL wrapper for priority-based crawling"""
    def __init__(self, url, depth, priority_score=1, risk_tags=None):
        self.url = url
        self.depth = depth
        self.priority = priority_score
        self.risk_tags = risk_tags or []
        self.timestamp = time.time()
    
    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority > other.priority
        return self.timestamp < other.timestamp
    
    def __eq__(self, other):
        return self.url == other.url
    
    def __hash__(self):
        return hash(self.url)


# =================================================
# Spider Engine
# =================================================

class SpiderEngine:

    def __init__(self, base_url, emit, depth=3, threads=8, auth=False, options=None):
        # === 1. Basic config ===
        self.base_url = self.normalize(base_url)
        self.base_domain = urlparse(self.base_url).netloc
        self.emit = emit
        self.max_depth = depth
        self.max_threads = threads
        self.auth_enabled = auth
        self.strict_mode = options.get("strict", True) if options else True
        
        # === 2. Thread safety & synchronization (DEFINE EARLY) ===
        self.lock = threading.Lock()
        
        # === 3. Tracking sets (must exist before _enqueue is called) ===
        self.content_hashes = set()
        self.js_hashes = set()
        self.visited = set()
        self._queue_set = set()
        
        # === 4. SPA Shell Fingerprinting ===
        self.spa_shell_hash = None
        self.spa_shell_samples = set()
        
        # === 5. Components ===
        self.extractor = JSExtractor()
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        
        # === 6. Rate limiting ===
        self.request_timestamps = deque(maxlen=100)
        self.min_delay = 0.15
        
        # === 7. Crawl state ===
        self.running = True
        self.login_detected = False
        
        # === 8. Priority queue (now safe to initialize) ===
        self.queue = []
        self._enqueue(self.base_url, 0, priority=10)
        
        # === 9. Intelligence storage - PRIORITY 1: Three Buckets ===
        self.intel = {
            "endpoints": [],
            "raw_js_routes": [],        # ✅ PRIORITY 1: Raw JS routes
            "validated_api": [],        # ✅ PRIORITY 1: Validated APIs only
            "rejected_routes": [],      # ✅ PRIORITY 1: Failed validation
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
            "websocket_endpoints": [],
            "lazy_routes": [],
            "client_routes": [],
            "discovered_fields": [],    # ✅ PRIORITY 2: JSON field extraction
            "id_patterns": [],          # ✅ PRIORITY 2: ID pattern detection
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

    def _enqueue(self, url, depth, priority=1, risk_tags=None):
        """Add URL to priority queue with deduplication"""
        url = self.normalize(url)
        if not self.in_scope(url):
            return
        
        with self.lock:
            if url in self._queue_set or url in self.visited:
                return
            self._queue_set.add(url)
            heapq.heappush(self.queue, PriorityURL(url, depth, priority, risk_tags))

    def _dequeue(self):
        """Get next URL from priority queue"""
        with self.lock:
            while self.queue:
                item = heapq.heappop(self.queue)
                self._queue_set.discard(item.url)
                return item.url, item.depth, item.priority, item.risk_tags
        return None, None, None, None

    def _respect_rate_limit(self):
        """Polite crawling with rate limiting"""
        now = time.time()
        while self.request_timestamps and self.request_timestamps[0] < now - 1:
            self.request_timestamps.popleft()
        
        if len(self.request_timestamps) >= 10:
            time.sleep(0.1)
        
        self.request_timestamps.append(now)
        time.sleep(self.min_delay)

    def is_junk(self, text):
        t = text.lower()
        if any(k in t for k in JUNK_KEYWORDS):
            return True
        if t.startswith("http://") or t.startswith("https://"):
            return True
        return False

    def is_code_like(self, text):
        indicators = ['||', '&&', '=>', 'function', 'return ', 'catch', 'throw']
        t_lower = text.lower()
        if any(i in t_lower for i in indicators):
            interesting = ['flag', 'secret', 'admin', 'password', 'todo', 'bug']
            if any(k in t_lower for k in interesting):
                return False
            return True
        return False

    def classify_risks(self, params):
        risks = []
        param_list = params if isinstance(params, list) else params.get("body", []) + params.get("query", [])
        for p in param_list:
            name = p["name"].lower() if isinstance(p, dict) else p.lower()
            if name in RISK_KEYWORDS:
                risks.append(RISK_KEYWORDS[name])
                continue
            for key in RISK_KEYWORDS:
                if key in name:
                    risks.append(RISK_KEYWORDS[key])
                    break
        return list(set(risks))

    def calculate_priority(self, risks, url=""):
        score = 1
        if "COMMAND_INJECTION" in risks: score += 5
        if "SYSTEM_INTERACTION" in risks: score += 4
        if "SQLI_POTENTIAL" in risks: score += 3
        if "IDOR_POTENTIAL" in risks: score += 2
        if "AUTH_SURFACE" in risks: score += 3
        if "OPEN_REDIRECT" in risks: score += 2
        
        url_lower = url.lower()
        if any(k in url_lower for k in ['admin', 'login', 'auth', 'api', 'graphql']):
            score += 2
        if any(k in url_lower for k in ['debug', 'config', 'env', 'backup']):
            score += 3
            
        return score

    def classify_endpoint_response(self, response_text: str, headers: dict) -> dict:
        """Classify endpoint type for injection agent"""
        classification = {
            "is_api": False,
            "is_spa_shell": False,
            "likely_json": False,
            "interactive": True,
            "response_length": len(response_text)
        }
        
        content_type = headers.get("Content-Type", "").lower()
        
        if re.search(r'<div\s+id=["\']root["\']', response_text, re.I) or \
           re.search(r'<app-root>', response_text, re.I) or \
           re.search(r'<div\s+id=["\']app["\']', response_text, re.I):
            classification["is_spa_shell"] = True
            classification["interactive"] = False
        
        if content_type.startswith("application/json") or \
           (response_text.strip() and response_text.strip()[0] in "{["):
            classification["is_api"] = True
            classification["likely_json"] = True
        
        if len(response_text.strip()) < 150 and not classification["is_api"]:
            classification["interactive"] = False
        
        return classification

    def _extract_json_fields(self, data, fields=None, path=""):
        """
        ✅ PRIORITY 2: Recursively extract field names from JSON response
        """
        if fields is None:
            fields = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                fields.add(key.lower())
                self._extract_json_fields(value, fields, f"{path}.{key}")
        elif isinstance(data, list):
            for item in data:
                self._extract_json_fields(item, fields, path)
        
        return fields

    def _detect_id_patterns(self, data, endpoint_url):
        """
        ✅ PRIORITY 2: Detect ID patterns for IDOR testing
        """
        id_patterns = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = key.lower()
                # Common ID field names
                if any(id_name in key_lower for id_name in ['id', 'uid', 'uuid', 'user_id', 'product_id', 'account_id']):
                    if isinstance(value, (int, str)) and str(value).isdigit():
                        id_patterns.append({
                            "field": key,
                            "value": value,
                            "endpoint": endpoint_url,
                            "test_candidates": [int(value) + i for i in range(-2, 3) if int(value) + i > 0]
                        })
        
        return id_patterns

    def _validate_endpoint_lightweight(self, url: str) -> dict:
        """
        ✅ PRIORITY 1, 2, 3, 8: Comprehensive endpoint validation with injection metadata
        """
        result = {
            "valid": False,
            "status": None,
            "content_type": None,
            "length": 0,
            "is_spa_shell": False,
            "hash": None,
            "discovered_fields": [],
            "id_patterns": [],
            "accepts_json": False,
            "auth_required": False,
            "confidence": 0.0,
            "response_sample": None
        }
        
        try:
            r = self.session.head(url, timeout=3, allow_redirects=True)
            
            if r.status_code in [405, 501]:
                r = self.session.get(url, timeout=5, stream=True)
                content_sample = r.raw.read(4096)
                r.close()
            else:
                content_sample = b""
            
            result["status"] = r.status_code
            result["content_type"] = r.headers.get("Content-Type", "").lower()
            result["length"] = int(r.headers.get("Content-Length", 0))
            
            content_for_hash = content_sample if content_sample else r.text[:2048].encode()
            result["hash"] = hashlib.md5(content_for_hash).hexdigest()
            
            # ✅ PRIORITY 3: SPA Shell Fingerprinting
            if "text/html" in result["content_type"]:
                sample = content_for_hash.decode(errors="ignore").lower()
                if re.search(r'<div\s+id=["\']root["\']', sample) or \
                   re.search(r'<app-root>', sample) or \
                   sample.count("<script") > 5:
                    result["is_spa_shell"] = True
            
            # ✅ PRIORITY 3: Compare against SPA shell fingerprints
            if result["hash"] and self.spa_shell_hash:
                if result["hash"] == self.spa_shell_hash:
                    result["is_spa_shell"] = True
                    result["valid"] = False
                    result["confidence"] = 0.0
            
            if result["hash"] in self.spa_shell_samples:
                result["is_spa_shell"] = True
                result["valid"] = False
                result["confidence"] = 0.0
            
            # ✅ PRIORITY 2: JSON Response Field Extraction
            if result["status"] == 200 and "application/json" in result["content_type"]:
                try:
                    # Re-fetch for full JSON parsing
                    r_full = self.session.get(url, timeout=5)
                    data = r_full.json()
                    
                    result["discovered_fields"] = list(self._extract_json_fields(data))
                    result["id_patterns"] = self._detect_id_patterns(data, url)
                    result["accepts_json"] = True
                    result["confidence"] = 0.95  # ✅ PRIORITY 5: High confidence for JSON APIs
                    
                    # Store discovered fields globally
                    with self.lock:
                        for field in result["discovered_fields"]:
                            if field not in self.intel["discovered_fields"]:
                                self.intel["discovered_fields"].append(field)
                        
                        for id_pattern in result["id_patterns"]:
                            if id_pattern not in self.intel["id_patterns"]:
                                self.intel["id_patterns"].append(id_pattern)
                    
                except Exception:
                    result["confidence"] = 0.7
            elif result["status"] == 200:
                result["confidence"] = 0.6
            elif result["status"] in [401, 403]:
                result["auth_required"] = True
                result["confidence"] = 0.5
            elif result["status"] == 404:
                result["confidence"] = 0.1
            
            # Validation logic
            if result["status"] == 200:
                if "application/json" in result["content_type"]:
                    result["valid"] = True
                elif "text/html" in result["content_type"] and not result["is_spa_shell"]:
                    if result["length"] > 500:
                        result["valid"] = True
                elif result["length"] > 100:
                    result["valid"] = True
            
            # ✅ PRIORITY 8: Store response sample for injection engine
            if content_sample:
                result["response_sample"] = content_sample[:500].decode(errors="ignore")
            elif hasattr(r, 'text'):
                result["response_sample"] = r.text[:500]
            
            return result
            
        except Exception as e:
            self.emit.warn(f"Endpoint validation failed for {url}: {e}")
            return result

    def _normalize_route_for_storage(self, route: str) -> str:
        """
        ✅ PRIORITY 1 & 3: Normalize route before storing
        """
        if not route:
            return None
        
        # Lowercase and strip
        route = route.lower().rstrip("/")
        
        # Remove fragments and query strings
        route = route.split('#')[0].split('?')[0]
        
        # Normalize slashes
        route = re.sub(r'//+', '/', route)
        
        return route if route else None

    def _is_placeholder_route(self, route: str) -> bool:
        """
        ✅ PRIORITY 1: Reject placeholder routes with { }
        """
        if not route:
            return True
        
        # Reject any route with template placeholders
        if "{" in route or "}" in route:
            return True
        
        if re.search(r"/\{.*?\}", route):
            return True
        
        # Must start with /
        if not route.startswith("/"):
            return True
        
        # Must have at least 2 path segments
        if route.count("/") < 2:
            return True
        
        return False

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
                        if path and path != "/":
                            disallows.append(path)
                
                if disallows:
                    with self.lock:
                        self.intel["robots_disallowed"] = disallows
                    
                    self.emit.success(f"Found {len(disallows)} disallowed entries in robots.txt")
                    for path in disallows:
                        target_url = urljoin(self.base_url, path)
                        if self.in_scope(target_url):
                            self._enqueue(target_url, 1, priority=7, risk_tags=["robots_disallowed"])
            else:
                self.emit.info(f"robots.txt not found (Status: {r.status_code})")
        except Exception as e:
            self.emit.warn(f"Error checking robots.txt: {e}")

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
            
            if method == "POST": 
                self.session.post(target, data=data, timeout=5)
            else: 
                self.session.get(target, params=data, timeout=5)
            return True
        except Exception as e:
            self.emit.warn(f"Login attempt failed: {e}")
            return False

    def _add_signal(self, signal):
        """Add signal without duplicates"""
        with self.lock:
            if signal not in self.intel["signals"]:
                self.intel["signals"].append(signal)

    def worker(self):
        while self.running:
            try:
                url, depth, priority, risk_tags = self._dequeue()
                if url is None:
                    time.sleep(0.05)
                    continue
            except IndexError:
                time.sleep(0.05)
                continue

            url = self.normalize(url)
            with self.lock:
                if url in self.visited or depth > self.max_depth: 
                    continue
                self.visited.add(url)
                self.intel["stats"]["links"] += 1

            self._respect_rate_limit()

            try:
                r = self.session.get(url, timeout=8)
                if r.status_code >= 400:
                    continue
                if "not found" in r.text.lower() and r.status_code == 200:
                    continue
            except Exception as e:
                continue

            content_type = r.headers.get("Content-Type", "").lower()
            content_hash = hashlib.md5(r.text.encode()).hexdigest()

            with self.lock:
                if content_hash in self.content_hashes:
                    continue
                self.content_hashes.add(content_hash)

            response_class = self.classify_endpoint_response(r.text, r.headers)

            if "text/html" in content_type:
                self.analyze_headers(r)
                self.detect_tech(r)
                self.parse_html(r.text, url, depth)
                
                endpoint_entry = {
                    "url": url,
                    "method": "GET",
                    "type": "html",
                    "classification": response_class,
                    "tags": ["html_page"]
                }
                with self.lock:
                    if endpoint_entry not in self.intel["api_endpoints"]:
                        self.intel["api_endpoints"].append(endpoint_entry)
            
            elif "javascript" in content_type or url.endswith(".js"):
                with self.lock:
                    self.intel["stats"]["js_files"] += 1
                    if url not in self.intel["js_files"]:
                        self.intel["js_files"].append(url)

                js_content_hash = hashlib.md5(r.text.encode()).hexdigest()
                with self.lock:
                    if js_content_hash in self.js_hashes:
                        continue
                    self.js_hashes.add(js_content_hash)

                extracted = self.extractor.extract(r.text)

                with self.lock:
                    # ✅ PRIORITY 1: Store raw JS routes separately
                    for route_info in extracted.get("routes", []):
                        route = route_info.get("path", "")
                        
                        # ✅ PRIORITY 1: Normalize before storing
                        normalized_route = self._normalize_route_for_storage(route)
                        if not normalized_route:
                            continue
                        
                        # ✅ PRIORITY 1: Reject placeholder routes
                        if self._is_placeholder_route(normalized_route):
                            rejection_entry = {
                                "route": normalized_route,
                                "reason": "placeholder_or_invalid",
                                "source": route_info.get("source", "js")
                            }
                            if rejection_entry not in self.intel["rejected_routes"]:
                                self.intel["rejected_routes"].append(rejection_entry)
                            continue
                        
                        # Store in raw_js_routes
                        raw_entry = {
                            "path": normalized_route,
                            "method": route_info.get("method", "GET"),
                            "params": route_info.get("params", []),
                            "source": route_info.get("source", "js"),
                            "base_url": url,
                            "confidence": 0.5  # ✅ PRIORITY 5: Raw JS = medium confidence
                        }
                        
                        # ✅ PRIORITY 4: Case deduplication
                        exists = any(
                            e["path"].lower() == raw_entry["path"].lower()
                            for e in self.intel["raw_js_routes"]
                        )
                        if not exists:
                            self.intel["raw_js_routes"].append(raw_entry)

                    for gql in extracted.get("graphql", []):
                        if gql not in self.intel.get("graphql", []):
                            if "graphql" not in self.intel:
                                self.intel["graphql"] = []
                            self.intel["graphql"].append(gql)

                    for param in extracted.get("parameters", []):
                        if param not in self.intel.get("js_parameters", []):
                            if "js_parameters" not in self.intel:
                                self.intel["js_parameters"] = []
                            self.intel["js_parameters"].append(param)

                    for key in extracted.get("potential_keys", []):
                        if key not in self.intel["potential_keys"]:
                            self.intel["potential_keys"].append(key)
                    
                    for ws in extracted.get("websocket_endpoints", []):
                        if ws not in self.intel["websocket_endpoints"]:
                            self.intel["websocket_endpoints"].append(ws)
                    
                    for lazy in extracted.get("lazy_routes", []):
                        if lazy not in self.intel["lazy_routes"]:
                            self.intel["lazy_routes"].append(lazy)

                # Queue discovered routes for validation
                for route_info in extracted.get("routes", []):
                    route = route_info["path"]
                    full = urljoin(self.base_url, route)
                    if self.in_scope(full):
                        method = route_info.get("method", "GET")
                        priority_boost = 3 if method in ["POST", "PUT", "DELETE"] else 1
                        self._enqueue(full, depth + 1, priority=priority_boost)

                if ".min.js" not in url:
                    self.parse_js_content(r.text, url)
                else:
                    self.analyze_js(r.text)

            elif response_class["is_api"] or "application/json" in content_type:
                # ✅ PRIORITY 1, 2, 3, 8: Full validation with injection metadata
                validation = self._validate_endpoint_lightweight(url)
                
                # ✅ PRIORITY 1: Store in appropriate bucket
                normalized_url = self._normalize_route_for_storage(urlparse(url).path)
                
                if not validation["valid"] or validation["is_spa_shell"]:
                    with self.lock:
                        rejection_entry = {
                            "route": normalized_url or url,
                            "reason": "validation_failed" if not validation["valid"] else "spa_shell_match",
                            "confidence": validation["confidence"],
                            "status": validation["status"]
                        }
                        if rejection_entry not in self.intel["rejected_routes"]:
                            self.intel["rejected_routes"].append(rejection_entry)
                    continue
                
                # ✅ PRIORITY 8: Store comprehensive injection metadata
                validated_entry = {
                    "url": url,
                    "path": normalized_url,
                    "method": "GET",  # Will be updated from JS routes if available
                    "accepts_json": validation["accepts_json"],
                    "response_size": validation["length"],
                    "contains_ids": len(validation["id_patterns"]) > 0,
                    "auth_required": validation["auth_required"],
                    "confidence": validation["confidence"],  # ✅ PRIORITY 5
                    "discovered_fields": validation["discovered_fields"],  # ✅ PRIORITY 2
                    "id_patterns": validation["id_patterns"],  # ✅ PRIORITY 2
                    "content_type": validation["content_type"],
                    "status_code": validation["status"],
                    "response_hash": validation["hash"],
                    "tags": ["validated_api"]
                }
                
                # ✅ PRIORITY 7: Match with JS routes for accurate method
                with self.lock:
                    for js_route in self.intel["raw_js_routes"]:
                        if js_route["path"] == normalized_url:
                            validated_entry["method"] = js_route["method"]
                            validated_entry["params"] = js_route["params"]
                            validated_entry["source"] = js_route["source"]
                            # Boost confidence if JS confirms method
                            if validated_entry["confidence"] < 0.9:
                                validated_entry["confidence"] = 0.9
                            break
                    
                    # ✅ PRIORITY 1: Only add to validated_api (injection uses this)
                    exists = any(
                        e["url"].lower() == validated_entry["url"].lower()
                        for e in self.intel["validated_api"]
                    )
                    if not exists:
                        self.intel["validated_api"].append(validated_entry)

    def parse_html(self, html, base_url, depth):
        soup = BeautifulSoup(html, "html.parser")

        # ✅ PRIORITY 3: SPA Shell Fingerprinting
        if re.search(r'<div\s+id=["\']root["\']', html, re.I) or \
           re.search(r'<app-root>', html, re.I) or \
           re.search(r'<div[^>]*data-reactroot', html, re.I):
            
            hashes = [
                hashlib.md5(html[:1024].encode()).hexdigest(),
                hashlib.md5(html[:2048].encode()).hexdigest(),
                hashlib.md5(re.sub(r'\s+', ' ', html[:2048]).encode()).hexdigest(),
            ]
            
            with self.lock:
                if not self.spa_shell_hash:
                    self.spa_shell_hash = hashes[0]
                self.spa_shell_samples.update(hashes)
                
                if len(self.spa_shell_samples) == 1:
                    self.emit.info(f"Detected SPA shell pattern (hash: {self.spa_shell_hash[:8]}...)")

        if soup.find("input", {"type": "password"}): 
            self.login_detected = True

        self.extract_get_params(base_url)
        self.extract_comments(soup) 

        for tag in soup.find_all("a", href=True):
            link = urljoin(base_url, tag["href"])
            if self.in_scope(link):
                link_lower = link.lower()
                priority = 2
                if any(k in link_lower for k in ['admin', 'api', 'login', 'auth']):
                    priority = 5
                self._enqueue(link, depth + 1, priority=priority)

        for script in soup.find_all("script", src=True):
            js_link = urljoin(base_url, script["src"])
            if self.in_scope(js_link): 
                self._enqueue(js_link, depth + 1, priority=4)
            if script.string: 
                self.analyze_js(script.string)

        for form in soup.find_all("form"): 
            self.process_form(form, base_url)
        
        for iframe in soup.find_all("iframe", src=True):
            link = urljoin(base_url, iframe["src"])
            if self.in_scope(link): 
                self._enqueue(link, depth + 1, priority=3)

        self.extract_client_routes(soup, base_url)

    def extract_client_routes(self, soup, base_url):
        """Detect client-side routing patterns"""
        content = str(soup)
        
        react_routes = re.findall(r'<Route[^>]+path=["\']([^"\']+)["\']', content, re.I)
        vue_routes = re.findall(r'path\s*:\s*["\']([^"\']+)["\']', content, re.I)
        
        all_routes = react_routes + vue_routes
        for route in all_routes:
            normalized = re.sub(r':([a-zA-Z_][a-zA-Z0-9_]*)', r'{\1}', route)
            # ✅ PRIORITY 1: Skip placeholder routes
            if self._is_placeholder_route(normalized):
                continue
            full_url = urljoin(base_url, normalized)
            if self.in_scope(full_url) and normalized not in [r.get("path") for r in self.intel.get("client_routes", [])]:
                with self.lock:
                    self.intel["client_routes"].append({
                        "path": normalized,
                        "source": "html_router",
                        "framework": "react" if route in react_routes else "vue/angular"
                    })
                self._enqueue(full_url, 1, priority=3, risk_tags=["client_route"])

    def extract_comments(self, soup):
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        keywords = ['todo', 'fixme', 'bug', 'admin', 'hidden', 'secret', 'key', 'debug', 'pass', 
                    'flag', 'hint', 'ctf', 'config', 'env', 'stage', 'dev', 'backup', 'old', 'note']
        
        for c in comments:
            c_text = c.strip()
            if not c_text or len(c_text) < 3: continue
            if self.is_junk(c_text): continue

            score = 0
            c_lower = c_text.lower()
            if c.parent and c.parent.name == "form":
                score += 3
            if any(k in c_lower for k in ["secret", "api_key", "jwt", "password", "token"]):
                score += 5
            if any(k in c_lower for k in keywords):
                score += 2
            
            if score >= 2 or len(c_text) > 50:
                self.save_comment(f"[Score:{score}] [HTML] {c_text}")

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
                parts = line.split('//', 1)
                if len(parts) > 1:
                    self.check_js_comment(parts[1].strip())
        blocks = re.findall(r'/\*(.*?)\*/', content, re.DOTALL)
        for block in blocks:
            self.check_js_comment(block.strip())

    def analyze_js(self, content):
        api_matches = re.findall(r'["\']([/][A-Za-z0-9_\-\.\/]+(?:api|v1|v2|graphql|rest|admin|login|user)[A-Za-z0-9_\-\.\/]*)["\']', content, re.IGNORECASE)
        
        with self.lock:
            for match in api_matches:
                # ✅ PRIORITY 1: Strict validation
                if not self._is_valid_endpoint_simple(match):
                    continue
                if match not in [e["path"] for e in self.intel["js_endpoints"]] and len(match) > 3:
                    self.intel["js_endpoints"].append({
                        "path": match,
                        "method": "GET",
                        "params": [],
                        "source": "regex_fallback"
                    })

        ips = re.findall(r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', content)
        if ips: 
            self.emit.warn(f"Internal IP found in JS: {ips[0]}")

        keys = re.findall(r'["\']([A-Za-z0-9_\-]{20,})["\']', content)
        for key in keys:
            if len(key) > 25 and key.isalnum() and not key.startswith("http"):
                 with self.lock:
                    if key not in self.intel["potential_keys"]:
                        self.intel["potential_keys"].append(key)
            if "flag" in key.lower() or key.startswith("CTF"):
                 with self.lock:
                    entry = f"[JS Potential Flag] {key}"
                    if entry not in self.intel["comments"]:
                        self.intel["comments"].append(entry)

        auth_patterns = [
            re.compile(r'Authorization\s*:\s*["\']Bearer\s+([A-Za-z0-9_\-\.]+)["\']', re.I),
            re.compile(r'["\']?(?:api[_-]?key|access[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I)
        ]
        for pattern in auth_patterns:
            for match in pattern.findall(content):
                with self.lock:
                    entry = f"[Hardcoded Auth] {match[:10]}..."
                    if entry not in self.intel["potential_keys"]:
                        self.intel["potential_keys"].append(entry)
                        self._add_signal("HARDCODED_AUTH_TOKEN_DETECTED")

        base_patterns = re.findall(r'(?:const|let|var)\s+([A-Z_]+)\s*=\s*["\'](/api[^"\']*)["\']', content, re.I)
        for var_name, base_path in base_patterns:
            with self.lock:
                if base_path not in self.intel.get("api_bases", []):
                    if "api_bases" not in self.intel:
                        self.intel["api_bases"] = []
                    self.intel["api_bases"].append({"var": var_name, "base": base_path})

    def _is_valid_endpoint_simple(self, route: str) -> bool:
        """Simple endpoint validation for analyze_js"""
        if not route or not route.startswith("/"):
            return False
        segments = [s for s in route.split("/") if s]
        if len(segments) < 2:
            return False
        if re.match(r"^/[a-zA-Z0-9_-]+$", route.split("?")[0]):
            if not any(k in route.lower() for k in ["api", "v1", "v2", "graphql", "rest", "auth", "admin"]):
                return False
        return True

    def scan_text_for_urls(self, text):
        urls = re.findall(r'https?://[^\s<>"\'(){}|\\\^`[\]]+', text)
        for url in urls:
            clean_url = url.rstrip('.,;!?)\'"')
            if self.in_scope(clean_url):
                clean_url = self.normalize(clean_url)
                with self.lock:
                    if clean_url not in self.visited and clean_url not in self._queue_set:
                        self._enqueue(clean_url, self.max_depth, priority=1)

    def extract_get_params(self, url):
        parsed = urlparse(url)
        if not parsed.query: 
            return
        params = [{"name": k, "type": "query"} for k in parse_qs(parsed.query).keys()]
        risks = self.classify_risks(params)
        priority = self.calculate_priority(risks, url)
        normalized_url = parsed.scheme + "://" + parsed.netloc + parsed.path
        endpoint = {
            "method": "GET", 
            "url": normalized_url, 
            "params": {"query": [p["name"] for p in params]}, 
            "risks": risks, 
            "priority": priority, 
            "tags": ["GET_PARAM"]
        }
        with self.lock:
            if endpoint not in self.intel["endpoints"]:
                self.intel["endpoints"].append(endpoint)
                self.intel["stats"]["get"] += 1
                self.intel["stats"]["total"] += 1
                if risks: 
                    self._add_signal("HIGH_RISK_PARAMETERS_DETECTED")

    def process_form(self, form, base_url):
        action = form.get("action")
        method = form.get("method", "POST").upper()
        
        if not action: 
            action = base_url
        else:
            action = urljoin(base_url, action)

        params = {"query": [], "body": [], "path": []}
        for inp in form.find_all(["input", "textarea", "button"]):
            name = inp.get("name")
            inp_type = inp.get("type", "text")
            if name:
                params["body"].append({"name": name, "type": inp_type})
        
        risks = self.classify_risks(params["body"])
        priority = self.calculate_priority(risks, action)
        
        if any(p["name"].lower() in ["password", "pass", "pwd"] for p in params["body"]):
            with self.lock:
                if action not in self.intel["auth_surfaces"]:
                    self.intel["auth_surfaces"].append(action)
                self._add_signal("AUTH_SURFACE_DETECTED")

        endpoint = {
            "method": method, 
            "url": action, 
            "params": params, 
            "risks": risks, 
            "priority": priority, 
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
                if risks: 
                    self._add_signal("HIGH_RISK_PARAMETERS_DETECTED")
        
        if self.in_scope(action):
            self._enqueue(action, 1, priority=priority, risk_tags=risks)

    def analyze_headers(self, response):
        headers = response.headers
        self.intel["security_headers"] = dict(headers)
        important = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]
        for h in important:
            if h not in headers: 
                self._add_signal(f"MISSING_{h.upper().replace('-', '_')}")

    def detect_tech(self, response):
        server = response.headers.get("Server", "").lower()
        x_powered = response.headers.get("X-Powered-By", "").lower()
        if "php" in x_powered: self.intel["tech_stack"].append("PHP")
        if "express" in x_powered: self.intel["tech_stack"].append("Node/Express")
        if "django" in server: self.intel["tech_stack"].append("Django")
        if "nginx" in server: self.intel["tech_stack"].append("Nginx")
        if "cloudflare" in server: self.intel["tech_stack"].append("Cloudflare")

    def _calculate_risk_score(self):
        """
        ✅ PRIORITY 6: Fixed risk scoring scale
        """
        risk_score = 0

        hidden_routes_count = (
            len(self.intel.get("validated_api", [])) +
            len(self.intel.get("graphql", [])) +
            len(self.intel.get("robots_disallowed", [])) +
            len(self.intel.get("websocket_endpoints", []))
        )
        risk_score += (hidden_routes_count // 3)

        intel_leaks = (
            len(self.intel.get("potential_keys", [])) +
            len([c for c in self.intel.get("comments", []) if "[Score:" in c or "secret" in c.lower()])
        )
        risk_score += (intel_leaks // 2)

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
                risk_score += 1
            elif "HARDCODED_AUTH_TOKEN" in signal_upper:
                risk_score += 4
        
        # ✅ PRIORITY 2: Add IDOR risk from discovered patterns
        if self.intel.get("id_patterns"):
            risk_score += len(self.intel["id_patterns"]) * 2
        
        # ✅ PRIORITY 2: Add risk from sensitive field exposure
        sensitive_fields = ['password', 'token', 'secret', 'key', 'auth', 'credit', 'ssn']
        for field in self.intel.get("discovered_fields", []):
            if any(s in field.lower() for s in sensitive_fields):
                risk_score += 3

        return risk_score

    def _get_risk_level(self, score):
        """
        ✅ PRIORITY 6: Proper risk level classification
        """
        if score < 20:
            return "LOW"
        elif score < 50:
            return "MEDIUM"
        elif score < 120:
            return "HIGH"
        else:
            return "CRITICAL"

    def run(self):
        if "signals" not in self.intel: 
            self.intel["signals"] = []
        if self.auth_enabled: 
            self.attempt_login(self.base_url)
        
        self.emit.info(f"Spider initialized ({self.max_threads} threads) - Deep Scan Mode")
        self.emit.info(f"Strict Mode: {'Enabled' if self.strict_mode else 'Disabled'}")
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
            with self.lock:
                queue_empty = len(self.queue) == 0
            if queue_empty:
                time.sleep(2)
                with self.lock:
                    still_empty = len(self.queue) == 0
                if still_empty:
                    self.running = False
                    break
        
        for t in threads: 
            t.join()
        
        if self.login_detected and not self.auth_enabled and self.intel["stats"]["links"] < 5:
            self._add_signal("LOGIN_WALL_DETECTED")
        
        self.intel["signals"] = list(set(self.intel["signals"]))
        self.intel["tech_stack"] = list(set(self.intel["tech_stack"]))

        raw_summary = (f"GET: {self.intel['stats']['get']} | POST: {self.intel['stats']['post']} | "
                       f"TOTAL: {self.intel['stats']['total']} | LINKS: {self.intel['stats']['links']} | "
                       f"JS_FILES: {self.intel['stats']['js_files']}")
        
        # ✅ PRIORITY 6: Fixed risk scoring
        risk_score = self._calculate_risk_score()
        risk_level = self._get_risk_level(risk_score)
        
        self.intel["risk_score"] = risk_score
        self.intel["risk_level"] = risk_level

        recommendations = []
        if self.intel.get("auth_surfaces"):
            recommendations.append("Test auth endpoints for credential stuffing & bypass")
        if any("HIGH_RISK" in s for s in self.intel["signals"]):
            recommendations.append("Prioritize testing endpoints with high-risk parameters")
        if self.intel.get("potential_keys"):
            recommendations.append("Validate discovered tokens/keys for privilege escalation")
        if self.intel.get("graphql"):
            recommendations.append("Test GraphQL endpoints for introspection & injection")
        if self.intel.get("id_patterns"):
            recommendations.append(f"Test {len(self.intel['id_patterns'])} ID patterns for IDOR/BAC")
        if self.intel.get("discovered_fields"):
            sensitive = [f for f in self.intel["discovered_fields"] if any(s in f for s in ['password', 'token', 'secret', 'key'])]
            if sensitive:
                recommendations.append(f"Review {len(sensitive)} sensitive fields for exposure")
        
        # ✅ PRIORITY 8: Create injection-ready summary
        injection_summary = {
            "total_validated_apis": len(self.intel["validated_api"]),
            "high_confidence_targets": len([e for e in self.intel["validated_api"] if e.get("confidence", 0) >= 0.8]),
            "endpoints_with_ids": len([e for e in self.intel["validated_api"] if e.get("contains_ids", False)]),
            "auth_required_endpoints": len([e for e in self.intel["validated_api"] if e.get("auth_required", False)]),
            "json_apis": len([e for e in self.intel["validated_api"] if e.get("accepts_json", False)])
        }
        
        return {
            "raw": raw_summary, 
            "intel": self.intel,
            "recommendations": recommendations,
            "injection_summary": injection_summary,
            "risk_level": risk_level
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
    engine = SpiderEngine(target, emit, depth=depth, threads=threads, auth=auth, options=options)
    result = engine.run()
    emit.success("Spider crawl complete.")
    emit.success(result["raw"])
    emit.success(f"Risk Level: {result['risk_level']} (Score: {result['intel']['risk_score']})")
    emit.success(f"Validated APIs: {len(result['intel']['validated_api'])} | High Confidence: {result['injection_summary']['high_confidence_targets']}")
    return result