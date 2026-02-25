import re
from urllib.parse import urlparse, urljoin


class JSExtractor:
    """
    Advanced JavaScript parser for SPA endpoint discovery.
    Extracts routes, methods, parameters, and security-relevant patterns.
    """

    # ✅ PRIORITY 7: Enhanced method detection patterns
    REST_PATTERNS = [
        # axios.METHOD("path")
        re.compile(r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', re.I),
        # fetch("path", { method: "POST" })
        re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*method\s*:\s*["\']?(GET|POST|PUT|DELETE|PATCH)["\']?', re.I),
        # fetch("path") - default GET
        re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']\s*\)', re.I),
        # $.ajax({ url: "path", method: "POST" })
        re.compile(r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\'][^}]*method\s*:\s*["\']?(GET|POST|PUT|DELETE|PATCH)["\']?', re.I),
        # Generic: .get("path"), .post("path")
        re.compile(r'\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', re.I),
        # API path literals: "/api/users", "/v1/auth"
        re.compile(r'["\'](/(?:rest|api|v[0-9]+|graphql|admin)[a-zA-Z0-9_\-\.\/]*)["\']', re.I),
    ]

    GRAPHQL_PATTERN = re.compile(r'["\'](/graphql[^"\']*)["\']', re.I)
    QUERY_PARAM_PATTERN = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=', re.I)
    BODY_PARAM_PATTERN = re.compile(r'JSON\.stringify\s*\(\s*\{([^}]+)\}', re.DOTALL)
    TEMPLATE_PATTERN = re.compile(r'`(/[^`$]*(?:\$\{[^}]+\}[^`$]*)*)`')
    WS_PATTERN = re.compile(r'(?:new\s+)?(WebSocket|EventSource)\s*\(\s*["\']([^"\']+)["\']', re.I)
    LAZY_LOAD_PATTERN = re.compile(r'import\s*\(\s*["\']\.?/([^"\']+)["\']\s*\)', re.I)
    KEY_PATTERN = re.compile(r'["\']([A-Za-z0-9_\-]{20,})["\']')

    @staticmethod
    def normalize_route(route: str) -> str:
        """
        Normalize route path for consistent matching.
        Handles fragments, query strings, IDs, and case.
        """
        if not route:
            return None
        
        route = route.split('#')[0].split('?')[0]
        
        parsed = urlparse(route)
        path = parsed.path or route
        
        path = re.sub(r'//+', '/', path)
        
        path = re.sub(r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '/{id}', path, flags=re.I)
        path = re.sub(r'/[0-9a-fA-F]{24}', '/{id}', path, flags=re.I)
        path = re.sub(r'/[0-9a-fA-F]{8,}', '/{id}', path, flags=re.I)
        path = re.sub(r'/\d+', '/{id}', path)
        
        path = re.sub(r'\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}', r'{\1}', path)
        path = re.sub(r':([a-zA-Z_][a-zA-Z0-9_]*)', r'{\1}', path)
        
        # ✅ PRIORITY 1 & 3: Normalize to lowercase
        path = path.lower()
        
        return path.rstrip("/")

    @staticmethod
    def _is_valid_endpoint(route: str) -> bool:
        """
        ✅ PRIORITY 1: Strict validation to filter noise from JS route extraction.
        """
        if not route or not isinstance(route, str):
            return False
        
        # ✅ PRIORITY 1: Must start with /
        if not route.startswith("/"):
            return False
        
        clean_route = route.split("?")[0].split("#")[0]
        
        # ✅ PRIORITY 1: Must have at least 2 path segments
        segments = [s for s in clean_route.split("/") if s]
        if len(segments) < 2:
            return False
        
        # ✅ PRIORITY 2: Reject pure single-word paths
        if re.match(r"^/[a-zA-Z0-9_-]+$", clean_route):
            if not any(k in clean_route.lower() for k in ["api", "v1", "v2", "graphql", "rest", "auth", "admin"]):
                return False
        
        # ✅ PRIORITY 1: Reject placeholder-only patterns
        if re.match(r"^/\{[a-zA-Z]+\}$", clean_route):
            return False
        
        # ✅ PRIORITY 1: Reject routes that are just template vars
        if "${" in route or clean_route.count("{") == len(segments):
            return False
        
        # ✅ PRIORITY 1: Reject obvious non-endpoints
        noise_patterns = [
            r"^/static/", r"^/assets/", r"^/images/", r"^/fonts/",
            r"^/\.well-known/", r"^/favicon", r"^/robots\.txt",
            r"\.(css|js|png|jpg|svg|ico|woff|woff2)$"
        ]
        if any(re.search(p, clean_route, re.I) for p in noise_patterns):
            return False
        
        return True

    @staticmethod
    def _is_telemetry_event(text: str) -> bool:
        """
        ✅ PRIORITY 3: Detect and filter analytics/telemetry event strings.
        """
        if not text or not isinstance(text, str):
            return False
        
        if not re.match(r'^[a-z][a-z0-9_]*$', text):
            return False
        
        if text.startswith("/"):
            return False
        
        if "_" not in text:
            return False
        
        telemetry_keywords = [
            'added', 'removed', 'clicked', 'viewed', 'loaded', 'submitted',
            'success', 'error', 'failed', 'start', 'end', 'complete',
            'basket', 'cart', 'checkout', 'payment', 'address', 'coupon',
            'challenge', 'verification', 'tracking', 'analytics', 'pixel',
            'impression', 'conversion', 'funnel', 'segment', 'event'
        ]
        
        if any(kw in text for kw in telemetry_keywords):
            return True
        
        if text.count("_") >= 2 and len(text.split("_")) >= 3:
            return True
        
        return False

    @staticmethod
    def _is_valid_parameter_name(name: str) -> bool:
        """
        ✅ PRIORITY 4: Filter out minified/garbage parameter names.
        """
        if not name or not isinstance(name, str):
            return False
        
        name = name.strip()
        
        # ✅ PRIORITY 4: Reject too short (minified vars)
        if len(name) <= 2:
            return False
        
        # ✅ PRIORITY 4: Reject single uppercase letter
        if len(name) == 1 and name.isupper():
            return False
        
        # ✅ PRIORITY 4: Reject purely numeric
        if name.isdigit():
            return False
        
        # ✅ PRIORITY 4: Whitelist of meaningful parameter patterns
        meaningful_patterns = [
            r'^[a-z_]+$',
            r'^[a-z]+[A-Z][a-zA-Z]*$',
            r'^(id|uuid|token|key|secret|auth|api|access|refresh|client|scope|redirect|email|user|account|password|pass|pwd|query|search|filter|sort|limit|offset|page|format|lang|locale|callback|state|nonce|timestamp)$',
        ]
        
        if any(re.match(p, name, re.I) for p in meaningful_patterns):
            return True
        
        # ✅ PRIORITY 4: Reject if looks like minified
        if re.match(r'^[a-zA-Z]$', name):
            return False
        
        # ✅ PRIORITY 4: Must match proper variable pattern
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]{2,}$", name):
            return False
        
        return len(name) >= 3 and not name.startswith("_")

    @staticmethod
    def extract_body_params(js_content: str) -> list:
        """Extract parameter names from JSON.stringify blocks"""
        params = set()
        
        for match in JSExtractor.BODY_PARAM_PATTERN.finditer(js_content):
            body_content = match.group(1)
            keys = re.findall(r'["\']?([a-zA-Z_][a-zA-Z0-9_]*)["\']?\s*:', body_content)
            for key in keys:
                if key.lower() not in ['function', 'return', 'var', 'let', 'const', 'if', 'else']:
                    params.add(key)
        
        return sorted(params)

    @staticmethod
    def extract_query_params(route: str) -> list:
        """Extract query parameter names from route string"""
        params = set()
        for match in JSExtractor.QUERY_PARAM_PATTERN.finditer(route):
            params.add(match.group(1))
        return sorted(params)

    def extract(self, content: str) -> dict:
        """
        Main extraction method. Returns structured intelligence.
        """
        routes = {}
        graphql = set()
        parameters = set()
        potential_keys = set()
        websocket_endpoints = set()
        lazy_routes = set()

        for pattern in self.REST_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                method = None
                path = None
                
                if isinstance(match, tuple):
                    if len(match) == 2:
                        method, path = match
                    else:
                        path = match[0]
                else:
                    path = match
                
                if not path:
                    continue
                
                # ✅ PRIORITY 1: Strict validation before normalization
                if not self._is_valid_endpoint(path):
                    continue
                
                # ✅ PRIORITY 7: Determine method if not captured
                if not method:
                    pattern_str = pattern.pattern.lower()
                    if 'post' in pattern_str:
                        method = 'POST'
                    elif 'put' in pattern_str:
                        method = 'PUT'
                    elif 'delete' in pattern_str:
                        method = 'DELETE'
                    elif 'patch' in pattern_str:
                        method = 'PATCH'
                    else:
                        method = 'GET'
                
                normalized = self.normalize_route(path)
                if not normalized:
                    continue
                
                if not self._is_valid_endpoint(normalized):
                    continue
                
                query_params = self.extract_query_params(path)
                body_params = []
                
                source = "regex"
                if 'axios' in pattern.pattern.lower():
                    source = "axios"
                elif 'fetch' in pattern.pattern.lower():
                    source = "fetch"
                elif 'ajax' in pattern.pattern.lower():
                    source = "jquery"
                
                if normalized not in routes:
                    routes[normalized] = {
                        "path": normalized,
                        "method": method,
                        "params": query_params,
                        "source": source,
                        "confidence": 0.7 if method != "GET" else 0.5  # ✅ PRIORITY 5
                    }
                else:
                    existing = routes[normalized]
                    if existing["method"] == "GET" and method != "GET":
                        existing["method"] = method
                        existing["confidence"] = 0.8  # ✅ PRIORITY 5: Boost for confirmed method
                    existing["params"] = sorted(set(existing["params"] + query_params))

        body_params_map = self.extract_body_params(content)
        
        for path, info in routes.items():
            if info["method"] in ["POST", "PUT", "PATCH"]:
                info["params"] = sorted(set(info["params"] + body_params_map))

        for match in self.GRAPHQL_PATTERN.findall(content):
            normalized = self.normalize_route(match)
            if normalized:
                graphql.add(normalized)
                if normalized not in routes:
                    routes[normalized] = {
                        "path": normalized,
                        "method": "POST",
                        "params": [],
                        "source": "graphql",
                        "confidence": 0.9  # ✅ PRIORITY 5: GraphQL = high confidence
                    }

        for match in self.TEMPLATE_PATTERN.findall(content):
            normalized = re.sub(r'\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}', r'{\1}', match)
            normalized = self.normalize_route(normalized)
            if normalized and normalized not in routes:
                routes[normalized] = {
                    "path": normalized,
                    "method": "GET",
                    "params": [],
                    "source": "template_literal",
                    "confidence": 0.3  # ✅ PRIORITY 5: Template = lower confidence
                }

        for match in self.QUERY_PARAM_PATTERN.findall(content):
            param = match.strip()
            # ✅ PRIORITY 3: Filter telemetry events
            if self._is_telemetry_event(param):
                continue
            # ✅ PRIORITY 4: Validate parameter name quality
            if not self._is_valid_parameter_name(param):
                continue
            parameters.add(param)

        for key in self.KEY_PATTERN.findall(content):
            if len(key) > 25 and key.isalnum() and not key.startswith("http"):
                potential_keys.add(key)

        for ws_type, ws_url in self.WS_PATTERN.findall(content):
            normalized = self.normalize_route(ws_url)
            if normalized:
                websocket_endpoints.add(normalized)

        for lazy_path in self.LAZY_LOAD_PATTERN.findall(content):
            if lazy_path and not lazy_path.endswith(('.css', '.png', '.jpg', '.svg')):
                lazy_routes.add(lazy_path)

        routes_list = sorted(routes.values(), key=lambda x: x["path"])

        return {
            "routes": routes_list,
            "graphql": sorted(graphql),
            "parameters": sorted(parameters),
            "potential_keys": sorted(potential_keys),
            "websocket_endpoints": sorted(websocket_endpoints),
            "lazy_routes": sorted(lazy_routes)
        }