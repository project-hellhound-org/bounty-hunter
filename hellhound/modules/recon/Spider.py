#!/usr/bin/env python3
"""
SPIDER - Hellhound Recon Brain v10.1 (Enterprise Edition)
Async Web Crawler + JS Analysis + Parameter Probing + Auth-Aware Session Management

Improvements over v9:
  - Robust session cookie handling (string, dict, Netscape file, header injection)
  - Auto re-auth detection on 401/403 mid-crawl
  - URL normalization + path-parameter clustering (/users/123 -> /users/{id})
  - Retry logic with exponential backoff (tenacity-style, no extra dep)
  - Per-domain adaptive rate limiting (backs off on 429)
  - Structured JSONL streaming output
  - GraphQL introspection auto-probe
  - OpenAPI / Swagger auto-discovery
  - CORS misconfiguration detection
  - CSP header parsing for endpoint hints
  - Crawl-delay from robots.txt respected
  - URL budget per depth level (prevents explosion)
  - Confidence levels: LOW / MEDIUM / HIGH / CONFIRMED
  - Config validation on startup
  - Diff mode: compare two crawl JSON results
  - Multiple export formats: JSON, JSONL, CSV, Burp XML
  - Verbosity flag: verbose=False (clean mode) / verbose=True (debug mode)
  - Fixed: continue inside async-with, self.emit refs, worker count math

Verbosity:
  Default (clean):  only scan start, critical findings (secrets/cors/graphql/openapi), summary
  Verbose/debug:    all internal discovery logs (forms, JS APIs, params, comments, robots, etc.)
"""

import asyncio
import aiohttp
import csv
import hashlib
import io
import json
import re
import sys
import time
import random
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from pathlib import Path
from datetime import datetime
from http.cookiejar import MozillaCookieJar
from typing import Optional, Dict, List, Any
from colorama import Fore, Style

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from bs4 import BeautifulSoup, Comment

# =================================================
# METADATA
# =================================================

NAME        = "spider"
CATEGORY    = "recon"
VERSION     = "10.1"
DESCRIPTION = "Hellhound Recon Brain — Enterprise Async Crawler + Auth-Aware Session"

# =================================================
# CONFIDENCE LEVELS
# =================================================

class Confidence:
    LOW       = 1   # Single indirect signal
    MEDIUM    = 3   # Confirmed via HTML / JS reference
    HIGH      = 6   # Form or direct JS fetch call
    CONFIRMED = 10  # Dynamic browser traffic / OpenAPI definition

# =================================================
# CONFIG & VALIDATION
# =================================================

DEFAULT_CONFIG = {
    "max_depth":            3,
    "concurrency":          10,
    "timeout":              12,
    "max_retries":          3,
    "retry_base_delay":     0.5,       # seconds; doubles each retry
    "max_urls_per_depth":   200,       # budget per depth level
    "user_agent":           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "extensions_to_ignore": [".png",".jpg",".jpeg",".gif",".ico",".svg",
                              ".woff",".woff2",".ttf",".css",".mp4",".mp3",
                              ".zip",".pdf",".exe",".dmg"],
    "enable_probing":           True,
    "enable_method_discovery":  True,
    "enable_graphql_probe":     True,
    "enable_openapi_probe":     True,
    "enable_cors_check":        True,
    "enable_playwright":        True,
    "jitter_min":               0.05,
    "jitter_max":               0.4,
    "streaming_output":         False,  # emit JSONL lines as discovered
    "stream_file":              None,   # path or None for stdout
    "verbose":                  False,  # verbose=False: clean output / True: full debug logs
}

REQUIRED_KEYS = ["max_depth", "concurrency", "timeout", "user_agent"]

def validate_config(cfg: dict) -> None:
    for k in REQUIRED_KEYS:
        if k not in cfg:
            raise ValueError(f"[Config] Missing required key: {k}")
    if cfg["max_depth"] < 0 or cfg["max_depth"] > 20:
        raise ValueError("[Config] max_depth must be 0-20")
    if cfg["concurrency"] < 1 or cfg["concurrency"] > 100:
        raise ValueError("[Config] concurrency must be 1-100")

# =================================================
# VERBOSE EMIT WRAPPER
# =================================================

class VerboseEmit:
    """
    Wraps the caller's emit object and gates .info() / .success() calls
    behind the verbose flag.

    Logic:
      verbose=False (clean mode)  — only .warn() and explicitly "always" calls pass through
      verbose=True  (debug mode)  — everything passes through unchanged

    Usage inside the spider:
        self.emit.info(...)         # gated — only shown in verbose mode
        self.emit.warn(...)         # always shown (critical findings)
        self.emit.success(...)      # gated — only shown in verbose mode
        self.emit.always_info(...)  # always shown regardless of verbose flag
        self.emit.always_success(...) # always shown regardless of verbose flag
    """

    def __init__(self, base_emit, verbose: bool):
        self._emit   = base_emit
        self._verbose = verbose

    def info(self, msg: str):
        if self._verbose:
            self._emit.info(msg)

    def success(self, msg: str):
        if self._verbose:
            self._emit.success(msg)

    def warn(self, msg: str):
        if "[SECRET" in msg:
            msg = Fore.MAGENTA + msg + Style.RESET_ALL
        elif "[Probe:Sensitive]" in msg:
            msg = Fore.RED + msg + Style.RESET_ALL
        elif "[CORS:HIGH]" in msg:
            msg = Fore.RED + msg + Style.RESET_ALL
        elif "[CORS:MEDIUM]" in msg:
            msg = Fore.YELLOW + msg + Style.RESET_ALL
        elif "[Auth-wall" in msg:
            msg = Fore.YELLOW + msg + Style.RESET_ALL
        elif "[SourceMap]" in msg:
            msg = Fore.YELLOW + msg + Style.RESET_ALL
        else:
            msg = Fore.RED + msg + Style.RESET_ALL

        self._emit.warn(msg)

    def always_info(self, msg: str):
        msg = Fore.CYAN + msg + Style.RESET_ALL
        self._emit.info(msg)
        
    def always_success(self, msg: str):
        msg = Fore.GREEN + msg + Style.RESET_ALL
        self._emit.success(msg)


# =================================================
# SESSION COOKIE HANDLING
# =================================================

class SessionManager:
    """
    Handles every cookie format a pentester might throw at us:
      1. Raw string:  "session=abc123; csrf=xyz"
      2. Dict:        {"session": "abc123", "csrf": "xyz"}
      3. Netscape / MozillaCookieJar file path
      4. JSON file:   [{"name": "session", "value": "abc123", "domain": "..."}]
      5. Header pair: {"Authorization": "Bearer <token>"}  (extra_headers option)
    """

    @staticmethod
    def parse(raw) -> Dict[str, str]:
        """Returns a plain dict of name -> value cookies."""
        if not raw:
            return {}

        # Already a dict
        if isinstance(raw, dict):
            # Could be header-style or cookie-style — split them
            if any(k.lower() in ("authorization", "x-api-key") for k in raw):
                return {}  # These go into headers, not cookies
            return raw

        if isinstance(raw, str):
            raw = raw.strip()

            # File path (Netscape or JSON)
            p = Path(raw)
            if p.exists() and p.is_file():
                return SessionManager._load_file(p)

            # Inline cookie string: "name=val; name2=val2"
            cookies = {}
            for part in raw.split(";"):
                part = part.strip()
                if "=" in part:
                    name, _, val = part.partition("=")
                    cookies[name.strip()] = val.strip()
            return cookies

        return {}

    @staticmethod
    def _load_file(path: Path) -> Dict[str, str]:
        # Try JSON array format first (exported from browser devtools / Burp)
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                return {c["name"]: c["value"] for c in data if "name" in c and "value" in c}
        except (json.JSONDecodeError, KeyError):
            pass

        # Try Netscape cookie file
        try:
            jar = MozillaCookieJar(str(path))
            jar.load(ignore_discard=True, ignore_expires=True)
            return {c.name: c.value for c in jar}
        except Exception:
            pass

        return {}

    @staticmethod
    def parse_extra_headers(raw) -> Dict[str, str]:
        """Extract header-style auth values (Authorization, X-API-Key, etc.)"""
        if isinstance(raw, dict):
            return {k: v for k, v in raw.items()
                    if k.lower() in ("authorization", "x-api-key", "x-auth-token",
                                     "x-csrf-token", "x-access-token")}
        return {}

# =================================================
# RATE LIMITER (per-domain adaptive)
# =================================================

class DomainRateLimiter:
    def __init__(self, base_delay: float = 0.1):
        self._delays: Dict[str, float] = defaultdict(lambda: base_delay)
        self._locks:  Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def wait(self, domain: str):
        async with self._locks[domain]:
            await asyncio.sleep(self._delays[domain])

    def backoff(self, domain: str):
        """Called on 429 — doubles delay, capped at 10s."""
        self._delays[domain] = min(self._delays[domain] * 2, 10.0)

    def reset(self, domain: str):
        """Gradually recover delay after successful request."""
        self._delays[domain] = max(self._delays[domain] * 0.9, 0.05)

# =================================================
# RETRY HELPER
# =================================================

async def fetch_with_retry(session: aiohttp.ClientSession,
                           method: str,
                           url: str,
                           rate_limiter: DomainRateLimiter,
                           max_retries: int = 3,
                           base_delay: float = 0.5,
                           **kwargs):
    """
    Wraps aiohttp requests with exponential-backoff retry.
    Returns (response_obj, text) or (None, None) on failure.
    Caller must NOT use 'async with' — we return the consumed text.
    """
    domain = urlparse(url).netloc
    await rate_limiter.wait(domain)

    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            async with session.request(method, url, **kwargs) as resp:
                if resp.status == 429:
                    rate_limiter.backoff(domain)
                    retry_after = int(resp.headers.get("Retry-After", base_delay * (2 ** attempt)))
                    await asyncio.sleep(retry_after)
                    continue
                text = await resp.text(errors="replace")
                rate_limiter.reset(domain)
                return resp.status, dict(resp.headers), text
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            last_exc = e
            if attempt < max_retries:
                await asyncio.sleep(base_delay * (2 ** attempt))

    return None, None, None

# =================================================
# URL NORMALIZER + PATH PARAM CLUSTERING
# =================================================

_ID_SEGMENT = re.compile(r'^(\d+|[0-9a-fA-F\-]{8,}|[0-9a-fA-F]{24})$')

def normalize_url(url: str) -> str:
    """
    1. Sort query params alphabetically.
    2. Strip fragment.
    3. Lowercase scheme + host.
    """
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    sorted_qs = urlencode(sorted(qs.items()), doseq=True)
    normalized = urlunparse((
        p.scheme.lower(),
        p.netloc.lower(),
        p.path.rstrip("/") or "/",
        p.params,
        sorted_qs,
        ""  # no fragment
    ))
    return normalized

def cluster_path(url: str) -> str:
    """
    Replace numeric / UUID path segments with {id} for deduplication.
    /users/42/posts/abc123 -> /users/{id}/posts/{id}
    """
    p = urlparse(url)
    segments = p.path.split("/")
    clustered = ["{id}" if _ID_SEGMENT.match(s) else s for s in segments]
    clustered_path = "/".join(clustered)
    return urlunparse((p.scheme, p.netloc, clustered_path, "", "", ""))

# =================================================
# DATA STORE
# =================================================

class InMemoryStore:
    def __init__(self, stream_cb=None):
        self.endpoints:      Dict[str, dict] = {}
        self.comments:       List[dict]       = []
        self.secrets:        List[dict]       = []
        self.tech_stack:     set              = set()
        self.robots_entries: List[str]        = []
        self.sourcemaps:     List[dict]       = []
        self.cors_issues:    List[dict]       = []
        self.graphql_schemas:List[dict]       = []
        self.openapi_specs:  List[dict]       = []
        self._stream_cb = stream_cb  # callable(event_type, data)

    # ---- internal ----

    def _cluster_key(self, url: str, method: str) -> str:
        return f"{method}:{cluster_path(normalize_url(url))}"

    def _make_endpoint(self, url: str, method: str) -> dict:
        return {
            "url":                 url,
            "cluster":             cluster_path(normalize_url(url)),
            "methods":             [method],
            "params":              {"form": [], "js_static": [], "error_based": [],
                                    "runtime": [], "openapi": []},
            "source":              [],
            "confidence":          0,
            "confidence_label":    "LOW",
            "sensitive_keywords":  [],
            "baseline":            None,
            "parameter_sensitive": False,
            "observed_status":     [],
            "auth_required":       False,
        }

    def _label(self, score: int) -> str:
        if score >= Confidence.CONFIRMED: return "CONFIRMED"
        if score >= Confidence.HIGH:      return "HIGH"
        if score >= Confidence.MEDIUM:    return "MEDIUM"
        return "LOW"

    def _stream(self, etype: str, data: dict):
        if self._stream_cb:
            self._stream_cb(etype, data)

    # ---- public API ----

    def add_endpoint(self, url: str, method: str = "GET",
                     source: str = "Static",
                     params: Optional[List[str]] = None,
                     confidence_increment: int = Confidence.LOW,
                     auth_required: bool = False) -> dict:
        key = self._cluster_key(url, method)
        if key not in self.endpoints:
            self.endpoints[key] = self._make_endpoint(url, method)

        ep = self.endpoints[key]

        if source not in ep["source"]:
            ep["source"].append(source)
        ep["confidence"] = min(ep["confidence"] + confidence_increment, Confidence.CONFIRMED)
        ep["confidence_label"] = self._label(ep["confidence"])

        if params:
            if source == "Form":
                ep["params"]["form"] = list(set(ep["params"]["form"] + params))
            elif source == "OpenAPI":
                ep["params"]["openapi"] = list(set(ep["params"]["openapi"] + params))

        if auth_required:
            ep["auth_required"] = True

        self._stream("endpoint", ep)
        return ep

    def add_params_from_js(self, url: str, params: List[str],
                           source_type: str = "js_static") -> bool:
        key = self._cluster_key(url, "GET")
        if key not in self.endpoints:
            self.endpoints[key] = self._make_endpoint(url, "GET")
        ep = self.endpoints[key]
        if source_type not in ep["params"]:
            ep["params"][source_type] = []
        new = [p for p in params if p not in ep["params"][source_type]]
        ep["params"][source_type].extend(new)
        if new:
            ep["confidence"] = min(ep["confidence"] + 1, Confidence.CONFIRMED)
            ep["confidence_label"] = self._label(ep["confidence"])
            return True
        return False

    def update_methods(self, url: str, methods: List[str]):
        key = self._cluster_key(url, methods[0] if methods else "GET")
        if key not in self.endpoints:
            self.endpoints[key] = self._make_endpoint(url, methods[0] if methods else "GET")
        ep = self.endpoints[key]
        for m in methods:
            if m not in ep["methods"]:
                ep["methods"].append(m)
        ep["confidence"] = min(ep["confidence"] + 1, Confidence.CONFIRMED)
        ep["confidence_label"] = self._label(ep["confidence"])

    def update_baseline(self, url: str, method: str,
                        status: int, body_hash: str, length: int):
        key = self._cluster_key(url, method)
        if key in self.endpoints:
            self.endpoints[key]["baseline"] = {
                "status": status, "hash": body_hash, "length": length
            }
            if status in (401, 403):
                self.endpoints[key]["auth_required"] = True

    def mark_sensitive(self, url: str, method: str):
        key = self._cluster_key(url, method)
        if key in self.endpoints:
            self.endpoints[key]["parameter_sensitive"] = True
            self.endpoints[key]["confidence"] = min(
                self.endpoints[key]["confidence"] + 2, Confidence.CONFIRMED)
            self.endpoints[key]["confidence_label"] = self._label(
                self.endpoints[key]["confidence"])

    def record_status(self, url: str, method: str, status: int):
        key = self._cluster_key(url, method)
        if key in self.endpoints:
            if status not in self.endpoints[key]["observed_status"]:
                self.endpoints[key]["observed_status"].append(status)

    def add_comment(self, content: str, source_url: str) -> bool:
        content = content.strip()
        if len(content) < 5 or content.startswith("["):
            return False
        if any(c["content"] == content for c in self.comments):
            return False
        self.comments.append({"content": content, "source": source_url})
        self._stream("comment", self.comments[-1])
        return True

    def add_secret(self, content: str, stype: str, source_url: str) -> bool:
        if any(s["content"] == content for s in self.secrets):
            return False
        self.secrets.append({"content": content, "type": stype, "source": source_url})
        self._stream("secret", self.secrets[-1])
        return True

    def add_cors_issue(self, url: str, origin_sent: str, origin_reflected: str,
                       allow_credentials: bool):
        self.cors_issues.append({
            "url": url,
            "origin_sent": origin_sent,
            "origin_reflected": origin_reflected,
            "allow_credentials": allow_credentials,
            "severity": "HIGH" if allow_credentials else "MEDIUM"
        })
        self._stream("cors", self.cors_issues[-1])

    def add_tech(self, tech: str):        self.tech_stack.add(tech)
    def add_robots_entry(self, path: str):
        if path not in self.robots_entries: self.robots_entries.append(path)
    def add_sourcemap(self, map_url: str, parent: str):
        if not any(s["url"] == map_url for s in self.sourcemaps):
            self.sourcemaps.append({"url": map_url, "parent": parent})

    def get_endpoints(self) -> List[dict]:
        return list(self.endpoints.values())

    def export(self, target_url: str, fmt: str = "json") -> Any:
        eps = [e for e in self.endpoints.values() if e["confidence"] >= Confidence.LOW]
        data = {
            "meta": {
                "tool":    f"Hellhound Spider v{VERSION}",
                "target":  target_url,
                "date":    datetime.utcnow().isoformat() + "Z",
            },
            "summary": {
                "endpoints_count":          len(eps),
                "confirmed_count":          len([e for e in eps if e["confidence_label"] == "CONFIRMED"]),
                "high_confidence_count":    len([e for e in eps if e["confidence_label"] in ("HIGH","CONFIRMED")]),
                "parameter_sensitive_count":len([e for e in eps if e["parameter_sensitive"]]),
                "auth_required_count":      len([e for e in eps if e["auth_required"]]),
                "cors_issues_count":        len(self.cors_issues),
                "secrets_found":            len(self.secrets),
                "tech_stack":               sorted(self.tech_stack),
            },
            "endpoints":    eps,
            "comments":     self.comments,
            "secrets":      self.secrets,
            "cors_issues":  self.cors_issues,
            "graphql":      self.graphql_schemas,
            "openapi":      self.openapi_specs,
            "tech_stack":   sorted(self.tech_stack),
            "robots_txt":   self.robots_entries,
            "sourcemaps":   self.sourcemaps,
        }

        if fmt == "json":
            return json.dumps(data, indent=2)

        if fmt == "jsonl":
            lines = [json.dumps({"type": "meta",     "data": data["meta"]}),
                     json.dumps({"type": "summary",  "data": data["summary"]})]
            for ep in eps:
                lines.append(json.dumps({"type": "endpoint", "data": ep}))
            return "\n".join(lines)

        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["url","cluster","methods","confidence","confidence_label",
                         "auth_required","parameter_sensitive","sources",
                         "form_params","js_params","observed_status"])
            for ep in eps:
                w.writerow([
                    ep["url"], ep["cluster"],
                    "|".join(ep["methods"]),
                    ep["confidence"], ep["confidence_label"],
                    ep["auth_required"], ep["parameter_sensitive"],
                    "|".join(ep["source"]),
                    "|".join(ep["params"].get("form",[])),
                    "|".join(ep["params"].get("js_static",[])),
                    "|".join(str(s) for s in ep.get("observed_status",[])),
                ])
            return buf.getvalue()

        if fmt == "burp":
            root = ET.Element("items", burpVersion="2.0", exportTime=datetime.utcnow().isoformat())
            for ep in eps:
                item = ET.SubElement(root, "item")
                ET.SubElement(item, "url").text      = ep["url"]
                ET.SubElement(item, "method").text   = ep["methods"][0]
                ET.SubElement(item, "confidence").text = ep["confidence_label"]
                ET.SubElement(item, "authRequired").text = str(ep["auth_required"])
                ET.SubElement(item, "params").text   = str(ep["params"])
            return ET.tostring(root, encoding="unicode", xml_declaration=True)

        return json.dumps(data, indent=2)

# =================================================
# DIFF ENGINE
# =================================================

def diff_crawls(old_json: str, new_json: str) -> dict:
    """
    Compare two JSON crawl results (from export()).
    Returns a dict with added / removed / changed endpoint clusters.
    """
    old = json.loads(old_json)
    new = json.loads(new_json)

    old_map = {e["cluster"]: e for e in old.get("endpoints", [])}
    new_map = {e["cluster"]: e for e in new.get("endpoints", [])}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    added   = [new_map[k] for k in (new_keys - old_keys)]
    removed = [old_map[k] for k in (old_keys - new_keys)]
    changed = []

    for k in old_keys & new_keys:
        o, n = old_map[k], new_map[k]
        changes = {}
        if set(o["methods"]) != set(n["methods"]):
            changes["methods"] = {"old": o["methods"], "new": n["methods"]}
        if o["confidence_label"] != n["confidence_label"]:
            changes["confidence"] = {"old": o["confidence_label"], "new": n["confidence_label"]}
        if o["auth_required"] != n["auth_required"]:
            changes["auth_required"] = {"old": o["auth_required"], "new": n["auth_required"]}
        if changes:
            changed.append({"cluster": k, "url": n["url"], "changes": changes})

    return {
        "old_target": old.get("meta", {}).get("target"),
        "new_target": new.get("meta", {}).get("target"),
        "added":   added,
        "removed": removed,
        "changed": changed,
        "summary": {
            "added_count":   len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
        }
    }

# =================================================
# EXTRACTOR
# =================================================

class Extractor:
    JS_NOISE = {"console","window","document","return","function","const","let",
                "var","this","class","import","export","default","null","undefined",
                "true","false","new","async","await","try","catch","if","else"}

    PARAM_PATTERNS = [
        (r'body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]{1,300})\}',    "json_body"),
        (r'axios\.(?:post|put|patch)\([^,]{1,100},\s*\{([^}]{1,300})\}', "axios_obj"),
        (r'data\s*:\s*\{([^}]{1,300})\}',                            "data_obj"),
        (r'params\s*:\s*\{([^}]{1,300})\}',                          "params_obj"),
        (r'new\s+URLSearchParams\s*\(\s*\{([^}]{1,300})\}',          "search_params"),
        (r'let\s+\w+\s*=\s*\{([^}]{1,300})\}',                       "var_obj"),
    ]

    SECRET_PATTERNS = [
        (r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b',                "Bitcoin_Address"),
        (r'\b(0x[a-fA-F0-9]{40})\b',                               "Ethereum_Address"),
        (r'(AIza[0-9A-Za-z\-_]{35})',                              "Google_API_Key"),
        (r'(AKIA[0-9A-Z]{16})',                                     "AWS_Access_Key"),
        (r'Bearer\s+([a-zA-Z0-9\-._~+/]{20,}=*)',                  "Bearer_Token"),
        (r'["\']sk-[a-zA-Z0-9]{20,}["\']',                         "Stripe_Key"),
        (r'gh[pousr]_[A-Za-z0-9_]{36,}',                           "GitHub_PAT"),
        (r'["\']([0-9a-fA-F]{32})["\']',                           "Possible_MD5_Secret"),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',               "Private_Key_PEM"),
        (r'["\'](?:password|passwd|pwd|secret|api_?key)\s*["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
                                                                    "Hardcoded_Credential"),
    ]

    API_PATTERNS = [
        r'["\']([/][a-zA-Z0-9_\-\.\/]+'
        r'(?:api|v\d|graphql|admin|auth|login|rest|search|data|internal)'
        r'[a-zA-Z0-9_\-\.\/]*)["\']',
        r'(?:axios|fetch)\s*\(\s*["\']([^"\'?\s]{5,})["\']',
        r'\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\'?\s]{5,})["\']',
    ]

    @staticmethod
    def _extract_keys(block: str) -> List[str]:
        keys = re.findall(r'["\']?([a-zA-Z_$][a-zA-Z0-9_$]*)["\']?\s*:', block)
        return [k for k in keys if k not in Extractor.JS_NOISE and len(k) > 1]

    @staticmethod
    def extract_js_params(text: str, base_url: str, store: InMemoryStore, emit):
        for pattern, ptype in Extractor.PARAM_PATTERNS:
            for match in re.finditer(pattern, text):
                block = match.group(1)
                keys  = Extractor._extract_keys(block)
                if not keys:
                    continue
                pre = text[max(0, match.start()-200):match.start()]
                um  = re.search(r'["\']([/][a-zA-Z0-9_\-\.\/]+)["\']', pre)
                if um:
                    turl = urljoin(base_url, um.group(1))
                    if store.add_params_from_js(turl, keys, "js_static"):
                        emit.info(f"[JS Params] {keys} -> {turl}")

    @staticmethod
    def extract_secrets(text: str, url: str, store: InMemoryStore, emit):
        for pattern, stype in Extractor.SECRET_PATTERNS:
            for match in re.finditer(pattern, text):
                val = match.group(1) if match.lastindex else match.group(0)
                if stype not in ("Bitcoin_Address","Ethereum_Address","Private_Key_PEM",
                                  "Hardcoded_Credential","GitHub_PAT") and len(val) < 20:
                    continue
                if store.add_secret(val, stype, url):
                    emit.warn(f"[SECRET:{stype}] {val[:60]}")

    @staticmethod
    def extract_js_endpoints(text: str, url: str, store: InMemoryStore, emit):
        for pattern in Extractor.API_PATTERNS:
            for match in re.finditer(pattern, text):
                path = match.group(1)
                if not path.startswith("/") or len(path) < 4:
                    continue
                path     = path.split("?")[0]
                full_url = urljoin(url, path)
                store.add_endpoint(full_url, method="GET", source="JS_Analysis",
                                   confidence_increment=Confidence.MEDIUM)
                emit.info(f"[JS API] {full_url}")

    @staticmethod
    def extract_comments(soup, url: str, store: InMemoryStore, emit):
        kw = {'todo','fixme','bug','admin','hidden','secret','debug',
              'config','key','password','cred','token','hack','temp','test'}
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            txt = c.strip()
            if len(txt) < 3:
                continue
            interesting = any(k in txt.lower() for k in kw) \
                       or bool(re.match(r'^[/\.][a-z0-9_\-\.#]{3,}', txt))
            if interesting and store.add_comment(txt, url):
                emit.info(f"[Comment] {txt[:80]}")

    @staticmethod
    def parse_csp_endpoints(headers: dict, base_url: str,
                            store: InMemoryStore, emit):
        """Extract endpoint hints from Content-Security-Policy header."""
        csp = headers.get("Content-Security-Policy", "") or \
              headers.get("content-security-policy", "")
        if not csp:
            return
        parsed = urlparse(base_url)
        for token in csp.split():
            token = token.rstrip(";")
            if token.startswith(("https://","http://")) \
               and urlparse(token).netloc != parsed.netloc:
                emit.info(f"[CSP] Third-party: {token}")
            elif token.startswith("/") and len(token) > 2:
                full = urljoin(base_url, token)
                store.add_endpoint(full, source="CSP_Header",
                                   confidence_increment=Confidence.LOW)

# =================================================
# INTELLIGENT PROBER
# =================================================

class IntelligentProber:
    METHODS_TO_TEST = ["OPTIONS","PUT","PATCH","DELETE","HEAD"]

    def __init__(self, session, store: InMemoryStore, emit,
                 rate_limiter: DomainRateLimiter, config: dict):
        self.session      = session
        self.store        = store
        self.emit         = emit
        self.rl           = rate_limiter
        self.config       = config

    async def run(self):
        self.emit.info("Phase: Intelligent Probing (Baseline + Mutation + Methods)…")
        endpoints = self.store.get_endpoints()
        targets   = [
            e for e in endpoints
            if any(k in e["url"] for k in
                   ("api","rest","admin","v1","v2","v3","data","login","auth","graphql"))
        ][:40]

        count_sens, count_methods = 0, 0

        for ep in targets:
            url    = ep["url"]
            method = ep["methods"][0] if ep["methods"] else "GET"

            status, hdrs, text = await fetch_with_retry(
                self.session, method, url, self.rl,
                max_retries=self.config["max_retries"],
                base_delay=self.config["retry_base_delay"])

            if status is None:
                continue

            bh = hashlib.md5(text.encode(errors="ignore")).hexdigest()
            self.store.update_baseline(url, method, status, bh, len(text))
            self.store.record_status(url, method, status)

            if await self._test_mutation(url, method, status, bh, len(text)):
                self.store.mark_sensitive(url, method)
                self.emit.warn(f"[Probe:Sensitive] {url}")
                count_sens += 1

            if self.config["enable_method_discovery"]:
                found = await self._discover_methods(url, hdrs or {})
                if found:
                    self.store.update_methods(url, found)
                    self.emit.info(f"[Methods] {url} -> {', '.join(found)}")
                    count_methods += 1

            if self.config["enable_cors_check"]:
                await self._check_cors(url)

        if count_sens or count_methods:
            self.emit.always_success(
                f"Probing done. Sensitive: {count_sens}, New Methods: {count_methods}")

    async def _test_mutation(self, url: str, method: str,
                              base_status: int, base_hash: str,
                              base_len: int) -> bool:
        probe = url + ("&" if "?" in url else "?") + f"_hh={int(time.time())}"
        s, _, t = await fetch_with_retry(self.session, method, probe, self.rl)
        if s is None:
            return False
        h = hashlib.md5(t.encode(errors="ignore")).hexdigest()
        return h != base_hash or abs(len(t) - base_len) > 50

    async def _discover_methods(self, url: str, base_headers: dict) -> List[str]:
        found = []
        # First try OPTIONS
        s, hdrs, _ = await fetch_with_retry(self.session, "OPTIONS", url, self.rl)
        if hdrs:
            allow = hdrs.get("Allow", "") or hdrs.get("allow", "")
            if allow:
                return [m for m in self.METHODS_TO_TEST if m in allow]
        # Fallback: try each method
        for m in self.METHODS_TO_TEST:
            s, _, _ = await fetch_with_retry(self.session, m, url, self.rl,
                                              data="{}", headers={"Content-Type":"application/json"})
            if s is not None and s not in (405, 501, 400):
                found.append(m)
        return found

    async def _check_cors(self, url: str):
        evil = "https://evil.hellhound.local"
        s, hdrs, _ = await fetch_with_retry(
            self.session, "GET", url, self.rl,
            headers={"Origin": evil})
        if hdrs is None:
            return
        acao = hdrs.get("Access-Control-Allow-Origin","") or \
               hdrs.get("access-control-allow-origin","")
        acac = (hdrs.get("Access-Control-Allow-Credentials","") or
                hdrs.get("access-control-allow-credentials","")).lower() == "true"
        if acao and (acao == "*" or acao == evil):
            self.store.add_cors_issue(url, evil, acao, acac)
            sev = "HIGH" if acac else "MEDIUM"
            self.emit.warn(f"[CORS:{sev}] {url} reflects origin={acao} creds={acac}")

# =================================================
# GRAPHQL PROBER
# =================================================

GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name fields { name } } } }"}'
GRAPHQL_PATHS = ["/graphql","/api/graphql","/gql","/query","/v1/graphql","/graphiql"]

async def probe_graphql(session, base_url: str, store: InMemoryStore,
                        emit, rate_limiter: DomainRateLimiter):
    for path in GRAPHQL_PATHS:
        url = urljoin(base_url, path)
        s, hdrs, text = await fetch_with_retry(
            session, "POST", url, rate_limiter,
            data=GRAPHQL_INTROSPECTION,
            headers={"Content-Type": "application/json"})
        if s and s < 400 and '"__schema"' in (text or ""):
            emit.warn(f"[GraphQL] Introspection OPEN at {url}")
            store.add_endpoint(url, method="POST", source="GraphQL_Probe",
                               confidence_increment=Confidence.CONFIRMED)
            try:
                schema = json.loads(text)
                store.graphql_schemas.append({"url": url, "schema": schema})
                types = schema.get("data",{}).get("__schema",{}).get("types",[])
                emit.warn(f"[GraphQL] {len(types)} types exposed — introspection should be disabled")
            except json.JSONDecodeError:
                pass
            break  # Found it, stop checking

# =================================================
# OPENAPI / SWAGGER PROBER
# =================================================

OPENAPI_PATHS = [
    "/swagger.json","/swagger/v1/swagger.json",
    "/api-docs","/api-docs.json",
    "/openapi.json","/openapi.yaml","/openapi/v3/api-docs",
    "/v1/swagger.json","/v2/swagger.json","/v3/api-docs",
    "/.well-known/openapi",
]

async def probe_openapi(session, base_url: str, store: InMemoryStore,
                        emit, rate_limiter: DomainRateLimiter):
    for path in OPENAPI_PATHS:
        url = urljoin(base_url, path)
        s, _, text = await fetch_with_retry(session, "GET", url, rate_limiter)
        if s != 200 or not text:
            continue
        try:
            spec = json.loads(text)
        except json.JSONDecodeError:
            continue
        if "paths" not in spec and "swagger" not in spec and "openapi" not in spec:
            continue

        emit.warn(f"[OpenAPI] Spec exposed at {url} — full endpoint map available")
        store.openapi_specs.append({"url": url})
        server_base = ""
        for server in spec.get("servers", []):
            server_base = server.get("url","")
            break

        for ep_path, methods in spec.get("paths", {}).items():
            for method, details in methods.items():
                if method.lower() in ("get","post","put","patch","delete","head"):
                    full = urljoin(base_url, (server_base + ep_path).replace("{","").replace("}",""))
                    params = [
                        p.get("name","") for p in details.get("parameters",[])
                        if p.get("name")
                    ]
                    body_params = []
                    rb = details.get("requestBody",{}).get("content",{})
                    for ct, ct_data in rb.items():
                        schema = ct_data.get("schema",{})
                        body_params += list(schema.get("properties",{}).keys())

                    store.add_endpoint(full, method=method.upper(), source="OpenAPI",
                                       params=params + body_params,
                                       confidence_increment=Confidence.CONFIRMED)
                    emit.info(f"[OpenAPI] {method.upper()} {full} ({len(params+body_params)} params)")
        break  # First spec found is enough

# =================================================
# CORE SPIDER
# =================================================

class AutonomousSpider:
    def __init__(self, target_url: str, emit, options: dict = None):
        self.target_url  = target_url
        self.emit        = emit
        self.options     = options or {}
        self.base_domain = urlparse(target_url).netloc
        self.store       = InMemoryStore()
        self.visited     = set()
        self.queue       = asyncio.Queue()
        self.queue.put_nowait((target_url, 0, "Root"))

        # Build config
        self.config = DEFAULT_CONFIG.copy()
        for k in ("concurrency","timeout","max_retries","max_urls_per_depth","max_depth","verbose"):
            if k in self.options:
                self.config[k] = self.options[k]
        validate_config(self.config)

        # Wrap emit with verbosity control
        # From this point, self.emit is always a VerboseEmit instance
        self.emit = VerboseEmit(emit, verbose=self.config["verbose"])

        self.sem          = asyncio.Semaphore(self.config["concurrency"])
        self.rate_limiter = DomainRateLimiter(base_delay=0.05)
        self._depth_counts: Dict[int, int] = defaultdict(int)

        # --- Auth setup ---
        raw_cookie  = self.options.get("cookie")
        raw_auth    = self.options.get("auth")  # alias
        cookie_src  = raw_cookie or raw_auth
        self.cookies = SessionManager.parse(cookie_src)
        self.extra_headers = SessionManager.parse_extra_headers(
            self.options.get("headers", {}))

        if self.cookies:
            self.emit.always_info(f"[Auth] Session cookies loaded: {list(self.cookies.keys())}")
        elif "Authorization" in self.extra_headers:
            self.emit.info("[Auth] Authorization header loaded")
        else:
            self.emit.info("[Auth] No credentials — unauthenticated crawl")

    # ---- helpers ----

    def is_valid(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.netloc != self.base_domain:
            return False
        if any(url.lower().endswith(ext) for ext in self.config["extensions_to_ignore"]):
            return False
        return True

    def _over_budget(self, depth: int) -> bool:
        return self._depth_counts[depth] >= self.config["max_urls_per_depth"]

    def detect_tech(self, headers: dict, url: str, body: str = ""):
        tech = set()
        s = (headers.get("Server","") or headers.get("server","")).lower()
        x = (headers.get("X-Powered-By","") or headers.get("x-powered-by","")).lower()
        ct = (headers.get("Content-Type","") or "").lower()

        if "php"          in x:                    tech.add("PHP")
        if "express"      in x:                    tech.add("Node.js/Express")
        if "asp.net"      in x:                    tech.add("ASP.NET")
        if "django"       in (headers.get("X-Framework","") or "").lower(): tech.add("Django")
        if "nginx"        in s:                    tech.add("Nginx")
        if "apache"       in s:                    tech.add("Apache")
        if "cloudflare"   in s:                    tech.add("Cloudflare")
        if "socket.io"    in url.lower():           tech.add("Socket.IO")
        if "__next"       in body or "_next" in body: tech.add("Next.js")
        if "wp-content"   in body:                 tech.add("WordPress")
        if "Drupal"       in body:                 tech.add("Drupal")
        if "X-Shopify-Stage" in headers:           tech.add("Shopify")

        for t in tech:
            self.store.add_tech(t)
        if tech:
            self.emit.always_info(f"[Tech] {', '.join(sorted(tech))}")

    async def check_sourcemap(self, session, js_url: str):
        map_url = js_url + ".map"
        s, _, _ = await fetch_with_retry(session, "GET", map_url, self.rate_limiter)
        if s == 200:
            self.emit.warn(f"[SourceMap] Exposed: {map_url}")
            self.store.add_sourcemap(map_url, js_url)

    async def parse_sitemap(self, session, sitemap_url: str):
        if not self.is_valid(sitemap_url):
            return
        s, _, text = await fetch_with_retry(session, "GET", sitemap_url, self.rate_limiter)
        if s != 200 or not text:
            return
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for loc in root.findall("sm:sitemap/sm:loc", ns):
            await self.parse_sitemap(session, loc.text)
        count = 0
        for loc in root.findall("sm:url/sm:loc", ns):
            url = loc.text
            if url and self.is_valid(url):
                self.queue.put_nowait((url, 1, "Sitemap"))
                self.store.add_endpoint(url, source="Sitemap",
                                        confidence_increment=Confidence.LOW)
                count += 1
        if count:
            self.emit.info(f"[Sitemap] Added {count} URLs")

    async def check_robots(self, session) -> float:
        """Returns Crawl-delay (seconds) if found."""
        robots_url  = urljoin(self.target_url, "/robots.txt")
        crawl_delay = 0.0
        s, _, text  = await fetch_with_retry(session, "GET", robots_url, self.rate_limiter)
        if s != 200 or not text:
            return crawl_delay
        for line in text.splitlines():
            line = line.strip()
            lower = line.lower()
            if lower.startswith("crawl-delay:"):
                try:
                    crawl_delay = float(line.split(":", 1)[1].strip())
                    self.emit.always_info(f"[Robots] Crawl-delay: {crawl_delay}s — honouring")
                except ValueError:
                    pass
            elif lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    full = urljoin(self.target_url, path)
                    if self.is_valid(full):
                        self.queue.put_nowait((full, 1, "Robots"))
                        self.store.add_robots_entry(full)
            elif lower.startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                await self.parse_sitemap(session, sitemap)
        return crawl_delay

    async def playwright_scan(self):
        if not PLAYWRIGHT_AVAILABLE or not self.config["enable_playwright"]:
            return
        self.emit.info("[Playwright] Launching headless browser…")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                ctx_opts: dict = {}
                if self.cookies:
                    ctx_opts["extra_http_headers"] = {
                        "Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())
                    }
                if self.extra_headers:
                    ctx_opts.setdefault("extra_http_headers", {}).update(self.extra_headers)

                context = await browser.new_context(**ctx_opts)
                page    = await context.new_page()

                async def handle_request(req):
                    url = req.url
                    if req.resource_type in ("fetch","xhr","websocket"):
                        auth = any(h in (req.headers or {})
                                   for h in ("authorization","cookie","x-auth-token"))
                        self.store.add_endpoint(
                            url, method=req.method, source="Playwright_Dynamic",
                            confidence_increment=Confidence.CONFIRMED,
                            auth_required=auth)
                        self.emit.success(f"[Dynamic] {req.method} {url}")
                    elif req.resource_type == "script" and self.is_valid(url):
                        self.queue.put_nowait((url, 1, "Playwright_Script"))

                page.on("request", handle_request)
                await page.goto(self.target_url, wait_until="networkidle", timeout=15000)
                try:
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await asyncio.sleep(1)
                    btn = page.locator("button").first
                    if await btn.is_visible():
                        await btn.click()
                        await asyncio.sleep(1)
                except Exception:
                    pass
                await browser.close()
        except Exception as e:
            self.emit.warn(f"[Playwright] Error: {e}")

    # ---- worker ----

    async def worker(self, session, worker_id: int, crawl_delay: float):
        while True:
            item_acquired = False
            try:
                async with self.sem:
                    try:
                        url, depth, source = await asyncio.wait_for(
                            self.queue.get(), timeout=3.0)
                        item_acquired = True
                    except asyncio.TimeoutError:
                        break

                    norm = normalize_url(url)
                    if norm in self.visited \
                       or depth > self.config["max_depth"] \
                       or self._over_budget(depth):
                        pass  # skip — task_done called in finally
                    else:
                        self.visited.add(norm)
                        self._depth_counts[depth] += 1

                        status, headers, text = await fetch_with_retry(
                            session, "GET", url, self.rate_limiter,
                            max_retries=self.config["max_retries"],
                            base_delay=self.config["retry_base_delay"])

                        if status is None or text is None:
                            pass  # network failure — skip
                        else:
                            self.store.record_status(url, "GET", status)

                            # Auth-wall detection
                            if status in (401, 403):
                                self.store.add_endpoint(
                                    url, source=source,
                                    confidence_increment=Confidence.MEDIUM,
                                    auth_required=True)
                                self.emit.always_info(f"[Auth-wall:{status}] {url}")
                            elif status == 200:
                                if depth == 0 or source == "Root":
                                    self.detect_tech(headers, url, text)
                                    Extractor.parse_csp_endpoints(headers, url, self.store, self.emit)

                                ct = (headers.get("Content-Type","") or
                                      headers.get("content-type","")).lower()

                                if "text/html" in ct:
                                    self.store.add_endpoint(
                                        url, source=f"HTML({source})",
                                        confidence_increment=Confidence.MEDIUM)
                                    soup = BeautifulSoup(text, "html.parser")
                                    Extractor.extract_comments(soup, url, self.store, self.emit)

                                    for a in soup.find_all("a", href=True):
                                        href = urljoin(url, a["href"])
                                        if self.is_valid(href):
                                            self.queue.put_nowait((href, depth+1, "Link"))

                                    for form in soup.find_all("form"):
                                        action = form.get("action") or url
                                        full   = urljoin(url, action)
                                        method = form.get("method","POST").upper()
                                        inputs = [i.get("name") for i in
                                                  form.find_all(["input","select","textarea"])
                                                  if i.get("name")]
                                        if inputs:
                                            self.emit.info(
                                                f"[Form] {method} {full} ({', '.join(inputs)})")
                                        self.store.add_endpoint(
                                            full, method=method, source="Form",
                                            params=inputs or [],
                                            confidence_increment=Confidence.HIGH)

                                elif "javascript" in ct or url.endswith(".js"):
                                    self.store.add_endpoint(
                                        url, source="JS_File",
                                        confidence_increment=Confidence.LOW)
                                    Extractor.extract_secrets(text, url, self.store, self.emit)
                                    Extractor.extract_js_endpoints(text, url, self.store, self.emit)
                                    Extractor.extract_js_params(text, url, self.store, self.emit)
                                    await self.check_sourcemap(session, url)

                                elif "json" in ct:
                                    self.store.add_endpoint(
                                        url, source="JSON_Response",
                                        confidence_increment=Confidence.MEDIUM)

            except Exception:
                pass
            finally:
                if item_acquired:
                    self.queue.task_done()
                if item_acquired and crawl_delay > 0:
                    await asyncio.sleep(crawl_delay)
                elif item_acquired:
                    await asyncio.sleep(random.uniform(
                        self.config["jitter_min"], self.config["jitter_max"]))

    # ---- run ----

    async def run(self):
        req_headers = {"User-Agent": self.config["user_agent"]}
        req_headers.update(self.extra_headers)

        connector = aiohttp.TCPConnector(limit=self.config["concurrency"], ttl_dns_cache=300)
        timeout   = aiohttp.ClientTimeout(total=self.config["timeout"])

        async with aiohttp.ClientSession(
            headers=req_headers,
            cookies=self.cookies,
            timeout=timeout,
            connector=connector
        ) as session:
            crawl_delay = await self.check_robots(session)

            if self.config["enable_graphql_probe"]:
                await probe_graphql(session, self.target_url, self.store,
                                    self.emit, self.rate_limiter)

            if self.config["enable_openapi_probe"]:
                await probe_openapi(session, self.target_url, self.store,
                                    self.emit, self.rate_limiter)

            await self.playwright_scan()

            self.emit.always_info(f"[Spider] Crawling started (depth={self.config['max_depth']}, "
                           f"concurrency={self.config['concurrency']}, "
                           f"authenticated={'yes' if self.cookies or self.extra_headers else 'no'})…")

            tasks = [asyncio.create_task(self.worker(session, i, crawl_delay))
                     for i in range(self.config["concurrency"])]
            await self.queue.join()
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

            if self.config["enable_probing"]:
                prober = IntelligentProber(session, self.store, self.emit,
                                           self.rate_limiter, self.config)
                await prober.run()

# =================================================
# FRAMEWORK ENTRY POINT
# =================================================

def run(target: str, emit, options: dict = None, stop_check=None, pause_check=None):
    """
    options keys (all optional):
      cookie         : str | dict | file_path  — session cookie(s)
      auth           : alias for cookie
      headers        : dict — extra headers (Authorization, X-API-Key, etc.)
      concurrency    : int
      timeout        : int
      max_depth      : int
      max_retries    : int
      enable_probing : bool
      verbose        : bool  — False (default): clean output, only critical findings + summary
                               True: full debug logs for every discovery event
      output_format  : "json" | "jsonl" | "csv" | "burp"
      output_file    : str — path to save report
    """
    if not target.startswith("http"):
        target = "https://" + target

    verbose = (options or {}).get("verbose", False)
    mode_label = "verbose" if verbose else "clean"
    if verbose:
        emit.info(f"Hellhound Spider v{VERSION} — target: {target} — mode: verbose")
    else:
        emit.success(f"Hellhound Spider v{VERSION} — target locked")
    start_time = time.time()

    spider: Optional[AutonomousSpider] = None
    try:
        spider = AutonomousSpider(target, emit, options or {})
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(spider.run())
    except KeyboardInterrupt:
        emit.warn("Interrupted by user.")
    except ValueError as e:
        emit.warn(f"Config error: {e}")
        return {"raw": str(e), "intel": {}}
    except Exception as e:
        emit.warn(f"Spider error: {e}")

    if spider is None:
        return {"raw": "Spider failed to initialize.", "intel": {}}

    elapsed     = time.time() - start_time
    fmt         = (options or {}).get("output_format","json")
    report_data = spider.store.export(target, fmt=fmt)
    report_dict = spider.store.export(target, fmt="json")  # always keep dict version

    # Save to file if requested
    output_file = (options or {}).get("output_file")
    if output_file:
        try:
            Path(output_file).write_text(
                report_data if isinstance(report_data, str) else json.dumps(report_data, indent=2))
            emit.info(f"[Report] Saved to {output_file}")
        except Exception as e:
            emit.warn(f"[Report] Save failed: {e}")

    try:
        parsed_dict = json.loads(report_dict)
        summary     = parsed_dict["summary"]
    except Exception:
        summary = {}

    summary_str = (
        f"Target: {target} | "
        f"Time: {elapsed:.1f}s | "
        f"Endpoints: {summary.get('endpoints_count','?')} | "
        f"Confirmed: {summary.get('confirmed_count','?')} | "
        f"High: {summary.get('high_confidence_count','?')} | "
        f"Param-Sensitive: {summary.get('parameter_sensitive_count','?')} | "
        f"Auth-Walled: {summary.get('auth_required_count','?')} | "
        f"CORS Issues: {summary.get('cors_issues_count','?')} | "
        f"Secrets: {summary.get('secrets_found','?')} | "
        f"Tech: {', '.join(summary.get('tech_stack',[])) or 'unknown'}"
    )

    # Always show final summary — use raw emit (not spider's VerboseEmit)
    emit.success("Spider Scan Complete")
    emit.success(summary_str)

    return {
        "raw":   summary_str,
        "intel": json.loads(report_dict) if isinstance(report_dict, str) else report_dict
    }