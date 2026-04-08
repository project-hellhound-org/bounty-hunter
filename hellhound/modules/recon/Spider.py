#!/usr/bin/env python3
"""
SPIDER - Hellhound Recon Brain v12.0 (Framework Module Edition)
Full SPA + Non-SPA Crawler | robots.txt | sitemap.xml | JS Analysis

Converted from v11.2 standalone to Hellhound module interface.
All crawling logic, intelligence extraction, and probing are preserved exactly.
CLI dependencies removed. Findings suppressed from output; stored in intel only.
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
from datetime import datetime, timezone
from http.cookiejar import MozillaCookieJar
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

from bs4 import BeautifulSoup, Comment
from hellhound.core import http_utils

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ══════════════════════════════════════════════════════════════════════
# METADATA
# ══════════════════════════════════════════════════════════════════════

NAME        = "spider"
CATEGORY    = "recon"
VERSION     = "12.0"
DESCRIPTION = "Advanced SPA-aware crawler with API discovery and intelligence extraction"

# ══════════════════════════════════════════════════════════════════════
# OPTIONS  (replaces argparse flags — consumed by Hellhound console)
# ══════════════════════════════════════════════════════════════════════

OPTIONS = [
    {"name": "max_depth",           "type": int,  "default": 4,     "help": "Maximum crawl depth"},
    {"name": "concurrency",         "type": int,  "default": 12,    "help": "Concurrent workers"},
    {"name": "timeout",             "type": int,  "default": 15,    "help": "Per-request timeout (seconds)"},
    {"name": "max_retries",         "type": int,  "default": 3,     "help": "Max retries per request"},
    {"name": "max_urls_per_depth",  "type": int,  "default": 500,   "help": "URL budget per depth level"},
    {"name": "verbose",             "type": bool, "default": False, "help": "Show all discovery logs"},
    {"name": "cookie",              "type": str,  "default": None,  "help": "Cookie string (format: key=value; key2=value2) OR path to cookie file"},
    {"name": "auth",                "type": str,  "default": None,  "help": "Authorization header e.g. 'Bearer eyJ...'"},
    {"name": "headers",             "type": dict, "default": {},    "help": "Extra headers dict"},
    {"name": "output_format",       "type": str,  "default": "json","help": "Export format: json | jsonl | csv | burp"},
    {"name": "output_file",         "type": str,  "default": None,  "help": "Path to save report file"},
    {"name": "use_playwright",      "type": bool, "default": True,  "help": "Enable headless Chromium SPA scan"},
    {"name": "enable_spa_interact", "type": bool, "default": False, "help": "Enable SPA form filling and button clicking"},
    {"name": "enable_probing",      "type": bool, "default": True,  "help": "Enable intelligent probing phase"},
    {"name": "enable_method_disc",  "type": bool, "default": True,  "help": "Discover HTTP methods per endpoint"},
    {"name": "enable_graphql",      "type": bool, "default": True,  "help": "Probe for exposed GraphQL introspection"},
    {"name": "enable_openapi",      "type": bool, "default": True,  "help": "Probe for exposed OpenAPI/Swagger specs"},
    {"name": "enable_cors",         "type": bool, "default": True,  "help": "Check for CORS misconfigurations"},
]

# ══════════════════════════════════════════════════════════════════════
# STRIP ANSI HELPER
# ══════════════════════════════════════════════════════════════════════

def _strip(s: str) -> str:
    """Remove ANSI escape codes from any string."""
    return re.sub(r'\033\[[^m]*m', '', s)

# ══════════════════════════════════════════════════════════════════════
# MODULE EMIT WRAPPER
# Only progress/lifecycle shown. Findings suppressed — intel only.
# verbose=False : phase headers + summaries only
# verbose=True  : all internal discovery progress logs
# ══════════════════════════════════════════════════════════════════════

class ModuleEmit:
    """
    Adapts Hellhound's base emit object to the spider's internal emit API.

    .info()           — gated behind verbose flag (noisy discovery detail)
    .success()        — gated behind verbose flag (minor hits)
    .warn()           — SUPPRESSED: findings go to intel, not output
    .always_info()    — always shown (phase headers, auth, lifecycle)
    .always_success() — always shown (phase completions, final summary)
    .section()        — always shown as a phase divider
    .row()            — gated behind verbose flag
    .finding()        — SUPPRESSED: goes to intel only
    .endpoint_row()   — SUPPRESSED: goes to intel only
    .print_always()   — always shown
    ._nc              — always True (no ANSI codes in module context)
    """

    def __init__(self, base_emit, verbose: bool):
        self._base    = base_emit
        self._verbose = verbose

    def info(self, msg: str):
        if self._verbose:
            self._base.info(msg)

    def success(self, msg: str):
        if self._verbose:
            self._base.success(_strip(msg))

    def warn(self, msg: str):
        # All findings go to intel via the store. No console output.
        pass

    def always_info(self, msg: str):
        self._base.info(_strip(msg))

    def always_success(self, msg: str):
        self._base.success(_strip(msg))

    def section(self, title: str):
        self._base.section(_strip(title))

    def row(self, label: str, value, **kw):
        if self._verbose:
            self._base.info(f"{label}: {_strip(str(value))}")

    def finding(self, *args):
        # Findings suppressed — stored in intel via the store.
        pass

    def endpoint_row(self, ep: dict):
        # Suppressed — endpoints returned in intel dict.
        pass

    def print_always(self, msg: str):
        self._base.info(_strip(msg))


# ══════════════════════════════════════════════════════════════════════
# CONFIDENCE
# ══════════════════════════════════════════════════════════════════════

class Conf:
    LOW       = 1
    MEDIUM    = 3
    HIGH      = 6
    CONFIRMED = 10

    @staticmethod
    def label(score: int) -> str:
        if score >= Conf.CONFIRMED: return "CONFIRMED"
        if score >= Conf.HIGH:      return "HIGH"
        if score >= Conf.MEDIUM:    return "MEDIUM"
        return "LOW"

# ══════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════

class Config:
    def __init__(self, **kw):
        self.max_depth           = kw.get("max_depth",           4)
        self.concurrency         = kw.get("concurrency",         12)
        self.timeout             = kw.get("timeout",             15)
        self.max_retries         = kw.get("max_retries",         3)
        self.retry_base_delay    = kw.get("retry_base_delay",    0.5)
        self.max_urls_per_depth  = kw.get("max_urls_per_depth",  500)
        self.jitter_min          = kw.get("jitter_min",          0.05)
        self.jitter_max          = kw.get("jitter_max",          0.35)
        self.verbose             = kw.get("verbose",             False)
        self.use_playwright      = kw.get("use_playwright",      True)
        self.enable_spa_interact = kw.get("enable_spa_interact", False)
        self.enable_probing      = kw.get("enable_probing",      True)
        self.enable_method_disc  = kw.get("enable_method_disc",  True)
        self.enable_graphql      = kw.get("enable_graphql",      True)
        self.enable_openapi      = kw.get("enable_openapi",      True)
        self.enable_cors         = kw.get("enable_cors",         True)
        self.output_format       = kw.get("output_format",       "json")
        self.output_file: Optional[str] = kw.get("output_file", None)
        self.user_agent = kw.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        )
        self.extensions_to_ignore: List[str] = kw.get("extensions_to_ignore", [
            ".png",".jpg",".jpeg",".gif",".ico",".svg",".webp",
            ".woff",".woff2",".ttf",".eot",".css",
            ".mp4",".mp3",".avi",".mov",".webm",
            ".zip",".gz",".tar",".rar",".pdf",".exe",".dmg",".apk",
        ])

    def validate(self):
        if not (0 <= self.max_depth <= 20):
            raise ValueError("max_depth must be 0-20")
        if not (1 <= self.concurrency <= 100):
            raise ValueError("concurrency must be 1-100")

# ══════════════════════════════════════════════════════════════════════
# SESSION / COOKIE MANAGER
# ══════════════════════════════════════════════════════════════════════

class SessionManager:
    @staticmethod
    def parse_cookies(raw) -> Dict[str, str]:
        if not raw:
            return {}
        if isinstance(raw, dict):
            if any(k.lower() in ("authorization","x-api-key","x-auth-token") for k in raw):
                return {}
            return raw
        if isinstance(raw, str):
            raw = raw.strip()
            _looks_like_path = (
                len(raw) <= 255
                and " " not in raw
                and ("/" in raw or raw.endswith((".txt", ".json")))
            )
            if _looks_like_path:
                try:
                    p = Path(raw)
                    if p.exists() and p.is_file():
                        return SessionManager._load_file(p)
                except OSError:
                    pass
            out: Dict[str, str] = {}
            for part in raw.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    k = k.strip(); v = v.strip()
                    if k:
                        out[k] = v
            return out
        return {}

    @staticmethod
    def _load_file(path: Path) -> Dict[str, str]:
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                return {c["name"]: c["value"] for c in data if "name" in c and "value" in c}
        except Exception:
            pass
        try:
            jar = MozillaCookieJar(str(path))
            jar.load(ignore_discard=True, ignore_expires=True)
            return {c.name: c.value for c in jar}
        except Exception:
            pass
        return {}

    @staticmethod
    def parse_auth_header(raw) -> Dict[str, str]:
        if not raw:
            return {}
        if isinstance(raw, dict):
            return {k: v for k, v in raw.items()
                    if k.lower() in ("authorization","x-api-key","x-auth-token",
                                     "x-csrf-token","x-access-token")}
        if isinstance(raw, str):
            raw = raw.strip()
            if re.match(r'^(Bearer|Basic|Token)\s+\S+', raw, re.I):
                return {"Authorization": raw}
        return {}

# ══════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ══════════════════════════════════════════════════════════════════════

class DomainRateLimiter:
    def __init__(self, base_delay: float = 0.05):
        self._delays: Dict[str, float] = defaultdict(lambda: base_delay)
        self._locks:  Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def wait(self, domain: str):
        async with self._locks[domain]:
            await asyncio.sleep(self._delays[domain])

    def backoff(self, domain: str):
        self._delays[domain] = min(self._delays[domain] * 2.0, 10.0)

    def recover(self, domain: str):
        self._delays[domain] = max(self._delays[domain] * 0.9, 0.03)

# ══════════════════════════════════════════════════════════════════════
# FETCH HELPER
# ══════════════════════════════════════════════════════════════════════

async def fetch(session, method, url, rl, max_retries=3, base_delay=0.5, proxy=None, **kw):
    if proxy is None and hasattr(session, "_hellhound_proxy"):
        proxy = session._hellhound_proxy
    domain = urlparse(url).netloc
    await rl.wait(domain)
    for attempt in range(max_retries + 1):
        try:
            async with session.request(method, url, ssl=False, proxy=proxy, **kw) as resp:
                if resp.status == 429:
                    rl.backoff(domain)
                    await asyncio.sleep(float(resp.headers.get("Retry-After", base_delay * (2**attempt))))
                    continue
                body = await resp.text(errors="replace")
                rl.recover(domain)
                return resp.status, dict(resp.headers), body
        except Exception:
            if attempt < max_retries:
                await asyncio.sleep(base_delay * (2**attempt))
    return None, None, None

# ══════════════════════════════════════════════════════════════════════
# URL UTILITIES
# ══════════════════════════════════════════════════════════════════════

_ID_RE = re.compile(
    r'^(?:\d{1,20}'
    r'|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    r'|[0-9a-fA-F]{24}'
    r'|[0-9a-zA-Z]{20,}'
    r')$',
    re.I
)

def normalize(url: str) -> str:
    try:
        p  = urlparse(url)
        qs = urlencode(sorted(parse_qs(p.query, keep_blank_values=True).items()), doseq=True)
        return urlunparse((p.scheme.lower(), p.netloc.lower(),
                           p.path.rstrip("/") or "/", p.params, qs, ""))
    except Exception:
        return url

def cluster(url: str) -> str:
    try:
        p    = urlparse(url)
        segs = ["{id}" if _ID_RE.match(s) else s for s in p.path.split("/")]
        return urlunparse((p.scheme, p.netloc, "/".join(segs), "", "", ""))
    except Exception:
        return url

# ══════════════════════════════════════════════════════════════════════
# DATA STORE
# ══════════════════════════════════════════════════════════════════════

class Store:
    def __init__(self):
        self.endpoints:    Dict[str, dict] = {}
        self.comments:     List[dict]       = []
        self.secrets:      List[dict]       = []
        self.tech_stack:   Set[str]         = set()
        self.robots_paths: List[str]        = []
        self.cors_issues:  List[dict]       = []
        self.graphql:      List[dict]       = []
        self.openapi:      List[dict]       = []
        self.sourcemaps:   List[dict]       = []
        self.well_known:   List[dict]       = []

    def _key(self, url, method):
        return f"{method.upper()}:{cluster(normalize(url))}"

    def _new_ep(self, url, method):
        return {
            "url": url, "cluster": cluster(normalize(url)),
            "methods": [method.upper()],
            "params": {"query":[],"form":[],"js":[],"openapi":[],"runtime":[]},
            "observed_values": {},
            "headers": {},
            "source": [], "confidence": 0, "confidence_label": "LOW",
            "auth_required": False, "parameter_sensitive": False,
            "observed_status": [], "baseline": None,
        }

    def add_endpoint(self, url, method="GET", source="Static",
                     params=None, score=Conf.LOW, auth_required=False):
        key = self._key(url, method)
        if key not in self.endpoints:
            self.endpoints[key] = self._new_ep(url, method)
        ep = self.endpoints[key]
        if source not in ep["source"]:
            ep["source"].append(source)
        ep["confidence"]       = min(ep["confidence"] + score, Conf.CONFIRMED)
        ep["confidence_label"] = Conf.label(ep["confidence"])
        if auth_required:
            ep["auth_required"] = True
        if params:
            if source == "OpenAPI":
                bucket = "openapi"
            elif source == "Form":
                bucket = "form"
            elif source.startswith("JS_") or source in ("SPA_XHR", "SPA_DOM"):
                bucket = "js"
            else:
                bucket = "runtime"
            for p in params:
                if p and p not in ep["params"][bucket]:
                    ep["params"][bucket].append(p)
        return ep

    _HEADER_SKIP = frozenset({
        "accept", "accept-encoding", "accept-language", "cache-control",
        "connection", "host", "origin", "pragma", "referer",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
        "upgrade-insecure-requests", "user-agent",
    })

    def merge_headers(self, url: str, method: str, headers: dict) -> bool:
        if not headers:
            return False
        key = self._key(url, method)
        if key not in self.endpoints:
            return False
        ep    = self.endpoints[key]
        added = False
        for k, v in headers.items():
            lo = k.lower()
            if lo in self._HEADER_SKIP:
                continue
            if lo not in ep["headers"]:
                ep["headers"][lo] = v
                added = True
        return added

    def add_js_params(self, url, params):
        key = self._key(url, "GET")
        if key not in self.endpoints:
            self.endpoints[key] = self._new_ep(url, "GET")
        ep  = self.endpoints[key]
        new = [p for p in params if p not in ep["params"]["js"]]
        ep["params"]["js"].extend(new)
        if new:
            ep["confidence"] = min(ep["confidence"] + 1, Conf.CONFIRMED)
            ep["confidence_label"] = Conf.label(ep["confidence"])
        return bool(new)

    _RISK_PARAMS = frozenset({
        "cmd","command","exec","run","shell","host","hostname","ip","addr","address",
        "url","uri","target","dest","src","source","file","path","dir","query","q",
        "search","input","arg","id","key","token","user","pass","passwd","password",
    })
    _PARAM_SUFFIXES = ("_raw","_sanitized","_input","_clean","_safe","_encoded","_value","_param")

    def add_runtime_params(self, url: str, method: str, names: List[str]) -> bool:
        key = self._key(url, method)
        if key not in self.endpoints:
            return False
        ep = self.endpoints[key]
        sanitization_seen = False
        added = []
        for raw_name in names:
            if not raw_name:
                continue
            base = raw_name
            is_suffixed = False
            for suf in self._PARAM_SUFFIXES:
                if raw_name.endswith(suf):
                    base = raw_name[: -len(suf)]
                    is_suffixed = True
                    break
            if is_suffixed:
                sanitization_seen = True
            if base and base not in ep["params"]["runtime"]:
                ep["params"]["runtime"].append(base)
                added.append(base)
        if added:
            ep["confidence"] = min(ep["confidence"] + 1, Conf.CONFIRMED)
            ep["confidence_label"] = Conf.label(ep["confidence"])
        if sanitization_seen:
            ep["parameter_sensitive"] = True
            ep["confidence"] = min(ep["confidence"] + 2, Conf.CONFIRMED)
            ep["confidence_label"] = Conf.label(ep["confidence"])
        return bool(added)

    def add_query_params(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return
        key = self._key(url, "GET")
        if key not in self.endpoints:
            self.endpoints[key] = self._new_ep(url, "GET")
        ep = self.endpoints[key]
        for param, values in parse_qs(parsed.query).items():
            if param not in ep["params"]["query"]:
                ep["params"]["query"].append(param)
            if values:
                existing = ep["observed_values"].setdefault(param, [])
                for v in values:
                    if v and v not in existing:
                        existing.append(v)

    def update_methods(self, url, methods):
        key = self._key(url, methods[0] if methods else "GET")
        if key not in self.endpoints:
            return
        ep = self.endpoints[key]
        for m in methods:
            if m not in ep["methods"]:
                ep["methods"].append(m)
        ep["confidence"] = min(ep["confidence"] + 1, Conf.CONFIRMED)
        ep["confidence_label"] = Conf.label(ep["confidence"])

    def record_status(self, url, method, status):
        key = self._key(url, method)
        if key in self.endpoints:
            ep = self.endpoints[key]
            if status not in ep["observed_status"]:
                ep["observed_status"].append(status)
            if status in (401, 403):
                ep["auth_required"] = True

    def mark_sensitive(self, url, method):
        key = self._key(url, method)
        if key in self.endpoints:
            ep = self.endpoints[key]
            ep["parameter_sensitive"] = True
            ep["confidence"] = min(ep["confidence"] + 2, Conf.CONFIRMED)
            ep["confidence_label"] = Conf.label(ep["confidence"])

    def add_comment(self, content, source_url):
        content = content.strip()
        if len(content) < 4 or any(c["content"] == content for c in self.comments):
            return False
        self.comments.append({"content": content, "source": source_url})
        return True

    def add_secret(self, val, stype, source_url):
        if any(s["content"] == val for s in self.secrets):
            return False
        self.secrets.append({"content": val, "type": stype, "source": source_url})
        return True

    def add_cors(self, url, origin_sent, reflected, creds):
        self.cors_issues.append({
            "url": url, "origin_sent": origin_sent, "reflected": reflected,
            "allow_credentials": creds, "severity": "HIGH" if creds else "MEDIUM"
        })

    def add_well_known(self, url, content_snippet, discovered_paths=None):
        if not any(w["url"] == url for w in self.well_known):
            self.well_known.append({
                "url": url,
                "content": content_snippet,
                "discovered_paths": discovered_paths or []
            })

    def add_sourcemap(self, map_url, parent):
        if not any(s["url"] == map_url for s in self.sourcemaps):
            self.sourcemaps.append({"url": map_url, "parent": parent})

    def all_endpoints(self):
        return [e for e in self.endpoints.values() if e["confidence"] >= Conf.LOW]

    def export(self, target, fmt="json"):
        eps  = self.all_endpoints()
        meta = {"tool": f"Hellhound Spider v{VERSION}", "target": target}
        summary = {
            "total_endpoints":     len(eps),
            "confirmed":           sum(1 for e in eps if e["confidence_label"] == "CONFIRMED"),
            "high":                sum(1 for e in eps if e["confidence_label"] == "HIGH"),
            "auth_required":       sum(1 for e in eps if e["auth_required"]),
            "parameter_sensitive": sum(1 for e in eps if e["parameter_sensitive"]),
            "secrets":             len(self.secrets),
            "cors_issues":         len(self.cors_issues),
            "graphql_exposed":     len(self.graphql),
            "openapi_exposed":     len(self.openapi),
            "sourcemaps_exposed":  len(self.sourcemaps),
            "tech_stack":          sorted(self.tech_stack),
        }
        data = {
            "meta": meta, "summary": summary, "endpoints": eps,
            "secrets": self.secrets, "cors_issues": self.cors_issues,
            "graphql": self.graphql, "openapi": self.openapi,
            "sourcemaps": self.sourcemaps, "comments": self.comments,
            "robots_disallowed": self.robots_paths,
            "well_known": self.well_known,
            "tech_stack": sorted(self.tech_stack),
        }

        if fmt == "json":
            return json.dumps(data, indent=2)

        if fmt == "jsonl":
            lines = [json.dumps({"type":"meta","data":meta}),
                     json.dumps({"type":"summary","data":summary})]
            for ep in eps:
                lines.append(json.dumps({"type":"endpoint","data":ep}))
            return "\n".join(lines)

        if fmt == "csv":
            buf = io.StringIO()
            w   = csv.writer(buf)
            w.writerow(["url","cluster","methods","confidence","auth_required",
                         "param_sensitive","sources","query_params","form_params",
                         "js_params","openapi_params","status_codes","headers"])
            for ep in eps:
                w.writerow([ep["url"], ep["cluster"], "|".join(ep["methods"]),
                             ep["confidence_label"], ep["auth_required"],
                             ep["parameter_sensitive"], "|".join(ep["source"]),
                             "|".join(ep["params"].get("query",[])),
                             "|".join(ep["params"].get("form",[])),
                             "|".join(ep["params"].get("js",[])),
                             "|".join(ep["params"].get("openapi",[])),
                             "|".join(str(s) for s in ep.get("observed_status",[])),
                             json.dumps(ep.get("headers", {}))])
            return buf.getvalue()

        if fmt == "burp":
            root = ET.Element("items", burpVersion="2.0",
                              exportTime=datetime.now(timezone.utc).isoformat())
            for ep in eps:
                item = ET.SubElement(root, "item")
                ET.SubElement(item, "url").text          = ep["url"]
                ET.SubElement(item, "method").text       = ep["methods"][0]
                ET.SubElement(item, "confidence").text   = ep["confidence_label"]
                ET.SubElement(item, "authRequired").text = str(ep["auth_required"])
                ET.SubElement(item, "params").text       = json.dumps(ep["params"])
                ET.SubElement(item, "headers").text      = json.dumps(ep.get("headers", {}))
            return ET.tostring(root, encoding="unicode", xml_declaration=True)

        return json.dumps(data, indent=2)

# ══════════════════════════════════════════════════════════════════════
# DIFF ENGINE
# ══════════════════════════════════════════════════════════════════════

def diff_crawls(old_json: str, new_json: str) -> dict:
    old = json.loads(old_json); new = json.loads(new_json)
    om  = {e["cluster"]: e for e in old.get("endpoints",[])}
    nm  = {e["cluster"]: e for e in new.get("endpoints",[])}
    ok, nk = set(om), set(nm)
    added   = [nm[k] for k in (nk - ok)]
    removed = [om[k] for k in (ok - nk)]
    changed = []
    for k in ok & nk:
        o, n = om[k], nm[k]; diff: dict = {}
        if set(o["methods"]) != set(n["methods"]):
            diff["methods"] = {"old": o["methods"], "new": n["methods"]}
        if o["confidence_label"] != n["confidence_label"]:
            diff["confidence"] = {"old": o["confidence_label"], "new": n["confidence_label"]}
        if o["auth_required"] != n["auth_required"]:
            diff["auth_required"] = {"old": o["auth_required"], "new": n["auth_required"]}
        if diff: changed.append({"cluster": k, "url": n["url"], "changes": diff})
    return {"old_target": old.get("meta",{}).get("target"),
            "new_target": new.get("meta",{}).get("target"),
            "added": added, "removed": removed, "changed": changed,
            "summary": {"added": len(added), "removed": len(removed), "changed": len(changed)}}

# ══════════════════════════════════════════════════════════════════════
# EXTRACTORS
# ══════════════════════════════════════════════════════════════════════

class Extractor:
    _JS_NOISE = {
        "console","window","document","return","function","const","let","var",
        "this","class","import","export","default","null","undefined","true",
        "false","new","async","await","try","catch","if","else","for","while",
        "switch","case","break","continue","typeof","instanceof","void","delete",
    }
    _PARAM_RE = [
        r'body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]{1,400})\}',
        r'axios\.(?:post|put|patch)\s*\([^,]{1,120},\s*\{([^}]{1,400})\}',
        r'(?:data|payload|body)\s*:\s*\{([^}]{1,400})\}',
        r'params\s*:\s*\{([^}]{1,400})\}',
        r'new\s+URLSearchParams\s*\(\s*\{([^}]{1,400})\}',
        r'FormData\s*\(\s*\)\s*;(?:[^}]{0,200}\.append\s*\(\s*["\']([^"\']+)["\'])',
    ]
    _SECRET_RE = [
        (r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b',                       "Bitcoin_Address"),
        (r'\b(0x[a-fA-F0-9]{40})\b',                                      "Ethereum_Address"),
        (r'(AIza[0-9A-Za-z\-_]{35})',                                     "Google_API_Key"),
        (r'(AKIA[0-9A-Z]{16})',                                            "AWS_Access_Key"),
        (r'Bearer\s+([a-zA-Z0-9\-._~+/]{20,}=*)',                         "Bearer_Token"),
        (r'["\']sk-[a-zA-Z0-9]{20,}["\']',                                "Stripe_Key"),
        (r'gh[pousr]_[A-Za-z0-9_]{36,}',                                  "GitHub_PAT"),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                      "Private_Key_PEM"),
        (r'["\'](?:password|passwd|secret|api_?key|token)\s*["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
                                                                           "Hardcoded_Credential"),
        (r'["\']([0-9a-fA-F]{32})["\']',                                  "Possible_MD5"),
    ]
    _API_RE = [
        r'["\']([/][a-zA-Z0-9_\-\.\/]*(?:api|v\d+|graphql|admin|auth|login|logout|rest|search|data|internal|upload|download|config|settings|user|profile|account|msg|post|comment|item|product|cart|checkout|pay|order|invoice|report|log|status|health|healthcheck|metrics|debug|test|dev|internal|hidden)[a-zA-Z0-9_\-\.\/]*(?:\?[^"\'#\s]*)?)["\']',
        r'(?:fetch|axios|request|api|service)\s*\(\s*["\']([^"\'#\s]{5,})["\']',
        r'\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\'#\s]{5,})["\']',
        r'`\$\{[^}]+\}(/[a-zA-Z0-9_\-\/]+(?:\?[^`#\s]*)?)`',
        r'(?:path|route|url|endpoint|action|href)\s*[:=]\s*["\']([/][^"\'#\s]{3,})["\']',
        r'["\']((?:https?://|//)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[a-zA-Z0-9_\-\.\/]*)*)["\']',
    ]

    @classmethod
    def _obj_keys(cls, block):
        keys = re.findall(r'["\']?([a-zA-Z_$][a-zA-Z0-9_$]*)["\']?\s*:', block)
        return [k for k in keys if k not in cls._JS_NOISE and len(k) > 1]

    @classmethod
    def _build_var_url_map(cls, text):
        var_map = {}
        for m in re.finditer(
            r"""(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["']([/][a-zA-Z0-9_\-\./?&=]+)["']""",
            text
        ):
            var_map[m.group(1)] = m.group(2)
        for m in re.finditer(
            r"""(?:url|endpoint|action|path|href)\s*:\s*["']([/][a-zA-Z0-9_\-\./]+)["']""",
            text
        ):
            var_map["__prop_%d" % m.start()] = m.group(1)
        return var_map

    @classmethod
    def _find_url_for_params(cls, text, match_start, match_end, base_url, var_map):
        url_lit = r"""["']([/][a-zA-Z0-9_\-\./]+(?:\?[^"'#\s]*)?)["']"""
        pre_window = text[max(0, match_start - 600): match_start]
        pre_matches = list(re.finditer(url_lit, pre_window))
        if pre_matches:
            return urljoin(base_url, pre_matches[-1].group(1).split("?")[0])
        post_window = text[match_end: match_end + 500]
        post_m = re.search(url_lit, post_window)
        if post_m:
            return urljoin(base_url, post_m.group(1).split("?")[0])
        for varname, vpath in var_map.items():
            if varname.startswith("__prop_"):
                if abs(int(varname[7:]) - match_start) <= 800:
                    return urljoin(base_url, vpath.split("?")[0])
            else:
                window = text[max(0, match_start - 800): match_end + 800]
                if re.search(r"\b" + re.escape(varname) + r"\b", window):
                    return urljoin(base_url, vpath.split("?")[0])
        return base_url

    @classmethod
    def js_params(cls, text, base_url, store, emit):
        var_map = cls._build_var_url_map(text)
        for pat in cls._PARAM_RE:
            for m in re.finditer(pat, text, re.S):
                keys = cls._obj_keys(m.group(1) if m.lastindex else m.group(0))
                if not keys:
                    continue
                turl = cls._find_url_for_params(text, m.start(), m.end(), base_url, var_map)
                if store.add_js_params(turl, keys):
                    emit.info("[JS-Params] %s -> %s" % (keys, turl))

    @classmethod
    def secrets(cls, text, url, store, emit):
        for pat, stype in cls._SECRET_RE:
            for m in re.finditer(pat, text):
                val = m.group(1) if m.lastindex else m.group(0)
                if stype not in ("Bitcoin_Address","Ethereum_Address","Private_Key_PEM",
                                  "Hardcoded_Credential","GitHub_PAT") and len(val) < 20:
                    continue
                # Stored in intel only — no output
                store.add_secret(val, stype, url)

    @classmethod
    def exposed_files(cls, text, base_url, store, emit):
        # Passive discovery of common backend/backup/config extensions
        _EXPOSED_RE = r'(?:https?://|//|/)[a-zA-Z0-9_\-\.\/]*\.(?:log|bak|sql|old|txt|zip|tar\.gz|env|json|xml|yml|yaml|ini|conf)\b'
        _seen = set()
        for m in re.finditer(_EXPOSED_RE, text, re.I):
            raw = m.group(0)
            if raw in _seen: continue
            _seen.add(raw)
            if raw.startswith("//"): full = "http:" + raw
            elif raw.startswith("/"): full = urljoin(base_url, raw)
            else: full = raw
            store.add_endpoint(full, source="Leaked_File", score=Conf.MEDIUM)
            emit.info(f"[Leaked-File] {full}")

    @classmethod
    def js_endpoints(cls, text, base_url, store, emit):
        _seen_paths: set = set()
        for pat in cls._API_RE:
            for m in re.finditer(pat, text):
                raw = m.group(1)
                if not raw or not raw.startswith("/") or len(raw) < 3:
                    continue
                _parsed    = urlparse(raw)
                _qs_params = list(parse_qs(_parsed.query).keys())
                clean_path = _parsed.path
                if not clean_path or clean_path == "/":
                    continue
                full = urljoin(base_url, clean_path)
                _dedup_key = (full, frozenset(_qs_params))
                if _dedup_key in _seen_paths:
                    continue
                _seen_paths.add(_dedup_key)
                store.add_endpoint(full, source="JS_Analysis", score=Conf.MEDIUM)
                if _qs_params:
                    store.add_js_params(full, _qs_params)
                    emit.info(f"[JS-QS-Params] {_qs_params} <- {full}")
                emit.info(f"[JS-API] {full}")

    @classmethod
    def html_comments(cls, soup, url, store, emit):
        kw = {"todo","fixme","bug","admin","hidden","secret","debug","config",
              "key","password","cred","token","hack","temp","test","internal",
              "private","disabled","api","endpoint"}
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            txt = c.strip()
            if len(txt) < 4:
                continue
            if (any(k in txt.lower() for k in kw)
                    or bool(re.match(r'^[/\.][a-z0-9_\-\.#]{3,}', txt))):
                if store.add_comment(txt, url):
                    emit.info(f"[Comment] {txt[:100]}")

    @classmethod
    def csp_hints(cls, headers, base_url, store, emit):
        csp = headers.get("Content-Security-Policy","") or headers.get("content-security-policy","")
        if not csp:
            return
        domain = urlparse(base_url).netloc
        for tok in csp.split():
            tok = tok.rstrip(";")
            if tok.startswith("/") and len(tok) > 2:
                store.add_endpoint(urljoin(base_url, tok), source="CSP", score=Conf.LOW)
            elif tok.startswith(("https://","http://")) and urlparse(tok).netloc != domain:
                emit.info(f"[CSP-3rd-party] {tok}")

# ══════════════════════════════════════════════════════════════════════
# GRAPHQL PROBER
# ══════════════════════════════════════════════════════════════════════

_GQL_PATHS = ["/graphql","/api/graphql","/gql","/query","/v1/graphql","/graphiql","/playground"]
_GQL_QUERY = '{"query":"{ __schema { queryType { name } types { name fields { name args { name } } } } }"}'

async def probe_graphql(session, base, store, emit, rl):
    emit.section("GraphQL Introspection Probe")
    for path in _GQL_PATHS:
        url = urljoin(base, path)
        s, _, text = await fetch(session, "POST", url, rl, data=_GQL_QUERY,
                                  headers={"Content-Type": "application/json"})
        if s and s < 400 and text and '"__schema"' in text:
            store.add_endpoint(url, method="POST", source="GraphQL", score=Conf.CONFIRMED)
            try:
                schema = json.loads(text)
                types  = schema.get("data",{}).get("__schema",{}).get("types",[])
                store.graphql.append({"url": url, "types_count": len(types), "schema": schema})
                emit.always_success(f"GraphQL introspection EXPOSED: {url} ({len(types)} types)")
            except Exception:
                pass
            return

# ══════════════════════════════════════════════════════════════════════
# OPENAPI PROBER
# ══════════════════════════════════════════════════════════════════════

_OAS_PATHS = [
    "/swagger.json","/swagger/v1/swagger.json","/swagger/v2/swagger.json",
    "/api-docs","/api-docs.json","/api-docs/swagger.json",
    "/openapi.json","/openapi.yaml","/openapi/v3/api-docs",
    "/v1/swagger.json","/v2/swagger.json","/v3/api-docs",
    "/.well-known/openapi","/api/swagger.json",
]

async def probe_openapi(session, base, store, emit, rl):
    emit.section("OpenAPI / Swagger Probe")
    for path in _OAS_PATHS:
        url = urljoin(base, path)
        s, _, text = await fetch(session, "GET", url, rl)
        if s != 200 or not text:
            continue
        try:
            spec = json.loads(text)
        except Exception:
            continue
        if not any(k in spec for k in ("paths","swagger","openapi")):
            continue
        store.openapi.append({"url": url})
        emit.always_success(f"OpenAPI spec EXPOSED: {url}")
        server_prefix = ""
        for srv in spec.get("servers", []):
            u = srv.get("url","")
            if not u.startswith("http"):
                server_prefix = u
            break
        count = 0
        for ep_path, methods_obj in spec.get("paths", {}).items():
            for method, detail in methods_obj.items():
                if method.lower() not in ("get","post","put","patch","delete","head","options"):
                    continue
                clean  = (server_prefix + ep_path).replace("{","").replace("}","")
                full   = urljoin(base, clean)
                params = [p.get("name","") for p in detail.get("parameters",[]) if p.get("name")]
                bp: List[str] = []
                for ct_data in detail.get("requestBody",{}).get("content",{}).values():
                    bp += list(ct_data.get("schema",{}).get("properties",{}).keys())
                store.add_endpoint(full, method=method.upper(), source="OpenAPI",
                                   params=params+bp, score=Conf.CONFIRMED)
                emit.info(f"[OpenAPI] {method.upper()} {full} ({len(params+bp)} params)")
                count += 1
        emit.always_success(f"OpenAPI: mapped {count} endpoints from spec")
        return

# ══════════════════════════════════════════════════════════════════════
# INTELLIGENT PROBER
# ══════════════════════════════════════════════════════════════════════

class IntelligentProber:
    _METHODS = ["OPTIONS","PUT","PATCH","DELETE","HEAD","TRACE"]

    def __init__(self, session, store, emit, rl, cfg):
        self.session = session; self.store = store
        self.emit = emit; self.rl = rl; self.cfg = cfg

    async def run(self):
        self.emit.section("Intelligent Probing")

        _slug_re = re.compile(r'^[a-z][a-z0-9]{3,9}$')

        def _is_slug_path(url: str) -> bool:
            segs = urlparse(url).path.strip("/").split("/")
            return any(
                _slug_re.match(seg) and not seg.isalpha() and not seg.isdigit()
                for seg in segs
            )

        def _has_params(ep: dict) -> bool:
            return any(ep.get("params",{}).get(b) for b in ("form","js","openapi","query","runtime"))

        all_eps = self.store.all_endpoints()
        targets = [
            e for e in all_eps
            if (
                e.get("confidence", 0) >= Conf.MEDIUM
                or _has_params(e)
                or _is_slug_path(e.get("url",""))
            )
        ]
        targets = sorted(targets, key=lambda e: e.get("confidence", 0), reverse=True)[:100]

        self.emit.always_info(f"Prober: {len(targets)} endpoints selected")
        n_sens = n_meth = 0
        for ep in targets:
            url = ep["url"]; method = ep["methods"][0]
            s, hdrs, body = await fetch(self.session, method, url, self.rl)
            if s is None: continue
            self.store.record_status(url, method, s)
            bh = hashlib.md5(body.encode(errors="ignore")).hexdigest()
            ep["baseline"] = {"status": s, "hash": bh, "length": len(body)}
            probe = url + ("&" if "?" in url else "?") + f"_hh={int(time.time())}"
            s2, _, b2 = await fetch(self.session, method, probe, self.rl)
            if s2 and b2:
                h2 = hashlib.md5(b2.encode(errors="ignore")).hexdigest()
                if h2 != bh or abs(len(b2) - len(body)) > 50:
                    self.store.mark_sensitive(url, method)
                    # Stored in intel — no output
                    n_sens += 1
            if self.cfg.enable_method_disc:
                found = await self._methods(url, hdrs or {})
                if found:
                    self.store.update_methods(url, found)
                    self.emit.info(f"[Methods] {url} -> {', '.join(found)}")
                    n_meth += 1
            if self.cfg.enable_cors:
                await self._cors(url)
        self.emit.always_success(f"Probing done — sensitive: {n_sens}, new methods: {n_meth}")

    async def _methods(self, url, base_hdrs):
        found = []
        _, hdrs, _ = await fetch(self.session, "OPTIONS", url, self.rl)
        if hdrs:
            allow = hdrs.get("Allow","") or hdrs.get("allow","")
            if allow:
                return [m for m in self._METHODS if m in allow]
        for m in self._METHODS:
            s, _, _ = await fetch(self.session, m, url, self.rl,
                                   data="{}", headers={"Content-Type":"application/json"})
            if s is not None and s not in (405, 501, 400, 404):
                found.append(m)
        return found

    async def _cors(self, url):
        evil = "https://evil.hellhound.test"
        _, hdrs, _ = await fetch(self.session, "GET", url, self.rl, headers={"Origin": evil})
        if not hdrs: return
        acao = hdrs.get("Access-Control-Allow-Origin","") or hdrs.get("access-control-allow-origin","")
        acac = (hdrs.get("Access-Control-Allow-Credentials","") or
                hdrs.get("access-control-allow-credentials","")).lower() == "true"
        if acao and (acao == "*" or acao == evil):
            # Stored in intel — no output
            self.store.add_cors(url, evil, acao, acac)

# ══════════════════════════════════════════════════════════════════════
# ROBOTS + SITEMAP PARSER
# Disallowed paths are crawled as high-value targets, not skipped.
# ══════════════════════════════════════════════════════════════════════

class RobotsParser:
    def __init__(self, session, base_url, store, queue, emit, rl, is_valid_fn):
        self.session = session; self.base_url = base_url
        self.store = store; self.queue = queue
        self.emit = emit; self.rl = rl; self.is_valid = is_valid_fn
        self.crawl_delay = 0.0
        self._sitemap_seen: Set[str] = set()

    async def run(self) -> float:
        url = urljoin(self.base_url, "/robots.txt")
        s, _, text = await fetch(self.session, "GET", url, self.rl)
        if s != 200 or not text:
            return 0.0
        self.emit.section("Robots.txt / Sitemap")
        self.emit.always_info(f"Robots: parsing {url}")
        dis_count = sit_count = 0
        for line in text.splitlines():
            line = line.strip(); lower = line.lower()
            if lower.startswith("crawl-delay:"):
                try:
                    self.crawl_delay = float(line.split(":",1)[1].strip())
                    self.emit.always_info(f"Robots: crawl-delay {self.crawl_delay}s — honouring")
                except ValueError:
                    pass
            elif lower.startswith("disallow:"):
                path = line.split(":",1)[1].strip()
                if not path or path == "/": continue
                full = urljoin(self.base_url, path)
                if self.is_valid(full):
                    self.store.robots_paths.append(path)
                    self.store.add_endpoint(full, source="Robots_Disallow", score=Conf.MEDIUM)
                    self.queue.put_nowait((full, 1, "Robots_Disallow"))
                    dis_count += 1
                    self.emit.info(f"[Robots] Disallow queued: {path}")
            elif lower.startswith("allow:"):
                path = line.split(":",1)[1].strip()
                if path and path != "/":
                    full = urljoin(self.base_url, path)
                    if self.is_valid(full):
                        self.store.add_endpoint(full, source="Robots_Allow", score=Conf.LOW)
                        self.queue.put_nowait((full, 1, "Robots_Allow"))
                        self.emit.info(f"[Robots] Allow queued: {path}")
            elif lower.startswith("sitemap:"):
                sitemap_url = line.split(":",1)[1].strip()
                if not sitemap_url.startswith("http"):
                    sitemap_url = line.partition(":")[2].strip()
                await self.parse_sitemap(sitemap_url)
                sit_count += 1
        self.emit.always_info(
            f"Robots: done — {dis_count} disallow, {sit_count} sitemaps, "
            f"crawl-delay={self.crawl_delay}s")
        return self.crawl_delay

    async def parse_sitemap(self, sitemap_url: str):
        if sitemap_url in self._sitemap_seen: return
        self._sitemap_seen.add(sitemap_url)
        s, _, text = await fetch(self.session, "GET", sitemap_url, self.rl)
        if s != 200 or not text: return
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for loc in (root.findall("sm:sitemap/sm:loc", ns) or root.findall("sitemap/loc")):
            if loc.text: await self.parse_sitemap(loc.text.strip())
        count = 0
        for loc in (root.findall("sm:url/sm:loc", ns) or root.findall("url/loc")):
            u = (loc.text or "").strip()
            if u and self.is_valid(u):
                self.store.add_endpoint(u, source="Sitemap", score=Conf.LOW)
                self.queue.put_nowait((u, 1, "Sitemap"))
                count += 1
        if count:
            self.emit.always_info(f"Sitemap: {sitemap_url} -> {count} URLs queued")

# ══════════════════════════════════════════════════════════════════════
# SPA SCANNER
# ══════════════════════════════════════════════════════════════════════

class SPAScanner:
    def __init__(self, target_url, store, emit, cookies, extra_headers, queue, is_valid_fn, enable_spa_interact=False, options=None):
        self.target_url = target_url; self.store = store; self.emit = emit
        self.cookies = cookies; self.extra_headers = extra_headers
        self.queue = queue; self.is_valid = is_valid_fn
        self._enable_spa_interact = enable_spa_interact
        self.options = options or {}

    async def run(self):
        if not PLAYWRIGHT_AVAILABLE:
            self.emit.info("[SPA] Playwright not installed — skipping")
            return
        self.emit.section("SPA Headless Chromium Scan")
        try:
            async with async_playwright() as pw:
                try:
                    launch_args = {
                        "headless": True,
                        "args": [
                            "--no-sandbox","--disable-dev-shm-usage",
                            "--disable-blink-features=AutomationControlled"
                        ]
                    }
                    if self.options.get("proxy"):
                        launch_args["proxy"] = {"server": self.options["proxy"]}
                        
                    browser = await pw.chromium.launch(**launch_args)
                except Exception as launch_err:
                    err_str = str(launch_err)
                    if "Connection closed" in err_str or "cli.js" in err_str or "driver" in err_str.lower():
                        self.emit.always_info(
                            "[SPA] Playwright driver not found — skipping SPA scan. "
                            "Fix: pip install playwright && playwright install chromium"
                        )
                    else:
                        self.emit.always_info(f"[SPA] Browser launch failed: {launch_err}")
                    return
                ctx_args: dict = {"ignore_https_errors": True}
                if self.cookies:
                    parsed = urlparse(self.target_url)
                    ctx_args["storage_state"] = {"cookies": [
                        {"name":k,"value":v,"domain":parsed.netloc,"path":"/"}
                        for k, v in self.cookies.items()]}
                if self.extra_headers:
                    ctx_args["extra_http_headers"] = self.extra_headers
                context = await browser.new_context(**ctx_args)
                await context.route(
                    re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|woff2?|ttf|css|mp4|mp3)(\?.*)?$'),
                    lambda route, _: asyncio.create_task(route.abort()))
                page = await context.new_page()

                async def on_request(req):
                    url = req.url; rtype = req.resource_type; method = req.method or "GET"
                    if rtype in ("fetch","xhr"):
                        hdrs = dict(req.headers or {})
                        auth = any(h.lower() in ("authorization","cookie","x-auth-token")
                                   for h in hdrs)
                        self.store.add_endpoint(url, method=method, source="SPA_XHR",
                                                score=Conf.CONFIRMED, auth_required=auth)
                        if self.store.merge_headers(url, method, hdrs):
                            self.emit.info(f"[SPA-Headers] captured for {url}")
                        if method == "POST":
                            try:
                                post_data = req.post_data
                                if post_data:
                                    try:
                                        body_obj = json.loads(post_data)
                                        if isinstance(body_obj, dict):
                                            self.store.add_endpoint(
                                                url, method="POST", source="SPA_XHR_POST",
                                                params=list(body_obj.keys()),
                                                score=Conf.CONFIRMED, auth_required=auth)
                                    except Exception:
                                        parsed_body = parse_qs(post_data)
                                        if parsed_body:
                                            self.store.add_endpoint(
                                                url, method="POST", source="SPA_XHR_POST",
                                                params=list(parsed_body.keys()),
                                                score=Conf.CONFIRMED, auth_required=auth)
                            except Exception:
                                pass
                        self.emit.success(f"[SPA-XHR] {method} {url}")
                    elif rtype == "websocket":
                        self.store.add_endpoint(url, method="WS", source="SPA_WebSocket",
                                                score=Conf.CONFIRMED)
                        # Stored in intel — no output
                    elif rtype == "script" and self.is_valid(url):
                        self.queue.put_nowait((url, 1, "SPA_Script"))

                page.on("request", on_request)

                async def on_response(resp):
                    try:
                        r_url    = resp.url
                        r_method = resp.request.method or "GET"
                        r_status = resp.status
                        r_rtype  = resp.request.resource_type
                        if r_rtype not in ("fetch", "xhr"): return
                        if r_status not in range(200, 210): return
                        ct = (resp.headers.get("content-type") or "").lower()
                        if "json" not in ct: return
                        body = await resp.text()
                        if not body or len(body) > 512_000: return
                        try:
                            obj = json.loads(body)
                        except Exception:
                            return
                        def _mine_resp(o, depth=0):
                            if depth > 3 or not isinstance(o, dict): return
                            for k, v in o.items():
                                if re.match(
                                    r'^(?:id|uid|user_?id|order_?id|basket_?id|'
                                    r'item_?id|product_?id|address_?id|card_?id)$',
                                    str(k), re.I
                                ):
                                    vstr = str(v) if v is not None else ""
                                    if re.match(r'^\d{1,12}$', vstr):
                                        r_key = self.store._key(r_url, r_method)
                                        if r_key in self.store.endpoints:
                                            ep  = self.store.endpoints[r_key]
                                            obs = ep["observed_values"].setdefault(k, [])
                                            if vstr not in obs:
                                                obs.append(vstr)
                                                self.emit.info(f"[SPA-ResponseID] {k}={vstr} <- {r_url}")
                                if isinstance(v, (dict, list)):
                                    _mine_resp(v, depth + 1)
                        if isinstance(obj, list):
                            for item in obj[:10]: _mine_resp(item)
                        else:
                            _mine_resp(obj)
                    except Exception:
                        pass

                page.on("response", on_response)

                try:
                    await page.goto(self.target_url, wait_until="networkidle", timeout=20000)
                except Exception as e:
                    self.emit.info(f"[SPA] Goto warning: {e}")
                try:
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await asyncio.sleep(1.5)
                    await page.evaluate("window.scrollTo(0, 0)")
                    await asyncio.sleep(0.5)
                except Exception:
                    pass
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                    await asyncio.sleep(1.0)
                except Exception:
                    pass
                if self._enable_spa_interact:
                    await self._interact(page)
                await self._harvest_dom(page)
                await self._harvest_hash(page)
                await browser.close()
                self.emit.always_info("SPA dynamic analysis complete")
        except Exception as e:
            self.emit.info(f"[SPA] Error: {e}")

    async def _interact(self, page):
        for sel in ["[role='menuitem']","[role='tab']",".nav-item","[data-toggle]","a[href]:not([href^='http'])"]:
            try:
                for el in (await page.query_selector_all(sel))[:8]:
                    try:
                        if await el.is_visible():
                            await el.click(timeout=1500); await asyncio.sleep(0.4)
                    except Exception: pass
            except Exception: pass
        try:
            for form in (await page.query_selector_all("form"))[:5]:
                try:
                    if not await form.is_visible(): continue
                    for inp in (await form.query_selector_all(
                        "input[type='text'],input[type='email'],input[type='number'],input:not([type])"
                    ))[:6]:
                        try:
                            itype = await inp.get_attribute("type") or "text"
                            name  = (await inp.get_attribute("name") or "").lower()
                            if "email" in name or itype == "email":
                                await inp.fill("test@example.com", timeout=800)
                            elif "quantity" in name or "qty" in name or itype == "number":
                                await inp.fill("1", timeout=800)
                            else:
                                await inp.fill("test", timeout=800)
                        except Exception: pass
                    submit = await form.query_selector(
                        "button[type='submit'],input[type='submit'],button:not([type])")
                    if submit and await submit.is_visible():
                        await submit.click(timeout=1500); await asyncio.sleep(0.5)
                except Exception: pass
        except Exception: pass
        try:
            for el in (await page.query_selector_all("button:not([disabled]):not([type='submit'])"))[:10]:
                try:
                    if await el.is_visible():
                        await el.click(timeout=1500); await asyncio.sleep(0.3)
                except Exception: pass
        except Exception: pass

    async def _harvest_dom(self, page):
        try:
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('[href],[src],[action]'))
                    .map(e => e.href || e.src || e.action)
                    .filter(u => u && u.startsWith('/'))
            """)
            for path in (links or []):
                full = urljoin(self.target_url, path) if path.startswith("/") else path
                if self.is_valid(full):
                    self.store.add_endpoint(full, source="SPA_DOM", score=Conf.MEDIUM)
                    self.queue.put_nowait((full, 1, "SPA_DOM"))
        except Exception: pass

    async def _harvest_hash(self, page):
        try:
            src = await page.content()
            for r in re.findall(r'["\']#/([a-zA-Z0-9_\-/]+)["\']', src):
                url = self.target_url.rstrip("/") + "/#/" + r
                self.store.add_endpoint(url, source="SPA_HashRoute", score=Conf.MEDIUM)
                self.emit.info(f"[SPA-Hash] {url}")
        except Exception: pass

# ══════════════════════════════════════════════════════════════════════
# CORE SPIDER
# ══════════════════════════════════════════════════════════════════════

class Spider:
    def __init__(self, target, cfg, emit, cookies, extra_headers, options=None):
        self.target = target; self.cfg = cfg; self.emit = emit
        self.cookies = cookies; self.extra_headers = extra_headers
        self.options = options or {}
        self.base_domain = urlparse(target).netloc
        self.store = Store()
        self.visited: Set[str] = set()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.sem = asyncio.Semaphore(cfg.concurrency)
        self.rl = DomainRateLimiter()
        self._depth_cnt: Dict[int,int] = defaultdict(int)
        self.queue.put_nowait((target, 0, "Seed"))

    def is_valid(self, url):
        try:
            p = urlparse(url)
        except Exception:
            return False
        if p.netloc != self.base_domain: return False
        low = url.lower()
        if any(low.endswith(ext) or f"{ext}?" in low for ext in self.cfg.extensions_to_ignore):
            return False
        return bool(p.scheme in ("http","https"))

    def _over_budget(self, depth):
        return self._depth_cnt[depth] >= self.cfg.max_urls_per_depth

    def _detect_tech(self, headers, body, url):
        tech: Set[str] = set()
        srv     = (headers.get("Server","")       or headers.get("server","")).lower()
        xpb     = (headers.get("X-Powered-By","") or headers.get("x-powered-by","")).lower()
        body_lo = body.lower()

        # ── Leakage: Expose highly verbose Server headers ───────────────
        raw_srv = headers.get("Server") or headers.get("server", "")
        raw_xpb = headers.get("X-Powered-By") or headers.get("x-powered-by", "")
        raw_asp = headers.get("X-AspNet-Version") or headers.get("x-aspnet-version", "")
        if raw_srv: tech.add(f"Server: {raw_srv}")
        if raw_xpb: tech.add(f"X-Powered-By: {raw_xpb}")
        if raw_asp: tech.add(f"X-AspNet-Version: {raw_asp}")

        # ── Server / infrastructure ──────────────────────────────────────
        if "nginx"      in srv: tech.add("Nginx")
        if "apache"     in srv: tech.add("Apache")
        if "cloudflare" in srv: tech.add("Cloudflare")
        if "iis"        in srv: tech.add("IIS")
        if "gunicorn"   in srv: tech.add("Python/Gunicorn")
        if "werkzeug"   in srv: tech.add("Python/Werkzeug")
        if "jetty"      in srv: tech.add("Java/Jetty")
        if "tomcat"     in srv: tech.add("Java/Tomcat")
        if "lighttpd"   in srv: tech.add("Lighttpd")
        if "caddy"      in srv: tech.add("Caddy")
        if "php"        in xpb: tech.add("PHP")
        if "express"    in xpb: tech.add("Node.js/Express")
        if "asp.net"    in xpb: tech.add("ASP.NET")
        if "next.js"    in xpb: tech.add("Next.js")
        if "servlet"    in xpb or "jsp" in xpb: tech.add("Java")
        if headers.get("X-Shopify-Stage"): tech.add("Shopify")
        if headers.get("x-drupal-cache") or headers.get("X-Drupal-Cache"): tech.add("Drupal")
        if headers.get("x-pingback") or "xmlrpc.php" in body: tech.add("WordPress")
        if headers.get("x-generator","").lower().startswith("drupal"): tech.add("Drupal")
        if "laravel_session" in (headers.get("set-cookie","") or "").lower(): tech.add("Laravel")
        if "django" in (headers.get("set-cookie","") or "").lower(): tech.add("Django")
        if "_next/" in body or "__NEXT_DATA__" in body: tech.add("Next.js")
        if "__nuxt" in body or "_nuxt/" in body: tech.add("Nuxt.js")
        _is_angular = (
            "<app-root" in body or "ng-version=" in body or
            ("zone.js" in body_lo and "angular" in body_lo) or
            "platformBrowserDynamic" in body or "BrowserModule" in body
        )
        if _is_angular: tech.add("Angular")
        if re.search(r'<[^>]+\bng-app\b', body) or re.search(r'<[^>]+\bng-controller\b', body):
            tech.add("AngularJS")
        _is_react = (
            "ReactDOM" in body or "react-dom" in body_lo or
            "__reactFiber" in body or "__reactProps" in body or "data-reactroot" in body
        )
        if _is_react and "Angular" not in tech: tech.add("React")
        if "__vue_app__" in body or "v-bind:" in body or "data-v-" in body: tech.add("Vue.js")
        elif "vue" in body_lo and "v-app" in body: tech.add("Vue.js")
        if "__svelte" in body or "svelte-" in body_lo: tech.add("Svelte")
        if "wp-content" in body or "wp-json" in body or "wp-login" in body: tech.add("WordPress")
        if "Drupal.settings" in body or "drupal.js" in body_lo: tech.add("Drupal")
        if "csrfmiddlewaretoken" in body_lo or ("django" in body_lo and "__admin" in body_lo):
            tech.add("Django")
        if "laravel" in body_lo and ("csrf_token" in body_lo or "blade" in body_lo):
            tech.add("Laravel")
        if "rails-ujs" in body_lo or 'data-remote="true"' in body_lo: tech.add("Ruby on Rails")
        if "jsf" in body_lo and "javax.faces" in body_lo: tech.add("Java/JSF")
        if "socket.io" in body_lo: tech.add("Socket.IO")
        if "graphql" in body_lo and ("__schema" in body or "introspection" in body_lo):
            tech.add("GraphQL")
        if re.search(r'class=["\'][^"\']*\b(?:navbar-brand|btn-primary|btn-secondary|col-md-|container-fluid)\b', body):
            tech.add("Bootstrap")
        if "jquery" in body_lo and ("$.ajax" in body or "$(document)" in body): tech.add("jQuery")
        if "material-icons" in body_lo or "mat-" in body_lo: tech.add("Angular Material")

        new_tech = tech - self.store.tech_stack
        for t in tech: self.store.tech_stack.add(t)
        if new_tech: self.emit.always_success(f"Tech detected: {', '.join(sorted(new_tech))}")

    async def _check_sourcemap(self, session, js_url):
        s, _, _ = await fetch(session, "GET", js_url + ".map", self.rl)
        if s == 200:
            # Stored in intel — no output
            self.store.add_sourcemap(js_url + ".map", js_url)

    def _queue_url(self, url, depth, source):
        if not self.is_valid(url): return
        norm = normalize(url)
        if norm in self.visited: return
        self.store.add_query_params(url)
        self.queue.put_nowait((url, depth, source))

    @staticmethod
    def _collect_json_keys(obj) -> List[str]:
        if isinstance(obj, dict):
            return [k for k in obj.keys() if isinstance(k, str)]
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    return [k for k in item.keys() if isinstance(k, str)]
        return []

    @staticmethod
    def _strip_param_suffix(name: str) -> str:
        for suf in Store._PARAM_SUFFIXES:
            if name.endswith(suf):
                return name[: -len(suf)]
        return name

    def _extract_body_param_hints(self, url, body):
        found = []
        err_pats = [
            r"""(?:missing|required|invalid|unknown|bad)\s+(?:field|param|parameter|key|argument)[:\s]+["']?([a-zA-Z_][a-zA-Z0-9_]{2,40})["']?""",
            r"""["']([a-zA-Z_][a-zA-Z0-9_]{2,40})["']\s+(?:is required|is missing|not found|is invalid)""",
            r"""(?:field|param|parameter)[:\s]+["']([a-zA-Z_][a-zA-Z0-9_]{2,40})["']""",
        ]
        for pat in err_pats:
            for m in re.finditer(pat, body, re.I):
                n = m.group(1).strip()
                if n and n not in found: found.append(n)
        for m in re.finditer(
            r"""["'](?:required|fields|params|parameters|missing|expected)["']\s*:\s*\[([^\]]{1,400})\]""",
            body, re.I
        ):
            for nm in re.finditer(r"""["']([a-zA-Z_][a-zA-Z0-9_]{2,40})["']""", m.group(1)):
                n = nm.group(1)
                if n not in found: found.append(n)
        for m in re.finditer(r"""name=["']([a-zA-Z_][a-zA-Z0-9_]{2,40})["']""", body):
            n = m.group(1)
            if n not in found: found.append(n)
        if found:
            self.store.add_endpoint(url, source="Body_Hints", score=Conf.LOW)
            changed = self.store.add_runtime_params(url, "GET", found)
            if changed:
                self.emit.info("[Body-Hints] %s <- %s" % (found, url))

    def _process_html(self, url, text, depth, source):
        try:
            soup = BeautifulSoup(text, "lxml")
        except Exception:
            soup = BeautifulSoup(text, "html.parser")
        Extractor.html_comments(soup, url, self.store, self.emit)
        for tag in soup.find_all(["a","link","area"], href=True):
            href = tag.get("href","").strip()
            if href and not href.startswith(("javascript:","mailto:","tel:","#")):
                self._queue_url(urljoin(url, href), depth+1, "HTML_Link")
        for tag in soup.find_all("script", src=True):
            src = tag.get("src","").strip()
            if src:
                full = urljoin(url, src)
                if self.is_valid(full): self._queue_url(full, depth+1, "HTML_Script")
        for tag in soup.find_all("script"):
            if not tag.get("src") and tag.string:
                Extractor.js_endpoints(tag.string, url, self.store, self.emit)
                Extractor.js_params(tag.string, url, self.store, self.emit)
                Extractor.secrets(tag.string, url, self.store, self.emit)
                Extractor.exposed_files(tag.string, url, self.store, self.emit)
        for form in soup.find_all("form"):
            action = form.get("action") or url
            full   = urljoin(url, action)
            method = (form.get("method") or "POST").upper()
            inputs = []
            for el in form.find_all(["input","select","textarea","button","datalist"]):
                nm = el.get("name","").strip()
                if nm and nm not in inputs: inputs.append(nm)
                for da in ("data-param","data-field","data-name","data-key","data-input"):
                    dv = el.get(da,"").strip()
                    if dv and dv not in inputs: inputs.append(dv)
            for da in ("data-params","data-fields","data-inputs"):
                dv = form.get(da,"").strip()
                if dv:
                    for part in re.split(r"[,;|\s]+", dv):
                        p = part.strip()
                        if p and p not in inputs: inputs.append(p)
            if inputs: self.emit.info("[Form] %s %s <- [%s]" % (method, full, ", ".join(inputs)))
            self.store.add_endpoint(full, method=method, source="Form", score=Conf.HIGH)
            self.store.add_query_params(full)
            _fkey = self.store._key(full, method)
            if _fkey in self.store.endpoints:
                _ep = self.store.endpoints[_fkey]
                for _p in inputs:
                    if _p and _p not in _ep["params"]["form"]: _ep["params"]["form"].append(_p)
            self._queue_url(full, depth+1, "Form_Action")
        for attr in ("data-src","data-href","data-url"):
            for tag in soup.find_all(attrs={attr: True}):
                self._queue_url(urljoin(url, tag[attr]), depth+1, "DataAttr")
        for tag in soup.find_all("script", type="application/ld+json"):
            if tag.string:
                for m in re.finditer(r'"(?:url|@id|contentUrl|embedUrl)"\s*:\s*"([^"]+)"', tag.string):
                    self._queue_url(m.group(1), depth+1, "JSONLD")

    async def _process_js(self, url, text, session):
        Extractor.secrets(text, url, self.store, self.emit)
        Extractor.js_endpoints(text, url, self.store, self.emit)
        Extractor.js_params(text, url, self.store, self.emit)
        Extractor.exposed_files(text, url, self.store, self.emit)
        await self._check_sourcemap(session, url)
        for m in re.finditer(r'import\s*\(\s*["\']([^"\']+)["\']', text):
            full = urljoin(url, m.group(1))
            if self.is_valid(full): self._queue_url(full, 1, "JS_DynImport")
        for m in re.finditer(r'["\']\/(?:static|_next|assets)\/[a-zA-Z0-9._\-\/]+\.js["\']', text):
            path = m.group(0).strip('"\'')
            self._queue_url(urljoin(url, path), 1, "JS_Chunk")

    async def _worker(self, session, worker_id, crawl_delay):
        while True:
            acquired = False
            try:
                async with self.sem:
                    try:
                        url, depth, source = await asyncio.wait_for(self.queue.get(), timeout=4.0)
                        acquired = True
                    except asyncio.TimeoutError:
                        break
                    norm = normalize(url)
                    if norm in self.visited or depth > self.cfg.max_depth or self._over_budget(depth):
                        pass
                    else:
                        self.visited.add(norm)
                        self._depth_cnt[depth] += 1
                        s, hdrs, body = await fetch(session, "GET", url, self.rl,
                                                    max_retries=self.cfg.max_retries,
                                                    base_delay=self.cfg.retry_base_delay)
                        if s is not None and body is not None:
                            self.store.record_status(url, "GET", s)
                            if s in (401, 403):
                                self.store.add_endpoint(url, source=source,
                                                        score=Conf.MEDIUM, auth_required=True)
                                self.emit.info(f"[Auth-wall:{s}] {url}")
                            elif s in (500, 501, 502, 503) and body:
                                _ERR_RE = re.compile(
                                    r'(?:Traceback|Exception in thread|SyntaxError|ParseError|'
                                    r'SQLSTATE|You have an error in your SQL|ORA-\d{5}|'
                                    r'Fatal error:|Warning:|Uncaught \w+Error|'
                                    r'at [a-zA-Z\.]+\([a-zA-Z]+\.java:\d+\))',
                                    re.I
                                )
                                if _ERR_RE.search(body):
                                    self.store.add_endpoint(url, source="Error_Leak", score=Conf.HIGH)
                                    self.store.add_secret(body[:200], "Error_Stack_Trace", url)
                                    self.emit.info(f"[Error-Leak] Verbose error at {url}")
                            elif s == 200:
                                if depth <= 1:
                                    self._detect_tech(hdrs, body, url)
                                    Extractor.csp_hints(hdrs, url, self.store, self.emit)
                                ct = (hdrs.get("Content-Type","") or hdrs.get("content-type","")).lower()
                                if "text/html" in ct:
                                    self.store.add_endpoint(url, source=f"HTML({source})", score=Conf.MEDIUM)
                                    try:
                                        self._process_html(url, body, depth, source)
                                    except Exception:
                                        pass
                                    self._extract_body_param_hints(url, body)
                                elif "javascript" in ct or url.split("?")[0].endswith(".js"):
                                    self.store.add_endpoint(url, source="JS_File", score=Conf.LOW)
                                    await self._process_js(url, body, session)
                                elif "json" in ct:
                                    self.store.add_endpoint(url, source="JSON_Response", score=Conf.MEDIUM)
                                    # -- Geo-location leak
                                    _GEO_RE = re.compile(
                                        r'(?:"latitude"|"lat"|"lng"|"longitude"|"geo"|"coordinates")'
                                        r'\s*:\s*(-?\d{1,3}\.\d+)',
                                        re.I
                                    )
                                    for _gm in _GEO_RE.finditer(body):
                                        self.store.add_secret(
                                            f"GeoCoord: {_gm.group(0)[:60]}",
                                            "GeoLocation_Leak", url)
                                        self.emit.info(f"[Geo-Leak] Coordinates in response: {url}")
                                        break
                                    for m in re.finditer(r'"([/][a-zA-Z0-9_\-\/]+)"', body):
                                        path = m.group(1)
                                        if len(path) > 3:
                                            full = urljoin(url, path)
                                            if self.is_valid(full):
                                                self.store.add_endpoint(full, source="JSON_Path", score=Conf.LOW)
                                                if not self._over_budget(depth + 1):
                                                    self._queue_url(full, depth + 1, "JSON_Path")
                                    self._extract_body_param_hints(url, body)
                                    try:
                                        _jdata = json.loads(body)
                                        _top_keys = self._collect_json_keys(_jdata)
                                        _risk = [
                                            k for k in _top_keys
                                            if self._strip_param_suffix(k) in Store._RISK_PARAMS
                                        ]
                                        if _risk:
                                            changed = self.store.add_runtime_params(url, "GET", _risk)
                                            if changed:
                                                _bases = self.store.endpoints[
                                                    self.store._key(url, "GET")
                                                ]["params"]["runtime"]
                                                self.emit.info(f"[JSON-Params] {_bases} <- {url}")
                                    except Exception:
                                        pass
                                elif "xml" in ct:
                                    try:
                                        root = ET.fromstring(body)
                                        ns = {"sm":"http://www.sitemaps.org/schemas/sitemap/0.9"}
                                        for loc in root.findall("sm:url/sm:loc", ns):
                                            if loc.text: self._queue_url(loc.text, depth+1, "XML_Sitemap")
                                    except Exception:
                                        pass
            except Exception:
                pass
            finally:
                if acquired:
                    self.queue.task_done()
                if acquired:
                    delay = crawl_delay if crawl_delay > 0 else random.uniform(
                        self.cfg.jitter_min, self.cfg.jitter_max)
                    await asyncio.sleep(delay)

    async def run(self):
        # Initial request headers
        req_headers = {
            "User-Agent": self.cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "application/json;q=0.8,*/*;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
        }
        req_headers.update(self.extra_headers)
        
        # Apply Global Proxy & Headers
        proxy = self.options.get("proxy")
        global_headers = self.options.get("global_headers", {})
        enable_waf = self.options.get("enable_waf_bypass")
        
        req_headers.update(global_headers)
        if enable_waf:
            req_headers.update(http_utils.get_waf_bypass_header())
        connector = aiohttp.TCPConnector(limit=self.cfg.concurrency, ttl_dns_cache=300, ssl=False)
        timeout   = aiohttp.ClientTimeout(total=self.cfg.timeout)
        async with aiohttp.ClientSession(headers=req_headers, cookies=self.cookies,
                                          timeout=timeout, connector=connector) as session:
            session._hellhound_proxy = proxy
            if self.cfg.enable_graphql:
                await probe_graphql(session, self.target, self.store, self.emit, self.rl)
            if self.cfg.enable_openapi:
                await probe_openapi(session, self.target, self.store, self.emit, self.rl)
            robots = RobotsParser(session, self.target, self.store, self.queue,
                                  self.emit, self.rl, self.is_valid)
            crawl_delay = await robots.run()

            # Unconditionally probe canonical sitemap paths
            for _smap in ("/sitemap.xml", "/sitemap_index.xml", "/.well-known/sitemap.xml"):
                _smap_url = urljoin(self.target, _smap)
                if _smap_url not in robots._sitemap_seen:
                    _s, _, _t = await fetch(session, "GET", _smap_url, self.rl)
                    if _s == 200 and _t:
                        await robots.parse_sitemap(_smap_url)

            # Probe .well-known and sensitive root paths
            _WK_PATHS = (
                "/.git/HEAD",
                "/.git/config",
                "/.env",
                "/.well-known/security.txt", 
                "/security.txt",
                "/.well-known/change-password",
                "/.well-known/openid-configuration",
                "/.well-known/assetlinks.json",
                "/.well-known/apple-app-site-association",
            )
            for _wk in _WK_PATHS:
                _wk_url = urljoin(self.target, _wk)
                _s, _hdrs, _t = await fetch(session, "GET", _wk_url, self.rl)
                if _s == 200 and _t:
                    _ct = (_hdrs or {}).get("content-type", "").lower()
                    # Skip SPA false positives (Angular/React return 200+HTML for unknown paths)
                    if "text/html" in _ct and "<html" in _t.lower():
                        continue
                    self.store.add_endpoint(_wk_url, source="WellKnown", score=Conf.CONFIRMED)
                    self.emit.always_success(f"[Surface] Exposed: {_wk_url}")
                    discovered = []
                    # Extract relative/absolute paths from body
                    for _m in re.finditer(r'(?:^|\s|"|\'|)((?:https?://[^\s"\'>]+|/[a-zA-Z0-9_\-\./\?\#]+))', _t, re.M):
                        _path = _m.group(1).strip()
                        if _path.startswith("/") and len(_path) > 1:
                            _full = urljoin(self.target, _path)
                            if self.is_valid(_full):
                                self.store.add_endpoint(_full, source="WellKnown", score=Conf.LOW)
                                self._queue_url(_full, 1, "WellKnown")
                                discovered.append(_full)
                        elif _path.startswith("http") and self.is_valid(_path):
                            self.store.add_endpoint(_path, source="WellKnown", score=Conf.LOW)
                            discovered.append(_path)
                    
                    self.store.add_well_known(_wk_url, _t[:200].replace("\n", " "), discovered)

            if self.cfg.use_playwright:
                spa = SPAScanner(self.target, self.store, self.emit, self.cookies,
                                 self.extra_headers, self.queue, self.is_valid,
                                 enable_spa_interact=self.cfg.enable_spa_interact,
                                 options=self.options)
                await spa.run()

            self.emit.section("Crawling")
            self.emit.always_info(
                f"depth={self.cfg.max_depth} | "
                f"concurrency={self.cfg.concurrency} | "
                f"auth={'yes' if self.cookies or self.extra_headers else 'no'} | "
                f"seed={self.queue.qsize()} URLs")

            workers = [asyncio.create_task(self._worker(session, i, crawl_delay))
                       for i in range(self.cfg.concurrency)]
            await self.queue.join()
            for w in workers: w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

            if self.cfg.enable_probing:
                prober = IntelligentProber(session, self.store, self.emit, self.rl, self.cfg)
                await prober.run()

# ══════════════════════════════════════════════════════════════════════
# AUTO-SAVE
# ══════════════════════════════════════════════════════════════════════

def _auto_save(store: Store, target: str, out_path: Optional[str], fmt: str, emit) -> str:
    domain    = re.sub(r'[^a-zA-Z0-9_\-]', '_', urlparse(target).netloc)
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = out_path if (out_path and out_path.endswith(".json")) \
                else f"hellhound_{domain}_{ts}.json"
    try:
        Path(json_path).write_text(store.export(target, fmt="json"))
        emit.always_info(f"Report saved: {json_path}")
    except Exception as e:
        emit.info(f"Report save failed: {e}")
        json_path = ""
    if out_path and fmt != "json":
        try:
            Path(out_path).write_text(store.export(target, fmt=fmt))
            emit.always_info(f"{fmt.upper()} saved: {out_path}")
        except Exception as e:
            emit.info(f"{fmt.upper()} save failed: {e}")
    return json_path

# ══════════════════════════════════════════════════════════════════════
# SHARED RUN LOGIC
# ══════════════════════════════════════════════════════════════════════

def _do_run(target: str, cfg: Config, emit,
            cookies: Dict[str, str], extra_headers: Dict[str, str], options: dict = None) -> dict:
    if not target.startswith("http"):
        target = "https://" + target

    emit.always_info(f"Hellhound Spider v{VERSION} — {target}")
    start = time.time()

    spider: Optional[Spider] = None
    try:
        spider = Spider(target, cfg, emit, cookies, extra_headers, options=options)
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(spider.run())
    except KeyboardInterrupt:
        emit.always_info("Scan interrupted — partial results follow")
    except ValueError as e:
        emit.always_info(f"Config error: {e}")
        return {"raw": str(e), "intel": {}}
    except Exception as e:
        emit.always_info(f"Spider error: {e}")

    if spider is None:
        return {"raw": "Spider failed to initialize.", "intel": {}}

    elapsed   = time.time() - start
    intel     = json.loads(spider.store.export(target, fmt="json"))
    s         = intel.get("summary", {})

    raw_summary = (
        f"Target: {target} | "
        f"Time: {elapsed:.1f}s | "
        f"Endpoints: {s.get('total_endpoints','?')} | "
        f"Confirmed: {s.get('confirmed','?')} | "
        f"High: {s.get('high','?')} | "
        f"Auth-Walled: {s.get('auth_required','?')} | "
        f"Param-Sensitive: {s.get('parameter_sensitive','?')} | "
        f"Secrets: {s.get('secrets','?')} | "
        f"CORS: {s.get('cors_issues','?')} | "
        f"GraphQL: {s.get('graphql_exposed','?')} | "
        f"OpenAPI: {s.get('openapi_exposed','?')} | "
        f"SourceMaps: {s.get('sourcemaps_exposed','?')} | "
        f"Tech: {', '.join(s.get('tech_stack',[])) or 'unknown'}"
    )

    emit.section("Spider Summary")
    emit.always_success(f"Scan complete — {elapsed:.1f}s")
    emit.always_info(f"Target             : {target}")
    emit.always_info(f"Endpoints          : {s.get('total_endpoints', '?')}")
    emit.always_info(f"High Confidence    : {s.get('high', '?')}")
    emit.always_info(f"Auth-Required      : {s.get('auth_required', '?')}")
    emit.always_info(f"Param-Sensitive    : {s.get('parameter_sensitive', '?')}")
    emit.always_info(f"Secrets Found      : {s.get('secrets', '?')}")
    emit.always_info(f"CORS Issues        : {s.get('cors_issues', '?')}")
    tech_str = ', '.join(s.get('tech_stack', [])) or 'unknown'
    emit.always_info(f"Tech Stack         : {tech_str}")
    gql = s.get('graphql_exposed', 0)
    oas = s.get('openapi_exposed', 0)
    if gql:
        emit.always_success(f"GraphQL Exposed    : {gql} endpoint(s)")
    if oas:
        emit.always_success(f"OpenAPI Exposed    : {oas} spec(s)")

    return {"raw": raw_summary, "intel": intel}

# ══════════════════════════════════════════════════════════════════════
# FRAMEWORK ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def run(target: str, emit_obj, options: dict = None, stop_check=None, pause_check=None):
    """
    Hellhound module entry point.

    options keys (all optional — see OPTIONS list above):
      cookie              : str | dict | file_path  — session cookie(s)
      auth                : str — Authorization header e.g. "Bearer eyJ..."
      headers             : dict — extra headers dict
      max_depth           : int   (default 4)
      concurrency         : int   (default 12)
      timeout             : int   (default 15)
      max_retries         : int   (default 3)
      max_urls_per_depth  : int   (default 500)
      verbose             : bool  — False: phase headers + summary only (default)
                                    True:  all internal discovery logs
      use_playwright      : bool  (default True)
      enable_spa_interact : bool  (default False)
      enable_probing      : bool  (default True)
      enable_method_disc  : bool  (default True)
      enable_graphql      : bool  (default True)
      enable_openapi      : bool  (default True)
      enable_cors         : bool  (default True)
      output_format       : str   "json" | "jsonl" | "csv" | "burp"
      output_file         : str   path to save report file

    Returns:
      {"raw": str, "intel": dict}
    """
    opts    = options or {}
    raw_cookie = opts.get("cookie") or opts.get("auth")
    cookies = SessionManager.parse_cookies(raw_cookie)
    xhdrs   = SessionManager.parse_auth_header(opts.get("headers", {}))

    # Fallback: if parse_cookies returned nothing but the raw value is a non-empty
    # string with no "key=value" structure (e.g. a bare JWT or session token),
    # store it under the key "token" so it is actually sent with requests.
    if not cookies and isinstance(raw_cookie, str) and raw_cookie.strip():
        raw_stripped = raw_cookie.strip()
        if "=" not in raw_stripped or raw_stripped.startswith("eyJ"):
            cookies = {"token": raw_stripped}

    # Build Config — skip auth/header keys that don't belong in Config
    _cfg_skip = {"cookie", "auth", "headers"}
    cfg = Config(**{k: v for k, v in opts.items() if k not in _cfg_skip})
    try:
        cfg.validate()
    except ValueError as e:
        emit_obj.info(f"Config error: {e}")
        return {"raw": str(e), "intel": {}}

    if cookies:
        emit_obj.info(f"Session cookies loaded: {list(cookies.keys())}")
    elif xhdrs:
        emit_obj.info(f"Auth header loaded: {list(xhdrs.keys())}")
    else:
        emit_obj.info("No credentials — unauthenticated scan")

    emit = ModuleEmit(emit_obj, verbose=cfg.verbose)
    return _do_run(target, cfg, emit, cookies, xhdrs, options=opts)

# ══════════════════════════════════════════════════════════════════════
# CUSTOM RENDERER HOOK
# ══════════════════════════════════════════════════════════════════════

def render_header(intel: dict):
    """
    Called dynamically by Hellhound console during `loot` to render
    a custom module-specific ASCII banner before the generic tables.
    """
    from colorama import Fore, Style
    
    summary   = intel.get("summary", {})
    endpoints = intel.get("endpoints", [])
    secrets   = intel.get("secrets", [])
    cors      = intel.get("cors_issues", [])
    maps      = intel.get("sourcemaps", [])
    tech      = intel.get("tech_stack", summary.get("tech_stack", []))
    
    total   = summary.get("total_endpoints", len(endpoints))
    conf    = summary.get("confirmed", 0)
    highs   = summary.get("high", 0)
    auth_n  = summary.get("auth_required", 0)
    param_n = summary.get("parameter_sensitive", 0)
    sec_n   = summary.get("secrets", len(secrets))
    cors_n  = summary.get("cors_issues", len(cors))
    maps_n  = summary.get("sourcemaps_exposed", len(maps))

    line1 = f"Endpoints: {total}    Confirmed: {conf}    High: {highs}    Auth-Walled: {auth_n}    Param-Sensitive: {param_n}"
    t_str = ", ".join(tech) if tech else "Unknown"
    if len(t_str) > 25: t_str = t_str[:22] + "..."
    line2 = f"Secrets: {sec_n}      CORS: {cors_n}         Maps: {maps_n}        Tech: {t_str}"

    print(f"  {Fore.CYAN + Style.BRIGHT}╔══════════════════ SPIDER RECONNAISSANCE ══════════════════╗{Style.RESET_ALL}")
    
    # Calculate padding dynamically for perfect right border alignment
    for raw_line in (line1, line2):
        padding = 59 - len(raw_line)
        if padding < 0: padding = 0
        
        # Colorize specific keywords after length calculation to avoid ANSI width issues
        colored = raw_line
        colored = colored.replace(f"Endpoints: {total}", f"{Fore.WHITE}Endpoints: {Fore.GREEN + Style.BRIGHT}{total}{Fore.WHITE}")
        colored = colored.replace(f"Confirmed: {conf}", f"Confirmed: {Fore.GREEN + Style.BRIGHT}{conf}{Fore.WHITE}")
        colored = colored.replace(f"High: {highs}", f"High: {(Fore.RED + Style.BRIGHT) if highs else Fore.WHITE}{highs}{Fore.WHITE}")
        colored = colored.replace(f"Auth-Walled: {auth_n}", f"Auth-Walled: {Fore.YELLOW + Style.BRIGHT}{auth_n}{Fore.WHITE}")
        colored = colored.replace(f"Param-Sensitive: {param_n}", f"Param-Sensitive: {Fore.YELLOW + Style.BRIGHT}{param_n}{Fore.WHITE}")
        
        # Line 2 replacements
        colored = colored.replace(f"Secrets: {sec_n}", f"{Fore.WHITE}Secrets: {(Fore.RED + Style.BRIGHT) if sec_n else Fore.GREEN}{sec_n}{Fore.WHITE}")
        colored = colored.replace(f"CORS: {cors_n}", f"CORS: {(Fore.YELLOW + Style.BRIGHT) if cors_n else Fore.GREEN}{cors_n}{Fore.WHITE}")
        colored = colored.replace(f"Maps: {maps_n}", f"Maps: {(Fore.YELLOW + Style.BRIGHT) if maps_n else Fore.GREEN}{maps_n}{Fore.WHITE}")
        colored = colored.replace(f"Tech: {t_str}", f"Tech: {Fore.CYAN}{t_str}{Fore.WHITE}")
        
        print(f"  {Fore.CYAN + Style.BRIGHT}║{Style.RESET_ALL}  {Fore.WHITE}{colored}{Style.RESET_ALL}{' ' * padding}{Fore.CYAN + Style.BRIGHT}║{Style.RESET_ALL}")
        
    print(f"  {Fore.CYAN + Style.BRIGHT}╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print()