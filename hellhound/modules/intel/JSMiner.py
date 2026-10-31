NAME = "JSMiner"
DESCRIPTION = "Live JS endpoint/route mining — finds a target's JS bundles and extracts the API endpoints/routes called from them. Not a sourcemap tool (see BlobUnpacker for that)."
CATEGORY = "intel"
OPTIONS = []

import re
import requests
from urllib.parse import urljoin, urlparse

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# CAUGHT IN THE WILD (2026-10): the researcher asked for js_static_analysis
# (which is BlobUnpacker + SourceAuditor chained together) to pull API
# endpoints out of a target's live JS, and got "No JS files found for
# analysis" despite manually curling real JS bundles minutes earlier.
# BlobUnpacker genuinely IS the wrong tool for that specific job — its
# whole reason for existing is reconstructing original source from exposed
# .map sourcemap files (hence the name); it only mines endpoints/secrets
# out of raw JS as a side effect of scanning for sourcemap references, and
# (separately, now fixed in BlobUnpacker.py) used to throw that side-effect
# data away entirely whenever no sourcemap/secret was found. Here's the
# tool actually being asked for: given a URL, find every reachable JS file
# (regular <script src>, SPA/webpack/Next.js chunks), fetch each one, and
# extract the API endpoints/routes called from it — nothing about
# sourcemaps, nothing about secrets. If BOTH tools happen to find the same
# JS file, that's fine; they're answering different questions about it.

# Patterns that find an endpoint/route STRING inside JS source, deliberately
# broader than BlobUnpacker's 3 patterns (which exist there only to help
# find/confirm a sourcemap, not as this tool's primary job):
#   - fetch()/axios()/axios.<method>() calls
#   - XMLHttpRequest .open("METHOD", "...")
#   - "url:" / "endpoint:" / "path:" config keys (ajax/axios config objects)
#   - bare absolute paths that look like real API routes (/api/, /v1/,
#     /v2/, /graphql, /rest/, etc. — not just "any string starting with /",
#     which floods results with CSS classes, SVG ids, and the like)
#   - template-literal endpoints (`${BASE}/users/${id}` style) — captures
#     the literal path segments around the interpolation, since the raw
#     variable name isn't itself useful but the surrounding route shape is
_METHOD_CALL_RE = re.compile(
    r'(?:fetch|axios(?:\.(get|post|put|delete|patch|head|options))?)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
    re.IGNORECASE,
)
_XHR_OPEN_RE = re.compile(
    r'\.open\s*\(\s*[\'"`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
    re.IGNORECASE,
)
_CONFIG_KEY_RE = re.compile(
    r'(?:url|endpoint|path|baseURL)\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
)
_API_LOOKING_PATH_RE = re.compile(
    r'[\'"`](/(?:api|v[0-9]+|rest|graphql|gql|auth|internal|admin|service|services)/[a-zA-Z0-9\-_/\{\}\.]*|/(?:api|graphql|gql)\b[a-zA-Z0-9\-_/\{\}\.]*)[\'"`]',
    re.IGNORECASE,
)
_TEMPLATE_LITERAL_RE = re.compile(
    r'`([a-zA-Z0-9\-_/\.:${}]*\$\{[^}]+\}[a-zA-Z0-9\-_/\.:${}]*)`'
)
_GRAPHQL_OP_RE = re.compile(
    r'\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]+)\s*(?:\(|\{)',
)

# CAUGHT IN THE WILD (2026-10): run against a real Codiad instance (classic
# PHP-MVC web app, jQuery 1.7.2-era frontend) with 14 live JS files fetched
# successfully, js_miner still reported "found no endpoint-shaped strings"
# every single time. Root cause: every pattern above assumes a modern
# REST/SPA convention — fetch()/axios(), or a path starting with "/api/",
# "/v1/", etc. Codiad's actual JS calls $.ajax({url: "components/user/
# controller.php?action=authenticate", ...}) and similar — a RELATIVE path
# (no leading "/") to a classic backend script, which the old _record()
# rejected outright (it only accepted paths starting with "/", "http", or
# "{param}"). This isn't a Codiad-specific quirk — it's the default shape
# for most pre-SPA PHP/ASP/JSP apps (WordPress admin-ajax.php, osCommerce,
# phpBB, classic ASP sites), which this tool had zero coverage for despite
# claiming to be a general endpoint miner. Fixed two ways: (1) a dedicated
# pattern for bare backend-script references regardless of surrounding
# context (not just inside a url:/endpoint: config key or fetch() call),
# and (2) _record()'s own accept/reject gate no longer requires a leading
# "/" when the path looks like a real backend script (ends in a known
# server-side extension, optionally with a query string).
_SCRIPT_EXT_RE = re.compile(r'\.(?:php\d?|aspx?|jsp|cgi|do|ashx)(?:\?[^\'"`]*)?$', re.IGNORECASE)
_BARE_SCRIPT_REF_RE = re.compile(
    r'[\'"`](/?[a-zA-Z0-9_][a-zA-Z0-9_\-./]*\.(?:php\d?|aspx?|jsp|cgi|do|ashx)(?:\?[a-zA-Z0-9_=&%.\-{}\$]*)?)[\'"`]',
)

# Noise to strip out — file extensions / asset paths that technically
# match "starts with /" but are never an API endpoint worth reporting.
_ASSET_EXT_RE = re.compile(
    r'\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|map|mp4|webm|avif)(?:[?#]|$)',
    re.IGNORECASE,
)


def _clean_path(raw: str) -> str:
    return raw.strip().strip('"\'`')


def _extract_endpoints(content: str, source_url: str) -> list:
    # Keyed on PATH alone (not (path, method)) — several of the patterns
    # below legitimately rediscover the same literal path with no method
    # attached (e.g. _API_LOOKING_PATH_RE matching the same string literal
    # a fetch()/axios.post() call already captured WITH a method). Keying
    # on (path, method) made that second, method-less discovery a
    # SEPARATE entry that could silently win a naive "last one wins"
    # lookup and erase the real method a researcher actually needs (e.g.
    # reporting axios.post("/api/v2/auth/login", ...) as a bare, methodless
    # route instead of the POST it actually is). Keying on path alone and
    # merging every method seen for it fixes that.
    paths: dict = {}

    def _record(path: str, method: str = ""):
        path = _clean_path(path)
        if not path:
            return
        # Collapse template-literal interpolations wherever they show up
        # (not just in a dedicated template-literal pass) — the
        # quote-agnostic method-call regex also matches backtick strings,
        # so `fetch(\`${API_BASE}/users/${id}\`)` is captured whole here
        # too; without this, the raw "${API_BASE}/users/${id}" leaks the
        # JS variable name instead of reading as a route shape.
        if "${" in path:
            path = re.sub(r'\$\{[^}]+\}', '{param}', path)
        if len(path) < 2:
            return
        _looks_like_endpoint = (
            path.startswith("/") or path.startswith("http") or path.startswith("{param}")
            or bool(_SCRIPT_EXT_RE.search(path))  # relative classic-backend-script ref, e.g. "components/user/controller.php?action=X"
        )
        if not _looks_like_endpoint:
            return
        if _ASSET_EXT_RE.search(path):
            return
        entry = paths.setdefault(path, {"methods": set(), "source": source_url})
        if method:
            entry["methods"].add(method.upper())

    for m in _METHOD_CALL_RE.finditer(content):
        is_fetch = content[m.start():m.start() + 5].lower() == "fetch"
        method = (m.group(1) or "").upper()
        if not method and is_fetch:
            method = "GET"
        _record(m.group(2), method)

    for m in _XHR_OPEN_RE.finditer(content):
        _record(m.group(2), m.group(1))

    for m in _CONFIG_KEY_RE.finditer(content):
        _record(m.group(1))

    for m in _API_LOOKING_PATH_RE.finditer(content):
        _record(m.group(1))

    for m in _TEMPLATE_LITERAL_RE.finditer(content):
        _record(m.group(1))

    for m in _BARE_SCRIPT_REF_RE.finditer(content):
        _record(m.group(1))

    graphql_ops = sorted(set(m.group(1) for m in _GRAPHQL_OP_RE.finditer(content)))

    results = []
    for path, info in paths.items():
        methods = sorted(info["methods"])
        results.append({
            "url": path,
            # Several distinct methods on the same route (e.g. both GET
            # and POST to the same endpoint) are reported together rather
            # than arbitrarily picking one — "/".join keeps it a single
            # readable field instead of forcing a list every consumer has
            # to special-case.
            "method": "/".join(methods) if methods else None,
            "source": info["source"],
        })
    return results, graphql_ops


def _discover_js_files(target_url: str, session: requests.Session, spider_intel: dict, explicit_js_urls=None) -> list:
    js_files = set()

    if explicit_js_urls:
        for u in explicit_js_urls:
            if u:
                js_files.add(u)

    # 1. Anything spider/katana already discovered this session.
    for ep in (spider_intel or {}).get("endpoints", []):
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        if url.endswith(".js"):
            js_files.add(url)

    # 2. Live crawl of the target page itself — same proven approach
    # BlobUnpacker already uses (regular <script src>, plus Next.js
    # _buildManifest.js chunk discovery for SPA bundles that don't show up
    # as plain <script> tags in the initial HTML at all).
    try:
        resp = session.get(target_url, timeout=10, verify=False, allow_redirects=True)
        if resp.status_code == 200:
            html = resp.text
            for src in re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html, re.IGNORECASE):
                js_files.add(urljoin(target_url, src))

            manifest_match = re.search(r'/_next/static/([^/]+)/_buildManifest\.js', html)
            if manifest_match:
                build_id = manifest_match.group(1)
                manifest_url = urljoin(target_url, f"/_next/static/{build_id}/_buildManifest.js")
                try:
                    m_resp = session.get(manifest_url, timeout=8, verify=False)
                    if m_resp.status_code == 200:
                        for chunk in re.findall(r'["\']([^"\']+\.js)["\']', m_resp.text):
                            if not chunk.startswith(("http", "/")):
                                chunk = f"/_next/{chunk}"
                            js_files.add(urljoin(target_url, chunk))
                except Exception:
                    pass

            # Generic webpack-style chunk-manifest hint: a lot of non-Next
            # bundlers still emit a "webpackJsonp" / chunk-map script that
            # references further .js chunk filenames as bare strings —
            # cheap to also sweep any inline <script> (not just src=) for
            # further *.js-looking string literals, since those chunks
            # are exactly the ones that never show up as a real <script
            # src=...> tag at all.
            for inline in re.findall(r'<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>', html, re.IGNORECASE):
                for chunk in re.findall(r'["\']([a-zA-Z0-9_\-./]+\.js)["\']', inline):
                    if chunk.startswith(("http", "/")) or "/" in chunk:
                        js_files.add(urljoin(target_url, chunk))
    except Exception:
        pass

    return list(js_files)


def run(target, emit, options=None):
    opt = options or {}
    spider_intel = opt.get("spider_intel", {})

    from hellhound.core import http_utils
    session = requests.Session()
    http_utils.apply_session_config(session, opt)

    target_url = target if str(target).startswith(("http://", "https://")) else f"https://{target}"

    emit.progress_start("JSMiner")
    emit.info(f"JS Miner: discovering JS bundles for {target_url}")

    js_files = _discover_js_files(target_url, session, spider_intel, explicit_js_urls=opt.get("js_urls"))

    if not js_files:
        emit.progress_stop()
        emit.info("No JS files discovered to mine.")
        return {
            "raw": "No JS files found.",
            "intel": {"endpoints": [], "graphql_operations": [], "js_files_scanned": 0},
            "risk_score": 0,
        }

    # Same throttle BlobUnpacker uses, same reason: don't hang the
    # framework scanning hundreds of chunk files on a huge SPA.
    js_todo = js_files[:50]
    emit.info(f"Fetching and mining {len(js_todo)} JS file(s) for API endpoints...")

    all_endpoints = []
    all_graphql_ops = set()
    fetched = 0
    fetch_errors = 0

    for i, js_url in enumerate(js_todo):
        emit.progress_update(i, "JSMiner")
        try:
            resp = session.get(js_url, timeout=10, verify=False)
            if resp.status_code != 200 or not resp.text:
                continue
            fetched += 1
            eps, graphql_ops = _extract_endpoints(resp.text, js_url)
            all_endpoints.extend(eps)
            all_graphql_ops.update(graphql_ops)
        except Exception:
            fetch_errors += 1
            continue

    emit.progress_stop()

    # Dedup across files — the same endpoint string often appears in
    # several chunks (shared API client module bundled into each page
    # chunk), and the researcher wants the distinct route list, not one
    # entry per chunk it happens to be bundled into.
    seen = set()
    deduped = []
    for ep in all_endpoints:
        key = (ep["url"], ep["method"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ep)

    if deduped:
        emit.success(f"[+] JS Miner found {len(deduped)} distinct endpoint(s) across {fetched} JS file(s).")
    else:
        emit.info(f"Fetched {fetched} JS file(s) but found no endpoint-shaped strings in them.")

    return {
        "raw": f"Mined {len(deduped)} endpoints from {fetched} JS file(s) ({len(js_todo)} attempted, {fetch_errors} fetch error(s)).",
        "intel": {
            "endpoints": deduped,
            "graphql_operations": sorted(all_graphql_ops),
            "js_files_scanned": fetched,
            "js_files_found": len(js_files),
            "fetch_errors": fetch_errors,
        },
        "risk_score": 0,
    }
