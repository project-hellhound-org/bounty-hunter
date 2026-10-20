import urllib.request
import ssl
import random

# ==========================================================
# WAF BYPASS DATA
# ==========================================================

WAF_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Proto": "http"}
]

# ==========================================================
# UNIFIED PROXY & HEADER UTILS
# ==========================================================

def get_waf_bypass_header() -> dict:
    """Returns a random WAF bypass header."""
    return random.choice(WAF_BYPASS_HEADERS)

def apply_proxy_to_session(session, proxy_url: str):
    """Applies a proxy to a requests.Session instance."""
    if not proxy_url:
        return
    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }
    if hasattr(session, "proxies"):
        session.proxies.update(proxies)
    else:
        # aiohttp sessions don't have a proxies attribute; 
        # proxy is usually handled per-request or in connector
        pass

def apply_session_config(session, options: dict):
    """
    Standardizes session configuration for all Hellhound modules.
    Applies proxy, merges global headers, carries over the target's
    captured authenticated session (if any), and adds WAF bypass if enabled.

    `options=None` is tolerated (treated as {}) rather than crashing — a
    caller that forgets to pass options used to blow up here with
    AttributeError on the very first `.get()` below, which every module's
    own broad `except Exception` then swallowed silently: the module
    LOOKED like it ran (no visible error) but every request inside it
    never actually fired. wafbuster's own agent.py wrapper was hitting
    exactly this (never passed `options` at all) — confirmed independently
    while wiring auth through here, not a hypothetical.
    """
    options = options or {}

    # 1. Apply Proxy
    proxy = options.get("proxy")
    if proxy:
        apply_proxy_to_session(session, proxy)

    # 2. Merge Headers
    options["global_headers"] = options.get("global_headers", {})
    headers = merge_global_context(options, session.headers.copy())
    if hasattr(session, "_default_headers"):
        session._default_headers.update(headers)
    elif hasattr(session, "headers"):
        try:
            session.headers.update(headers)
        except (AttributeError, TypeError):
            pass # Immutable headers (like aiohttp) should be handled by the caller or during creation

    # 2b. Carry over the target's already-captured authenticated session.
    # Every one of these rule-based modules (CORSbuster, GraphQL hunter,
    # WAFbuster, SurfaceAuditor, TransportAuditor) used to build its own
    # bare, unauthenticated requests.Session() — a real gap for exactly
    # the checks that matter most while logged in (does this CORS misconfig
    # actually leak an authenticated response, does this GraphQL mutation
    # work once authenticated, does the WAF behave differently for a real
    # session). Callers pass the captured state as auth_cookies (dict) and
    # auth_headers (dict) in options; this applies both onto the session
    # that's about to be used, same source of truth (target.state) every
    # other request-sending tool already reads from.
    auth_cookies = options.get("auth_cookies")
    if isinstance(auth_cookies, dict):
        for k, v in auth_cookies.items():
            try:
                session.cookies.set(str(k), str(v))
            except Exception:
                pass
    auth_headers = options.get("auth_headers")
    if isinstance(auth_headers, dict) and hasattr(session, "headers"):
        try:
            session.headers.update({str(k): str(v) for k, v in auth_headers.items()})
        except (AttributeError, TypeError):
            pass

    # 3. Security configurations
    session.verify = False # Modules typically handle internal/self-signed certs

def get_urllib_opener(proxy_url: str = None):
    """Returns a urllib.request opener with optional proxy support."""
    handlers = []
    
    # SSL context to ignore self-signed certs (common with proxies)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    
    if proxy_url:
        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        handlers.append(proxy_handler)
        
    return urllib.request.build_opener(*handlers)

from typing import Any, Dict, Optional


def normalize_headers(raw: Any) -> Dict[str, str]:
    """Safely converts dicts, string blobs, or header lists into a standardized {str: str} dict."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, (list, tuple)):
        out = {}
        for item in raw:
            if isinstance(item, str) and ":" in item:
                k, v = item.split(":", 1)
                out[k.strip()] = v.strip()
        return out
    if isinstance(raw, str):
        out = {}
        for line in raw.splitlines():
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
        return out
    return {}


def normalize_cookies(raw: Any) -> Dict[str, str]:
    """Safely converts dicts or cookie strings ('k=v; a=b') into a {str: str} dict."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str):
        out = {}
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out
    return {}


def merge_global_context(options: Any, runtime_headers: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    Merges global context (proxy, global_headers) into module options.
    Safely handles BugBounty headers and WAF bypasses.
    """
    headers: Dict[str, str] = {}
    if isinstance(runtime_headers, dict):
        headers = {str(k): str(v) for k, v in runtime_headers.items()}

    opts_dict = options if isinstance(options, dict) else {}

    # 1. Check for researcher handle to inject X-Bugbounty header
    handle = opts_dict.get("researcher_handle")
    if not handle:
        from hellhound.core.ai_utils import load_config
        cfg = load_config()
        handle = cfg.get("researcher_handle", "")
    if handle and "X-Bugbounty" not in headers:
        headers["X-Bugbounty"] = str(handle)

    # 2. Apply Global Headers (Bug Bounty IDs, etc.)
    gt = opts_dict.get("global_headers", {})
    if gt:
        headers.update(normalize_headers(gt))
    
    # 3. Apply WAF Bypasses if requested
    if opts_dict.get("enable_waf_bypass"):
        headers.update(get_waf_bypass_header())
        
    return headers