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
    session.proxies.update(proxies)

def apply_session_config(session, options: dict):
    """
    Standardizes session configuration for all Hellhound modules.
    Applies proxy, merges global headers, and adds WAF bypass if enabled.
    """
    # 1. Apply Proxy
    proxy = options.get("proxy")
    if proxy:
        apply_proxy_to_session(session, proxy)
    
    # 2. Merge Headers
    options["global_headers"] = options.get("global_headers", {})
    headers = merge_global_context(options, session.headers.copy())
    session.headers.update(headers)
    
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

def merge_global_context(options: dict, runtime_headers: dict = None) -> dict:
    """
    Merges global context (proxy, global_headers) into module options.
    Safely handles BugBounty headers and WAF bypasses.
    """
    headers = runtime_headers or {}
    
    # 1. Apply Global Headers (Bug Bounty IDs, etc.)
    gt = options.get("global_headers", {})
    if gt:
        headers.update(gt)
    
    # 2. Apply WAF Bypasses if requested
    if options.get("enable_waf_bypass"):
        headers.update(get_waf_bypass_header())
        
    return headers
