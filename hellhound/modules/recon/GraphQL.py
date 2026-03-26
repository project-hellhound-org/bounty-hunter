import requests
import json
import urllib.parse

NAME = "graphql_hunter"
CATEGORY = "recon"
DESCRIPTION = "Advanced GraphQL endpoint discovery and introspection analysis"
OPTIONS = [
    {"name": "manual_endpoint", "type": str, "default": "", "help": "Provide a manual GraphQL endpoint to test (e.g. http://site.com/graphql)"}
]

def test_graphql(url, emit):
    # 1. Test Introspection
    introspection_query = {"query": "{__schema{types{name}}}"}
    
    # 2. Test Field Suggestion (error-based detection)
    suggestion_query = {"query": "{hellhound_probe}"}

    headers = {"Content-Type": "application/json"}
    
    findings = {}
    is_graphql = False
    
    try:
        # Try POST suggestion first (lowest impact to confirm it's GraphQL)
        r = requests.post(url, json=suggestion_query, headers=headers, timeout=5)
        if r.status_code in [200, 400] and "errors" in r.text:
            if "Cannot query field" in r.text or "hellhound_probe" in r.text:
                is_graphql = True
                findings["endpoint"] = url
                findings["suggestions_enabled"] = True
    except Exception:
        pass
        
    try:
        # Try POST introspection
        r = requests.post(url, json=introspection_query, headers=headers, timeout=5)
        if r.status_code == 200 and "data" in r.text and "__schema" in r.text:
            is_graphql = True
            findings["endpoint"] = url
            findings["introspection_enabled"] = True
    except Exception:
        pass
        
    if not is_graphql:
        try:
            # Try GET introspection as fallback
            get_url = f"{url}?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
            r = requests.get(get_url, timeout=5)
            if r.status_code == 200 and "data" in r.text and "__schema" in r.text:
                is_graphql = True
                findings["endpoint"] = url
                findings["introspection_enabled"] = True
        except Exception:
            pass
            
    return findings if is_graphql else None

def run(target, emit, options=None):
    emit.info(f"[*] GraphQL Hunter: Analyzing {target}")
    
    base_url = target if target.startswith("http") else f"http://{target}"
    base_url = base_url.rstrip("/")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    urls_to_test = set()
    
    # 1. Manual user endpoint
    if options and options.get("manual_endpoint"):
        urls_to_test.add(options.get("manual_endpoint"))
    
    # 2. Standard GraphQL paths (expanded)
    standard_paths = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/graphiql", "/api/graphiql", "/graphql.php", "/graphql/console",
        "/api/v1/graphql", "/api/v2/graphql", "/query", "/api/query",
        "/.well-known/graphql", "/explorer", "/api/explorer"
    ]
    for p in standard_paths:
        urls_to_test.add(base_url + p)
        # Also try without the leading slash if the base_url is just a domain
        urls_to_test.add(base_url.rstrip("/") + p)
        
    # 3. Spider endpoints
    for ep in endpoints:
        ep_url = ep.get("url")
        if ep_url:
            urls_to_test.add(ep_url.split("?")[0])
            
    urls_to_test = list(urls_to_test)
    if len(urls_to_test) > 150:
        urls_to_test = urls_to_test[:150]
        
    emit.info(f"    [i] Testing {len(urls_to_test)} potential endpoints...")
    
    discovered = []
    signals = []
    risk_score = 0
    
    for url in urls_to_test:
        result = test_graphql(url, emit)
        if result:
            discovered.append(result)
            emit.success(f"    [+] GraphQL Endpoint found: {url}")
            if result.get("introspection_enabled"):
                emit.warn(f"        [!] Introspection is ENABLED (Critical Info Leak)")
                risk_score += 8
            if result.get("suggestions_enabled"):
                emit.warn(f"        [!] Field Suggestions are ENABLED")
                risk_score += 2
                
            # If we explicitly found it on a standard path not in spider, record it
            if url not in [e.get("url") for e in endpoints]:
                signals.append("HIDDEN_GRAPHQL_DISCOVERED")

    if discovered:
        signals.append("GRAPHQL_EXPOSED")
        emit.success(f"[+] Found {len(discovered)} active GraphQL endpoints.")
    else:
        emit.info("[-] No GraphQL endpoints detected.")
        
    return {
        "raw": f"GraphQL Endpoints: {len(discovered)}",
        "intel": {"graphql_endpoints": discovered, "risk_score": risk_score},
        "signals": signals
    }
