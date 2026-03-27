import requests
import json
import urllib.parse
import re

NAME = "graphql_hunter"
CATEGORY = "recon"
DESCRIPTION = "Advanced GraphQL discovery and active security testing (Depth, Suggestion, Introspection)"

def test_graphql(url, emit):
    headers = {"Content-Type": "application/json"}
    is_graphql = False
    findings = {"endpoint": url, "vulnerabilities": []}

    # 1. Introspection Check (POST then GET)
    introspection = {"query": "{__schema{types{name}}}"}
    try:
        r = requests.post(url, json=introspection, headers=headers, timeout=5)
        if r.status_code == 200 and "__schema" in r.text:
            is_graphql = True
            findings["introspection_enabled"] = True
            findings["vulnerabilities"].append("CRITICAL: Introspection is ENABLED (via POST)")
        
        # Test for GET-based introspection (often missed by WAFs/Loggers)
        get_url = f"{url}?query=" + urllib.parse.quote("{__schema{types{name}}}")
        r_get = requests.get(get_url, timeout=5)
        if r_get.status_code == 200 and "__schema" in r_get.text:
            is_graphql = True
            findings["vulnerabilities"].append("CRITICAL: Introspection is ENABLED (via GET)")
    except: pass

    # 2. Field Suggestions Check
    suggestion = {"query": "{hellhound_probe}"}
    try:
        r = requests.post(url, json=suggestion, headers=headers, timeout=5)
        if "errors" in r.text and ("Cannot query field" in r.text or "Did you mean" in r.text):
            is_graphql = True
            findings["suggestions_enabled"] = True
            findings["vulnerabilities"].append("MEDIUM: Field Suggestions are ENABLED")
    except: pass

    if not is_graphql: return None

    # 3. Query Depth / Complexity Test (DOS)
    # Build a deep query: { user { user { user ... } } }
    deep_q = "{" + (" user { " * 8) + " id " + (" } " * 8) + "}"
    try:
        r = requests.post(url, json={"query": deep_q}, headers=headers, timeout=5)
        if r.status_code == 200 and "errors" not in r.text:
            findings["vulnerabilities"].append("HIGH: Deeply nested queries (Depth 8+) accepted (potential DOS)")
        elif "depth" in r.text.lower() or "too deep" in r.text.lower():
            findings["vulnerabilities"].append("INFO: Query depth limit detected")
    except: pass

    # 4. Alias Overload Test (DOS)
    # query { a: user{id} b: user{id} ... }
    alias_q = "query { " + " ".join([f"a{i}: __typename" for i in range(50)]) + " }"
    try:
        r = requests.post(url, json={"query": alias_q}, headers=headers, timeout=5)
        if r.status_code == 200 and "data" in r.text:
            findings["vulnerabilities"].append("MEDIUM: Large number of aliases accepted (potential Resource Exhaustion)")
    except: pass

    return findings

def run(target, emit, options=None):
    emit.info(f"[*] GraphQL Hunter: {target}")
    url = target if target.startswith("http") else f"http://{target}"
    
    # 1. Discover Endpoints
    potential = set([
        url + "/graphql", url + "/api/graphql", url + "/v1/graphql", 
        url + "/graphiql", url + "/query", url + "/api/v1/graphql",
        url + "/api/v2/graphql", url + "/gql", url + "/api/gql",
        url + "/graph", url + "/api/graph", url + "/explorer",
        url + "/console"
    ])
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    for ep in spider_intel.get("endpoints", []):
        u = ep.get("url", "")
        if "graphql" in u.lower() or "graphiql" in u.lower():
            potential.add(u.split("?")[0])

    discovered = []
    risk = 0
    for up in list(potential)[:50]:
        res = test_graphql(up, emit)
        if res:
            discovered.append(res)
            emit.success(f"    [+] GraphQL Found: {up}")
            for v in res["vulnerabilities"]:
                emit.warn(f"        [!] {v}")
                risk += 8 if "CRITICAL" in v else 4 if "HIGH" in v else 2
    
    return {"raw": f"Found {len(discovered)} GraphQL endpoints", "intel": {"endpoints": discovered, "risk_score": risk}, "signals": ["GRAPHQL_EXPOSED"] if discovered else []}
