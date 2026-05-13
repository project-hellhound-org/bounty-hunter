import re
import json
import urllib.parse
from collections import deque

# ANSI escape sequence regex
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# Metadata/Source strings to ignore as nodes
GARBAGE_SOURCES = {
    "html_link", "wellknown", "spa_xhr", "js_analysis", 
    "spider_heuristic", "manual_entry", "regex_fallback",
    "directory_brute", "config_leak", "unknown"
}

# Keys that often contain actual findings or further nested objects
CONTAINER_KEYS = {
    "intel", "data", "results", "findings", "report", "output", 
    "vulnerabilities", "endpoints", "secrets", "findings_list", "cves"
}

# Role Classification Keywords (Generic & Refined)
ROLE_HEURISTICS = {
    "PRIVILEGE_CARRIER": ["key", "token", "secret", "password", "credential", "auth", "jwt", "cookie", "session", "bearer", "ssh", "access", "privilege", "client_id", "client_secret"],
    "VALUE_CONTAINER": ["admin", "dashboard", "internal", "backup", "config", "database", "db", "user", "profile", "private", "root", "financial", "payment", "pii", "vault", "s3", "bucket", "storage", "backup", "etc/passwd", ".env", ".git"],
    "ACCESS_POINT": ["login", "api", "graphql", "oauth", "signin", "signup", "portal", "gateway", "entry", "webhook", "rest", "v1", "v2", "sso", "saml", "ldap"],
    "WEAKNESS": ["vulnerability", "vuln", "cve", "finding", "issue", "flaw", "bug", "weakness", "exploit", "risk", "cwe", "security", "sqli", "xss", "idor", "ssrf", "rce", "lfi", "rfi", "csrf", "broken_access"],
    "TARGET_ASSET": ["url", "endpoint", "domain", "host", "server", "cloud", "storage", "blob"]
}

DEBUG = True # Set to True to enable production-tuning logs

def log_debug(msg):
    if DEBUG: print(f"[NODES_ENGINE_DEBUG] {msg}")

def clean_string(s):
    """Strip ANSI and whitespace."""
    if not isinstance(s, str): return str(s)
    return ANSI_RE.sub('', s).strip()

def is_garbage(s):
    """Filter out non-meaningful strings."""
    if not isinstance(s, str): return True
    s_clean = clean_string(s)
    if not s_clean: return True
    if s_clean.isdigit(): return True
    if s_clean.lower() in GARBAGE_SOURCES: return True
    if s_clean.startswith('{') and s_clean.endswith('}'): return True
    if s_clean.startswith('[') and s_clean.endswith(']'): return True
    return False

def normalize_url(url):
    """Normalize URL for consistent node identity."""
    s = clean_string(url)
    try:
        parsed = urllib.parse.urlparse(s)
        path = parsed.path.rstrip('/')
        if not path: path = ''
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    except:
        return s

def clamp(n, min_n=0, max_n=10):
    return max(min_n, min(n, max_n))

def classify_role(label, node_type, metadata=None):
    """Generic heuristic-driven role classification with score normalization."""
    l = label.lower()
    t = node_type.lower()
    m = str(metadata).lower() if metadata else ""
    
    # Priority 1: Explicit Vulnerability
    if "vuln" in t or any(x in l for x in ROLE_HEURISTICS["WEAKNESS"]):
        score = 5
        sev = (metadata or {}).get("severity", "").lower()
        if "critical" in sev: score = 10
        elif "high" in sev: score = 8
        elif "medium" in sev: score = 5
        elif "low" in sev: score = 3
        # Direct vulnerability keyword match boost
        if any(x in l for x in ["rce", "sqli", "lfi"]): score = max(score, 9)
        log_debug(f"Role classified: {label} -> WEAKNESS (score: {score})")
        return "WEAKNESS", clamp(score)
    
    # Priority 2: Privilege Carriers
    if any(x in l or x in t for x in ROLE_HEURISTICS["PRIVILEGE_CARRIER"]):
        score = 7
        if any(x in l for x in ["admin", "root", "prod", "private_key"]): score = 10
        elif "secret" in l or "key" in l: score = 8
        log_debug(f"Role classified: {label} -> PRIVILEGE_CARRIER (score: {score})")
        return "PRIVILEGE_CARRIER", clamp(score)
        
    # Priority 3: Value Containers
    if any(x in l or x in t for x in ROLE_HEURISTICS["VALUE_CONTAINER"]):
        score = 6
        if any(x in l for x in ["financial", "payment", "pii", "admin", "vault", "backup"]): score += 3
        log_debug(f"Role classified: {label} -> VALUE_CONTAINER (score: {score})")
        return "VALUE_CONTAINER", clamp(score)
        
    # Priority 4: Access Points
    if any(x in l or x in t for x in ROLE_HEURISTICS["ACCESS_POINT"]):
        score = 5
        if "login" in l or "oauth" in l: score = 6
        log_debug(f"Role classified: {label} -> ACCESS_POINT (score: {score})")
        return "ACCESS_POINT", clamp(score)
        
    # Default: Target Asset
    score = 4
    log_debug(f"Role classified: {label} -> TARGET_ASSET (score: {score})")
    return "TARGET_ASSET", clamp(score)

def synthesize_attack_chains(nodes, edges):
    """
    POLISHED HEURISTIC ENGINE: Discovering meaningful attack paths.
    Includes deduplication, pruning, and 3D rendering enhancements.
    """
    all_chains = []
    
    # Build Adjacency List
    adj = {}
    for edge in edges:
        u, v = edge["data"]["source"], edge["data"]["target"]
        if u not in adj: adj[u] = []
        adj[u].append(v)
        
    # Filter key node roles
    access_points = [n for n in nodes if n["data"]["role"] == "ACCESS_POINT"]
    value_containers = [n for n in nodes if n["data"]["role"] == "VALUE_CONTAINER"]

    # 1. Path-Based Synthesis (Entry -> Target)
    for start in access_points:
        start_id = start["data"]["id"]
        # BFS with depth limit and early termination
        q = deque([(start_id, [start_id], 0)]) # (node_id, path, depth)
        visited_at_depth = {start_id: 0}
        
        while q:
            curr_id, path, depth = q.popleft()
            
            if depth >= 4: continue # PERFORMANCE: Don't explore beyond 4 hops
            
            # Check if we hit a value container
            target_node = next((n for n in value_containers if n["data"]["id"] == curr_id), None)
            if target_node and len(path) >= 2: # PRUNING: Minimum path length
                # Found a potential chain!
                path_nodes = [next(n for n in nodes if n["data"]["id"] == pid) for pid in path]
                has_weakness = any(n["data"]["role"] == "WEAKNESS" for n in path_nodes)
                has_carrier = any(n["data"]["role"] == "PRIVILEGE_CARRIER" for n in path_nodes)
                
                if has_weakness or has_carrier: # PRUNING: Require weakness or carrier
                    # Calculate Confidence
                    conf = 0.5
                    if has_weakness: conf += 0.25
                    if has_carrier: conf += 0.15
                    if len(path) <= 3: conf += 0.1
                    conf = clamp(conf, 0, 1.0)
                    
                    if conf >= 0.6: # PRUNING: Minimum confidence
                        w_node = next((n for n in path_nodes if n["data"]["role"] == "WEAKNESS"), None)
                        c_node = next((n for n in path_nodes if n["data"]["role"] == "PRIVILEGE_CARRIER"), None)
                        
                        # Dynamic Naming
                        vuln_type = w_node["data"]["label"].upper() if w_node else (c_node["data"]["label"].upper() if c_node else "UNKNOWN")
                        chain_label = f"{vuln_type.split('_')[0]} -> {target_node['data']['label'].upper()}_COMPROMISE"
                        
                        all_chains.append({
                            "target_id": curr_id,
                            "confidence": conf,
                            "label": chain_label,
                            "path_nodes": [n["data"]["id"] for n in path_nodes],
                            "description": f"Attack path: {' -> '.join([n['data']['label'] for n in path_nodes])}",
                            "severity": "critical" if conf > 0.8 else "high"
                        })
                        log_debug(f"Chain discovered: {chain_label} (conf: {conf})")
                        # PERFORMANCE: Early termination on this path branch
                        continue 

            # Continue Search
            for neighbor in adj.get(curr_id, []):
                # Standard BFS allows re-visiting nodes at different depths, but for attack chains we avoid cycles
                if neighbor not in path:
                    q.append((neighbor, path + [neighbor], depth + 1))

    # 2. Deduplication (Group by Target, keep best)
    deduped_chains = {}
    for c in all_chains:
        tid = c["target_id"]
        if tid not in deduped_chains or c["confidence"] > deduped_chains[tid]["confidence"]:
            if tid in deduped_chains:
                # Merge alternative path info
                c["alternative_paths"] = deduped_chains[tid].get("alternative_paths", []) + [deduped_chains[tid]["path_nodes"]]
            deduped_chains[tid] = c
        else:
            # Store as alternative path
            deduped_chains[tid].setdefault("alternative_paths", []).append(c["path_nodes"])

    # 3. Final Format (Max 20 chains for noise reduction)
    final_nodes = []
    sorted_chains = sorted(deduped_chains.values(), key=lambda x: x["confidence"], reverse=True)[:20]
    
    for i, c in enumerate(sorted_chains):
        chain_id = f"chain_{i}"
        node = {
            "data": {
                "id": chain_id,
                "label": c["label"],
                "type": "attack_chain",
                "role": "SYNTHESIS",
                "layer": "post_exploit",
                "severity": c["severity"],
                "size": 45,             # 3D RENDERER POLISH
                "color": "#9b5de5",     # 3D RENDERER POLISH
                "glow": True,           # 3D RENDERER POLISH
                "pulsate": True,        # 3D RENDERER POLISH
                "metadata": {
                    "description": c["description"],
                    "confidence": "HIGH" if c["confidence"] > 0.8 else "MEDIUM",
                    "path_nodes": c["path_nodes"],
                    "alternative_paths_count": len(c.get("alternative_paths", []))
                }
            }
        }
        final_nodes.append(node)
        
    return final_nodes

def build_graph(loot_map, howl=None):
    """
    Production-ready graph engine with optimized synthesis.
    """
    nodes = []
    edges = []
    node_cache = {}
    id_counter = 0

    def add_node(label, node_type, metadata=None):
        nonlocal id_counter
        if not label or is_garbage(label): return None
        
        label = normalize_url(label) if "url" in node_type or "endpoint" in node_type else clean_string(label)
        key = (label, node_type)
        if key in node_cache: return node_cache[key]
        
        role, score = classify_role(label, node_type, metadata)
        node_id = f"n{id_counter}"
        
        node_entry = {
            "data": {
                "id": node_id,
                "label": label,
                "type": node_type,
                "role": role,
                "privilege_score": score,
                "metadata": metadata or {"confidence": "MEDIUM", "source": "HEURISTIC"}
            }
        }
        nodes.append(node_entry)
        node_cache[key] = node_id
        id_counter += 1
        return node_id

    def add_edge(u, v, label):
        if u is None or v is None or u == v: return
        edge_id = f"e{u}_{v}"
        if not any(e["data"]["id"] == edge_id for e in edges):
            edges.append({"data": {"id": edge_id, "source": u, "target": v, "label": label}})

    # Initial Extraction Loop (Recursive)
    def process_recursive(data, parent_id, mod_id, mod_name):
        if isinstance(data, dict):
            if "url" in data and ("params_list" in data or "method" in data):
                u_id = add_node(data["url"], "endpoint", {"source": mod_name, "method": data.get("method", "GET")})
                add_edge(mod_id, u_id, "mapped")
                for p in data.get("params_list", []):
                    p_id = add_node(p, "parameter", {"source": mod_name}); add_edge(u_id, p_id, "accepts")
                for k, v in data.items():
                    if k not in ["url", "params_list"]: process_recursive(v, u_id, mod_id, mod_name)
                return
            if "content" in data and "source" in data:
                s_id = add_node(data["content"], "secret", {"source": mod_name, "found_in": data["source"]})
                u_id = add_node(data["source"], "url", {"source": mod_name}); add_edge(u_id, s_id, "leaks")
                return
            if "type" in data and ("url" in data or "endpoint" in data):
                v_id = add_node(data["type"], "vulnerability", {**data, "source": mod_name})
                u_val = data.get("url") or data.get("endpoint")
                u_id = add_node(u_val, "url", {"source": mod_name}); add_edge(u_id, v_id, "vulnerable_at")
                return
            for k, v in data.items():
                if k.lower() in CONTAINER_KEYS: process_recursive(v, parent_id, mod_id, mod_name)
                elif any(x in k.lower() for x in ["url", "endpoint"]) and isinstance(v, str):
                    u_id = add_node(v, "url", {"source": mod_name}); add_edge(parent_id, u_id, "discovered")
                elif any(x in k.lower() for x in ["secret", "token", "key", "password"]) and isinstance(v, str):
                    s_id = add_node(v, "secret", {"source": mod_name}); add_edge(parent_id, s_id, "leaks")
                elif any(x in k.lower() for x in ["vulnerab", "finding", "issue"]) and isinstance(v, str):
                    v_id = add_node(v, "vulnerability", {"source": mod_name}); add_edge(parent_id, v_id, "reported")
                elif isinstance(v, (dict, list)): process_recursive(v, parent_id, mod_id, mod_name)
        elif isinstance(data, list):
            for item in data: process_recursive(item, parent_id, mod_id, mod_name)
        elif isinstance(data, str) and "://" in data:
            u_id = add_node(data, "url", {"source": mod_name}); add_edge(parent_id, u_id, "referenced")

    # Start Processing
    for mod_key, module_data in loot_map.items():
        mod_name = mod_key.upper().split('/')[-1].replace('.JSON', '')
        mod_id = add_node(mod_name, "module", {"source": "CORE"})
        process_recursive(module_data, mod_id, mod_id, mod_name)

    # RUN SYNTHESIS
    chains = synthesize_attack_chains(nodes, edges)
    
    # Merge chains into graph with Enhanced Edge Labels
    for chain in chains:
        nodes.append(chain)
        path_node_ids = chain["data"]["metadata"].get("path_nodes", [])
        for pid in path_node_ids:
            # Find the member node to determine edge label
            member = next(n for n in nodes if n["data"]["id"] == pid)
            label = "part_of_chain"
            if member["data"]["role"] == "WEAKNESS": label = "exploits"
            elif member["data"]["role"] == "PRIVILEGE_CARRIER": label = "uses_credential"
            elif member["data"]["role"] == "ACCESS_POINT": label = "entry_via"
            elif member["data"]["role"] == "VALUE_CONTAINER": label = "targets"
            
            add_edge(pid, chain["data"]["id"], label)

    # Final mapping for 3D renderer
    return {
        "nodes": [{"id": n["data"]["id"], **n["data"]} for n in nodes],
        "links": [{"source": e["data"]["source"], "target": e["data"]["target"], "label": e["data"]["label"]} for e in edges]
    }
