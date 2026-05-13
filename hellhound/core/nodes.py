import re
import json
import urllib.parse

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

def clean_string(s):
    """Strip ANSI and whitespace."""
    if not isinstance(s, str): return str(s)
    return ANSI_RE.sub('', s).strip()

def is_garbage(s):
    """Filter out non-meaningful strings like counts, sources, or raw JSON."""
    if not isinstance(s, str): return True
    s_clean = clean_string(s)
    if not s_clean: return True
    if s_clean.isdigit(): return True
    if s_clean.lower() in GARBAGE_SOURCES: return True
    if s_clean.startswith('{') and s_clean.endswith('}'): return True
    if s_clean.startswith('[') and s_clean.endswith(']'): return True
    if '\\u001b' in s_clean or '\x1b' in s_clean: return True
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

def build_graph(loot_map):
    """
    Parses the lootMap and builds a clean, high-fidelity 2D attack graph (Maltego Style).
    """
    nodes = []
    edges = []
    node_cache = {}  # (label, type) -> id
    id_counter = 0

    def get_layer(node_type):
        mapping = {
            "module": "core",
            "url": "recon",
            "endpoint": "recon",
            "secret": "intel",
            "parameter": "intel",
            "vulnerability": "vuln_core",
            "technology": "technology",
            "attack_chain": "post_exploit"
        }
        return mapping.get(node_type, "external")

    def get_size(node_type, severity=None):
        if node_type == "vulnerability":
            if severity == "critical": return 60
            if severity == "high": return 50
            if severity == "medium": return 40
            return 35
        if node_type == "module": return 45
        if "url" in node_type or "endpoint" in node_type: return 40
        return 35

    def get_color(node_type, severity=None):
        if node_type == "vulnerability":
            if severity == "critical": return "#dc2626"
            if severity == "high": return "#ef4444"
            if severity == "medium": return "#f97316"
            return "#fbbf24"
        if "secret" in node_type: return "#f4a261"
        if "url" in node_type or "endpoint" in node_type: return "#48cae4"
        if node_type == "module": return "#ffffff"
        if "tech" in node_type: return "#2a9d8f"
        return "#6c757d"

    def add_node(label, node_type, metadata=None):
        nonlocal id_counter
        if not label or is_garbage(label): return None
        
        if "url" in node_type or "endpoint" in node_type:
            label = normalize_url(label)
        else:
            label = clean_string(label)
            
        key = (label, node_type)
        if key in node_cache:
            if metadata:
                idx = next(i for i, n in enumerate(nodes) if n["data"]["id"] == node_cache[key])
                nodes[idx]["data"]["metadata"].update(metadata)
            return node_cache[key]
        
        node_id = f"n{id_counter}"
        severity = (metadata or {}).get("severity", "").lower()
        
        node_entry = {
            "data": {
                "id": node_id,
                "label": label,
                "type": node_type,
                "layer": get_layer(node_type),
                "size": get_size(node_type, severity),
                "color": get_color(node_type, severity),
                "metadata": metadata or {
                    "description": f"Extracted {node_type} entity.",
                    "confidence": "MEDIUM",
                    "source": "unknown"
                }
            }
        }
        
        nodes.append(node_entry)
        node_cache[key] = node_id
        id_counter += 1
        return node_id

    def add_edge(u, v, label):
        if u is None or v is None or u == v: return
        edge_id = f"e{u}_{v}"
        edge = {"data": {"id": edge_id, "source": u, "target": v, "label": label}}
        if not any(e["data"]["id"] == edge_id for e in edges):
            edges.append(edge)

    def process_recursive(data, parent_id, mod_id, mod_name):
        if isinstance(data, dict):
            if "url" in data and ("params_list" in data or "method" in data):
                u_id = add_node(data["url"], "endpoint", {
                    "description": f"Endpoint discovered by {mod_name}",
                    "source": mod_name,
                    "method": data.get("method", "GET")
                })
                add_edge(mod_id, u_id, "mapped")
                for p in data.get("params_list", []):
                    p_id = add_node(p, "parameter", {"source": mod_name})
                    add_edge(u_id, p_id, "accepts")
                for k, v in data.items():
                    if k not in ["url", "params_list"]:
                        process_recursive(v, u_id, mod_id, mod_name)
                return

            if "content" in data and "source" in data:
                s_id = add_node(data["content"], "secret", {
                    "description": "Sensitive information leakage",
                    "source": mod_name,
                    "found_in": data["source"]
                })
                u_id = add_node(data["source"], "url", {"source": mod_name})
                add_edge(u_id, s_id, "leaks")
                return

            if "type" in data and ("url" in data or "endpoint" in data):
                v_type = data["type"]
                sev = data.get("severity", "medium").lower()
                v_id = add_node(v_type, "vulnerability", {
                    "description": data.get("description", f"Vulnerability detected by {mod_name}"),
                    "severity": sev,
                    "confidence": data.get("confidence", "HIGH"),
                    "source": mod_name,
                    "cwe": data.get("cwe", "CWE-Unknown"),
                    "cvss": data.get("cvss", "N/A")
                })
                u_val = data.get("url") or data.get("endpoint")
                u_id = add_node(u_val, "url", {"source": mod_name})
                add_edge(u_id, v_id, "vulnerable_at")
                return

            for k, v in data.items():
                k_low = k.lower()
                if k_low in CONTAINER_KEYS:
                    process_recursive(v, parent_id, mod_id, mod_name)
                    continue
                if any(x in k_low for x in ["url", "endpoint", "uri"]):
                    if isinstance(v, str):
                        u_id = add_node(v, "url", {"source": mod_name})
                        add_edge(parent_id, u_id, "discovered")
                elif any(x in k_low for x in ["secret", "token", "key", "credential", "password"]):
                    if isinstance(v, str):
                        s_id = add_node(v, "secret", {"source": mod_name})
                        add_edge(parent_id, s_id, "leaks")
                elif any(x in k_low for x in ["vulnerab", "finding", "issue", "flaw", "cve"]):
                    if isinstance(v, str):
                        v_id = add_node(v, "vulnerability", {"source": mod_name})
                        add_edge(parent_id, v_id, "reported")
                elif isinstance(v, (dict, list)):
                    process_recursive(v, parent_id, mod_id, mod_name)

        elif isinstance(data, list):
            for item in data:
                process_recursive(item, parent_id, mod_id, mod_name)
        
        elif isinstance(data, str) and "://" in data:
            u_id = add_node(data, "url", {"source": mod_name})
            add_edge(parent_id, u_id, "referenced")

    for mod_key, module_data in loot_map.items():
        mod_name = mod_key.upper().split('/')[-1].replace('.JSON', '')
        mod_id = add_node(mod_name, "module", {"description": f"Hellhound module: {mod_name}", "source": "CORE"})
        process_recursive(module_data, mod_id, mod_id, mod_name)

    # Format for 2D (Cytoscape)
    elements = []
    for node_id, node_data in nodes.items():
        elements.append({
            "data": {
                "id": node_id,
                "label": node_data.get("label", node_id),
                **node_data.get("metadata", {})
            }
        })
    for edge in edges:
        elements.append({
            "data": {
                "id": f"{edge['source']}-{edge['target']}",
                "source": edge["source"],
                "target": edge["target"],
                "label": edge["label"]
            }
        })

    # Format for 3D (3d-force-graph)
    forceData = {
        "nodes": [{"id": nid, "label": nd["label"], **nd.get("metadata", {})} for nid, nd in nodes.items()],
        "links": [{"source": e["source"], "target": e["target"], "label": e["label"]} for e in edges]
    }

    return {
        "elements": elements,
        "forceData": forceData,
        "raw": {"nodes": nodes, "edges": edges}
    }
