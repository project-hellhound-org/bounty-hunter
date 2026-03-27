import requests
import re
import os
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Any, Set

NAME = "stalk"
CATEGORY = "recon"
DESCRIPTION = "Universal Deep Web Asset Discovery (Active JS & Chunk Prober)"

# Module Options
OPTIONS = [
    {"name": "concurrency", "default": 20, "required": False, "help": "Max concurrent JS fetches"},
    {"name": "depth", "default": 4, "required": False, "help": "Recursion depth for JS chunks"},
    {"name": "proactive", "default": True, "required": False, "help": "Proactively enumerate chunks (0.js, 1.js, etc)"}
]

# ==========================================================
# UNIVERSAL DISCOVERY PATTERNS
# ==========================================================

# Aggressive API discovery including internal routes
API_ROOT_REGEX = re.compile(
    r'(?:["\'`])(?:/(?:api|rest|v[0-9]|graphql|auth|internal|service|app|api-docs|v1|v2|v3))'
    r'(?:/[a-zA-Z0-9_\-\.]+){0,6}(?:["\'`])'
)

# Common JS service constants and environment vars
CONSTANT_REGEX = re.compile(
    r'(?:const|let|var|this|process\.env|window|global)\.?([A-Z0-9_]{3,30})\s*[:=]\s*(?:["\'`])([^"\'`\n]{2,150})(?:["\'`])'
)

# Dynamic Import / Chunk Discovery
DYNAMIC_IMPORT_REGEX = re.compile(r'(?:import|require\.e|require\.ensure)\s*\(\s*["\'`]([^"\'`\n]+)["\'`]\s*\)')
WEBPACK_CHUNK_REGEX = re.compile(r'\b([0-9]{1,5})\.js\b')
ROUTING_PATH_REGEX = re.compile(r'(?:path|route|alias)\s*[:=]\s*["\'`](/[a-zA-Z0-9_\-\./\*]+)["\'`]')

# ==========================================================
# CORE PROBER ENGINE
# ==========================================================

class UniversalMiner:
    def __init__(self, emit, concurrency=20):
        self.emit = emit
        self.concurrency = concurrency
        self.assets: List[Dict[str, Any]] = []
        self.visited_urls: Set[str] = set()
        self._lock = threading.Lock()

    def mine(self, url: str, depth=3, is_proactive=False):
        if depth < 0 or url in self.visited_urls: return
        self.visited_urls.add(url)

        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code != 200: return
            content = resp.text
        except: return

        # 1. API Roots & Internal Routes
        for r in API_ROOT_REGEX.findall(content):
            self._add_asset("API_ROOT", r.strip("\"'`"), url)
        
        for p in ROUTING_PATH_REGEX.findall(content):
            self._add_asset("SPA_ROUTE", p, url)

        # 2. Constants / Env
        for name, val in CONSTANT_REGEX.findall(content):
            atype = "INTERNAL_SERVICE" if "/" in val or "http" in val else "ENVIRONMENTAL"
            self._add_asset(atype, f"{name}: {val}", url)

        # 3. Dynamic Imports & Webpack Chunks
        imports = DYNAMIC_IMPORT_REGEX.findall(content)
        for imp in imports:
            self._add_asset("DYNAMIC_IMPORT", imp, url)
            chunk_url = urljoin(url, imp)
            self.mine(chunk_url, depth - 1)

        # 4. Proactive Chunk Enumeration (Numeric)
        numeric_chunks = list(set(WEBPACK_CHUNK_REGEX.findall(content)))
        if numeric_chunks:
            base_dir = "/".join(url.split("/")[:-1]) + "/"
            for num in numeric_chunks[:10]:
                self._add_asset("CHUNK_ID", f"{num}.js", url)
                # Proactively probe adjacent chunks
                if is_proactive:
                    n = int(num)
                    for adjacent in range(max(0, n-2), n+3):
                        adj_url = urljoin(base_dir, f"{adjacent}.js")
                        if adj_url not in self.visited_urls:
                            self.emit.info(f"    [+] Stalk: Proactively probing chunk {adjacent}.js")
                            self.mine(adj_url, depth - 1)

    def _add_asset(self, type_str, val, source):
        with self._lock:
            if any(a["asset"] == val and a["type"] == type_str for a in self.assets): return
            self.assets.append({"type": type_str, "asset": val, "source": source})

def run(target: str, emit, options: Optional[Dict[str, Any]] = None):
    emit.info(f"[*] Stalk v12.3 (Universal prober): {target}")
    opt = options or {}
    base_url = target if target.startswith("http") else f"http://{target}"
    
    # Ingest intelligence for initial seeds
    spider_intel = opt.get("spider_intel", {})
    initial_scripts = set()
    for ep in spider_intel.get("endpoints", []):
        url = ep.get("url", "")
        if url.endswith(".js"): initial_scripts.add(url)

    if not initial_scripts:
        initial_scripts = {urljoin(base_url, b) for b in ["main.js", "runtime.js", "polyfills.js", "vendor.js"]}

    miner = UniversalMiner(emit, concurrency=opt.get("concurrency", 20))
    is_proactive = opt.get("proactive", True)
    
    with ThreadPoolExecutor(max_workers=opt.get("concurrency", 20)) as pool:
        for script_url in initial_scripts:
            pool.submit(miner.mine, script_url, depth=opt.get("depth", 4), is_proactive=is_proactive)

    unique_assets = {}
    for a in miner.assets:
        key = f"{a['type']}:{a['asset']}"
        unique_assets[key] = a

    api_roots = [a for a in unique_assets.values() if a["type"] in ("API_ROOT", "SPA_ROUTE")]
    chunks = [a for a in unique_assets.values() if a["type"] in ("DYNAMIC_IMPORT", "CHUNK_ID")]
    env_vars = [a for a in unique_assets.values() if a["type"] in ("ENVIRONMENTAL", "INTERNAL_SERVICE")]

    emit.info(f"    [✔] Stalk: Universal discovery complete.")
    emit.info(f"    [✔] Found {len(api_roots)} roots and {len(miner.visited_urls)} unique JS bundles.")

    return {
        "raw": f"Discovered {len(unique_assets)} unique assets across {len(miner.visited_urls)} bundles.",
        "intel": {
            "endpoints": [{"url": a["asset"], "confidence_label": "HIGH", "source": "stalk_universal"} for a in api_roots],
            "js_chunks": list(set([c["asset"] for c in chunks])),
            "secrets": [{"type": a["type"], "content": a["asset"], "source": a["source"]} for a in env_vars],
            "risk_score": len(api_roots) * 3 + len(env_vars) * 5
        },
        "risk_score": len(api_roots) + len(env_vars) * 2
    }