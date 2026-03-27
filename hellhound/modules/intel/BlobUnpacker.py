import requests
import json
import re
import os
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Any, Set, Union

NAME = "blobunpacker"
CATEGORY = "intel"
DESCRIPTION = "Source Map Recon & Wordlist Mining (Intelligence Extractor)"

# Regex for common secrets and endpoints
SECRET_REGEX = re.compile(r'(?:api_?key|secret|password|token|auth|admin_?pass)["\'`]?\s*[:=]\s*["\'`]([^"\'`\n]{6,64})["\'`]', re.I)
ENDPOINT_REGEX = re.compile(r'(?:["\'`])(?:/api/|/rest/|/v[0-9]/|/graphql)(?:/[a-zA-Z0-9_\-\.]+){1,5}(?:["\'`])')

class BlobUnpacker:
    def __init__(self, emit):
        self.emit = emit
        self.loot = {
            "reconstructed_files": [],
            "secrets": [],
            "new_endpoints": [],
            "target_wordlist": []
        }

    def unpack_map(self, map_input: Union[str, Dict]):
        if isinstance(map_input, dict):
            map_url = map_input.get("url", "")
        else:
            map_url = map_input

        if not map_url: return
        display_name = map_url.split('/')[-1] if isinstance(map_url, str) else "map"
        
        try:
            resp = requests.get(map_url, timeout=10, verify=False, allow_redirects=False)
            if resp.status_code != 200:
                self.emit.info(f"    [i] Blob: Skipped {display_name} (Status {resp.status_code})")
                return
            
            # Fidelity Check: Relaxed validation for non-standard servers
            text_start = resp.text[:100].lower()
            if "<html" in text_start or "<!doctype html" in text_start:
                self.emit.info(f"    [i] Blob: Skipped {display_name} (Unexpected HTML content)")
                return

            if not resp.text.strip():
                self.emit.info(f"    [i] Blob: Skipped {display_name} (Empty response)")
                return

            data = resp.json()
        except Exception as e:
            # If it's not JSON, it's not a valid map
            self.emit.info(f"    [i] Blob: Failed to parse {display_name} as JSON")
            return

        self.emit.info(f"    [✔] Blob: Successfully unpacked {display_name}")

        # 1. Wordlist Mining
        sources = data.get("sources", [])
        names = data.get("names", [])
        
        for s in sources:
            if "/" in s:
                fname = s.split("/")[-1].replace(".ts", "").replace(".js", "").replace(".vue", "")
                if fname and len(fname) > 2: self.loot["target_wordlist"].append(fname)
            
        for n in names:
            if len(n) > 2: self.loot["target_wordlist"].append(n)

        # 2. Reconstruct Source if present
        sources_content = data.get("sourcesContent", [])
        if sources_content and len(sources_content) == len(sources):
            for i, content in enumerate(sources_content):
                if not content: continue
                filename = sources[i]
                self.loot["reconstructed_files"].append(filename)
                self._mine_content(content, filename)

    def _mine_content(self, content: str, source_name: str):
        secrets = SECRET_REGEX.findall(content)
        for s in secrets:
            self.loot["secrets"].append({"type": "Potential Secret", "content": s, "source": source_name})
            self.emit.warn(f"    [!] Discovery: Secret found in {source_name.split('/')[-1]}")

        endpoints = ENDPOINT_REGEX.findall(content)
        for e in endpoints:
            clean_e = e.strip("\"'`")
            self.loot["new_endpoints"].append({"url": clean_e, "source": source_name})

def run(target: str, emit, options: Optional[Dict[str, Any]] = None):
    emit.info(f"[*] Blob Unpacker (Professional Fidelity): {target}")
    opt = options or {}
    
    spider_intel = opt.get("spider_intel", {})
    maps = spider_intel.get("sourcemaps", [])
    
    if not maps:
        base_url = target if target.startswith("http") else f"http://{target}"
        maps = [
            urljoin(base_url, "main.js.map"),
            urljoin(base_url, "vendor.js.map"),
            urljoin(base_url, "runtime.js.map"),
            urljoin(base_url, "polyfills.js.map")
        ]

    unpacker = BlobUnpacker(emit)
    for m in maps:
        unpacker.unpack_map(m)

    unpacked_count = len(unpacker.loot["reconstructed_files"])
    wordlist_size = len(set(unpacker.loot["target_wordlist"]))

    if unpacked_count == 0 and wordlist_size == 0:
        return {"raw": "No valid source maps recovered or mined.", "intel": {}, "risk_score": 0}

    return {
        "raw": f"Unpacked {unpacked_count} files and mined {wordlist_size} metadata hints.",
        "intel": {
            "reconstructed": unpacker.loot["reconstructed_files"],
            "secrets": unpacker.loot["secrets"],
            "new_endpoints": unpacker.loot["new_endpoints"],
            "wordlist_hints": list(set(unpacker.loot["target_wordlist"])),
            "risk_score": len(unpacker.loot["secrets"]) * 5 + len(unpacker.loot["new_endpoints"]) * 2
        },
        "risk_score": len(unpacker.loot["secrets"]) * 3 + unpacked_count
    }
