NAME = "BlobUnpacker"
DESCRIPTION = "Source Map Recon & Wordlist Mining (Intelligence Extractor)"
CATEGORY    = "intel"
OPTIONS = []

import re
import requests
import os
import json
import math
import base64
import gzip
from urllib.parse import urljoin, urlparse

# Suppression for insecure requests (common in internal pentests)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# High-fidelity patterns for secret detection
SECRET_PATTERNS = {
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Stripe API Key": r'(?:sk|pk)[-_](?:test|live)[-_][0-9a-zA-Z]{12,32}',
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'[^A-Za-z0-9/+=][A-Za-z0-9/+=]{40}[^A-Za-z0-9/+=]',
    "GitHub PAT": r'gh[pousr]_[A-Za-z0-9_]{36,255}',
    "Slack Webhook": r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    "Generic Secret": r'(?:api_?key|secret|password|token|auth|admin_?pass)["\'`]?\s*[:=]\s*["\'`]([^"\'`\n]{8,128})["\'`]'
}

# Regex for endpoint discovery in source code
ENDPOINT_PATTERNS = [
    r'[\'"](/[a-zA-Z0-9\-_/\{\}]+)[\'"]', # Absolute paths
    r'(?:fetch|axios(?:\.get|\.post)?)\s*\(\s*[\'"]([^\'"]+)[\'"]', # fetch/axios calls
    r'url\s*:\s*[\'"]([^\'"]+)[\'"]' # AJAX config objects
]

# Regex for finding source maps in JS files
MAP_COMMENT_REGEX = re.compile(r'sourceMappingURL=([a-zA-Z0-9_\-\./]+\.map)')

# Regex for developer comments (Internal logic hints)
COMMENT_PATTERNS = [
    r'/\*[\s\S]*?\*/', # Block comments
    r'//.*'           # Line comments
]

def shannon_entropy(data):
    """Calculates the Shannon entropy of a string (Joe-Style fidelity check)."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

class BlobUnpacker:
    def __init__(self, emit):
        self.emit = emit
        self.loot = {
            "reconstructed_files": [],
            "reconstructed_content": {}, # filename -> content
            "minified_content": {},      # url -> content
            "secrets": [],
            "new_endpoints": [],
            "comments": [],
            "target_wordlist": [],
            "discovered_maps": [],    # Propagation check
            "map_headers": {}         # For SourceAuditor analysis
        }
        self._processed_maps = set()

    def unpack_map(self, map_url: str):
        if not map_url or map_url in self._processed_maps: return
        self._processed_maps.add(map_url)

        display_name = map_url.split('/')[-1]
        
        try:
            # 1. Handle Inline Base64 Maps (Format Handling Fix)
            if map_url.startswith("data:application/json;base64,"):
                self.emit.info(f"    [✔] Blob: Successfully unpacked inline base64 map")
                raw_data = map_url.split(",", 1)[1]
                map_content = base64.b64decode(raw_data).decode('utf-8')
                data = json.loads(map_content)
                resp_headers = {"Content-Type": "application/json", "X-Source-Map-Source": "inline"}
            else:
                resp = requests.get(map_url, timeout=10, verify=False, allow_redirects=True)
                if resp.status_code != 200:
                    self.emit.error(f"    [x] Failed to fetch map: {map_url} (Status: {resp.status_code})")
                    return
                
                # Support for manual Gzip decompression if needed (Format Handling Fix)
                if resp.headers.get("Content-Encoding") == "gzip":
                    try:
                        map_content = gzip.decompress(resp.content).decode("utf-8")
                        data = json.loads(map_content)
                    except:
                        map_content = resp.text
                        data = resp.json()
                else:
                    map_content = resp.text
                    data = resp.json()
                
                resp_headers = dict(resp.headers)
                resp_headers["_target_url"] = map_url # For auditor
                self.loot["map_headers"][map_url] = resp_headers
                self.loot["discovered_maps"].append(map_url)
            
            # Fidelity Check: Ensure it's not a generic HTML error page
            if not isinstance(data, dict):
                return
        except Exception as e:
            self.emit.error(f"    [x] Error unpacking map {display_name}: {str(e)}")
            return

        self.emit.info(f"    [✔] Blob: Successfully unpacked {display_name}")

        # 1. Metadata / Wordlist Mining
        sources = data.get("sources", [])
        names = data.get("names", [])
        
        for s in sources:
            if s:
                # Preservation Fix: Do NOT strip extensions (fixes "Aboutx" bug)
                fname = s.split("/")[-1]
                if len(fname) > 2: self.loot["target_wordlist"].append(fname)
            
        for n in names:
            if len(n) > 2: self.loot["target_wordlist"].append(n)

        # 1.5. Comment Mining (Fidelity Upgrade)
        comments = []
        for pat in COMMENT_PATTERNS:
            comments.extend(re.findall(pat, map_content))
        for c in comments:
            if len(c) > 10 and any(k in c.lower() for k in ["admin", "todo", "fixme", "dev", "internal", "config", "api"]):
                self.loot["comments"].append({"content": c.strip(), "source": display_name})

        # 2. Reconstruct Source and Mine Intelligence
        sources_content = data.get("sourcesContent", [])
        if sources_content and len(sources_content) == len(sources):
            # Create a local directory to dump the reconstructed source for 'proof'
            host = urlparse(map_url).netloc.replace(":", "_")
            out_dir = os.path.join(os.getcwd(), "reconstructed_source", host)
            os.makedirs(out_dir, exist_ok=True)

            for i, content in enumerate(sources_content):
                if not content: continue
                filename = sources[i]
                
                # Sanitize and resolve filename for local storage (Universal Path Handling)
                safe_name = filename.replace("../", "parent/").replace("./", "").lstrip("/")
                full_out_path = os.path.normpath(os.path.join(out_dir, safe_name))
                
                # Ensure we don't escape the output directory (Safety Check)
                if not full_out_path.startswith(out_dir):
                    full_out_path = os.path.join(out_dir, os.path.basename(safe_name))

                os.makedirs(os.path.dirname(full_out_path), exist_ok=True)
                
                try:
                    with open(full_out_path, "w", encoding="utf-8") as f:
                        f.write(content)
                  
                    self.loot["reconstructed_files"].append(filename)
                    self.loot["reconstructed_content"][filename] = content
                    self._mine_content(content, filename)
                except Exception as e:
                    self.emit.error(f"    [x] Failed to write reconstructed file {filename}: {str(e)}")

    def _mine_content(self, content: str, source_name: str):
        # Secret Scanning
        for label, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for m in matches:
                # If it's a tuple (from groups), take the first group
                val = m[0] if isinstance(m, tuple) else m
                if val and len(val) > 4:
                    # Garbage Filter: If it looks like code (common JS words + brackets)
                    garbage_words = ["handle", "onPress", "firesOn", "callback", "return", "function", "const", "let", "var"]
                    if any(w in val.lower() for w in garbage_words) or any(c in val for c in ["{", "}", "(", ")", ";", "=>"]):
                        continue
                        
                    # Entropy Validation: Most real secrets have entropy > 3.5
                    if label in ["AWS Secret Key", "Generic Secret"]:
                        entropy = shannon_entropy(val)
                        if entropy < 3.2: # Likely code or predictable string
                            continue
                            
                    # Deduplication: If this exact content was already found as a specialized key, skip generic
                    if label == "Generic Secret":
                        if any(s["content"] == val for s in self.loot["secrets"] if s["type"] != "Generic Secret"):
                            continue
                    
                    self.loot["secrets"].append({"type": label, "content": val, "source": source_name})
                    self.emit.warn(f"    [!] Discovery: {label} found in {source_name.split('/')[-1]}")

        # Endpoint / Route Discovery
        for pattern in ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, content)
            for m in matches:
                path = m.group(1)
                # Filter out obvious non-endpoints (extensions like .ts, .js if not a route)
                if path and len(path) > 1:
                    clean_path = path.strip()
                    if not clean_path.endswith((".ts", ".tsx", ".scss", ".css", ".png", ".jpg")):
                        self.loot["new_endpoints"].append({"url": clean_path, "source": source_name})

    def _beautify_js(self, js_code: str) -> str:
        """
        Universal lightweight JS beautifier (No external dependencies).
        Implements basic indentation and line-breaking for minified analysis.
        """
        indent = 0
        output = []
        # Simple tokenization for formatting
        tokens = re.split(r'([{};])', js_code)
        
        for token in tokens:
            token = token.strip()
            if not token: continue
            
            if token == '{':
                output.append(' {\n' + '    ' * (indent + 1))
                indent += 1
            elif token == '}':
                indent = max(0, indent - 1)
                output.append('\n' + '    ' * indent + '}\n' + '    ' * indent)
            elif token == ';':
                output.append(';\n' + '    ' * indent)
            else:
                output.append(token)
                
        return "".join(output)

    def scan_js_for_maps(self, js_url: str):
        """Fetches a JS file, mines it for secrets/routes, and looks for a source map comment"""
        try:
            resp = requests.get(js_url, timeout=5, verify=False)
            if resp.status_code == 200:
                # 1. Beautify and Mine the JS file itself
                beautified = self._beautify_js(resp.text)
                self._mine_content(beautified, js_url)
                self.loot["minified_content"][js_url] = beautified
                
                # 2. Look for the map reference
                match = MAP_COMMENT_REGEX.search(resp.text[-2000:]) # Usually at the end
                if match:
                    map_file = match.group(1)
                    full_map_url = urljoin(js_url, map_file)
                    self.loot["discovered_maps"].append(full_map_url)
                    return full_map_url
        except: pass
        return None

def run(target, emit, options=None):
    """Entry point for the Hellhound framework"""
    emit.info(f"[*] Blob Unpacker (Intelligence Mastery): {target}")
    
    opt = options or {}
    spider_intel = opt.get("spider_intel", {})
    raw_maps = spider_intel.get("sourcemaps", [])
    maps = set()
    
    for m in raw_maps:
        if isinstance(m, dict):
            url = m.get("url")
            if url: maps.add(url)
        elif isinstance(m, str):
            maps.add(m)
    
    # 1. Discovery Phase: Scan all discovered JS files for hidden map references
    js_files = []
    # Extract JS files from spider intel
    for ep in spider_intel.get("endpoints", []):
        url = ep.get("url", "")
        if url.endswith(".js"):
            js_files.append(url)
    
    unpacker = BlobUnpacker(emit)
    
    if js_files:
        emit.info(f"    [i] Scanning {len(js_files)} JS files for hidden source maps...")
        # Deduplicate and cap scan
        for js in list(set(js_files))[:25]:
            map_url = unpacker.scan_js_for_maps(js)
            if map_url:
                maps.add(map_url)

    # 2. Extraction Phase: Unpack all discovered maps
    for m_url in maps:
        unpacker.unpack_map(m_url)

    # Calculate Risk Score
    # 10 points per unique secret type found, 2 points per source file recovered
    risk_score = (len(set([s["type"] for s in unpacker.loot["secrets"]])) * 10)
    unpacked_count = len(unpacker.loot["reconstructed_files"])
    new_eps_count = len(unpacker.loot["new_endpoints"])

    if unpacked_count == 0 and not unpacker.loot["secrets"]:
        return {"raw": "No valid source maps recovered.", "intel": {}, "risk_score": 0}

    return {
        "raw": f"Recovered {unpacked_count} files | {new_eps_count} endpoints | {len(unpacker.loot['secrets'])} secrets",
        "intel": {
            "reconstructed": unpacker.loot["reconstructed_files"],
            "reconstructed_content": unpacker.loot["reconstructed_content"],
            "minified_content": unpacker.loot.get("minified_content", {}), # New link for SourceAuditor
            "secrets": unpacker.loot["secrets"],
            "new_endpoints": unpacker.loot["new_endpoints"],
            "comments": unpacker.loot["comments"],
            "discovered_maps": list(set(unpacker.loot["discovered_maps"])),
            "map_headers": unpacker.loot["map_headers"],
            "wordlist_hints": list(set(unpacker.loot["target_wordlist"])),
            "risk_score": risk_score
        },
        "risk_score": risk_score
    }
