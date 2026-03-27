import subprocess
import shutil
import re
from hellhound.modules.recon.utils.signatures import WAF_SIGNATURES, TECH_SIGNATURES
import requests
import socket
from urllib.parse import urlparse

NAME = "stalk"
CATEGORY = "recon"
DESCRIPTION = "Unified Recon Engine (Infrastructure + Web + Exposure Intelligence)"


# ==========================================================
# Helpers
# ==========================================================

def tool_exists(tool):
    return shutil.which(tool) is not None


def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=60
        )
        return result.stdout.strip()
    except Exception:
        return ""


def fetch_json(url):
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ==========================================================
# Stalk Engine
# ==========================================================

class StalkEngine:

    def __init__(self, target, emit, options=None):
        self.target = target
        self.emit = emit
        self.options = options or {}
        self.mode = "deep" if self.options.get("mode") == "deep" else "quick"

        parsed = urlparse(target)
        self.domain = parsed.netloc if parsed.netloc else target

        self.data = {

            "web": {
                "http_services": [],
                "technologies": [],
                "urls": [],
                "js_files": [],
                "parameters": []
            },
            "exposure": {
                "leaks": [],
                "takeover_candidates": []
            },
            "signals": list([])
        }


    # ======================================================
    # Phase 2 — Web Surface Mapping
    # ======================================================

    def probe_http(self):
        self.emit.info("Phase 2: Web Surface Mapping")

        services = []

        # 1. Try httpx (Best for discovery)
        if tool_exists("httpx"):
            ports = "80,443,8080,8443,8000,8888"
            out = run_cmd(["httpx", "-silent", "-u", self.domain, "-ports", ports])
            services = list(set(out.splitlines()))

        # 2. FALLBACK: Use Python Requests (Guaranteed to work)
        # If httpx isn't installed, we manually check the target
        if not services:
            try:
                # Check if target is an IP or Domain
                url = self.target if self.target.startswith("http") else f"http://{self.target}"
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    services.append(url)
                    self.emit.info(f"    [i] Fallback mode: Detected service at {url}")
            except Exception as e:
                self.emit.warn(f"    [!] Fallback mode failed: {e}")

        if services:
            self.data["web"]["http_services"] = list(services)
            if len(services) > 1:
                self.data["signals"].append("MULTIPLE_WEB_SERVICES")

    def fingerprint_tech(self):
        self.emit.info("Phase 2: Technology WAFbustering")

        detected_tech = set()
        waf_detected = None

        # We iterate over services found in probe_http
        for url in self.data["web"]["http_services"]:

            # --- Header Analysis (Python Native) ---
            try:
                r = requests.get(url, timeout=6)

                headers = r.headers

                server = headers.get("Server", "").lower()
                via = headers.get("Via", "").lower()
                cf_ray = headers.get("CF-Ray", "")
                x_akamai = headers.get("X-Akamai-Transformed", "")
                x_sucuri = headers.get("X-Sucuri-ID", "")

                # --- Signature Based Detection (Unified) ---
                # WAFs
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if any(sig in str(h).lower() for h in headers.values()) or sig in r.text.lower():
                            waf_detected = waf
                            break
                
                # Tech
                server = headers.get("Server", "").lower()
                for sig, name in TECH_SIGNATURES["Server"].items():
                    if sig in server: detected_tech.add(name)
                
                powered = headers.get("X-Powered-By", "").lower()
                for sig, name in TECH_SIGNATURES["Framework"].items():
                    if sig in powered: detected_tech.add(name)
                    
                for cat, sigs in TECH_SIGNATURES.items():
                    if isinstance(sigs, dict) and cat != "Server" and cat != "Framework":
                        for sig, name in sigs.items():
                            if sig in r.text.lower() or any(sig in str(c).lower() for c in r.cookies.get_dict()):
                                detected_tech.add(name)

            except Exception:
                continue

        # ---------------------------------------------
        # Store Results
        # ---------------------------------------------
        self.data["web"]["technologies"] = list(detected_tech)

        if waf_detected:
            if "WAF_DETECTED" not in self.data["signals"]:
                self.data["signals"].append("WAF_DETECTED")

        if detected_tech:
             self.data["signals"].append("TECH_DETECTED")

        # Strategic Signals
        if len(detected_tech) > 5:
            self.data["signals"].append("COMPLEX_TECH_STACK")

    def harvest_urls(self):
        if self.mode != "deep":
            return

        # Only use external tools if available
        if tool_exists("gau"):
            out = run_cmd(["gau", self.domain])
            self.data["web"]["urls"].extend(out.splitlines())

        if tool_exists("katana"):
            out = run_cmd(["katana", "-u", f"http://{self.domain}", "-silent"])
            for u in out.splitlines():
                self.data["web"]["urls"].append(u)
                if u.endswith(".js"):
                    self.data["web"]["js_files"].append(u)

        # Extract parameters
        for url in self.data["web"]["urls"]:
            if "?" in url:
                params = url.split("?", 1)[1]
                for pair in params.split("&"):
                    key = pair.split("=")[0]
                    if key:
                        risky_keywords = ["id", "user", "uid", "account", "file", "path", "cmd", "token"]
                        if key.lower() in risky_keywords:
                            self.data["signals"].append("HIGH_RISK_PARAMETER")
                            
                        self.data["web"]["parameters"].append(key)

    # ======================================================
    # Phase 2 — JavaScript Secret Analysis
    # ======================================================

    def scan_js_for_secrets(self):
        self.emit.info("Phase 2: JavaScript Secret Analysis")

        secret_patterns = [
            r"AKIA[0-9A-Z]{16}",
            r"AIza[0-9A-Za-z-_]{35}",
            r"sk_live_[0-9a-zA-Z]{24}",
            r"(?i)api[_-]?key\s*=\s*['\"]?[A-Za-z0-9_\-]{16,}"
        ]

        for js_url in self.data["web"]["js_files"]:
            try:
                r = requests.get(js_url, timeout=5)
                if r.status_code != 200:
                    continue

                content = r.text

                leaks_list = self.data["exposure"]["leaks"]
                signals_list = self.data["signals"]
                for pattern in secret_patterns:
                    if re.search(pattern, content):
                        leaks_list.append(js_url)
                        signals_list.append("JS_SECRET_EXPOSED")
                        break

            except:
                continue


    # ======================================================
    # Phase 3 — Exposure Detection
    # ======================================================

    def detect_leaks(self):
        self.emit.info("Phase 3: Exposure Analysis")

        base = f"http://{self.domain}"
        leak_paths = {
            "/.env": ["DB_PASSWORD=", "APP_KEY=", "AWS_SECRET", "DATABASE_URL="],
            "/.git/config": ["repositoryformatversion", "[core]", "remote \"origin\""],
            "/backup.zip": ["PK\x03\x04"]
        }

        for path, fingerprints in leak_paths.items():
            try:
                r = requests.get(base + path, timeout=5, allow_redirects=False)

                if r.status_code != 200:
                    continue

                # ZIP validation
                if path.endswith(".zip"):
                    if "zip" in r.headers.get("Content-Type", "").lower():
                        if r.content.startswith(b"PK"):
                            self.data["exposure"]["leaks"].append(base + path)
                            self.data["signals"].append("CONFIRMED_ZIP_EXPOSED")
                    continue

                # Text-based validation (.env / .git)
                content = r.text[:5000]  # limit parsing

                leaks_list = self.data["exposure"]["leaks"]
                signals_list = self.data["signals"]
                for pattern in fingerprints:
                    if pattern in content:
                        leaks_list.append(base + path)
                        signals_list.append("CONFIRMED_FILE_EXPOSED")
                        break

            except Exception:
                continue



    # ======================================================
    # Risk Scoring
    # ======================================================

    def ingest_spider(self):
        spider_intel = self.options.get("spider_intel", {})
        if not spider_intel:
            return

        self.emit.info("Phase 1b: Ingesting Spider Intelligence (Unified)")
        
        # Merge URLs
        eps = spider_intel.get("endpoints", [])
        for ep in eps:
            url = ep.get("url", "")
            if url:
                self.data["web"]["urls"].append(url)
                if url.endswith(".js"):
                    self.data["web"]["js_files"].append(url)
                
                params = ep.get("params", {})
                for ptype, pnames in params.items():
                    self.data["web"]["parameters"].extend(pnames)
        
        # Merge technology stack and ensure it stays a list of strings
        tech = spider_intel.get("tech_stack", [])
        combined_tech = set(self.data["web"]["technologies"])
        for t in tech:
            combined_tech.add(str(t))
        self.data["web"]["technologies"] = list(combined_tech)
        
        if tech:
            self.data["signals"].append("TECH_DETECTED_FROM_SPIDER")

    # Risk Score
    def calculate_risk(self):
        risk_score = 0
        signals = self.data.get("signals", [])
        if self.data["web"].get("http_services"): risk_score += 2
        if "WAF_DETECTED" in signals: risk_score += 1
        if "JS_SECRET_EXPOSED" in signals: risk_score += 3
        if "HIGH_RISK_PARAMETER" in signals: risk_score += 2
        if "CONFIRMED_FILE_EXPOSED" in signals: risk_score += 4
        if "TECH_DETECTED_FROM_SPIDER" in signals: risk_score += 1
        self.data["risk_score"] = risk_score

    # ======================================================
    # RUN
    # ======================================================

    def run(self):
        # Phase 2
        self.probe_http()
        self.fingerprint_tech()
        self.ingest_spider()           # NEW: Ingest spider data
        self.harvest_urls()

        if self.mode == "deep":
            self.scan_js_for_secrets()

        # Phase 3
        self.detect_leaks()

        # Risk Score
        self.calculate_risk()

        summary = (
            f"Endpoints: {len(self.data['web']['urls'])} | "
            f"Leaks: {len(self.data['exposure']['leaks'])} | "
            f"Risk Score: {self.data.get('risk_score', 0)}"
        )

        return {
            "raw": summary,
            "intel": self.data
        }

# ==========================================================
# Framework Entry
# ==========================================================

def run(target, emit, options=None, stop_check=None, pause_check=None):

    emit.info(f"Stalk Recon Started: {target}")

    engine = StalkEngine(target, emit, options)
    result = engine.run()

    emit.success("Stalk reconnaissance complete.")
    emit.success(result["raw"])

    return result