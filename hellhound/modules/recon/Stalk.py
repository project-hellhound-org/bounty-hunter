import subprocess
import shutil
import re
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
            "infrastructure": {
                "subdomains": [],
                "netrange": [],
                "asn": "",
                "netname": "",
                "mx_records": [],
                "email_provider": [],
                "waf": "",
            },
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
            "signals": []
        }

    # ======================================================
    # Phase 1 — Infrastructure Intelligence
    # ======================================================

    def enumerate_subdomains(self):
        self.emit.info("Phase 1: Subdomain Intelligence")

        clean_target = self.domain.replace("http://", "").replace("https://", "")
        url = f"https://crt.sh/?q=%.{clean_target}&output=json"

        response = fetch_json(url)
        if not response:
            return

        subs = set()
        for entry in response:
            names = entry.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip()
                if name.startswith("*."):
                    name = name[2:]
                if clean_target in name:
                    subs.add(name)

        self.data["infrastructure"]["subdomains"] = sorted(subs)

        if len(subs) > 20:
            self.data["signals"].append("LARGE_ATTACK_SURFACE")

    def extract_netrange_asn(self):
        if not tool_exists("dig") or not tool_exists("whois"):
            return

        ip_output = run_cmd(["dig", "+short", self.domain, "A"])
        if not ip_output:
            return

        main_ip = ip_output.splitlines()[0]

        whois_output = run_cmd(["whois", main_ip])
        if not whois_output:
            return

        cidr = re.findall(r'(NetRange|CIDR|inetnum):\s*([^\n]+)', whois_output)
        for match in cidr:
            self.data["infrastructure"]["netrange"].append(match[1].strip())

        asn_match = re.search(r'(Origin|OriginAS):\s*([A-Z0-9]+)', whois_output)
        if asn_match:
            self.data["infrastructure"]["asn"] = asn_match.group(2)
            self.data["signals"].append("ASN_IDENTIFIED")


    def analyze_email_stack(self):
        if not tool_exists("dig"):
            return

        mx_output = run_cmd(["dig", "+short", self.domain, "MX"])
        mx_hosts = [line.split()[-1] for line in mx_output.splitlines() if line]
        self.data["infrastructure"]["mx_records"] = mx_hosts

        txt_output = run_cmd(["dig", "+short", self.domain, "TXT"])

        providers = set()

        for line in txt_output.splitlines():
            if "google" in line.lower():
                providers.add("Google Workspace")
            if "outlook" in line.lower():
                providers.add("Microsoft O365")
            if "zoho" in line.lower():
                providers.add("Zoho")

        if providers:
            self.data["infrastructure"]["email_provider"] = list(providers)
            self.data["signals"].append("EMAIL_PROVIDER_IDENTIFIED")

    # ======================================================
    # Phase 2 — Web Surface Mapping
    # ======================================================

    def probe_http(self):
        self.emit.info("Phase 2: Web Surface Mapping")

        if tool_exists("httpx"):
            ports = "80,443,8080,8443,8000,8888"
            out = run_cmd(["httpx", "-silent", "-u", self.domain, "-ports", ports])
            services = list(set(out.splitlines()))
            self.data["web"]["http_services"] = services

            if len(services) > 1:
                self.data["signals"].append("MULTIPLE_WEB_SERVICES")

    def fingerprint_tech(self):
        self.emit.info("Phase 2: Technology Fingerprinting")

        detected_tech = set()
        waf_detected = None

        for url in self.data["web"]["http_services"]:

            # ---------------------------------------------
            # 1️⃣ WHATWEB (if installed)
            # ---------------------------------------------
            if tool_exists("whatweb"):
                result = run_cmd(["whatweb", "-q", url])
                if result:
                    detected_tech.add(result)

                    if "cloudflare" in result.lower():
                        waf_detected = "Cloudflare"
                    if "akamai" in result.lower():
                        waf_detected = "Akamai"
                    if "sucuri" in result.lower():
                        waf_detected = "Sucuri"
                    if "imperva" in result.lower():
                        waf_detected = "Imperva"

            # ---------------------------------------------
            # 2️⃣ HEADER ANALYSIS (More Reliable)
            # ---------------------------------------------
            try:
                r = requests.get(url, timeout=6)

                headers = r.headers

                server = headers.get("Server", "")
                powered = headers.get("X-Powered-By", "")
                via = headers.get("Via", "")
                cf_ray = headers.get("CF-Ray", "")
                x_akamai = headers.get("X-Akamai-Transformed", "")
                x_sucuri = headers.get("X-Sucuri-ID", "")

                # --- Server Header ---
                if server:
                    detected_tech.add(f"Server: {server}")

                    if "nginx" in server.lower():
                        detected_tech.add("Nginx")
                    if "apache" in server.lower():
                        detected_tech.add("Apache")
                    if "iis" in server.lower():
                        detected_tech.add("Microsoft IIS")

                # --- X-Powered-By ---
                if powered:
                    detected_tech.add(f"Powered: {powered}")

                    if "php" in powered.lower():
                        detected_tech.add("PHP")
                    if "asp" in powered.lower():
                        detected_tech.add("ASP.NET")

                # --- CDN / WAF Detection ---
                if cf_ray or "cloudflare" in server.lower():
                    waf_detected = "Cloudflare"

                if x_akamai:
                    waf_detected = "Akamai"

                if x_sucuri:
                    waf_detected = "Sucuri"

                if via:
                    detected_tech.add(f"Proxy: {via}")

            except:
                continue

        # ---------------------------------------------
        # Store Results
        # ---------------------------------------------
        self.data["web"]["technologies"] = list(detected_tech)

        if waf_detected:
            self.data["infrastructure"]["waf"] = waf_detected
            if "WAF_DETECTED" not in self.data["signals"]:
                self.data["signals"].append("WAF_DETECTED")

        # Strategic Signals
        if len(detected_tech) > 5:
            self.data["signals"].append("COMPLEX_TECH_STACK")


    def harvest_urls(self):
        if self.mode != "deep":
            return

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

                for pattern in secret_patterns:
                    if re.search(pattern, content):
                        self.data["exposure"]["leaks"].append(js_url)
                        self.data["signals"].append("JS_SECRET_EXPOSED")
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

                # Only consider direct 200 responses
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

                for pattern in fingerprints:
                    if pattern in content:
                        self.data["exposure"]["leaks"].append(base + path)
                        self.data["signals"].append("CONFIRMED_FILE_EXPOSED")
                        break

            except Exception:
                continue


    # ======================================================
    # Phase 4 — IP Reputation
    # ======================================================

    def check_ip_reputation(self):
        try:
            ip = socket.gethostbyname(self.domain)
            if ip.startswith("127."):
                self.data["signals"].append("LOCAL_TARGET")
        except:
            pass


    # ======================================================
    # Risk Scoring
    # ======================================================

    def calculate_risk(self):

        risk_score = 0

        if "WAF_DETECTED" in self.data["signals"]:
            risk_score += 1

        if "JS_SECRET_EXPOSED" in self.data["signals"]:
            risk_score += 3

        if "HIGH_RISK_PARAMETER" in self.data["signals"]:
            risk_score += 2

        if "CONFIRMED_FILE_EXPOSED" in self.data["signals"]:
            risk_score += 4

        self.data["risk_score"] = risk_score

    # ======================================================
    # RUN
    # ======================================================

    def run(self):

        # Phase 1
        self.enumerate_subdomains()
        self.extract_netrange_asn()
        self.analyze_email_stack()

        # Phase 2
        self.probe_http()
        self.fingerprint_tech()
        self.harvest_urls()

        if self.mode == "deep":
            self.scan_js_for_secrets()

        # Phase 3
        self.detect_leaks()

        # Risk Score
        self.calculate_risk()

        summary = (
            f"Subs: {len(self.data['infrastructure']['subdomains'])} | "
            f"URLs: {len(self.data['web']['urls'])} | "
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
