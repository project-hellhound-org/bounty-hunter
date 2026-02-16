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
            out = run_cmd(["httpx", "-silent", "-u", self.domain])
            self.data["web"]["http_services"] = out.splitlines()

    def fingerprint_tech(self):
        if not tool_exists("whatweb"):
            return

        for url in self.data["web"]["http_services"]:
            result = run_cmd(["whatweb", "-q", url])
            if result:
                self.data["web"]["technologies"].append(result)

            if "cloudflare" in result.lower():
                self.data["infrastructure"]["waf"] = "Cloudflare"
                self.data["signals"].append("WAF_DETECTED")

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
                        self.data["web"]["parameters"].append(key)

    # ======================================================
    # Phase 3 — Exposure Detection
    # ======================================================

    def detect_leaks(self):
        self.emit.info("Phase 3: Exposure Analysis")

        base = f"http://{self.domain}"
        leak_paths = ["/.env", "/.git/config", "/backup.zip"]

        for path in leak_paths:
            try:
                r = requests.get(base + path, timeout=5)
                if r.status_code == 200 and len(r.text) > 10:
                    self.data["exposure"]["leaks"].append(base + path)
                    self.data["signals"].append("POTENTIAL_LEAK_EXPOSED")
            except:
                continue

    # ======================================================
    # Run
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

        # Phase 3
        self.detect_leaks()

        summary = (
            f"Subs: {len(self.data['infrastructure']['subdomains'])} | "
            f"URLs: {len(self.data['web']['urls'])} | "
            f"Leaks: {len(self.data['exposure']['leaks'])}"
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
