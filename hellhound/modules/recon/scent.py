import subprocess
import shutil
import re
import requests
import socket

NAME = "scent"
CATEGORY = "recon"
DESCRIPTION = "Actionable passive recon (Subdomains, NetRange, Email Stack, WAF/Tech ID, Leak & Takeover Detection)"

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def tool_exists(tool):
    return shutil.which(tool) is not None


def run_dig(target, record_type="A"):
    if not tool_exists("dig"):
        return ""
    try:
        cmd = ["dig", "+short", target, record_type]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10
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


def initialize_data(target):
    return {
        "target": target,
        "subdomains": [],
        "netrange": [],
        "netname": "",
        "asn": "",
        "email_provider": [],
        "mx_records": [],
        "server": "",
        "waf": "",
        "tech": [],
        "leak_indicators": [],
        "takeover_candidates": [],
        "signals": []
    }

# -------------------------------------------------
# Stage 1: Passive Subdomain Enumeration
# -------------------------------------------------

def get_subdomains(target, data, emit):
    emit.info("[scent] Harvesting subdomains via Certificate Transparency...")

    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    url = f"https://crt.sh/?q=%.{clean_target}&output=json"
    response = fetch_json(url)

    if not response:
        emit.info("[scent] No CT data returned.")
        return

    subs = set()
    for entry in response:
        name_value = entry.get('name_value', '')
        for name in name_value.split('\n'):
            name = name.strip()
            if name.startswith("*."):
                name = name[2:]
            if clean_target in name:
                subs.add(name)

    data["subdomains"] = sorted(subs)

    if len(subs) > 15:
        data["signals"].append("LARGE_ATTACK_SURFACE")

    emit.info(f"[scent] Found {len(subs)} subdomains.")

# -------------------------------------------------
# Stage 2: NetRange & ASN
# -------------------------------------------------

def get_netrange(target, data, emit):
    emit.info("[scent] Extracting NetRange & ASN...")

    ips = run_dig(target, "A").splitlines()
    if not ips:
        return

    main_ip = ips[0]

    if not tool_exists("whois"):
        emit.info("[scent] whois not installed. Skipping NetRange.")
        return

    try:
        result = subprocess.run(
            ["whois", main_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15
        )

        whois_text = result.stdout

        cidr_matches = re.findall(r'(NetRange|inetnum|CIDR):\s*([^\n]+)', whois_text)
        for match in cidr_matches:
            data["netrange"].append(match[1].strip())

        org_match = re.search(r'(NetName|OrgName|owner):\s*([^\n]+)', whois_text)
        if org_match:
            data["netname"] = org_match.group(2).strip()

        asn_match = re.search(r'(Origin|OriginAS):\s*([A-Z0-9]+)', whois_text)
        if asn_match:
            data["asn"] = asn_match.group(2).strip()
            data["signals"].append("ASN_IDENTIFIED")

    except Exception:
        pass

# -------------------------------------------------
# Stage 3: Email Infrastructure
# -------------------------------------------------

def analyze_email_stack(target, data, emit):
    emit.info("[scent] Analyzing Email Infrastructure...")

    mx_out = run_dig(target, "MX")
    mx_hosts = [line.split(" ")[-1] for line in mx_out.splitlines() if line]
    data["mx_records"] = mx_hosts

    txt_out = run_dig(target, "TXT")

    providers_found = set()

    for line in txt_out.splitlines():
        if "v=spf1" in line:
            includes = re.findall(r'include:([^\s]+)', line)
            for inc in includes:
                if "google" in inc:
                    providers_found.add("Google Workspace")
                elif "outlook" in inc:
                    providers_found.add("Microsoft O365")
                elif "zoho" in inc:
                    providers_found.add("Zoho")

    if providers_found:
        data["email_provider"] = list(providers_found)
        data["signals"].append("EMAIL_PROVIDER_IDENTIFIED")

# -------------------------------------------------
# Stage 4: Tech & WAF Fingerprinting
# -------------------------------------------------

def fingerprint_tech(target, data, emit):
    emit.info("[scent] Fingerprinting Tech & WAF...")

    if not target.startswith("http"):
        target = "http://" + target

    try:
        r = requests.get(target, timeout=8)
        headers = r.headers

        server = headers.get("Server", "")
        data["server"] = server

        if "cloudflare" in server.lower():
            data["waf"] = "Cloudflare"
            data["signals"].append("WAF_DETECTED")

        powered = headers.get("X-Powered-By", "")
        tech = []

        if "php" in powered.lower():
            tech.append("PHP")
        if "nginx" in server.lower():
            tech.append("Nginx")
        if "apache" in server.lower():
            tech.append("Apache")

        data["tech"] = list(set(tech))

    except Exception:
        pass

# -------------------------------------------------
# Stage 5: Leak Detection
# -------------------------------------------------

def detect_leaks(target, data, emit):
    emit.info("[scent] Checking for common exposed leaks...")

    if not target.startswith("http"):
        target = "http://" + target

    leak_paths = ["/.env", "/.git/config", "/backup.zip", "/database.sql"]

    for path in leak_paths:
        try:
            r = requests.get(target + path, timeout=5)
            if r.status_code == 200 and len(r.text) > 10:
                data["leak_indicators"].append(target + path)
                data["signals"].append("POTENTIAL_LEAK_EXPOSED")
        except:
            continue

# -------------------------------------------------
# Stage 6: Subdomain Takeover Detection
# -------------------------------------------------

def detect_takeover(data, emit):
    emit.info("[scent] Checking subdomain takeover possibilities...")

    vulnerable_patterns = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "amazonaws.com": "AWS S3",
        "azurewebsites.net": "Azure"
    }

    error_signatures = [
        "NoSuchBucket",
        "There isn't a GitHub Pages site here",
        "No such app",
        "The specified bucket does not exist"
    ]

    for sub in data["subdomains"]:
        cname = run_dig(sub, "CNAME")
        if not cname:
            continue

        for pattern, provider in vulnerable_patterns.items():
            if pattern in cname:
                try:
                    r = requests.get("http://" + sub, timeout=5)
                    for sig in error_signatures:
                        if sig.lower() in r.text.lower():
                            data["takeover_candidates"].append({
                                "subdomain": sub,
                                "provider": provider
                            })
                            data["signals"].append("SUBDOMAIN_TAKEOVER_POSSIBLE")
                except:
                    continue

# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):

    emit.info(f"[*] Scent: Deep Intelligence for {target}")

    data = initialize_data(target)

    get_subdomains(target, data, emit)
    get_netrange(target, data, emit)
    analyze_email_stack(target, data, emit)
    fingerprint_tech(target, data, emit)
    detect_leaks(target, data, emit)
    detect_takeover(data, emit)

    emit.success("[+] Scent Recon Complete")

    summary = (
        f"Subs: {len(data['subdomains'])} | "
        f"Leaks: {len(data['leak_indicators'])} | "
        f"Takeover: {len(data['takeover_candidates'])}"
    )

    return {
        "raw": summary,
        "intel": data
    }
