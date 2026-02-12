import subprocess
import shutil
import re

NAME = "scent"
CATEGORY = "recon"
DESCRIPTION = "Full-scope reconnaissance (ASN, IP, Hosting, Cloud, CDN, DNS Records, Zone Transfer)"


# -------------------------------------------------
# Helpers
# -------------------------------------------------

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


def initialize_data(target):
    """
    Initializes a data structure holding both Asset and DNS information
    """
    return {
        "target": target,
        # Asset Intelligence
        "ips": [],
        "asn": [],
        "org": [],
        "cdn": [],
        "cloud": [],
        "whois": {},
        # DNS Intelligence
        "records": {
            "A": [],
            "AAAA": [],
            "NS": [],
            "MX": [],
            "TXT": [],
            "PTR": []
        },
        "zone_transfer": False,
        # Signals
        "signals": []
    }


# -------------------------------------------------
# Asset Recon Stages
# -------------------------------------------------

def resolve_ips(target, data, emit):
    """Stage 1: Resolve direct IP addresses"""
    emit.info("[asset_recon] Resolving IP addresses")

    if tool_exists("dig"):
        out = run_cmd(["dig", "+short", target])
        for line in out.splitlines():
            if re.match(r"\d+\.\d+\.\d+\.\d+", line):
                data["ips"].append(line)

    data["ips"] = sorted(set(data["ips"]))


def run_whois(target, data, emit):
    """Stage 2: Collect WHOIS and Organization data"""
    emit.info("[asset_recon] Collecting WHOIS data")

    if not tool_exists("whois"):
        emit.warn("[asset_recon] whois not available")
        return

    out = run_cmd(["whois", target])
    data["whois"]["raw"] = out

    for line in out.splitlines():
        if line.lower().startswith("org"):
            data["org"].append(line.split(":", 1)[-1].strip())
        if "asn" in line.lower():
            data["asn"].append(line.strip())


def detect_cdn_cloud(data, emit):
    """Stage 3: Analyze WHOIS to detect CDN and Cloud providers"""
    emit.info("[asset_recon] Detecting CDN / Cloud providers")

    CDN_KEYWORDS = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "fastly": "Fastly",
        "incapsula": "Imperva"
    }

    CLOUD_KEYWORDS = {
        "amazon": "AWS",
        "aws": "AWS",
        "google": "GCP",
        "microsoft": "Azure",
        "azure": "Azure",
        "digitalocean": "DigitalOcean"
    }

    text_blob = " ".join(data["org"]) + " " + data["whois"].get("raw", "").lower()

    for key, name in CDN_KEYWORDS.items():
        if key in text_blob:
            data["cdn"].append(name)
            data["signals"].append("CDN_DETECTED")

    for key, name in CLOUD_KEYWORDS.items():
        if key in text_blob:
            data["cloud"].append(name)
            data["signals"].append("CLOUD_HOSTED")

    data["cdn"] = sorted(set(data["cdn"]))
    data["cloud"] = sorted(set(data["cloud"]))


# -------------------------------------------------
# DNS Recon Stages
# -------------------------------------------------

def resolve_dns_records(target, data, emit):
    """Stage 4: Gather standard DNS records"""
    emit.info("[asset_recon] Resolving DNS records (A, AAAA, NS, MX, TXT)")

    if not tool_exists("dig"):
        emit.warn("[asset_recon] dig not found")
        return

    record_types = ["A", "AAAA", "NS", "MX", "TXT"]

    for rtype in record_types:
        out = run_cmd(["dig", "+short", target, rtype])
        for line in out.splitlines():
            data["records"][rtype].append(line.strip())

    # Deduplicate
    for rtype in data["records"]:
        data["records"][rtype] = sorted(set(data["records"][rtype]))


def reverse_dns_lookup(data, emit):
    """Stage 5: Perform reverse DNS on found IPs"""
    emit.info("[asset_recon] Performing reverse DNS lookup")

    if not tool_exists("dig"):
        return

    for ip in data["records"]["A"]:
        if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
            out = run_cmd(["dig", "+short", "-x", ip])
            for line in out.splitlines():
                data["records"]["PTR"].append(line.strip())

    data["records"]["PTR"] = sorted(set(data["records"]["PTR"]))


def check_zone_transfer(target, data, emit):
    """Stage 6: Attempt DNS Zone Transfer"""
    emit.info("[asset_recon] Checking for DNS zone transfer")

    if not tool_exists("dig"):
        return

    for ns in data["records"]["NS"]:
        out = run_cmd(["dig", "AXFR", target, "@"+ns])
        if out and "Transfer failed" not in out:
            data["zone_transfer"] = True
            data["signals"].append("ZONE_TRANSFER_POSSIBLE")
            emit.warn("[asset_recon] ZONE TRANSFER POSSIBLE!")
            break


# -------------------------------------------------
# Final Signal Generation
# -------------------------------------------------

def generate_signals(data, emit):
    """Stage 7: Compile findings into actionable signals"""
    emit.info("[asset_recon] Generating tactical signals")

    # Asset Signals
    if len(data["ips"]) > 1:
        data["signals"].append("MULTIPLE_IPS")

    if any(org for org in data["org"]):
        data["signals"].append("ORG_LARGE")

    # DNS Signals
    if len(data["records"]["NS"]) > 1:
        data["signals"].append("MULTIPLE_NS")

    if data["records"]["MX"]:
        data["signals"].append("MX_PRESENT")

    for txt in data["records"]["TXT"]:
        if txt.lower().startswith("v=spf"):
            data["signals"].append("SPF_PRESENT")
        if txt.lower().startswith("v=dmarc"):
            data["signals"].append("DMARC_PRESENT")

    if data["records"]["PTR"]:
        data["signals"].append("REVERSE_DNS_FOUND")

    data["signals"] = sorted(set(data["signals"]))


# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):
    emit.info(f"[asset_recon] Starting full-scope reconnaissance for: {target}")

    data = initialize_data(target)

    # Run Asset Stages
    resolve_ips(target, data, emit)
    run_whois(target, data, emit)
    detect_cdn_cloud(data, emit)

    # Run DNS Stages
    resolve_dns_records(target, data, emit)
    reverse_dns_lookup(data, emit)
    check_zone_transfer(target, data, emit)

    # Final Analysis
    generate_signals(data, emit)

    emit.success("[asset_recon] Full reconnaissance complete")

    # -------- Summary String --------
    summary = (
        f"IPs: {len(data['ips'])} | "
        f"NS: {len(data['records']['NS'])} | "
        f"MX: {len(data['records']['MX'])} | "
        f"CDN: {len(data['cdn'])} | "
        f"Cloud: {len(data['cloud'])}"
    )

    return {
        "raw": summary,
        "intel": data
    }
