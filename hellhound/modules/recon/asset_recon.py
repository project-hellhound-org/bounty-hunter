import subprocess
import shutil
import re

NAME = "asset_recon"
CATEGORY = "recon"
DESCRIPTION = "Target-level asset reconnaissance (ASN, IPs, hosting, CDN, cloud)"


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
    return {
        "target": target,
        "ips": [],
        "asn": [],
        "org": [],
        "cdn": [],
        "cloud": [],
        "whois": {},
        "signals": []
    }


# -------------------------------------------------
# Recon Stages
# -------------------------------------------------

def resolve_ips(target, data, emit):
    emit.info("[asset_recon] Resolving IP addresses")

    if tool_exists("dig"):
        out = run_cmd(["dig", "+short", target])
        for line in out.splitlines():
            if re.match(r"\d+\.\d+\.\d+\.\d+", line):
                data["ips"].append(line)

    data["ips"] = sorted(set(data["ips"]))


def run_whois(target, data, emit):
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


def generate_signals(data, emit):
    emit.info("[asset_recon] Generating signals")

    if len(data["ips"]) > 1:
        data["signals"].append("MULTIPLE_IPS")

    if any(org for org in data["org"]):
        data["signals"].append("ORG_LARGE")

    data["signals"] = sorted(set(data["signals"]))


# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):
    emit.info(f"[asset_recon] Reconning assets for: {target}")

    data = initialize_data(target)

    resolve_ips(target, data, emit)
    run_whois(target, data, emit)
    detect_cdn_cloud(data, emit)
    generate_signals(data, emit)

    emit.success("[asset_recon] Asset reconnaissance complete")
    return data
