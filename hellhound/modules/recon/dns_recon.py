import subprocess
import shutil
import re

NAME = "dns_recon"
CATEGORY = "recon"
DESCRIPTION = "DNS intelligence gathering (records, NS, MX, TXT, zone transfer checks)"


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
            timeout=30
        )
        return result.stdout.strip()
    except Exception:
        return ""


def initialize_data(target):
    return {
        "target": target,
        "records": {
            "A": [],
            "AAAA": [],
            "NS": [],
            "MX": [],
            "TXT": [],
            "PTR": []
        },
        "zone_transfer": False,
        "signals": []
    }


# -------------------------------------------------
# DNS Recon Stages
# -------------------------------------------------

def resolve_basic_records(target, data, emit):
    emit.info("[dns_recon] Resolving DNS records")

    if not tool_exists("dig"):
        emit.warn("[dns_recon] dig not found")
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
    emit.info("[dns_recon] Performing reverse DNS lookup")

    if not tool_exists("dig"):
        return

    for ip in data["records"]["A"]:
        if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
            out = run_cmd(["dig", "+short", "-x", ip])
            for line in out.splitlines():
                data["records"]["PTR"].append(line.strip())

    data["records"]["PTR"] = sorted(set(data["records"]["PTR"]))


def check_zone_transfer(target, data, emit):
    emit.info("[dns_recon] Checking for DNS zone transfer")

    if not tool_exists("dig"):
        return

    for ns in data["records"]["NS"]:
        out = run_cmd(["dig", "AXFR", target, "@"+ns])
        if out and "Transfer failed" not in out:
            data["zone_transfer"] = True
            data["signals"].append("ZONE_TRANSFER_POSSIBLE")
            break


def generate_signals(data, emit):
    emit.info("[dns_recon] Generating DNS signals")

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
    emit.info(f"[dns_recon] Gathering DNS intelligence for: {target}")

    data = initialize_data(target)

    resolve_basic_records(target, data, emit)
    reverse_dns_lookup(data, emit)
    check_zone_transfer(target, data, emit)
    generate_signals(data, emit)

    emit.success("[dns_recon] DNS reconnaissance complete")
    return data
