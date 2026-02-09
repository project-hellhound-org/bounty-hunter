import subprocess
import shutil

NAME = "stalk"
CATEGORY = "web-recon"
DESCRIPTION = "Passive-first web intelligence gathering with quick and deep modes"


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def tool_exists(tool):
    return shutil.which(tool) is not None


def run_cmd(cmd, stdin=None):
    try:
        result = subprocess.run(
            cmd,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=300
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_depth(options, emit):
    if options and "depth" in options:
        depth = options["depth"]
        emit.info(f"[stalk] Using recon depth: {depth}")
        return depth

    try:
        depth = input("Recon depth? [quick/deep] (default: quick): ").strip().lower()
        if depth not in ["quick", "deep"]:
            depth = "quick"
    except Exception:
        depth = "quick"

    emit.info(f"[stalk] Using recon depth: {depth}")
    return depth


def initialize_data(target):
    return {
        "target": target,
        "dns": {
            "resolved": []
        },
        "http": {
            "alive": [],
            "raw": {},
            "titles": {}
        },
        "tech": {
            "fingerprints": []
        },
        "urls": {
            "endpoints": [],
            "js_files": []
        },
        "parameters": [],
        "signals": []
    }


# -------------------------------------------------
# Recon Stages
# -------------------------------------------------

def ingest_dns_recon(options, data, emit):
    """
    Consume resolved hosts from dns_recon if available
    """
    if not options:
        return

    dns_data = options.get("dns_recon")
    if not dns_data:
        return

    a_records = dns_data.get("records", {}).get("A", [])
    if a_records:
        emit.info("[stalk] Using resolved hosts from dns_recon")
        data["dns"]["resolved"].extend(a_records)


def run_http_probe(data, emit):
    emit.info("[stalk] Probing HTTP services")

    if not tool_exists("httpx"):
        emit.warn("[stalk] httpx not found")
        return

    if not data["dns"]["resolved"]:
        emit.warn("[stalk] No resolved hosts available for HTTP probing")
        return

    joined = "\n".join(sorted(set(data["dns"]["resolved"])))
    out = run_cmd(
        ["httpx", "-silent", "-title", "-status-code", "-web-server"],
        stdin=joined
    )

    for line in out.splitlines():
        parts = line.split(" ", 1)
        url = parts[0]
        data["http"]["alive"].append(url)
        data["http"]["raw"][url] = line
        data["http"]["titles"][url] = line

    data["http"]["alive"] = sorted(set(data["http"]["alive"]))


def run_tech_fingerprint(data, emit):
    emit.info("[stalk] Fingerprinting technology (whatweb)")

    if not tool_exists("whatweb"):
        emit.warn("[stalk] whatweb not found")
        return

    for url in data["http"]["alive"]:
        out = run_cmd(["whatweb", "-q", url])
        if out:
            data["tech"]["fingerprints"].append(out)

    data["tech"]["fingerprints"] = sorted(set(data["tech"]["fingerprints"]))

def run_katana(target, data, emit):
    emit.info("[stalk] Running katana crawler (deep mode)")

    if not tool_exists("katana"):
        emit.warn("[stalk] katana not found")
        return

    cmd = [
        "katana",
        "-u", f"https://{target}",
        "-silent",
        "-depth", "2",
        "-jc",          # crawl JS
        "-kf",          # known files
        "-ef", "png,jpg,jpeg,css,woff,woff2"
    ]

    out = run_cmd(cmd)

    for line in out.splitlines():
        data["urls"]["endpoints"].append(line)
        if line.endswith(".js"):
            data["urls"]["js_files"].append(line)

    # Deduplicate
    data["urls"]["endpoints"] = sorted(set(data["urls"]["endpoints"]))
    data["urls"]["js_files"] = sorted(set(data["urls"]["js_files"]))


def run_url_harvest(target, data, emit):
    emit.info("[stalk] Harvesting URLs (deep mode)")

    endpoints = set()
    js_files = set()

    if tool_exists("waybackurls"):
        out = run_cmd(["waybackurls", target])
        for line in out.splitlines():
            endpoints.add(line)
            if line.endswith(".js"):
                js_files.add(line)

    if tool_exists("gau"):
        out = run_cmd(["gau", target])
        for line in out.splitlines():
            endpoints.add(line)
            if line.endswith(".js"):
                js_files.add(line)

    data["urls"]["endpoints"] = sorted(endpoints)
    data["urls"]["js_files"] = sorted(js_files)


def run_param_discovery(data, emit):
    emit.info("[stalk] Extracting parameters (passive)")

    params = set()

    for url in data["urls"]["endpoints"]:
        if "?" in url:
            query = url.split("?", 1)[1]
            for pair in query.split("&"):
                key = pair.split("=", 1)[0]
                if key:
                    params.add(key)

    data["parameters"] = sorted(params)


def generate_signals(data, emit, depth):
    emit.info("[stalk] Generating signals")

    if len(data["dns"]["resolved"]) > 1:
        data["signals"].append("MULTI_TENANT_SUSPECTED")

    for url in data["http"]["alive"]:
        if any(x in url.lower() for x in ["login", "auth", "signin", "sso"]):
            data["signals"].append("AUTH_ENDPOINT_FOUND")

    if depth == "deep":
        if len(data["urls"]["js_files"]) > 5:
            data["signals"].append("JS_HEAVY_APPLICATION")

        if any("api" in u.lower() for u in data["urls"]["endpoints"]):
            data["signals"].append("API_HEAVY_APPLICATION")

    data["signals"] = sorted(set(data["signals"]))


# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):
    emit.info(f"[stalk] Stalking target: {target}")

    depth = get_depth(options, emit)
    data = initialize_data(target)

    # Consume DNS recon output (no DNS logic here)
    ingest_dns_recon(options, data, emit)

    run_http_probe(data, emit)
    run_tech_fingerprint(data, emit)

    if depth == "deep":
        run_url_harvest(target, data, emit)
        run_katana(target, data, emit)
        run_param_discovery(data, emit)

    generate_signals(data, emit, depth)

    emit.success("[stalk] Web reconnaissance complete")
    return data
