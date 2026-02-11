import subprocess
import shutil

NAME = "stalk"
CATEGORY = "web"
DESCRIPTION = "Passive-first web intelligence gathering (quick/deep)"


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

def run(target, emit, options=None):
    emit.info(f"Stalking target: {target}")

    try:
        depth = input("Recon depth? [quick/deep] (default: quick): ").strip().lower()
        if depth not in ("quick", "deep"):
            depth = "quick"
    except Exception:
        depth = "quick"

    emit.info(f"Using recon depth: {depth}")

    data = {
        "http": [],
        "tech": [],
        "urls": [],
        "js": [],
        "params": [],
        "signals": []
    }

    # HTTP probe
    if tool_exists("httpx"):
        emit.info("Probing HTTP services")
        out = run_cmd(["httpx", "-silent", "-u", target])
        data["http"] = out.splitlines()

    # Tech fingerprint
    if tool_exists("whatweb"):
        emit.info("Fingerprinting technologies")
        for url in data["http"]:
            res = run_cmd(["whatweb", "-q", url])
            if res:
                data["tech"].append(res)

    if depth == "deep":
        # URL harvest
        if tool_exists("gau"):
            emit.info("Harvesting URLs (gau)")
            out = run_cmd(["gau", target])
            data["urls"].extend(out.splitlines())

        if tool_exists("katana"):
            emit.info("Crawling with katana")
            out = run_cmd(["katana", "-u", f"http://{target}", "-silent"])
            for u in out.splitlines():
                data["urls"].append(u)
                if u.endswith(".js"):
                    data["js"].append(u)

    # Parameter extraction
    for url in data["urls"]:
        if "?" in url:
            for pair in url.split("?", 1)[1].split("&"):
                key = pair.split("=", 1)[0]
                if key:
                    data["params"].append(key)

    # Signals
    if any("login" in u.lower() for u in data["urls"]):
        data["signals"].append("AUTH_ENDPOINT_FOUND")

    if len(data["js"]) > 5:
        data["signals"].append("JS_HEAVY_APPLICATION")

    emit.success("Web reconnaissance complete")
    return data
