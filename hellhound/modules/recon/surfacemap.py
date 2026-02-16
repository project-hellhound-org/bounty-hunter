import subprocess
import shutil
import xml.etree.ElementTree as ET
import re

NAME = "surfacemap"
CATEGORY = "recon"
DESCRIPTION = "Active service enumeration, version fingerprinting, and attack surface correlation"

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
            timeout=300 # 5 min timeout for scanning
        )
        return result.stdout.strip()
    except Exception:
        return ""


def initialize_data(target):
    return {
        "target": target,
        "map": {}, # Structure: { "IP": { "port/proto": {"service": "ssh", "version": "OpenSSH" }}}
        "total_ports": 0,
        "web_servers": [],
        "tech_stack": [],
        "signals": []
    }


# -------------------------------------------------
# Active Scanning Stages
# -------------------------------------------------

def discover_targets(target, options, emit):
    """
    Determine what assets to actively scan.
    Priority:
    1. Stalk HTTP services
    2. Stalk subdomains
    3. Resolved IP of main target
    """

    targets = []

    stalk_data = options.get("stalk_results") if options else None

    # -------------------------------------------------
    # 1️⃣ Use HTTP services discovered by Stalk
    # -------------------------------------------------
    if stalk_data and "intel" in stalk_data:
        web_data = stalk_data["intel"].get("web", {})
        infra_data = stalk_data["intel"].get("infrastructure", {})

        http_services = web_data.get("http_services", [])
        subdomains = infra_data.get("subdomains", [])

        # Extract IP from http services
        for service in http_services:
            try:
                parsed = re.findall(r"https?://([^:/]+)", service)
                if parsed:
                    ip = socket.gethostbyname(parsed[0])
                    if ip not in targets:
                        targets.append(ip)
            except:
                continue

        # Resolve subdomains
        for sub in subdomains[:15]:
            try:
                ip = socket.gethostbyname(sub)
                if ip not in targets:
                    targets.append(ip)
            except:
                continue

    # -------------------------------------------------
    # 2️⃣ Fallback: Resolve main target
    # -------------------------------------------------
    if not targets:
        try:
            host = re.sub(r"https?://", "", target).split("/")[0]
            ip = socket.gethostbyname(host)
            targets.append(ip)
        except:
            targets.append(target)

    emit.info(f"[surfacemap] Targets identified: {len(targets)}")
    return targets



def scan_surface(targets, data, emit):
    """
    Runs Nmap on all discovered targets to build the surface map.
    Uses Nmap XML output for parsing.
    """
    emit.info(f"[surfacemap] Active probing {len(targets)} targets...")
    
    if not tool_exists("nmap"):
        emit.error("[surfacemap] nmap not found. Cannot map surface.")
        return

    # Scan Top 1000 ports + Version + Script Detection
    # -Pn: Skip ping (assume up)
    # -T4: Fast scan
    for ip in targets:
        emit.info(f"[surfacemap] Mapping surface of: {ip}")
        
        cmd = [
            "nmap", "-sV", "-sC", "-p-", "-Pn", "-T4", 
            "-oX", "-",  # XML to stdout
            ip
        ]
        
        xml_output = run_cmd(cmd)
        parse_nmap_xml(ip, xml_output, data)


def parse_nmap_xml(ip, xml_string, data):
    """
    Parses Nmap XML to populate the 'map' and 'tech_stack'
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return

    host = root.find(".//host")
    if host is None:
        return

    data["map"][ip] = {}

    for port in host.findall(".//port"):
        port_id = port.get("portid")
        protocol = port.get("protocol")
        state = port.find("state").get("state")

        if state == "open":
            data["total_ports"] += 1
            port_key = f"{port_id}/{protocol}"
            
            # Get Service Info
            svc_elem = port.find("service")
            service_name = "unknown"
            service_prod = ""
            service_ver = ""

            if svc_elem is not None:
                service_name = svc_elem.get("name", "unknown")
                service_prod = svc_elem.get("product", "")
                service_ver = svc_elem.get("version", "")
                
                # Add to global tech stack
                if service_prod:
                    data["tech_stack"].append(service_prod)
                if service_ver:
                    data["tech_stack"].append(f"{service_prod} {service_ver}")

            # Store in Map
            data["map"][ip][port_key] = {
                "service": service_name,
                "product": service_prod,
                "version": service_ver,
                "script_output": ""
            }

            # Script Output
            scripts = port.findall("script")
            for script in scripts:
                script_id = script.get("id")
                out = script.get("output", "")
                data["map"][ip][port_key]["script_output"] += f"{script_id}: {out}\n"

            # Identify Web Servers
            if service_name in ["http", "https", "ssl/http"]:
                if f"{ip}:{port_id}" not in data["web_servers"]:
                    data["web_servers"].append(f"{ip}:{port_id}")


def generate_signals(data, emit):
    """
    Analyzes the map to generate strategic signals
    """
    emit.info("[surfacemap] Analyzing attack surface...")
    
    unique_ips = len(data["map"].keys())
    
    if unique_ips > 1:
        data["signals"].append("MULTIPLE_ASSETS")
    
    if data["total_ports"] > 10:
        data["signals"].append("LARGE_SURFACE_AREA")
    
    if not data["web_servers"] and data["total_ports"] > 0:
        data["signals"].append("NON_WEB_TARGET")
    elif data["web_servers"]:
        data["signals"].append("WEB_APPLICATION_PRESENT")

    # Check for interesting tech
    tech_blob = " ".join(data["tech_stack"]).lower()
    if "ssh" in tech_blob:
        data["signals"].append("SSH_ACCESSIBLE")
    if "mysql" in tech_blob or "mariadb" in tech_blob:
        data["signals"].append("DATABASE_PRESENT")


# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):

    emit.info(f"[surfacemap] Initiating Surface Mapping for: {target}")

    data = initialize_data(target)

    if not options:
        options = {}

    # -------------------------------------------------
    # 1️⃣ Discover Targets (Now Integrated with Stalk)
    # -------------------------------------------------
    targets = discover_targets(target, options, emit)

    # -------------------------------------------------
    # 2️⃣ Active Scanning
    # -------------------------------------------------
    scan_surface(targets, data, emit)

    # -------------------------------------------------
    # 3️⃣ Analysis
    # -------------------------------------------------
    generate_signals(data, emit)

    # Clean duplicates
    data["tech_stack"] = list(set(data["tech_stack"]))
    data["signals"] = list(set(data["signals"]))

    emit.success(
        f"[surfacemap] Mapping complete. "
        f"{data['total_ports']} open ports across {len(data['map'])} assets."
    )

    return {
        "raw": f"Ports: {data['total_ports']} | Assets: {len(data['map'])}",
        "intel": data
    }