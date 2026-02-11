import subprocess
import re
import xml.etree.ElementTree as ET

NAME = "nmap"
CATEGORY = "network"
DESCRIPTION = "Adaptive recon, versioning, and vulnerability extraction"

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def build_command(target, options):
    opts = options or {}
    mode = opts.get("mode", "default")
    
    # Base command with XML output for parsing
    cmd = ["nmap", "-oX", "-"]

    # 1. SCAN MODES
    if mode == "quick":
        cmd.extend(["-T4", "-F"])
    elif mode == "full":
        cmd.extend(["-T4", "-p-", "-sV"])
    elif mode == "udp":
        # Top 20 UDP ports - fast enough for a quick check
        cmd.extend(["-sU", "--top-ports", "20", "-sV"])
    elif mode == "vuln":
        # Runs vulnerability scripts automatically
        cmd.extend(["-sV", "--script", "vuln"])
    elif mode == "stealth":
        cmd.extend(["-sS", "-T2", "-Pn"])
    elif mode == "aggressive":
        cmd.extend(["-A", "-T4"])
    else:
        # Default (Balanced)
        cmd.extend(["-sV", "-sC", "-T4"])

    # 2. EVASION TECHNIQUES (Pro Feature)
    evasion = opts.get("evasion")
    if evasion == "fragment":
        cmd.append("-f")  # Fragment packets
    elif evasion == "decoy":
        # Generate random decoy IPs to hide real IP
        cmd.extend(["-D", "RND:10"]) 
    elif evasion == "source_port":
        # Force scan from port 53 (DNS) to bypass firewall rules
        cmd.extend(["--source-port", "53"])

    # 3. MISC OPTIONS
    if opts.get("skip_ping"):
        cmd.append("-Pn")
    
    if opts.get("scripts"):
        cmd.extend(["--script", opts.get("scripts")])

    cmd.append(target)
    return cmd


def parse_xml_output(xml_string):
    """
    Parses Nmap XML to extract:
    1. Ports/Services/Versions
    2. NSE Script Findings (Vulnerabilities)
    """
    intel = {
        "open_ports": [],
        "services": {},
        "scripts": [],      # Stores NSE script outputs
        "vulnerabilities": [] # Extracted high-priority findings
    }

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return intel

    host = root.find(".//host")
    if host is None:
        return intel

    # Iterate ports
    for port in host.findall(".//port"):
        port_id = port.get("portid")
        proto = port.get("protocol")
        state = port.find("state").get("state")

        if state == "open":
            intel["open_ports"].append(int(port_id))
            
            # Service Info
            svc = port.find("service")
            service_name = svc.get("name", "unknown") if svc is not None else "unknown"
            service_prod = svc.get("product", "") if svc is not None else ""
            service_ver = svc.get("version", "") if svc is not None else ""

            intel["services"][f"{port_id}/{proto}"] = {
                "service": service_name,
                "product": service_prod,
                "version": service_ver
            }

            # Script Results (NSE)
            for script in port.findall("script"):
                script_id = script.get("id")
                output = script.get("output")
                
                intel["scripts"].append({
                    "port": port_id,
                    "id": script_id,
                    "output": output
                })

                # LOGIC: If script output looks like a vulnerability, flag it!
                if "VULNERABLE" in output.upper() or "CVE" in output.upper():
                    intel["vulnerabilities"].append({
                        "port": port_id,
                        "script": script_id,
                        "description": output
                    })

    return intel

# -------------------------------------------------
# Entry
# -------------------------------------------------

from colorama import Fore

def run(target, emit, options=None):
    emit(f"[*] Nmap scan initiated against {target}")

    cmd = build_command(target, options)
    emit(f"[CMD] {' '.join(cmd)}")

    # Capture XML silently (NO streaming to console)
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = process.communicate()

    if process.returncode != 0:
        emit(f"[!] Nmap error:\n{stderr}")
        return {}

    # Parse XML
    intel = parse_xml_output(stdout)

    emit(f"[✓] Scan complete. {len(intel['open_ports'])} ports open.")

    # Display clean structured summary
    if intel["services"]:
        emit("\n[ Open Ports ]")
        for port_proto, data in intel["services"].items():
            service = data.get("service", "unknown")
            product = data.get("product", "")
            version = data.get("version", "")
            emit(f"  {port_proto:<8} {service:<12} {product} {version}")

    # Alert for vulnerabilities
    if intel["vulnerabilities"]:
        emit(Fore.RED + f"\n[!!!] {len(intel['vulnerabilities'])} POTENTIAL VULNERABILITIES DETECTED")
        for vuln in intel["vulnerabilities"]:
            emit(Fore.RED + f"  Port {vuln['port']} → {vuln['script']}")

    return {
        "raw": stdout,
        "intel": intel
    }
