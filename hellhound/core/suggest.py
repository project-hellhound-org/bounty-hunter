import re

# -------------------------------------------------
# 1. THE KNOWLEDGE BASE (No more hardcoding ports)
# -------------------------------------------------

# Maps Nmap Service Names -> Hellhound Modules
# Keys are lowercased service names detected by Nmap
SERVICE_MODULES = {
    # File Transfer
    "ftp": {
        "modules": ["ftp_enum", "ftp_bruteforce"],
        "reason": "FTP service detected (Cleartext credentials)",
        "severity": 4
    },
    # Remote Access
    "ssh": {
        "modules": ["ssh_enum", "ssh_bruteforce"],
        "reason": "SSH service detected (Brute force target)",
        "severity": 3
    },
    "telnet": {
        "modules": ["telnet_enum"],
        "reason": "Telnet detected (Insecure cleartext)",
        "severity": 5
    },
    "rdp": {
        "modules": ["rdp_enum"],
        "reason": "Remote Desktop Protocol detected",
        "severity": 3
    },
    # Web Services (Covers http, https, ssl/http, etc)
    "http": {
        "modules": ["dirsearch", "vhost", "nuclei"],
        "reason": "Web service detected (Application attack surface)",
        "severity": 3
    },
    "https": {
        "modules": ["dirsearch", "vhost", "nuclei", "ssl_scan"],
        "reason": "Secure web service detected",
        "severity": 3
    },
    # Database
    "mysql": {
        "modules": ["mysql_enum", "mysql_bruteforce"],
        "reason": "MySQL database detected",
        "severity": 4
    },
    "ms-sql-s": {
        "modules": ["mssql_enum", "mssql_bruteforce"],
        "reason": "MSSQL database detected",
        "severity": 4
    },
    # Windows / SMB
    "microsoft-ds": {
        "modules": ["smb_enum", "smb_vuln"],
        "reason": "SMB/File sharing detected",
        "severity": 5
    },
    "netbios-ssn": {
        "modules": ["smb_enum"],
        "reason": "NetBIOS detected",
        "severity": 3
    },
    # Infrastructure
    "domain": {
        "modules": ["dns_zone_transfer", "dns_enum"],
        "reason": "DNS server detected",
        "severity": 3
    },
    "smtp": {
        "modules": ["smtp_enum"],
        "reason": "Mail server detected (User enumeration)",
        "severity": 3
    }
}

# -------------------------------------------------
# 2. VERSION HEURISTICS (Smart Hints)
# -------------------------------------------------

# Regex patterns to match specific vulnerable versions
VERSION_HINTS = [
    {
        "match": r"vsftpd\s*2\.3\.4",
        "hint": "CHECK: Vsftpd 2.3.4 Backdoor (CVE-2011-2523)",
        "priority": 10
    },
    {
        "match": r"openssh\s*7\.[2-4]",
        "hint": "CHECK: OpenSSH User Enumeration (CVE-2018-15473)",
        "priority": 6
    },
    {
        "match": r"apache\s*2\.4\.49",
        "hint": "CRITICAL: Apache Path Traversal (CVE-2021-41773)",
        "priority": 10
    },
    {
        "match": r"smb.*?smtp",
        "hint": "CHECK: SMB Vulnerable to EternalBlue (MS17-010)",
        "priority": 10
    }
]

# -------------------------------------------------
# 3. CORE ENGINE
# -------------------------------------------------

def get_service_rule(service_name):
    """
    Lookup modules based on service name.
    Normalizes names like 'ssl/http' -> 'http'
    """
    service_name = service_name.lower()
    
    # Direct match
    if service_name in SERVICE_MODULES:
        return SERVICE_MODULES[service_name]
    
    # Partial match (e.g., 'ssl/http' contains 'http')
    for key in SERVICE_MODULES:
        if key in service_name:
            return SERVICE_MODULES[key]

    return None


def analyze_version(version_string):
    """
    Check version string against known vulnerable patterns
    """
    hints = []
    if not version_string:
        return hints

    for rule in VERSION_HINTS:
        if re.search(rule["match"], version_string, re.IGNORECASE):
            hints.append({
                "type": "VULNERABILITY_HINT",
                "hint": rule["hint"],
                "priority": rule["priority"]
            })
    return hints


def suggest_actions(nmap_result):
    intel = nmap_result.get("intel", {})
    if intel.get("vulnerabilities"):
        for vuln in intel['vulnerabilities']:
            suggestions.append(f"CRITICAL: {vuln['script']} found on port {vuln['port']}")
    
    if not nmap_result:
        return ["[!] No scan data provided"]

    # Backward compatibility: Handle if raw string is passed by accident
    if isinstance(nmap_result, str):
        return ["[!] Legacy nmap output detected. Please re-run scan to use intel engine."]

    intel = nmap_result.get("intel", {})
    services = intel.get("services", {})
    
    if not services:
        return ["[!] No services found. Try 'nmap mode=full'"]

    suggestions = []

    # Iterate over found services
    for port_proto, data in services.items():
        
        port = port_proto.split("/")[0]
        service = data.get("service", "unknown")
        version = data.get("version", "")
        
        # 1. Check Service Rules
        rule = get_service_rule(service)
        if rule:
            mods = ", ".join(rule["modules"])
            suggestions.append(
                f"[PORT {port}] {service.upper()} → {mods} ({rule['reason']})"
            )
        else:
            # Unknown service generic advice
            suggestions.append(
                f"[PORT {port}] UNKNOWN SERVICE ({service}) → Manual analysis required"
            )

        # 2. Check Version Heuristics (CVE checks)
        v_hints = analyze_version(version)
        for hint in v_hints:
            suggestions.append(
                f"[CRITICAL] {hint['hint']} (Detected on port {port})"
            )

    # Remove duplicates and sort
    suggestions = list(dict.fromkeys(suggestions))
    
    return suggestions