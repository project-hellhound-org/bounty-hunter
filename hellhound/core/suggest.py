import re

# -------------------------------------------------
# Port-based suggestions (new structured format)
# -------------------------------------------------

PORT_SUGGESTIONS = {
    21: {
        "modules": ["ftp_enum", "ftp_bruteforce"],
        "reason": "FTP service detected",
        "severity": 4,
        "confidence": 4
    },
    22: {
        "modules": ["ssh_enum", "ssh_bruteforce"],
        "reason": "SSH service detected",
        "severity": 4,
        "confidence": 4
    },
    23: {
        "modules": ["telnet_enum"],
        "reason": "Telnet uses cleartext communication",
        "severity": 5,
        "confidence": 5
    },
    25: {
        "modules": ["smtp_enum"],
        "reason": "SMTP service detected",
        "severity": 4,
        "confidence": 4
    },
    53: {
        "modules": ["dns_zone_transfer", "dns_enum"],
        "reason": "DNS service detected",
        "severity": 3,
        "confidence": 4
    },
    80: {
        "modules": ["dirsearch", "vhost"],
        "reason": "HTTP service detected",
        "severity": 3,
        "confidence": 4
    },
    443: {
        "modules": ["dirsearch", "vhost", "ssl_enum"],
        "reason": "HTTPS service detected",
        "severity": 3,
        "confidence": 4
    },
    445: {
        "modules": ["smb_enum", "smb_vuln_check"],
        "reason": "SMB service detected",
        "severity": 5,
        "confidence": 5
    },
    3306: {
        "modules": ["mysql_enum", "mysql_bruteforce"],
        "reason": "MySQL service detected",
        "severity": 4,
        "confidence": 4
    },
    3389: {
        "modules": ["rdp_enum"],
        "reason": "RDP service detected",
        "severity": 4,
        "confidence": 4
    }
}

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def extract_open_ports(nmap_output: str):
    ports = set()
    for line in nmap_output.splitlines():
        match = re.match(r"(\d+)/tcp\s+open", line)
        if match:
            ports.add(int(match.group(1)))
    return ports


def score(entry):
    return entry.get("severity", 1) * entry.get("confidence", 1)


# -------------------------------------------------
# Core Suggest Engine (internal)
# -------------------------------------------------

def _build_suggestions(nmap_output: str):
    suggestions = []

    if not nmap_output:
        return []

    open_ports = extract_open_ports(nmap_output)

    for port in sorted(open_ports):
        entry = PORT_SUGGESTIONS.get(port)
        if entry:
            suggestions.append({
                "port": port,
                "modules": entry["modules"],
                "reason": entry["reason"],
                "priority": score(entry),
                "severity": entry["severity"],
                "confidence": entry["confidence"]
            })
        else:
            suggestions.append({
                "port": port,
                "modules": [],
                "reason": "Unknown service – manual analysis required",
                "priority": 1,
                "severity": 1,
                "confidence": 1
            })

    suggestions.sort(key=lambda x: x["priority"], reverse=True)
    return suggestions


# -------------------------------------------------
# PUBLIC API (Legacy Console Compatible)
# -------------------------------------------------

def suggest_actions(nmap_output: str):
    """
    Legacy-compatible API.
    Returns a LIST OF STRINGS (required by console).
    """

    structured = _build_suggestions(nmap_output)

    if not structured:
        return ["No actionable suggestions available"]

    output = []

    for s in structured:
        if s["modules"]:
            mods = ", ".join(s["modules"])
            output.append(
                f"[PRIORITY {s['priority']}] "
                f"[{s['port']}] {mods} — {s['reason']}"
            )
        else:
            output.append(
                f"[{s['port']}] {s['reason']}"
            )

    return output
