import re

# Common port → action mapping
PORT_SUGGESTIONS = {
    21: [
        "Check FTP for anonymous login",
        "Bruteforce FTP credentials",
        "Upload files if write access exists"
    ],
    22: [
        "Enumerate SSH users",
        "Check for weak SSH credentials",
        "Look for outdated SSH versions"
    ],
    23: [
        "Telnet detected – check for cleartext credentials"
    ],
    25: [
        "Enumerate SMTP users (VRFY / EXPN)",
        "Check for open relay"
    ],
    53: [
        "Attempt DNS zone transfer",
        "Enumerate subdomains via DNS"
    ],
    80: [
        "Run dirsearch for directory discovery",
        "Check for virtual hosts (vhost)",
        "Fingerprint web technologies",
        "Run nuclei for web vulnerabilities"
    ],
    443: [
        "Run dirsearch over HTTPS",
        "Check SSL/TLS configuration",
        "Run nuclei with SSL templates"
    ],
    110: [
        "Check POP3 for weak credentials"
    ],
    139: [
        "Enumerate SMB shares",
        "Check for null sessions"
    ],
    445: [
        "Enumerate SMB users and shares",
        "Check for SMB vulnerabilities (EternalBlue, etc.)"
    ],
    3306: [
        "Enumerate MySQL version",
        "Check for weak MySQL credentials",
        "Attempt local file read via MySQL"
    ],
    3389: [
        "Check RDP for weak credentials",
        "Check for NLA misconfiguration"
    ],
    8080: [
        "Enumerate web service on port 8080",
        "Check for admin panels"
    ]
}


def extract_open_ports(nmap_output: str):
    """
    Extract open TCP ports from Nmap output
    """
    ports = set()

    for line in nmap_output.splitlines():
        match = re.match(r"(\d+)/tcp\s+open", line)
        if match:
            ports.add(int(match.group(1)))

    return ports


def suggest_actions(nmap_output: str):
    """
    Suggest next actions purely based on detected open ports
    """

    if not nmap_output:
        return ["Run nmap scan first"]

    open_ports = extract_open_ports(nmap_output)

    if not open_ports:
        return ["No open ports detected – consider UDP scan"]

    suggestions = []

    for port in sorted(open_ports):
        if port in PORT_SUGGESTIONS:
            for action in PORT_SUGGESTIONS[port]:
                suggestions.append(f"[{port}] {action}")
        else:
            suggestions.append(f"[{port}] Research service manually")

    return suggestions
