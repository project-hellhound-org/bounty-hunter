# hellhound/core/strategies.py

# Defines what modules to run automatically based on services found
# weight: 1-10 (Higher runs first)
# mode: console (interactive) or hunt (auto)

HUNT_RULES = [
    {
        "service": "ftp",
        "modules": ["ftp_enum"],
        "weight": 5,
        "description": "FTP Anonymous Check"
    },
    {
        "service": "ssh",
        "modules": ["ssh_bruteforce"], # Be careful with bruteforce in auto mode
        "weight": 4,
        "description": "SSH Credential Check"
    },
    {
        "service": "http",
        "modules": ["dirsearch", "vhost", "nuclei"],
        "weight": 8,
        "description": "Web Application Attack Surface"
    },
    {
        "service": "https",
        "modules": ["dirsearch", "vhost", "nuclei"],
        "weight": 8,
        "description": "Secure Web Application Attack Surface"
    },
    {
        "service": "microsoft-ds",
        "modules": ["smb_enum"],
        "weight": 9,
        "description": "SMB Enumeration & Vulnerability Check"
    },
    {
        "service": "mysql",
        "modules": ["mysql_enum"],
        "weight": 6,
        "description": "MySQL Access Check"
    }
]