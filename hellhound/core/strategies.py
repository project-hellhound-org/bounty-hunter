# hellhound/core/strategies.py

# Defines what modules to run automatically based on services found
# weight: 1-10 (Higher runs first)
# mode: console (interactive) or hunt (auto)

HUNT_RULES = [
    {
        "service": "ftp",
        "modules": ["ftp"],
        "options": {"mode": "enum"},  # SAFE: Checks for Anonymous first
        "weight": 9, # High priority (Anonymous FTP is gold)
        "description": "FTP Anonymous Login Check"
    },
    {
        "service": "ssh",
        "modules": ["ssh_enum"],
        "weight": 5,
        "description": "SSH Enumeration"
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