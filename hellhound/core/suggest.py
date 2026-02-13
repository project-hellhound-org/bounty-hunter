import re


# =================================================
# SERVICE KNOWLEDGE BASE (For Nmap)
# =================================================

SERVICE_MODULES = {
    "ftp": {
        "modules": ["ftp"],
        "reason": "FTP service detected (Cleartext credentials)",
    },
    "ssh": {
        "modules": ["ssh"],
        "reason": "SSH detected (Brute force / Key audit)"
    },
    "http": {
        "modules": ["spider", "dirsearch", "vhost", "nuclei"],
        "reason": "Web service detected"
    },
    "https": {
        "modules": ["spider", "dirsearch", "vhost", "nuclei"],
        "reason": "Secure web service detected"
    },
    "mysql": {
        "modules": ["mysql_enum"],
        "reason": "MySQL database detected"
    },
    "microsoft-ds": {
        "modules": ["smb_enum"],
        "reason": "SMB service detected"
    }
}


# =================================================
# VERSION HEURISTICS
# =================================================

VERSION_HINTS = [
    {
        "match": r"apache\s*2\.4\.49",
        "hint": "CRITICAL: Apache Path Traversal (CVE-2021-41773)"
    },
    {
        "match": r"vsftpd\s*2\.3\.4",
        "hint": "CRITICAL: Vsftpd 2.3.4 Backdoor (CVE-2011-2523)"
    }
]


# =================================================
# MAIN INTEL ANALYZER
# =================================================

def suggest_actions(results):
    """
    Accepts full self.results dict from console.
    Works across ALL modules.
    """

    if not results:
        return ["[!] No intelligence gathered yet"]

    suggestions = []

    # -------------------------------------------------
    # 1️⃣ NMAP INTEL
    # -------------------------------------------------
    if "nmap" in results:

        nmap_result = results["nmap"]
        intel = nmap_result.get("intel", {})
        services = intel.get("services", {})

        for port_proto, data in services.items():
            port = port_proto.split("/")[0]
            service = data.get("service", "").lower()
            version = data.get("version", "")

            # Service rule
            for key in SERVICE_MODULES:
                if key in service:
                    mods = ", ".join(SERVICE_MODULES[key]["modules"])
                    suggestions.append(
                        f"[PORT {port}] {service.upper()} → Run: {mods}"
                    )

            # Version hint
            for rule in VERSION_HINTS:
                if re.search(rule["match"], version, re.IGNORECASE):
                    suggestions.append(
                        f"[PORT {port}] {rule['hint']}"
                    )

        if not services:
            suggestions.append("No services found. Try full Nmap scan.")

    # -------------------------------------------------
    # 2️⃣ SPIDER / SNIFF INTEL
    # -------------------------------------------------
    for mod in ["spider", "sniff"]:
        if mod in results:

            intel = results[mod].get("intel", {})
            signals = intel.get("signals", [])
            endpoints = intel.get("endpoints", [])
            apis = intel.get("api_endpoints", [])

            # Login wall
            if "LOGIN_WALL_DETECTED" in signals:
                suggestions.append("Authentication wall detected → Re-run spider with --auth")

            # IDOR risk
            for ep in endpoints:
                for param in ep.get("params", []):
                    if param["name"].lower() in ["id", "user_id"]:
                        suggestions.append("Potential IDOR detected → Manual ID manipulation testing recommended")

            # SQLi risk
            for ep in endpoints:
                for param in ep.get("params", []):
                    if param["name"].lower() in ["search", "query"]:
                        suggestions.append("Potential SQLi parameter found → Test with manual payloads")

            # APIs found
            if apis:
                suggestions.append("API endpoints discovered → Run nuclei or manual API fuzzing")

            # Missing headers
            for sig in signals:
                if sig.startswith("MISSING_"):
                    suggestions.append("Security headers missing → Review security misconfiguration")

            # JWT
            if "JWT_DETECTED" in signals:
                suggestions.append("JWT detected → Attempt token decoding & signature testing")

    # -------------------------------------------------
    # 3️⃣ SCENT INTEL
    # -------------------------------------------------
    if "scent" in results:

        intel = results["scent"].get("intel", {})
        signals = intel.get("signals", [])

        if "LARGE_ATTACK_SURFACE" in signals:
            suggestions.append("Large subdomain surface → Consider subdomain takeover testing")

        if "WAF_CLOUDFLARE" in signals:
            suggestions.append("Cloudflare WAF detected → Consider bypass techniques")

        if "ASN_IDENTIFIED" in signals:
            suggestions.append("ASN identified → Expand recon to entire netrange")

        if intel.get("subdomains"):
            suggestions.append("Discovered subdomains → Run dirsearch/spider on each")

    # -------------------------------------------------
    # Final Clean
    # -------------------------------------------------

    suggestions = list(dict.fromkeys(suggestions))

    if not suggestions:
        suggestions.append("No immediate attack paths identified. Continue manual analysis.")

    return suggestions
