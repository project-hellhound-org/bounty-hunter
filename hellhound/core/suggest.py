def suggest_actions(nmap_output: str):
    suggestions = []

    if "80/tcp" in nmap_output or "http" in nmap_output.lower():
        suggestions.append("Web detected → try: run vhost, run dirsearch")

    if "21/tcp" in nmap_output:
        suggestions.append("FTP detected → try anonymous login, brute force")

    if "22/tcp" in nmap_output:
        suggestions.append("SSH detected → optional brute-force")

    if "445/tcp" in nmap_output or "139/tcp" in nmap_output:
        suggestions.append("SMB detected → try enum, share listing")

    if not suggestions:
        suggestions.append("No obvious attack surface detected yet")

    return suggestions
