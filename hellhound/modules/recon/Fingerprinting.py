import requests
import re
from bs4 import BeautifulSoup

NAME = "tech_fingerprint"
CATEGORY = "recon"
DESCRIPTION = "Active technology fingerprinting (Headers, Meta Tags, Cookies)"

# Signatures to look for
TECH_SIGNATURES = {
    "Server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "cloudflare": "Cloudflare",
        "iis": "Microsoft IIS",
        "litespeed": "LiteSpeed"
    },
    "X-Powered-By": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Node.js (Express)",
        "next.js": "Next.js"
    },
    "Set-Cookie": {
        "phpsessid": "PHP",
        "jsessionid": "Java (JSP)",
        "laravel_session": "Laravel",
        "wordpress_": "WordPress",
        "asp.net_sessionid": "ASP.NET"
    }
}

def run(target, emit, options=None):
    emit.info(f"[*] Tech Fingerprint: Analyzing {target}")
    
    url = target if target.startswith("http") else f"http://{target}"
    
    detected_tech = []

    try:
        r = requests.get(url, timeout=8)
        headers = r.headers
        content = r.text
        cookies = r.cookies.get_dict()
        
        # 1. Analyze Headers
        for header_name, signatures in TECH_SIGNATURES.items():
            if header_name in headers or header_name == "Set-Cookie": # Cookies handled specially
                header_val = headers.get(header_name, "").lower()
                
                if header_name == "Set-Cookie":
                    # Check keys in cookies
                    for cookie_key in cookies:
                        cookie_key_lower = cookie_key.lower()
                        for sig, tech in signatures.items():
                            if sig in cookie_key_lower and tech not in detected_tech:
                                detected_tech.append(tech)
                                emit.info(f"    [+] Detected via Cookie: {tech}")
                else:
                    # Check standard headers
                    for sig, tech in signatures.items():
                        if sig in header_val and tech not in detected_tech:
                            detected_tech.append(tech)
                            emit.info(f"    [+] Detected via Header: {tech}")

        # 2. Analyze HTML Meta Tags (Generator)
        soup = BeautifulSoup(content, "html.parser")
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            gen_content = generator["content"]
            emit.info(f"    [+] Generator Meta: {gen_content}")
            if gen_content not in detected_tech:
                detected_tech.append(gen_content)

    except Exception as e:
        emit.error(f"Error fetching target: {e}")
        return {"raw": "Connection Failed", "signals": []}

    if detected_tech:
        emit.success(f"[+] Technology Stack Identified: {', '.join(detected_tech)}")
        return {
            "raw": f"Tech: {', '.join(detected_tech)}",
            "intel": {"tech_stack": detected_tech},
            "signals": ["TECH_IDENTIFIED"]
        }
    else:
        emit.info("[-] Could not confidently identify technology.")
        return {"raw": "No tech detected", "signals": []}