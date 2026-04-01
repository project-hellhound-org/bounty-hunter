import requests
import urllib.parse
from hellhound.core import http_utils

NAME = "cors_buster"
CATEGORY = "recon"
DESCRIPTION = "Active CORS misconfiguration detection (Origin reflection, Null trust, Arbitrary trust)"

def generate_poc(url, origin, credentials):
    """Generates a clean HTML/JS PoC for the CORS misconfiguration"""
    creds_js = "xhr.withCredentials = true;" if credentials else ""
    
    poc_html = f"""
<!DOCTYPE html>
<html>
<body>
    <h2>Hellhound CORS Exploit PoC</h2>
    <p>Target: {url}</p>
    <p>Reflected Origin: {origin}</p>
    <script>
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {{
            if (xhr.readyState == 4) {{
                alert("Exploit Success! Data: " + xhr.responseText.substring(0, 100));
            }}
        }};
        xhr.open("GET", "{url}", true);
        {creds_js}
        xhr.send();
    </script>
</body>
</html>
"""
    return poc_html.strip()

def test_cors(url, origin, session=None):
    headers = {"Origin": origin}
    try:
        if session:
            r = session.options(url, headers=headers, timeout=5)
            if "Access-Control-Allow-Origin" not in r.headers:
                r = session.get(url, headers=headers, timeout=5)
        else:
            r = requests.options(url, headers=headers, timeout=5)
            if "Access-Control-Allow-Origin" not in r.headers:
                r = requests.get(url, headers=headers, timeout=5)
            
        acao = r.headers.get("Access-Control-Allow-Origin")
        if not acao:
            return None
            
        acac = r.headers.get("Access-Control-Allow-Credentials", "false").lower() == "true"
        return {"origin": origin, "acao": acao, "credentials": acac}
    except Exception:
        pass
    return None

def run(target, emit, options=None):
    emit.info(f"[*] CORS Buster: Analyzing Origins for {target}")
    
    # Configure session with global proxy and headers
    session = requests.Session()
    http_utils.apply_session_config(session, options)
    
    base_url = target if target.startswith("http") else f"http://{target}"
    parsed = urllib.parse.urlparse(base_url)
    domain = parsed.netloc
    
    # Grab spider endpoints properly from options passed by console.py
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    urls_to_test = [base_url]
    for ep in endpoints:
        ep_url = ep.get("url")
        if ep_url:
            urls_to_test.append(ep_url)
        
    urls_to_test = list(set(urls_to_test))
    if len(urls_to_test) > 100:
        # If there are a massive number of endpoints, cap to 100 to save time
        urls_to_test = list(urls_to_test)[:100]
    
    payloads = [
        "https://evil.com", 
        "null", 
        f"https://{domain}.evil.com", # Post-domain trust
        f"https://evil{domain}",      # Pre-domain trust
        f"http://{domain}"            # HTTP trust on HTTPS
    ]
    
    findings = []
    signals = []
    risk_score = 0
    
    for url in urls_to_test:
        for payload in payloads:
            result = test_cors(url, payload, session=session)
            if not result:
                continue
                
            acao = result["acao"]
            acac = result["credentials"]
            
            vuln_type = None
            risk_val = 0
            
            if acao == payload:
                vuln_type = "Origin Reflection"
                if payload == "null": vuln_type = "Null Origin Trust"
                elif "evil" in payload: vuln_type = "Arbitrary Origin Trust"
                elif payload == f"http://{domain}": vuln_type = "Insecure HTTP Trust"
                
                risk_val = 5 if acac else 3
                
            elif acao == "*" and acac:
                vuln_type = "Wildcard with Credentials"
                risk_val = 5 
                
            elif acao == "*" and not acac:
                vuln_type = "Open CORS (Wildcard)"
                risk_val = 1
                
            if vuln_type:
                # Prevent duplicate finding types for the same URL
                duplicate = any(f["url"] == url and f["type"] == vuln_type for f in findings)
                if not duplicate:
                    finding = {
                        "url": url,
                        "type": vuln_type,
                        "payload": payload,
                        "credentials_allowed": acac,
                        "poc_html": generate_poc(url, payload, acac),
                        "repro_data": {
                            "method": "OPTIONS",
                            "url": url,
                            "headers": {"Origin": payload}
                        }
                    }
                    findings.append(finding)
                    risk_score += risk_val
                    emit.warn(f"    [!] {vuln_type} on {url} (Origin: {payload}) [Creds: {acac}]")

    if findings:
        signals.append("CORS_MISCONFIGURATION")
        emit.success(f"[+] Found {len(findings)} CORS misconfigurations.")
    else:
        emit.info("[-] No CORS misconfigurations detected.")
        
    return {
        "raw": f"CORS Misconfigs: {len(findings)}",
        "intel": {"cors_vulnerabilities": findings, "risk_score": risk_score},
        "signals": signals
    }
