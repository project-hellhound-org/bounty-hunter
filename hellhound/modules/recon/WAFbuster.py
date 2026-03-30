import requests
import re
from bs4 import BeautifulSoup
from hellhound.core import http_utils

NAME = "wafbuster"
CATEGORY = "recon"
DESCRIPTION = "Advanced WAF detection and Technology Fingerprinting (Passive + Active)"

from hellhound.modules.recon.utils.signatures import WAF_SIGNATURES, TECH_SIGNATURES

def active_trigger(url, emit, session=None):
    """Sends a suspicious payload to trigger WAF response patterns"""
    payloads = [
        "/?id=<script>alert(1)</script>",
        "/?file=../../etc/passwd",
        "/?query=UNION SELECT ALL NULL,NULL,NULL--"
    ]
    
    triggered_wafs = []
    
    for p in payloads:
        try:
            if session:
                r = session.get(url + p, timeout=5)
            else:
                r = requests.get(url + p, timeout=5, headers={"User-Agent": "Hellhound/1.0"})
            
            # Cloudflare 403 / 1020
            if r.status_code in [403, 1020] and "error code: 1020" in r.text.lower():
                triggered_wafs.append("Cloudflare (Active)")
            # Generic WAF 403
            elif r.status_code == 403:
                if "waf" in r.text.lower() or "firewall" in r.text.lower() or "blocked" in r.text.lower():
                    triggered_wafs.append("Generic WAF (Active)")
            # AWS WAF 403
            if r.status_code == 403 and "x-amzn-requestid" in r.headers:
                triggered_wafs.append("AWS WAF (Active)")
                
        except:
            pass
            
    return list(set(triggered_wafs))

def run(target, emit, options=None):
    emit.info(f"[*] WAFbuster: Starting deep analysis of {target}")
    
    base_url = target if target.startswith("http") else f"http://{target}"
    base_url = base_url.rstrip("/")
    
    detected_wafs = []
    detected_tech = []
    signals = []

    try:
        # Configure session with global proxy and headers
        session = requests.Session()
        http_utils.apply_session_config(session, options)
        session.headers.update({"User-Agent": "Hellhound/1.0"})

        # --- Phase 1: Passive Analysis ---
        r = session.get(base_url, timeout=10)
        headers_low = {k.lower(): str(v).lower() for k, v in r.headers.items()}
        cookies_low = {k.lower(): str(v).lower() for k, v in r.cookies.get_dict().items()}
        body_low = r.text.lower()

        # 1. Detect WAFs (Passive)
        for waf, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if any(sig in h_val for h_val in headers_low.values()) or \
                   any(sig in c_key for c_key in cookies_low) or \
                   sig in body_low:
                    detected_wafs.append(waf)
                    break

        # 2. Detect Tech (Passive)
        # Server header
        server = headers_low.get("server", "")
        for sig, name in TECH_SIGNATURES["Server"].items():
            if sig in server:
                detected_tech.append(name)
        
        # Powered By header
        powered = headers_low.get("x-powered-by", "")
        for sig, name in TECH_SIGNATURES["Framework"].items():
            if sig in powered:
                detected_tech.append(name)

        # Cookies
        for category, sigs in TECH_SIGNATURES.items():
            if isinstance(sigs, dict):
                for sig, tech_name in sigs.items():
                    if any(sig in c for c in cookies_low):
                        detected_tech.append(tech_name)

        # HTML Meta Generator
        soup = BeautifulSoup(r.text, "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            detected_tech.append(gen["content"])

        # --- Phase 2: Active Triggering ---
        emit.info("    [i] Performing active WAF triggering...")
        active_results = active_trigger(base_url, emit, session=session)
        detected_wafs.extend(active_results)

    except Exception as e:
        emit.error(f"    [!] Error during analysis: {e}")

    detected_wafs = list(set(detected_wafs))
    detected_tech = list(set(detected_tech))

    if detected_wafs:
        emit.warn(f"[!] Protection Detected: {', '.join(detected_wafs)}")
        signals.append("WAF_DETECTED")
        
    if detected_tech:
        emit.success(f"[+] Technologies Identified: {', '.join(detected_tech)}")
        signals.append("TECH_IDENTIFIED")

    return {
        "raw": f"WAF: {', '.join(detected_wafs) if detected_wafs else 'None'} | Tech: {', '.join(detected_tech)}",
        "intel": {
            "waf": detected_wafs,
            "tech_stack": detected_tech,
            "risk_score": 5 if detected_wafs else 0
        },
        "signals": signals
    }