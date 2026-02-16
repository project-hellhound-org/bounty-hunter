import requests

NAME = "waf_buster"
CATEGORY = "evasion"
DESCRIPTION = "Detects WAF presence and generates evasion headers"

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare"],
    "akamai": ["akamai-ghost", "akamaighost"],
    "aws": ["x-amz-cf-id"],
    "fastly": ["fastly"],
    "imperva": ["incapsula"]
}

EVASSION_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36", # Standard
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", # Bot
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15" # Safari
]

def detect_waf(target):
    waf_list = []
    try:
        # Use the User-Agent from your Spider to be consistent, or standard
        headers = {"User-Agent": "HellhoundScanner/1.0"}
        url = target if target.startswith("http") else f"http://{target}"
        r = requests.get(url, headers=headers, timeout=8)
        
        headers_low = {k.lower(): v.lower() for k, v in r.headers.items()}
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                # Check headers
                if any(sig in h for h in headers_low.values()):
                    waf_list.append(waf_name)
                # Check body
                if sig in r.text.lower():
                    waf_list.append(waf_name)
                    
    except Exception:
        pass
        
    return list(set(waf_list))

def run(target, emit, options=None):
    emit.info(f"[*] WAF Buster: Checking for firewalls at {target}")
    
    detected_wafs = detect_waf(target)
    
    if not detected_wafs:
        emit.info("[+] No WAF signatures detected.")
        return {
            "raw": "Clean (No WAF detected)",
            "intel": {"waf": None},
            "signals": ["NO_WAF"]
        }
    
    emit.warn(f"[!] WAF Detected: {', '.join(detected_wafs)}")
    emit.info("[i] Suggested Evasion User-Agents:")
    
    for agent in EVASSION_AGENTS:
        emit.info(f"    - {agent}")
        
    return {
        "raw": f"WAF Found: {', '.join(detected_wafs)}",
        "intel": {
            "waf": detected_wafs,
            "suggested_uas": EVASSION_AGENTS
        },
        "signals": [f"WAF_DETECTED: {detected_wafs[0]}"]
    }