import re

NAME = "param_xray"
CATEGORY = "vuln"
DESCRIPTION = "Analyzes endpoints and parameters for injection risks (SQLi, IDOR, XSS)"

# Risky parameter keywords
SUSPICIOUS_PARAMS = {
    "id": "IDOR_POTENTIAL",
    "user_id": "IDOR_POTENTIAL",
    "uid": "IDOR_POTENTIAL",
    "search": "SQLI_POTENTIAL",
    "query": "SQLI_POTENTIAL",
    "name": "XSS_POTENTIAL",
    "redirect": "OPEN_REDIRECT",
    "next": "OPEN_REDIRECT",
    "file": "LFI_POTENTIAL",
    "page": "LFI_POTENTIAL"
}

def run(target, emit, options=None):
    emit.info(f"[*] Param Xray: Analyzing injection points...")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    risks = []

    if not endpoints:
        emit.warn("[!] No endpoints found. Did Spider run?")
        return {"raw": "No data", "signals": ["NO_ENDPOINTS"]}

    for ep in endpoints:
        params = ep.get("params", [])
        url = ep.get("url")
        method = ep.get("method")
        
        for p in params:
            param_name = p.get("name", "").lower()
            
            if param_name in SUSPICIOUS_PARAMS:
                risk_type = SUSPICIOUS_PARAMS[param_name]
                risk_detail = f"{risk_type} on {param_name} in {method} {url}"
                risks.append(risk_detail)
                emit.warn(f"    [!] {risk_detail}")

    # Summarize
    signals = []
    if risks:
        signals.append("HIGH_RISK_PARAMS_DETECTED")
    
    return {
        "raw": f"Analyzed {len(endpoints)} endpoints. Found {len(risks)} risks.",
        "intel": {"risks": risks},
        "signals": signals
    }