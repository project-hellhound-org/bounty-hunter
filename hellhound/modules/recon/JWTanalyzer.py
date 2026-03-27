import json
import base64
import re
from urllib.parse import urlparse

NAME = "jwt_analyzer"
CATEGORY = "recon"
DESCRIPTION = "JSON Web Token (JWT) extraction, decoding, and vulnerability analysis"
OPTIONS = [
    {"name": "token", "type": str, "default": "", "help": "Provide a manual JWT string to analyze"}
]

def pad_base64(data):
    data = data.replace('-', '+').replace('_', '/')
    return data + '=' * (-len(data) % 4)

def analyze_jwt(token, source, target_url=None):
    findings = {
        "token": token,
        "source": source,
        "header": {},
        "payload": {},
        "vulnerabilities": list([]),
        "sensitive_claims": list([])
    }
    
    parts = token.split('.')
    if len(parts) != 3:
        return None
        
    try:
        header_json = base64.urlsafe_b64decode(pad_base64(parts[0])).decode('utf-8')
        findings["header"] = json.loads(header_json)
    except Exception:
        return None  # Not a valid JWT header
        
    try:
        payload_json = base64.urlsafe_b64decode(pad_base64(parts[1])).decode('utf-8')
        findings["payload"] = json.loads(payload_json)
    except Exception:
        pass

    # Force types to dict to prevent crashes if JSON is a list or other type
    if not isinstance(findings["header"], dict): findings["header"] = {}
    if not isinstance(findings["payload"], dict): findings["payload"] = {}
    if not isinstance(findings["vulnerabilities"], list): findings["vulnerabilities"] = []
    if not isinstance(findings["sensitive_claims"], list): findings["sensitive_claims"] = []

    # 1. Check for Alg: None
    alg = findings["header"].get("alg", "")
    if alg and isinstance(alg, str) and alg.lower() == "none":
        findings["vulnerabilities"].append("CRITICAL: Algorithm 'none' accepted")
    
    # 2. Check for weak algorithms
    if alg and isinstance(alg, str) and alg.lower() in ["hs256", "hs384", "hs512"]:
        findings["vulnerabilities"].append(f"HIGH: Symmetric Algorithm ({alg.upper()}) - susceptible to brute-force")
    
    # 3. Check for Header Injection (kid)
    kid = findings["header"].get("kid")
    if kid and isinstance(kid, str):
        if "../" in kid or "/" in kid or "\\" in kid:
            findings["vulnerabilities"].append("MEDIUM: Potential 'kid' (Key ID) path traversal injection")
            
    # 4. Check for JKU (JWK Set URL)
    jku = findings["header"].get("jku")
    if jku and isinstance(jku, str):
        findings["vulnerabilities"].append(f"MEDIUM: External JKU defined: {jku} (potential key spoofing)")

    # 5. Check for expiration
    exp = findings["payload"].get("exp")
    if exp:
        import time
        try:
            if float(exp) < time.time():
                findings["vulnerabilities"].append("LOW: Token EXPIRED")
        except (ValueError, TypeError):
            pass
    else:
        findings["vulnerabilities"].append("INFO: Missing 'exp' claim")

    # 6. Check for sensitive PII claims in payload
    sensitive_keys = ["email", "password", "role", "admin", "privilege", "superuser", "username", "uid", "secret", "key", "token", "pwd", "ssn", "phone"]
    for key, val in findings["payload"].items():
        if isinstance(key, str):
            key_low = key.lower()
            if any(sk in key_low for sk in sensitive_keys) or key_low in ["id", "user_id", "sub"]:
                findings["sensitive_claims"].append(f"{key}: {val}")
            
    # 7. Check for Issuer and Audience context
    if target_url:
        target_domain = urlparse(target_url).netloc
        iss = findings["payload"].get("iss")
        aud = findings["payload"].get("aud")
        
        if iss and isinstance(iss, str) and target_domain not in iss:
            findings["vulnerabilities"].append(f"INFO: Token issuer '{iss}' does not match target domain")
        if aud and isinstance(aud, str) and target_domain not in aud:
            findings["vulnerabilities"].append(f"INFO: Token audience '{aud}' does not match target domain")

    return findings

def run(target, emit, options=None):
    emit.info(f"[*] JWT Analyzer: Searching for exposed tokens in {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    secrets = spider_intel.get("secrets", [])
    
    # Try to find tokens from spider intel (or any long eyJ string)
    potential_tokens = set()
    
    for s in secrets:
        content = s.get("content", "")
        # Regex to find JWT-like strings
        matches = re.findall(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", content)
        for m in matches:
            potential_tokens.add((m, s.get("source", "spider_secrets")))
            
    # Also support a direct token passed via options (e.g. set token=eyJ...)
    if options and options.get("token"):
        potential_tokens.add((options.get("token"), "user_provided"))
        
    if not potential_tokens:
        emit.info("[-] No JWTs discovered in spider intel or options.")
        return {
            "raw": "JWTs analyzed: 0",
            "intel": {"jwts": [], "risk_score": 0},
            "signals": []
        }
        
    analyzed_tokens = []
    signals = []
    risk_score = 0
    
    emit.info(f"    [i] Analyzing {len(potential_tokens)} potential JWTs...")
    
    for token, source in potential_tokens:
        result = analyze_jwt(token, source, target_url=target)
        if result:
            analyzed_tokens.append(result)
            emit.success(f"    [+] Valid JWT Found (Source: {source})")
            
            for v in result["vulnerabilities"]:
                emit.warn(f"        [!] Vuln: {v}")
                if "CRITICAL" in v: risk_score += 10
                else: risk_score += 3
                
            for c in result["sensitive_claims"]:
                emit.info(f"        [i] Claim: {c}")
                
    if analyzed_tokens:
        signals.append("JWT_EXPOSED")
    
    return {
        "raw": f"JWTs analyzed: {len(analyzed_tokens)}",
        "intel": {"jwts": analyzed_tokens, "risk_score": risk_score},
        "signals": signals
    }
