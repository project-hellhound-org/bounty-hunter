import json
import base64
import re
import hmac
import hashlib
from urllib.parse import urlparse

NAME = "jwt_analyzer"
CATEGORY = "recon"
DESCRIPTION = "Advanced JWT analysis with automated brute-forcing and algorithm confusion testing"
OPTIONS = [
    {"name": "token", "default": None, "required": False, "help": "Manual JWT token to analyze"},
    {"name": "cookie", "default": None, "required": False, "help": "Cookie string to extract JWT from (format: key=jwt_val)"}
]

COMMON_SECRETS = [
    "secret", "123456", "password", "key", "jwt", "admin", "12345678", 
    "qwerty", "supersecret", "changeit", "access", "root", "dev", "test"
]

def pad_base64(data):
    data = data.replace('-', '+').replace('_', '/')
    return data + '=' * (-len(data) % 4)

def brute_force_hs256(header_b64, payload_b64, signature_b64):
    """Tries to brute-force HS256 signature with common secrets"""
    msg = f"{header_b64}.{payload_b64}".encode()
    try:
        sig = base64.urlsafe_b64decode(pad_base64(signature_b64))
    except: return None
    
    for secret in COMMON_SECRETS:
        h = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        if h == sig: return secret
    return None

def analyze_jwt(token, source, target_url=None):
    parts = token.split('.')
    if len(parts) != 3: return None
    
    findings = {"token": token, "source": source, "header": {}, "payload": {}, "vulnerabilities": [], "sensitive_claims": []}
    
    try:
        findings["header"] = json.loads(base64.urlsafe_b64decode(pad_base64(parts[0])).decode())
        findings["payload"] = json.loads(base64.urlsafe_b64decode(pad_base64(parts[1])).decode())
    except: return None

    # Ensure they are dicts to prevent attribute errors
    if not isinstance(findings["header"], dict): findings["header"] = {}
    if not isinstance(findings["payload"], dict): findings["payload"] = {}

    alg = findings["header"].get("alg", "").lower()
    
    # 1. Algorithm: None
    if alg == "none":
        findings["vulnerabilities"].append("CRITICAL: Algorithm 'none' accepted")
    
    # 2. HS256 Brute-force
    if alg == "hs256":
        weak_secret = brute_force_hs256(parts[0], parts[1], parts[2])
        if weak_secret:
            findings["vulnerabilities"].append(f"CRITICAL: Weak HS256 secret found: {weak_secret}")
    
    # 3. Algorithm Confusion (Logic only, needs user to provide pubkey if available)
    if alg == "rs256":
        findings["vulnerabilities"].append("INFO: RS256 found. Potential for algorithm confusion if public key is leaked.")

    # 4. Header Injections (kid)
    kid = findings["header"].get("kid")
    if kid and isinstance(kid, str):
        if any(c in kid for c in ["../", "/", "\\", "'", "\"", " "]):
            findings["vulnerabilities"].append(f"MEDIUM: Potential 'kid' injection/traversal: {kid}")

    # 5. Sensitive Claims
    sens = ["email", "role", "admin", "password", "secret", "id", "user"]
    for k, v in findings["payload"].items():
        if any(s in k.lower() for s in sens):
            findings["sensitive_claims"].append(f"{k}: {v}")

    return findings

def run(target, emit, options=None):
    emit.info(f"[*] JWT Analyzer: {target}")
    spider_intel = options.get("spider_intel", {}) if options else {}
    secrets = spider_intel.get("secrets", [])
    
    tokens = set()
    for s in secrets:
        content = s.get("content", "")
        # Standard JWT regex
        matches = re.findall(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", content)
        for m in matches: tokens.add((m, s.get("source", "spider")))
    
    if token_opt := options.get("token") if options else None:
        tokens.add((token_opt, "manual"))
    
    if cookie_opt := options.get("cookie") if options else None:
        # Extract everything that looks like a JWT from the cookie string
        matches = re.findall(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", str(cookie_opt))
        for m in matches: tokens.add((m, "manual_cookie"))

    if not tokens:
        emit.info("[-] No JWTs discovered.")
        return {"raw": "0 JWTs found", "signals": []}

    results = []
    risk = 0
    for t, src in tokens:
        res = analyze_jwt(t, src, target)
        if res:
            results.append(res)
            emit.success(f"    [+] JWT from {src}")
            for v in res["vulnerabilities"]:
                emit.warn(f"        [!] {v}")
                risk += 10 if "CRITICAL" in v else 3
            for c in res["sensitive_claims"]:
                emit.info(f"        [i] Policy: {c}")

    return {"raw": f"Analyzed {len(results)} JWTs", "intel": {"jwts": results, "risk_score": risk}, "signals": ["JWT_EXPOSED"] if results else []}
