import ssl
import socket
import re
import datetime
import requests
import urllib.parse
from hellhound.core import http_utils

NAME        = "TransportAuditor"
DESCRIPTION = "Transport & Session Security: SSL cert, HTTPS enforcement, HSTS, cookie flags, payment transit"
CATEGORY    = "recon"

OPTIONS = [
    {"name": "check_ssl",     "type": bool, "default": True,  "help": "Validate SSL/TLS certificate"},
    {"name": "check_cookies", "type": bool, "default": True,  "help": "Audit session cookie security flags"},
    {"name": "check_https",   "type": bool, "default": True,  "help": "Check HTTP→HTTPS redirect and HSTS"},
    {"name": "check_payment", "type": bool, "default": True,  "help": "Verify payment endpoints use strict TLS"},
]

# ══════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════

_PAYMENT_PATH_RE = re.compile(
    r'/(?:checkout|cart|order|pay|payment|billing|card|wallet|purchase|'
    r'stripe|paypal|braintree|bank|invoice|subscription|renew)',
    re.I
)

_SENSITIVE_COOKIE_NAMES = re.compile(
    r'(?:session|auth|token|jwt|sid|login|access|refresh|csrf|xsrf)',
    re.I
)

_WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
}

# ══════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE CHECKER
# ══════════════════════════════════════════════════════════════════════

def check_ssl_certificate(host: str, port: int = 443) -> dict:
    result = {
        "host": host, "port": port,
        "valid": False, "expired": False,
        "days_to_expiry": None, "subject": {},
        "issuer": {}, "version": None,
        "weak_cipher": False, "cipher": None,
        "protocol": None, "findings": []
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()  # (name, protocol, bits)

        result["valid"]    = True
        result["cipher"]   = cipher[0] if cipher else None
        result["protocol"] = cipher[1] if cipher else None
        result["version"]  = cert.get("version")

        # Expiry
        na  = cert.get("notAfter", "")
        if na:
            exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            delta = (exp - now).days
            result["days_to_expiry"] = delta
            if delta < 0:
                result["expired"] = True
                result["findings"].append({"id": "TA-001", "severity": 9,
                    "name": "SSL Certificate Expired",
                    "description": f"Certificate expired {abs(delta)} days ago."})
            elif delta < 30:
                result["findings"].append({"id": "TA-002", "severity": 6,
                    "name": "SSL Certificate Expiring Soon",
                    "description": f"Certificate expires in {delta} days."})

        # Subject / issuer
        for item in cert.get("subject", ()):
            result["subject"][item[0][0]] = item[0][1]
        for item in cert.get("issuer", ()):
            result["issuer"][item[0][0]] = item[0][1]

        # Weak cipher
        cname = (cipher[0] or "") if cipher else ""
        if any(w.lower() in cname.lower() for w in _WEAK_CIPHERS):
            result["weak_cipher"] = True
            result["findings"].append({"id": "TA-003", "severity": 7,
                "name": "Weak Cipher Suite",
                "description": f"Weak cipher in use: {cname}"})

        # Protocol version
        proto = (cipher[1] or "") if cipher else ""
        if any(old in proto for old in ("SSLv2", "SSLv3", "TLSv1 ", "TLSv1.1")):
            result["findings"].append({"id": "TA-004", "severity": 8,
                "name": "Deprecated TLS Protocol",
                "description": f"Deprecated protocol in use: {proto}"})

    except ssl.SSLCertVerificationError as e:
        result["findings"].append({"id": "TA-005", "severity": 8,
            "name": "SSL Certificate Verification Failure",
            "description": str(e)})
    except ssl.CertificateError as e:
        result["findings"].append({"id": "TA-006", "severity": 7,
            "name": "SSL Certificate Hostname Mismatch",
            "description": str(e)})
    except ConnectionRefusedError:
        result["findings"].append({"id": "TA-007", "severity": 5,
            "name": "Port 443 Refused",
            "description": f"{host}:443 is not accepting connections."})
    except Exception as e:
        result["findings"].append({"id": "TA-000", "severity": 2,
            "name": "SSL Check Failed",
            "description": str(e)})
    return result


# ══════════════════════════════════════════════════════════════════════
# HTTPS ENFORCEMENT + HSTS CHECKER
# ══════════════════════════════════════════════════════════════════════

def check_https_enforcement(base_url: str, session) -> list:
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    host   = parsed.netloc

    # 1. Does HTTP redirect to HTTPS?
    http_url = f"http://{host}/"
    try:
        r = session.get(http_url, allow_redirects=False, timeout=6)
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
            pass  # good: HTTP redirects to HTTPS
        elif r.status_code == 200:
            findings.append({"id": "TA-010", "severity": 7,
                "name": "Unencrypted HTTP Traffic",
                "description": "Site serves content over plain HTTP without redirecting to HTTPS."})
    except Exception:
        pass  # Port 80 not open — likely HTTPS-only

    # 2. HSTS header on HTTPS response
    if base_url.startswith("https://"):
        try:
            r = session.get(base_url, timeout=6)
            hsts = r.headers.get("Strict-Transport-Security", "")
            if not hsts:
                findings.append({"id": "TA-011", "severity": 6,
                    "name": "Missing HSTS Header",
                    "description": "Strict-Transport-Security header not present. Users can be downgraded to HTTP."})
            else:
                # Check max-age
                ma_match = re.search(r'max-age\s*=\s*(\d+)', hsts, re.I)
                if ma_match and int(ma_match.group(1)) < 31536000:
                    findings.append({"id": "TA-012", "severity": 3,
                        "name": "Weak HSTS max-age",
                        "description": f"HSTS max-age is {ma_match.group(1)} sec (recommended >= 31536000)."})
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════
# SESSION COOKIE AUDITOR
# ══════════════════════════════════════════════════════════════════════

def check_cookies(session, base_url: str, endpoints: list) -> list:
    findings = []
    seen_cookies = set()

    urls_to_probe = [base_url] + [ep.get("url", "") for ep in endpoints[:30] if ep.get("auth_required")]

    for url in urls_to_probe:
        if not url:
            continue
        try:
            r = session.get(url, timeout=5)
        except Exception:
            continue

        for cookie in r.cookies:
            key = f"{cookie.name}@{urllib.parse.urlparse(url).netloc}"
            if key in seen_cookies:
                continue
            seen_cookies.add(key)

            is_sensitive = bool(_SENSITIVE_COOKIE_NAMES.search(cookie.name))
            severity_base = 6 if is_sensitive else 3

            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "_rest", {}).get("HttpOnly"):
                findings.append({"id": "TA-020", "severity": severity_base,
                    "name": f"Cookie Missing HttpOnly: {cookie.name}",
                    "description": f"Cookie '{cookie.name}' on {url} is missing HttpOnly flag. "
                                   f"Accessible via JavaScript — XSS can steal session."})

            if not cookie.secure:
                findings.append({"id": "TA-021", "severity": severity_base + 1,
                    "name": f"Cookie Missing Secure Flag: {cookie.name}",
                    "description": f"Cookie '{cookie.name}' on {url} is missing the Secure flag. "
                                   f"Can be transmitted over HTTP."})

            samesite = getattr(cookie, "_rest", {}).get("SameSite", "").lower()
            if not samesite or samesite == "none":
                findings.append({"id": "TA-022", "severity": severity_base,
                    "name": f"Cookie Missing SameSite: {cookie.name}",
                    "description": f"Cookie '{cookie.name}' has no SameSite attribute (or SameSite=None). "
                                   f"Exposed to CSRF attacks."})

    return findings


# ══════════════════════════════════════════════════════════════════════
# PAYMENT ENDPOINT TLS VALIDATOR
# ══════════════════════════════════════════════════════════════════════

def check_payment_transit(endpoints: list) -> list:
    findings = []
    for ep in endpoints:
        url = ep.get("url", "")
        if not url or not _PAYMENT_PATH_RE.search(url):
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            findings.append({"id": "TA-030", "severity": 9,
                "name": "Payment Endpoint Over HTTP",
                "description": f"Payment-related endpoint '{url}' is served over unencrypted HTTP. "
                               f"PCI-DSS violation."})
    return findings


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def run(target, emit, options=None):
    options  = options or {}
    emit.info(f"[*] Transport Auditor: {target}")

    session = requests.Session()
    session.verify = False
    http_utils.apply_session_config(session, options)

    parsed   = urllib.parse.urlparse(target if target.startswith("http") else f"https://{target}")
    host     = parsed.hostname or parsed.netloc.split(":")[0]
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    spider_intel = options.get("spider_intel", {})
    endpoints    = spider_intel.get("endpoints", [])

    all_findings = []
    risk_score   = 0

    # ── 1. SSL Certificate ──────────────────────────────────────────
    if options.get("check_ssl", True) and parsed.scheme == "https":
        emit.info("    [SSL] Checking certificate...")
        ssl_result = check_ssl_certificate(host, port)
        for f in ssl_result["findings"]:
            all_findings.append(f)
            risk_score += f["severity"]
            emit.warn(f"    [!] {f['name']} — {f['description'][:80]}")
        if not ssl_result["findings"]:
            cn = ssl_result["subject"].get("commonName", host)
            days = ssl_result.get("days_to_expiry")
            emit.info(f"    [✔] Certificate valid — CN={cn}, expires in {days}d, cipher={ssl_result.get('cipher')}")

    # ── 2. HTTPS enforcement + HSTS ─────────────────────────────────
    if options.get("check_https", True):
        emit.info("    [HTTPS] Checking enforcement & HSTS...")
        https_findings = check_https_enforcement(base_url, session)
        for f in https_findings:
            all_findings.append(f)
            risk_score += f["severity"]
            emit.warn(f"    [!] {f['name']} — {f['description'][:80]}")
        if not https_findings:
            emit.info("    [✔] HTTPS properly enforced with valid HSTS")

    # ── 3. Session Cookie Flags ──────────────────────────────────────
    if options.get("check_cookies", True):
        emit.info("    [Cookies] Auditing session cookie flags...")
        cookie_findings = check_cookies(session, base_url, endpoints)
        for f in cookie_findings:
            all_findings.append(f)
            risk_score += f["severity"]
            emit.warn(f"    [!] {f['name']}")
        if not cookie_findings:
            emit.info("    [✔] All observed cookies have proper security flags")

    # ── 4. Payment Transit ───────────────────────────────────────────
    if options.get("check_payment", True) and endpoints:
        emit.info("    [Payment] Checking payment endpoint transport security...")
        pay_findings = check_payment_transit(endpoints)
        for f in pay_findings:
            all_findings.append(f)
            risk_score += f["severity"]
            emit.warn(f"    [!] {f['name']} — {f['description'][:80]}")
        if not pay_findings:
            emit.info("    [✔] No payment endpoints over plaintext HTTP detected")

    risk_score = min(100, risk_score)
    total = len(all_findings)

    if total:
        emit.success(f"[+] Transport Auditor: {total} findings (risk_score={risk_score})")
    else:
        emit.info("[✔] Transport Auditor: No transport-layer issues detected")

    return {
        "raw": f"Transport findings: {total} | Risk: {risk_score}",
        "intel": {
            "findings": all_findings,
            "risk_score": risk_score,
        },
        "signals": ["TRANSPORT_ISSUES"] if all_findings else [],
        "risk_score": risk_score,
    }
