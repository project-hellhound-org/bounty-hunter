import re
import json
import socket
import requests
import urllib.parse
from hellhound.core import http_utils

NAME        = "SurfaceAuditor"
DESCRIPTION = "Infrastructure surface checks: default configs, CDN, port scan, OS fingerprint, dependency CVE"
CATEGORY    = "recon"

OPTIONS = [
    {"name": "check_defaults",    "type": bool, "default": True,  "help": "Detect default server config/admin pages"},
    {"name": "check_cdn",         "type": bool, "default": True,  "help": "Analyze CDN configuration and origin leaks"},
    {"name": "check_ports",       "type": bool, "default": True,  "help": "Scan common service ports (firewall check)"},
    {"name": "check_os",          "type": bool, "default": True,  "help": "Fingerprint OS and banner from response headers"},
    {"name": "check_dependencies", "type": bool, "default": True, "help": "Parse dependency manifests for outdated packages"},
    {"name": "ports",             "type": str,  "default": None,  "help": "Custom port list (comma-separated) e.g. 21,22,25,3306"},
]

# ══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════

_DEFAULT_PAGE_SIGS = [
    (re.compile(r'Apache2 Ubuntu Default Page|It works!|Apache HTTP Server Test Page', re.I), "Apache Default Page"),
    (re.compile(r'Welcome to nginx', re.I), "Nginx Default Page"),
    (re.compile(r'IIS Windows Server|Welcome to IIS', re.I), "IIS Default Page"),
    (re.compile(r'Tomcat default|Apache Tomcat/[\d\.]+\s+Default', re.I), "Tomcat Default Page"),
    (re.compile(r'phpMyAdmin', re.I), "phpMyAdmin Exposed"),
    (re.compile(r'Adminer — Login', re.I), "Adminer Exposed"),
    (re.compile(r'WordPress › Installation', re.I), "WordPress Not Installed"),
    (re.compile(r'Laravel\s+–\s+The PHP Framework', re.I), "Laravel Debug Page"),
    (re.compile(r'You are seeing this page because DEBUG=True', re.I), "Django Debug Page"),
    (re.compile(r'Rails Welcome', re.I), "Rails Default Page"),
    (re.compile(r'Werkzeug Debugger', re.I), "Werkzeug Interactive Debugger (CRITICAL)"),
    (re.compile(r'Whoa, you found a secret feature', re.I), "Express Debug Page"),
]

_EXPOSURE_SIGNATURES = {
    ".git/config": [r"\[core\]", r"repositoryformatversion"],
    ".env": [r"^\w+=", r"DB_", r"API_", r"SECRET"],
    ".dockerconfigjson": [r'"auths":', r'{\s*"auths"'],
    ".DS_Store": [r"Bud1"],
    "phpinfo.php": [r"PHP Version", r"System"],
    "info.php": [r"PHP Version", r"System"],
    "robots.txt": [r"User-agent:", r"Disallow:"],
    "security.txt": [r"Contact:", r"Encryption:"],
    ".well-known/security.txt": [r"Contact:", r"Encryption:"],
    ".htaccess": [r"RewriteEngine", r"Options"],
}

_DEFAULT_PATHS = [
    "/", "/server-status", "/server-info",
    "/phpmyadmin", "/pma", "/adminer",
    "/wp-admin/install.php",
    "/.well-known/security.txt",
]

_CDN_HEADER_MAP = {
    "CF-Ray":               "Cloudflare",
    "X-Cache":              "Generic CDN Cache",
    "X-Amz-Cf-Id":         "Amazon CloudFront",
    "X-Amz-Cf-Pop":        "Amazon CloudFront",
    "Via":                  "Proxy/CDN",
    "X-Fastly-Request-Id": "Fastly",
    "X-Served-By":         "Fastly",
    "X-Akamai-Transformed": "Akamai",
    "X-CDN":               "Generic CDN",
    "X-Azure-Ref":         "Azure CDN",
    "X-Varnish":           "Varnish Cache",
}

_INTERESTING_PORTS = [
    (21,   "FTP"),
    (22,   "SSH"),
    (23,   "Telnet"),
    (25,   "SMTP"),
    (53,   "DNS"),
    (110,  "POP3"),
    (143,  "IMAP"),
    (445,  "SMB"),
    (1433, "MSSQL"),
    (1521, "Oracle DB"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (27017, "MongoDB"),
    (9200, "Elasticsearch"),
    (9300, "Elasticsearch (transport)"),
]

_OS_BANNER_RE = {
    re.compile(r'Ubuntu|Debian|CentOS|Red Hat|Fedora|Alpine',   re.I): "Linux Distribution Fingerprinted",
    re.compile(r'Win(?:dows)?\s(?:NT|Server|XP|7|8|10|11)',    re.I): "Windows Version Fingerprinted",
    re.compile(r'Darwin',                                        re.I): "macOS/Darwin Detected",
}

# ══════════════════════════════════════════════════════════════════════
# DEFAULT CONFIG DETECTOR
# ══════════════════════════════════════════════════════════════════════

def check_default_pages(base_url: str, session) -> list:
    findings = []
    tested   = set()
    for path in _DEFAULT_PATHS:
        url = base_url.rstrip("/") + path
        if url in tested: continue
        tested.add(url)
        try:
            r = session.get(url, timeout=6, allow_redirects=True)
            if r.status_code == 200:
                for sig, label in _DEFAULT_PAGE_SIGS:
                    if sig.search(r.text):
                        findings.append({"id": "SA-101", "severity": 7 if "CRITICAL" not in label else 10,
                            "name": f"Default Config: {label}",
                            "url": url,
                            "description": f"Default installation page or exposed admin panel detected at {url}."})
                        break
        except Exception:
            pass
    return findings

def check_data_exposure(base_url: str, session) -> list:
    """High-fidelity sensitive file exposure audit."""
    findings = []
    for path, patterns in _EXPOSURE_SIGNATURES.items():
        url = base_url.rstrip("/") + "/" + path
        try:
            r = session.get(url, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                body = r.text
                # Signature Check
                matched = any(re.search(p, body, re.M | re.I) for p in patterns)
                if not matched: continue
                
                # Boilerplate Filter
                if any(x in body.lower()[:500] for x in ["404", "not found", "cannot find"]):
                    continue
                
                severity = 9 if ".git" in path or ".env" in path else 4
                findings.append({
                    "id": "SA-201", "severity": severity,
                    "name": f"Sensitive File Exposed: {path}",
                    "url": url,
                    "description": f"Confirmed {path} leak via signature verification. "
                                   f"Contains sensitive architectural or credential data."
                })
        except Exception:
            pass
    return findings


# ══════════════════════════════════════════════════════════════════════
# CDN CONFIG CHECKER
# ══════════════════════════════════════════════════════════════════════

def check_cdn(base_url: str, session) -> list:
    findings = []
    try:
        r = session.get(base_url, timeout=6)
        hdrs = r.headers

        detected_cdn = []
        for header, cdn_name in _CDN_HEADER_MAP.items():
            if header in hdrs or header.lower() in (k.lower() for k in hdrs):
                detected_cdn.append(cdn_name)

        if detected_cdn:
            # Check Cache-Control on authenticated-looking endpoints
            cc = hdrs.get("Cache-Control", hdrs.get("cache-control", ""))
            if "no-store" not in cc.lower() and "private" not in cc.lower():
                findings.append({"id": "SA-102", "severity": 5,
                    "name": f"CDN Misconfiguration: Permissive Cache-Control",
                    "url": base_url,
                    "description": f"CDN ({', '.join(set(detected_cdn))}) in use but Cache-Control is '{cc}'. "
                                   f"Sensitive responses may be cached by intermediaries."})

        # Check for origin IP leak (CDN bypass via real IP)
        origin_headers = ["X-Real-IP", "X-Forwarded-For", "X-Origin-Server", "X-Backend-Server"]
        for h in origin_headers:
            val = hdrs.get(h, "")
            if val and re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', val):
                findings.append({"id": "SA-103", "severity": 6,
                    "name": f"CDN Origin IP Leak via {h}",
                    "url": base_url,
                    "description": f"Response header {h}: {val} exposes the real origin server IP, "
                                   f"allowing attackers to bypass CDN/WAF protection."})

        # No CDN / WAF protection detected
        if not detected_cdn:
            findings.append({"id": "SA-104", "severity": 2,
                "name": "No CDN/WAF Detected",
                "url": base_url,
                "description": "No CDN or WAF layer detected. The origin server is directly exposed."})

    except Exception:
        pass
    return findings


# ══════════════════════════════════════════════════════════════════════
# PORT SCANNER (Firewall Rule Check)
# ══════════════════════════════════════════════════════════════════════

def check_ports(host: str, custom_ports: str = None) -> list:
    findings = []
    port_list = _INTERESTING_PORTS
    if custom_ports:
        try:
            port_list = [(int(p.strip()), f"Custom:{p.strip()}") for p in custom_ports.split(",") if p.strip()]
        except ValueError:
            pass

    for port, service in port_list:
        try:
            with socket.create_connection((host, port), timeout=1.5) as s:
                # Try to grab a banner
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode(errors="replace").strip()
                except Exception:
                    banner = ""
                findings.append({"id": "SA-110", "severity": 4,
                    "name": f"Open Port: {port}/{service}",
                    "port": port, "service": service,
                    "banner": banner[:100] if banner else "",
                    "description": f"Port {port} ({service}) is openly accessible from the scanner. "
                                   f"Verify firewall rules restrict external access."})
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass  # Port closed or filtered
    return findings


# ══════════════════════════════════════════════════════════════════════
# OS FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════

def check_os_fingerprint(base_url: str, session) -> list:
    findings = []
    try:
        r = session.get(base_url, timeout=6)
        hdrs = r.headers

        # Combine all header values into one string for banner matching
        banner = " ".join(filter(None, [
            hdrs.get("Server", ""),
            hdrs.get("X-Powered-By", ""),
            hdrs.get("Via", ""),
            hdrs.get("X-AspNet-Version", ""),
            hdrs.get("X-Runtime", ""),
        ]))

        for pattern, label in _OS_BANNER_RE.items():
            if pattern.search(banner):
                findings.append({"id": "SA-120", "severity": 4,
                    "name": label,
                    "description": f"OS/runtime fingerprinted from response headers: '{banner.strip()}'."})

        # PHP version disclosure
        php_m = re.search(r'PHP/(\d+\.\d+(?:\.\d+)?)', banner, re.I)
        if php_m:
            ver = php_m.group(1)
            major = int(ver.split(".")[0])
            minor = int(ver.split(".")[1])
            findings.append({"id": "SA-121", "severity": 6 if major < 8 else 3,
                "name": f"PHP Version Disclosed: {ver}",
                "description": f"PHP/{ver} disclosed in response headers. "
                               + ("PHP < 8.x has known unpatched CVEs." if major < 8 else "Consider hiding version info.")})

        # Apache version
        apache_m = re.search(r'Apache/([\d\.]+)', banner, re.I)
        if apache_m:
            ver = apache_m.group(1)
            findings.append({"id": "SA-122", "severity": 5,
                "name": f"Apache Version Disclosed: {ver}",
                "description": f"Apache/{ver} version exposed. Cross-reference with NVD for known CVEs."})

        # OpenSSL version
        ssl_m = re.search(r'OpenSSL/([\d\.]+[a-z]?)', banner, re.I)
        if ssl_m:
            findings.append({"id": "SA-123", "severity": 4,
                "name": f"OpenSSL Version Disclosed: {ssl_m.group(1)}",
                "description": f"OpenSSL version exposed via Server header. Verify against known CVEs."})

    except Exception:
        pass
    return findings


# ══════════════════════════════════════════════════════════════════════
# DEPENDENCY AGE / MANIFEST CHECKER
# ══════════════════════════════════════════════════════════════════════

_MANIFEST_PATHS = [
    "/package.json",
    "/composer.json",
    "/requirements.txt",
    "/Gemfile",
    "/build.gradle",
    "/pom.xml",
]

# Known minimum safe versions for common frontend packages
_KNOWN_VULN_VERSIONS = {
    "lodash":  (4, 17, 21),
    "axios":   (1, 0,  0),
    "jquery":  (3, 7,  0),
    "angular": (17, 0, 0),
    "express": (4, 18, 0),
}

def _parse_semver(vstr):
    """Parse 'X.Y.Z' or '^X.Y.Z' or '~X.Y.Z' into (x, y, z) tuple."""
    cleaned = re.sub(r'[^\d\.]', '', vstr)
    parts   = cleaned.split(".")
    try:
        return tuple(int(p) for p in (parts + [0, 0])[:3])
    except ValueError:
        return (0, 0, 0)

def check_dependencies(base_url: str, session, spider_intel: dict) -> list:
    findings = []

    # Try to access manifest files directly
    for path in _MANIFEST_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = session.get(url, timeout=5)
            if r.status_code != 200: continue
            ct = r.headers.get("content-type", "")
            if "text/html" in ct and "<html" in r.text.lower(): continue  # SPA catch-all

            if path.endswith("package.json"):
                try:
                    manifest = json.loads(r.text)
                    deps = {}
                    deps.update(manifest.get("dependencies", {}))
                    deps.update(manifest.get("devDependencies", {}))
                    for pkg, ver_str in deps.items():
                        pkg_lower = pkg.lower()
                        if pkg_lower in _KNOWN_VULN_VERSIONS:
                            min_safe = _KNOWN_VULN_VERSIONS[pkg_lower]
                            parsed   = _parse_semver(ver_str)
                            if parsed < min_safe:
                                findings.append({"id": "SA-130", "severity": 6,
                                    "name": f"Outdated Dependency: {pkg}@{ver_str}",
                                    "url": url,
                                    "description": f"'{pkg}' version {ver_str} is below known-safe {'.'.join(map(str, min_safe))}. "
                                                   f"Cross-reference NVD for CVEs."})
                except json.JSONDecodeError:
                    pass
            else:
                # For non-JSON manifests just flag exposure
                findings.append({"id": "SA-131", "severity": 3,
                    "name": f"Dependency Manifest Exposed: {path}",
                    "url": url,
                    "description": f"Dependency manifest {path} is publicly accessible. "
                                   f"Reveals technology stack and dependency tree."})
        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def run(target, emit, options=None):
    options  = options or {}
    emit.info(f"[*] Surface Auditor: {target}")

    session = requests.Session()
    session.verify = False
    http_utils.apply_session_config(session, options)

    parsed   = urllib.parse.urlparse(target if target.startswith("http") else f"http://{target}")
    host     = parsed.hostname or parsed.netloc.split(":")[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    spider_intel = options.get("spider_intel", {})
    all_findings = []
    risk_score   = 0

    # ── 1. Default Config Pages ──────────────────────────────────────
    if options.get("check_defaults", True):
        emit.info("    [Defaults] Probing for default/admin pages...")
        df = check_default_pages(base_url, session)
        for f in df:
            all_findings.append(f)
            risk_score += f["severity"]
            emit.warn(f"    [!] {f['name']} at {f['url']}")
        if not df:
            emit.info("    [✔] No default configuration pages detected")

    # ── 1.5 Data Exposure ───────────────────────────────────────────
    emit.info("    [Exposure] Auditing for sensitive file leaks...")
    ex_f = check_data_exposure(base_url, session)
    for f in ex_f:
        all_findings.append(f)
        risk_score += f["severity"]
        emit.warn(f"    [!] {f['name']} at {f['url']}")
    if not ex_f:
        emit.info("    [✔] No sensitive file exposures confirmed")

    # ── 2. CDN Config ───────────────────────────────────────────────
    if options.get("check_cdn", True):
        emit.info("    [CDN] Analyzing CDN/WAF configuration...")
        cdn_f = check_cdn(base_url, session)
        for f in cdn_f:
            all_findings.append(f)
            risk_score += f["severity"]
            if f["severity"] >= 4:
                emit.warn(f"    [!] {f['name']}")
            else:
                emit.info(f"    [i] {f['name']}")
        if not any(f["severity"] >= 4 for f in cdn_f):
            emit.info("    [✔] CDN configuration appears correct")

    # ── 3. Port Scanner / Firewall Check ────────────────────────────
    if options.get("check_ports", True):
        custom_ports = options.get("ports")
        emit.info(f"    [Ports] Scanning {host} for exposed services...")
        port_f = check_ports(host, custom_ports)
        for f in port_f:
            all_findings.append(f)
            risk_score += f["severity"]
            svc  = f["service"]
            port = f["port"]
            bang = " ⚠" if svc in ("Telnet", "FTP", "SMB", "Redis", "MongoDB", "Elasticsearch") else ""
            emit.warn(f"    [!] Port {port}/{svc} OPEN{bang}")
        if not port_f:
            emit.info("    [✔] No unexpected services on common ports")

    # ── 4. OS Fingerprint ────────────────────────────────────────────
    if options.get("check_os", True):
        emit.info("    [OS] Fingerprinting OS/server version from headers...")
        os_f = check_os_fingerprint(base_url, session)
        for f in os_f:
            all_findings.append(f)
            risk_score += f["severity"]
            emit.warn(f"    [!] {f['name']}")
        if not os_f:
            emit.info("    [✔] No version disclosure detected in response headers")

    # ── 5. Dependency/Manifest Check ────────────────────────────────
    if options.get("check_dependencies", True):
        emit.info("    [Deps] Checking for exposed dependency manifests...")
        dep_f = check_dependencies(base_url, session, spider_intel)
        for f in dep_f:
            all_findings.append(f)
            risk_score += f["severity"]
            emit.warn(f"    [!] {f['name']}")
        if not dep_f:
            emit.info("    [✔] No exposed dependency manifests found")

    risk_score = min(100, risk_score)
    total = len(all_findings)

    if total:
        emit.success(f"[+] Surface Auditor: {total} findings (risk_score={risk_score})")
    else:
        emit.info("[✔] Surface Auditor: Infrastructure looks clean")

    return {
        "raw": f"Surface findings: {total} | Risk: {risk_score}",
        "intel": {
            "findings": all_findings,
            "risk_score": risk_score,
        },
        "signals": ["SURFACE_ISSUES"] if all_findings else [],
        "risk_score": risk_score,
    }
