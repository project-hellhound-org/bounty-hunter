import socket
import ssl
import datetime

NAME = "ssl_auditor"
CATEGORY = "recon"
DESCRIPTION = "Deep SSL/TLS configuration analysis (Ciphers, Protocols, Certs)"

def analyze_cert(cert):
    issues = []
    expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    days_left = (expiry_date - datetime.datetime.utcnow()).days
    
    if days_left < 7:
        issues.append(f"CRITICAL: Certificate expires in {days_left} days")
    elif days_left < 30:
        issues.append(f"WARN: Certificate expires in {days_left} days")
        
    return issues

def run(target, emit, options=None):
    emit.info(f"[*] SSL Auditor: Deep crypto analysis of {target}")
    
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    port = 443
    
    findings = []
    
    try:
        context = ssl.create_default_context()
        # We deliberately allow insecure connections to audit them
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # 1. Certificate Analysis
                cert = ssock.getpeercert()
                findings.extend(analyze_cert(cert))
                
                emit.info(f"    [i] Issuer: {cert['issuer']}")
                
                # 2. Protocol Version Analysis
                version = ssock.version()
                if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                    findings.append(f"WEAK: Using obsolete protocol {version}")
                else:
                    emit.info(f"    [i] Protocol: {version} (OK)")
                
                # 3. Cipher Analysis
                cipher = ssock.cipher()
                emit.info(f"    [i] Cipher: {cipher[0]}")
                
                if "anon" in cipher[0].lower() or "null" in cipher[0].lower():
                    findings.append(f"CRITICAL: Using Anonymous/NULL cipher (No Encryption)")
                elif "export" in cipher[0].lower():
                    findings.append(f"WEAK: Using Export-grade cipher")

    except ssl.SSLError as e:
        findings.append(f"SSL Error: {str(e)}")
    except Exception as e:
        return {"raw": f"Connection Failed: {str(e)}", "signals": []}

    if findings:
        emit.error("[!] Crypto Issues Detected:")
        for f in findings:
            emit.error(f"    - {f}")
        return {
            "raw": f"Found {len(findings)} SSL issues.",
            "intel": {"issues": findings},
            "signals": ["WEAK_SSL_CONFIG"]
        }
    else:
        emit.success("[+] SSL Configuration looks strong.")
        return {"raw": "SSL Secure", "intel": {"status": "Secure"}, "signals": []}