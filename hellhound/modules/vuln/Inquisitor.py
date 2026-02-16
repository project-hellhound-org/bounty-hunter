import requests
import re
import hashlib

NAME = "param_inquisitor"
CATEGORY = "vuln"
DESCRIPTION = "Logic testing for IDOR and input validation bypasses"

def get_content_hash(content):
    return hashlib.md5(content.encode('utf-8')).hexdigest()

def run(target, emit, options=None):
    emit.info(f"[*] Param Inquisitor: Testing application logic on {target}")
    
    url = target if target.startswith("http") else f"http://{target}"
    
    risks = []
    
    try:
        r = requests.get(url, timeout=8)
        original_hash = get_content_hash(r.text)
        
        # 1. Extract Parameters (GET or Forms)
        params = []
        
        # Check GET params
        if '?' in url:
            query = url.split('?')[1]
            pairs = query.split('&')
            for p in pairs:
                if '=' in p:
                    params.append(p.split('=')[0])
        
        # Check Forms
        import re
        form_inputs = re.findall(r'<input[^>]*name="([^"]+)"', r.text, re.IGNORECASE)
        params.extend(form_inputs)
        
        params = list(set(params)) # Unique
        
        if not params:
            emit.info("    [-] No input parameters found to test.")
            return {"raw": "No inputs", "signals": []}
            
        emit.info(f"    [i] Found {len(params)} parameters to probe: {params}")

        # 2. IDOR Testing (Logic: Change numeric IDs)
        # Look for parameters like 'id', 'user', 'uid', 'file'
        idor_candidates = [p for p in params if re.search(r'id|uid|user|file|doc', p, re.I)]
        
        if idor_candidates:
            emit.info("    [*] Testing IDOR candidates...")
            
            # We need a base URL without query params for modification
            base = url.split('?')[0]
            
            for param in idor_candidates:
                # Test 1: High ID
                test_url = f"{base}?{param}=999999"
                try:
                    r_test = requests.get(test_url, timeout=5)
                    
                    # Logic: If 999999 returns a 200 OK and DIFFERENT content than the original page,
                    # it might be exposing data or error messages it shouldn't.
                    if r_test.status_code == 200:
                        new_hash = get_content_hash(r_test.text)
                        if new_hash != original_hash:
                            risks.append(f"Potential IDOR: Parameter '{param}' accepts arbitrary IDs (999999)")
                            emit.warn(f"    [!] Content changed with ID=999999 on param '{param}'")
                except:
                    pass
                    
                # Test 2: SQL Injection Logic (Simple syntax error check)
                # We send a single quote to break syntax
                test_sqli = f"{base}?{param}=1'"
                try:
                    r_sql = requests.get(test_sqli, timeout=5)
                    if "sql" in r_sql.text.lower() or "syntax error" in r_sql.text.lower():
                        risks.append(f"Potential SQLi Syntax Leak: Parameter '{param}' triggers DB errors")
                        emit.warn(f"    [!] SQL Error detected on param '{param}'")
                except:
                    pass

    except Exception as e:
        emit.error(f"Scan failed: {e}")
        return {"raw": "Error", "signals": []}

    if risks:
        emit.success(f"[+] Logic vulnerabilities identified!")
        return {
            "raw": f"Found {len(risks)} logic flaws.",
            "intel": {"risks": risks},
            "signals": ["LOGIC_VULNERABILITIES"]
        }
    else:
        emit.info("[-] No obvious logic flaws detected.")
        return {"raw": "Clean", "signals": []}