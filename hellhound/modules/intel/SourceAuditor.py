NAME = "SourceAuditor"
DESCRIPTION = "Automated Static Analysis of Recovered Source Code"
CATEGORY    = "intel"
OPTIONS = [
    {"name": "use_ai", "type": bool, "default": True, "help": "Use AI (LLM) to verify findings and reduce false positives"},
]

import os
import re
from urllib.parse import urlparse
from hellhound.core import ai_utils

# Vulnerability Signatures
SIGNATURES = [
    {
        "id": "SA-001",
        "name": "Dangerous Sink: eval()",
        "pattern": r'eval\s*\(',
        "description": "Use of eval() can lead to remote code execution (RCE) if input is untrusted.",
        "severity": 9,
        "type": "Code Execution"
    },
    {
        "id": "SA-002",
        "name": "Dangerous Sink: dangerouslySetInnerHTML",
        "pattern": r'dangerouslySetInnerHTML',
        "description": "React property that can lead to Cross-Site Scripting (XSS).",
        "severity": 7,
        "type": "XSS"
    },
    {
        "id": "SA-003",
        "name": "Hardcoded Logic: Admin Check",
        "pattern": r'(?:isAdmin|isOwner|role|permission)\s*[:=]\s*(?:true|\'admin\'|"admin")',
        "description": "Hardcoded administrative roles or permissions found in client-side code.",
        "severity": 8,
        "type": "Logic Bypass"
    },
    {
        "id": "SA-004",
        "name": "Insecure Storage: localStorage",
        "pattern": r'localStorage\.(?:setItem|getItem)',
        "description": "Sensitive tokens should not be stored in localStorage as it is accessible via XSS.",
        "severity": 4,
        "type": "Data Leakage"
    },
    {
        "id": "SA-005",
        "name": "Debug Mode Enabled",
        "pattern": r'(?:debug|isDev|verbose)\s*[:=]\s*true',
        "description": "Debug or development flags active in production code.",
        "severity": 3,
        "type": "Information Disclosure"
    },
    {
        "id": "SA-006",
        "name": "Exposed Internal URL",
        "pattern": r'https?://(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)',
        "description": "References to internal or development environments found in the bundle.",
        "severity": 5,
        "type": "Information Disclosure"
    },
    {
        "id": "SA-007",
        "name": "SQL Injection Pattern",
        "pattern": r'(?:SELECT|INSERT|UPDATE|DELETE).+WHERE.+[\'"]\s*\+',
        "description": "Client-side SQL string concatenation detected. This is a high-risk indicator of SQL Injection.",
        "severity": 9,
        "type": "SQL Injection"
    },
    {
        "id": "SA-008",
        "name": "Hardcoded Credential",
        "pattern": r'(?:PASSWORD|PWD|PASS|SECRET|CREDENTIALS)\s*[:=]\s*[\'"][^\'"]{6,}[\'"]',
        "description": "Brute-force/descriptive variable names assigned to hardcoded strings.",
        "severity": 8,
        "type": "Credential Leak"
    },
    {
        "id": "SA-009",
        "name": "Insecure WebSocket/API",
        "pattern": r'(?:ws|http)://[a-zA-Z0-9\-\.]+(?::\d+)?/(?:api|v1|v2)',
        "description": "Unencrypted communication protocol found for API/WebSocket endpoints.",
        "severity": 6,
        "type": "Insecure Transport"
    },
    {
        "id": "SA-010",
        "name": "Hidden Admin/Debug Route",
        "pattern": r'/(?:admin|debug|internal|test|stage)/[a-zA-Z0-9\-_/]+',
        "description": "Potential hidden administrative or debugging route found in source code.",
        "severity": 5,
        "type": "Information Disclosure"
    },
    {
        "id": "SA-011",
        "name": "Prototype Pollution",
        "pattern": r'__proto__|constructor\[["\']prototype["\']\]|Object\.assign\s*\(|jQuery\.extend\s*\(\s*(?:true|false)\s*,',
        "description": "Unsafe object merging or prototype access detected. Vulnerable to Prototype Pollution which can lead to RCE or Logic Bypass.",
        "severity": 8,
        "type": "Prototype Pollution"
    },
    {
        "id": "SA-012",
        "name": "Insecure postMessage Listener",
        "pattern": r'\.addEventListener\s*\(\s*["\']message["\']|window\.onmessage\s*=',
        "description": "Web Messaging (postMessage) listener without origin validation can lead to XSS or sensitive data theft.",
        "severity": 7,
        "type": "Cross-Window Communication"
    },
    {
        "id": "SA-013",
        "name": "Weak Encryption Algorithm",
        "pattern": r'(?:MD5|SHA1|RC4|DES)\s*\(|crypto\.(?:createHash|createCipheriv?)\s*\(\s*["\'](?:md5|sha1|rc4|des)["\']',
        "description": "Usage of deprecated and weak cryptographic algorithms detected.",
        "severity": 6,
        "type": "Cryptography"
    },
    {
        "id": "SA-014",
        "name": "Client Storage Leak",
        "pattern": r'(?:sessionStorage|indexedDB)\.(?:setItem|open|put|add)',
        "description": "Sensitive data might be stored in insecure client-side storage mechanisms.",
        "severity": 4,
        "type": "Data Leakage"
    },
    {
        "id": "SA-015",
        "name": "Sensitive Logger Leak",
        "pattern": r'console\.(?:log|error|warn|info|debug)\s*\(\s*[^)]*(?:password|token|key|secret|auth|cred)[^)]*\)',
        "description": "Console logging of potentially sensitive variables (tokens, passwords).",
        "severity": 5,
        "type": "Information Disclosure"
    },
    {
        "id": "SA-016",
        "name": "Outdated/Insecure SDK Reference",
        "pattern": r'https?://(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com)/.*?/(?:jquery|angular|react|vue)@[0-2]\.',
        "description": "Reference to an older, potentially vulnerable major version of a frontend framework/SDK via CDN.",
        "severity": 3,
        "type": "Dependency Vulnerability"
    },
    {
        "id": "SA-017",
        "name": "Debug Statement Found",
        "pattern": r'console\.(log|debug|info|warn|error)\(|debugger;',
        "description": "Debug or verbose logging statements left in production code can reveal internal state and logic.",
        "severity": 3,
        "type": "Logic Exposure"
    },
    {
        "id": "SA-018",
        "name": "Third-Party Library Exposure",
        "pattern": r'node_modules/|bower_components/|vendor/',
        "description": "Original third-party library source code is exposed. Useful for targeted CVE research.",
        "severity": 2,
        "type": "Information Disclosure"
    },
    {
        "id": "SA-019",
        "name": "Environment Variable Reference",
        "pattern": r'process\.env\.[A-Z0-9_]+',
        "description": "References to environment variables found. May indicate configuration hooks or internal logic targets.",
        "severity": 4,
        "type": "Configuration Analysis"
    },
    {
        "id": "SA-020",
        "name": "Third-Party Integration: Stripe",
        "pattern": r'Stripe\s*\(\s*["\'](pk_(?:test|live)_[0-9a-zA-Z]{24,})',
        "description": "Stripe payment integration found with public key. Useful for mapping payment transit and business logic.",
        "severity": 4,
        "type": "Third-Party SDK"
    },
    {
        "id": "SA-018",
        "name": "Third-Party Integration: Segment/Mixpanel",
        "pattern": r'(?:analytics\.load|mixpanel\.init)\s*\(\s*["\']([0-9a-zA-Z]{32})',
        "description": "Analytics SDK integration detected. Can be used to track user flows or exfiltrate session data if misconfigured.",
        "severity": 3,
        "type": "Third-Party SDK"
    },
    {
        "id": "SA-019",
        "name": "Third-Party Integration: Sentry DSN",
        "pattern": r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/\d+',
        "description": "Sentry DSN leak. Can reveal internal error logs and stack traces if the DSN has excessive permissions.",
        "severity": 5,
        "type": "Information Disclosure"
    },
    {
        "id": "SA-020",
        "name": "Sensitive Config Object",
        "pattern": r'(?:window|globalConfig|appConfig|env)\.(?:api|url|endpoint|secret|key|auth)\s*=',
        "description": "Application configuration object found with potentially sensitive keys or endpoints.",
        "severity": 6,
        "type": "Configuration Analysis"
    },
    {
        "id": "SA-021",
        "name": "Insecure postMessage Origin",
        "pattern": r'\.addEventListener\s*\(\s*["\']message["\']\s*,\s*(?:\(\s*[a-zA-Z0-9_]+\s*\)|function\s*\(\s*[a-zA-Z0-9_]+\s*\))\s*{\s*(?![^}]*origin\s*==|[^}]*origin\s*===)',
        "description": "postMessage listener without explicit origin validation detected. Vulnerable to XSS or data theft via cross-window messaging.",
        "severity": 8,
        "type": "Cross-Window Communication"
    },
    {
        "id": "SA-022",
        "name": "Cloud Metadata Service Access",
        "pattern": r'169\.254\.169\.254|metadata\.google\.internal|instance-data',
        "description": "Reference to Cloud Metadata services found. Indicates potential SSRF targets or internal environment logic.",
        "severity": 7,
        "type": "SSRF Pivot"
    }
]

class SourceAuditor:
    def __init__(self, emit):
        self.emit = emit
        self.loot = {
            "vulnerabilities": [],
            "files_scanned": 0,
            "risk_score": 0,
            "reconstructed_files": [],
            "third_party_sdks": [],
            "ai_insights": []
        }

    def audit_file(self, content, filename, use_ai=False, ai_key=None, ai_provider="gemini", ai_model="gemini-1.5-flash-latest"):
        file_findings = []
        for sig in SIGNATURES:
            # Use finditer to catch ALL instances in the file (Joe-Style thoroughness)
            for match in re.finditer(sig["pattern"], content, re.IGNORECASE):
                # Extract line number
                line_no = content.count('\n', 0, match.start()) + 1
                
                finding = {
                    "id": sig["id"],
                    "name": sig["name"],
                    "description": sig["description"],
                    "severity": sig["severity"],
                    "type": sig["type"],
                    "file": filename,
                    "line": line_no,
                    "ai_verified": False,
                    "repro_data": {
                        "type": "static_analysis",
                        "file": filename,
                        "line": line_no,
                        "pattern": sig["pattern"],
                        "context": content[max(0, match.start()-40):min(len(content), match.end()+40)].strip()
                    }
                }
                
                # Flag high-severity findings for user-triggered AI analysis
                is_first_of_type = not any(f["id"] == sig["id"] for f in file_findings)
                if sig["severity"] >= 7 and is_first_of_type:
                    finding["needs_ai_verification"] = True
                    if use_ai and ai_key:
                        prompt = (
                            f"Analyze this potential security finding in the source code of '{filename}':\n\n"
                            f"Vulnerability: {sig['name']}\n"
                            f"Context:\n```{content[max(0, match.start()-100):min(len(content), match.end()+100)]}```\n\n"
                            f"Is this a true positive? Answer with a brief verification or explain why it's a false positive."
                        )
                        insight = ai_utils.call_ai(prompt, ai_provider, ai_key, model=ai_model)
                        if insight and not str(insight).startswith("Error"):
                            finding["ai_verified"] = True
                            finding["ai_insight"] = insight
                            self.loot["ai_insights"].append({"file": filename, "finding": sig["name"], "insight": insight})

                file_findings.append(finding)
                self.loot["vulnerabilities"].append(finding)
                
                # Global Tracking for SDKs
                if finding["type"] == "Third-Party SDK":
                    self.loot["third_party_sdks"].append(finding["name"])
        
        
        return file_findings

    def audit_headers(self, headers: dict):
        """Analyze HTTP headers of source map responses for security weaknesses."""
        url = headers.get("_target_url", "Unknown")
        
        # 1. Transport Security
        if url.startswith("http://"):
            self.loot["vulnerabilities"].append({
                "id": "SA-H01",
                "name": "Insecure Transport (HTTP)",
                "description": "Source map served over unencrypted HTTP protocol.",
                "severity": 3,
                "type": "Transport Security",
                "file": url,
                "line": "N/A"
            })

        # 2. CORS Analysis
        cors = headers.get("Access-Control-Allow-Origin")
        if cors == "*":
            self.loot["vulnerabilities"].append({
                "id": "SA-H02",
                "name": "Permissive CORS Policy",
                "description": "Access-Control-Allow-Origin is set to *. Allows anyone to fetch the source map.",
                "severity": 3,
                "type": "Access Control",
                "file": url,
                "line": "N/A"
            })

        # 3. Cache Analysis
        cache = headers.get("Cache-Control", "").lower()
        if "max-age" in cache and any(x in cache for x in ["31536000", "86400"]): # Long cache
            self.loot["vulnerabilities"].append({
                "id": "SA-H03",
                "name": "Long Cache Lifetime",
                "description": "Source maps have long cache persistence, increasing exposure duration.",
                "severity": 2,
                "type": "Information Disclosure",
                "file": url,
                "line": "N/A"
            })

def run(target, emit, options=None):
    """Entry point for the Hellhound framework"""
    emit.info(f"[*] Source Auditor (Static Intelligence): {target}")
    
    auditor = SourceAuditor(emit)
    host = urlparse(target).netloc.replace(":", "_")
    source_dir = os.path.join(os.getcwd(), "reconstructed_source", host)

    # Ensure we use global AI settings from options if provided
    ai_key = options.get("ai_key")
    ai_provider = options.get("ai_provider", "gemini")
    ai_model = options.get("ai_model", "gemini-1.5-flash")

    # Zero-Config AI: Auto-enable if key is present
    use_ai = options.get("use_ai", False)
    if ai_key and not options.get("use_ai_disabled"):
        use_ai = True
        
    if os.path.exists(source_dir):
        emit.info(f"    [i] Auditing files in {source_dir} (AI: {'ENABLED' if use_ai else 'OFF'})...")
        files_to_scan = []
        for root, _, files in os.walk(source_dir):
            for file in files:
                files_to_scan.append(os.path.join(root, file))
        
        emit.progress_update(0, label="SOURCE-AUDIT")
        for i, filepath in enumerate(files_to_scan):
            emit.progress_update(i + 1)
            rel_path = os.path.relpath(filepath, source_dir)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    auditor.audit_file(content, rel_path, use_ai=use_ai, 
                                     ai_key=ai_key, ai_provider=ai_provider,
                                     ai_model=ai_model)
                    auditor.loot["files_scanned"] += 1
            except:
                pass
        else:
            blob_intel = options.get("blobunpacker_intel", {})
            reconstructed_content = blob_intel.get("reconstructed_content", {})
            minified_content = blob_intel.get("minified_content", {}) 
            
            if not reconstructed_content and minified_content:
                emit.info(f"    [i] Auditing {len(minified_content)} minified files from memory (AI: {'ENABLED' if use_ai else 'OFF'})...")
                for url, content in minified_content.items():
                    filename = url.split("/")[-1]
                    auditor.audit_file(content, filename, use_ai=use_ai, 
                                     ai_key=ai_key, ai_provider=ai_provider,
                                     ai_model=ai_model)
                    auditor.loot["files_scanned"] += 1
            elif reconstructed_content:
                auditor.loot["reconstructed_files"] = list(reconstructed_content.keys())
                emit.info(f"    [i] Auditing {len(reconstructed_content)} reconstructed files from memory (AI: {'ENABLED' if use_ai else 'OFF'})...")
                for filename, content in reconstructed_content.items():
                    auditor.audit_file(content, filename, use_ai=use_ai, 
                                     ai_key=ai_key, ai_provider=ai_provider,
                                     ai_model=ai_model)
                    auditor.loot["files_scanned"] += 1
            else:
                emit.warn("    [!] No source found (reconstructed or minified). Run 'BlobUnpacker' first.")
                return {"raw": "No source files found for auditing.", "intel": {}, "risk_score": 0}

    # Cross-Module Fix: Process headers from BlobUnpacker
    blob_intel = options.get("blobunpacker_intel", {})
    map_headers = blob_intel.get("map_headers", {})
    if map_headers:
        emit.info(f"    [i] Analyzing {len(map_headers)} source map transport headers...")
        for url, headers in map_headers.items():
            auditor.audit_headers(headers)

    # Inherent Finding: Source Map Exposure (Risk Clarity Fix)
    if auditor.loot["reconstructed_files"]:
        auditor.loot["vulnerabilities"].append({
            "id": "SA-X01",
            "name": "Source Map Exposure",
            "description": "Publicly accessible source maps detected. Enables full source code reconstruction and internal path disclosure.",
            "severity": 3,
            "type": "Information Disclosure",
            "file": f"{len(auditor.loot['reconstructed_files'])} files recovered",
            "line": "N/A"
        })

    # Extract comments from BlobUnpacker if available (Joe-Style Contextual Mining)
    blob_intel = options.get("blobunpacker_intel", {})
    if blob_intel.get("comments"):
        emit.info(f"    [i] Auditing {len(blob_intel['comments'])} developer comments for logic leaks...")
        for comment in blob_intel["comments"]:
            # Simple keyword audit for comments
            for keyword in ["admin", "todo", "fixme", "internal", "auth", "bypass", "temp"]:
                if keyword in comment["content"].lower():
                    finding = {
                        "id": "SA-C01",
                        "name": f"Sensitive Comment ({keyword})",
                        "description": "Developer comment identifying potential logic flaws or internal secrets.",
                        "severity": 4,
                        "type": "Developer Artifact",
                        "file": comment["source"],
                        "line": "N/A",
                        "context": comment["content"]
                    }
                    auditor.loot["vulnerabilities"].append(finding)

    # Calculate Risk Score
    max_severity = 0
    if auditor.loot["vulnerabilities"]:
        # Risk Score Calibration (Weighted Model Fix)
        # Weights: LOW=10, MEDIUM=30, HIGH/CRITICAL=60
        score = 0
        categories_found = set()
        for v in auditor.loot["vulnerabilities"]:
            sev = v.get("severity", 1)
            if sev >= 8: score += 60
            elif sev >= 5: score += 30
            else: score += 10
            categories_found.add(v.get("type"))
        
        # Cap at 100, baseline for map exposure is already factored via sev=3 finding
        risk_score = min(100, score)
    else:
        risk_score = 0

    auditor.loot["risk_score"] = risk_score
    vuln_count = len(auditor.loot["vulnerabilities"])

    if vuln_count > 0:
        emit.success(f"[+] Identified {vuln_count} potential vulnerabilities in recovered source.")
        for v in auditor.loot["vulnerabilities"][:5]: # Show first 5
            emit.warn(f"    [!] {v['name']} ({v['file']})")
    else:
        emit.info("    [✔] No critical flaws found in source code.")

    return {
        "raw": f"Audited {auditor.loot['files_scanned']} files | Found {vuln_count} vulnerabilities",
        "intel": {
            "vulnerabilities": auditor.loot["vulnerabilities"],
            "reconstructed_files": auditor.loot["reconstructed_files"],
            "files_scanned": auditor.loot["files_scanned"],
            "third_party_sdks": list(set(auditor.loot["third_party_sdks"])),
            "risk_score": risk_score
        },
        "risk_score": risk_score
    }
