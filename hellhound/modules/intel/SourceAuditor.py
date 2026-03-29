NAME = "SourceAuditor"
DESCRIPTION = "Automated Static Analysis of Recovered Source Code"
OPTIONS = []

import os
import re
from urllib.parse import urlparse

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
    }
]

class SourceAuditor:
    def __init__(self, emit):
        self.emit = emit
        self.loot = {
            "vulnerabilities": [],
            "files_scanned": 0,
            "risk_score": 0
        }

    def audit_file(self, content, filename):
        file_findings = []
        for sig in SIGNATURES:
            if re.search(sig["pattern"], content, re.IGNORECASE):
                finding = {
                    "id": sig["id"],
                    "name": sig["name"],
                    "description": sig["description"],
                    "severity": sig["severity"],
                    "type": sig["type"],
                    "file": filename
                }
                file_findings.append(finding)
                self.loot["vulnerabilities"].append(finding)
        return file_findings

def run(target, emit, options=None):
    """Entry point for the Hellhound framework"""
    emit.info(f"[*] Source Auditor (Static Intelligence): {target}")
    
    auditor = SourceAuditor(emit)
    host = urlparse(target).netloc.replace(":", "_")
    source_dir = os.path.join(os.getcwd(), "reconstructed_source", host)

    if not os.path.exists(source_dir):
        # Fallback: check if content was passed in options (auto-fed from BlobUnpacker)
        opt = options or {}
        blob_intel = opt.get("blobunpacker_intel", {})
        reconstructed_content = blob_intel.get("reconstructed_content", {})
        
        if not reconstructed_content:
            # Backup: check for direct reconstructed_content if manually passed
            reconstructed_content = opt.get("reconstructed_content", {})

        if reconstructed_content:
            emit.info(f"    [i] Auditing {len(reconstructed_content)} files from memory...")
            for filename, content in reconstructed_content.items():
                auditor.audit_file(content, filename)
                auditor.loot["files_scanned"] += 1
        else:
            emit.warn("    [!] No reconstructed source found. Run 'BlobUnpacker' first.")
            return {"raw": "No source files found for auditing.", "intel": {}, "risk_score": 0}
    else:
        emit.info(f"    [i] Auditing files in {source_dir}...")
        for root, _, files in os.walk(source_dir):
            for file in files:
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, source_dir)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                        auditor.audit_file(content, rel_path)
                        auditor.loot["files_scanned"] += 1
                except:
                    pass

    # Calculate Risk Score
    max_severity = 0
    if auditor.loot["vulnerabilities"]:
        max_severity = max([v["severity"] for v in auditor.loot["vulnerabilities"]])
        # Total score is max severity * 10 (cap at 100)
        risk_score = min(100, max_severity * 10)
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
            "files_scanned": auditor.loot["files_scanned"],
            "risk_score": risk_score
        },
        "risk_score": risk_score
    }
