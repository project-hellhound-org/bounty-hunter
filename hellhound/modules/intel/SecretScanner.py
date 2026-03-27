#!/usr/bin/env python3
"""
SecretScanner - Hellhound Intel Intelligence Module
Deep analysis of spider intelligence for API keys, PII, and sensitive exposures.
"""

import re
import json
from base64 import b64decode
from typing import Dict, List, Any, Optional

# ══════════════════════════════════════════════════════════════════════
# METADATA
# ══════════════════════════════════════════════════════════════════════

NAME        = "secretscanner"
CATEGORY    = "intel"
DESCRIPTION = "Extracts API keys, tokens, PII, and credentials from recon data"

# ══════════════════════════════════════════════════════════════════════
# OPTIONS
# ══════════════════════════════════════════════════════════════════════

OPTIONS = [
    {"name": "show_low",     "type": bool,  "default": False, "help": "Show low confidence matches (low entropy or weight < 3)"},
    {"name": "min_entropy",  "type": float, "default": 3.5,   "help": "Minimum Shannon entropy for generic secret detection (default: 3.5)"},
]

# ══════════════════════════════════════════════════════════════════════
# SIGNATURES
# ══════════════════════════════════════════════════════════════════════

SIGNATURES = [
    # --- Cloud & Infra ---
    (r'(?i)AIza[0-9A-Za-z\-_]{35}',                                     "Google_API_Key", 10),
    (r'(?i)AKIA[0-9A-Z]{16}',                                            "AWS_Access_Key", 10),
    (r'(?i)secret_key\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',          "AWS_Secret_Key", 8),
    (r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',                  "Slack_Token", 10),
    (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', "Slack_Webhook", 9),
    
    # --- Finance & SaaS ---
    (r'sk_live_[0-9a-zA-Z]{24}',                                        "Stripe_Live_Secret", 10),
    (r'sk_test_[0-9a-zA-Z]{24}',                                        "Stripe_Test_Secret", 5),
    (r'gh[pousr]_[A-Za-z0-9_]{36,}',                                  "GitHub_PAT", 10),
    (r'sq0csp-[0-9A-Za-z\-_]{43}',                                      "Square_Secret", 9),
    (r'EAACEdEose0cBA[0-9A-Za-z]+',                                     "Facebook_Token", 9),
    (r'key-[0-9a-zA-Z]{32}',                                            "Mailgun_API_Key", 8),
    (r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',                    "SendGrid_API_Key", 9),

    # --- PII & Identity ---
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',            "Email_Address", 2),
    (r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',   "Phone_Number", 2),
    (r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b',     "JWT_Token", 4),

    # --- Generic Secrets ---
    (r'(?i)(?:password|passwd|secret|api_?key|token|creds?|private_?key)\s*[:=]\s*["\']([^"\']{6,})["\']', "Hardcoded_Credential", 6),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                      "Private_Key_PEM", 10),
    
    # --- Internal Assets ---
    (r'["\'](/admin/[a-zA-Z0-9_\-/]*)["\']',                            "Internal_Path_Admin", 4),
    (r'["\'](/internal/[a-zA-Z0-9_\-/]*)["\']',                         "Internal_Path_Private", 4),
    (r'(?i)todo\s*:\s*(.{1,100})',                                      "Developer_TODO", 3),
]

# ══════════════════════════════════════════════════════════════════════
# UTILS
# ══════════════════════════════════════════════════════════════════════

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not data: return 0.0
    import math
    probs = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in probs)

# ══════════════════════════════════════════════════════════════════════
# SCANNER LOGIC
# ══════════════════════════════════════════════════════════════════════

def scan_text(text: str, source: str, min_entropy: float = 3.5) -> List[Dict[str, Any]]:
    findings = []
    _seen = set()

    for pattern, stype, weight in SIGNATURES:
        for match in re.finditer(pattern, text):
            val = match.group(1) if match.lastindex else match.group(0)
            val = val.strip().strip('"\'')
            
            if not val or len(val) < 4: continue
            
            # De-duplicate
            key = f"{stype}:{val}"
            if key in _seen: continue
            _seen.add(key)

            # 1. Entropy filter for generic secrets
            if stype == "Hardcoded_Credential":
                entropy = shannon_entropy(val)
                if entropy < min_entropy:
                    continue  # Skip low-entropy generic strings

            findings.append({
                "type": stype,
                "content": val,
                "weight": weight,
                "source": source
            })
            
            # JWT Decoding logic
            if stype == "JWT_Token":
                parts = val.split('.')
                if len(parts) >= 2:
                    try:
                        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        decoded = json.loads(b64decode(payload))
                        findings[-1]["decoded"] = decoded
                    except:
                        pass

    return findings

# ══════════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════════

def run(target: str, emit: Any, options: Optional[Dict[str, Any]] = None):
    options = options or {}
    spider_intel = options.get("spider_intel", {})
    show_low = options.get("show_low", False)
    min_entropy = options.get("min_entropy", 3.5)

    if not spider_intel:
        emit.warn("No spider intelligence found. Run 'spider' first for best results.")
        return None

    emit.info(f"SecretScanner: Analyzing intelligence for {target}")

    all_findings = []
    
    # 1. Scan Comments
    comments = spider_intel.get("comments", [])
    for c in comments:
        f = scan_text(c.get("content", ""), c.get("source", "Spider Comment"), min_entropy)
        all_findings.extend(f)

    # 2. Scan Secrets already found
    existing_secrets = spider_intel.get("secrets", [])
    for s in existing_secrets:
        all_findings.append({
            "type": s.get("type", "Unknown"),
            "content": s.get("content", ""),
            "weight": 5,
            "source": s.get("source", "Spider Finding")
        })

    # 3. Scan Endpoints
    endpoints = spider_intel.get("endpoints", [])
    for ep in endpoints:
        f = scan_text(ep.get("url", ""), "Endpoint URL", min_entropy)
        all_findings.extend(f)
        
        headers = ep.get("headers", {})
        for k, v in headers.items():
            f = scan_text(f"{k}: {v}", f"Endpoint Header: {ep.get('url')}", min_entropy)
            all_findings.extend(f)

    # Filtering & Risk Scoring
    final_findings = []
    total_risk = 0
    _final_seen = set()

    for f in final_findings:
        # This part was missing in the previous partial edit, let's fix it
        pass # Wait, I need to iterate over all_findings

    for f in all_findings:
        key = f"{f['type']}:{f['content']}"
        if key in _final_seen: continue
        _final_seen.add(key)

        if not show_low and f.get("weight", 0) < 3:
            continue
            
        final_findings.append(f)
        total_risk += f.get("weight", 0)

    type_counts = {}
    for f in final_findings:
        type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1

    emit.success(f"Scanning complete. Found {len(final_findings)} interesting items.")
    for stype, count in type_counts.items():
        emit.info(f"    - {stype}: {count}")

    signals = []
    if total_risk > 20: signals.append("CRITICAL_EXPOSURE")
    elif total_risk > 10: signals.append("HIGH_EXPOSURE")
    
    if any(f["type"] == "Google_API_Key" for f in final_findings): signals.append("GOOGLE_CLOUD_LEAK")
    if any(f["type"] == "AWS_Access_Key" for f in final_findings): signals.append("AWS_CREDENTIAL_LEAK")

    return {
        "intel": {
            "secrets": final_findings,
            "summary": type_counts,
            "risk_score": total_risk,
            "signals": signals
        },
        "risk_score": total_risk
    }
