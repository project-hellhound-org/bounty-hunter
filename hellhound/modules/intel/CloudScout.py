#!/usr/bin/env python3
"""
CloudScout - Hellhound Intel Intelligence Module
Identifies cloud infrastructure (S3, Azure, GCP, Firebase) from recon data.
"""

import re
from typing import Dict, List, Any, Optional

# ══════════════════════════════════════════════════════════════════════
# METADATA
# ══════════════════════════════════════════════════════════════════════

NAME        = "cloudscout"
CATEGORY    = "intel"
DESCRIPTION = "Discovers cloud assets (Buckets, Blobs, Functions) in application code"

# ══════════════════════════════════════════════════════════════════════
# OPTIONS
# ══════════════════════════════════════════════════════════════════════

OPTIONS = [
    {"name": "verify_public", "type": bool, "default": False, "help": "Verify if discovered buckets are publicly accessible"},
]

# ══════════════════════════════════════════════════════════════════════
# SIGNATURES
# ══════════════════════════════════════════════════════════════════════

CLOUD_PATTERNS = [
    # --- AWS ---
    (r'([a-z0-9.-]+\.s3\.amazonaws\.com)',                          "AWS_S3_Bucket"),
    (r'([a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com)',               "AWS_S3_Bucket_Regional"),
    (r's3://([a-z0-9.-]+)',                                          "AWS_S3_Uri"),
    (r'([a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com)',        "AWS_API_Gateway"),

    # --- Azure ---
    (r'([a-z0-9]+\.blob\.core\.windows\.net)',                      "Azure_Blob_Storage"),
    (r'([a-z0-9]+\.file\.core\.windows\.net)',                      "Azure_File_Storage"),
    (r'([a-z0-9]+\.queue\.core\.windows\.net)',                     "Azure_Queue_Storage"),
    (r'([a-z0-9]+\.azurewebsites\.net)',                            "Azure_App_Service"),
    (r'([a-z0-9]+\.azure-api\.net)',                                "Azure_API_Management"),

    # --- GCP / Firebase ---
    (r'([a-z0-9-]+\.firebaseio\.com)',                              "Firebase_Database"),
    (r'([a-z0-9-]+\.appspot\.com)',                                 "GCP_App_Engine"),
    (r'storage\.googleapis\.com/([a-z0-9.-]+)',                     "GCP_Storage_Bucket"),
    (r'([a-z0-9-]+\.cloudfunctions\.net)',                          "GCP_Cloud_Function"),
    (r'([a-z0-9-]+\.run\.app)',                                     "GCP_Cloud_Run"),

    # --- Others ---
    (r'([a-z0-9.-]+\.[a-z0-9-]+\.digitaloceanspaces\.com)',         "DigitalOcean_Space"),
    (r'([a-z0-9.-]+\.linodeobjects\.com)',                          "Linode_Object_Storage"),
    (r'([a-z0-9.-]+\.backblazeb2\.com)',                            "Backblaze_B2"),
]

# ══════════════════════════════════════════════════════════════════════
# SCANNER LOGIC
# ══════════════════════════════════════════════════════════════════════

def scan_for_cloud(text: str, source: str) -> List[Dict[str, Any]]:
    findings = []
    _seen = set()

    for pattern, asset_type in CLOUD_PATTERNS:
        for match in re.finditer(pattern, text, re.I):
            val = match.group(1)
            if val in _seen: continue
            _seen.add(val)

            findings.append({
                "type": asset_type,
                "content": val,
                "source": source,
                "provider": asset_type.split('_')[0]
            })

    return findings

# ══════════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════════

def run(target: str, emit: Any, options: Optional[Dict[str, Any]] = None):
    options = options or {}
    spider_intel = options.get("spider_intel", {})
    verify_public = options.get("verify_public", False)

    if not spider_intel:
        emit.warn("No spider intelligence found. Cloud discovery will be limited.")
        all_text = target
    else:
        text_chunks = []
        for ep in spider_intel.get("endpoints", []):
            text_chunks.append(ep.get("url", ""))
            for k, v in ep.get("headers", {}).items():
                text_chunks.append(f"{k}: {v}")
        for c in spider_intel.get("comments", []):
            text_chunks.append(c.get("content", ""))
        for s in spider_intel.get("secrets", []):
            text_chunks.append(s.get("source", ""))
            text_chunks.append(s.get("content", ""))
        all_text = "\n".join(text_chunks)

    emit.info(f"CloudScout: Scanning for cloud assets on {target}")

    findings = scan_for_cloud(all_text, "Hellhound Reconnaissance")

    if not findings:
        emit.info("No explicit cloud assets discovered.")
        return {"intel": {"assets": []}, "risk_score": 0}

    emit.success(f"Discovered {len(findings)} cloud assets.")
    
    # Optional verification placeholder
    if verify_public:
        emit.info("Cloud verification enabled (experimental). Checking for public access...")
        # In a real scenario, we'd do requests.get(asset) or similar
        for f in findings:
            if "S3" in f["type"]:
                f["public"] = "Unknown (Probe required)"

    by_provider = {}
    for f in findings:
        by_provider.setdefault(f["provider"], []).append(f["content"])

    for prov, assets in by_provider.items():
        emit.info(f"    - {prov}: {len(assets)} assets found")
        for a in assets[:5]:
            emit.info(f"        [>] {a}")

    risk_score = len(findings) // 2
    
    return {
        "intel": {
            "assets": findings,
            "providers": list(by_provider.keys()),
            "risk_score": risk_score,
            "signals": ["CLOUD_INFRA_FOUND"] if findings else []
        },
        "risk_score": risk_score
    }
