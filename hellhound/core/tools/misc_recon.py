"""
hellhound/core/tools/misc_recon.py - independent passive-recon tools.

Split slice 8 from agent.py. Two self-contained, dependency-free recon tools:
dig (DNS interrogation — A/AAAA/CNAME/MX/TXT/NS, CNAME-takeover hints) and
cloudscout (cloud asset discovery — S3/Azure/GCS/Firebase buckets). Neither
touches any agent.py internal. agent.py re-imports both executors; TOOL_REGISTRY
wiring is unchanged.
"""
import json
import re
import subprocess
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from hellhound.core.tasks import Target


def _execute_dig(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    domain = args.get("domain") or target.name
    record_type = args.get("type", "A").upper()
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]

    records = []
    try:
        cmd = ["dig", "+short", record_type, domain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.strip():
                    records.append(line.strip())
    except Exception as e:
        records.append(f"Error running dig: {e}")

    return {
        "domain": domain,
        "type": record_type,
        "records": records
    }


# =========================================================================
# Structured Artifact Store & Extraction Engine (Token / Secret Inventory)
# =========================================================================


def _execute_cloudscout(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Scan application and recon text for cloud infrastructure assets."""
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    verify_public = args.get("verify_public", False)
    opts = {
        "spider_intel": spider_intel,
        "verify_public": verify_public
    }
    engine = HellhoundEngine()
    try:
        res = engine.run_single("cloudscout", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        assets = intel.get("assets", [])
        providers = intel.get("providers", [])
        return {
            "url": url,
            "assets_found": len(assets),
            "providers": providers,
            "assets": assets[:25],
            "risk_score": intel.get("risk_score", 0),
            "signals": intel.get("signals", [])
        }
    except Exception as e:
        return {"url": url, "error": f"CloudScout error: {e}"}
