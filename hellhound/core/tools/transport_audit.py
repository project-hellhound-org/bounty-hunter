"""
hellhound/core/tools/transport_audit.py - TLS/HTTPS/cookie transport-security audit.

Split slice 9 from agent.py. transport_auditor delegates the actual probing to
HellhoundEngine (imported lazily inside the function). Its only agent.py
dependency, _target_auth_options, is reached through the lazy shim below so this
module and agent.py don't form an import cycle. agent.py re-imports the executor;
TOOL_REGISTRY wiring is unchanged.
"""
from typing import Any, Dict

from hellhound.core.tasks import Target


def _target_auth_options(target):
    """Lazy hop back to agent._target_auth_options (deferred to call time)."""
    from hellhound.core.agent import _target_auth_options as _f
    return _f(target)


def _execute_transport_auditor(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Audit transport security: SSL certs, HTTPS/HSTS, and cookie security flags."""
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    opts = {
        "spider_intel": spider_intel,
        "check_ssl": args.get("check_ssl", True),
        "check_https": args.get("check_https", True),
        "check_cookies": args.get("check_cookies", True),
        "check_payment": args.get("check_payment", True),
    }
    opts.update(_target_auth_options(target))
    engine = HellhoundEngine()
    try:
        res = engine.run_single("transport_auditor", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        findings = intel.get("findings", [])
        risk_score = res.get("risk_score", 0) if isinstance(res, dict) else 0

        for f in findings:
            if f.get("severity", 0) >= 15:
                finding = {
                    "type": f"Transport Security: {f.get('name', 'Issue')}",
                    "target": url,
                    "severity": "HIGH" if f.get("severity", 0) >= 30 else "MEDIUM",
                    "description": f.get("description", ""),
                    "verified": True
                }
                if finding not in target.findings:
                    target.findings.append(finding)

        return {
            "url": url,
            "findings_count": len(findings),
            "findings": findings,
            "risk_score": risk_score,
            "signals": res.get("signals", []) if isinstance(res, dict) else []
        }
    except Exception as e:
        return {"url": url, "error": f"Transport auditor error: {e}"}
