"""
hellhound/core/tools/http_bypass.py - the 403/401 access-control bypass battery.

Split slice 3 from agent.py. _execute_403_bypass shells out to the bundled
hellhound/tools/403-bypass.sh and reports which payloads changed the status code
(it confirms nothing itself). No agent.py internals; the only move-sensitive bit
was the script path, which is now anchored to the package root (hellhound.__file__)
instead of a fragile __file__.parent.parent, so it resolves wherever this module
lives. agent.py re-imports the executor so TOOL_REGISTRY wiring is unchanged.
"""
import re
import subprocess
from pathlib import Path
from typing import Any, Dict

import hellhound
from hellhound.core.tasks import Target


_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*m')


def _execute_403_bypass(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Runs the bundled 403-bypass.sh payload battery (header spoofing,
    protocol/port tricks, HTTP method override, URL encoding, and a
    SQLi/WAF-bypass mode) against a URL currently returning 403/401. This
    only reports which payloads got a DIFFERENT status code back — it does
    NOT confirm any of them is a real bypass. A 2xx here can just as
    easily be a generic SPA shell, a redirect-then-200 login page, or a
    custom error page that happens to return 200, as it can be the actual
    protected content. See the 403-bypass skill's False-Positive
    Discipline section: every 2xx candidate this returns MUST be curled
    individually and its actual response body read before it's treated as
    a confirmed bypass or passed to record_finding.
    """
    url = str(args.get("url", "")).strip()
    if not url:
        return {
            "status": "no_url_given",
            "note": "Nah bro, that 403_bypass call had no url — nothing to point the battery at. Pass the exact 403/401-returning URL, then call this again.",
        }
    mode = str(args.get("mode", "exploit")).strip().lower()
    mode_flag_map = {
        "header": "--header", "protocol": "--protocol", "port": "--port",
        "httpmethod": "--HTTPmethod", "encode": "--encode", "sqli": "--SQLi", "exploit": "--exploit",
    }
    flag = mode_flag_map.get(mode)
    if not flag:
        return {
            "status": "unknown_mode",
            "note": f"Nah bro, '{mode}' isn't a real mode for this script — valid ones are {', '.join(mode_flag_map.keys())}. Pick one of those and retry.",
        }

    script_path = Path(hellhound.__file__).resolve().parent / "tools" / "403-bypass.sh"
    if not script_path.exists():
        return {"error": f"403-bypass.sh not found at {script_path}"}

    try:
        cmd = ["bash", str(script_path), "-u", url, flag]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "403-bypass.sh timed out after 120s. The --exploit mode runs every technique against every payload — if the target is slow, try a narrower mode (header, protocol, port, HTTPmethod, encode, sqli) instead of exploit."}
    except Exception as e:
        return {"error": f"403-bypass.sh execution failed: {e}"}

    # The script is written for a human's terminal (ANSI colors, emoji, box
    # art) — it has no JSON/structured output mode. Strip all of that down
    # to plain "<payload label>: Status: <code>, Length: <n>" lines so the
    # results are actually usable here.
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    plain = _ANSI_ESCAPE_RE.sub('', combined)
    for junk in ("💀", "🍺", "👌"):
        plain = plain.replace(junk, "")
    lines = plain.splitlines()

    checks: List[Dict[str, Any]] = []
    for line in lines:
        m = re.match(r'^(.*?):\s*Status:\s*(\d{3}),\s*Length\s*:\s*(\d+)\s*$', line.strip())
        if m:
            label, status_str, length_str = m.groups()
            checks.append({"payload": label.strip(), "status": int(status_str), "length": int(length_str)})

    # The script only prints a reproducible "PAYLOAD :" curl command box
    # underneath a 2xx hit, in the same order the checks ran — pull those
    # out and attach them to the matching candidate so the model has the
    # exact request to re-curl, not just a description.
    repro_cmds: List[str] = []
    for line in lines:
        pm = re.search(r'PAYLOAD\s*:\s*(curl .+?)\s*$', line)
        if pm:
            repro_cmds.append(pm.group(1).strip())

    candidates = [c for c in checks if 200 <= c["status"] < 300]
    for idx, cand in enumerate(candidates):
        if idx < len(repro_cmds):
            cand["curl_repro"] = repro_cmds[idx]

    result: Dict[str, Any] = {
        "url": url,
        "mode": mode,
        "checks_run": len(checks),
        "candidates_2xx": candidates,
    }
    if candidates:
        result["note"] = (
            f"{len(candidates)} payload(s) came back 2xx instead of 403/401 — none of these are confirmed yet. "
            "For EACH candidate: curl it yourself with curl_repro (or the same header on a fresh request), READ the actual response body — "
            "is it the real protected content, or a generic SPA shell / redirect-to-login / custom error page that happens to return 200? — "
            "and run it through the skill's False-Positive Discipline checks (reproduce as a single clean request, retest fresh, compare "
            "against a known-bad control path) before calling record_finding. Do not record a finding off the status code alone."
        )
    else:
        result["note"] = "No payload in this battery came back 2xx — this endpoint held against these techniques. This script doesn't cover the request-smuggling/parser-discrepancy techniques in the skill's advanced section; those still need to be tried manually if this doesn't turn up anything."
    return result



# ==========================================================
# EXTRA RECON TOOLS — passive URL/asset discovery, active
# exposure sweeps, OSINT lookups. Added from the researcher's
# personal script collection; ported to native Python/structured
# JSON instead of shelling out to the original scripts so output
# matches the rest of TOOL_REGISTRY (Nah-bro voice on self-made
# mistakes, real errors as "error", no raw ANSI/banner noise).
# ==========================================================

