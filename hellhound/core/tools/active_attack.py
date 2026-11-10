"""
hellhound/core/tools/active_attack.py - heavy active-attack shell-out tools.

Split slice 14. sqlmap_scan (automated SQL-injection) and hydra (auth / logic
brute + per-parameter role findings) — both long-running shell-out tools that pull
their plumbing from tool_shared. agent.py re-imports both executors; TOOL_REGISTRY
wiring unchanged.
"""
import os
import re
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from hellhound.core.tool_shared import (
    _find_binary, _run_cmd_with_heartbeat, _bounded_request,
    _with_identity_bearer_header, _target_auth_options)
from hellhound.core.scope import is_in_scope, normalize_host
from hellhound.core.tasks import Target, save_target, sanitize_target_name
from hellhound.core.ai_utils import load_config
from hellhound.core.http_utils import merge_global_context, normalize_headers, normalize_cookies
from hellhound.core.toolcheck import ensure_tool, get_binary_path, is_available, pick_available, install_hint

logger = logging.getLogger("hellhound.agent")


def _execute_sqlmap_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Confirm SQL injection on a SPECIFIC url/parameter using sqlmap, instead
    of hand-crafting payloads one at a time. Deliberately scoped tight:
    by default this only confirms injectability and, if injectable, lists
    database NAMES (--dbs/--current-db/--banner) as the impact proof —
    naming a real database is already "I can extract data," which is
    enough to back a finding without this tool also pulling row-level
    data. --batch keeps sqlmap from blocking on an interactive
    prompt, and risk/level are capped to the tool's own sane defaults
    (not sqlmap's noisiest settings) unless the caller raises them.

    Opt-in `dump_sample_rows` (default off, hard-capped at 5) goes one
    step further: a SMALL sample dump (--dump --limit 0-N), not a full
    extraction. A mass-PII-leak report backed by 4 real rows (names,
    emails, hashes — whatever's actually in the table) is categorically
    stronger evidence than "a database named X exists," and most
    programs pay more for it. Still a proof-of-impact slice, not row-level
    exfiltration — N stays small on purpose. If the caller names a
    table/db (`table`/`db`), the dump targets that one; otherwise sqlmap
    dumps whatever table it lands on by default, which is fine for
    confirming impact but may not be the most interesting table.

    Reuses whatever session this target already has captured (same
    target.state cookies/headers every other request-sending tool reads
    from) so it doesn't need a fresh login replayed into it separately.
    """
    url = (args.get("url") or "").strip()
    if not url:
        return {"error": "No url specified — sqlmap needs one specific endpoint (and, ideally, the parameter) to target, not a whole site."}
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("sqlmap", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {"error": "sqlmap not installed", "message": check["message"], "hint": install_hint("sqlmap")}

    binary = get_binary_path("sqlmap") or "sqlmap"

    # Clamp rather than trust the caller blindly — this tool's whole point
    # is confirmation with low noise, not sqlmap's most aggressive mode.
    level = max(1, min(int(args.get("level", 1) or 1), 3))
    risk = max(1, min(int(args.get("risk", 1) or 1), 2))

    cmd = [binary, "-u", url, "--batch", "--level", str(level), "--risk", str(risk)]

    data = args.get("data") or args.get("body")
    if data:
        cmd += ["--data", str(data)]
    param = args.get("param") or args.get("parameter")
    if param:
        cmd += ["-p", str(param)]

    state = target.state if (target and isinstance(target.state, dict)) else {}
    session_cookie = state.get("session_cookie") or ""
    if not session_cookie and isinstance(state.get("cookies"), dict) and state["cookies"]:
        session_cookie = "; ".join(f"{k}={v}" for k, v in state["cookies"].items())
    if session_cookie:
        cmd += ["--cookie", str(session_cookie)]
    headers = state.get("headers") if isinstance(state.get("headers"), dict) else {}
    # Identity-model extension: previously only cookie-based sessions
    # reached sqlmap — an identity captured/activated via a bearer token
    # (auth_token/forged_token, e.g. a JWT-only API) never got attached,
    # so a sqlmap run against a Bearer-auth endpoint silently ran
    # unauthenticated. Same bearer auto-attach curl/fuzz_hunter/hydra use.
    headers = _with_identity_bearer_header(headers, target)
    for hk, hv in headers.items():
        if hk.lower() == "cookie":
            continue
        cmd += ["-H", f"{hk}: {hv}"]

    # Database NAME enumeration is the default proof-of-impact step; the
    # caller can turn it off for a pure injectability check with nothing
    # further. Table/row-level dumping is intentionally not wired up here.
    if args.get("list_databases", True):
        cmd += ["--dbs"]
    if args.get("current_db"):
        cmd += ["--current-db"]
    if args.get("is_dba"):
        cmd += ["--is-dba"]

    dump_sample = False
    sample_limit = 0
    if args.get("dump_sample_rows"):
        dump_sample = True
        try:
            sample_limit = int(args.get("dump_sample_rows"))
        except (TypeError, ValueError):
            sample_limit = 4
        # Hard cap regardless of what the caller asked for -- this is a
        # proof-of-impact sample, not a row-dump tool. 1 is floored so
        # "dump_sample_rows: true" (no number) still does something.
        sample_limit = max(1, min(sample_limit, 5))
        db_name = args.get("db") or args.get("database")
        table_name = args.get("table")
        if db_name:
            cmd += ["-D", str(db_name)]
        if table_name:
            cmd += ["-T", str(table_name)]
        cmd += ["--dump", "--limit", f"0-{sample_limit - 1}"]

    # CAUGHT IN THE WILD (result.gujaratuniversity.ac.in): sqlmap had
    # already confirmed injectability AND enumerated database names before
    # hitting the wall clock -- especially likely once --dump is added on
    # top of --dbs, since dumping needs real extra time beyond a bare
    # confirm. The old flat 240s applied even to a dump_sample_rows call
    # that structurally needs longer. Let the caller raise it (e.g. for a
    # sample dump), default higher than before, capped so this tool stays
    # "confirm + light proof," never an hours-long unattended run.
    default_timeout = 360 if dump_sample else 240
    try:
        timeout_s = max(60, min(int(args.get("timeout", default_timeout) or default_timeout), 600))
    except (TypeError, ValueError):
        timeout_s = default_timeout

    timed_out = False
    try:
        proc = _run_cmd_with_heartbeat(cmd, timeout=timeout_s, emit=emit, label=f"sqlmap ({url})")
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        # Salvage whatever sqlmap had already confirmed before the kill
        # (see the matching fix in _run_cmd_with_heartbeat) instead of
        # discarding it and forcing a full, noisy re-run from scratch.
        timed_out = True
        output = (getattr(e, "stdout", None) or getattr(e, "output", None) or "") + "\n" + (getattr(e, "stderr", None) or "")
        if not output.strip():
            return {"url": url, "error": f"sqlmap timed out after {timeout_s}s with no output captured yet — try a narrower level/risk, a specific --param, or pass a higher 'timeout'."}
    except Exception as e:
        return {"url": url, "error": f"sqlmap execution failed: {e}"}

    injectable = bool(re.search(r"is vulnerable|injection point\(s\)|sqlmap identified the following injection point", output, re.I))
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", output)
    databases: List[str] = []
    db_section = re.search(r"available databases \[\d+\]:\s*\n((?:\[\*\].+\n?)+)", output)
    if db_section:
        databases = [line.strip().lstrip("[*]").strip() for line in db_section.group(1).splitlines() if line.strip()]
    current_db_match = re.search(r"current database:\s*'?([^'\n]+)'?", output, re.I)
    is_dba_match = re.search(r"current user is DBA:\s*(True|False)", output, re.I)

    tail_lines = [ln for ln in output.splitlines() if ln.strip()][-40:]

    result = {
        "url": url,
        "command": " ".join(cmd),
        "injectable": injectable,
        "dbms": dbms_match.group(1).strip() if dbms_match else None,
        "databases": databases,
        "current_db": current_db_match.group(1).strip() if current_db_match else None,
        "is_dba": (is_dba_match.group(1).lower() == "true") if is_dba_match else None,
        "raw_tail": "\n".join(tail_lines),
    }
    if timed_out:
        result["timed_out"] = True
        result["note"] = (
            f"sqlmap hit the {timeout_s}s wall clock before finishing, but partial output was captured and "
            f"parsed above (injectable/dbms/databases reflect whatever sqlmap had already confirmed at that "
            f"point, if anything) -- don't assume a blank field means it wasn't found, it may just not have "
            f"gotten there yet. Re-running from scratch isn't usually necessary; if dump_sample_rows was the "
            f"goal and it's not in the result below, re-call with a higher 'timeout' or narrower level/risk "
            f"rather than repeating the same call."
        )

    if dump_sample:
        # sqlmap's dump table render looks like:
        #   Database: wordpress
        #   Table: wp_users
        #   [4 entries]
        #   +----+------------+-------------------------+
        #   | id | user_login | user_email               |
        #   +----+------------+-------------------------+
        #   | 1  | elyana     | elyana@example.com       |
        #   +----+------------+-------------------------+
        dump_table_match = re.search(r"Database:\s*(.+?)\nTable:\s*(.+?)\n\[\d+ entries?\]\n(\+[-+]+\+\n.*?\+[-+]+\+)", output, re.S)
        result["dump_sample_requested"] = sample_limit
        if dump_table_match:
            result["dumped"] = True
            result["dumped_db"] = dump_table_match.group(1).strip()
            result["dumped_table"] = dump_table_match.group(2).strip()
            result["dumped_sample"] = dump_table_match.group(3).strip()
            # Cheap PII signal off the dumped column header row, so the
            # caller doesn't have to re-parse the ASCII table itself to
            # judge whether this is worth reporting as a mass-PII leak.
            header_match = re.search(r"\+[-+]+\+\n\|(.+?)\|\n\+[-+]+\+", dump_table_match.group(3))
            pii_cols = []
            if header_match:
                cols = [c.strip().lower() for c in header_match.group(1).split("|")]
                pii_markers = ("email", "mail", "pass", "hash", "phone", "ssn", "address", "dob", "name", "token", "secret")
                pii_cols = [c for c in cols if any(m in c for m in pii_markers)]
            result["dumped_columns_with_pii_signal"] = pii_cols
        else:
            result["dumped"] = False
            result["dump_note"] = "--dump ran but no table output was parsed from sqlmap's output -- check raw_tail (sqlmap may have needed an interactive choice despite --batch, found an empty table, or the table/db name didn't exist)."

    return result


def _execute_hydra(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Execute Hydra parameter and logic flaw analysis across discovered endpoints."""
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    spider_intel = args.get("spider_intel") or target.state.get("spider_intel", {})
    if not spider_intel and "endpoints" in target.state:
        spider_intel = {"endpoints": [{"url": ep} if isinstance(ep, str) else ep for ep in target.state.get("endpoints", [])]}

    concurrency = args.get("concurrency", 10)
    enable_probing = args.get("enable_probing", False)
    opts = {
        "spider_intel": spider_intel,
        "concurrency": concurrency,
        "enable_probing": enable_probing,
    }
    # Identity-model extension: this analysis used to run fully
    # unauthenticated regardless of whatever session swap_session had
    # active, so a logic-flaw/param-anomaly sweep against an auth-gated
    # endpoint silently tested as an anonymous visitor. Same auth source
    # of truth (target.state cookies/auth_token/headers) every other
    # request-sending tool already reads from.
    opts.update(_target_auth_options(target))
    engine = HellhoundEngine()
    try:
        res = engine.run_single("hydra", url, options=opts, emit=emit)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        surfaces = intel.get("surfaces", [])
        logic_chains = intel.get("logic_chains", [])
        vulns = intel.get("vulnerabilities", [])

        for v in vulns:
            finding = {
                "type": f"Logic Flaw / Param Anomaly ({v.get('parameter', '')})",
                "target": v.get("url", url),
                "severity": "HIGH" if v.get("impact_score", 0) >= 8 else "MEDIUM",
                "details": v.get("impact_path") or v.get("attack_chains", []),
                "verified": False
            }
            if finding not in target.findings:
                target.findings.append(finding)

        # Persist the full per-parameter role/impact map (not just the
        # subset that cleared the bar for a `vulns` finding above) into
        # target.state["param_signals"] — this was computed every call and
        # then entirely discarded (same "computed and thrown away" pattern
        # wafbuster had before its own persistence fix), so
        # generate_hypotheses had no way to see hydra's richer per-
        # parameter signal (admin flags, auth-sensitive params, path
        # references, GraphQL introspectability, OAuth callback sinks) —
        # only bare discovered parameter NAMES. Deduped by (url, parameter)
        # and kept to the single highest-impact finding per pair so
        # repeated hydra runs don't grow this unbounded; capped overall so
        # a huge endpoint set can't bloat target.state indefinitely.
        try:
            if hasattr(target, "state") and isinstance(target.state, dict) and surfaces:
                bucket = target.state.setdefault("param_signals", [])
                if not isinstance(bucket, list):
                    bucket = []
                    target.state["param_signals"] = bucket
                by_key = {(s.get("url"), s.get("parameter")): s for s in bucket if isinstance(s, dict)}
                for s in surfaces:
                    if not isinstance(s, dict) or not s.get("roles"):
                        continue
                    k = (s.get("url"), s.get("parameter"))
                    existing = by_key.get(k)
                    if existing is None or (s.get("impact_score", 0) or 0) > (existing.get("impact_score", 0) or 0):
                        by_key[k] = s
                merged = sorted(by_key.values(), key=lambda s: -(s.get("impact_score", 0) or 0))[:200]
                target.state["param_signals"] = merged
                save_target(target)
        except Exception:
            pass

        return {
            "url": url,
            "raw": res.get("raw", "") if isinstance(res, dict) else str(res),
            "surfaces_analyzed": len(surfaces),
            "logic_chains_found": len(logic_chains),
            "high_impact_vulnerabilities": len(vulns),
            "signals": res.get("signals", []) if isinstance(res, dict) else [],
            "top_findings": surfaces[:10]
        }
    except Exception as e:
        return {"url": url, "error": f"Hydra analysis error: {e}"}
