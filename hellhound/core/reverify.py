"""
hellhound/core/reverify.py — pre-submission re-verification of recorded findings.

The single worst outcome for a bounty hunter is filing a report whose PoC
no longer reproduces — the bug was silently patched between discovery and
submission, or it was a flaky/borderline positive. That burns signal with
the program and can get an account throttled or banned. Discovery and
submission can be hours (or a crash/resume) apart, so "it reproduced when I
found it" is not the same as "it reproduces right now."

This module is the freshness check a careful researcher does right before
hitting submit: for each recorded finding, replay its EXACT captured request
live and decide whether it still behaves the way it did at discovery.

Design (mirrors verify_engine.py's honesty):
  - It issues no network traffic itself. The caller (agent.py's
    `reverify_findings` tool) replays through the normal scope-gated curl
    path and hands this module the live response dict + the stored evidence
    entry; this module is pure assessment.
  - Verdicts are three-state: "reproduces" / "stale" / "uncertain" — never a
    silent pass. "stale" and "uncertain" are the ones a report must surface.
  - When verify_engine has a class verifier whose signal is self-contained in
    the response (a SQL error string, cloud-metadata marker, CORS header
    combo), a live "verified"/"refuted" from it UPGRADES the verdict to a
    strong reproduces/stale. Otherwise the verdict falls back to an honest
    HTTP-status-class comparison (a success-shaped finding that now 401/404/
    5xx's is the clearest, most general "it changed" signal there is).
  - It NEVER edits the finding's recorded severity or deletes it — it only
    attaches a freshness verdict. The researcher (and export_report's
    warning) decide what to do with a stale finding; nothing here files or
    retracts anything on its own.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from hellhound.core import verify_engine


_SESSION_DEAD_LANGUAGE = (
    "session has expired", "session expired", "please log in", "please sign in",
    "not authenticated", "unauthenticated", "you must be logged in",
    "login required", "authentication required", "token has expired",
    "invalid or expired token", "please login to continue",
)

# Kinds whose positive proof is an authenticated/authorized response — a live
# 401/403 on these is ambiguous (dead session vs genuine fix), so we say
# "uncertain, re-auth first" rather than declaring the bug patched.
_AUTH_DEPENDENT_KINDS = {
    "idor", "access_control", "broken_access_control", "bac", "authz_bypass",
    "auth_bypass", "broken_auth", "authentication_bypass", "account_takeover",
    "privilege_escalation", "mass_assignment", "bola", "bfla",
}


def _body_of(resp: Optional[Dict[str, Any]]) -> str:
    if not isinstance(resp, dict):
        return ""
    return str(resp.get("body_preview") or resp.get("body") or "")


def _original_resp_from_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reconstruct a response dict (status_code/headers/body_preview) from a
    stored curl_evidence_log entry's human-readable `raw` block — shaped like
    "$ curl ...\\n\\nHTTP/1.1 <status> <reason>\\n<headers>\\n\\n<body>" — so the
    class verifier can be run against the ORIGINAL response too, not just the
    live one. Lets us detect "the signal that defined this finding is gone"
    for verifiers (like sqli) that return inconclusive, not refuted, on an
    absent signal.
    """
    raw = str(entry.get("raw") or "")
    status = _status_of(entry)
    body = ""
    headers: Dict[str, str] = {}
    if raw:
        parts = raw.split("\n\n")
        for i, p in enumerate(parts):
            if p.lstrip().startswith("HTTP/"):
                body = "\n\n".join(parts[i + 1:]).strip()
                for hl in p.splitlines()[1:]:  # skip the HTTP status line itself
                    if ":" in hl:
                        k, v = hl.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                break
    return {"status_code": status, "body_preview": body, "headers": headers}


def _status_of(resp: Optional[Dict[str, Any]]) -> Optional[int]:
    if not isinstance(resp, dict):
        return None
    for k in ("status_code", "status"):
        v = resp.get(k)
        try:
            if v is not None:
                return int(v)
        except (TypeError, ValueError):
            continue
    return None


def _ok(status: Optional[int]) -> bool:
    return bool(status) and 200 <= int(status) < 400


def find_evidence_entry(target: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Return the newest structured curl_evidence_log entry whose URL matches
    this finding's endpoint (request_ref, stored as finding['target']), or
    None. The structured entry carries the exact request to replay
    (method/url/req_headers/req_cookies/req_json/req_data) plus the status
    the server returned at discovery — unlike _lookup_curl_evidence, which
    only returns the human-readable raw text.
    """
    ref = str(finding.get("target") or "").strip().lower()
    if not ref or not hasattr(target, "state") or not isinstance(target.state, dict):
        return None
    log = target.state.get("curl_evidence_log") or []
    for e in reversed(log):  # newest first
        if not isinstance(e, dict):
            continue
        url = str(e.get("url") or "").lower()
        if url and (ref in url or url in ref):
            return e
    return None


def request_args_from_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Rebuild curl-tool args that replay the entry's exact request."""
    args: Dict[str, Any] = {
        "url": entry.get("url"),
        "method": str(entry.get("method") or "GET").upper(),
        # Replay EXACTLY what was sent — stored headers/cookies, and isolate so
        # the current active session isn't auto-attached on top (which would
        # make a now-dead captured session look alive, or vice versa).
        "headers": dict(entry.get("req_headers") or {}) or None,
        "cookies": dict(entry.get("req_cookies") or {}) or None,
        "isolate": True,
    }
    if entry.get("req_json") is not None:
        args["json"] = entry.get("req_json")
    elif entry.get("req_data") is not None:
        args["body"] = entry.get("req_data")
    return args


def assess(finding: Dict[str, Any], live_resp: Dict[str, Any],
           entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decide whether `finding` still reproduces, given a fresh replay
    (`live_resp`) of its captured request (`entry`). Pure — no network.
    Returns {verdict: reproduces|stale|uncertain, reason, live_status,
    original_status, signal}.
    """
    kind = str(finding.get("kind") or "").strip().lower()
    orig_status = _status_of(entry)
    live_status = _status_of(live_resp)
    live_body_l = _body_of(live_resp).lower()

    def out(verdict: str, reason: str, signal: str = "") -> Dict[str, Any]:
        return {
            "verdict": verdict,
            "reason": reason,
            "live_status": live_status,
            "original_status": orig_status,
            "signal": signal,
        }

    # A live session-death page means we tested with a dead session, not that
    # the bug is gone — for auth-dependent kinds especially, don't call it stale.
    session_looks_dead = (
        (live_status in (401, 403))
        or any(p in live_body_l for p in _SESSION_DEAD_LANGUAGE)
    )

    # Strongest signal: a class verifier whose evidence is self-contained in
    # the response (SQL error string, cloud-metadata marker, CORS header combo)
    # firing (or explicitly not firing) on the LIVE response.
    vargs: Dict[str, Any] = {}
    if entry.get("origin_sent"):
        vargs["origin_sent"] = entry.get("origin_sent")
    try:
        vres = verify_engine.verify(kind, live_resp, None, vargs)
    except Exception:
        vres = None
    if vres is not None:
        if vres.status == "verified":
            return out("reproduces",
                       f"class signal still fires on a live replay: {vres.reason}",
                       signal=str(vres.positive_evidence or ""))
        if vres.status == "refuted":
            return out("stale",
                       f"class signal is GONE on a live replay: {vres.reason} — looks fixed; "
                       f"re-confirm before filing.",
                       signal=str(vres.positive_evidence or ""))

    # The class signal wasn't conclusive on the live response. Some verifiers
    # (sqli error-based, ssrf) return INCONCLUSIVE — not refuted — when their
    # signal is simply absent, so an absent signal alone can't be read as
    # "fixed". But if the ORIGINAL captured response DID carry that signal (it
    # verified at discovery) and the identical replay no longer does, the
    # thing that defined this finding is gone — that's genuinely stale.
    orig_had_signal = False
    orig_vres = None
    if vres is not None and vres.status != "no_verifier_for_class":
        try:
            orig_vres = verify_engine.verify(kind, _original_resp_from_entry(entry), None, vargs)
            orig_had_signal = orig_vres.status == "verified"
        except Exception:
            orig_had_signal = False
    if orig_had_signal:
        if session_looks_dead and kind in _AUTH_DEPENDENT_KINDS:
            return out("uncertain",
                       f"live replay came back HTTP {live_status} / unauthenticated — the {kind} signal is "
                       f"absent, but that may just be a dead replayed session, not a fix. Re-auth and re-run.")
        return out("stale",
                   f"the {kind} signal that proved this at discovery ({orig_vres.reason}) no longer fires "
                   f"on an identical live replay — looks fixed; re-confirm before filing.",
                   signal=str(orig_vres.positive_evidence or ""))

    # No conclusive class signal — fall back to HTTP-status-class comparison.
    if session_looks_dead and kind in _AUTH_DEPENDENT_KINDS:
        return out("uncertain",
                   f"live replay came back HTTP {live_status} / unauthenticated, but this is an "
                   f"auth-dependent finding — that may just mean the replayed session is dead, not "
                   f"that the bug is fixed. Re-auth (swap_session / re-capture) and re-run reverify "
                   f"before trusting this either way.")

    if _ok(orig_status) and not _ok(live_status):
        return out("stale",
                   f"was HTTP {orig_status} at discovery, now HTTP {live_status} on an identical "
                   f"replay — the endpoint no longer returns what the PoC relied on (patched, moved, "
                   f"or access revoked). Do NOT file as-is; re-verify first.")

    if not _ok(orig_status) and _ok(live_status):
        return out("uncertain",
                   f"was HTTP {orig_status} at discovery, now HTTP {live_status} — the response "
                   f"changed shape; re-check that the PoC still demonstrates the bug.")

    if orig_status is not None and live_status is not None and orig_status != live_status:
        return out("uncertain",
                   f"status changed from HTTP {orig_status} to HTTP {live_status} on an identical "
                   f"replay — same success class, but worth a manual look before filing.")

    # Same status class, no verifier signal to lean on either way.
    return out("reproduces",
               f"identical replay still returns HTTP {live_status}, the same as at discovery. "
               f"(This confirms the endpoint still behaves the same; for injection/XSS/IDOR classes "
               f"strengthen with the class marker via verify_finding if you want a full re-exploit.)")


def summarize(results: List[Dict[str, Any]]) -> str:
    """One-line human summary of a sweep's verdicts."""
    if not results:
        return "No findings with a replayable captured request to re-verify."
    counts: Dict[str, int] = {}
    for r in results:
        v = r.get("verdict", "uncertain")
        counts[v] = counts.get(v, 0) + 1
    repro = counts.get("reproduces", 0)
    stale = counts.get("stale", 0)
    unc = counts.get("uncertain", 0)
    lead = f"{repro}/{len(results)} findings still reproduce"
    tail = []
    if stale:
        tail.append(f"{stale} STALE (no longer reproduce — do not file as-is)")
    if unc:
        tail.append(f"{unc} uncertain (needs a manual/re-auth re-check)")
    return lead + (" — " + "; ".join(tail) if tail else " — all clear to file.")
