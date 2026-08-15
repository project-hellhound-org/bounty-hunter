"""
hellhound/memory/investigation.py

Structured investigation memory built on top of the existing
hellhound.core.tasks.Target (~/.hellhound/targets/<target>/task.json).

This module does NOT introduce a new storage system. It extends the
existing `target.state` dict with a richer, deduplicated schema and
provides read-side helpers that answer questions ("what did we find so
far?", "what's next?", "what happened recently?") directly from that
structured state instead of re-parsing chat transcripts.

Every function here is defensive: target.state is a plain dict that may
be partially populated (or missing keys entirely) depending on which
tools have run, so every read uses .get() with safe defaults and every
write initializes the key it needs.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Schema ────────────────────────────────────────────────────────────────
# Canonical list of structured-memory keys living inside target.state.
# List-type fields are append-only + deduplicated via merge_state_list().

LIST_FIELDS = [
    "subdomains",
    "live_hosts",
    "open_ports",
    "endpoints",
    "js_routes",
    "parameters",
    "parameter_sensitive",
    "technologies",
    "takeover_candidates",
    "dismissed_false_positives",
    "artifacts",
    "screenshots",
    "timeline",
    "recent_evidence",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entry_key(item: Any) -> Any:
    """Best-effort identity key for dedup of dict/str list entries."""
    if isinstance(item, str):
        return item.strip().lower()
    if isinstance(item, dict):
        for k in ("url", "name", "id", "endpoint", "param", "host", "value"):
            if k in item:
                return (k, str(item[k]).strip().lower())
        return str(sorted(item.items()))
    return item


def merge_state_list(target, key: str, items: List[Any]) -> int:
    """
    Appends `items` into target.state[key], deduplicating by identity key.
    Never overwrites existing entries. Returns the count of newly added items.
    """
    if not items:
        return 0
    if not hasattr(target, "state") or target.state is None:
        return 0
    bucket = target.state.setdefault(key, [])
    if not isinstance(bucket, list):
        bucket = []
        target.state[key] = bucket

    existing_keys = {_entry_key(e) for e in bucket}
    added = 0
    for item in items:
        if item is None or item == "":
            continue
        k = _entry_key(item)
        if k in existing_keys:
            continue
        bucket.append(item)
        existing_keys.add(k)
        added += 1
    return added


def record_timeline(target, event: str, meta: Optional[Dict[str, Any]] = None) -> None:
    """Appends a single timestamped investigation event to target.state['timeline']."""
    if not hasattr(target, "state") or target.state is None:
        return
    timeline = target.state.setdefault("timeline", [])
    if not isinstance(timeline, list):
        timeline = []
        target.state["timeline"] = timeline
    timeline.append({
        "ts": _now_iso(),
        "event": event,
        "meta": meta or {},
    })
    # Keep the timeline bounded so task.json doesn't grow unbounded.
    if len(timeline) > 500:
        target.state["timeline"] = timeline[-500:]


def build_case_delta(target) -> Optional[str]:
    """
    Compares current structured memory against the snapshot taken the last
    time a briefing was generated, and returns a short "since last time"
    delta string (Feature 1 — Case Delta). Returns None if no prior snapshot
    exists (i.e. this is the first briefing for this target).
    """
    st = target.state if hasattr(target, "state") and isinstance(target.state, dict) else {}
    prev = st.get("last_briefing_snapshot")
    if not isinstance(prev, dict):
        return None

    def n(key):
        v = st.get(key, [])
        return len(v) if isinstance(v, list) else 0

    findings_now = len(target.findings) if isinstance(target.findings, list) else 0

    deltas = []
    for key, label in (
        ("subdomains", "subdomains"),
        ("live_hosts", "live hosts"),
        ("endpoints", "endpoints"),
        ("takeover_candidates", "takeover candidates"),
        ("parameter_sensitive", "parameter-sensitive endpoints"),
    ):
        diff = n(key) - int(prev.get(key, 0))
        if diff > 0:
            deltas.append(f"+{diff} {label}")

    findings_diff = findings_now - int(prev.get("findings", 0))
    if findings_diff > 0:
        deltas.append(f"+{findings_diff} new finding(s)")

    dismissed_now = len(st.get("dismissed_false_positives", []))
    resolved = dismissed_now - int(prev.get("dismissed_false_positives", 0))
    if resolved > 0:
        deltas.append(f"{resolved} finding(s) resolved")

    if not deltas:
        return None
    return "Since your last investigation: " + ", ".join(deltas) + "."


def snapshot_briefing_state(target) -> None:
    """
    Records the current structured-memory counts as the baseline for the next
    Case Delta comparison. Call this immediately after a briefing has been
    shown to the user (not on every state mutation) so the delta always
    reflects "since you last looked", not "since the last tool ran".
    """
    if not hasattr(target, "state") or target.state is None:
        return
    st = target.state

    def n(key):
        v = st.get(key, [])
        return len(v) if isinstance(v, list) else 0

    target.state["last_briefing_snapshot"] = {
        "subdomains": n("subdomains"),
        "live_hosts": n("live_hosts"),
        "endpoints": n("endpoints"),
        "takeover_candidates": n("takeover_candidates"),
        "parameter_sensitive": n("parameter_sensitive"),
        "findings": len(target.findings) if isinstance(target.findings, list) else 0,
        "dismissed_false_positives": n("dismissed_false_positives"),
        "ts": _now_iso(),
    }


# ── Evidence Cards (Feature 3) ───────────────────────────────────────────

_SEVERITY_BY_KIND = {
    "takeover_candidate": "high",
    "idor": "high",
    "parameter_sensitive": "medium",
    "graphql_endpoint": "medium",
    "sourcemap": "low",
    "interesting_endpoint": "low",
}


def record_evidence_card(
    target,
    title: str,
    kind: str,
    severity: Optional[str] = None,
    confidence: Optional[float] = None,
    request_ref: str = "",
    response_ref: str = "",
    screenshot_ref: str = "",
) -> None:
    """
    Preserves a structured Evidence Card for a meaningful discovery (takeover
    candidate, IDOR, interesting endpoint, GraphQL discovery, sourcemap,
    parameter-sensitive endpoint, ...). Tool executors call this directly so
    evidence capture happens automatically rather than as a manual step.
    """
    if not hasattr(target, "state") or target.state is None:
        return
    evidence = target.state.setdefault("recent_evidence", [])
    if not isinstance(evidence, list):
        evidence = []
        target.state["recent_evidence"] = evidence
    card = {
        "ts": _now_iso(),
        "title": title,
        "type": kind,
        "severity": severity or _SEVERITY_BY_KIND.get(kind, "low"),
        "confidence": confidence if confidence is not None else 0.5,
        "request_ref": request_ref,
        "response_ref": response_ref,
        "screenshot_ref": screenshot_ref,
    }
    # Dedup on (title, type) so re-running a tool doesn't spam duplicate cards.
    existing_keys = {(e.get("title"), e.get("type")) for e in evidence if isinstance(e, dict)}
    if (title, kind) not in existing_keys:
        evidence.append(card)
        if len(evidence) > 200:
            target.state["recent_evidence"] = evidence[-200:]
    target.state["evidence_count"] = len(target.state.get("recent_evidence", []))


def record_evidence(target, kind: str, ref: str, note: str = "") -> None:
    """
    Preserves a lightweight reference to evidence (screenshot path, request/response
    hash, header dump location, etc.) without embedding large blobs into task.json.
    Kept for simple ad-hoc references; prefer record_evidence_card() for
    discoveries that should render as an Evidence Card in the UI.
    """
    if not hasattr(target, "state") or target.state is None:
        return
    evidence = target.state.setdefault("recent_evidence", [])
    if not isinstance(evidence, list):
        evidence = []
        target.state["recent_evidence"] = evidence
    evidence.append({
        "ts": _now_iso(),
        "kind": kind,       # e.g. "screenshot" | "request" | "response" | "headers" | "body_hash"
        "ref": ref,
        "note": note,
    })
    if len(evidence) > 200:
        target.state["recent_evidence"] = evidence[-200:]
    target.state["evidence_count"] = len(target.state.get("recent_evidence", []))


def dismiss_false_positive(target, item: str, reason: str = "") -> None:
    """Marks a finding/lead as reviewed-and-dismissed so it is never re-suggested."""
    merge_state_list(target, "dismissed_false_positives", [{
        "item": item, "reason": reason, "ts": _now_iso(),
    }])
    record_timeline(target, f"Dismissed as false positive: {item}", {"reason": reason})


# ── Module-specific update helpers ──────────────────────────────────────────
# Thin wrappers so each tool executor calls one function instead of hand-rolling
# merge + timeline logic. All are safe no-ops on empty input.

def update_from_subfinder(target, subdomains: List[str]) -> None:
    added = merge_state_list(target, "subdomains", subdomains)
    if added:
        record_timeline(target, f"Subfinder completed — {added} new subdomain(s) discovered.")


def update_from_httpx(target, live_hosts: List[str], technologies: Optional[List[str]] = None) -> None:
    added_hosts = merge_state_list(target, "live_hosts", live_hosts)
    added_tech = merge_state_list(target, "technologies", technologies or [])
    if added_hosts or added_tech:
        parts = []
        if added_hosts:
            parts.append(f"{added_hosts} live host(s) confirmed")
        if added_tech:
            parts.append(f"{added_tech} technology fingerprint(s) identified")
        record_timeline(target, "HTTPX completed — " + ", ".join(parts) + ".")


def update_from_spider(
    target,
    endpoints: List[Any],
    js_routes: Optional[List[Any]] = None,
    parameters: Optional[List[str]] = None,
    parameter_sensitive: Optional[List[Any]] = None,
) -> None:
    added_ep = merge_state_list(target, "endpoints", endpoints)
    added_js = merge_state_list(target, "js_routes", js_routes or [])
    added_params = merge_state_list(target, "parameters", parameters or [])
    added_sensitive = merge_state_list(target, "parameter_sensitive", parameter_sensitive or [])
    if added_ep or added_js or added_params:
        parts = []
        if added_ep:
            parts.append(f"{added_ep} new endpoint(s)")
        if added_js:
            parts.append(f"{added_js} JS-derived route(s)")
        if added_params:
            parts.append(f"{added_params} parameter(s)")
        record_timeline(target, "Spider mapped " + ", ".join(parts) + ".")
    if added_sensitive:
        record_timeline(target, f"{added_sensitive} parameter-sensitive endpoint(s) flagged for follow-up.")
        for item in (parameter_sensitive or []):
            endpoint = item.get("endpoint") if isinstance(item, dict) else item
            if endpoint:
                record_evidence_card(
                    target,
                    title=f"Parameter-sensitive endpoint: {endpoint}",
                    kind="parameter_sensitive",
                    confidence=0.5,
                    request_ref=str(endpoint),
                )


def update_from_subzy(target, takeover_candidates: List[Any]) -> None:
    added = merge_state_list(target, "takeover_candidates", takeover_candidates)
    if added:
        record_timeline(target, f"Subzy flagged {added} takeover candidate(s).")
        for item in takeover_candidates:
            name = item.get("target") if isinstance(item, dict) else item
            if name:
                record_evidence_card(
                    target,
                    title=f"Takeover candidate: {name}",
                    kind="takeover_candidate",
                    severity="high",
                    confidence=0.7,
                    request_ref=str(name),
                )


def update_from_bac(target, findings: List[Any], parameter_sensitive: Optional[List[Any]] = None) -> None:
    added_sensitive = merge_state_list(target, "parameter_sensitive", parameter_sensitive or [])
    if findings:
        if not isinstance(target.findings, list):
            target.findings = []
        existing = {_entry_key(f) for f in target.findings}
        added_findings = 0
        for f in findings:
            if _entry_key(f) in existing:
                continue
            target.findings.append(f)
            existing.add(_entry_key(f))
            added_findings += 1
            title = f.get("type") if isinstance(f, dict) else str(f)
            asset = f.get("target") if isinstance(f, dict) else ""
            record_evidence_card(
                target,
                title=f"{title}: {asset}".strip(": "),
                kind="idor" if title and "access" in str(title).lower() else "interesting_endpoint",
                severity=str(f.get("severity", "medium")).lower() if isinstance(f, dict) else "medium",
                confidence=0.6,
                request_ref=str(asset),
            )
        if added_findings:
            record_timeline(target, f"Broken access control review surfaced {added_findings} finding(s).")
    if added_sensitive:
        record_timeline(target, f"{added_sensitive} parameter-sensitive endpoint(s) flagged for follow-up.")


# ── Read-side: memory-first answers ─────────────────────────────────────────

def _confidence_score(target) -> Optional[float]:
    score = target.state.get("confidence_score") if hasattr(target, "state") else None
    if isinstance(score, (int, float)):
        return float(score)
    return None


def build_investigation_summary(target) -> str:
    """
    Concise, human-readable snapshot of the whole investigation, built entirely
    from target.state / target.findings. This is the core of the Investigation
    Briefing surfaced when a target is reopened, and the answer given to
    "what did we find so far?" style questions. Never dumps raw logs.
    """
    st = target.state if hasattr(target, "state") and isinstance(target.state, dict) else {}

    def n(key):
        v = st.get(key, [])
        return len(v) if isinstance(v, list) else 0

    lines: List[str] = []
    lines.append(f"The {target.name} investigation remains active." if n("subdomains") or target.findings
                 else f"Opening a fresh case file on {target.name}.")
    lines.append("")
    lines.append("Current intelligence:")

    stat_lines = []
    if n("subdomains"):
        stat_lines.append(f"{n('subdomains')} subdomains mapped")
    if n("live_hosts"):
        stat_lines.append(f"{n('live_hosts')} live hosts confirmed")
    if n("endpoints"):
        stat_lines.append(f"{n('endpoints')} endpoints collected")
    if n("js_routes"):
        stat_lines.append(f"{n('js_routes')} JS-derived routes")
    if n("parameters"):
        stat_lines.append(f"{n('parameters')} parameters discovered")
    if n("technologies"):
        techs = st.get("technologies", [])
        tech_names = ", ".join(str(t) for t in techs[:4])
        stat_lines.append(f"technologies: {tech_names}" + (", ..." if len(techs) > 4 else ""))
    if n("takeover_candidates"):
        stat_lines.append(f"{n('takeover_candidates')} takeover candidate(s) unresolved")

    findings_count = len(target.findings) if isinstance(target.findings, list) else 0
    if findings_count:
        stat_lines.append(f"{findings_count} unresolved finding(s)")

    if not stat_lines:
        lines.append("• No intelligence gathered yet.")
    else:
        for s in stat_lines:
            lines.append(f"• {s}")

    priorities = build_next_actions(target, limit=3)
    if priorities:
        lines.append("")
        lines.append("Highest priority:")
        for p in priorities:
            lines.append(f"- {p}")

    score = _confidence_score(target)
    if score is not None:
        lines.append("")
        lines.append(f"Confidence in current lead set: {score:.0%}")

    return "\n".join(lines)


def _dismissed_label_set(target) -> set:
    """Flat set of lowercase strings representing dismissed leads, for simple substring/equality checks."""
    st = target.state if hasattr(target, "state") and isinstance(target.state, dict) else {}
    labels = set()
    for d in st.get("dismissed_false_positives", []):
        item = d.get("item") if isinstance(d, dict) else d
        if item:
            labels.add(str(item).strip().lower())
    return labels


def _lead_label(item: Any) -> str:
    """Extracts a comparable label from a takeover/parameter-sensitive lead entry."""
    if isinstance(item, dict):
        return str(item.get("endpoint") or item.get("target") or item.get("url") or item).strip().lower()
    return str(item).strip().lower()


def build_next_actions(target, limit: int = 3) -> List[str]:
    """
    Derives concrete, non-duplicate next actions from current memory.
    Never re-suggests dismissed false positives or already-completed work.
    """
    st = target.state if hasattr(target, "state") and isinstance(target.state, dict) else {}
    dismissed = _dismissed_label_set(target)

    actions: List[str] = []

    takeovers = [t for t in st.get("takeover_candidates", []) if _lead_label(t) not in dismissed]
    if takeovers:
        actions.append("Verify remaining takeover candidate(s) with an active CNAME/fingerprint check.")

    sensitive = [p for p in st.get("parameter_sensitive", []) if _lead_label(p) not in dismissed]
    if sensitive:
        label = sensitive[0]
        label = label.get("endpoint") or label.get("url") if isinstance(label, dict) else label
        actions.append(f"Probe the parameter-sensitive endpoint {label}." if label else
                        "Probe the flagged parameter-sensitive endpoints.")

    js_routes = st.get("js_routes", [])
    endpoints = st.get("endpoints", [])
    if js_routes and not sensitive:
        actions.append("Cross-reference JS-derived routes against known endpoints for undocumented API surface.")
    elif endpoints and not js_routes:
        actions.append("Run the JavaScript crawler to extract additional client-side routes.")

    if not st.get("live_hosts") and st.get("subdomains"):
        actions.append("Resolve discovered subdomains to confirm which hosts are live.")

    if not st.get("subdomains"):
        actions.append("Begin passive subdomain enumeration to establish the initial attack surface.")

    findings = target.findings if isinstance(target.findings, list) else []
    unresolved_findings = [f for f in findings if _lead_label(f.get("type") if isinstance(f, dict) else f) not in dismissed]
    if unresolved_findings and len(actions) < limit:
        actions.append("Triage the outstanding finding(s) for true/false-positive verification.")

    if not actions:
        actions.append("Continue reconnaissance — no immediate leads outstanding.")

    return actions[:limit]


def build_recent_activity(target, limit: int = 10) -> List[Dict[str, Any]]:
    """Returns the most recent structured timeline events, newest last (chronological)."""
    st = target.state if hasattr(target, "state") and isinstance(target.state, dict) else {}
    timeline = st.get("timeline", [])
    if not isinstance(timeline, list):
        return []
    return timeline[-limit:]


def answer_from_memory(target, question: Optional[str] = None) -> str:
    """
    Generic memory-first answer used for "what did we find?", "what happened
    yesterday?", "continue", "what's still suspicious?" style questions.
    Reads structured state directly rather than replaying chat transcripts.
    """
    return build_investigation_summary(target)


# ── Investigation Graph (Feature 5 prototype) ───────────────────────────────

def build_investigation_graph(target) -> Dict[str, List[Dict[str, Any]]]:
    """
    Builds a lightweight node/edge graph from structured memory:
    Target -> Subdomain -> Endpoint -> Parameter -> Finding.
    Deliberately capped in size — this is a prototype visualization, not a
    full asset-relationship engine.
    """
    st = target.state if hasattr(target, "state") and isinstance(target.state, dict) else {}
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen = set()

    def add_node(node_id: str, label: str, node_type: str, **extra):
        if node_id in seen:
            return
        seen.add(node_id)
        nodes.append({"id": node_id, "label": label, "type": node_type, **extra})

    def add_edge(src: str, dst: str):
        edges.append({"source": src, "target": dst})

    root_id = f"target:{target.name}"
    add_node(root_id, target.name, "target")

    subdomains = st.get("subdomains", [])[:40]
    for s in subdomains:
        sid = f"sub:{s}"
        add_node(sid, s, "subdomain")
        add_edge(root_id, sid)

    endpoints = st.get("endpoints", [])[:60]
    for ep in endpoints:
        ep_label = ep if isinstance(ep, str) else str(ep)
        eid = f"ep:{ep_label}"
        add_node(eid, ep_label, "endpoint")
        # attach to the subdomain whose hostname appears in the endpoint URL, else root
        parent = root_id
        for s in subdomains:
            if s in ep_label:
                parent = f"sub:{s}"
                break
        add_edge(parent, eid)

    for item in st.get("parameter_sensitive", [])[:40]:
        endpoint = item.get("endpoint") if isinstance(item, dict) else item
        params = item.get("params", []) if isinstance(item, dict) else []
        if not endpoint:
            continue
        eid = f"ep:{endpoint}"
        add_node(eid, str(endpoint), "endpoint")
        for p in params[:5]:
            pid = f"param:{endpoint}:{p}"
            add_node(pid, p, "parameter")
            add_edge(eid, pid)

    techs = st.get("technologies", [])[:15]
    for t in techs:
        tid = f"tech:{t}"
        add_node(tid, str(t), "technology")
        add_edge(root_id, tid)

    findings = target.findings if isinstance(target.findings, list) else []
    for f in findings[:40]:
        title = f.get("type") if isinstance(f, dict) else str(f)
        asset = f.get("target") if isinstance(f, dict) else None
        fid = f"finding:{title}:{asset}"
        add_node(fid, str(title), "finding", severity=(f.get("severity") if isinstance(f, dict) else None))
        parent = f"ep:{asset}" if asset and f"ep:{asset}" in seen else (f"sub:{asset}" if asset and f"sub:{asset}" in seen else root_id)
        add_edge(parent, fid)

    return {"nodes": nodes, "edges": edges}