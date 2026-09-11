"""
hellhound/memory/lessons.py

Cross-target "lessons learned" memory.

This is deliberately separate from the per-target session digest
(Agent.session_digest, stored in target.state). The digest answers "what
happened on THIS target" and gets wiped when a target is done. This module
answers a different question: "have I seen something like THIS target
before, and what worked or didn't?" — the closest thing to self-learning
that's possible here, since there's no way to fine-tune the underlying
cloud model. Instead, HELLHOUND keeps its own external notes and feeds the
relevant ones back into the prompt when a similar situation comes up again.

Storage: a single flat JSON file at ~/.hellhound/lessons.json, global across
every target. Each entry is a short, structured record — not a transcript —
so this file stays small and the retrieval step (find_relevant_lessons) stays
a cheap local keyword match, never another LLM call.

A "lesson" always has an outcome of "worked" or "failed". Failed lessons are
NOT hard bans — a technique that failed on one target for one reason can
still be worth trying again elsewhere; find_relevant_lessons returns them
labeled clearly so the model can use judgment rather than treat the past as
an absolute rule.
"""

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_LESSONS_PATH = os.path.expanduser("~/.hellhound/lessons.json")
_MAX_LESSONS = 500  # hard ceiling on stored entries — oldest pruned beyond this


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_signature(tech_signature: Any) -> List[str]:
    """Coerces a tech signature into a clean, deduplicated, lowercase list of tags."""
    if not tech_signature:
        return []
    if isinstance(tech_signature, str):
        tech_signature = re.split(r"[,\s]+", tech_signature)
    out = []
    seen = set()
    for t in tech_signature:
        t = str(t).strip().lower()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def load_lessons() -> List[Dict[str, Any]]:
    """Reads the global lessons file. Never raises — returns [] on any read/parse failure."""
    try:
        if not os.path.exists(_LESSONS_PATH):
            return []
        with open(_LESSONS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_lessons(lessons: List[Dict[str, Any]]) -> None:
    """Writes the global lessons file. Best-effort — a write failure here should never break a turn."""
    try:
        os.makedirs(os.path.dirname(_LESSONS_PATH), exist_ok=True)
        with open(_LESSONS_PATH, "w", encoding="utf-8") as f:
            json.dump(lessons, f, indent=2)
    except Exception:
        pass


def _dedup_key(technique: str, outcome: str, tech_signature: List[str]) -> str:
    return f"{technique.strip().lower()}|{outcome}|{','.join(sorted(tech_signature))}"


def add_lesson(
    technique: str,
    outcome: str,
    tech_signature: Optional[List[str]] = None,
    note: str = "",
    target_name: str = "",
) -> None:
    """
    Records one generalizable lesson. Deduplicates against an existing entry
    with the same (technique, outcome, tech_signature) — bumps its
    seen_count and refreshes the timestamp/note instead of growing the file
    every time the same thing is re-confirmed on yet another target.
    """
    technique = (technique or "").strip()
    outcome = (outcome or "").strip().lower()
    if not technique or outcome not in ("worked", "failed"):
        return
    tech_signature = _normalize_signature(tech_signature)

    lessons = load_lessons()
    key = _dedup_key(technique, outcome, tech_signature)
    for entry in lessons:
        if _dedup_key(entry.get("technique", ""), entry.get("outcome", ""), entry.get("tech_signature", [])) == key:
            entry["seen_count"] = int(entry.get("seen_count", 1)) + 1
            entry["last_seen"] = _now_iso()
            if note:
                entry["note"] = note[:400]
            if target_name and target_name not in entry.get("targets", []):
                entry.setdefault("targets", []).append(target_name)
                entry["targets"] = entry["targets"][-10:]  # keep it bounded
            _save_lessons(lessons)
            return

    lessons.append({
        "technique": technique[:200],
        "outcome": outcome,
        "tech_signature": tech_signature,
        "note": note[:400],
        "targets": [target_name] if target_name else [],
        "seen_count": 1,
        "first_seen": _now_iso(),
        "last_seen": _now_iso(),
    })

    # Prune oldest (by last_seen) once over the ceiling — repeatedly-seen
    # lessons (seen_count > 1) are protected from pruning since they're the
    # ones proven to generalize across multiple targets.
    if len(lessons) > _MAX_LESSONS:
        protected = [e for e in lessons if int(e.get("seen_count", 1)) > 1]
        prunable = sorted(
            (e for e in lessons if int(e.get("seen_count", 1)) <= 1),
            key=lambda e: e.get("last_seen", ""),
        )
        keep_count = max(0, _MAX_LESSONS - len(protected))
        lessons = protected + prunable[-keep_count:] if keep_count else protected

    _save_lessons(lessons)


def find_relevant_lessons(tech_signature: Any, limit: int = 6) -> List[Dict[str, Any]]:
    """
    Returns up to `limit` stored lessons whose tech_signature overlaps with
    the current target's, ranked by overlap size then by seen_count (a
    lesson confirmed across several targets outranks a one-off). If the
    current target has no known tech_signature yet, returns the most
    frequently-confirmed lessons across all targets instead (still useful —
    e.g. general WAF/rate-limit behavior) rather than nothing at all.
    """
    tech_signature = set(_normalize_signature(tech_signature))
    lessons = load_lessons()
    if not lessons:
        return []

    if tech_signature:
        scored = []
        for entry in lessons:
            overlap = len(tech_signature & set(entry.get("tech_signature", [])))
            if overlap > 0:
                scored.append((overlap, int(entry.get("seen_count", 1)), entry))
        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        results = [e for _, __, e in scored[:limit]]
        if results:
            return results

    # No signature match (or no signature at all yet) — fall back to the
    # most-confirmed general lessons.
    general = sorted(lessons, key=lambda e: int(e.get("seen_count", 1)), reverse=True)
    return general[:limit]


def format_lessons_block(lessons: List[Dict[str, Any]]) -> str:
    """Renders a list of lesson entries into a compact prompt block. Empty string if none."""
    if not lessons:
        return ""
    lines = [
        "LESSONS FROM PAST TARGETS (external notes, not this target's own "
        "history — may or may not apply here; use judgment. A 'failed' "
        "entry is not a hard ban: if the situation looks meaningfully "
        "different here, it can still be worth trying again. A 'worked' "
        "entry earns a bit more weight the more targets it was confirmed "
        "on.)"
    ]
    for e in lessons:
        tag = ", ".join(e.get("tech_signature", [])) or "general"
        seen = int(e.get("seen_count", 1))
        seen_note = f", confirmed on {seen} target(s)" if seen > 1 else ""
        note = f" — {e['note']}" if e.get("note") else ""
        lines.append(f"- [{e.get('outcome','?').upper()}{seen_note}] ({tag}) {e.get('technique','')}{note}")
    return "\n".join(lines)