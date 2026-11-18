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

Storage: a single flat JSON file at ~/.beast/lessons.json, global across
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

_LESSONS_PATH = os.path.expanduser("~/.beast/lessons.json")
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


_STOP = frozenset({"the", "a", "an", "to", "for", "of", "in", "on", "and", "or", "with",
                   "via", "when", "that", "this", "is", "as", "by", "it", "if", "from",
                   "use", "using", "check", "test", "try"})


def _tokens(technique: str) -> set:
    """Content-word token set for similarity — lowercased alphanumerics, 3+ chars,
    minus generic filler, so 'Check for password reset token leak in response' and
    'Password reset token exposed in the response body' read as near-identical."""
    import re as _re
    return {t for t in _re.findall(r"[a-z0-9]{3,}", (technique or "").lower()) if t not in _STOP}


def _near_dup(a: Dict[str, Any], b: Dict[str, Any], threshold: float = 0.6) -> bool:
    """True if two SAME-OUTCOME lessons are near-duplicates: high content-token
    overlap (Jaccard) AND at least one shared signature tag (or both unsignatured),
    so distinct techniques that merely share a word don't get merged."""
    if a.get("outcome") != b.get("outcome"):
        return False
    sa, sb = set(a.get("tech_signature") or []), set(b.get("tech_signature") or [])
    if (sa or sb) and not (sa & sb):
        return False
    ta, tb = _tokens(a.get("technique", "")), _tokens(b.get("technique", ""))
    if not ta or not tb:
        return False
    jacc = len(ta & tb) / len(ta | tb)
    return jacc >= threshold


def _merge_into(canon: Dict[str, Any], dup: Dict[str, Any]) -> None:
    """Fold a near-duplicate lesson into the canonical one, preserving signal."""
    canon["seen_count"] = int(canon.get("seen_count", 1)) + int(dup.get("seen_count", 1))
    # Keep the longer, more descriptive note and technique wording.
    if len(dup.get("note", "")) > len(canon.get("note", "")):
        canon["note"] = dup.get("note", "")
    if len(dup.get("technique", "")) > len(canon.get("technique", "")):
        canon["technique"] = dup.get("technique", "")
    canon["tech_signature"] = sorted(set(canon.get("tech_signature") or []) | set(dup.get("tech_signature") or []))
    tg = list(dict.fromkeys((canon.get("targets") or []) + (dup.get("targets") or [])))
    canon["targets"] = tg[-10:]
    canon["first_seen"] = min(canon.get("first_seen", ""), dup.get("first_seen", "")) or canon.get("first_seen", "")
    canon["last_seen"] = max(canon.get("last_seen", ""), dup.get("last_seen", "")) or canon.get("last_seen", "")


def consolidate_lessons(lessons: List[Dict[str, Any]], threshold: float = 0.6) -> List[Dict[str, Any]]:
    """Merge NEAR-duplicate lessons (same outcome, overlapping signature, high
    content-token similarity) into one, so the store doesn't bloat with 16 reworded
    copies of 'password reset token leak' that crowd out diverse recall. Greedy
    single pass per outcome bucket — each lesson joins the first canonical it's a
    near-dup of, else becomes a new canonical. Exact dups are already handled at
    write time; this catches the semantic ones. Returns the consolidated list."""
    from collections import defaultdict
    buckets = defaultdict(list)
    for e in lessons:
        buckets[e.get("outcome", "")].append(e)
    out: List[Dict[str, Any]] = []
    for _outcome, group in buckets.items():
        # Process higher seen_count first so the proven lesson becomes the canonical.
        canonicals: List[Dict[str, Any]] = []
        for e in sorted(group, key=lambda x: -int(x.get("seen_count", 1))):
            hit = next((c for c in canonicals if _near_dup(c, e, threshold)), None)
            if hit is not None:
                _merge_into(hit, e)
            else:
                canonicals.append(e)
        out.extend(canonicals)
    return out


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

    # CONTRADICTION RESOLUTION — a confirmed SUCCESS supersedes a prior FAILED
    # lesson for the same situation. The end-of-session LLM miner over-labels
    # "failed" (a technique probed but not recorded shows up failed even when it
    # actually reached the target, e.g. an SSRF that hit cloud metadata but wasn't
    # recorded before the turn budget ran out). Once the SAME technique is confirmed
    # to WORK on a strongly-overlapping stack, the stale failure must not keep
    # discouraging it. Drop failed lessons whose signature is largely contained in
    # this worked lesson's (>=2 shared tags and >=60% of the failed one's tags).
    if outcome == "worked" and len(tech_signature) >= 2:
        _sig = set(tech_signature)
        _kept = []
        for e in lessons:
            if e.get("outcome") == "failed":
                _f = set(e.get("tech_signature") or [])
                _inter = _sig & _f
                if _f and len(_inter) >= 2 and len(_inter) >= 0.6 * len(_f):
                    continue  # superseded by this confirmed success
            _kept.append(e)
        lessons = _kept

    # Merge semantic near-duplicates before pruning — keeps the store diverse
    # (16 reworded 'password reset token leak' copies collapse to one with a
    # summed seen_count) instead of letting dead weight push out distinct lessons.
    # Only when it's actually growing, to keep the O(n*canon) pass off every write.
    if len(lessons) > 60:
        lessons = consolidate_lessons(lessons)

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
                worked = 1 if entry.get("outcome") == "worked" else 0
                scored.append((overlap, worked, int(entry.get("seen_count", 1)), entry))
        # Rank by stack overlap, then WORKED-first at equal overlap, then by how
        # many targets confirmed it. Recall should LEAD with what actually worked —
        # a confirmed technique is more actionable than a past failure, and the
        # end-of-session LLM miner over-labels "failed" (a technique probed but not
        # recorded shows up failed even when it reached the target).
        scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
        # Cap failed lessons to at most half the slots so recall isn't a wall of
        # past failures crowding out the wins.
        results, failed_used = [], 0
        failed_cap = max(1, limit // 2)
        for _ov, worked, _sc, entry in scored:
            if not worked:
                if failed_used >= failed_cap:
                    continue
                failed_used += 1
            results.append(entry)
            if len(results) >= limit:
                break
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