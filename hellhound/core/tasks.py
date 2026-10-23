"""
hellhound/core/tasks.py

Persistent per-target task management.
Stores target context, scope rules, summaries, timestamps, notes, and findings
in ~/.hellhound/targets/<target>/task.json.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Dict, Any, List, Optional, Callable
from urllib.parse import urlparse

import hashlib

from hellhound.core.scope import ScopeRules, parse_program_rules
from hellhound.core.rotation import rotate_if_needed


def hash_auth_value(value: str) -> str:
    """One-way hash of secret value so it's not recoverable from disk/logs."""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def redact_sensitive_dict_keys(d: Any) -> Any:
    """Recursively walks a dict/list structure and replaces sensitive keys with hashed values."""
    if isinstance(d, dict):
        new_d = {}
        for k, v in d.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("cookie", "auth", "token", "key", "secret", "password")):
                if isinstance(v, str):
                    new_d[k] = hash_auth_value(v) if v else ""
                elif isinstance(v, dict):
                    new_d[k] = redact_sensitive_dict_keys(v)
                else:
                    new_d[k] = "********"
            else:
                new_d[k] = redact_sensitive_dict_keys(v)
        return new_d
    elif isinstance(d, list):
        return [redact_sensitive_dict_keys(item) for item in d]
    return d



def _get_targets_dir() -> str:
    base = os.path.expanduser("~/.hellhound/targets")
    os.makedirs(base, exist_ok=True)
    return base


STOPWORDS = {"this", "the", "target", "a", "an", "my", "our", "all", "any", "it", "to", "for"}

def sanitize_target_name(target: str) -> str:
    """Normalize target domain or URL to a safe filesystem folder name."""
    if not target:
        return "default"
    cleaned = target.strip().lower()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path
    cleaned = re.sub(r'[:/\\?#%*|"<> ]', '_', cleaned)
    cleaned = re.sub(r'_+', '_', cleaned).strip('._')
    if cleaned in STOPWORDS:
        return "default"
    return cleaned or "default"


def extract_raw_host(target: str) -> str:
    """
    Same URL/scheme stripping as sanitize_target_name, but preserves the
    exact host[:port] text instead of mangling it into a filesystem-safe
    name. sanitize_target_name's colon->underscore substitution makes
    "192.168.1.5:8080" into "192.168.1.5_8080" — correct for a folder name,
    useless (and silently broken) as an actual hostname to connect to. This
    is what Target.host stores for anything that needs to build a real
    network request or show the researcher what's actually being hit.
    """
    if not target:
        return ""
    cleaned = target.strip()
    if cleaned.lower().startswith("http://") or cleaned.lower().startswith("https://"):
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path
    return cleaned


@dataclass
class Target:
    name: str
    scope_raw: str = ""
    scope_rules: ScopeRules = field(default_factory=ScopeRules)
    scope_summary: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_active: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: Optional[str] = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    state: Dict[str, Any] = field(default_factory=dict)
    host: str = ""  # real, connectable host[:port] — see extract_raw_host(). `name`
                     # is the filesystem-safe folder name and must NEVER be used to
                     # build an actual URL/hostname (colons get mangled to underscores).
    program: str = ""  # safe-name of the bug-bounty PROGRAM/engagement this target
                        # belongs to (e.g. "agov-engagement"), if any — see
                        # get_program_dir() / attach_target_to_program() below. A
                        # single program can have many in-scope domains, each its
                        # own Target (own findings/session/state), grouped by this
                        # field so they can be listed and scoped together instead
                        # of each one being a disconnected flat target.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "scope_raw": self.scope_raw,
            "scope_rules": self.scope_rules.to_dict() if isinstance(self.scope_rules, ScopeRules) else self.scope_rules,
            "scope_summary": self.scope_summary,
            "created_at": self.created_at,
            "last_active": self.last_active,
            "notes": self.notes,
            "findings": self.findings,
            "state": redact_sensitive_dict_keys(self.state),
            "host": self.host,
            "program": self.program,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Target":
        if not isinstance(data, dict):
            return cls(name="default")
        scope_rules_data = data.get("scope_rules", {})
        if isinstance(scope_rules_data, dict):
            scope_rules = ScopeRules.from_dict(scope_rules_data)
        elif isinstance(scope_rules_data, ScopeRules):
            scope_rules = scope_rules_data
        else:
            scope_rules = ScopeRules()

        findings_raw = data.get("findings")
        findings = list(findings_raw) if isinstance(findings_raw, list) else []

        state_raw = data.get("state")
        state = dict(state_raw) if isinstance(state_raw, dict) else {}

        return cls(
            name=sanitize_target_name(str(data.get("name", "default"))),
            scope_raw=str(data.get("scope_raw", "")),
            scope_rules=scope_rules,
            scope_summary=str(data.get("scope_summary", "")),
            created_at=str(data.get("created_at", datetime.now(timezone.utc).isoformat())),
            last_active=str(data.get("last_active", datetime.now(timezone.utc).isoformat())),
            notes=data.get("notes", ""),
            findings=findings,
            state=state,
            host=str(data.get("host", "")),  # "" for targets saved before this field existed
            program=str(data.get("program", "")),  # "" for targets saved before this field existed, or ungrouped
        )


def get_target_path(target_name: str) -> str:
    safe_name = sanitize_target_name(target_name)
    target_dir = os.path.join(_get_targets_dir(), safe_name)
    os.makedirs(target_dir, exist_ok=True)
    return os.path.join(target_dir, "task.json")


def save_target(target: Target) -> None:
    target.last_active = datetime.now(timezone.utc).isoformat()
    path = get_target_path(target.name)
    try:
        rotate_if_needed(Path(path))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(target.to_dict(), f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Warning: Failed to persist target {target.name}: {e}")


def create_or_load_target(name: str) -> Target:
    raw_host = extract_raw_host(name)
    safe_name = sanitize_target_name(name)
    path = get_target_path(safe_name)

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                loaded = Target.from_dict(data)
                if not loaded.host and raw_host:
                    # Backfill: target was saved before the `host` field
                    # existed (or was created some other way without it).
                    loaded.host = raw_host
                    save_target(loaded)
                return loaded
        except Exception as e:
            print(f"[!] Warning: Failed to load target {safe_name} from disk (corrupted JSON?): {e}")

    # Create new target with clean empty scope
    target = Target(name=safe_name, host=raw_host)
    save_target(target)
    return target


def set_scope(target: Target, raw_text: str, model_call: Optional[Callable] = None) -> Target:
    """Updates the target scope rules from raw text or markdown program rules."""
    target.scope_raw = raw_text
    target.scope_rules = parse_program_rules(raw_text)

    # If in_scope was empty, add the target domain by default
    if not target.scope_rules.in_scope and target.name and "." in target.name:
        clean_name = target.name.lstrip("*.")
        target.scope_rules.in_scope.append(f"*.{clean_name}")
        target.scope_rules.in_scope.append(clean_name)

    in_count = len(target.scope_rules.in_scope)
    out_count = len(target.scope_rules.out_scope)
    dis_count = len(target.scope_rules.disallowed)
    target.scope_summary = f"{in_count} in-scope domains, {out_count} out-of-scope exclusions, {dis_count} prohibited rules"

    save_target(target)
    return target


def list_targets(exclude_default: bool = True) -> List[str]:
    base = _get_targets_dir()
    targets_with_time = []
    if not os.path.exists(base):
        return []
    for entry in os.listdir(base):
        if exclude_default and (entry == "default" or entry in STOPWORDS or "." not in entry):
            continue
        task_file = os.path.join(base, entry, "task.json")
        if os.path.isfile(task_file):
            try:
                mtime = os.path.getmtime(task_file)
                targets_with_time.append((entry, mtime))
            except Exception:
                targets_with_time.append((entry, 0))
    # Sort most recently modified first
    targets_with_time.sort(key=lambda x: x[1], reverse=True)
    return [t[0] for t in targets_with_time]


# ══════════════════════════════════════════════════════════════════════════
# PROGRAM / ENGAGEMENT GROUPING
# ══════════════════════════════════════════════════════════════════════════
#
# A bug-bounty PROGRAM (e.g. "AGOV") typically ships with several in-scope
# domains, each of which needs its own independent Target (own findings,
# own session/auth state, own curl history) — but they're one engagement,
# sharing one scope and one "which domains am I allowed to touch" answer.
# Before this, /target <domain> only ever created a flat, disconnected
# target with no relationship to any other domain from the same program,
# and there was no way to apply one scope update to every domain in a
# program at once — setting scope under a program name ended up replacing
# that one target's identity instead of fanning out to its domains. This
# section stores one program.json per program (its own scope_raw/
# scope_rules, plus the list of target names that belong to it) and keeps
# every attached Target's own scope_rules in sync with it.

def _get_programs_dir() -> str:
    base = os.path.expanduser("~/.hellhound/programs")
    os.makedirs(base, exist_ok=True)
    return base


def sanitize_program_name(name: str) -> str:
    """Same filesystem-safe normalization as sanitize_target_name, kept as
    its own function (rather than reusing that one directly) because a
    program name is free text ("AGOV Engagement"), not a domain/URL — no
    scheme-stripping, no STOPWORDS collapse-to-"default"."""
    if not name:
        return ""
    cleaned = name.strip().lower()
    cleaned = re.sub(r'[:/\\?#%*|"<> ]', '-', cleaned)
    cleaned = re.sub(r'-+', '-', cleaned).strip('.-')
    return cleaned


def get_program_path(program_name: str) -> str:
    safe_name = sanitize_program_name(program_name)
    program_dir = os.path.join(_get_programs_dir(), safe_name)
    os.makedirs(program_dir, exist_ok=True)
    return os.path.join(program_dir, "program.json")


def load_program(program_name: str) -> Optional[Dict[str, Any]]:
    """Returns the program's stored record, or None if it hasn't been
    created yet (e.g. referenced by name but never set up)."""
    safe_name = sanitize_program_name(program_name)
    if not safe_name:
        return None
    path = get_program_path(safe_name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Warning: Failed to load program {safe_name} from disk (corrupted JSON?): {e}")
        return None


def _save_program(record: Dict[str, Any]) -> None:
    path = get_program_path(record["name"])
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)


def list_programs() -> List[str]:
    base = _get_programs_dir()
    if not os.path.exists(base):
        return []
    out = []
    for entry in os.listdir(base):
        if os.path.isfile(os.path.join(base, entry, "program.json")):
            out.append(entry)
    return sorted(out)


def attach_target_to_program(target: Target, program_name: str) -> Target:
    """
    Tags `target` as belonging to `program_name` and, if that program
    already has scope rules saved (from set_program_scope, or a prior
    target attached to it), applies them to this target too — so a NEW
    in-scope domain added under an existing program immediately inherits
    the program's full in-scope list (itself included) rather than
    starting with an empty scope the researcher has to re-set by hand.
    Creates the program's own record if this is the first target attached
    to it. Idempotent — attaching the same target to the same program
    twice is a harmless no-op beyond a dedup check.
    """
    safe_program = sanitize_program_name(program_name)
    if not safe_program:
        return target

    record = load_program(safe_program)
    if record is None:
        record = {
            "name": safe_program,
            "display_name": program_name.strip(),
            "scope_raw": "",
            "scope_rules": ScopeRules().to_dict(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "targets": [],
        }

    if target.name not in record["targets"]:
        record["targets"].append(target.name)
        _save_program(record)

    target.program = safe_program
    # Only overwrite this target's scope if the PROGRAM actually has scope
    # rules worth inheriting — an empty program (just created) shouldn't
    # blank out scope a researcher already set directly on this target.
    prog_scope = record.get("scope_rules") or {}
    if prog_scope.get("in_scope") or prog_scope.get("out_scope") or prog_scope.get("disallowed"):
        target.scope_raw = record.get("scope_raw", "")
        target.scope_rules = ScopeRules.from_dict(prog_scope)
        in_count = len(target.scope_rules.in_scope)
        out_count = len(target.scope_rules.out_scope)
        dis_count = len(target.scope_rules.disallowed)
        target.scope_summary = f"{in_count} in-scope domains, {out_count} out-of-scope exclusions, {dis_count} prohibited rules"
    save_target(target)
    return target


def set_program_scope(program_name: str, raw_text: str) -> Dict[str, Any]:
    """
    Parses `raw_text` (the program's scope policy — a domain list, or full
    program rules markdown, same format set_scope() on a single target
    already accepts) into ScopeRules, saves it as this PROGRAM's scope, and
    propagates it to EVERY target currently attached to the program — this
    is what actually fixes "setting scope under the program name changed
    the target instead of spreading to all its in-scope domains": one call
    here updates the shared scope once, and every domain under the program
    picks it up, instead of the researcher having to repeat /scope on each
    domain individually (and instead of the AI mistakenly treating the
    program name itself as if it were one of the domains).
    """
    safe_program = sanitize_program_name(program_name)
    record = load_program(safe_program) or {
        "name": safe_program,
        "display_name": program_name.strip(),
        "scope_raw": "",
        "scope_rules": ScopeRules().to_dict(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "targets": [],
    }

    scope_rules = parse_program_rules(raw_text)
    record["scope_raw"] = raw_text
    record["scope_rules"] = scope_rules.to_dict()
    _save_program(record)

    updated_targets = []
    for target_name in record.get("targets", []):
        try:
            t = create_or_load_target(target_name)
        except Exception:
            continue
        t.scope_raw = raw_text
        t.scope_rules = parse_program_rules(raw_text)  # fresh instance per target, not a shared mutable object
        in_count = len(t.scope_rules.in_scope)
        out_count = len(t.scope_rules.out_scope)
        dis_count = len(t.scope_rules.disallowed)
        t.scope_summary = f"{in_count} in-scope domains, {out_count} out-of-scope exclusions, {dis_count} prohibited rules"
        save_target(t)
        updated_targets.append(target_name)

    return {
        "program": safe_program,
        "scope_rules": scope_rules.to_dict(),
        "scope_summary": record.get("scope_rules"),
        "targets_updated": updated_targets,
    }


def list_program_targets(program_name: str) -> List[str]:
    record = load_program(program_name)
    if not record:
        return []
    return list(record.get("targets", []))