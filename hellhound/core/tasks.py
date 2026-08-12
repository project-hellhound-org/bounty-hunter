"""
hellhound/core/tasks.py

Persistent per-target task management.
Stores target context, scope rules, summaries, timestamps, notes, and findings
in ~/.hellhound/targets/<target>/task.json.
"""

from dataclasses import dataclass, field, asdict
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
    safe_name = sanitize_target_name(name)
    path = get_target_path(safe_name)

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return Target.from_dict(data)
        except Exception as e:
            print(f"[!] Warning: Failed to load target {safe_name} from disk (corrupted JSON?): {e}")

    # Create new target with clean empty scope
    target = Target(name=safe_name)
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


def migrate_legacy_history() -> int:
    """Migrate legacy targets from gui/target_history.json into target tasks."""
    history_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "gui", "target_history.json")
    if not os.path.exists(history_file):
        return 0
    try:
        with open(history_file, "r", encoding="utf-8") as f:
            items = json.load(f)
            if not isinstance(items, list):
                return 0
            migrated = 0
            for item in items:
                if isinstance(item, str) and item.strip():
                    t = create_or_load_target(item.strip())
                    migrated += 1
            return migrated
    except Exception:
        return 0
