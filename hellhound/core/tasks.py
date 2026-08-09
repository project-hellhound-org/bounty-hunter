"""
hellhound/core/tasks.py

Persistent per-target task management.
Stores target context, scope rules, summaries, timestamps, notes, and findings
in ~/.hellhound/targets/<target>/task.json.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
import json
import os
import re
from typing import Dict, Any, List, Optional, Callable
from urllib.parse import urlparse

from hellhound.core.scope import ScopeRules, parse_program_rules


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
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_active: str = field(default_factory=lambda: datetime.utcnow().isoformat())
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
            "state": self.state,
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

        return cls(
            name=str(data.get("name", "default")),
            scope_raw=str(data.get("scope_raw", "")),
            scope_rules=scope_rules,
            scope_summary=str(data.get("scope_summary", "")),
            created_at=str(data.get("created_at", datetime.utcnow().isoformat())),
            last_active=str(data.get("last_active", datetime.utcnow().isoformat())),
            notes=data.get("notes", ""),
            findings=list(data.get("findings", [])),
            state=dict(data.get("state", {})),
        )


def get_target_path(target_name: str) -> str:
    safe_name = sanitize_target_name(target_name)
    target_dir = os.path.join(_get_targets_dir(), safe_name)
    os.makedirs(target_dir, exist_ok=True)
    return os.path.join(target_dir, "task.json")


def save_target(target: Target) -> None:
    target.last_active = datetime.utcnow().isoformat()
    path = get_target_path(target.name)
    try:
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
        except Exception:
            pass

    # Create new target
    target = Target(name=name)
    # Default initial in_scope rule to the target itself if valid domain
    if name and "." in name:
        target.scope_rules.in_scope.append(f"*.{name.lstrip('*.')}")
        target.scope_rules.in_scope.append(name.lstrip("*."))
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
