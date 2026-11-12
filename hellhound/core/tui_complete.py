"""
hellhound/core/tui_complete.py — slash-command autocomplete for the TUI.

Ports the old prompt_toolkit `HellhoundCompleter` logic into a framework-
agnostic function: given the current input text, return a ranked list of
suggestions. The Textual UI renders these in a dropdown you arrow-key through
(see tui.py's SuggestionBox); this module just computes WHAT to suggest so the
command/argument knowledge lives in one place.

Each suggestion is a tuple: (new_line, label, meta)
  new_line — the full input line to set if this suggestion is accepted
             (so the UI never has to do cursor math)
  label    — short text shown in the dropdown (the command/value)
  meta     — dim description shown after the label
"""

from __future__ import annotations

import os
from typing import List, Tuple

Suggestion = Tuple[str, str, str]


# Static subcommand/argument tables, mirrored from the classic completer.
_SUBCOMMANDS = {
    ("/model", "/ai"): [
        ("orchestrator", "Configure fast local tool-selection model"),
        ("synthesizer", "Configure deep cloud-reasoning analysis model"),
        ("set-key", "Configure API key for provider (e.g. /model set-key nvidia <key>)"),
        ("--session-only", "Apply model to current session without saving config"),
    ],
    ("/setup", "/health", "/doctor"): [
        ("tools auto-install on", "Enable automated binary dependency installation"),
        ("tools auto-install off", "Disable automated binary dependency installation"),
        ("tools install-all", "Install all missing tool dependencies"),
        ("recaps on", "Enable recap footers after multi-tool analysis"),
        ("recaps off", "Disable recap footers after multi-tool analysis"),
    ],
    ("/scope", "/rules"): [
        ("show", "View current target scope rules"),
        ("clear", "Clear active scope rules"),
        ("in", "Add in-scope host(s)"),
        ("out", "Add out-of-scope exclusion(s)"),
        ("disallow", "Add a prohibited rule"),
    ],
    ("/report", "/loot"): [
        ("--format html", "Generate interactive HTML report"),
        ("--format json", "Generate structured JSON report"),
    ],
    ("/recon", "/surface", "/spider"): [
        ("subdomains", "Asset discovery only (dns_bruteforce/subfinder)"),
        ("endpoints", "Content and endpoint discovery only (spider)"),
        ("tech", "Live-host and technology fingerprinting only (httpx)"),
    ],
}

# /program sub-verbs (now includes rename/edit/switch).
_PROGRAM_VERBS = [
    ("show", "Show a program's attached targets + scope"),
    ("list", "List every program created so far"),
    ("create", "Create a program and attach domains"),
    ("add", "Add domain(s) to the active program"),
    ("attach", "Attach the current target to its program"),
    ("scope", "Set/replace the whole program's scope"),
    ("select", "Select a program to work (use when none is active yet)"),
    ("switch", "Switch the active session to another program/host"),
    ("rename", "Rename a program (fix a typo'd name)"),
    ("private", "Hide this program's name from lists/autocomplete (stream-safe)"),
    ("public", "Make a private program visible again"),
]


def _match(val: str, word: str) -> bool:
    return val.lower().startswith(word.lower())


def compute_suggestions(text: str, limit: int = 40) -> List[Suggestion]:
    """Return autocomplete suggestions for the current input line."""
    if not text.startswith("/"):
        return []

    try:
        from hellhound.core.commands import COMMAND_REGISTRY
    except Exception:
        COMMAND_REGISTRY = {}

    tokens = text.split()

    # 1. Base command completion ("/sc" -> /scope, /scan, ...)
    if len(tokens) <= 1 and not text.endswith(" "):
        target = (tokens[0] if tokens else "/").lower()
        seen = set()
        system, skills = [], []
        for name, cmd in COMMAND_REGISTRY.items():
            if not str(name).startswith("/"):
                continue
            primary = cmd.name.lower()
            if primary in seen or not primary.startswith(target):
                continue
            seen.add(primary)
            meta = (cmd.description or "").split("\n")[0][:70]
            entry = (cmd.name + " ", cmd.name, meta)
            if getattr(cmd, "category", "") == "skills":
                skills.append(entry)
            else:
                system.append(entry)
        system.sort(key=lambda e: e[1].lower())
        skills.sort(key=lambda e: e[1].lower())
        return (system + skills)[:limit]

    # 2. Subcommand / argument completion
    cmd_name = tokens[0].lower()
    word = "" if text.endswith(" ") else tokens[-1]
    prefix = text[: len(text) - len(word)]

    def mk(val: str, meta: str) -> Suggestion:
        return (prefix + val + " ", val, meta)

    # dynamic: target names
    if cmd_name in ("/target", "/targets"):
        out: List[Suggestion] = []
        try:
            from hellhound.core.tasks import list_targets, _get_targets_dir, is_target_private
            for name in list_targets(exclude_default=False):
                if is_target_private(name):
                    continue  # private engagement — don't surface its domain on screen
                meta = "saved target"
                try:
                    mtime = os.path.getmtime(os.path.join(_get_targets_dir(), name, "task.json"))
                    meta = f"saved target · {_humanize_age(mtime)}"
                except Exception:
                    pass
                if _match(name, word):
                    out.append(mk(name, meta))
        except Exception:
            pass
        if not word:
            out.append(mk("--clear-history", "Wipe saved chat history for the CURRENT target"))
        return out[:limit]

    # dynamic: program sub-verbs + program names
    if cmd_name in ("/program", "/programs", "/engagement"):
        try:
            from hellhound.core.tasks import list_programs, is_program_private
            progs = [p for p in list_programs() if not is_program_private(p)]
        except Exception:
            progs = []
        arg_tokens = tokens[1:]
        # first arg -> suggest the verb
        if len(arg_tokens) == 0 or (len(arg_tokens) == 1 and not text.endswith(" ")):
            return [mk(v, m) for v, m in _PROGRAM_VERBS if _match(v, word)][:limit]
        # verb already chosen; for show/rename/scope/switch suggest existing
        # program names as the second token.
        verb = arg_tokens[0].lower()
        if verb in ("show", "rename", "scope", "switch", "select", "use", "open", "private", "public") and (
            len(arg_tokens) == 1 or (len(arg_tokens) == 2 and not text.endswith(" "))
        ):
            return [mk(p, "existing program") for p in progs if _match(p, word)][:limit]
        # 'switch' takes an optional THIRD token — the specific domain inside
        # the already-chosen program — so walking Tab -> Tab goes program,
        # then domain, then Enter switches: the click-a-session-window flow
        # the researcher expects, done via the keyboard.
        if verb in ("switch", "select", "use", "open") and len(arg_tokens) >= 2:
            prog_name = arg_tokens[1]
            try:
                from hellhound.core.tasks import list_program_targets, load_program
                doms = list(list_program_targets(prog_name))
                # also offer concrete in-scope hosts you haven't worked yet
                rec = load_program(prog_name) or {}
                for d in (rec.get("scope_rules") or {}).get("in_scope", []):
                    if d and not d.startswith("*") and d not in doms:
                        doms.append(d)
            except Exception:
                doms = []
            return [mk(d, "host in this program — Enter lands on it") for d in doms if _match(d, word)][:limit]
        return []

    # static subcommand tables
    for keys, subs in _SUBCOMMANDS.items():
        if cmd_name in keys:
            return [mk(val, meta) for val, meta in subs if _match(val, word)][:limit]

    return []


def _humanize_age(mtime: float) -> str:
    import time
    delta = max(0, int(time.time() - mtime))
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"