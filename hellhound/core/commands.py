"""
hellhound/core/commands.py

Unified Slash-Command Architecture & Central Dispatcher.
Provides a unified entrypoint for interactive console and headless CLI
automation (--print).
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Any
import inspect
import os
import re
import sys
import json
import shlex
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from hellhound.core.scope import ScopeRules, is_in_scope, check_module_against_rules
from hellhound.core.tasks import create_or_load_target, set_scope as task_set_scope, save_target, list_program_targets
from hellhound.core.ai_utils import (
    load_config, save_config, ask_neural_core,
    ping_ollama, list_available_models, detect_ai_config,
    NVIDIA_DEFAULT_MODEL
)
from hellhound.core.agent import handle_message as agent_handle_message, get_agent
from hellhound.core.emit import PlainEmit
from hellhound.core.http_utils import merge_global_context
from hellhound.core.nodes import build_graph
from hellhound.core.toolcheck import (
    check_all_tools, try_install, check_wordlists,
    update_all_tools, sync_python_dependencies, update_hellhound_source,
)

# Recon/OSINT tool API keys — separate namespace from the LLM provider
# keys /model set-key handles (those are validated against a fixed
# provider list tied to model selection; these are read directly by their
# tool executors in agent.py via cfg["api_keys"][<name>]). Centralized
# here so /setup can both display status and offer to collect them,
# instead of a researcher having to discover each tool's env var by
# reading source.
RECON_API_KEY_INFO: Dict[str, Dict[str, str]] = {
    "urlscan": {
        "label": "urlscan.io",
        "used_by": "urlscan_recon",
        "signup_url": "https://urlscan.io/user/signup",
        "env_var": "URLSCAN_API_KEY",
        "where": "after signup: urlscan.io -> top-right profile menu -> API",
    },
    "virustotal": {
        "label": "VirusTotal",
        "used_by": "virustotal_lookup",
        "signup_url": "https://www.virustotal.com/gui/join-us",
        "env_var": "VT_API_KEY",
        "where": "after signup: virustotal.com -> your profile icon -> API key",
    },
}


def _interactive_prompt(prompt_text: str) -> str:
    print(f"\033[93m[?]\033[0m {prompt_text}")
    try:
        val = input("> ").strip()
        return val
    except (KeyboardInterrupt, EOFError):
        return ""


def _interactive_prompt_multiline(prompt_text: str) -> str:
    print(f"\033[93m[?]\033[0m {prompt_text}")
    lines = []
    try:
        while True:
            line = input("> ")
            if not line:
                break
            lines.append(line)
        return "\n".join(lines).strip()
    except (KeyboardInterrupt, EOFError):
        return ""


@dataclass
class Command:
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    usage: str = ""
    category: str = "general"
    handler: Optional[Callable[[List[str], Dict[str, Any], Any], Dict[str, Any]]] = None


COMMAND_REGISTRY: Dict[str, Command] = {}


def register_command(cmd: Command):
    """Registers a slash command and its aliases in the central registry."""
    COMMAND_REGISTRY[cmd.name.lower()] = cmd
    for alias in cmd.aliases:
        COMMAND_REGISTRY[alias.lower()] = cmd


def get_command(name: str) -> Optional[Command]:
    """Retrieves a command by name or alias."""
    name_clean = name.strip().lower()
    if not name_clean.startswith("/"):
        name_clean = "/" + name_clean
    return COMMAND_REGISTRY.get(name_clean)


# ─────────────────────────────────────────────────────────────
# SLASH COMMAND HANDLERS
# ─────────────────────────────────────────────────────────────

def _ensure_scope(session_context: Dict[str, Any]) -> ScopeRules:
    target_name = session_context.get("target") or "default"
    target = create_or_load_target(target_name)
    if target and target.scope_rules and target.scope_rules.in_scope:
        session_context["scope_rules"] = target.scope_rules
        return target.scope_rules

    rules = session_context.get("scope_rules")
    if not rules:
        cfg = load_config()
        scope_data = cfg.get("scope", {})
        rules = ScopeRules.from_dict(scope_data)
        session_context["scope_rules"] = rules
    return rules


def _extract_target_from_args(args: List[str], session_context: Dict[str, Any]) -> str:
    """Intelligently extract the real target domain/URL from positional args or session context."""
    stopwords = {"this", "the", "target", "a", "an", "my", "our", "all", "any", "it", "to", "for", "on", "at"}
    # 1. Check if any arg looks like a domain, IP, or URL
    for arg in args:
        clean = arg.strip().strip("'\"")
        if not clean or "=" in clean or clean.startswith("-"):
            continue
        if "." in clean or clean.startswith("http://") or clean.startswith("https://") or "localhost" in clean:
            return clean.lstrip("*.")
    
    # 2. Check first non-stopword arg
    for arg in args:
        clean = arg.strip().strip("'\"").lower()
        if clean and not clean.startswith("-") and "=" not in clean and clean not in stopwords:
            return clean

    # 3. Fallback to session_context target
    ctx_target = session_context.get("target", "")
    if ctx_target and ctx_target.lower() not in stopwords and ctx_target != "default":
        return ctx_target

    # 4. Fallback to active scope rules if target was default
    scope_rules = session_context.get("scope_rules")
    if scope_rules and getattr(scope_rules, "in_scope", None):
        return scope_rules.in_scope[0].lstrip("*.")

    return ""


def _call_tool_traced(agent, tool_name: str, args: Dict[str, Any], emit: Any,
                      cancel_check: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
    """
    Executes a tool via agent.execute_tool_call() while emitting live
    tool_start/tool_result events — the same events agent.py's agentic
    handle_message() loop already emits around its own tool calls.
    """
    if cancel_check and cancel_check():
        return {"error": "cancelled", "message": "Execution stopped by user", "blocked": True}

    if emit and hasattr(emit, "tool_start"):
        emit.tool_start(tool_name, args)
    result = agent.execute_tool_call(tool_name, args, emit=emit)
    if emit and hasattr(emit, "tool_result"):
        emit.tool_result(tool_name, result)
    return result


def handle_recon(args: List[str], session_context: Dict[str, Any], emit: Any,
                 on_token: Optional[Callable[[str], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
    """
    /recon [subdomains [active|passive] [permute] | endpoints | tech] <target> [--json]
    Deterministic reconnaissance pipelines — known tool sequences are called
    directly via execute_tool_call() with zero LLM round-trips for tool
    selection.
    """
    if cancel_check and cancel_check():
        return {"status": "cancelled", "message": "Execution stopped by user"}

    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    known_modes = {
        "subdomains": "subdomains", "subdomain": "subdomains", "subs": "subdomains", "sub": "subdomains",
        "endpoints": "endpoints", "endpoint": "endpoints",
        "tech": "tech"
    }
    mode = "full"

    if clean_args and clean_args[0].lower() in known_modes:
        mode = known_modes[clean_args[0].lower()]
        clean_args = clean_args[1:]

    target = _extract_target_from_args(clean_args, session_context)
    if not target:
        msg = "No target specified. Usage: /recon [subdomains|endpoints|tech] <target> [--json]"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "error": "missing_target", "message": msg}

    from hellhound.core.tasks import sanitize_target_name
    target = sanitize_target_name(target)
    session_context["target"] = target
    agent = get_agent(target)

    # ── Deterministic pipelines for narrow modes ─────────────────────
    results = {}
    answer = ""

    if mode == "subdomains":
        # Parse optional active/passive submode and permute flag-word
        sub_mode = None
        if clean_args and clean_args[0].lower() in ("active", "passive"):
            sub_mode = clean_args[0].lower()
            clean_args = clean_args[1:]
            re_target = _extract_target_from_args(clean_args, session_context)
            if re_target:
                target = sanitize_target_name(re_target)
                session_context["target"] = target
                agent = get_agent(target)

        has_permute = False
        permute_idx = None
        for idx, a in enumerate(clean_args):
            if a.lower() == "permute":
                has_permute = True
                permute_idx = idx
                break
        if permute_idx is not None:
            clean_args = clean_args[:permute_idx] + clean_args[permute_idx + 1:]
            re_target = _extract_target_from_args(clean_args, session_context)
            if re_target:
                target = sanitize_target_name(re_target)
                session_context["target"] = target
                agent = get_agent(target)

        # Default to passive when the user didn't specify a mode. If the
        # target isn't publicly indexed, subfinder will simply come back
        # empty and the fallback escalation to dns_bruteforce below picks
        # up the slack — no need to pre-judge based on the domain's name.
        if sub_mode is None:
            sub_mode = "passive"

        if cancel_check and cancel_check():
            return {"status": "cancelled", "message": "Execution stopped by user"}

        if sub_mode == "active":
            results["dns_bruteforce"] = _call_tool_traced(
                agent, "dns_bruteforce", {"domain": target}, emit, cancel_check=cancel_check
            )
            found = results["dns_bruteforce"].get("subdomains", [])
            if len(found) < 3:
                results["subfinder"] = _call_tool_traced(
                    agent, "subfinder", {"domain": target}, emit, cancel_check=cancel_check
                )
                supplement = results["subfinder"].get("subdomains", [])
                found = list(dict.fromkeys(found + supplement))
        else:
            results["subfinder"] = _call_tool_traced(
                agent, "subfinder", {"domain": target}, emit, cancel_check=cancel_check
            )
            found = results["subfinder"].get("subdomains", [])
            if len(found) < 3:
                results["dns_bruteforce"] = _call_tool_traced(
                    agent, "dns_bruteforce", {"domain": target}, emit, cancel_check=cancel_check
                )
                supplement = results["dns_bruteforce"].get("subdomains", [])
                found = list(dict.fromkeys(found + supplement))

        if cancel_check and cancel_check():
            return {"status": "cancelled", "message": "Execution stopped by user"}

        # Perform permutation and fast resolution sequence (always resolve discovered subdomains)
        if found:
            perm = _call_tool_traced(
                agent, "permute_subdomains", {"subdomains": found}, emit, cancel_check=cancel_check
            )
            results["permute_subdomains"] = perm
            candidates = perm.get("candidates", [])
            if candidates:
                res_cands = _call_tool_traced(
                    agent, "resolve_candidates",
                    {"candidates": candidates},
                    emit,
                    cancel_check=cancel_check
                )
                results["resolve_candidates"] = res_cands
                resolved = res_cands.get("subdomains", [])
                found = list(dict.fromkeys(found + resolved))

        if cancel_check and cancel_check():
            return {"status": "cancelled", "message": "Execution stopped by user"}

        # HTTP Service Discovery via httpx across all discovered subdomains
        if found:
            results["httpx"] = _call_tool_traced(
                agent, "httpx", {"target": found}, emit, cancel_check=cancel_check
            )

    elif mode == "endpoints":
        if cancel_check and cancel_check():
            return {"status": "cancelled", "message": "Execution stopped by user"}
        results["httpx"] = _call_tool_traced(
            agent, "httpx", {"target": [target]}, emit, cancel_check=cancel_check
        )
        if cancel_check and cancel_check():
            return {"status": "cancelled", "message": "Execution stopped by user"}
        results["spider"] = _call_tool_traced(
            agent, "spider", {"url": target}, emit, cancel_check=cancel_check
        )

    elif mode == "tech":
        if cancel_check and cancel_check():
            return {"status": "cancelled", "message": "Execution stopped by user"}
        results["httpx"] = _call_tool_traced(
            agent, "httpx", {"target": [target]}, emit, cancel_check=cancel_check
        )

    if cancel_check and cancel_check():
        return {"status": "cancelled", "message": "Execution stopped by user"}

    # ── Advisory synthesis or agentic fallback ───────────────────────
    if mode in ("subdomains", "endpoints", "tech"):
        advice = ask_neural_core(
            prompt=(
                f"Reconnaissance on {target} (mode: {mode}) completed.\n"
                f"Raw Tool Results: {json.dumps(results, default=str)[:5000]}.\n\n"
                f"REQUIREMENTS FOR YOUR RESPONSE:\n"
                f"1. Mention the underlying tools used: active DNS brute-forcing using shuffledns (via dns_bruteforce), permutation candidate generation, and candidate resolution using dnsx (via resolve_candidates).\n"
                f"2. Explicitly explain what kind of targets were discovered by HTTPX (e.g. list each live host, its resolved IP, HTTP status code, title/headers, and identified service type like API endpoint, web app, or database service).\n"
                f"3. Provide a prioritized Next-step reconnaissance action table (Columns: #, Action, Target/Reasoning, Expected Outcome).\n"
                f"4. Be specific and actionable based on the actual HTTPX results."
            ),
            role="synthesizer",
            thinking=True,
            on_token=on_token,
        )
        answer = advice
    else:
        prompt = (
            f"Perform reconnaissance on {target}. Follow proper methodology: "
            f"asset discovery and live-host confirmation first (subfinder, escalate "
            f"to dns_bruteforce if passive results are thin), then content/endpoint "
            f"discovery (spider) only against confirmed live hosts, then deeper "
            f"analysis (wafbuster, tech fingerprinting) as warranted. Respect scope "
            f"throughout."
        )
        answer = agent.handle_message(prompt, session_context=session_context, emit=emit, on_token=on_token, cancel_check=cancel_check)

    if not is_json and not on_token:
        emit(answer)
    return {"status": "success", "target": target, "mode": mode, "results": results, "advice": answer}


def handle_scan(args: List[str], session_context: Dict[str, Any], emit: Any,
                on_token: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """
    /scan <module> [target] [--json] [key=val ...]
    Deterministic single-module execution — calls the named tool directly via
    execute_tool_call() with zero LLM round-trips, then a single
    ask_neural_core() advisory call reviews the real result.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    if not clean_args:
        msg = "Usage: /scan <module> [target] [--json] [options...]"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "error": "missing_module", "message": msg}

    module_name = clean_args[0].lower()
    target_args = [a for a in clean_args[1:] if "=" not in a]
    target = _extract_target_from_args(target_args, session_context)

    if not target:
        msg = "No target specified. Set with /recon or pass as argument."
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "error": "missing_target", "message": msg}

    scope_rules = _ensure_scope(session_context)

    # 1. Target Scope Check (unchanged — already correctly deterministic)
    allowed_target, t_reason = is_in_scope(target, scope_rules)
    if not allowed_target:
        if not is_json:
            emit.error(f"[SECURITY] Target out of scope: {t_reason}")
        return {"status": "error", "error": "out_of_scope", "target": target, "reason": t_reason}

    # 2. Module Restriction Check (unchanged — already correctly deterministic)
    allowed_mod, m_reason = check_module_against_rules(module_name, scope_rules)
    if not allowed_mod:
        if not is_json:
            emit.error(f"[SECURITY] Module disallowed by program rules: {m_reason}")
        return {"status": "error", "error": "module_disallowed", "module": module_name, "reason": m_reason}

    custom_opts = {}
    for arg in clean_args[1:]:
        if "=" in arg:
            k, v = arg.split("=", 1)
            custom_opts[k.strip()] = v.strip()

    merged_opts = dict(session_context.get("options", {}))
    merged_opts.update(custom_opts)
    merge_global_context(merged_opts, session_context.get("options", {}))

    # Inject the target into tool args under the most common parameter names
    # so execute_tool_call() scope gate can extract and validate it
    if "domain" not in merged_opts and "url" not in merged_opts and "target" not in merged_opts:
        merged_opts["domain"] = target
        merged_opts["target"] = target
        merged_opts["url"] = target if target.startswith(("http://", "https://")) else f"https://{target}"

    session_context["target"] = target
    session_context["module"] = module_name

    agent = get_agent(target)

    # ── Direct tool execution — no LLM round-trip for tool selection ──
    result = _call_tool_traced(agent, module_name, merged_opts, emit)

    # ── Single advisory call — reviews real result ────────────────────
    advice = ask_neural_core(
        prompt=(
            f"Ran '{module_name}' against {target}. "
            f"Result: {json.dumps(result, default=str)[:4000]}. "
            f"Review this and advise on next steps, or state clearly if "
            f"nothing actionable was found."
        ),
        role="synthesizer",
        thinking=True,
        on_token=on_token,
    )

    if not is_json and not on_token:
        emit(advice)

    return {
        "status": "success",
        "module": module_name,
        "target": target,
        "result": result,
        "advice": advice
    }


def handle_hunt(args: List[str], session_context: Dict[str, Any], emit: Any,
                on_token: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """
    /hunt [target] [--json]
    Delegates to the agent's own reasoning for an autonomous, scope-aware multi-stage hunt and triage.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]
    target = _extract_target_from_args(clean_args, session_context)

    if not target:
        msg = "No target specified. Usage: /hunt <target> [--json]"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "error": "missing_target", "message": msg}

    session_context["target"] = target
    agent = get_agent(target)
    prompt = (
        f"Execute a complete, autonomous, scope-aware multi-stage hunt against target {target}. "
        f"Discover the surface area (subdomains, ports, live hosts), run passive and active analysis "
        f"modules (spider, surface_auditor, corsbuster, graphql, exmap, wafbuster), and triage all findings."
    )
    answer = agent.handle_message(prompt, session_context=session_context, emit=emit, on_token=on_token)
    if not is_json and not on_token:
        emit(answer)
    return {"status": "success", "target": target, "advice": answer}


def handle_scope(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /scope [show | clear | in <host...> | out <host...> | disallow <rule...> | remove <host...> | <pasted program policy text>]

    show                    — display the current scope for the active target
    clear                   — wipe all scope rules for the active target
    in <host...>            — ADD one or more hosts to in-scope (aliases: include, add-in)
    out <host...>           — ADD one or more hosts to out-of-scope (aliases: exclude, add-out)
    disallow <rule...>      — ADD one or more prohibited-action rules (alias: prohibit)
    remove <host...>        — REMOVE one or more entries, wherever they currently sit
                              (in-scope, out-of-scope, or disallowed) — use this to undo
                              a wrongly-added host (aliases: rm, delete, del, drop)
    <pasted policy text>    — anything else REPLACES the entire scope, parsed from
                              free-form/markdown program-policy text (e.g. pasting a
                              HackerOne/Bugcrowd scope page). Use this for the initial
                              scope setup; use in/out/disallow/remove for incremental
                              edits afterward — they add to or remove from what's
                              already there instead of wiping it.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    target_name = session_context.get("target") or "default"

    if target_name == "default":
        extracted = _extract_target_from_args(clean_args, session_context)
        if extracted:
            target_name = extracted
            session_context["target"] = target_name

    from hellhound.core.tasks import sanitize_target_name
    target_name = sanitize_target_name(target_name)
    session_context["target"] = target_name

    if target_name == "default" and not is_json and sys.stdin.isatty():
        target_name = _interactive_prompt("No target is currently active. Which target is this scope for? (type a domain)")
        if not target_name:
            msg = "No target specified. Usage: /scope [show | clear | <rules_text>]"
            emit.warn(msg)
            return {"status": "error", "error": "missing_target", "message": msg}
        target_name = sanitize_target_name(target_name)
        session_context["target"] = target_name
        # If they didn't provide args, prompt for scope rules as well
        if not clean_args:
            raw_text = _interactive_prompt_multiline(f"Paste the in-scope rules for {target_name} (blank line to finish):")
            if raw_text:
                clean_args = [raw_text]

    target_obj = create_or_load_target(target_name)

    if not clean_args or clean_args[0] == "show":
        rules = target_obj.scope_rules
        if not is_json:
            emit.info(f"Target: {target_obj.name}")
            emit.info(f"In-Scope Assets ({len(rules.in_scope)}): {', '.join(rules.in_scope) if rules.in_scope else 'None'}")
            emit.info(f"Out-of-Scope Exclusions ({len(rules.out_scope)}): {', '.join(rules.out_scope) if rules.out_scope else 'None'}")
            emit.info(f"Disallowed Actions ({len(rules.disallowed)}): {', '.join(rules.disallowed) if rules.disallowed else 'None'}")
        return {"status": "success", "target": target_obj.name, "scope": rules.to_dict()}

    if clean_args[0] == "clear":
        target_obj.scope_rules = ScopeRules()
        target_obj.scope_raw = ""
        target_obj.scope_summary = ""
        save_target(target_obj)
        session_context["scope_rules"] = target_obj.scope_rules
        if not is_json:
            emit.success(f"Scope cleared for target: {target_obj.name}")
        return {"status": "success", "action": "cleared"}

    # Explicit shorthand verbs — /scope in <host...>, /scope out <host...>,
    # /scope disallow <rule...> — ADD to the matching list on the existing
    # scope_rules. This must run BEFORE the generic free-text branch below:
    # that branch calls set_scope(), which re-derives the WHOLE ScopeRules
    # object from parse_program_rules() using ONLY this call's raw text —
    # not merged with what was already there. Two bugs that combined to
    # bite here: (1) "out" was never actually a recognized keyword to that
    # parser — it only recognizes full phrases like "out of scope:" or
    # "exclusions:" as a line-starting section header, so a bare "out X"
    # matched no header and silently fell through to the parser's DEFAULT
    # section, which is in_scope; and (2) even if "out" had been
    # recognized, calling set_scope() at all replaces the entire scope
    # from scratch, so a previously-set "*.arc.io" in-scope wildcard would
    # vanish the moment any other /scope command ran, "out" or not.
    scope_verb_map = {
        "in": "in_scope", "include": "in_scope", "add-in": "in_scope",
        "out": "out_scope", "exclude": "out_scope", "add-out": "out_scope",
        "disallow": "disallowed", "prohibit": "disallowed",
    }
    verb = clean_args[0].lower()
    if verb in scope_verb_map and len(clean_args) > 1:
        list_name = scope_verb_map[verb]
        rules = target_obj.scope_rules
        target_list = getattr(rules, list_name)
        added = []
        # clean_args is whitespace-tokenized, so "a.com,b.com,c.com" typed
        # with no spaces arrives as ONE token — split each on commas too,
        # or a comma-separated list silently becomes a single malformed
        # entry (confirmed: this is exactly what happened with
        # "help.arc.io,explorer.arc.io,community.arc.io").
        raw_hosts = []
        for raw_entry in clean_args[1:]:
            raw_hosts.extend(raw_entry.split(","))
        for host_piece in raw_hosts:
            entry = host_piece.strip().strip(",")
            if not entry:
                continue
            if entry not in target_list:
                target_list.append(entry)
                added.append(entry)
            # A host can't be simultaneously in and out of scope — moving it
            # to one list removes it from the others so the state can't end
            # up self-contradictory.
            for other_name in ("in_scope", "out_scope", "disallowed"):
                if other_name == list_name:
                    continue
                other_list = getattr(rules, other_name)
                if entry in other_list:
                    other_list.remove(entry)

        target_obj.scope_summary = f"{len(rules.in_scope)} in-scope domains, {len(rules.out_scope)} out-of-scope exclusions, {len(rules.disallowed)} prohibited rules"
        save_target(target_obj)
        session_context["scope_rules"] = rules

        if not is_json:
            if added:
                emit.success(f"Scope updated for target '{target_obj.name}':")
            else:
                emit.info(f"Nothing new to add — {', '.join(h.strip().strip(',') for h in raw_hosts if h.strip())} already in {list_name} for '{target_obj.name}'.")
            emit.info(f"  In-Scope: {rules.in_scope}")
            emit.info(f"  Out-of-Scope: {rules.out_scope}")
            emit.info(f"  Disallowed: {rules.disallowed}")
        return {"status": "success", "action": "added", "list": list_name, "added": added, "target": target_obj.name, "scope": rules.to_dict()}

    # /scope remove <host...> — undo a wrongly-added entry, wherever it
    # currently sits. Unlike in/out/disallow above, this doesn't target one
    # specific list: the researcher asking to remove something usually
    # doesn't know (or care) which list it landed in, especially right
    # after a typo'd /scope out that put it somewhere unexpected. Search
    # all three and strip it from whichever one(s) actually contain it.
    remove_verbs = ("remove", "rm", "delete", "del", "drop")
    if verb in remove_verbs and len(clean_args) > 1:
        rules = target_obj.scope_rules
        raw_hosts = []
        for raw_entry in clean_args[1:]:
            raw_hosts.extend(raw_entry.split(","))
        removed: Dict[str, List[str]] = {"in_scope": [], "out_scope": [], "disallowed": []}
        not_found = []
        for host_piece in raw_hosts:
            entry = host_piece.strip().strip(",")
            if not entry:
                continue
            hit = False
            for list_name in ("in_scope", "out_scope", "disallowed"):
                target_list = getattr(rules, list_name)
                if entry in target_list:
                    target_list.remove(entry)
                    removed[list_name].append(entry)
                    hit = True
            if not hit:
                not_found.append(entry)

        target_obj.scope_summary = f"{len(rules.in_scope)} in-scope domains, {len(rules.out_scope)} out-of-scope exclusions, {len(rules.disallowed)} prohibited rules"
        save_target(target_obj)
        session_context["scope_rules"] = rules

        total_removed = sum(len(v) for v in removed.values())
        if not is_json:
            if total_removed:
                emit.success(f"Removed from scope for target '{target_obj.name}':")
                for list_name, entries in removed.items():
                    if entries:
                        emit.info(f"  {list_name}: -{', '.join(entries)}")
            if not_found:
                emit.warn(f"Not found in any scope list — nothing to remove: {', '.join(not_found)}")
            emit.info(f"  In-Scope: {rules.in_scope}")
            emit.info(f"  Out-of-Scope: {rules.out_scope}")
            emit.info(f"  Disallowed: {rules.disallowed}")
        return {
            "status": "success", "action": "removed", "removed": removed,
            "not_found": not_found, "target": target_obj.name, "scope": rules.to_dict()
        }

    raw_text = " ".join(clean_args)
    task_set_scope(target_obj, raw_text)
    session_context["scope_rules"] = target_obj.scope_rules

    if not is_json:
        emit.success(f"Scope updated for target '{target_obj.name}':")
        emit.info(f"  In-Scope: {target_obj.scope_rules.in_scope}")
        emit.info(f"  Out-of-Scope: {target_obj.scope_rules.out_scope}")
        emit.info(f"  Disallowed: {target_obj.scope_rules.disallowed}")

    return {"status": "success", "action": "updated", "target": target_obj.name, "scope": target_obj.scope_rules.to_dict()}


def handle_program(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /program [show [name] | list | create <name> [domain1,domain2,...] | add <domain...> | attach <domain...> | scope <policy text>]

    For a bug-bounty PROGRAM/engagement with several in-scope domains
    (e.g. "AGOV" shipping a.gov.sg, b.gov.sg, c.gov.sg) — groups them
    under one program instead of each domain being its own disconnected
    flat target. Each domain still gets its own real target (own
    findings/session/recon history); /program only tags them together and
    gives them one shared scope. This is entirely separate from /target —
    nothing here runs automatically when you set a target; use /program
    explicitly whenever you actually want this structure, so a quick
    one-off "here's your target, go find X" never gets interrupted asking
    about programs.

    show [name]              — show a program's attached targets + scope
                                (default: the CURRENT target's program, if any)
    list                     — list every program name created so far
    create <name> [domains]  — create (or re-attach to) a program, attaching the
                                CURRENT target to it, plus any extra comma-separated
                                in-scope domains given (each becomes its own real
                                target, created if it doesn't exist yet) — creates
                                the program's folder under ~/.hellhound/programs/
    add <domain...>          — add more in-scope domain(s) to the CURRENT target's
                                program (comma-separated or space-separated) — the
                                current target must already belong to one; run
                                'create' first if not
    attach <domain...>       — alias for 'add': attaches an existing (or brand-new)
                                target to the CURRENT target's program by domain
                                name. Each attached target keeps its own real recon
                                data at ~/.hellhound/targets/<domain>/ AND gets a
                                browsable directory for it under
                                ~/.hellhound/programs/<program>/targets/<domain>/ —
                                so every in-scope subdomain of the program shows up
                                as its own separate directory inside the program's
                                directory, instead of scattered flat sibling folders.
    scope <policy text>      — set/REPLACE the whole program's scope (in-scope,
                                out-of-scope, disallowed), parsed the same free-form
                                way /scope accepts a pasted program policy page —
                                propagates to every target already attached to this
                                program in one shot, instead of repeating /scope on
                                each domain by hand. Applies to the CURRENT target's
                                program.
    """
    from hellhound.core.tasks import (
        attach_target_to_program, set_program_scope, load_program,
        sanitize_program_name, list_programs, list_program_targets,
    )

    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    target_name = session_context.get("target") or "default"
    from hellhound.core.tasks import sanitize_target_name as _sanitize_target_name
    target_name = _sanitize_target_name(target_name)
    target_obj = create_or_load_target(target_name) if target_name != "default" else None

    def _show_program(prog_name: str) -> Dict[str, Any]:
        record = load_program(prog_name)
        if not record:
            msg = f"No program named '{prog_name}' exists yet. Create one with: /program create {prog_name} [domain1,domain2,...]"
            if not is_json:
                emit.warn(msg)
            return {"status": "not_found", "program": prog_name, "message": msg}
        rules = record.get("scope_rules") or {}
        if not is_json:
            emit.info(f"Program: [bold cyan]{record.get('display_name', record['name'])}[/bold cyan]")
            emit.info(f"Targets ({len(record.get('targets', []))}): {', '.join(record.get('targets', [])) or 'None'}")
            emit.info(f"In-Scope ({len(rules.get('in_scope', []))}): {', '.join(rules.get('in_scope', [])) or 'None'}")
            emit.info(f"Out-of-Scope ({len(rules.get('out_scope', []))}): {', '.join(rules.get('out_scope', [])) or 'None'}")
            emit.info(f"Disallowed ({len(rules.get('disallowed', []))}): {', '.join(rules.get('disallowed', [])) or 'None'}")
        return {"status": "success", "program": record["name"], "targets": record.get("targets", []), "scope_rules": rules}

    if not clean_args or clean_args[0] == "show":
        prog_name = clean_args[1] if len(clean_args) > 1 else (getattr(target_obj, "program", "") if target_obj else "")
        if not prog_name:
            msg = (
                "No program specified and the active target isn't attached to one. "
                "Usage: /program [show [name] | list | create <name> [domains] | add <domain...> | scope <policy text>]"
            )
            if not is_json:
                emit.info(msg)
            return {"status": "no_program", "message": msg}
        return _show_program(prog_name)

    verb = clean_args[0].lower()

    if verb == "list":
        names = list_programs()
        if not is_json:
            if names:
                emit.info(f"Programs ({len(names)}): {', '.join(names)}")
            else:
                emit.info("No programs created yet. Use: /program create <name> [domain1,domain2,...]")
        return {"status": "success", "programs": names}

    if verb == "create":
        if len(clean_args) < 2:
            msg = "Usage: /program create <name> [domain1,domain2,...]"
            emit.warn(msg)
            return {"status": "error", "error": "missing_name", "message": msg}

        # CAUGHT IN THE WILD (2026-10): '/program create mercado libre'
        # (name genuinely has a space, typed without quotes) silently took
        # clean_args[1] ("mercado") as the whole name and clean_args[2:]
        # ("libre") as an EXTRA DOMAIN TO ATTACH — "libre" got
        # create_or_load_target()'d as if it were a real in-scope host,
        # which it plainly isn't (no dot, not a domain at all). A domain
        # is syntactically distinguishable from a name word (it has a
        # dot, or the documented comma-separated list syntax is used), so
        # walk the tokens after the verb and only start treating them as
        # domains once one of them actually looks like one — everything
        # before that point is the (possibly multi-word) program name.
        # '/program create "mercado libre"' already worked correctly
        # before this fix (shlex.split keeps the quoted phrase as one
        # token) and still does — this only fixes the unquoted case.
        def _looks_like_domain_token(tok: str) -> bool:
            t = tok.strip().strip(",")
            if "," in tok:
                return True  # the documented domain-list separator -- unambiguous either way
            return bool(re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+$', t))

        rest = list(clean_args[1:])
        name_tokens = []
        idx = 0
        while idx < len(rest) and not _looks_like_domain_token(rest[idx]):
            name_tokens.append(rest[idx])
            idx += 1
        if not name_tokens:
            # The very first token already looked like a domain (e.g. the
            # researcher deliberately named the program "example.com") --
            # fall back to the original single-token-name behavior rather
            # than ending up with an empty name.
            name_tokens = [rest[0]]
            idx = 1
        prog_name = " ".join(name_tokens)
        domain_tokens = rest[idx:]

        if target_name == "default" or target_obj is None:
            msg = "No active target to attach — set one first with /target <domain>, or pass it as the first in-scope domain."
            emit.warn(msg)
            return {"status": "error", "error": "no_active_target", "message": msg}
        attach_target_to_program(target_obj, prog_name)
        attached = [target_obj.name]
        extra_domains = []
        for raw_entry in domain_tokens:
            extra_domains.extend(raw_entry.split(","))
        for d in extra_domains:
            d = d.strip().strip(",").lower()
            if not d or d == target_obj.name:
                continue
            d_target = create_or_load_target(d)
            attach_target_to_program(d_target, prog_name)
            attached.append(d_target.name)
        if not is_json:
            emit.success(f"Program '{sanitize_program_name(prog_name)}' created — {len(attached)} target(s) attached: {', '.join(attached)}")
            emit.info(f"Next: /program scope <policy text>  to set the program's shared in-scope/out-of-scope rules.")
        return {"status": "success", "action": "created", "program": sanitize_program_name(prog_name), "targets": attached}

    if verb in ("add", "attach"):
        prog_name = getattr(target_obj, "program", "") if target_obj else ""
        if not prog_name:
            msg = "The active target isn't attached to a program yet — run /program create <name> first."
            emit.warn(msg)
            return {"status": "error", "error": "no_active_program", "message": msg}
        raw_domains = []
        for raw_entry in clean_args[1:]:
            raw_domains.extend(raw_entry.split(","))
        added = []
        for d in raw_domains:
            d = d.strip().strip(",").lower()
            if not d:
                continue
            # create_or_load_target() LOADS the target's existing recon
            # data if that domain was already worked as a standalone
            # target before (its own findings/session/state) rather than
            # wiping it — attaching it to a program doesn't lose anything
            # already gathered, and attach_target_to_program() below links
            # that same real data directory in under the program's own
            # directory tree (see _ensure_program_target_link).
            d_target = create_or_load_target(d)
            attach_target_to_program(d_target, prog_name)
            added.append(d_target.name)
        if not added:
            msg = f"Usage: /program {verb} <domain1,domain2,...>"
            emit.warn(msg)
            return {"status": "error", "error": "no_domains_given", "message": msg}
        if not is_json:
            verb_past = "Attached" if verb == "attach" else "Added"
            emit.success(f"{verb_past} {len(added)} domain(s) to program '{prog_name}': {', '.join(added)}")
            emit.info(f"  Each now has its own directory under ~/.hellhound/programs/{prog_name}/targets/")
        return {"status": "success", "action": "attached", "program": prog_name, "domains_added": added}

    if verb == "scope":
        prog_name = getattr(target_obj, "program", "") if target_obj else ""
        if not prog_name:
            msg = "The active target isn't attached to a program yet — run /program create <name> first."
            emit.warn(msg)
            return {"status": "error", "error": "no_active_program", "message": msg}
        raw_text = " ".join(clean_args[1:]).strip()
        if not raw_text:
            msg = "Usage: /program scope <policy text>  (same free-form format /scope accepts — domain list or a pasted program policy page)"
            emit.warn(msg)
            return {"status": "error", "error": "no_scope_text", "message": msg}
        result = set_program_scope(prog_name, raw_text)
        if not is_json:
            emit.success(f"Scope updated for program '{prog_name}' — propagated to {len(result['targets_updated'])} target(s): {', '.join(result['targets_updated'])}")
            rules = result.get("scope_rules") or {}
            emit.info(f"  In-Scope: {rules.get('in_scope', [])}")
            emit.info(f"  Out-of-Scope: {rules.get('out_scope', [])}")
            emit.info(f"  Disallowed: {rules.get('disallowed', [])}")
        return {"status": "success", "action": "scope_updated", **result}

    msg = f"Unknown /program subcommand '{verb}'. Usage: /program [show [name] | list | create <name> [domains] | add <domain...> | attach <domain...> | scope <policy text>]"
    emit.warn(msg)
    return {"status": "error", "error": "unknown_subcommand", "message": msg}


def handle_model(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /model [orchestrator|synthesizer] [<provider> <model_name>] | [<provider/model_name>]
    /model [set-key <provider> <api_key>] | [--session-only]
    Inspects or switches the active local/cloud AI model for orchestrator/synthesizer roles.
    """
    KNOWN_PROVIDERS = ("nvidia", "openai", "anthropic", "gemini", "ollama")
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    session_only = "--session-only" in args
    clean_args = [a for a in args if a not in ("--json", "-j", "--session-only")]

    cfg = load_config()
    current_orch_prov = session_context.get("options", {}).get("orchestrator_provider") or cfg.get("orchestrator_provider", "ollama")
    current_orch_model = session_context.get("options", {}).get("orchestrator_model") or cfg.get("orchestrator_model", "")
    current_synth_prov = session_context.get("options", {}).get("synthesizer_provider") or cfg.get("synthesizer_provider", "nvidia")
    current_synth_model = session_context.get("options", {}).get("synthesizer_model") or cfg.get("synthesizer_model", NVIDIA_DEFAULT_MODEL)

    # ── Subcommand: /model set-key <provider> <api_key> ──────────────
    if clean_args and clean_args[0] == "set-key":
        if len(clean_args) < 3 and not is_json and sys.stdin.isatty():
            provider = ""
            if len(clean_args) >= 2:
                provider = clean_args[1].lower()
            else:
                provider = _interactive_prompt("Enter cloud provider (nvidia, openai, anthropic, gemini):").lower()
            
            if provider in ("nvidia", "openai", "anthropic", "gemini"):
                key = _interactive_prompt(f"Enter API key for {provider}:")
                if key:
                    clean_args = ["set-key", provider, key]

        if len(clean_args) < 3:
            if not is_json:
                emit.error("Usage: /model set-key <provider> <api_key>")
                emit.info("  Providers: nvidia, openai, anthropic, gemini")
            return {"status": "error", "error": "usage"}
        provider = clean_args[1].lower()
        key = clean_args[2]
        if provider not in ("nvidia", "openai", "anthropic", "gemini"):
            if not is_json:
                emit.error(f"Unknown provider '{provider}'. Use: nvidia, openai, anthropic, gemini")
            return {"status": "error", "error": "unknown_provider", "provider": provider}
        cfg.setdefault("api_keys", {})[provider] = key
        # Also store as the legacy api_key field if it's the first key being set
        if not cfg.get("api_key") or cfg.get("api_key") == "ollama":
            cfg["api_key"] = key
            cfg["ai_provider"] = provider
        save_config(cfg)
        if not is_json:
            masked = key[:8] + "..." + key[-4:] if len(key) > 16 else key[:4] + "..."
            emit.success(f"API key saved for {provider} ({masked})")
        return {"status": "success", "provider": provider}

    # ── No args: list models with usage help ─────────────────────────
    if not clean_args:
        models = list_available_models()
        if not is_json:
            emit.banner("HELLHOUND TWO-TIER AI ROUTING")
            emit.info(f"Orchestrator (Tool Selection): [{current_orch_prov.upper()}] {current_orch_model or '(default)'}")
            emit.info(f"Synthesizer  (Deep Analysis):  [{current_synth_prov.upper()}] {current_synth_model or '(default)'}\n")
            if models:
                emit.info("Available Models:")
                for m in models:
                    curr_flag = ""
                    if m.get("provider") == current_orch_prov and (m.get("name") == current_orch_model or (not current_orch_model and m.get("current"))):
                        curr_flag += " [bold cyan][orchestrator][/bold cyan]"
                    if m.get("provider") == current_synth_prov and (m.get("name") == current_synth_model or (not current_synth_model and m.get("current"))):
                        curr_flag += " [bold green][synthesizer][/bold green]"
                    emit(f"  • [{m['provider'].upper()}] {m['name']}{curr_flag}")
            else:
                emit.warn("No local Ollama models or cloud API keys configured.")
            # Usage hint
            emit(f"")
            emit.info("To add a cloud provider:          /model set-key <provider> <api_key>")
            emit.info("To switch orchestrator (tools):   /model orchestrator <provider> <model_name>")
            emit.info("To switch synthesizer (analysis): /model synthesizer <provider> <model_name>")
            emit.info("To switch both tiers:             /model <provider> <model_name>")
        return {
            "status": "success",
            "orchestrator_provider": current_orch_prov,
            "orchestrator_model": current_orch_model,
            "synthesizer_provider": current_synth_prov,
            "synthesizer_model": current_synth_model,
            "models": models
        }

    # ── Check for role-specific prefix: orchestrator vs synthesizer ──
    target_role = None
    if clean_args[0].lower() in ("orchestrator", "orch", "tools"):
        target_role = "orchestrator"
        clean_args = clean_args[1:]
    elif clean_args[0].lower() in ("synthesizer", "synth", "analysis"):
        target_role = "synthesizer"
        clean_args = clean_args[1:]
    elif clean_args[0].lower() in ("both", "all"):
        # Explicit "set both tiers to the same thing" — functionally
        # identical to just omitting a role prefix (target_role stays
        # None, which already means "update both" below), but a
        # researcher reaching for `/model both nvidia <model>` shouldn't
        # have that word get mistaken for a provider name and error out.
        clean_args = clean_args[1:]

    if not clean_args:
        if not is_json and sys.stdin.isatty():
            model_spec = _interactive_prompt(f"Enter model for {target_role or 'both tiers'} (e.g., 'gemini gemini-2.5-flash' or 'ollama qwen2.5:3b'):")
            if model_spec:
                clean_args = model_spec.split()

    if not clean_args:
        if not is_json:
            emit.error(f"Usage: /model {target_role} <provider> <model_name> or /model {target_role} <model_name>")
        return {"status": "error", "error": "missing_model_spec"}

    # ── Resolve provider and model ───────────────────────────────────
    if len(clean_args) >= 2 and clean_args[0].lower() in KNOWN_PROVIDERS:
        prov_hint = clean_args[0].lower()
        new_model = clean_args[1]
    else:
        new_model = clean_args[0]
        prov_hint = None
        if "/" in new_model:
            if any(kw in new_model for kw in ("llama", "mistral", "deepseek", "nemotron", "nvidia")):
                prov_hint = "nvidia"
        if prov_hint is None:
            if new_model.startswith("gpt-") or new_model.startswith("o1-"):
                prov_hint = "openai"
            elif new_model.startswith("claude-"):
                prov_hint = "anthropic"
            elif new_model.startswith("gemini-"):
                prov_hint = "gemini"

        if prov_hint is None:
            if not is_json and sys.stdin.isatty():
                ans = _interactive_prompt(f"Provider for '{new_model}' could not be determined. Enter provider (ollama, nvidia, openai, gemini, anthropic):")
                if ans.strip().lower() in KNOWN_PROVIDERS:
                    prov_hint = ans.strip().lower()

            if prov_hint is None:
                installed_ollama = {m["name"] for m in list_available_models() if m["provider"] == "ollama"}
                if new_model in installed_ollama:
                    prov_hint = "ollama"
                else:
                    if not is_json:
                        emit.warn(f"'{new_model}' is not an installed Ollama model and the provider could not be determined.")
                        emit.info(f"Specify the provider explicitly:  /model {f'{target_role} ' if target_role else ''}<provider> {new_model}")
                    return {"status": "error", "error": "ambiguous_provider", "model": new_model}

    # Validate that the target provider has credentials configured (unless it's ollama)
    if prov_hint != "ollama":
        api_keys = cfg.get("api_keys", {})
        legacy_key = cfg.get("api_key", "")
        has_key = bool(api_keys.get(prov_hint))
        if not has_key and legacy_key and legacy_key != "ollama":
            detected_prov, _ = detect_ai_config(legacy_key)
            if detected_prov == prov_hint:
                has_key = True
        env_map = {"nvidia": "NVIDIA_API_KEY", "openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
        if not has_key and os.environ.get(env_map.get(prov_hint, ""), ""):
            has_key = True
        if not has_key:
            if not is_json and sys.stdin.isatty():
                ans = _interactive_prompt(f"No API key configured for '{prov_hint}'. Enter API key now (blank to skip):")
                if ans.strip():
                    cfg.setdefault("api_keys", {})[prov_hint] = ans.strip()
                    if not cfg.get("api_key") or cfg.get("api_key") == "ollama":
                        cfg["api_key"] = ans.strip()
                        cfg["ai_provider"] = prov_hint
                    save_config(cfg)
                    has_key = True

            if not has_key:
                if not is_json:
                    emit.warn(f"No API key configured for provider '{prov_hint}'.")
                    emit.info(f"Set one first:  /model set-key {prov_hint} <your_api_key>")
                return {"status": "error", "error": "no_api_key", "provider": prov_hint}

    roles_to_update = [target_role] if target_role else ["orchestrator", "synthesizer"]

    for r in roles_to_update:
        session_context.setdefault("options", {})[f"{r}_model"] = new_model
        session_context.setdefault("options", {})[f"{r}_provider"] = prov_hint
        if not session_only:
            cfg[f"{r}_model"] = new_model
            cfg[f"{r}_provider"] = prov_hint

    # Also update legacy keys for general backward compatibility
    session_context.setdefault("options", {})["ai_model"] = new_model
    session_context.setdefault("options", {})["ai_provider"] = prov_hint
    if not session_only:
        cfg["ai_model"] = new_model
        cfg["ai_provider"] = prov_hint
        save_config(cfg)

    role_desc = f"{target_role.capitalize()}" if target_role else "Both Orchestrator & Synthesizer"
    if not is_json:
        emit.success(f"{role_desc} updated to: {new_model} (Provider: {prov_hint}) {'[Session Only]' if session_only else '[Persistent]'}")

    return {
        "status": "success",
        "role": target_role or "all",
        "model": new_model,
        "provider": prov_hint,
        "persisted": not session_only
    }


def handle_headers(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /headers [Key: Value | --clear]
    Inspects or manages global custom HTTP headers.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    opts = session_context.setdefault("options", {})
    from hellhound.core.http_utils import normalize_headers
    headers = normalize_headers(opts.get("global_headers"))
    opts["global_headers"] = headers

    if "--clear" in args:
        opts["global_headers"] = {}
        cfg = load_config()
        cfg["global_headers"] = {}
        save_config(cfg)
        if not is_json:
            emit.success("Global headers cleared.")
        return {"status": "success", "headers": {}}

    if not clean_args:
        cfg = load_config()
        handle = cfg.get("researcher_handle", "")
        if not is_json:
            if handle:
                emit.info(f"Researcher Handle (X-Bugbounty): {handle}")
            if headers:
                emit.info(f"Active Global Headers ({len(headers)}):")
                for k, v in headers.items():
                    emit(f"  {k}: {v}")
            elif not handle:
                emit.info("No custom global headers set.")
        
        # Interactive prompt for setting a header if in interactive terminal
        if not is_json and sys.stdin.isatty():
            new_header = _interactive_prompt("Enter a header to add in Header-Name: Value format (blank to skip):")
            if new_header:
                clean_args = [new_header]
            else:
                return {"status": "success", "headers": headers, "researcher_handle": handle}
        else:
            return {"status": "success", "headers": headers, "researcher_handle": handle}

    raw = " ".join(clean_args)
    if ":" in raw:
        k, v = raw.split(":", 1)
        headers[k.strip()] = v.strip()
        cfg = load_config()
        cfg["global_headers"] = headers
        save_config(cfg)
        if not is_json:
            emit.success(f"Header set: {k.strip()}: {v.strip()}")
        return {"status": "success", "headers": headers}
    else:
        # Check if interactive and prompt for value
        if not is_json and sys.stdin.isatty():
            header_name = raw.strip()
            header_val = _interactive_prompt(f"Enter the value for header '{header_name}':")
            if header_val:
                headers[header_name] = header_val
                cfg = load_config()
                cfg["global_headers"] = headers
                save_config(cfg)
                if not is_json:
                    emit.success(f"Header set: {header_name}: {header_val}")
                return {"status": "success", "headers": headers}

        msg = "Invalid header format. Use: /headers Header-Name: Value"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "message": msg}


def _mask_secret(secret: str) -> str:
    if not secret:
        return ""
    return secret[:6] + "..." + secret[-4:] if len(secret) > 14 else secret[:3] + "..."


# Every non-LLM tool that actually reads a key from tool_api_keys (see
# agent.py's _execute_wpscan_scan / _execute_virustotal_lookup /
# _execute_urlscan_recon) gets an entry here so `/apikey` with no args can
# show EVERY key the system knows how to use — set or not — plus where to
# get one. Without this, a researcher has no way to discover that
# virustotal_lookup/urlscan_recon even take a key short of reading the
# source; it looked like wpscan was the only tool this applied to.
# Update this alongside any new tool wired to read tool_api_keys.
KNOWN_TOOL_API_KEYS: Dict[str, str] = {
    "wpscan": "Free token: https://wpscan.com/api (sign up, then Profile -> API Token). Used by wpscan_scan for its vulnerability-database lookups.",
    "virustotal": "Free key: https://www.virustotal.com/gui/my-apikey. Used by virustotal_lookup for passive DNS/subdomain discovery.",
    "urlscan": "Free key: https://urlscan.io/user/signup (Settings -> API). Used by urlscan_recon for crawl-index search.",
}


def handle_apikey(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /apikey                        — list every tool this system knows how to use a key for (set or not), with a hint on where to get one
    /apikey <tool> <value>         — save/update an API key/token for ANY external tool, known or not
    /apikey <tool> --clear         — remove a saved key

    One persistent store for every non-LLM tool's key (wpscan, virustotal,
    urlscan, and anything added later) — separate from the LLM-provider
    api_keys used for the orchestrator/synthesizer themselves, and
    replacing the old per-tool '/model set-key <tool> <key>' convention
    (which still works as a fallback read, but isn't where new keys get
    written). 'tool' isn't restricted to KNOWN_TOOL_API_KEYS — any future
    tool_api_keys consumer works immediately with this same command, it
    just won't get a hint line until it's added to that table.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    cfg = load_config()
    tool_keys = cfg.get("tool_api_keys")
    if not isinstance(tool_keys, dict):
        tool_keys = {}

    if not clean_args:
        if not is_json:
            emit.info("API keys for external tools (/apikey <tool> <value> to set, /apikey <tool> --clear to remove):")
            all_names = sorted(set(KNOWN_TOOL_API_KEYS) | set(tool_keys))
            for name in all_names:
                if name in tool_keys and tool_keys[name]:
                    emit(f"  [set]   {name}: {_mask_secret(str(tool_keys[name]))}")
                else:
                    hint = KNOWN_TOOL_API_KEYS.get(name, "")
                    emit(f"  [unset] {name}" + (f" — {hint}" if hint else ""))
            if not all_names:
                emit.info("Nothing configured yet. e.g. /apikey wpscan <token>")
        return {
            "status": "success",
            "tool_api_keys": {k: _mask_secret(str(v)) for k, v in tool_keys.items() if v},
            "known_tools": KNOWN_TOOL_API_KEYS,
        }

    tool_name = clean_args[0].strip().lower()
    if len(clean_args) == 1:
        hint = KNOWN_TOOL_API_KEYS.get(tool_name, "")
        msg = f"No value given. Usage: /apikey {tool_name} <value>  or  /apikey {tool_name} --clear"
        if hint:
            msg += f"\n{hint}"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "message": msg}

    if clean_args[1] in ("--clear", "-c", "clear"):
        tool_keys.pop(tool_name, None)
        cfg["tool_api_keys"] = tool_keys
        save_config(cfg)
        if not is_json:
            emit.success(f"Cleared the saved API key for '{tool_name}'.")
        return {"status": "success", "tool": tool_name, "cleared": True}

    value = " ".join(clean_args[1:]).strip()
    tool_keys[tool_name] = value
    cfg["tool_api_keys"] = tool_keys
    save_config(cfg)
    if not is_json:
        emit.success(f"Saved API key for '{tool_name}': {_mask_secret(value)} — every future target will use it automatically.")
    return {"status": "success", "tool": tool_name, "key_masked": _mask_secret(value)}


def handle_mcp(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /mcp                            — show Burp/Caido configuration + live status
    /mcp burp [host_or_url]          — configure Burp's MCP server (auto-detects transport; default http://127.0.0.1:9876)
    /mcp burp remove                — remove the Burp entry from config
    /mcp caido [url]                — configure Caido via caido-mcp-server (stdio MCP, 66 tools) if it's on PATH,
                                       otherwise falls back to the old direct-GraphQL integration (3 tools)
    /mcp caido graphql [url] [token] — force the direct-GraphQL path even if caido-mcp-server is installed
    /mcp caido token [token]        — update just the GraphQL access token (for the weekly 7-day refresh)
    /mcp caido remove               — remove the Caido entry from config (either integration)
    /mcp test                       — re-test whatever's currently configured, without changing it

    Writes directly into ~/.hellhound/config.json via load_config()/save_config()
    (a plain read-modify-write of the whole file, so any other keys already in
    there — ai_provider, api_keys, scope, etc. — are preserved untouched) so a
    researcher never has to hand-edit JSON to wire up Burp or Caido. Every
    subcommand that changes something also tries connecting immediately and
    reports what it found, rather than leaving that to be discovered on the
    next session start.

    Caido has TWO integrations now. The preferred one is `c0tton-fluff`'s
    third-party caido-mcp-server (https://github.com/c0tton-fluff/caido-mcp-server)
    — a real stdio MCP server with proper OAuth auth and 66 tools/6 resources,
    vastly more capable than bounty-hunter's original hand-rolled GraphQL
    wrapper (3 tools, manual 7-day token refresh). If the `caido-mcp-server`
    binary is found on PATH, `/mcp caido [url]` configures and uses it
    automatically; the old GraphQL path is kept as a fallback (and reachable
    explicitly via `/mcp caido graphql`) for anyone who hasn't installed it.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]
    cfg = load_config()

    def _test_burp(server_cfg: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from hellhound.core.mcp_bridge import MCPBridge
        except ImportError:
            return {"ok": False, "error": "The 'mcp' Python package is not installed (pip install mcp)."}
        bridge = MCPBridge("burp", server_cfg)
        ok = bridge.start(timeout=8.0)
        tool_names = [t.name for t in bridge.tools] if ok else []
        bridge.stop()
        return {"ok": ok, "error": bridge.error, "tools": tool_names}

    def _test_caido(caido_cfg: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from hellhound.core.caido_bridge import CaidoClient, CaidoConfig
        except ImportError:
            return {"ok": False, "error": "The 'requests' package is not installed."}
        client = CaidoClient(CaidoConfig(
            url=caido_cfg.get("url") or "http://localhost:8080/graphql",
            token=caido_cfg.get("token"),
            verify_tls=caido_cfg.get("verify_tls", True),
        ))
        ok = client.ping()
        return {"ok": ok, "error": client.last_error}

    def _test_caido_mcp(server_cfg: Dict[str, Any]) -> Dict[str, Any]:
        # caido-mcp-server spawns its own subprocess (stdio) and, on first
        # use, loads the OAuth session caido-mcp-server login stored on
        # disk — there's no token to pass here, which is the whole point
        # of switching to it. A longer timeout than Burp's HTTP probe
        # because process startup + session load is slower than an HTTP
        # round-trip.
        try:
            from hellhound.core.mcp_bridge import MCPBridge
        except ImportError:
            return {"ok": False, "error": "The 'mcp' Python package is not installed (pip install mcp)."}
        bridge = MCPBridge("caido", server_cfg)
        ok = bridge.start(timeout=15.0)
        tool_names = [t.name for t in bridge.tools] if ok else []
        err = bridge.error
        bridge.stop()
        if not ok and err and "command" not in (err or "").lower():
            err = (
                f"{err} — if you haven't yet, run: CAIDO_URL={server_cfg.get('env', {}).get('CAIDO_URL', 'http://localhost:8080')} "
                f"caido-mcp-server login"
            )
        return {"ok": ok, "error": err, "tools": tool_names}

    # ── /mcp test — re-check current config without changing it ──────────
    if clean_args and clean_args[0].lower() == "test":
        result: Dict[str, Any] = {"status": "success"}
        burp_cfg = (cfg.get("mcp_servers") or {}).get("burp")
        if burp_cfg:
            r = _test_burp(burp_cfg)
            result["burp"] = r
            if not is_json:
                if r["ok"]:
                    emit.success(f"Burp ({burp_cfg.get('url')}) — still solid, {len(r['tools'])} tool(s): {', '.join(r['tools']) or '(none exposed)'}")
                else:
                    emit.warn(f"Burp ({burp_cfg.get('url')}) — not talking to me: {r['error']}")
        else:
            if not is_json:
                emit.info("Burp is not configured. Use: /mcp burp [host_or_url]")
        caido_mcp_cfg = (cfg.get("mcp_servers") or {}).get("caido")
        caido_cfg = cfg.get("caido")
        if caido_mcp_cfg:
            r = _test_caido_mcp(caido_mcp_cfg)
            result["caido"] = r
            if not is_json:
                if r["ok"]:
                    emit.success(f"Caido (caido-mcp-server) — still solid, {len(r['tools'])} tool(s) available.")
                else:
                    emit.warn(f"Caido (caido-mcp-server) — not talking to me: {r['error']}")
        elif caido_cfg:
            r = _test_caido(caido_cfg)
            result["caido"] = r
            if not is_json:
                if r["ok"]:
                    emit.success(f"Caido ({caido_cfg.get('url')}) — still solid.")
                else:
                    emit.warn(f"Caido ({caido_cfg.get('url')}) — not talking to me: {r['error']}")
        else:
            if not is_json:
                emit.info("Caido is not configured. Use: /mcp caido [url]")
        return result

    # ── /mcp burp [url] | /mcp burp remove ────────────────────────────────
    if clean_args and clean_args[0].lower() == "burp":
        sub = clean_args[1:]
        if sub and sub[0].lower() == "remove":
            if "mcp_servers" in cfg and "burp" in cfg["mcp_servers"]:
                del cfg["mcp_servers"]["burp"]
                save_config(cfg)
                if not is_json:
                    emit.success("Burp removed from config.")
                return {"status": "success", "removed": "burp"}
            if not is_json:
                emit.info("Burp wasn't configured.")
            return {"status": "success", "removed": None}

        url = sub[0] if sub else ""
        if not url:
            if not is_json and sys.stdin.isatty():
                url = _interactive_prompt(
                    "Burp's MCP tab -> \"Server host\" / \"Server port\" (default http://127.0.0.1:9876):"
                ) or "http://127.0.0.1:9876"
            else:
                url = "http://127.0.0.1:9876"
        if not url.startswith("http"):
            url = "http://" + url

        # Burp ships TWO different MCP implementations depending on version
        # — the older standalone PortSwigger extension JAR, which speaks
        # legacy SSE at a /sse sub-path, and recent Burp's native MCP tab
        # (Dashboard... > MCP), which speaks the newer Streamable HTTP
        # transport, usually at /mcp. Pointing bounty-hunter at the wrong
        # one produces a plain 404 that gives no hint which transport is
        # actually right — so rather than hardcode a guess, probe every
        # plausible transport/path combination against whatever host:port
        # was given and use whichever one actually completes a real MCP
        # handshake. A researcher just pastes what Burp's own settings tab
        # shows them; this figures out the rest.
        try:
            from hellhound.core.mcp_bridge import probe_http_mcp_server
        except ImportError:
            probe_http_mcp_server = None

        if not is_json:
            emit.info(f"Probing {url} for Burp's MCP transport (tries Streamable HTTP, then legacy SSE)...")
        resolved = probe_http_mcp_server(url) if probe_http_mcp_server else None

        if resolved:
            cfg.setdefault("mcp_servers", {})["burp"] = resolved
            save_config(cfg)
            r = _test_burp(cfg["mcp_servers"]["burp"])
            if not is_json:
                emit.success(
                    f"Found Burp via {resolved['transport']} at {resolved['url']} — "
                    f"{len(r['tools'])} tool(s) I can use now: {', '.join(r['tools']) or '(none exposed)'}"
                )
            return {"status": "success", "burp": cfg["mcp_servers"]["burp"], "test": r}

        # Nothing worked — save the sse+/sse guess anyway (so /mcp test can
        # be re-run after fixing whatever's wrong without retyping the
        # URL), but be explicit that none of the probed combinations
        # actually answered.
        cfg.setdefault("mcp_servers", {})["burp"] = {"transport": "sse", "url": url.rstrip("/") + "/sse"}
        save_config(cfg)
        if not is_json:
            emit.warn(f"Saved {url}, but nothing answered there on any transport I know — Burp's not talking to me yet.")
            emit.info(
                "Check: the MCP tab's \"Enabled\" toggle is on AND its status indicator "
                "(bottom-right of that tab) doesn't still say \"Disabled\" — the toggle and the "
                "indicator are separate controls, and the indicator is the one that reflects "
                "whether the listener has actually started. Also confirm the host/port match "
                "what's shown in Burp's \"Advanced Options\". Then run /mcp test."
            )
        return {"status": "success", "burp": cfg["mcp_servers"]["burp"], "test": {"ok": False, "error": "no transport answered"}}

    # ── /mcp caido [url] | /mcp caido graphql [url] [token] | /mcp caido token [token] | /mcp caido remove ──
    if clean_args and clean_args[0].lower() == "caido":
        sub = clean_args[1:]
        if sub and sub[0].lower() == "remove":
            removed = []
            if "mcp_servers" in cfg and "caido" in cfg["mcp_servers"]:
                del cfg["mcp_servers"]["caido"]
                removed.append("caido-mcp-server")
            if "caido" in cfg:
                del cfg["caido"]
                removed.append("graphql")
            if removed:
                save_config(cfg)
                if not is_json:
                    emit.success(f"Caido removed from config ({', '.join(removed)}).")
                return {"status": "success", "removed": removed}
            if not is_json:
                emit.info("Caido wasn't configured.")
            return {"status": "success", "removed": None}

        # ── caido-mcp-server detection ───────────────────────────────────
        # If the user has c0tton-fluff/caido-mcp-server on PATH, it's the
        # better integration by a wide margin — a real stdio MCP server
        # with proper OAuth (no manual 7-day token refresh) and ~66 tools
        # vs. our original 3 hand-rolled GraphQL ones. Prefer it unless
        # the user explicitly asks for the old GraphQL path via
        # `/mcp caido graphql ...`, or the binary just isn't installed.
        import shutil as _shutil
        force_graphql = bool(sub and sub[0].lower() == "graphql")
        if force_graphql:
            sub = sub[1:]
        caido_mcp_binary = None if force_graphql else _shutil.which("caido-mcp-server")

        if caido_mcp_binary and not (sub and sub[0].lower() == "token"):
            url = sub[0] if sub else ((cfg.get("mcp_servers") or {}).get("caido", {}).get("env", {}).get("CAIDO_URL")) or "http://localhost:8080"
            if not url.startswith("http"):
                url = "http://" + url
            server_cfg = {
                "transport": "stdio",
                "command": caido_mcp_binary,
                "args": ["serve"],
                "env": {"CAIDO_URL": url},
            }
            cfg.setdefault("mcp_servers", {})["caido"] = server_cfg
            # the old GraphQL entry, if any, would otherwise shadow this
            # one in status displays and /mcp test's "prefer mcp_servers"
            # check only looks at one or the other per-feature, not both —
            # drop it so there's one source of truth for where Caido's
            # config lives.
            cfg.pop("caido", None)
            save_config(cfg)
            if not is_json:
                emit.info(f"Found caido-mcp-server on your PATH — ditching the old GraphQL wrapper for it. Testing {url} ...")
            r = _test_caido_mcp(server_cfg)
            if not is_json:
                if r["ok"]:
                    emit.success(f"Caido's wired up via caido-mcp-server — {len(r['tools'])} tool(s) I can use now.")
                else:
                    emit.warn(f"Saved it, but Caido's not talking to me yet: {r['error']}")
                    emit.info(
                        f"First time using caido-mcp-server against this Caido instance? Run: "
                        f"CAIDO_URL={url} caido-mcp-server login  — it opens a browser consent flow once, "
                        f"then `serve` reuses that session."
                    )
            return {"status": "success", "caido": server_cfg, "test": r}

        if not is_json and caido_mcp_binary is None and not force_graphql:
            emit.info(
                "caido-mcp-server not found on PATH — using the built-in GraphQL integration (3 tools) instead. "
                "For the fuller integration (66 tools, OAuth): "
                "curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/caido-mcp-server/main/install.sh | bash"
            )

        existing = cfg.get("caido") or {}

        if sub and sub[0].lower() == "token":
            token = sub[1] if len(sub) >= 2 else ""
            if not token:
                if not is_json and sys.stdin.isatty():
                    try:
                        import getpass
                        token = getpass.getpass(
                            "New Caido access token (devtools console: "
                            "JSON.parse(localStorage.CAIDO_AUTHENTICATION).accessToken) — hidden while typing: "
                        ).strip()
                    except Exception:
                        token = _interactive_prompt("New Caido access token:")
            if not token:
                if not is_json:
                    emit.warn("No token given. Usage: /mcp caido token <token>")
                return {"status": "error", "error": "missing_token"}
            url = existing.get("url") or "http://localhost:8080/graphql"
            cfg["caido"] = {**existing, "url": url, "token": token}
        else:
            url = sub[0] if sub else (existing.get("url") or "")
            token = sub[1] if len(sub) >= 2 else ""
            if not url:
                if not is_json and sys.stdin.isatty():
                    url = _interactive_prompt("Caido GraphQL URL (default http://localhost:8080/graphql):") or "http://localhost:8080/graphql"
                else:
                    url = "http://localhost:8080/graphql"
            if not token:
                token = existing.get("token", "")
                if not token and not is_json and sys.stdin.isatty():
                    try:
                        import getpass
                        token = getpass.getpass(
                            "Caido access token (devtools console: "
                            "JSON.parse(localStorage.CAIDO_AUTHENTICATION).accessToken) — hidden while typing: "
                        ).strip()
                    except Exception:
                        token = _interactive_prompt("Caido access token:")
            if not token:
                if not is_json:
                    emit.warn("No token given. Usage: /mcp caido <url> <token>")
                return {"status": "error", "error": "missing_token"}
            cfg["caido"] = {"url": url, "token": token}

        save_config(cfg)
        if not is_json:
            emit.info(f"Saved. Testing connection to {cfg['caido']['url']} ...")
        r = _test_caido(cfg["caido"])
        if not is_json:
            if r["ok"]:
                emit.success("Good, Caido's talking to me.")
            else:
                emit.warn(f"Saved it, but Caido's not talking to me yet: {r['error']}")
                emit.info("Caido access tokens expire after 7 days — if it worked before and stopped, grab a fresh one and run /mcp caido token <token>.")
        return {"status": "success", "caido": {"url": cfg["caido"]["url"], "token": _mask_secret(cfg["caido"]["token"])}, "test": r}

    # ── No args: status overview ───────────────────────────────────────────
    burp_cfg = (cfg.get("mcp_servers") or {}).get("burp")
    caido_mcp_cfg = (cfg.get("mcp_servers") or {}).get("caido")
    caido_cfg = cfg.get("caido")
    if not is_json:
        emit.banner("MCP / INTEGRATIONS")
        if burp_cfg:
            emit.info(f"Burp:  configured — {burp_cfg.get('url')}")
        else:
            emit.info("Burp:  not configured")
        if caido_mcp_cfg:
            emit.info(f"Caido: configured — caido-mcp-server (stdio, {caido_mcp_cfg.get('env', {}).get('CAIDO_URL', '?')})")
        elif caido_cfg:
            emit.info(f"Caido: configured — GraphQL direct, {caido_cfg.get('url')} (token {_mask_secret(caido_cfg.get('token', ''))})")
        else:
            emit.info("Caido: not configured")
        emit("")
        emit.info("Configure:  /mcp burp [host_or_url]    (auto-detects transport; default http://127.0.0.1:9876)")
        emit.info("            /mcp caido [url]           (uses caido-mcp-server if installed, else GraphQL; default http://localhost:8080)")
        emit.info("Force the old GraphQL path:  /mcp caido graphql [url] [token]")
        emit.info("Refresh Caido's GraphQL token:  /mcp caido token <token>")
        emit.info("Test current config:    /mcp test")
        emit.info("Remove:                 /mcp burp remove  |  /mcp caido remove")
    return {
        "status": "success",
        "burp": burp_cfg,
        "caido": (
            caido_mcp_cfg
            if caido_mcp_cfg
            else ({"url": caido_cfg.get("url"), "token": _mask_secret(caido_cfg.get("token", ""))} if caido_cfg else None)
        ),
    }


def handle_output(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /output [stderr] [N]
    Shows the FULL captured output of the last long-running tool call for
    the active target (ffuf, feroxbuster, run_terminal_command, etc.) —
    the terminal only ever streams a capped live feed of hits as a tool
    runs (so it doesn't flood the scrollback), this pulls the complete
    stdout/stderr of whichever one ran last. Held in memory only for the
    current session (target.state["_last_tool_output"], set by
    _run_cmd_with_heartbeat) — nothing is written to disk for this, and it
    only ever holds the single most recent run; it's gone once a
    different tool runs or the session ends.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a != "--json"]

    want_stderr = False
    tail_n = None
    for a in clean_args:
        if a.lower() == "stderr":
            want_stderr = True
        elif a.isdigit():
            tail_n = int(a)

    target_name = session_context.get("target") or "default"
    agent = get_agent(target_name)
    last = (agent.target.state or {}).get("_last_tool_output") if hasattr(agent.target, "state") else None

    if not last:
        if not is_json:
            emit.info("No tool output captured yet for this target this session — run a fuzzer or terminal command first.")
        return {"status": "empty"}

    stream_key = "stderr" if want_stderr else "stdout"
    text = last.get(stream_key, "") or ""
    truncated = bool(last.get(f"{stream_key}_truncated"))

    if tail_n:
        lines = text.splitlines()
        text = "\n".join(lines[-tail_n:])

    if is_json:
        return {
            "status": "success",
            "label": last.get("label"),
            "cmd": last.get("cmd"),
            "returncode": last.get("returncode"),
            "stream": stream_key,
            "output": text,
            "truncated_in_memory": truncated,
        }

    age_s = int(time.time() - last.get("ts", time.time()))
    emit.info(f"Last tool: [bold cyan]{last.get('label')}[/bold cyan]  (exit {last.get('returncode')}, {age_s}s ago)")
    emit.info(f"Command: {last.get('cmd')}")
    if truncated:
        emit.warn(f"{stream_key} was longer than the in-memory cap — showing the last portion kept, not the absolute start of the run.")
    dump = text if text.strip() else "(empty)"
    # print_always exists on PlainEmit/ConsoleEmit but NOT on a raw
    # ThinkingIndicator (the actual `emit` the main interactive REPL passes
    # into dispatch()) -- fall back to a direct stdout write rather than
    # routing a multi-line raw dump through info()/print_step(), which
    # prefixes every call with a single icon and tree-branch glyph meant
    # for one-line status messages, not a wall of tool output.
    printer = getattr(emit, "print_always", None)
    if callable(printer):
        printer(dump)
    else:
        try:
            sys.stdout.write(dump + "\n")
            sys.stdout.flush()
        except Exception:
            pass
    return {"status": "success", "label": last.get("label"), "stream": stream_key, "chars": len(text)}


def handle_target(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /target [domain_or_name] [--clear-history]
    Switch or display the current active target for the session.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clear_history = "--clear-history" in args or "--reset" in args
    clean_args = [a for a in args if a not in ("--json", "-j", "--clear-history", "--reset")]

    # ── --clear-history: wipe this target's saved conversation turns ──
    # self.history is loaded straight from target.state["history"] on
    # every Agent init (see agent.py) — it's NOT reset by restarting the
    # process, switching models, or editing any persona/system-prompt
    # file. A stale turn sitting in there (e.g. the model having already
    # answered a question a prior persona build got wrong) keeps getting
    # fed back as conversation context forever, silently outweighing a
    # freshly corrected system prompt. This is the way to actually clear
    # that out for one target without renaming/abandoning it.
    if clear_history:
        target_name_for_clear = (clean_args[0].strip().lower() if clean_args else session_context.get("target", "default"))
        if target_name_for_clear.startswith(("http://", "https://")):
            target_name_for_clear = urlparse(target_name_for_clear).netloc.split(":")[0]
        target_obj = create_or_load_target(target_name_for_clear)
        prior_len = len(target_obj.state.get("history") or [])
        target_obj.state["history"] = []
        save_target(target_obj)
        if not is_json:
            emit.success(f"Cleared {prior_len} saved conversation turn(s) for target '{target_name_for_clear}'. Next message starts with a clean slate.")
        if not clean_args:
            return {"status": "success", "target": target_name_for_clear, "history_cleared": prior_len}

    if not clean_args:
        current_target = session_context.get("target", "default")
        if not is_json:
            emit.info(f"Active session target: [bold cyan]{current_target}[/bold cyan]")
            emit.info("To switch target: /target <domain_or_name>")
            emit.info("To wipe saved chat history for this target: /target --clear-history")
        return {"status": "success", "target": current_target}

    new_target_name = clean_args[0].strip().lower()
    if new_target_name.startswith(("http://", "https://")):
        new_target_name = urlparse(new_target_name).netloc.split(":")[0]

    session_context["target"] = new_target_name
    target_obj = create_or_load_target(new_target_name)
    session_context["scope_rules"] = target_obj.scope_rules

    if not is_json:
        emit.success(f"Active target switched to: [bold cyan]{new_target_name}[/bold cyan]")
        if target_obj.scope_rules.in_scope:
            emit.info(f"In-Scope Target(s): {', '.join(target_obj.scope_rules.in_scope)}")
        # If this target belongs to a program (set up via the manage_program
        # tool / an in-chat request to group a bug-bounty program's several
        # in-scope domains), surface that here too, so switching between a
        # program's domains makes the grouping visible rather than looking
        # like a set of unrelated flat targets.
        if getattr(target_obj, "program", ""):
            try:
                sibling_domains = list_program_targets(target_obj.program)
            except Exception:
                sibling_domains = []
            others = [d for d in sibling_domains if d != new_target_name]
            if others:
                emit.info(f"Part of program '{target_obj.program}' — other in-scope domain(s): {', '.join(others)}")

    return {
        "status": "success",
        "target": new_target_name,
        "program": getattr(target_obj, "program", ""),
        "scope_rules": target_obj.scope_rules.to_dict()
    }


def handle_report(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /report [--format html|json] [--output path]
    Generates a consolidated bug bounty reconnaissance report from target findings.
    """
    is_json = "--json" in args or "--format=json" in args
    target_name = session_context.get("target", "default")
    target_obj = create_or_load_target(target_name)

    results = session_context.get("results", {})
    report_data = {
        "target": target_obj.name,
        "created_at": target_obj.created_at,
        "last_active": target_obj.last_active,
        "scope": target_obj.scope_rules.to_dict(),
        "findings": target_obj.findings,
        "modules_executed": list(results.keys()),
    }

    if not is_json:
        emit.banner(f"HELLHOUND REPORT: {target_obj.name}")
        emit.info(f"Verified Findings: {len(target_obj.findings)}")
        for idx, f in enumerate(target_obj.findings, 1):
            emit(f"  [{idx}] {f.get('type', 'Finding')} - {f.get('target', '')} ({f.get('severity', 'INFO')})")

    return {
        "status": "success",
        "target": target_obj.name,
        "report": report_data
    }


def handle_update(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /update [source|deps|tools]

    One unified command that updates EVERYTHING Hellhound depends on, in
    one call, instead of a researcher needing to separately remember
    `git pull`, re-run install.sh, and re-run `pdtm -i` for each binary.
    Three independent stages — a bare `/update` runs all three; passing
    one of `source`, `deps`, or `tools` runs only that stage:

      source  — git-pulls the Hellhound checkout itself (skipped with a
                clear note if this isn't a git clone)
      deps    — re-syncs this install's Python packages against
                requirements.txt (catches drift like a package that's in
                requirements.txt but was never in setup.py's own list —
                lxml and cryptography, historically — which is exactly
                why one researcher's spider crawl can fail with missing
                parser errors while another's doesn't, on the same code)
      tools   — updates every ALREADY-INSTALLED external binary (PD
                suite via `pdtm -ua`, plus the standalone Go/pip tools)
                to its latest version; tools with no single safe
                update command (nmap, feroxbuster, sqlmap via apt) are
                listed, not silently skipped

    This never installs a tool that isn't already present — that's
    `/setup tools install-all`. This only updates what's already there.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]
    stage = clean_args[0].lower() if clean_args else "all"
    valid_stages = {"all", "source", "deps", "tools"}
    if stage not in valid_stages:
        msg = f"Unknown stage '{stage}'. Usage: /update [source|deps|tools]"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "error": "invalid_stage", "message": msg}

    if not is_json:
        emit.banner("HELLHOUND UNIFIED UPDATE")

    result: Dict[str, Any] = {}

    if stage in ("all", "source"):
        if not is_json:
            emit("\n[bold red]─── SOURCE ───[/bold red]")
        result["source"] = update_hellhound_source(emit=(None if is_json else emit))
        if is_json is False and result["source"].get("skipped"):
            emit.info(f"[*] Skipped: {result['source']['reason']}")

    if stage in ("all", "deps"):
        if not is_json:
            emit("\n[bold red]─── PYTHON DEPENDENCIES ───[/bold red]")
        result["deps"] = sync_python_dependencies(emit=(None if is_json else emit))

    if stage in ("all", "tools"):
        if not is_json:
            emit("\n[bold red]─── EXTERNAL TOOLS ───[/bold red]")
        result["tools"] = update_all_tools(emit=(None if is_json else emit))

    if not is_json:
        emit("")
        src = result.get("source")
        if src is not None:
            if src.get("skipped"):
                emit.info(f"Source:  not a git checkout — {src.get('reason', '')}")
            elif src.get("ok"):
                emit.success("Source:  up to date" if src.get("already_up_to_date") else "Source:  updated")
            else:
                emit.warn("Source:  update failed — see above")
        deps = result.get("deps")
        if deps is not None:
            emit.success("Deps:    synced") if deps.get("ok") else emit.warn("Deps:    sync failed — see above")
        tools = result.get("tools")
        if tools is not None:
            updated_other = sum(1 for v in tools.get("other", {}).values() if v)
            total_other = len(tools.get("other", {}))
            pdtm_info = tools.get("pdtm")
            pdtm_str = "updated" if (pdtm_info and pdtm_info.get("ok")) else ("not run — pdtm missing" if pdtm_info is None else "failed")
            emit.success(f"Tools:   PD suite {pdtm_str}; {updated_other}/{total_other} standalone tool(s) updated")
            if tools.get("skipped"):
                emit.info(f"         Skipped (no single update command): {', '.join(s.split(' ')[0] for s in tools['skipped'])}")
        emit.success("\nUpdate complete.")

    return {"status": "success", **result}


def handle_setup(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /setup [tools [auto-install on|off]]
    Interactive or automated environment, AI connectivity, and binary tool availability verification.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]
    cfg = load_config()

    # ── Subcommands: /setup tools auto-install on|off or /setup auto-install on|off ──
    if clean_args:
        first = clean_args[0].lower()
        if first in ("auto-install", "autoinstall") or (first == "tools" and len(clean_args) > 1 and clean_args[1].lower() in ("auto-install", "autoinstall")):
            action = clean_args[-1].lower()
            known_actions = {"on", "true", "1", "enable", "enabled", "off", "false", "0", "disable", "disabled"}
            if action not in known_actions and not is_json and sys.stdin.isatty():
                ans = _interactive_prompt("Enable tool auto-installation? (y/n)")
                action = "on" if ans.lower() in ("y", "yes") else "off"

            if action in ("on", "true", "1", "enable", "enabled"):
                cfg["auto_install_missing_tools"] = True
                save_config(cfg)
                if not is_json:
                    emit.success("Tool auto-installation ENABLED. Missing tools will be installed automatically during execution.")
                return {"status": "success", "auto_install_missing_tools": True}
            elif action in ("off", "false", "0", "disable", "disabled"):
                cfg["auto_install_missing_tools"] = False
                save_config(cfg)
                if not is_json:
                    emit.success("Tool auto-installation DISABLED. Missing tools will prompt with manual installation instructions.")
                return {"status": "success", "auto_install_missing_tools": False}
            else:
                if not is_json:
                    emit.warn("Usage: /setup tools auto-install [on|off]")
                return {"status": "error", "error": "invalid_option", "message": "Usage: /setup tools auto-install [on|off]"}

        if first in ("recaps", "recap"):
            action = clean_args[-1].lower()
            if action in ("on", "true", "1", "enable", "enabled"):
                cfg["show_recaps"] = True
                save_config(cfg)
                if not is_json:
                    emit.success("Recap footers ENABLED.")
                return {"status": "success", "show_recaps": True}
            elif action in ("off", "false", "0", "disable", "disabled"):
                cfg["show_recaps"] = False
                save_config(cfg)
                if not is_json:
                    emit.success("Recap footers DISABLED.")
                return {"status": "success", "show_recaps": False}
            else:
                if not is_json:
                    emit.warn("Usage: /setup recaps [on|off]")
                return {"status": "error", "error": "invalid_option", "message": "Usage: /setup recaps [on|off]"}

        if first in ("max-iterations", "max-iter", "iterations"):
            if len(clean_args) < 2:
                current = int(cfg.get("max_agent_iterations", 60))
                if not is_json:
                    emit.info(f"Max tool-call iterations per turn: {current}")
                    emit.info("Set with: /setup max-iterations <n>")
                return {"status": "success", "max_agent_iterations": current}
            try:
                n = max(1, min(500, int(clean_args[1])))
            except ValueError:
                if not is_json:
                    emit.warn("Usage: /setup max-iterations <positive integer>")
                return {"status": "error", "error": "invalid_option"}
            cfg["max_agent_iterations"] = n
            save_config(cfg)
            if not is_json:
                emit.success(f"Max tool-call iterations per turn set to {n}.")
            return {"status": "success", "max_agent_iterations": n}

        # ── Subcommand: /setup set-key [<provider> <api_key>] ──────
        # Recon/OSINT tool keys (urlscan, virustotal) — NOT the same list
        # as /model set-key, which is for LLM providers only.
        if first in ("set-key", "setkey", "keys"):
            provider = clean_args[1].lower() if len(clean_args) >= 2 else ""
            key = clean_args[2] if len(clean_args) >= 3 else ""

            if not provider and not is_json and sys.stdin.isatty():
                names = ", ".join(RECON_API_KEY_INFO.keys())
                provider = _interactive_prompt(f"Which tool's key? ({names}):").lower()
            if provider not in RECON_API_KEY_INFO:
                if not is_json:
                    emit.error(f"Unknown recon tool '{provider}'. Use: {', '.join(RECON_API_KEY_INFO.keys())}")
                    emit.info("Usage: /setup set-key <tool> <api_key>")
                return {"status": "error", "error": "unknown_provider", "provider": provider}

            if not key and not is_json and sys.stdin.isatty():
                info = RECON_API_KEY_INFO[provider]
                emit.info(f"Don't have one? Get it at: {info['signup_url']}  ({info['where']})")
                key = _interactive_prompt(f"Enter API key for {info['label']}:")
            if not key:
                if not is_json:
                    emit.error("Usage: /setup set-key <tool> <api_key>")
                return {"status": "error", "error": "usage"}

            cfg.setdefault("api_keys", {})[provider] = key
            save_config(cfg)
            if not is_json:
                masked = key[:6] + "..." + key[-4:] if len(key) > 14 else key[:3] + "..."
                emit.success(f"API key saved for {RECON_API_KEY_INFO[provider]['label']} ({masked}). {RECON_API_KEY_INFO[provider]['used_by']} will pick it up automatically.")
            return {"status": "success", "provider": provider}

        if first in ("install-all", "install") or (first == "tools" and len(clean_args) > 1 and clean_args[1].lower() in ("install-all", "install")):
            tool_status = check_all_tools()
            missing_pd = tool_status.get("missing_pd", [])
            missing_other = tool_status.get("missing_other", [])
            if not missing_pd and not missing_other:
                if not is_json:
                    emit.success("All binary tools are already installed.")
                return {"status": "success", "message": "All tools already installed"}

            if not is_json:
                emit.banner("INSTALLING MISSING TOOLS")
            for t in missing_pd + missing_other:
                ok = try_install(t, emit=emit)
                if not is_json:
                    if ok:
                        emit.success(f"[✓] {t} installed.")
                    else:
                        emit.warn(f"[✗] {t} still missing — see the error above (or install it manually).")
            tool_status = check_all_tools()
            if not is_json:
                emit.success(f"Installation complete. Installed {tool_status['installed_count']}/{tool_status['total_tools']} tools.")
            return {"status": "success", "tools": tool_status}

    # ── Full Environment & Tool Status Check ───────────────────────
    ollama_ok = ping_ollama()
    models = list_available_models()
    nv_key = os.environ.get("NVIDIA_API_KEY") or (cfg.get("api_keys", {}).get("nvidia") if isinstance(cfg.get("api_keys"), dict) else "") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("nvapi-") else "")
    gemini_key = os.environ.get("GEMINI_API_KEY") or (cfg.get("api_keys", {}).get("gemini") if isinstance(cfg.get("api_keys"), dict) else "") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("AIza") else "")
    openai_key = os.environ.get("OPENAI_API_KEY") or (cfg.get("api_keys", {}).get("openai") if isinstance(cfg.get("api_keys"), dict) else "") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("sk-") and not str(cfg.get("api_key", "")).startswith("sk-ant-") else "")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY") or (cfg.get("api_keys", {}).get("anthropic") if isinstance(cfg.get("api_keys"), dict) else "") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("sk-ant-") else "")

    tool_status = check_all_tools()
    wordlist_status = check_wordlists()
    auto_install_enabled = bool(cfg.get("auto_install_missing_tools", False))

    status = {
        "ollama_connected": ollama_ok,
        "researcher_handle": cfg.get("researcher_handle", ""),
        "active_model": cfg.get("ai_model", ""),
        "active_provider": cfg.get("ai_provider", "ollama"),
        "available_models_count": len(models),
        "auto_install_missing_tools": auto_install_enabled,
        "providers": {
            "ollama": ollama_ok,
            "nvidia": bool(nv_key),
            "gemini": bool(gemini_key),
            "openai": bool(openai_key),
            "anthropic": bool(anthropic_key)
        },
        "tools": tool_status,
        "wordlists": wordlist_status
    }

    if not is_json:
        emit.banner("HELLHOUND ENVIRONMENT & TOOL STATUS")
        emit(f"  Local Ollama: {'[bold green][✓] Connected[/bold green]' if ollama_ok else '[bold red][✗] Offline[/bold red]'}")
        emit(f"  Researcher Handle: {status['researcher_handle'] or '(not set)'} [dim](Set with: /handle <name>)[/dim]")
        emit(f"  Active Model: {status['active_model'] or '(dynamic default)'} (Provider: {status['active_provider']}) [dim](Set with: /model [orchestrator|synthesizer|both] <provider> <model-id>)[/dim]")
        emit(f"  Configured AI Providers: [dim](Set with: /model set-key <provider> <key>)[/dim]")
        for prov, has_key in status["providers"].items():
            state_str = "[bold green]Configured[/bold green]" if has_key else "[dim]Not Set[/dim]"
            emit(f"    - {prov.upper()}: {state_str}")

        emit("\n  Binary Recon Dependencies:")
        for tool_name, info in tool_status["tools"].items():
            if info["available"]:
                emit(f"    [bold green][✓][/bold green] {tool_name:<14} ({info['type']}) -> {info['path']}")
            else:
                emit(f"    [bold red][✗][/bold red] {tool_name:<14} ({info['type']}) -> Missing! Install: {info['install']}")

        if tool_status["missing_pd"]:
            emit(f"\n  [bold yellow][*] Bulk ProjectDiscovery Install:[/bold yellow] `{tool_status['combined_pd_install']}`")
        if tool_status["missing_other"]:
            emit("  [bold yellow][*] Standalone Installs:[/bold yellow]")
            for t in tool_status["missing_other"]:
                emit(f"    - {t}: `{tool_status['tools'][t]['install']}`")

        emit("\n  Wordlists & SecLists Dependencies:")
        if wordlist_status["seclists_installed"]:
            emit(f"    [bold green][✓][/bold green] SecLists Wordlists -> {wordlist_status['seclists_path']}")
        else:
            emit(f"    [bold yellow][!][/bold yellow] SecLists Missing -> Install: `{wordlist_status['install_hint_apt']}`")
            emit(f"                           or: `{wordlist_status['install_hint_git']}`")

        # ── Recon/OSINT tool API keys (urlscan, virustotal, etc.) ──────
        # These aren't LLM provider keys — they belong to individual
        # TOOL_REGISTRY executors (urlscan_recon, virustotal_lookup) that
        # would otherwise fail with "no_api_key" the first time a
        # researcher tries them, with no earlier warning anywhere that a
        # key was ever needed. Surface it here, same spot as every other
        # dependency check.
        recon_api_keys = cfg.get("api_keys", {}) if isinstance(cfg.get("api_keys"), dict) else {}
        emit("\n  Recon/OSINT Tool API Keys (optional — unlocks extra tools):")
        missing_recon_keys = []
        for key_name, info in RECON_API_KEY_INFO.items():
            has_key = bool(recon_api_keys.get(key_name) or os.environ.get(info["env_var"], ""))
            if has_key:
                emit(f"    [bold green][✓][/bold green] {info['label']:<12} -> used by {info['used_by']}")
            else:
                emit(f"    [dim][ ][/dim] {info['label']:<12} -> used by {info['used_by']} (not set) — get one: {info['signup_url']}")
                missing_recon_keys.append(key_name)
        if missing_recon_keys:
            emit(f"    [*] Set with: `/setup set-key <tool> <api_key>` (e.g. `/setup set-key urlscan <key>`)")
        status["recon_api_keys"] = {k: bool(recon_api_keys.get(k) or os.environ.get(v["env_var"], "")) for k, v in RECON_API_KEY_INFO.items()}

        auto_state = "[bold green]ON[/bold green]" if auto_install_enabled else "[dim]OFF[/dim]"
        emit(f"\n  Auto-Install Missing Tools: {auto_state} (Toggle: `/setup tools auto-install on|off`)")

        recap_state = "[bold green]ON[/bold green]" if cfg.get("show_recaps", True) else "[dim]OFF[/dim]"
        emit(f"  Multi-tool Recap Footers:   {recap_state} (Toggle: `/setup recaps on|off`)")

        max_iter = int(cfg.get("max_agent_iterations", 60))
        emit(f"  Max Tool-Call Iterations:   {max_iter} (Set: `/setup max-iterations <n>`)")

        # ── Everything-in-one-place reference. The researcher shouldn't
        # have to already know /handle, /model, or /apikey exist (or
        # separately run /help) just to find out HOW to configure
        # Hellhound — every knob and the command that sets it is listed
        # here, in the one command people naturally reach for first.
        emit("\n[bold red]─── QUICK SETUP REFERENCE ───[/bold red]")
        emit("  Researcher identity:")
        emit("    /handle <name>                        — set the name used in reports & the X-Bugbounty header")
        emit("  AI model & provider:")
        emit("    /model [orchestrator|synthesizer|both] <provider> <model-id>")
        emit("    /model set-key <provider> <key>        — save an LLM provider key (ollama/nvidia/gemini/openai/anthropic)")
        emit("  External tool API keys:")
        emit("    /apikey <tool> <value>                 — save a key for a scanning tool (wpscan, urlscan, virustotal, ...)")
        emit("    /apikey                                — list every tool key this system knows about")
        emit("    /setup set-key <tool> <api_key>         — same store, recon-tool shortcut (urlscan/virustotal)")
        emit("  Binary tool dependencies:")
        emit("    /setup tools install-all               — install every missing recon/exploit binary now")
        emit("    /setup tools auto-install on|off        — auto-install missing tools the moment a run needs them")
        emit("    /update                                 — update Hellhound itself + every installed tool/dependency")
        emit("  Target scope:")
        emit("    /scope in <host...>                     — add host(s)/wildcards to in-scope")
        emit("    /scope out <host...>                    — add host(s) to out-of-scope (wins over any in-scope wildcard)")
        emit("    /scope show                             — show current in-scope / out-of-scope / disallowed lists")
        emit("    /program <paste program text>           — parse scope straight from a bug-bounty program page")
        emit("  Behavior tuning:")
        emit("    /setup recaps on|off                    — toggle multi-tool recap footers")
        emit("    /setup max-iterations <n>               — cap tool-call iterations per turn")
        emit("  Run /help for the full command catalog, or /help skills for the methodology library.")

        if (tool_status["missing_pd"] or tool_status["missing_other"]) and not is_json and sys.stdin.isatty():
            ans = _interactive_prompt("Some binary tools are missing. Would you like to install them now? (y/n)")
            if ans.lower() in ("y", "yes"):
                emit.banner("INSTALLING MISSING TOOLS")
                still_missing = []
                for t in tool_status["missing_pd"] + tool_status["missing_other"]:
                    ok = try_install(t, emit=emit)
                    if ok:
                        emit.success(f"[✓] {t} installed.")
                    else:
                        still_missing.append(t)
                        emit.warn(f"[✗] {t} still missing — see the error above (or install it manually).")
                tool_status = check_all_tools()
                status["tools"] = tool_status
                if still_missing:
                    emit.warn(f"\n{len(still_missing)} tool(s) could not be auto-installed: {', '.join(still_missing)}. Run `/setup` again to recheck after installing manually.")

        if missing_recon_keys and not is_json and sys.stdin.isatty():
            ans = _interactive_prompt(f"Set up recon tool API key(s) now? ({', '.join(missing_recon_keys)}) (y/n)")
            if ans.lower() in ("y", "yes"):
                for key_name in missing_recon_keys:
                    info = RECON_API_KEY_INFO[key_name]
                    emit.info(f"Don't have one? Get it at: {info['signup_url']}  ({info['where']})")
                    val = _interactive_prompt(f"API key for {info['label']} (blank to skip):")
                    if val.strip():
                        cfg.setdefault("api_keys", {})[key_name] = val.strip()
                        save_config(cfg)
                        emit.success(f"Saved key for {info['label']}.")

    return {"status": "success", "setup": status}


def handle_ask(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /ask <question>
    Context-aware AI tactical assistance.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]
    question = " ".join(clean_args)

    if not question:
        msg = "Please provide a question. Usage: /ask <question>"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "message": msg}

    agent = get_agent(session_context.get("target"))
    answer = agent.handle_message(question, session_context=session_context, emit=emit)

    if not is_json:
        emit(answer)

    return {"status": "success", "question": question, "response": answer}


def handle_howl(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /howl [--graph]
    AI attack correlation and attack graph synthesis.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    is_graph = "--graph" in args or "-g" in args
    target_name = _extract_target_from_args(args, session_context)

    results = {}
    target_obj = create_or_load_target(target_name)
    if target_obj and target_obj.modules:
        for m_name, m_data in target_obj.modules.items():
            results[m_name] = m_data.get("output", {})
    
    if not results:
        legacy_sync = os.path.join(os.getcwd(), "storage", "sync", "session_sync.json")
        if os.path.exists(legacy_sync):
            try:
                with open(legacy_sync, "r", encoding="utf-8") as f:
                    results = json.load(f)
            except Exception:
                pass

    if is_graph:
        graph_data = build_graph(results)
        if not is_json:
            emit(json.dumps(graph_data, indent=2))
        return {"status": "success", "graph": graph_data}

    agent = get_agent(target_name)
    prompt = f"Correlate all attack findings and construct attack chains for target {target_name}."
    answer = agent.handle_message(prompt, session_context=session_context, emit=emit)

    if not is_json:
        emit(answer)

    return {"status": "success", "target": target_name, "response": answer}


def handle_help(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /help [skills]
    Displays reference table for all available slash commands grouped by
    category. Deliberately does NOT list the individual per-skill slash
    commands (/access-control, /auth-bypass, etc. — auto-registered by
    _register_skill_commands() purely for tab-completion convenience) —
    those used to flood the main listing with one row per skill the moment
    a new skill got added, drowning out the actual commands in a wall of
    skill descriptions nobody asked for here. That listing lives at
    /help skills (or just /skills) instead, which already formats it
    properly (short descriptions, usage counts) rather than as the same
    flat command-row format as everything else.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    # /help skills — explicit opt-in to the skill library listing, instead
    # of it being baked into the default /help output.
    if clean_args and clean_args[0].lower() in ("skills", "skill"):
        return handle_skills([a for a in clean_args[1:]] + (["--json"] if is_json else []), session_context, emit)

    catalog = []
    seen = set()
    for name, cmd in COMMAND_REGISTRY.items():
        if cmd.name in seen:
            continue
        seen.add(cmd.name)
        # Per-skill auto-registered commands (category="skills", one per
        # discovered skill) are deliberately excluded from the general
        # help catalog — see docstring above. They still work as real
        # slash commands (tab-complete finds them fine); this only keeps
        # them out of /help's wall of text.
        if getattr(cmd, "category", "general").lower() == "skills":
            continue
        catalog.append({
            "command": cmd.name,
            "aliases": cmd.aliases,
            "category": getattr(cmd, "category", "general"),
            "usage": cmd.usage,
            "description": cmd.description
        })

    if not is_json:
        try:
            from rich.markup import escape
        except Exception:
            def escape(t): return t

        category_titles = {
            "hunting": "RECONNAISSANCE & HUNTING",
            "config": "CONFIGURATION & TARGET SCOPE",
            "session": "SESSION & REPORTING",
            "general": "GENERAL UTILITIES"
        }
        category_order = ["hunting", "config", "session", "general"]

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for item in catalog:
            cat = item.get("category", "general").lower()
            grouped.setdefault(cat, []).append(item)

        emit.banner("HELLHOUND UNIFIED SLASH COMMANDS")
        for cat_key in category_order:
            if cat_key not in grouped:
                continue
            cat_title = category_titles.get(cat_key, cat_key.upper())
            emit(f"\n[bold red]─── {cat_title} ───[/bold red]")
            for item in grouped[cat_key]:
                aliases_str = f" [dim](Aliases: {', '.join(item['aliases'])})[/dim]" if item['aliases'] else ""
                desc_str = escape(item['description'])
                emit.info(f"• [bold cyan]{item['command']}[/bold cyan]{aliases_str} — {desc_str}")
                usage_lines = [u.strip() for u in item['usage'].split("\n") if u.strip()]
                for u in usage_lines:
                    emit(f"    [dim]Usage:[/dim] [yellow]{escape(u)}[/yellow]")
            emit("")

        # Handle any uncategorized or extra categories (deliberately
        # excludes "skills" — see docstring above).
        for cat_key, items in grouped.items():
            if cat_key in category_order or cat_key == "skills":
                continue
            emit(f"\n[bold red]─── {cat_key.upper()} ───[/bold red]")
            for item in items:
                aliases_str = f" [dim](Aliases: {', '.join(item['aliases'])})[/dim]" if item['aliases'] else ""
                desc_str = escape(item['description'])
                emit.info(f"• [bold cyan]{item['command']}[/bold cyan]{aliases_str} — {desc_str}")
                usage_lines = [u.strip() for u in item['usage'].split("\n") if u.strip()]
                for u in usage_lines:
                    emit(f"    [dim]Usage:[/dim] [yellow]{escape(u)}[/yellow]")
            emit("")

        emit("[dim]For the full methodology skill library, run /skills (or /help skills).[/dim]")

    return {"status": "success", "commands": catalog}


# ─────────────────────────────────────────────────────────────
# REGISTER ALL SLASH COMMANDS
# ─────────────────────────────────────────────────────────────

register_command(Command(
    name="/recon",
    aliases=["/surface", "/spider"],
    description="Run target reconnaissance pipeline with scope verification",
    usage="/recon [subdomains [active|passive] [permute] | endpoints | tech] <target> [--json]",
    category="hunting",
    handler=handle_recon
))

register_command(Command(
    name="/scan",
    aliases=["/strike"],
    description="Execute a specific discovery/analysis module against target",
    usage="/scan <module> [target] [--json] [key=val...]",
    category="hunting",
    handler=handle_scan
))

register_command(Command(
    name="/hunt",
    aliases=["/auto"],
    description="Execute an autonomous, scope-aware multi-stage hunt and triage",
    usage="/hunt [target] [--json]",
    category="hunting",
    handler=handle_hunt
))

register_command(Command(
    name="/howl",
    aliases=["/correlate", "/graph"],
    description="Correlate discoveries or generate visual attack graph",
    usage="/howl [--graph] [target] [--json]",
    category="hunting",
    handler=handle_howl
))

def handle_skills(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /skills [search_query] [--json]
    Lists discovered skills or searches skill repository.
    """
    from hellhound.core.skills import discover_skills, search_skills
    try:
        from rich.markup import escape
    except Exception:
        def escape(t): return t

    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    if not clean_args:
        skills = discover_skills()
        if not is_json:
            from hellhound.core.skills import get_short_description, get_skill_usage_counts
            usage = get_skill_usage_counts()
            sorted_skills = sorted(skills.items(), key=lambda item: (-usage.get(item[0].lower(), 0), item[0].lower()))
            emit.banner(f"HELLHOUND SKILL LIBRARY ({len(skills)} Available)")
            for name, s in sorted_skills:
                tag = " (user)" if s.is_user_defined else ""
                short_desc = escape(get_short_description(s.description))
                emit(f"  • [bold cyan]{name}[/bold cyan]{tag}: {short_desc}")
        return {
            "status": "success",
            "skills": [
                {
                    "name": s.name,
                    "description": s.description,
                    "is_user_defined": s.is_user_defined,
                    "path": s.path,
                    "has_references": bool(s.references_dir)
                }
                for s in skills.values()
            ]
        }

    query = " ".join(clean_args)
    results = search_skills(query, max_results=5)
    if not is_json:
        from hellhound.core.skills import get_short_description
        emit.banner(f"SKILL SEARCH RESULTS FOR: '{query}'")
        if not results:
            emit.warn("No matching skills found.")
        for s in results:
            tag = " (user)" if s.is_user_defined else ""
            short_desc = escape(get_short_description(s.description))
            emit(f"  • [bold green]{s.name}[/bold green]{tag}: {short_desc}")

    return {
        "status": "success",
        "query": query,
        "results": [
            {
                "name": s.name,
                "description": s.description,
                "is_user_defined": s.is_user_defined,
                "path": s.path
            }
            for s in results
        ]
    }


register_command(Command(
    name="/skills",
    aliases=["/skill"],
    description="List or search loaded methodology skills and checklists",
    usage="/skills [query] [--json]",
    category="hunting",
    handler=handle_skills
))

register_command(Command(
    name="/scope",
    aliases=["/rules"],
    description="Inspect, clear, or configure program scope rules for target",
    usage="/scope [show | clear | in <host...> | out <host...> | disallow <rule...> | <pasted program policy text>]",
    category="config",
    handler=handle_scope
))

register_command(Command(
    name="/program",
    aliases=["/programs", "/engagement"],
    description="Group several in-scope domains of one bug-bounty program/engagement under a shared scope (each domain keeps its own findings/session) — entirely optional, never triggered automatically by /target",
    usage="/program [show [name] | list | create <name> [domain1,domain2,...] | add <domain...> | attach <domain...> | scope <policy text>]",
    category="config",
    handler=handle_program
))

register_command(Command(
    name="/output",
    aliases=["/tail", "/show-output"],
    description="Show the FULL output of the last long-running tool call (ffuf, feroxbuster, run_terminal_command, etc.) for the active target — the terminal only streams a capped live feed of hits while a tool runs; this pulls the complete captured stdout/stderr. In-memory only, no file written.",
    usage="/output [stderr] [N]  (N = only the last N lines; add 'stderr' to see stderr instead of stdout)",
    category="hunting",
    handler=handle_output
))

register_command(Command(
    name="/model",
    aliases=["/ai"],
    description="Inspect, switch active AI model for orchestrator/synthesizer, or configure API keys",
    usage="/model [orchestrator|synthesizer|both] <provider> <model-id>  e.g. /model orchestrator ollama qwen2.5:3b-instruct  /model synthesizer nvidia nemotron-3-ultra-550b-a55b\n/model both nvidia nvidia/nemotron-3-ultra-550b-a55b  (same as omitting the role — sets both tiers in one command)\n/model set-key <provider> <key>  (any NIM model ID works, not just the examples shown)",
    category="config",
    handler=handle_model
))

register_command(Command(
    name="/mcp",
    aliases=["/integrations"],
    description="Configure and test Burp (MCP) and Caido (GraphQL) integrations — no manual config.json editing needed",
    usage="/mcp | /mcp burp [host_or_url] | /mcp caido [url] [token] | /mcp caido token <token> | /mcp test | /mcp burp|caido remove",
    category="config",
    handler=handle_mcp
))

register_command(Command(
    name="/headers",
    aliases=["/head"],
    description="Manage global custom HTTP request headers and BugBounty handle",
    usage="/headers [Header: Value | --clear]",
    category="config",
    handler=handle_headers
))

register_command(Command(
    name="/apikey",
    aliases=["/apikeys", "/tool-key"],
    description="Save/view/clear API keys or tokens for external security tools (wpscan, virustotal, urlscan, and anything else wired to use one) — with a sign-up hint for each. Saved once, reused automatically on every future target so you're never asked for it mid-engagement again",
    usage="/apikey | /apikey <tool> <value> | /apikey <tool> --clear  (e.g. /apikey wpscan abc123...)",
    category="config",
    handler=handle_apikey
))

register_command(Command(
    name="/update",
    aliases=["/upgrade"],
    description="Update Hellhound itself (git pull), resync Python dependencies, and update every already-installed external tool to its latest version — all in one command",
    usage="/update  (runs all three stages)\n/update source   — git-pull the Hellhound checkout only\n/update deps     — resync Python packages against requirements.txt only\n/update tools    — update already-installed external binaries only",
    category="general",
    handler=handle_update
))

register_command(Command(
    name="/setup",
    aliases=["/health", "/doctor"],
    description="The one-stop setup hub — AI connectivity, tool dependencies, and a quick-reference list of every configuration command (handle, model, API keys, scope, auto-install, recaps)",
    usage="/setup  (shows full status + quick setup reference)\n/setup tools [auto-install on|off | install-all]\n/setup set-key <recon_tool> <api_key>\n/setup recaps on|off\n/setup max-iterations <n>",
    category="config",
    handler=handle_setup
))

register_command(Command(
    name="/target",
    aliases=["/tgt", "/set-target"],
    description="Inspect or switch the active engagement target",
    usage="/target [domain_or_name] [--clear-history]",
    category="session",
    handler=handle_target
))

register_command(Command(
    name="/report",
    aliases=["/loot"],
    description="Generate structured bug bounty reconnaissance report",
    usage="/report [--format html|json]",
    category="session",
    handler=handle_report
))

register_command(Command(
    name="/ask",
    aliases=["/chat"],
    description="Query AI assistant with session context and tool access",
    usage="/ask <question>",
    category="session",
    handler=handle_ask
))

def handle_handle(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /handle [name]
    Sets (or shows) the researcher_handle used to personalize the
    "Happy hacking" sign-off and the X-Bugbounty header.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]
    cfg = load_config()

    if not clean_args:
        current = cfg.get("researcher_handle", "")
        if not is_json:
            emit.info(f"Researcher handle: {current or '(not set)'}")
            emit.info("To set: /handle <name>")
        return {"status": "success", "researcher_handle": current}

    new_handle = " ".join(clean_args).strip()
    cfg["researcher_handle"] = new_handle
    save_config(cfg)
    if not is_json:
        emit.success(f"Researcher handle set to: {new_handle}")
    return {"status": "success", "researcher_handle": new_handle}


def handle_uninstall(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /uninstall [--yes] [--keep-data] [--purge-tools] [--purge-source]

    Fully removes the local HELLHOUND install (venv, symlinks, shell
    aliases, desktop entry, icons, and — unless --keep-data is passed —
    ~/.hellhound config/targets/findings).

    This is destructive and irreversible, so it is intentionally NOT part
    of the agent's TOOL_REGISTRY (which the LLM drives autonomously against
    network targets). Uninstall requests are matched by a deterministic
    keyword check in dispatch() before anything reaches the model, and the
    handler itself always stops and asks for explicit confirmation before
    deleting anything — the one place in the tool where the agent is
    required to halt rather than act on its own judgment.
    """
    flags = {a.lower() for a in args if a.startswith("-")}
    auto_confirm = ("--yes" in flags) or ("-y" in flags)
    keep_data = "--keep-data" in flags
    purge_tools = "--purge-tools" in flags
    purge_source = "--purge-source" in flags

    is_json = "--json" in flags or getattr(emit, "json_mode", False)

    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "uninstall.sh"

    home = Path.home()
    plan = {
        "venv": home / ".hellhound-env",
        "local_bin_symlink": home / ".local" / "bin" / "hellhound",
        "global_bin_symlink": Path("/usr/local/bin/hellhound"),
        "desktop_entry": home / ".local" / "share" / "applications" / "hellhound.desktop",
        "icon_assets": home / ".local" / "share" / "hellhound",
        "icon_file": home / ".local" / "share" / "icons" / "hellhound.png",
        "config_and_data": home / ".hellhound",
    }
    existing = {k: str(v) for k, v in plan.items() if v.exists() or v.is_symlink()}

    if not auto_confirm:
        # Hard stop: never delete anything without the user explicitly
        # confirming this exact action. This is a valid, deliberate place
        # for the agent/dispatcher to refuse to "just do it".
        msg = (
            "Uninstall requested. This will permanently remove:\n"
            + "\n".join(f"  - {k}: {v}" for k, v in existing.items())
            + ("\n\n  ~/.hellhound (config, targets, findings) will be KEPT (--keep-data)." if keep_data
               else "\n\n  Including ~/.hellhound — ALL saved targets, scope, and findings.")
            + "\n\nNothing has been deleted. Re-run with explicit confirmation to proceed:"
            + "\n  /uninstall --yes" + (" --keep-data" if keep_data else "")
        )
        if not is_json:
            emit.warn(msg)
        return {
            "status": "needs_confirmation",
            "would_remove": existing,
            "keep_data": keep_data,
            "confirm_with": "/uninstall --yes" + (" --keep-data" if keep_data else ""),
        }

    if not script_path.exists():
        # Package was installed without the repo tree alongside it (e.g. a
        # bare pip install) — fall back to performing the same steps in
        # Python instead of failing outright.
        import shutil as _shutil
        removed = []
        try:
            if plan["venv"].exists():
                _shutil.rmtree(plan["venv"], ignore_errors=True)
                removed.append(str(plan["venv"]))
            for key in ("local_bin_symlink", "global_bin_symlink", "desktop_entry", "icon_file"):
                p = plan[key]
                if p.exists() or p.is_symlink():
                    try:
                        p.unlink()
                        removed.append(str(p))
                    except PermissionError:
                        if not is_json:
                            emit.warn(f"Permission denied removing {p} — remove manually (may need sudo).")
            if plan["icon_assets"].exists():
                _shutil.rmtree(plan["icon_assets"], ignore_errors=True)
                removed.append(str(plan["icon_assets"]))
            if not keep_data and plan["config_and_data"].exists():
                _shutil.rmtree(plan["config_and_data"], ignore_errors=True)
                removed.append(str(plan["config_and_data"]))
        except Exception as e:  # noqa: BLE001
            if not is_json:
                emit.error(f"Uninstall hit an error partway through: {e}")
            return {"status": "error", "error": str(e), "removed": removed}
        if not is_json:
            emit.success("HELLHOUND uninstalled.")
            emit.info("Shell alias lines were not touched (uninstall.sh not found alongside the install) — remove 'alias hellhound=' / 'alias hellhound-gui=' from your shell rc file manually.")
        return {"status": "success", "removed": removed, "method": "python_fallback"}

    cmd = [str(script_path), "--yes"]
    if keep_data:
        cmd.append("--keep-data")
    if purge_tools:
        cmd.append("--purge-tools")
    if purge_source:
        cmd.append("--purge-source")

    if not is_json:
        emit.info(f"Running {script_path.name} --yes ...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = (proc.stdout or "") + (proc.stderr or "")
        if not is_json:
            emit(output)
        status = "success" if proc.returncode == 0 else "error"
        if status == "success" and not is_json:
            emit.success("HELLHOUND uninstalled. This process should now exit.")
        return {"status": status, "returncode": proc.returncode, "output": output}
    except Exception as e:  # noqa: BLE001
        if not is_json:
            emit.error(f"Failed to run uninstall.sh: {e}")
        return {"status": "error", "error": str(e)}


register_command(Command(
    name="/uninstall",
    aliases=["/remove-hellhound"],
    description="Permanently remove HELLHOUND (venv, symlinks, aliases, desktop entry, and config/data unless --keep-data). Always asks for confirmation first.",
    usage="/uninstall [--yes] [--keep-data] [--purge-tools] [--purge-source]",
    category="general",
    handler=handle_uninstall
))

register_command(Command(
    name="/help",
    aliases=["/?"],
    description="Show all available slash commands and usage",
    usage="/help",
    category="general",
    handler=handle_help
))

register_command(Command(
    name="/handle",
    aliases=["/researcher-handle"],
    description="Set or show your researcher handle — personalizes the exit message and X-Bugbounty header",
    usage="/handle [name]",
    category="config",
    handler=handle_handle
))


# ─────────────────────────────────────────────────────────────
# REGISTER SKILLS AS DIRECT SLASH COMMANDS (for autocomplete parity
# with /recon, /report, etc. — see HellhoundCompleter in chat_ui.py,
# which reads straight from COMMAND_REGISTRY)
# ─────────────────────────────────────────────────────────────

def _make_skill_handler(_skill_name: str):
    def _handler(args: List[str], session_context: Dict[str, Any], emit: Any,
                 on_token: Optional[Callable[[str], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
        task_text = " ".join(args).strip()
        if not task_text:
            emit.warn(f"Usage: /{_skill_name} <task description>")
            return {"status": "error", "error": "missing_task", "skill": _skill_name}
        response = agent_handle_message(task_text, session_context=session_context, emit=emit, on_token=on_token, cancel_check=cancel_check, forced_skill=_skill_name)
        if not on_token:
            emit(response)
        return {"status": "success", "response": response, "forced_skill": _skill_name}
    return _handler


def _register_skill_commands():
    try:
        from hellhound.core.skills import discover_skills
        for _name, _meta in sorted(discover_skills().items()):
            cmd_name = "/" + _name
            if cmd_name.lower() in COMMAND_REGISTRY:
                continue  # a real command already owns this name — don't shadow it
            register_command(Command(
                name=cmd_name,
                description=(_meta.description or f"Run the '{_name}' methodology skill directly")[:200],
                usage=f"{cmd_name} <task description>",
                category="skills",
                handler=_make_skill_handler(_name)
            ))
    except Exception:
        pass  # autocomplete convenience only — never block startup on this


_register_skill_commands()


# ─────────────────────────────────────────────────────────────
# UNINSTALL INTENT DETECTION
#
# Deliberately NOT delegated to the LLM agent loop: TOOL_REGISTRY tools are
# meant to be chosen autonomously by the model against a network target, and
# a filesystem-deleting action has no business being one more entry an LLM
# can reach for on a bad turn. This is a small, deterministic keyword gate
# instead — cheap, auditable, and it only ever routes into handle_uninstall(),
# which itself always stops for confirmation before deleting anything unless
# the user has already said so explicitly in the same message.
# ─────────────────────────────────────────────────────────────

_UNINSTALL_VERB_RE = re.compile(r"\buninstall(?:ed|ing|s)?\b", re.I)
_DESTRUCTIVE_VERB_RE = re.compile(r"\b(remove|delete|wipe|purge|nuke|get rid of)\b", re.I)
_TOOL_SCOPE_RE = re.compile(r"\b(hellhound|this tool|the tool|everything|all (my )?data|completely)\b", re.I)
_UNINSTALL_CONFIRM_RE = re.compile(
    r"\b(--yes|confirm(ed)?|i confirm|yes[, ]+(please )?(do it|uninstall|remove)|really uninstall|i'?m sure|go ahead)\b",
    re.I,
)


def _looks_like_uninstall_intent(text: str) -> bool:
    """Deterministic (non-LLM) check for 'remove HELLHOUND entirely' requests."""
    if _UNINSTALL_VERB_RE.search(text):
        return True
    return bool(_DESTRUCTIVE_VERB_RE.search(text) and _TOOL_SCOPE_RE.search(text))


# ─────────────────────────────────────────────────────────────
# CENTRAL DISPATCHER
# ─────────────────────────────────────────────────────────────

def dispatch(raw_input: str, session_context: Dict[str, Any], emit: Any = None,
             on_token: Optional[Callable[[str], None]] = None,
             cancel_check: Optional[Callable[[], bool]] = None) -> Optional[Dict[str, Any]]:
    """
    Main dispatch entry point for all command execution paths.
    Routes slash commands to specific handlers, and routes plain natural language
    directly to the Agent reasoning loop.
    """
    if not raw_input or not raw_input.strip():
        return None

    if emit is None:
        emit = PlainEmit()

    raw_clean = raw_input.strip()
    try:
        tokens = shlex.split(raw_clean)
    except ValueError:
        tokens = raw_clean.split()

    if not tokens:
        return None

    cmd_token = tokens[0]
    args = tokens[1:]

    # Check for registered slash command
    if cmd_token.startswith("/"):
        command = get_command(cmd_token)
        if command and command.handler:
            handler_params = inspect.signature(command.handler).parameters
            kwargs = {}
            if "on_token" in handler_params:
                kwargs["on_token"] = on_token
            if "cancel_check" in handler_params:
                kwargs["cancel_check"] = cancel_check
            result = command.handler(args, session_context, emit, **kwargs)
            if "--json" in tokens or getattr(emit, "json_mode", False):
                print(json.dumps(result, indent=2))
            return result

        # Not a registered command — check if it names an actual skill
        # (e.g. "/access-control target is ... take over the owner console").
        # This bypasses automatic skill selection entirely and forces that
        # skill's full methodology for this one message.
        skill_name = cmd_token[1:].strip().lower()
        try:
            from hellhound.core.skills import discover_skills
            available_skills = discover_skills()
        except Exception:
            available_skills = {}
        if skill_name in available_skills:
            task_text = " ".join(args).strip()
            if not task_text:
                emit.warn(f"Usage: /{skill_name} <task description>")
                return {"status": "error", "error": "missing_task", "skill": skill_name}
            response = agent_handle_message(task_text, session_context=session_context, emit=emit, on_token=on_token, cancel_check=cancel_check, forced_skill=skill_name)
            if "--json" in tokens or getattr(emit, "json_mode", False):
                res_dict = {"status": "success", "response": response, "forced_skill": skill_name}
                print(json.dumps(res_dict, indent=2))
                return res_dict
            else:
                if not on_token:
                    emit(response)
                return {"status": "success", "response": response, "forced_skill": skill_name}

        emit.warn(f"Unknown command '{cmd_token}'. Type /help for available commands, or /skills to list methodology skills you can invoke directly.")
        return {"status": "error", "error": "unknown_command", "command": cmd_token}

    # Built-in utility commands allowed without slash (e.g. 'help', 'exit', 'quit', 'clear')
    if cmd_token.lower() in ("help", "exit", "quit", "clear", "?"):
        command = get_command("/" + cmd_token)
        if command and command.handler:
            result = command.handler(args, session_context, emit)
            if "--json" in tokens or getattr(emit, "json_mode", False):
                print(json.dumps(result, indent=2))
            return result

    # Uninstall intent, spoken in plain language rather than as /uninstall.
    # Caught here — before the message ever reaches the LLM — precisely
    # because it's destructive; see comment above _looks_like_uninstall_intent.
    if _looks_like_uninstall_intent(raw_clean):
        uninstall_args = ["--yes"] if _UNINSTALL_CONFIRM_RE.search(raw_clean) else []
        result = handle_uninstall(uninstall_args, session_context, emit)
        if "--json" in tokens or getattr(emit, "json_mode", False):
            print(json.dumps(result, indent=2))
        return result

    # Plain natural language input -> Route directly to Agent Reasoning Loop
    response = agent_handle_message(raw_clean, session_context=session_context, emit=emit, on_token=on_token, cancel_check=cancel_check)
    if "--json" in tokens or getattr(emit, "json_mode", False):
        res_dict = {"status": "success", "response": response}
        print(json.dumps(res_dict, indent=2))
        return res_dict
    else:
        if not on_token:
            emit(response)
        return {"status": "success", "response": response}