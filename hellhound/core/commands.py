"""
hellhound/core/commands.py

Unified Slash-Command Architecture & Central Dispatcher.
Provides a unified entrypoint for interactive console, headless CLI automation (--print),
and GUI IPC command execution.
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Any, Tuple
import os
import sys
import json
import shlex
from urllib.parse import urlparse
import requests

from hellhound.core.scope import ScopeRules, is_in_scope, check_module_against_rules, parse_program_rules
from hellhound.core.tasks import create_or_load_target, set_scope as task_set_scope, list_targets, Target, save_target
from hellhound.core.ai_utils import (
    load_config, save_config, ask_neural_core,
    ping_ollama, call_ollama, list_available_models, detect_ai_config
)
from hellhound.core.agent import handle_message as agent_handle_message, get_agent
from hellhound.core.emit import PlainEmit, ConsoleEmit
from hellhound.core.http_utils import merge_global_context
from hellhound.core.nodes import build_graph
from hellhound.core.toolcheck import check_all_tools, try_install, ensure_tool, install_hint, check_wordlists


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


def handle_recon(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /recon [subdomains|endpoints|tech] <target> [--json]
    Delegates to the agent's own reasoning — asset discovery, live-host
    confirmation, and content discovery in proper order, chosen dynamically
    rather than a fixed script.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    known_modes = {"subdomains", "endpoints", "tech"}
    mode = "full"

    if clean_args and clean_args[0].lower() in known_modes:
        mode = clean_args[0].lower()
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

    if mode == "subdomains":
        prompt = (
            f"Enumerate subdomains for {target} using passive discovery, "
            f"escalating to active brute-force only if passive results are thin. "
            f"Don't proceed to content discovery or deeper analysis. Respect scope throughout."
        )
    elif mode == "endpoints":
        prompt = (
            f"Perform content and endpoint discovery on {target} using spider. "
            f"Assume live hosts are already known or do a quick httpx check first. "
            f"Do not perform subdomain enumeration. Respect scope throughout."
        )
    elif mode == "tech":
        prompt = (
            f"Perform live-host confirmation and technology fingerprinting on {target} "
            f"using httpx. Do not perform any crawling, spidering, or subdomain enumeration. "
            f"Respect scope throughout."
        )
    elif is_ctf_domain_pattern(target) or is_ctf_auto_scope_eligible(target):
        prompt = (
            f"Perform active CTF/lab reconnaissance on {target}. "
            f"This is an isolated/unindexed challenge target. Do NOT perform passive subdomain enumeration (no subfinder). "
            f"Start with active DNS brute-force (dns_bruteforce) and live-host confirmation (httpx), "
            f"then content/endpoint discovery and vhost fuzzing on live ports. Respect scope throughout."
        )
    else:
        prompt = (
            f"Perform reconnaissance on {target}. Follow proper methodology: "
            f"asset discovery and live-host confirmation first (subfinder, escalate "
            f"to dns_bruteforce if passive results are thin), then content/endpoint "
            f"discovery (spider) only against confirmed live hosts, then deeper "
            f"analysis (wafbuster, tech fingerprinting) as warranted. Respect scope "
            f"thoughtout."
        )

    answer = agent.handle_message(prompt, session_context=session_context, emit=emit)
    if not is_json:
        emit(answer)
    return {"status": "success", "target": target, "mode": mode, "response": answer}


def handle_scan(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /scan <module> [target] [--json] [key=val ...]
    Executes a specific discovery/analysis module against the target.
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

    # 1. Target Scope Check
    allowed_target, t_reason = is_in_scope(target, scope_rules)
    if not allowed_target:
        if not is_json:
            emit.error(f"[SECURITY] Target out of scope: {t_reason}")
        return {"status": "error", "error": "out_of_scope", "target": target, "reason": t_reason}

    # 2. Module Restriction Check
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

    session_context["target"] = target
    session_context["module"] = module_name

    agent = get_agent(target)
    # Reconstruct options string
    opt_str = " ".join(f"{k}={v}" for k, v in custom_opts.items())
    prompt = f"Run the '{module_name}' tool/module against target {target} with parameters/arguments: {opt_str}."
    answer = agent.handle_message(prompt, session_context=session_context, emit=emit)

    if not is_json:
        emit(answer)

    return {
        "status": "success",
        "module": module_name,
        "target": target,
        "response": answer
    }


def handle_hunt(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
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
    answer = agent.handle_message(prompt, session_context=session_context, emit=emit)
    if not is_json:
        emit(answer)
    return {"status": "success", "target": target, "response": answer}


def handle_scope(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /scope [show | clear | <rules_text>]
    Inspects, clears, or configures persistent program scope rules for current target.
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

    raw_text = " ".join(clean_args)
    task_set_scope(target_obj, raw_text)
    session_context["scope_rules"] = target_obj.scope_rules

    if not is_json:
        emit.success(f"Scope updated for target '{target_obj.name}':")
        emit.info(f"  In-Scope: {target_obj.scope_rules.in_scope}")
        emit.info(f"  Out-of-Scope: {target_obj.scope_rules.out_scope}")
        emit.info(f"  Disallowed: {target_obj.scope_rules.disallowed}")

    return {"status": "success", "action": "updated", "target": target_obj.name, "scope": target_obj.scope_rules.to_dict()}


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
    current_synth_model = session_context.get("options", {}).get("synthesizer_model") or cfg.get("synthesizer_model", "nvidia/nemotron-3-super-120b-a12b")

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
    headers = opts.setdefault("global_headers", {})

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


def handle_target(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /target [domain_or_name]
    Switch or display the current active target for the session.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    if not clean_args:
        current_target = session_context.get("target", "default")
        if not is_json:
            emit.info(f"Active session target: [bold cyan]{current_target}[/bold cyan]")
            emit.info("To switch target: /target <domain_or_name>")
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

    return {
        "status": "success",
        "target": new_target_name,
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
                try_install(t, emit=emit)
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
        emit(f"  Researcher Handle: {status['researcher_handle'] or '(not set)'}")
        emit(f"  Active Model: {status['active_model'] or '(dynamic default)'} (Provider: {status['active_provider']})")
        emit(f"  Configured AI Providers:")
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

        auto_state = "[bold green]ON[/bold green]" if auto_install_enabled else "[dim]OFF[/dim]"
        emit(f"\n  Auto-Install Missing Tools: {auto_state} (Toggle: `/setup tools auto-install on|off`)")
        
        recap_state = "[bold green]ON[/bold green]" if cfg.get("show_recaps", True) else "[dim]OFF[/dim]"
        emit(f"  Multi-tool Recap Footers:   {recap_state} (Toggle: `/setup recaps on|off`)")

        if (tool_status["missing_pd"] or tool_status["missing_other"]) and not is_json and sys.stdin.isatty():
            ans = _interactive_prompt("Some binary tools are missing. Would you like to install them now? (y/n)")
            if ans.lower() in ("y", "yes"):
                emit.banner("INSTALLING MISSING TOOLS")
                for t in tool_status["missing_pd"] + tool_status["missing_other"]:
                    try_install(t, emit=emit)
                tool_status = check_all_tools()
                status["tools"] = tool_status

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
    /help
    Displays reference table for all available slash commands grouped by category.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)

    catalog = []
    seen = set()
    for name, cmd in COMMAND_REGISTRY.items():
        if cmd.name in seen:
            continue
        seen.add(cmd.name)
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

        # Handle any uncategorized or extra categories
        for cat_key, items in grouped.items():
            if cat_key in category_order:
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

    return {"status": "success", "commands": catalog}


# ─────────────────────────────────────────────────────────────
# REGISTER ALL SLASH COMMANDS
# ─────────────────────────────────────────────────────────────

register_command(Command(
    name="/recon",
    aliases=["/surface", "/spider"],
    description="Run target reconnaissance pipeline with scope verification",
    usage="/recon [subdomains|endpoints|tech] <target> [--json]",
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
    from hellhound.core.skills import discover_skills, search_skills, load_skill_body
    try:
        from rich.markup import escape
    except Exception:
        def escape(t): return t

    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    if not clean_args:
        skills = discover_skills()
        if not is_json:
            emit.banner(f"HELLHOUND SKILL LIBRARY ({len(skills)} Available)")
            for name, s in sorted(skills.items()):
                tag = " (user)" if s.is_user_defined else ""
                desc_str = escape(s.description[:110])
                emit.info(f"• [bold cyan]{name}[/bold cyan]{tag}: {desc_str}...")
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
        emit.banner(f"SKILL SEARCH RESULTS FOR: '{query}'")
        if not results:
            emit.warn("No matching skills found.")
        for s in results:
            tag = " (user)" if s.is_user_defined else ""
            desc_str = escape(s.description[:130])
            emit.info(f"• [bold green]{s.name}[/bold green]{tag}: {desc_str}...")

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
    usage="/scope [show | clear | <rules_text>]",
    category="config",
    handler=handle_scope
))

register_command(Command(
    name="/model",
    aliases=["/ai"],
    description="Inspect, switch active AI model for orchestrator/synthesizer, or configure API keys",
    usage="/model [orchestrator|synthesizer] <provider/model-id>  e.g. /model orchestrator ollama qwen2.5:3b-instruct  /model synthesizer nvidia/nemotron-3-super-120b-a12b\n/model set-key <provider> <key>",
    category="config",
    handler=handle_model
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
    name="/setup",
    aliases=["/health", "/doctor"],
    description="Verify AI connectivity, external tool dependencies, and auto-install settings",
    usage="/setup [tools [auto-install on|off]]\n/setup tools install-all",
    category="config",
    handler=handle_setup
))

register_command(Command(
    name="/target",
    aliases=["/tgt", "/set-target"],
    description="Inspect or switch the active engagement target",
    usage="/target [domain_or_name]",
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

register_command(Command(
    name="/help",
    aliases=["/?"],
    description="Show all available slash commands and usage",
    usage="/help",
    category="general",
    handler=handle_help
))


# ─────────────────────────────────────────────────────────────
# CENTRAL DISPATCHER
# ─────────────────────────────────────────────────────────────

def dispatch(raw_input: str, session_context: Dict[str, Any], emit: Any = None) -> Optional[Dict[str, Any]]:
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
            result = command.handler(args, session_context, emit)
            if "--json" in tokens or getattr(emit, "json_mode", False):
                print(json.dumps(result, indent=2))
            return result
        emit.warn(f"Unknown command '{cmd_token}'. Type /help for available commands.")
        return {"status": "error", "error": "unknown_command", "command": cmd_token}

    # Built-in utility commands allowed without slash (e.g. 'help', 'exit', 'quit', 'clear')
    if cmd_token.lower() in ("help", "exit", "quit", "clear", "?"):
        command = get_command("/" + cmd_token)
        if command and command.handler:
            result = command.handler(args, session_context, emit)
            if "--json" in tokens or getattr(emit, "json_mode", False):
                print(json.dumps(result, indent=2))
            return result

    # Plain natural language input -> Route directly to Agent Reasoning Loop
    response = agent_handle_message(raw_clean, session_context=session_context, emit=emit)
    if "--json" in tokens or getattr(emit, "json_mode", False):
        res_dict = {"status": "success", "response": response}
        print(json.dumps(res_dict, indent=2))
        return res_dict
    else:
        emit(response)
        return {"status": "success", "response": response}
