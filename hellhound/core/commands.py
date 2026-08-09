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
import requests

from hellhound.core.scope import ScopeRules, is_in_scope, check_module_against_rules, parse_program_rules
from hellhound.core.tasks import create_or_load_target, set_scope as task_set_scope, list_targets, Target, save_target
from hellhound.core.ai_utils import (
    load_config, save_config, ask_neural_core,
    ping_ollama, call_ollama, list_available_models, detect_ai_config
)
from hellhound.core.agent import handle_message as agent_handle_message, get_agent
from hellhound.core.engine import HellhoundEngine
from hellhound.core.emit import PlainEmit, ConsoleEmit
from hellhound.core.http_utils import merge_global_context
from hellhound.core.nodes import build_graph


@dataclass
class Command:
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    usage: str = ""
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
    /recon <target> [--json]
    Executes reconnaissance pipeline (Spider, WAFBuster) with scope verification.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    target = _extract_target_from_args(clean_args, session_context)
    if not target:
        msg = "No target specified. Usage: /recon <target> [--json]"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "error": "missing_target", "message": msg}

    target_obj = create_or_load_target(target)
    scope_rules = target_obj.scope_rules if target_obj.scope_rules.in_scope else _ensure_scope(session_context)
    allowed, reason = is_in_scope(target, scope_rules)
    if not allowed:
        if not is_json:
            emit.error(f"[SECURITY] Scope check failed: {reason}")
        return {"status": "error", "error": "out_of_scope", "target": target, "reason": reason}

    session_context["target"] = target
    engine = HellhoundEngine(console=getattr(emit, "console", None))

    if not is_json:
        emit.banner(f"RECONNAISSANCE PIPELINE: {target}")

    results = session_context.setdefault("results", {})
    recon_summary = {}

    # 1. Run Spider
    spider_opts = {"max_depth": 3, "fast": True}
    merge_global_context(spider_opts, session_context.get("options", {}))
    spider_res = engine.run_single("spider", target, options=spider_opts, emit=emit)
    if spider_res:
        results["spider"] = spider_res
        recon_summary["spider"] = spider_res

    # 2. Run WAFBuster
    waf_opts = {}
    merge_global_context(waf_opts, session_context.get("options", {}))
    waf_res = engine.run_single("wafbuster", target, options=waf_opts, emit=emit)
    if waf_res:
        results["wafbuster"] = waf_res
        recon_summary["wafbuster"] = waf_res

    if not is_json:
        emit.success(f"Recon complete for {target}")

    return {
        "status": "success",
        "target": target,
        "results": recon_summary,
        "total_modules_run": len(recon_summary)
    }


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

    engine = HellhoundEngine(console=getattr(emit, "console", None))
    result = engine.run_single(module_name, target, options=merged_opts, emit=emit)

    results = session_context.setdefault("results", {})
    if result:
        results[module_name] = result

    return {
        "status": "success",
        "module": module_name,
        "target": target,
        "result": result
    }


def handle_hunt(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /hunt [target] [--json]
    Executes an autonomous, scope-aware multi-stage hunt and triage.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]
    target = _extract_target_from_args(clean_args, session_context)

    if not target:
        msg = "No target specified. Usage: /hunt <target> [--json]"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "error": "missing_target", "message": msg}

    scope_rules = _ensure_scope(session_context)
    allowed, reason = is_in_scope(target, scope_rules)
    if not allowed:
        if not is_json:
            emit.error(f"[SECURITY] Scope check failed: {reason}")
        return {"status": "error", "error": "out_of_scope", "target": target, "reason": reason}

    session_context["target"] = target
    engine = HellhoundEngine(console=getattr(emit, "console", None))

    if not is_json:
        emit.banner(f"STARTING AUTONOMOUS HUNT: {target}")

    results = session_context.setdefault("results", {})

    # Phase 1: Reconnaissance
    spider_opts = {"max_depth": 3}
    merge_global_context(spider_opts, session_context.get("options", {}))
    spider_res = engine.run_single("spider", target, options=spider_opts, emit=emit)
    if spider_res:
        results["spider"] = spider_res

    # Phase 2: Surface & Exposure Auditing
    candidates = ["surface_auditor", "corsbuster", "graphql", "exmap"]
    executed = []
    for mod in candidates:
        ok, r_reason = check_module_against_rules(mod, scope_rules)
        if ok:
            mod_res = engine.run_single(mod, target, options=session_context.get("options", {}), emit=emit)
            if mod_res:
                results[mod] = mod_res
                executed.append(mod)

    # Phase 3: Agent Triage
    agent = get_agent(target)
    triage_prompt = f"Summarize and triage findings discovered during autonomous hunt for {target}."
    triage_output = agent.handle_message(triage_prompt, session_context=session_context, emit=emit)

    if not is_json:
        emit.success(f"Hunt completed across {len(executed) + 1} modules.")

    return {
        "status": "success",
        "target": target,
        "executed_modules": executed,
        "findings_count": len(results),
        "triage": triage_output
    }


def handle_scope(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /scope [show | clear | <rules_text>]
    Inspects, clears, or configures persistent program scope rules for current target.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    clean_args = [a for a in args if a not in ("--json", "-j")]

    target_name = session_context.get("target") or "default"
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
    /model [set-key <provider> <api_key>] | [<provider> <model_name>] | [<model_name>] | [--session-only]
    Inspects or switches the active local/cloud AI model with dynamic model discovery.
    Supports explicit API key configuration and provider-qualified model switching.
    """
    KNOWN_PROVIDERS = ("nvidia", "openai", "anthropic", "gemini", "ollama")
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    session_only = "--session-only" in args
    clean_args = [a for a in args if a not in ("--json", "-j", "--session-only")]

    cfg = load_config()
    current_model = session_context.get("options", {}).get("ai_model") or cfg.get("ai_model", "")
    current_provider = session_context.get("options", {}).get("ai_provider") or cfg.get("ai_provider", "ollama")

    # ── Subcommand: /model set-key <provider> <api_key> ──────────────
    if clean_args and clean_args[0] == "set-key":
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
            emit.banner("HELLHOUND AI MODELS")
            emit.info(f"Active Provider: {current_provider} | Active Model: {current_model or '(default)'}\n")
            if models:
                for m in models:
                    curr_flag = " \033[92m(current)\033[0m" if m.get("current") else ""
                    emit(f"  • [{m['provider'].upper()}] {m['name']}{curr_flag}")
            else:
                emit.warn("No local Ollama models or cloud API keys configured.")
            # Usage hint
            emit(f"")
            emit.info("To add a cloud provider:  /model set-key <provider> <api_key>")
            emit.info("  Providers: nvidia, openai, anthropic, gemini")
            emit.info("To switch models:         /model <provider> <model_name>")
            emit.info("  e.g. /model nvidia nemotron-3-super-120b-a12b")
        return {
            "status": "success",
            "current_model": current_model,
            "provider": current_provider,
            "models": models
        }

    # ── Explicit provider form: /model <provider> <model_name> ───────
    if len(clean_args) >= 2 and clean_args[0].lower() in KNOWN_PROVIDERS:
        prov_hint = clean_args[0].lower()
        new_model = clean_args[1]
    else:
        new_model = clean_args[0]
        # Auto-detect provider from model name prefix
        prov_hint = None
        if "/" in new_model:
            # Slash-namespaced models are cloud models
            if any(kw in new_model for kw in ("llama", "mistral", "deepseek", "nemotron", "nvidia")):
                prov_hint = "nvidia"
        if prov_hint is None:
            if new_model.startswith("gpt-") or new_model.startswith("o1-"):
                prov_hint = "openai"
            elif new_model.startswith("claude-"):
                prov_hint = "anthropic"
            elif new_model.startswith("gemini-"):
                prov_hint = "gemini"

        # If we still couldn't detect, check if it's a known Ollama model
        if prov_hint is None:
            installed_ollama = {m["name"] for m in list_available_models() if m["provider"] == "ollama"}
            if new_model in installed_ollama:
                prov_hint = "ollama"
            else:
                # Ambiguous — warn and refuse
                if not is_json:
                    emit.warn(f"'{new_model}' is not an installed Ollama model and the provider could not be determined.")
                    emit.info(f"Specify the provider explicitly:  /model <provider> {new_model}")
                    emit.info(f"  e.g. /model nvidia {new_model}")
                return {"status": "error", "error": "ambiguous_provider", "model": new_model}

    # Validate that the target provider has credentials configured (unless it's ollama)
    if prov_hint != "ollama":
        api_keys = cfg.get("api_keys", {})
        legacy_key = cfg.get("api_key", "")
        has_key = bool(api_keys.get(prov_hint))
        if not has_key and legacy_key and legacy_key != "ollama":
            # Check if legacy key matches this provider
            detected_prov, _ = detect_ai_config(legacy_key)
            if detected_prov == prov_hint:
                has_key = True
        # Also check environment variables
        env_map = {"nvidia": "NVIDIA_API_KEY", "openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
        if not has_key and os.environ.get(env_map.get(prov_hint, ""), ""):
            has_key = True
        if not has_key:
            if not is_json:
                emit.warn(f"No API key configured for provider '{prov_hint}'.")
                emit.info(f"Set one first:  /model set-key {prov_hint} <your_api_key>")
            return {"status": "error", "error": "no_api_key", "provider": prov_hint}

    session_context.setdefault("options", {})["ai_model"] = new_model
    session_context.setdefault("options", {})["ai_provider"] = prov_hint

    if not session_only:
        cfg["ai_model"] = new_model
        cfg["ai_provider"] = prov_hint
        save_config(cfg)

    if not is_json:
        emit.success(f"AI model updated to: {new_model} (Provider: {prov_hint}) {'[Session Only]' if session_only else '[Persistent]'}")

    return {
        "status": "success",
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
        msg = "Invalid header format. Use: /headers Header-Name: Value"
        if not is_json:
            emit.warn(msg)
        return {"status": "error", "message": msg}


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
    /setup
    Interactive or automated environment and AI connectivity verification.
    """
    is_json = "--json" in args or getattr(emit, "json_mode", False)
    cfg = load_config()

    ollama_ok = ping_ollama()
    models = list_available_models()
    nv_key = os.environ.get("NVIDIA_API_KEY") or (cfg.get("api_keys", {}).get("nvidia") if isinstance(cfg.get("api_keys"), dict) else "") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("nvapi-") else "")
    gemini_key = os.environ.get("GEMINI_API_KEY") or (cfg.get("api_keys", {}).get("gemini") if isinstance(cfg.get("api_keys"), dict) else "") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("AIza") else "")
    openai_key = os.environ.get("OPENAI_API_KEY") or (cfg.get("api_keys", {}).get("openai") if isinstance(cfg.get("api_keys"), dict) else "") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("sk-") and not str(cfg.get("api_key", "")).startswith("sk-ant-") else "")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY") or (cfg.get("api_keys", {}).get("anthropic") if isinstance(cfg.get("api_keys"), dict) else "") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("sk-ant-") else "")

    status = {
        "ollama_connected": ollama_ok,
        "researcher_handle": cfg.get("researcher_handle", ""),
        "active_model": cfg.get("ai_model", ""),
        "active_provider": cfg.get("ai_provider", "ollama"),
        "available_models_count": len(models),
        "providers": {
            "ollama": ollama_ok,
            "nvidia": bool(nv_key),
            "gemini": bool(gemini_key),
            "openai": bool(openai_key),
            "anthropic": bool(anthropic_key)
        }
    }

    if not is_json:
        emit.banner("HELLHOUND ENVIRONMENT STATUS")
        emit(f"  Local Ollama: {'\033[92m[✓] Connected\033[0m' if ollama_ok else '\033[91m[x] Offline\033[0m'}")
        emit(f"  Researcher Handle: {status['researcher_handle'] or '(not set)'}")
        emit(f"  Active Model: {status['active_model'] or '(dynamic default)'} (Provider: {status['active_provider']})")
        emit(f"  Configured Providers:")
        for prov, has_key in status["providers"].items():
            state_str = "\033[92mConfigured\033[0m" if has_key else "\033[90mNot Set\033[0m"
            emit(f"    - {prov.upper()}: {state_str}")

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


def handle_help(args: List[str], session_context: Dict[str, Any], emit: Any) -> Dict[str, Any]:
    """
    /help
    Displays reference table for all available slash commands.
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
            "usage": cmd.usage,
            "description": cmd.description
        })

    if not is_json:
        emit.banner("HELLHOUND UNIFIED SLASH COMMANDS")
        for item in catalog:
            aliases_str = f" (Aliases: {', '.join(item['aliases'])})" if item['aliases'] else ""
            emit.info(f"{item['command']}{aliases_str} — {item['description']}")
            emit(f"  Usage: {item['usage']}\n")

    return {"status": "success", "commands": catalog}


# ─────────────────────────────────────────────────────────────
# REGISTER ALL SLASH COMMANDS
# ─────────────────────────────────────────────────────────────

register_command(Command(
    name="/recon",
    aliases=["/surface", "/spider"],
    description="Run target reconnaissance pipeline with scope verification",
    usage="/recon <target> [--json]",
    handler=handle_recon
))

register_command(Command(
    name="/scan",
    aliases=["/strike"],
    description="Execute a specific discovery/analysis module against target",
    usage="/scan <module> [target] [--json] [key=val...]",
    handler=handle_scan
))

register_command(Command(
    name="/hunt",
    aliases=["/auto"],
    description="Execute an autonomous, scope-aware multi-stage hunt and triage",
    usage="/hunt [target] [--json]",
    handler=handle_hunt
))

register_command(Command(
    name="/scope",
    aliases=["/rules"],
    description="Inspect, clear, or configure program scope rules for target",
    usage="/scope [show | clear | <rules_text>]",
    handler=handle_scope
))

register_command(Command(
    name="/model",
    aliases=["/ai"],
    description="Inspect or set persistent AI model and provider",
    usage="/model [model_name] [--session-only]",
    handler=handle_model
))

register_command(Command(
    name="/headers",
    aliases=["/head"],
    description="Manage global custom HTTP request headers and BugBounty handle",
    usage="/headers [Header: Value | --clear]",
    handler=handle_headers
))

register_command(Command(
    name="/report",
    aliases=["/loot"],
    description="Generate structured bug bounty reconnaissance report",
    usage="/report [--format html|json]",
    handler=handle_report
))

register_command(Command(
    name="/setup",
    aliases=["/health"],
    description="Verify local Ollama, cloud API keys, and environment",
    usage="/setup",
    handler=handle_setup
))

register_command(Command(
    name="/ask",
    aliases=["/chat"],
    description="Query AI assistant with session context and tool access",
    usage="/ask <question>",
    handler=handle_ask
))

register_command(Command(
    name="/help",
    aliases=["/?"],
    description="Show all available slash commands and usage",
    usage="/help",
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
    command = get_command(cmd_token)
    if command and command.handler:
        result = command.handler(args, session_context, emit)
        if "--json" in tokens or getattr(emit, "json_mode", False):
            print(json.dumps(result, indent=2))
        return result

    # Check if user typed bare command name (e.g. 'help', 'setup', 'model', 'scope', or short 'recon <domain>')
    if not cmd_token.startswith("/"):
        conversational_words = {"this", "the", "target", "and", "see", "find", "what", "how", "why", "is", "can", "we", "if", "please", "check", "audit", "run", "do"}
        is_conversational = len(tokens) > 2 or any(t.lower() in conversational_words for t in tokens)

        if not is_conversational:
            command_fallback = get_command("/" + cmd_token)
            if command_fallback and command_fallback.handler:
                result = command_fallback.handler(args, session_context, emit)
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

    emit.warn(f"Unknown command '{cmd_token}'. Type /help for available commands.")
    return {"status": "error", "error": "unknown_command", "command": cmd_token}
