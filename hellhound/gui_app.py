"""
hellhound/gui_app.py

Modern single-process PyWebView application for HELLHOUND.
Exposes HellhoundAPI directly to the frontend JavaScript runtime without
any Electron/IPC serialization overhead.
"""

import warnings
warnings.filterwarnings("ignore", message=".*urllib3.*match a supported version.*")
warnings.filterwarnings("ignore", message=".*RequestsDependencyWarning.*")

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Dict, Any, List, Optional

from hellhound.core.agent import Agent
from hellhound.core.tasks import (
    list_targets,
    create_or_load_target,
    save_target,
    set_scope,
    sanitize_target_name,
    _get_targets_dir
)
from hellhound.core.ai_utils import load_config, ThinkingIndicator
from hellhound.core.toolcheck import check_all_tools

logger = logging.getLogger("hellhound.gui")


class GuiEmit:
    """Emits agent progress and tool execution events to PyWebView."""
    def __init__(self, window=None, target_name: str = ""):
        self.window = window
        self.target_name = target_name
        self.events: List[Dict[str, Any]] = []
        self.tokens = 0
        self._last_status_push = 0.0
        self.indicator = ThinkingIndicator(status_callback=self._send_js)
        self.indicator.start()

    def _send_js(self, event_type: str, payload: Any):
        if event_type == "status" and self.events and self.events[-1]["type"] == "status":
            self.events[-1]["payload"] = payload
            self.events[-1]["time"] = datetime.now(timezone.utc).isoformat()
        else:
            self.events.append({"type": event_type, "payload": payload, "time": datetime.now(timezone.utc).isoformat()})

        if event_type == "status":
            # The underlying ThinkingIndicator ticks ~12x/second for a smooth
            # CLI terminal spinner. That's fine for a direct stdout rewrite,
            # but pushed through evaluate_js it means 12 new IPC calls a
            # second driving a single "what's happening now" line — throttle
            # this specific event type; every other event type (tool_start,
            # tool_result, token, etc.) still dispatches immediately.
            now = time.time()
            if now - self._last_status_push < 0.35:
                return
            self._last_status_push = now

        if self.window:
            try:
                js_code = f"if (window.onAgentEmit) {{ window.onAgentEmit({json.dumps({'target': self.target_name, 'type': event_type, 'payload': payload})}); }}"
                self.window.evaluate_js(js_code)
            except Exception as e:
                logger.warning(f"[GuiEmit] evaluate_js failed: {e}")

    def info(self, msg: str):
        self.indicator.info(msg)

    def warn(self, msg: str):
        self.indicator.warn(msg)

    def error(self, msg: str):
        self.indicator.error(msg)

    def success(self, msg: str):
        self.indicator.success(msg)

    def set_label(self, label: str):
        self.indicator.set_label(label)

    def tool_start(self, tool_name: str, args: Dict[str, Any]):
        self.indicator.tool_start(tool_name, args)

    def tool_result(self, tool_name: str, result: Any):
        self.indicator.tool_result(tool_name, result)

    def progress_start(self, desc: str):
        self.set_label(f"RUNNING: {desc}")

    def progress_stop(self):
        self.set_label("THINKING...")

    def set_token_count(self, count: int):
        self.tokens += count

    def request_approval(self, tool_name: str, method: str, url: str, reason: str) -> bool:
        """
        Blocks and shows a native confirm() dialog via PyWebView's synchronous
        evaluate_js, so destructive-action approval actually works from the
        GUI. Previously guard.check_request()'s 'require_approval' decision
        only had a code path for sys.stdin.isatty() — GUI sessions always
        fell through to the "non-interactive" branch, so any approval-gated
        action was permanently blocked with zero way to ever authorize it
        (no UI anywhere ever looked for the requires_approval flag).
        """
        if not self.window:
            return False
        msg = (
            f"GUARD APPROVAL REQUIRED\\n\\nTool: {tool_name}\\nAction: {method} {url}\\n"
            f"Reason: {reason}\\n\\nAuthorize this destructive action?"
        )
        try:
            result = self.window.evaluate_js(f"confirm({json.dumps(msg)})")
            return bool(result)
        except Exception as e:
            logger.warning(f"[GuiEmit] approval dialog failed: {e}")
            return False

    def __call__(self, msg: Any):
        if isinstance(msg, str):
            self.info(msg)
        else:
            self._send_js("info", msg)


class HellhoundAPI:
    """Python API bridge exposed directly to window.pywebview.api in JavaScript."""

    def __init__(self):
        self._agents: Dict[str, Agent] = {}
        self._cancel_flags: Dict[str, bool] = {}
        self._window = None

    def set_window(self, window):
        self._window = window

    # ── TARGET MANAGEMENT ──────────────────────────────────────────────

    def list_targets(self) -> List[Dict[str, Any]]:
        """Returns all targets with summary metadata and finding counts."""
        target_names = list_targets(exclude_default=False)
        results = []
        for name in target_names:
            try:
                t = create_or_load_target(name)
                # Compute total finding count
                findings_count = len(t.findings)
                for cat in ["subdomains", "open_ports", "live_hosts", "takeover_candidates", "endpoints", "tls_info"]:
                    items = t.state.get(cat, [])
                    if isinstance(items, list):
                        findings_count += len(items)

                in_scope_count = len(t.scope_rules.in_scope) if t.scope_rules else 0
                scope_str = t.scope_summary or f"{in_scope_count} in-scope rules"

                results.append({
                    "name": t.name,
                    "created_at": t.created_at,
                    "last_active": t.last_active,
                    "scope_summary": scope_str,
                    "findings_count": findings_count,
                    "notes": t.notes or "",
                })
            except Exception:
                continue

        return results

    def create_target(self, name: str) -> Dict[str, Any]:
        """Creates or loads a target and returns its structured representation."""
        clean_name = sanitize_target_name(name)
        target = create_or_load_target(clean_name)
        return target.to_dict()

    def get_target(self, name: str) -> Dict[str, Any]:
        """Retrieves a single target's full details."""
        clean_name = sanitize_target_name(name)
        target = create_or_load_target(clean_name)
        return target.to_dict()

    def delete_target(self, name: str) -> Dict[str, Any]:
        """Deletes a target and its associated task data directory."""
        clean_name = sanitize_target_name(name)
        if clean_name == "default":
            return {"status": "error", "message": "Cannot delete default target."}

        target_dir = os.path.join(_get_targets_dir(), clean_name)
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)

        if clean_name in self._agents:
            del self._agents[clean_name]
        if clean_name in self._cancel_flags:
            del self._cancel_flags[clean_name]

        return {"status": "ok", "deleted": clean_name}

    def set_scope(self, target_name: str, scope_text: str) -> Dict[str, Any]:
        """Updates scope rules for a specific target."""
        clean_name = sanitize_target_name(target_name)
        target = create_or_load_target(clean_name)
        updated = set_scope(target, scope_text)
        return updated.to_dict()

    # ── STRUCTURALLY TARGET-SCOPED FINDINGS ─────────────────────────────

    def get_findings(self, target_name: str) -> Dict[str, Any]:
        """
        Reads findings directly from this target's own isolated task.json state.
        Structurally guarantees zero data bleed across targets.
        """
        clean_name = sanitize_target_name(target_name)
        target = create_or_load_target(clean_name)

        categories = {
            "takeover_candidates": list(target.state.get("takeover_candidates", [])),
            "subdomains": list(target.state.get("subdomains", [])),
            "open_ports": list(target.state.get("open_ports", [])),
            "live_hosts": list(target.state.get("live_hosts", [])),
            "endpoints": list(target.state.get("endpoints", [])),
            "tls_info": list(target.state.get("tls_info", [])),
            "vulnerabilities": list(target.findings or target.state.get("vulnerabilities", [])),
        }

        total_count = sum(len(v) for v in categories.values())

        return {
            "target": target.name,
            "total_count": total_count,
            "categories": categories,
            "findings": target.findings,
            "state": target.state,
        }

    # ── CONVERSATION & CHAT THREAD ─────────────────────────────────────

    def get_chat_history(self, target_name: str) -> List[Dict[str, Any]]:
        """Retrieves persisted chat conversation for the given target."""
        clean_name = sanitize_target_name(target_name)
        target = create_or_load_target(clean_name)
        return list(target.state.get("chat_history", []))

    def clear_chat_history(self, target_name: str) -> Dict[str, Any]:
        """Clears the chat conversation history for the given target."""
        clean_name = sanitize_target_name(target_name)
        target = create_or_load_target(clean_name)
        target.state["chat_history"] = []
        save_target(target)

        if clean_name in self._agents:
            self._agents[clean_name].history = []

        return {"status": "ok", "cleared": clean_name}

    def send_message(self, target_name: str, text: str) -> Dict[str, Any]:
        """
        Executes a user message / slash command through the Agent for the specific target.
        """
        clean_name = sanitize_target_name(target_name)
        target = create_or_load_target(clean_name)

        # Clear cancel flag
        self._cancel_flags[clean_name] = False

        # Get or create cached Agent instance for this target
        agent = self._agents.get(clean_name)
        if agent is None:
            agent = Agent(target)
            self._agents[clean_name] = agent
        else:
            agent.target = target

        gui_emit = GuiEmit(window=self._window, target_name=clean_name)
        start_time = time.time()
        try:
            gui_emit.set_label("INITIALIZING RECON ENGINE")

            now_iso = datetime.now(timezone.utc).isoformat()

            # Record user message in target chat history
            if "chat_history" not in target.state:
                target.state["chat_history"] = []
            target.state["chat_history"].append({
                "role": "user",
                "content": text,
                "timestamp": now_iso,
            })
            save_target(target)

            try:
                session_ctx = {
                    "target": clean_name,
                    "options": {},
                    "scope_rules": target.scope_rules
                }

                if text.strip().startswith("/"):
                    from hellhound.core.commands import dispatch
                    res = dispatch(
                        text,
                        session_ctx,
                        gui_emit,
                        cancel_check=lambda: self._cancel_flags.get(clean_name, False)
                    )
                    if isinstance(res, dict):
                        response_text = res.get("advice") or res.get("response") or res.get("message") or json.dumps(res, indent=2)
                    else:
                        response_text = str(res)
                else:
                    response_text = agent.handle_message(
                        text,
                        session_context=session_ctx,
                        emit=gui_emit,
                        cancel_check=lambda: self._cancel_flags.get(clean_name, False)
                    )

                # Check if cancelled mid-execution
                if self._cancel_flags.get(clean_name, False):
                    response_text += "\n\n*[Execution stopped by user]*"

                # Reload target to capture updated findings/state from tool executions
                target = create_or_load_target(clean_name)

                # Extract finding chips
                finding_chips = []
                if target.state.get("takeover_candidates"):
                    finding_chips.append({"category": "takeover_candidates", "label": "Takeovers", "count": len(target.state["takeover_candidates"])})
                if target.state.get("subdomains"):
                    finding_chips.append({"category": "subdomains", "label": "Subdomains", "count": len(target.state["subdomains"])})
                if target.state.get("open_ports"):
                    finding_chips.append({"category": "open_ports", "label": "Open Ports", "count": len(target.state["open_ports"])})
                if target.state.get("live_hosts"):
                    finding_chips.append({"category": "live_hosts", "label": "Live Hosts", "count": len(target.state["live_hosts"])})
                if target.state.get("endpoints"):
                    finding_chips.append({"category": "endpoints", "label": "Endpoints", "count": len(target.state["endpoints"])})
                if target.findings or target.state.get("vulnerabilities"):
                    vuln_count = len(target.findings) or len(target.state.get("vulnerabilities", []))
                    finding_chips.append({"category": "vulnerabilities", "label": "Vulnerabilities", "count": vuln_count})

                end_time = time.time()
                time_sec = int(end_time - start_time)
                metrics = {"tokens": gui_emit.tokens, "time_sec": time_sec}

                # Record assistant response
                target.state["chat_history"].append({
                    "role": "assistant",
                    "content": response_text,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "chips": finding_chips,
                    "emits": gui_emit.events,
                    "metrics": metrics,
                })
                save_target(target)

                return {
                    "status": "ok",
                    "response": response_text,
                    "target": clean_name,
                    "chips": finding_chips,
                    "emits": gui_emit.events,
                    "metrics": metrics,
                }

            except Exception as e:
                err_msg = f"Error processing query: {str(e)}"
                target.state["chat_history"].append({
                    "role": "assistant",
                    "content": f"❌ {err_msg}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "chips": [],
                    "emits": gui_emit.events,
                })
                save_target(target)
                return {
                    "status": "error",
                    "error": str(e),
                    "response": f"❌ {err_msg}",
                    "target": clean_name,
                    "chips": [],
                }
        finally:
            gui_emit.indicator.stop()

    def stop_request(self, target_name: str) -> Dict[str, Any]:
        """Signals cancellation for the active request on the specified target."""
        clean_name = sanitize_target_name(target_name)
        self._cancel_flags[clean_name] = True
        return {"status": "ok", "message": f"Stop signal sent for target {clean_name}"}

    # ── SYSTEM & ENVIRONMENT INFO / SETTINGS ───────────────────────────

    def get_system_info(self) -> Dict[str, Any]:
        """Returns model configuration, active provider, and tool availability."""
        cfg = load_config()
        tools_status = check_all_tools()
        return {
            "ai_model": cfg.get("orchestrator_model", cfg.get("ai_model", "qwen2.5:3b-instruct")),
            "ai_provider": cfg.get("orchestrator_provider", cfg.get("ai_provider", "ollama")),
            "orchestrator_provider": cfg.get("orchestrator_provider", cfg.get("ai_provider", "ollama")),
            "orchestrator_model": cfg.get("orchestrator_model", cfg.get("ai_model", "qwen2.5:3b-instruct")),
            "synthesizer_provider": cfg.get("synthesizer_provider", "nvidia"),
            "synthesizer_model": cfg.get("synthesizer_model", "nvidia/nemotron-3-super-120b-a12b"),
            "researcher_handle": cfg.get("researcher_handle", ""),
            "tools": tools_status,
            "version": "12.7.0",
        }

    def get_settings(self) -> Dict[str, Any]:
        """Returns full configuration state and tool dependencies for the Settings UI."""
        cfg = load_config()
        tools_status = check_all_tools()
        return {
            "orchestrator_provider": cfg.get("orchestrator_provider", cfg.get("ai_provider", "ollama")),
            "orchestrator_model": cfg.get("orchestrator_model", cfg.get("ai_model", "qwen2.5:3b-instruct")),
            "synthesizer_provider": cfg.get("synthesizer_provider", "nvidia"),
            "synthesizer_model": cfg.get("synthesizer_model", "nvidia/nemotron-3-super-120b-a12b"),
            "api_keys": cfg.get("api_keys", {}),
            "researcher_handle": cfg.get("researcher_handle", ""),
            "global_headers": cfg.get("global_headers", {}),
            "auto_install_missing_tools": cfg.get("auto_install_missing_tools", False),
            "tools": tools_status,
            "version": "12.7.0",
        }

    def save_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        """Saves updated settings and persists to config.json."""
        from hellhound.core.ai_utils import save_config
        cfg = load_config()

        if "orchestrator_provider" in settings:
            cfg["orchestrator_provider"] = str(settings["orchestrator_provider"]).strip().lower()
            cfg["ai_provider"] = cfg["orchestrator_provider"]
        if "orchestrator_model" in settings:
            cfg["orchestrator_model"] = str(settings["orchestrator_model"]).strip()
            cfg["ai_model"] = cfg["orchestrator_model"]
        if "synthesizer_provider" in settings:
            cfg["synthesizer_provider"] = str(settings["synthesizer_provider"]).strip().lower()
        if "synthesizer_model" in settings:
            cfg["synthesizer_model"] = str(settings["synthesizer_model"]).strip()
        if "api_keys" in settings and isinstance(settings["api_keys"], dict):
            if "api_keys" not in cfg:
                cfg["api_keys"] = {}
            for k, v in settings["api_keys"].items():
                if v and str(v).strip():
                    cfg["api_keys"][k.lower()] = str(v).strip()
        if "researcher_handle" in settings:
            cfg["researcher_handle"] = str(settings["researcher_handle"]).strip()
        if "global_headers" in settings and isinstance(settings["global_headers"], dict):
            cfg["global_headers"] = settings["global_headers"]
        if "auto_install_missing_tools" in settings:
            cfg["auto_install_missing_tools"] = bool(settings["auto_install_missing_tools"])

        success = save_config(cfg)
        return {"status": "ok" if success else "error", "settings": self.get_settings()}

    def install_missing_tools(self) -> Dict[str, Any]:
        """Triggers installation of missing PD/standalone tools."""
        from hellhound.core.toolcheck import try_install, check_all_tools
        status = check_all_tools()
        installed_now = []
        failed = []
        for t in status.get("missing_pd", []) + status.get("missing_other", []):
            if try_install(t):
                installed_now.append(t)
            else:
                failed.append(t)
        return {
            "status": "ok",
            "installed_now": installed_now,
            "failed": failed,
            "tools": check_all_tools()
        }

    # ── WINDOW CONTROLS ────────────────────────────────────────────────

    def minimize_window(self):
        if self._window:
            self._window.minimize()

    def toggle_fullscreen(self):
        if self._window:
            self._window.toggle_fullscreen()

    def close_window(self):
        if self._window:
            self._window.destroy()


def _detect_gui_backend() -> Optional[str]:
    """Detects available GUI framework for pywebview to prevent GTK fallback error traces."""
    try:
        import gi  # noqa: F401
        return "gtk"
    except Exception:
        pass
    try:
        import qtpy  # noqa: F401
        return "qt"
    except Exception:
        pass
    try:
        import PyQt6  # noqa: F401
        return "qt"
    except Exception:
        pass
    try:
        import PyQt5  # noqa: F401
        return "qt"
    except Exception:
        pass
    return None


def launch_gui(target: Optional[str] = None, debug: bool = False):
    """Launches the PyWebView GUI application."""
    import webview

    gui_dir = Path(__file__).resolve().parent.parent / "gui"
    html_path = gui_dir / "app.html"

    if not html_path.exists():
        raise FileNotFoundError(f"GUI layout file not found at {html_path}")

    # Ensure target exists if provided
    if target:
        create_or_load_target(target)

    api = HellhoundAPI()

    window = webview.create_window(
        title="HELLHOUND | BOUNTY HUNTER",
        url=str(html_path),
        js_api=api,
        width=1360,
        height=880,
        min_size=(960, 640),
        background_color="#020204",
        frameless=False,
    )
    api.set_window(window)

    backend = _detect_gui_backend()
    if backend:
        webview.start(gui=backend, debug=debug)
    else:
        webview.start(debug=debug)


if __name__ == "__main__":
    import sys
    t = sys.argv[1] if len(sys.argv) > 1 else None
    launch_gui(target=t)