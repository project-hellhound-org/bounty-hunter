"""
hellhound/core/tui.py — Textual interactive terminal (Claude Code-style).

A real full-screen TUI: a scrollable transcript in the middle, a pinned
input at the bottom, and — the whole point — every tool call rendered as a
clickable, collapsible card that shows the REAL request/response (so you can
finally see exactly what a `curl` sent and got back, not just "a tool ran").

This module is the SHELL, not the brain. It reuses the exact same agent loop
(`Agent.handle_message`) and slash-command dispatch (`commands.dispatch`) the
classic REPL uses; it just renders their `emit`/`on_token` callbacks as
widgets instead of printing to scrollback. The classic prompt_toolkit UI
stays available as a fallback (set HELLHOUND_CLASSIC_UI=1, or it is used
automatically if this TUI fails to start).

Threading model: the agent turn runs in a Textual worker thread (it's a long,
blocking, network-bound call). Every emit/token callback fires on that worker
thread and marshals back onto the UI thread via `App.call_from_thread`, which
is the supported Textual pattern for exactly this.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, Optional

from rich.markup import escape as _rich_escape

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.content import Content
from textual.widgets import Collapsible, Footer, Input, Markdown, OptionList, Static
from textual.widgets.option_list import Option

from hellhound.core.emit import PlainEmit
from hellhound.core.tui_status import WorkingIndicator
from hellhound.core.tui_complete import compute_suggestions


# ── Small helpers ────────────────────────────────────────────────────────────

def _summarize_args(args: Dict[str, Any], limit: int = 90) -> str:
    """Compact one-line arg summary for a tool-card title (values truncated)."""
    if not isinstance(args, dict) or not args:
        return ""
    parts = []
    for k, v in args.items():
        vs = str(v)
        if len(vs) > 48:
            vs = vs[:45] + "…"
        parts.append(f"{k}={vs}")
    s = ", ".join(parts)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _format_tool_result(tool_name: str, result: Any, cap: int = 6000) -> str:
    """Render a tool result into readable text for a collapsible card body.

    For HTTP-shaped results (curl/response_diff/etc.) this surfaces the real
    status/headers/body so the researcher can see what actually happened on
    the wire — the exact visibility gap this TUI exists to close.
    """
    if result is None:
        return "(no result)"
    if isinstance(result, str):
        return result[:cap]
    if not isinstance(result, dict):
        return str(result)[:cap]

    lines = []
    # HTTP-shaped single response (curl, verify_finding replay, etc.)
    if "status_code" in result or "body_preview" in result:
        if result.get("url"):
            lines.append(f"URL: {result.get('url')}")
        if "status_code" in result:
            lines.append(f"Status: {result.get('status_code')}")
        hdrs = result.get("headers")
        if isinstance(hdrs, dict) and hdrs:
            shown = {k: hdrs[k] for k in list(hdrs)[:12]}
            lines.append("Response headers:")
            for k, v in shown.items():
                lines.append(f"  {k}: {v}")
        body = result.get("body_preview")
        if body:
            lines.append("")
            lines.append("Response body:")
            lines.append(str(body)[:cap])
        if result.get("isolation_note"):
            lines.append("")
            lines.append(f"[isolation] {result['isolation_note']}")
        return "\n".join(lines)[:cap]

    # response_diff-shaped
    if result.get("diff_type") in ("json", "text"):
        lines.append(result.get("summary", ""))
        for c in (result.get("field_changes") or [])[:40]:
            lines.append(f"  • {c.get('path')}: {c.get('baseline')!r} -> {c.get('test')!r}")
        for ln in (result.get("body_line_diff") or [])[:60]:
            lines.append(ln)
        return "\n".join(lines)[:cap]

    # Generic dict: show the useful fields, skip giant blobs.
    import json as _json
    try:
        pretty = _json.dumps(result, indent=2, default=str)
    except Exception:
        pretty = str(result)
    return pretty[:cap]


# ── Transcript widgets ───────────────────────────────────────────────────────

class UserMessage(Static):
    """A researcher message bubble."""


class AssistantMessage(Static):
    """A streamed assistant response; tokens are appended live."""

    def __init__(self) -> None:
        super().__init__("", markup=False)
        self._buf = ""

    def append(self, token: str) -> None:
        self._buf += token
        self.update(self._buf)

    @property
    def text(self) -> str:
        return self._buf


class LogLine(Static):
    """An inline status/info line (warn/success/section/etc.)."""

    def __init__(self, content, raw: str = "") -> None:
        super().__init__(content)
        self.raw = raw  # original message text, for introspection/tests


class SuggestionBox(OptionList):
    """Arrow-key dropdown of slash-command / argument suggestions, shown just
    above the input. Hidden when there's nothing to suggest."""

    def __init__(self) -> None:
        super().__init__(id="suggest")
        self._insert_lines: list = []  # parallel: option index -> full input line to apply

    def update_for(self, text: str) -> None:
        self.clear_options()
        self._insert_lines = []
        suggestions = compute_suggestions(text)
        if not suggestions:
            self.display = False
            return
        for new_line, label, meta in suggestions:
            self._insert_lines.append(new_line)
            self.add_option(Option(Content.from_markup(
                f"[white]{_rich_escape(label)}[/white]"
                + (f"  [dim]{_rich_escape(meta)}[/dim]" if meta else "")
            )))
        self.display = True
        self.highlighted = 0

    def current_line(self) -> Optional[str]:
        if self.display and self.highlighted is not None and 0 <= self.highlighted < len(self._insert_lines):
            return self._insert_lines[self.highlighted]
        return None

    def move(self, delta: int) -> None:
        if not self.display or not self._insert_lines:
            return
        cur = self.highlighted if self.highlighted is not None else 0
        self.highlighted = max(0, min(len(self._insert_lines) - 1, cur + delta))


class ToolCard(Collapsible):
    """A clickable, collapsible tool-call card.

    Collapsed: a one-line title (tool + arg summary + status glyph).
    Expanded: the real request/response / result body.
    """

    def __init__(self, tool_name: str, args: Dict[str, Any]) -> None:
        self._tool_name = tool_name
        self._args_summary = _summarize_args(args)
        self._result_text = "running…"
        self._body = Static("running…", markup=False)
        super().__init__(self._body, title=f"● {tool_name}({self._args_summary})", collapsed=True)

    def set_result(self, result: Any) -> None:
        ok = not (isinstance(result, dict) and (result.get("error") or result.get("blocked")))
        glyph = "✓" if ok else "✗"
        self.title = f"{glyph} {self._tool_name}({self._args_summary})"
        self._result_text = _format_tool_result(self._tool_name, result)
        self._body.update(self._result_text)


# ── Emit bridge ──────────────────────────────────────────────────────────────

class TextualEmit(PlainEmit):
    """Routes every agent emit callback onto the Textual UI thread.

    PlainEmit's text methods (info/warn/success/section/finding/...) all funnel
    through `_send`, so overriding `_send` alone captures the lot and keeps
    them off stdout (which would corrupt the full-screen app). tool_start /
    tool_result / __call__ get their own widget-aware handling.
    """

    def __init__(self, app: "HellhoundApp") -> None:
        super().__init__()
        self._app = app

    def _send(self, msg):  # noqa: D401 - overrides PlainEmit
        try:
            self._app.call_from_thread(self._app.add_log_line, str(msg))
        except Exception:
            pass

    def __call__(self, msg):
        if msg and str(msg).strip():
            self._send(msg)

    def tool_start(self, tool_name: str, args: dict):
        try:
            self._app.call_from_thread(self._app.start_tool_card, tool_name, dict(args or {}))
        except Exception:
            pass

    def tool_result(self, tool_name: str, result: Any):
        try:
            self._app.call_from_thread(self._app.finish_tool_card, tool_name, result)
        except Exception:
            pass

    # No-op spinner/progress hooks the agent may call — the UI shows liveness
    # via the input state and the streaming response, so these are silent.
    def set_label(self, label: str): pass
    def set_token_count(self, count: int): pass
    def stop_indicator(self): pass
    def restart_indicator(self, label: str = ""): pass


# ── The app ──────────────────────────────────────────────────────────────────

_LOGO = r"""[bold red]    ▲                 ▲
   /█\   .───────.   /█\
  /███\_/  ▄   ▄  \_/███\
 < ◥███   [bold white](●) (●)[/bold white]   ███◤ >
  \ ◥██    \___/    ██◤ /
   \__ \_  ▲ ▲ ▲  _/ __/
      \__\ ▼ ▼ ▼ /__/[/bold red]"""


class HellhoundApp(App):
    """Claude Code-style interactive terminal for Hellhound."""

    TITLE = "HELLHOUND — Bounty Hunter"
    CSS = """
    Screen { background: #0b0d12; }
    #banner { height: auto; background: #0b0d12; }
    #logo { width: auto; height: auto; color: red; padding: 0 2 0 1; }
    #baninfo { width: 1fr; height: auto; padding: 1 1 0 2; }
    #transcript { height: 1fr; padding: 1 2; background: #0b0d12; scrollbar-background: #0b0d12; scrollbar-color: #5a1f27; }
    UserMessage { color: $text; background: #1a1d26; margin: 2 0 1 0; padding: 0 1; border-left: thick red; }
    AssistantMessage { margin: 1 0 0 0; padding: 0 1; }
    Markdown { margin: 1 0 2 0; padding: 0 1; background: #0b0d12; }
    LogLine { color: $text-muted; margin: 0 0 1 1; }
    ToolCard { margin: 0 0 0 1; border: none; background: #0b0d12; }
    ToolCard > CollapsibleTitle { color: red; background: #0b0d12; }
    #working { height: 1; padding: 0 2; color: $text; }
    #suggest { height: auto; max-height: 10; margin: 0 1; border: round #7a2630; background: #141821; display: none; }
    #suggest > .option-list--option-highlighted { background: #5a1f27; color: $text; }
    #prompt { height: 3; border: round red; margin: 0 1; background: #0b0d12; }
    Footer { height: 1; background: #141821; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("escape", "cancel_turn", "Cancel turn"),
        Binding("down", "sugg_next", show=False, priority=True),
        Binding("up", "sugg_prev", show=False, priority=True),
        Binding("tab", "sugg_accept", show=False, priority=True),
    ]

    def __init__(
        self,
        initial_target: Optional[str] = None,
        agent: Any = None,
        dispatch_fn: Optional[Callable] = None,
    ) -> None:
        super().__init__()
        self._initial_target = initial_target or "default"
        self._agent = agent
        self._dispatch_fn = dispatch_fn
        self._cancel_event = threading.Event()
        self._pending_cards: Dict[str, list] = {}
        self._assistant: Optional[AssistantMessage] = None

    # -- lifecycle --
    def compose(self) -> ComposeResult:
        yield Horizontal(
            Static(_LOGO, id="logo", markup=True),
            Static("", id="baninfo", markup=True),
            id="banner",
        )
        yield VerticalScroll(id="transcript")
        yield WorkingIndicator(id="working")
        yield SuggestionBox()
        yield Input(placeholder="Ask Hellhound, or type /help … (type / for commands)", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        if self._agent is None:
            # Import lazily so tests can inject a fake agent without touching
            # the heavy real agent module / network.
            from hellhound.core.agent import get_agent
            self._agent = get_agent(self._initial_target)
        if self._dispatch_fn is None:
            from hellhound.core.commands import dispatch as _dispatch
            self._dispatch_fn = _dispatch
        self.query_one("#baninfo", Static).update(self._banner_info())
        self.query_one("#prompt", Input).focus()

    def _banner_info(self) -> str:
        """The at-a-glance context the old UI showed — model/provider, target,
        scope status, recent targets — minus the redundant product name (the
        logo already says who this is)."""
        tname = self._initial_target
        scope_active = False
        try:
            if self._agent is not None and getattr(self._agent, "target", None):
                tname = self._agent.target.name
                rules = getattr(self._agent.target, "scope_rules", None)
                scope_active = bool(rules and getattr(rules, "in_scope", None))
        except Exception:
            pass

        model = provider = handle = ""
        recent = ""
        try:
            from hellhound.core.ai_utils import load_config
            cfg = load_config()
            model = str(cfg.get("ai_model", "") or "")
            if len(model) > 26:
                model = model[:23] + "…"
            provider = str(cfg.get("ai_provider", "") or "").capitalize()
            handle = str(cfg.get("researcher_handle", "") or "")
        except Exception:
            pass
        try:
            from hellhound.core.tasks import list_targets
            others = [t for t in list_targets(exclude_default=True) if t != tname][:3]
            recent = ", ".join(others) if others else "none yet"
        except Exception:
            recent = "none yet"

        scope_str = "[bold red]Active Scope[/bold red]" if scope_active else "[dim]Default Scope[/dim]"
        who = (f"{model} ({provider})" if model else "—") + (f" · @{handle}" if handle else "")
        lines = [
            "[bold red]Welcome back,[/bold red] [bold white]Researcher.[/bold white]",
            f"[red]Model:[/red] [white]{_rich_escape(who)}[/white]",
            f"[red]Target:[/red] [bold white]{_rich_escape(str(tname))}[/bold white]  [dim]·[/dim] {scope_str}",
            f"[red]Recent:[/red] [white]{_rich_escape(recent)}[/white]",
            "[dim]Type[/dim] [bold red]/[/bold red] [dim]for commands,[/dim] [bold red]/help[/bold red] [dim]for all · Esc cancels · Ctrl+Q quits[/dim]",
        ]
        return "\n".join(lines)

    def refresh_banner(self) -> None:
        try:
            self.query_one("#baninfo", Static).update(self._banner_info())
        except Exception:
            pass

    # -- transcript mutations (always called on the UI thread) --
    def _mount(self, widget) -> None:
        self.query_one("#transcript", VerticalScroll).mount(widget)
        self.query_one("#transcript", VerticalScroll).scroll_end(animate=False)

    def add_log_line(self, msg: str) -> None:
        msg = str(msg)
        try:
            content = Content.from_markup(msg)
        except Exception:
            content = Content(msg)  # literal, no markup
        self._mount(LogLine(content, raw=msg))

    def add_user_message(self, text: str) -> None:
        # Literal Content so brackets in the user's own text never parse as markup.
        self._mount(UserMessage(Content(f"❯ {text}")))

    def new_assistant_message(self) -> AssistantMessage:
        self._assistant = AssistantMessage()
        self._mount(self._assistant)
        return self._assistant

    def append_assistant_token(self, token: str) -> None:
        if self._assistant is None:
            self.new_assistant_message()
        self._assistant.append(token)
        self.query_one("#transcript", VerticalScroll).scroll_end(animate=False)

    def finalize_assistant_message(self, text: Optional[str]) -> None:
        # Prefer the authoritative cleaned return value (text) over the raw
        # streamed buffer: handle_message/dispatch already strip orchestrator
        # tool-call JSON and other noise, so rendering `text` is what stops
        # raw JSON leaking into the transcript (a live-streamed token blob can
        # contain it; the final return does not).
        streamed = self._assistant.text if self._assistant is not None else ""
        final = (text if (text and text.strip()) else streamed) or ""
        final = final.strip()

        # Last-ditch guard: never render a bare tool-call JSON object as the
        # assistant reply (it's leaked internal plumbing, not prose).
        if _looks_like_tool_call_json(final):
            final = ""

        if self._assistant is not None:
            if final:
                try:
                    md = Markdown(final)
                    self.query_one("#transcript", VerticalScroll).mount(md, after=self._assistant)
                except Exception:
                    pass  # keep the raw Static if markdown mount fails
            self._assistant.remove()
        elif final:
            self.query_one("#transcript", VerticalScroll).mount(Markdown(final))
        self._assistant = None

    def start_tool_card(self, tool_name: str, args: Dict[str, Any]) -> None:
        card = ToolCard(tool_name, args)
        self._pending_cards.setdefault(tool_name, []).append(card)
        self._mount(card)
        # Pin the spinner to the running tool so you can see WHAT is running.
        try:
            self.query_one("#working", WorkingIndicator).set_label(f"Running {tool_name}")
        except Exception:
            pass

    def finish_tool_card(self, tool_name: str, result: Any) -> None:
        stack = self._pending_cards.get(tool_name)
        if stack:
            card = stack.pop(0)
            try:
                card.set_result(result)
            except Exception:
                pass
        # Back to the rotating phrases between tools.
        try:
            self.query_one("#working", WorkingIndicator).set_label("")
        except Exception:
            pass

    # -- autocomplete wiring --
    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "prompt":
            self._suggest().update_for(event.value or "")

    def _suggest(self) -> SuggestionBox:
        return self.query_one(SuggestionBox)

    def action_sugg_next(self) -> None:
        self._suggest().move(1)

    def action_sugg_prev(self) -> None:
        self._suggest().move(-1)

    def action_sugg_accept(self) -> None:
        """Tab: fill the input with the highlighted suggestion."""
        line = self._suggest().current_line()
        if line is not None:
            inp = self.query_one("#prompt", Input)
            inp.value = line
            inp.cursor_position = len(line)
            self._suggest().update_for(line)  # cascade (e.g. /scope -> its subcommands)

    # -- input handling --
    def on_input_submitted(self, event: Input.Submitted) -> None:
        # If the dropdown is open with a highlight, Enter accepts the
        # suggestion into the input rather than submitting — same feel as the
        # old prompt_toolkit completer.
        box = self._suggest()
        chosen = box.current_line()
        if chosen is not None:
            inp = self.query_one("#prompt", Input)
            inp.value = chosen
            inp.cursor_position = len(chosen)
            box.update_for(chosen)
            return

        line = (event.value or "").strip()
        if not line:
            return

        # exit/quit work here the way they did in the classic REPL.
        if line.lower() in ("exit", "quit", ":q", ":q!", "/exit", "/quit"):
            self.exit()
            return

        inp = self.query_one("#prompt", Input)
        inp.value = ""
        box.update_for("")  # clear/hide dropdown
        inp.disabled = True
        self.add_user_message(line)
        self._cancel_event = threading.Event()
        try:
            self.query_one("#working", WorkingIndicator).start()
        except Exception:
            pass
        self.run_turn(line)

    def action_cancel_turn(self) -> None:
        # Esc first dismisses the dropdown if it's open, otherwise cancels the turn.
        box = self._suggest()
        if box.display:
            box.display = False
            return
        self._cancel_event.set()
        self.add_log_line("[bold orange1][!][/bold orange1] cancel requested — winding down this turn…")

    def _reenable_input(self) -> None:
        try:
            self.query_one("#working", WorkingIndicator).stop()
        except Exception:
            pass
        inp = self.query_one("#prompt", Input)
        inp.disabled = False
        inp.focus()

    # -- the worker: runs the real agent/dispatch off the UI thread --
    @work(thread=True, exclusive=True)
    def run_turn(self, line: str) -> None:
        emit = TextualEmit(self)

        def on_token(tok: str) -> None:
            try:
                self.call_from_thread(self.append_assistant_token, tok)
            except Exception:
                pass

        t0 = time.monotonic()
        final_text: Optional[str] = None
        try:
            if _looks_like_command(line):
                cmd_line = line if line.startswith("/") else "/" + line
                session_ctx = {
                    "target": self._agent.target.name,
                    "scope_rules": self._agent.target.scope_rules,
                    "options": {},
                }
                res = self._dispatch_fn(cmd_line, session_ctx, emit, on_token=on_token, cancel_check=self._cancel_event.is_set)
                if isinstance(res, dict):
                    final_text = res.get("advice") or res.get("response")
                elif isinstance(res, str):
                    final_text = res
                if session_ctx.get("target"):
                    try:
                        self._agent.set_target(session_ctx["target"])
                    except Exception:
                        pass
            else:
                next_input = line
                while True:
                    session_ctx = {
                        "target": self._agent.target.name,
                        "scope_rules": self._agent.target.scope_rules,
                    }
                    final_text = self._agent.handle_message(
                        next_input,
                        session_context=session_ctx,
                        emit=emit,
                        on_token=on_token,
                        cancel_check=self._cancel_event.is_set,
                    )
                    if session_ctx.get("target") and session_ctx["target"] != "default":
                        try:
                            self._agent.set_target(session_ctx["target"])
                        except Exception:
                            pass
                    self.call_from_thread(self.finalize_assistant_message, final_text)
                    if self._cancel_event.is_set():
                        break
                    if not getattr(self._agent, "_last_turn_auto_continue", False):
                        break
                    next_input = "continue"
                    self.call_from_thread(self.add_log_line, "[dim][*] Still mid-investigation — continuing on its own…[/dim]")
                    self.call_from_thread(self.new_assistant_message)
        except Exception as e:  # never let a turn crash the whole app
            self.call_from_thread(self.add_log_line, f"[bold red][✗][/bold red] turn error: {type(e).__name__}: {e}")
        finally:
            if _looks_like_command(line):
                self.call_from_thread(self.finalize_assistant_message, final_text)
            elapsed = time.monotonic() - t0
            es = f"{int(elapsed // 60)}m {int(elapsed % 60)}s" if elapsed >= 60 else f"{elapsed:.0f}s"
            self.call_from_thread(self.add_log_line, f"[dim]✳ Cooked for {es}[/dim]")
            self.call_from_thread(self.refresh_banner)  # target/scope may have changed
            self.call_from_thread(self._reenable_input)


def _looks_like_tool_call_json(text: str) -> bool:
    """True if `text` is (just) a raw orchestrator tool-call JSON blob that
    leaked past cleanup — e.g. {"tool": "curl", "args": {...}}. We never want
    to render that as the assistant's prose reply."""
    s = (text or "").strip()
    if not (s.startswith("{") and s.endswith("}")):
        return False
    try:
        import json as _json
        obj = _json.loads(s)
    except Exception:
        return False
    return isinstance(obj, dict) and ("tool" in obj or "args" in obj or "tool_call" in obj)


def _looks_like_command(line: str) -> bool:
    if line.startswith("/"):
        return True
    try:
        from hellhound.core.commands import get_command
        first = line.split()[0].lower()
        # Only treat a bare word as a command if it's short (not a sentence).
        if len(line.split()) <= 2 and (get_command(first) or get_command("/" + first)):
            return True
    except Exception:
        pass
    return False


def start_tui_session(initial_target: Optional[str] = None) -> None:
    """Launch the Textual interactive terminal."""
    HellhoundApp(initial_target=initial_target).run()
