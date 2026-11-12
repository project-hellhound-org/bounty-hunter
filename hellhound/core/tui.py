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
import re
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
from hellhound.core.tui_banners import random_banner


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


def _maybe_pretty_json(text: str) -> str:
    """If text is a JSON object/array (a common API response body), indent it so
    it's human-readable instead of a one-line blob. Otherwise return unchanged."""
    t = text.strip()
    if not (t[:1] in "{[" and t[-1:] in "}]"):
        return text
    try:
        import json as _json
        return _json.dumps(_json.loads(t), indent=2, ensure_ascii=False)
    except Exception:
        return text


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
            lines.append(_maybe_pretty_json(str(body))[:cap])
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


_STATUS_RE = re.compile(r'^\s*\[(\d{3})\]\s*(.*)$')


def _colorize_log(raw: str) -> str:
    """Status-aware colouring for a live log line so a crawl reads at a glance:
    2xx green, 3xx amber, 4xx orange, 5xx red; the URL/rest in gray. Returns Rich
    markup; a line with no [NNN] prefix becomes a plain gray line."""
    s = str(raw)
    m = _STATUS_RE.match(s)
    if not m:
        return f"[#9aa0ac]{_rich_escape(s)}[/]"
    code, rest = m.group(1), m.group(2)
    c = int(code)
    col = ("#4cc46a" if 200 <= c < 300 else
           "#e0a030" if 300 <= c < 400 else
           "#e0772d" if 400 <= c < 500 else "#e0554e")
    return f"[{col}]\\[{code}][/] [#848b97]{_rich_escape(rest)}[/]"


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

    _LIVE_TAIL = 200  # rolling cap so a huge crawl can't make one card unbounded
    # Mixed palette — red is the persona accent elsewhere, but a wall of red text
    # is tiring, so cards read like a status line: white tool name, gray args,
    # and a status-coloured glyph/suffix (amber running, green ok, red error).
    _C_NAME = "#f0f2f5"
    _C_ARGS = "#848b97"
    _C_RUN = "#e0a030"
    _C_OK = "#4cc46a"
    _C_ERR = "#e0554e"

    # Static assets (images/css/js/fonts) flood a crawl with noise — '[200]
    # …/products/49.jpg' x200 — that buries the real endpoints. Count them
    # instead of listing them.
    _ASSET_RE = re.compile(r'\.(?:png|jpe?g|gif|svg|webp|ico|bmp|css|js|mjs|woff2?|ttf|otf|eot|map|mp4|webm|pdf)(?:\?|#|$)', re.I)

    def __init__(self, tool_name: str, args: Dict[str, Any]) -> None:
        self._tool_name = tool_name
        self._args_summary = _summarize_args(args)
        self._result_text = "running…"
        self._live_lines: list = []
        self._asset_count = 0
        self._done = False
        self._body = Static("running…", markup=False)
        # Running cards start EXPANDED (watch live work); they auto-collapse when
        # the result lands, so the transcript settles into tidy done-cards.
        super().__init__(self._body, title=self._mk_title("●", self._C_RUN, "running"), collapsed=False)

    def _mk_title(self, glyph: str, glyph_color: str, suffix: str) -> str:
        name = _rich_escape(self._tool_name)
        args = _rich_escape(self._args_summary)
        suf = f"  [{glyph_color}]{_rich_escape(suffix)}[/]" if suffix else ""
        return (f"[{glyph_color}]{glyph}[/] [{self._C_NAME}]{name}[/]"
                f"[{self._C_ARGS}]({args})[/]{suf}")

    def append_live(self, batch: str) -> None:
        """Fold a tool's live output (e.g. fuzz_hunter/spider '[200] <url>' lines)
        INTO this card instead of the flat transcript, so it's collapsible with
        the tool and the transcript stays clean. No-op once the result has landed."""
        if self._done:
            return
        for ln in str(batch).split("\n"):
            ln = ln.strip()
            if not ln:
                continue
            if self._ASSET_RE.search(ln):
                self._asset_count += 1   # fold static-asset hits into a count
                continue
            self._live_lines.append(_colorize_log(ln))
        if len(self._live_lines) > self._LIVE_TAIL:
            self._live_lines = self._live_lines[-self._LIVE_TAIL:]
        n = len(self._live_lines)
        suffix = f"running · {n} hit{'s' if n != 1 else ''}"
        if self._asset_count:
            suffix += f" · {self._asset_count} assets"
        self.title = self._mk_title("●", self._C_RUN, suffix)
        body = list(self._live_lines)
        if self._asset_count:
            body.append(f"[#6b7280]· {self._asset_count} static assets (images, css, js) folded[/]")
        try:
            self._body.update(Content.from_markup("\n".join(body)))
        except Exception:
            self._body.update("\n".join(body))

    def set_result(self, result: Any) -> None:
        self._done = True
        ok = not (isinstance(result, dict) and (result.get("error") or result.get("blocked")))
        self.title = self._mk_title("✓" if ok else "✗", self._C_OK if ok else self._C_ERR, "")
        self._result_text = _format_tool_result(self._tool_name, result)
        self._body.update(self._result_text)
        self.collapsed = True   # tuck finished work away; click to re-open


# ── Emit bridge ──────────────────────────────────────────────────────────────

class TextualEmit(PlainEmit):
    """Routes every agent emit callback onto the Textual UI thread.

    PlainEmit's text methods (info/warn/success/section/finding/...) all funnel
    through `_send`, so overriding `_send` alone captures the lot and keeps
    them off stdout (which would corrupt the full-screen app). tool_start /
    tool_result / __call__ get their own widget-aware handling.
    """

    # Live tool output (fuzz_hunter/spider emit HUNDREDS of "[200] <url>" lines)
    # used to be one synchronous call_from_thread PER LINE — each marshaling onto
    # the UI thread and mounting a widget — which saturated the event loop and
    # starved key handling, so Ctrl+Q/Esc/typing froze during a big crawl. These
    # lines are now coalesced into throttled batches (one UI update per ~120ms, or
    # once 40 lines pile up), cutting the UI-thread pressure by 1-2 orders of
    # magnitude and keeping the TUI responsive.
    _FLUSH_INTERVAL = 0.12
    _FLUSH_MAX = 40

    def __init__(self, app: "HellhoundApp") -> None:
        super().__init__()
        self._app = app
        self._buf: list = []
        self._buf_lock = threading.Lock()
        self._last_flush = 0.0

    def _flush(self):
        with self._buf_lock:
            if not self._buf:
                return
            batch = "\n".join(self._buf)
            self._buf.clear()
            self._last_flush = time.monotonic()
        try:
            self._app.call_from_thread(self._app.route_live_output, batch)
        except Exception:
            pass

    def _send(self, msg):  # noqa: D401 - overrides PlainEmit
        flush_now = False
        with self._buf_lock:
            self._buf.append(str(msg))
            if len(self._buf) >= self._FLUSH_MAX or (time.monotonic() - self._last_flush) >= self._FLUSH_INTERVAL:
                flush_now = True
        if flush_now:
            self._flush()

    def __call__(self, msg):
        if msg and str(msg).strip():
            self._send(msg)

    def tool_start(self, tool_name: str, args: dict):
        self._flush()  # keep buffered log lines ordered ahead of this card
        try:
            self._app.call_from_thread(self._app.start_tool_card, tool_name, dict(args or {}))
        except Exception:
            pass

    def tool_result(self, tool_name: str, result: Any):
        self._flush()
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
    LogLine { color: #9aa0ac; margin: 0 0 1 1; }
    ToolCard { margin: 0 0 0 1; border: none; background: #0b0d12; }
    ToolCard > CollapsibleTitle { color: #cdd2db; background: #0b0d12; }
    ToolCard > CollapsibleTitle:hover { background: #1a1d26; }
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
        # The input box always holds keyboard focus (so you can type without
        # clicking first), which means plain Up/Down never reach the
        # transcript — they're claimed above for suggestion-nav/history
        # recall. Without an explicit binding, the ONLY way to review earlier
        # output is the mouse wheel, which doesn't exist over an SSH session
        # without mouse reporting. PageUp/PageDown give a keyboard path to
        # the same scrolling the mouse wheel already does.
        Binding("pageup", "scroll_transcript_up", "Scroll transcript up", show=False, priority=True),
        Binding("pagedown", "scroll_transcript_down", "Scroll transcript down", show=False, priority=True),
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
        self._active_cards: list = []  # running ToolCards, newest last — live output folds into the top one
        self._assistant_md: Optional[Markdown] = None  # live-rendered reply
        self._assistant_buf = ""                         # accumulated reply text
        self._last_md_flush = 0.0                        # throttle timestamp
        self._sugg_nav = False  # True once the user arrow-navigates the dropdown
        self._input_history: list = []   # submitted inputs, oldest-first (shell-style ↑/↓ recall)
        self._hist_pos: Optional[int] = None

    # -- lifecycle --
    def compose(self) -> ComposeResult:
        yield Horizontal(
            Static(random_banner(), id="logo", markup=True),
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
        self._check_ai_ready()

    @work(thread=True, exclusive=False)
    def _check_ai_ready(self) -> None:
        """Surface the classic UI's 'AI not configured' feedback on startup —
        run off the UI thread since it may ping Ollama."""
        issues = _ai_readiness()
        if not issues:
            return
        msg = ("[bold orange1][!][/bold orange1] No AI is fully configured yet — "
               + "; ".join(issues)
               + ". Set one with [bold red]/model[/bold red] (or [bold red]/model set-key <provider> <key>[/bold red]); "
               "until then hunting turns can't run.")
        try:
            self.call_from_thread(self.add_log_line, msg)
        except Exception:
            pass

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
    def _is_pinned_to_bottom(self) -> bool:
        """True if the transcript is scrolled all the way down (or has no
        overflow yet). Checked BEFORE mutating the transcript, since adding
        content changes max_scroll_y and would make the check meaningless
        if read after."""
        try:
            return self.query_one("#transcript", VerticalScroll).is_vertical_scroll_end
        except Exception:
            return True

    def _mount(self, widget, force_scroll: bool = False) -> None:
        # Classic-REPL parity fix: only auto-scroll to the bottom if the
        # researcher was already pinned there (or this is their own action,
        # force_scroll=True). Otherwise, a reply streaming in below keeps
        # yanking the view back down every ~100ms the moment they scroll up
        # mid-stream to re-read something earlier — they'd have to wait for
        # the whole turn to finish before they could look back. Checking
        # pinned-state BEFORE the mount (not after) matters: mounting new
        # content grows max_scroll_y, which would make an "already at the
        # bottom" researcher look un-pinned if checked afterward.
        transcript = self.query_one("#transcript", VerticalScroll)
        pinned = force_scroll or transcript.is_vertical_scroll_end
        transcript.mount(widget)
        if pinned:
            transcript.scroll_end(animate=False)

    def add_log_line(self, msg: str) -> None:
        msg = str(msg)
        try:
            content = Content.from_markup(msg)
        except Exception:
            content = Content(msg)  # literal, no markup
        self._mount(LogLine(content, raw=msg))

    def add_user_message(self, text: str) -> None:
        # Sending your own message always jumps you to the latest content,
        # like any chat app — this is the one case that should override a
        # scrolled-up position, since it's the researcher's own action.
        # Literal Content so brackets in the user's own text never parse as markup.
        self._mount(UserMessage(Content(f"❯ {text}")), force_scroll=True)

    def new_assistant_message(self) -> Markdown:
        # Reply renders LIVE into a Markdown widget as tokens stream in
        # (throttled), so formatting appears instantly like Claude Code
        # instead of only at the end.
        self._assistant_buf = ""
        self._last_md_flush = 0.0
        self._assistant_md = Markdown("")
        self._mount(self._assistant_md)
        return self._assistant_md

    def append_assistant_token(self, token: str) -> None:
        if self._assistant_md is None:
            self.new_assistant_message()
        self._assistant_buf += token
        now = time.monotonic()
        # Throttle the markdown re-parse to ~10x/sec so it stays smooth on a
        # fast token stream but still visibly renders as it arrives.
        if now - self._last_md_flush >= 0.1:
            self._last_md_flush = now
            # Read pinned-state BEFORE re-rendering the markdown — growing the
            # reply's rendered height changes max_scroll_y, same reasoning as
            # _mount() above. A researcher who scrolled up to re-read an
            # earlier message stays put; only a pinned-to-bottom researcher
            # tracks the live stream automatically.
            pinned = self._is_pinned_to_bottom()
            try:
                self._assistant_md.update(self._assistant_buf)
            except Exception:
                pass
            if pinned:
                self.query_one("#transcript", VerticalScroll).scroll_end(animate=False)

    def finalize_assistant_message(self, text: Optional[str]) -> None:
        # Prefer the authoritative cleaned return value (text) over the raw
        # streamed buffer: handle_message/dispatch already strip orchestrator
        # tool-call JSON and other noise, so the final render stops raw JSON
        # leaking into the transcript (a live-streamed token blob can contain
        # it; the final return does not).
        final = (text if (text and text.strip()) else self._assistant_buf) or ""
        final = final.strip()
        if _looks_like_tool_call_json(final):
            final = ""

        if self._assistant_md is not None:
            if final:
                try:
                    self._assistant_md.update(final)
                except Exception:
                    pass
            else:
                try:
                    self._assistant_md.remove()
                except Exception:
                    pass
            self._assistant_md = None
        elif final:
            self._mount(Markdown(final))
        self._assistant_buf = ""

    def route_live_output(self, batch: str) -> None:
        """A tool's live output goes INTO its card (collapsible, Claude-Code
        style) when one is running; only genuinely top-level status lines (no
        tool active) land in the flat transcript."""
        if self._active_cards:
            try:
                self._active_cards[-1].append_live(batch)
                return
            except Exception:
                pass
        self.add_log_line(batch)

    def start_tool_card(self, tool_name: str, args: Dict[str, Any]) -> None:
        card = ToolCard(tool_name, args)
        self._pending_cards.setdefault(tool_name, []).append(card)
        self._active_cards.append(card)
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
                self._active_cards.remove(card)
            except ValueError:
                pass
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
            # Fresh typing resets "did the user navigate the dropdown", so
            # Enter after typing submits instead of accepting a suggestion.
            self._sugg_nav = False
            self._suggest().update_for(event.value or "")

    def _suggest(self) -> SuggestionBox:
        return self.query_one(SuggestionBox)

    def action_sugg_next(self) -> None:
        # Dropdown showing -> move selection down; otherwise shell-style history
        # recall toward NEWER entries (down arrow).
        if self._suggest().display:
            self._sugg_nav = True
            self._suggest().move(1)
        else:
            self._history_recall(+1)

    def action_sugg_prev(self) -> None:
        # Dropdown showing -> move selection up; otherwise recall OLDER history
        # (up arrow), exactly like a terminal.
        if self._suggest().display:
            self._sugg_nav = True
            self._suggest().move(-1)
        else:
            self._history_recall(-1)

    def _history_recall(self, direction: int) -> None:
        """Walk submitted-input history with ↑/↓ and load it into the prompt,
        like a shell. ↑ (direction -1) goes older, ↓ (+1) newer; stepping past
        the newest clears to a fresh empty line."""
        hist = self._input_history
        if not hist:
            return
        try:
            inp = self.query_one("#prompt", Input)
        except Exception:
            return
        if self._hist_pos is None:
            self._hist_pos = len(hist)  # start just past the newest (the live line)
        new_pos = self._hist_pos + direction
        if new_pos < 0:
            new_pos = 0
        if new_pos >= len(hist):
            self._hist_pos = None
            inp.value = ""
            return
        self._hist_pos = new_pos
        inp.value = hist[new_pos]
        inp.cursor_position = len(inp.value)

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
        # Enter behavior (matches the classic completer):
        #  - still typing the COMMAND NAME (one "/token", not yet an exact
        #    command) -> Enter COMPLETES it (so "/se"+Enter -> "/setup "),
        #  - arrow-navigated into the list -> Enter accepts the highlighted one,
        #  - otherwise (full command, args, or plain text) -> Enter SUBMITS.
        # Tab always completes; Esc dismisses.
        box = self._suggest()
        raw = event.value or ""
        chosen = box.current_line() if box.display else None
        if chosen is not None:
            toks = raw.split()
            first = toks[0] if toks else ""
            typing_cmd_name = raw.startswith("/") and len(toks) <= 1 and not raw.endswith(" ")
            is_exact = typing_cmd_name and _is_exact_command(first)
            if (typing_cmd_name and not is_exact) or self._sugg_nav:
                inp = self.query_one("#prompt", Input)
                inp.value = chosen
                inp.cursor_position = len(chosen)
                self._sugg_nav = False
                box.update_for(chosen)
                return

        line = raw.strip()
        if not line:
            return

        # exit/quit work here the way they did in the classic REPL.
        if line.lower() in ("exit", "quit", ":q", ":q!", "/exit", "/quit"):
            self.exit()
            return

        # Record for shell-style ↑/↓ recall (skip consecutive dupes), and reset
        # the history cursor so the next ↑ starts from the newest entry.
        if not self._input_history or self._input_history[-1] != line:
            self._input_history.append(line)
        self._hist_pos = None

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

    def action_scroll_transcript_up(self) -> None:
        try:
            self.query_one("#transcript", VerticalScroll).scroll_page_up()
        except Exception:
            pass

    def action_scroll_transcript_down(self) -> None:
        try:
            self.query_one("#transcript", VerticalScroll).scroll_page_down()
        except Exception:
            pass

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
            elif _looks_autonomous_msg(line):
                # Plain message that clearly asks for a hands-off, run-to-
                # completion engagement — route through dispatch, whose plain-NL
                # path applies the same auto-continuation loop as /hunt (keeps
                # going class by class instead of stopping after the first batch).
                session_ctx = {
                    "target": self._agent.target.name,
                    "scope_rules": self._agent.target.scope_rules,
                    "options": {},
                }
                res = self._dispatch_fn(line, session_ctx, emit, on_token=on_token, cancel_check=self._cancel_event.is_set)
                if isinstance(res, dict):
                    final_text = res.get("response") or res.get("advice")
                elif isinstance(res, str):
                    final_text = res
                if session_ctx.get("target") and session_ctx["target"] != "default":
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
            emit._flush()  # push any trailing coalesced log lines before wrap-up
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


def _is_exact_command(token: str) -> bool:
    """True if `token` (e.g. '/setup') is already a complete, known command —
    so Enter submits it instead of re-completing it from the dropdown."""
    if not token:
        return False
    try:
        from hellhound.core.commands import get_command
        return bool(get_command(token) or get_command(token.lstrip("/")))
    except Exception:
        return False


def _ai_readiness() -> List[str]:
    """Returns a list of human-readable issues if the configured AI providers
    aren't usable yet (cloud provider with no key, or local Ollama not
    reachable). Empty list == good to go. Mirrors the classic UI's startup
    'AI not configured' feedback so a fresh install knows what to set."""
    issues: List[str] = []
    try:
        from hellhound.core.ai_utils import load_config
        cfg = load_config()
    except Exception:
        return issues
    api_keys = cfg.get("api_keys", {}) if isinstance(cfg.get("api_keys"), dict) else {}
    checked = set()
    for role in ("orchestrator", "synthesizer"):
        prov = str(cfg.get(f"{role}_provider") or cfg.get("ai_provider") or "ollama").lower()
        if prov in checked:
            continue
        checked.add(prov)
        if prov == "ollama":
            try:
                import requests as _rq
                _rq.get("http://localhost:11434/api/tags", timeout=1.5)
            except Exception:
                issues.append(f"{role}: local Ollama isn't reachable on :11434 (start it, or `/model {role} <cloud-provider> <model>`)")
        else:
            key = api_keys.get(prov) or os.environ.get(f"{prov.upper()}_API_KEY")
            if not key:
                issues.append(f"{role}: no {prov} API key set (`/model set-key {prov} <key>`)")
    return issues


def _looks_autonomous_msg(line: str) -> bool:
    """Plain message that asks for a hands-off run-to-completion engagement —
    routed through dispatch's auto-continuation loop (same as /hunt)."""
    try:
        from hellhound.core.commands import _looks_autonomous
        return _looks_autonomous(line)
    except Exception:
        return False


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