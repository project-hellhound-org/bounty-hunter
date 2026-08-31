"""
hellhound/core/chat_ui.py

Claude Code-style Terminal Chat Interface for Hellhound Bounty Hunter.
Provides a modern, double-pane dashboard card, pixel mascot, recent activity tracker,
interactive slash command palette with live autocomplete dropdown via prompt_toolkit,
and clean response bubbles.
"""

import os
import sys
import shutil
import textwrap
import html
import re
import time
from typing import Optional, Dict, Any, List

from colorama import Fore, Back, Style, init
init(autoreset=True)

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style as PTStyle
from prompt_toolkit.widgets import Frame, TextArea
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import FloatContainer, Float, HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import Dimension as D
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.key_binding.defaults import load_key_bindings
from prompt_toolkit.key_binding.key_bindings import merge_key_bindings

from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel

rich_console = Console()


def _exit_message() -> str:
    """'Happy hacking' sign-off, personalized with researcher_handle from
    config when set — otherwise a generic version plus a hint on how to
    add one, so the personalization is discoverable rather than silently
    absent.
    """
    cfg = load_config()
    handle = (cfg.get("researcher_handle") or "").strip()
    if handle:
        return f" {C_RED_MAIN}[+] Happy hacking :) {handle}!{RST}\n"
    return (
        f" {C_RED_MAIN}[+] Happy hacking, researcher!{RST}\n"
        f" {C_TEXT_DIM}    Want your name here next time? Run /handle <name>.{RST}\n"
    )


def _auto_markdown_emphasis(text: str) -> str:
    """
    Safely highlights key signals in plain text.
    If the text already contains rich markdown formatting (code blocks, headers, bold, bullets),
    returns text untouched to prevent markdown corruption.
    """
    if not text:
        return text

    # If text already has markdown syntax, do not mutate it
    if any(sig in text for sig in ("```", "# ", "## ", "**", "__", "`http", "• ", "  - ")):
        return text

    out = text

    # HTTP status codes -> inline code
    out = re.sub(r'(?<![`\d])\b(1\d{2}|2\d{2}|3\d{2}|4\d{2}|5\d{2})\b(?![`\d])', r'`\1`', out)

    # Severity / impact keywords -> bold
    severity_words = (
        "CRITICAL", "VULNERABLE", "TAKEOVER", "BYPASS", "EXPOSED",
        "COMPROMISED", "SUCCESSFUL LOGIN", "AUTHENTICATED", "ACHIEVED",
    )
    for w in severity_words:
        out = re.sub(rf'(?<!\*)\b({re.escape(w)})\b(?!\*)', r'**\1**', out, flags=re.I)

    # Bare URLs -> inline code
    out = re.sub(r'(?<!`)(https?://[^\s`)]+)(?!`)', r'`\1`', out)

    return out

from hellhound.core.tasks import list_targets, create_or_load_target, Target
from hellhound.core.ai_utils import load_config
from hellhound.core.agent import get_agent
from hellhound.core.commands import dispatch, get_command, COMMAND_REGISTRY


# -------------------------------------------------------------
# Color & Style Palette (Hellhound Bounty Hunter Theme)
# -------------------------------------------------------------
C_RED_MAIN   = "\033[38;5;196;1m"   # Vibrant Crimson Red (Main headers & brand)
C_RED_ACCENT = "\033[38;5;203m"     # Soft Coral Red (Status errors, prompt & accents)
C_ORANGE     = "\033[38;5;208;1m"   # Neon Orange (Bullets, inline code & HTTP verbs)
C_GRAY_BOX   = "\033[38;5;240m"     # Subtle Box Gray
C_TEXT_WHITE = "\033[97;1m"         # Crisp Bold White
C_TEXT_DIM   = "\033[38;5;244m"        # Dim Gray Text
C_BOLD          = "\033[1m"
C_GREEN         = "\033[38;5;114;1m"   # Emerald Green (Code & 200 OK)
C_RESET         = "\033[0m"
RST          = Style.RESET_ALL

PT_CUSTOM_STYLE = PTStyle.from_dict({
    'prompt': '#ff1a1a bold',
    'frame.border': '#555555',
    'frame.label': '#888888',
    'completion-menu': 'bg:#1e1e1e #cccccc',
    'completion-menu.completion': 'bg:#1e1e1e #cccccc',
    'completion-menu.completion.current': 'bg:#880000 #ffffff bold',
    'completion-menu.meta': 'bg:#141414 #888888',
    'completion-menu.meta.current': 'bg:#550000 #ffffff',
    'scrollbar.background': 'bg:#1e1e1e',
    'scrollbar.button': 'bg:#444444',
})


def get_terminal_width() -> int:
    cols = shutil.get_terminal_size((90, 24)).columns
    return max(60, cols)


def re_strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


# -------------------------------------------------------------
# Slash Command Palette Completer
# -------------------------------------------------------------
class HellhoundCompleter(Completer):
    """
    Dynamic prompt_toolkit completer reading directly from COMMAND_REGISTRY.
    Displays slash commands with inline descriptions and usage syntax in an interactive dropdown.
    """
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/"):
            return

        tokens = text.split()
        if not tokens:
            return

        # 1. Base command completion
        if len(tokens) == 1 and not text.endswith(" "):
            target = tokens[0].lower()
            seen = set()
            for name, cmd in COMMAND_REGISTRY.items():
                if not name.startswith("/"):
                    continue
                if name in seen or name != cmd.name.lower():
                    continue
                seen.add(name)
                if name.startswith(target):
                    meta_parts = []
                    if cmd.description:
                        meta_parts.append(cmd.description)
                    if cmd.usage:
                        primary_usage = cmd.usage.split("\n")[0].strip()
                        meta_parts.append(f"[{primary_usage}]")
                    display_meta = " — ".join(meta_parts)
                    yield Completion(
                        cmd.name,
                        start_position=-len(target),
                        display=cmd.name,
                        display_meta=display_meta,
                    )
            return

        # 2. Subcommand & argument hints for specific commands
        cmd_name = tokens[0].lower()
        arg_text = text[len(tokens[0]):].lstrip()
        word_before = document.get_word_before_cursor()

        if cmd_name in ("/model", "/ai"):
            sub_suggestions = [
                ("orchestrator", "Configure fast local tool-selection model"),
                ("synthesizer", "Configure deep cloud-reasoning analysis model"),
                ("nvidia/nemotron-3-super-120b-a12b", "Nvidia Nemotron 120B (Synthesizer Cloud)"),
                ("anthropic/claude-3-5-sonnet", "Claude 3.5 Sonnet (Synthesizer Cloud)"),
                ("openai/gpt-4o", "GPT-4o (Synthesizer Cloud)"),
                ("deepseek/deepseek-chat", "DeepSeek V3 (Synthesizer Cloud)"),
                ("qwen2.5:3b-instruct-q4_0", "Local Ollama Model (Orchestrator)"),
                ("set-key", "Configure API key for provider (e.g. /model set-key nvidia <key>)"),
                ("--session-only", "Apply model to current session without saving config"),
            ]
            for val, meta in sub_suggestions:
                if val.lower().startswith(word_before.lower()):
                    yield Completion(val, start_position=-len(word_before), display=val, display_meta=meta)

        elif cmd_name in ("/setup", "/health", "/doctor"):
            sub_suggestions = [
                ("tools auto-install on", "Enable automated binary dependency installation"),
                ("tools auto-install off", "Disable automated binary dependency installation"),
                ("tools install-all", "Install all missing tool dependencies via pdtm"),
                ("recaps on", "Enable recap footers after multi-tool analysis"),
                ("recaps off", "Disable recap footers after multi-tool analysis"),
            ]
            for val, meta in sub_suggestions:
                if val.lower().startswith(arg_text.lower()):
                    yield Completion(val, start_position=-len(arg_text), display=val, display_meta=meta)

        elif cmd_name in ("/scope", "/rules"):
            sub_suggestions = [
                ("show", "View current target scope rules"),
                ("clear", "Clear active scope rules"),
            ]
            for val, meta in sub_suggestions:
                if val.lower().startswith(word_before.lower()):
                    yield Completion(val, start_position=-len(word_before), display=val, display_meta=meta)

        elif cmd_name in ("/report", "/loot"):
            sub_suggestions = [
                ("--format html", "Generate interactive HTML report"),
                ("--format json", "Generate structured JSON report"),
            ]
            for val, meta in sub_suggestions:
                if val.lower().startswith(arg_text.lower()):
                    yield Completion(val, start_position=-len(arg_text), display=val, display_meta=meta)

        elif cmd_name in ("/recon", "/surface", "/spider"):
            arg_tokens = arg_text.split()
            in_subdomains_mode = bool(arg_tokens) and arg_tokens[0].lower() in ("subdomains", "subdomain")

            if in_subdomains_mode:
                # Already-typed active/passive selector — don't re-suggest it
                already_has_mode = any(
                    t.lower() in ("active", "passive") for t in arg_tokens[1:]
                )
                already_has_permute = any(
                    t.lower() == "permute" for t in arg_tokens[1:]
                )
                sub_suggestions = []
                if not already_has_mode:
                    sub_suggestions += [
                        ("active", "DNS brute-force enumeration (CTF/lab targets, isolated zones)"),
                        ("passive", "CT-log/passive sources via subfinder (default for public targets)"),
                    ]
                if not already_has_permute:
                    sub_suggestions.append(
                        ("permute", "Generate + resolve mutated candidate subdomains from found hosts")
                    )
            else:
                sub_suggestions = [
                    ("subdomains", "Asset discovery only (dns_bruteforce/subfinder)"),
                    ("endpoints", "Content and endpoint discovery only (spider)"),
                    ("tech", "Live-host and technology fingerprinting only (httpx)"),
                ]

            for val, meta in sub_suggestions:
                if val.lower().startswith(word_before.lower()):
                    yield Completion(val, start_position=-len(word_before), display=val, display_meta=meta)


def render_banner_card(target_name: Optional[str] = None):
    r"""
    Renders the Claude Code-inspired double-pane card with exact character boundaries.
    """
    w = get_terminal_width()
    card_w = min(w - 4, 96)
    col1_w = (card_w // 2) - 2
    col2_w = card_w - col1_w - 5

    cfg = load_config()
    active_model = cfg.get("ai_model", "qwen2.5:3b-instruct-q4_0")
    if len(active_model) > 22:
        active_model = active_model[:19] + "..."
    active_prov = cfg.get("ai_provider", "ollama").capitalize()
    handle = cfg.get("researcher_handle", "")
    handle_str = f" • @{handle}" if handle else " • Hunter"

    # Targets & activity - read dynamically from ~/.hellhound/targets/
    targets = list_targets(exclude_default=True)
    curr_target = target_name or (targets[0] if targets else "default")
    t_obj = create_or_load_target(curr_target)
    scope_status = "Active Scope" if (t_obj.scope_rules and t_obj.scope_rules.in_scope) else "Default Scope"

    # Recent real user activity
    recent_targets = [t for t in targets if t != curr_target][:3]
    if not recent_targets and curr_target != "default":
        recent_targets = [curr_target]
    recent_str = ", ".join(recent_targets) if recent_targets else "No recent targets"

    title = " Bounty Hunter "
    # Top line total inner span = col1_w + col2_w + 5
    top_dashes = (col1_w + col2_w + 5) - len(title) - 1
    top_line = f"╭─{C_RED_MAIN}{title}{C_RED_ACCENT}" + ("─" * max(0, top_dashes)) + "╮"

    # Column 1 Lines (Left Pane)
    def center_ansi(text: str, width: int) -> str:
        raw_len = len(re_strip_ansi(text))
        if raw_len >= width:
            return text
        pad = (width - raw_len) // 2
        rem = width - raw_len - pad
        return (" " * pad) + text + (" " * rem)

    c1_lines = [
        "",
        center_ansi(f"{C_TEXT_WHITE}Welcome back, Researcher!{RST}", col1_w),
        "",
        center_ansi(f"{C_RED_MAIN}▲                 ▲{RST}", col1_w),
        center_ansi(f"{C_RED_ACCENT}/█\\   .───────.   /█\\{RST}", col1_w),
        center_ansi(f"{C_RED_MAIN}/███\\_/  ▄   ▄  \\_/███\\{RST}", col1_w),
        center_ansi(f"{C_RED_ACCENT}< ◥███   {C_TEXT_WHITE}(●) (●){C_RED_ACCENT}   ███◤ >{RST}", col1_w),
        center_ansi(f"{C_RED_MAIN}\\ ◥██    \\___/    ██◤ /{RST}", col1_w),
        center_ansi(f"{C_RED_ACCENT}\\__ \\_  ▲ ▲ ▲  _/ __/{RST}", col1_w),
        center_ansi(f"{C_RED_MAIN}\\__\\ ▼ ▼ ▼ /__/{RST}", col1_w),
        "",
        center_ansi(f"{C_TEXT_DIM}{active_model} ({active_prov}){handle_str}{RST}", col1_w),
        center_ansi(f"{C_TEXT_DIM}Target: {C_TEXT_WHITE}{curr_target[:18]}{C_TEXT_DIM} • {C_RED_ACCENT}{scope_status}{RST}", col1_w),
        ""
    ]

    # Column 2 Lines (Right Pane)
    tip1 = "Ask Hellhound to recon a target, enumerate subdomains, probe live tech, or audit API surfaces."
    tip1_wrapped = textwrap.wrap(tip1, width=col2_w - 2)
    while len(tip1_wrapped) < 2:
        tip1_wrapped.append("")

    c2_lines = [
        "",
        f"{C_ORANGE}Tips for getting started{RST}",
        f"{C_TEXT_WHITE}{tip1_wrapped[0]}{RST}" if len(tip1_wrapped) > 0 else "",
        f"{C_TEXT_WHITE}{tip1_wrapped[1]}{RST}" if len(tip1_wrapped) > 1 else "",
        f"{C_GRAY_BOX}{'─' * (col2_w)}{RST}",
        f"{C_ORANGE}Recent activity{RST}",
        f"{C_TEXT_DIM}{recent_str[:col2_w-2]}{RST}",
        "",
        f"{C_TEXT_DIM}Type {C_ORANGE}/help{C_TEXT_DIM} or ask naturally below{RST}",
        ""
    ]

    max_rows = max(len(c1_lines), len(c2_lines))

    # Print Card
    print(f"\n {C_RED_ACCENT}{top_line}{RST}")
    for i in range(max_rows):
        l1 = c1_lines[i] if i < len(c1_lines) else ""
        l2 = c2_lines[i] if i < len(c2_lines) else ""

        # Strip ANSI for accurate length calculation
        raw_l1 = re_strip_ansi(l1)
        raw_l2 = re_strip_ansi(l2)

        pad1 = " " * max(0, col1_w - len(raw_l1))
        pad2 = " " * max(0, col2_w - len(raw_l2))

        print(f" {C_RED_ACCENT}│{RST} {l1}{pad1} {C_GRAY_BOX}│{RST} {l2}{pad2} {C_RED_ACCENT}│{RST}")

    bottom_line = f"╰─" + ("─" * col1_w) + "─┴─" + ("─" * col2_w) + "─╯"
    print(f" {C_RED_ACCENT}{bottom_line}{RST}\n")

    # Quick command hint bar
    print(f"  {C_TEXT_DIM}/model to switch models  •  /scope to configure target scope  •  /hunt for auto triage{RST}\n")


def print_turn_separator():
    print("\n")


def prompt_user_input(agent, session=None, history_file: Optional[str] = None) -> Optional[str]:
    """
    Renders the input prompt inside a full-width Frame box.
    After submission, the frame collapses to a flat '❯ input' line with Claude Code spacing.
    """
    w = get_terminal_width()

    if isinstance(session, FileHistory):
        history = session
    else:
        hist_path = history_file or os.path.expanduser("~/.hellhound_history")
        history = FileHistory(hist_path)

    kb = KeyBindings()

    text_area = TextArea(
        multiline=False,
        prompt=HTML("<ansired><b>❯ </b></ansired>"),
        completer=HellhoundCompleter(),
        complete_while_typing=True,
        history=history,
        dont_extend_height=True,
        height=D.exact(1),
        style="class:input-text",
    )

    @kb.add("enter")
    def _on_enter(event):
        event.app.exit(result=text_area.text)

    @kb.add("c-c")
    def _on_sigint(event):
        event.app.exit(result=None)

    @kb.add("c-d")
    def _on_eof(event):
        event.app.exit(result=None)

    all_kb = merge_key_bindings([load_key_bindings(), kb])

    frame = Frame(
        body=text_area,
        height=D.exact(3),
        width=D.exact(w),
        style="class:frame",
    )

    def _get_toolbar_text():
        cfg = load_config()
        auto = "auto-install: on" if cfg.get("auto_install_missing_tools") else "auto-install: off"
        target_name = agent.target.name if agent else "default"
        prov = (cfg.get("orchestrator_provider") or cfg.get("ai_provider", "ollama")).upper()
        model = cfg.get("orchestrator_model") or cfg.get("ai_model", "auto")
        if len(model) > 20:
            model = model[:17] + "..."
        return HTML(f"<ansigray>{auto} · {target_name} · {prov}/{model} · esc to interrupt · /help for commands</ansigray>")

    toolbar = Window(
        content=FormattedTextControl(_get_toolbar_text),
        height=D.exact(1),
        style="class:toolbar"
    )

    main_split = HSplit([frame, toolbar])

    root = FloatContainer(
        content=main_split,
        floats=[
            Float(
                xcursor=True,
                ycursor=True,
                content=CompletionsMenu(max_height=8),
            )
        ],
    )

    app = Application(
        layout=Layout(root, text_area.window),
        key_bindings=all_kb,
        style=PT_CUSTOM_STYLE,
        full_screen=False,
        erase_when_done=True,
    )

    try:
        raw_result = app.run()

        if raw_result is None:
            return None
        text = raw_result.strip()
        if text:
            history.append_string(text)
            # Print collapsed input line with breathing room: ❯ user input
            print(f" {C_RED_MAIN}❯{RST} {text}\n")
        return text
    except (KeyboardInterrupt, EOFError):
        return None

def _sanitize_h1(text: str) -> str:
    """Convert lone H1 headers (# Title) to H2 (## Title) for left-aligned rendering.
    Rich centers H1 across the terminal width; H2 stays left-aligned."""
    out = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("# ") and not stripped.startswith("## "):
            line = re.sub(r'^(\s*)#\s+(.+)', r'\1## \2', line)
        out.append(line)
    return "".join(out)


_STATUS_TAG_STYLES = (
    (re.compile(r'\[STATUS:\s*OBJECTIVE ACHIEVED[^\]]*\]', re.IGNORECASE), "bold green"),
    (re.compile(r'\[STATUS:\s*PARTIAL[^\]]*\]', re.IGNORECASE), "bold yellow"),
    (re.compile(r'\[STATUS:\s*BLOCKED[^\]]*\]', re.IGNORECASE), "bold red"),
)


def _print_with_status_color(text: str):
    """
    Prints Markdown text through Rich, with any [STATUS: ...] tag pulled
    out and printed with real color via Rich's console markup first — the
    same tag the GUI colors as a badge (see status-tag CSS in app.css).
    Rich's Markdown renderer doesn't support arbitrary color spans inside
    CommonMark, so the tag is rendered separately, outside Markdown(), and
    the remaining text goes through Markdown() exactly as before. Only
    used for FINAL, settled output — not the live-streaming preview, where
    a partially-typed tag would flicker in and out of color as it streams.
    """
    matched_style = None
    remaining = text
    for pattern, style in _STATUS_TAG_STYLES:
        m = pattern.search(text)
        if m:
            matched_style = style
            tag_text = m.group(0)
            remaining = (text[:m.start()] + text[m.end():]).strip()
            rich_console.print(f"[{style}]{tag_text}[/{style}]")
            break
    if remaining:
        rich_console.print(Markdown(remaining))


class StreamRenderer:
    """
    Incremental-commit markdown streaming, matching how Claude Code does it.

    Content is committed PERMANENTLY to real scrollback the instant a
    paragraph finishes (a blank line, not mid-code-fence) — printed once,
    outside any live-redraw region. From that moment it's ordinary
    terminal text: the user can scroll up and read it immediately,
    without waiting for the whole response to finish. Only the currently
    still-typing trailing paragraph sits in a small `Live` region at the
    bottom, capped to a few lines. This also removes almost the entire
    surface area for the duplicate-rendering bug: Live never has more
    than one short, in-progress paragraph to erase and redraw, instead
    of the whole growing document.
    """
    _LIVE_TAIL_LINES = 12

    def __init__(self, title: str = "HELLHOUND", border_style: str = "bold red"):
        self.title = title
        self.border_style = border_style
        self.buffer = ""
        self._committed_len = 0  # how much of self.buffer is already permanently printed
        self._recap_line = None
        self._live = None
        self._token_count = 0

    def _find_safe_commit_point(self) -> int:
        """Furthest index into self.buffer that ends on a completed
        paragraph boundary (blank line) which isn't inside an open code
        fence — safe to print permanently. Returns the current committed
        length if nothing new is safely committable yet."""
        text = self.buffer
        best = self._committed_len
        idx = self._committed_len
        while True:
            nl = text.find("\n\n", idx)
            if nl == -1:
                break
            if text.count("```", 0, nl) % 2 == 0:  # not mid-fence at this point
                best = nl + 2
            idx = nl + 2
        return best

    def _commit_up_to(self, end_idx: int):
        if end_idx <= self._committed_len:
            return
        chunk = self.buffer[self._committed_len:end_idx]
        self._committed_len = end_idx
        # Pull out any recap line before printing — same suppress-and-save
        # behavior as before, just applied per-chunk instead of once at the end.
        out_lines = []
        for line in chunk.splitlines(keepends=True):
            if line.strip().lower().startswith("recap:"):
                self._recap_line = line.strip()
            else:
                out_lines.append(line)
        printable = _sanitize_h1("".join(out_lines)).rstrip("\n")
        if printable.strip():
            _print_with_status_color(printable)

    def on_token(self, token: str):
        if not token:
            return
        self.buffer += token
        self._token_count += 1

        # Commit any newly-completed, fence-safe paragraph(s) permanently.
        # Stop the live tail first so the commit print doesn't visually
        # collide with it; it restarts fresh below for whatever's left.
        safe_point = self._find_safe_commit_point()
        if safe_point > self._committed_len:
            if self._live is not None:
                try:
                    self._live.stop()
                except Exception:
                    pass
                self._live = None
            self._commit_up_to(safe_point)

        tail = self.buffer[self._committed_len:]
        if not tail.strip():
            return

        if self._live is None:
            self._live = Live(
                Markdown(""),
                refresh_per_second=12,
                console=rich_console,
                vertical_overflow="crop",
                transient=True,
            )
            self._live.start()

        # Throttle: update display every 3 tokens to avoid excessive re-renders
        # on very fast streams while keeping visual feedback smooth
        if self._token_count % 3 == 0 or "\n" in token:
            clean_tail = _sanitize_h1(tail)
            lines = (clean_tail or " ").splitlines() or [" "]
            preview = "\n".join(lines[-self._LIVE_TAIL_LINES:])
            try:
                self._live.update(Markdown(preview))
            except Exception:
                pass

    def finish(self, final_text=None):
        """Stop the live tail and commit whatever's left (the final
        paragraph, which never got a trailing blank line to trigger a
        commit on its own)."""
        if self._live is not None:
            try:
                self._live.stop()  # transient=True erases the live tail cleanly
            except Exception:
                pass
            self._live = None
        self._commit_up_to(len(self.buffer))

        if self._recap_line:
            print_formatted_text(HTML(f"<i><ansigray>{html.escape(self._recap_line)}</ansigray></i>"))
            print()


def render_response_bubble(response_text: str, sender: str = "HELLHOUND"):
    """
    Renders AI findings and assistant responses as clean unboxed Markdown (Claude Code style).
    Used for non-streaming responses (e.g. short status messages routed through emit.__call__).
    """
    if not response_text or not response_text.strip():
        return
    clean = _sanitize_h1(response_text.strip())
    rich_console.print()
    _print_with_status_color(clean)
    rich_console.print()

def format_completion_phrase(elapsed_str: str) -> str:
    """Returns the user-preferred completion phrase for Hellhound."""
    return f"✳ Cooked for {elapsed_str}"


from hellhound.core.emit import PlainEmit
class InteractiveAgentEmit(PlainEmit):
    """Emit that wraps a ThinkingIndicator for live Claude Code-style feedback.
    
    The spinner starts IMMEDIATELY on construction so the user always sees
    activity from the very first millisecond. info/warn/success/error print
    inline alongside the running spinner (just like Claude Code does).
    Only the final response output (__call__) kills the spinner.
    """
    def __init__(self, label="Let me think"):
        super().__init__()
        from hellhound.core.ai_utils import ThinkingIndicator
        self.indicator = ThinkingIndicator(label)
        self.indicator.start()

    def set_label(self, label: str):
        if self.indicator:
            self.indicator.set_label(label)

    def tool_start(self, tool_name: str, args: dict):
        if self.indicator:
            self.indicator.tool_start(tool_name, args)

    def tool_result(self, tool_name: str, result: any):
        if self.indicator:
            self.indicator.tool_result(tool_name, result)

    def set_token_count(self, count: int):
        if self.indicator:
            self.indicator.set_token_count(count)

    def stop_indicator(self):
        if self.indicator:
            try:
                self.indicator.stop()
            except Exception:
                pass
            self.indicator = None

    def restart_indicator(self, label="Let me think"):
        if self.indicator is None:
            from hellhound.core.ai_utils import ThinkingIndicator
            self.indicator = ThinkingIndicator(label)
            self.indicator.start()

    def __call__(self, msg):
        self.stop_indicator()
        if not msg or not msg.strip():
            return
        # Short status messages stay plain; longer AI responses get a panel
        if len(msg) < 120 and ("switched to" in msg or "Target set" in msg or "No target" in msg):
            super().__call__(msg)
        else:
            render_response_bubble(msg)

    # ── Inline messages: print alongside the running spinner ──
    # These clear the current spinner line, print the message, then the
    # spinner thread immediately redraws on the next tick. This gives the
    # Claude Code live-feed look.
    def info(self, msg):
        if self.indicator:
            self.indicator.info(msg)
        else:
            super().info(msg)

    def success(self, msg):
        if self.indicator:
            self.indicator.success(msg)
        else:
            super().success(msg)

    def warn(self, msg):
        if self.indicator:
            self.indicator.warn(msg)
        else:
            super().warn(msg)

    def error(self, msg):
        if self.indicator:
            self.indicator.error(msg)
        else:
            super().error(msg)



def start_chat_session(initial_target: Optional[str] = None):
    """
    Main interactive Claude Code style REPL loop for Hellhound Bounty Hunter.
    """
    target = initial_target or "default"
    agent = get_agent(target)

    # Configure persistent history
    history_file = os.path.expanduser("~/.hellhound_history")
    history = FileHistory(history_file)

    # ── Warmup: pre-load Ollama model in background while banner renders ──
    # First Ollama call takes ~40s (cold model load). By firing a tiny 1-token
    # request now with keep_alive=-1, the model is cached in RAM permanently.
    import threading
    def _warmup_ollama():
        try:
            from hellhound.core.ai_utils import load_config
            cfg = load_config()
            orch_prov = (cfg.get("orchestrator_provider") or cfg.get("ai_provider") or "ollama").lower()
            if orch_prov == "ollama":
                model = cfg.get("orchestrator_model") or cfg.get("ai_model") or "qwen2.5:3b-instruct-q4_0"
                import requests
                requests.post(
                    "http://localhost:11434/api/generate",
                    json={"model": model, "prompt": "ok", "stream": False,
                          "keep_alive": -1,
                          "options": {"num_predict": 1}},
                    timeout=180
                )
        except Exception:
            pass  # non-critical, just a warmup

    threading.Thread(target=_warmup_ollama, daemon=True).start()

    # Clear terminal cleanly for fresh Claude Code aesthetic
    os.system("clear" if os.name == "posix" else "cls")

    # Render Welcome Banner Card
    render_banner_card(target_name=agent.target.name)

    while True:
        try:
            user_input = prompt_user_input(agent, session=history)
            if user_input is None:
                print(_exit_message())
                break

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit", "q", ":q"):
                print(_exit_message())
                break

            if user_input in ("?", "/help", "help"):
                from hellhound.core.commands import handle_help
                from hellhound.core.emit import PlainEmit
                handle_help([], {}, PlainEmit())
                print_turn_separator()
                continue

            if user_input.lower() == "clear":
                os.system("clear" if os.name == "posix" else "cls")
                render_banner_card(target_name=agent.target.name)
                continue

            # Determine whether input is a strict slash command / CLI command or conversational prompt
            tokens = user_input.split()
            first_word = tokens[0].lower() if tokens else ""
            conversational_words = {"this", "the", "target", "and", "see", "find", "what", "how", "why", "is", "can", "we", "if", "please", "check", "audit", "run", "do"}
            is_conversational = len(tokens) > 2 or any(t.lower() in conversational_words for t in tokens)

            is_explicit_cmd = user_input.startswith("/")
            is_bare_cmd = (not is_conversational) and bool(get_command(first_word) or get_command("/" + first_word))

            if is_explicit_cmd or is_bare_cmd:
                cmd_line = user_input if user_input.startswith("/") else "/" + user_input
                session_ctx = {
                    "target": agent.target.name,
                    "scope_rules": agent.target.scope_rules,
                    "options": {}
                }

                # Determine if this is an AI / methodology skill command that needs live spinner and streaming
                cmd_base = cmd_line.split()[0].lower()
                cmd_obj = get_command(cmd_base)
                is_ai_cmd = cmd_base in {"/recon", "/scan", "/audit", "/hunt", "/auto", "/spider", "/surface", "/ask", "/chat", "/howl"}
                if not is_ai_cmd and cmd_obj and getattr(cmd_obj, "category", "") in ("skills", "hunting"):
                    is_ai_cmd = True
                if not is_ai_cmd:
                    try:
                        from hellhound.core.skills import discover_skills
                        if cmd_base.lstrip("/").lower() in discover_skills():
                            is_ai_cmd = True
                    except Exception:
                        pass

                if is_ai_cmd:
                    label = f"Let me cook — {cmd_base.lstrip('/').replace('-', ' ')}"
                    emit = InteractiveAgentEmit(label)
                    streamer = StreamRenderer(title="HELLHOUND")

                    def on_token_callback(token: str):
                        emit.stop_indicator()
                        streamer.on_token(token)

                    t0 = time.monotonic()
                    try:
                        res = dispatch(cmd_line, session_ctx, emit, on_token=on_token_callback)
                    finally:
                        emit.stop_indicator()
                        final_text = None
                        if isinstance(res, dict):
                            final_text = res.get("advice") or res.get("response")
                        elif isinstance(res, str):
                            final_text = res

                        streamer.finish(final_text)

                        t1 = time.monotonic()
                        elapsed = t1 - t0
                        elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s" if elapsed >= 60 else f"{elapsed:.0f}s"
                        print_formatted_text(HTML(f"<ansigray>{format_completion_phrase(elapsed_str)}</ansigray>"))
                else:
                    # Simple non-AI utility commands (/help, /setup, /scope, /model, etc.)
                    from hellhound.core.emit import PlainEmit as _PlainEmit
                    res = dispatch(cmd_line, session_ctx, _PlainEmit())

                if session_ctx.get("target"):
                    agent.set_target(session_ctx["target"])
                print_turn_separator()
                continue

            # Natural Language Query → Route to Agent reasoning loop with live thinking indicator and streaming
            from hellhound.core.ai_utils import ThinkingIndicator
            indicator = ThinkingIndicator("Let me think")
            indicator.start()

            streamer = StreamRenderer(title="HELLHOUND")

            def on_token_callback(token: str):
                if indicator.thread and indicator.thread.is_alive():
                    indicator.stop()
                streamer.on_token(token)

            session_ctx = {
                "target": agent.target.name,
                "scope_rules": agent.target.scope_rules
            }
            ai_response = None
            t0 = time.monotonic()
            try:
                ai_response = agent.handle_message(
                    user_input,
                    session_context=session_ctx,
                    emit=indicator,
                    on_token=on_token_callback
                )
                if session_ctx.get("target") and session_ctx["target"] != "default":
                    agent.set_target(session_ctx["target"])
            finally:
                indicator.stop()
                
                streamer.finish(ai_response)
                
                t1 = time.monotonic()
                elapsed = t1 - t0
                elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s" if elapsed >= 60 else f"{elapsed:.0f}s"
                print_formatted_text(HTML(f"<ansigray>{format_completion_phrase(elapsed_str)}</ansigray>"))

            print_turn_separator()

        except (KeyboardInterrupt, EOFError):
            print(f"\n{_exit_message()}")
            break
        except Exception as e:
            print(f"\n {Fore.RED}[x] Error: {e}{RST}\n")