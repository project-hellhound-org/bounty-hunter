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
from prompt_toolkit.layout.containers import FloatContainer, Float
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

from hellhound.core.tasks import list_targets, create_or_load_target, Target
from hellhound.core.ai_utils import load_config
from hellhound.core.agent import get_agent
from hellhound.core.commands import dispatch, get_command, COMMAND_REGISTRY


# -------------------------------------------------------------
# Color & Style Palette (Hellhound Bounty Hunter Theme)
# -------------------------------------------------------------
C_RED_MAIN   = "\033[38;5;196;1m"   # Vibrant Crimson Red (Main borders & brand)
C_RED_ACCENT = "\033[38;5;203m"     # Soft Coral Red
C_ORANGE     = "\033[38;5;208;1m"   # Neon Orange
C_CYAN       = "\033[38;5;51;1m"    # Electric Cyan
C_GRAY_BOX   = "\033[38;5;240m"     # Subtle Box Gray
C_TEXT_WHITE = "\033[97;1m"         # Crisp Bold White
C_TEXT_DIM   = "\033[38;5;244m"     # Dim Secondary Text
C_BG_PROMPT  = "\033[48;5;234m"     # Dark Slate Prompt Highlight
RST          = Style.RESET_ALL

PT_CUSTOM_STYLE = PTStyle.from_dict({
    'prompt': '#00ffff bold',
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
            sub_suggestions = [
                ("subdomains", "Asset discovery only (subfinder/dns_bruteforce)"),
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
        center_ansi(f"{C_TEXT_DIM}Target: {C_TEXT_WHITE}{curr_target[:18]}{C_TEXT_DIM} • {C_CYAN}{scope_status}{RST}", col1_w),
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
        f"{C_TEXT_DIM}Type {C_CYAN}/help{C_TEXT_DIM} or ask naturally below{RST}",
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
    width = shutil.get_terminal_size(fallback=(80, 24)).columns
    print(f"\n{C_GRAY_BOX}{'─' * width}{RST}\n")


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
        prompt=HTML("<ansicyan><b>❯ </b></ansicyan>"),
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

    root = FloatContainer(
        content=frame,
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
    )

    try:
        raw_result = app.run()

        # Collapse the bordered frame cleanly to a flat Claude Code-style line
        try:
            sys.stdout.write("\033[3A\033[J")
            sys.stdout.flush()
        except Exception:
            pass

        if raw_result is None:
            return None
        text = raw_result.strip()
        if text:
            history.append_string(text)
            # Print collapsed input line with breathing room: ❯ user input
            print(f" {C_CYAN}❯{RST} {text}\n")
        return text
    except (KeyboardInterrupt, EOFError):
        try:
            sys.stdout.write("\033[3A\033[J")
            sys.stdout.flush()
        except Exception:
            pass
        return None


class StreamRenderer:
    """
    Renders streaming tokens incrementally inside a Rich Markdown Panel with Live display.
    """
    def __init__(self, title: str = "HELLHOUND", border_style: str = "bold red"):
        self.title = title
        self.border_style = border_style
        self.accumulated_text = ""
        self.live: Optional[Live] = None
        self._started = False

    def on_token(self, token: str):
        if not token:
            return
        self.accumulated_text += token
        if not self._started:
            self._started = True
            self.live = Live(
                self._render_panel(),
                console=rich_console,
                refresh_per_second=12,
                vertical_overflow="visible"
            )
            self.live.start()
        else:
            if self.live:
                self.live.update(self._render_panel())

    def _render_panel(self) -> Panel:
        md = Markdown(self.accumulated_text or " ")
        return Panel(
            md,
            title=f"[bold red] {self.title} [/bold red]",
            title_align="left",
            border_style=self.border_style,
            padding=(0, 1)
        )

    def finish(self, final_text: Optional[str] = None):
        if final_text and not self.accumulated_text:
            self.accumulated_text = final_text

        if self.live and self._started:
            if final_text:
                self.accumulated_text = final_text
            self.live.update(self._render_panel())
            self.live.stop()
            self.live = None
        elif self.accumulated_text:
            rich_console.print(self._render_panel())


def render_response_bubble(response_text: str, sender: str = "HELLHOUND"):
    """
    Renders AI findings and assistant responses in a visually distinct Rich Markdown Panel.
    """
    if not response_text or not response_text.strip():
        return
    clean_sender = re_strip_ansi(sender)
    md = Markdown(response_text.strip())
    rich_console.print(Panel(
        md,
        title=f"[bold red] {clean_sender} [/bold red]",
        title_align="left",
        border_style="bold red",
        padding=(0, 1)
    ))

from hellhound.core.emit import PlainEmit
class InteractiveAgentEmit(PlainEmit):
    """Emit that wraps a ThinkingIndicator for live Claude Code-style feedback.
    
    The spinner starts IMMEDIATELY on construction so the user always sees
    activity from the very first millisecond. info/warn/success/error print
    inline alongside the running spinner (just like Claude Code does).
    Only the final response output (__call__) kills the spinner.
    """
    def __init__(self, label="HELLHOUND IS ANALYZING & EXECUTING"):
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

    def stop_indicator(self):
        if self.indicator:
            try:
                self.indicator.stop()
            except Exception:
                pass
            self.indicator = None

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
                print(f" {C_RED_MAIN}[+] Exiting Hellhound Bounty Hunter. Happy Hunting!{RST}\n")
                break

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit", "q", ":q"):
                print(f" {C_RED_MAIN}[+] Exiting Hellhound Bounty Hunter. Happy Hunting!{RST}\n")
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

                # Determine if this is a long-running AI command that needs the live spinner
                ai_commands = {"/recon", "/scan", "/audit", "/hunt", "/spider", "/surface"}
                cmd_base = cmd_line.split()[0].lower()
                if cmd_base in ai_commands:
                    # Start spinner IMMEDIATELY so user sees activity from the first ms
                    emit = InteractiveAgentEmit(f"EXECUTING {cmd_base.upper()[1:]}")
                    try:
                        res = dispatch(cmd_line, session_ctx, emit)
                    finally:
                        emit.stop_indicator()
                else:
                    # Simple non-AI commands (/help, /setup, /scope, etc.) don't need a spinner
                    from hellhound.core.emit import PlainEmit as _PlainEmit
                    res = dispatch(cmd_line, session_ctx, _PlainEmit())

                if session_ctx.get("target"):
                    agent.set_target(session_ctx["target"])
                print_turn_separator()
                continue

            # Natural Language Query → Route to Agent reasoning loop with live thinking indicator and streaming
            from hellhound.core.ai_utils import ThinkingIndicator
            indicator = ThinkingIndicator("HELLHOUND IS ANALYZING & EXECUTING")
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
            try:
                ai_response = agent.handle_message(
                    user_input,
                    session_context=session_ctx,
                    emit=indicator,
                    on_token=on_token_callback
                )
            finally:
                indicator.stop()
                streamer.finish(ai_response)

            print_turn_separator()

        except (KeyboardInterrupt, EOFError):
            print(f"\n {C_RED_MAIN}[+] Exiting Hellhound Bounty Hunter.{RST}\n")
            break
        except Exception as e:
            print(f"\n {Fore.RED}[x] Error: {e}{RST}\n")
