"""
hellhound/core/chat_ui.py

Claude Code-style Terminal Chat Interface for Hellhound Bounty Hunter.
Provides a modern, double-pane dashboard card, pixel mascot, recent activity tracker,
and unified conversational chat prompt.
"""

import os
import sys
import shutil
import textwrap
import readline
from typing import Optional, Dict, Any, List

from colorama import Fore, Back, Style, init
init(autoreset=True)

from hellhound.core.tasks import list_targets, create_or_load_target, Target
from hellhound.core.ai_utils import load_config, detect_ai_config, thinking_animation
from hellhound.core.agent import get_agent
from hellhound.core.commands import dispatch, get_command


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


def get_terminal_width() -> int:
    cols = shutil.get_terminal_size((90, 24)).columns
    return max(60, cols)


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


def re_strip_ansi(text: str) -> str:
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def render_response_bubble(response_text: str, sender: str = "HELLHOUND"):
    if not response_text or not response_text.strip():
        return
    try:
        from rich.console import Console
        from rich.markdown import Markdown
        console = Console()
        print()
        console.print(Markdown(response_text.strip()))
        print()
    except Exception:
        print(f"\n{response_text.strip()}\n")


def start_chat_session(initial_target: Optional[str] = None):
    """
    Main interactive Claude Code style REPL loop for Hellhound Bounty Hunter.
    """
    target = initial_target or "default"
    agent = get_agent(target)
    
    # Configure readline history
    history_file = os.path.expanduser("~/.hellhound_history")
    try:
        readline.read_history_file(history_file)
    except FileNotFoundError:
        pass

    # Clear terminal cleanly for fresh Claude Code aesthetic
    os.system("clear" if os.name == "posix" else "cls")

    # Render Welcome Banner Card
    render_banner_card(target_name=agent.target.name)

    while True:
        try:
            full_w = get_terminal_width()
            line_w = max(40, full_w - 2)
            # Top divider line spanning the full terminal width
            print(f" {C_GRAY_BOX}{'─' * line_w}{RST}")
            
            # Interactive prompt line (like Claude Code '> ')
            prompt_str = f" {C_RED_MAIN}>{RST} "
            user_input = input(prompt_str).strip()

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit", "q", ":q"):
                print(f" {C_RED_MAIN}[+] Exiting Hellhound Bounty Hunter. Happy Hunting!{RST}\n")
                break

            if user_input in ("?", "/help", "help"):
                from hellhound.core.commands import handle_help
                from hellhound.core.emit import PlainEmit
                handle_help([], {}, PlainEmit())
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
                from hellhound.core.emit import PlainEmit
                session_ctx = {
                    "target": agent.target.name,
                    "scope_rules": agent.target.scope_rules,
                    "options": {}
                }
                res = dispatch(cmd_line, session_ctx, PlainEmit())
                if session_ctx.get("target") and session_ctx["target"] != agent.target.name:
                    agent.set_target(session_ctx["target"])
                continue

            # Natural Language Query → Route to Agent reasoning loop with live thinking indicator
            from hellhound.core.ai_utils import ThinkingIndicator
            indicator = ThinkingIndicator("HELLHOUND IS ANALYZING & EXECUTING")
            indicator.start()

            session_ctx = {
                "target": agent.target.name,
                "scope_rules": agent.target.scope_rules
            }
            try:
                ai_response = agent.handle_message(user_input, session_context=session_ctx, emit=indicator)
            finally:
                indicator.stop()

            # Render clean response card
            render_response_bubble(ai_response)

        except (KeyboardInterrupt, EOFError):
            print(f"\n {C_RED_MAIN}[+] Exiting Hellhound Bounty Hunter.{RST}\n")
            break
        except Exception as e:
            print(f"\n {Fore.RED}[x] Error: {e}{RST}\n")

    # Save command history
    try:
        readline.set_history_length(1000)
        readline.write_history_file(history_file)
    except Exception:
        pass
