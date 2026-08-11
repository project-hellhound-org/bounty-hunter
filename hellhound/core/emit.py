"""
hellhound/core/emit.py

Single source of truth for the Emit interface.
Imported by engine.py — do NOT duplicate this class elsewhere.

Two modes:
  ConsoleEmit(console)  — wraps a HellhoundConsole instance, uses its
                          colored print methods. Used when running inside
                          the interactive console.
  PlainEmit()           — plain stdout fallback for headless / API use.
                          Also used as base by engine when no console attached.
"""

from colorama import Fore, Style, init
init(autoreset=True)


# ══════════════════════════════════════════════════════
# BASE: PlainEmit
# Full API surface that Spider and all modules depend on.
# No colors — safe for headless / socketio / logging use.
# ══════════════════════════════════════════════════════

try:
    from rich.console import Console
    _rich_console = Console()
except Exception:
    _rich_console = None


class PlainEmit:
    """
    Standard emit backed by Rich Console for vibrant terminal formatting,
    with fallback to plain stdout and WebSocket support.
    """

    def __init__(self, socketio=None):
        self.socketio = socketio

    def __call__(self, msg):
        self._send(msg)

    def info(self, msg):
        self._send(f"[bold cyan][*][/bold cyan] {msg}")

    def warn(self, msg):
        self._send(f"[bold yellow][!][/bold yellow] {msg}")

    def warning(self, msg):
        """Compatibility alias for warn."""
        self.warn(msg)

    def set_label(self, label: str):
        """Update active status label if supported."""
        pass

    def tool_start(self, tool_name: str, args: dict):
        """Emits start of tool execution."""
        args_str = ", ".join(f"{k}={repr(v)}" for k, v in (args or {}).items())
        self._send(f"[bold cyan][*][/bold cyan] Executing tool: [bold white]{tool_name}[/bold white]({args_str})")

    def tool_result(self, tool_name: str, result: any):
        """Emits tool execution result."""
        pass

    def success(self, msg):
        self._send(f"[bold green][✓][/bold green] {msg}")

    def error(self, msg):
        self._send(f"[bold red][✗][/bold red] {msg}")

    # Always-visible methods (not gated by verbose)
    def always_info(self, msg):
        self.info(msg)

    def always_success(self, msg):
        self.success(msg)

    # Visual / structural
    def banner(self, title):
        self._send(f"\n[bold red]═══ {title} ═══[/bold red]")

    def section(self, title):
        self._send(f"\n[bold red]── {title} ──[/bold red]")

    def row(self, key, value, **kwargs):
        self._send(f"[bold white]{key}:[/bold white] {value}")

    def finding(self, *args):
        self._send(f"[bold red][!][/bold red] {' '.join(map(str, args))}")

    def endpoint_row(self, ep):
        self._send(ep.get("url", ""))

    def print_always(self, msg):
        self._send(msg)

    def log(self, *args, **kwargs):
        msg = " ".join(map(str, args))
        self._send(msg)

    def progress(self, label, current, total, start_time=None):
        """Legacy standalone call."""
        pass

    def progress_start(self, label, total=0):
        """Start sticky animation."""
        pass

    def progress_update(self, current, label=None):
        """Update sticky animation stats."""
        pass

    def progress_stop(self):
        """Stop sticky animation."""
        pass

    def _send(self, msg):
        if _rich_console:
            try:
                _rich_console.print(msg)
            except Exception:
                print(msg)
        else:
            print(msg)
        if self.socketio:
            self.socketio.emit("log", {"message": msg})


# ══════════════════════════════════════════════════════
# COLORED: ConsoleEmit
# Wraps HellhoundConsole so module output gets the same
# colors as native console output.
# ══════════════════════════════════════════════════════

class ConsoleEmit(PlainEmit):
    """
    Colored emit backed by a HellhoundConsole instance.
    Engine passes this when running inside the interactive console.
    Falls back to PlainEmit behavior if console method is missing.
    """

    def __init__(self, console, socketio=None):
        super().__init__(socketio=socketio)
        self._console = console

    def _w(self, method_name, *args, **kwargs):
        """Clears progress line and prints while holding the terminal lock."""
        with self._console.term_lock:
            # 1. Clear the animation line
            if hasattr(self._console, "clear_progress_unlocked"):
                self._console.clear_progress_unlocked()
            
            # 2. Call the actual console printing method
            method = getattr(self._console, method_name, None)
            if method:
                method(*args, **kwargs)
            else:
                # Fallback print if console method is missing
                print(f"[{method_name}] {' '.join(map(str, args))}")
            
            # 3. No manual redraw here. 
            # The background thread will take the lock and redraw in its next cycle.

    def info(self, msg):
        self._w("info", msg)

    def warn(self, msg):
        self._w("warn", msg)

    def success(self, msg):
        self._w("success", msg)

    def error(self, msg):
        self._w("error", msg)

    def always_info(self, msg):
        if hasattr(self._console, "always_info"):
            self._w("always_info", msg)
        else:
            self.info(msg)

    def always_success(self, msg):
        if hasattr(self._console, "always_success"):
            self._w("always_success", msg)
        else:
            self.success(msg)

    def section(self, title):
        self._w("section", title)

    def row(self, key, value, **kwargs):
        self._w("row", key, value, **kwargs)

    def finding(self, *args):
        self._w("finding", *args)

    def endpoint_row(self, ep):
        self._w("endpoint_row", ep)

    def print_always(self, msg):
        self._w("print_always", msg)

    def log(self, *args, **kwargs):
        msg = " ".join(map(str, args))
        self._w("print_always", msg)

    def print_always(self, msg):
        if hasattr(self._console, "print_always"):
            self._console.print_always(msg)
        else:
            print(msg)

    def progress(self, label, current, total, start_time=None):
        """Legacy / Direct Update."""
        if hasattr(self._console, "progress"):
            self._console.progress(label, current, total, start_time)

    def progress_start(self, label, total=0):
        """Start background sticky animation."""
        if hasattr(self._console, "start_animation"):
            self._console.start_animation(label, total)

    def progress_update(self, current, label=None):
        """Update current stats."""
        if hasattr(self._console, "update_animation"):
            self._console.update_animation(current, label)

    def progress_stop(self):
        """Stop and clear."""
        if hasattr(self._console, "stop_animation"):
            self._console.stop_animation()


# ══════════════════════════════════════════════════════
# LEGACY ALIAS
# Keeps any code that does `from hellhound.core.emit import Emit` working.
# ══════════════════════════════════════════════════════
Emit = PlainEmit