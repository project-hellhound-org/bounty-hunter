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

class PlainEmit:
    """
    Colorless emit. Used by engine in headless mode.
    Defines the complete emit contract every module can rely on.
    """

    def __init__(self, socketio=None):
        self.socketio = socketio

    def __call__(self, msg):
        self._send(msg)

    def info(self, msg):
        self._send(f"[*] {msg}")

    def warn(self, msg):
        self._send(f"[!] {msg}")

    def success(self, msg):
        self._send(f"[✓] {msg}")

    def error(self, msg):
        self._send(f"[✗] {msg}")

    # Always-visible methods (not gated by verbose)
    def always_info(self, msg):
        self._send(f"[*] {msg}")

    def always_success(self, msg):
        self._send(f"[✓] {msg}")

    # Visual / structural
    def section(self, title):
        self._send(f"\n── {title} ──")

    def row(self, key, value, **kwargs):
        self._send(f"{key}: {value}")

    def finding(self, *args):
        self._send(f"[!] {' '.join(map(str, args))}")

    def endpoint_row(self, ep):
        self._send(ep.get("url", ""))

    def print_always(self, msg):
        self._send(msg)

    def _send(self, msg):
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

    def info(self, msg):
        self._console.info(msg)

    def warn(self, msg):
        self._console.warn(msg)

    def success(self, msg):
        self._console.success(msg)

    def error(self, msg):
        # console.py defines error()
        if hasattr(self._console, "error"):
            self._console.error(msg)
        else:
            print(Fore.RED + f"[✗] {msg}" + Style.RESET_ALL)

    def always_info(self, msg):
        if hasattr(self._console, "always_info"):
            self._console.always_info(msg)
        else:
            self.info(msg)

    def always_success(self, msg):
        if hasattr(self._console, "always_success"):
            self._console.always_success(msg)
        else:
            self.success(msg)

    def section(self, title):
        self._console.section(title)

    def row(self, key, value, **kwargs):
        if hasattr(self._console, "row"):
            self._console.row(key, value, **kwargs)
        else:
            print(f"{Fore.CYAN}{key}{Style.RESET_ALL}: {value}")

    def finding(self, *args):
        if hasattr(self._console, "finding"):
            self._console.finding(*args)
        else:
            print(Fore.YELLOW + f"[!] {' '.join(map(str, args))}" + Style.RESET_ALL)

    def endpoint_row(self, ep):
        if hasattr(self._console, "endpoint_row"):
            self._console.endpoint_row(ep)
        else:
            print(Fore.CYAN + ep.get("url", "") + Style.RESET_ALL)

    def print_always(self, msg):
        if hasattr(self._console, "print_always"):
            self._console.print_always(msg)
        else:
            print(msg)


# ══════════════════════════════════════════════════════
# LEGACY ALIAS
# Keeps any code that does `from hellhound.core.emit import Emit` working.
# ══════════════════════════════════════════════════════
Emit = PlainEmit