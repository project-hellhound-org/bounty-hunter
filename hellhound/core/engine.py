# hellhound/core/engine.py

import importlib
import shutil
import subprocess
import traceback
import pkgutil

import hellhound.modules
from hellhound.core.emit import PlainEmit, ConsoleEmit


# =================================================
# Hellhound Engine
# =================================================

class HellhoundEngine:

    def __init__(self, socketio=None, console=None):
        """
        socketio : optional SocketIO instance for web streaming
        console  : optional HellhoundConsole instance
                   When provided, module output is routed through the
                   console's colored emit methods instead of plain stdout.
        """
        self.socketio = socketio
        self.console  = console

        # Build the emit object once.
        # If a console is attached, use ConsoleEmit (colored).
        # Otherwise fall back to PlainEmit (headless / API safe).
        if console is not None:
            self.emit = ConsoleEmit(console, socketio=socketio)
        else:
            self.emit = PlainEmit(socketio=socketio)

        self.module_categories = [
            name for _, name, _ in pkgutil.iter_modules(hellhound.modules.__path__)
        ]

    def attach_console(self, console):
        """
        Called by HellhoundConsole after __init__ to wire itself in.
        Upgrades emit from PlainEmit → ConsoleEmit so module output is colored.
        """
        self.console = console
        self.emit    = ConsoleEmit(console, socketio=self.socketio)

    # =================================================
    # Run Single Module
    # =================================================

    def run_single(self, module_name, target, options=None, emit=None):
        """
        emit parameter: caller can pass a custom emit object.
        If None, uses self.emit (ConsoleEmit when console is attached).
        """
        active_emit = emit or self.emit

        try:
            module = self.load_module(module_name)
        except Exception as e:
            active_emit.warn(f"Failed to load module '{module_name}': {e}")
            return ""

        if not callable(getattr(module, "run", None)):
            active_emit.warn(f"Module '{module_name}' must define run(target, emit, options)")
            return ""

        try:
            return module.run(target, active_emit, options=options)
        except Exception as e:
            active_emit.warn(f"Module '{module_name}' crashed:\n{traceback.format_exc()}")
            return ""

    # =================================================
    # External Module Runner
    # =================================================

    def run_external(self, name, target):
        meta   = self.external_modules[name]
        binary = meta["binary"]

        if not shutil.which(binary):
            self.emit.warn(f"External tool '{binary}' not found in PATH")
            return ""

        args = meta["args"](target)
        cmd  = [binary] + args

        self.emit.info(f"Executing external tool: {' '.join(cmd)}")

        output  = ""
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:
            if line.strip():
                self.emit(line.strip())
                output += line

        process.wait()
        self.emit.success(f"External module '{name}' completed")
        return output

    # =================================================
    # Module Loader
    # =================================================

    def load_module(self, name):
        for category in self.module_categories:
            try:
                return importlib.import_module(
                    f"hellhound.modules.{category}.{name}"
                )
            except ModuleNotFoundError:
                continue
        raise ImportError(f"Module '{name}' not found")