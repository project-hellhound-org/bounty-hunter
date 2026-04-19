# hellhound/core/engine.py

import importlib
import shutil
import subprocess
import traceback
import pkgutil
import asyncio
import inspect

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
            # AUTO-ANIMATION START
            active_emit.progress_start(module_name.upper())

            # Check if run is a coroutine function or a regular function returning a coroutine
            result = module.run(target, active_emit, options=options)
            
            if inspect.iscoroutine(result):
                # Synchronous bridge to async execution
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        res = loop.run_until_complete(result)
                    else:
                        res = asyncio.run(result)
                except RuntimeError:
                    res = asyncio.run(result)
            else:
                res = result
            return res
        except Exception as e:
            active_emit.warn(f"Module '{module_name}' crashed:\n{traceback.format_exc()}")
            return ""
        finally:
            # AUTO-ANIMATION STOP
            active_emit.progress_stop()

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

        self.emit.progress_start(name.upper())
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
        self.emit.progress_stop()
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