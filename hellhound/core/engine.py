# hellhound/core/engine.py

import importlib
import shutil
import subprocess
import traceback
import pkgutil
import hellhound.modules
# =================================================
# Emit Handler
# =================================================

class Emit:
    """
    Unified emit handler.

    Supports:
      emit("message")
      emit.info("message")
      emit.warn("message")
      emit.success("message")
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

    def _send(self, msg):
        print(msg)
        if self.socketio:
            self.socketio.emit("log", {"message": msg})


# =================================================
# Hellhound Engine
# =================================================

class HellhoundEngine:

    def __init__(self, socketio=None):
        self.socketio = socketio
        self.emit = Emit(socketio)

        self.module_categories = [
    name for _, name, _ in pkgutil.iter_modules(hellhound.modules.__path__)
]

    # =================================================
    # Run Single Module
    # =================================================

    def run_single(self, module_name, target, options=None):

        try:
            module = self.load_module(module_name)
        except Exception as e:
            self.emit.warn(f"Failed to load module '{module_name}': {e}")
            return ""

        if not callable(getattr(module, "run", None)):
            self.emit.warn(f"Module '{module_name}' must define run(target, emit, options)")
            return ""

        try:
            return module.run(target, self.emit, options=options)
        except Exception as e:
            self.emit.warn(f"Module '{module_name}' crashed:\n{traceback.format_exc()}")
            return ""

    # =================================================
    # External Module Runner
    # =================================================

    def run_external(self, name, target):
        meta = self.external_modules[name]
        binary = meta["binary"]

        if not shutil.which(binary):
            self.emit.warn(f"External tool '{binary}' not found in PATH")
            return ""

        args = meta["args"](target)
        cmd = [binary] + args

        self.emit.info(f"Executing external tool: {' '.join(cmd)}")

        output = ""
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
    # Module Loader (CLEAN + FUTURE PROOF)
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
