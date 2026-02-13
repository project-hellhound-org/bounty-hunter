# hellhound/core/engine.py

import importlib
import subprocess
import shutil


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

        # External binary-backed modules
        self.external_modules = {
            "reconcombo": {
                "binary": "reconcomboGo",
                "args": lambda target: ["--url", target]
            }
        }

        # 🔥 Single source of truth for categories
        self.module_categories = [
            "network",
            "web",
            "enum",
            "recon",
            "vuln",      # ✅ ADDED
            "post",      # future-proof
            "exploit"    # future-proof
        ]

    # =================================================
    # Run Single Module
    # =================================================

    def run_single(self, module_name, target, options=None):

        # 1️⃣ External module handling
        if module_name in self.external_modules:
            return self.run_external(module_name, target)

        # 2️⃣ Python module handling
        try:
            module = self.load_module(module_name)
        except Exception as e:
            self.emit.warn(f"Failed to load module '{module_name}': {e}")
            return ""

        if not hasattr(module, "run"):
            self.emit.warn(f"Module '{module_name}' has no run() function")
            return ""

        try:
            result = module.run(target, self.emit, options=options)
            return result
        except Exception as e:
            self.emit.warn(f"Module '{module_name}' crashed: {e}")
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
    # Module Loader (FIXED + FUTURE PROOF)
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
