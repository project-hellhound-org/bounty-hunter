import importlib

class HellhoundEngine:
    def __init__(self, socketio=None):
        self.socketio = socketio

    def emit(self, msg):
        print(msg)
        if self.socketio:
            self.socketio.emit("log", {"message": msg})

    def run_single(self, module_name, target, **kwargs):
        try:
            module = self.load_module(module_name)
        except Exception as e:
            self.emit(f"[!] Failed to load module '{module_name}': {e}")
            return ""

        if not hasattr(module, "run"):
            self.emit(f"[!] Module '{module_name}' has no run() function")
            return ""

        return module.run(target, self.emit, **kwargs)

    def load_module(self, name):
        # Try network
        try:
            return importlib.import_module(f"hellhound.modules.network.{name}")
        except:
            pass

        # Try web
        try:
            return importlib.import_module(f"hellhound.modules.web.{name}")
        except:
            pass

        # Try enum
        try:
            return importlib.import_module(f"hellhound.modules.enum.{name}")
        except:
            pass

        raise ImportError(f"Module '{name}' not found")
