import os
import json
import threading
from datetime import datetime
from hellhound.modules import nmap, vhost

BASE = os.path.dirname(os.path.dirname(__file__))
SESSIONS = os.path.join(BASE, "storage")


class HellhoundEngine:
    def __init__(self, socketio=None):
        self.socketio = socketio

    # ---- Web dashboard emit ----
    def emit(self, msg):
        print(msg)
        if self.socketio:
            self.socketio.emit("log", {"message": msg})

    # ---- Start threaded scan (dashboard mode) ----
    def start_scan(self, target, modules, wordlist):
        thread = threading.Thread(
            target=self.run,
            args=(target, modules, wordlist),
            daemon=True
        )
        thread.start()

    # ---- Main execution flow (dashboard mode) ----
    def run(self, target, modules, wordlist):
        os.makedirs(SESSIONS, exist_ok=True)

        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join(SESSIONS, f"{target}_{session_id}")
        os.makedirs(session_dir, exist_ok=True)

        self.emit(f"[+] Session created: {session_dir}")
        self.emit(f"[+] Modules selected: {', '.join(modules)}")

        results = {}

        if "nmap" in modules:
            self.emit("[*] Running Nmap")
            results["nmap"] = nmap.run(target, self.emit)

        if "vhost" in modules:
            self.emit("[*] Running VHOST fuzzing")
            results["vhost"] = vhost.run(target, self.emit, wordlist)

        report_path = os.path.join(session_dir, "results.json")
        with open(report_path, "w") as f:
            json.dump(results, f, indent=4)

        self.emit(f"[+] Results saved: {report_path}")
        self.emit("[✓] Scan completed")

    # =====================================================
    # NEW: Console support (CLI framework mode)
    # =====================================================

    def emit_console(self, msg):
        print(msg)

    def run_single(self, module, target, wordlist=None):
        if module == "nmap":
            return nmap.run(target, self.emit_console)

        if module == "vhost":
            return vhost.run(target, self.emit_console, wordlist)

        print(f"[!] Unknown module: {module}")
