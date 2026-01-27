import os
import json
import threading
from datetime import datetime
from hellhound.modules import nmap, vhost

BASE = os.path.dirname(os.path.dirname(__file__))
SESSIONS = os.path.join(BASE, "storage")


class HellhoundEngine:
    def __init__(self, socketio):
        self.socketio = socketio

    def emit(self, msg):
        print(msg)
        self.socketio.emit("log", {"message": msg})

    def start_scan(self, target, modules, wordlist):
        thread = threading.Thread(
            target=self.run,
            args=(target, modules, wordlist),
            daemon=True
        )
        thread.start()

    def run(self, target, modules, wordlist):
        # Create session folder
        os.makedirs(SESSIONS, exist_ok=True)

        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join(SESSIONS, f"{target}_{session_id}")
        os.makedirs(session_dir, exist_ok=True)

        self.emit(f"[+] Session created: {session_dir}")
        self.emit(f"[+] Modules selected: {', '.join(modules)}")

        results = {}

        # Run modules only if user selected them
        if "nmap" in modules:
            self.emit("[*] Running Nmap")
            results["nmap"] = nmap.run(target, self.emit)

        if "vhost" in modules:
            self.emit("[*] Running VHOST fuzzing")
            results["vhost"] = vhost.run(target, self.emit, wordlist)

        # Future-ready:
        # if "nuclei" in modules:
        #     results["nuclei"] = nuclei.run(...)

        # Save results
        report_path = os.path.join(session_dir, "results.json")
        with open(report_path, "w") as f:
            json.dump(results, f, indent=4)

        self.emit(f"[+] Results saved: {report_path}")
        self.emit("[✓] Scan completed")
