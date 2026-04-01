import json
import time
import requests
from colorama import Fore, Style
from hellhound.core import http_utils

class ReproEngine:
    """
    HELLHOUND REPRODUCTION ENGINE
    Universal engine for replaying discovered findings through a global proxy.
    """
    def __init__(self, emit):
        self.emit = emit
        self.replayed = 0
        self.errors = 0

    def run(self, target, all_results, proxy=None, options=None):
        """
        Harvests findings from all_results and repro-analyzes them.
        """
        options = options or {}
        
        self.emit.section("HELLHOUND REPRODUCTION ENGINE")
        
        if not all_results:
            self.emit.warn("No intelligence collected in this session to reproduce.")
            return None

        # Harvest all findings with repro_data
        repro_queue = []
        for mod_name, result in all_results.items():
            intel = result.get("intel", {})
            # Look for diverse finding keys
            findings = (intel.get("vulnerabilities", []) or 
                        intel.get("findings", []) or 
                        intel.get("cors_vulnerabilities", []))
            
            for f in findings:
                if f.get("repro_data"):
                    f["_source_mod"] = mod_name
                    repro_queue.append(f)

        if not repro_queue:
            self.emit.warn("No findings with valid reproduction metadata found in loot.")
            return None

        self.emit.info(f"[*] Found {len(repro_queue)} finding(s) ready for reproduction.")
        if proxy:
            self.emit.success(f"[✓] Proxy active for replay: {proxy}")
        else:
            self.emit.warn("[!] No proxy configured for reproduction (direct replay).")
        
        session = requests.Session()
        session.verify = False
        if proxy:
            http_utils.apply_proxy_to_session(session, proxy)

        for i, finding in enumerate(repro_queue, 1):
            data = finding["repro_data"]
            url = data.get("url")
            method = data.get("method", "GET").upper()
            headers = data.get("headers", {})
            body = data.get("body")
            mod = finding.get("_source_mod", "unknown").upper()
            name = finding.get("name", "Vulnerability")

            self.emit.print_always(f"\n  [{i:02d}] {Fore.CYAN + Style.BRIGHT}{mod}{Style.RESET_ALL} -> {name}")
            self.emit.print_always(f"       {method} {url}")

            try:
                # Enforce clean headers
                headers.pop("Content-Length", None)
                headers.pop("Host", None)
                
                # Replay
                start_time = time.time()
                resp = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body if method != "GET" else None,
                    timeout=options.get("timeout", 10),
                    allow_redirects=False
                )
                duration = time.time() - start_time
                
                status_color = Fore.GREEN if 200 <= resp.status_code < 300 else Fore.YELLOW
                if resp.status_code >= 400: status_color = Fore.RED
                
                self.emit.print_always(f"       Status: {status_color}{resp.status_code}{Style.RESET_ALL} ({len(resp.content)} bytes) in {duration:.2f}s")
                self.replayed += 1
                
            except Exception as e:
                self.emit.error(f"       [x] Replay failed: {str(e)}")
                self.errors += 1
                
            time.sleep(options.get("delay", 0.5))

        self.emit.section("REPRO SUMMARY")
        self.emit.success(f"[+] Replayed: {self.replayed} | Errors: {self.errors}")
        
        return {
            "replayed_count": self.replayed,
            "error_count": self.errors
        }
