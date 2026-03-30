import http.server
import threading
import random
import socket
import time
import urllib.parse
from colorama import Fore, Style

# ─────────────────────────────────────────────────────────────────────────────
# OOB HANDLER (HTTP)
# ─────────────────────────────────────────────────────────────────────────────
class _OOBHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler — records path+query, responds with 200."""
    def do_GET(self):
        self.server._oob_hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace") if length else ""
        self.server._oob_hits.append(self.path + "?" + body)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        pass  # suppress access log noise

# ─────────────────────────────────────────────────────────────────────────────
# OOB SERVER
# ─────────────────────────────────────────────────────────────────────────────
class OOBServer:
    """
    Centralized Out-of-Band (OOB) listener daemon.
    
    This server spawns an HTTP listener on a random port (8000-9000).
    It is used for confirming blind injections/vulns where the target
    has outbound connectivity but no direct response leakage.
    """
    def __init__(self):
        self._server = None
        self._thread = None
        self.host    = None
        self.port    = None
        self.hits    = []  # Backwards compatibility alias for _oob_hits

    def start(self, port_range=(8000, 9000)):
        """Start the background HTTP server on a random port in range."""
        if self._server:
            return self.host, self.port

        for _ in range(50):
            port = random.randint(*port_range)
            try:
                srv = http.server.HTTPServer(("0.0.0.0", port), _OOBHandler)
                srv._oob_hits = [] 
                self._server = srv
                self.port    = port
                self.hits    = srv._oob_hits
                break
            except OSError:
                continue

        if not self._server:
            return None, None

        # Resolve outbound IP — what the target sees
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80)) # Google DNS reachable check
                self.host = sock.getsockname()[0]
        except Exception:
            self.host = "127.0.0.1"

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="hellhound-oob-listener"
        )
        self._thread.start()
        return self.host, self.port

    def poll(self, token, timeout=10):
        """Poll for a request containing token."""
        deadline = time.time() + timeout
        token_lc = token.lower()
        while time.time() < deadline:
            if self._server:
                # Use list copy for thread safety
                for hit in list(self._server._oob_hits):
                    if token_lc in hit.lower():
                        return True, hit
            time.sleep(0.5)
        return False, ""

    def stop(self):
        """Stop the server cleanly."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join()
            self._thread = None

    def get_url(self):
        """Return the listener URL (e.g. http://192.168.1.5:8000)."""
        if self.host and self.port:
            return f"http://{self.host}:{self.port}"
        return None

def resolve_oob_url(options):
    """
    Helper to extract the OOB URL from module options.
    Logic priority: 
    1. Global collaborator URL (options['oob_url'])
    2. Local server URL (options['oob_server'].get_url())
    """
    # Prefer an explicitly set external collaborator URL
    if options.get("oob_url"):
        return options["oob_url"]

    # Fallback to local server instance provided by engine/console
    oob_server = options.get("oob_server")
    if oob_server and hasattr(oob_server, "get_url"):
        return oob_server.get_url()

    return None
