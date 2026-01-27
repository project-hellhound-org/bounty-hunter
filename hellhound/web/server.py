from flask import Flask, render_template
from flask_socketio import SocketIO
from hellhound.core.engine import HellhoundEngine
import sys
import logging

# Silence Werkzeug logs
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", log_output=False)

engine = HellhoundEngine(socketio)

# Defaults
port = 8080
target = None
modules = []
wordlist = None

# Parse CLI args
for arg in sys.argv:
    if arg.startswith("--port="):
        port = int(arg.split("=", 1)[1])
    elif arg.startswith("--target="):
        target = arg.split("=", 1)[1]
    elif arg.startswith("--modules="):
        modules = arg.split("=", 1)[1].split(",")
    elif arg.startswith("--wordlist="):
        val = arg.split("=", 1)[1]
        wordlist = val if val else None


@app.route("/")
def index():
    return render_template("index.html", target=target)


@socketio.on("connect")
def handle_connect():
    if target and modules:
        engine.start_scan(target, modules, wordlist)


if __name__ == "__main__":
    print(f"[+] Dashboard running: http://127.0.0.1:{port}")
    socketio.run(app, host="0.0.0.0", port=port)
