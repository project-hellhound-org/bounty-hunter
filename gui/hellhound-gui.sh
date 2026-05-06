#!/usr/bin/env bash
# Apex-King HUD Launcher (Portable)
# Detects its own location and environment dynamically.

# Get the directory where this script is located
HUD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -d "$HUD_DIR" ]; then
    cd "$HUD_DIR"
    # Ensure node_modules exists
    if [ ! -d "node_modules" ]; then
        echo "[!] GUI dependencies missing. Running npm install..."
        npm install --quiet
    fi
    # Launch Electron
    nohup npm start > /dev/null 2>&1 &
    echo "[+] Hellhound Apex-King HUD launched in background."
else
    if command -v notify-send &>/dev/null; then
        notify-send "Hellhound Error" "Could not find HUD directory."
    fi
    exit 1
fi
