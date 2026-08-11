#!/usr/bin/env bash
# HELLHOUND // Modern PyWebView GUI Launcher

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$DIR")"

# Activate Virtual Environment if present
if [ -d "$HOME/.hellhound-env" ]; then
    source "$HOME/.hellhound-env/bin/activate"
fi

echo "[*] Launching HELLHOUND PyWebView GUI..."
python3 -m hellhound.gui_app "$@"
