#!/usr/bin/env bash
# HELLHOUND // Modern PyWebView GUI Launcher

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$DIR")"

# Activate Virtual Environment if present
if [ -d "$HOME/.hellhound-env" ]; then
    source "$HOME/.hellhound-env/bin/activate"
fi

# ── Invalidate stale WebView disk cache ──────────────────────────────────
# The underlying GUI engine (QtWebEngine on Linux, WebKitGTK, WKWebView on
# macOS, WebView2 on Windows) keeps its own on-disk HTTP/resource cache for
# the app.html/app.js/app.css bundle across launches, independent of what's
# actually in this repo. That means editing the frontend files here doesn't
# always show up on next run. Clear the known cache locations every launch
# so what's on disk in gui/ is always what renders — this is a pure cache,
# safe to delete, and gets rebuilt automatically.
echo "[*] Clearing stale WebView cache..."
for d in \
    "$HOME/.cache/pywebview" \
    "$HOME/.local/share/pywebview" \
    "$HOME/.cache/hellhound" \
    "$HOME/.local/share/hellhound/QtWebEngine" \
    "$HOME/.cache/HELLHOUND" \
    "$HOME/.config/HELLHOUND/QtWebEngine" \
    "$HOME/.cache/qtwebengine" \
; do
    if [ -d "$d" ]; then
        rm -rf "$d"
        echo "    removed $d"
    fi
done

echo "[*] Launching HELLHOUND PyWebView GUI..."
python3 -m hellhound.gui_app "$@"