#!/usr/bin/env bash
# hellhound-launch.sh
#
# Invoked by the .desktop entry instead of relying on Terminal=true.
# Terminal=true just hands off to whatever the desktop environment resolves
# as ITS default terminal — there's no way to pin that to a specific emulator,
# and users on GNOME/KDE/i3/etc. all land on different apps. This script
# picks the terminal explicitly:
#
#   1. $HELLHOUND_TERMINAL env var, if set (one-off override)
#   2. ~/.hellhound/terminal_preference, if set (persistent, via
#      `hellhound terminal set <name>`)
#   3. First terminal found from a priority list of common emulators
#   4. x-terminal-emulator (Debian/Ubuntu alternatives system)
#   5. Terminal=true-style fallback: just exec hellhound in whatever
#      controlling terminal this script already has (covers the case where
#      it's launched from inside a terminal, not the app menu)
#
# Each terminal emulator has its own flag for "run this command and don't
# just open a shell", so those are mapped explicitly below rather than
# guessing one flag works everywhere.

set -f  # no globbing needed anywhere below

PREF_FILE="$HOME/.hellhound/terminal_preference"
CMD="hellhound"

# A reasonable starting geometry for emulators that support it, so the
# window doesn't open tiny by default the way the raw DE fallback did.
GEOM_COLS=140
GEOM_ROWS=42

launch_with() {
    local term="$1"
    case "$term" in
        ghostty)
            exec ghostty --window-width="$GEOM_COLS" --window-height="$GEOM_ROWS" -e "$CMD"
            ;;
        kitty)
            exec kitty -o initial_window_width=${GEOM_COLS}c -o initial_window_height=${GEOM_ROWS}c "$CMD"
            ;;
        alacritty)
            exec alacritty -o "window.dimensions.columns=$GEOM_COLS" -o "window.dimensions.lines=$GEOM_ROWS" -e "$CMD"
            ;;
        wezterm)
            exec wezterm start --always-new-process -- "$CMD"
            ;;
        gnome-terminal)
            exec gnome-terminal --geometry=${GEOM_COLS}x${GEOM_ROWS} -- "$CMD"
            ;;
        konsole)
            exec konsole --geometry ${GEOM_COLS}x${GEOM_ROWS} -e "$CMD"
            ;;
        xfce4-terminal)
            exec xfce4-terminal --geometry=${GEOM_COLS}x${GEOM_ROWS} -x "$CMD"
            ;;
        terminator)
            exec terminator -e "$CMD"
            ;;
        tilix)
            exec tilix -e "$CMD"
            ;;
        foot)
            exec foot -e "$CMD"
            ;;
        xterm)
            exec xterm -geometry ${GEOM_COLS}x${GEOM_ROWS} -e "$CMD"
            ;;
        *)
            return 1
            ;;
    esac
}

# 1. Explicit one-off override
if [ -n "$HELLHOUND_TERMINAL" ] && command -v "$HELLHOUND_TERMINAL" &>/dev/null; then
    launch_with "$HELLHOUND_TERMINAL"
fi

# 2. Persistent user preference (set via `hellhound terminal set <name>`)
if [ -f "$PREF_FILE" ]; then
    PREFERRED="$(tr -d '[:space:]' < "$PREF_FILE")"
    if [ -n "$PREFERRED" ] && command -v "$PREFERRED" &>/dev/null; then
        launch_with "$PREFERRED"
    fi
fi

# 3. Auto-detect: first known terminal found on PATH
for term in ghostty kitty alacritty wezterm gnome-terminal konsole xfce4-terminal terminator tilix foot xterm; do
    if command -v "$term" &>/dev/null; then
        launch_with "$term"
    fi
done

# 4. Debian/Ubuntu alternatives system
if command -v x-terminal-emulator &>/dev/null; then
    exec x-terminal-emulator -e "$CMD"
fi

# 5. Last resort — run inline (covers being launched from an existing shell)
exec "$CMD"
