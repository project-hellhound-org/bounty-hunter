#!/usr/bin/env bash
# ══════════════════════════════════════════════════════
#  HELLHOUND — Uninstall Script
#  Reverses everything install.sh created. Safe to run
#  from any directory.
#
#  Usage:
#    ./uninstall.sh                 # interactive, asks for confirmation
#    ./uninstall.sh --yes           # skip confirmation prompt
#    ./uninstall.sh --keep-data     # keep ~/.hellhound (config, targets, findings)
#    ./uninstall.sh --purge-tools   # also remove gowitness binary installed by install.sh
#    ./uninstall.sh --purge-source  # also remove ~/.hellhound-src (bootstrap clone, if any)
# ══════════════════════════════════════════════════════

set -u

RED='\033[91m'
GRN='\033[92m'
CYN='\033[96m'
YLW='\033[93m'
RST='\033[0m'
BLD='\033[1m'

info()    { echo -e "${CYN}[*]${RST} $1"; }
success() { echo -e "${GRN}${BLD}[✓]${RST} $1"; }
warn()    { echo -e "${YLW}[!]${RST} $1"; }
error()   { echo -e "${RED}[✗]${RST} $1"; }

YES=0
KEEP_DATA=0
PURGE_TOOLS=0
PURGE_SOURCE=0

for arg in "$@"; do
    case "$arg" in
        -y|--yes) YES=1 ;;
        --keep-data) KEEP_DATA=1 ;;
        --purge-tools) PURGE_TOOLS=1 ;;
        --purge-source) PURGE_SOURCE=1 ;;
        -h|--help)
            echo "Usage: ./uninstall.sh [--yes] [--keep-data] [--purge-tools] [--purge-source]"
            exit 0
            ;;
        *) warn "Unknown flag: $arg (ignored)" ;;
    esac
done

VENV_DIR="$HOME/.hellhound-env"
HELLHOUND_HOME="$HOME/.hellhound"
SRC_DIR="$HOME/.hellhound-src"
LOCAL_BIN_LINK="$HOME/.local/bin/hellhound"
GLOBAL_BIN_LINK="/usr/local/bin/hellhound"
DESKTOP_FILE="$HOME/.local/share/applications/hellhound.desktop"
DATA_ICON_DIR="$HOME/.local/share/hellhound"
ICON_FILE="$HOME/.local/share/icons/hellhound.png"
GOWITNESS_LOCAL="$HOME/.local/bin/gowitness"

if [ "$(basename "${SHELL:-bash}")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ "$(basename "${SHELL:-bash}")" = "bash" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.profile"
fi

echo -e "\n${RED}${BLD}  HELLHOUND — Uninstall${RST}\n"
info "This will remove the following, if present:"
[ -d "$VENV_DIR" ]        && echo "    - Virtual environment : $VENV_DIR"
[ -L "$LOCAL_BIN_LINK" ]  && echo "    - Symlink              : $LOCAL_BIN_LINK"
[ -L "$GLOBAL_BIN_LINK" ] && echo "    - Symlink (system)     : $GLOBAL_BIN_LINK (requires sudo)"
[ -f "$DESKTOP_FILE" ]    && echo "    - Desktop entry        : $DESKTOP_FILE"
[ -d "$DATA_ICON_DIR" ]   && echo "    - Icon assets          : $DATA_ICON_DIR"
[ -f "$ICON_FILE" ]       && echo "    - Icon                 : $ICON_FILE"
echo "    - Shell alias lines    : hellhound / hellhound-gui in $SHELL_RC"
if [ "$KEEP_DATA" -eq 1 ]; then
    warn "  --keep-data set: $HELLHOUND_HOME (config, targets, findings) will be PRESERVED."
else
    [ -d "$HELLHOUND_HOME" ] && echo "    - Config & target data : $HELLHOUND_HOME (findings, credentials, scope, config.json)"
fi
if [ "$PURGE_TOOLS" -eq 1 ]; then
    [ -f "$GOWITNESS_LOCAL" ] && echo "    - Gowitness binary     : $GOWITNESS_LOCAL"
fi
if [ "$PURGE_SOURCE" -eq 1 ]; then
    [ -d "$SRC_DIR" ] && echo "    - Bootstrap source repo: $SRC_DIR"
fi
echo ""
warn "Ollama, any Ollama models, and system packages installed outside install.sh are NOT touched."
echo ""

if [ "$YES" -ne 1 ]; then
    read -p "$(echo -e "${YLW}[?]${RST} Type UNINSTALL to confirm: ")" CONFIRM
    if [ "$CONFIRM" != "UNINSTALL" ]; then
        info "Aborted. Nothing was removed."
        exit 0
    fi
fi

# ── Remove venv ────────────────────────────────────────
if [ -d "$VENV_DIR" ]; then
    rm -rf "$VENV_DIR" && success "Removed virtual environment: $VENV_DIR"
fi

# ── Remove symlinks ─────────────────────────────────────
if [ -L "$LOCAL_BIN_LINK" ] || [ -e "$LOCAL_BIN_LINK" ]; then
    rm -f "$LOCAL_BIN_LINK" && success "Removed symlink: $LOCAL_BIN_LINK"
fi
if [ -L "$GLOBAL_BIN_LINK" ] || [ -e "$GLOBAL_BIN_LINK" ]; then
    if [ "$EUID" -eq 0 ]; then
        rm -f "$GLOBAL_BIN_LINK" && success "Removed symlink: $GLOBAL_BIN_LINK"
    elif sudo -n true 2>/dev/null; then
        sudo rm -f "$GLOBAL_BIN_LINK" && success "Removed symlink: $GLOBAL_BIN_LINK"
    else
        warn "Skipped $GLOBAL_BIN_LINK — re-run with sudo to remove it, or: sudo rm -f $GLOBAL_BIN_LINK"
    fi
fi

# ── Remove desktop integration ──────────────────────────
[ -f "$DESKTOP_FILE" ] && rm -f "$DESKTOP_FILE" && success "Removed desktop entry: $DESKTOP_FILE"
[ -d "$DATA_ICON_DIR" ] && rm -rf "$DATA_ICON_DIR" && success "Removed icon assets: $DATA_ICON_DIR"
[ -f "$ICON_FILE" ] && rm -f "$ICON_FILE" && success "Removed icon: $ICON_FILE"
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database "$HOME/.local/share/applications/" &>/dev/null || true
fi

# ── Remove shell aliases ────────────────────────────────
if [ -f "$SHELL_RC" ]; then
    if grep -qF "alias hellhound=" "$SHELL_RC" 2>/dev/null || grep -qF "alias hellhound-gui=" "$SHELL_RC" 2>/dev/null; then
        cp "$SHELL_RC" "$SHELL_RC.hellhound-uninstall.bak"
        sed -i \
            -e "/^# HELLHOUND$/d" \
            -e "/^alias hellhound=/d" \
            -e "/^alias hellhound-gui=/d" \
            "$SHELL_RC"
        success "Removed hellhound aliases from $SHELL_RC (backup: $SHELL_RC.hellhound-uninstall.bak)"
    fi
fi

# ── Data directory (config, targets, findings, loot) ────
if [ "$KEEP_DATA" -eq 1 ]; then
    warn "Preserved $HELLHOUND_HOME (--keep-data)"
elif [ -d "$HELLHOUND_HOME" ]; then
    rm -rf "$HELLHOUND_HOME" && success "Removed config & target data: $HELLHOUND_HOME"
fi

# ── Optional: shared tool binaries ──────────────────────
if [ "$PURGE_TOOLS" -eq 1 ] && [ -f "$GOWITNESS_LOCAL" ]; then
    rm -f "$GOWITNESS_LOCAL" && success "Removed gowitness binary: $GOWITNESS_LOCAL"
fi

# ── Optional: bootstrap clone ───────────────────────────
if [ "$PURGE_SOURCE" -eq 1 ] && [ -d "$SRC_DIR" ]; then
    rm -rf "$SRC_DIR" && success "Removed bootstrap source repo: $SRC_DIR"
fi

echo ""
success "HELLHOUND uninstalled."
info "Open a new terminal (or 'source $SHELL_RC') for the alias removal to take effect."
if [ "$KEEP_DATA" -eq 1 ]; then
    info "Your findings/config are still at $HELLHOUND_HOME — remove manually or re-run without --keep-data."
fi
