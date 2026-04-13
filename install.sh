#!/usr/bin/env bash
# ══════════════════════════════════════════════════════
#  HELLHOUND — Install Script
#  Run once from the project root directory.
#  After this, type `hellhound` from anywhere.
# ══════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

VENV_DIR="$HOME/.hellhound-env"

echo -e "\n${RED}  HELLHOUND — Install${RESET}\n"

# ── 1. Must be run from project root ──────────────────
if [ ! -f "setup.py" ]; then
    echo -e "${RED}[x] Run this script from the HELLHOUND project root (where setup.py is).${RESET}"
    exit 1
fi

PROJECT_ROOT="$(pwd)"

# ── 2. Detect shell rc file ───────────────────────────
if [ "$(basename "$SHELL")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ "$(basename "$SHELL")" = "bash" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.profile"
fi

# ── 3. Create venv ────────────────────────────────────
echo -e "${CYAN}[*] Creating virtual environment at $VENV_DIR ...${RESET}"
python3 -m venv "$VENV_DIR"

# ── 4. Install hellhound as editable into venv ────────
echo -e "${CYAN}[*] Installing HELLHOUND into venv...${RESET}"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -e "$PROJECT_ROOT"

# ── 5. Install Playwright browsers ────────────────────
echo -e "${CYAN}[*] Installing Playwright Chromium browser...${RESET}"
if "$VENV_DIR/bin/python" -m playwright install chromium 2>/dev/null; then
    echo -e "${GREEN}[+] Playwright Chromium installed.${RESET}"
else
    echo -e "${YELLOW}[!] Playwright browser install failed.${RESET}"
    echo -e "${YELLOW}    Fix: source $VENV_DIR/bin/activate && playwright install chromium${RESET}"
fi

# ── 6. Write alias to shell rc ────────────────────────
ALIAS_LINE="alias hellhound='$VENV_DIR/bin/hellhound'"

if grep -qF "alias hellhound=" "$SHELL_RC" 2>/dev/null; then
    sed -i "s|alias hellhound=.*|$ALIAS_LINE|" "$SHELL_RC"
    echo -e "${CYAN}[*] Updated existing hellhound alias in $SHELL_RC${RESET}"
else
    echo "" >> "$SHELL_RC"
    echo "# HELLHOUND" >> "$SHELL_RC"
    echo "$ALIAS_LINE" >> "$SHELL_RC"
    echo -e "${CYAN}[*] Added hellhound alias to $SHELL_RC${RESET}"
fi

# ── 7. Symlink into ~/.local/bin for new shell sessions ──
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV_DIR/bin/hellhound" "$HOME/.local/bin/hellhound"

# ── 8. System-wide Symlink (Optional) ──────────────────
if [ "$EUID" -eq 0 ]; then
    echo -e "${CYAN}[*] Sudo detected. Creating system-wide symlink...${RESET}"
    ln -sf "$VENV_DIR/bin/hellhound" "/usr/local/bin/hellhound"
    echo -e "${GREEN}[+] System-wide symlink created: /usr/local/bin/hellhound${RESET}"
fi

# ── 9. Make scripts executable ────────────────────────
chmod +x "$PROJECT_ROOT/update.sh"
chmod +x "$PROJECT_ROOT/install.sh"

# ── 10. Done ──────────────────────────────────────────
echo -e "\n${GREEN}[+] HELLHOUND installed successfully.${RESET}"
echo -e "${GREEN}    Venv    : $VENV_DIR${RESET}"
echo -e "${GREEN}    Command : hellhound${RESET}"
echo ""
echo -e "${YELLOW}  To upgrade in the future, use:${RESET}"
echo -e "    hellhound upgrade"
echo -e "  Or from within the console:"
echo -e "    hellhound > upgrade"
echo ""
echo -e "${YELLOW}  Activate now (current terminal):${RESET}"
echo -e "    source $SHELL_RC"
echo -e "  Or just open a new terminal.\n"