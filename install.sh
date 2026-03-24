#!/usr/bin/env bash
# ══════════════════════════════════════════════════════
#  HELLHOUND — System Install Script
#  Run once from the project root directory.
#  After this, type `hellhound` from anywhere.
# ══════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "\n${RED}  HELLHOUND — System Install${RESET}\n"

# 1. Must be run from project root (where setup.py lives)
if [ ! -f "setup.py" ]; then
    echo -e "${RED}[x] Run this script from the HELLHOUND project root (where setup.py is).${RESET}"
    exit 1
fi

# 2. Editable install — source edits take effect immediately, no reinstall needed
echo -e "${CYAN}[*] Installing HELLHOUND as editable system package...${RESET}"
pip install -e . --break-system-packages --quiet

# 3. Install Playwright browsers (needed for Spider SPA mode)
echo -e "${CYAN}[*] Installing Playwright Chromium browser...${RESET}"
python3 -m playwright install chromium 2>/dev/null || \
    echo -e "${YELLOW}[!] Playwright install skipped (run manually: playwright install chromium)${RESET}"

# 4. Verify the command is available
if command -v hellhound &>/dev/null; then
    echo -e "\n${GREEN}[✓] hellhound installed successfully.${RESET}"
    echo -e "${GREEN}    You can now run: hellhound${RESET}"
    echo -e "${GREEN}    From any directory, any terminal.\n${RESET}"
else
    echo -e "\n${YELLOW}[!] Install completed but 'hellhound' not found in PATH.${RESET}"
    echo -e "${YELLOW}    Try: export PATH=\$PATH:\$HOME/.local/bin${RESET}"
    echo -e "${YELLOW}    Add that line to your ~/.bashrc or ~/.zshrc\n${RESET}"
fi