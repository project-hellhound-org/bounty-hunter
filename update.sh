#!/usr/bin/env bash
# ══════════════════════════════════════════════════════
#  HELLHOUND — Update Script
#  Pulls latest changes and syncs environment.
# ══════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

VENV_DIR="$HOME/.hellhound-env"
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo -e "\n${RED}  HELLHOUND — Framework Upgrade${RESET}\n"

cd "$PROJECT_ROOT"

FORCE=false
if [[ "$*" == *"--force"* ]]; then
    FORCE=true
fi

# ── 1. Check for Git ──────────────────────────────────
if [ ! -d ".git" ]; then
    echo -e "${RED}[x] Error: Not a Git repository. Cannot auto-upgrade.${RESET}"
    exit 1
fi

# ── 2. Git Pull ───────────────────────────────────────
echo -e "${CYAN}[*] Checking for updates...${RESET}"
PULL_OUTPUT=$(git pull 2>&1)

if [[ "$PULL_OUTPUT" == *"Already up to date"* ]]; then
    if [ "$FORCE" = false ]; then
        echo -e "${GREEN}[+] HELLHOUND is already up to date.${RESET}"
        echo -e "${YELLOW}    Tip: Use './update.sh --force' to sync dependencies anyway.${RESET}\n"
        exit 0
    else
        echo -e "${YELLOW}[!] Force mode enabled. Re-syncing environment...${RESET}"
    fi
elif [[ "$PULL_OUTPUT" == *"Updating"* ]] || [[ "$PULL_OUTPUT" == *"Fast-forward"* ]]; then
    echo -e "${GREEN}[+] Source code updated.${RESET}"
else
    echo -e "${RED}[x] Git pull failed or encountered an error:${RESET}"
    echo -e "$PULL_OUTPUT"
    exit 1
fi

# ── 3. Update Venv ────────────────────────────────────
if [ -d "$VENV_DIR" ]; then
    echo -e "${CYAN}[*] Updating dependencies in $VENV_DIR...${RESET}"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -e .
    
    if [ -f "requirements.txt" ]; then
        "$VENV_DIR/bin/pip" install --quiet -r requirements.txt
    fi
    echo -e "${GREEN}[+] Dependencies synchronized.${RESET}"
else
    echo -e "${YELLOW}[!] Warning: Virtual environment at $VENV_DIR not found.${RESET}"
    echo -e "${YELLOW}    Skipping dependency update. You may need to run install.sh.${RESET}"
fi

# ── 4. Update Playwright ──────────────────────────────
echo -e "${CYAN}[*] Checking for browser updates...${RESET}"
if [ -d "$VENV_DIR" ]; then
    if grep -q "Kali" /etc/os-release 2>/dev/null; then
        echo -e "${YELLOW}[*] Kali Linux detected — ensuring optimized Ubuntu fallback is current.${RESET}"
    fi
    "$VENV_DIR/bin/python" -m playwright install chromium --with-deps > /dev/null 2>&1 || true
    echo -e "${GREEN}[+] Playwright browsers verified.${RESET}"
fi

# ── 5. Done ───────────────────────────────────────────
echo -e "\n${GREEN}[+] HELLHOUND successfully upgraded to the latest version.${RESET}"
echo -e "${GREEN}    Restart your terminal or Hellhound console to apply changes.${RESET}\n"
