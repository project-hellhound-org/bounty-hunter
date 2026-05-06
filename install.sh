#!/usr/bin/env bash
# ══════════════════════════════════════════════════════
#  HELLHOUND — Install Script (Cinematic v12.6)
#  Run once from the project root directory.
#  After this, type `hellhound` from anywhere.
# ══════════════════════════════════════════════════════

set -e

RED='\033[91m'
GRN='\033[92m'
CYN='\033[96m'
YLW='\033[93m'
RST='\033[0m'
BLD='\033[1m'

info()    { echo -e "${CYN}[*]${RST} $1"; }
success() { echo -e "${GRN}${BLD}[✓]${RST} $1"; }
warn()    { echo -e "${YLW}[!]${RST} $1"; }
error()   { echo -e "${RED}[✗]${RST} $1"; stop_animation; exit 1; }

# ── Animator Logic (Cinematic) ────────────────────────────────────────────────
ANIM_PID=0

start_animation() {
    local label="$1"
    stop_animation
    
    # T31: Case-Wave for Label
    # P33: Braille-Wave for Progress (Scaled to 'Ultra-Wide' 50 character bar)
    python3 -c "
import math, time, sys, shutil
label = \"$label\"
def wave(label, t):
    res = ''
    for i, c in enumerate(label):
        if not c.isalpha(): res += c; continue
        v = math.sin(t * 10 + i * 0.4)
        if v > 0: res += f'\033[91m\033[1m{c.upper()}\033[0m'
        else: res += f'\033[31m{c.lower()}\033[0m'
    return res
def braille(t, cols):
    chars = '⡀⡄⡆⡇⣇⣧⣷⣿'
    bar = ''
    prefix_len = len(label) + 4
    bar_len = max(10, cols - prefix_len - 10)
    for i in range(bar_len):
        idx = int((math.sin(t * 5 + i * 0.2) + 1) / 2 * (len(chars) - 1))
        bar += f'\033[91m{chars[idx]}\033[0m'
    return bar
start = time.time()
try:
    while True:
        cols = shutil.get_terminal_size((80, 24)).columns
        t = time.time() - start
        sys.stdout.write(f'\r  {wave(label, t)}  {braille(t, cols)} ')
        sys.stdout.flush()
        time.sleep(0.06)
except:
    pass
" &
    ANIM_PID=$!
}

stop_animation() {
    if [ "$ANIM_PID" -ne 0 ]; then
        kill -9 "$ANIM_PID" &>/dev/null || true
        wait "$ANIM_PID" 2>/dev/null || true
        # Clean the line thoroughly
        printf "\r\033[2K\r" 
        ANIM_PID=0
    fi
}

trap "stop_animation" EXIT INT TERM

echo -e "\n${RED}${BLD}  HELLHOUND — Install${RST}\n"

# ── 1. Preparation ────────────────────────────────────
if [ ! -f "setup.py" ]; then
    echo -e "${RED}[✗] Run this script from the HELLHOUND project root (where setup.py is).${RST}"
    exit 1
fi

PROJECT_ROOT="$(pwd)"
VENV_DIR="$HOME/.hellhound-env"

# Detect shell rc file
if [ "$(basename "$SHELL")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ "$(basename "$SHELL")" = "bash" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.profile"
fi

# ── 2. Virtual Environment ────────────────────────────
start_animation "ISOLATING CORE"
python3 -m venv "$VENV_DIR" || error "Failed to create virtual environment."
stop_animation
success "Virtual environment ready at $VENV_DIR"

# ── 3. Core Engine ────────────────────────────────────
start_animation "DECRYPTING DEPENDENCIES"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -e "$PROJECT_ROOT"
stop_animation
success "HELLHOUND core engine installed"

# ── 4. Playwright (Spider-style handling) ──────────────
stop_animation
info "Mounting SPA Engine..."

    if [ -f /etc/debian_version ] || grep -q "Kali" /etc/os-release 2>/dev/null; then
        info "Debian/Kali detected — applying dependency patches..."
        # Fix for Kali's t64 transition and missing Ubuntu font packages
        DUMMY_DIR=$(mktemp -d)
        
        # 1. Dummy ttf-unifont -> fonts-unifont
        mkdir -p "$DUMMY_DIR/ttf-unifont/DEBIAN"
        cat <<EOF > "$DUMMY_DIR/ttf-unifont/DEBIAN/control"
Package: ttf-unifont
Version: 1:99.0
Section: fonts
Priority: optional
Architecture: all
Depends: fonts-unifont
Description: Dummy package for ttf-unifont
EOF
        dpkg-deb --build "$DUMMY_DIR/ttf-unifont" "$DUMMY_DIR/ttf-unifont.deb" &>/dev/null
        
        # 2. Dummy libasound2 -> libasound2t64
        mkdir -p "$DUMMY_DIR/libasound2/DEBIAN"
        cat <<EOF > "$DUMMY_DIR/libasound2/DEBIAN/control"
Package: libasound2
Version: 1:99.0
Section: libs
Priority: optional
Architecture: all
Depends: libasound2t64
Description: Dummy package for libasound2
EOF
        dpkg-deb --build "$DUMMY_DIR/libasound2" "$DUMMY_DIR/libasound2.deb" &>/dev/null

        # 3. Dummy ttf-ubuntu-font-family -> fonts-liberation
        mkdir -p "$DUMMY_DIR/ttf-ubuntu-font-family/DEBIAN"
        cat <<EOF > "$DUMMY_DIR/ttf-ubuntu-font-family/DEBIAN/control"
Package: ttf-ubuntu-font-family
Version: 1:99.0
Section: fonts
Priority: optional
Architecture: all
Depends: fonts-liberation
Description: Dummy package for ttf-ubuntu-font-family
EOF
        dpkg-deb --build "$DUMMY_DIR/ttf-ubuntu-font-family" "$DUMMY_DIR/ttf-ubuntu-font-family.deb" &>/dev/null
        
        if command -v sudo &>/dev/null; then
            sudo dpkg -i "$DUMMY_DIR/ttf-unifont.deb" "$DUMMY_DIR/libasound2.deb" "$DUMMY_DIR/ttf-ubuntu-font-family.deb" &>/dev/null || true
        else
            dpkg -i "$DUMMY_DIR/ttf-unifont.deb" "$DUMMY_DIR/libasound2.deb" "$DUMMY_DIR/ttf-ubuntu-font-family.deb" &>/dev/null || true
        fi
        rm -rf "$DUMMY_DIR"
    fi

# Suppress redundant 'BEWARE' warnings on Kali to keep output clean
info "Fetching Chromium (this may take a minute)..."
"$VENV_DIR/bin/python" -m playwright install chromium 2>&1 | grep --line-buffered -vE "BEWARE|fallback" || true

info "Hardening system dependencies..."
if command -v sudo &>/dev/null && [ "$EUID" -ne 0 ]; then
    sudo "$VENV_DIR/bin/python" -m playwright install-deps chromium 2>&1 | grep --line-buffered -vE "BEWARE|fallback" || true
else
    "$VENV_DIR/bin/python" -m playwright install-deps chromium 2>&1 | grep --line-buffered -vE "BEWARE|fallback" || true
fi
success "SPA Engine mounted successfully"

# ── 5. System Integration ──────────────────────────────
start_animation "FINALIZING INTEGRATION"

# Alias integration
ALIAS_LINE="alias hellhound='$VENV_DIR/bin/hellhound'"
if grep -qF "alias hellhound=" "$SHELL_RC" 2>/dev/null; then
    sed -i "s|alias hellhound=.*|$ALIAS_LINE|" "$SHELL_RC"
else
    echo "" >> "$SHELL_RC"
    echo "# HELLHOUND" >> "$SHELL_RC"
    echo "$ALIAS_LINE" >> "$SHELL_RC"
fi

# Local bin symlink
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV_DIR/bin/hellhound" "$HOME/.local/bin/hellhound"

# Global bin symlink (if sudo available)
if [ "$EUID" -eq 0 ]; then
    ln -sf "$VENV_DIR/bin/hellhound" "/usr/local/bin/hellhound"
elif sudo -n true 2>/dev/null; then
    sudo ln -sf "$VENV_DIR/bin/hellhound" "/usr/local/bin/hellhound" 2>/dev/null || true
fi

chmod +x "$PROJECT_ROOT/update.sh"
chmod +x "$PROJECT_ROOT/install.sh"

stop_animation
success "System integration complete"

# ── 6. Ollama + Local SLM (AI Engine) ─────────────────
# Ollama provides local AI (gemma2:2b) for unlimited pentesting
# without API tokens. Skip with: SKIP_OLLAMA=1 ./install.sh

if [ "${SKIP_OLLAMA:-0}" = "1" ]; then
    warn "Skipping Ollama install (SKIP_OLLAMA=1)"
else
    echo ""
    info "Setting up Local AI Engine (Ollama + gemma2:2b)..."
    
    if command -v ollama &>/dev/null; then
        success "Ollama already installed: $(ollama --version 2>/dev/null || echo 'unknown')"
    else
        info "Installing Ollama..."
        if curl -fsSL https://ollama.com/install.sh | sh 2>&1 | tail -3; then
            success "Ollama installed successfully"
        else
            warn "Ollama install failed — you can install it manually: https://ollama.com/download"
            warn "Hellhound will still work with Gemini API keys without local AI."
        fi
    fi

    # Pull the default SLM model if Ollama is available
    if command -v ollama &>/dev/null; then
        # Check if gemma2:2b is already pulled
        if ollama list 2>/dev/null | grep -q "gemma2:2b"; then
            success "Model gemma2:2b already available"
        else
            info "Pulling gemma2:2b (~1.6 GB, this may take a few minutes)..."
            start_animation "DOWNLOADING SLM"
            if ollama pull gemma2:2b 2>&1 | tail -1; then
                stop_animation
                success "gemma2:2b model ready for local AI pentesting"
            else
                stop_animation
                warn "Failed to pull gemma2:2b — you can pull it later: ollama pull gemma2:2b"
            fi
        fi
    fi
fi

# ── 7. System GUI (Electron HUD) ──────────────────────
# The high-fidelity desktop HUD for the Apex-King release.
echo ""
info "Configuring Hellhound Apex-King HUD (System GUI)..."

# Ensure logo.png is the source of truth
if [ -f "$PROJECT_ROOT/Images/logo.png" ]; then
    ICON_SRC="$PROJECT_ROOT/Images/logo.png"
else
    ICON_SRC="$PROJECT_ROOT/Images/hellhound.png"
fi

if command -v npm &>/dev/null; then
    start_animation "INITIALIZING HUD"
    cd "$PROJECT_ROOT/gui" && npm install --quiet &>/dev/null || warn "Failed to install Electron dependencies. Manual fix: 'cd gui && npm install'"
    cd "$PROJECT_ROOT"
    stop_animation
    success "GUI dependencies installed"
    
    chmod +x "$PROJECT_ROOT/gui/hellhound-gui.sh"

    # Register Icon for System (Universal Linux Path)
    mkdir -p "$HOME/.local/share/icons"
    cp "$ICON_SRC" "$HOME/.local/share/icons/hellhound.png"

    # Create Desktop Entry (Searchable in App Menu)
    DESKTOP_FILE="$HOME/.local/share/applications/hellhound.desktop"
    mkdir -p "$(dirname "$DESKTOP_FILE")"
    
    cat <<EOF > "$DESKTOP_FILE"
[Desktop Entry]
Name=Hellhound Apex-King
Comment=Offensive Intelligence HUD
Exec=$PROJECT_ROOT/gui/hellhound-gui.sh
Icon=hellhound
Terminal=false
Type=Application
Categories=Network;Security;
Keywords=pentest;ai;hellhound;
EOF
    
    # Update system desktop database for app menu visibility
    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database "$HOME/.local/share/applications/" &>/dev/null || true
    fi
    
    # Update system alias
    GUI_ALIAS="alias hellhound-gui='$PROJECT_ROOT/gui/hellhound-gui.sh'"
    if grep -qF "alias hellhound-gui=" "$SHELL_RC" 2>/dev/null; then
        sed -i "s|alias hellhound-gui=.*|$GUI_ALIAS|" "$SHELL_RC"
    else
        echo "$GUI_ALIAS" >> "$SHELL_RC"
    fi
    
    success "GUI Integrated: You can now launch 'Hellhound' from your system menu."
else
    warn "NPM/Node.js not found. Skipping GUI setup."
    warn "To use the HUD, install Node.js and run 'npm install' in this directory."
fi

# ── 8. Done ──────────────────────────────────────────
echo ""
echo -e "  ${GRN}${BLD}HELLHOUND installed successfully.${RST}"
echo -e "  Venv    : ${CYN}$VENV_DIR${RST}"
echo -e "  Command : ${CYN}hellhound${RST}"
echo -e "  GUI HUD : ${CYN}hellhound-gui${RST}"
if command -v ollama &>/dev/null; then
    echo -e "  Local AI: ${CYN}Ollama (gemma2:2b)${RST} — use ${YLW}set api_key ollama${RST} in console"
else
    echo -e "  Local AI: ${YLW}Not installed${RST} — use Gemini API key or install Ollama later"
fi
echo ""
echo -e "  ${YLW}Activate now:${RST}"
echo -e "    source $SHELL_RC"
echo ""