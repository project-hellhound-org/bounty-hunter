import cmd
import asyncio
import threading
import yaml
import importlib.resources as pkg_resources
import os
import time
import sys
import random
from datetime import datetime
import json
import re
import math
from rich.console import Console

# Initialize Rich Console for cinematic UI
console = Console()

from colorama import Fore, Back, Style, init
init(autoreset=True)

from hellhound.core import oob_utils
from hellhound.core.engine import HellhoundEngine
from hellhound.core import ai_utils
from hellhound.core.repro_engine import ReproEngine
from hellhound.core.loot import render_loot, process_framework_results

# ----------------------------
# UI / COLOR CONSTANTS
# ----------------------------

W          = 70           # Global Banner Width
R          = Style.RESET_ALL
C_BORDER   = "\033[91;1m"  # VIBRANT RED
C_HEAD     = "\033[91;1m"  # VIBRANT RED
C_CRITICAL = "\033[38;5;196;1m" # DEEP RED
C_HIGH     = "\033[38;5;208;1m" # VIBRANT ORANGE
C_MEDIUM   = "\033[96;1m"       # NEON CYAN
C_LOW      = "\033[97m"         # BRIGHT WHITE
C_CHAIN    = "\033[38;5;201;1m" # BRIGHT PINK
C_SKIP     = Fore.LIGHTBLACK_EX
C_LABEL    = "\033[97;1m"       # BOLD WHITE
C_DIM      = "\033[37m"         # DIM WHITE
C_EVIDENCE = "\033[96m"         # HUD CYAN
C_STEP     = "\033[91;1m"       # VIBRANT RED
C_URL      = "\033[93m"         # VIBRANT YELLOW
C_OK       = "\033[91;1m"       # VIBRANT RED (User wants more red/vibrant than green)

# NEW ANIMATION PALETTE
C_PRIMARY_RED = "\033[91;1m"
C_DIM_RED     = "\033[31m"
C_HUD_CYAN    = "\033[96m"
C_WHITE       = "\033[97m"

CONF_COLORS = {
    "confirmed": Fore.RED    + Style.BRIGHT,
    "strong":    Fore.YELLOW + Style.BRIGHT,
    "likely":    Fore.CYAN   + Style.BRIGHT,
    "possible":  Fore.WHITE,
}

# ----------------------------
# BOOT ANIMATION
# ----------------------------

def _boot_sequence():
    """
    HELLHOUND v12.5.1 Apex-King Boot Sequence.
    Features: Red Braille Prefix, Case-Wave Technical Text, Red Pipe Suffix, Smooth Logo Reveal.
    """
    BANNER = r"""


            .:@@@-..                             ...                                                
            .#@@@@@@..                        ..+%.                                                 
           ..@@@@@@@@@%:.                  .-%@:                                                    
           .#@@@@@@@@@@@@@=.   .::.                             .:.                                 
           .@@@@@@@@@@@@@@@@@@@@@@@@@@@@#=:...         ....+@@@@@+.                                 
           .%**=@@@@@@@@@@@@@@@@**@@@@@@@@@#+:......:+@@@@@+..+@#.                                  
           .%@@%@%:=@@@@@@@@=@@*%@=:#@@@@@@@@@@@@@@@@@@%=*#:%@@@..                                  
           .#@:%@@@@@:-@@@@@@.#@@@@*-+%@@@@@@@@@@@@@@@@@@@@@@@@:.                                   
           .=.   -%@@@@%+@@@@@#*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:.                                    
                  .=@@@@@@@@@@@@@@@@@@@@@@@@@@=%%@@@@@@@@@@*.                                       
                     .:@@@@@@@@@@@@@@@@@@@@@@@@+%@%-#@@@@#.....     ....                            
            .           .=@*@@@@@@@@@@@@@@@@@@@@@#*@@@@@:..  :@@#-.. ..:-.                          
           ==   ....  ..%@@-@@.+@@@@@@@@@@@@@@@@@@@=@@@@@@%.. .@@@@@:%:..                           
          .@%..:@:%@+#@@*-#@@@.+.+@-@@@%@@@:@@@@#-@@*@@@@%:#@+..*@@@@@@*:.                          
          :%@@@%+--..+@@@@@@@@%:@+. :@@.@@%:.+@@@:.#@@@@@@@@#.-#-:@@@@@@@@@*.                       
          %@@@@@@@@@@@@@@@-+@@@-@@%.+=:.:@.%@-.#@+::-@@@@@@=@@@@:..:@=+@@=#@@:.                     
          .*@@@@@@@@@@@@@@@@@@@@@@@+.%@=...@@@%.=#.@=.#@@@@*+@@@@@@@@+:=-@@%:-%#..                  
            .=@::....::..=@@@@@@@@@@.+@@@:*@@@@@+#.*@#.@@@@%.+@@@@@@@@@@@@@@@@=..+=.                
                         .@@@@@@@@@#.%@@@@@@@@@@@+.*@@%@@@@#. -@@@@@@@@@@@@@@@@@:       .:          
                         .@#@@@@@*@:=@@@@@@@@@@@*.-@@@@@@@@=....%@@@#*@@@@@=%%@@@@.. .*@=.          
                         .%-@@@@@+.-@@@@@@@@-@@-.=@@@@@@@@@...#-.-@@@@@:.#@@@@@*-@@-.*-.            
                          .+@@@@-.+@@@@@@@@-**.:@@@@@@@@@@:...#@#..*@@@@@#..#@@@@@@@:.              
                          .#=@@@.%@@@@@@@@-..+@@@@@@@@@@@+@-..%@@@:..@@@@@@@-.-=@@@@@..             
                          .:.@@@@@@@@@@@@-.%@@@@@@@@@@@@@:.%..@@@@@#..:@@@@@@@=..@@@@:.             
                            .@@@@@@@@@@@=@@@@@@@@@@@@%:..%@#.:@@@@@@@. .@@@@+:@# .%@@-.             
                            .@@@@@@@@@@%@@@@@@#@#+-...*@@@@..*@@@@@@@% .@@@+ .=-..@@:.              
                            .@*@@@+@@@@@@@@@-=*...:@@@@@@@:..@@@@@@@@@. .*@@:     .#@.              
                            .--@@+:@@@@@@@=.+..=@@@@%%@@@...*@@@@@@@@@. .*@+      .*=.              
                              -@=.+@@@@@%...=@@@*:..=@@+.. -@@-%@@@@@:...@-.     ..*.               
                              --. *@@@@=..+@@+.. ..#@%.   -@=.-@@@@@.. .=.        ..                
                              .. .#@@@:.:@@..   .-@#..   ++...%@@@%..                               
                                 .@@@:.:@:.   ..%=..  ..#.. .#@@@..                                 
                                 .@@. .#.    .-.           .%@%..                                   
                                .#*.  ..                 .+@=..                                     
                                +.                    ..=+..                                        
                 ██╗  ██╗███████╗██╗     ██╗     ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
                 ██║  ██║██╔════╝██║     ██║     ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
                 ███████║█████╗  ██║     ██║     ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
                 ██╔══██║██╔══╝  ██║     ██║     ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
                 ██║  ██║███████╗███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
                 ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
"""
    # 1. Initialise Animation (Preserving terminal history)
    
    white = Fore.WHITE + Style.BRIGHT
    red = Fore.RED + Style.BRIGHT
    reset = Style.RESET_ALL
    
    braille_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    
    # ENLARGED BOOT HUD (60 chars width)
    duration = 4.2
    end_time = time.time() + duration
    frame = 0
    import shutil
    while time.time() < end_time:
        t = time.time() - (end_time - duration)
        prefix = f"{red}{braille_frames[frame % 10]}{reset}"
        
        # Wave Text (Enlarged)
        full_text = f"HELLHOUND FRAMEWORK CONSOLE IS STARTING"
        wave_label = ""
        for i, char in enumerate(full_text):
            v = math.sin(t * 10 + i * 0.4)
            if v > 0:
                wave_label += f"{red}{Style.BRIGHT}{char.upper()}{reset}"
            else:
                wave_label += f"{Fore.RED}{char.lower()}{reset}"
        
        # DYNAMIC PROGRESS BAR (Fills terminal)
        cols = shutil.get_terminal_size((80, 24)).columns
        prefix_len = len(full_text) + 10
        bar_len = max(10, cols - prefix_len)
        
        bar = ""
        bframes = ["⡀", "⡄", "⡆", "⡇", "⣇", "⣧", "⣷", "⣿"]
        for i in range(bar_len):
            idx = int((math.sin(t * 5 + i * 0.3) + 1) / 2 * 7)
            bar += f"{red}{bframes[idx]}{reset}"
        
        sys.stdout.write(f"\r {prefix}  {wave_label}  {bar}")
        sys.stdout.flush()
        time.sleep(0.06)
        frame += 1

    # CLEAR ANIMATION LINE BEFORE LOGO
    sys.stdout.write("\033[2K\r")
    sys.stdout.flush()
    
    # 2. Reveal Banner (Classic Centered)
    import shutil
    w = shutil.get_terminal_size((120, 24)).columns
    AUTHOR_META = "[ Created by L4ZZ3RJ0D — @l4zz3rj0d ]"

    lines = [l.rstrip() for l in BANNER.split('\n') if l.strip()]
    if lines:
        max_line_w = max(len(l) for l in lines)
        offset = max(0, (w - max_line_w) // 2)
        # Print full logo block instantly to avoid terminal scroll clutter
        full_logo = "\n".join([( " " * offset ) + line for line in lines])
        sys.stdout.write(Fore.RED + full_logo + Style.RESET_ALL + "\n")
        sys.stdout.flush()
    
    # Author Metadata (Centered)
    print(f"\033[37m{AUTHOR_META:^{w}}\033[0m\n")
    time.sleep(0.3)


# ----------------------------
# Load modules from filesystem + config.yaml (descriptions only)
# ----------------------------
_MODULE_LOAD_ERRORS = {}   # module_name → error string (for debug display)

def load_modules(debug: bool = False):
    modules = {}

    base = pkg_resources.files("hellhound").joinpath("modules")

    for category in os.listdir(base):
        cat_path = base.joinpath(category)
        if not cat_path.is_dir():
            continue

        for file in os.listdir(cat_path):
            if not file.endswith(".py") or file.startswith("__"):
                continue

            module_name = file[:-3]

            try:
                module = __import__(
                    f"hellhound.modules.{category}.{module_name}",
                    fromlist=["*"]
                )

                description = getattr(module, "DESCRIPTION", "No description provided")
                real_category = getattr(module, "CATEGORY", category)

            except Exception as exc:
                description = f"[BROKEN] Failed to load"
                real_category = category
                _MODULE_LOAD_ERRORS[module_name] = str(exc)
                if debug:
                    print(
                        Fore.YELLOW + f"[!] Module '{module_name}' failed to load: "
                        + Fore.RED + str(exc) + Style.RESET_ALL
                    )

            modules[module_name] = {
                "category": real_category,
                "description": description
            }

    return modules

class HellhoundConsole(cmd.Cmd):

    # Intro is empty now because we handle the visual in preloop
    intro = "" 

    prompt = Fore.RED + "hellhound > " + Style.RESET_ALL

    # ----------------------------
    # Init
    # ----------------------------
    def __init__(self):
        super().__init__()
        self.target = None
        self.target_type = None   # host | web
        self.engine = HellhoundEngine(socketio=None)
        self.engine.attach_console(self)  # Route module emit through console colored methods
        self.results = {}
        self.active_module = None
        self.modules = load_modules()
        self.module_options = {}

        from hellhound.core.emit import ConsoleEmit
        from hellhound.core.ai_utils import load_config
        from hellhound.core.scope import ScopeRules

        cfg = load_config()
        self.options = {
            "ai_model": cfg.get("ai_model", "qwen2.5:3b-instruct-q4_0"),
            "ai_provider": cfg.get("ai_provider", "ollama"),
            "global_headers": cfg.get("global_headers", {})
        }
        self.scope_rules = ScopeRules.from_dict(cfg.get("scope", {}))
        self.emit = ConsoleEmit(self)

        # ----------------------------
        # Target Session Context
        # ----------------------------
        self.target_context = {
            "url": None,
            "cookies": None,
            "headers": {},
            "proxy": None,
            "proxy_enabled": True,
            "global_headers": {},
            "enable_waf_bypass": False,
            "oob_url": None,
            "oob_server": None,
            "ai_key": None,
            "ai_provider": "gemini",
            "ai_model": "gemini-1.5-flash-latest",
            "ai_status_label": "NOT CONNECTED",
            "proxy_mode": "repro_only"
        }
        self.update_available = False

        # ANIMATOR STATE
        self._anim_active  = False
        self._anim_thread  = None
        self._anim_stop_event = threading.Event()
        self.term_lock     = threading.Lock() # SYNCHRONIZATION LOCK
        self._anim_label   = ""
        self._anim_total   = 0
        self._anim_current = 0
        self._last_anim_line = ""
        self._anim_start_time = 0

        self.aliases = {
            "hunt": "prey",
            "run": "strike",
            "use": "equip",
            "back": "release",
            "OPTIONS": [
                {"name": "use_ai", "type": bool, "default": False, "help": "Use AI (LLM) to verify findings and reduce false positives"},
            ],
            "ls": "arsenal",
            "results": "loot",
            "quit": "exit",
            "q": "exit",
            "cls": "clear",
            "setg": "setg",
            "show": "show"
        }

        # ---- Command history via readline ----
        try:
            import readline
            self._history_file = os.path.expanduser("~/.hellhound_history")
            try:
                readline.read_history_file(self._history_file)
            except FileNotFoundError:
                pass
            readline.set_history_length(500)
            import atexit
            atexit.register(readline.write_history_file, self._history_file)
        except ImportError:
            pass

    # ----------------------------
    # ANIMATION HELPERS
    # ----------------------------
    def _get_case_wave(self, label: str, t: float) -> str:
        """Pulsing case-wave logic: v = sin(t * 10 + i * 0.4)"""
        res = ""
        for i, char in enumerate(label):
            if not char.isalpha():
                res += char
                continue
            v = math.sin(t * 10 + i * 0.4)
            if v > 0:
                res += f"{C_PRIMARY_RED}{char.upper()}{Style.RESET_ALL}"
            else:
                res += f"{C_DIM_RED}{char.lower()}{Style.RESET_ALL}"
        return res

    def _get_braille_wave(self, t: float, width: int = 60) -> str:
        """Braille-wave logic: idx = int((sin(t * 5 + i * 0.3) + 1) / 2 * 7)"""
        frames = ["⡀", "⡄", "⡆", "⡇", "⣇", "⣧", "⣷", "⣿"]
        res = ""
        for i in range(width):
            idx = int((math.sin(t * 5 + i * 0.3) + 1) / 2 * 7)
            res += f"{C_PRIMARY_RED}{frames[idx]}{Style.RESET_ALL}"
        return res

    # ----------------------------
    # NEW STICKY ANIMATOR API
    # ----------------------------

    def clear_progress_unlocked(self):
        """Wipes the current animation line without acquiring the lock."""
        if self._last_anim_line:
            # Strip ANSI to get real length
            clean_len = len(re.sub(r'\033\[[^m]*m', '', self._last_anim_line))
            sys.stdout.write("\r" + " " * (clean_len + 5) + "\r")
            sys.stdout.flush()

    def clear_progress(self):
        """Wipes the current animation line to allow clean log printing."""
        with self.term_lock:
            self.clear_progress_unlocked()

    def start_animation(self, label: str, total: int = 0):
        """Starts the background animation thread."""
        self._anim_active = True
        self._anim_label = label
        self._anim_total = total
        self._anim_current = 0
        self._anim_start_time = time.time()
        self._anim_stop_event.clear()
        
        if self._anim_thread and self._anim_thread.is_alive():
            self.stop_animation()
            
        self._anim_thread = threading.Thread(target=self._animate_loop_thread, daemon=True)
        self._anim_thread.start()

    def progress_stop(self):
        """Stop sticky animation."""
        pass
    
    def stop_animation(self):
        """Alias for progress_stop."""
        self.progress_stop()
        self._anim_active = False
        self._anim_stop_event.set()
        if self._anim_thread:
            # We don't join to avoid blocking for too long, but we ensure it stops
            self._anim_thread = None
        self.clear_progress()
        self._last_anim_line = ""

    def update_animation(self, current: int, label: str = None):
        """Updates the progress stats for the active animation."""
        self._anim_current = current
        if label:
            self._anim_label = label

    def _animate_loop_thread(self):
        """Background thread that handles the actual rendering."""
        while not self._anim_stop_event.is_set():
            try:
                t = time.time() - self._anim_start_time
                
                # Render components
                full_label = f"HELLHOUND IS USING {self._anim_label.upper()}"
                wave_label = ""
                for i, char in enumerate(full_label):
                    v = math.sin(t * 10 + i * 0.4)
                    if v > 0:
                        wave_label += f"{C_PRIMARY_RED}{Style.BRIGHT}{char.upper()}{Style.RESET_ALL}"
                    else:
                        wave_label += f"{C_DIM_RED}{char.lower()}{Style.RESET_ALL}"

                bar = self._get_braille_wave(t)
                line = f"   {wave_label}   {bar}"
                self._last_anim_line = line
                
                with self.term_lock:
                    sys.stdout.write("\r" + line)
                    sys.stdout.flush()
                
                # Precise timing
                time.sleep(0.06)
            except Exception:
                time.sleep(0.5)

    def progress(self, label: str, current: int, total: int, start_time: float = None):
        """Legacy sync bridge / direct call (if animator not used)."""
        # Since we moved to background animator, this can either trigger it or 
        # just do a one-off render. To maintain compatibility with existing 
        # Spider integration, we'll make it update the animator if active.
        if self._anim_active:
            self.update_animation(current, label)
        else:
            # Fallback to the old one-off render logic if for some reason animator isn't used
            t = time.time()
            wave_label = self._get_case_wave(label, t)
            bar = self._get_braille_wave(t)
            if total > 0:
                stats = f"{C_WHITE}{current}/{total}{Style.RESET_ALL} ({int(current/total*100)}%)"
            else:
                stats = f"{C_WHITE}{current}{Style.RESET_ALL}"
            line = f" {C_HUD_CYAN}[*]{Style.RESET_ALL} {wave_label}  {bar} {stats}"
            self._last_anim_line = line
            sys.stdout.write(f"\r{line}")
            sys.stdout.flush()

    # ----------------------------


    # ----------------------------
    # Hackeristic Boot Sequence (UPGRADED)
    # ----------------------------
    def preloop(self):
        # ── 1. Start background update check ──────────────────
        # Runs during the boot animation to save time.
        check_thread = threading.Thread(target=self._check_for_updates, daemon=True)
        check_thread.start()

        # ── 2. Run Boot Animation ─────────────────────────────
        _boot_sequence()

        # ── 3. Post-Animation Logic ───────────────────────────
        print(f"{Fore.WHITE}Type '{Fore.YELLOW}/help{Fore.WHITE}' (or '{Fore.YELLOW}help{Fore.WHITE}') to view all unified slash commands.")
        print(f"{Fore.WHITE}Type '{Fore.CYAN}/recon <target>{Fore.WHITE}' to begin target reconnaissance.")
        print(f"{Fore.WHITE}Type '{Fore.CYAN}/howl{Fore.WHITE}' or '{Fore.CYAN}/ask <question>{Fore.WHITE}' to query the AI Neural Core.\n")
        
        # Give the thread a tiny bit more time if it's not finished
        # (Though animation is 4.2s, so it should be done)
        check_thread.join(timeout=0.5)

        if self.update_available:
            print(f"  {Fore.RED + Style.BRIGHT}[!] Update available: {Fore.WHITE}A newer version of Hellhound is ready.{Style.RESET_ALL}")
            print(f"      {Fore.WHITE}Type '{Fore.YELLOW}upgrade{Fore.WHITE}' to install latest features and patches.{Style.RESET_ALL}\n")

    def _check_for_updates(self):
        """
        Fast, lightweight check for framework updates.
        Sets self.update_available if an update is found on origin.
        Designed to be called in a background thread.
        """
        import subprocess
        from pathlib import Path
        try:
            # Find project root
            import hellhound
            root = Path(hellhound.__file__).resolve().parent.parent
            
            # 1. Get current local SHA
            local_sha = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], 
                cwd=root, 
                stderr=subprocess.DEVNULL,
                timeout=3
            ).decode().strip()

            # 2. Get remote SHA without full fetch (fast)
            remote_output = subprocess.check_output(
                ["git", "ls-remote", "origin", "HEAD"],
                cwd=root,
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode().strip()
            
            if not remote_output:
                return
                
            remote_sha = remote_output.split()[0]
            
            if local_sha != remote_sha:
                self.update_available = True
                
        except Exception:
            # Silently fail on network error, no git repo, or timeout
            pass
    
    # ============================
    # TAB COMPLETION
    # ============================

    def complete_strike(self, text, line, begidx, endidx):
        """
        TAB completion for: strike <module>
        """
        return self._module_autocomplete(text)

    def complete_equip(self, text, line, begidx, endidx):
        """
        TAB completion for: equip <module>
        """
        return self._module_autocomplete(text)

    def _module_autocomplete(self, text):
        """
        Returns matching modules based on typed text.
        Case-insensitive.
        """
        modules = list(self.modules.keys())

        if not text:
            return modules

        return [m for m in modules if m.lower().startswith(text.lower())]

    # ============================
    # CORE COMMANDS
    # ============================

    def do_prey(self, arg):
        """
        prey <domain> [--cookie "..."] [--header "Key: Value"]
        """

        parts = arg.split()
        if not parts:
            print("Usage: prey <domain> [--cookie \"...\"] [--header \"Key: Value\"]")
            return

        domain = parts[0]
        cookies = None
        headers = {}

        i = 1
        while i < len(parts):
            if parts[i] == "--cookie" and i + 1 < len(parts):
                cookies = parts[i + 1]
                i += 2
            elif parts[i] == "--header" and i + 1 < len(parts):
                header_input = parts[i + 1]
                if ":" in header_input:
                    k, v = header_input.split(":", 1)
                    headers[k.strip()] = v.strip()
                i += 2
            else:
                i += 1

        self.target = domain
        self.target_type = "web"

        self.target_context["url"] = domain
        self.target_context["cookies"] = cookies
        self.target_context["headers"] = headers

        print(Fore.CYAN + f"[+] Web target acquired: {domain}")

        if cookies:
            print(Fore.CYAN + "[*] Session cookie loaded")
        if headers:
            print(Fore.CYAN + "[*] Custom headers loaded")

        
    def do_exit(self, arg):
        """exit → Leave console"""
        print(Fore.RED + "[+] Exiting Hellhound console")
        return True

    def do_upgrade(self, arg):
        """upgrade → Pull latest updates and sync dependencies from within console"""
        import subprocess
        import os
        from pathlib import Path

        print(Fore.CYAN + "[*] Initializing framework upgrade...")
        
        # Find the project root
        # Since this is installed via 'pip install -e .', we can use the package path
        try:
            import hellhound
            project_root = Path(hellhound.__file__).resolve().parent.parent
            update_script = project_root / "update.sh"

            if not update_script.exists():
                print(Fore.RED + f"[x] Error: Update script not found at {update_script}")
                return

            # Ensure it's executable
            os.chmod(update_script, 0o755)

            # Inform user
            print(Fore.YELLOW + "[!] The console will temporarily suspend to run the update process.")
            print(Fore.YELLOW + "[!] After update completes, please restart hellhound.")
            time.sleep(1.5)

            subprocess.run(["bash", str(update_script)], check=True)
            
            print(Fore.GREEN + "\n[✓] Upgrade complete. Please exit and restart hellhound to use the new version.")
        except Exception as e:
            print(Fore.RED + f"[x] Critical error during console upgrade: {e}")

    def do_debug(self, arg):
        """debug modules → Show list of modules that failed to load and the error reason"""
        cmd = arg.strip().lower()
        if cmd == "modules" or not cmd:
            if not _MODULE_LOAD_ERRORS:
                print(Fore.GREEN + Style.BRIGHT + "[✓] All modules loaded successfully. No errors." + Style.RESET_ALL)
                return
            print(Fore.YELLOW + Style.BRIGHT + f"\n[!] {len(_MODULE_LOAD_ERRORS)} module(s) failed to load:\n" + Style.RESET_ALL)
            for mod, err in _MODULE_LOAD_ERRORS.items():
                print(f"  {Fore.RED + Style.BRIGHT}✗ {mod}{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}{err}{Style.RESET_ALL}\n")
        else:
            print(Fore.YELLOW + "[!] Usage: debug modules")


    # ============================
    # DISPLAY
    # ============================

    def do_arsenal(self, arg):
        """arsenal [category] → List available modules, optionally filtered by category"""

        filter_cat = arg.strip().lower() if arg.strip() else None

        # Group by category
        categorized = {}
        for name, meta in sorted(self.modules.items()):
            cat = meta.get("category", "unknown").lower()
            if filter_cat and cat != filter_cat:
                continue
            categorized.setdefault(cat, []).append((name, meta["description"]))

        if not categorized:
            if filter_cat:
                print(Fore.YELLOW + f"[!] No modules found for category '{filter_cat}'." + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "[!] No modules loaded." + Style.RESET_ALL)
            return

        cat_colors = {
            "recon":    Fore.CYAN   + Style.BRIGHT,
            "analysis": Fore.BLUE   + Style.BRIGHT,
            "exploit":  Fore.RED    + Style.BRIGHT,
            "intel":    Fore.MAGENTA + Style.BRIGHT,
            "vuln":     Fore.YELLOW + Style.BRIGHT,
        }

        print(Fore.RED + Style.BRIGHT + "\n╔══════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + "║           HELLHOUND — ARSENAL        ║")
        print(Fore.RED + Style.BRIGHT + "╚══════════════════════════════════════╝" + Style.RESET_ALL)

        for cat in ["recon", "analysis", "vuln", "exploit", "intel", "unknown"]:
            if cat not in categorized:
                continue
            cc = cat_colors.get(cat, Fore.WHITE)
            print(f"\n  {cc}{Style.BRIGHT}[ {cat.upper()} ]{Style.RESET_ALL}")
            for name, desc in categorized[cat]:
                active_marker = Style.BRIGHT + Fore.GREEN + " ◀ ACTIVE" + Style.RESET_ALL if name == self.active_module else ""
                print(f"    {Fore.WHITE + Style.BRIGHT}{name:<16}{Style.RESET_ALL}{Fore.WHITE}{desc}{Style.RESET_ALL}{active_marker}")

        # ── CORE ENGINES (Universal Commands) ─────────────────
        print(f"\n  {Fore.RED + Style.BRIGHT}[ CORE ENGINES ]{Style.RESET_ALL}")
        print(f"    {Fore.WHITE + Style.BRIGHT}{'howl':<16}{Style.RESET_ALL}{Fore.WHITE}AI-Powered Attack Path Correlation & Reasoning{Style.RESET_ALL}")
        print(f"    {Fore.WHITE + Style.BRIGHT}{'reproduce':<16}{Style.RESET_ALL}{Fore.WHITE}Universal Vulnerability Replay Engine (Alias: repro){Style.RESET_ALL}")
        print()

        print()

    # ============================
    # MODULE SELECTION
    # ============================

    def do_equip(self, arg):
        """equip <module> → Load a module and prepare it for execution"""
        module_name = arg.strip()

        if not module_name:
            print(Fore.YELLOW + "[!] Usage: equip <module_name>" + Style.RESET_ALL)
            return

        # Case-insensitive match
        match = None
        for name in self.modules:
            if name.lower() == module_name.lower():
                match = name
                break

        if not match:
            print(Fore.RED + f"[x] Module '{module_name}' not found. Use 'arsenal' to list available modules." + Style.RESET_ALL)
            return

        mod_obj = self._load_module(match)
        if not mod_obj:
            print(Fore.RED + f"[x] Failed to load module '{match}'." + Style.RESET_ALL)
            return

        self.active_module = match

        # Load default options from module OPTIONS definition
        options_def = self._get_normalized_options(mod_obj)
        self.module_options = {opt.get("name"): opt.get("default") for opt in options_def if isinstance(opt, dict)}

        category = self.modules[match].get("category", "unknown")
        description = self.modules[match].get("description", "")

        print(Style.BRIGHT + Fore.CYAN + f"\n[+] Module equipped: {match}" + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.WHITE + f"    Category    " + Style.RESET_ALL + f": {Style.BRIGHT + Fore.CYAN}{category}" + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.WHITE + f"    Description " + Style.RESET_ALL + f": {Fore.WHITE}{description}" + Style.RESET_ALL)

        if options_def:
            print(Style.BRIGHT + Fore.YELLOW + f"\n    Options loaded. Use 'options' to view, 'set <option> <value>' to configure." + Style.RESET_ALL)

        print()
        # Update prompt to show active module
        self.prompt = (Fore.RED + Style.BRIGHT + "hellhound" + Style.RESET_ALL + Fore.WHITE + " [" +
                       Style.BRIGHT + Fore.CYAN + match + Style.RESET_ALL + Fore.WHITE + "] > " + Style.RESET_ALL)

    def do_release(self, arg):
        """release → Unload the current module"""
        if not self.active_module:
            print(Fore.YELLOW + "[!] No module currently equipped." + Style.RESET_ALL)
            return
        print(Fore.YELLOW + f"[*] Released module: {self.active_module}" + Style.RESET_ALL)
        self.active_module = None
        self.module_options = {}
        self.prompt = Fore.RED + "hellhound > " + Style.RESET_ALL

    # ============================
    # OPTIONS & CONFIGURATION
    # ============================

    def _print_opt_line(self, name, current, required, helptext, C_NAME=22, C_VAL=24, C_REQ=10):
        if current is None or current == "" or current == {}:
            disp = ""
        elif isinstance(current, str) and len(current) > 100 and current.startswith("eyJ"):
            c_str = str(current)
            disp = f"{c_str[:8]}...{c_str[-4:]}"
        elif isinstance(current, str) and current.lower().startswith("bearer "):
            c_str = str(current)
            tok  = c_str[7:]
            disp = f"Bearer {tok[:8]}...{tok[-4:]}"
        elif isinstance(current, str) and "=" in current and len(current) > C_VAL:
            c_str = str(current)
            first = c_str.split(";")[0].strip()
            if "=" in first:
                k, v  = first.split("=", 1)
                max_v = max(4, C_VAL - len(k) - 4)
                disp  = f"{k}={v[:max_v]}..." if len(v) > max_v else f"{k}={v}"
            else:
                disp = first[:C_VAL-3] + "..."
        else:
            raw = str(current)
            disp = raw[:C_VAL - 3] + "..." if len(raw) > C_VAL else raw

        if disp:
            val_color = Fore.GREEN + Style.BRIGHT
        elif required:
            val_color = Fore.RED
            disp      = "not set"
        else:
            val_color = Fore.LIGHTBLACK_EX
            disp      = ""

        req_str   = "yes" if required else "no"
        req_color = Fore.RED + Style.BRIGHT if required else Fore.WHITE

        pad_name = " " * max(0, C_NAME - len(name))
        pad_val  = " " * max(0, C_VAL  - len(disp))
        pad_req  = " " * max(0, C_REQ  - len(req_str))

        print(f"   {Fore.CYAN + Style.BRIGHT}{name}{Style.RESET_ALL}{pad_name}"
              f"{val_color}{disp}{Style.RESET_ALL}{pad_val}"
              f"{req_color}{req_str}{Style.RESET_ALL}{pad_req}"
              f"{Fore.WHITE}{helptext}{Style.RESET_ALL}")

    def do_options(self, arg):
        """options → Show current module and global options"""
        # Column widths
        C_NAME = 22
        C_VAL  = 24
        C_REQ  = 10

        # Labels & Separators
        h_name = f"{'Name':<{C_NAME}}"
        h_val  = f"{'Current Setting':<{C_VAL}}"
        h_req  = f"{'Required':<{C_REQ}}"
        h_desc = "Description"
        
        sep_name = "-" * len("Name")
        sep_val  = "-" * len("Current Setting")
        sep_req  = "-" * len("Required")
        sep_desc = "-" * len("Description")
        
        header_line = f"   {Style.BRIGHT + Fore.WHITE}{h_name}{h_val}{h_req}{h_desc}{Style.RESET_ALL}"
        sep_line    = f"   {Fore.WHITE}{sep_name:<{C_NAME}}{sep_val:<{C_VAL}}{sep_req:<{C_REQ}}{sep_desc}{Style.RESET_ALL}"

        # ── 1. Module Options ─────────────────────────────────────
        if self.active_module:
            mod_obj = self._load_module(self.active_module)
            options_def = self._get_normalized_options(mod_obj) if mod_obj else []
            cat = self.modules.get(self.active_module, {}).get("category", "module")
            
            print(f"\n  Module options ({Fore.CYAN + Style.BRIGHT}{cat}/{self.active_module}{Style.RESET_ALL}):\n")
            print(header_line)
            print(sep_line)

            for opt in options_def:
                name     = opt.get("name", "")
                default  = opt.get("default")
                helptext = opt.get("help", "")
                required = opt.get("required", False)
                current  = self.module_options.get(name, default)
                self._print_opt_line(name, current, required, helptext, C_NAME, C_VAL, C_REQ)
            print()
        else:
            print(Style.BRIGHT + Fore.YELLOW + "\n[•] No module equipped. Showing global options only." + Style.RESET_ALL)

        # ── 2. Global Options ─────────────────────────────────────
        print(f"  Global options:\n")
        print(header_line)
        print(sep_line)

        # Proxy
        p_val = self.target_context.get("proxy")
        if p_val:
            p_status = " (ENABLED)" if self.target_context.get("proxy_enabled", True) else " (DISABLED)"
            p_disp   = f"{p_val}{p_status}"
        else:
            p_disp   = ""
        self._print_opt_line("proxy", p_disp, False, "Global HTTP/S proxy (use 'proxy enable/disable' to toggle)", C_NAME, C_VAL, C_REQ)
        
        # Proxy Mode
        pm_val = self.target_context.get("proxy_mode", "repro_only").upper()
        self._print_opt_line("proxy_mode", pm_val, False, "Proxy behavior: repro_only (Silent Scan) | all", C_NAME, C_VAL, C_REQ)

        # BugBounty
        bb = self.target_context.get("global_headers", {}).get("X-Bugbounty", "")
        self._print_opt_line("bugbounty", bb, False, "Bug Bounty ID added to X-Bugbounty header", C_NAME, C_VAL, C_REQ)
        
        # WAF Bypass
        waf = "true" if self.target_context.get("enable_waf_bypass") else "false"
        self._print_opt_line("wafbypass", waf, False, "Enable automatic WAF/IPS bypass header injection", C_NAME, C_VAL, C_REQ)
        
        # OOB
        oob = self.target_context.get("oob_url", "")
        self._print_opt_line("oob", oob, False, "Global OOB URL for blind detection", C_NAME, C_VAL, C_REQ)
        # AI in global options table
        ai_k = self.target_context.get("ai_key", "")
        if ai_k and ai_k != "local":
            ai_disp = f"{ai_k[:4]}...{ai_k[-4:] if len(ai_k)>8 else ''}"
        elif ai_k == "local":
            ai_disp = "LOCAL (Ollama)"
        else:
            ai_disp = ""
        self._print_opt_line("ai", ai_disp, False, "AI engine: 'setg ai local' or 'setg ai <api_key>'", C_NAME, C_VAL, C_REQ)
        print()

        # ── 3. AI Intelligence (Tag Style) ────────────────
        BG_RED = "\033[41;97;1m"
        RST_ANSI = "\033[0m"
        
        ai_label = self.target_context.get("ai_status_label", "NOT CONNECTED")
        ai_provider = self.target_context.get("ai_provider", "")
        ai_model = self.target_context.get("ai_model", "")
        is_connected = ai_label.startswith("CONNECTED")
        
        if is_connected:
            print(f"  {BG_RED} AI {RST_ANSI} \033[91;1mINTELLIGENCE\033[0m  \033[92;1m● ONLINE\033[0m  \033[96m{ai_provider.upper()} / {ai_model}\033[0m")
            print(f"  \033[37m     ask  ·  analyze  ·  howl\033[0m")
        else:
            print(f"  {BG_RED} AI {RST_ANSI} \033[91;1mINTELLIGENCE\033[0m  \033[31m○ OFFLINE\033[0m")
            print(f"  \033[37m     setg ai local  ·  setg ai <api_key>\033[0m")
        print()

    def do_show(self, arg):
        """show <options|modules|loot> → Display various framework states"""
        cmd = arg.lower().strip()
        if not cmd:
            print(Fore.YELLOW + "[!] Usage: show <options|modules|loot|info>")
            return
        
        if cmd == "options":
            self.do_options("")
        elif cmd in ("modules", "arsenal"):
            self.do_arsenal("")
        elif cmd in ("loot", "results"):
            self.do_loot("")
        elif cmd == "info":
            if self.active_module:
                self.do_equip(self.active_module)
            else:
                print(Fore.YELLOW + "[!] No module equipped to show info for.")
        else:
            print(Fore.RED + f"[x] Unknown show target: {cmd}")


    def do_set(self, arg):
        """set <option> <value> → Set a module option"""
        if not self.active_module:
            print(Fore.YELLOW + "[!] No module equipped. Use 'equip <module>' first." + Style.RESET_ALL)
            return

        parts = arg.split(None, 1)
        if len(parts) < 2:
            print(Fore.YELLOW + "[!] Usage: set <option> <value>" + Style.RESET_ALL)
            return

        key, raw_value = parts[0].strip().lower(), parts[1].strip()

        # Catch Global AI settings for Zero-Config experience
        if key in ("ai_key", "aikey", "ai"):
            return self.do_setg(f"ai {raw_value}")

        mod_obj = self._load_module(self.active_module)
        options_def = self._get_normalized_options(mod_obj) if mod_obj else []

        # Find the option definition to enforce correct type
        opt_def = next((o for o in options_def if o["name"] == key), None)

        if not opt_def:
            # Warn but allow — future-proof for dynamic options
            print(Fore.YELLOW + f"[!] '{key}' is not a declared option for {self.active_module}." + Style.RESET_ALL)
            print(Fore.YELLOW + f"    Setting anyway. Use 'options' to see valid options." + Style.RESET_ALL)
            self.module_options[key] = raw_value
            return

        # Type coercion with validation
        typ = opt_def.get("type", str)
        try:
            if typ == bool:
                if raw_value.lower() in ("true", "1", "yes"):
                    coerced = True
                elif raw_value.lower() in ("false", "0", "no"):
                    coerced = False
                else:
                    raise ValueError(f"Expected bool (true/false), got '{raw_value}'")
            elif typ == int:
                coerced = int(raw_value)
            elif typ == dict:
                coerced = json.loads(raw_value)
            else:
                coerced = str(raw_value)
        except (ValueError, json.JSONDecodeError) as e:
            print(Fore.RED + f"[x] Type error for '{key}': {e}" + Style.RESET_ALL)
            return

        self.module_options[key] = coerced
        print(Fore.GREEN + f"[✓] {key} => {coerced}" + Style.RESET_ALL)

    def do_setg(self, arg):
        """setg <option> <value> → Set a global option (proxy | bugbounty | wafbypass | oob | ai_key)"""
        parts = arg.split(None, 1)
        if len(parts) < 1:
            print(Fore.CYAN + "── GLOBAL CONFIGURATION ──")
            p = self.target_context.get("proxy", "None") or "None"
            s = "ENABLED" if self.target_context.get("proxy_enabled", True) else "DISABLED"
            color = Fore.GREEN if s == "ENABLED" else Fore.RED
            print(f"  Proxy:      {p} [{color}{s}{Fore.CYAN}]")
            print(f"  WAF Bypass: {'ENABLED' if self.target_context.get('enable_waf_bypass') else 'DISABLED'}")
            print(f"  OOB URL:    {self.target_context.get('oob_url') or 'None'}")
            print(f"  OOB Server: {'RUNNING' if self.target_context.get('oob_server') and self.target_context.get('oob_server')._server else 'STOPPED'}")
            print(f"  Headers:    {self.target_context.get('global_headers', {})}")
            print(f"  Proxy Mode: {self.target_context.get('proxy_mode', 'repro_only').upper()}")
            
            # Integrated AI view in setg summary
            ai_lbl = self.target_context.get("ai_status_label", "NOT CONNECTED")
            ai_color = Fore.GREEN if "CONNECTED" in ai_lbl else Fore.RED
            print(f"  Intelligence: {ai_color}{ai_lbl}{Style.RESET_ALL}")

            return

        if len(parts) < 2:
            key = parts[0].lower()
            if key == "proxy":
                self.target_context["proxy"] = None
                print(Fore.GREEN + "[✓] Global Proxy cleared.")
            else:
                print(Fore.YELLOW + "[!] Usage: setg <proxy|bugbounty|wafbypass|oob|ai_key> <value>")
            return

        key, raw_value = parts[0].lower(), parts[1]

        if key == "proxy":
            self.target_context["proxy"] = raw_value
            self.target_context["proxy_enabled"] = True
            print(Fore.GREEN + f"[✓] Global Proxy => {raw_value} (ENABLED)")
        elif key == "bugbounty":
            self.target_context["global_headers"]["X-Bugbounty"] = raw_value
            print(Fore.GREEN + f"[✓] BugBounty Header => X-Bugbounty: {raw_value}")
        elif key == "wafbypass":
            self.target_context["enable_waf_bypass"] = raw_value.lower() in ("true", "1", "yes")
            state = "ENABLED" if self.target_context["enable_waf_bypass"] else "DISABLED"
            print(Fore.GREEN + f"[✓] Global WAF Bypass => {state}")
        elif key == "oob":
            self.target_context["oob_url"] = raw_value
            print(Fore.GREEN + f"[✓] Global OOB URL set: {raw_value}" + Style.RESET_ALL)
        elif key in ("ai_key", "key", "ai"):
            self._activate_ai(raw_value)

        elif key in ("ai_provider", "aiprovider"):
            # Still allow manual override if needed, but mark as manual
            prov = raw_value.lower().strip()
            if prov in ("gemini", "openai", "anthropic", "local", "ollama"):
                self.target_context["ai_provider"] = prov
                self.target_context["ai_status_label"] = f"MANUAL: {prov.upper()}"
                print(Fore.GREEN + f"[✓] Global AI Provider => {prov} (Manual Override)")
            else:
                print(Fore.RED + f"[x] Unsupported AI provider: {prov}. Use gemini | openai | anthropic | local")
        elif key == "ai_model":
            self.target_context["ai_model"] = raw_value
            self.target_context["ai_status_label"] = f"MANUAL: {raw_value.upper()}"
            print(Fore.GREEN + f"[✓] Global AI Model => {raw_value} (Manual Override)")
        elif key == "proxy_mode":
            mode = raw_value.lower().strip()
            if mode in ("all", "repro_only", "none"):
                self.target_context["proxy_mode"] = mode
                print(Fore.GREEN + f"[✓] Global Proxy Mode => {mode.upper()}")
            else:
                print(Fore.RED + f"[x] Unsupported proxy mode: {mode}. Use all | repro_only | none")

        else:
            # Custom global header
            if ":" in arg:
                k, v = arg.split(":", 1)
                self.target_context["global_headers"][k.strip()] = v.strip()
                print(Fore.GREEN + f"[✓] Global Header => {k.strip()}: {v.strip()}")
            else:
                print(Fore.RED + f"[x] Unknown global option: {key}. Supported: proxy, bugbounty, wafbypass, oob, ai_key, key" + Style.RESET_ALL)

    def do_activate(self, arg):
        """activate hellhound → Launch and connect the local AI engine (Ollama)"""
        target = arg.lower().strip()
        if target != "hellhound":
            print(Fore.YELLOW + "[!] Use 'activate hellhound' to launch the AI core.")
            return
        
        # Connect silently
        result = self._activate_ai("local", silent=True)
        
        if result and result.get("success"):
            print(Fore.RED + Style.BRIGHT + "Hellhound is activated")
            if not result.get("pulled", True):
                print(Fore.YELLOW + "    [!] Note: Model is being pulled in the background. First response may be slow.")
        else:
            print(Fore.RED + f"[x] Failed to activate Hellhound engine: {result.get('message', 'Unknown error')}")
            print(Fore.YELLOW + "    Ensure Ollama is running (ollama serve) and accessible at http://localhost:11434")

    def complete_activate(self, text, line, begidx, endidx):
        """TAB completion for: activate hellhound"""
        options = ["hellhound"]
        return [o for o in options if o.startswith(text.lower())]

    def _activate_ai(self, raw_value, silent=False):
        """Private helper to handle AI handshake and context updates."""
        explicit_prov = self.target_context.get("ai_provider")
        if raw_value.lower() in ("local", "ollama"):
            # Local SLM mode
            self.target_context["ai_key"] = "local"
            if not silent:
                with console.status("[bold white]INITIALIZING NEURAL CORE...[/]", spinner="earth"):
                    result = ai_utils.universal_handshake("ollama", explicit_provider="ollama")
            else:
                result = ai_utils.universal_handshake("ollama", explicit_provider="ollama")
        else:
            self.target_context["ai_key"] = raw_value
            masked = f"{raw_value[:4]}...{raw_value[-4:] if len(raw_value)>8 else ''}"
            if not silent:
                print(Fore.GREEN + f"[✓] AI Key => {masked}")
                with console.status("[bold white]ESTABLISHING QUANTUM LINK...[/]", spinner="bouncingBall"):
                    result = ai_utils.universal_handshake(raw_value, explicit_provider=explicit_prov)
            else:
                result = ai_utils.universal_handshake(raw_value, explicit_provider=explicit_prov)
        
        if result["success"]:
            self.target_context["ai_provider"] = result["provider"]
            self.target_context["ai_model"] = result["model"]
            self.target_context["ai_status_label"] = f"CONNECTED: {result['label']}"
            if not silent:
                print(Fore.CYAN + f"[✓] Intelligence Connected: {Style.BRIGHT}{result['label']}")
                print(Fore.WHITE + f"    Use 'ask' for Q&A | 'analyze' for finding analysis | 'howl' for attack chains" + Style.RESET_ALL)
        else:
            self.target_context["ai_status_label"] = "FAILED (Key Rejected)"
            if not silent:
                print(Fore.RED + f"[x] Intelligence Discovery Failed: {result['message']}")
        
        return result

    def do_oob(self, arg):
        """oob <start|stop|status> → Manage the global Out-of-Band (OOB) listener"""
        cmd = arg.lower().strip()
        if not cmd or cmd == "status":
            srv = self.target_context.get("oob_server")
            if srv and srv._server:
                print(Fore.GREEN + f"[*] OOB Server: RUNNING on {srv.get_url()}" + Style.RESET_ALL)
                print(Fore.WHITE + f"    Total Hits: {len(srv.hits)}")
            else:
                print(Fore.YELLOW + "[!] OOB Server: STOPPED" + Style.RESET_ALL)
            
            if self.target_context.get("oob_url"):
                print(Fore.CYAN + f"[*] External Collaborator: {self.target_context['oob_url']}" + Style.RESET_ALL)
            return

        if cmd == "start":
            if not self.target_context.get("oob_server"):
                self.target_context["oob_server"] = oob_utils.OOBServer()
            
            srv = self.target_context["oob_server"]
            if srv._server:
                print(Fore.YELLOW + f"[!] OOB Server is already running on {srv.get_url()}" + Style.RESET_ALL)
                return
            
            print(Fore.WHITE + "[*] Starting local OOB listener..." + Style.RESET_ALL)
            host, port = srv.start()
            if host and port:
                print(Fore.GREEN + f"[✓] OOB Listener active: http://{host}:{port}" + Style.RESET_ALL)
                print(Fore.WHITE + "    All modules will now use this for blind detection.")
            else:
                print(Fore.RED + "[x] Failed to start OOB listener." + Style.RESET_ALL)

        elif cmd == "stop":
            srv = self.target_context.get("oob_server")
            if srv and srv._server:
                srv.stop()
                print(Fore.YELLOW + "[*] OOB Server stopped." + Style.RESET_ALL)
            else:
                print(Fore.WHITE + "[*] No OOB server running." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[x] Unknown oob command: {cmd}. Usage: oob <start|stop|status>" + Style.RESET_ALL)

    def do_proxy(self, arg):
        """proxy <enable|disable|status> → Toggle or check the global proxy status"""
        cmd = arg.lower().strip()
        if cmd == "enable":
            if not self.target_context.get("proxy"):
                print(Fore.YELLOW + "[!] No proxy URL set. Use 'setg proxy <url>' first.")
                return
            self.target_context["proxy_enabled"] = True
            print(Fore.GREEN + f"[✓] Proxy Enabled: {self.target_context['proxy']}")
        elif cmd == "disable":
            self.target_context["proxy_enabled"] = False
            print(Fore.YELLOW + "[!] Proxy Disabled (Traffic will be direct)")
        elif cmd == "status" or not cmd:
            p = self.target_context.get("proxy", "None") or "None"
            s = "ENABLED" if self.target_context.get("proxy_enabled", True) else "DISABLED"
            color = Fore.GREEN if s == "ENABLED" else Fore.RED
            print(f"[*] Proxy: {p} [{color}{s}{Style.RESET_ALL}]")

    def do_verify_ai(self, arg):
        """verify-ai → Test AI connectivity and API key health"""
        key = self.target_context.get("ai_key")
        prov = self.target_context.get("ai_provider", "gemini")
        model = self.target_context.get("ai_model", "gemini-1.5-flash-latest")

        if not key:
            print(Fore.RED + "[x] AI Key not set. Use 'setg ai_key <key>' first.")
            return

        print(f"[*] Testing {prov.upper()} connectivity ({model})...")
        status = ai_utils.verify_ai(key, prov, model)
        
        if "[✓]" in status:
            print(Fore.GREEN + status)
        else:
            print(Fore.RED + f"[x] AI Verification failed: {status}")
            if "404" in status or "not found" in status.lower():
                print(Fore.YELLOW + "    Tip: Check if the model name is correct for your region/key.")

    def complete_set(self, text, line, begidx, endidx):
        """TAB completion for: set <option>"""
        if not self.active_module:
            return []
        mod_obj = self._load_module(self.active_module)
        if not mod_obj:
            return []
        options_def = self._get_normalized_options(mod_obj) if mod_obj else []
        names = [o["name"] for o in options_def]
        return [n for n in names if n.lower().startswith(text.lower())]

    # ============================
    # EXECUTION
    # ============================

    def _persist_results(self):
        """Saves current results to a shared sync file for the Intel Engine."""
        sync_dir = os.path.join("storage", "sync")
        if not os.path.exists(sync_dir):
            try: os.makedirs(sync_dir)
            except: pass
        
        sync_file = os.path.join(sync_dir, "session_sync.json")
        try:
            with open(sync_file, 'w') as f:
                json.dump(self.results, f, indent=4, default=str)
        except Exception:
            pass 

    def _load_sync_data(self):
        """Reloads results from the shared sync file (used by Intel Engine)."""
        sync_file = os.path.join("storage", "sync", "session_sync.json")
        if os.path.exists(sync_file):
            try:
                with open(sync_file, 'r') as f:
                    data = json.load(f)
                    self.results.update(data)
            except Exception:
                pass

    def do_strike(self, arg):
        """strike → Execute the equipped module against the target"""

        # ── Guard: target ──────────────────────────────────────
        if not self.target:
            print(Fore.RED + "[x] No target set. Use 'prey <target>' first." + Style.RESET_ALL)
            return

        # ── Guard: module ──────────────────────────────────────
        if not self.active_module:
            print(Fore.RED + "[x] No module equipped. Use 'equip <module>' first." + Style.RESET_ALL)
            return

        # ── Validate required options ──────────────────────────
        mod_obj = self._load_module(self.active_module)
        if not mod_obj:
            print(Fore.RED + f"[x] Failed to load module '{self.active_module}'." + Style.RESET_ALL)
            return

        options_def = self._get_normalized_options(mod_obj) if mod_obj else []
        missing = []
        for opt in options_def:
            if opt.get("required") and self.module_options.get(opt["name"]) in (None, ""):
                missing.append(opt["name"])

        if missing:
            print(Fore.RED + f"[x] Missing required options: {', '.join(missing)}" + Style.RESET_ALL)
            print(Fore.YELLOW + "    Use 'set <option> <value>' to configure." + Style.RESET_ALL)
            return

        # ── Merge target context into options ──────────────────
        runtime_options = dict(self.module_options)
        if self.target_context.get("cookies") and "cookie" not in runtime_options:
            runtime_options["cookie"] = self.target_context["cookies"]
        if self.target_context.get("headers") and "headers" not in runtime_options:
            runtime_options["headers"] = self.target_context["headers"]

        # ── Auto-feed Spider intel to any module that wants it ──
        # Silently inject previously collected spider intel so modules
        # can skip their internal crawlers and use the Spider brain instead.
        if not runtime_options.get("spider_intel"):
            for mod_name in ["spider", "surface_auditor", "hydra"]: # Best sources first
                res = self.results.get(mod_name)
                if res and res.get("intel") and res["intel"].get("endpoints"):
                    runtime_options["spider_intel"] = res["intel"]
                    break

        # ── Auto-feed Global Session Context ───────────────────
        proxy = self.target_context.get("proxy")
        proxy_mode = self.target_context.get("proxy_mode", "repro_only")
        
        if proxy and self.target_context.get("proxy_enabled", True):
            if proxy_mode == "all":
                runtime_options["proxy"] = proxy
            elif proxy_mode == "none":
                pass
        
        # Feed global headers and waf_bypass too
        if self.target_context.get("global_headers"):
            runtime_options.setdefault("global_headers", {}).update(self.target_context["global_headers"])
        if self.target_context.get("enable_waf_bypass"):
            runtime_options["enable_waf_bypass"] = self.target_context["enable_waf_bypass"]

        # ── Auto-feed BlobUnpacker intel ────────────────────────
        blob_result = self.results.get("blobunpacker")
        if blob_result and not runtime_options.get("blobunpacker_intel"):
            runtime_options["blobunpacker_intel"] = blob_result.get("intel", {})

        # ── Cookie raw-token detection warning ────────────────
        raw_cookie_val = self.target_context.get("cookies") or runtime_options.get("cookie")
        if raw_cookie_val and isinstance(raw_cookie_val, str) and "=" not in raw_cookie_val:
            print(Style.BRIGHT + Fore.YELLOW + "[•] Session token detected (auto-mapped)" + Style.RESET_ALL)

        # ── Auto-feed OOB Context ──────────────────────────────
        if self.target_context.get("oob_url"):
            runtime_options["oob_url"] = self.target_context["oob_url"]
        if self.target_context.get("oob_server"):
            runtime_options["oob_server"] = self.target_context["oob_server"]

        # ── Auto-feed AI Context ──────────────────────────────
        if self.target_context.get("ai_key"):
            runtime_options["ai_key"] = self.target_context["ai_key"]
            runtime_options["ai_provider"] = self.target_context.get("ai_provider", "gemini")
            runtime_options["ai_model"] = self.target_context.get("ai_model", "gemini-1.5-flash-latest")

        # ── Minimal strike header ──────────────────────────────
        print(Style.BRIGHT + Fore.RED + "\n[ STRIKE ]" + Style.RESET_ALL)
        
        print(Style.BRIGHT + Fore.WHITE + "  Module" + Style.RESET_ALL +
              " : " + Style.BRIGHT + Fore.CYAN + self.active_module.upper() + Style.RESET_ALL)
        print(Style.BRIGHT + Fore.WHITE + "  Target" + Style.RESET_ALL +
              " : " + Style.BRIGHT + Fore.CYAN + self.target + Style.RESET_ALL + "\n")

        try:
            result = self.engine.run_single(
                module_name=self.active_module,
                target=self.target,
                options=runtime_options
            )
        except Exception as e:
            print(Style.BRIGHT + Fore.RED + f"[✖] Strike failed: {e}" + Style.RESET_ALL)
            return

        if result:
            self.results[self.active_module.lower()] = result
            self._persist_results()
            print(Style.BRIGHT + Fore.GREEN + f"\n[+] Strike complete. Intel stored under '{self.active_module.lower()}'." + Style.RESET_ALL)
            print(Fore.CYAN + "    Use 'loot' to view results, 'howl' for suggestions, or 'repro' to verify.\n" + Style.RESET_ALL)
        else:
            print(Style.BRIGHT + Fore.YELLOW + "[•] Module returned no results." + Style.RESET_ALL)

    def _load_module(self, module_name):
        for category in ["recon", "analysis", "exploit", "intel", "vuln"]:
            try:
                module = __import__(
                    f"hellhound.modules.{category}.{module_name}",
                    fromlist=["*"]
                )
                return module
            except ImportError:
                continue
        return None

    def _get_normalized_options(self, mod_obj):
        """Standardizes module OPTIONS (converts dict to list of dicts if needed)."""
        options_def = getattr(mod_obj, "OPTIONS", [])
        if isinstance(options_def, dict):
            # Convert legacy dict-based OPTIONS to standard list-of-dicts
            normalized = []
            for k, v in options_def.items():
                opt = {"name": k}
                if isinstance(v, dict):
                    opt.update(v)
                    if "description" in v and "help" not in v:
                        opt["help"] = v["description"]
                normalized.append(opt)
            return normalized
        return options_def

    def _calculate_global_risk(self):
        total_risk = 0
        total_vulns = 0
        breakdown = {}

        for mod, output in self.results.items():
            module_risk = 0

            if not isinstance(output, dict):
                continue

            intel = output.get("intel", {})
            # ==============================
            # GLOBAL INTEL BOOSTS (NEW)
            # ==============================

            # Secrets exposure
            if intel.get("secrets"):
                module_risk += len(intel.get("secrets", [])) * 5

            # GraphQL exposed
            if intel.get("graphql"):
                module_risk += 4

            # OpenAPI exposed
            if intel.get("openapi"):
                module_risk += 3

            # ── Risk Scoring Precision ─────────────────────
            # Prioritize top-level module score to avoid double-counting nested intel keys.
            module_risk = 0
            if "risk_score" in output:
                module_risk = output["risk_score"]
            else:
                # Fallback: sum nested risk only if no top-level score exists
                module_risk += intel.get("risk_score", 0)
                if "bac" in intel and isinstance(intel["bac"], dict):
                    if "risk_score" not in intel:
                        module_risk += intel["bac"].get("risk_score", 0)

            # 4️⃣ BAC total vulns tracking (regardless of score source)
            if "bac" in intel and isinstance(intel["bac"], dict):
                total_vulns += len(intel["bac"].get("findings", []))

            # 4️⃣ Generic vulnerabilities
            if "vulnerabilities" in intel:
                total_vulns += len(intel.get("vulnerabilities", []))

            breakdown[mod] = module_risk
            total_risk += module_risk

        return total_risk, total_vulns, breakdown

    def do_loot(self, arg):
        """loot [--json | --summary | --export] → View gathered intelligence"""

        if not self.results:
            print(Fore.RED + "[!] No loot collected yet")
            return

        def strip_ansi(text):
            return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

        def _risk_color(level):
            return {
                "LOW":      Fore.WHITE,
                "MEDIUM":   Fore.YELLOW,
                "HIGH":     Fore.RED,
                "CRITICAL": Fore.MAGENTA,
            }.get(level, Fore.WHITE)

        def _risk_level(score):
            if score < 50:   return "LOW"
            if score < 150:  return "MEDIUM"
            if score < 300:  return "HIGH"
            return "CRITICAL"

        parts = arg.split()

        # ──────────────────────────────────────────────────────
        # --json : raw dump
        # ──────────────────────────────────────────────────────
        if "--json" in parts:
            print(json.dumps(self.results, indent=4, default=str))
            return

        # ──────────────────────────────────────────────────────
        # --summary : one-screen executive view
        # ──────────────────────────────────────────────────────
        if "--summary" in parts:
            total_risk, total_vulns, breakdown = self._calculate_global_risk()
            level     = _risk_level(total_risk)
            lc        = _risk_color(level)
            print(Fore.RED + Style.BRIGHT + "\n╔══════════════════════════════════════╗")
            print(Fore.RED + Style.BRIGHT + "║     HELLHOUND — ASSESSMENT SUMMARY   ║")
            print(Fore.RED + Style.BRIGHT + "╚══════════════════════════════════════╝" + Style.RESET_ALL)
            print(f"  {Fore.WHITE}Target   {Style.RESET_ALL}: {Fore.WHITE}{self.target}")
            print(f"  {Fore.WHITE}Modules  {Style.RESET_ALL}: {Fore.WHITE}{len(self.results)}")
            print(f"  {Fore.WHITE}Risk     {Style.RESET_ALL}: {lc}{total_risk} — {level}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Issues   {Style.RESET_ALL}: {Fore.WHITE}{total_vulns}")
            print()
            for mod, score in breakdown.items():
                bar = "█" * min(int(score / 5), 30)
                sc  = _risk_color(_risk_level(score))
                print(f"  {Fore.CYAN}{mod.upper():<14}{Style.RESET_ALL} {sc}{bar} {score}{Style.RESET_ALL}")
            print()
            return

        # ──────────────────────────────────────────────────────
        # --export : write files
        # ──────────────────────────────────────────────────────
        if "--export" in parts:
            target_slug = re.sub(r'[^a-zA-Z0-9_\-]', '_', self.target or "unknown")
            base_path   = os.path.join("storage", "reports", target_slug)
            os.makedirs(base_path, exist_ok=True)
            ts          = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            json_path   = os.path.join(base_path, f"{ts}.json")
            summary_path= os.path.join(base_path, f"{ts}_summary.txt")
            total_risk, total_vulns, _ = self._calculate_global_risk()
            with open(json_path, "w") as f:
                json.dump(self.results, f, indent=4, default=str)
            with open(summary_path, "w") as f:
                f.write(f"Target: {self.target}\n"
                        f"Modules Run: {len(self.results)}\n"
                        f"Risk Score: {total_risk}\n"
                        f"Vulnerabilities Identified: {total_vulns}\n")
            print(Fore.CYAN + f"[✓] Report exported.")
            print(Fore.CYAN + f"    JSON    : {json_path}")
            print(Fore.CYAN + f"    Summary : {summary_path}")
            return

        # DEFAULT: detail view using the new recursive 'Hellhound Signature' UI
        if not self.results:
            print(Fore.YELLOW + "[!] No intelligence collected in this session to render.")
            return

        render_loot(self.target, self.results)

        return

    def do_howl(self, arg):
        """howl [--graph] → AI-powered attack chain correlation or attack graph generation"""
        
        self._load_sync_data()

        if not self.results:
            print(Fore.YELLOW + Style.BRIGHT + "[!] No intelligence collected yet — run Spider first." + Style.RESET_ALL)
            return

        # ── Attack Graph Generation (--graph) ────────────────
        if "--graph" in arg:
            from hellhound.core import nodes
            graph_data = nodes.build_graph(self.results)
            print(json.dumps(graph_data, indent=4))
            return

        # ── AI Enhanced Howl ──────────────────────────────────
        ai_key = self.target_context.get("ai_key")
        ai_provider = self.target_context.get("ai_provider", "gemini")
        model = self.target_context.get("ai_model", "gemini-1.5-flash")
        
        if not ai_key:
            print(Fore.YELLOW + "[!] AI Not Configured. Run 'setg ai local' or 'setg ai <api_key>' first." + Style.RESET_ALL)
            return

        # Build findings summary and perform local Reality Check (Pre-flight)
        findings_lines = []
        total_findings = 0
        for mod, output in self.results.items():
            intel = output.get("intel", {}) if isinstance(output, dict) else {}
            
            # 1. Standard
            vulns = intel.get("vulnerabilities", []) or intel.get("findings", []) or intel.get("cves", []) or intel.get("surfaces", [])
            for v in vulns:
                vtype = v.get("type", v.get("id", "unknown")) if isinstance(v, dict) else str(v)
                sev = v.get("severity", "UNKNOWN") if isinstance(v, dict) else "INFO"
                findings_lines.append(f"{sev:8}  {vtype}")
                total_findings += 1
            
            # 2. JWT (Deep)
            for j in intel.get("jwts", []):
                for v in j.get("vulnerabilities", []):
                    findings_lines.append(f"HIGH      JWT: {v[:30]}")
                    total_findings += 1
                for av in j.get("active_verifications", []):
                    if av.get("status") == "VERIFIED":
                        findings_lines.append(f"CRITICAL  JWT Exploit: {av.get('type')}")
                        total_findings += 1

            # 3. Secrets
            for s in intel.get("secrets", []):
                findings_lines.append(f"HIGH      Secret: {s.get('type')}")
                total_findings += 1
        
        # Reality Check: Hard stop if insufficient data
        if total_findings < 2:
            print(Fore.RED + Style.BRIGHT + "\n[!] INSUFFICIENT FINDINGS FOR CHAINING" + Style.RESET_ALL)
            print(f"    Findings received: {total_findings}")
            print("    Required: At least 2 findings from different modules or endpoints")
            print("    Recommendation: Run additional modules (recon + vuln scans) before chaining\n")
            return

        findings_summary = "\n".join(findings_lines[:15]) # Cap the tree root display for the UI

        prompt = f"[TRIAGE REQUEST]\nAnalyze these findings from reconnaissance for target {self.target}:\n{findings_summary}\nProvide a correlated vulnerability assessment and risk ranking."
        anim_thread, anim_stop = ai_utils.thinking_animation("CORRELATING ATTACK CHAINS")
        
        # Select persona based on provider
        persona = ai_utils.CORRELATION_PERSONA_SLM if ai_provider == "ollama" else ai_utils.CORRELATION_PERSONA
        
        ai_response = ai_utils.call_ai(prompt, ai_provider, ai_key, model=model, system_prompt=persona)
        anim_stop.set()
        anim_thread.join()
        
        if not ai_response or str(ai_response).startswith("Error"):
            print(Fore.RED + f"  [x] AI analysis failed: {ai_response}")
        else:
            ai_utils.render_ai_box(ai_response)

    # ============================
    # ASK — Interactive AI Q&A
    # ============================

    def do_ask(self, arg):
        """ask [question] → Interactive AI chat for bug bounty questions"""
        
        self._load_sync_data()
        
        ai_key = self.target_context.get("ai_key")
        ai_provider = self.target_context.get("ai_provider", "gemini")
        model = self.target_context.get("ai_model", "gemini-1.5-flash")

        if not ai_key:
            print(Fore.YELLOW + "[!] AI not configured. Run 'setg ai local' or 'setg ai <api_key>' first." + Style.RESET_ALL)
            return

        # Initialize history once per session if not already present
        if not hasattr(self, '_ask_history'):
            self._ask_history = []

        # One-shot mode: ask <question>
        if arg.strip():
            ai_utils.render_session_header()
            self._ask_ai(arg.strip(), ai_provider, ai_key, model)
            ai_utils.render_session_footer()
            return

        # Interactive session — everything inside one frame
        ai_utils.render_session_header()

        while True:
            try:
                question = input(f"\033[38;5;46m$\033[0m \033[97;1m")
                print("\033[0m", end="")  # reset after bold input
            except (EOFError, KeyboardInterrupt):
                print("\033[0m")
                break
            
            if not question.strip():
                continue
            if question.strip().lower() in ("exit", "quit", "q", "back"):
                break

            self._ask_ai(question.strip(), ai_provider, ai_key, model)
            ai_utils.render_session_divider()

        ai_utils.render_session_footer()

    def _ask_ai(self, question, provider, key, model):
        """Send a question to AI and render the response inside the session frame."""
        # Pick SLM-optimized persona if on ollama
        persona = ai_utils.ASK_PERSONA_SLM if provider == "ollama" else ai_utils.ASK_PERSONA
        
        # Build context from existing scan results if available
        context = ""
        if self.target:
            context += f"\n\n[SYSTEM CONTEXT: Active Target = {self.target}]\n"
            
        if not self._ask_history and self.results:
            context += "Recent Scan Findings:\n"
            found_any = False
            for mod, output in self.results.items():
                intel = output.get("intel", {}) if isinstance(output, dict) else {}
                vulns = intel.get("vulnerabilities", []) or intel.get("findings", []) or intel.get("cves", [])
                if vulns:
                    found_any = True
                    context += f"  {mod}: {len(vulns)} finding(s)\n"
                    for v in vulns[:3]:
                        vtype = v.get("type", v.get("id", "unknown"))
                        sev = v.get("severity", "")
                        context += f"    - {vtype} {sev}\n"
            if not found_any:
                context += "  No findings discovered yet.\n"
        
        prompt = f"{question}{context}"
        
        # Fast health check for Ollama
        if provider == "ollama":
            if not ai_utils.ping_ollama(model):
                print(f"  \033[91m[!] Ollama not running or model '{model}' not pulled.\033[0m")
                print(f"      \033[90mRun: ollama pull {model}\033[0m")
                return

        print()
        # Cinematic thinking animation
        anim_thread, anim_stop = ai_utils.thinking_animation("HELLHOUND IS THINKING")
        response = ai_utils.call_ai(prompt, provider, key, model=model, system_prompt=persona, history=self._ask_history)
        anim_stop.set()
        anim_thread.join()
        
        if response:
            # Append this turn to history
            self._ask_history.append({"role": "user", "content": question})
            self._ask_history.append({"role": "assistant", "content": response})
            
            # Cap history to last 10 turns (20 messages) to avoid blowing context window
            if len(self._ask_history) > 20:
                self._ask_history = self._ask_history[-20:]
                
            ai_utils.render_ai_box(response)
        else:
            print(Fore.RED + "  [x] AI returned no response. Check connectivity." + Style.RESET_ALL)

    # ============================
    # ANALYZE — On-Demand AI Analysis
    # ============================

    def do_analyze(self, arg):
        """analyze → AI-powered analysis of scan findings (on-demand, no auto-trigger)"""
        
        self._load_sync_data()
        
        ai_key = self.target_context.get("ai_key")
        ai_provider = self.target_context.get("ai_provider", "gemini")
        model = self.target_context.get("ai_model", "gemini-1.5-flash")

        if not ai_key:
            print(Fore.YELLOW + "[!] AI not configured. Run 'setg ai local' or 'setg ai <api_key>' first." + Style.RESET_ALL)
            return

        if not self.results:
            print(Fore.YELLOW + "[!] No scan results to analyze. Run some modules first." + Style.RESET_ALL)
            return

        # Collect all findings across modules with deduplication
        all_findings = []
        seen_keys = set()
        
        for mod, output in self.results.items():
            if not isinstance(output, dict):
                continue
            intel = output.get("intel", {})
            
            # 1. Standard vulnerabilities (top-level)
            raw_v = intel.get("vulnerabilities", []) or intel.get("findings", []) or intel.get("cves", []) or []
            cors = intel.get("cors_vulnerabilities", [])
            
            # 2. JWT Deep-Scan (Nested findings)
            jwt_v = []
            for j in intel.get("jwts", []):
                for v in j.get("vulnerabilities", []):
                    jwt_v.append({
                        "type": f"JWT: {v.split(':')[0] if ':' in v else 'Vuln'}",
                        "severity": "HIGH" if "HIGH" in v else "CRITICAL" if "CRITICAL" in v else "MEDIUM",
                        "url": j.get("url", j.get("source", "")),
                        "evidence": v
                    })
                for av in j.get("active_verifications", []):
                    if av.get("status") == "VERIFIED":
                        jwt_v.append({
                            "type": f"JWT Exploit: {av.get('type')}",
                            "severity": "CRITICAL",
                            "url": av.get("verified_urls", [""])[0] if av.get("verified_urls") else j.get("url", ""),
                            "payload": av.get("forged_token", ""),
                            "evidence": f"Escalated Claims: {json.dumps(av.get('forged_payload'))}"
                        })

            # 3. Secrets (Leaked addresses/keys)
            secrets_v = []
            for s in intel.get("secrets", []):
                secrets_v.append({
                    "type": f"Secret: {s.get('type', 'Leaked Data')}",
                    "severity": "HIGH",
                    "url": s.get("context", s.get("source", "")),
                    "evidence": s.get("value", "")
                })

            # Merge and deduplicate
            for v in raw_v + cors + jwt_v + secrets_v:
                ftype = v.get("type", v.get("id", "Unknown"))
                url = v.get("url", "")
                method = v.get("method", "GET")
                key = (ftype, url, method, mod)
                
                if key not in seen_keys:
                    v["_source_module"] = mod
                    all_findings.append(v)
                    seen_keys.add(key)

        if not all_findings:
            print(Fore.YELLOW + "[!] No specific findings to analyze." + Style.RESET_ALL)
            return

        # ── Handle choice as argument (For GUI/Non-Interactive) ────
        if arg and arg.strip():
            choices = [c.strip() for c in arg.split(",")]
            selected = []
            if "a" in choices:
                selected = all_findings
            else:
                for c in choices:
                    try:
                        idx = int(c) - 1
                        if 0 <= idx < len(all_findings):
                            selected.append(all_findings[idx])
                    except: continue
            
            if selected:
                self._run_surgical_analysis(selected, ai_key, ai_provider, model)
                return

        # ── Interactive Selection (For Console) ─────────────────────
        print(Fore.CYAN + "\n[ INTEL SELECTION CENTER ]" + Style.RESET_ALL)
        for i, v in enumerate(all_findings, 1):
            sev = v.get("severity", "INFO")
            ftype = v.get("type", "Finding")
            url = v.get("url", "")
            print(f"[{i}] {Fore.RED if 'HIGH' in sev or 'CRITICAL' in sev else Fore.YELLOW}{ftype}{Style.RESET_ALL} -> {url[:70]}")
        
        print(f"\n[A] Analyze All | [Q] Abort")
        choice = input(Fore.YELLOW + "\nhellhound [intel] > " + Style.RESET_ALL).strip().lower()

        if choice == 'q': return
        
        selected = []
        if choice == 'a':
            selected = all_findings
        else:
            try:
                indices = [int(i.strip()) - 1 for i in choice.split(",")]
                selected = [all_findings[idx] for idx in indices if 0 <= idx < len(all_findings)]
            except:
                print(Fore.RED + "[!] Invalid selection." + Style.RESET_ALL)
                return

        if selected:
            self._run_surgical_analysis(selected, ai_key, ai_provider, model)

    def _run_surgical_analysis(self, selected, key, provider, model):
        """Internal helper for AI surgical reasoning."""
        print(Fore.MAGENTA + f"\n[*] Performing deep intelligence analysis on {len(selected)} target(s)..." + Style.RESET_ALL)
        from hellhound.core import ai_utils
        
        for f in selected:
            ftype = f.get("type", f.get("id", "Unknown"))
            sev = f.get("severity", "")
            url = f.get("url", "")
            param = f.get("parameter", "")
            evidence = f.get("evidence", f.get("payload", ""))
            
            prompt = (
                f"Vulnerability: {ftype}\n"
                f"Severity: {sev}\n"
                f"URL: {url}\n"
                f"Parameter: {param}\n"
                f"Evidence: {str(evidence)[:800]}\n"
                f"Target: {self.target}\n\n"
                f"Analyze this finding for bug bounty impact and escalation potential. "
                f"Provide a concise, high-fidelity report with reproduction steps."
            )
            
            anim_thread, anim_stop = ai_utils.thinking_animation(f"ANALYZING {ftype.upper()[:20]}")
            response = ai_utils.call_ai(prompt, provider, key, model=model, system_prompt=ai_utils.IMPACT_ADVISOR_PERSONA)
            anim_stop.set()
            anim_thread.join()
            
            if response:
                ai_utils.render_ai_box(response)
            else:
                print(Fore.RED + f"  [x] AI analysis failed for {ftype}." + Style.RESET_ALL)


    def do_repro(self, arg):
        """repro → Alias for reproduce"""
        self.do_reproduce(arg)

    def do_reproduce(self, arg):
        """reproduce → Instantly replay and verify all findings through the global proxy"""
        if not self.results:
            print(Fore.YELLOW + Style.BRIGHT + "[!] No intelligence collected in this session to reproduce." + Style.RESET_ALL)
            return

        proxy = self.target_context.get("proxy") if (self.target_context.get("proxy_enabled", True)) else None
        
        # Repro Engine Options
        options = {
            "timeout": 10,
            "delay": 0.5
        }
        
        # Parse potential arg overrides (e.g. reproduce timeout=20)
        if arg:
            parts = arg.split()
            for p in parts:
                if "=" in p:
                    try:
                        k, v = p.split("=", 1)
                        options[k] = float(v) if "." in v else int(v)
                    except: pass

        engine = ReproEngine(self)
        engine.run(
            target=self.target,
            all_results=self.results,
            proxy=proxy,
            options=options
        )
        print()


    # ============================
    # SYSTEM
    # ============================

    def do_clear(self, arg):
        """clear → Clear the screen"""
        os.system("clear" if os.name == "posix" else "cls")

    # ============================
    # EMIT METHODS (FOR MODULES)
    # ============================

    def info(self, msg):
        # Use subtle HUD Cyan for the marker, keep the message as-is (respecting internal colors)
        print(f" {C_HUD_CYAN}[*]{R} {msg}")

    def success(self, msg):
        print(f" {Fore.GREEN}[+]{R} {msg}")

    def warn(self, msg):
        print(f" {Fore.YELLOW}[*]{R} {msg}")

    def always_info(self, msg):
        print(f" {C_HUD_CYAN}[*]{R} {msg}")

    def always_success(self, msg):
        if "Target:" in msg:
            msg = msg.replace("High:", Fore.RED + Style.BRIGHT + "High:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            msg = msg.replace("Secrets:", Fore.MAGENTA + Style.BRIGHT + "Secrets:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            msg = msg.replace("Param-Sensitive:", Fore.YELLOW + Style.BRIGHT + "Param-Sensitive:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
        print(Style.BRIGHT + Fore.GREEN + f"[+] {msg}" + Style.RESET_ALL)

    def error(self, msg):
        print(Style.BRIGHT + Fore.RED + f"[x] {msg}" + Style.RESET_ALL)

    def section(self, title):
        print(Style.BRIGHT + Fore.MAGENTA + f"\n  ── {title} ──" + Style.RESET_ALL)

    def row(self, key, value, **kwargs):
        print(f"{key}: {value}")

    def finding(self, *args):
        print(f"[!] {' '.join(map(str, args))}")

    def endpoint_row(self, ep):
        print(ep.get("url", ""))

    def print_always(self, msg):
        print(msg)

    def do_status(self, arg):
        """status → Show framework status"""

        print("\n[ Hellhound Status ]")
        print(f"Target     : {self.target or 'not set'}")
        print(f"Type       : {self.target_type or 'unknown'}")
        print(f"Equipped   : {self.active_module or 'none'}")
        print(f"Modules    : {len(self.modules)}")
        print(f"Results    : {len(self.results)}")
        print()

    def do_sessions(self, arg):
        """sessions → List previous hunts"""

        base = os.path.join(os.path.dirname(__file__), "storage")
        if not os.path.exists(base):
            print("[!] No sessions directory")
            return

        print("\n[ Sessions ]")
        for s in sorted(os.listdir(base)):
            print(f"  - {s}")
        print()

    # ============================
    # CUSTOM HELP
    # ============================

    def do_help(self, arg):
        """help [command] → Show command reference or detailed help for a command"""

        detailed = {
            "prey":     "prey <url> [--cookie \"k=v\"] [--header \"Key: Value\"]\n"
                        "    Lock onto a web target. Supports session cookies and custom headers.\n"
                        "    Example: prey https://example.com --cookie \"session=abc123\"",
            "equip":    "equip <module>\n"
                        "    Load a module and prepare it for execution. Loads default options.\n"
                        "    Example: equip Spider",
            "options":  "options\n"
                        "    Show all configurable options for the equipped module.\n"
                        "    Displays name, type, current value, and description.",
            "set":      "set <option> <value>\n"
                        "    Set an option for the equipped module. Type is enforced.\n"
                        "    Example: set timeout 20\n"
                        "    Example: set cookie session=abc123",
            "strike":   "strike\n"
                        "    Execute the equipped module against the current target.\n"
                        "    Validates required options before running.",
            "loot":     "loot [--json | --summary | --export]\n"
                        "    View gathered intelligence.\n"
                        "    --json    : Raw JSON dump of all results\n"
                        "    --summary : Executive risk overview\n"
                        "    --export  : Save report to storage/",
            "howl":     "howl\n"
                        "    Correlated attack suggestions based on collected intel.",
            "arsenal":  "arsenal [category]\n"
                        "    List available modules grouped by category.\n"
                        "    Filter: arsenal recon | arsenal vuln | arsenal exploit",
            "release":  "release\n"
                        "    Unload the current module and reset options.",
            "status":   "status\n"
                        "    Show current framework state: target, module, results count.",
            "clear":    "clear\n"
                        "    Clear the terminal screen.",
            "sessions": "sessions\n"
                        "    List previously saved session directories.",
            "upgrade":  "upgrade\n"
                        "    Pull latest updates and sync dependencies from within console.\n"
                        "    Executes the framework's internal update logic.",
            "exit":     "exit\n"
                        "    Exit the Hellhound console.",
        }

        if arg.strip() and arg.strip() in detailed:
            print(Fore.CYAN + f"\n  {arg.strip()}" + Style.RESET_ALL)
            print(Fore.WHITE + f"  {detailed[arg.strip()]}" + Style.RESET_ALL)
            print()
            return

        print(Fore.RED + Style.BRIGHT + "\n╔══════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + "║        HELLHOUND — COMMAND MANUAL    ║")
        print(Fore.RED + Style.BRIGHT + "╚══════════════════════════════════════╝" + Style.RESET_ALL)

        sections = [
            ("TARGET", [
                ("prey <url>",           "Set web target (supports --cookie, --header)"),
            ]),
            ("MODULE", [
                ("arsenal [category]",   "List all modules, optionally filter by category"),
                ("equip <module>",       "Load a module"),
                ("options",              "Show module options"),
                ("set <option> <value>", "Configure a module option"),
                ("strike",               "Execute the equipped module"),
                ("release",              "Unload the current module"),
            ]),
            ("INTELLIGENCE", [
                ("loot",                 "View gathered results (--json / --summary / --export)"),
                ("howl",                 "Get correlated attack suggestions"),
            ]),
            ("SYSTEM", [
                ("status",               "Show framework state"),
                ("sessions",             "List saved sessions"),
                ("upgrade",              "Pull latest framework updates"),
                ("clear",                "Clear the screen"),
                ("exit",                 "Exit console"),
            ]),
            ("AI CORE", [
                ("activate hellhound",   "Quick-launch local intelligence engine (Ollama)"),
                ("ask <question>",       "Interactive Q&A with Hellhound AI"),
                ("analyze",              "Analyze current findings for deep impact"),
            ]),
            ("ALIASES", [
                ("hunt → prey",          ""),
                ("use  → equip",         ""),
                ("run  → strike",        ""),
                ("back → release",       ""),
                ("ls   → arsenal",       ""),
                ("results → loot",       ""),
                ("q / quit → exit",      ""),
            ]),
        ]

        for section_name, commands in sections:
            print(f"\n  {Fore.RED}{Style.BRIGHT}{section_name}{Style.RESET_ALL}")
            for cmd_name, desc in commands:
                if desc:
                    print(f"    {Fore.CYAN + Style.BRIGHT}{cmd_name:<26}{Style.RESET_ALL}{Fore.WHITE}{desc}{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.WHITE}{cmd_name}{Style.RESET_ALL}")

        print(Fore.YELLOW + Style.BRIGHT + "\n  Tip: 'help <command>' for detailed usage.\n" + Style.RESET_ALL)



    def default(self, line):
        """
        Handle slash commands, aliases, and unknown commands via the unified dispatcher.
        """
        clean = line.strip()
        if not clean:
            return

        # 1. Direct Slash Command Routing
        if clean.startswith("/"):
            from hellhound.core.commands import dispatch
            from hellhound.core.scope import ScopeRules
            from hellhound.core.ai_utils import load_config

            cfg = load_config()
            session_ctx = {
                "options": self.options,
                "scope_rules": getattr(self, "scope_rules", ScopeRules.from_dict(cfg.get("scope", {}))),
                "results": getattr(self, "results", {}),
                "target": getattr(self, "target", "")
            }
            dispatch(clean, session_ctx, emit=self.emit)
            # Sync back state
            self.target = session_ctx.get("target", self.target)
            self.scope_rules = session_ctx.get("scope_rules", getattr(self, "scope_rules", None))
            return

        parts = clean.split()
        cmd = parts[0]
        args = " ".join(parts[1:])

        # Allow real legacy commands always
        if hasattr(self, f"do_{cmd}"):
            return self.onecmd(clean)

        if cmd in self.aliases:
            real_cmd = self.aliases[cmd]
            rewritten = f"{real_cmd} {args}".strip()
            return self.onecmd(rewritten)

        # Fallback to dispatcher for slash commands, bare commands, or plain conversational natural language
        from hellhound.core.commands import dispatch
        from hellhound.core.scope import ScopeRules
        from hellhound.core.ai_utils import load_config

        cfg = load_config()
        session_ctx = {
            "options": self.options,
            "scope_rules": getattr(self, "scope_rules", ScopeRules.from_dict(cfg.get("scope", {}))),
            "results": getattr(self, "results", {}),
            "target": getattr(self, "target", "")
        }
        dispatch(clean, session_ctx, emit=self.emit)
        self.target = session_ctx.get("target", self.target)
        self.scope_rules = session_ctx.get("scope_rules", getattr(self, "scope_rules", None))