import cmd
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

from colorama import Fore, Back, Style, init
init(autoreset=True)

from hellhound.core import oob_utils
from hellhound.core.engine import HellhoundEngine
from hellhound.core.suggest import suggest_actions, suggest_report
from hellhound.core import ai_utils
from hellhound.core.repro_engine import ReproEngine

# ----------------------------
# UI / COLOR CONSTANTS
# ----------------------------

W          = 70           # Global Banner Width
R          = Style.RESET_ALL
C_BORDER   = Fore.RED     + Style.BRIGHT
C_HEAD     = Fore.RED     + Style.BRIGHT
C_CRITICAL = Fore.RED     + Style.BRIGHT
C_HIGH     = Fore.YELLOW  + Style.BRIGHT
C_MEDIUM   = Fore.CYAN    + Style.BRIGHT
C_LOW      = Fore.WHITE
C_CHAIN    = Fore.MAGENTA + Style.BRIGHT
C_SKIP     = Fore.LIGHTBLACK_EX
C_LABEL    = Fore.WHITE   + Style.BRIGHT
C_DIM      = Fore.WHITE
C_EVIDENCE = Fore.CYAN
C_STEP     = Fore.RED     + Style.BRIGHT
C_URL      = Fore.YELLOW
C_OK       = Fore.GREEN   + Style.BRIGHT

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
    HELLHOUND v12.5 Apex-King Boot Sequence.
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
    # 1. Clear & Initialise Animation
    os.system('clear' if os.name == 'posix' else 'clear')
    
    text = "STARTING HELLHOUND FRAMEWORK CONSOLE"
    duration = 4.2
    WHITE = Fore.WHITE + Style.BRIGHT
    RED = Fore.RED + Style.BRIGHT
    RESET = Style.RESET_ALL
    
    braille_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    pipe_frames = ['|', '/', '-', '\\']
    
    end_time = time.time() + duration
    frame = 0
    while time.time() < end_time:
        prefix = f"{RED}{braille_frames[frame % 10]}{RESET}"
        
        # Wave Text
        res = list(text.upper())
        idx = frame % len(text)
        line = ""
        for i, char in enumerate(res):
            if i == idx:
                line += f"{RED}{char.lower()}{WHITE}"
            elif i == (idx - 1) % len(text) or i == (idx + 1) % len(text):
                line += f"{RED}{char}{WHITE}"
            else:
                line += char
        
        pipe = f"{RED}{pipe_frames[frame % 4]}{RESET}"
        sys.stdout.write(f"\r {prefix}  {WHITE}{line}  {pipe}")
        sys.stdout.flush()
        time.sleep(0.06)
        frame += 1

    print("\n")
    
    # 2. Smooth Reveal (Banner)
    for line in BANNER.split('\n'):
        if line.strip():
            sys.stdout.write(Fore.RED + line + Style.RESET_ALL + "\n")
            sys.stdout.flush()
            time.sleep(0.012)
    
    time.sleep(0.3)
    # The Prompt
    print(f"\n" + Fore.LIGHTRED_EX + "hellhound" + Fore.WHITE + " > " + Style.RESET_ALL, end="", flush=True)
    time.sleep(0.5)


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
    # Hackeristic Boot Sequence (UPGRADED)
    # ----------------------------
    def preloop(self):
        os.system('cls' if os.name == 'nt' else 'clear')

        # ── 1. Start background update check ──────────────────
        # Runs during the boot animation to save time.
        check_thread = threading.Thread(target=self._check_for_updates, daemon=True)
        check_thread.start()

        # ── 2. Run Boot Animation ─────────────────────────────
        _boot_sequence()

        # ── 3. Post-Animation Logic ───────────────────────────
        print(f"\n{Fore.WHITE}Type '{Fore.YELLOW}help{Fore.WHITE}' to view available commands.\n")
        
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

        print(Fore.GREEN + f"[+] Web target acquired: {domain}")

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
        options_def = getattr(mod_obj, "OPTIONS", [])
        self.module_options = {opt["name"]: opt["default"] for opt in options_def}

        category = self.modules[match].get("category", "unknown")
        description = self.modules[match].get("description", "")

        print(Style.BRIGHT + Fore.GREEN + f"\n[+] Module equipped: {match}" + Style.RESET_ALL)
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
            options_def = getattr(mod_obj, "OPTIONS", []) if mod_obj else []
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
        print()

        # ── 3. AI Intelligence (Professional Block) ────────────────
        print(f"  {Fore.MAGENTA + Style.BRIGHT}╔══════════════════════════════════════╗")
        print(f"  ║         {Fore.WHITE}HELLHOUND — INTELLIGENCE     {Fore.MAGENTA}║")
        print(f"  ╚══════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        ai_label = self.target_context.get("ai_status_label", "NOT CONNECTED")
        st_color = Fore.GREEN if "CONNECTED" in ai_label else Fore.RED
        
        print(f"   Status     : {st_color}{ai_label}{Style.RESET_ALL}")
        
        ai_k = self.target_context.get("ai_key", "")
        if ai_k:
            masked = f"{ai_k[:4]}...{ai_k[-4:] if len(ai_k)>8 else ''}"
            print(f"   Key        : {Fore.WHITE}{masked}{Style.RESET_ALL}")
        else:
            print(f"   Key        : {Fore.RED}NOT SET{Style.RESET_ALL}")
        
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
        if key in ("ai_key", "aikey"):
            return self.do_setg(f"ai_key {raw_value}")

        mod_obj = self._load_module(self.active_module)
        options_def = getattr(mod_obj, "OPTIONS", []) if mod_obj else []

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
        elif key in ("ai_key", "key"):
            self.target_context["ai_key"] = raw_value
            print(Fore.GREEN + f"[✓] Global AI Key => {raw_value[:4]}...{raw_value[-4:] if len(raw_value)>8 else ''}")
            
            # Universal Handshake (Professional Discovery)
            print(f"[*] Starting Intelligence discovery handshake...")
            result = ai_utils.universal_handshake(raw_value)
            
            if result["success"]:
                self.target_context["ai_provider"] = result["provider"]
                self.target_context["ai_model"] = result["model"]
                self.target_context["ai_status_label"] = f"CONNECTED: {result['label']}"
                print(Fore.GREEN + f"[✓] Intelligence Connected: {Style.BRIGHT}{result['label']}")
            else:
                self.target_context["ai_status_label"] = "FAILED (Key Rejected)"
                print(Fore.RED + f"[x] Intelligence Discovery Failed: {result['message']}")

        elif key in ("ai_provider", "aiprovider"):
            # Still allow manual override if needed, but mark as manual
            prov = raw_value.lower().strip()
            if prov in ("gemini", "openai", "anthropic"):
                self.target_context["ai_provider"] = prov
                self.target_context["ai_status_label"] = f"MANUAL: {prov.upper()}"
                print(Fore.GREEN + f"[✓] Global AI Provider => {prov} (Manual Override)")
            else:
                print(Fore.RED + f"[x] Unsupported AI provider: {prov}. Use gemini | openai | anthropic")
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
        options_def = getattr(mod_obj, "OPTIONS", [])
        names = [o["name"] for o in options_def]
        return [n for n in names if n.lower().startswith(text.lower())]

    # ============================
    # EXECUTION
    # ============================

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

        options_def = getattr(mod_obj, "OPTIONS", [])
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
            for mod_name in ["spider", "idordetector", "bacdetector"]: # Best sources first
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
                "LOW":      Fore.GREEN,
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
            print(Fore.GREEN + f"[✓] Report exported.")
            print(Fore.GREEN + f"    JSON    : {json_path}")
            print(Fore.GREEN + f"    Summary : {summary_path}")
            return

        # ──────────────────────────────────────────────────────
        # DEFAULT: full detail view
        # Each module is rendered via:
        #   1. Its own LOOT_SECTIONS if defined (module-declared renderer)
        #   2. Generic fallback for any intel shape (no console changes needed)
        # ──────────────────────────────────────────────────────
        total_risk, total_vulns, breakdown = self._calculate_global_risk()
        level = _risk_level(total_risk)
        lc    = _risk_color(level)

        print(Fore.RED + Style.BRIGHT + "\n╔══════════════════════════════════════╗")
        print(Fore.RED + Style.BRIGHT + "║         HELLHOUND — LOOT             ║")
        print(Fore.RED + Style.BRIGHT + "╚══════════════════════════════════════╝" + Style.RESET_ALL)
        print(f"  Target : {Fore.WHITE}{self.target}{Style.RESET_ALL}   "
              f"Risk : {lc}{total_risk} ({level}){Style.RESET_ALL}   "
              f"Issues : {Fore.WHITE}{total_vulns}{Style.RESET_ALL}\n")

        printed_keys = set()

        for mod, output in self.results.items():
            mod_clean = mod.lower()
            if mod_clean in printed_keys:
                continue
            printed_keys.add(mod_clean)

            if not isinstance(output, dict):
                continue

            intel      = output.get("intel", {})
            file_reads = intel.get("file_reads", [])
            raw_stats  = output.get("raw", "")
            mod_score = breakdown.get(mod_clean, 0)
            sc        = _risk_color(_risk_level(mod_score))

            # Module header
            print(Fore.RED + "  ┌─────────────────────────────────────")
            print(Fore.RED + f"  │ " + Fore.WHITE + Style.BRIGHT + f"{mod_clean.upper()}" +
                  Style.RESET_ALL + Fore.WHITE + f"  risk={sc}{mod_score}{Style.RESET_ALL}")
            print(Fore.RED + "  └─────────────────────────────────────" + Style.RESET_ALL)

            if raw_stats:
                print(Fore.WHITE + f"  {raw_stats}" + Style.RESET_ALL)
            print()

            # ── Shared helpers ────────────────────────────────────
            def _sev_color(sev):
                s = str(sev).upper()
                if s == "CRITICAL": return Fore.MAGENTA + Style.BRIGHT
                if s == "HIGH":     return Fore.RED     + Style.BRIGHT
                if s == "MEDIUM":   return Fore.YELLOW  + Style.BRIGHT
                return Fore.WHITE

            def _render_findings(findings, label="Vulnerabilities"):
                if not findings:
                    return
                sev_w = {"critical":0,"high":1,"medium":2,"low":3,"info":4,"confirmed":1}
                sf = sorted([f for f in findings if isinstance(f, dict)],
                            key=lambda x: sev_w.get(str(x.get("severity", x.get("confidence", "info"))).lower(), 99))
                if not sf:
                    return
                print(Fore.MAGENTA + Style.BRIGHT + f"  [ {label} — {len(sf)} ]" + Style.RESET_ALL)
                for f in sf:
                    sev   = str(f.get("severity", f.get("confidence", "info"))).upper()
                    name  = str(f.get("type", f.get("vulnerability", f.get("finding_type", f.get("name","Finding")))))
                    url   = f.get("url",  f.get("endpoint",""))
                    proof = f.get("proof",f.get("evidence",""))
                    sc2   = _sev_color(sev)
                    
                    # Format title nicely
                    name = name.replace("_", " ").title()
                    print(f"    {Style.BRIGHT}[{sc2}{sev}{Style.RESET_ALL}] {Fore.WHITE}{name}")
                    if url:
                        print(f"       {Fore.WHITE}url   : {Fore.CYAN}{url}{Style.RESET_ALL}")
                    if proof:
                        ps = str(proof)
                        print(f"       {Fore.WHITE}proof : {Fore.WHITE}{ps[:120]}{'...' if len(ps)>120 else ''}{Style.RESET_ALL}")
                    if f.get("poc_curl"):
                        print(f"       {Fore.WHITE}curl  : {Fore.YELLOW}{f['poc_curl']}{Style.RESET_ALL}")
                    if f.get("poc_browser"):
                        print(f"       {Fore.WHITE}open  : {Fore.CYAN}{f['poc_browser']}{Style.RESET_ALL}")
                        
                    # Universal dynamic extraction of leftover metadata keys for cleaner structure
                    handled_keys = {"severity", "confidence", "type", "vulnerability", "finding_type", 
                                    "name", "url", "endpoint", "proof", "evidence", "poc_curl", "poc_browser", "poc_html"}
                    
                    for k, v in f.items():
                        if k in handled_keys or not v:
                            continue
                        # format key beautifully
                        k_nice = k.replace("_", " ")
                        if isinstance(v, dict):
                            # Stringify dict values cleanly instead of raw JSON
                            v_clean = " ".join([f"{dk}={dv}" for dk, dv in v.items() if dv])
                            if not v_clean: v_clean = str(v)
                        elif isinstance(v, list):
                            v_clean = ", ".join(str(i) for i in v)
                        else:
                            v_clean = str(v)
                            
                        # Wrap long values
                        if len(v_clean) > 130:
                            v_clean = v_clean[:127] + "..."
                        print(f"       {Fore.LIGHTBLACK_EX}{k_nice:<5} : {Fore.WHITE}{v_clean}{Style.RESET_ALL}")
                    print()

            # ── Module-specific renderers ─────────────────────────
            # Only load the module for THIS key — never fall back to
            # self.active_module which contaminates other modules' output.
            mod_obj       = self._load_module(mod_clean)
            loot_sections = getattr(mod_obj, "LOOT_SECTIONS", None) if mod_obj else None

            # ── Dynamic Module UI Hook ──────────────────────────────
            if hasattr(mod_obj, "render_header") and callable(mod_obj.render_header):
                try:
                    mod_obj.render_header(intel)
                except Exception as e:
                    print(Fore.RED + f"  [!] Custom renderer failed: {e}" + Style.RESET_ALL)
            
            rendered_anything = False

            # 1. Attempt to extract findings from standard top-level 'results'
            top_findings = output.get("results", [])
            if isinstance(top_findings, list) and top_findings:
                if not rendered_anything:
                    print()
                    rendered_anything = True
                _render_findings(top_findings, "Identified Findings")

            # 2. Iteratively process intelligence keys for maximum module support
            if isinstance(intel, dict):
                # Sort keys to ensure 'vulnerabilities' or main findings appear first if present
                priority_keys = ["vulnerabilities", "cors_vulnerabilities", "sqli_vulnerabilities"]
                sorted_keys = sorted(intel.keys(), key=lambda k: (0 if k in priority_keys else 1, k))

                for key in sorted_keys:
                    val = intel[key]
                    
                    # Handle duplicates: skip Spider's 'cors_issues' if CORSbuster is operating in the framework
                    if key == "cors_issues" and any(k.lower() == "corsbuster" for k in self.results.keys()):
                        continue
                        
                    # Skip empty elements or raw stats, as well as redundant internal metadata
                    if not val or key in ("status", "raw", "summary_stats", "file_reads", "meta", "summary", "risk_score", "tech_stack", "comments"):
                        continue

                    # Format title (e.g. "cors_vulnerabilities" -> "Cors Vulnerabilities")
                    title = str(key).replace("_", " ").title()

                    if isinstance(val, list):
                        if not rendered_anything:
                            print(); rendered_anything = True
                        
                        if val and isinstance(val[0], dict):
                            # Treat lists as findings if they contain core definitive structural vulnerability keys
                            is_security_item = any(k in item for item in val[:5] for k in ["severity", "vulnerability", "finding_type"])
                            is_security_title = title.lower() in ("vulnerabilities", "cors vulnerabilities", "sqli vulnerabilities", "findings")
                            
                            if is_security_item or is_security_title:
                                _render_findings(val, title)
                            else:
                                # Fallback list-of-dicts dynamic renderer
                                print(Fore.MAGENTA + Style.BRIGHT + f"  [ {title} — {len(val)} ]" + Style.RESET_ALL)
                                for item in val:
                                    # Primary anchor key deduction
                                    p_keys = ("url", "origin", "file", "endpoint", "path", "name", "type", "asset")
                                    primary_val = None
                                    primary_k = None
                                    
                                    for pk in p_keys:
                                        if pk in item and item[pk]:
                                            primary_val = item[pk]
                                            primary_k = pk
                                            break
                                            
                                    print(f"    {Style.BRIGHT}{Fore.WHITE}•{Style.RESET_ALL}", end="")
                                    if primary_val:
                                        print(f" {Fore.CYAN + Style.BRIGHT}{primary_val}{Style.RESET_ALL}")
                                    else:
                                        print()
                                        
                                    clean_extras = []
                                    long_content = None
                                    for k, v in item.items():
                                        # Silence universally noisy keys from bullet metadata
                                        if k in (primary_k, "poc_html", "cluster", "baseline", "confidence", "hash", "source") or not v: 
                                            continue
                                            
                                        if k == "content":
                                            long_content = str(v)
                                            continue
                                        if isinstance(v, dict):
                                            subitems = [f"{dk}: {dv}" for dk, dv in v.items() if dv]
                                            if subitems: clean_extras.append(f"{k}: [{' | '.join(subitems)}]")
                                        elif isinstance(v, list) and not v:
                                            continue
                                        else:
                                            clean_extras.append(f"{k}: {v}")
                                            
                                    if clean_extras:
                                        extra_str = " | ".join(clean_extras)
                                        # Use standard visible WHITE instead of blue/gray to distinct layout from URL
                                        print(f"       {Fore.WHITE}↳ {extra_str}{Style.RESET_ALL}")
                                        
                                    # Print multiline raw content dynamically for deeper visibility (e.g., well_known files)
                                    if long_content:
                                        lines = long_content.strip().splitlines()
                                        for line in lines[:8]:
                                            print(f"         {Fore.LIGHTGREEN_EX}{line.strip()[:140]}{Style.RESET_ALL}")
                                        if len(lines) > 8:
                                            print(f"         {Fore.LIGHTGREEN_EX}... (truncated){Style.RESET_ALL}")
                                    
                                    # Visual separator between items if long content was printed
                                    if long_content:
                                        print()
                                print()
                        elif val:
                            # Render flat list
                            print(Fore.MAGENTA + Style.BRIGHT + f"  [ {title} — {len(val)} ]" + Style.RESET_ALL)
                            for item in list(val):
                                print(f"    {Fore.WHITE}• {item}{Style.RESET_ALL}")
                            print()

                    elif isinstance(val, dict):
                        if not rendered_anything:
                            print(); rendered_anything = True
                        print(Fore.MAGENTA + Style.BRIGHT + f"  [ {title} ]" + Style.RESET_ALL)
                        for sub_k, sub_v in list(val.items())[:15]:
                            print(f"    {Fore.WHITE}{str(sub_k):<20}:{Style.RESET_ALL} {Fore.CYAN}{sub_v}{Style.RESET_ALL}")
                        print()
                        
                    elif isinstance(val, (str, int, float, bool)):
                        if not rendered_anything:
                            print(); rendered_anything = True
                        print(f"  {Fore.MAGENTA + Style.BRIGHT}[ {title} ]{Style.RESET_ALL} {Fore.CYAN}{val}{Style.RESET_ALL}")

            # 3. Special case for file_reads (common across many modules, outside intel)
            if isinstance(file_reads, list) and file_reads:
                if not rendered_anything:
                    print(); rendered_anything = True
                print(Fore.MAGENTA + Style.BRIGHT + f"  [ Disclosed Files — {len(file_reads)} ]" + Style.RESET_ALL)
                for fr in file_reads:
                    fpath = fr.get("file", "unknown_file")
                    print(f"    {Fore.RED + Style.BRIGHT}✗ {fpath}{Style.RESET_ALL}")
                    if fr.get("content"):
                        content = str(fr["content"]).strip().splitlines()
                        for line in content[:5]:
                            print(f"       {Fore.GREEN}{line.strip()}{Style.RESET_ALL}")
                        if len(content) > 5:
                            print(f"       {Fore.LIGHTBLACK_EX}... (truncated){Style.RESET_ALL}")
                    print()

            # 4. Fallback: if absolutely nothing got rendered, dump the raw keys
            if not rendered_anything:
                keys = [k for k in output.keys() if k not in ("results", "intel", "raw", "status")]
                if keys:
                    print(Fore.LIGHTBLACK_EX + f"  [ Metadata: {', '.join(keys)} ]" + Style.RESET_ALL)
                    for k in keys:
                        val = str(output[k])
                        print(f"    {Fore.WHITE}{k:<12}: {val[:80]}{'...' if len(val) > 80 else ''}")
                    print()
                else:
                    print(Fore.LIGHTBLACK_EX + "  (No parsable findings identified)" + Style.RESET_ALL)
                    print()



            # ── Generic LOOT_SECTIONS path (module-defined sections) ───
            if loot_sections:
                for section in loot_sections:
                    title    = section.get("title","")
                    key      = section.get("key","")
                    renderer = section.get("type","list")
                    data     = intel.get(key)
                    if not data:
                        continue
                    print(Fore.MAGENTA + f"  [{title}]" + Style.RESET_ALL)
                    if renderer == "findings":
                        _render_findings(data if isinstance(data, list) else [], title)
                        continue
                    elif renderer == "table":
                        for row in (data if isinstance(data, list) else []):
                            if isinstance(row, dict):
                                for k, v in row.items():
                                    print(f"    {Fore.CYAN}{k:<16}{Style.RESET_ALL} {v}")
                                print()
                            else:
                                print(f"    {Fore.WHITE}{row}")
                    elif renderer == "kv":
                        if isinstance(data, dict):
                            for k, v in data.items():
                                print(f"    {Fore.CYAN}{k:<20}{Style.RESET_ALL} {v}")
                        print()
                    else:
                        for item in (data if isinstance(data, list) else [data]):
                            if isinstance(item, dict):
                                url = item.get("url", item.get("path", str(item)))
                                print(f"    {Fore.WHITE}• {url}")
                            else:
                                print(f"    {Fore.WHITE}• {item}")
                        print()


        # ── High value targets across all modules ─────────────
        high_value = []
        hvt_keywords = ["admin", "api", "login", "upload", "password", "env", "config", "token", "ftp", "secret", "auth", "graphql", "swagger", "openapi", "backup"]
        
        # Gather URLs that have active vulnerabilities to prioritize them
        vuln_urls = set()
        for mod, output in self.results.items():
            if not isinstance(output, dict): continue
            intel = output.get("intel", {})
            for key in ["vulnerabilities", "cors_vulnerabilities", "sqli_vulnerabilities"]:
                for vuln in intel.get(key, []):
                    if isinstance(vuln, dict):
                        sev = str(vuln.get("severity", vuln.get("confidence", "info"))).upper()
                        if sev in ("CRITICAL", "HIGH", "MEDIUM") and vuln.get("url"):
                            vuln_urls.add(vuln.get("url"))

        for mod, output in self.results.items():
            if not isinstance(output, dict): continue
            for ep in output.get("intel", {}).get("endpoints", []):
                url = ep.get("url", "")
                
                is_vuln = url in vuln_urls
                has_params = bool(ep.get("parameter_sensitive"))
                has_auth = bool(ep.get("auth_required"))
                is_confirmed = ep.get("confidence_label") in ("HIGH", "CONFIRMED")
                has_keyword = any(kw in url.lower() for kw in hvt_keywords)
                
                # Sophisticated True-Positive High Value Target Selection
                if is_vuln or (has_params and has_auth) or (is_confirmed and has_keyword) or (has_params and is_confirmed):
                    high_value.append(ep)

        if high_value:
            # Deduplicate by URL
            unique_hvts = {}
            for ep in high_value:
                unique_hvts[ep.get("url")] = ep
            high_value = list(unique_hvts.values())
            
            high_value = sorted(high_value,
                key=lambda e: (e.get("url") in vuln_urls,
                               bool(e.get("parameter_sensitive")),
                               bool(e.get("auth_required"))), reverse=True)
            print(Fore.RED + Style.BRIGHT + "  ── HIGH VALUE TARGETS ──" + Style.RESET_ALL)
            for ep in high_value[:15]:
                conf_color = Fore.RED if ep.get("url") in vuln_urls else Fore.YELLOW
                label = "VULNERABLE" if ep.get("url") in vuln_urls else ep.get("confidence_label", "CONFIRMED")
                print(f"  {Fore.CYAN}{ep.get('url','')} "
                      f"{conf_color}[{label}]{Style.RESET_ALL}")
            print()

        print(Fore.RED + "  " + "─" * 38 + Style.RESET_ALL + "\n")
    def do_howl(self, arg):
        """howl → Correlated intelligent attack suggestions"""

        if not self.results:
            print(Fore.YELLOW + Style.BRIGHT + "[!] No intelligence collected yet — run Spider first." + Style.RESET_ALL)
            return

        # ── AI Enhanced Howl ──────────────────────────────────
        ai_key = self.target_context.get("ai_key")
        ai_provider = self.target_context.get("ai_provider", "gemini")
        model = self.target_context.get("ai_model", "gemini-1.5-flash")
        
        if ai_key:
            print(Fore.MAGENTA + Style.BRIGHT + f"\n[ Howl — AI Correlation Engine ({ai_provider.upper()}) ]")
            print(Fore.WHITE + f"  Asking Hellhound Intelligence for attack chains ({model})...\n" + Style.RESET_ALL)
            
            prompt = ai_utils.format_howl_prompt(self.results)
            ai_response = ai_utils.call_ai(prompt, ai_provider, ai_key, model=model, system_prompt=ai_utils.CORRELATION_PERSONA)
            
            if not ai_response or ai_response.startswith("Error"):
                print(Fore.RED + f"  [x] AI analysis failed: {ai_response}")
            else:
                # Professional High-Fidelity AI Renderer
                for line in ai_response.split('\n'):
                    line = line.strip()
                    if not line: continue
                    
                    # Transform Markdown Headers into Professional Terminal Headers
                    if line.startswith("###") or line.startswith("##") or line.startswith("#"):
                        clean_header = line.lstrip("#").strip().upper()
                        print(f"\n  {Fore.MAGENTA}{Style.BRIGHT}{clean_header}{Style.RESET_ALL}")
                    # Transform Bold markers into Bright White
                    elif "**" in line:
                        parts = line.split("**")
                        # Basic bold replacement (first pair only for simplicity/fidelity)
                        if len(parts) >= 3:
                            processed = f"{parts[0]}{Style.BRIGHT}{parts[1]}{Style.NORMAL}{parts[2]}"
                            print(f"  {Fore.CYAN}{processed}{Style.RESET_ALL}")
                        else:
                            print(f"  {Fore.CYAN}{line.replace('**', '')}{Style.RESET_ALL}")
                    # Bullet points
                    elif line.startswith("*") or line.startswith("-"):
                        print(f"  {Fore.WHITE}• {Fore.CYAN}{line.lstrip('*-').strip()}{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.CYAN}{line}{Style.RESET_ALL}")
            print()
        else:
            print(Fore.YELLOW + "[!] AI Not Configured. Run 'setg ai_key <your_key>' to enable Howl attack chaining." + Style.RESET_ALL)

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
        print(Style.BRIGHT + Fore.CYAN + f"[*] {msg}" + Style.RESET_ALL)

    def success(self, msg):
        print(Style.BRIGHT + Fore.GREEN + f"[+] {msg}" + Style.RESET_ALL)

    def warn(self, msg):
        print(Style.BRIGHT + Fore.YELLOW + f"[*] {msg}" + Style.RESET_ALL)

    def always_info(self, msg):
        print(Style.BRIGHT + Fore.CYAN + f"[*] {msg}" + Style.RESET_ALL)

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
                ("clear",                "Clear the screen"),
                ("exit",                 "Exit console"),
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
        Handle command aliases and unknown commands
        """
        parts = line.split()
        if not parts:
            return

        cmd = parts[0]
        args = " ".join(parts[1:])

        # Allow real commands always
        if hasattr(self, f"do_{cmd}"):
            return self.onecmd(line)

        if cmd in self.aliases:
            real_cmd = self.aliases[cmd]
            rewritten = f"{real_cmd} {args}".strip()
            return self.onecmd(rewritten)

        print(f"[!] Unknown command: {cmd}")