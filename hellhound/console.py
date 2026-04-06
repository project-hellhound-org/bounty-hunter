import cmd
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
def load_modules():
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

            except Exception:
                description = "No description available"
                real_category = category

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
        _boot_sequence()

        logo = r"""


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
        # Initialise commands
        print(f"\n{Fore.WHITE}Type '{Fore.YELLOW}help{Fore.WHITE}' to view available commands.\n")
    
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

        print(Style.BRIGHT + Fore.GREEN + f"\n[✔] Module equipped: {match}" + Style.RESET_ALL)
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
            print(Style.BRIGHT + Fore.GREEN + f"\n[✔] Strike complete. Intel stored under '{self.active_module.lower()}'." + Style.RESET_ALL)
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
                sev_w = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                sf = sorted([f for f in findings if isinstance(f, dict)],
                            key=lambda x: sev_w.get(str(x.get("severity","info")).lower(), 99))
                if not sf:
                    return
                print(Fore.MAGENTA + f"  [{label}]" + Style.RESET_ALL)
                for f in sf:
                    sev   = str(f.get("severity","info")).upper()
                    name  = f.get("type", f.get("vulnerability", f.get("name","Finding")))
                    url   = f.get("url",  f.get("endpoint",""))
                    proof = f.get("proof",f.get("evidence",""))
                    sc2   = _sev_color(sev)
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
                    print()

            # ── Module-specific renderers ─────────────────────────
            # Only load the module for THIS key — never fall back to
            # self.active_module which contaminates other modules' output.
            mod_obj       = self._load_module(mod_clean)
            loot_sections = getattr(mod_obj, "LOOT_SECTIONS", None) if mod_obj else None

            # ── CMDinj dedicated renderer ─────────────────────────
            if mod_clean == "cmdinj":
                vulns      = intel.get("vulnerabilities", [])
                file_reads = intel.get("file_reads", [])

                if vulns:
                    confirmed   = [v for v in vulns if v.get("detection") not in (None,"") or v.get("confirmed")]
                    n_confirmed = len(confirmed)
                    print(Fore.MAGENTA + Style.BRIGHT
                          + f"  [Command Injection — {len(vulns)} finding(s)"
                          + (f"  {Fore.RED}{n_confirmed} confirmed" if n_confirmed else "")
                          + Fore.MAGENTA + Style.BRIGHT + "]" + Style.RESET_ALL)
                    print()
                    sev_w = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                    for f in sorted(vulns, key=lambda x: sev_w.get(str(x.get("severity","info")).lower(),99)):
                        sev     = str(f.get("severity","critical")).upper()
                        det     = f.get("detection","")
                        param   = f.get("parameter", f.get("param",""))
                        payload = f.get("payload","")
                        url     = f.get("url","")
                        proof   = f.get("proof", f.get("evidence",""))
                        os_tag  = f.get("os","")
                        sc2     = _sev_color(sev)
                        det_c   = Fore.GREEN + Style.BRIGHT if det in ("direct-output","direct_output") else Fore.YELLOW + Style.BRIGHT
                        det_tag = f" [{det_c}{det.upper().replace('-',' ')}{Style.RESET_ALL}]" if det else ""
                        print(f"    {Style.BRIGHT}[{sc2}{sev}{Style.RESET_ALL}]{det_tag}  "
                              f"{Fore.WHITE + Style.BRIGHT}Command Injection{Style.RESET_ALL}")
                        if url:
                            print(f"       {Fore.WHITE}url     : {Fore.CYAN}{url}{Style.RESET_ALL}")
                        if param:
                            print(f"       {Fore.WHITE}param   : {Fore.YELLOW}{param}{Style.RESET_ALL}")
                        if payload:
                            print(f"       {Fore.WHITE}payload : {Fore.RED}{payload}{Style.RESET_ALL}")
                        if os_tag:
                            print(f"       {Fore.WHITE}os      : {Fore.WHITE}{os_tag}{Style.RESET_ALL}")
                        if proof:
                            ps = str(proof)
                            print(f"       {Fore.WHITE}proof   : {Fore.WHITE}{ps[:120]}{'...' if len(ps)>120 else ''}{Style.RESET_ALL}")
                        if f.get("poc_curl"):
                            print(f"       {Fore.WHITE}curl    : {Fore.YELLOW}{f['poc_curl']}{Style.RESET_ALL}")
                        if f.get("poc_browser"):
                            print(f"       {Fore.WHITE}open    : {Fore.CYAN}{f['poc_browser']}{Style.RESET_ALL}")
                        print()

                if file_reads:
                    print(Fore.MAGENTA + Style.BRIGHT + f"  [File Reads — {len(file_reads)} proof(s)]" + Style.RESET_ALL)
                    for fr in file_reads:
                        fpath    = fr.get("file","")
                        endpoint = fr.get("endpoint", fr.get("url",""))
                        param    = fr.get("param","")
                        strategy = fr.get("strategy","")
                        content  = fr.get("content","")
                        print(f"    {Fore.RED + Style.BRIGHT}{fpath}{Style.RESET_ALL}")
                        if endpoint: print(f"       {Fore.WHITE}endpoint : {Fore.CYAN}{endpoint}{Style.RESET_ALL}")
                        if param:    print(f"       {Fore.WHITE}param    : {Fore.YELLOW}{param}{Style.RESET_ALL}")
                        if strategy: print(f"       {Fore.WHITE}strategy : {Fore.WHITE}{strategy}{Style.RESET_ALL}")
                        if content:
                            cs_lines = str(content).replace("\\n", "\n").splitlines()
                            print(f"       {Fore.WHITE}content  :{Style.RESET_ALL}")
                            for line in cs_lines[:6]:
                                print(f"         {Fore.GREEN}{line.strip()}{Style.RESET_ALL}")
                            if len(cs_lines) > 6:
                                print(f"         {Fore.LIGHTBLACK_EX}... truncated{Style.RESET_ALL}")
                        print()
                
                if not vulns and not file_reads:
                    print(Fore.LIGHTBLACK_EX + "  [Command Injection]  no findings" + Style.RESET_ALL)

            # ── IDORdetector dedicated renderer ───────────────────────
            elif mod_clean == "idordetector":
                vulns = intel.get("vulnerabilities", [])

                if vulns:
                    print(Fore.MAGENTA + Style.BRIGHT 
                          + f"  [IDOR Vulnerabilities — {len(vulns)} finding(s)]" 
                          + Style.RESET_ALL)
                    print()
                    sev_w = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                    for f in sorted(vulns, key=lambda x: sev_w.get(str(x.get("severity","info")).lower(), 99)):
                        sev     = str(f.get("severity","high")).upper()
                        param   = f.get("parameter", f.get("param", ""))
                        url     = f.get("url", "")
                        proof   = f.get("proof", f.get("evidence", ""))
                        sc2     = _sev_color(sev)
                        
                        print(f"    {Style.BRIGHT}[{sc2}{sev}{Style.RESET_ALL}]  "
                              f"{Fore.WHITE + Style.BRIGHT}Insecure Direct Object Reference{Style.RESET_ALL}")
                        if url:
                            print(f"       {Fore.WHITE}url     : {Fore.CYAN}{url}{Style.RESET_ALL}")
                        if param:
                            print(f"       {Fore.WHITE}param   : {Fore.YELLOW}{param}{Style.RESET_ALL}")
                        if proof:
                            ps = str(proof)
                            print(f"       {Fore.WHITE}proof   : {Fore.WHITE}{ps[:120]}{'...' if len(ps)>120 else ''}{Style.RESET_ALL}")
                        if f.get("poc_curl"):
                            print(f"       {Fore.WHITE}curl    : {Fore.YELLOW}{f['poc_curl']}{Style.RESET_ALL}")
                        if f.get("poc_browser"):
                            print(f"       {Fore.WHITE}open    : {Fore.CYAN}{f['poc_browser']}{Style.RESET_ALL}")
                        print()
                else:
                    print(Fore.LIGHTBLACK_EX + "  [IDOR Vulnerabilities]  no findings" + Style.RESET_ALL)

            # ── BlobUnpacker dedicated renderer ──────────────────────
            elif mod_clean == "blobunpacker":
                files_recovered = intel.get("recovered_files_count", 0) or len(intel.get("reconstructed", []))
                endpoints = intel.get("new_endpoints", [])
                secrets = intel.get("secrets", [])
                
                print(f"  {Fore.MAGENTA + Style.BRIGHT}╔════════════ SOURCE INTELLIGENCE ════════════╗")
                print(f"  ║ {Fore.WHITE}Engine: BLOBUNPACKER   Status: {Fore.GREEN}DECODED{Fore.MAGENTA}      ║")
                print(f"  ╚════════════════════════════════════════════╝{Style.RESET_ALL}")
                
                print(f"\n    {Fore.WHITE + Style.BRIGHT}Inventory:{Style.RESET_ALL}")
                print(f"      • Recovered Files : {Fore.GREEN}{files_recovered}{Style.RESET_ALL}")
                print(f"      • API Endpoints   : {Fore.CYAN}{len(endpoints)}{Style.RESET_ALL}")
                print(f"      • Secrets Found   : {Fore.RED if secrets else Fore.GREEN}{len(secrets)}{Style.RESET_ALL}")

                if secrets:
                    print(f"\n    {Fore.RED + Style.BRIGHT}[ CRITICAL SECRETS ]{Style.RESET_ALL}")
                    for s in secrets[:10]:
                        val = s.get("content", s.get("value", ""))
                        stype = s.get("type", "Secret")
                        sfile = s.get("source", s.get("file", "unknown"))
                        print(f"      {Fore.WHITE}• {stype} : {Fore.MAGENTA}{val}{Style.RESET_ALL} ({Fore.LIGHTBLACK_EX}{sfile}{Style.RESET_ALL})")

                if endpoints:
                    print(f"\n    {Fore.CYAN + Style.BRIGHT}[ NEW ENDPOINTS (SAMPLE) ]{Style.RESET_ALL}")
                    for ep in endpoints[:10]:
                        print(f"      {Fore.WHITE}• {Fore.CYAN}{ep.get('url','')}{Style.RESET_ALL}")
                print()

            # ── SourceAuditor dedicated renderer ─────────────────────
            elif mod_clean == "sourceauditor":
                vulns = intel.get("vulnerabilities", [])
                files_count = intel.get("files_scanned", 0)
                
                print(f"  {Fore.CYAN + Style.BRIGHT}╔══════════════ DEEP SOURCE AUDIT ════════════╗")
                print(f"  ║ {Fore.WHITE}Engine: SOURCEAUDITOR   Files: {Fore.CYAN}{files_count:02d}{Fore.CYAN}       ║")
                print(f"  ╚════════════════════════════════════════════╝{Style.RESET_ALL}")

                if vulns:
                    print(f"\n    {Fore.WHITE + Style.BRIGHT}Security Findings ({len(vulns)}):{Style.RESET_ALL}")
                    for f in vulns:
                        sev = str(f.get("severity", "HIGH")).upper()
                        s_color = _sev_color(sev)
                        name = f.get("name", "Vulnerability")
                        f_id = f.get("id", "SA-???")
                        f_path = f.get("file", "unknown")
                        ai_tag = f" {Fore.MAGENTA + Style.BRIGHT}[AI VERIFIED]{Style.RESET_ALL}" if f.get("ai_verified") else ""
                        
                        print(f"      {Style.BRIGHT}[{s_color}{sev}{Style.RESET_ALL}]{ai_tag} {Fore.WHITE + Style.BRIGHT}{f_id}: {name}{Style.RESET_ALL}")
                        print(f"        {Fore.WHITE}File    : {Fore.CYAN}{f_path}{Style.RESET_ALL}")
                        
                        insight = f.get("ai_insight") or f.get("ai_reasoning")
                        if insight:
                            clean_insight = insight.replace("\n", " ").strip()
                            if len(clean_insight) > 200: clean_insight = clean_insight[:197] + "..."
                            print(f"        {Fore.MAGENTA}Insight : {Fore.WHITE}{clean_insight}{Style.RESET_ALL}")
                else:
                    print(f"\n    {Fore.GREEN}[✓] No critical source-level vulnerabilities found.{Style.RESET_ALL}")
                print()

            # ── CORSbuster dedicated renderer ─────────────────────
            elif mod_clean == "corsbuster":
                cors_vulns = intel.get("cors_vulnerabilities", [])
                cors_risk  = intel.get("risk_score", 0)

                if cors_vulns:
                    # Group findings by type
                    by_type = {}
                    for f in cors_vulns:
                        vtype = f.get("type", "Unknown")
                        by_type.setdefault(vtype, []).append(f)

                    # Severity ordering and colors for each type
                    type_severity = {
                        "Origin Reflection":       ("CRITICAL", Fore.MAGENTA + Style.BRIGHT),
                        "Null Origin Trust":       ("HIGH",     Fore.RED     + Style.BRIGHT),
                        "Arbitrary Origin Trust":  ("HIGH",     Fore.RED     + Style.BRIGHT),
                        "Wildcard with Credentials": ("HIGH",   Fore.RED     + Style.BRIGHT),
                        "Insecure HTTP Trust":     ("MEDIUM",   Fore.YELLOW  + Style.BRIGHT),
                        "Open CORS (Wildcard)":    ("LOW",      Fore.WHITE),
                    }
                    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

                    # Sort types by severity
                    sorted_types = sorted(
                        by_type.keys(),
                        key=lambda t: sev_order.index(type_severity.get(t, ("INFO", Fore.WHITE))[0])
                    )

                    cred_count = sum(1 for f in cors_vulns if f.get("credentials_allowed"))
                    header = f"  [CORS Misconfigurations — {len(cors_vulns)} finding(s)"
                    if cred_count:
                        header += f"  {Fore.RED}{Style.BRIGHT}{cred_count} with credentials{Style.RESET_ALL}{Fore.MAGENTA}{Style.BRIGHT}"
                    header += "]"
                    print(Fore.MAGENTA + Style.BRIGHT + header + Style.RESET_ALL)
                    print()

                    for vtype in sorted_types:
                        items = by_type[vtype]
                        sev, sev_c = type_severity.get(vtype, ("INFO", Fore.WHITE))

                        print(f"    {Style.BRIGHT}[{sev_c}{sev}{Style.RESET_ALL}{Style.BRIGHT}] "
                              f"{Fore.WHITE}{vtype}{Style.RESET_ALL}  "
                              f"{Fore.LIGHTBLACK_EX}({len(items)} endpoint{'s' if len(items) != 1 else ''}){Style.RESET_ALL}")

                        for f in items:
                            cred_tag = (f"  {Fore.RED + Style.BRIGHT}[CREDS]{Style.RESET_ALL}"
                                        if f.get("credentials_allowed") else "")
                            print(f"       {Fore.CYAN}{f.get('url','')}{Style.RESET_ALL}{cred_tag}")
                            
                            if f.get("poc_html"):
                                # Advanced feature: Provide a "copy-ready" hint
                                print(f"       {Fore.WHITE}exploit : {Fore.YELLOW}[HTML PoC Generated]{Style.RESET_ALL}")
                                print(f"       {Fore.LIGHTBLACK_EX}View raw loot ('loot --json') to copy full PoC script.{Style.RESET_ALL}")
                        print()
                else:
                    print(Fore.LIGHTBLACK_EX + "  [CORS]  no misconfigurations found" + Style.RESET_ALL)
                    print()

            # ── Exmap dedicated renderer ──────────────────────────
            elif mod_clean == "exmap":
                components = intel.get("components", [])
                cves       = intel.get("cves", [])
                low_conf   = intel.get("low_confidence", [])
                exploits   = intel.get("exploits", [])
                msf        = intel.get("metasploit_modules", [])

                def _cvss_color(score):
                    try: s = float(score or 0)
                    except: s = 0.0
                    if s >= 9.0: return Fore.MAGENTA + Style.BRIGHT
                    if s >= 7.0: return Fore.RED     + Style.BRIGHT
                    if s >= 4.0: return Fore.YELLOW  + Style.BRIGHT
                    return Fore.WHITE

                def _ev_bar(score):
                    try: s = int(score or 0)
                    except: s = 0
                    filled = round(s / 25)
                    bar = "█" * filled + "░" * (4 - filled)
                    c = (Fore.GREEN + Style.BRIGHT if s >= 75 else
                         Fore.YELLOW + Style.BRIGHT if s >= 50 else Fore.RED)
                    return f"{c}{bar}{Style.RESET_ALL}"

                if components:
                    print(Fore.MAGENTA + Style.BRIGHT + "  [Mapped Components]" + Style.RESET_ALL)
                    for comp in components:
                        if comp.get("has_version"):
                            print(f"    {Fore.CYAN + Style.BRIGHT}{comp.get('name',''):<22}{Style.RESET_ALL}"
                                  f"  {Fore.GREEN + Style.BRIGHT}v{comp.get('version',''):<14}{Style.RESET_ALL}"
                                  f"  {Fore.WHITE}{comp.get('source','')}{Style.RESET_ALL}")
                        else:
                            print(f"    {Fore.CYAN}{comp.get('name',''):<22}{Style.RESET_ALL}"
                                  f"  {Fore.LIGHTBLACK_EX}no version      {Style.RESET_ALL}"
                                  f"  {Fore.WHITE}{comp.get('source','')}{Style.RESET_ALL}")
                    print()

                if cves:
                    sev_w = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                    sc = sorted(cves, key=lambda x: (sev_w.get(str(x.get("severity","info")).lower(),4), -(x.get("evidence_score") or 0)))
                    crit_c = sum(1 for c in sc if (c.get("cvss") or 0) >= 9.0)
                    high_c = sum(1 for c in sc if 7.0 <= (c.get("cvss") or 0) < 9.0)
                    wpn_c  = sum(1 for c in sc if c.get("weaponized"))
                    print(Fore.MAGENTA + Style.BRIGHT + f"  [CVE Findings — {len(sc)} confirmed"
                          + (f"  {crit_c} critical" if crit_c else "")
                          + (f"  {high_c} high"     if high_c else "")
                          + (f"  {wpn_c} weaponized" if wpn_c  else "")
                          + "]" + Style.RESET_ALL)
                    print()
                    for cve in sc:
                        cvss = cve.get("cvss") or 0
                        sev  = str(cve.get("severity","")).upper() or ("CRITICAL" if cvss>=9 else "HIGH" if cvss>=7 else "MEDIUM")
                        ev   = cve.get("evidence_score",0)
                        wpn  = cve.get("weaponized",False)
                        comp = cve.get("component","")
                        cv   = cve.get("component_version","")
                        cc   = _cvss_color(cvss)
                        wpn_tag = (Fore.RED + Style.BRIGHT + " [WEAPONIZED]" + Style.RESET_ALL) if wpn else ""
                        print(f"    {cc}[{sev}]{Style.RESET_ALL}{wpn_tag}  "
                              f"{Fore.WHITE + Style.BRIGHT}{cve.get('id','')}{Style.RESET_ALL}  "
                              f"{cc}CVSS:{cvss}{Style.RESET_ALL}  "
                              f"evidence:{_ev_bar(ev)} {Fore.WHITE}{ev}/100{Style.RESET_ALL}  "
                              f"{Fore.CYAN}{comp}{(' '+cv) if cv else ''}{Style.RESET_ALL}")
                        summary = cve.get("summary","")
                        nvd_url = cve.get("nvd_url","")
                        cwes    = cve.get("cwes",[])
                        notes   = cve.get("evidence_notes",[])
                        if summary:
                            print(f"       {Fore.WHITE}{summary[:110]}{'...' if len(summary)>110 else ''}{Style.RESET_ALL}")
                        if nvd_url:
                            print(f"       {Fore.LIGHTBLACK_EX}nvd   : {Fore.CYAN}{nvd_url}{Style.RESET_ALL}")
                        if cwes:
                            print(f"       {Fore.LIGHTBLACK_EX}cwe   : {Fore.WHITE}{', '.join(cwes[:4])}{Style.RESET_ALL}")
                        if notes:
                            print(f"       {Fore.LIGHTBLACK_EX}score : {Fore.WHITE}{' | '.join(notes[:3])}{Style.RESET_ALL}")
                        print()
                else:
                    print(Fore.LIGHTBLACK_EX + "  [CVE Findings]  no CVEs above evidence threshold" + Style.RESET_ALL)
                    print()

                if exploits:
                    print(Fore.MAGENTA + Style.BRIGHT + f"  [ExploitDB — {len(exploits)} exploit(s)]" + Style.RESET_ALL)
                    for ex in exploits[:10]:
                        print(f"    {Fore.RED + Style.BRIGHT}EDB-{ex.get('edb_id',''):<8}{Style.RESET_ALL}  "
                              f"{Fore.WHITE + Style.BRIGHT}{ex.get('title','')}{Style.RESET_ALL}  "
                              f"{Fore.YELLOW}[{ex.get('type','')}]{Style.RESET_ALL}")
                        if ex.get("url"): print(f"       {Fore.LIGHTBLACK_EX}{ex['url']}{Style.RESET_ALL}")
                    print()

                if msf:
                    print(Fore.MAGENTA + Style.BRIGHT + f"  [Metasploit Modules — {len(msf)}]" + Style.RESET_ALL)
                    for m in msf[:10]:
                        print(f"    {Fore.RED}{m}{Style.RESET_ALL}")
                    print()

                if low_conf:
                    print(Fore.LIGHTBLACK_EX + f"  [Suppressed — {len(low_conf)} CVE(s) below evidence threshold]" + Style.RESET_ALL)
                    for cve in low_conf[:5]:
                        print(f"    {Fore.LIGHTBLACK_EX}{cve.get('id',''):<18}  CVSS:{cve.get('cvss') or 0:<5}  evidence:{cve.get('evidence_score',0)}/100{Style.RESET_ALL}")
                    if len(low_conf) > 5:
                        print(Fore.LIGHTBLACK_EX + f"    ... +{len(low_conf)-5} more (use loot --json)" + Style.RESET_ALL)
                    print()

            # ── GraphQL Hunter dedicated renderer ─────────────────────
            elif mod_clean == "graphql_hunter":
                graphql_eps = intel.get("graphql_endpoints", [])
                
                if graphql_eps:
                    print(Fore.MAGENTA + Style.BRIGHT + f"  [GraphQL Exposed — {len(graphql_eps)} endpoint(s)]" + Style.RESET_ALL)
                    print()
                    for ep in graphql_eps:
                        url = ep.get("endpoint", "")
                        print(f"    {Fore.RED + Style.BRIGHT}[GRAPHQL]{Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL}")
                        
                        if ep.get("introspection_enabled"):
                            print(f"       {Fore.MAGENTA + Style.BRIGHT}[CRITICAL]{Style.RESET_ALL} Introspection is ENABLED")
                        if ep.get("suggestions_enabled"):
                            print(f"       {Fore.YELLOW + Style.BRIGHT}[WARNING]{Style.RESET_ALL} Field suggestions are ENABLED")
                        print()
                else:
                    print(Fore.LIGHTBLACK_EX + "  [GraphQL]  no endpoints found" + Style.RESET_ALL)
                    print()

            # ── JWT Analyzer dedicated renderer ───────────────────────
            elif mod_clean == "jwt_analyzer":
                jwts = intel.get("jwts", [])
                if jwts:
                    print(Fore.MAGENTA + Style.BRIGHT + f"  [JSON Web Tokens — {len(jwts)} analyzed]" + Style.RESET_ALL)
                    print()
                    for token in jwts:
                        src = token.get("source", "unknown")
                        vulns = token.get("vulnerabilities", [])
                        claims = token.get("sensitive_claims", [])
                        
                        raw = token.get("token", "")
                        disp_token = f"{raw[:15]}...{raw[-10:]}" if len(raw) > 30 else raw
                        
                        # Decide color based on vulnerabilities
                        sev_color = Fore.MAGENTA if any("CRITICAL" in v for v in vulns) else Fore.RED if vulns else Fore.YELLOW if claims else Fore.GREEN
                        sev_tag = "[CRITICAL JWT]" if any("CRITICAL" in v for v in vulns) else "[WEAK JWT]" if vulns else "[SENSITIVE JWT]" if claims else "[JWT FOUND]"
                        
                        print(f"    {sev_color + Style.BRIGHT}{sev_tag}{Style.RESET_ALL} {Fore.WHITE}{disp_token}{Style.RESET_ALL}")
                        print(f"       {Fore.WHITE}source : {Fore.CYAN}{src}{Style.RESET_ALL}")
                        
                        if vulns:
                            for v in vulns:
                                vc = Fore.MAGENTA + Style.BRIGHT if "CRITICAL" in v else Fore.RED + Style.BRIGHT
                                print(f"       {vc}vuln   : {v}{Style.RESET_ALL}")
                                
                        if claims:
                            for c in claims:
                                print(f"       {Fore.YELLOW}claim  : {c}{Style.RESET_ALL}")
                        print()
                else:
                    print(Fore.LIGHTBLACK_EX + "  [JWT]  no tokens discovered" + Style.RESET_ALL)
                    print()

            # ── Hydra dedicated renderer ─────────────────────────
            elif mod_clean == "hydra":
                surfaces = intel.get("surfaces", [])
                logic_chains = intel.get("logic_chains", [])
                
                print(f"  {Fore.MAGENTA + Style.BRIGHT}╔════════════ HYDRA LOGIC AUDIT ════════════╗")
                print(f"  ║ {Fore.WHITE}Engine: HYDRA (Geryon/Lailaps/Cerberus) ║")
                print(f"  ╚═══════════════════════════════════════════╝{Style.RESET_ALL}")
                
                if surfaces:
                    print(f"\n    {Fore.WHITE + Style.BRIGHT}Mapped Surfaces ({len(surfaces)}):{Style.RESET_ALL}")
                    show_surfaces = surfaces[:30]
                    for s in show_surfaces:
                        pname = s.get("parameter", "unknown")
                        url   = s.get("url", "")
                        roles = s.get("roles", [])
                        delta = s.get("differential")
                        recom = s.get("recommended_auditor")
                        
                        # Color coding based on roles
                        role_str = ""
                        if roles:
                            role_c = Fore.RED if "SENSITIVE_DATA" in roles else Fore.YELLOW if any(x in roles for x in ["OBJECT_IDENTIFIER", "JWT_TOKEN"]) else Fore.WHITE
                            role_str = f" {role_c}[{'/'.join(roles)}]{Style.RESET_ALL}"
                        
                        print(f"      • {Fore.WHITE}{pname:<16}{Style.RESET_ALL} {Style.BRIGHT}{Fore.WHITE}->{Style.RESET_ALL} {Fore.CYAN}{url}{Style.RESET_ALL}{role_str}")
                        
                        if delta:
                            d_type = delta.get("delta_type", "DYNAMISM")
                            l_shift = delta.get("length_shift", 0)
                            s_shift = "STATUS_SHIFT " if delta.get("status_shift") else ""
                            print(f"        {Fore.GREEN}└─ Lailaps Probe : {s_shift}{d_type} (ΔLen: {l_shift}){Style.RESET_ALL}")
                        
                        if recom:
                            print(f"        {Fore.MAGENTA}└─ Target Auditor: {Fore.WHITE + Style.BRIGHT}{recom}{Style.RESET_ALL}")
                    if len(surfaces) > 30:
                        print(f"\n      {Fore.LIGHTBLACK_EX}... +{len(surfaces)-30} more surfaces (use --json for full list){Style.RESET_ALL}")
                
                if logic_chains:
                    print(f"\n    {Fore.MAGENTA + Style.BRIGHT}[ GERYON Logic Correlations ]{Style.RESET_ALL}")
                    for chain in logic_chains:
                        pname = chain.get("parameter", "unknown")
                        ctype = chain.get("type", "CORRELATION")
                        urls  = chain.get("urls", [])
                        print(f"      • {Fore.WHITE + Style.BRIGHT}{pname}{Style.RESET_ALL} : {Fore.YELLOW}{ctype}{Style.RESET_ALL}")
                        for u in urls[:3]:
                            print(f"        {Fore.WHITE}- {u}{Style.RESET_ALL}")
                        if len(urls) > 3:
                            print(f"        {Fore.LIGHTBLACK_EX}  ... +{len(urls)-3} more{Style.RESET_ALL}")
                print()

            # ── Stalk (Hybrid OSINT) dedicated renderer ───────────
            elif mod_clean == "stalk":
                subdomains = intel.get("subdomains", [])
                urls       = intel.get("historical_urls", [])
                git        = intel.get("git_exposed", [])
                cloud      = intel.get("cloud_assets", [])
                leaks      = intel.get("leak_candidates", [])
                banners    = intel.get("banners", [])

                if subdomains:
                    print(Fore.MAGENTA + Style.BRIGHT + f"  [Subdomains — {len(subdomains)} discovered]" + Style.RESET_ALL)
                    for s in subdomains:
                        host = s.get("host", "unknown")
                        ip   = s.get("ip", "unresolved")
                        src  = s.get("source", "unknown")
                        res  = s.get("resolved", False)
                        
                        host_c = Fore.WHITE + Style.BRIGHT if res else Fore.WHITE
                        ip_c   = Fore.CYAN if res else Fore.LIGHTBLACK_EX
                        print(f"    • {host_c}{host:<30}{Style.RESET_ALL} {ip_c}{ip:<16}{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}[{src}]{Style.RESET_ALL}")
                    print()

                if git:
                    print(Fore.RED + Style.BRIGHT + f"  [Git Exposure — {len(git)} repository found!]" + Style.RESET_ALL)
                    for g in git:
                        url = g.get("url", "unknown")
                        print(f"    {Fore.RED + Style.BRIGHT}[!] EXPOSED:{Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL}")
                        if g.get("head"):
                            print(f"        {Fore.LIGHTBLACK_EX}HEAD: {g['head'][:80]}{Style.RESET_ALL}")
                    print()

                if cloud:
                    print(Fore.YELLOW + Style.BRIGHT + f"  [Cloud Assets — {len(cloud)} buckets/containers]" + Style.RESET_ALL)
                    for c in cloud:
                        status = c.get("status", "unknown").upper()
                        provider = c.get("provider", "unknown")
                        url = c.get("url", "unknown")
                        sc = Fore.RED + Style.BRIGHT if "PUBLIC" in status else Fore.YELLOW
                        print(f"    • {sc}[{status}]{Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}({provider}){Style.RESET_ALL}")
                    print()

                if urls:
                    limit = 150
                    print(Fore.MAGENTA + Style.BRIGHT + f"  [Historical URLs — showing {min(len(urls), limit)}/{len(urls)}]" + Style.RESET_ALL)
                    for u in urls[:limit]:
                        url = u.get("url", "unknown")
                        src = u.get("source", "unknown")
                        print(f"    {Fore.WHITE}• {url} {Fore.LIGHTBLACK_EX}[{src}]{Style.RESET_ALL}")
                    if len(urls) > limit:
                        print(f"    {Fore.LIGHTBLACK_EX}... +{len(urls)-limit} more (use loot --json to see all){Style.RESET_ALL}")
                    print()

                if leaks:
                    print(Fore.RED + Style.BRIGHT + f"  [Leak Candidates — {len(leaks)} findings]" + Style.RESET_ALL)
                    for l in leaks:
                        url = l.get("url", "unknown")
                        snippet = l.get("snippet", "")
                        print(f"    {Fore.YELLOW}[leak]{Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL}")
                        if snippet:
                            print(f"           {Fore.LIGHTBLACK_EX}\"{snippet[:100]}...\"{Style.RESET_ALL}")
                    print()

                if banners:
                    print(Fore.CYAN + Style.BRIGHT + f"  [Banner Exposure — {len(banners)} records]" + Style.RESET_ALL)
                    for b in banners:
                        host   = b.get("host", "unknown")
                        port   = b.get("port", "unknown")
                        banner = b.get("banner", "")
                        src    = b.get("source", "unknown")
                        print(f"    • {Fore.WHITE}{host}:{port}{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}[{src}]{Style.RESET_ALL}")
                        if banner:
                            print(f"      {Fore.CYAN}{banner[:100]}{Style.RESET_ALL}")
                    print()

            # ── Generic LOOT_SECTIONS path ────────────────────────
            elif loot_sections:
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

            else:
                # ── Universal fallback ────────────────────────────
                # Covers any module not explicitly handled above.

                # 1. vulnerabilities key
                vulns = intel.get("vulnerabilities", [])
                if vulns:
                    _render_findings(vulns)

                # 2. findings key (alternate)
                top_findings = intel.get("findings", [])
                if top_findings and not vulns:
                    _render_findings(top_findings, "Findings")

                # 3. bac nested block
                if "bac" in intel and isinstance(intel.get("bac"), dict):
                    bac      = intel["bac"]
                    findings = bac.get("findings", [])
                    summary  = bac.get("summary", {})
                    if summary:
                        print(Fore.MAGENTA + "  [Access Control Summary]" + Style.RESET_ALL)
                        for sev in ("Critical","High","Medium","Low","Info"):
                            cnt = summary.get(sev, 0)
                            if cnt:
                                print(f"    {_sev_color(sev)}{sev:<8}{Style.RESET_ALL} : {cnt}")
                        print()
                    if findings:
                        normed = [{"severity": f.get("severity","info"),
                                   "name":     f.get("vulnerability", f.get("name","Finding")),
                                   "url":      f.get("endpoint", f.get("url","")),
                                   "proof":    f.get("proof",""),
                                   "poc_curl": f.get("poc_curl",""),
                                   "poc_browser": f.get("poc_browser","")}
                                  for f in findings if isinstance(f, dict)]
                        _render_findings(normed, "Access Control Findings")


                # 4. endpoints (Spider / any recon module)
                endpoints = intel.get("endpoints", [])
                if endpoints:
                    # Build cluster map
                    cluster_map = {}
                    for ep in endpoints:
                        cl = ep.get("cluster", ep.get("url",""))
                        if cl not in cluster_map:
                            cluster_map[cl] = {
                                "url":       ep.get("url",""),
                                "methods":   set(ep.get("methods",[])),
                                "confidence":ep.get("confidence_label",""),
                                "auth":      ep.get("auth_required",False),
                                "sensitive": ep.get("parameter_sensitive",False),
                            }
                        else:
                            cluster_map[cl]["methods"].update(ep.get("methods",[]))

                    # Critical signals
                    sensitive = [v for v in cluster_map.values() if v["sensitive"]]
                    auth_walls= [v for v in cluster_map.values() if v["auth"]]
                    if sensitive or auth_walls:
                        print(Fore.YELLOW + "  [Critical Signals]" + Style.RESET_ALL)
                        if sensitive:
                            print(Fore.YELLOW + f"    Parameter-Sensitive ({len(sensitive)})" + Style.RESET_ALL)
                            for e in list(sensitive)[:10]:
                                print(f"      {Fore.CYAN}{e.get('url','')}{Style.RESET_ALL}")
                        if auth_walls:
                            print(Fore.YELLOW + f"    Auth-Walled ({len(auth_walls)})" + Style.RESET_ALL)
                            for e in list(auth_walls)[:10]:
                                print(f"      {Fore.CYAN}{e.get('url','')}{Style.RESET_ALL}")
                        print()

                    print(Fore.MAGENTA + f"  [Attack Surface — {len(cluster_map)} endpoints]" + Style.RESET_ALL)
                    for ep in list(cluster_map.values()):
                        tags = []
                        if ep["confidence"] in ("HIGH","CONFIRMED"): tags.append(ep["confidence"])
                        if ep["auth"]:      tags.append("AUTH")
                        if ep["sensitive"]: tags.append("SENS")
                        tag_str    = (Fore.RED + f"[{'|'.join(tags)}]" + Style.RESET_ALL) if tags else ""
                        method_str = "|".join(sorted(ep["methods"]))
                        print(f"    {Fore.WHITE}{method_str:<10}{Style.RESET_ALL} {Fore.WHITE}{ep['url']} {tag_str}")
                    print()

                secrets = intel.get("secrets", [])
                if secrets:
                    print(Fore.MAGENTA + f"  [Secrets — {len(secrets)} found]" + Style.RESET_ALL)
                    for s in secrets:
                        stype   = s.get("type", "unknown")
                        content = s.get("content", "")
                        source  = s.get("source", "")
                        print(f"    {Fore.YELLOW}{stype:<20}{Style.RESET_ALL} {Fore.WHITE}{content}{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}({source}){Style.RESET_ALL}")
                    print()

                # 5. cors_issues
                cors = intel.get("cors_issues", [])
                if cors:
                    print(Fore.MAGENTA + f"  [CORS Issues — {len(cors)}]" + Style.RESET_ALL)
                    for c in cors:
                        print(f"    {Fore.CYAN}{c.get('url','')} {Fore.YELLOW}({c.get('severity','')}){Style.RESET_ALL}")
                    print()

                # 6. sourcemaps
                sourcemaps = intel.get("sourcemaps", [])
                if sourcemaps:
                    print(Fore.MAGENTA + f"  [Source Maps — {len(sourcemaps)}]" + Style.RESET_ALL)
                    for sm in sourcemaps:
                        print(f"    {Fore.CYAN}{sm.get('url',sm)}{Style.RESET_ALL}")
                    print()

                # 7. well_known
                well_known = intel.get("well_known", [])
                if well_known:
                    print(Fore.MAGENTA + f"  [Well-Known Discovery — {len(well_known)} file(s)]" + Style.RESET_ALL)
                    for wk in well_known:
                        url     = wk.get("url", "")
                        content = wk.get("content", "")
                        paths   = wk.get("discovered_paths", [])
                        
                        print(f"    {Fore.WHITE + Style.BRIGHT}File: {Fore.CYAN}{url}{Style.RESET_ALL}")
                        if content:
                            print(f"      {Fore.LIGHTBLACK_EX}Content: {content[:100]}...{Style.RESET_ALL}")
                        if paths:
                            print(f"      {Fore.GREEN}Discovered {len(paths)} unique path(s) inside{Style.RESET_ALL}")
                            for p in paths[:5]:
                                print(f"        {Fore.WHITE}• {p}{Style.RESET_ALL}")
                            if len(paths) > 5:
                                print(f"        {Fore.LIGHTBLACK_EX}... +{len(paths)-5} more{Style.RESET_ALL}")
                    print()

                # 8. Generic list keys not already handled — future-proof catch-all
                known_keys = {"vulnerabilities","bac","endpoints","secrets",
                              "cors_issues","sourcemaps","summary","stats",
                              "tech_stack","robots_paths","graphql","openapi",
                              "metadata", "jwts", "graphql_endpoints", "well_known"}
                for key, val in intel.items():
                    if key in known_keys or not val:
                        continue
                    
                    if isinstance(val, list) and val:
                        print(Fore.MAGENTA + f"  [{key}]" + Style.RESET_ALL)
                        for item in list(val)[:20]:
                            if isinstance(item, dict):
                                # Try to find a good primary field to show
                                primary_keys = ("url", "path", "name", "content", "title", "id", "asset")
                                primary_val = None
                                for pk in primary_keys:
                                    if item.get(pk):
                                        primary_val = item.get(pk)
                                        break
                                
                                # Collect everything else
                                exclude = set(primary_keys)
                                extra = {k:v for k,v in item.items() if k not in exclude}
                                
                                if primary_val:
                                    line_text = f"    {Fore.WHITE}• {str(primary_val)[:100]}"
                                    if extra:
                                        line_text += Fore.LIGHTBLACK_EX + f"  {json.dumps(extra, default=str)[:80]}"
                                    print(line_text + Style.RESET_ALL)
                                else:
                                    # Full dump if no primary field found
                                    print(f"    {Fore.WHITE}• {json.dumps(item, default=str)[:140]}{Style.RESET_ALL}")
                            else:
                                print(f"    {Fore.WHITE}• {item}{Style.RESET_ALL}")
                        
                        if len(val) > 20:
                            print(Fore.WHITE + f"    ... +{len(val)-20} more" + Style.RESET_ALL)
                        print()
                    
                    elif isinstance(val, dict) and val:
                        print(Fore.MAGENTA + f"  [{key}]" + Style.RESET_ALL)
                        for k2, v2 in list(val.items())[:15]:
                            print(f"    {Fore.CYAN}{str(k2):<20}{Style.RESET_ALL} {v2}")
                        print()

        # ── High value targets across all modules ─────────────
        high_value = []
        for mod, output in self.results.items():
            if not isinstance(output, dict): continue
            for ep in output.get("intel", {}).get("endpoints", []):
                if ep.get("parameter_sensitive") or ep.get("auth_required") or \
                        ep.get("confidence_label") in ("HIGH","CONFIRMED"):
                    high_value.append(ep)

        if high_value:
            high_value = sorted(high_value,
                key=lambda e: (e.get("confidence_label")=="CONFIRMED",
                               bool(e.get("parameter_sensitive")),
                               bool(e.get("auth_required"))), reverse=True)
            print(Fore.RED + Style.BRIGHT + "  ── HIGH VALUE TARGETS ──" + Style.RESET_ALL)
            for ep in high_value[:10]:
                conf_color = Fore.RED if ep.get("confidence_label") in ("HIGH","CONFIRMED") else Fore.YELLOW
                print(f"  {Fore.CYAN}{ep.get('url','')} "
                      f"{conf_color}[{ep.get('confidence_label','')}]{Style.RESET_ALL}")
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
        print(Style.BRIGHT + Fore.CYAN + f"[•] {msg}" + Style.RESET_ALL)

    def success(self, msg):
        print(Style.BRIGHT + Fore.GREEN + f"[✔] {msg}" + Style.RESET_ALL)

    def warn(self, msg):
        print(Style.BRIGHT + Fore.YELLOW + f"[•] {msg}" + Style.RESET_ALL)

    def always_info(self, msg):
        print(Style.BRIGHT + Fore.CYAN + f"[•] {msg}" + Style.RESET_ALL)

    def always_success(self, msg):
        if "Target:" in msg:
            msg = msg.replace("High:", Fore.RED + Style.BRIGHT + "High:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            msg = msg.replace("Secrets:", Fore.MAGENTA + Style.BRIGHT + "Secrets:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
            msg = msg.replace("Param-Sensitive:", Fore.YELLOW + Style.BRIGHT + "Param-Sensitive:" + Style.RESET_ALL + Fore.GREEN + Style.BRIGHT)
        print(Style.BRIGHT + Fore.GREEN + f"[✔] {msg}" + Style.RESET_ALL)

    def error(self, msg):
        print(Style.BRIGHT + Fore.RED + f"[✖] {msg}" + Style.RESET_ALL)

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