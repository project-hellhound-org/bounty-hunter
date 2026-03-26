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

from hellhound.core.engine import HellhoundEngine
from hellhound.core.suggest import suggest_actions

# ----------------------------
# BOOT ANIMATION
# ----------------------------

def _boot_sequence():
    """
    HELLHOUND boot sequence.
    Phase 1 — typed boot log lines specific to the framework.
    Phase 2 — scanline logo reveal (line by line, dim→bright, no cursor tricks).
    Skippable: any keypress during phase 1 jumps straight to logo.
    Terminal-safe: no ANSI cursor repositioning.
    """
    import select
    import tty
    import termios

    def _kbhit(timeout=0):
        """Non-blocking keypress check (Unix only). Returns True if key waiting."""
        try:
            dr, _, _ = select.select([sys.stdin], [], [], timeout)
            return bool(dr)
        except Exception:
            return False

    def _flush_stdin():
        try:
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass

    prompt  = Fore.LIGHTRED_EX + "hellhound" + Fore.WHITE + "@" + Fore.RED + "core" + Fore.WHITE + ":~# " + Style.RESET_ALL
    boot_lines = [
        ("hellhound --init",          Fore.WHITE + "  Initialising HELLHOUND framework v12.0"),
        ("hellhound --load-modules",  Fore.WHITE + "  Modules loaded: recon, vuln, exploit, intel, analysis"),
        ("hellhound --verify-chain",  Fore.WHITE + "  Engine ✓  Emit ✓  Session ✓  Loot ✓"),
        ("hellhound --arm",           Fore.RED           + "  All systems armed. Awaiting operator."),
    ]

    skipped = False
    _flush_stdin()

    for cmd_str, response in boot_lines:
        if skipped or _kbhit(0):
            skipped = True
            break

        # Type out the command character by character
        sys.stdout.write(prompt)
        sys.stdout.flush()
        for ch in cmd_str:
            if _kbhit(0):
                skipped = True
                break
            sys.stdout.write(Fore.WHITE + ch)
            sys.stdout.flush()
            time.sleep(0.03)

        print()
        if not skipped:
            time.sleep(0.05)
            print(response + Style.RESET_ALL)
            time.sleep(0.18)

    if not skipped:
        print(Fore.GREEN + "\n  [ HELLHOUND ONLINE ]\n" + Style.RESET_ALL)
        time.sleep(0.3)


def _scanline_logo(text):
    """
    Reveal the logo line-by-line like a CRT scanline.
    Each line starts at dim dark-red and snaps to full bright red.
    No cursor repositioning — fully terminal-safe.
    """
    lines = text.split('\n')

    for i, line in enumerate(lines):
        # Determine brightness based on how far through the logo we are
        progress = i / max(len(lines) - 1, 1)

        if progress < 0.3:
            color = Fore.RED
        elif progress < 0.7:
            color = Fore.RED
        else:
            color = Fore.RED + Style.BRIGHT

        sys.stdout.write(color + line + Style.RESET_ALL + "\n")
        sys.stdout.flush()
        time.sleep(0.018)

    # Final flash: reprint last line bright white then back to red
    if lines:
        last = lines[-1]
        sys.stdout.write("\r" + Fore.WHITE + Style.BRIGHT + last + Style.RESET_ALL + "\n")
        sys.stdout.flush()
        time.sleep(0.08)
        sys.stdout.write("\r" + Fore.RED + Style.BRIGHT + last + Style.RESET_ALL + "\n")
        sys.stdout.flush()


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
            "headers": {}
        }

        self.aliases = {
            "hunt": "prey",
            "run": "strike",
            "use": "equip",
            "back": "release",
            "ls": "arsenal",
            "results": "loot",
            "quit": "exit",
            "q": "exit",
            "cls": "clear",
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
                
        _scanline_logo(logo)
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

    def do_options(self, arg):
        """options → Show current module options"""
        if not self.active_module:
            print(Style.BRIGHT + Fore.YELLOW + "[•] No module equipped. Use 'equip <module>' first." + Style.RESET_ALL)
            return

        mod_obj = self._load_module(self.active_module)
        if not mod_obj:
            print(Style.BRIGHT + Fore.RED + "[✖] Could not reload module for options." + Style.RESET_ALL)
            return

        options_def = getattr(mod_obj, "OPTIONS", [])
        if not options_def:
            print(Style.BRIGHT + Fore.YELLOW + "[•] This module has no configurable options." + Style.RESET_ALL)
            return

        # Column widths
        C_NAME = 22
        C_VAL  = 24
        C_REQ  = 10

        # Header
        cat = self.modules.get(self.active_module, {}).get("category", "module")
        print(f"\n  Module options ({Fore.CYAN + Style.BRIGHT}{cat}/{self.active_module}{Style.RESET_ALL}):\n")

        # Column labels
        h_name = f"{'Name':<{C_NAME}}"
        h_val  = f"{'Current Setting':<{C_VAL}}"
        h_req  = f"{'Required':<{C_REQ}}"
        h_desc = "Description"
        print(f"   {Style.BRIGHT + Fore.WHITE}{h_name}{h_val}{h_req}{h_desc}{Style.RESET_ALL}")

        # Separator — dashes under each header word only (Metasploit style)
        sep_name = "-" * len("Name")
        sep_val  = "-" * len("Current Setting")
        sep_req  = "-" * len("Required")
        sep_desc = "-" * len("Description")
        print(f"   {Fore.WHITE}"
              f"{sep_name:<{C_NAME}}{sep_val:<{C_VAL}}{sep_req:<{C_REQ}}{sep_desc}"
              f"{Style.RESET_ALL}")

        for opt in options_def:
            name     = opt.get("name", "")
            default  = opt.get("default")
            helptext = opt.get("help", "")
            required = opt.get("required", False)
            current  = self.module_options.get(name, default)

            # ── Value display ──────────────────────────────────────
            if current is None or current == "" or current == {}:
                disp = ""
            elif isinstance(current, str) and current.startswith("eyJ"):
                # Raw JWT — show head...tail only
                disp = f"{current[:8]}...{current[-4:]}"
            elif isinstance(current, str) and current.lower().startswith("bearer "):
                tok  = current[7:]
                disp = f"Bearer {tok[:8]}...{tok[-4:]}"
            elif isinstance(current, str) and "=" in current and len(current) > C_VAL:
                # Cookie key=value style
                first = current.split(";")[0].strip()
                k, v  = first.split("=", 1)
                max_v = max(4, C_VAL - len(k) - 4)
                disp  = f"{k}={v[:max_v]}..." if len(v) > max_v else f"{k}={v}"
            else:
                raw = str(current)
                disp = raw[:C_VAL - 3] + "..." if len(raw) > C_VAL else raw

            # Colors
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

            # Padding uses only visible char counts — no ANSI in disp
            pad_name = " " * max(0, C_NAME - len(name))
            pad_val  = " " * max(0, C_VAL  - len(disp))
            pad_req  = " " * max(0, C_REQ  - len(req_str))

            print(f"   {Fore.CYAN + Style.BRIGHT}{name}{Style.RESET_ALL}{pad_name}"
                  f"{val_color}{disp}{Style.RESET_ALL}{pad_val}"
                  f"{req_color}{req_str}{Style.RESET_ALL}{pad_req}"
                  f"{Fore.WHITE}{helptext}{Style.RESET_ALL}")

        print()


    def do_set(self, arg):
        """set <option> <value> → Set a module option"""
        if not self.active_module:
            print(Fore.YELLOW + "[!] No module equipped. Use 'equip <module>' first." + Style.RESET_ALL)
            return

        parts = arg.split(None, 1)
        if len(parts) < 2:
            print(Fore.YELLOW + "[!] Usage: set <option> <value>" + Style.RESET_ALL)
            return

        key, raw_value = parts[0].strip(), parts[1].strip()

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
        spider_result = self.results.get("spider")
        if spider_result and "spider_intel" not in runtime_options:
            runtime_options["spider_intel"] = spider_result.get("intel", {})

        # ── Cookie raw-token detection warning ────────────────
        raw_cookie_val = self.target_context.get("cookies") or runtime_options.get("cookie")
        if raw_cookie_val and isinstance(raw_cookie_val, str) and "=" not in raw_cookie_val:
            print(Style.BRIGHT + Fore.YELLOW + "[•] Session token detected (auto-mapped)" + Style.RESET_ALL)

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
                emit=self,
                options=runtime_options
            )
        except Exception as e:
            print(Style.BRIGHT + Fore.RED + f"[✖] Strike failed: {e}" + Style.RESET_ALL)
            return

        if result:
            self.results[self.active_module.lower()] = result
            print(Style.BRIGHT + Fore.GREEN + f"\n[✔] Strike complete. Intel stored under '{self.active_module.lower()}'." + Style.RESET_ALL)
            print(Fore.CYAN + "    Use 'loot' to view results or 'howl' for suggestions.\n" + Style.RESET_ALL)
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

            # 1️⃣ Direct risk
            module_risk += output.get("risk_score", 0)

            # 2️⃣ Standard intel risk (Spider style)
            module_risk += intel.get("risk_score", 0)
            # ==============================
            # ENDPOINT INTELLIGENCE (NEW)
            # ==============================

            endpoints = intel.get("endpoints", [])

            for ep in endpoints:

                # Parameter-sensitive endpoints (high priority)
                if ep.get("parameter_sensitive"):
                    module_risk += 5

                # Auth-required endpoints (BAC / IDOR potential)
                if ep.get("auth_required"):
                    module_risk += 2

                # Confidence weighting
                conf = ep.get("confidence_label")

                if conf == "CONFIRMED":
                    module_risk += 3
                elif conf == "HIGH":
                    module_risk += 2
                elif conf == "MEDIUM":
                    module_risk += 1

                # Parameter count (attack surface size)
                params = ep.get("params", {})
                param_count = sum(len(v) for v in params.values())

                if param_count >= 3:
                    module_risk += 2
                elif param_count > 0:
                    module_risk += 1
            # 3️⃣ BAC nested risk
            if "bac" in intel and isinstance(intel["bac"], dict):
                bac_data = intel["bac"]
                module_risk += bac_data.get("risk_score", 0)
                total_vulns += len(bac_data.get("findings", []))

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

            intel     = output.get("intel", {})
            raw_stats = output.get("raw", "")
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

            # ── Shared severity helper (used by both paths) ─────
            def _sev_color(sev):
                s = sev.upper()
                if s == "CRITICAL": return Fore.MAGENTA + Style.BRIGHT
                if s == "HIGH":     return Fore.RED     + Style.BRIGHT
                if s == "MEDIUM":   return Fore.YELLOW  + Style.BRIGHT
                return Fore.WHITE

            def _render_findings(findings, label="Vulnerabilities"):
                """Render any list of finding dicts, sorted by severity."""
                if not findings:
                    return
                sev_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                sorted_f = sorted(
                    [f for f in findings if isinstance(f, dict)],
                    key=lambda x: sev_weight.get(x.get("severity", "info").lower(), 99)
                )
                if not sorted_f:
                    return
                print(Fore.MAGENTA + f"  [{label}]" + Style.RESET_ALL)
                for f in sorted_f:
                    sev   = f.get("severity", "info").upper()
                    name  = f.get("type", f.get("vulnerability", f.get("name", "Finding")))
                    url   = f.get("url",   f.get("endpoint", ""))
                    proof = f.get("proof", f.get("evidence", ""))
                    sc2   = _sev_color(sev)
                    print(f"    {Style.BRIGHT}[{sc2}{sev}{Style.RESET_ALL}] {Fore.WHITE}{name}")
                    if url:
                        print(f"       {Fore.WHITE}url   : {Fore.CYAN}{url}{Style.RESET_ALL}")
                    if proof:
                        ps = str(proof)
                        print(f"       {Fore.WHITE}proof : {Fore.WHITE}{ps[:120]}{'...' if len(ps)>120 else ''}{Style.RESET_ALL}")
                    poc_curl    = f.get("poc_curl", "")
                    poc_browser = f.get("poc_browser", "")
                    if poc_curl:
                        print(f"       {Fore.WHITE}curl  : {Fore.YELLOW}{poc_curl}{Style.RESET_ALL}")
                    if poc_browser:
                        print(f"       {Fore.WHITE}open  : {Fore.CYAN}{poc_browser}{Style.RESET_ALL}")
                    print()

            # ── Try module-declared renderer first ──────────────
            # Only load the module for THIS iteration key.
            # Never fall back to self.active_module — that may be
            # a completely different module, causing wrong sections
            # to render and real sections to silently disappear.
            mod_obj       = self._load_module(mod_clean)
            loot_sections = getattr(mod_obj, "LOOT_SECTIONS", None) if mod_obj else None

            if loot_sections:
                for section in loot_sections:
                    title    = section.get("title", "")
                    key      = section.get("key", "")
                    renderer = section.get("type", "list")
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

                    else:  # "list"
                        for item in (data if isinstance(data, list) else [data]):
                            if isinstance(item, dict):
                                url = item.get("url", item.get("path", str(item)))
                                print(f"    {Fore.WHITE}• {url}")
                            else:
                                print(f"    {Fore.WHITE}• {item}")
                        print()

            else:
                # ── Universal fallback ───────────────────────────
                # Checks every known findings key so no module
                # silently renders blank regardless of intel shape.

                rendered_something = False

                # 1. Standard vulnerabilities key
                vulns = intel.get("vulnerabilities", [])
                if vulns:
                    _render_findings(vulns)
                    rendered_something = True

                # 2. bac nested block (BACdetector)
                if "bac" in intel and isinstance(intel["bac"], dict):
                    bac      = intel["bac"]
                    findings = bac.get("findings", [])
                    summary  = bac.get("summary", {})
                    if summary:
                        print(Fore.MAGENTA + "  [Access Control Summary]" + Style.RESET_ALL)
                        for sev in ("Critical", "High", "Medium", "Low", "Info"):
                            cnt = summary.get(sev, 0)
                            if cnt:
                                print(f"    {_sev_color(sev)}{sev:<8}{Style.RESET_ALL} : {cnt}")
                        print()
                    if findings:
                        # Normalise key names — BAC uses "vulnerability", fallback uses "name"
                        normed = []
                        for f in findings:
                            if isinstance(f, dict):
                                normed.append({
                                    "severity":    f.get("severity", "info"),
                                    "name":        f.get("vulnerability", f.get("name", "Finding")),
                                    "url":         f.get("endpoint", f.get("url", "")),
                                    "proof":       f.get("proof", ""),
                                    "poc_curl":    f.get("poc_curl", ""),
                                    "poc_browser": f.get("poc_browser", ""),
                                })
                        _render_findings(normed, "Access Control Findings")

                # 3. endpoints (Spider / any recon module)
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
                            for e in sensitive[:10]:
                                print(f"      {Fore.CYAN}{e['url']}{Style.RESET_ALL}")
                        if auth_walls:
                            print(Fore.YELLOW + f"    Auth-Walled ({len(auth_walls)})" + Style.RESET_ALL)
                            for e in auth_walls[:10]:
                                print(f"      {Fore.CYAN}{e['url']}{Style.RESET_ALL}")
                        print()

                    print(Fore.MAGENTA + f"  [Attack Surface — {len(cluster_map)} endpoints]" + Style.RESET_ALL)
                    for ep in list(cluster_map.values())[:50]:
                        tags = []
                        if ep["confidence"] in ("HIGH","CONFIRMED"): tags.append(ep["confidence"])
                        if ep["auth"]:      tags.append("AUTH")
                        if ep["sensitive"]: tags.append("SENS")
                        tag_str    = (Fore.RED + f"[{'|'.join(tags)}]" + Style.RESET_ALL) if tags else ""
                        method_str = "|".join(sorted(ep["methods"]))
                        print(f"    {Fore.WHITE}{method_str:<10}{Style.RESET_ALL} {Fore.WHITE}{ep['url']} {tag_str}")
                    if len(cluster_map) > 50:
                        print(Fore.WHITE + f"    ... +{len(cluster_map)-50} more (use loot --json)" + Style.RESET_ALL)
                    print()

                # 4. secrets
                secrets = intel.get("secrets", [])
                if secrets:
                    print(Fore.MAGENTA + f"  [Secrets — {len(secrets)}]" + Style.RESET_ALL)
                    by_type = {}
                    for s in secrets:
                        by_type[s.get("type","unknown")] = by_type.get(s.get("type","unknown"),0)+1
                    for t, c in by_type.items():
                        print(f"    {Fore.YELLOW}{t:<20}{Style.RESET_ALL} × {c}")
                    print()

                # 5. cors_issues
                cors = intel.get("cors_issues", [])
                if cors:
                    print(Fore.MAGENTA + f"  [CORS Issues — {len(cors)}]" + Style.RESET_ALL)
                    for c in cors[:5]:
                        print(f"    {Fore.CYAN}{c.get('url','')} {Fore.YELLOW}({c.get('severity','')}){Style.RESET_ALL}")
                    if len(cors) > 5:
                        print(Fore.WHITE + f"    ... +{len(cors)-5} more" + Style.RESET_ALL)
                    print()

                # 6. sourcemaps
                sourcemaps = intel.get("sourcemaps", [])
                if sourcemaps:
                    print(Fore.MAGENTA + f"  [Source Maps — {len(sourcemaps)}]" + Style.RESET_ALL)
                    for sm in sourcemaps:
                        print(f"    {Fore.CYAN}{sm.get('url',sm)}{Style.RESET_ALL}")
                    print()

                # 7. Generic list keys not already handled — future-proof catch-all
                known_keys = {"vulnerabilities","bac","endpoints","secrets",
                              "cors_issues","sourcemaps","summary","stats",
                              "tech_stack","robots_paths","graphql","openapi","metadata"}
                for key, val in intel.items():
                    if key in known_keys or not val:
                        continue
                    if isinstance(val, list) and val:
                        print(Fore.MAGENTA + f"  [{key}]" + Style.RESET_ALL)
                        for item in val[:20]:
                            if isinstance(item, dict):
                                url = item.get("url", item.get("path", item.get("name", "")))
                                extra = {k:v for k,v in item.items() if k not in ("url","path","name")}
                                line = f"    {Fore.WHITE}• {url or json.dumps(item, default=str)[:80]}"
                                if extra: line += Fore.WHITE + f"  {json.dumps(extra, default=str)[:60]}"
                                print(line + Style.RESET_ALL)
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
                               e.get("parameter_sensitive"),
                               e.get("auth_required")), reverse=True)
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

        # ── Import structured report ──────────────────────────
        try:
            from hellhound.core.suggest import suggest_report
            report = suggest_report(self.results)
        except ImportError:
            # Legacy fallback: suggest_actions returns List[str]
            from hellhound.core.suggest import suggest_actions
            lines = suggest_actions(self.results)
            print(Fore.RED + Style.BRIGHT + "\n[ Howl — Intelligence Correlation Engine ]\n" + Style.RESET_ALL)
            for l in lines:
                print(f"  {Fore.CYAN}{l}{Style.RESET_ALL}")
            return

        # ── Color constants ───────────────────────────────────
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
        R          = Style.RESET_ALL

        CONF_COLORS = {
            "confirmed": Fore.RED    + Style.BRIGHT,
            "strong":    Fore.YELLOW + Style.BRIGHT,
            "likely":    Fore.CYAN   + Style.BRIGHT,
            "possible":  Fore.WHITE,
        }

        W = 62  # inner content width

        def _section_head(title, color=None):
            color = color or C_HEAD
            side  = "─" * 3
            pad   = max(0, W - len(title) - 8)
            print(f"\n  {C_BORDER}{side}{R} {color}{title}{R} {C_BORDER}{side + '─' * pad}{R}")

        def _priority_badge(s):
            plabel = s.priority_label
            if plabel == "CRITICAL":
                return C_CRITICAL + "[CRIT]" + R
            elif plabel == "HIGH":
                return C_HIGH + "[HIGH]" + R
            elif plabel == "MEDIUM":
                return C_MEDIUM + "[MED] " + R
            else:
                return C_LOW + "[LOW] " + R

        def _conf_inline(s):
            """Short coloured confidence tag for inline display."""
            cc = CONF_COLORS.get(s.confidence, Fore.WHITE)
            bar = cc + s.confidence_bar + R
            tag = cc + s.confidence + R
            return f"{bar} {tag}"

        def _print_suggestion(s, index=None):
            badge = _priority_badge(s)

            # Step counter or chain bullet
            if index is not None:
                prefix = f"{C_STEP}[{index:02d}]{R}"
            else:
                prefix = f"{C_CHAIN}  +--{R}"

            # ── Action line with inline badge ──────────────────
            print(f"  {prefix} {badge}  {C_LABEL}{s.action}{R}")

            # ── Why ────────────────────────────────────────────
            print(f"       {C_DIM}why        {R}{s.reason}")

            # ── Confidence ─────────────────────────────────────
            print(f"       {C_DIM}confidence {R}{_conf_inline(s)}")

            # ── Evidence — URLs get URL colour, others get evidence colour ──
            for ev in s.evidence:
                ev = ev.strip()
                if not ev:
                    continue
                if ev.startswith("http"):
                    print(f"       {C_DIM}evidence   {R}{C_URL}{ev}{R}")
                else:
                    print(f"       {C_DIM}evidence   {R}{C_EVIDENCE}{ev}{R}")

            # ── Chain label ────────────────────────────────────
            if s.chain:
                print(f"       {C_DIM}chain      {R}{C_CHAIN}{s.chain}{R}")

        def _print_optional(s):
            conf_c = CONF_COLORS.get(s.confidence, Fore.WHITE)
            badge  = _priority_badge(s)
            print(f"  {C_MEDIUM}  [+]{R} {badge}  {Fore.WHITE + Style.BRIGHT}{s.action}{R}")
            print(f"       {C_DIM}why        {R}{s.reason}")
            print(f"       {C_DIM}confidence {R}{_conf_inline(s)}")
            for ev in s.evidence[:3]:
                ev = ev.strip()
                if not ev:
                    continue
                if ev.startswith("http"):
                    print(f"       {C_DIM}evidence   {R}{C_URL}{ev}{R}")
                else:
                    print(f"       {C_DIM}evidence   {R}{C_EVIDENCE}{ev}{R}")
            if s.chain:
                print(f"       {C_DIM}chain      {R}{C_CHAIN}{s.chain}{R}")

        def _print_skip(s):
            print(f"  {C_SKIP}  [-] {s.action:<30}  {s.reason}{R}")

        # ── Header banner ─────────────────────────────────────
        print()
        print(C_BORDER + "  " + "═" * W + R)
        inner = "HELLHOUND  —  HOWL  ENGINE"
        title_pad = (W - len(inner)) // 2
        print(C_BORDER + "  ║" + " " * title_pad
              + Fore.WHITE + Style.BRIGHT + inner
              + " " * (W - title_pad - len(inner) - 2) + C_BORDER + "║" + R)
        print(C_BORDER + "  " + "═" * W + R)

        # ── Session context block ─────────────────────────────
        if report.ran_modules:
            mods_str = "  ".join(m.upper() for m in sorted(report.ran_modules))
            print(f"\n  {C_LABEL}Modules analysed:{R}  {C_EVIDENCE}{mods_str}{R}")

        # Quick risk tally line
        n_crit  = sum(1 for s in report.critical_path if s.priority_label == "CRITICAL")
        n_high  = sum(1 for s in report.critical_path if s.priority_label == "HIGH")
        n_chain = len(report.chains)
        print(
            f"  {C_LABEL}Session risk:{R}  "
            f"{C_CRITICAL}{n_crit} critical{R}  "
            f"{C_HIGH}{n_high} high{R}  "
            f"{C_CHAIN}{n_chain} chain(s){R}"
        )

        # ── Confirmed attack chains (top — operator sees them first) ──
        if report.attack_chains:
            _section_head("CONFIRMED CHAINS", C_CHAIN)
            print(f"  {C_DIM}End-to-end exploitation paths proven this session.{R}\n")
            for chain in report.attack_chains:
                print(f"  {C_CHAIN}  [⚡]{R} {Fore.WHITE + Style.BRIGHT}{chain}{R}")
            print()

        # ── Critical Path ─────────────────────────────────────
        if report.critical_path:
            _section_head("CRITICAL PATH", C_CRITICAL)
            print(f"  {C_DIM}Run these. In this order. Do not skip.{R}\n")
            for i, s in enumerate(report.critical_path, 1):
                _print_suggestion(s, index=i)
                print()
        else:
            _section_head("CRITICAL PATH", C_CRITICAL)
            print(f"  {C_DIM}No critical-path findings yet.{R}")

        # ── Attack Chains ─────────────────────────────────────
        if report.chains:
            _section_head("ATTACK CHAINS", C_CHAIN)
            print(f"  {C_DIM}Cross-module correlations — multi-step exploitation paths.{R}\n")
            for s in report.chains:
                _print_suggestion(s)
                print()

        # ── Optional Intel ────────────────────────────────────
        if report.optional_intel:
            _section_head("OPTIONAL INTEL", C_MEDIUM)
            print(f"  {C_DIM}Useful context — pursue when critical path is done.{R}\n")
            for s in report.optional_intel:
                _print_optional(s)
                print()

        # ── Skip List ─────────────────────────────────────────
        if report.skip_list:
            _section_head("SKIP FOR NOW", C_SKIP)
            print(f"  {C_DIM}Not recommended — reason given for each.{R}\n")
            for s in report.skip_list:
                _print_skip(s)
            print()

        # ── Footer ────────────────────────────────────────────
        print(C_BORDER + "\n  " + "─" * W + R)
        print(
            f"  {C_DIM}Critical/High:{R} {C_CRITICAL}{len(report.critical_path)}{R}"
            f"  {C_DIM}Chains:{R} {C_CHAIN}{len(report.chains)}{R}"
            f"  {C_DIM}Optional:{R} {C_MEDIUM}{len(report.optional_intel)}{R}"
            f"  {C_DIM}Skipped:{R} {C_SKIP}{len(report.skip_list)}{R}"
        )
        print(C_BORDER + "  " + "─" * W + R + "\n")

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