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

    prompt  = Fore.LIGHTRED_EX + "hellhound" + Fore.LIGHTBLACK_EX + "@" + Fore.RED + "core" + Fore.LIGHTBLACK_EX + ":~# " + Style.RESET_ALL
    boot_lines = [
        ("hellhound --init",          Fore.LIGHTBLACK_EX + "  Initialising HELLHOUND framework v12.0"),
        ("hellhound --load-modules",  Fore.LIGHTBLACK_EX + "  Modules loaded: recon, vuln, exploit, intel, analysis"),
        ("hellhound --verify-chain",  Fore.LIGHTBLACK_EX + "  Engine ✓  Emit ✓  Session ✓  Loot ✓"),
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
            color = Fore.RED + Style.DIM
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
        """arsenal → List web modules"""

        print("\n[ Arsenal — WEB MODULES ]\n")

        for name, meta in sorted(self.modules.items()):
            print(f"  {name:<12} - {meta['description']}")

        print()

    def _load_module(self, module_name):
        for category in ["recon", "analysis", "exploit", "intel"]:
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
            print(f"  {Fore.LIGHTBLACK_EX}Target   {Style.RESET_ALL}: {Fore.WHITE}{self.target}")
            print(f"  {Fore.LIGHTBLACK_EX}Modules  {Style.RESET_ALL}: {Fore.WHITE}{len(self.results)}")
            print(f"  {Fore.LIGHTBLACK_EX}Risk     {Style.RESET_ALL}: {lc}{total_risk} — {level}{Style.RESET_ALL}")
            print(f"  {Fore.LIGHTBLACK_EX}Issues   {Style.RESET_ALL}: {Fore.WHITE}{total_vulns}")
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
                  Style.RESET_ALL + Fore.LIGHTBLACK_EX + f"  risk={sc}{mod_score}{Style.RESET_ALL}")
            print(Fore.RED + "  └─────────────────────────────────────" + Style.RESET_ALL)

            if raw_stats:
                print(Fore.LIGHTBLACK_EX + f"  {raw_stats}" + Style.RESET_ALL)
            print()

            # ── Try module-declared renderer first ──────────────
            mod_obj = self._load_module(mod_clean) or self._load_module(self.active_module or "")
            loot_sections = getattr(mod_obj, "LOOT_SECTIONS", None) if mod_obj else None

            if loot_sections:
                # Module exports LOOT_SECTIONS = list of dicts describing what to render
                # Each section: {"title": str, "key": str, "type": "list"|"findings"|"table"|"kv"}
                for section in loot_sections:
                    title    = section.get("title", "")
                    key      = section.get("key", "")
                    renderer = section.get("type", "list")
                    data     = intel.get(key)

                    if not data:
                        continue

                    print(Fore.MAGENTA + f"  [{title}]" + Style.RESET_ALL)

                    if renderer == "findings":
                        # Standard vuln findings list
                        sev_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                        sorted_findings = sorted(
                            data if isinstance(data, list) else [],
                            key=lambda x: sev_weight.get(x.get("severity", "info").lower(), 99)
                        )
                        for f in sorted_findings:
                            sev  = f.get("severity", "info").upper()
                            name = f.get("type", f.get("vulnerability", f.get("name", "Unknown")))
                            url  = f.get("url", f.get("endpoint", ""))
                            proof= f.get("proof", f.get("evidence", ""))
                            sc2  = (Fore.MAGENTA if sev == "CRITICAL" else
                                    Fore.RED     if sev == "HIGH"     else
                                    Fore.YELLOW  if sev == "MEDIUM"   else Fore.WHITE)
                            print(f"    {Style.BRIGHT}[{sc2}{sev}{Style.RESET_ALL}] {Fore.WHITE}{name}")
                            if url:   print(f"       {Fore.LIGHTBLACK_EX}url   : {Fore.CYAN}{url}{Style.RESET_ALL}")
                            if proof: print(f"       {Fore.LIGHTBLACK_EX}proof : {Fore.LIGHTBLACK_EX}{str(proof)[:120]}{Style.RESET_ALL}")
                            print()

                    elif renderer == "table":
                        # List of dicts — print as key:value rows
                        for row in (data if isinstance(data, list) else []):
                            if isinstance(row, dict):
                                for k, v in row.items():
                                    print(f"    {Fore.CYAN}{k:<16}{Style.RESET_ALL} {v}")
                                print()
                            else:
                                print(f"    {Fore.WHITE}{row}")

                    elif renderer == "kv":
                        # Single dict
                        if isinstance(data, dict):
                            for k, v in data.items():
                                print(f"    {Fore.CYAN}{k:<20}{Style.RESET_ALL} {v}")
                        print()

                    else:  # "list" — plain list of strings or simple items
                        for item in (data if isinstance(data, list) else [data]):
                            if isinstance(item, dict):
                                url = item.get("url", item.get("path", str(item)))
                                print(f"    {Fore.WHITE}• {url}")
                            else:
                                print(f"    {Fore.WHITE}• {item}")
                        print()

            else:
                # ── Generic fallback — works for ANY intel shape ─
                # Renders whatever keys exist without module-specific knowledge.

                # 1. vulnerabilities / findings (standard key)
                vulns = intel.get("vulnerabilities", [])
                if vulns:
                    print(Fore.MAGENTA + "  [Vulnerabilities]" + Style.RESET_ALL)
                    sev_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                    for f in sorted(vulns, key=lambda x: sev_weight.get(
                            x.get("severity", "info").lower() if isinstance(x, dict) else "info", 99)):
                        if isinstance(f, dict):
                            sev  = f.get("severity", "info").upper()
                            name = f.get("type", f.get("vulnerability", f.get("name", "Finding")))
                            url  = f.get("url", f.get("endpoint", ""))
                            proof= f.get("proof", f.get("evidence", ""))
                            sc2  = (Fore.MAGENTA if sev == "CRITICAL" else
                                    Fore.RED     if sev == "HIGH"     else
                                    Fore.YELLOW  if sev == "MEDIUM"   else Fore.WHITE)
                            print(f"    {Style.BRIGHT}[{sc2}{sev}{Style.RESET_ALL}] {Fore.WHITE}{name}")
                            if url:   print(f"       {Fore.LIGHTBLACK_EX}url   : {Fore.CYAN}{url}{Style.RESET_ALL}")
                            if proof: print(f"       {Fore.LIGHTBLACK_EX}proof : {Fore.LIGHTBLACK_EX}{str(proof)[:120]}{Style.RESET_ALL}")
                            print()
                        else:
                            print(f"    {Fore.WHITE}• {f}")
                    print()

                # 2. bac nested block (BACdetector legacy)
                if "bac" in intel and isinstance(intel["bac"], dict):
                    bac      = intel["bac"]
                    findings = bac.get("findings", [])
                    summary  = bac.get("summary", {})
                    if summary:
                        print(Fore.MAGENTA + "  [Access Control Summary]" + Style.RESET_ALL)
                        for sev in ("Critical", "High", "Medium", "Low", "Info"):
                            if sev in summary:
                                sc2 = (Fore.RED if sev in ("Critical","High") else
                                       Fore.YELLOW if sev == "Medium" else Fore.WHITE)
                                print(f"    {sc2}{sev:<8} : {summary[sev]}{Style.RESET_ALL}")
                        print()
                    if findings:
                        print(Fore.MAGENTA + "  [Access Control Findings]" + Style.RESET_ALL)
                        sev_weight = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
                        for f in sorted(findings, key=lambda x: sev_weight.get(x.get("severity","Info"),99)):
                            sev  = f.get("severity","Unknown").upper()
                            name = f.get("vulnerability","Unknown")
                            ep   = f.get("endpoint","")
                            sc2  = (Fore.MAGENTA if sev=="CRITICAL" else
                                    Fore.RED if sev=="HIGH" else
                                    Fore.YELLOW if sev=="MEDIUM" else Fore.WHITE)
                            print(f"    [{sc2}{sev}{Style.RESET_ALL}] {Fore.WHITE}{name}")
                            if ep: print(f"       {Fore.LIGHTBLACK_EX}endpoint : {Fore.CYAN}{ep}{Style.RESET_ALL}")
                            print()

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
                        print(f"    {Fore.LIGHTBLACK_EX}{method_str:<10}{Style.RESET_ALL} {Fore.WHITE}{ep['url']} {tag_str}")
                    if len(cluster_map) > 50:
                        print(Fore.LIGHTBLACK_EX + f"    ... +{len(cluster_map)-50} more (use loot --json)" + Style.RESET_ALL)
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
                        print(Fore.LIGHTBLACK_EX + f"    ... +{len(cors)-5} more" + Style.RESET_ALL)
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
                                if extra: line += Fore.LIGHTBLACK_EX + f"  {json.dumps(extra, default=str)[:60]}"
                                print(line + Style.RESET_ALL)
                            else:
                                print(f"    {Fore.WHITE}• {item}{Style.RESET_ALL}")
                        if len(val) > 20:
                            print(Fore.LIGHTBLACK_EX + f"    ... +{len(val)-20} more" + Style.RESET_ALL)
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
            print("[!] No intelligence collected yet.")
            return

        suggestions = suggest_actions(self.results)

        print("\n[ Howl — Intelligence Correlation Engine ]\n")

        for s in suggestions:
            print(f"  → {s}")

        print("\n==========================================================\n")

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
        print(Fore.LIGHTBLUE_EX + f"[*] {msg}" + Style.RESET_ALL)

    def success(self, msg):
        print(Fore.GREEN + f"[✓] {msg}" + Style.RESET_ALL)

    def warn(self, msg):
        print(Fore.YELLOW + f"[!] {msg}" + Style.RESET_ALL)

    def always_info(self, msg):
        print(Fore.BLUE + msg + Style.RESET_ALL)

    def always_success(self, msg):
        if "Target:" in msg:
            msg = msg.replace("High:", Fore.RED + "High:" + Style.RESET_ALL + Fore.GREEN)
            msg = msg.replace("Secrets:", Fore.MAGENTA + "Secrets:" + Style.RESET_ALL + Fore.GREEN)
            msg = msg.replace("Param-Sensitive:", Fore.YELLOW + "Param-Sensitive:" + Style.RESET_ALL + Fore.GREEN)
        print(Fore.GREEN + f"[✓] {msg}" + Style.RESET_ALL)

    def error(self, msg):
        print(Fore.RED + f"[x] {msg}" + Style.RESET_ALL)

    def section(self, title):
        print(Fore.MAGENTA + f"\n  ── {title} ──" + Style.RESET_ALL)

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
        """Show Hellhound command manual"""
        print("""
Documented commands:
=====================
prey      → Set target (lock onto a host)
nmap      → Run reconnaissance scan
arsenal   → List available tools
equip     → Select a tool/module
strike    → Execute selected tool
howl      → Get suggested next actions
loot      → View gathered results
release   → Exit tool mode
exit      → Exit console
auto      → Intelligent attack chain
clear     → Clear the console screen
status    → Show framework status
sessions  → List previous hunts
report    → Export full intelligence report to storage

Aliases:
=====================
hunt <ip>     → prey <ip>
use <module>  → equip <module>
run           → strike
back          → release
ls            → arsenal
results       → loot
quit / q      → exit
cls           → clear
""")

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