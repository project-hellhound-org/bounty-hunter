import cmd
import yaml
import importlib.resources as pkg_resources
import os
import time
import sys
import random

from colorama import Fore, Style, init
init(autoreset=True)

from hellhound.core.engine import HellhoundEngine
from hellhound.core.suggest import suggest_actions

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
                # Dynamically import module
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

    intro = r"""
     ██╗  ██╗███████╗██╗     ██╗     ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
     ██║  ██║██╔════╝██║     ██║     ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
     ███████║█████╗  ██║     ██║     ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
     ██╔══██║██╔══╝  ██║     ██║     ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
     ██║  ██║███████╗███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 

              Hellhound Pentest Framework v1.0
        Modular Red-Team Assistant | CLI + Dashboard Mode
                  Developed by Team Hellhound

Type 'help' to view available commands.
"""

    prompt = Fore.RED + "hellhound > " + Style.RESET_ALL

    # ----------------------------
    # Init
    # ----------------------------
    def __init__(self):
        super().__init__()
        self.target = None
        self.target_type = None   # host | web
        self.engine = HellhoundEngine(socketio=None)
        self.results = {}
        self.active_module = None
        self.modules = load_modules()

        # ----------------------------
        # Module Flag Registry
        # ----------------------------
        self.MODULE_FLAGS = {
            "nmap": {
                "--fast": {"mode": "quick"},
                "--full": {"mode": "full"},
                "--udp": {"mode": "udp"},
                "--vuln": {"mode": "vuln"},
                "--stealth": {"mode": "stealth"},
            },
            "ftp": {
                "--enum": {"mode": "enum"},
                "--brute": {"mode": "bruteforce"},
            },
            "ssh": {
                "--enum": {"mode": "enum"},
                "--brute": {"mode": "bruteforce"},
            },
            "dirsearch": {
                "--deep": {"mode": "deep"}
            },
            "nuclei": {
                "--critical": {"severity": "critical"}
            }
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

        self.quotes = [
            "The prey never knows when the hunt begins.",
            "No firewall outruns a hungry hound.",
            "Silence means enumeration succeeded.",
            "If it’s listening, it’s already too late.",
            "Packets don’t lie. Targets do.",
            "Every open port is a broken promise.",
            "The hunt starts before the scan."
        ]


    # ----------------------------
    # Hackeristic Boot Sequence (UNCHANGED)
    # ----------------------------
    def preloop(self):
        os.system("clear" if os.name == "posix" else "cls")

        print(Style.DIM + Fore.RED + "ACCESSING RESTRICTED MEMORY...")
        for _ in range(6):
            hex_line = " ".join([f"{random.randint(0, 255):02X}" for _ in range(16)])
            print(f"  0x{random.randint(1000, 9999):X}  {hex_line}")
            time.sleep(0.05)

        print("\n" + Fore.RED + Style.BRIGHT + "  [ SYSTEM BREACH DETECTED ]")
        self._glitch_text("INITIATING HELLHOUND PROTOCOLS...")

        print("\n" + Fore.RED + Style.BRIGHT)
        self._glitch_text(f"“{random.choice(self.quotes)}”")
        print()


    def _glitch_text(self, text):
        chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
        for char in text:
            for _ in range(3):
                sys.stdout.write(Style.DIM + Fore.RED + random.choice(chars))
                sys.stdout.flush()
                time.sleep(0.01)
            sys.stdout.write('\b\b\b' + Style.BRIGHT + Fore.RED + char)
            sys.stdout.flush()
            time.sleep(0.02)
        print(Style.RESET_ALL)

    # ============================
    # CORE COMMANDS
    # ============================

    def do_prey(self, arg):
        """prey <ip|domain> → Lock onto a target"""

        if not arg.strip():
            print("Usage: prey <ip | domain>")
            return

        self.target = arg.strip()

        print("\nWhat kind of prey is this?")
        print("  [1] Full machine / host (CTF, server, network)")
        print("  [2] Web application / domain\n")

        choice = input("Select type [1/2]: ").strip()

        if choice == "1":
            self.target_type = "host"
            print(Fore.GREEN + f"[+] Prey locked as FULL MACHINE: {self.target}")

        elif choice == "2":
            self.target_type = "web"
            print(Fore.GREEN + f"[+] Prey locked as WEB APPLICATION: {self.target}")

        else:
            print(Fore.RED + "[!] Invalid choice. Prey not set.")
            self.target = None
            self.target_type = None
            return

        print(Fore.GREEN + f"[+] Prey acquired: {self.target} ({self.target_type.upper()})")

    def do_exit(self, arg):
        """exit → Leave console"""
        print(Fore.RED + "[+] Exiting Hellhound console")
        return True

    # ============================
    # DISPLAY
    # ============================

    def do_arsenal(self, arg):
        """arsenal → List available tools"""

        print()

        # If no prey selected
        if not self.target_type:
            print("[ Arsenal — ALL MODULES ]\n")
            for name, meta in sorted(self.modules.items()):
                print(f"  {name:<12} - {meta['description']}")
            print()
            return

        print(f"[ Arsenal — {self.target_type.upper()} ]\n")

        for name, meta in sorted(self.modules.items()):
            category = meta.get("category", "")

            # WEB prey
            if self.target_type == "web":
                # Allow web + recon + network + nmap
                if category in ["web", "recon", "network"] or name == "nmap":
                    print(f"  {name:<12} - {meta['description']}")

            # HOST prey
            elif self.target_type == "host":
                # Host sees everything
                print(f"  {name:<12} - {meta['description']}")

        print()




    def do_hunt(self, arg):
            """
            hunt → Intelligent, automated attack chain.
            Runs Nmap, analyzes results, and strikes automatically.
            """
            if not self.target:
                print("[!] No prey set. Use: prey <target>")
                return

            from hellhound.core.strategies import HUNT_RULES

            print(Fore.YELLOW + "\n[!] HUNT MODE ENGAGED")
            print(Fore.YELLOW + "[*] Phase 1: Reconnaissance (Nmap)")

            # 1. Run Nmap (Fast + Version detection for speed)
            nmap_result = self.engine.run_single("nmap", self.target, options={"mode": "default"})
            self.results["nmap"] = nmap_result

            # 2. Analyze Intel
            intel = nmap_result.get("intel", {})
            services = intel.get("services", {})
            found_vulns = intel.get("vulnerabilities", [])

            if not services:
                print(Fore.RED + "[!] No services found. Hunt aborted.")
                return

            print(Fore.GREEN + f"[✓] Nmap found {len(services)} services.")

            # 3. Check for immediate vulnerabilities found by Nmap scripts
            if found_vulns:
                print(Fore.RED + f"\n[!!!] CRITICAL VULNERABILITIES DETECTED:")
                for v in found_vulns:
                    print(f"    - {v['description']}")

            # 4. Plan the Attack
            print(Fore.YELLOW + "\n[*] Phase 2: Planning Attacks")
            
            attack_plan = []

            for port_proto, data in services.items():
                service_name = data.get("service", "").lower()
                
                # Find matching rule
                for rule in HUNT_RULES:
                    # Simple matching: if rule service is inside detected service
                    if rule["service"] in service_name:
                        attack_plan.append({
                            "port": port_proto,
                            "service": service_name,
                            "modules": rule["modules"],
                            "desc": rule["description"]
                        })
                        break # One rule per service is enough

            if not attack_plan:
                print("[*] No automatic attack rules match these services.")
                return

            print(f"[*] Generated Attack Plan:")
            for idx, attack in enumerate(attack_plan):
                print(f"    {idx+1}. {attack['port']} ({attack['service']}) -> {attack['desc']}")

            # 5. Execute
            print(Fore.YELLOW + "\n[*] Phase 3: The Strike")
            
            for attack in attack_plan:
                for module_name in attack["modules"]:
                    if module_name not in self.modules:
                        continue
                    
                    print(Fore.CYAN + f"\n>> Hound is striking: {module_name} on {attack['port']}")
                    
                    # GET OPTIONS FROM STRATEGY
                    module_opts = attack.get("options", {})
                    
                    try:
                        # PASS OPTIONS TO ENGINE
                        output = self.engine.run_single(module_name, self.target, options=module_opts)
                        self.results[module_name] = output
                        print(Fore.GREEN + f"[✓] {module_name} finished.")
                    except Exception as e:
                        print(Fore.RED + f"[x] {module_name} failed: {str(e)}")

    def do_loot(self, arg):
        """loot → View gathered results"""

        if not self.results:
            print(Fore.RED + "[!] No loot collected yet")
            return

        print("\n" + Fore.CYAN + "========== [ LOOT ] ==========\n")

        for mod, output in self.results.items():

            print(Fore.YELLOW + f"[{mod.upper()}]")

            # -----------------------------------------
            # 1️⃣ Structured Modules (Preferred Design)
            # -----------------------------------------
            if isinstance(output, dict) and "intel" in output:

                intel = output.get("intel", {})

                # --- NMAP STYLE ---
                if "services" in intel:
                    services = intel.get("services", {})
                    if services:
                        print(Fore.GREEN + "  Open Services:")
                        for port_proto, data in services.items():
                            service = data.get("service", "unknown")
                            product = data.get("product", "")
                            version = data.get("version", "")
                            print(
                                f"    {Fore.CYAN}{port_proto:<8} "
                                f"{Fore.WHITE}{service:<12} "
                                f"{Fore.YELLOW}{product} {version}"
                            )
                    print()

                # --- ENDPOINT STYLE (sniff, stalk, etc.) ---
                if "endpoints" in intel:
                    endpoints = intel.get("endpoints", [])
                    stats = intel.get("stats", {})

                    if stats:
                        print(Fore.GREEN + "  Attack Surface Summary:")
                        print(f"    GET  : {stats.get('get', 0)}")
                        print(f"    POST : {stats.get('post', 0)}")
                        print(f"    TOTAL: {stats.get('total', 0)}")
                        print()

                    for idx, ep in enumerate(endpoints, 1):
                        method = ep.get("method", "GET")
                        url = ep.get("url", "")

                        method_color = Fore.BLUE if method == "GET" else Fore.MAGENTA
                        print(method_color + f"  [{idx}] {method}  {url}")

                        # Parameters
                        for p in ep.get("params", []):
                            pname = p.get("name", "")
                            ptype = p.get("type", "")

                            risk_color = (
                                Fore.RED if pname.lower() in ["id", "token", "password", "uid"]
                                else Fore.WHITE
                            )

                            print(f"       - {risk_color}{pname} {Fore.YELLOW}({ptype})")

                        # Tags
                        if ep.get("tags"):
                            print(Fore.RED + f"       Tags: {', '.join(ep['tags'])}")

                        print()

                # --- JS FILES ---
                if "js_files" in intel:
                    js_files = intel.get("js_files", [])
                    if js_files:
                        print(Fore.GREEN + "  JavaScript Files:")
                        for js in js_files:
                            print(f"    - {js}")
                        print()

                # --- SIGNALS ---
                if "signals" in intel:
                    signals = intel.get("signals", [])
                    if signals:
                        print(Fore.GREEN + "  Signals:")
                        for s in signals:
                            print(f"    - {s}")
                        print()

                # --- VULNERABILITIES ---
                if "vulnerabilities" in intel:
                    vulns = intel.get("vulnerabilities", [])
                    if vulns:
                        print(Fore.RED + "  ⚠ Vulnerabilities Detected:")
                        for v in vulns:
                            print(f"    - Port {v.get('port')} | {v.get('description')}")
                        print()

            # -----------------------------------------
            # 2️⃣ Raw Text Fallback
            # -----------------------------------------
            elif isinstance(output, str):
                print(Fore.WHITE + output.strip()[:1000])
                print()

            # -----------------------------------------
            # 3️⃣ Unknown Format Fallback
            # -----------------------------------------
            else:
                print(Fore.WHITE + str(output))
                print()

        print(Fore.CYAN + "================================\n")




    # ============================
    # RECON
    # ============================

    def do_nmap(self, arg):
        """nmap → Run reconnaissance scan"""
        
        if not self.target:
            print("[!] Set prey first")
            return

        # 1. Ask user for mode (This logic belongs in the UI, not the module)
        print("\nSelect Scan Profile:")
        print("  [1] Default (Version & Scripts)")
        print("  [2] Quick (Top 100 ports)")
        print("  [3] Full (All 65535 ports)")
        print("  [4] Stealth (Syn Scan)")
        
        try:
            choice = input("Choice [1]: ").strip() or "1"
        except:
            choice = "1"

        modes = {"1": "default", "2": "quick", "3": "full", "4": "stealth"}
        selected_mode = modes.get(choice, "default")

        # 2. Call Module with options
        print(Fore.YELLOW + f"[*] Running Nmap ({selected_mode} mode)...")
        
        # Pass the mode in the options dictionary
        output = self.engine.run_single("nmap", self.target, options={"mode": selected_mode})
        
        self.results["nmap"] = output

    # ============================
    # MODULE CONTROL
    # ============================

    def do_equip(self, arg):
        """equip <module> → Select a tool"""

        if not self.target_type:
            print("[!] Set prey first using: prey <target>")
            return

        module = arg.strip()

        if module not in self.modules:
            print(f"[!] Unknown module: {module}")
            return
        self.active_module = module
        self.prompt = Fore.RED + f"hellhound({module}) > " + Style.RESET_ALL
        print(Fore.GREEN + f"[+] {module} equipped")

    def do_release(self, arg):
        """release → Exit tool mode"""
        self.active_module = None
        self.prompt = Fore.RED + "hellhound > " + Style.RESET_ALL

    def do_strike(self, arg):
        """
        strike [module] [--flags]
        Executes selected module with validated flags.
        """

        if not self.target or not self.target_type:
            print("[!] No prey set")
            return

        parts = arg.split()

        # Determine module
        module = self.active_module
        if parts and not parts[0].startswith("--"):
            module = parts[0]
            parts = parts[1:]  # Remove module name from flag parsing

        if not module:
            print("Usage: strike <module> [--flags]")
            print("       strike (if tool equipped)")
            return

        # Category-based scope enforcement
        category = self.modules[module]["category"]

        ALLOWED_FOR_WEB = {"web", "recon", "network"}

        if self.target_type == "web" and category not in ALLOWED_FOR_WEB:
            print(Fore.RED + f"[!] '{module}' not suitable for WEB targets")
            return

        # Handle help flag
        if "--help" in parts:
            self._show_module_help(module)
            return

        # Validate flags
        module_flags = self.MODULE_FLAGS.get(module, {})
        options = {}

        for flag in parts:
            if flag not in module_flags:
                print(Fore.RED + f"[!] Unsupported flag '{flag}' for module '{module}'")
                return

            # Merge mapped options
            options.update(module_flags[flag])

        print(Fore.YELLOW + f"[*] Executing {module}...")
        output = self.engine.run_single(module, self.target, options=options if options else None)
        self.results[module] = output

    def _show_module_help(self, module):
        print(f"\n[ Help — {module} ]")

        flags = self.MODULE_FLAGS.get(module, {})
        if not flags:
            print("  No flags available.")
            return

        for flag in flags:
            print(f"  {flag}")

        print()


    # ============================
    # INTELLIGENCE
    # ============================

    def do_howl(self, arg):
        """howl → Correlated intelligent attack suggestions"""

        if not self.results:
            print("[!] No intelligence collected yet.")
            return

        suggestions = suggest_actions(self.results)

        print("\n[ Howl — Intelligence Correlation Engine ]\n")

        for s in suggestions:
            print(f"  → {s}")

        print()

    # ============================
    # SYSTEM
    # ============================

    def do_clear(self, arg):
        """clear → Clear the screen"""
        os.system("clear" if os.name == "posix" else "cls")

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
