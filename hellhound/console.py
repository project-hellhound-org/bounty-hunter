import cmd
import yaml
import importlib.resources as pkg_resources
import os
import time

from colorama import Fore, init
init(autoreset=True)

from hellhound.core.engine import HellhoundEngine
from hellhound.core.suggest import suggest_actions


# ----------------------------
# Load modules from config.yaml
# ----------------------------
def load_modules():
    try:
        with pkg_resources.files("hellhound").joinpath("config.yaml").open("r") as f:
            return yaml.safe_load(f).get("modules", {})
    except Exception:
        return {}


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

    prompt = "hellhound > "

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
        self.MODULE_SCOPE = {
            "host": {
                "nmap", "ftp", "ssh"
            },
            "web": {
                "nmap", "vhost", "dirsearch", "nikto", "nuclei"
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
    # Startup animation
    # ----------------------------
    def preloop(self):
        import random

        self._stage("Awakening Hellhound core", "CORE ONLINE")
        self._stage("Loading weapon modules", f"{len(self.modules)} TOOLS ARMED")
        self._stage("Calibrating intelligence engine", "PREDICTION READY")
        self._stage("Sniffing network scent", "PREY DETECTION ENABLED")
        self._stage("Releasing restraints", "LEASH REMOVED")

        print(Fore.RED + f"\n“{random.choice(self.quotes)}”\n")
        print(Fore.GREEN + "[✓] Console ready\n")


    def _stage(self, text, result, delay=0.9):
        dots = ""
        for i in range(3):
            dots += "."
            print(Fore.CYAN + f"\r[*] {text}{dots}", end="")
            time.sleep(delay / 3)

        print(Fore.GREEN + f"\r[✓] {text:<35} {result}")



    def _loading(self, text, delay=1.2):
        for i in range(3):
            print(Fore.CYAN + f"\r{text}" + "." * (i + 1), end="")
            time.sleep(delay / 3)
        print()

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
        print("[+] Exiting Hellhound console")
        return True

    # ============================
    # DISPLAY
    # ============================

    def do_arsenal(self, arg):
        """arsenal → List available tools"""
        print("\n[ Arsenal ]")
        for name, meta in self.modules.items():
            desc = meta.get("description", "No description")
            print(f"  {name:<12} - {desc}")
        print()

    def do_loot(self, arg):
        """loot → View gathered results"""
        if not self.results:
            print("[!] No loot collected yet")
            return

        print("\n[ Loot ]")
        for mod, output in self.results.items():
            print(f"\n[{mod.upper()}]")
            print(output[:500] if isinstance(output, str) else output)

    # ============================
    # RECON
    # ============================

    def do_nmap(self, arg):
        """nmap → Run reconnaissance scan"""

        if not self.target:
            print("[!] Set prey first")
            return

        print(Fore.YELLOW + "[*] Running Nmap...")
        output = self.engine.run_single("nmap", self.target)
        self.results["nmap"] = output

    # ============================
    # MODULE CONTROL
    # ============================

    def do_equip(self, arg):
        """equip <module> → Select a tool"""

        if not self.target or not self.target_type:
            print("[!] Set prey first using: prey <target>")
            return

        module = arg.strip()
        if module not in self.modules:
            print(f"[!] Unknown module: {module}")
            return

        allowed = self.MODULE_SCOPE.get(self.target_type, set())
        if module not in allowed:
            print(Fore.RED + f"[!] Module '{module}' not suitable for {self.target_type} targets")
            return

        self.active_module = module
        self.prompt = f"hellhound({module}) > "
        print(Fore.GREEN + f"[+] {module} equipped")

    def do_release(self, arg):
        """release → Exit tool mode"""
        self.active_module = None
        self.prompt = "hellhound > "

    def do_strike(self, arg):
        """strike → Execute selected tool"""

        if not self.target or not self.target_type:
            print("[!] No prey set")
            return

        module = self.active_module or arg.strip()
        if not module:
            print("Usage: strike OR equip <module> then strike")
            return

        allowed = self.MODULE_SCOPE.get(self.target_type, set())
        if module not in allowed:
            print(Fore.RED + f"[!] '{module}' not allowed for {self.target_type} prey")
            return

        print(Fore.YELLOW + f"[*] Executing {module}...")
        output = self.engine.run_single(module, self.target)
        self.results[module] = output


    # ============================
    # INTELLIGENCE
    # ============================

    def do_howl(self, arg):
        """howl → Suggest next actions"""

        if not self.target_type:
            print("[!] Prey not defined")
            return

        if "nmap" not in self.results:
            print("[!] Run nmap first")
            return

        suggestions = suggest_actions(
            self.results["nmap"],
            target_type=self.target_type
        )

        print("\n[ Howl — recommended actions ]")
        for s in suggestions:
            print(f"  → {s}")
        print()

    # ============================
    # AUTO MODE (basic)
    # ============================

    def do_auto(self, arg):
        """auto → Intelligent attack chain"""

        if not self.target:
            print("[!] No prey set")
            return

        print(Fore.YELLOW + "[*] Auto mode engaged...")

        nmap_output = self.engine.run_single("nmap", self.target)
        self.results["nmap"] = nmap_output

        open_ports = []
        for line in nmap_output.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.split("/")[0])

        print(Fore.GREEN + f"[+] Open ports: {', '.join(open_ports)}")

        if self.target_type == "web" and "reconcombo" in self.modules:
            print(Fore.YELLOW + "[*] Suggest running reconcombo manually")

        print(Fore.GREEN + "[✓] Auto mode finished")

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

        if cmd in self.aliases:
            real_cmd = self.aliases[cmd]
            rewritten = f"{real_cmd} {args}".strip()
            return self.onecmd(rewritten)

        print(f"[!] Unknown command: {cmd}")
