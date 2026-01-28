import cmd
import yaml
import importlib.resources as pkg_resources
import os
import time

from hellhound.core.engine import HellhoundEngine
from hellhound.core.suggest import suggest_actions

from colorama import Fore, init
init(autoreset=True)


def load_modules():
    try:
        with pkg_resources.files("hellhound").joinpath("config.yaml").open("r") as f:
            return yaml.safe_load(f).get("modules", {})
    except:
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
                     L4ZZ3RJ0D & alph4_rc

Type 'help' to view available commands.
"""

    prompt = "hellhound > "

    def __init__(self):
        super().__init__()
        self.target = None
        self.engine = HellhoundEngine(socketio=None)
        self.results = {}
        self.active_module = None
        self.modules = load_modules()

    # -------------------
    # Startup
    # -------------------

    def preloop(self):
        self.loading("Initializing Hellhound core")
        self.loading(f"Loading modules ({len(self.modules)})")
        self.loading("Bringing intelligence engine online")
        print(Fore.GREEN + "[✓] Console ready\n")

    def loading(self, text, seconds=1.2):
        for i in range(3):
            print(Fore.CYAN + f"\r{text}" + "." * (i + 1), end="")
            time.sleep(seconds / 3)
        print()

    # -------------------
    # CORE
    # -------------------

    def do_prey(self, arg):
        """prey <ip> → Lock onto a target host"""
        if not arg.strip():
            print("Usage: prey <ip>")
            return
        self.target = arg.strip()
        print(Fore.GREEN + f"[+] Prey acquired: {self.target}")

    def do_exit(self, arg):
        """exit → Leave console"""
        print("[+] Exiting Hellhound console")
        return True

    # -------------------
    # DISPLAY
    # -------------------

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

    # -------------------
    # RECON
    # -------------------

    def do_nmap(self, arg):
        """nmap → Run reconnaissance"""
        if not self.target:
            print("[!] Set prey first: prey <ip>")
            return
        print(Fore.YELLOW + "[*] Running Nmap...")
        output = self.engine.run_single("nmap", self.target)
        self.results["nmap"] = output

    # -------------------
    # MODULE CONTROL
    # -------------------

    def do_equip(self, arg):
        """equip <module> → Select a tool"""
        module = arg.strip()
        if module not in self.modules:
            print(f"[!] Unknown module: {module}")
            return
        self.active_module = module
        self.prompt = f"hellhound({module}) > "
        print(f"[+] {module} equipped")

    def do_release(self, arg):
        """release → Exit tool mode"""
        self.active_module = None
        self.prompt = "hellhound > "

    def do_strike(self, arg):
        """strike → Execute selected tool"""
        if not self.target:
            print("[!] No prey set")
            return

        module = self.active_module or arg.strip()
        if not module:
            print("Usage: strike OR equip <module> then strike")
            return

        if module not in self.modules:
            print("[!] Unknown module")
            return

        print(Fore.YELLOW + f"[*] Executing {module}...")
        output = self.engine.run_single(module, self.target)
        self.results[module] = output

    # -------------------
    # INTELLIGENCE
    # -------------------

    def do_howl(self, arg):
        """howl → Suggest next actions"""
        if "nmap" not in self.results:
            print("[!] No scent yet. Run nmap first.")
            return

        suggestions = suggest_actions(self.results["nmap"])
        print("\n[ Howl — recommended actions ]")
        for s in suggestions:
            print(f"  → {s}")
        print()

    # -------------------
    # AUTO MODE
    # -------------------

    def do_auto(self, arg):
        """auto → Intelligent attack chain"""
        if not self.target:
            print("[!] No prey set")
            return

        print(Fore.YELLOW + "[*] Auto mode engaged...\n")

        nmap_output = self.engine.run_single("nmap", self.target)
        self.results["nmap"] = nmap_output

        open_ports = []
        for line in nmap_output.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.split("/")[0])

        print(Fore.GREEN + f"[+] Open ports: {', '.join(open_ports)}")

        selected = []

        if any(p in {"80", "443", "8080"} for p in open_ports):
            for m in ("vhost", "dirsearch"):
                if m in self.modules:
                    selected.append(m)

        if "21" in open_ports and "ftp" in self.modules:
            selected.append("ftp")

        if not selected:
            print(Fore.YELLOW + "[!] No relevant modules identified.")
            return

        for mod in selected:
            print(Fore.YELLOW + f"[*] Auto executing: {mod}")
            self.results[mod] = self.engine.run_single(mod, self.target)

        print(Fore.GREEN + "\n[✓] Auto complete")

    # -------------------
    # SYSTEM
    # -------------------

    def do_clear(self, arg):
        """clear → Clear the screen"""
        os.system("clear" if os.name == "posix" else "cls")

    def do_status(self, arg):
        """status → Show framework status"""
        print("\n[ Hellhound Status ]")
        print(f"Target     : {self.target or 'not set'}")
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

    # -------------------
    # CUSTOM HELP
    # -------------------

    def do_help(self, arg):
        """Show Hellhound command manual"""
        print("""
Documented commands:
=====================
prey      → Set target (lock onto a host)
nmap      → Run reconnaissance scan
arsenal   → List available tools
equip     → Select a tool/module
scope     → View tool configuration
strike    → Execute selected tool
howl      → Get suggested next actions
loot      → View gathered results
release   → Exit tool mode
exit      → Exit console
auto      → Intelligent attack chain
clear     → Clear the console screen
status    → Show framework status
sessions  → List previous hunts
""")
