import cmd
import yaml
import importlib.resources as pkg_resources

from hellhound.core.engine import HellhoundEngine
from hellhound.core.suggest import suggest_actions
from colorama import Fore, Style, init
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
    
    def preloop(self):
        import time
        self.loading("Initializing Hellhound core")
        self.loading(f"Loading modules ({len(self.modules)})")
        self.loading("Bringing intelligence engine online")
        print(Fore.GREEN + "[✓] Console ready\n")


    def loading(self, text, seconds=1.2):
        import time
        for _ in range(3):
            print(Fore.CYAN + f"\r{text}" + "." * (_ + 1), end="")
            time.sleep(seconds / 3)
        print()

    # -------------------
    # CORE COMMANDS
    # -------------------

    def do_prey(self, arg):
        """prey <ip> → lock onto a target"""
        if not arg.strip():
            print("Usage: prey <ip>")
            return

        self.target = arg.strip()
        print(Fore.GREEN + f"[+] Prey acquired: {self.target}")

    def do_exit(self, arg):
        """Exit console"""
        print("[+] Exiting Hellhound console")
        return True

    # -------------------
    # DISPLAY
    # -------------------

    def do_show(self, arg):
        """show modules | show results"""

        if arg.strip() == "modules":
            print("\nAvailable modules:\n")
            for name, meta in self.modules.items():
                desc = meta.get("description", "No description")
                print(f"  {name:<10} - {desc}")
            print()

        elif arg.strip() == "results":
            if not self.results:
                print("[!] No results yet")
                return

            print("\nLast results:\n")
            for mod, output in self.results.items():
                print(f"[{mod.upper()}]")
                if isinstance(output, str):
                    print(output[:400] + "\n")
                else:
                    print(output)
        else:
            print("Usage: show modules | show results")

    # -------------------
    # RECON
    # -------------------

    def do_nmap(self, arg):
        """nmap → Run reconnaissance"""
        if not self.target:
            print("[!] Set prey first: prey <ip>")
            return

        print("[*] Running Nmap...")
        output = self.engine.run_single("nmap", self.target)
        self.results["nmap"] = output

    # -------------------
    # EXECUTION
    # -------------------

    def do_strike(self, arg):
        """strike → run module"""

        if not self.target:
            print(Fore.RED + "[!] No prey set. Use: prey <ip>")
            return

        module = self.active_module or arg.strip()

        if not module:
            print("Usage: strike OR equip <module> then strike")
            return

        if module not in self.modules:
            print(f"[!] Unknown module: {module}")
            return

        print(f"[*] Executing: {module}")
        output = self.engine.run_single(module, self.target)
        self.results[module] = output

    # -------------------
    # TOOL CONTROL
    # -------------------

    def do_equip(self, arg):
        """equip <module>"""
        module = arg.strip()

        if module not in self.modules:
            print(f"[!] Unknown module: {module}")
            return

        self.active_module = module
        self.prompt = f"hellhound({module}) > "
        print(f"[+] {module} equipped")

    def do_release(self, arg):
        """release tool"""
        self.active_module = None
        self.prompt = "hellhound > "

    def do_scope(self, arg):
        """scope → show module options"""

        if not self.active_module:
            print("[!] No tool equipped. Use: equip <module>")
            return

        print(f"\nScope for '{self.active_module}':")

        if self.active_module == "vhost":
            print("  TARGET     - Target IP or domain")
            print("  WORDLIST   - Optional custom wordlist")

        elif self.active_module == "nmap":
            print("  TARGET     - Target IP")

        print()

    # -------------------
    # INTELLIGENCE
    # -------------------

    def do_howl(self, arg):
        """howl → suggest next actions"""

        if "nmap" not in self.results:
            print("[!] No scent yet. Run: nmap")
            return

        suggestions = suggest_actions(self.results["nmap"])
        print("\n[Howl: recommended actions]")
        for s in suggestions:
            print(f"  → {s}")
        print()

    def do_clear(self, arg):
        """clear → Clear the console screen"""
        import os
        os.system("clear" if os.name == "posix" else "cls")

       
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
    
def do_auto(self, arg):
    """auto → intelligent attack chain"""

    if not self.target:
        print(Fore.RED + "[!] No prey set. Use: prey <ip>")
        return

    print(Fore.YELLOW + "[*] Auto mode engaged...\n")

    # 1. Always run Nmap first
    print(Fore.CYAN + "[*] Running reconnaissance (nmap)...")
    nmap_output = self.engine.run_single("nmap", self.target)
    self.results["nmap"] = nmap_output

    # 2. Extract open ports
    open_ports = []
    for line in nmap_output.splitlines():
        if "/tcp" in line and "open" in line:
            port = line.split("/")[0].strip()
            open_ports.append(port)

    print(Fore.GREEN + f"[+] Open ports detected: {', '.join(open_ports) or 'none'}")

    # 3. Decide which modules make sense
    selected_modules = []

    web_ports = {"80", "443", "8080"}
    if any(p in web_ports for p in open_ports):
        if "vhost" in self.modules:
            selected_modules.append("vhost")
        if "dirsearch" in self.modules:
            selected_modules.append("dirsearch")

    if "21" in open_ports and "ftp" in self.modules:
        selected_modules.append("ftp")

    # 4. No relevant modules
    if not selected_modules:
        print(Fore.YELLOW + "[!] No additional modules relevant for detected services.")
        return

    print(Fore.CYAN + f"\n[*] Auto-selected modules: {', '.join(selected_modules)}\n")

    # 5. Execute selected modules
    for module in selected_modules:
        print(Fore.YELLOW + f"[*] Executing: {module}")
        output = self.engine.run_single(module, self.target)
        self.results[module] = output

    print(Fore.GREEN + "\n[✓] Auto mode completed.")


    def do_status(self, arg):
        """status → show current session state"""

        print("\n[ Hellhound Status ]")
        print("----------------------------")

        print(f"Prey        : {self.target or 'not set'}")
        print(f"Equipped    : {self.active_module or 'none'}")
        print(f"Modules     : {len(self.modules)} loaded")
        print(f"Loot        : {len(self.results)} results collected")
        print(f"Sessions    : {self.get_session_count()}")


        if "nmap" in self.results:
            print("Recon       : completed")
        else:
            print("Recon       : not yet run")

        print("----------------------------\n")

    def get_session_count(self):
        import os
        base = os.path.join(os.path.dirname(__file__), "storage")
        try:
            return len(os.listdir(base))
        except:
            return 0

    def do_sessions(self, arg):
        """sessions → List all previous hunts"""

        import os

        base = os.path.join(os.path.dirname(__file__), "storage")

        if not os.path.exists(base):
            print("[!] No sessions directory found.")
            return

        sessions = sorted(os.listdir(base))

        if not sessions:
            print("[!] No previous sessions found.")
            return

        print("\n[ Hellhound Sessions ]")
        print("======================")

        for i, s in enumerate(sessions, 1):
            print(f"{i}. {s}")

        print(f"\nTotal sessions: {len(sessions)}\n")
