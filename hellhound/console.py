import cmd
import yaml
import importlib.resources as pkg_resources

from hellhound.core.engine import HellhoundEngine
from hellhound.core.suggest import suggest_actions


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
    # CORE COMMANDS
    # -------------------

    def do_prey(self, arg):
        """prey <ip> → lock onto a target"""
        if not arg.strip():
            print("Usage: prey <ip>")
            return

        self.target = arg.strip()
        print(f"[+] Prey acquired: {self.target}")

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
            print("[!] No prey set. Use: prey <ip>")
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
lair      → Exit console
""")
