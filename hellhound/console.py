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
    intro = "\nHellhound Console v1.0\nType help or ? to list commands.\n"
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

    def do_set(self, arg):
        """set target <ip>"""
        args = arg.split()
        if len(args) == 2 and args[0] == "target":
            self.target = args[1]
            print(f"[+] Target set to {self.target}")
        else:
            print("Usage: set target <ip>")

    def do_exit(self, arg):
        """Exit console"""
        print("[+] Exiting Hellhound console")
        return True

    # -------------------
    # SHOW COMMANDS
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
    # SCANNING
    # -------------------

    def do_scan(self, arg):
        """scan nmap"""
        if not self.target:
            print("[!] Set target first: set target <ip>")
            return

        if arg.strip() != "nmap":
            print("Usage: scan nmap")
            return

        print("[*] Running Nmap...")
        output = self.engine.run_single("nmap", self.target)
        self.results["nmap"] = output

    # -------------------
    # MODULE EXECUTION
    # -------------------

    def do_run(self, arg):
        """run (runs active module) or run <module>"""

        if not self.target:
            print("[!] Set target first")
            return

        module = self.active_module or arg.strip()

        if not module:
            print("Usage: run OR use <module> then run")
            return

        if module not in self.modules:
            print(f"[!] Unknown module: {module}")
            return

        print(f"[*] Running module: {module}")
        output = self.engine.run_single(module, self.target)
        self.results[module] = output

    # -------------------
    # METASPLOIT STYLE MODE
    # -------------------

    def do_use(self, arg):
        """use <module>"""
        module = arg.strip()

        if module not in self.modules:
            print(f"[!] Unknown module: {module}")
            return

        self.active_module = module
        self.prompt = f"hellhound({module}) > "
        print(f"[+] Using module: {module}")

    def do_back(self, arg):
        """Exit module context"""
        self.active_module = None
        self.prompt = "hellhound > "

    def do_options(self, arg):
        """Show options for current module"""

        if not self.active_module:
            print("[!] No active module. Use: use <module>")
            return

        print(f"\nOptions for module '{self.active_module}':")

        if self.active_module == "vhost":
            print("  TARGET     - Target IP or domain")
            print("  WORDLIST   - Optional custom wordlist")

        elif self.active_module == "nmap":
            print("  TARGET     - Target IP")

        print()

    # -------------------
    # SUGGESTIONS
    # -------------------

    def do_suggest(self, arg):
        """Suggest next actions based on scan results"""

        if "nmap" not in self.results:
            print("[!] Run scan nmap first")
            return

        suggestions = suggest_actions(self.results["nmap"])
        print("\nSuggestions:")
        for s in suggestions:
            print(f"  - {s}")
        print()
