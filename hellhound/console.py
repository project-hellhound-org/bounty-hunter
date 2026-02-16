import cmd
import yaml
import importlib.resources as pkg_resources
import os
import time
import sys
import random

from colorama import Fore, Back, Style, init
init(autoreset=True)

from hellhound.core.engine import HellhoundEngine
from hellhound.core.suggest import suggest_actions

# ----------------------------
# NEW ANIMATION HELPERS
# ----------------------------
def run_exploit_script():
    """
    Simulates running a shell script to initialize the framework.
    """
    prompt = f"{Fore.LIGHTRED_EX}root@hellhound:~#{Fore.WHITE}"
    
    commands = [
        ("./init_framework.sh", "Loading dependencies..."),
        ("--force-ssl", "Bypassing SSL verification..."),
        ("--connect-c2", "Establishing secure link to Command & Control..."),
        ("--load-modules", "Importing payloads..."),
        ("--stealth-mode", "Hiding process from task manager...")
    ]

    print(f"\n{Back.BLACK}{Fore.WHITE}")
    for cmd_input, response in commands:
        sys.stdout.write(f"{prompt} {cmd_input}")
        sys.stdout.flush()
        time.sleep(0.2)
        print(f"\n{Fore.LIGHTBLACK_EX}[+] {response}")
        time.sleep(0.3)
        
    print(f"\n{prompt} {Fore.GREEN}System Ready.\n")
    time.sleep(0.3)

def simple_static_glitch(text):
    """
    Simple, shape-preserving static glitch.
    Uses cursor anchoring to prevent the banner from jumping/moving.
    """
    # Split lines, but remove the very last empty line if it exists (prevents drift)
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    
    height = len(lines)
    
    # 1. Print the logo normally first
    # We use sys.stdout.write to ensure no extra flushes happen yet
    sys.stdout.write(f"{Fore.LIGHTBLACK_EX}{Style.DIM}{text}\n")
    sys.stdout.flush()
    time.sleep(0.3)

    # 2. Move cursor UP to the start of the logo immediately (The Anchor)
    # This ensures we are exactly at the top of the logo before we start animating
    sys.stdout.write(f"\033[{height}F")

    # 3. The Static Loop
    for _ in range(10): 
        # We are currently at the TOP of the logo.
        
        # Iterate and draw the glitched frame
        for line in lines:
            glitch_line = ""
            for char in line:
                if char == ' ':
                    glitch_line += " "
                else:
                    # 15% chance to swap character
                    if random.random() < 0.15:
                        glitch_line += random.choice("@%#*+")
                    else:
                        glitch_line += char
            
            # Random color flicker
            color = Fore.RED
            if random.random() < 0.15: color = Fore.WHITE
            
            # Write the line + newline
            sys.stdout.write(f"{color}{glitch_line}\n")

        # Flush the frame to screen
        sys.stdout.flush()
        
        # CRITICAL FIX: Snap cursor back UP to the top of the logo
        # This prevents it from drifting down.
        sys.stdout.write(f"\033[{height}F")
        
        time.sleep(0.04)

    # 4. Final Clean Render
    # We are currently at the TOP of the logo.
    # We print the final clean version. 
    # Because we do NOT move the cursor up after this, the cursor naturally ends up at the bottom.
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Back.BLACK}{Fore.RED}{Style.BRIGHT}{text}")
    print(Style.RESET_ALL, end="")


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
            },
            "stalk": {
                "--deep": {"mode": "deep"}
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


    # ----------------------------
    # Hackeristic Boot Sequence (UPGRADED)
    # ----------------------------
    def preloop(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        run_exploit_script()
        
        # Using the exact logo provided
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
                
        simple_static_glitch(logo)
        print(f"\n{Fore.WHITE}Type '{Fore.YELLOW}help{Fore.WHITE}' to view available commands.\n")

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
                if category in ["web", "recon", "network", "vuln"] or name == "nmap":
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

            # -------------------------------------------------
            # Structured Modules (Preferred Design with "intel" key)
            # -------------------------------------------------
            if isinstance(output, dict) and "intel" in output:

                intel = output.get("intel", {})
                summary = intel.get("summary", {})

                # =================================================
                # 1️⃣ GENERIC SUMMARY BLOCK
                # =================================================
                if summary:
                    print(Fore.GREEN + "  Summary:")
                    for k, v in summary.items():
                        print(f"    {k.replace('_',' ').title()} : {v}")
                    print()

                # =================================================
                # 2️⃣ INFRASTRUCTURE (Stalk Phase 1)
                # =================================================
                if "infrastructure" in intel:
                    infra = intel.get("infrastructure", {})
                    print(Fore.GREEN + "  Infrastructure:")

                    if infra.get("subdomains"):
                        subs = infra["subdomains"]
                        print(f"    Subdomains: {len(subs)} found")
                        for s in subs[:10]:
                            print(f"      - {Fore.CYAN}{s}")
                        if len(subs) > 10:
                            print(f"      ... +{len(subs)-10} more")
                        print()

                    if infra.get("netrange"):
                        print("    NetRange:")
                        for n in infra["netrange"]:
                            print(f"      - {n}")
                        print()

                    if infra.get("asn"):
                        print(f"    ASN: {Fore.YELLOW}{infra['asn']}")
                        print()

                    if infra.get("mx_records"):
                        print("    MX Records:")
                        for mx in infra["mx_records"]:
                            print(f"      - {mx}")
                        print()
                    
                    if infra.get("email_provider"):
                        print(f"    Email Provider: {Fore.CYAN}{', '.join(infra['email_provider'])}")
                        print()

                    if infra.get("waf"):
                        print(f"    WAF: {Fore.RED}{infra['waf']}")
                        print()

                # =================================================
                # 2.5️⃣ EXPOSURE (Stalk Phase 3)
                # =================================================
                if "exposure" in intel:
                    exp = intel.get("exposure", {})
                    
                    if exp.get("leaks"):
                        print(Fore.RED + "  ⚠ Potential Leaks:")
                        for l in exp["leaks"]:
                            print(f"    - {Fore.YELLOW}{l}")
                        print()

                    if exp.get("takeover_candidates"):
                        print(Fore.RED + "  ⚠ Takeover Candidates:")
                        for t in exp["takeover_candidates"]:
                            print(f"    - {Fore.CYAN}{t}")
                        print()

                # =================================================
                # 3️⃣ WEB SURFACE (Stalk / Spider)
                # =================================================
                if "web" in intel:
                    web = intel.get("web", {})

                    if web.get("http_services"):
                        print(Fore.GREEN + "  HTTP Services:")
                        for h in web["http_services"]:
                            print(f"      - {Fore.CYAN}{h}")
                        print()

                    if web.get("technologies"):
                        print(Fore.GREEN + "  Technologies:")
                        for t in web["technologies"]:
                            print(f"      - {t}")
                        print()

                    if web.get("urls"):
                        print(f"    URLs Discovered: {len(web['urls'])}")
                        print()
                    
                    if web.get("js_files"):
                        print(Fore.GREEN + "  JavaScript Files:")
                        for js in web["js_files"]:
                            print(f"      - {Fore.CYAN}{js}")
                        print()

                # =================================================
                # 4️⃣ SERVICE MAP (Surfacemap Style)
                # =================================================
                if "map" in intel:
                    surface = intel.get("map", {})
                    for ip, ports in surface.items():
                        print(Fore.GREEN + f"  Surface Map → {ip}")
                        for port_proto, data in ports.items():
                            service = data.get("service", "")
                            product = data.get("product", "")
                            version = data.get("version", "")
                            print(
                                f"    {Fore.CYAN}{port_proto:<8} "
                                f"{Fore.WHITE}{service:<10} "
                                f"{Fore.YELLOW}{product} {version}"
                            )
                        print()

                # =================================================
                # 5️⃣ ENDPOINTS (Spider / Stalk)
                # =================================================
                if "endpoints" in intel:
                    endpoints = intel.get("endpoints", [])
                    stats = intel.get("stats", {})

                    if stats:
                        print(Fore.GREEN + "  Attack Surface Summary:")
                        for key, val in stats.items():
                            print(f"    {key.upper():<6}: {val}")
                        print()

                    for idx, ep in enumerate(endpoints, 1):
                        method = ep.get("method", "GET")
                        url = ep.get("url", "")
                        color = Fore.BLUE if method == "GET" else Fore.MAGENTA
                        print(color + f"  [{idx}] {method}  {url}")

                        for p in ep.get("params", []):
                            pname = p.get("name", "")
                            ptype = p.get("type", "")
                            print(f"       - {Fore.WHITE}{pname} {Fore.YELLOW}({ptype})")

                        if ep.get("tags"):
                            print(Fore.RED + f"       Tags: {', '.join(ep['tags'])}")

                        print()

                # =================================================
                # 6️⃣ EMAILS / CREDLEAK / PHISHING
                # =================================================
                if "emails" in intel and intel["emails"]:
                    print(Fore.GREEN + "  Emails Found:")
                    for email in intel["emails"]:
                        print(f"    - {Fore.CYAN}{email}")
                    print()

                if "paste_hits" in intel and intel["paste_hits"]:
                    print(Fore.GREEN + "  Paste References:")
                    for link in intel["paste_hits"]:
                        print(f"    - {Fore.YELLOW}{link}")
                    print()

                if "exposed_keys" in intel and intel["exposed_keys"]:
                    print(Fore.RED + "  ⚠ Exposed Keys Detected:")
                    for key in intel["exposed_keys"]:
                        print(f"    - {key}")
                    print()

                if "security_policy" in intel:
                    pol = intel["security_policy"]
                    print(Fore.GREEN + "  Phishing Intel:")
                    if intel.get("phishing_domain"):
                        print(f"    Suggested Domain : {Fore.CYAN}{intel['phishing_domain']}")
                    if pol.get("spf"):
                        print(f"    SPF Status      : {Fore.YELLOW}{pol.get('spf_type')}")
                    if pol.get("dmarc"):
                        print(f"    DMARC Policy    : {Fore.YELLOW}{pol.get('dmarc_policy')}")
                    if intel.get("target_emails"):
                        print(f"    Target Emails   : {len(intel['target_emails'])}")
                    print()

                # =================================================
                # 7️⃣ VULNERABILITIES (Universal)
                # =================================================
                if "vulnerabilities" in intel:
                    vulns = intel.get("vulnerabilities", [])
                    if vulns:
                        print(Fore.RED + "  ⚠ Vulnerabilities Detected:\n")
                        for idx, v in enumerate(vulns, 1):
                            vtype = v.get("type", "UNKNOWN")
                            url = v.get("url", "")
                            param = v.get("parameter", "")
                            payload = v.get("payload_used")
                            confidence = v.get("confidence", "")
                            print(Fore.YELLOW + f"  [{idx}] {vtype}")
                            print(f"       Target     : {Fore.CYAN}{url}")
                            if param:
                                print(f"       Parameter  : {Fore.WHITE}{param}")
                            if payload:
                                print(f"       Payload    : {Fore.GREEN}{payload}")
                            if confidence:
                                print(f"       Confidence : {confidence}")
                            if v.get("proof"):
                                print(Fore.MAGENTA + f"       Proof      : {v.get('proof')}")
                            print()

                # =================================================
                # 8️⃣ SIGNALS
                # =================================================
                if "signals" in intel:
                    signals = intel.get("signals", [])
                    if signals:
                        print(Fore.GREEN + "  Signals:")
                        for s in signals:
                            print(f"    - {s}")
                        print()

            # -------------------------------------------------
            # RAW FALLBACK (Handles dicts without 'intel', strings, or lists)
            # -------------------------------------------------
            elif isinstance(output, dict):
                # Handle modules returning {'raw': ..., 'signals': ...}
                if "raw" in output:
                    print(Fore.WHITE + output["raw"])
                
                if "signals" in output and output["signals"]:
                    print(Fore.GREEN + "  Signals:")
                    for s in output['signals']:
                        print(f"    - {s}")
                    print()
                elif "summary" in output:
                    print(Fore.WHITE + str(output["summary"]))
                else:
                    # Fallback for unknown dicts
                    print(Fore.WHITE + str(output))

            elif isinstance(output, list):
                # Handle modules returning lists (e.g. simple lists of strings)
                for item in output:
                    print(Fore.WHITE + f"    - {item}")
            
            elif isinstance(output, str):
                print(Fore.WHITE + output.strip()[:1000])
                print()

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
            parts = parts[1:]

        if not module:
            print("Usage: strike <module> [--flags]")
            print("       strike (if tool equipped)")
            return

        if module not in self.modules:
            print(Fore.RED + f"[!] Unknown module: {module}")
            return

        # Scope enforcement
        category = self.modules[module]["category"]
        ALLOWED_FOR_WEB = {"web", "recon", "network", "vuln"}

        if self.target_type == "web" and category not in ALLOWED_FOR_WEB:
            print(Fore.RED + f"[!] '{module}' not suitable for WEB targets")
            return

        # Handle help
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
            options.update(module_flags[flag])

        # ==========================================================
        # AUTO-INTEGRATION LOGIC
        # ==========================================================

        # 1. Spider -> Cmdinj (Existing)
        if module == "cmdinj":
            if "spider" in self.results:
                options["spider_results"] = self.results["spider"]
                
        # 2. Stalk -> Surfacemap (New Integration)
        if module == "surfacemap":
            if "stalk" in self.results:
                stalk_data = self.results["stalk"]
                
                # Check if Stalk data has the expected structure
                if isinstance(stalk_data, dict) and "intel" in stalk_data:
                    intel = stalk_data["intel"]
                    
                    # Extract HTTP Services
                    http_services = intel.get("web", {}).get("http_services", [])
                    if http_services:
                        options["http_services"] = http_services
                        print(Fore.CYAN + f"[*] Auto-fed {len(http_services)} HTTP targets from Stalk")

                    # Extract Subdomains
                    subdomains = intel.get("infrastructure", {}).get("subdomains", [])
                    if subdomains:
                        options["subdomains"] = subdomains
                        print(Fore.CYAN + f"[*] Auto-fed {len(subdomains)} Subdomains from Stalk")

        # ==========================================================

        print(Fore.YELLOW + f"[*] Executing {module}...")

        try:
            output = self.engine.run_single(module, self.target, options=options)
            self.results[module] = output
            print(Fore.GREEN + f"[✓] {module} finished.")
        except Exception as e:
            print(Fore.RED + f"[x] {module} failed: {str(e)}")


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

        print("\n==========================================================\n")

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
