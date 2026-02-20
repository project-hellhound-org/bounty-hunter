import cmd
import yaml
import importlib.resources as pkg_resources
import os
import time
import sys
import random
from datetime import datetime
import json


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
            "stalk": {
                "--deep": {"mode": "deep"}
            },
            "fuzzhunter": { 
                "--deep": {"mode": "deep"}
            },
            "cmdinj": {
                "--rev": {"mode": "reverse_shell"}
            },
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
        """prey <domain> → Lock onto web target"""

        if not arg.strip():
            print("Usage: prey <domain>")
            return

        self.target = arg.strip()
        self.target_type = "web"

        print(Fore.GREEN + f"[+] Web target acquired: {self.target}")

        
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


    def do_loot(self, arg):
            """loot → View gathered results"""
            import json
            import os
            import re # Ensure regex is imported
            from datetime import datetime

            if not self.results:
                print(Fore.RED + "[!] No loot collected yet")
                return

            # ==============================================
            # HELPER: Strip ANSI Color Codes
            # ==============================================
            def strip_ansi(text):
                """Removes ANSI escape codes from strings"""
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                return ansi_escape.sub('', text)

            parts = arg.split()

            # ======================================================
            # 1. LOOT --JSON (Raw Data Dump)
            # ======================================================
            if "--json" in parts:
                print(json.dumps(self.results, indent=4, default=str))
                return

            # ======================================================
            # 2. LOOT --SUMMARY (Executive View)
            # ======================================================
            if "--summary" in parts:

                print(Fore.CYAN + "\n========== [ SUMMARY ] ==========\n")

                # Calculate Risk & Vulnerability Stats
                total_risk = 0
                total_vulns = 0

                for mod, output in self.results.items():
                    if isinstance(output, dict) and "intel" in output:
                        intel = output["intel"]
                        # Aggregate risk (default 0 if not present)
                        total_risk += intel.get("risk_score", 0)
                        # Aggregate vulnerabilities
                        total_vulns += len(intel.get("vulnerabilities", []))

                # Determine Risk Level
                if total_risk <= 2:
                    level = "LOW"
                    level_color = Fore.GREEN
                elif total_risk <= 6:
                    level = "MEDIUM"
                    level_color = Fore.YELLOW
                elif total_risk <= 10:
                    level = "HIGH"
                    level_color = Fore.RED
                else:
                    level = "CRITICAL"
                    level_color = Fore.MAGENTA

                print(f"Target       : {self.target}")
                print(f"Modules Run  : {len(self.results)}")
                print(f"Risk Score   : {total_risk} ({level_color}{level}{Style.RESET_ALL})")
                print(f"Vulnerabilities Identified : {total_vulns}")
                print("\n================================\n")
                return

            # ======================================================
            # 3. LOOT --EXPORT (File Export)
            # ======================================================
            if "--export" in parts:

                from datetime import datetime
                import json

                base_path = os.path.join("storage", "reports", self.target)
                os.makedirs(base_path, exist_ok=True)

                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

                json_path = os.path.join(base_path, f"{timestamp}.json")
                summary_path = os.path.join(base_path, f"{timestamp}_summary.txt")

                # Save JSON safely
                with open(json_path, "w") as f:
                    json.dump(self.results, f, indent=4, default=str)

                # Build summary
                total_risk = 0
                total_vulns = 0

                for mod, output in self.results.items():
                    if isinstance(output, dict) and "intel" in output:
                        intel = output["intel"]
                        total_risk += intel.get("risk_score", 0)
                        total_vulns += len(intel.get("vulnerabilities", []))

                summary_content = (
                    f"Target: {self.target}\n"
                    f"Modules Run: {len(self.results)}\n"
                    f"Risk Score: {total_risk}\n"
                    f"Vulnerabilities Identified: {total_vulns}\n"
                )

                with open(summary_path, "w") as f:
                    f.write(summary_content)

                print(Fore.GREEN + f"[✓] Report exported successfully.")
                print(Fore.GREEN + f"    JSON: {json_path}")
                print(Fore.GREEN + f"    Summary: {summary_path}")
                return

            # ======================================================
            # 4. LOOT (Default - Detailed View)
            # ======================================================
            print("\n" + Fore.CYAN + "========== [ LOOT ] ==========\n")
            
            # ----------------------------------
            # GLOBAL RISK AGGREGATION
            # ----------------------------------
            total_risk = 0
            breakdown = {}

            for mod, output in self.results.items():
                if isinstance(output, dict) and "intel" in output:
                    module_risk = output["intel"].get("risk_score", 0)
                    
                    # DYNAMIC RISK CALCULATION FOR SEIGE
                    # If module doesn't have a risk_score but has Nuclei findings, calculate it
                    if module_risk == 0 and "nuclei_findings" in output["intel"]:
                        vulns = output["intel"]["nuclei_findings"]
                        for v in vulns:
                            clean_v = strip_ansi(v) # Use clean version for checking
                            if "[CRITICAL]" in clean_v: module_risk += 10
                            elif "[HIGH]" in clean_v: module_risk += 7
                            elif "[MEDIUM]" in clean_v: module_risk += 4
                            elif "[LOW]" in clean_v: module_risk += 1
                        # Add Nikto risk
                        if "nikto_findings" in output["intel"]:
                            module_risk += len(output["intel"]["nikto_findings"]) * 2

                    total_risk += module_risk
                    breakdown[mod] = module_risk

            print(Fore.CYAN + "========== [ RISK BREAKDOWN ] ==========\n")

            for mod, score in breakdown.items():
                print(f"  {mod.upper():<12} : {score}")

            print("----------------------------------------")
            print(f"  TOTAL RISK SCORE : {total_risk}")

            # Risk classification
            if total_risk <= 3:
                level = "LOW"
            elif total_risk <= 8:
                level = "MEDIUM"
            elif total_risk <= 15:
                level = "HIGH"
            else:
                level = "CRITICAL"

            print(Fore.RED + f"  OVERALL SECURITY POSTURE : {level}")
            print(Fore.CYAN + "========================================\n")

            # Track keys we have already printed to avoid duplicates
            printed_keys = set()

            for mod, output in self.results.items():
                
                # 1. Normalize module name to lowercase for consistency
                mod_clean = mod.lower()
                
                # 2. Skip if we already printed this module
                if mod_clean in printed_keys:
                    continue
                
                printed_keys.add(mod_clean)

                print(Fore.YELLOW + f"[{mod_clean.upper()}]")

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
                            print(f"    ASN: {Fore.YELLOW}{intel['asn']}")
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
                            print(f"    WAF: {Fore.RED}{intel['waf']}")
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
                    # 3️⃣ WEB SURFACE (Stalk / Spider) - UPDATED
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

                        # --- URLs: List them, don't just count ---
                        if web.get("urls"):
                            urls = web["urls"]
                            print(f"    URLs Discovered: {len(urls)}")
                            for u in urls[:10]: # Show first 10
                                print(f"      - {Fore.CYAN}{u}")
                            if len(urls) > 10:
                                print(f"      ... +{len(urls)-10} more")
                            print()
                        
                        if web.get("js_files"):
                            print(Fore.GREEN + "  JavaScript Files:")
                            for js in web["js_files"]:
                                print(f"      - {Fore.CYAN}{js}")
                            print()

                        # --- Parameters: List them ---
                        if web.get("parameters"):
                            params = web["parameters"]
                            print(f"    Parameters Found: {len(params)}")
                            for p in params[:15]: # Show first 15
                                print(f"      - {Fore.MAGENTA}{p}")
                            if len(params) > 15:
                                print(f"      ... +{len(params)-15} more")
                            print()

                    # =================================================
                    #  DEVELOPER COMMENTS (New - Spider)
                    # =================================================
                    if "comments" in intel:
                        comments = intel["comments"]
                        if comments:
                            print(Fore.GREEN + "  Developer Comments:")
                            for c in comments:
                                print(f"    - {Fore.YELLOW}{c}")
                            print()

                    # =================================================
                    #  SECURITY HEADERS (New - Spider)
                    # =================================================
                    if "security_headers" in intel:
                        headers = intel["security_headers"]
                        if headers:
                            print(Fore.GREEN + "  Security Headers:")
                            for k, v in headers.items():
                                print(f"    {Fore.CYAN}{k}: {Fore.WHITE}{v}")
                            print()

                    # =================================================
                    # ROBOTS.TXT & SENSITIVE FILES (UPDATED)
                    # =================================================
                    # Check for disallowed paths found in robots.txt
                    disallowed = intel.get("disallowed_entries") or intel.get("robots_entries") or intel.get("robots_txt") or intel.get("robots_disallowed")
                    if disallowed:
                        print(Fore.GREEN + "  Robots.txt Intelligence:")
                        if isinstance(disallowed, list):
                            print(f"    Disallowed Entries: {len(disallowed)}")
                            for entry in disallowed:
                                print(f"      - {Fore.YELLOW}{entry}")
                        elif isinstance(disallowed, str):
                            print(f"    Content Preview:\n      {Fore.WHITE}{disallowed[:200]}...")
                        print()

                    # Check for other sensitive files
                    if "sensitive_files" in intel:
                        files = intel.get("sensitive_files")
                        if files:
                            print(Fore.RED + "  ⚠ Sensitive Files Detected:")
                            for f in files:
                                print(f"    - {Fore.CYAN}{f}")
                            print()
                   
                    # JS ROUTES
                    routes = intel.get("js_routes") or intel.get("js_endpoints")
                    
                    if routes:
                        # Updated print to show total count
                        print(Fore.GREEN + f"  JS Discovered Routes ({len(routes)} found):")
                        
                        # Iterate over the FULL list (removed [:20])
                        for r in routes:
                            print(f"    - {Fore.CYAN}{r}")
                        
                        print()

                    # GRAPHQL
                    if "graphql" in intel:
                        gql = intel["graphql"]
                        if gql:
                            print(Fore.MAGENTA + "  GraphQL Endpoints:")
                            for g in gql:
                                print(f"    - {g}")
                            print()

                    # =================================================
                    #  JS PARAMETERS (FIXED: Checks 'js_parameters')
                    # =================================================
                    # Spider saves it as 'js_parameters', loot was looking for 'parameters'
                    # JS PARAMETERS (Show all)
                    params = intel.get("js_parameters") or intel.get("parameters")
                    
                    if params:
                        print(Fore.YELLOW + f"  JS Parameters ({len(params)} found):")
                        for p in params:
                            print(f"    - {p}")
                        print()

                    # =================================================
                    #  POTENTIAL KEYS (FIXED: Filters out function names)
                    # =================================================
                    if "potential_keys" in intel:
                        keys = intel["potential_keys"]
                        if keys:
                            print(Fore.RED + "  ⚠ Potential Secrets Found:")
                            for k in keys:
                                # Simple Heuristic Filter:
                                # 1. Ignore if it starts with a lowercase letter followed by uppercase (CamelCase function name)
                                # 2. Ignore if it contains common code words
                                is_code_noise = False
                                
                                lower_k = k.lower()
                                noise_indicators = ['handler', 'verify', 'show', 'displayed', 'difficulty', 'notification', 'repeat']
                                
                                if any(n in lower_k for n in noise_indicators):
                                    is_code_noise = True
                                
                                # Allow if it looks like a hash/HEX or BTC address
                                # (BTC addresses start with 1, 3, or bc1; Hashes are hex)
                                if not is_code_noise:
                                    print(f"    - {k}")
                            print()

                    # RISK SCORE
                    if "risk_score" in intel:
                        print(Fore.CYAN + f"  Risk Score: {intel['risk_score']}\n")
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
                    # 5️⃣ ENDPOINTS (Universal: Spider, Fuzzhunter, Parax)
                    # =================================================
                    if "endpoints" in intel:
                        endpoints = intel.get("endpoints", [])
                        stats = intel.get("stats", {})

                        if stats:
                            print(Fore.GREEN + "  Attack Surface Summary:")
                            for key, val in stats.items():
                                print(f"    {key.upper():<6}: {val}")
                            print()

                        for idx, el in enumerate(endpoints, 1):
                            
                            # FIX: Convert to string before calling .upper() to handle integer status codes
                            raw_method_or_status = el.get("method", el.get("status", "UNK"))
                            method = str(raw_method_or_status).upper()
                            
                            url = el.get("url", "")
                            path = el.get("path", "")
                            
                            # Fallback for URL construction if only path exists
                            if not url and path:
                                url = f"/{path}"

                            # Color Logic
                            color = Fore.BLUE if method == "GET" else Fore.MAGENTA
                            if method.isdigit(): color = Fore.CYAN # Handle status codes as method for Fuzzhunter style
                            
                            # Display Logic: If it's a number, show it as Status, otherwise Method
                            display_method = f"Status {method}" if method.isdigit() else method

                            print(color + f"  [{idx}] {display_method}  {url}")

                            # Show Params (Spider)
                            if el.get("params"):
                                for p in el.get("params"):
                                    pname = p.get("name", "")
                                    ptype = p.get("type", "")
                                    print(f"       - {Fore.WHITE}{pname} {Fore.YELLOW}({ptype})")
                            
                            # Show Size/Details (Fuzzhunter)
                            if el.get("size"):
                                print(f"       - Size: {el.get('size')} bytes")

                            # Show Risks/Priority (Spider/Parax)
                            if el.get("risks"):
                                print(f"       - {Fore.RED}Risks: {', '.join(el['risks'])}")
                            if el.get("priority"):
                                print(f"       - Priority: {el.get('priority')}")

                            if el.get("tags"):
                                print(Fore.CYAN + f"       Tags: {', '.join(el['tags'])}")

                            print()

                    # =================================================
                    # 5.5️⃣ CREDLEAK / CLOUD (Upgraded)
                    # =================================================
                    if "s3_buckets" in intel:
                        print(Fore.GREEN + "  Cloud Assets (S3):")
                        for bucket in intel["s3_buckets"]:
                            print(f"    - {Fore.CYAN}http://{bucket}.s3.amazonaws.com")
                        print()

                    if "hardcoded_creds" in intel:
                        creds = intel["hardcoded_creds"]
                        if creds:
                            print(Fore.RED + "  ⚠ Hardcoded Credentials Extracted:")
                            for cred in creds:
                                print(f"    - {Fore.YELLOW}{cred}")
                            print()

                    if "paste_hits" in intel and intel["paste_hits"]:
                        print(Fore.GREEN + "  Paste References:")
                        for link in intel["paste_hits"]:
                            print(f"    - {Fore.YELLOW}{link}")
                        print()

                    if "exposed_keys" in intel and intel["exposed_keys"]:
                        keys = intel["exposed_keys"]
                        if keys:
                            print(Fore.RED + "  ⚠ Exposed Keys Detected:")
                            for key in keys:
                                print(f"    - {key}")
                            print()

                    # =================================================
                    # 6️⃣ EMAILS / PHISHING
                    # =================================================
                    if "emails" in intel and intel["emails"]:
                        print(Fore.GREEN + "  Emails Found:")
                        for email in intel["emails"]:
                            print(f"    - {Fore.CYAN}{email}")
                        print()

                    # =================================================
                    # 6.5️⃣ PHISHING INTEL (Consolidated)
                    # =================================================
                    if "security_policy" in intel:
                        pol = intel.get("security_policy")
                        print(Fore.GREEN + "  Phishing Intel:")
                        if intel.get("phishing_domain"):
                            print(f"    Suggested Domain : {Fore.CYAN}{intel['phishing_domain']}")
                        if pol.get("spf"):
                            print(f"    SPF Status      : {Fore.YELLOW}{pol.get('spf_type')}")
                        if pol.get("dmarc"):
                            print(f"    DMARC Policy    : {Fore.YELLOW}{pol.get('dmarc_policy')}")
                        
                        # UPDATED: Show ONLY Top 10 emails + Indicate Source
                        if intel.get("target_emails"):
                            emails = intel["target_emails"]
                            signals = intel.get("signals", [])
                            
                            # Detect source of emails
                            if "SCRAPED_EMAILS_FOUND" in signals:
                                source_color = Fore.GREEN
                                source_text = "Real (Scraped from HTML)"
                            elif "SMART_PATTERN_DEDUCTION" in signals:
                                source_color = Fore.MAGENTA
                                source_text = "Derived (Pattern Matching)"
                            else:
                                source_color = Fore.LIGHTBLACK_EX
                                source_text = "Predicted (Based on Usernames)"

                            print(f"    Target Emails   : {len(emails)} found ({source_color}{source_text}{Style.RESET_ALL})")
                            
                            # ONLY SHOW TOP 10
                            for e in emails[:10]:
                                print(f"      - {Fore.CYAN}{e}")
                            
                            # Hide the rest
                            if len(emails) > 10:
                                print(f"      ... +{len(emails)-10} more (Hidden to reduce noise)")
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
                    # 7.5️⃣ VULNERABILITY SCANNER (Nikto/Nuclei) - SEIGE MODULE - FIXED
                    # =================================================
                    if "nikto_findings" in intel or "nuclei_findings" in intel:
                        print(Fore.RED + "  ⚠️  Vulnerability Scan Results:\n")

                        # --- NIKTO ---
                        if intel.get("nikto_findings"):
                            print(Fore.CYAN + "    [Nikto Issues]")
                            for f in intel["nikto_findings"]:
                                # Clean up the string slightly for display
                                # Remove the leading '+' if present for cleaner look
                                display_f = f.replace("+ ", "").strip()
                                print(Fore.WHITE + f"      • {display_f}")
                            print()

                        # --- NUCLEI ---
                        if intel.get("nuclei_findings"):
                            print(Fore.CYAN + "    [Confirmed Vulnerabilities]")
                            
                            # Sort by severity (Critical/High first)
                            vulns = intel["nuclei_findings"]
                            
                            # FIX: Use strip_ansi on findings before checking keywords
                            critical = [v for v in vulns if "[CRITICAL]" in strip_ansi(v)]
                            high = [v for v in vulns if "[HIGH]" in strip_ansi(v)]
                            medium = [v for v in vulns if "[MEDIUM]" in strip_ansi(v)]
                            low = [v for v in vulns if "[LOW]" in strip_ansi(v) or "[INFO]" in strip_ansi(v)]
                            
                            all_sorted = critical + high + medium + low
                            
                            for v in all_sorted:
                                # Clean the string for display (removes Nuclei's native colors)
                                clean_v = strip_ansi(v)
                                
                                # Color Coding based on CVSS/Severity (Hellhound Colors)
                                if "[CRITICAL]" in clean_v:
                                    print(Fore.RED + f"      🔴 {clean_v}")
                                elif "[HIGH]" in clean_v:
                                    print(Fore.LIGHTRED_EX + f"      🟠 {clean_v}")
                                elif "[MEDIUM]" in clean_v:
                                    print(Fore.YELLOW + f"      🟡 {clean_v}")
                                else:
                                    print(Fore.WHITE + f"      🟢 {clean_v}")
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

        if not self.target:
            print(Fore.RED + "[!] No prey set")
            return

        parts = arg.split()

        # -----------------------------------------
        # Determine module (case-insensitive)
        # -----------------------------------------
        module_input = self.active_module

        if parts and not parts[0].startswith("--"):
            module_input = parts[0]
            parts = parts[1:]
            
        if not module_input:
            print("Usage: strike <module> [--flags]")
            print("       strike (if tool equipped)")
            return

        # Resolve module name ignoring case
        module = None
        for m in self.modules:
            if m.lower() == module_input.lower():
                module = m
                break

        if not module:
            print(Fore.RED + f"[!] Unknown module: {module_input}")
            return


        # -----------------------------------------
        # Handle Help
        # -----------------------------------------
        if "--help" in parts:
            self._show_module_help(module)
            return

        # -----------------------------------------
        # Validate Flags
        # -----------------------------------------
        module_key = module.lower() # Always use lowercase for keys/flags
        module_flags = self.MODULE_FLAGS.get(module_key, {})
        options = {}

        for flag in parts:
            if flag not in module_flags:
                print(Fore.RED + f"[!] Unsupported flag '{flag}' for module '{module}'")
                return
            options.update(module_flags[flag])

        # ==========================================================
        # 🔥 AUTO-INTEGRATION LOGIC (Case-Insensitive)
        # ==========================================================

        # Spider → CmdInj
        if module_key == "cmdinj":
            # Check both 'spider' and 'Spider' to be safe
            spider_data = self.results.get("spider") or self.results.get("Spider")
            if spider_data:
                options["spider_results"] = spider_data
                print(Fore.CYAN + "[*] Auto-fed Spider results into CMDinj")
        
        # Spider -> Parax Auto Feed
        if module.lower() == "parax":
            if "spider" in self.results:
                spider_data = self.results["spider"]
                if isinstance(spider_data, dict) and "intel" in spider_data:
                    options["spider_intel"] = spider_data["intel"]
                    print(Fore.CYAN + "[*] Auto-fed Spider results into Parax")

        # Stalk → Surfacemap
        if module_key == "surfacemap":
            # Check both 'stalk' and 'Stalk'
            stalk_data = self.results.get("stalk") or self.results.get("Stalk")

            if stalk_data and isinstance(stalk_data, dict) and "intel" in stalk_data:
                intel = stalk_data["intel"]

                http_services = intel.get("web", {}).get("http_services", [])
                if http_services:
                    options["http_services"] = http_services
                    print(Fore.CYAN + f"[*] Auto-fed {len(http_services)} HTTP targets from Stalk")

                subdomains = intel.get("infrastructure", {}).get("subdomains", [])
                if subdomains:
                    options["subdomains"] = subdomains
                    print(Fore.CYAN + f"[*] Auto-fed {len(subdomains)} subdomains from Stalk")

        # ==========================================================

        print(Fore.YELLOW + f"[*] Executing {module}...")

        try:
            output = self.engine.run_single(module, self.target, options=options)
            
            # FIX: Store using module_key (lowercase) to prevent duplicates
            self.results[module_key] = output
            
            print(Fore.GREEN + f"[✓] {module} finished.")
        except Exception as e:
            print(Fore.RED + f"[x] {module} failed: {str(e)}")



    def _show_module_help(self, module):
        print(f"\n[ Help — {module} ]")

        flags = self.MODULE_FLAGS.get(module.lower(), {})
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
