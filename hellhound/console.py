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
            "spider": {
                "--deep": {"mode": "deep"}
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

    def _calculate_global_risk(self):
        total_risk = 0
        total_vulns = 0
        breakdown = {}

        for mod, output in self.results.items():
            module_risk = 0

            if not isinstance(output, dict):
                continue

            intel = output.get("intel", {})

            # 1️⃣ Direct risk
            module_risk += output.get("risk_score", 0)

            # 2️⃣ Standard intel risk (Spider style)
            module_risk += intel.get("risk_score", 0)

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

        if not self.results:
            print(Fore.RED + "[!] No loot collected yet")
            return

        # ==============================================
        # HELPER: Strip ANSI Color Codes
        # ==============================================
        def strip_ansi(text):
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

            print(Fore.CYAN + "\n========== [ WEB ASSESSMENT SUMMARY ] ==========\n")

            total_risk, total_vulns, breakdown = self._calculate_global_risk()

            modules_active = len(self.results)

            # Risk level thresholds
            if total_risk < 50:
                level = "LOW"
                level_color = Fore.GREEN
            elif total_risk < 150:
                level = "MEDIUM"
                level_color = Fore.YELLOW
            elif total_risk < 300:
                level = "HIGH"
                level_color = Fore.RED
            else:
                level = "CRITICAL"
                level_color = Fore.MAGENTA

            print(f"Target             : {self.target}")
            print(f"Modules Executed   : {modules_active}")
            print(f"Total Risk Score   : {total_risk} ({level_color}{level}{Style.RESET_ALL})")
            print(f"Issues Identified  : {total_vulns}")
            print("\n==========================================\n")
            return

        # ======================================================
        # 3. LOOT --EXPORT (File Export)
        # ======================================================
        if "--export" in parts:
            base_path = os.path.join("storage", "reports", self.target)
            os.makedirs(base_path, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            json_path = os.path.join(base_path, f"{timestamp}.json")
            summary_path = os.path.join(base_path, f"{timestamp}_summary.txt")

            with open(json_path, "w") as f:
                json.dump(self.results, f, indent=4, default=str)

            total_risk, total_vulns, _ = self._calculate_global_risk()
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
        # 4. LOOT (Default - Detailed Web View)
        # ======================================================
        print("\n" + Fore.CYAN + "========== [ LOOT - WEB INTEL ] ==========\n")
        
        total_risk, total_vulns, breakdown = self._calculate_global_risk()

        print(Fore.CYAN + "========== [ RISK BREAKDOWN ] ==========\n")
        for mod, score in breakdown.items():
            print(f"  {mod.upper():<12} : {score}")
        print("----------------------------------------")
        print(f"  TOTAL RISK SCORE : {total_risk}")

        if total_risk < 50:
            level = "LOW"
        elif total_risk < 150:
            level = "MEDIUM"
        elif total_risk < 300:
            level = "HIGH"
        else:
            level = "CRITICAL"

        print(Fore.RED + f"  SECURITY POSTURE   : {level}")
        print(Fore.CYAN + "========================================\n")

        printed_keys = set()

        for mod, output in self.results.items():
            mod_clean = mod.lower()
            if mod_clean in printed_keys: continue
            printed_keys.add(mod_clean)

            print(Fore.YELLOW + f"[{mod_clean.upper()}]")

            # -------------------------------------------------
            # RAW STATISTICS
            # -------------------------------------------------
            if isinstance(output, dict) and "raw" in output:
                print(Fore.WHITE + f"  Raw Stats: {output['raw']}")

            if isinstance(output, dict) and "intel" in output:
                intel = output.get("intel", {})
                
                # =================================================
                # 1️⃣ SPIDER SPECIFIC INTEL
                # =================================================
                
                # -- 1.1 Crawl Stats --
                if "stats" in intel:
                    stats = intel["stats"]
                    print(Fore.CYAN + "  [Crawl Statistics]")
                    print(f"    GET Requests : {stats.get('get', 0)}")
                    print(f"    POST Requests: {stats.get('post', 0)}")
                    print(f"    Total Links  : {stats.get('links', 0)}")
                    print(f"    JS Files     : {stats.get('js_files', 0)}")
                    print()

                # -- 1.2 API Endpoints (Surface) -- CLEANED UP
                endpoints = intel.get("endpoints", [])
                if endpoints:
                    # Sort by Priority Descending (High risk first)
                    # This reduces noise by showing the important stuff first
                    endpoints_sorted = sorted(endpoints, key=lambda x: x.get("priority", 0), reverse=True)
                    
                    print(Fore.GREEN + f"  [Surface Endpoints] ({len(endpoints)})")
                    
                    for ep in endpoints_sorted[:15]: 
                        method = ep.get("method", "GET").upper()
                        url = ep.get("url", "")
                        params = ep.get("params", [])
                        risks = ep.get("risks", [])
                        
                        # Format Risks as Color Badges
                        risk_badges = ""
                        if risks:
                            for r in risks:
                                if "SQLI" in r: risk_badges += f"{Fore.MAGENTA}[{r}] "
                                elif "CMD" in r: risk_badges += f"{Fore.RED}[{r}] "
                                elif "AUTH" in r: risk_badges += f"{Fore.RED}[{r}] "
                                elif r == "LFI_RFI_POTENTIAL": risk_badges += f"{Fore.YELLOW}[LFI] "
                                elif r == "IDOR_POTENTIAL": risk_badges += f"{Fore.YELLOW}[IDOR] "
                        
                        # Format Params (Summary)
                        param_str = ""
                        if params:
                            param_names = [p['name'] for p in params if 'name' in p]
                            if len(param_names) > 2:
                                param_str = f" ({param_names[0]}, {param_names[1]}, ... +{len(param_names)-2})"
                            else:
                                param_str = f" ({', '.join(param_names)})"

                        m_color = Fore.BLUE if method == "GET" else (Fore.MAGENTA if method == "POST" else Fore.CYAN)
                        
                        print(f"    {m_color}{method:<6}{Style.RESET_ALL} {url}{param_str} {risk_badges}")
                    
                    if len(endpoints) > 15: print(f"    ... +{len(endpoints)-15} more")
                    print()

                # -- 1.3 JS Endpoints --
                js_endpoints = intel.get("js_endpoints", [])
                if js_endpoints:
                    print(Fore.GREEN + f"  [Discovered API Routes] ({len(js_endpoints)} found in JS)")
                    
                    for ep in js_endpoints[:25]: 
                        if isinstance(ep, dict):
                            path = ep.get("path", "Unknown")
                            method = ep.get("method", "GET")
                            conf = ep.get("confidence", 0)
                            
                            m_color = Fore.BLUE if method == "GET" else (Fore.MAGENTA if method == "POST" else Fore.CYAN)
                            conf_color = Fore.GREEN if conf > 0.8 else (Fore.YELLOW if conf > 0.5 else Fore.RED)
                            
                            print(f"    {m_color}{method:<6}{Style.RESET_ALL} {path} ({conf_color}conf: {conf}{Style.RESET_ALL})")
                        else:
                            print(f"    {Fore.WHITE}{ep}")
                    
                    if len(js_endpoints) > 25: print(f"    ... +{len(js_endpoints)-25} more hidden")
                    print()

                # -- 1.4 JavaScript Files --
                js_files = intel.get("js_files", [])
                if js_files:
                    print(Fore.GREEN + "  [JavaScript Files]")
                    for js in js_files:
                        print(f"    - {Fore.CYAN}{js}")
                    print()

                # -- 1.5 Auth Surfaces --
                auth_surfaces = intel.get("auth_surfaces", [])
                if auth_surfaces:
                    print(Fore.YELLOW + "  [Authentication Surfaces]")
                    for auth in auth_surfaces:
                        print(f"    - {Fore.RED}{auth}")
                    print()

                # -- 1.6 Tech Stack --
                tech_stack = intel.get("tech_stack", [])
                if tech_stack:
                    print(Fore.GREEN + "  [Technology Stack]")
                    for tech in tech_stack:
                        print(f"    - {Fore.CYAN}{tech}")
                    print()

                # -- 1.7 GraphQL --
                graphql = intel.get("graphql", [])
                if graphql:
                    print(Fore.MAGENTA + "  [GraphQL Endpoints]")
                    for g in graphql:
                        print(f"    - {g}")
                    print()

                # -- 1.8 Comments --
                comments = intel.get("comments", [])
                if comments:
                    print(Fore.GREEN + "  [Developer Comments]")
                    for c in comments:
                        print(f"    - {Fore.YELLOW}{c[:80]}{'...' if len(c) > 80 else ''}")
                    print()

                # -- 1.9 Security Headers --
                sec_headers = intel.get("security_headers", {})
                if sec_headers:
                    print(Fore.GREEN + "  [Security Headers]")
                    for k, v in sec_headers.items():
                        print(f"    {Fore.CYAN}{k:<25}: {Fore.WHITE}{v}")
                    print()

                # -- 1.10 Signals --
                signals = intel.get("signals", [])
                if signals:
                    print(Fore.RED + "  [Security Signals]")
                    for s in signals:
                        print(f"    - {s}")
                    print()

                # -- 1.11 Potential Keys --
                pot_keys = intel.get("potential_keys", [])
                if pot_keys:
                    print(Fore.RED + "  [Potential Secrets/Keys]")
                    for k in pot_keys:
                        print(f"    - {k}")
                    print()

                # -- 1.12 JS Parameters --
                params = intel.get("js_parameters", [])
                if params:
                    print(Fore.GREEN + f"  [JS Parameters] ({len(params)})")
                    print(f"    {Fore.WHITE}{', '.join(params)}")
                    print()

                # -- 1.13 Robots.txt --
                robots_disallowed = intel.get("robots_disallowed", [])
                robots_raw = intel.get("robots_raw", "")
                
                if robots_disallowed:
                    print(Fore.GREEN + "  [Robots.txt Intel]")
                    print(f"    Disallowed: {', '.join(robots_disallowed)}")
                    if robots_raw:
                        print(f"    Raw Content:\n{Fore.LIGHTBLACK_EX}{robots_raw}")
                    print()

                # =================================================
                # 2️⃣ BAC MODULE (Access Control)
                # =================================================
                if "bac" in intel:
                    bac_data = intel["bac"]
                    findings = bac_data.get("findings", [])
                    summary = bac_data.get("summary", {})
                    
                    if summary:
                        print(Fore.GREEN + "  [Vulnerability Summary]")
                        order = ["Critical", "High", "Medium", "Low", "Info"]
                        for sev in order:
                            if sev in summary:
                                count = summary[sev]
                                color = Fore.RED if sev in ["Critical", "High"] else (Fore.YELLOW if sev == "Medium" else Fore.WHITE)
                                print(f"    {color}{sev:<8} : {count}")
                        print()
                    
                    if findings:
                        print(Fore.RED + "  [Detailed BAC Findings]")
                        
                        sev_weight = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                        sorted_findings = sorted(findings, key=lambda x: sev_weight.get(x.get("severity", "Info"), 99))

                        for f in sorted_findings:
                            sev = f.get("severity", "Unknown").upper()
                            name = f.get("vulnerability", "Unknown")
                            ep = f.get("endpoint", "N/A")
                            param = f.get("parameter", "")
                            evidence = f.get("evidence", "")
                            
                            c_sev = Fore.MAGENTA if sev == "CRITICAL" else (Fore.RED if sev == "HIGH" else (Fore.YELLOW if sev == "MEDIUM" else Fore.WHITE))
                            
                            print(f"    {Style.BRIGHT}[{c_sev}{sev}{Style.RESET_ALL}] {Fore.WHITE}{name}")
                            print(f"       Endpoint  : {Fore.CYAN}{ep}")
                            if param: print(f"       Parameter : {Fore.LIGHTBLACK_EX}{param}")
                            
                            if evidence:
                                clean_evi = evidence.replace('\n', ' ')[:120].strip()
                                if len(evidence) > 120: clean_evi += "..."
                                print(f"       Evidence   : {Fore.LIGHTBLACK_EX}{clean_evi}")
                            print()
                    else:
                        print(Fore.GREEN + "  [+] No access control issues detected.\n")

                # =================================================
                # 3️⃣ GENERAL VULNERABILITIES
                # =================================================
                if "vulnerabilities" in intel:
                    vulns = intel.get("vulnerabilities", [])
                    if vulns:
                        print(Fore.RED + "  [General Vulnerabilities]\n")
                        for idx, v in enumerate(vulns, 1):
                            vtype = v.get("type", "UNKNOWN")
                            url = v.get("url", "")
                            print(Fore.YELLOW + f"  [{idx}] {vtype}")
                            print(f"       Target  : {Fore.CYAN}{url}")
                            if v.get("proof"): print(f"       Proof   : {Fore.MAGENTA}{v.get('proof')}")
                            print()

                # =================================================
                # 4️⃣ EXTERNAL SCANNERS
                # =================================================
                if "nikto_findings" in intel or "nuclei_findings" in intel:
                    print(Fore.RED + "  [External Scanner Results]\n")

                    if intel.get("nikto_findings"):
                        print(Fore.CYAN + "    [Nikto]")
                        for f in intel["nikto_findings"]:
                            print(Fore.WHITE + f"      • {f.replace('+ ', '').strip()}")
                        print()

                    if intel.get("nuclei_findings"):
                        print(Fore.CYAN + "    [Nuclei]")
                        vulns = intel["nuclei_findings"]
                        critical = [v for v in vulns if "[CRITICAL]" in strip_ansi(v)]
                        high = [v for v in vulns if "[HIGH]" in strip_ansi(v)]
                        medium = [v for v in vulns if "[MEDIUM]" in strip_ansi(v)]
                        low = [v for v in vulns if "[LOW]" in strip_ansi(v)]
                        
                        for v in critical + high + medium + low:
                            clean_v = strip_ansi(v)
                            c = Fore.RED if "[CRITICAL]" in clean_v else (Fore.LIGHTRED_EX if "[HIGH]" in clean_v else (Fore.YELLOW if "[MEDIUM]" in clean_v else Fore.WHITE))
                            print(c + f"      {clean_v}")
                        print()

            # -------------------------------------------------
            # RAW FALLBACK
            # -------------------------------------------------
            elif isinstance(output, dict):
                if "raw" in output: print(Fore.WHITE + output["raw"])
                elif "summary" in output: print(Fore.WHITE + str(output["summary"]))
                else: print(Fore.WHITE + str(output))
            elif isinstance(output, list):
                for item in output: print(Fore.WHITE + f"    - {item}")
            elif isinstance(output, str):
                print(Fore.WHITE + output.strip()[:1000])

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
