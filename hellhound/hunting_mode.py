import click
import os
import json
import sys
import time
import random
import datetime
import requests
import string
import textwrap
import threading  # Added for timeout functionality
from colorama import Fore, Back, Style, init
from hellhound.modules import discover_modules
from hellhound.core.emit import Emit

# Initialize colorama
init(autoreset=True)

class HellhoundFramework:
    def __init__(self, mode="brutal", target="192.168.1.1"):
        self.mode = mode
        self.target = target

    def _get_banner_raw(self):
        """Helper to return the raw banner string."""
        return textwrap.dedent(r"""


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
""")

    def _display_banner(self):
        """Static banner for the Final Report (No Animation)."""
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = self._get_banner_raw()
        print(Fore.RED + banner + Style.RESET_ALL)
        print(Fore.CYAN + "               HELLHOUND PENTEST FRAMEWORK v1.0" + Style.RESET_ALL)
        print(Fore.CYAN + "=" * 75 + Style.RESET_ALL + "\n")

    def _kernel_panic(self):
        """Simulates a system crash before the actual boot."""
        os.system('cls' if os.name == 'nt' else 'clear')
        panic_text = [
            "KERNEL PANIC", "MEMORY DUMP INITIATED", 
            "0x000000 ACCESS VIOLATION", "CORRUPTING SECTORS...",
            "fsociety was here", "REBOOTING..."
        ]
        
        for _ in range(20):
            bg = random.choice([Back.BLACK, Back.RED, Back.WHITE])
            fg = random.choice([Fore.RED, Fore.WHITE, Fore.BLACK, Fore.GREEN])
            y = random.randint(1, 10)
            x = random.randint(1, 40)
            msg = random.choice(panic_text)
            sys.stdout.write(f"\033[{y};{x}H{bg}{fg}{msg}")
            sys.stdout.flush()
            time.sleep(0.03)

        time.sleep(0.5)
        os.system('cls' if os.name == 'nt' else 'clear')

    def _mega_glitch(self, banner_lines):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in banner_lines:
            print(Fore.RED + line)
        
        iterations = 30
        height = len(banner_lines)
        
        for i in range(iterations):
            target_line_idx = random.randint(0, height - 1)
            original_line = banner_lines[target_line_idx]
            line_len = len(original_line) 
            if line_len == 0: continue

            glitch_type = random.choice(['shift', 'corrupt', 'invert', 'tear'])
            sys.stdout.write(f"\033[{target_line_idx + 1};0H")
            
            if glitch_type == 'shift':
                offset = random.randint(-2, 5)
                space = " " * max(0, offset)
                color = random.choice([Fore.WHITE, Fore.CYAN, Fore.YELLOW])
                sys.stdout.write(f"{color}{space}{original_line}")

            elif glitch_type == 'corrupt':
                new_line = list(original_line)
                for _ in range(min(5, line_len)):
                    pos = random.randint(0, line_len - 1)
                    new_line[pos] = random.choice(['#', '@', '%', '&', '?'])
                sys.stdout.write(f"{Fore.WHITE}{''.join(new_line)}")

            elif glitch_type == 'invert':
                bg = Back.RED if i % 2 == 0 else Back.WHITE
                fg = Fore.BLACK if i % 2 == 0 else Fore.RED
                sys.stdout.write(f"{bg}{fg}{original_line}")

            elif glitch_type == 'tear':
                if target_line_idx < height - 1 and line_len > 10:
                    max_slice = min(20, line_len - 1)
                    slice_len = random.randint(5, max_slice)
                    start_pos = random.randint(0, line_len - slice_len)
                    slice_text = original_line[start_pos : start_pos+slice_len]
                    
                    sys.stdout.write(f"\033[{target_line_idx + 2};{start_pos}H")
                    sys.stdout.write(f"{Fore.CYAN}{slice_text}")

            sys.stdout.flush()
            time.sleep(0.04)

        time.sleep(0.1)
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in banner_lines:
            print(Fore.RED + line)

    def _type_text_jitter(self, text, color=Fore.CYAN):
        sys.stdout.write(color)
        for i, char in enumerate(text):
            sys.stdout.write(char)
            sys.stdout.flush()
            if random.random() < 0.05:
                sys.stdout.write("\b")
                time.sleep(0.05)
                sys.stdout.write(char)
                sys.stdout.flush()
            time.sleep(random.uniform(0.01, 0.05))
        print(Style.RESET_ALL)

    def boot_sequence(self):
        self._kernel_panic()
        banner_lines = self._get_banner_raw().split('\n')
        self._mega_glitch(banner_lines)
        
        # FIXED: Added extra newlines to prevent text overlap
        print("\n\n") 
        
        self._type_text_jitter("               HELLHOUND PENTEST FRAMEWORK v1.0")
        print(Fore.CYAN + "=" * 75 + Style.RESET_ALL + "\n")

        mode_name = self.mode.upper()
        self._type_text_jitter(f"[*] INITIALIZING PROTOCOL: {mode_name}...")
        
        for _ in range(15):
            hex_str = " ".join([f"{random.randint(0, 255):02X}" for _ in range(12)])
            c = random.choice([Fore.GREEN, Fore.WHITE, Fore.CYAN])
            print(f"   [LOADING] {c}{hex_str}")
            time.sleep(0.04)
            sys.stdout.write("\033[1F")

        for _ in range(15):
            sys.stdout.write("\033[2K")
            sys.stdout.write("\033[1A")

        time.sleep(0.2)
        if self.mode == "stealth":
            print(f"{Fore.GREEN}[+] STEALTH MODULES: INJECTED{Style.RESET_ALL}")
        elif self.mode == "camouflage":
            print(f"{Fore.GREEN}[+] CAMOUFLAGE PROTOCOLS: ACTIVE{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[+] BRUTAL FORCE VECTOR: ARMED{Style.RESET_ALL}")

        print()
        for _ in range(3):
            sys.stdout.write(f"\r[+] TARGET LOCKED: {Fore.RED}{self.target}{Style.RESET_ALL}       ")
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write(f"\r[+] TARGET LOCKED: {Fore.WHITE}{self.target}{Style.RESET_ALL}       ")
            sys.stdout.flush()
            time.sleep(0.1)
        
        print(f"\n[+] TARGET LOCKED: {Fore.RED}{self.target}{Style.RESET_ALL}\n")

# ============================================================
# REAL-TIME INTELLIGENCE ENGINE (Cleaned up)
# ============================================================
class RealTimeCVSS:
    def __init__(self):
        self.nist_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.request_delay = 1.5 

    def get_vulnerability_data(self, signal_name):
        if "ERROR" in signal_name or "CRASH" in signal_name or "TIMEOUT" in signal_name or "DUMP" in signal_name:
            return {"desc": signal_name, "cvss": 0.0, "cve": "N/A", "severity": "Info", "source": "System"}

        # FIXED: Removed verbose click.echo to stop table breaking
        # click.echo(f"    [⚙] Risk: {signal_name}...", nl=False) 
        
        api_result = self._query_nist_api(signal_name)
        if api_result:
            # click.echo(f" {Fore.GREEN}[API]{Style.RESET_ALL}")
            return api_result

        # click.echo(f" {Fore.YELLOW}[HEURISTIC]{Style.RESET_ALL}")
        return self._heuristic_calculate(signal_name)

    def _query_nist_api(self, keyword):
        try:
            time.sleep(self.request_delay)
            params = {"keywordSearch": keyword, "resultsPerPage": 1}
            response = requests.get(self.nist_api_url, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                    vuln = data["vulnerabilities"][0]
                    cve = vuln["cve"]["id"]
                    metrics = vuln["cve"]["metrics"]
                    if "cvssMetricV31" in metrics:
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                        return {"desc": keyword, "cvss": score, "cve": cve, "severity": severity, "source": "API"}
        except Exception:
            pass
        return None

    def _heuristic_calculate(self, signal_name):
        name_lower = signal_name.lower()
        if any(x in name_lower for x in ["rce", "remote code", "buffer overflow", "inject", "sql"]):
            return {"desc": signal_name, "cvss": 9.8, "cve": "PENDING", "severity": "Critical", "source": "Heuristic"}
        if any(x in name_lower for x in ["xss", "csrf", "auth bypass", "privilege"]):
            return {"desc": signal_name, "cvss": 8.1, "cve": "PENDING", "severity": "High", "source": "Heuristic"}
        if any(x in name_lower for x in ["disclosure", "leak", "info", "misconfig", "default", "open port"]):
            return {"desc": signal_name, "cvss": 5.3, "cve": "N/A", "severity": "Medium", "source": "Heuristic"}
        if any(x in name_lower for x in ["version", "banner", "fingerprint", "dump"]):
            return {"desc": signal_name, "cvss": 0.0, "cve": "N/A", "severity": "Info", "source": "Heuristic"}
        return {"desc": signal_name, "cvss": 4.3, "cve": "UNKNOWN", "severity": "Medium", "source": "Heuristic"}


POST_EXPLOIT_IDEAS = {
    "RCE": "Attempt Metasploit exploit.",
    "SQL": "Use SQLMap to dump credentials.",
    "XSS": "Capture cookies via BeEF.",
    "AUTH": "Try default credentials.",
    "MISCONFIG": "Review config files.",
    "INFO": "Search Exploit-DB manually."
}

class HuntingMode(HellhoundFramework):

    MODULE_POLICIES = {
        "camouflage": {"camouflage_recon": {}},
        "stealth": {
            "nmap": {"profile": "quick"},
            "stalk": {"mode": "quick"},
            "ftp": {"mode": "banner"},
            "ssh": {"mode": "banner"},
            "vhost": {"intensity": "light"},
        },
        "brutal": {
            "nmap": {"profile": "full"},
            "stalk": {"mode": "deep"},
            "ftp": {"mode": "full"},
            "ssh": {"mode": "full"},
            "vhost": {"intensity": "deep"},
            "dirsearch": {"depth": "max"},
            "nikto": {"scan": "full"},
            "nuclei": {"templates": "all"},
            "files": {"mode": "aggressive"},
            "users": {"mode": "aggressive"},
        }
    }

    def __init__(self, target, mode="camouflage"):
        super().__init__(mode, target)
        self.current_phase = mode 
        self.modules = discover_modules()
        
        self.base_path = os.path.join(os.getcwd(), "hellhound_storage")
        if not os.path.exists(self.base_path):
            try:
                os.makedirs(self.base_path)
            except Exception as e:
                click.echo(f"[!] Could not create storage directory: {e}")

        self.global_intel = {
            "target": target,
            "start_time": str(datetime.datetime.now()),
            "phases": {"camouflage": {}, "stealth": {}, "brutal": {}},
            "all_signals": [], 
            "confidence": 0.0
        }
        
        self.emit = Emit(click.echo)
        self.cvss_engine = RealTimeCVSS()
        self.final_report_lines = []

    # ==========================================
    # HELPER: TIMEOUT WRAPPER (Prevents Hanging)
    # ==========================================
    def _run_with_timeout(self, func, args=(), kwargs={}, timeout=60):
        result = [None]
        exception = [None]
        def worker():
            try:
                result[0] = func(*args, **kwargs)
            except Exception as e:
                exception[0] = e
        
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        t.join(timeout)
        
        if t.is_alive():
            return None # Indicates timeout
        if exception[0]:
            raise exception[0]
        return result[0]

    # ==========================================
    # HELPER: SANITIZE OUTPUT (Fixes Messy Table)
    # ==========================================
    def _sanitize_signals(self, raw_text):
        if not raw_text: return []
        
        # If it's a dict, return as is (already structured)
        if isinstance(raw_text, dict): 
            return raw_text.get("signals", [])

        # If it's a string, split into lines
        lines = str(raw_text).split('\n')
        clean_signals = []
        
        for line in lines:
            line = line.strip()
            # Filter out noise
            if not line: continue
            if "Starting Nmap" in line: continue
            if "Nmap done" in line: continue
            if "Nmap scan report" in line: continue
            if "Service detection performed" in line: continue
            if "PORT   STATE" in line: continue
            if "Recon depth?" in line: continue
            if "Recon depth" in line: continue
            if "Using recon depth" in line: continue
            if "Probing HTTP services" in line: continue
            if "Fingerprinting technologies" in line: continue
            if "Web reconnaissance complete" in line: continue
            if "FTP module running" in line: continue
            if "Checking FTP service" in line: continue
            if "FTP enumeration completed" in line: continue
            if "SSH enumeration completed" in line: continue
            if "Starting virtual host enumeration" in line: continue
            if "VHOST fuzzing completed" in line: continue
            if "Starting directory discovery" in line: continue
            if "Directory discovery completed" in line: continue
            if "Starting Nikto scan" in line: continue
            if "CMD]" in line: continue
            
            # If line is massive (raw dump), summarize
            if len(line) > 100:
                # If it looks like port info, try to extract it
                if "tcp" in line and "http" in line:
                     clean_signals.append(line[:80] + "...") # Allow port info
                else:
                     clean_signals.append(f"[DATA DUMP] Raw output ({len(line)} chars) saved to report")
            else:
                clean_signals.append(line)
                
        # If nothing was extracted, provide a generic success message
        if not clean_signals:
            return ["Module executed successfully (No raw output parsed)"]
            
        return clean_signals[:10] # Limit to 10 entries to prevent flooding

    def run(self):
        self.boot_sequence()

        if self.current_phase in ["camouflage", "hunt"]:
            self.run_phase("camouflage")
            self.show_interim_summary("camouflage")
            if not self.confirm_next_phase("STEALTH"):
                self.finalize_and_save()
                return

        self.run_phase("stealth", context_from="camouflage")
        self.show_interim_summary("stealth")
        if not self.confirm_next_phase("BRUTAL"):
            self.finalize_and_save()
            return

        self.run_phase("brutal", context_from="stealth")
        self.show_interim_summary("brutal")
        self.finalize_and_save()

    def run_phase(self, phase_name, context_from=None):
        click.echo(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}[*] INITIATING PHASE: {phase_name.upper()}{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        if context_from:
            prev_data = self.global_intel["phases"][context_from]
            prev_count = sum(len(d.get("signals", [])) for d in prev_data.values())
            click.echo(f"[!] CONTEXT: Loaded {prev_count} signals from {context_from.upper()}.\n")

        policy = self.MODULE_POLICIES.get(phase_name)
        phase_results = {}
        
        for module_name, options in policy.items():
            click.echo(f"[>] Executing Module: {Fore.CYAN}{module_name}{Style.RESET_ALL}")
            
            # FIXED: Check if module exists in discovery list to avoid Camouflage crash
            if module_name not in self.modules:
                click.echo(f"    [!] Module '{module_name}' not found in discovery list. Skipping.")
                phase_results[module_name] = {"signals": [f"SKIP: Module {module_name} not installed"]}
                continue
            
            module_meta = self.modules.get(module_name)
            module = module_meta["module"]
            
            try:
                # FIXED: Use Timeout Wrapper (60s max per module)
                result = self._run_with_timeout(module.run, args=(self.target, self.emit), kwargs={"options": options}, timeout=60)
                
                if result is None:
                    click.echo(f"    [!] {Fore.RED}Module timed out (60s limit).{Style.RESET_ALL}")
                    phase_results[module_name] = {"signals": [f"TIMEOUT: {module_name} took too long"]}
                    continue

                # Process Result
                if isinstance(result, dict):
                    phase_results[module_name] = result
                    self.process_signals(result.get("signals", []))
                elif isinstance(result, str) or isinstance(result, bytes):
                    # Sanitize raw text output
                    clean_signals = self._sanitize_signals(result)
                    phase_results[module_name] = {"signals": clean_signals}
                    self.process_signals(clean_signals)
                else:
                    phase_results[module_name] = {"signals": []}
                    
            except Exception as e:
                err_msg = f"CRASH: {str(e)}"
                click.echo(f"    [!] {err_msg}")
                phase_results[module_name] = {"signals": [err_msg]}

        self.global_intel["phases"][phase_name] = phase_results
        click.echo(f"\n{Fore.GREEN}[✓] PHASE {phase_name.upper()} COMPLETED.{Style.RESET_ALL}")

    def show_interim_summary(self, phase_name):
        click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}    PHASE REPORT: {phase_name.upper()}{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        phase_data = self.global_intel["phases"][phase_name]
        if not phase_data:
            click.echo("[-] Phase executed but returned no data.")
            return

        print(f"{'MODULE':<15} | {'FINDING':<30} | {'SEVERITY'}")
        print("-" * 60)
        
        has_findings = False
        for mod_name, data in phase_data.items():
            signals = data.get("signals", [])
            if not signals: continue
            
            has_findings = True
            for sig in signals:
                calc = self.cvss_engine.get_vulnerability_data(sig)
                sev_color = Fore.RED if calc['severity'] in ['Critical','High'] else Fore.YELLOW if calc['severity'] == 'Medium' else Fore.WHITE
                # FIXED: Truncate finding display to fit table
                display_sig = sig[:30] + "..." if len(sig) > 30 else sig
                print(f"{mod_name:<15} | {display_sig:<30} | {sev_color}{calc['severity']:<10}{Style.RESET_ALL}")
        
        if not has_findings:
            click.echo("[-] No vulnerabilities detected in this phase.")

    def finalize_and_save(self):
        self._display_banner()

        print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.RED}           MASTER ATTACK CHAIN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}\n")

        report_content = []
        report_content.append(f"HELLHOUND PENTEST REPORT - {self.target}")
        report_content.append(f"Date: {self.global_intel['start_time']}\n")
        report_content.append("="*70)
        report_content.append("MASTER ATTACK CHAIN SUMMARY")
        report_content.append("="*70 + "\n")
        
        for phase in ["camouflage", "stealth", "brutal"]:
            phase_data = self.global_intel["phases"][phase]
            if not phase_data:
                report_content.append(f">> Phase: {phase.upper()} - [NO DATA]")
                print(f"{Fore.CYAN}>> Phase: {phase.upper()}{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}[NO DATA]{Style.RESET_ALL}")
                continue

            print(f"{Fore.CYAN}>> Phase: {phase.upper()}{Style.RESET_ALL}")
            report_content.append(f">> Phase: {phase.upper()}")
            
            phase_has_data = False
            for mod_name, data in phase_data.items():
                signals = data.get("signals", [])
                if not signals: 
                    report_content.append(f"    Module: {mod_name:<15} | Status: Clean/No Output")
                    print(f"    Module: {mod_name:<15} | Status: {Fore.GREEN}Clean{Style.RESET_ALL}")
                    continue

                phase_has_data = True
                for sig in signals:
                    calc = self.cvss_engine.get_vulnerability_data(sig)
                    self.global_intel["all_signals"].append(sig)
                    
                    sev_color = Fore.RED if calc['severity'] in ['Critical','High'] else Fore.YELLOW if calc['severity'] == 'Medium' else Fore.WHITE
                    display_sig = sig[:30] + "..." if len(sig) > 30 else sig
                    print(f"    Module: {mod_name:<15} | Vuln: {display_sig:<30} | {sev_color}{calc['cvss']} ({calc['severity']}){Style.RESET_ALL}")
                    
                    report_content.append(f"    Module: {mod_name:<15} | Vuln: {sig:<30} | CVSS: {calc['cvss']} ({calc['severity']}) | Source: {calc['source']}")
            
            if not phase_has_data:
                 print(f"    {Fore.LIGHTBLACK_EX}All modules executed but found no vulnerabilities.{Style.RESET_ALL}")
                 report_content.append(f"    All modules executed but found no vulnerabilities.")

            print("")
            report_content.append("")

        print(f"{Fore.GREEN}[+] SUGGESTED POST-EXPLOITATION{Style.RESET_ALL}")
        report_content.append("\nSUGGESTED POST-EXPLOITATION ACTIONS:")
        
        found_actions = False
        for sig in self.global_intel["all_signals"]:
            for key, action in POST_EXPLOIT_IDEAS.items():
                if key.lower() in sig.lower() and "ERROR" not in sig and "CRASH" not in sig and "TIMEOUT" not in sig:
                    print(f"    * {action}")
                    report_content.append(f"    * {action}")
                    found_actions = True
        
        if not found_actions:
            print("    [-] Manual review required.")
            report_content.append("    [-] Manual review required.")

        self._save_text_report("\n".join(report_content))
        
        print(f"\n{Fore.RED}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}[+] HUNT COMPLETE & REPORT SAVED.{Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}")

    def _save_text_report(self, content):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"hunt_report_{self.target}_{timestamp}.txt"
        filepath = os.path.join(self.base_path, filename)
        
        try:
            with open(filepath, "w") as f:
                f.write(content)
            print(f"\n[!] Report saved to: {Fore.CYAN}{filepath}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n[!] CRITICAL: Failed to save report to {filepath}")
            print(f"    Error: {e}")
            try:
                with open("hunt_report_fallback.txt", "w") as f:
                    f.write(content)
                print(f"[!] Saved to: hunt_report_fallback.txt")
            except:
                pass

    def process_signals(self, signals):
        for signal in signals:
            if "ERROR" in signal or "CRASH" in signal or "TIMEOUT" in signal: continue 
            
            if signal not in self.global_intel["all_signals"]:
                pass 
            
            if "RCE" in signal: self.global_intel["confidence"] += 0.5
            elif "INTERNAL" in signal: self.global_intel["confidence"] += 0.1
            elif "VULN" in signal: self.global_intel["confidence"] += 0.2
        self.global_intel["confidence"] = min(self.global_intel["confidence"], 1.0)

    def confirm_next_phase(self, next_phase_name):
        choice = click.prompt(
            f"\n[?] Proceed to {Fore.RED}{next_phase_name}{Style.RESET_ALL} mode? (yes/no)",
            default="yes"
        )
        return choice.lower() in ["yes", "y"]
