import click
import time
import sys
import os
import random
from colorama import Fore, Back, Style, init
from hellhound.modules import discover_modules
from hellhound.core.emit import Emit

# Initialize colorama
init(autoreset=True)

class HuntingMode:

    # ==================================================
    # POLICY ENGINE
    # ==================================================
    MODULE_POLICIES = {

        # ------------------------------
        # CAMOUFLAGE (Passive Only)
        # ------------------------------
        "camouflage": {
            "asset_recon": {},
            "dns_recon": {}
        },

        # ------------------------------
        # STEALTH (Low Interaction)
        # ------------------------------
        "stealth": {
            "asset_recon": {},
            "dns_recon": {},
            "nmap": {"profile": "quick"},
            "stalk": {"mode": "quick"},
            "ftp": {"mode": "banner"},
            "ssh": {"mode": "banner"},
            "vhost": {"intensity": "light"},
        },

        # ------------------------------
        # BRUTAL (Full Attack)
        # ------------------------------
        "brutal": {
            "asset_recon": {},
            "dns_recon": {},
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

    # ==================================================
    # INIT
    # ==================================================
    def __init__(self, target, mode="camouflage"):
        self.target = target
        self.mode = mode
        self.modules = discover_modules()
        self.knowledge = {}
        self.confidence = 0.0
        self.emit = Emit(click.echo)

    # ==================================================
    # ENTRY
    # ==================================================
    def run(self):
        self.boot_sequence()

        policy = self.MODULE_POLICIES.get(self.mode, {})

        if not policy:
            click.echo("[!] No policy defined for this mode.")
            return

        for module_name, options in policy.items():
            self.execute_module(module_name, options)

        self.generate_summary()

    # ==================================================
    # BOOT SEQUENCE (PROFESSIONAL FRAMEWORK EDITION)
    # ==================================================
    def boot_sequence(self):
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')

        # 1. The Framework Header (MSF Style)
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  HELLHOUND PENTEST FRAMEWORK v1.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  [ Code Name: Cerberus ]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

        # 2. Select Mode Boot
        if self.mode == "camouflage":
            self._boot_camouflage()
        elif self.mode == "stealth":
            self._boot_stealth()
        else: # Brutal
            self._boot_brutal()

        click.echo(f"[+] Target locked: {self.target}\n")

    # --------------------------------------------------
    # ANIMATION: CAMOUFLAGE (Identity Concealment)
    # Visual: Loading checks for spoofing and masking
    # --------------------------------------------------
    def _boot_camouflage(self):
        print(f"{Fore.WHITE}[*] Initializing Passive Recon Engine...{Style.RESET_ALL}")
        
        # Technical tasks list
        tasks = [
            "Loading User-Agent Spoofers",
            "Initializing MAC Address Randomizer",
            "Setting Network Delay: 5000ms",
            "Verifying Passive DNS Caching",
            "Masking HTTP Headers"
        ]
        
        self._run_load_sequence(tasks, Fore.LIGHTBLACK_EX, speed=0.1)
        
        print(f"{Fore.GREEN}[+] SYSTEM READY: TRAFFIC OBFUSCATED{Style.RESET_ALL}")

    # --------------------------------------------------
    # ANIMATION: STEALTH (Network Evasion)
    # Visual: Loading checks for IDS evasion
    # --------------------------------------------------
    def _boot_stealth(self):
        print(f"{Fore.WHITE}[*] Initializing Evasive Tactics Engine...{Style.RESET_ALL}")
        
        tasks = [
            "Loading Nmap Decoy Modules",
            "Setting Timing: T2 (Polite)",
            "Disabling ICMP Pings (-Pn)",
            "Generating Random Source Ports",
            "Parsing Firewall Signatures"
        ]
        
        self._run_load_sequence(tasks, Fore.YELLOW, speed=0.08)
        
        print(f"{Fore.YELLOW}[+] SYSTEM READY: EVASION ACTIVE{Style.RESET_ALL}")

    # --------------------------------------------------
    # ANIMATION: BRUTAL (Exploitation Arming)
    # Visual: Loading checks for weaponization
    # --------------------------------------------------
    def _boot_brutal(self):
        print(f"{Fore.RED}[*] Initializing Aggressive Exploitation Engine...{Style.RESET_ALL}")
        
        tasks = [
            "Maximizing Concurrency Threads (50)",
            "Loading Vulnerability Payloads",
            "Bypassing WAF Signatures",
            "Arming Web Attack Vectors",
            "Initializing Brute-Force Dictionaries"
        ]
        
        # Faster speed to imply aggression
        self._run_load_sequence(tasks, Fore.RED, speed=0.05)
        
        print(f"{Fore.RED}[+] SYSTEM READY: WEAPONS FREE{Style.RESET_ALL}")

    # --------------------------------------------------
    # HELPER: The "Framework Loader"
    # Mimics the loading bars of professional tools
    # --------------------------------------------------
    def _run_load_sequence(self, tasks, color, speed):
        """
        Generates a professional loading checklist.
        """
        for task in tasks:
            sys.stdout.write(f"\r{color}[LOADING] ... {Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(speed)
            
            sys.stdout.write(f"\r{color}[+] {task}{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(speed)

    # ==================================================
    # MODULE EXECUTION (Unchanged)
    # ==================================================
    def execute_module(self, name, options):

        module_meta = self.modules.get(name)

        if not module_meta:
            click.echo(f"[!] Module '{name}' not found.")
            return

        module = module_meta["module"]

        click.echo(f"[>] Running module: {name}")
        if options:
            click.echo(f"    ↳ Policy: {options}")

        try:
            result = module.run(self.target, self.emit, options=options)
            if isinstance(result, dict):
                self.knowledge[name] = result
                self.process_signals(result)

        except Exception as e:
            click.echo(f"[!] Module '{name}' failed: {e}")
            
    def process_signals(self, data):

        signals = data.get("signals", [])

        for signal in signals:
            self.emit.info(f"[signal] {signal}")

            # Example scoring logic
            if signal in ["ZONE_TRANSFER_POSSIBLE"]:
                self.confidence += 0.3

            if signal in ["CDN_DETECTED", "CLOUD_HOSTED"]:
                self.confidence += 0.1

            if signal in ["MULTIPLE_IPS"]:
                self.confidence += 0.05

        # Cap confidence
        self.confidence = min(self.confidence, 1.0)

    # ==================================================
    # EMIT HANDLER (Unchanged)
    # ==================================================
    def emit(self, message):
        click.echo(f"    {message}")

    # ==================================================
    # SUMMARY (Unchanged)
    # ==================================================
    def generate_summary(self):

        click.echo("\n[+] Hunting Summary")
        click.echo("-" * 40)
        click.echo(f"Target      : {self.target}")
        click.echo(f"Mode        : {self.mode}")
        click.echo(f"Confidence  : {self.confidence}")
        click.echo("-" * 40)


    # ==================================================
    # MODULE EXECUTION
    # ==================================================
    def execute_module(self, name, options):

        module_meta = self.modules.get(name)

        if not module_meta:
            click.echo(f"[!] Module '{name}' not found.")
            return

        module = module_meta["module"]

        click.echo(f"[>] Running module: {name}")
        if options:
            click.echo(f"    ↳ Policy: {options}")

        try:
            result = module.run(self.target, self.emit, options=options)
            if isinstance(result, dict):
                self.knowledge[name] = result
                self.process_signals(result)

        except Exception as e:
            click.echo(f"[!] Module '{name}' failed: {e}")
            
    def process_signals(self, data):

        signals = data.get("signals", [])

        for signal in signals:
            self.emit.info(f"[signal] {signal}")

            # Example scoring logic
            if signal in ["ZONE_TRANSFER_POSSIBLE"]:
                self.confidence += 0.3

            if signal in ["CDN_DETECTED", "CLOUD_HOSTED"]:
                self.confidence += 0.1

            if signal in ["MULTIPLE_IPS"]:
                self.confidence += 0.05

        # Cap confidence
        self.confidence = min(self.confidence, 1.0)

    # ==================================================
    # EMIT HANDLER
    # ==================================================
    def emit(self, message):
        click.echo(f"    {message}")

    # ==================================================
    # SUMMARY
    # ==================================================
    def generate_summary(self):

        click.echo("\n[+] Hunting Summary")
        click.echo("-" * 40)
        click.echo(f"Target      : {self.target}")
        click.echo(f"Mode        : {self.mode}")
        click.echo(f"Confidence  : {self.confidence}")
        click.echo("-" * 40)

# Add missing import for terminal width
import shutil