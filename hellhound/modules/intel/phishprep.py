import subprocess
import re

NAME = "phishprep"
CATEGORY = "intel"
DESCRIPTION = "Phishing campaign preparation (Email generation & SPF/DKIM analysis)"


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def tool_exists(tool):
    return shutil.which(tool) is not None


def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30
        )
        return result.stdout.strip()
    except Exception:
        return ""


def initialize_data(target):
    return {
        "target": target,
        "target_emails": [],      # Generated email candidates
        "phishing_domain": "",     # Recommended domain to spoof
        "security_policy": {
            "spf": "Not Found",
            "spf_type": "Unknown",  # Hard, Soft, None
            "dmarc": "Not Found",
            "dmarc_policy": "None"  # None, Quarantine, Reject
        },
        "signals": []
    }


# -------------------------------------------------
# Phish Prep Engine
# -------------------------------------------------

class PhishPrepEngine:

    def __init__(self, target, emit, options=None):
        self.target = target
        self.emit = emit
        self.options = options or {}
        self.data = initialize_data(target)

        # Common usernames to try
        self.usernames = [
            "admin", "info", "support", "contact", 
            "help", "sales", "billing", "hr", "it",
            "security", "ceo", "cfo", "webmaster"
        ]

    def generate_targets_from_stalk(self):
        """Generates email candidates using subdomains found by Stalk"""
        self.emit.info("Generating email candidates from discovered infrastructure")

        subdomains = []
        
        # 1. Check if Stalk provided subdomains
        if "subdomains" in self.options:
            subdomains = self.options["subdomains"]
        else:
            # Fallback to main target
            subdomains = [self.target]

        emails = []
        
        for sub in subdomains[:20]: # Limit to first 20 subdomains
            # Clean up subdomain (remove http://)
            sub_clean = sub.replace("http://", "").replace("https://", "")
            
            # Don't generate for generic top-level domains
            if len(sub_clean.split('.')) < 2:
                continue

            for user in self.usernames:
                emails.append(f"{user}@{sub_clean}")

        self.data["target_emails"] = sorted(list(set(emails)))
        
        if self.data["target_emails"]:
            self.data["signals"].append("EMAIL_TARGETS_GENERATED")
            self.emit.info(f"Generated {len(emails)} potential email targets")

    def analyze_mail_security(self):
        """Checks SPF, DMARC, and DKIM records to assess spoofability"""
        self.emit.info("Analyzing Mail Security (SPF/DKIM/DMARC)")

        target_domain = self.target.replace("http://", "").replace("https://", "").split("/")[0]

        # 1. Check SPF
        spf_output = run_cmd(["dig", "+short", "TXT", target_domain])
        self._parse_spf(spf_output)

        # 2. Check DMARC
        dmarc_output = run_cmd(["dig", "+short", "TXT", f"_dmarc.{target_domain}"])
        self._parse_dmarc(dmarc_output)

    def _parse_spf(self, output):
        for line in output.splitlines():
            if "v=spf1" in line:
                self.data["security_policy"]["spf"] = line.strip('"')
                
                if "~all" in line:
                    self.data["security_policy"]["spf_type"] = "SoftFail (Moderate Risk)"
                    self.data["signals"].append("WEAK_SPF_CONFIG")
                elif "-all" in line:
                    self.data["security_policy"]["spf_type"] = "HardFail (Difficult to Spoof)"
                else:
                    self.data["security_policy"]["spf_type"] = "Permissive (Easy to Spoof)"
                    self.data["signals"].append("OPEN_SPF_CONFIG")

    def _parse_dmarc(self, output):
        for line in output.splitlines():
            if "v=DMARC1" in line:
                self.data["security_policy"]["dmarc"] = line.strip('"')
                
                if "p=reject" in line:
                    self.data["security_policy"]["dmarc_policy"] = "Reject (High Security)"
                elif "p=quarantine" in line:
                    self.data["security_policy"]["dmarc_policy"] = "Quarantine (Medium Security)"
                elif "p=none" in line:
                    self.data["security_policy"]["dmarc_policy"] = "None (Low Security)"
                    self.data["signals"].append("WEAK_DMARC_CONFIG")

    def generate_recommendation(self):
        """Suggests a domain for phishing"""
        target_domain = self.target.replace("http://", "").replace("https://", "").split("/")[0]
        
        # Suggest a lookalike domain
        if ".com" in target_domain:
            parts = target_domain.split('.')
            if len(parts) > 2:
                # For sub.example.com -> suggest sub-login.com
                suggested = f"{parts[0]}-login.{parts[-1]}"
            else:
                # For example.com -> suggest example-login.com
                suggested = f"{parts[0]}-login.{parts[-1]}"
            
            self.data["phishing_domain"] = suggested
            self.emit.info(f"Recommended Phishing Domain: {suggested}")


# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):
    emit.info(f"Phish Prep Started: {target}")

    engine = PhishPrepEngine(target, emit, options)
    
    engine.generate_targets_from_stalk()
    engine.analyze_mail_security()
    engine.generate_recommendation()

    summary = (
        f"Targets: {len(engine.data['target_emails'])} | "
        f"SPF: {engine.data['security_policy']['spf_type']}"
    )

    return {
        "raw": summary,
        "intel": engine.data
    }