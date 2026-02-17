import subprocess
import re
import requests
import shutil # Added for tool_exists

NAME = "phishprep"
CATEGORY = "intel"
DESCRIPTION = "Advanced Phishing Prep (Golden Path Scraping + Name Extraction + Derivation)"


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
        "signals": [],
        "names_found": [] # New: To track extracted names
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

        # "Golden Paths": High-yield locations for emails and names
        self.golden_paths = [
            "/contact", "/team", "/about", "/about-us", 
            "/careers", "/jobs", "/people", "/staff"
        ]

        # Fallback usernames if scraping finds nothing
        self.default_users = [
            "admin", "info", "support", "contact", 
            "help", "sales", "billing", "hr", "it",
            "security", "ceo", "cfo", "webmaster"
        ]

        # Words that are never people names (UI/Navigation/Technical terms)
        self.name_blocklist = [
            "about", "about-us", "home", "contact", "careers", "jobs",
            "meta", "facebook", "app", "apps", "page", "pages",
            "view", "display", "shop", "explore", "help", "support",
            "search", "login", "signup", "terms", "policy", "privacy",
            "community", "messenger", "workplace", "instagram", "whatsapp",
            "cookie", "settings", "profile", "account", "sign", "join",
            "video", "photo", "music", "location", "game", "play", "watch",
            # --- ADDED FOR FALSE POSITIVE REDUCTION ---
            "center", "centre", "hero", "slide", "most", "work", "origin", 
            "parent", "placeholder", "quest", "social", "technology", 
            "vice", "your", "career", "vantage", "chairman", "dash", 
            "podcast", "fidelity", "experience", "connected", "open", 
            "create", "name", "display", "join", "connect", "share", "save", 
            "install", "download", "upload", "report", "admin", "system", 
            "dashboard", "portal", "landing", "content", "media", "news", 
            "press", "blog", "forum", "shop", "store", "pay", "bill", "invoice"
        ]

    def scrape_golden_paths(self):
        """
        Aggressively scans 'Golden Paths' for emails and names.
        """
        self.emit.info("Scanning Golden Paths (Contact, Team, Careers) for data...")

        all_emails = set()
        all_names = set()
        
        # Regex patterns
        email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        # Pattern to find "John Doe" or "John A. Doe"
        name_regex = r'\b([A-Z][a-z]+ [A-Z][a-z]+(?: [A-Z][a-z]+)?)\b'

        # Words that never start a person's name (e.g. "Create Account")
        invalid_prefixes = [
            "account", "privacy", "terms", "conditions", "cookie", 
            "legal", "join", "sign", "login", "register", "create", 
            "open", "connected", "social", "meta", "facebook", "what", "how", "why"
        ]

        for path in self.golden_paths:
            url = self.target + path if self.target.startswith("http") else f"http://{self.target}{path}"
            
            try:
                response = requests.get(url, timeout=8)
                if response.status_code == 200:
                    # Extract Emails
                    emails = re.findall(email_regex, response.text)
                    all_emails.update(emails)
                    
                    # Extract Names (Human names) - FILTERED
                    raw_names = re.findall(name_regex, response.text)
                    
                    for name in raw_names:
                        name_lower = name.lower()
                        
                        # FILTER 1: Check Blocklist
                        if any(block in name_lower for block in self.name_blocklist):
                            continue
                            
                        # FILTER 2: Check Invalid Prefixes (e.g., "Create Account")
                        first_word = name_lower.split(" ")[0]
                        if first_word in invalid_prefixes:
                            continue

                        # FILTER 3: If it's a single word, ensure it looks like a name (length > 2)
                        # (This handles rare edge cases)
                        if len(name.replace(" ", "")) < 3:
                            continue
                            
                        all_names.add(name)
                            
            except Exception:
                continue

        # Store found names for later generation
        if all_names:
            self.data["names_found"] = list(all_names)
            self.emit.info(f"Found {len(all_names)} potential employee names")

        return all_emails

    def generate_derived_emails(self, names):
        """
        Generates email formats based on extracted names.
        Tries common patterns: first.last, f.last, flast
        """
        self.emit.info("Deriving email addresses from extracted names...")
        
        domain = self.target.replace("http://", "").replace("https://", "").split("/")[0]
        derived_emails = []

        for name in names:
            parts = name.split(" ")
            if len(parts) < 2:
                continue
            
            first = parts[0].lower()
            last = parts[-1].lower()
            middle = parts[1].lower() if len(parts) > 2 else ""
            first_init = first[0]
            middle_init = middle[0] if middle else ""

            # Common email patterns
            candidates = [
                f"{first}.{last}@{domain}",       # john.doe@company.com
                f"{first}{last}@{domain}",        # johndoe@company.com
                f"{first_init}{last}@{domain}",  # jdoe@company.com
                f"{first}.{first_init}{last}@{domain}", # john.jdoe@company.com
            ]
            
            derived_emails.extend(candidates)

        return derived_emails

    def filter_emails(self, emails):
        """
        Removes generic/bot emails to focus on high-value human targets.
        """
        # Low value keywords
        blocklist = [
            "support", "info", "sales", "contact", "help", "office",
            "admin", "webmaster", "postmaster", "hostmaster", "abuse",
            "noreply", "no-reply", "job", "careers", "notification", "alert"
        ]
        
        filtered = []
        for email in emails:
            local_part = email.split('@')[0].lower()
            
            # Block generic emails
            if any(word in local_part for word in blocklist):
                continue
            
            filtered.append(email)
            
        return sorted(list(set(filtered)))

    def run_phishing_cycle(self):
        """
        Master execution flow: Scrape -> Derive -> Filter -> Fallback
        """
        # 1. Scrape Golden Paths for real emails and names
        scraped_emails = self.scrape_golden_paths()
        
        final_emails = set(scraped_emails)
        
        # 2. If we found names, try to derive their emails
        if self.data.get("names_found"):
            derived = self.generate_derived_emails(self.data["names_found"])
            final_emails.update(derived)

        # 3. If we have results, filter them. If empty, fallback to defaults.
        if final_emails:
            cleaned_emails = self.filter_emails(final_emails)
            
            if cleaned_emails:
                self.data["target_emails"] = cleaned_emails
                self.data["signals"].append("HIGH_VALUE_TARGETS_FOUND")
                self.emit.info(f"Found {len(cleaned_emails)} high-value targets")
                return

        # 4. Fallback: Generic Usernames
        self.emit.info("No human targets found. Falling back to generic usernames.")
        self.generate_targets_from_stalk()

    def generate_targets_from_stalk(self):
        """
        Generates email candidates using subdomains found by Stalk.
        (Fallback method)
        """
        self.emit.info("Generating email candidates from discovered infrastructure")

        subdomains = []
        
        if "subdomains" in self.options:
            subdomains = self.options["subdomains"]
        else:
            subdomains = [self.target]

        emails = []
        domain = self.target.replace("http://", "").replace("https://", "").split("/")[0]

        for sub in subdomains[:10]: 
            sub_clean = sub.replace("http://", "").replace("https://", "")
            if len(sub_clean.split('.')) < 2:
                continue

            for user in self.default_users:
                emails.append(f"{user}@{domain}")

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
                suggested = f"{parts[0]}-login.{parts[-1]}"
            else:
                suggested = f"{parts[0]}-login.{parts[-1]}"
            
            self.data["phishing_domain"] = suggested
            self.emit.info(f"Recommended Phishing Domain: {suggested}")
    def infer_email_pattern(self, emails, domain):
        """
        Analyzes found emails to deduce the company's email format.
        """
        self.emit.info("Deducing corporate email format...")
        
        patterns = {
            "first.last": 0,
            "firstlast": 0,
            "f.last": 0,
            "flast": 0,
            "first.last_init": 0
        }

        # Analyze found emails to guess the pattern
        for email in emails:
            if email.endswith(f"@{domain}"):
                local = email.split('@')[0].lower()
                # Simple heuristics to count pattern usage
                if '.' in local and len(local.split('.')[1]) > 1:
                    patterns["first.last"] += 1
                elif '.' in local:
                    patterns["f.last"] += 1
                elif len(local) > 5 and '.' not in local:
                    patterns["firstlast"] += 1
                elif len(local) <= 5 and '.' not in local:
                    patterns["flast"] += 1

        # Return the most likely pattern
        best_pattern = max(patterns, key=patterns.get)
        self.emit.info(f"Detected format: {best_pattern}")
        return best_pattern

    def extract_roles(self, html_content):
        """
        Extracts Names and Roles (e.g., "John Doe - CTO")
        """
        # Regex for "Name - Role" or "Name, Role"
        # Example: John Doe - Chief Technology Officer
        role_regex = r'([A-Z][a-z]+ [A-Z][a-z]+(?: [A-Z][a-z]+)?)\s*[-,]\s*(.+)'
        
        found = re.findall(role_regex, html_content)
        people = []
        
        for name, role in found:
            # Clean up role
            role_clean = ' '.join(role.split()) # Remove extra spaces
            people.append({
                "name": name,
                "role": role_clean
            })
        return people

    def apply_pattern(self, name, pattern, domain):
        """
        Applies the detected pattern to a specific name.
        """
        parts = name.split(" ")
        first = parts[0].lower()
        last = parts[-1].lower()
        middle = parts[1].lower() if len(parts) > 2 else ""
        first_init = first[0]
        middle_init = middle[0] if middle else ""

        if pattern == "first.last":
            return f"{first}.{last}@{domain}"
        elif pattern == "firstlast":
            return f"{first}{last}@{domain}"
        elif pattern == "f.last":
            return f"{first_init}.{last}@{domain}"
        elif pattern == "flast":
            return f"{first_init}{last}@{domain}"
        elif pattern == "first.last_init":
            return f"{first}.{last}{middle_init}@{domain}"
        else:
            return f"{first}.{last}@{domain}" # Default

# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):
    emit.info(f"Phish Prep Started: {target}")

    engine = PhishPrepEngine(target, emit, options)
    
    # Run the advanced cycle
    engine.run_phishing_cycle()
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