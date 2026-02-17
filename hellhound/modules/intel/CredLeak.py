import requests
import re
import urllib.parse

NAME = "credleak"
CATEGORY = "intel"
DESCRIPTION = "Credential exposure intelligence (Emails, Keys, S3 Buckets, Pastes)"

# =================================================
# Helper Functions
# =================================================

def clean_domain(target):
    target = target.replace("http://", "").replace("https://", "")
    return target.split("/")[0]


def fetch_url(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return ""


# =================================================
# Leak Detection Engine
# =================================================

class CredLeakEngine:

    def __init__(self, target, emit, options=None):
        self.target = clean_domain(target)
        self.emit = emit
        self.options = options or {}

        self.results = {
            "emails": [],
            "usernames": [],
            "exposed_keys": [],
            "paste_hits": [],
            "s3_buckets": [], # New: Cloud Assets
            "hardcoded_creds": [], # New: Actual values found
            "signals": []
        }

    # -------------------------------------------------
    # Email Harvest (Passive)
    # -------------------------------------------------

    def find_emails(self):

        self.emit.info("Searching for exposed emails...")

        # Use DuckDuckGo HTML search
        query = f"site:{self.target} email"
        url = f"https://duckduckgo.com/html/?q={urllib.parse.quote(query)}"

        html = fetch_url(url)

        emails = set(re.findall(
            rf"[a-zA-Z0-9._%+-]+@{re.escape(self.target)}",
            html
        ))

        self.results["emails"] = list(emails)

        if emails:
            self.results["signals"].append("PUBLIC_EMAILS_FOUND")

    # -------------------------------------------------
    # S3 Bucket Hunter (New Upgrade)
    # -------------------------------------------------
    def hunt_s3_buckets(self):
        """
        Uses DDG to find public S3 buckets related to the target.
        """
        self.emit.info("Scanning for exposed S3 buckets...")

        # Dork: Find s3.amazonaws.com links containing the target name
        query = f'site:s3.amazonaws.com "{self.target}"'
        url = f"https://duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        html = fetch_url(url)

        # Extract bucket names (s3.amazonaws.com/bucket-name)
        buckets = re.findall(r"s3\.amazonaws\.com\/([a-z0-9.\-]+)", html)

        # Deduplicate
        self.results["s3_buckets"] = list(set(buckets))

        if self.results["s3_buckets"]:
            self.results["signals"].append("OPEN_S3_BUCKETS_DISCOVERED")

    # -------------------------------------------------
    # GitHub/Code Dorking (New Upgrade)
    # -------------------------------------------------

    def detect_exposed_keys(self):
        """
        Smart GitHub Dorking for keys and tokens.
        """
        self.emit.info("Scanning code repositories for exposed keys...")

        # Dork 1: Target Name + API Key
        query = f'site:github.com "{self.target}" "api_key"'
        url = f"https://duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        html = fetch_url(url)

        patterns = [
            r"AKIA[0-9A-Z]{16}",  # AWS
            r"ghp_[A-Za-z0-9]{36}",  # GitHub
            r"AIza[0-9A-Za-z\-_]{35}",  # Google API
            r"sk_live_[0-9A-Za-z]{24}", # Stripe Live
            r"xoxb-[0-9a-zA-Z]{24}",  # Stripe
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.",  # JWT
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html)
            self.results["exposed_keys"].extend(matches)

        if self.results["exposed_keys"]:
            self.results["signals"].append("EXPOSED_KEYS_DETECTED")

    # -------------------------------------------------
    # Paste Monitoring
    # -------------------------------------------------

    def search_pastes(self):

        self.emit.info("Searching paste sites for leaks...")

        query = f'"{self.target}" password OR leaked'
        url = f"https://duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        html = fetch_url(url)

        links = re.findall(r"https?://[^\s\"<>]+", html)

        paste_sites = [
            "pastebin.com",
            "ghostbin",
            "hastebin",
            "justpaste"
        ]

        hits = []

        for link in links:
            if any(site in link for site in paste_sites):
                hits.append(link)

        self.results["paste_hits"] = list(set(hits))

        if hits:
            self.results["signals"].append("PASTE_LEAK_REFERENCES")

    # -------------------------------------------------
    # Spider Integration (Upgraded: Extract Values)
    # -------------------------------------------------

    def integrate_spider(self):

        spider_data = self.options.get("spider_results")
        if not spider_data:
            return

        intel = spider_data.get("intel", {})
        js_files = intel.get("js_files", [])

        if js_files:
            self.emit.info(f"Analyzing {len(js_files)} JS files for credential patterns...")

        for js in js_files[:10]: # Limit to top 10 JS files
            content = fetch_url(js)
            if not content:
                continue

            # Upgrade 1: Hardcoded Password Extraction
            # Look for patterns like: var password = "12345"; or password="12345"
            pwd_matches = re.findall(r'password\s*[:=]\s*[\'"]([^\'"]+)', content, re.IGNORECASE)
            if pwd_matches:
                self.results["hardcoded_creds"].extend(pwd_matches)
                self.results["signals"].append("HARDCODED_PASSWORD_EXTRACTED")

            # Upgrade 2: API Key Extraction
            # Look for patterns like: const apiKey = "XYZ";
            key_matches = re.findall(r'(api[_-]?key\s*[:=]\s*[\'"])([^\'"]+)', content, re.IGNORECASE)
            if key_matches:
                self.results["hardcoded_creds"].extend(key_matches)
                self.results["signals"].append("HARDCODED_API_KEY_EXTRACTED")

    # -------------------------------------------------
    # Run
    # -------------------------------------------------

    def run(self):
        self.find_emails()
        self.hunt_s3_buckets() # Added S3 Hunter
        self.detect_exposed_keys()
        self.search_pastes()
        self.integrate_spider()

        summary = {
            "total_emails": len(self.results["emails"]),
            "total_keys": len(self.results["exposed_keys"]),
            "paste_references": len(self.results["paste_hits"]),
            "s3_buckets": len(self.results["s3_buckets"]) # Added to summary
        }

        return {
            "raw": (
                f"Emails: {summary['total_emails']} | "
                f"Keys: {summary['total_keys']} | "
                f"Pastes: {summary['paste_references']} | "
                f"S3: {summary['s3_buckets']}"
            ),
            "intel": {
                "summary": summary,
                **self.results
            }
        }


# =================================================
# Framework Entry
# =================================================

def run(target, emit, options=None):

    emit.info(f"Credential Exposure Intelligence: {target}")

    engine = CredLeakEngine(target, emit, options)
    result = engine.run()

    emit.success("Credential Intelligence Complete")
    emit.success(result["raw"])

    return result