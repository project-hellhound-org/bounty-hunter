import requests
import re
import hashlib
import urllib.parse

NAME = "credleak"
CATEGORY = "intel"
DESCRIPTION = "Credential exposure intelligence (Emails, Leaks, Tokens, Paste monitoring)"

# =================================================
# Helper Functions
# =================================================

def clean_domain(target):
    target = target.replace("http://", "").replace("https://", "")
    return target.split("/")[0]


def fetch_url(url):
    try:
        r = requests.get(url, timeout=10)
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
            "signals": []
        }

    # -------------------------------------------------
    # Email Harvest (Passive)
    # -------------------------------------------------

    def find_emails(self):

        self.emit.info("Searching for exposed emails...")

        # Use DuckDuckGo HTML search (lightweight)
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
    # GitHub Token & Key Detection
    # -------------------------------------------------

    def detect_exposed_keys(self):

        self.emit.info("Scanning for exposed API keys...")

        query = f'"{self.target}" "API_KEY"'
        url = f"https://duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        html = fetch_url(url)

        patterns = [
            r"AKIA[0-9A-Z]{16}",  # AWS
            r"ghp_[A-Za-z0-9]{36}",  # GitHub
            r"AIza[0-9A-Za-z\-_]{35}",  # Google API
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
    # Spider Integration (Optional)
    # -------------------------------------------------

    def integrate_spider(self):

        spider_data = self.options.get("spider_results")
        if not spider_data:
            return

        intel = spider_data.get("intel", {})
        js_files = intel.get("js_files", [])

        if js_files:
            self.emit.info("Analyzing JS files for credential patterns...")

        for js in js_files[:10]:
            content = fetch_url(js)
            if not content:
                continue

            # Look for password assignments
            if re.search(r"password\s*[:=]", content, re.IGNORECASE):
                self.results["signals"].append("HARD_CODED_PASSWORD_PATTERN")

            if re.search(r"api[_-]?key\s*[:=]", content, re.IGNORECASE):
                self.results["signals"].append("HARDCODED_API_KEY_PATTERN")

    # -------------------------------------------------
    # Run
    # -------------------------------------------------

    def run(self):

        self.find_emails()
        self.detect_exposed_keys()
        self.search_pastes()
        self.integrate_spider()

        summary = {
            "total_emails": len(self.results["emails"]),
            "total_keys": len(self.results["exposed_keys"]),
            "paste_references": len(self.results["paste_hits"])
        }

        return {
            "raw": (
                f"Emails: {summary['total_emails']} | "
                f"Keys: {summary['total_keys']} | "
                f"Pastes: {summary['paste_references']}"
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
