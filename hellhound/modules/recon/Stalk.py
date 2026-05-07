import re
import json
import socket
import threading
import requests
import urllib.parse
import urllib3
import time
import random
import secrets
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from colorama import Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# MODULE CONTRACT
# ============================================================

NAME        = "stalk"
CATEGORY    = "recon"
VERSION     = "3.2.0"
DESCRIPTION = "Autonomous Attack Surface Mapping — Subdomain Takeover, Cloud Exposure & Zombie Discovery"

OPTIONS = [
    {"name": "concurrency",         "default": 15,    "required": False, "help": "Max concurrent workers for OSINT/DNS"},
    {"name": "permutation_depth",   "default": "common", "required": False, "help": "DNS brute wordlist depth: common | full"},
    {"name": "wayback_limit",       "default": 500,   "required": False, "help": "Max historical endpoints from Wayback CDX"},
    {"name": "scope_skip_primary",  "default": True,  "required": False, "help": "Focus exclusively on lateral subdomains"},
    {"name": "stealth_mode",        "default": True,  "required": False, "help": "Enable jitter and DNS-first verification"},
    {"name": "rate_limit",          "default": 0,     "required": False, "help": "Global delay (ms) between active HTTP probes"},
    {"name": "timeout",             "default": 8,     "required": False, "help": "Request timeout for active phases"},
]

TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "github.io": ["There isn't a GitHub Pages site here", "404 Not Found"],
    "herokuapp.com": ["herokucdn.com/error-pages/no-such-app.html", "No such app"],
    "azurewebsites.net": ["404 Web Site not found"],
    "cloudfront.net": ["Bad Request: CloudFront attempted to establish a connection"],
    "bitbucket.io": ["404 Not Found"],
}

SUBDOMAIN_PERMUTATIONS_COMMON = ["api", "dev", "staging", "admin", "test", "beta", "prod", "internal", "vpn", "mail", "uat", "app", "auth", "login", "portal", "dashboard", "static", "cdn", "assets", "media", "img", "upload", "download", "ftp", "ssh", "git", "jenkins", "ci", "jira", "confluence", "grafana", "monitor", "metrics", "status", "help", "support", "docs", "developer", "sandbox", "preprod", "qa", "demo", "shop", "store", "pay", "payment", "secure", "v1", "v2", "api-v1", "api-v2", "mobile", "m", "wap", "old", "new", "backup", "bak", "db", "database"]
SUBDOMAIN_PERMUTATIONS_FULL = SUBDOMAIN_PERMUTATIONS_COMMON + ["webmail", "smtp", "imap", "pop", "ns1", "ns2", "mx", "proxy", "gateway", "fw", "firewall", "router", "switch", "nas", "storage", "archive", "log", "logs", "syslog", "vault", "terraform", "ansible", "puppet", "chef", "k8s", "docker", "registry", "harbor", "nexus", "artifactory", "canary", "edge", "ws", "websocket", "graphql", "grpc"]
CLOUD_BUCKET_SUFFIXES = ["", "-prod", "-production", "-dev", "-development", "-staging", "-stage", "-test", "-testing", "-qa", "-uat", "-demo", "-backup", "-assets", "-static", "-media", "-files", "-public", "-private", "-internal", "-cdn"]

# ============================================================
# INTEL COLLECTOR
# ============================================================

class IntelCollector:
    def __init__(self, skip_hosts=None, skip_urls=None):
        self._lock = threading.Lock()
        self.subdomains:       List[Dict] = []
        self.historical_urls:  List[Dict] = []
        self.git_exposed:      List[Dict] = []
        self.cloud_assets:     List[Dict] = []
        self.takeovers:        List[Dict] = []
        self.orphans:          List[Dict] = []
        self.deprecated_assets: List[Dict] = []
        self.fuzz_seeds:       Dict[str, Set[str]] = {}
        self._seen_hosts:      Set[str]   = set(skip_hosts or [])
        self._seen_urls:       Set[str]   = set(skip_urls or [])
        self.stalk_unique_hosts: Set[str] = set()
        self.stalk_unique_urls:  Set[str] = set()

    def add_subdomain(self, host: str, source: str, resolved: bool = False, ip: str = ""):
        with self._lock:
            if host in self._seen_hosts: return
            self._seen_hosts.add(host)
            self.stalk_unique_hosts.add(host)
            self.subdomains.append({"host": host, "resolved": resolved, "ip": ip, "source": source})

    def add_url(self, url: str, source: str):
        with self._lock:
            if url in self._seen_urls: return
            self._seen_urls.add(url)
            self.stalk_unique_urls.add(url)
            self.historical_urls.append({"url": url, "source": source})

    def add_takeover(self, host: str, provider: str):
        with self._lock: self.takeovers.append({"host": host, "provider": provider})

    def add_orphan(self, url: str, status: int):
        with self._lock: self.orphans.append({"url": url, "status": status})

    def add_cloud(self, url: str, status: str, provider: str):
        with self._lock: self.cloud_assets.append({"url": url, "status": status, "provider": provider})

    def add_deprecated_asset(self, url: str, version: str):
        with self._lock: self.deprecated_assets.append({"url": url, "version": version})

    def add_fuzz_seed(self, param: str, value: str):
        with self._lock:
            if param not in self.fuzz_seeds: self.fuzz_seeds[param] = set()
            self.fuzz_seeds[param].add(str(value))

# ============================================================
# HARVESTERS
# ============================================================

def harvest_robots_sitemap(domain: str, collector: IntelCollector, emit):
    emit.info("  [*] Harvesting robots.txt and sitemap.xml...")
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}/robots.txt", timeout=10, verify=False)
            if r.status_code == 200:
                paths = re.findall(r'Disallow: (.+)', r.text)
                for p in paths: collector.add_url(urljoin(f"{scheme}://{domain}", p.strip()), "robots")
        except: pass
        try:
            r = requests.get(f"{scheme}://{domain}/sitemap.xml", timeout=10, verify=False)
            if r.status_code == 200:
                urls = re.findall(r'<loc>(.+)</loc>', r.text)
                for u in urls: collector.add_url(u.strip(), "sitemap")
        except: pass

def harvest_subdomains(domain: str, collector: IntelCollector, emit, timeout: int):
    emit.info("  [*] OSINT Subdomain harvest (Passive)...")
    def _resolve(h):
        try: return socket.gethostbyname(h)
        except: return None
    def _crtsh(d):
        for i in range(3):
            try:
                r = requests.get(f"https://crt.sh/?q=%.{d}&output=json", timeout=20, verify=False)
                if r.status_code == 200: return [e.get("name_value", "").strip().lstrip("*.") for e in r.json()]
            except: time.sleep(2**i)
        return []
    def _ht(d):
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={d}", timeout=timeout, verify=False)
            return [line.split(",")[0].strip() for line in r.text.strip().splitlines() if "," in line]
        except: return []

    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = {pool.submit(_crtsh, domain): "crt.sh", pool.submit(_ht, domain): "hackertarget"}
        for fut in as_completed(futs):
            for sub in fut.result():
                if sub.endswith(domain) and sub not in collector._seen_hosts:
                    ip = _resolve(sub)
                    collector.add_subdomain(sub, futs[fut], resolved=True if ip else False, ip=ip or "")

def harvest_wayback(domain: str, collector: IntelCollector, emit, limit: int):
    emit.info("  [*] Wayback CDX harvest (Ghost Endpoints)...")
    try:
        r = requests.get("http://web.archive.org/cdx/search/cdx", params={"url": f"*.{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey", "limit": limit, "filter": "statuscode:200,302,401,403,500"}, timeout=45)
        if r.status_code == 200:
            for row in r.json()[1:]:
                collector.add_url(row[0], "wayback")
    except: pass

# ============================================================
# ACTIVE DISCOVERY ENGINE
# ============================================================

def _apply_stealth(options):
    if bool(options.get("stealth_mode", True)): time.sleep(random.uniform(0.5, 1.5))
    rl = int(options.get("rate_limit", 0))
    if rl > 0: time.sleep(rl / 1000.0)

def _check_takeover(host, emit, timeout):
    try:
        cname = ""
        try:
            res = subprocess.run(["dig", "CNAME", host, "+short"], capture_output=True, text=True, timeout=5)
            cname = res.stdout.strip().lower()
        except:
            try:
                info = socket.getaddrinfo(host, 0, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, socket.AI_CANONNAME)
                cname = info[0][3].lower() if info and info[0][3] else ""
            except: pass
        if not cname: return None
        for provider, sigs in TAKEOVER_SIGNATURES.items():
            if provider in cname:
                try:
                    r = requests.get(f"http://{host}", timeout=timeout, verify=False)
                    if any(sig in r.text for sig in sigs) or r.status_code == 404: return {"host": host, "provider": provider}
                except: return {"host": host, "provider": provider}
    except: pass
    return None

def active_dns_permutation(domain, collector, emit, depth, concurrency, wildcard_ips, options):
    emit.info("  [*] Lateral DNS permutation bruteforce...")
    wordlist = SUBDOMAIN_PERMUTATIONS_FULL if depth == "full" else SUBDOMAIN_PERMUTATIONS_COMMON
    def _r(h):
        _apply_stealth(options)
        try: return socket.gethostbyname(h)
        except: return None
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = {pool.submit(_r, f"{w}.{domain}"): f"{w}.{domain}" for w in wordlist if f"{w}.{domain}" not in collector._seen_hosts}
        for fut in as_completed(futs):
            ip = fut.result()
            if ip and ip not in wildcard_ips: collector.add_subdomain(futs[fut], "dns_brute", resolved=True, ip=ip)

def active_git_detection(collector, emit, concurrency, options):
    emit.info("  [*] Probing live hosts for Git exposure...")
    def _p(h):
        _apply_stealth(options)
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{h}/.git/HEAD", timeout=options.get("timeout", 8), verify=False, allow_redirects=False)
                if r.status_code == 200 and ("ref:" in r.text or re.match(r'^[0-9a-f]{40}$', r.text.strip())): return f"{scheme}://{h}/.git/HEAD"
            except: pass
        return None
    live = [s["host"] for s in collector.subdomains if s.get("resolved")]
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(_p, h) for h in live]
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                collector.add_git(res, {"head": "detected"})
                emit.warn(f"{Fore.RED + Style.BRIGHT}GIT EXPOSED: {res}{Style.RESET_ALL}")

def active_cloud_permutation(domain, collector, emit, timeout, concurrency, options):
    emit.info("  [*] Cloud asset (S3/Azure/GCP) probing...")
    org = domain.split(".")[0]
    names = {f"{org}{s}" for s in CLOUD_BUCKET_SUFFIXES}
    def _p(n):
        _apply_stealth(options)
        # S3
        try:
            r = requests.head(f"https://{n}.s3.amazonaws.com", timeout=timeout)
            if r.status_code == 200: collector.add_cloud(f"https://{n}.s3.amazonaws.com", "public", "s3")
        except: pass
        # Azure
        try:
            r = requests.head(f"https://{n}.blob.core.windows.net", timeout=timeout)
            if r.status_code == 200: collector.add_cloud(f"https://{n}.blob.core.windows.net", "public", "azure")
        except: pass
        # GCP
        try:
            r = requests.head(f"https://storage.googleapis.com/{n}", timeout=timeout)
            if r.status_code == 200: collector.add_cloud(f"https://storage.googleapis.com/{n}", "public", "gcp")
        except: pass
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        [pool.submit(_p, n) for n in names]

# ============================================================
# ENTRY POINT
# ============================================================

def run(target: str, emit, options: Optional[Dict] = None, spider_intel: Optional[Dict] = None):
    opt = options or {}
    domain = urlparse(target).netloc or target
    domain = domain.replace("www.", "").split(":")[0]
    emit.always_info(f"Stalk v3.2.0 — Bug Bounty Attack Surface Mapping")
    
    skip_hosts = set()
    skip_urls = set()
    if spider_intel:
        for entry in spider_intel.get("crawled_urls", []):
            u = entry["url"]; skip_urls.add(u); skip_hosts.add(urlparse(u).netloc)
        emit.info(f"    [+] Spider-Seeding: Skipping {len(skip_hosts)} already-audited hosts.")
    
    if opt.get("scope_skip_primary", True):
        skip_hosts.add(domain); skip_hosts.add(f"www.{domain}")

    collector = IntelCollector(skip_hosts=skip_hosts, skip_urls=skip_urls)
    
    # Discovery Phases
    if not spider_intel:
        harvest_robots_sitemap(domain, collector, emit)
    else:
        # Extract from spider_intel instead
        if "robots" in spider_intel:
            for url in spider_intel["robots"].get("disallow_paths", []):
                collector.add_url(urljoin(f"https://{domain}", url), "spider_robots")
        if "sitemap" in spider_intel:
            for url in spider_intel["sitemap"].get("urls", []):
                collector.add_url(url, "spider_sitemap")
        emit.info(f"    [+] Skipped robots/sitemap fetch (already in spider_intel)")
    
    harvest_subdomains(domain, collector, emit, int(opt.get("timeout", 8)))
    harvest_wayback(domain, collector, emit, int(opt.get("wayback_limit", 500)))
    
    # Version Detection & Fuzz Seeding
    for u in collector.historical_urls:
        v_match = re.search(r'[\-\/]([\d\.]{3,7})[\.\-]', u["url"])
        if v_match: collector.add_deprecated_asset(u["url"], v_match.group(1))
        for k, v in parse_qs(urlparse(u["url"]).query).items(): collector.add_fuzz_seed(k, v[0] if v else "")
    if spider_intel and "forms" in spider_intel:
        for f in spider_intel["forms"]:
            for i in f.get("inputs", []):
                if i.get("name"): collector.add_fuzz_seed(i["name"], "")

    # Wildcard 
    wildcard_ips = set()
    ips_list = []
    for _ in range(15):
        try: ips_list.append(socket.gethostbyname(f"wildcard-{secrets.token_hex(4)}.{domain}"))
        except: pass
    if len(set(ips_list)) >= 3: wildcard_ips = set(ips_list)

    # Active Strike
    with ThreadPoolExecutor(max_workers=int(opt.get("concurrency", 15))) as pool:
        futs = {pool.submit(_check_takeover, h["host"], emit, int(opt.get("timeout", 8))): h for h in collector.subdomains}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                collector.add_takeover(res["host"], res["provider"])
                emit.warn(f"{Fore.RED + Style.BRIGHT}[!] TAKEOVER CANDIDATE: {res['host']} ({res['provider']}){Style.RESET_ALL}")

    active_dns_permutation(domain, collector, emit, str(opt.get("permutation_depth", "common")), int(opt.get("concurrency", 15)), wildcard_ips, opt)
    active_git_detection(collector, emit, int(opt.get("concurrency", 15)), opt)
    active_cloud_permutation(domain, collector, emit, int(opt.get("timeout", 8)), int(opt.get("concurrency", 15)), opt)

    # Orphan Validation (GET-Stream)
    orphans = [u["url"] for u in collector.historical_urls if u["url"] not in skip_urls]
    if orphans:
        def _v(u):
            _apply_stealth(opt)
            try:
                r = requests.get(u, timeout=opt.get("timeout", 8), stream=True, verify=False)
                if r.status_code == 200: r.close(); return u
            except: pass
            return None
        with ThreadPoolExecutor(max_workers=int(opt.get("concurrency", 15))) as pool:
            for fut in as_completed([pool.submit(_v, u) for u in orphans[:100]]):
                res = fut.result()
                if res: collector.add_orphan(res, 200)

    # Summary
    risk = len(collector.takeovers)*100 + len(collector.git_exposed)*30 + len(collector.orphans)*10 + (len(collector.historical_urls)//20)
    emit.success(f"Stalk v3.2.1 Strike Complete.")
    emit.row("    Stalk Delta", f"{Fore.CYAN}{len(collector.stalk_unique_hosts)} new hosts{Style.RESET_ALL} / {Fore.CYAN}{len(collector.stalk_unique_urls)} new endpoints{Style.RESET_ALL}")
    emit.row("    Takeovers",   f"{Fore.RED + Style.BRIGHT}{len(collector.takeovers)} candidates{Style.RESET_ALL}")
    emit.row("    Exposures",   f"{len(collector.git_exposed)} git repos | {len(collector.cloud_assets)} cloud assets")
    emit.row("    Orphans",     f"{len(collector.orphans)} verified ghost endpoints")
    emit.row("    Risk Score",  f"{risk}")

    return {
        "intel": {
            "takeovers": collector.takeovers,
            "git_exposed": collector.git_exposed,
            "cloud_assets": collector.cloud_assets,
            "orphans": collector.orphans,
            "fuzz_seeds": {k: list(v) for k, v in collector.fuzz_seeds.items()},
            "unique_hosts": list(collector.stalk_unique_hosts),
            "deprecated_assets": collector.deprecated_assets
        },
        "risk_score": risk
    }