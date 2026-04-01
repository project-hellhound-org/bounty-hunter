import re
import json
import socket
import threading
import requests
import urllib.parse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Set

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# MODULE CONTRACT
# ============================================================

NAME        = "stalk"
CATEGORY    = "recon"
VERSION     = "2.0.0"
DESCRIPTION = "Hybrid OSINT Engine — passive enumeration + active confirmation"

OPTIONS = [
    {"name": "concurrency",         "default": 15,    "required": False, "help": "Max concurrent DNS/HTTP workers"},
    {"name": "permutation_depth",   "default": "common", "required": False, "help": "Wordlist size for DNS brute: common | full"},
    {"name": "wayback_limit",       "default": 500,   "required": False, "help": "Max URLs to pull from Wayback CDX API"},
    {"name": "cloud_permutations",  "default": True,  "required": False, "help": "Enable S3 / Azure / GCP bucket probing"},
    {"name": "resolve_subdomains",  "default": True,  "required": False, "help": "DNS A-record confirmation pass on found subdomains"},
    {"name": "timeout",             "default": 8,     "required": False, "help": "HTTP request timeout in seconds"},
]

LOOT_SECTIONS = [
    "subdomains",
    "historical_urls",
    "git_exposed",
    "cloud_assets",
    "leak_candidates",
    "banners",
]

# ============================================================
# CONSTANTS
# ============================================================

SUBDOMAIN_PERMUTATIONS_COMMON = [
    "api", "dev", "staging", "admin", "test", "beta", "prod",
    "internal", "vpn", "mail", "uat", "app", "auth", "login",
    "portal", "dashboard", "static", "cdn", "assets", "media",
    "img", "upload", "download", "ftp", "ssh", "git", "jenkins",
    "ci", "jira", "confluence", "grafana", "monitor", "metrics",
    "status", "help", "support", "docs", "developer", "sandbox",
    "preprod", "qa", "demo", "shop", "store", "pay", "payment",
    "secure", "v1", "v2", "api-v1", "api-v2", "mobile", "m",
    "wap", "old", "new", "backup", "bak", "db", "database",
    "mysql", "redis", "elastic", "kibana", "search", "console",
    "aws", "cloud", "s3", "bucket", "files", "data", "intranet",
    "corp", "remote", "vpn2", "office", "hr", "crm", "erp",
]

SUBDOMAIN_PERMUTATIONS_FULL = SUBDOMAIN_PERMUTATIONS_COMMON + [
    "webmail", "smtp", "imap", "pop", "ns1", "ns2", "mx",
    "proxy", "gateway", "fw", "firewall", "router", "switch",
    "nas", "storage", "archive", "log", "logs", "syslog",
    "nagios", "zabbix", "prometheus", "alertmanager", "vault",
    "terraform", "ansible", "puppet", "chef", "k8s", "kubernetes",
    "docker", "registry", "harbor", "nexus", "artifactory",
    "sonar", "sonarqube", "gitlab", "github", "bitbucket",
    "staging2", "stage", "testing", "test2", "dev2", "uat2",
    "preview", "canary", "edge", "ws", "websocket", "graphql",
    "grpc", "rpc", "socket", "stream", "live", "video", "audio",
    "chat", "notify", "push", "event", "webhook", "callback",
    "integrations", "connect", "link", "id", "sso", "saml",
    "oauth", "token", "key", "secret", "config", "settings",
    "admin2", "superadmin", "root", "system", "sys", "ops",
    "devops", "sre", "infra", "infrastructure", "network",
]

CLOUD_BUCKET_SUFFIXES = [
    "", "-prod", "-production", "-dev", "-development", "-staging",
    "-stage", "-test", "-testing", "-qa", "-uat", "-demo",
    "-backup", "-bak", "-assets", "-static", "-media", "-files",
    "-images", "-img", "-uploads", "-data", "-logs", "-archive",
    "-public", "-private", "-internal", "-external", "-cdn",
    "-storage", "-store", "-bucket", "-blob", "-s3",
]

WAYBACK_SKIP_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "svg", "ico", "webp", "bmp",
    "css", "woff", "woff2", "ttf", "eot", "otf", "map",
    "mp4", "mp3", "avi", "mov", "wav", "ogg", "pdf", "zip",
}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}

# ============================================================
# THREAD-SAFE RESULT COLLECTOR
# ============================================================

class IntelCollector:
    def __init__(self):
        self._lock = threading.Lock()
        self.subdomains:       List[Dict] = []
        self.historical_urls:  List[Dict] = []
        self.git_exposed:      List[Dict] = []
        self.cloud_assets:     List[Dict] = []
        self.leak_candidates:  List[Dict] = []
        self.banners:          List[Dict] = []
        self._seen_hosts:      Set[str]   = set()
        self._seen_urls:       Set[str]   = set()

    def add_subdomain(self, host: str, source: str, resolved: bool = False, ip: str = ""):
        with self._lock:
            if host in self._seen_hosts:
                return
            self._seen_hosts.add(host)
            self.subdomains.append({
                "host": host,
                "resolved": resolved,
                "ip": ip,
                "source": source,
            })

    def add_url(self, url: str, source: str):
        with self._lock:
            if url in self._seen_urls:
                return
            self._seen_urls.add(url)
            self.historical_urls.append({"url": url, "source": source})

    def add_git(self, url: str, evidence: Dict):
        with self._lock:
            self.git_exposed.append({"url": url, **evidence})

    def add_cloud(self, url: str, status: str, provider: str):
        with self._lock:
            self.cloud_assets.append({"url": url, "status": status, "provider": provider})

    def add_leak(self, url: str, snippet: str, source: str):
        with self._lock:
            self.leak_candidates.append({"url": url, "snippet": snippet[:300], "source": source})

    def add_banner(self, host: str, data: Dict):
        with self._lock:
            self.banners.append({"host": host, **data})


# ============================================================
# PASSIVE PHASE — VECTOR 1: SUBDOMAIN HARVEST
# ============================================================

def _harvest_crtsh(domain: str, emit, timeout: int) -> List[str]:
    found = []
    # crt.sh is often slow, use a dedicated longer timeout
    dedicated_timeout = max(timeout, 20)
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers=HEADERS, timeout=dedicated_timeout, verify=False
        )
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        found.append(sub)
        emit.info(f"    [crt.sh] {len(found)} entries")
    except requests.exceptions.Timeout:
        emit.info(f"    [crt.sh] timeout (after {dedicated_timeout}s)")
    except Exception as e:
        emit.info(f"    [crt.sh] failed: {e}")
    return found


def _harvest_hackertarget(domain: str, emit, timeout: int) -> List[str]:
    found = []
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            headers=HEADERS, timeout=timeout, verify=False
        )
        if r.status_code == 200 and "API count" not in r.text:
            for line in r.text.strip().splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if sub:
                        found.append(sub)
        emit.info(f"    [HackerTarget] {len(found)} entries")
    except Exception as e:
        emit.info(f"    [HackerTarget] failed: {e}")
    return found


# BufferOver is defunct, removed from pipeline.


def _harvest_rapiddns(domain: str, emit, timeout: int) -> List[str]:
    found = []
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            headers=HEADERS, timeout=timeout, verify=False
        )
        if r.status_code == 200:
            matches = re.findall(r'<td>([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')</td>', r.text)
            found = list(set(matches))
        emit.info(f"    [RapidDNS] {len(found)} entries")
    except Exception as e:
        emit.info(f"    [RapidDNS] failed: {e}")
    return found


def harvest_subdomains(domain: str, collector: IntelCollector, emit, timeout: int):
    emit.info("  [*] Subdomain harvest (passive sources)...")
    all_found = set()

    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = {
            pool.submit(_harvest_crtsh,        domain, emit, timeout): "crt.sh",
            pool.submit(_harvest_hackertarget,  domain, emit, timeout): "hackertarget",
            pool.submit(_harvest_rapiddns,      domain, emit, timeout): "rapiddns",
        }
        for fut, src in futs.items():
            try:
                for sub in fut.result():
                    if sub and sub not in all_found:
                        all_found.add(sub)
                        collector.add_subdomain(sub, src)
            except Exception:
                pass

    emit.success(f"Subdomain harvest: {len(all_found)} unique hosts found")


# ============================================================
# PASSIVE PHASE — VECTOR 2: WAYBACK HARVEST
# ============================================================

def harvest_wayback(domain: str, collector: IntelCollector, emit, limit: int, timeout: int):
    emit.info("  [*] Wayback Machine CDX harvest...")
    try:
        params = {
            "url":       f"*.{domain}/*",
            "output":    "json",
            "fl":        "original",
            "collapse":  "urlkey",
            "limit":     limit,
            "filter":    "statuscode:200",
        }
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params=params, headers=HEADERS, timeout=45, verify=False
        )
        if r.status_code != 200:
            if r.status_code != 404:
                emit.warn(f"Wayback CDX returned {r.status_code}")
            return

        raw = r.json()
        count = 0
        for row in raw[1:]:  # skip header row
            url = row[0] if isinstance(row, list) else row
            if not url or not url.startswith("http"):
                continue
            parsed = urllib.parse.urlparse(url)
            ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
            if ext in WAYBACK_SKIP_EXTENSIONS:
                continue
            if "?" not in url and not parsed.path.strip("/"):
                continue
            collector.add_url(url, "wayback")
            count += 1

        emit.success(f"Wayback: {count} parameterised URLs harvested")
    except Exception as e:
        emit.error(f"Wayback harvest failed: {e}")


# ============================================================
# PASSIVE PHASE — VECTOR 3: DORK HARVEST
# ============================================================

DORK_QUERIES = [
    'site:github.com "{domain}"',
    'site:github.com "{domain}" password OR token OR secret OR key',
    'site:pastebin.com "{domain}"',
    'site:trello.com "{domain}"',
    'site:gitlab.com "{domain}"',
    '"{domain}" filetype:env OR filetype:sql OR filetype:log',
]

def _ddg_search(query: str, emit, timeout: int) -> List[Dict]:
    results = []
    try:
        r = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={**HEADERS, "Accept": "text/html"},
            timeout=timeout, verify=False
        )
        if r.status_code != 200:
            return results
        links = re.findall(r'<a[^>]+class="result__url"[^>]*>([^<]+)</a>', r.text)
        snippets = re.findall(r'<a[^>]+class="result__snippet"[^>]*>([^<]+)</a>', r.text)
        for i, link in enumerate(links[:5]):
            link = link.strip()
            snippet = snippets[i].strip() if i < len(snippets) else ""
            if link:
                results.append({"url": link, "snippet": snippet})
    except Exception:
        pass
    return results


def harvest_dorks(domain: str, collector: IntelCollector, emit, timeout: int):
    emit.section("DORK HARVEST (DDG)")
    total = 0
    for template in DORK_QUERIES:
        query = template.format(domain=domain)
        hits = _ddg_search(query, emit, timeout)
        for hit in hits:
            collector.add_leak(hit["url"], hit["snippet"], "dork_ddg")
            total += 1
    emit.success(f"Dorks: {total} leak candidates found")


# ============================================================
# PASSIVE PHASE — VECTOR 4: BANNER / EXPOSURE HARVEST
# ============================================================

def _scrape_shodan_web(domain: str, emit, timeout: int) -> List[Dict]:
    results = []
    try:
        r = requests.get(
            f"https://www.shodan.io/search?query=hostname%3A{domain}",
            headers=HEADERS, timeout=timeout, verify=False
        )
        if r.status_code != 200:
            return results
        port_matches = re.findall(
            r'<div[^>]+class="[^"]*port[^"]*"[^>]*>\s*<span[^>]*>(\d+)</span>',
            r.text
        )
        banner_matches = re.findall(
            r'<pre[^>]*class="[^"]*banner[^"]*"[^>]*>([\s\S]{0,200}?)</pre>',
            r.text
        )
        host_matches = re.findall(
            r'<span[^>]+class="[^"]*hostname[^"]*"[^>]*>([^<]+)</span>',
            r.text
        )
        for i, host in enumerate(host_matches[:10]):
            port = port_matches[i] if i < len(port_matches) else "unknown"
            banner = banner_matches[i].strip() if i < len(banner_matches) else ""
            banner = re.sub(r'<[^>]+>', '', banner).strip()
            results.append({
                "host": host.strip(),
                "port": port,
                "banner": banner[:200],
                "source": "shodan_web",
            })
    except Exception as e:
        emit.info(f"    [Shodan web] scrape failed: {e}")
    return results


def _scrape_censys_web(domain: str, emit, timeout: int) -> List[Dict]:
    results = []
    try:
        r = requests.get(
            f"https://search.censys.io/search?resource=hosts&q={domain}",
            headers=HEADERS, timeout=timeout, verify=False
        )
        if r.status_code != 200:
            return results
        ip_matches = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            r.text
        )
        service_matches = re.findall(
            r'<span[^>]+class="[^"]*service[^"]*"[^>]*>([^<]+)</span>',
            r.text
        )
        seen_ips = set()
        for i, ip in enumerate(ip_matches[:8]):
            if ip in seen_ips or ip.startswith(("127.", "0.", "255.")):
                continue
            seen_ips.add(ip)
            service = service_matches[i].strip() if i < len(service_matches) else ""
            results.append({
                "host": ip,
                "port": "unknown",
                "banner": service,
                "source": "censys_web",
            })
    except Exception as e:
        emit.info(f"    [Censys web] scrape failed: {e}")
    return results


def harvest_banners(domain: str, collector: IntelCollector, emit, timeout: int):
    emit.info("  [*] Banner harvest (Shodan/Censys public pages)...")
    total = 0
    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [
            pool.submit(_scrape_shodan_web, domain, emit, timeout),
            pool.submit(_scrape_censys_web, domain, emit, timeout),
        ]
        for fut in as_completed(futs):
            try:
                for banner in fut.result():
                    collector.add_banner(banner.pop("host"), banner)
                    total += 1
            except Exception:
                pass
    emit.success(f"Banners: {total} exposure records found")


# ============================================================
# ACTIVE PHASE — WILDCARD DNS DETECTION
# ============================================================

def _detect_wildcard(domain: str, emit) -> Set[str]:
    """
    Resolve 3 random canary subdomains.
    CDN providers (Cloudflare, Fastly) load-balance across multiple anycast IPs —
    a single canary only catches one of them. Three canaries builds the full set.
    Returns the set of wildcard IPs (empty set = no wildcard).
    """
    import random
    import string
    wildcard_ips: Set[str] = set()
    canaries = [
        f"stalk-{''.join(random.choices(string.ascii_lowercase, k=8))}.{domain}"
        for _ in range(3)
    ]
    for canary in canaries:
        try:
            ip = socket.gethostbyname(canary)
            wildcard_ips.add(ip)
        except socket.gaierror:
            pass

    if wildcard_ips:
        emit.warn(f"Wildcard DNS detected: *.{domain} → {', '.join(sorted(wildcard_ips))}")
        emit.warn(f"{len(wildcard_ips)} wildcard IP(s) will be filtered from permutation results")
    else:
        emit.info("No wildcard DNS detected — permutation brute is clean")
    return wildcard_ips


# ============================================================
# ACTIVE PHASE — VECTOR 1: DNS PERMUTATION BRUTE
# ============================================================

def _resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _http_confirm(host: str, timeout: int) -> bool:
    """
    Send a HEAD request to confirm the host serves real content,
    not just a Cloudflare/CDN catchall 'site not found' page.
    A real vhost returns 200, 301, 302, 403, or 401.
    A CDN catchall typically returns 404 or 530.
    """
    for scheme in ("https", "http"):
        try:
            r = requests.head(
                f"{scheme}://{host}/",
                headers=HEADERS, timeout=timeout,
                verify=False, allow_redirects=True
            )
            if r.status_code in (200, 301, 302, 307, 308, 401, 403):
                return True
            if r.status_code in (404, 530, 503):
                return False
        except Exception:
            pass
    return False


def active_dns_permutation(
    domain: str,
    collector: IntelCollector,
    emit,
    depth: str,
    concurrency: int,
    timeout: int = 8,
):
    emit.info("  [*] DNS permutation bruteforce...")

    wildcard_ips = _detect_wildcard(domain, emit)
    behind_cdn = len(wildcard_ips) > 0

    wordlist = SUBDOMAIN_PERMUTATIONS_FULL if depth == "full" else SUBDOMAIN_PERMUTATIONS_COMMON

    candidates = set()
    for word in wordlist:
        candidates.add(f"{word}.{domain}")
        for prefix in ["api", "dev", "staging", "admin"]:
            if word != prefix:
                candidates.add(f"{prefix}-{word}.{domain}")

    already_known = {s["host"] for s in collector.subdomains}
    candidates -= already_known

    emit.info(f"    [+] Probing {len(candidates)} permuted candidates...")
    dns_live: List[Dict] = []
    filtered = 0

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        fut_to_host = {pool.submit(_resolve_host, host): host for host in candidates}
        for fut in as_completed(fut_to_host):
            host = fut_to_host[fut]
            try:
                ip = fut.result()
                if ip:
                    if wildcard_ips and ip in wildcard_ips:
                        filtered += 1
                        continue
                    dns_live.append({"host": host, "ip": ip})
            except Exception:
                pass

    emit.info(f"    [+] DNS: {len(dns_live)} candidates passed wildcard filter ({filtered} wildcard hits dropped)")

    # HTTP confirmation pass — required when target is behind CDN
    # (all wildcard IPs resolve but CDN returns 404/530 for non-configured vhosts)
    confirmed = 0
    if behind_cdn and dns_live:
        emit.info(f"    [*] CDN detected — running HTTP confirmation pass on {len(dns_live)} candidates...")
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            fut_to_entry = {pool.submit(_http_confirm, e["host"], timeout): e for e in dns_live}
            for fut in as_completed(fut_to_entry):
                entry = fut_to_entry[fut]
                try:
                    if fut.result():
                        collector.add_subdomain(entry["host"], "dns_permutation", resolved=True, ip=entry["ip"])
                        emit.info(f"    [+] CONFIRMED: {entry['host']} → {entry['ip']}")
                        confirmed += 1
                except Exception:
                    pass
        emit.success(f"DNS permutation: {confirmed} real subdomains confirmed (HTTP-verified through CDN)")
    else:
        for entry in dns_live:
            collector.add_subdomain(entry["host"], "dns_permutation", resolved=True, ip=entry["ip"])
            confirmed += 1
        emit.success(f"DNS permutation: {confirmed} live subdomains confirmed")


def active_resolve_passive_subdomains(collector: IntelCollector, emit, concurrency: int):
    emit.info("  [*] Resolving passive subdomains (DNS A-record confirmation)...")
    unresolved = [s for s in collector.subdomains if not s["resolved"]]
    if not unresolved:
        emit.info("  [+] All passive subdomains already resolved")
        return

    confirmed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        fut_to_sub = {pool.submit(_resolve_host, s["host"]): s for s in unresolved}
        for fut in as_completed(fut_to_sub):
            sub = fut_to_sub[fut]
            try:
                ip = fut.result()
                if ip:
                    with collector._lock:
                        sub["resolved"] = True
                        sub["ip"] = ip
                    confirmed += 1
            except Exception:
                pass

    emit.success(f"Resolution pass: {confirmed}/{len(unresolved)} passive hosts live")


# ============================================================
# ACTIVE PHASE — VECTOR 2: GIT EXPOSURE DETECTION
# ============================================================

GIT_PROBE_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/COMMIT_EDITMSG",
    "/.git/info/refs",
]

def _probe_git(base_url: str, timeout: int) -> Optional[Dict]:
    try:
        r = requests.get(
            f"{base_url}/.git/HEAD",
            headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False
        )
        if r.status_code != 200:
            return None
        content = r.text.strip()
        if not content.startswith("ref:") and not re.match(r'^[0-9a-f]{40}$', content):
            return None

        evidence = {"head": content[:200]}

        # Pull config for juicy remote URLs
        try:
            rc = requests.get(
                f"{base_url}/.git/config",
                headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False
            )
            if rc.status_code == 200:
                evidence["config"] = rc.text[:500]
        except Exception:
            pass

        # Pull last commit message
        try:
            mc = requests.get(
                f"{base_url}/.git/COMMIT_EDITMSG",
                headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False
            )
            if mc.status_code == 200:
                evidence["last_commit_msg"] = mc.text.strip()[:200]
        except Exception:
            pass

        return evidence
    except Exception:
        return None


def active_git_detection(collector: IntelCollector, emit, timeout: int, concurrency: int):
    emit.info("  [*] Git exposure detection on live subdomains...")

    live_hosts = [s for s in collector.subdomains if s["resolved"]]
    if not live_hosts:
        emit.info("No live subdomains to probe for git — skipping")
        return

    emit.info(f"    [+] Probing {len(live_hosts)} confirmed live hosts for /.git/HEAD")

    # Probe https only — fall back to http only if https connection is refused/reset
    def probe_with_fallback(host: str) -> Optional[Dict]:
        for scheme in ("https", "http"):
            result = _probe_git(f"{scheme}://{host}", timeout)
            if result is not None:
                return {"url": f"{scheme}://{host}/.git/HEAD", **result}
        return None

    found = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        fut_to_host = {pool.submit(probe_with_fallback, s["host"]): s["host"] for s in live_hosts}
        for fut in as_completed(fut_to_host):
            host = fut_to_host[fut]
            try:
                result = fut.result()
                if result:
                    url = result.pop("url")
                    collector.add_git(url, result)
                    emit.warn(f"GIT EXPOSED: {url}")
                    found += 1
            except Exception:
                pass

    emit.success(f"Git detection: {found} exposed repositories found")


# ============================================================
# ACTIVE PHASE — VECTOR 3: CLOUD ASSET PERMUTATION
# ============================================================

def _extract_org_name(domain: str) -> str:
    parts = domain.split(".")
    return parts[0] if len(parts) >= 2 else domain


def _probe_s3(bucket: str, timeout: int) -> Optional[Dict]:
    url = f"https://{bucket}.s3.amazonaws.com"
    try:
        r = requests.head(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False)
        if r.status_code == 200:
            return {"url": url, "status": "public", "provider": "s3"}
        if r.status_code == 403:
            return {"url": url, "status": "private_exists", "provider": "s3"}
        if r.status_code in (301, 307):
            return {"url": url, "status": "redirect", "provider": "s3"}
    except Exception:
        pass
    return None


def _probe_azure(container: str, timeout: int) -> Optional[Dict]:
    url = f"https://{container}.blob.core.windows.net"
    try:
        r = requests.head(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False)
        if r.status_code in (200, 400):
            return {"url": url, "status": "public" if r.status_code == 200 else "exists", "provider": "azure_blob"}
        if r.status_code == 403:
            return {"url": url, "status": "private_exists", "provider": "azure_blob"}
    except Exception:
        pass
    return None


def _probe_gcp(bucket: str, timeout: int) -> Optional[Dict]:
    url = f"https://storage.googleapis.com/{bucket}"
    try:
        r = requests.head(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False)
        if r.status_code == 200:
            return {"url": url, "status": "public", "provider": "gcp_storage"}
        if r.status_code == 403:
            return {"url": url, "status": "private_exists", "provider": "gcp_storage"}
    except Exception:
        pass
    return None


def active_cloud_permutation(
    domain: str,
    collector: IntelCollector,
    emit,
    timeout: int,
    concurrency: int
):
    emit.info("  [*] Cloud asset permutation probing (S3 / Azure / GCP)...")
    
    # ── Local Target Protection ──────────────────────────
    if domain.lower() in ("localhost", "127.0.0.1", "0.0.0.0"):
        emit.info("    [i] Local target detected — skipping cloud permutation (too noisy)")
        return
    
    org = _extract_org_name(domain)

    candidates = set()
    for base in [org, domain.replace(".", "-"), org.replace("-", "")]:
        for suffix in CLOUD_BUCKET_SUFFIXES:
            name = f"{base}{suffix}".lower()
            name = re.sub(r'[^a-z0-9\-]', '-', name)
            name = re.sub(r'-+', '-', name).strip('-')
            if 3 <= len(name) <= 63:
                candidates.add(name)

    emit.info(f"    [+] Probing {len(candidates)} cloud bucket permutations...")
    found = 0

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = []
        for name in candidates:
            futs.append(pool.submit(_probe_s3,    name, timeout))
            futs.append(pool.submit(_probe_azure,  name, timeout))
            futs.append(pool.submit(_probe_gcp,    name, timeout))

        for fut in as_completed(futs):
            try:
                result = fut.result()
                if result:
                    collector.add_cloud(result["url"], result["status"], result["provider"])
                    severity = "!!" if result["status"] == "public" else "+"
                    emit.info(f"    [{severity}] CLOUD [{result['status'].upper()}]: {result['url']}")
                    found += 1
            except Exception:
                pass

    emit.success(f"Cloud permutation: {found} assets found")


# ============================================================
# RISK SCORING
# ============================================================

def _calculate_risk(collector: IntelCollector) -> int:
    score = 0
    score += len(collector.subdomains) * 1
    score += len([s for s in collector.subdomains if s["resolved"]]) * 2
    score += len(collector.git_exposed) * 25
    score += len([c for c in collector.cloud_assets if c["status"] == "public"]) * 20
    score += len([c for c in collector.cloud_assets if c["status"] == "private_exists"]) * 8
    score += len(collector.leak_candidates) * 5
    score += len(collector.banners) * 2
    score += len(collector.historical_urls) // 10
    return score


# ============================================================
# DOMAIN NORMALISER
# ============================================================

def _normalise_domain(target: str) -> str:
    target = target.strip()
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        target = parsed.netloc or parsed.path
    target = target.split("/")[0].split("?")[0].split(":")[0]
    # Strip leading www.
    if target.startswith("www."):
        target = target[4:]
    return target.lower()


# ============================================================
# MODULE ENTRY POINT
# ============================================================

def run(target: str, emit, options: Optional[Dict[str, Any]] = None):
    opt         = options or {}
    concurrency = int(opt.get("concurrency",        15))
    depth       = str(opt.get("permutation_depth",  "common"))
    wayback_lim = int(opt.get("wayback_limit",       500))
    do_cloud    = bool(opt.get("cloud_permutations", True))
    do_resolve  = bool(opt.get("resolve_subdomains", True))
    timeout     = int(opt.get("timeout",             8))

    domain = _normalise_domain(target)
    emit.always_info(f"Stalk v2.0 — Hybrid OSINT Engine")
    emit.info(f"Target domain: {domain}")
    emit.info(f"Concurrency: {concurrency} | Depth: {depth} | Wayback limit: {wayback_lim}")

    collector = IntelCollector()

    # ── PHASE 1: PASSIVE ──────────────────────────────────────
    emit.section("PHASE 1: PASSIVE OSINT")

    harvest_subdomains(domain, collector, emit, timeout)
    harvest_wayback(domain, collector, emit, wayback_lim, timeout)
    harvest_dorks(domain, collector, emit, timeout)
    harvest_banners(domain, collector, emit, timeout)

    emit.info("")
    emit.info(f"[*] Phase 1 complete — {len(collector.subdomains)} subdomains, "
              f"{len(collector.historical_urls)} URLs, "
              f"{len(collector.leak_candidates)} leak candidates, "
              f"{len(collector.banners)} banner records")
    emit.info("")

    # ── PHASE 2: ACTIVE ───────────────────────────────────────
    emit.section("PHASE 2: ACTIVE CONFIRMATION")

    if do_resolve:
        active_resolve_passive_subdomains(collector, emit, concurrency)

    active_dns_permutation(domain, collector, emit, depth, concurrency, timeout)
    active_git_detection(collector, emit, timeout, concurrency)

    if do_cloud:
        active_cloud_permutation(domain, collector, emit, timeout, concurrency)

    emit.info("")

    # ── SUMMARY ───────────────────────────────────────────────
    live_count   = len([s for s in collector.subdomains if s["resolved"]])
    git_count    = len(collector.git_exposed)
    cloud_public = len([c for c in collector.cloud_assets if c["status"] == "public"])
    cloud_exist  = len([c for c in collector.cloud_assets if c["status"] == "private_exists"])
    risk         = _calculate_risk(collector)

    emit.success(f"Stalk v2 complete.")
    emit.row("    Subdomains",   f"{len(collector.subdomains)} found / {live_count} live")
    emit.row("    Wayback URLs", f"{len(collector.historical_urls)}")
    emit.row("    Git exposed",  f"{git_count}")
    emit.row("    Cloud assets", f"public: {cloud_public} | private: {cloud_exist}")
    emit.row("    Leak hits",    f"{len(collector.leak_candidates)}")
    emit.row("    Banner data",  f"{len(collector.banners)}")
    emit.row("    Risk score",   f"{risk}")

    # ── INTEL DICT ────────────────────────────────────────────
    return {
        "raw": (
            f"Stalk v2: {len(collector.subdomains)} subdomains ({live_count} live), "
            f"{len(collector.historical_urls)} historical URLs, "
            f"{git_count} git exposed, "
            f"{len(collector.cloud_assets)} cloud assets, "
            f"{len(collector.leak_candidates)} leak candidates."
        ),
        "intel": {
            "subdomains":      collector.subdomains,
            "historical_urls": collector.historical_urls,
            "git_exposed":     collector.git_exposed,
            "cloud_assets":    collector.cloud_assets,
            "leak_candidates": collector.leak_candidates,
            "banners":         collector.banners,
        },
        "risk_score": risk,
    }