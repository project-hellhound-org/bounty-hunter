import requests
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

NAME = "fuzz_hunter"
CATEGORY = "recon"
DESCRIPTION = "Advanced recursive directory fuzzer with similarity-based 404 detection"

# High-value targets (Used for QUICK mode or fallback)
INTERNAL_WORDLIST = [
    ".env", ".git", "config.php", "config.json", "web.config", "backup.zip",
    "backup.sql", "admin", "administrator", "wp-admin", "console", "dashboard",
    "api", "v1", "v2", "debug", "test", "dev", "staging", "db", "database",
    "secret", "private", "internal", "logs", "access.log", "error.log",
    "install.php", "setup.php", "upgrade.php", "readme.html", "changelog.md"
]

def get_wordlist_path():
    """Resolves path to web wordlist, prioritizing standard Kali/SecLists paths with fast fallback."""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
        candidates = [
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            os.path.join(project_root, "wordlists", "web", "directories-fast.txt")
        ]
        for c in candidates:
            if os.path.exists(c) and os.path.getsize(c) > 0:
                return c
        return None
    except Exception:
        return None

class FuzzWorker:
    def __init__(self, base_url, emit, max_depth=2, threads=30):
        self.base_url = base_url.rstrip("/")
        self.emit = emit
        self.max_depth = max_depth
        self.threads = threads
        self.results = []
        self.found_dirs = set([""]) # Initial root
        self.lock = threading.Lock()
        
        # Heuristics
        self.not_found_size = 0
        self.not_found_status = 0
        self.not_found_content = ""

    def check_baseline(self):
        """Check how the server handles a definitely non-existent page"""
        try:
            r = requests.get(f"{self.base_url}/hh-baseline-{os.urandom(4).hex()}", timeout=5, allow_redirects=False)
            self.not_found_size = len(r.content)
            self.not_found_status = r.status_code
            self.not_found_content = r.text[:1000]
            return r.status_code
        except Exception:
            return 0

    def is_similar_to_404(self, status, content, size):
        if status != self.not_found_status and self.not_found_status != 0:
            return False
        if self.not_found_size > 0:
            diff = abs(size - self.not_found_size)
            if diff < 50 or diff < (self.not_found_size * 0.05):
                if self.not_found_content and content:
                    from difflib import SequenceMatcher
                    ratio = SequenceMatcher(None, self.not_found_content, content[:1000]).ratio()
                    if ratio > 0.8: return True
                else:
                    return True
        return False

    def test_path(self, base_path, word):
        rel_path = f"{base_path}/{word}".lstrip("/")
        url = f"{self.base_url}/{rel_path}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=False)
            size = len(r.content)
            is_interesting = False
            
            if r.status_code == 403:
                is_interesting = True
            elif r.status_code in [301, 302, 307, 308]:
                is_interesting = True
                loc = r.headers.get("Location", "")
                if loc.endswith("/") or word.endswith("/"):
                    with self.lock:
                        if rel_path not in self.found_dirs:
                            self.found_dirs.add(rel_path)
            elif r.status_code == 200:
                if not self.is_similar_to_404(r.status_code, r.text, size):
                    is_interesting = True
                    if rel_path.endswith("/") or "." not in word:
                        with self.lock:
                            if rel_path not in self.found_dirs:
                                self.found_dirs.add(rel_path)

            if is_interesting:
                with self.lock:
                    if any(res['path'] == rel_path for res in self.results): return
                    self.results.append({"path": rel_path, "status": r.status_code, "size": size, "url": url})
        except Exception:
            pass

def run(target, emit, options=None):
    emit.info(f"[*] Advanced Fuzzing: {target}")
    url = target if target.startswith("http") else f"http://{target}"
    
    max_depth = int(options.get("depth", 2)) if options else 2
    threads = int(options.get("threads", 30)) if options else 30
    mode = "deep" if options and options.get("mode") == "deep" else "quick"
    
    # Load Wordlist
    words = []
    spider_intel = options.get("spider_intel", {}) if options else {}
    tech_stack = spider_intel.get("tech_stack", [])
    
    tech_exts = []
    if any("PHP" in t for t in tech_stack): tech_exts.extend([".php", ".php.bak"])
    if any("Node" in t for t in tech_stack): tech_exts.extend([".js", "package.json"])
    
    # Tracked separately from `mode` so the returned result can tell the
    # orchestrator (not just a human watching the terminal) when a "deep"
    # request silently got the same ~25-word coverage as "quick" — emit.*
    # calls are console/UI-only and never reach the model's own context,
    # so without this field the model has no way to know its request for
    # thorough coverage was downgraded.
    degraded_wordlist = False
    if mode == "deep":
        wp = get_wordlist_path()
        if wp:
            try:
                with open(wp, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                emit.info(f"    [i] Loaded {len(words)} words (DEEP)")
            except Exception:
                words = INTERNAL_WORDLIST
                degraded_wordlist = True
                emit.warn(f"    [!] DEEP mode requested but wordlist at {wp} failed to load — falling back to the {len(INTERNAL_WORDLIST)}-word internal list. Coverage is degraded; consider content_discovery (ffuf) instead for this run.")
        else:
            words = INTERNAL_WORDLIST
            degraded_wordlist = True
            emit.warn(f"    [!] DEEP mode requested but no SecLists/dirb/dirbuster wordlist found on disk — falling back to the {len(INTERNAL_WORDLIST)}-word internal list. Coverage is degraded; install SecLists, or use content_discovery (ffuf) instead for this run.")
    else: words = INTERNAL_WORDLIST

    if tech_exts: words = list(set(words + tech_exts))
    scanner = FuzzWorker(url, emit, max_depth=max_depth, threads=threads)
    baseline = scanner.check_baseline()
    emit.info(f"    [i] Baseline: {baseline} (Size: {scanner.not_found_size})")

    # Recursive Loop
    current_depth = 0
    scanned_dirs = set()
    to_scan = [""]

    while current_depth < max_depth and to_scan:
        emit.info(f"    [i] Depth {current_depth}: Fuzzing {len(to_scan)} directories...")
        next_scan = []
        
        for base in to_scan:
            if base in scanned_dirs: continue
            scanned_dirs.add(base)
            
            with ThreadPoolExecutor(max_workers=scanner.threads) as executor:
                futures = [executor.submit(scanner.test_path, base, word) for word in words]
                for f in as_completed(futures): pass
        
        # Identify new directories found for next depth
        with scanner.lock:
            for d in scanner.found_dirs:
                if d not in scanned_dirs:
                    next_scan.append(d)
        
        to_scan = next_scan
        current_depth += 1

    wordlist_note = (
        f"WARNING: requested mode='{mode}' but only {len(words)} words were actually tried "
        f"(internal fallback list, not a real wordlist) — a negative result here does NOT mean "
        f"the surface is clean, it means coverage was thin. Prefer content_discovery (ffuf) for "
        f"a properly-covered negative result."
    ) if degraded_wordlist else None

    if scanner.results:
        scanner.results.sort(key=lambda x: x['status'])
        emit.success(f"[+] Found {len(scanner.results)} interesting endpoints.")
        for res in scanner.results:
            emit.info(f"    [{res['status']}] {res['path']} ({res['size']} bytes)")
        result = {"raw": f"Found {len(scanner.results)} endpoints", "intel": {"endpoints": scanner.results}, "signals": ["HIDDEN_ENDPOINTS_FOUND"], "words_tried": len(words)}
        if wordlist_note:
            result["degraded_coverage_warning"] = wordlist_note
            result["signals"].append("DEGRADED_WORDLIST_COVERAGE")
        return result

    emit.info("[-] No hidden files detected.")
    result = {"raw": "No files found", "signals": [], "words_tried": len(words)}
    if wordlist_note:
        result["degraded_coverage_warning"] = wordlist_note
        result["signals"].append("DEGRADED_WORDLIST_COVERAGE")
    return result