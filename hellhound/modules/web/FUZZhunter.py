import requests
import threading
import math

NAME = "fuzz_hunter"
CATEGORY = "recon"
DESCRIPTION = "Heuristic directory fuzzing with 404 detection and size filtering"

# High-value targets
WORDLIST = [
    ".env", ".git", "config.php", "config.json", "web.config", "backup.zip",
    "backup.sql", "admin", "administrator", "wp-admin", "console", "dashboard",
    "api", "v1", "v2", "debug", "test", "dev", "staging", "db", "database",
    "secret", "private", "internal", "logs", "access.log", "error.log",
    "install.php", "setup.php", "upgrade.php", "readme.html", "changelog.md"
]

class FuzzWorker:
    def __init__(self, base_url, wordlist, emit):
        self.base_url = base_url
        self.wordlist = wordlist
        self.emit = emit
        self.results = []
        self.lock = threading.Lock()
        
        # Heuristics
        self.not_found_size = 0
        self.not_found_count = 0

    def check_baseline(self):
        """Check how the server handles a definitely non-existent page"""
        try:
            r = requests.get(f"{self.base_url}/hellhound-should-not-exist-12345", timeout=5)
            self.not_found_size = len(r.content)
            self.not_found_count = 1
            return r.status_code
        except:
            return 000

    def worker(self, path):
        url = f"{self.base_url}/{path}"
        try:
            r = requests.get(url, timeout=3)
            size = len(r.content)
            
            # Logic: 
            # 1. If status is 200, check size.
            # 2. If size is different from the "Not Found" baseline, it's a hit.
            
            is_interesting = False
            
            if r.status_code == 200:
                if self.not_found_size == 0:
                    is_interesting = True
                elif abs(size - self.not_found_size) > 50: # Significant size difference
                    is_interesting = True
            
            elif r.status_code == 301 or r.status_code == 302:
                # Redirects to auth pages are interesting
                is_interesting = True

            elif r.status_code == 403:
                # Forbidden is VERY interesting (it exists but we can't see it)
                is_interesting = True

            if is_interesting:
                with self.lock:
                    self.results.append({
                        "path": path,
                        "status": r.status_code,
                        "size": size,
                        "url": url
                    })
                    
        except requests.RequestException:
            pass

def run(target, emit, options=None):
    emit.info(f"[*] Advanced Fuzzing: Starting heuristic scan on {target}")
    
    url = target if target.startswith("http") else f"http://{target}"
    
    scanner = FuzzWorker(url, WORDLIST, emit)
    
    # 1. Establish Baseline
    baseline_status = scanner.check_baseline()
    emit.info(f"    [i] Baseline Check: Non-existent pages return status {baseline_status} (Size: {scanner.not_found_size} bytes)")
    
    # 2. Launch Threads
    threads = []
    for word in WORDLIST:
        t = threading.Thread(target=scanner.worker, args=(word,))
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()

    # 3. Analyze Results
    if scanner.results:
        emit.success(f"[+] Found {len(scanner.results)} interesting endpoints.")
        for res in scanner.results:
            status_color = "GREEN" if res['status'] == 200 else "RED" if res['status'] == 403 else "YELLOW"
            emit.info(f"    [{res['status']}] {res['path']} ({res['size']} bytes)")
            
        return {
            "raw": f"Found {len(scanner.results)} endpoints.",
            "intel": {"endpoints": scanner.results},
            "signals": ["HIDDEN_ENDPOINTS_FOUND"]
        }
    else:
        emit.info("[-] No hidden files detected via fuzzing.")
        return {"raw": "No files found", "signals": []}