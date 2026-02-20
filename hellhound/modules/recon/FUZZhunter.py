import requests
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

NAME = "fuzz_hunter"
CATEGORY = "recon"
DESCRIPTION = "Heuristic directory fuzzing with 404 detection and size filtering"

# High-value targets (Used for QUICK mode or fallback)
INTERNAL_WORDLIST = [
    ".env", ".git", "config.php", "config.json", "web.config", "backup.zip",
    "backup.sql", "admin", "administrator", "wp-admin", "console", "dashboard",
    "api", "v1", "v2", "debug", "test", "dev", "staging", "db", "database",
    "secret", "private", "internal", "logs", "access.log", "error.log",
    "install.php", "setup.php", "upgrade.php", "readme.html", "changelog.md"
]

def get_wordlist_path():
    """
    Dynamically resolves the path to the wordlist assuming a standard repository structure.
    Expected Structure:
    /hellhound/
       /modules/
          /recon/
             fuzzhunter.py (this file)
       /wordlists/
          /web/
             directories.txt
    """
    try:
        # Get the directory where this script is located
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Go up 3 levels to reach the project root (recon -> modules -> root)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
        
        # Construct path to wordlist
        wordlist_path = os.path.join(project_root, "wordlists", "web", "directories.txt")
        
        if os.path.exists(wordlist_path):
            return wordlist_path
        else:
            return None
    except Exception:
        return None

class FuzzWorker:
    def __init__(self, base_url, emit):
        self.base_url = base_url
        self.emit = emit
        self.results = []
        self.lock = threading.Lock()
        
        # Heuristics
        self.not_found_size = 0
        self.not_found_status = 0

    def check_baseline(self):
        """Check how the server handles a definitely non-existent page"""
        try:
            # Use a random string that likely doesn't exist
            r = requests.get(f"{self.base_url}/hellhound-baseline-check-xyz123", timeout=5)
            self.not_found_size = len(r.content)
            self.not_found_status = r.status_code
            return r.status_code
        except Exception:
            return 0

    def test_path(self, path):
        """Worker function to test a single path"""
        url = f"{self.base_url}/{path}"
        try:
            r = requests.get(url, timeout=3)
            size = len(r.content)
            
            is_interesting = False
            
            # Logic: 
            # 1. If status is 200, check size vs baseline.
            # 2. If size differs significantly from 404 baseline, it's a hit.
            # 3. 403 (Forbidden) is always interesting (it exists).
            # 4. 301/302 (Redirects) are interesting.
            
            if r.status_code == 200:
                if self.not_found_size == 0:
                    # If we couldn't establish a baseline, treat all 200s as hits
                    is_interesting = True
                elif abs(size - self.not_found_size) > 20: # Allow small variations
                    is_interesting = True
            
            elif r.status_code == 403:
                is_interesting = True

            elif r.status_code in [301, 302, 307, 308]:
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
    
    # 1. DETERMINE MODE
    mode = "quick"
    if options and options.get("mode") == "deep":
        mode = "deep"
        emit.info(f"    [i] MODE: DEEP (Loading external wordlist)")
    else:
        emit.info(f"    [i] MODE: QUICK (Using internal top-targets)")

    # 2. LOAD WORDLIST
    words = []
    
    if mode == "deep":
        wordlist_path = get_wordlist_path()
        if wordlist_path:
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # Read lines, strip whitespace, ignore empty lines or comments
                    words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                emit.info(f"    [i] Loaded {len(words)} words from external wordlist.")
            except Exception as e:
                emit.warn(f"    [!] Failed to load wordlist: {e}")
                emit.warn(f"    [!] Falling back to internal list.")
                words = INTERNAL_WORDLIST
        else:
            emit.warn(f"    [!] Wordlist file not found at expected location.")
            emit.warn(f"    [!] Falling back to internal list.")
            words = INTERNAL_WORDLIST
    else:
        words = INTERNAL_WORDLIST

    scanner = FuzzWorker(url, emit)
    
    # 3. Establish Baseline
    baseline_status = scanner.check_baseline()
    
    baseline_msg = f"    [i] Baseline Check: Non-existent pages return status {baseline_status}"
    if baseline_status == 200 or baseline_status == 0:
        baseline_msg += f" (Size: {scanner.not_found_size} bytes)"
    emit.info(baseline_msg)
    
    # 4. Launch Thread Pool (Safe for large wordlists)
    # We limit threads to avoid DoS'ing the target or the local machine
    MAX_THREADS = 50 
    
    emit.info(f"    [i] Starting fuzzing with {MAX_THREADS} threads...")
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Submit all tasks
        future_to_path = {executor.submit(scanner.test_path, word): word for word in words}
        
        # Wait for completion
        for future in as_completed(future_to_path):
            # We just need to consume the futures to ensure they run
            pass

    # 5. Analyze Results
    if scanner.results:
        # Sort results by status code (200 first)
        scanner.results.sort(key=lambda x: x['status'])
        
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