#!/usr/bin/env python3
"""
audit_module.py — Hellhound Local Module Auditor

Verifies a module against framework standards before contribution.
Checks: Syntax, Metadata (DESCRIPTION, CATEGORY, OPTIONS), Imports, and Core Isolation.

Usage:
    python audit_module.py <path_to_module>
"""

import os
import sys
import subprocess
import importlib.util
from colorama import Fore, Style, init

init(autoreset=True)

def print_status(status, message):
    if status == "ok":
        print(Fore.GREEN + f"  [+] {message}")
    elif status == "warn":
        print(Fore.YELLOW + f"  [!] {message}")
    elif status == "err":
        print(Fore.RED + f"  [x] {message}")
    else:
        print(f"  [*] {message}")

def audit(module_path: str):
    print(Style.BRIGHT + f"\n── Hellhound Module Audit: {os.path.basename(module_path)} ──\n")

    if not os.path.exists(module_path):
        print_status("err", f"File not found: {module_path}")
        return False

    errors = 0

    # 1. Syntax Check
    try:
        subprocess.check_output(["python3", "-m", "py_compile", module_path], stderr=subprocess.STDOUT)
        print_status("ok", "Syntax: Valid Python")
    except subprocess.CalledProcessError as e:
        print_status("err", f"Syntax: ERROR\n{e.output.decode()}")
        errors += 1

    # 2. Protocol & Metadata Check
    try:
        with open(module_path, "r") as f:
            content = f.read()
        
        missing = []
        if "DESCRIPTION" not in content: missing.append("DESCRIPTION")
        if "CATEGORY" not in content:    missing.append("CATEGORY")
        if "OPTIONS" not in content:     missing.append("OPTIONS")
        if "def run(" not in content:    missing.append("run() entry-point")

        if missing:
            print_status("err", f"Metadata: Missing {', '.join(missing)}")
            errors += 1
        else:
            print_status("ok", "Metadata: All mandatory fields present")

    except Exception as e:
        print_status("err", f"File Read: {e}")
        errors += 1

    # 3. Isolation Check (Local Git Check)
    try:
        # Check if core files are modified locally
        diff = subprocess.check_output(["git", "diff", "--name-only"], text=True)
        violations = []
        for line in diff.splitlines():
            if line.startswith("hellhound/core/") or line == "hellhound/console.py" or line == "setup.py":
                violations.append(line)
        
        if violations:
            print_status("err", "Isolation: CORE VIOLATION DETECTED")
            for v in violations:
                print(Fore.RED + f"      -> Modified core file: {v}")
            errors += 1
        else:
            print_status("ok", "Isolation: No core file modifications detected")
    except Exception:
        print_status("warn", "Isolation: Could not verify (not a git repo or git not found)")

    # 4. Import Check
    try:
        # We try to load the module to check for missing dependencies
        spec = importlib.util.spec_from_file_location("audit_target", module_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        print_status("ok", "Imports: All dependencies resolvable")
    except Exception as e:
        print_status("err", f"Imports: FAILED (missing dependency or runtime error)\n      -> {e}")
        errors += 1

    print("\n" + "─" * 45)
    if errors == 0:
        print(Fore.GREEN + Style.BRIGHT + "  RESULT: PASS")
        print("  Your module is ready for contribution.")
        print("  Next: git push origin feature/<name> and open a PR.")
        return True
    else:
        print(Fore.RED + Style.BRIGHT + f"  RESULT: FAIL ({errors} errors)")
        print("  Please fix the issues above before contributing.")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    success = audit(sys.argv[1])
    sys.exit(0 if success else 1)
