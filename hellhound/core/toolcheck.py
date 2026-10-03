"""
hellhound/core/toolcheck.py

Centralized Tool Availability Checking, Install Hints, and Auto-Installation.
Manages ProjectDiscovery tool suite (via pdtm) and standalone offensive Go binaries.
"""

import os
import shutil
import site
import subprocess
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Set, List

# ProjectDiscovery suite — installable via `pdtm -i <name>`
PD_TOOLS: Set[str] = {
    "subfinder", "httpx", "naabu", "dnsx", "alterx", "tlsx",
    "shuffledns", "katana",
}

# Non-PD dependencies used elsewhere in the tool registry — pdtm can't
# install these, they need their own install hints.
OTHER_TOOLS: Dict[str, str] = {
    "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
    "subzy": "go install -v github.com/PentestPad/subzy@latest",
    "gowitness": "go install github.com/sensepost/gowitness@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "uro": "pip install uro",
    # Not a single runnable command (varies by distro/package manager) —
    # try_install() below recognizes the parenthetical and skips
    # auto-exec for this one rather than running it literally.
    "nmap": "apt install nmap (or the equivalent for your OS — brew install nmap on macOS, pacman -S nmap on Arch)",
}


def _get_search_path() -> str:
    """
    Constructs complete search path including standard Go binary locations
    AND the directories pip actually installs console scripts into.

    Why this matters: `pip install uro` installs a console-script entry
    point named `uro` into the SAME bin/ directory as whichever Python
    interpreter ran the install — e.g. ~/.hellhound-env/bin/uro for a venv
    install, or the --user site's bin/ for a --break-system-packages/--user
    install. If Hellhound itself is launched via a symlinked `hellhound`
    command that execs the venv's python directly (see install.sh) rather
    than through an activated shell, that bin/ dir is never on the
    inherited PATH env var — so a package that installed successfully (pip
    says "Requirement already satisfied") still reads as missing here,
    with no error, because this function was never looking in the one
    place pip actually put it.
    """
    custom_paths = [
        str(Path.home() / ".pdtm" / "go" / "bin"),
        str(Path.home() / "go" / "bin"),
        "/usr/local/bin",
        "/usr/bin",
        # The currently-running interpreter's own bin/ dir — where its
        # pip installs console scripts (covers venvs like .hellhound-env).
        str(Path(sys.executable).resolve().parent),
        # The `pip install --user` target's bin/ dir, for installs made
        # outside a venv with --user instead of --break-system-packages.
        str(Path(site.USER_BASE) / "bin") if hasattr(site, "USER_BASE") and site.USER_BASE else "",
    ]
    return os.environ.get("PATH", "") + ":" + ":".join(p for p in custom_paths if p)


def is_available(tool_name: str) -> bool:
    """Returns True if binary is executable in PATH or user Go bin directories."""
    return shutil.which(tool_name, path=_get_search_path()) is not None


def get_binary_path(tool_name: str) -> Optional[str]:
    """Returns the resolved absolute path to the binary if found."""
    return shutil.which(tool_name, path=_get_search_path())


def install_hint(tool_name: str) -> str:
    """Returns the exact shell command to install the missing tool."""
    if tool_name in PD_TOOLS:
        return f"pdtm -i {tool_name}"
    return OTHER_TOOLS.get(tool_name, f"(no known install command for {tool_name})")


def try_install(tool_name: str, emit=None) -> bool:
    """
    Attempt to install a missing tool. Returns True if it's available
    afterward.

    pip-based tools get special handling: on Debian/Ubuntu/Kali with
    Python 3.11+, a plain `pip install X` fails with an
    "externally-managed-environment" error (PEP 668) and the old version
    of this function swallowed that failure completely — it printed
    "Installing..." and then just silently stayed missing, with no error
    ever shown. This now retries with --break-system-packages / --user,
    and if every attempt fails, reports the REAL error back through emit
    instead of failing silently.
    """
    cmd = install_hint(tool_name)
    if cmd.startswith("(no known") or "(" in cmd:
        # Either genuinely unknown, or (like nmap) a human-readable hint
        # rather than a single runnable command — don't exec it literally.
        if emit and hasattr(emit, "warn") and "(" in cmd and not cmd.startswith("(no known"):
            emit.warn(f"[!] {tool_name} has no single auto-install command — install it yourself: {cmd}")
        return False
    if emit and hasattr(emit, "info"):
        emit.info(f"[*] Installing {tool_name} via `{cmd}`...")

    if cmd.startswith("pip install "):
        package = cmd[len("pip install "):].strip()
        attempts = [
            [sys.executable, "-m", "pip", "install", "--break-system-packages", package],
            [sys.executable, "-m", "pip", "install", "--user", package],
            [sys.executable, "-m", "pip", "install", package],
        ]
    else:
        attempts = [cmd.split()]

    last_error = ""
    for attempt_cmd in attempts:
        try:
            proc = subprocess.run(attempt_cmd, capture_output=True, text=True, timeout=180, check=False)
        except Exception as e:
            last_error = str(e)
            continue
        if is_available(tool_name):
            return True
        last_error = (proc.stderr or proc.stdout or "").strip().splitlines()[-1] if (proc.stderr or proc.stdout) else f"exit code {proc.returncode}"

    if emit and hasattr(emit, "warn") and last_error:
        if "already satisfied" in last_error.lower():
            # pip succeeded — the package IS installed — but is_available()
            # still can't find its console script on PATH. That used to
            # mean _get_search_path() wasn't checking the running
            # interpreter's own bin/ dir (fixed above); if this still
            # shows up after that fix, the package genuinely has no
            # console-script entry point, or something else put a
            # same-named file in the way.
            emit.warn(f"[!] pip says {tool_name} is already installed, but no '{tool_name}' executable was found on PATH.")
            emit.info(f"    Check where pip put it: {sys.executable} -m pip show -f {cmd.split()[-1]}  (look for a 'bin/{tool_name}' or 'Scripts/{tool_name}' entry)")
        else:
            emit.warn(f"[!] Install of {tool_name} failed: {last_error}")
            emit.info(f"    Try manually: {cmd}  (or: {sys.executable} -m pip install --break-system-packages {cmd.split()[-1]})" if cmd.startswith("pip install") else f"    Try manually: {cmd}")
    return False


def ensure_tool(tool_name: str, emit=None, auto_install: bool = False) -> Dict[str, Any]:
    """
    Returns {"available": bool, "message": str}.
    If the tool is missing and auto_install is True, attempts install via
    try_install() first. If still missing (or auto_install is False),
    returns available=False with a clear install-hint message the caller
    should surface to the user rather than failing silently.
    """
    if is_available(tool_name):
        return {"available": True, "message": ""}
    if auto_install:
        if try_install(tool_name, emit=emit):
            return {"available": True, "message": f"[*] {tool_name} installed successfully."}
    return {
        "available": False,
        "message": (
            f"[!] '{tool_name}' is not installed — results may be incomplete. "
            f"Install it with `{install_hint(tool_name)}` and re-run the same "
            f"request for more accurate results."
        ),
    }


def check_all_tools() -> Dict[str, Any]:
    """
    Checks all known PD and standalone tools.
    Returns status map, lists of installed/missing tools, and combined install command.
    """
    results = {}
    missing_pd: List[str] = []
    missing_other: List[str] = []
    installed: List[str] = []

    for t in sorted(PD_TOOLS):
        avail = is_available(t)
        results[t] = {
            "available": avail,
            "type": "ProjectDiscovery",
            "install": f"pdtm -i {t}",
            "path": get_binary_path(t) or ""
        }
        if avail:
            installed.append(t)
        else:
            missing_pd.append(t)

    for t, hint in sorted(OTHER_TOOLS.items()):
        avail = is_available(t)
        results[t] = {
            "available": avail,
            "type": "Standalone",
            "install": hint,
            "path": get_binary_path(t) or ""
        }
        if avail:
            installed.append(t)
        else:
            missing_other.append(t)

    combined_pd_cmd = f"pdtm -i {','.join(missing_pd)}" if missing_pd else ""

    return {
        "tools": results,
        "installed": installed,
        "missing_pd": missing_pd,
        "missing_other": missing_other,
        "total_tools": len(results),
        "installed_count": len(installed),
        "missing_count": len(missing_pd) + len(missing_other),
        "combined_pd_install": combined_pd_cmd
    }


def check_wordlists() -> Dict[str, Any]:
    """
    Checks availability of standard system wordlists (SecLists, Kali wordlists).
    Returns path, status, and installation recommendations.
    """
    seclists_paths = [
        "/usr/share/wordlists/seclists",
        "/usr/share/seclists",
        str(Path.home() / "wordlists" / "seclists"),
        str(Path.home() / "SecLists"),
    ]
    seclists_found = None
    for p in seclists_paths:
        if os.path.isdir(p) and os.path.exists(os.path.join(p, "Discovery")):
            seclists_found = p
            break

    kali_wordlists = os.path.isdir("/usr/share/wordlists")

    return {
        "seclists_installed": bool(seclists_found),
        "seclists_path": seclists_found or "",
        "kali_wordlists_installed": kali_wordlists,
        "install_hint_apt": "sudo apt update && sudo apt install -y seclists wordlists",
        "install_hint_git": "sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists"
    }