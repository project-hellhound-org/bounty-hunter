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
    # No single cross-distro install command (prebuilt binary release,
    # cargo, or a distro package depending on OS) — the parenthetical
    # makes try_install() treat this as a human-readable hint rather than
    # something to exec literally, same as the nmap entry below.
    "feroxbuster": "cargo install feroxbuster (or grab a prebuilt binary from https://github.com/epi052/feroxbuster/releases)",
    "subzy": "go install -v github.com/PentestPad/subzy@latest",
    "gowitness": "go install github.com/sensepost/gowitness@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "jsluice": "go install github.com/BishopFox/jsluice/cmd/jsluice@latest",
    "uro": "pip install uro",
    # Not a single runnable command (varies by distro/package manager) —
    # try_install() below recognizes the parenthetical and skips
    # auto-exec for this one rather than running it literally.
    "nmap": "apt install nmap (or the equivalent for your OS — brew install nmap on macOS, pacman -S nmap on Arch)",
    # Pre-installed on Kali by default; this hint only matters on a non-Kali
    # box where it's genuinely missing.
    "sqlmap": "apt install sqlmap (or: pip install sqlmap, or git clone https://github.com/sqlmapproject/sqlmap.git)",
}


# pip's default read-timeout (15s) is fine on a fast connection and too
# short on a slow/unstable one (mobile hotspot, congested campus wifi) --
# a single slow chunk from pypi.org trips "ReadTimeoutError" mid-download
# and the install/update just fails, with nothing to show for it but a
# generic error. Appended to every pip invocation in this file, same fix
# install.sh applies to its own pip calls.
PIP_NET_ARGS: List[str] = ["--timeout", "100", "--retries", "5"]


def pick_available(candidates: List[str]) -> Optional[str]:
    """
    Given an ordered list of binary names that all satisfy the same
    capability (e.g. ["dnsx"], or a future ["ffuf", "feroxbuster"] for
    content discovery), returns the first one actually present on this
    system, or None if every candidate is missing.

    This is the piece a fallback-aware executor is missing today:
    ensure_tool()/is_available() can only answer "is THIS ONE binary
    there," so every tool executor hardcodes a single binary and just
    fails outright if it's not installed. A caller that has more than one
    way to do the same job (a purpose-built Go binary, a stdlib/python
    fallback, a different CLI tool that covers the same capability) uses
    this to pick whichever is actually available instead of hardcoding
    one, falling all the way through to a pure-language implementation
    with no external binary at all when none of them are installed.
    """
    for name in candidates:
        if is_available(name):
            return name
    return None


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
        # Deliberately NOT .resolve()'d: a venv's bin/python3 is almost
        # always a symlink to the base system interpreter, so resolving it
        # walks straight past the venv's own bin/ to e.g. /usr/bin — which
        # is already on PATH and does NOT contain the venv's installed
        # console scripts (uro, etc.). sys.executable itself already
        # reports the venv path verbatim; resolving it threw away the one
        # directory this was added to find.
        str(Path(sys.executable).parent),
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
            [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--break-system-packages", package],
            [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--user", package],
            [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, package],
        ]
    else:
        attempts = [cmd.split()]

    last_error = ""
    saw_already_satisfied = False
    for attempt_cmd in attempts:
        try:
            proc = subprocess.run(attempt_cmd, capture_output=True, text=True, timeout=180, check=False)
        except Exception as e:
            last_error = str(e)
            continue
        if is_available(tool_name):
            return True
        out = (proc.stderr or "") + (proc.stdout or "")
        if "already satisfied" in out.lower():
            saw_already_satisfied = True
        last_error = out.strip().splitlines()[-1] if out.strip() else f"exit code {proc.returncode}"

    # Every normal attempt reported "already satisfied" — pip sees valid
    # package metadata in site-packages and skips re-installing entirely,
    # which ALSO skips regenerating the console-script wrapper in bin/.
    # That leaves a state where the package is genuinely present but the
    # command was never written (a prior install that got interrupted
    # after writing metadata but before writing scripts, a venv rebuilt
    # from a stale lib/ copy, etc.) — "already satisfied" looks like
    # success but the binary still doesn't exist. --force-reinstall
    # --no-deps re-extracts the package unconditionally and regenerates
    # its entry-point scripts, which fixes exactly this state without
    # needing to know anything about this specific package's internals.
    if cmd.startswith("pip install ") and saw_already_satisfied:
        package = cmd[len("pip install "):].strip()
        if emit and hasattr(emit, "info"):
            emit.info(f"[*] {tool_name} looks installed but its command is missing — forcing a reinstall to regenerate it...")
        for flag_set in (["--break-system-packages"], ["--user"], []):
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--force-reinstall", "--no-deps", *flag_set, package],
                    capture_output=True, text=True, timeout=180, check=False,
                )
            except Exception as e:
                last_error = str(e)
                continue
            if is_available(tool_name):
                return True
            out = (proc.stderr or "") + (proc.stdout or "")
            last_error = out.strip().splitlines()[-1] if out.strip() else f"exit code {proc.returncode}"

    if emit and hasattr(emit, "warn") and last_error:
        if saw_already_satisfied:
            emit.warn(f"[!] {tool_name} is installed (pip confirms it) but no '{tool_name}' executable exists anywhere on PATH, even after a forced reinstall.")
            emit.info(f"    Check what pip actually wrote: {sys.executable} -m pip show -f {cmd.split()[-1]}  (look for a 'bin/{tool_name}' or 'Scripts/{tool_name}' entry — if there genuinely isn't one, this package has no CLI command and must be used as a Python module instead)")
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


def update_all_tools(emit=None) -> Dict[str, Any]:
    """
    Updates every ALREADY-INSTALLED binary tool to its latest version —
    the update-side counterpart to try_install()/check_all_tools(), which
    only ever install a MISSING tool and never touch one that's already
    there. Two different users running the same Hellhound checkout can
    silently drift onto different tool versions (one picked up a nuclei
    template-format change, the other didn't) with no single command to
    reconcile that — this is it.

    Returns {"pdtm": {...}, "other": {<tool>: bool}, "skipped": [...]}.
    """
    result: Dict[str, Any] = {"pdtm": None, "other": {}, "skipped": []}

    # ── ProjectDiscovery suite: pdtm's own bulk-update flag updates every
    # PD tool it has installed in one shot, in place — no need to loop
    # per-tool like try_install() does for first-time installs.
    if is_available("pdtm"):
        if emit and hasattr(emit, "info"):
            emit.info("[*] Updating ProjectDiscovery tool suite via `pdtm -ua`...")
        try:
            proc = subprocess.run(
                ["pdtm", "-ua"], capture_output=True, text=True, timeout=300, check=False
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            result["pdtm"] = {"ok": proc.returncode == 0, "output": out.strip()[-2000:]}
            if emit and hasattr(emit, "success") and proc.returncode == 0:
                emit.success("[✓] ProjectDiscovery tools updated.")
            elif emit and hasattr(emit, "warn"):
                emit.warn(f"[!] `pdtm -ua` exited {proc.returncode} — some PD tools may not have updated.")
        except Exception as e:
            result["pdtm"] = {"ok": False, "output": str(e)}
            if emit and hasattr(emit, "warn"):
                emit.warn(f"[!] Could not run `pdtm -ua`: {e}")
    else:
        result["skipped"].append("pdtm (not installed — PD tools can't be bulk-updated; run /setup tools install-all first)")

    # ── Standalone Go/pip tools: only touch ones already installed.
    # `go install X@latest` always re-fetches the current latest release
    # even if one is already present, so re-running the same install
    # command IS the update for every go-based entry here. pip entries
    # get an explicit --upgrade. Hint-only entries (nmap, feroxbuster,
    # sqlmap's apt/git-clone variants) have no single safe command to
    # run unattended, same restriction try_install() already respects.
    for tool_name, cmd in sorted(OTHER_TOOLS.items()):
        if not is_available(tool_name):
            continue  # not installed — that's an install, not an update
        if cmd.startswith("(no known") or "(" in cmd:
            result["skipped"].append(f"{tool_name} (no single update command — {cmd})")
            continue

        if emit and hasattr(emit, "info"):
            emit.info(f"[*] Updating {tool_name}...")

        if cmd.startswith("pip install "):
            package = cmd[len("pip install "):].strip()
            attempts = [
                [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--upgrade", "--break-system-packages", package],
                [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--upgrade", "--user", package],
                [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--upgrade", package],
            ]
        else:
            attempts = [cmd.split()]

        ok = False
        last_error = ""
        for attempt_cmd in attempts:
            try:
                proc = subprocess.run(attempt_cmd, capture_output=True, text=True, timeout=180, check=False)
                if proc.returncode == 0:
                    ok = True
                    break
                out = (proc.stderr or "") + (proc.stdout or "")
                last_error = out.strip().splitlines()[-1] if out.strip() else f"exit code {proc.returncode}"
            except Exception as e:
                last_error = str(e)
        result["other"][tool_name] = ok
        if emit:
            if ok and hasattr(emit, "success"):
                emit.success(f"[✓] {tool_name} up to date.")
            elif not ok and hasattr(emit, "warn"):
                emit.warn(f"[!] {tool_name} update failed: {last_error}")

    return result


def sync_python_dependencies(project_root: Optional[str] = None, emit=None) -> Dict[str, Any]:
    """
    Re-syncs Hellhound's own Python dependencies against requirements.txt.

    This exists because setup.py's install_requires and requirements.txt
    can drift apart — install.sh only ever runs `pip install -e .`
    (setup.py's list), never `pip install -r requirements.txt`, so a
    package present in requirements.txt but missing from install_requires
    (lxml and cryptography, historically) is silently never installed on
    a fresh machine even though install.sh "succeeds." Re-running this
    against requirements.txt directly is what actually catches and fixes
    that drift for an existing install, regardless of whether setup.py
    has since been corrected.
    """
    root = project_root or str(Path(__file__).resolve().parents[2])
    req_file = Path(root) / "requirements.txt"
    if not req_file.is_file():
        return {"ok": False, "error": f"requirements.txt not found at {req_file}"}

    if emit and hasattr(emit, "info"):
        emit.info("[*] Syncing Python dependencies from requirements.txt...")

    attempts = [
        [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--upgrade", "--break-system-packages", "-r", str(req_file)],
        [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--upgrade", "--user", "-r", str(req_file)],
        [sys.executable, "-m", "pip", "install", *PIP_NET_ARGS, "--upgrade", "-r", str(req_file)],
    ]
    last_out = ""
    for attempt_cmd in attempts:
        try:
            proc = subprocess.run(attempt_cmd, capture_output=True, text=True, timeout=300, check=False)
        except Exception as e:
            last_out = str(e)
            continue
        last_out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            if emit and hasattr(emit, "success"):
                emit.success("[✓] Python dependencies up to date.")
            return {"ok": True, "output": last_out.strip()[-2000:]}
    if emit and hasattr(emit, "warn"):
        emit.warn(f"[!] Dependency sync failed: {last_out.strip().splitlines()[-1] if last_out.strip() else 'unknown error'}")
    return {"ok": False, "output": last_out.strip()[-2000:]}


def update_hellhound_source(project_root: Optional[str] = None, emit=None) -> Dict[str, Any]:
    """
    git-pulls the Hellhound source itself, mirroring update.sh's logic
    (stash local changes if dirty, pull, restore the stash) so `/update`
    inside a running session can do everything update.sh does without
    the researcher having to exit and find a terminal.
    """
    root = project_root or str(Path(__file__).resolve().parents[2])
    git_dir = Path(root) / ".git"
    if not git_dir.is_dir():
        return {"ok": False, "skipped": True, "reason": "not a git checkout — installed from a release archive, not `git clone`"}

    def _run(args: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", root] + args, capture_output=True, text=True, timeout=60, check=False)

    status = _run(["status", "--porcelain"])
    dirty = bool(status.stdout.strip())
    if dirty:
        if emit and hasattr(emit, "warn"):
            emit.warn("[!] Local changes detected — stashing them to pull cleanly...")
        _run(["stash"])

    branch_proc = _run(["rev-parse", "--abbrev-ref", "HEAD"])
    branch = branch_proc.stdout.strip() or "main"

    if emit and hasattr(emit, "info"):
        emit.info(f"[*] Pulling latest changes on branch '{branch}'...")
    pull = _run(["pull", "origin", branch])
    ok = pull.returncode == 0
    out = (pull.stdout or "") + (pull.stderr or "")
    if not ok:
        if emit and hasattr(emit, "warn"):
            emit.warn("[!] Standard pull failed — attempting fetch + hard reset to origin...")
        _run(["fetch", "--all"])
        reset = _run(["reset", "--hard", f"origin/{branch}"])
        ok = reset.returncode == 0
        out += "\n" + (reset.stdout or "") + (reset.stderr or "")

    if dirty:
        pop = _run(["stash", "pop"])
        if pop.returncode != 0 and emit and hasattr(emit, "warn"):
            emit.warn("[!] Could not auto-restore your local changes — they're still in `git stash list`.")

    already_up_to_date = "Already up to date" in out or "Already up-to-date" in out
    if ok and emit and hasattr(emit, "success"):
        emit.success("[✓] Already on the latest version." if already_up_to_date else "[✓] Hellhound source updated.")
    elif not ok and emit and hasattr(emit, "warn"):
        emit.warn(f"[!] Source update failed: {out.strip().splitlines()[-1] if out.strip() else 'unknown error'}")

    return {"ok": ok, "branch": branch, "already_up_to_date": already_up_to_date, "output": out.strip()[-2000:]}


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