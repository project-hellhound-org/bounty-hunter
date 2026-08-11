"""
hellhound/core/toolcheck.py

Centralized Tool Availability Checking, Install Hints, and Auto-Installation.
Manages ProjectDiscovery tool suite (via pdtm) and standalone offensive Go binaries.
"""

import os
import shutil
import subprocess
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
}


def _get_search_path() -> str:
    """Constructs complete search path including standard Go binary locations."""
    custom_paths = [
        str(Path.home() / ".pdtm" / "go" / "bin"),
        str(Path.home() / "go" / "bin"),
        "/usr/local/bin",
        "/usr/bin",
    ]
    return os.environ.get("PATH", "") + ":" + ":".join(custom_paths)


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
    """Attempt to install a missing tool. Returns True if it's available afterward."""
    cmd = install_hint(tool_name)
    if cmd.startswith("(no known"):
        return False
    if emit and hasattr(emit, "info"):
        emit.info(f"[*] Installing {tool_name} via `{cmd}`...")
    try:
        subprocess.run(cmd.split(), capture_output=True, text=True, timeout=180, check=False)
    except Exception:
        return False
    return is_available(tool_name)


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
