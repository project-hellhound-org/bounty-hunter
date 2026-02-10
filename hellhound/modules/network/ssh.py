import subprocess
import shutil

NAME = "ssh"
CATEGORY = "network"
DESCRIPTION = "SSH service enumeration"

def run(target, emit, options=None):
    emit.info("Enumerating SSH service")

    if not shutil.which("nmap"):
        emit.warn("nmap not found")
        return ""

    cmd = [
        "nmap",
        "-p", "22",
        "--script", "ssh-hostkey,ssh-auth-methods",
        target
    ]

    output = subprocess.run(cmd, capture_output=True, text=True).stdout
    emit.success("SSH enumeration completed")
    return output
