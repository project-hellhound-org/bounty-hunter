import subprocess
import shutil

NAME = "ftp"
CATEGORY = "network"
DESCRIPTION = "FTP enumeration and anonymous login checks"

def run(target, emit, options=None):
    emit.info("Checking FTP service")

    if not shutil.which("nmap"):
        emit.warn("nmap not found")
        return ""

    cmd = [
        "nmap",
        "-p", "21",
        "--script", "ftp-anon,ftp-syst",
        target
    ]

    output = subprocess.run(cmd, capture_output=True, text=True).stdout
    emit.success("FTP enumeration completed")
    return output
