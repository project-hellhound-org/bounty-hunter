import subprocess
import shutil

NAME = "nuclei"
CATEGORY = "web"
DESCRIPTION = "Template-based vulnerability scanning"

def run(target, emit, options=None):
    emit.info("Running nuclei scan")

    if not shutil.which("nuclei"):
        emit.warn("nuclei not installed")
        return ""

    cmd = [
        "nuclei",
        "-u", f"http://{target}",
        "-severity", "low,medium,high,critical",
        "-silent"
    ]

    output = subprocess.run(cmd, capture_output=True, text=True).stdout
    emit.success("Nuclei scan completed")
    return output
