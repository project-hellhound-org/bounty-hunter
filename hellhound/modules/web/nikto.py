import subprocess
import shutil

NAME = "nikto"
CATEGORY = "web"
DESCRIPTION = "Web server vulnerability scanning"

def run(target, emit, options=None):
    emit.info("Starting Nikto scan")

    if not shutil.which("nikto"):
        emit.warn("nikto not installed")
        return ""

    cmd = ["nikto", "-h", f"http://{target}", "-ask", "no"]

    output = subprocess.run(cmd, capture_output=True, text=True).stdout
    emit.success("Nikto scan completed")
    return output
