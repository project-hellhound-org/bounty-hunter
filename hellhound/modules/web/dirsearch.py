import subprocess
import shutil
import importlib.resources as pkg_resources

NAME = "dirsearch"
CATEGORY = "web"
DESCRIPTION = "Directory and endpoint discovery"

def run(target, emit, options=None):
    emit.info("Starting directory discovery")

    if not shutil.which("dirsearch"):
        emit.warn("dirsearch not installed")
        return ""

    wordlist = pkg_resources.files("hellhound").joinpath(
        "wordlists/web/directories.txt"
    )

    cmd = [
        "dirsearch",
        "-u", f"http://{target}",
        "-w", str(wordlist),
        "-e", "*",
        "--format", "plain"
    ]

    output = subprocess.run(cmd, capture_output=True, text=True).stdout
    emit.success("Directory discovery completed")
    return output
