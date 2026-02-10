import subprocess
import shutil
import importlib.resources as pkg_resources

NAME = "vhost"
CATEGORY = "web"
DESCRIPTION = "Virtual host enumeration using ffuf"

def run(target, emit, options=None):
    emit.info("Starting virtual host enumeration")

    if not shutil.which("ffuf"):
        emit.warn("ffuf not found")
        return ""

    wordlist = pkg_resources.files("hellhound").joinpath(
        "wordlists/vhosts/vhosts.txt"
    )

    cmd = [
        "ffuf",
        "-u", f"http://{target}",
        "-H", "Host: FUZZ",
        "-w", str(wordlist),
        "-mc", "200,301,302,403",
        "-s"
    ]

    output = subprocess.run(cmd, capture_output=True, text=True).stdout
    emit.success("VHOST fuzzing completed")
    return output
