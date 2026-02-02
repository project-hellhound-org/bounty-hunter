# hellhound/modules/web/dirsearch.py
import subprocess
import shutil
import os

NAME = "dirsearch"
CATEGORY = "web"
DESCRIPTION = "Directory and endpoint discovery using dirsearch"

def run(target, emit, options=None):
    emit("[*] Directory discovery started")

    if not shutil.which("dirsearch"):
        emit("[!] dirsearch not found in PATH. Install it first.")
        return ""

    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    default_wordlist = os.path.join(base_dir, "wordlists", "default.txt")

    wordlist = options.get("wordlist") if options else None
    if not wordlist:
        wordlist = default_wordlist
        emit(f"[i] Using default wordlist: {wordlist}")
    else:
        emit(f"[i] Using custom wordlist: {wordlist}")

    url = f"http://{target}"

    cmd = [
        "dirsearch",
        "-u", url,
        "-w", wordlist,
        "-e", "*",
        "--format", "plain"
    ]

    emit(f"[*] Executing: {' '.join(cmd)}")

    output = ""
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    for line in process.stdout:
        if line.strip():
            emit(line.strip())
            output += line

    process.wait()
    emit("[✓] Directory discovery completed")
    return output
