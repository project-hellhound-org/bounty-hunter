# hellhound/modules/web/vhost.py
import subprocess
import os

NAME = "vhost"
CATEGORY = "web"
DESCRIPTION = "Virtual host fuzzing using ffuf wrapper"

def run(target, emit, options=None):
    emit("[*] VHOST fuzzing started")

    # hellhound/modules/web -> hellhound/
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    script_path = os.path.join(base_dir, "scripts", "vhost-fuzzer.sh")
    default_wordlist = os.path.join(base_dir, "wordlists", "default.txt")

    if not os.path.exists(script_path):
        emit(f"[!] VHOST script not found: {script_path}")
        return ""

    wordlist = options.get("wordlist") if options else None
    if not wordlist:
        wordlist = default_wordlist
        emit(f"[i] Using default wordlist: {wordlist}")
    else:
        emit(f"[i] Using custom wordlist: {wordlist}")

    url = f"http://{target}"
    fs_filter = "4242"

    cmd = ["bash", script_path, target, wordlist, url, fs_filter]
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
    emit("[✓] VHOST fuzzing completed")
    return output
