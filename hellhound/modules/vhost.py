import subprocess
import os

def run(target, emit, wordlist=None):
    emit("VHOST fuzzing started")

    base_dir = os.path.dirname(__file__)
    script_path = os.path.abspath(os.path.join(base_dir, "..", "scripts", "vhost-fuzzer.sh"))

    if not wordlist:
        wordlist = os.path.abspath(os.path.join(base_dir, "..", "wordlists", "default.txt"))
        emit(f"Using default wordlist: {wordlist}")
    else:
        emit(f"Using custom wordlist: {wordlist}")

    url = f"http://{target}"
    fs_filter = "4242"

    cmd = ["bash", script_path, target, wordlist, url, fs_filter]
    emit(f"Executing: {' '.join(cmd)}")

    output = ""

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # Capture stdout
    for line in process.stdout:
        if line.strip():
            emit(line.strip())
            output += line

    # Capture stderr
    for line in process.stderr:
        if line.strip():
            emit(f"[stderr] {line.strip()}")
            output += line

    process.wait()

    emit("VHOST fuzzing completed")
    return output
