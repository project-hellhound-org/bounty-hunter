import subprocess

NAME = "dirsearch"
CATEGORY = "web"
DESCRIPTION = "Web directory discovery using ffuf"

def run(target, emit, options=None):
    emit("[*] Directory discovery started")

    wordlist = options.get("wordlist") if options else None
    if not wordlist:
        wordlist = "hellhound/wordlists/default.txt"

    url = f"http://{target}/FUZZ"

    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist,
        "-mc", "200,301,302,403"
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
