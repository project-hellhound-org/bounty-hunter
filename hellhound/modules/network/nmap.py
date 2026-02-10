import subprocess

NAME = "nmap"
CATEGORY = "network"
DESCRIPTION = "Service and version detection using Nmap"

def run(target, emit, options=None):
    emit(f"[*] Nmap scan started against {target}")

    args = ["nmap", "-sV", "-sC", target]

    if options and options.get("fast"):
        args = ["nmap", "-F", target]

    output = ""

    process = subprocess.Popen(
        args,
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
    emit.success("Nmap finished")
    return output
