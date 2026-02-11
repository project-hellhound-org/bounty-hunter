import subprocess

NAME = "ftp"
CATEGORY = "network"
DESCRIPTION = "FTP enumeration and credential testing"

RISK = "medium"

def run(target, emit, options=None):

    opts = options or {}
    mode = opts.get("mode", "enum")  # enum | bruteforce

    emit(f"[*] FTP module running in '{mode}' mode")

    if mode == "enum":
        return ftp_enum(target, emit)

    elif mode == "bruteforce":
        return ftp_bruteforce(target, emit)

    else:
        emit("[!] Unknown FTP mode. Defaulting to enum.")
        return ftp_enum(target, emit)


# -------------------------------------------------
# ENUMERATION MODE
# -------------------------------------------------

def ftp_enum(target, emit):

    emit("[*] Checking FTP service (Port 21)")

    cmd = ["nmap", "-p21", "-sV", "--script=ftp-anon,ftp-syst", target]

    output = ""

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    for line in process.stdout:
        if line.strip():
            emit(line.strip())
            output += line

    process.wait()

    emit("[✓] FTP enumeration completed")

    return output


# -------------------------------------------------
# BRUTEFORCE MODE (Controlled)
# -------------------------------------------------

def ftp_bruteforce(target, emit):

    emit("[!] Starting FTP brute force (use responsibly)")

    cmd = [
        "nmap",
        "-p21",
        "--script=ftp-brute",
        target
    ]

    output = ""

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    for line in process.stdout:
        if line.strip():
            emit(line.strip())
            output += line

    process.wait()

    emit("[✓] FTP brute force completed")

    return output
