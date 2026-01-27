import subprocess

def run(target, emit):
    emit(f"Nmap started on {target}")
    cmd = ["nmap", "-sV", "-sC", target]

    output = ""
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        emit(line.strip())
        output += line

    emit("Nmap finished")
    return output
