# hellhound/modules/reconcombo.py

import subprocess
import os

def run(target, emit):
    emit("[*] ReconComboGo engaged")
    emit("[*] Full reconnaissance chain starting")

    cmd = ["reconcomboGo", "--url", target]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    for line in process.stdout:
        emit(line.rstrip())

    process.wait()

    output_dir = os.path.join("reconcombo", target)

    if os.path.exists(output_dir):
        emit(f"[✓] Recon workspace ready: {output_dir}")
        return {
            "engine": "reconcomboGo",
            "output_dir": output_dir,
            "completed": True
        }

    emit("[!] ReconComboGo finished but output directory not found")
    return {"completed": False}
