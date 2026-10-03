import subprocess
import os
import concurrent.futures
import logging
from collections import defaultdict
import argparse
from datetime import datetime
from xml.etree import ElementTree as ET
import sys

logging.basicConfig(
    filename='nmap_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', default='naabu_results.txt')
    parser.add_argument('-o', '--output', default='nmap-out')
    parser.add_argument('-t', '--threads', type=int, default=4)
    return parser.parse_args()

def create_output_directory(path):
    os.makedirs(path, exist_ok=True)

def parse_file(path):
    data = defaultdict(list)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                ip, port = line.split(":")
                data[ip].append(port)
    return data

def run_nmap(ip, ports, outdir):
    ports_str = ",".join(ports)
    outfile = os.path.join(outdir, f"nmap_out_{ip}.xml")

    cmd = [
        "nmap",
        "-sS",                      # Stealth SYN scan
        "-sV",                      # Service version detection
        "-sC",                      # Default NSE scripts
        "--version-all",            # Aggressive version probing
        "--script", "vuln,default", # Vulnerability + default scripts
        "--open",                   # Show only open ports
        "--reason",                 # Why port is open
        "-T4",                      # Faster timing template
        "-Pn",                      # Skip host discovery
        "-p", ports_str,            # Ports from naabu
        "-oX", outfile,             # XML output
        ip
    ]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        logging.error(f"nmap failed for {ip}")

def combine_nmap_xml_files(output_dir):
    xmls = [f for f in os.listdir(output_dir)
            if f.startswith("nmap_out_") and f.endswith(".xml")]

    base_root = None
    hosts = []

    for x in xmls:
        try:
            root = ET.parse(os.path.join(output_dir, x)).getroot()
            if base_root is None:
                base_root = root
            hosts.extend(root.findall("host"))
        except Exception:
            continue

    if not base_root or not hosts:
        return

    for h in base_root.findall("host"):
        base_root.remove(h)

    for h in hosts:
        base_root.append(h)

    out = os.path.join(output_dir, "nmap_out.xml")
    ET.ElementTree(base_root).write(out)
    print(f"[+] Combined XML written: {out}")

def main():
    args = parse_arguments()
    outdir = os.path.join(args.output, datetime.now().strftime("%Y%m%d_%H%M%S"))
    create_output_directory(outdir)

    targets = parse_file(args.input)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)

    try:
        futures = [
            executor.submit(run_nmap, ip, ports, outdir)
            for ip, ports in targets.items()
        ]
        concurrent.futures.wait(futures)

    except KeyboardInterrupt:
        print("\n[!] Interrupted — merging partial results…")

    finally:
        executor.shutdown(wait=False)
        combine_nmap_xml_files(outdir)

if __name__ == "__main__":
    main()
