#!/usr/bin/env python3
import click
import subprocess
import webbrowser
import time
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def print_hellhound_banner():
    banner = r"""
       / \__
      (    @\___
      /         O    HELLHOUND v0.5
     /   (_____/
    /_____/   U     Professional Pentest Framework
    """
    click.echo(banner)

@click.group()
def cli():
    pass

@cli.command()
@click.argument('target')
@click.option('--port', default=8080, type=int)
def hunt(target, port):
    """Full pentest chain"""
    print_hellhound_banner()
    click.echo(f"[+] Target: {target}")
    click.echo(f"[+] Dashboard: http://localhost:{port}")
    
    # SILENT Flask launch
    cmd = [
        'python', 'hellhound/web/server.py',
        f'--port={port}'
    ]
    devnull = open(os.devnull, 'w')
    web_process = subprocess.Popen(cmd, cwd=os.getcwd(), stdout=devnull, stderr=devnull)
    
    # Healthcheck
    click.echo("[+] Booting dashboard...")
    for i in range(10):
        try:
            requests.get(f'http://localhost:{port}', timeout=1)
            click.echo(f"[+] LIVE: http://localhost:{port}")
            webbrowser.open(f'http://localhost:{port}')
            break
        except:
            time.sleep(1)
    
    # Clean Nmap
    click.echo("\n[+] Recon: nmap -sV -sC")
    result = subprocess.run(['nmap', '-sV', '-sC', '-oN', 'recon.txt', target], 
                           capture_output=True, text=True)
    output = result.stdout[:2000]
    click.echo("Nmap scan complete. Results saved to recon.txt")
    click.echo(f"[+] Services discovered: {len([l for l in output.split('\n') if '/tcp' in l])} open ports")
    
    click.echo(f"\n[*] Interactive dashboard: http://localhost:{port}")
    click.echo("[*] Ctrl+C to disengage")
    
    try:
        web_process.wait()
    except KeyboardInterrupt:
        web_process.terminate()
        click.echo("\n[+] Hellhound terminated")

def main():
    cli()

if __name__ == '__main__':
    cli()
