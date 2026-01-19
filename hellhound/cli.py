#!/usr/bin/env python3
import click
import subprocess
import os
from dotenv import load_dotenv
from hellhound.web.server import run_web_dashboard

load_dotenv()

@click.group()
def cli():
    """🐶 HELLHOUND - AI Pentesting Framework"""
    pass

@cli.command()
@click.argument('target')
@click.option('--port', default=8080, help='Web dashboard port')
def hunt(target, port):
    """Launch full pentest hunt on TARGET"""
    click.echo(f"🐶 HELLHOUND hunting {target}...")
    
    # Launch web dashboard
    click.echo("🌐 Starting Hellhound Dashboard...")
    subprocess.Popen(['python', '-m', 'hellhound.web.server', str(port)])
    
    # Recon phase (placeholder for Nmap integration)
    click.echo("🔍 Phase 1: Reconnaissance")
    subprocess.run(['nmap', '-sV', '-sC', target], capture_output=True)
    
    click.echo(f"📊 Dashboard live: http://localhost:{port}")
    click.echo("💀 Full attack chain ready - check web UI!")
    input("Press Enter to exit...")

if __name__ == '__main__':
    cli()
