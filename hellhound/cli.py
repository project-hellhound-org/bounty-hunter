import click
import yaml
import importlib.resources as pkg_resources
import subprocess
import time

# ----------------------------
# Config Loader
# ----------------------------
def load_config():
    try:
        with pkg_resources.files("hellhound").joinpath("config.yaml").open("r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        click.echo("[!] Failed to load config: {}".format(e))
        return {"modules": {}}


# ----------------------------
# Banner
# ----------------------------
def print_hellhound_banner():
    banner = r"""
       / \__
      (    @\___
      /         O    HELLHOUND v1.0
     /   (_____/
    /_____/   U     Modular Pentest Framework
    """
    click.echo(banner)


# ----------------------------
# CLI Root
# ----------------------------
@click.group()
def cli():
    """Hellhound Pentesting Framework"""
    pass


# ----------------------------
# List Modules
# ----------------------------
@cli.command()
def modules():
    """List available modules"""
    config = load_config()

    click.echo("\nAvailable modules:\n")
    for name, meta in config.get("modules", {}).items():
        desc = meta.get("description", "No description")
        click.echo(f"  {name:<10} - {desc}")
    click.echo()


# ----------------------------
# Hunt Mode
# ----------------------------
@cli.command()
@click.argument("target")
@click.option("--port", default=8080)
def hunt(target, port):
    print_hellhound_banner()

    config = load_config()
    available = list(config.get("modules", {}).keys())

    if not available:
        click.echo("[!] No modules found in config.yaml")
        return

    click.echo(f"[+] Target locked: {target}\n")

    click.echo("Select modules to run:\n")
    for i, mod in enumerate(available, 1):
        desc = config["modules"][mod].get("description", "")
        click.echo(f"  [{i}] {mod} - {desc}")
    click.echo(f"  [{len(available)+1}] all - Run everything\n")

    choice = click.prompt("Enter choice (comma separated)", default="1")

    try:
        if choice.strip() == str(len(available) + 1):
            selected = available
        else:
            selected = [available[int(i.strip()) - 1] for i in choice.split(",")]
    except:
        click.echo("[!] Invalid selection")
        return

    click.echo(f"\n[+] Selected modules: {', '.join(selected)}")

    wordlist = ""
    if "vhost" in selected:
        use_custom = click.confirm("Use custom wordlist for VHOST fuzzing?", default=False)
        if use_custom:
            wordlist = click.prompt("Enter path to wordlist")

    cmd = [
        "python", "-m", "hellhound.web.server",
        f"--port={port}",
        f"--target={target}",
        f"--modules={','.join(selected)}",
        f"--wordlist={wordlist}"
    ]

    proc = subprocess.Popen(cmd)

    click.echo("\n[+] Hellhound unleashed.")
    click.echo("[*] Press Ctrl+C to disengage.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\n[+] Shutting down Hellhound...")
        proc.terminate()
        click.echo("[✓] Hellhound terminated cleanly.")


# ----------------------------
# Console Mode
# ----------------------------
@cli.command()
def console():
    """Launch interactive console"""
    from hellhound.console import HellhoundConsole
    HellhoundConsole().cmdloop()


# ----------------------------
# Entry point (THIS FIXES YOUR ERROR)
# ----------------------------
def main():
    cli()


if __name__ == "__main__":
    main()
