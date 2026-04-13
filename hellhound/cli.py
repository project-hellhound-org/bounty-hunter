import sys
import warnings

# Suppress annoying requests/urllib3 dependency warnings before they trigger
warnings.filterwarnings("ignore", message=".*urllib3.*match a supported version.*")
warnings.filterwarnings("ignore", message=".*RequestsDependencyWarning.*")

import click


# -------------------------------------------------
# Root CLI Group
# invoke_without_command=True means bare `hellhound`
# launches the console instead of printing help.
# -------------------------------------------------
@click.group(
    invoke_without_command=True,
    context_settings=dict(help_option_names=["-h", "--help"])
)
@click.version_option("12.5.0", prog_name="HELLHOUND")
@click.pass_context
def cli(ctx):
    """
    HELLHOUND — Modular Web Offensive Framework

    Run without arguments to launch the interactive console.

      hellhound              → interactive console
      hellhound console      → same
    """
    if ctx.invoked_subcommand is None:
        _launch_console()


# -------------------------------------------------
# Console subcommand (explicit, for compatibility)
# -------------------------------------------------
@cli.command()
def console():
    """Launch interactive console mode"""
    _launch_console()


# -------------------------------------------------
# Upgrade subcommand
# -------------------------------------------------
@cli.command()
def upgrade():
    """Pull latest updates and sync dependencies"""
    import os
    import subprocess
    from pathlib import Path

    # Find the project root (where update.sh lives)
    project_root = Path(__file__).resolve().parent.parent
    update_script = project_root / "update.sh"

    if not update_script.exists():
        click.echo(click.style(f"[x] Error: Update script not found at {update_script}", fg="red"))
        return

    # Ensure it's executable
    os.chmod(update_script, 0o755)

    try:
        subprocess.run(["bash", str(update_script)], check=True)
    except subprocess.CalledProcessError:
        click.echo(click.style("[!] Upgrade process encountered an error.", fg="yellow"))
    except Exception as e:
        click.echo(click.style(f"[x] Critical error during upgrade: {e}", fg="red"))


# -------------------------------------------------
# Shared launcher
# -------------------------------------------------
def _launch_console():
    try:
        from hellhound.console import HellhoundConsole
        HellhoundConsole().cmdloop()
    except KeyboardInterrupt:
        click.echo("\n[+] Exiting HELLHOUND.")
        sys.exit(0)
    except Exception as e:
        click.echo(f"[!] Failed to start console: {e}")
        sys.exit(1)


# -------------------------------------------------
# Entry Point
# -------------------------------------------------
def main():
    cli()


if __name__ == "__main__":
    main()