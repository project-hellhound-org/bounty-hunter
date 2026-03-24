import sys
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
@click.version_option("12.0", prog_name="HELLHOUND")
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