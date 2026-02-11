import click


# -------------------------------------------------
# Root CLI Group
# -------------------------------------------------
@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option("1.0", prog_name="HELLHOUND")
def cli():
    """
    Hellhound Modular Pentesting Framework

    Modes:
      console   - Interactive operator-driven mode
      hunt      - Automated rule-driven hunting mode
    """
    pass


# -------------------------------------------------
# Console Mode
# -------------------------------------------------
@cli.command()
def console():
    """Launch interactive console mode"""
    try:
        from hellhound.console import HellhoundConsole
        HellhoundConsole().cmdloop()
    except Exception as e:
        click.echo(f"[!] Failed to start console: {e}")


# -------------------------------------------------
# Hunting Mode
# -------------------------------------------------
@cli.command()
@click.argument("target")
@click.option(
    "--mode",
    default="camouflage",
    show_default=True,
    type=click.Choice(["camouflage", "stealth", "brutal"]),
    help="Hunting doctrine level"
)
def hunt(target, mode):
    """
    Launch automated hunting mode against a target.
    """
    try:
        from hellhound.hunting_mode import HuntingMode
        hunter = HuntingMode(target=target, mode=mode)
        hunter.run()
    except Exception as e:
        click.echo(f"[!] Hunting mode failed: {e}")



# -------------------------------------------------
# Future Mode Placeholder (Optional Expansion)
# -------------------------------------------------
# Example:
# @cli.command()
# def dashboard():
#     from hellhound.dashboard import start_dashboard
#     start_dashboard()


# -------------------------------------------------
# Entry Point
# -------------------------------------------------
def main():
    cli()


if __name__ == "__main__":
    main()
