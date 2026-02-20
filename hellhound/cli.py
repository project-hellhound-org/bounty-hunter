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
# Entry Point
# -------------------------------------------------
def main():
    cli()


if __name__ == "__main__":
    main()
