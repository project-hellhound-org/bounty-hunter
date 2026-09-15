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
@click.option("--print", "-p", "print_cmd", default=None, help="Execute a slash command in headless mode and print output")
@click.option("--json", "-j", "json_output", is_flag=True, default=False, help="Force structured JSON output for automation")
@click.version_option("12.7.0", prog_name="HELLHOUND")
@click.pass_context
def cli(ctx, print_cmd, json_output):
    """
    HELLHOUND — Autonomous bug bounty recon & triage assistant

    Run without arguments to launch the interactive chat console.

      hellhound                     → interactive console
      hellhound --print "/scope show --json"
      hellhound -p "/recon example.com"
    """
    if print_cmd:
        _execute_headless(print_cmd, json_output)
        return

    if ctx.invoked_subcommand is None:
        _launch_console()


def _execute_headless(command_str: str, force_json: bool = False):
    """Executes a command via central dispatcher in headless mode."""
    from hellhound.core.commands import dispatch
    from hellhound.core.emit import PlainEmit
    from hellhound.core.ai_utils import load_config
    from hellhound.core.scope import ScopeRules

    cfg = load_config()
    session_context = {
        "options": {
            "ai_model": cfg.get("ai_model", ""),
            "ai_provider": cfg.get("ai_provider", "ollama"),
            "global_headers": cfg.get("global_headers", {})
        },
        "scope_rules": ScopeRules.from_dict(cfg.get("scope", {})),
        "results": {}
    }

    emit = PlainEmit()
    if force_json or "--json" in command_str:
        setattr(emit, "json_mode", True)

    try:
        dispatch(command_str, session_context, emit)
    except Exception as e:
        if force_json:
            import json
            print(json.dumps({"status": "error", "error": "execution_failed", "message": str(e)}))
        else:
            emit.error(f"Execution failed: {e}")
        sys.exit(1)



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
# Terminal preference (used by packaging/hellhound-launch.sh, the desktop
# launcher's entry point) — NOT read by the console itself. Stored as a
# plain one-line file, not config.json, so the bash wrapper can read it
# with `cat` before Python (and the venv) is even on the critical path.
# -------------------------------------------------
@cli.group()
def terminal():
    """Configure which terminal emulator the desktop launcher opens."""
    pass


@terminal.command("set")
@click.argument("name")
def terminal_set(name):
    """Pin the desktop launcher to a specific terminal (e.g. ghostty, kitty, alacritty)."""
    import os as _os
    import shutil as _shutil
    from pathlib import Path

    if _shutil.which(name) is None:
        click.echo(click.style(
            f"[!] Warning: '{name}' was not found on PATH right now — saving the "
            f"preference anyway in case it's installed later.", fg="yellow"
        ))

    pref_dir = Path.home() / ".hellhound"
    pref_dir.mkdir(parents=True, exist_ok=True)
    (pref_dir / "terminal_preference").write_text(name.strip() + "\n")
    click.echo(f"[+] Desktop launcher will now open HELLHOUND in: {name}")


@terminal.command("show")
def terminal_show():
    """Show the currently configured terminal preference."""
    from pathlib import Path
    pref_file = Path.home() / ".hellhound" / "terminal_preference"
    if pref_file.exists() and pref_file.read_text().strip():
        click.echo(pref_file.read_text().strip())
    else:
        click.echo("(none set — desktop launcher auto-detects an installed terminal)")


@terminal.command("clear")
def terminal_clear():
    """Clear the saved terminal preference and go back to auto-detect."""
    from pathlib import Path
    pref_file = Path.home() / ".hellhound" / "terminal_preference"
    if pref_file.exists():
        pref_file.unlink()
    click.echo("[+] Cleared — desktop launcher will auto-detect a terminal.")


# -------------------------------------------------
# Shared launcher
# -------------------------------------------------
def _launch_console():
    try:
        from hellhound.core.chat_ui import start_chat_session
        start_chat_session()
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