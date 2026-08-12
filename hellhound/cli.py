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
@click.option("--gui", is_flag=True, default=False, help="Launch PyWebView graphical user interface")
@click.version_option("12.6.0", prog_name="HELLHOUND")
@click.pass_context
def cli(ctx, print_cmd, json_output, gui):
    """
    HELLHOUND — Autonomous bug bounty recon & triage assistant

    Run without arguments to launch the interactive chat console.

      hellhound                     → interactive console
      hellhound gui                 → launch PyWebView GUI
      hellhound --print "/scope show --json"
      hellhound -p "/recon example.com"
    """
    if print_cmd:
        _execute_headless(print_cmd, json_output)
        return

    if gui:
        _launch_gui()
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
# GUI subcommand (PyWebView chat-archive interface)
# -------------------------------------------------
@cli.command()
@click.argument("target", required=False, default=None)
@click.option("--debug", is_flag=True, default=False, help="Enable webview developer tools")
def gui(target, debug):
    """Launch the modern PyWebView GUI interface"""
    _launch_gui(target=target, debug=debug)


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
        from hellhound.core.chat_ui import start_chat_session
        start_chat_session()
    except KeyboardInterrupt:
        click.echo("\n[+] Exiting HELLHOUND.")
        sys.exit(0)
    except Exception as e:
        click.echo(f"[!] Failed to start console: {e}")
        sys.exit(1)


def _launch_gui(target=None, debug: bool = False):
    try:
        from hellhound.gui_app import launch_gui
        launch_gui(target=target, debug=debug)
    except KeyboardInterrupt:
        click.echo("\n[+] Exiting HELLHOUND GUI.")
        sys.exit(0)
    except Exception as e:
        click.echo(f"[!] Failed to start GUI: {e}")
        sys.exit(1)


# -------------------------------------------------
# Entry Point
# -------------------------------------------------
def main():
    cli()


if __name__ == "__main__":
    main()