"""
OpenRemap CLI — root entry point.

Dispatching rules:
    openremap                          → launches the TUI
    openremap --help                   → CLI help
    openremap --version                → version string
    openremap <command> [args...]      → CLI command

Usage:
    openremap
    openremap --help
    openremap --version
    openremap commands
    openremap workflow
    openremap families
    openremap families --family EDC16
    openremap identify ecu.bin
    openremap cook stock.bin stage1.bin --output recipe.openremap
    openremap tune target.bin recipe.openremap
    openremap tune target.bin recipe.openremap --output target_tuned.bin
    openremap validate before target.bin recipe.openremap
    openremap validate check  target.bin recipe.openremap
    openremap validate after  target_tuned.bin recipe.openremap
    openremap scan ./my_bins/
    openremap scan ./my_bins/ --move --organize
"""

import sys
from importlib.metadata import version as _get_version
from typing import Optional

import typer

from openremap.cli.commands import validate
from openremap.cli.commands.cmds import commands
from openremap.cli.commands.cook import cook
from openremap.cli.commands.families import families
from openremap.cli.commands.identify import identify
from openremap.cli.commands.scan import scan
from openremap.cli.commands.tune import tune
from openremap.cli.commands.workflow import workflow

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="openremap",
    help=(
        "OpenRemap — ECU binary analysis and patching toolkit.\n\n"
        "Diff, validate, and apply tuning recipes to automotive ECU binaries "
        "without a running API server.\n\n"
        "New here?  Run  openremap workflow  for a plain-English step-by-step guide.\n"
        "Quick reminder?  Run  openremap commands  for a one-line-per-command cheat-sheet."
    ),
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
)

# ---------------------------------------------------------------------------
# Version flag
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"openremap {_get_version('openremap')}")
        raise typer.Exit()


@app.callback()
def _callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

# workflow, identify, cook, tune, scan, families, and commands are single-action
# commands — registered directly to avoid the Typer 0.12+ regression where
# @app.callback(invoke_without_command=True) with typer.Argument parameters
# fails when added via add_typer().

app.command(
    name="commands",
    help="Print a one-line-per-command cheat-sheet of every available command.",
)(commands)

app.command(
    name="workflow",
    help=(
        "Print a complete step-by-step workflow guide — plain English, "
        "with commands, expected output, and what to do when something goes wrong. "
        "Start here if you are new to OpenRemap or the terminal."
    ),
)(workflow)

app.command(
    name="families",
    help=(
        "List all supported ECU families with era, file size, and notes. "
        "Use --family <NAME> for full detail on a specific family."
    ),
)(families)

app.command(
    name="identify",
    help="Identify an ECU binary — manufacturer, family, software version, and more.",
    no_args_is_help=True,
)(identify)

app.command(
    name="cook",
    help="Cook a recipe by diffing an original and a modified ECU binary.",
    no_args_is_help=True,
)(cook)

# validate has real sub-commands (before / check / after) and uses
# @app.command() internally — add_typer works correctly for it.
app.add_typer(validate.app, name="validate")

app.command(
    name="tune",
    help=(
        "One-shot: validate before → apply recipe → validate after. "
        "The original file is never modified — the tuned result is written separately. "
        "Run  openremap validate check  if Phase 1 fails to diagnose why."
    ),
    no_args_is_help=True,
)(tune)

app.command(
    name="scan",
    help=(
        "Batch-scan a directory of ECU binaries through all registered extractors.\n\n"
        "Each file is classified and optionally moved into one of five sub-folders: "
        "scanned, sw_missing, contested, unknown, or trash."
    ),
)(scan)


# ---------------------------------------------------------------------------
# Smart dispatcher — bare `openremap` → TUI, anything else → CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the ``openremap`` console script.

    When invoked with no arguments the TUI is launched.  Any arguments or
    flags (``--help``, ``--version``, subcommands, etc.) are forwarded to
    the Typer CLI app as before.
    """
    if len(sys.argv) == 1:
        # No arguments at all → launch the TUI
        from openremap.tui.main import run as _run_tui

        _run_tui()
    else:
        app()


if __name__ == "__main__":
    main()
