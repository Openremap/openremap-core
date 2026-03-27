"""
openremap commands

Print a compact cheat-sheet of every available command — one line per command,
syntax + one-sentence description.  Designed for returning users who know the
workflow and just need a quick reminder.

Examples:
    openremap commands
"""

from __future__ import annotations

import typer

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

_W = 73  # separator width


def _sep() -> None:
    typer.echo(typer.style("  " + "─" * _W, dim=True))


def _blank() -> None:
    typer.echo("")


# ---------------------------------------------------------------------------
# Command table
# ---------------------------------------------------------------------------

# Each entry: (syntax, description)
# syntax is printed in bold green; description in normal white.
_COMMANDS: list[tuple[str, str]] = [
    (
        "openremap commands",
        "This cheat-sheet — all commands at a glance.",
    ),
    (
        "openremap workflow",
        "Full step-by-step guide with explanations. Start here if you are new.",
    ),
    (
        "openremap families",
        "List every supported ECU family with era, size, and vehicle notes.",
    ),
    (
        "openremap families --family <NAME>",
        "Detailed view for one family (e.g. --family EDC16).",
    ),
    (
        "openremap scan <DIR>",
        "Classify a folder of ECU binaries — preview mode, nothing moves.",
    ),
    (
        "openremap scan <DIR> --move --organize",
        "Sort classified binaries into Bosch/EDC17/ sub-folders.",
    ),
    (
        "openremap scan <DIR> --report report.json",
        "Write a full scan report (JSON or CSV) alongside the classification.",
    ),
    (
        "openremap identify <FILE>",
        "Read an ECU binary and print manufacturer, family, SW, HW, confidence.",
    ),
    (
        "openremap identify <FILE> --json",
        "Same as above but output raw JSON — useful for scripting.",
    ),
    (
        "openremap cook <STOCK> <TUNED> --output recipe.json",
        "Diff two binaries and save every changed byte block as a recipe.",
    ),
    (
        "openremap tune <TARGET> <RECIPE>",
        "One-shot: validate → apply → verify. Writes <target>_tuned<ext>.",
    ),
    (
        "openremap tune <TARGET> <RECIPE> --output <OUT>",
        "Same, with an explicit output path.",
    ),
    (
        "openremap tune <TARGET> <RECIPE> --report report.json",
        "Save the full three-phase tune report as JSON.",
    ),
    (
        "openremap validate before <TARGET> <RECIPE>",
        "Pre-flight check — are the original bytes at every expected offset?",
    ),
    (
        "openremap validate check  <TARGET> <RECIPE>",
        "Diagnostic — why did 'validate before' fail? (searches whole binary)",
    ),
    (
        "openremap validate after  <TUNED>  <RECIPE>",
        "Post-tune confirmation — are the new bytes written correctly?",
    ),
]

# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


def commands() -> None:
    """
    Print a one-line-per-command cheat-sheet of every openremap command.

    Use this as a quick reminder when you already know the workflow.
    Run  openremap workflow  for a full plain-English walkthrough.
    Run  openremap <command> --help  for complete options on any single command.
    """
    _blank()
    typer.echo(typer.style("  OpenRemap — Command Reference", bold=True))
    _sep()
    _body = (
        "  Run  openremap <command> --help  for full options on any command.\n"
        "  Run  openremap workflow           for the complete step-by-step guide."
    )
    typer.echo(_body)
    _sep()
    _blank()

    # Calculate column width from the longest syntax string
    max_syn = max(len(syn) for syn, _ in _COMMANDS)
    col = max_syn + 3  # padding

    for syntax, description in _COMMANDS:
        # Blank line before section breaks (detect by indented vs top-level)
        syn_styled = typer.style(syntax, fg=typer.colors.GREEN, bold=True)
        desc_styled = typer.style(description, dim=True)
        # Right-pad the syntax so descriptions align
        pad = col - len(syntax)
        typer.echo(f"  {syn_styled}{' ' * pad}{desc_styled}")

    _blank()
    _sep()
    typer.echo(
        "  "
        + typer.style("Tip: ", bold=True)
        + "new user? Run  "
        + typer.style("openremap workflow", fg=typer.colors.GREEN, bold=True)
        + "  — it walks you through every step."
    )
    _sep()
    _blank()
