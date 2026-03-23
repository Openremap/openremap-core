"""
openremap identify <file>

Identify a single ECU binary and print its metadata.

Examples:
    openremap identify ecu.bin
    openremap identify ecu.bin --json
    openremap identify ecu.bin --json --output result.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from openremap.tuning.services.identifier import identify_ecu

app = typer.Typer(
    help="Identify an ECU binary — manufacturer, family, software version, and more.",
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LABELS: list[tuple[str, str]] = [
    ("manufacturer", "Manufacturer"),
    ("ecu_family", "ECU Family"),
    ("ecu_variant", "ECU Variant"),
    ("software_version", "Software Version"),
    ("hardware_number", "Hardware Number"),
    ("calibration_id", "Calibration ID"),
    ("match_key", "Match Key"),
    ("file_size", "File Size"),
    ("sha256", "SHA-256"),
]


def _format_table(result: dict) -> str:
    """Render the identity dict as a two-column aligned table."""
    rows: list[tuple[str, str]] = []
    for key, label in _LABELS:
        value = result.get(key)
        if key == "file_size" and value is not None:
            display = f"{value:,} bytes"
        elif value is None:
            display = typer.style("unknown", fg=typer.colors.YELLOW)
        else:
            display = str(value)
        rows.append((label, display))

    col_width = max(len(label) for label, _ in rows)
    lines = []
    for label, value in rows:
        lines.append(f"  {label:<{col_width}}  {value}")
    return "\n".join(lines)


def _write_output(content: str, output: Optional[Path]) -> None:
    """Write content to a file or stdout."""
    if output:
        output.write_text(content, encoding="utf-8")
        typer.echo(f"Saved to {output}")
    else:
        typer.echo(content)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def identify(
    file: Path = typer.Argument(
        ...,
        help="ECU binary file to identify (.bin or .ori).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Output result as JSON instead of a human-readable table.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save the result to a file instead of printing to stdout.",
        writable=True,
        resolve_path=True,
    ),
) -> None:
    """
    Identify a single ECU binary.

    Prints manufacturer, ECU family, software version, hardware number,
    calibration ID, match key, file size, and SHA-256 hash.
    """
    suffix = file.suffix.lower()
    if suffix not in (".bin", ".ori"):
        typer.echo(
            typer.style(
                f"Error: '{file.name}' is not a .bin or .ori file.",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        data = file.read_bytes()
    except OSError as exc:
        typer.echo(
            typer.style(f"Error reading file: {exc}", fg=typer.colors.RED, bold=True),
            err=True,
        )
        raise typer.Exit(code=1)

    if not data:
        typer.echo(
            typer.style(
                f"Error: '{file.name}' is empty.", fg=typer.colors.RED, bold=True
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        result = identify_ecu(data=data, filename=file.name)
    except Exception as exc:
        typer.echo(
            typer.style(
                f"Identification failed: {exc}", fg=typer.colors.RED, bold=True
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    if as_json:
        content = json.dumps(result, indent=2)
        _write_output(content, output)
        return

    # --- Table output ---
    header = typer.style(f"\n  {file.name}", fg=typer.colors.CYAN, bold=True)

    identified = result.get("ecu_family") is not None
    status_colour = typer.colors.GREEN if identified else typer.colors.YELLOW
    status_label = (
        f"{result['manufacturer']} · {result['ecu_family']}"
        if identified
        else "Unknown ECU — no extractor matched this binary"
    )
    status_line = "  " + typer.style(status_label, fg=status_colour, bold=True)

    table = _format_table(result)

    full_output = f"{header}\n{status_line}\n\n{table}\n"

    if output:
        # Strip ANSI codes when writing to a file
        import re

        plain = re.sub(r"\x1b\[[0-9;]*m", "", full_output)
        output.write_text(plain, encoding="utf-8")
        typer.echo(f"Saved to {output}")
    else:
        typer.echo(full_output)
