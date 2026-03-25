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
import re
from pathlib import Path
from typing import Optional

import typer

from openremap.tuning.services.confidence import ConfidenceResult, score_identity
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

_TIER_COLOURS: dict[str, str] = {
    "High": typer.colors.GREEN,
    "Medium": typer.colors.YELLOW,
    "Low": typer.colors.MAGENTA,
    "Suspicious": typer.colors.RED,
    "Unknown": typer.colors.CYAN,
}


def _format_confidence_inline(confidence: ConfidenceResult) -> str:
    """Render the confidence result as a compact coloured string for the table."""
    colour = _TIER_COLOURS.get(confidence.tier, typer.colors.WHITE)
    tier_str = typer.style(confidence.tier.upper(), fg=colour, bold=True)
    summary = confidence.rationale_summary(max_signals=3)
    summary_str = typer.style(f"  {summary}", dim=True) if summary else ""
    return f"{tier_str}{summary_str}"


def _format_confidence_warnings(
    confidence: ConfidenceResult, indent: str = "  "
) -> str:
    """Return a formatted warnings block, or an empty string when there are none."""
    if not confidence.warnings:
        return ""
    lines = []
    for w in confidence.warnings:
        lines.append(indent + typer.style("⚠  " + w, fg=typer.colors.RED, bold=True))
    return "\n".join(lines)


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
    calibration ID, match key, file size, SHA-256 hash, and a confidence
    assessment of how likely the binary is to be an unmodified factory file.
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

    confidence = score_identity(result, filename=file.name)

    if as_json:
        json_out = dict(result)
        json_out["confidence"] = {
            "score": confidence.score,
            "tier": confidence.tier,
            "signals": [
                {"delta": s.delta, "label": s.label} for s in confidence.signals
            ],
            "warnings": confidence.warnings,
        }
        content = json.dumps(json_out, indent=2)
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

    # --- Confidence section ---
    conf_colour = _TIER_COLOURS.get(confidence.tier, typer.colors.WHITE)
    conf_header = typer.style(
        f"\n  ── Confidence " + "─" * 37,
        bold=True,
    )
    conf_tier_line = (
        "  "
        + typer.style("Tier   ", dim=True)
        + typer.style(confidence.tier.upper(), fg=conf_colour, bold=True)
    )

    conf_signals_lines = []
    for sig in confidence.signals:
        colour = typer.colors.GREEN if sig.delta >= 0 else typer.colors.RED
        marker = (
            typer.style("+", fg=colour, bold=True)
            if sig.delta >= 0
            else typer.style("-", fg=colour, bold=True)
        )
        conf_signals_lines.append(
            f"  {typer.style('Signal ', dim=True)} {marker}  {sig.label}"
        )

    conf_signals = "\n".join(conf_signals_lines)

    warnings_block = _format_confidence_warnings(confidence, indent="  ")
    warnings_section = f"\n{warnings_block}" if warnings_block else ""

    confidence_section = (
        f"{conf_header}\n{conf_tier_line}\n{conf_signals}{warnings_section}"
    )

    full_output = f"{header}\n{status_line}\n\n{table}\n{confidence_section}\n"

    if output:
        plain = re.sub(r"\x1b\[[0-9;]*m", "", full_output)
        output.write_text(plain, encoding="utf-8")
        typer.echo(f"Saved to {output}")
    else:
        typer.echo(full_output)
