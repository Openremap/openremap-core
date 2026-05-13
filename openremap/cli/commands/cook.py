"""
openremap cook <original> <modified> --output recipe.openremap

Cook a recipe by diffing an original and a modified ECU binary.

Examples:
    openremap cook stock.bin stage1.bin --output recipe.openremap
    openremap cook stock.bin stage1.bin --output recipe.openremap --pretty
    openremap cook stock.bin stage1.bin --context-size 64 --output recipe.openremap
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from openremap.core.services.recipe_builder import ECUDiffAnalyzer

app = typer.Typer(
    help="Cook a recipe by diffing an original and a modified ECU binary.",
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALLOWED = (".bin", ".ori")


def _check_bin(path: Path, label: str) -> None:
    """Validate that a path points to an allowed, non-empty binary file."""
    if path.suffix.lower() not in _ALLOWED:
        typer.echo(
            typer.style(
                f"Error: {label} file '{path.name}' must be a .bin or .ori file.",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)


def _read_bin(path: Path, label: str) -> bytes:
    """Read binary file contents with user-friendly error handling."""
    _check_bin(path, label)
    try:
        data = path.read_bytes()
    except OSError as exc:
        typer.echo(
            typer.style(
                f"Error reading {label} file: {exc}", fg=typer.colors.RED, bold=True
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    if not data:
        typer.echo(
            typer.style(
                f"Error: {label} file '{path.name}' is empty.",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    return data


def _print_summary(recipe: dict, output: Optional[Path]) -> None:
    """Print a compact summary of the produced recipe to stdout."""
    ecu = recipe.get("ecu", {})
    stats = recipe.get("statistics", {})
    meta = recipe.get("metadata", {})

    family = ecu.get("ecu_family") or "Unknown"
    manufacturer = ecu.get("manufacturer") or "Unknown"
    match_key = ecu.get("match_key") or "n/a"
    total_changes = stats.get("total_changes", 0)
    total_bytes = stats.get("total_bytes_changed", 0)
    fmt_version = meta.get("format_version", "?")

    typer.echo("")
    typer.echo(
        typer.style("  ✅ Recipe built successfully", fg=typer.colors.GREEN, bold=True)
    )
    typer.echo("")

    col = 22
    rows = [
        ("ECU", f"{manufacturer} · {family}"),
        ("Match Key", match_key),
        ("Format Version", fmt_version),
        ("Instructions", f"{total_changes:,}"),
        ("Bytes Changed", f"{total_bytes:,}"),
        ("Original", meta.get("original_file", "?")),
        ("Modified", meta.get("modified_file", "?")),
    ]

    # --- Flagged instructions ---
    flagged = sum(1 for inst in recipe.get("instructions", []) if inst.get("flags"))
    if flagged:
        rows.append(("⚠ Flagged", f"{flagged:,} instruction(s) need review"))

    # --- Trust level ---
    creator = recipe.get("creator", {})
    trust = creator.get("trust_level", "UNSIGNED")
    rows.append(("Trust Level", trust))

    for label, value in rows:
        typer.echo(f"  {label:<{col}} {value}")

    typer.echo("")
    if output:
        typer.echo(
            f"  Recipe saved to {typer.style(str(output), fg=typer.colors.CYAN, bold=True)}"
        )
    typer.echo("")


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def cook(
    original: Path = typer.Argument(
        ...,
        help="The unmodified (stock) ECU binary (.bin or .ori).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    modified: Path = typer.Argument(
        ...,
        help="The tuned ECU binary (.bin or .ori).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "File path to write the recipe to (use .openremap extension). "
            "If omitted, the recipe is printed to stdout."
        ),
        writable=True,
        resolve_path=True,
    ),
    context_size: int = typer.Option(
        32,
        "--context-size",
        "-c",
        help="Number of bytes of context to capture before each changed block (default: 32).",
        min=8,
        max=128,
    ),
    pretty: bool = typer.Option(
        True,
        "--pretty/--compact",
        help="Pretty-print JSON output with indentation (default: pretty).",
    ),
) -> None:
    """
    Cook a recipe by diffing an original and a modified ECU binary.

    The recipe captures every changed byte block along with its offset,
    original bytes (ob), modified bytes (mb), and a context anchor (ctx)
    used during patching. The ECU identity block is derived automatically
    from the original binary.

    Save the output recipe — it is the input for all validate and patch commands.
    """
    original_data = _read_bin(original, "Original")
    modified_data = _read_bin(modified, "Modified")

    typer.echo(
        f"\n  Cooking recipe from "
        f"{typer.style(original.name, fg=typer.colors.CYAN)} vs "
        f"{typer.style(modified.name, fg=typer.colors.CYAN)} …"
    )

    try:
        analyzer = ECUDiffAnalyzer(
            original_data=original_data,
            modified_data=modified_data,
            original_filename=original.name,
            modified_filename=modified.name,
            context_size=context_size,
        )
        recipe = analyzer.build_recipe()
    except ValueError as exc:
        # Includes size-mismatch hard error from the pre-cook guard
        typer.echo(
            typer.style(
                f"\n  Error: cook failed — {exc}", fg=typer.colors.RED, bold=True
            ),
            err=True,
        )
        raise typer.Exit(code=1)
    except Exception as exc:
        typer.echo(
            typer.style(
                f"\n  Error: cook failed — {exc}", fg=typer.colors.RED, bold=True
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    # Surface any non-fatal warnings produced during recipe building
    # (e.g. ECU identity mismatch between original and modified).
    for warning in analyzer.cook_warnings():
        typer.echo(
            typer.style(
                f"\n  ⚠  Warning: {warning}",
                fg=typer.colors.YELLOW,
                bold=True,
            ),
            err=True,
        )

    # Surface flagged instructions (VIN, checksum suspects, etc.)
    flagged_instructions = [
        inst for inst in recipe.get("instructions", []) if inst.get("flags")
    ]
    if flagged_instructions:
        typer.echo(
            typer.style(
                f"\n  ⚠  {len(flagged_instructions)} instruction(s) flagged for review:",
                fg=typer.colors.YELLOW,
                bold=True,
            ),
            err=True,
        )
        for inst in flagged_instructions:
            offset_hex = inst.get("offset_hex", f"{inst['offset']:X}")
            for flag in inst.get("flags", []):
                typer.echo(
                    typer.style(
                        f"     0x{offset_hex} — {flag['kind']} ({flag['confidence']}): {flag['reason']}",
                        fg=typer.colors.YELLOW,
                    ),
                    err=True,
                )

    indent = 2 if pretty else None
    json_content = json.dumps(recipe, indent=indent, ensure_ascii=False)

    if output:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json_content, encoding="utf-8")
        except OSError as exc:
            typer.echo(
                typer.style(
                    f"\n  Error: could not write recipe to '{output}': {exc}",
                    fg=typer.colors.RED,
                    bold=True,
                ),
                err=True,
            )
            raise typer.Exit(code=1)
    else:
        typer.echo(json_content)

    _print_summary(recipe, output)
