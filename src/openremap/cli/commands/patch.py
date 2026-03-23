"""
openremap patch apply <target> <recipe> --output patched.bin

Apply a recipe to a target ECU binary.

Internally runs strict pre-flight validation before writing anything.
Uses a ctx+ob anchor search within ±2 KB of the expected offset to
tolerate minor SW revision shifts.

Examples:
    openremap patch apply target.bin recipe.json
    openremap patch apply target.bin recipe.json --output my_patched.bin
    openremap patch apply target.bin recipe.json --skip-validation
    openremap patch apply target.bin recipe.json --json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from openremap.tuning.services.patcher import ECUPatcher

app = typer.Typer(
    help="Apply a recipe to a target ECU binary.",
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALLOWED_BIN = (".bin", ".ori")


def _read_bin(path: Path, label: str) -> bytes:
    """Read and validate a binary file."""
    if path.suffix.lower() not in _ALLOWED_BIN:
        typer.echo(
            typer.style(
                f"Error: {label} file '{path.name}' must be a .bin or .ori file.",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

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


def _read_recipe(path: Path) -> dict:
    """Read and parse a recipe JSON file."""
    if path.suffix.lower() != ".json":
        typer.echo(
            typer.style(
                f"Error: Recipe file '{path.name}' must be a .json file.",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        typer.echo(
            typer.style(
                f"Error reading recipe file: {exc}", fg=typer.colors.RED, bold=True
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        typer.echo(
            typer.style(
                f"Error: Recipe file '{path.name}' is not valid JSON: {exc}",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)


def _default_output(target: Path) -> Path:
    """Derive the default output filename from the target: target.bin → target_patched.bin"""
    stem = target.stem
    suffix = target.suffix
    return target.parent / f"{stem}_patched{suffix}"


def _print_summary(report: dict, output: Path) -> None:
    """Print a human-readable patch summary to stdout."""
    summary = report.get("summary", {})
    total = summary.get("total", 0)
    applied = summary.get("success", 0)
    failed = summary.get("failed", 0)
    shifted = summary.get("shifted", 0)
    patch_applied = summary.get("patch_applied", False)
    patched_md5 = summary.get("patched_md5")

    typer.echo("")

    if patch_applied:
        typer.echo(
            typer.style(
                "  ✅ Patch applied successfully", fg=typer.colors.GREEN, bold=True
            )
        )
    else:
        typer.echo(typer.style("  ❌ Patch failed", fg=typer.colors.RED, bold=True))

    col = 22
    typer.echo("")
    typer.echo(f"  {'Target':<{col}} {report.get('target_file', '?')}")
    typer.echo(f"  {'Target MD5':<{col}} {report.get('target_md5', '?')}")
    if patched_md5:
        typer.echo(f"  {'Patched MD5':<{col}} {patched_md5}")
    typer.echo(f"  {'Instructions':<{col}} {total:,}")
    typer.echo(
        f"  {'Applied':<{col}} "
        + typer.style(
            str(applied),
            fg=typer.colors.GREEN if applied == total else typer.colors.WHITE,
        )
    )
    if shifted:
        typer.echo(
            f"  {'Applied (shifted)':<{col}} "
            + typer.style(str(shifted), fg=typer.colors.YELLOW, bold=True)
        )
    if failed:
        typer.echo(
            f"  {'Failed':<{col}} "
            + typer.style(str(failed), fg=typer.colors.RED, bold=True)
        )

    # Print any failed instruction details
    failed_results = [
        r for r in report.get("results", []) if r.get("status") == "failed"
    ]
    if failed_results:
        typer.echo("")
        typer.echo(
            typer.style("  Failed instructions:", fg=typer.colors.RED, bold=True)
        )
        for r in failed_results:
            typer.echo(
                f"    #{r.get('index', '?'):>4}  "
                f"offset {r.get('offset_expected_hex', '?')}  "
                f"— {r.get('message', 'unknown error')}"
            )

    typer.echo("")

    if patch_applied:
        typer.echo(
            f"  Patched binary saved to "
            f"{typer.style(str(output), fg=typer.colors.CYAN, bold=True)}"
        )
        typer.echo(
            typer.style(
                "\n  ⚠  Always verify checksums with ECM Titanium, WinOLS, or a similar\n"
                "     tool before flashing the patched binary to a vehicle.",
                fg=typer.colors.YELLOW,
            )
        )

    typer.echo("")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def apply(
    target: Path = typer.Argument(
        ...,
        help="The unpatched ECU binary to patch (.bin or .ori).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    recipe: Path = typer.Argument(
        ...,
        help="The recipe .json file to apply.",
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
            "Path to write the patched binary. "
            "Defaults to <target_stem>_patched<ext> in the same directory as the target."
        ),
        writable=True,
        resolve_path=True,
    ),
    skip_validation: bool = typer.Option(
        False,
        "--skip-validation",
        help=(
            "Skip strict pre-flight validation and apply the recipe directly. "
            "Use with caution — only if you have already run 'validate strict'."
        ),
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Print the full patch report as JSON instead of a human-readable summary.",
    ),
    report_output: Optional[Path] = typer.Option(
        None,
        "--report",
        "-r",
        help="Save the patch report as a JSON file.",
        resolve_path=True,
    ),
) -> None:
    """
    Apply a recipe to a target ECU binary.

    Runs strict pre-flight validation before writing anything (unless
    --skip-validation is passed). Uses a ctx+ob anchor search within
    ±2 KB of the expected offset to tolerate minor SW revision shifts.

    On success, writes the patched binary and prints a patch summary.
    On failure, exits with code 1 and prints which instructions failed.

    \b
    Remember: always verify checksums with ECM Titanium, WinOLS, or a
    similar tool before flashing the patched binary to a vehicle.
    """
    target_data = _read_bin(target, "Target")
    recipe_dict = _read_recipe(recipe)

    resolved_output = output or _default_output(target)

    typer.echo(
        f"\n  Patching "
        f"{typer.style(target.name, fg=typer.colors.CYAN)} "
        f"with "
        f"{typer.style(recipe.name, fg=typer.colors.CYAN)} …"
    )

    if skip_validation:
        typer.echo(
            typer.style(
                "  ⚠  Pre-flight validation skipped (--skip-validation).",
                fg=typer.colors.YELLOW,
            )
        )

    try:
        patcher = ECUPatcher(
            target_data=target_data,
            recipe=recipe_dict,
            target_name=target.name,
            recipe_name=recipe.name,
            skip_validation=skip_validation,
        )
        patched_bytes = patcher.apply_all()
    except ValueError as exc:
        # Raised by the patcher when strict validation fails before any writes
        typer.echo(
            typer.style(
                f"\n  ❌ Patch rejected during pre-flight validation:\n\n  {exc}",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)
    except Exception as exc:
        typer.echo(
            typer.style(
                f"\n  Error: patch failed unexpectedly — {exc}",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    report = patcher.to_dict(patched_data=patched_bytes)
    patch_applied = report.get("summary", {}).get("patch_applied", False)

    # --- Write patched binary ---
    if patch_applied:
        try:
            resolved_output.parent.mkdir(parents=True, exist_ok=True)
            resolved_output.write_bytes(patched_bytes)
        except OSError as exc:
            typer.echo(
                typer.style(
                    f"\n  Error: could not write patched binary to '{resolved_output}': {exc}",
                    fg=typer.colors.RED,
                    bold=True,
                ),
                err=True,
            )
            raise typer.Exit(code=1)

    # --- Write report file if requested ---
    if report_output:
        try:
            report_output.parent.mkdir(parents=True, exist_ok=True)
            report_output.write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as exc:
            typer.echo(
                typer.style(
                    f"Warning: could not write report to '{report_output}': {exc}",
                    fg=typer.colors.YELLOW,
                ),
                err=True,
            )

    # --- Output ---
    if as_json:
        typer.echo(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _print_summary(report, resolved_output)

    if not patch_applied:
        raise typer.Exit(code=1)
