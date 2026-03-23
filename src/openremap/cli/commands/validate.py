"""
openremap validate strict  <target> <recipe>
openremap validate exists  <target> <recipe>
openremap validate patched <patched> <recipe>

Validate ECU binaries against a recipe before or after patching.

Examples:
    openremap validate strict  target.bin recipe.json
    openremap validate exists  target.bin recipe.json
    openremap validate patched patched.bin recipe.json
    openremap validate strict  target.bin recipe.json --json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from openremap.tuning.services.validate_exists import ECUExistenceValidator, MatchStatus
from openremap.tuning.services.validate_patched import ECUPatchedValidator
from openremap.tuning.services.validate_strict import ECUStrictValidator

app = typer.Typer(
    help=(
        "Validate a binary against a recipe.\n\n"
        "  strict   — verify ob bytes are at every recorded offset (run before patching)\n"
        "  exists   — search the entire binary for ob bytes (diagnose a strict failure)\n"
        "  patched  — confirm mb bytes were written correctly (run after patching)"
    ),
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# Shared helpers
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
    if not path.suffix.lower() == ".json":
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


def _write_json(data: dict, output: Optional[Path], pretty: bool) -> None:
    """Serialise a dict to JSON and write it to a file or stdout."""
    content = json.dumps(data, indent=2 if pretty else None, ensure_ascii=False)
    if output:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
            typer.echo(
                f"\n  Report saved to {typer.style(str(output), fg=typer.colors.CYAN, bold=True)}\n"
            )
        except OSError as exc:
            typer.echo(
                typer.style(
                    f"Error writing output file: {exc}", fg=typer.colors.RED, bold=True
                ),
                err=True,
            )
            raise typer.Exit(code=1)
    else:
        typer.echo(content)


def _warn_line(size_warn: str | None, match_key_warn: str | None) -> None:
    """Print warning lines if any mismatches were detected."""
    if size_warn:
        typer.echo(
            typer.style(f"  ⚠  Size mismatch: {size_warn}", fg=typer.colors.YELLOW),
        )
    if match_key_warn:
        typer.echo(
            typer.style(
                f"  ⚠  Match key mismatch: {match_key_warn}", fg=typer.colors.YELLOW
            ),
        )


# ---------------------------------------------------------------------------
# strict
# ---------------------------------------------------------------------------


@app.command()
def strict(
    target: Path = typer.Argument(
        ...,
        help="The unpatched ECU binary to validate (.bin or .ori).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    recipe: Path = typer.Argument(
        ...,
        help="The recipe .json file to validate against.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Output the full validation report as JSON.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save the report to a file instead of printing to stdout.",
        resolve_path=True,
    ),
) -> None:
    """
    Strict offset validation — verify ob bytes are at every recorded offset.

    Reads the exact offset of every recipe instruction and compares the original
    bytes (ob) against what is actually present in the binary. All instructions
    are checked before reporting.

    Run this before applying a patch. A result of safe_to_patch=true means
    every instruction matched and it is safe to call 'patch apply'.
    """
    target_data = _read_bin(target, "Target")
    recipe_dict = _read_recipe(recipe)

    typer.echo(
        f"\n  Validating "
        f"{typer.style(target.name, fg=typer.colors.CYAN)} "
        f"against "
        f"{typer.style(recipe.name, fg=typer.colors.CYAN)} …"
    )

    try:
        validator = ECUStrictValidator(
            target_data=target_data,
            recipe=recipe_dict,
            target_name=target.name,
            recipe_name=recipe.name,
        )
        size_warn = validator.check_file_size()
        match_key_warn = validator.check_match_key()
        validator.validate_all()
        report = validator.to_dict()
    except Exception as exc:
        typer.echo(
            typer.style(
                f"\n  Error: strict validation failed — {exc}",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    if as_json or output:
        _write_json(report, output, pretty=True)
        return

    # --- Human-readable output ---
    summary = report["summary"]
    safe = summary.get("safe_to_patch", False)
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    total = summary.get("total", 0)

    typer.echo("")
    _warn_line(size_warn, match_key_warn)

    if safe:
        typer.echo(typer.style("  ✅ Safe to patch", fg=typer.colors.GREEN, bold=True))
    else:
        typer.echo(
            typer.style("  ❌ NOT safe to patch", fg=typer.colors.RED, bold=True)
        )

    col = 20
    typer.echo("")
    typer.echo(f"  {'Target':<{col}} {report['target_file']}")
    typer.echo(f"  {'MD5':<{col}} {report['target_md5']}")
    typer.echo(f"  {'Instructions':<{col}} {total:,}")
    typer.echo(
        f"  {'Passed':<{col}} "
        + typer.style(
            str(passed),
            fg=typer.colors.GREEN if passed == total else typer.colors.WHITE,
        )
    )
    if failed:
        typer.echo(
            f"  {'Failed':<{col}} "
            + typer.style(str(failed), fg=typer.colors.RED, bold=True)
        )
    typer.echo("")

    if failed:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# exists
# ---------------------------------------------------------------------------


@app.command()
def exists(
    target: Path = typer.Argument(
        ...,
        help="The target ECU binary to search (.bin or .ori).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    recipe: Path = typer.Argument(
        ...,
        help="The recipe .json file to validate against.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Output the full validation report as JSON.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save the report to a file instead of printing to stdout.",
        resolve_path=True,
    ),
) -> None:
    """
    Existence validation — search the entire binary for ob bytes.

    Scans the whole binary for the original bytes (ob) of every instruction
    and classifies each as EXACT, SHIFTED, or MISSING.

    Run this after a strict validation failure to understand why it failed:
    SHIFTED means a SW revision moved the map — the patch may still be recoverable.
    MISSING means the ob bytes are nowhere in the binary — this is the wrong ECU.
    """
    target_data = _read_bin(target, "Target")
    recipe_dict = _read_recipe(recipe)

    typer.echo(
        f"\n  Searching "
        f"{typer.style(target.name, fg=typer.colors.CYAN)} "
        f"for all recipe instructions …"
    )

    try:
        validator = ECUExistenceValidator(
            target_data=target_data,
            recipe=recipe_dict,
            target_name=target.name,
            recipe_name=recipe.name,
        )
        size_warn = validator.check_file_size()
        match_key_warn = validator.check_match_key()
        validator.validate_all()
        report = validator.to_dict()
    except Exception as exc:
        typer.echo(
            typer.style(
                f"\n  Error: existence validation failed — {exc}",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    if as_json or output:
        _write_json(report, output, pretty=True)
        return

    # --- Human-readable output ---
    summary = report["summary"]
    verdict = summary.get("verdict", "unknown")
    total = summary.get("total", 0)
    exact = summary.get("exact", 0)
    shifted = summary.get("shifted", 0)
    missing = summary.get("missing", 0)

    typer.echo("")
    _warn_line(size_warn, match_key_warn)

    verdict_colour = {
        "safe_exact": typer.colors.GREEN,
        "shifted_recoverable": typer.colors.YELLOW,
        "missing_unrecoverable": typer.colors.RED,
    }.get(verdict, typer.colors.WHITE)

    typer.echo(
        f"  Verdict: "
        + typer.style(verdict.replace("_", " ").upper(), fg=verdict_colour, bold=True)
    )

    col = 20
    typer.echo("")
    typer.echo(f"  {'Target':<{col}} {report['target_file']}")
    typer.echo(f"  {'MD5':<{col}} {report['target_md5']}")
    typer.echo(f"  {'Instructions':<{col}} {total:,}")
    typer.echo(
        f"  {'Exact':<{col}} "
        + typer.style(
            str(exact), fg=typer.colors.GREEN if exact else typer.colors.WHITE
        )
    )
    if shifted:
        typer.echo(
            f"  {'Shifted':<{col}} "
            + typer.style(str(shifted), fg=typer.colors.YELLOW, bold=True)
        )
    if missing:
        typer.echo(
            f"  {'Missing':<{col}} "
            + typer.style(str(missing), fg=typer.colors.RED, bold=True)
        )
    typer.echo("")

    # Print shifted detail
    shifted_results = [
        r
        for r in report.get("results", [])
        if r.get("status") == MatchStatus.SHIFTED.value
    ]
    if shifted_results:
        typer.echo(
            typer.style("  Shifted instructions:", fg=typer.colors.YELLOW, bold=True)
        )
        for r in shifted_results:
            shift_val = r.get("shift", 0)
            direction = f"+{shift_val}" if shift_val >= 0 else str(shift_val)
            typer.echo(
                f"    #{r['instruction_index']:>4}  "
                f"expected {r['offset_hex_expected']}  "
                f"→  found at shift {direction}"
            )
        typer.echo("")

    # Print missing detail
    missing_results = [
        r
        for r in report.get("results", [])
        if r.get("status") == MatchStatus.MISSING.value
    ]
    if missing_results:
        typer.echo(
            typer.style("  Missing instructions:", fg=typer.colors.RED, bold=True)
        )
        for r in missing_results:
            typer.echo(
                f"    #{r['instruction_index']:>4}  "
                f"expected {r['offset_hex_expected']}  "
                f"size {r['size']} bytes  — not found anywhere"
            )
        typer.echo("")

    if verdict == "missing_unrecoverable":
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# patched
# ---------------------------------------------------------------------------


@app.command()
def patched(
    patched_file: Path = typer.Argument(
        ...,
        help="The patched ECU binary to verify (.bin or .ori).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        metavar="PATCHED",
    ),
    recipe: Path = typer.Argument(
        ...,
        help="The recipe .json file used during patching.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Output the full verification report as JSON.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save the report to a file instead of printing to stdout.",
        resolve_path=True,
    ),
) -> None:
    """
    Post-patch verification — confirm mb bytes were written correctly.

    Reads the exact offset of every instruction in a patched binary and
    confirms that the modified bytes (mb) are now present there.

    This is the mirror image of 'validate strict': strict checks ob bytes
    before patching; this command checks mb bytes after patching.

    Returns patch_confirmed=true only when every instruction passes.
    """
    patched_data = _read_bin(patched_file, "Patched")
    recipe_dict = _read_recipe(recipe)

    typer.echo(
        f"\n  Verifying "
        f"{typer.style(patched_file.name, fg=typer.colors.CYAN)} "
        f"against "
        f"{typer.style(recipe.name, fg=typer.colors.CYAN)} …"
    )

    try:
        validator = ECUPatchedValidator(
            patched_data=patched_data,
            recipe=recipe_dict,
            patched_name=patched_file.name,
            recipe_name=recipe.name,
        )
        size_warn = validator.check_file_size()
        match_key_warn = validator.check_match_key()
        validator.verify_all()
        report = validator.to_dict()
    except Exception as exc:
        typer.echo(
            typer.style(
                f"\n  Error: post-patch verification failed — {exc}",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    if as_json or output:
        _write_json(report, output, pretty=True)
        return

    # --- Human-readable output ---
    summary = report["summary"]
    confirmed = summary.get("patch_confirmed", False)
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    total = summary.get("total", 0)

    typer.echo("")
    _warn_line(size_warn, match_key_warn)

    if confirmed:
        typer.echo(
            typer.style(
                "  ✅ Patch confirmed — all mb bytes verified",
                fg=typer.colors.GREEN,
                bold=True,
            )
        )
    else:
        typer.echo(
            typer.style(
                "  ❌ Patch NOT confirmed — some instructions failed",
                fg=typer.colors.RED,
                bold=True,
            )
        )

    col = 20
    typer.echo("")
    typer.echo(f"  {'Patched File':<{col}} {report['patched_file']}")
    typer.echo(f"  {'MD5':<{col}} {report['patched_md5']}")
    typer.echo(f"  {'Instructions':<{col}} {total:,}")
    typer.echo(
        f"  {'Confirmed':<{col}} "
        + typer.style(
            str(passed),
            fg=typer.colors.GREEN if passed == total else typer.colors.WHITE,
        )
    )
    if failed:
        typer.echo(
            f"  {'Failed':<{col}} "
            + typer.style(str(failed), fg=typer.colors.RED, bold=True)
        )

    # Print failure details
    failures = [r for r in report.get("all_results", []) if not r.get("passed")]
    if failures:
        typer.echo("")
        typer.echo(
            typer.style("  Failed instructions:", fg=typer.colors.RED, bold=True)
        )
        for r in failures:
            typer.echo(
                f"    #{r['instruction_index']:>4}  "
                f"offset 0x{r['offset_hex']}  "
                f"size {r['size']} bytes  — {r['reason']}"
            )

    typer.echo("")

    if not confirmed:
        raise typer.Exit(code=1)
