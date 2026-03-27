"""
openremap validate before  <target> <recipe>
openremap validate check   <target> <recipe>
openremap validate after   <tuned>  <recipe>

Validate ECU binaries against a recipe before or after tuning.

Examples:
    openremap validate before target.bin recipe.json
    openremap validate check  target.bin recipe.json
    openremap validate after  target_tuned.bin recipe.json
    openremap validate before target.bin recipe.json --json

Deprecated aliases (still work, hidden from --help):
    openremap validate strict  →  openremap validate before
    openremap validate exists  →  openremap validate check
    openremap validate tuned   →  openremap validate after
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
        "  before  — verify ob bytes are at every recorded offset (run before tuning)\n"
        "  check   — search the entire binary for ob bytes (diagnose a before failure)\n"
        "  after   — confirm mb bytes were written correctly (run after tuning)"
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
# Core implementation functions (shared between primary and alias commands)
# ---------------------------------------------------------------------------


def _run_before(
    target: Path,
    recipe: Path,
    as_json: bool,
    output: Optional[Path],
) -> None:
    """Core logic for 'validate before' (pre-flight strict check)."""
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
                f"\n  Error: pre-flight validation failed — {exc}",
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
        typer.echo(typer.style("  ✅ Safe to tune", fg=typer.colors.GREEN, bold=True))
    else:
        typer.echo(typer.style("  ❌ NOT safe to tune", fg=typer.colors.RED, bold=True))

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

        failed_results = [
            r for r in report.get("results", []) if not r.get("passed", True)
        ]
        if failed_results:
            typer.echo("")
            typer.echo(
                typer.style("  Failed instructions:", fg=typer.colors.RED, bold=True)
            )
            for r in failed_results[:10]:
                typer.echo(
                    f"    #{r.get('index', r.get('instruction_index', '?')):>4}  "
                    f"offset {r.get('offset_expected_hex', r.get('offset', '?'))}  "
                    f"— {r.get('message', r.get('reason', 'ob not found at offset'))}"
                )
            if len(failed_results) > 10:
                typer.echo(
                    typer.style(
                        f"    … and {len(failed_results) - 10} more. "
                        "Use --json for the full report.",
                        dim=True,
                    )
                )

        typer.echo("")
        typer.echo(
            typer.style(
                "  Tip: run  openremap validate check  to find out why.",
                dim=True,
            )
        )

    typer.echo("")

    if failed:
        raise typer.Exit(code=1)


def _run_check(
    target: Path,
    recipe: Path,
    as_json: bool,
    output: Optional[Path],
) -> None:
    """Core logic for 'validate check' (whole-binary existence scan)."""
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
                f"\n  Error: existence check failed — {exc}",
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


def _run_after(
    patched_file: Path,
    recipe: Path,
    as_json: bool,
    output: Optional[Path],
) -> None:
    """Core logic for 'validate after' (post-tune byte confirmation)."""
    patched_data = _read_bin(patched_file, "Tuned")
    recipe_dict = _read_recipe(recipe)

    typer.echo(
        f"\n  Verifying tuned binary "
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
                f"\n  Error: post-tune verification failed — {exc}",
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
                "  ✅ Tune confirmed — all mb bytes verified",
                fg=typer.colors.GREEN,
                bold=True,
            )
        )
    else:
        typer.echo(
            typer.style(
                "  ❌ Tune NOT confirmed — some instructions failed",
                fg=typer.colors.RED,
                bold=True,
            )
        )

    col = 20
    typer.echo("")
    typer.echo(f"  {'Tuned File':<{col}} {report['patched_file']}")
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


# ---------------------------------------------------------------------------
# Primary commands
# ---------------------------------------------------------------------------


@app.command(name="before")
def before(
    target: Path = typer.Argument(
        ...,
        help="The untuned ECU binary to validate (.bin or .ori).",
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
    Pre-flight check — verify ob bytes are at every recorded offset.

    Reads the exact offset of every recipe instruction and compares the
    original bytes (ob) against what is present in the binary.  All
    instructions are checked before reporting.

    A result of 'Safe to tune' means every instruction matched and it is
    safe to run 'openremap tune'.

    Run 'openremap validate check' if this fails — it will tell you whether
    the bytes exist elsewhere (shifted SW revision) or not at all (wrong ECU).
    """
    _run_before(target, recipe, as_json, output)


@app.command(name="check")
def check(
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
    Diagnostic — search the entire binary for ob bytes.

    Scans the whole binary for the original bytes (ob) of every instruction
    and classifies each as EXACT, SHIFTED, or MISSING.

    Run this after 'validate before' fails to understand why:
      SHIFTED  — bytes exist but at a different offset; likely a SW revision
                 difference. 'openremap tune' may still recover them via its
                 ±2 KB anchor search.
      MISSING  — bytes are nowhere in the binary. This is the wrong ECU.
    """
    _run_check(target, recipe, as_json, output)


@app.command(name="after")
def after(
    patched_file: Path = typer.Argument(
        ...,
        help="The tuned ECU binary to verify (.bin or .ori).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        metavar="TUNED",
    ),
    recipe: Path = typer.Argument(
        ...,
        help="The recipe .json file used during tuning.",
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
    Post-tune confirmation — verify mb bytes were written correctly.

    Reads the exact offset of every instruction in the tuned binary and
    confirms that the modified bytes (mb) are now present there.

    The mirror image of 'validate before': before checks ob bytes before
    tuning; after checks mb bytes after tuning.

    Returns confirmed=true only when every instruction passes.
    """
    _run_after(patched_file, recipe, as_json, output)


# ---------------------------------------------------------------------------
# Deprecated aliases (hidden from --help, kept for backward compatibility)
# ---------------------------------------------------------------------------


@app.command(name="strict", hidden=True)
def strict(
    target: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    recipe: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    as_json: bool = typer.Option(False, "--json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", resolve_path=True),
) -> None:
    """[Deprecated] Use 'validate before' instead."""
    typer.echo(
        typer.style(
            "  Note: 'validate strict' has been renamed to 'validate before'.",
            fg=typer.colors.YELLOW,
            dim=True,
        )
    )
    _run_before(target, recipe, as_json, output)


@app.command(name="exists", hidden=True)
def exists(
    target: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    recipe: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    as_json: bool = typer.Option(False, "--json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", resolve_path=True),
) -> None:
    """[Deprecated] Use 'validate check' instead."""
    typer.echo(
        typer.style(
            "  Note: 'validate exists' has been renamed to 'validate check'.",
            fg=typer.colors.YELLOW,
            dim=True,
        )
    )
    _run_check(target, recipe, as_json, output)


@app.command(name="tuned", hidden=True)
def tuned(
    patched_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
        metavar="TUNED",
    ),
    recipe: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    as_json: bool = typer.Option(False, "--json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", resolve_path=True),
) -> None:
    """[Deprecated] Use 'validate after' instead."""
    typer.echo(
        typer.style(
            "  Note: 'validate tuned' has been renamed to 'validate after'.",
            fg=typer.colors.YELLOW,
            dim=True,
        )
    )
    _run_after(patched_file, recipe, as_json, output)
