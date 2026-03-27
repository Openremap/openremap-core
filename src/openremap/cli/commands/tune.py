"""
openremap tune <target> <recipe> [--output <out>]

One-shot workflow: validate → apply → verify.

  Phase 1 — validate before   : strict pre-flight check (ob bytes at expected offsets)
  Phase 2 — apply             : write mb bytes to target (with ±2 KB anchor search)
  Phase 3 — validate after    : confirm mb bytes are present in the tuned binary

The original file is never modified. The tuned binary is written only when all
three phases pass. Exit code 0 = success, 1 = any phase failed.

Use --skip-validation to bypass Phases 1 and 3 (escape hatch for scripted pipelines).

Examples:
    openremap tune target.bin recipe.json
    openremap tune target.bin recipe.json --output my_tuned.bin
    openremap tune target.bin recipe.json --report tune_report.json
    openremap tune target.bin recipe.json --skip-validation
    openremap tune target.bin recipe.json --json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from openremap.tuning.services.patcher import ECUPatcher
from openremap.tuning.services.validate_patched import ECUPatchedValidator
from openremap.tuning.services.validate_strict import ECUStrictValidator

# ---------------------------------------------------------------------------
# Helpers — file I/O
# ---------------------------------------------------------------------------

_ALLOWED_BIN = (".bin", ".ori")


def _read_bin(path: Path, label: str) -> bytes:
    """Read and validate a binary file, exiting with a clear message on error."""
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
    """Read and parse a recipe JSON file, exiting with a clear message on error."""
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
    """Derive the default output filename: target.bin → target_tuned.bin"""
    return target.parent / f"{target.stem}_tuned{target.suffix}"


# ---------------------------------------------------------------------------
# Helpers — output formatting
# ---------------------------------------------------------------------------

_W = 56  # separator width inside the output block


def _phase_header(number: int, title: str, skip: bool = False) -> None:
    dim_line = typer.style("  " + "─" * _W, dim=True)
    colour = typer.colors.YELLOW if skip else typer.colors.CYAN
    label = typer.style(f"  Phase {number} — {title}", fg=colour, bold=True)
    typer.echo(dim_line)
    typer.echo(label)
    typer.echo("")


def _ok(text: str) -> None:
    typer.echo("  " + typer.style("✅ ", fg=typer.colors.GREEN) + text)


def _fail(text: str) -> None:
    typer.echo("  " + typer.style("❌ ", fg=typer.colors.RED) + text)


def _skip(text: str) -> None:
    typer.echo(
        "  " + typer.style("⏭  ", fg=typer.colors.YELLOW) + typer.style(text, dim=True)
    )


def _kv(label: str, value: str, col: int = 24) -> None:
    typer.echo(f"  {label:<{col}} {value}")


def _warn(text: str) -> None:
    typer.echo(typer.style(f"  ⚠  {text}", fg=typer.colors.YELLOW))


# ---------------------------------------------------------------------------
# Phase runners
# ---------------------------------------------------------------------------


def _run_phase1(
    target_data: bytes,
    recipe_dict: dict,
    target_name: str,
    recipe_name: str,
) -> tuple[bool, dict]:
    """
    Phase 1 — validate before (strict pre-flight check).

    Returns (passed: bool, report: dict).
    """
    _phase_header(1, "Pre-flight check  (validate before)")

    try:
        validator = ECUStrictValidator(
            target_data=target_data,
            recipe=recipe_dict,
            target_name=target_name,
            recipe_name=recipe_name,
        )
        size_warn = validator.check_file_size()
        match_key_warn = validator.check_match_key()
        validator.validate_all()
        report = validator.to_dict()
    except Exception as exc:
        _fail(f"Strict validation error — {exc}")
        return False, {}

    summary = report.get("summary", {})
    safe = summary.get("safe_to_patch", False)
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    total = summary.get("total", 0)

    if size_warn:
        _warn(f"Size mismatch: {size_warn}")
    if match_key_warn:
        _warn(f"Match key mismatch: {match_key_warn}")

    col = 24
    _kv("Target", target_name, col)
    _kv("MD5", report.get("target_md5", "?"), col)
    _kv("Instructions", f"{total:,}", col)
    _kv(
        "Passed",
        typer.style(
            str(passed),
            fg=typer.colors.GREEN if passed == total else typer.colors.WHITE,
        ),
        col,
    )
    if failed:
        _kv(
            "Failed",
            typer.style(str(failed), fg=typer.colors.RED, bold=True),
            col,
        )

    typer.echo("")

    if safe:
        _ok("Target matches recipe — safe to apply")
    else:
        _fail(
            f"NOT safe to apply — {failed} instruction(s) failed. "
            "Run  openremap validate check  to diagnose."
        )

    typer.echo("")
    return safe, report


def _run_phase2(
    target_data: bytes,
    recipe_dict: dict,
    target_name: str,
    recipe_name: str,
    skip_validation: bool,
) -> tuple[bool, bytes, dict]:
    """
    Phase 2 — apply the recipe.

    The ECUPatcher always re-runs strict validation internally unless
    skip_validation=True. Since we already ran Phase 1 explicitly and it
    passed, we pass skip_validation=True here to avoid a redundant check.

    Returns (applied: bool, tuned_bytes: bytes, report: dict).
    """
    _phase_header(2, "Applying tune", skip=skip_validation)

    if skip_validation:
        _skip("Pre-flight validation skipped (--skip-validation)")

    try:
        patcher = ECUPatcher(
            target_data=target_data,
            recipe=recipe_dict,
            target_name=target_name,
            recipe_name=recipe_name,
            skip_validation=True,  # Phase 1 already ran (or was intentionally skipped)
        )
        tuned_bytes = patcher.apply_all()
    except ValueError as exc:
        _fail(f"Apply rejected — {exc}")
        return False, b"", {}
    except Exception as exc:
        _fail(f"Apply failed unexpectedly — {exc}")
        return False, b"", {}

    report = patcher.to_dict(patched_data=tuned_bytes)
    summary = report.get("summary", {})
    applied = summary.get("success", 0)
    failed = summary.get("failed", 0)
    shifted = summary.get("shifted", 0)
    total = summary.get("total", 0)
    tune_applied = summary.get("patch_applied", False)

    col = 24
    _kv("Instructions", f"{total:,}", col)
    _kv(
        "Applied",
        typer.style(
            str(applied),
            fg=typer.colors.GREEN if applied == total else typer.colors.WHITE,
        ),
        col,
    )
    if shifted:
        _kv(
            "Shifted",
            typer.style(str(shifted), fg=typer.colors.YELLOW, bold=True),
            col,
        )
        typer.echo(
            typer.style(
                "     Shifted instructions were recovered via ±2 KB anchor search.",
                dim=True,
            )
        )
    if failed:
        _kv(
            "Failed",
            typer.style(str(failed), fg=typer.colors.RED, bold=True),
            col,
        )
        # Print per-instruction failures
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

    if tune_applied:
        _ok(f"Recipe applied — {applied}/{total} instructions written")
    else:
        _fail(
            f"{failed} instruction(s) could not be applied — tuned binary NOT written"
        )

    typer.echo("")
    return tune_applied, tuned_bytes, report


def _run_phase3(
    tuned_bytes: bytes,
    recipe_dict: dict,
    tuned_name: str,
    recipe_name: str,
) -> tuple[bool, dict]:
    """
    Phase 3 — validate after (post-tune verification).

    Returns (confirmed: bool, report: dict).
    """
    _phase_header(3, "Post-tune verification  (validate after)")

    try:
        validator = ECUPatchedValidator(
            patched_data=tuned_bytes,
            recipe=recipe_dict,
            patched_name=tuned_name,
            recipe_name=recipe_name,
        )
        validator.verify_all()
        report = validator.to_dict()
    except Exception as exc:
        _fail(f"Post-tune verification error — {exc}")
        return False, {}

    summary = report.get("summary", {})
    confirmed = summary.get("patch_confirmed", False)
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    total = summary.get("total", 0)

    col = 24
    _kv("Instructions", f"{total:,}", col)
    _kv(
        "Confirmed",
        typer.style(
            str(passed),
            fg=typer.colors.GREEN if passed == total else typer.colors.WHITE,
        ),
        col,
    )
    if failed:
        _kv(
            "Failed",
            typer.style(str(failed), fg=typer.colors.RED, bold=True),
            col,
        )
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

    if confirmed:
        _ok("All mb bytes confirmed in tuned binary")
    else:
        _fail("Post-tune verification failed — do NOT flash this binary")

    typer.echo("")
    return confirmed, report


# ---------------------------------------------------------------------------
# Summary footer
# ---------------------------------------------------------------------------


def _print_footer(
    p1_ok: bool,
    p2_ok: bool,
    p3_ok: bool,
    output: Path,
    tune_applied: bool,
    target_md5: str,
    tuned_md5: str,
    skip_validation: bool,
) -> None:
    dim_line = typer.style("  " + "─" * _W, dim=True)
    typer.echo(dim_line)

    all_ok = (p1_ok or skip_validation) and p2_ok and (p3_ok or skip_validation)

    if all_ok:
        typer.echo(typer.style("  ✅ Tune complete", fg=typer.colors.GREEN, bold=True))
    else:
        typer.echo(typer.style("  ❌ Tune failed", fg=typer.colors.RED, bold=True))

    typer.echo("")

    col = 24
    _kv("Target MD5", target_md5, col)
    if tune_applied:
        _kv("Tuned MD5", tuned_md5, col)
        _kv(
            "Tuned binary",
            typer.style(str(output), fg=typer.colors.CYAN, bold=True),
            col,
        )
    typer.echo("")

    if all_ok:
        typer.echo(
            typer.style(
                "  ⚠  MANDATORY: correct checksums with ECM Titanium, WinOLS, or\n"
                "     a similar tool before flashing the tuned binary to a vehicle.\n"
                "     Flashing without checksum correction will brick the ECU.",
                fg=typer.colors.YELLOW,
            )
        )
        typer.echo("")

    typer.echo(dim_line)
    typer.echo("")


# ---------------------------------------------------------------------------
# JSON report builder
# ---------------------------------------------------------------------------


def _build_combined_report(
    target_name: str,
    recipe_name: str,
    output: Path,
    p1_report: dict,
    p2_report: dict,
    p3_report: dict,
    p1_skipped: bool,
    p3_skipped: bool,
) -> dict:
    return {
        "target_file": target_name,
        "recipe_file": recipe_name,
        "output_file": str(output),
        "phase_1_validate_before": {"skipped": p1_skipped, **p1_report},
        "phase_2_apply": p2_report,
        "phase_3_validate_after": {"skipped": p3_skipped, **p3_report},
        "success": (
            (p1_skipped or p1_report.get("summary", {}).get("safe_to_patch", False))
            and p2_report.get("summary", {}).get("patch_applied", False)
            and (
                p3_skipped or p3_report.get("summary", {}).get("patch_confirmed", False)
            )
        ),
    }


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


def tune(
    target: Annotated[
        Path,
        typer.Argument(
            help="The untuned ECU binary to apply the recipe to (.bin or .ori).",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    recipe: Annotated[
        Path,
        typer.Argument(
            help="The recipe .json file to apply.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help=(
                "Path to write the tuned binary. "
                "Defaults to <target_stem>_tuned<ext> in the same directory as the target."
            ),
            writable=True,
            resolve_path=True,
        ),
    ] = None,
    skip_validation: Annotated[
        bool,
        typer.Option(
            "--skip-validation",
            help=(
                "Skip Phases 1 and 3 (pre-flight and post-tune validation) and apply "
                "the recipe directly. Use with caution — only in scripted pipelines where "
                "you have already validated separately."
            ),
        ),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Print the combined three-phase report as JSON instead of the human-readable output.",
        ),
    ] = False,
    report_output: Annotated[
        Optional[Path],
        typer.Option(
            "--report",
            "-r",
            help="Save the combined three-phase report as a JSON file.",
            resolve_path=True,
        ),
    ] = None,
) -> None:
    """
    Validate, apply, and verify a tuning recipe in one shot.

    \b
    Phase 1 — validate before : strict pre-flight check
    Phase 2 — apply           : write mb bytes (±2 KB anchor search)
    Phase 3 — validate after  : confirm every mb byte was written correctly

    The original TARGET file is never modified. The tuned binary is written
    only when all three phases pass.  Pass --skip-validation to bypass
    Phases 1 and 3 (escape hatch for scripted pipelines).

    \b
    Run  openremap validate check  if Phase 1 fails — it searches the whole
    binary and tells you whether the maps shifted or the ECU is wrong.

    \b
    Remember: always correct checksums with ECM Titanium, WinOLS, or a
    similar tool before flashing the tuned binary to a vehicle.
    """
    target_data = _read_bin(target, "Target")
    recipe_dict = _read_recipe(recipe)
    resolved_output = output or _default_output(target)

    typer.echo("")
    typer.echo(
        typer.style("  openremap tune", bold=True)
        + "  "
        + typer.style(target.name, fg=typer.colors.CYAN)
        + "  +  "
        + typer.style(recipe.name, fg=typer.colors.CYAN)
    )
    typer.echo("")

    # ── Phase 1 ──────────────────────────────────────────────────────────────
    if skip_validation:
        _phase_header(1, "Pre-flight check  (validate before)", skip=True)
        _skip("Skipped (--skip-validation)")
        typer.echo("")
        p1_ok = True
        p1_report: dict = {}
        target_md5 = "—"
    else:
        p1_ok, p1_report = _run_phase1(
            target_data=target_data,
            recipe_dict=recipe_dict,
            target_name=target.name,
            recipe_name=recipe.name,
        )
        target_md5 = p1_report.get("target_md5", "?")

        if not p1_ok:
            # Fast-fail: no point applying if the target doesn't match
            combined = _build_combined_report(
                target.name,
                recipe.name,
                resolved_output,
                p1_report,
                {},
                {},
                p1_skipped=False,
                p3_skipped=skip_validation,
            )
            if as_json:
                typer.echo(json.dumps(combined, indent=2, ensure_ascii=False))
            if report_output:
                _write_report(combined, report_output)
            raise typer.Exit(code=1)

    # ── Phase 2 ──────────────────────────────────────────────────────────────
    p2_ok, tuned_bytes, p2_report = _run_phase2(
        target_data=target_data,
        recipe_dict=recipe_dict,
        target_name=target.name,
        recipe_name=recipe.name,
        skip_validation=skip_validation,
    )
    tuned_md5 = p2_report.get("summary", {}).get("patched_md5", "?")

    if not p2_ok:
        combined = _build_combined_report(
            target.name,
            recipe.name,
            resolved_output,
            p1_report,
            p2_report,
            {},
            p1_skipped=skip_validation,
            p3_skipped=skip_validation,
        )
        if as_json:
            typer.echo(json.dumps(combined, indent=2, ensure_ascii=False))
        if report_output:
            _write_report(combined, report_output)
        raise typer.Exit(code=1)

    # ── Phase 3 ──────────────────────────────────────────────────────────────
    if skip_validation:
        _phase_header(3, "Post-tune verification  (validate after)", skip=True)
        _skip("Skipped (--skip-validation)")
        typer.echo("")
        p3_ok = True
        p3_report: dict = {}
    else:
        p3_ok, p3_report = _run_phase3(
            tuned_bytes=tuned_bytes,
            recipe_dict=recipe_dict,
            tuned_name=resolved_output.name,
            recipe_name=recipe.name,
        )

    # ── Write tuned binary ───────────────────────────────────────────────────
    all_ok = p1_ok and p2_ok and p3_ok

    if p2_ok:
        try:
            resolved_output.parent.mkdir(parents=True, exist_ok=True)
            resolved_output.write_bytes(tuned_bytes)
        except OSError as exc:
            typer.echo(
                typer.style(
                    f"\n  Error: could not write tuned binary to '{resolved_output}': {exc}",
                    fg=typer.colors.RED,
                    bold=True,
                ),
                err=True,
            )
            raise typer.Exit(code=1)

    # ── Build combined report ────────────────────────────────────────────────
    combined = _build_combined_report(
        target.name,
        recipe.name,
        resolved_output,
        p1_report,
        p2_report,
        p3_report,
        p1_skipped=skip_validation,
        p3_skipped=skip_validation,
    )

    if report_output:
        _write_report(combined, report_output)

    # ── Output ───────────────────────────────────────────────────────────────
    if as_json:
        typer.echo(json.dumps(combined, indent=2, ensure_ascii=False))
    else:
        _print_footer(
            p1_ok=p1_ok,
            p2_ok=p2_ok,
            p3_ok=p3_ok,
            output=resolved_output,
            tune_applied=p2_ok,
            target_md5=target_md5,
            tuned_md5=tuned_md5,
            skip_validation=skip_validation,
        )

    if not all_ok:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Internal — report writer
# ---------------------------------------------------------------------------


def _write_report(data: dict, path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except OSError as exc:
        typer.echo(
            typer.style(
                f"Warning: could not write report to '{path}': {exc}",
                fg=typer.colors.YELLOW,
            ),
            err=True,
        )
