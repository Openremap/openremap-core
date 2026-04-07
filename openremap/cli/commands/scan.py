"""
openremap scan [DIRECTORY]

Batch ECU binary scanner.

Processes every file in a directory through all registered extractors and
sorts each file into one of five destination sub-folders:

  scanned    — exactly one extractor claimed the file AND a match_key was extracted
  sw_missing — exactly one extractor claimed the file BUT match_key is None
  contested  — more than one extractor claimed the file
  unknown    — no extractor could handle the file
  trash      — file does not have a .bin or .ori extension

Running without any flags performs a safe dry-run preview — nothing is moved.
Pass --move to actually sort files. Pass --organize to sort into
manufacturer/family sub-folders (e.g. scanned/Bosch/EDC17/) and create all
required directories automatically.

Examples:
    openremap scan                                   # dry-run in current directory
    openremap scan ./my_bins/                        # dry-run in a specific directory
    openremap scan ./my_bins/ --move                 # sort files (flat folders must exist)
    openremap scan ./my_bins/ --move --create-dirs   # sort, creating flat folders first
    openremap scan ./my_bins/ --move --organize      # sort into manufacturer/family tree
    openremap scan ./my_bins/ --organize             # preview the organized layout
    openremap scan ./my_bins/ --report report.json   # dry-run + write JSON report
    openremap scan ./my_bins/ --report report.csv    # dry-run + write CSV report
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Annotated, Optional

import typer

from openremap.core.manufacturers import EXTRACTORS
from openremap.core.manufacturers.base import BaseManufacturerExtractor
from openremap.core.services.confidence import ConfidenceResult, score_identity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_EXTENSIONS = {".bin", ".ori"}

DEST_SCANNED = "scanned"
DEST_SW_MISSING = "sw_missing"
DEST_CONTESTED = "contested"
DEST_UNKNOWN = "unknown"
DEST_TRASH = "trash"

ALL_DEST = [DEST_SCANNED, DEST_SW_MISSING, DEST_CONTESTED, DEST_UNKNOWN, DEST_TRASH]

# Only these destinations have a single confirmed extractor to derive
# manufacturer/family from — all others stay flat under --organize.
ORGANIZABLE_DEST = {DEST_SCANNED, DEST_SW_MISSING}

# Confidence tier → Typer colour mapping
_TIER_COLOURS: dict[str, str] = {
    "High": typer.colors.GREEN,
    "Medium": typer.colors.YELLOW,
    "Low": typer.colors.MAGENTA,
    "Suspicious": typer.colors.RED,
    "Unknown": typer.colors.CYAN,
}

# ---------------------------------------------------------------------------
# Result class
# ---------------------------------------------------------------------------


class ScanResult:
    """Holds the outcome of running all extractors against one file."""

    __slots__ = ("claimants", "extractor", "extraction", "destination", "detail")

    def __init__(
        self,
        claimants: list[BaseManufacturerExtractor],
        extractor: Optional[BaseManufacturerExtractor],
        extraction: Optional[dict],
        destination: str,
        detail: str,
    ) -> None:
        self.claimants = claimants
        self.extractor = extractor
        self.extraction = extraction
        self.destination = destination
        self.detail = detail


# ---------------------------------------------------------------------------
# Core classification logic
# ---------------------------------------------------------------------------


def classify_file(data: bytes, filename: str) -> ScanResult:
    """
    Run every registered extractor against data.

    Unlike the live identifier (which stops at the first match), all extractors
    are run so contested files can be detected.

    Routing rules:
      - No claimants              → unknown
      - More than one claimant    → contested
      - Exactly one claimant,
        match_key is None         → sw_missing
      - Exactly one claimant,
        match_key present         → scanned

    Routing is on match_key rather than software_version because some ECU
    architectures (e.g. LH-Jetronic Format A) have no software_version by design —
    their match_key is driven by calibration_id instead. Routing on match_key
    captures both cases correctly.
    """
    claimants: list[BaseManufacturerExtractor] = []
    for extractor in EXTRACTORS:
        try:
            if extractor.can_handle(data):
                claimants.append(extractor)
        except Exception:
            # A broken extractor must never abort the whole scan.
            pass

    if len(claimants) == 0:
        return ScanResult(
            claimants=[],
            extractor=None,
            extraction=None,
            destination=DEST_UNKNOWN,
            detail="no extractor matched",
        )

    if len(claimants) > 1:
        names = ", ".join(f"{e.__class__.__name__}({e.name})" for e in claimants)
        return ScanResult(
            claimants=claimants,
            extractor=None,
            extraction=None,
            destination=DEST_CONTESTED,
            detail=f"claimed by: {names}",
        )

    # Exactly one claimant — run full extraction to check match_key.
    extractor = claimants[0]
    try:
        extraction = extractor.extract(data, filename)
    except Exception as exc:
        return ScanResult(
            claimants=claimants,
            extractor=extractor,
            extraction=None,
            destination=DEST_SW_MISSING,
            detail=f"extraction error: {exc}",
        )

    sw = extraction.get("software_version")
    cal = extraction.get("calibration_id")
    family = extraction.get("ecu_family") or ""
    variant = extraction.get("ecu_variant") or ""
    hw = extraction.get("hardware_number") or ""
    key = extraction.get("match_key") or ""

    # Build individual display tokens — shown separately so both are visible
    # even when one is missing. Avoids "?/EDC17C66" or silent omissions.
    family_display = family or "?"
    variant_part = f"  variant: {variant}" if variant and variant != family else ""

    if key:
        if sw:
            version_detail = f"sw: {sw}"
        elif cal:
            version_detail = f"cal_id: {cal} (sw absent by architecture)"
        else:
            version_detail = f"sw: {sw}"

        detail = (
            f"extractor: {extractor.__class__.__name__}  "
            f"family: {family_display}"
            + variant_part
            + f"  {version_detail}"
            + (f"  hw: {hw}" if hw else "")
            + (f"  key: {key}" if key else "")
        )
        destination = DEST_SCANNED
    else:
        detail = (
            f"extractor: {extractor.__class__.__name__}  "
            f"family: {family_display}"
            + variant_part
            + f"  sw: None"
            + (f"  cal_id: {cal}" if cal else "")
            + (f"  hw: {hw}" if hw else "")
        )
        destination = DEST_SW_MISSING

    return ScanResult(
        claimants=claimants,
        extractor=extractor,
        extraction=extraction,
        destination=destination,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Confidence rendering helpers
# ---------------------------------------------------------------------------


def _render_confidence_tag(confidence: ConfidenceResult) -> str:
    """
    Return a short coloured inline tag for the scan detail line.

    Format:  [HIGH]  or  [SUSPICIOUS ⚠ IDENT BLOCK MISSING]
    """
    colour = _TIER_COLOURS.get(confidence.tier, typer.colors.WHITE)
    tier_label = typer.style(confidence.tier.upper(), fg=colour, bold=True)

    if confidence.warnings:
        warn_parts = "  ".join(
            typer.style(f"⚠ {w}", fg=typer.colors.RED) for w in confidence.warnings
        )
        return f"[{tier_label}]  {warn_parts}"
    return f"[{tier_label}]"


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------


def _build_report_row(
    filepath: Path,
    result: ScanResult,
    confidence: Optional[ConfidenceResult],
    sha256: Optional[str],
    elapsed_ms: float,
) -> dict:
    """Build a flat dict suitable for JSON / CSV report output."""
    extraction = result.extraction or {}
    row: dict = {
        "filename": filepath.name,
        "destination": result.destination,
        "manufacturer": extraction.get("manufacturer"),
        "ecu_family": extraction.get("ecu_family"),
        "ecu_variant": extraction.get("ecu_variant"),
        "software_version": extraction.get("software_version"),
        "hardware_number": extraction.get("hardware_number"),
        "calibration_id": extraction.get("calibration_id"),
        "match_key": extraction.get("match_key"),
        "file_size": filepath.stat().st_size if filepath.exists() else None,
        "sha256": sha256,
        "elapsed_ms": round(elapsed_ms, 2),
    }
    if confidence is not None:
        row["confidence_score"] = confidence.score
        row["confidence_tier"] = confidence.tier
        row["confidence_warnings"] = "; ".join(confidence.warnings)
    else:
        row["confidence_score"] = None
        row["confidence_tier"] = None
        row["confidence_warnings"] = None
    return row


def _write_report(rows: list[dict], report_path: Path) -> None:
    """Write the accumulated report rows to a JSON or CSV file."""
    suffix = report_path.suffix.lower()

    if suffix == ".json":
        report_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    elif suffix == ".csv":
        if not rows:
            report_path.write_text("", encoding="utf-8")
            return
        fieldnames = list(rows[0].keys())
        with report_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    else:
        # Unsupported extension — fall back to JSON so data is not lost.
        report_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Folder name sanitiser
# ---------------------------------------------------------------------------


def _safe_folder_name(name: str) -> str:
    """
    Sanitize a string so it can be used safely as a directory name.

    Removes characters that are illegal on Windows (\\/:*?"<>|) or that could
    cause confusion on any OS. Collapses redundant underscores/spaces and
    strips leading/trailing junk. Falls back to "unknown" if the result is
    empty after sanitisation.

    Args:
        name: Raw string to sanitise (e.g. a manufacturer or family name).

    Returns:
        A safe, non-empty directory name.
    """
    # Replace Windows-illegal characters and path separators
    name = re.sub(r'[\\/:*?"<>|]', "_", name)
    # Collapse consecutive underscores or spaces
    name = re.sub(r"[_\s]{2,}", "_", name).strip("_. ")
    return name or "unknown"


# ---------------------------------------------------------------------------
# Organised destination resolver
# ---------------------------------------------------------------------------


def _organized_dest_dir(base_dest: Path, result: ScanResult) -> Path:
    """
    Compute the final destination directory for a file under --organize mode.

    Only SCANNED and SW_MISSING results get manufacturer/family nesting because
    those are the only outcomes where a single extractor was positively
    identified. All other destinations (contested, unknown, trash) remain flat
    — there is no single unambiguous extractor to derive from.

    The directory is NOT created here; the caller is responsible for calling
    mkdir(parents=True, exist_ok=True) before moving the file.

    Args:
        base_dest: Flat destination directory (e.g. directory/scanned/).
        result:    The ScanResult from classify_file().

    Returns:
        Path to the final destination directory.
        Example: directory/scanned/Bosch/EDC17/
    """
    if result.destination not in ORGANIZABLE_DEST:
        return base_dest

    extraction = result.extraction or {}
    manufacturer = _safe_folder_name(
        extraction.get("manufacturer") or "unknown_manufacturer"
    )
    # Use ecu_variant as a fallback when ecu_family is absent — better to
    # land in scanned/Bosch/EDC17C66/ than in scanned/Bosch/unknown_family/.
    family = _safe_folder_name(
        extraction.get("ecu_family")
        or extraction.get("ecu_variant")
        or "unknown_family"
    )
    return base_dest / manufacturer / family


# ---------------------------------------------------------------------------
# Safe file move
# ---------------------------------------------------------------------------


def safe_move(src: Path, dest_dir: Path) -> Path:
    """
    Move src into dest_dir, avoiding collisions by appending a counter
    when a file with the same name already exists in the destination.
    """
    dest = dest_dir / src.name
    if dest.exists():
        stem = src.stem
        suffix = src.suffix
        counter = 1
        while dest.exists():
            dest = dest_dir / f"{stem}__{counter}{suffix}"
            counter += 1
    src.rename(dest)
    return dest


# ---------------------------------------------------------------------------
# Command — registered directly on the main app (not as a sub-Typer),
# which avoids the Click/Typer bug where options after a positional argument
# are misinterpreted as subcommand names.
# ---------------------------------------------------------------------------


def scan(
    directory: Annotated[
        Path,
        typer.Argument(
            help=(
                "Directory containing the raw .bin/.ori files to scan. "
                "Defaults to the current working directory."
            ),
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ] = Path("."),
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--move",
            help=(
                "Preview mode (default): classify every file and print results "
                "without moving anything. Destination folders are not required. "
                "Pass --move to actually sort files into the destination folders."
            ),
        ),
    ] = True,
    create_dirs: Annotated[
        bool,
        typer.Option(
            "--create-dirs",
            help=(
                "Automatically create the five flat destination sub-folders inside "
                "the scan directory if they do not already exist. "
                "Implied automatically by --organize."
            ),
        ),
    ] = False,
    organize: Annotated[
        bool,
        typer.Option(
            "--organize",
            "-O",
            help=(
                "Sort identified files into manufacturer/family sub-folders "
                "(e.g. scanned/Bosch/EDC17/). "
                "Automatically creates all required directories — no need to pass "
                "--create-dirs separately. "
                "Applies to SCANNED and SW MISSING outcomes only; "
                "contested, unknown, and trash remain in flat folders."
            ),
        ),
    ] = False,
    recursive: Annotated[
        bool,
        typer.Option(
            "--recursive",
            "-R",
            help=(
                "Recurse into sub-directories when collecting candidate files. "
                "Without this flag only direct children of the scan directory "
                "are considered (the default). File paths in the output will "
                "show their relative path from the scan root so you can see "
                "which sub-folder each file came from."
            ),
        ),
    ] = False,
    report: Annotated[
        Optional[Path],
        typer.Option(
            "--report",
            "-r",
            help=(
                "Write a structured scan report to a file. "
                "The format is determined by the file extension: "
                ".json produces a JSON array, .csv produces a CSV table. "
                "Any other extension falls back to JSON. "
                "The report includes identification fields, confidence score, "
                "tier, and warnings for every scanned file."
            ),
            writable=True,
            resolve_path=True,
        ),
    ] = None,
) -> None:
    """
    Batch-scan a directory of ECU binaries through all registered extractors.

    Running without flags performs a safe dry-run — files are classified and
    results are printed but nothing is moved. Pass --move when you are ready
    to actually sort files.

    Each file is classified and optionally moved into one of five sub-folders
    inside the scan directory:

    \b
      scanned    — identified with a valid match_key
      sw_missing — identified but match_key could not be extracted
      contested  — claimed by more than one extractor
      unknown    — no extractor matched
      trash      — not a .bin or .ori file

    Use --organize to further sort scanned and sw_missing files into
    manufacturer/family sub-folders (e.g. scanned/Bosch/EDC17/).
    --organize creates all required directories automatically.

    Use --report path.json or --report path.csv to save a structured report
    with identification results, confidence scores, and warnings for every file.
    """
    if not directory.is_dir():
        typer.echo(
            typer.style(
                f"\n  Error: directory not found: {directory}",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        raise typer.Exit(code=1)

    # Validate report path extension early so we fail fast before doing work.
    if report is not None:
        report_suffix = report.suffix.lower()
        if report_suffix not in (".json", ".csv"):
            typer.echo(
                typer.style(
                    f"\n  Warning: unrecognised report extension '{report_suffix}' "
                    f"— output will be JSON.\n",
                    fg=typer.colors.YELLOW,
                ),
            )

    # --organize implies --create-dirs for the flat top-level folders.
    effective_create_dirs = create_dirs or organize

    dest = {name: directory / name for name in ALL_DEST}

    # --- Create flat destination folders if requested ---
    if effective_create_dirs:
        for path in dest.values():
            path.mkdir(exist_ok=True)

    # --- Validate flat destination folders exist (only when moving without organize) ---
    # With --organize the flat dirs are always created above, so no extra check needed.
    if not dry_run and not organize:
        missing_dirs = [name for name in ALL_DEST if not dest[name].is_dir()]
        if missing_dirs:
            typer.echo(
                typer.style(
                    f"\n  Error: missing destination folders: {', '.join(missing_dirs)}\n"
                    f"  Run with --create-dirs to create them, or use --organize to\n"
                    f"  create the full manufacturer/family folder tree automatically.",
                    fg=typer.colors.RED,
                    bold=True,
                ),
                err=True,
            )
            raise typer.Exit(code=1)

    # --- Collect candidate files ---
    dest_names = set(ALL_DEST)
    if recursive:
        candidates: list[Path] = sorted(
            f
            for f in directory.rglob("*")
            if f.is_file()
            and f.name not in dest_names
            # Skip files inside the flat destination folders themselves so
            # re-running a scan after --move doesn't re-process them.
            and not any(f == dest[d] or dest[d] in f.parents for d in ALL_DEST)
        )
    else:
        candidates: list[Path] = sorted(
            f for f in directory.iterdir() if f.is_file() and f.name not in dest_names
        )

    if not candidates:
        typer.echo(
            typer.style(f"\n  No files found in {directory}\n", fg=typer.colors.YELLOW)
        )
        return

    total = len(candidates)
    counts = {k: 0 for k in ALL_DEST}

    typer.echo("")
    typer.echo(
        typer.style("  OpenRemap — Batch ECU Scanner", bold=True)
        + (
            typer.style(
                "  [dry run — pass --move to sort files]",
                fg=typer.colors.YELLOW,
            )
            if dry_run
            else ""
        )
        + (typer.style("  [organized]", fg=typer.colors.CYAN) if organize else "")
    )
    typer.echo(
        typer.style(
            f"  {total} file(s)  •  {len(EXTRACTORS)} extractor(s)  •  {directory}",
            dim=True,
        )
    )
    typer.echo("")

    idx_width = len(str(total))
    start_all = time.perf_counter()

    dest_colours: dict[str, tuple[str, str]] = {
        DEST_SCANNED: (typer.colors.GREEN, "  SCANNED    "),
        DEST_SW_MISSING: (typer.colors.MAGENTA, "  SW MISSING "),
        DEST_CONTESTED: (typer.colors.YELLOW, "  CONTESTED  "),
        DEST_UNKNOWN: (typer.colors.CYAN, "  UNKNOWN    "),
        DEST_TRASH: (typer.colors.RED, "  TRASH      "),
    }

    # Accumulate rows for the --report output (if requested).
    report_rows: list[dict] = []

    for idx, filepath in enumerate(candidates, start=1):
        label_idx = typer.style(f"[{idx:>{idx_width}}/{total}]", dim=True)
        ext = filepath.suffix.lower()

        # Display name: relative path when recursive, bare name otherwise.
        display_name = (
            str(filepath.relative_to(directory)) if recursive else filepath.name
        )

        # --- Wrong extension → trash ---
        if ext not in VALID_EXTENSIONS:
            actual_dest = dest[DEST_TRASH]
            if not dry_run:
                safe_move(filepath, actual_dest)
            counts[DEST_TRASH] += 1
            tag = typer.style("  TRASH      ", fg=typer.colors.RED)
            typer.echo(f"{label_idx}{tag}{display_name}")
            if report is not None:
                report_rows.append(
                    _build_report_row(
                        filepath,
                        ScanResult([], None, None, DEST_TRASH, "wrong extension"),
                        None,
                        None,
                        0.0,
                    )
                )
            continue

        # --- Read binary ---
        try:
            data = filepath.read_bytes()
        except OSError as exc:
            typer.echo(
                f"{label_idx}"
                + typer.style("  READ ERR   ", fg=typer.colors.RED)
                + f"{filepath.name}  ({exc})"
            )
            continue

        # --- Zero-byte files → trash ---
        # An empty file cannot be an ECU binary.  Route it to trash rather
        # than letting every extractor fail and reporting UNKNOWN.
        if len(data) == 0:
            actual_dest = dest[DEST_TRASH]
            if not dry_run:
                safe_move(filepath, actual_dest)
            counts[DEST_TRASH] += 1
            tag = typer.style("  TRASH      ", fg=typer.colors.RED)
            typer.echo(f"{label_idx}{tag}{display_name}  (empty file)")
            if report is not None:
                report_rows.append(
                    _build_report_row(
                        filepath,
                        ScanResult([], None, None, DEST_TRASH, "empty file"),
                        None,
                        None,
                        0.0,
                    )
                )
            continue

        # --- Classify ---
        t0 = time.perf_counter()
        result = classify_file(data, filepath.name)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # --- Confidence scoring ---
        # Only score files where we have an extraction result (scanned / sw_missing).
        # For contested, unknown, and trash we still call score_identity so the
        # "Unknown" tier is reported correctly in the --report output.
        identity_for_scoring: dict = result.extraction or {}

        # Inject evidence-based detection metadata from the winning extractor.
        # The raw extraction dict does not carry these — they live on the
        # extractor instance and are populated by can_handle().
        if result.extractor is not None:
            identity_for_scoring = dict(identity_for_scoring)  # avoid mutating original
            identity_for_scoring.setdefault(
                "detection_evidence",
                getattr(result.extractor, "last_detection_evidence", ()),
            )
            identity_for_scoring.setdefault(
                "detection_strength",
                getattr(result.extractor, "detection_strength", None),
            )

        confidence = score_identity(identity_for_scoring, filename=filepath.name)

        # --- SHA-256 for the report ---
        sha256_hex: Optional[str] = None
        if report is not None:
            sha256_hex = hashlib.sha256(data).hexdigest()

        # --- Resolve actual destination directory ---
        if organize:
            actual_dest = _organized_dest_dir(dest[result.destination], result)
        else:
            actual_dest = dest[result.destination]

        # --- Move (unless dry run) ---
        if not dry_run:
            if organize:
                # Nested dirs are created on-demand so we never pre-create
                # the full tree — only the dirs we actually need are made.
                actual_dest.mkdir(parents=True, exist_ok=True)
            safe_move(filepath, actual_dest)
        counts[result.destination] += 1

        colour, label = dest_colours[result.destination]
        tag = typer.style(label, fg=colour)
        timing = typer.style(f"  {elapsed_ms:6.1f} ms", dim=True)

        typer.echo(f"{label_idx}{tag}{display_name}{timing}")

        # --- Build detail line ---
        detail = result.detail

        # Append organised sub-path when relevant.
        if organize and result.destination in ORGANIZABLE_DEST:
            rel = actual_dest.relative_to(directory)
            detail += typer.style(f"  → {rel}/", fg=typer.colors.CYAN)

        # Append confidence tag for identified files (scanned / sw_missing).
        if result.destination in (DEST_SCANNED, DEST_SW_MISSING):
            conf_tag = _render_confidence_tag(confidence)
            detail += f"  {conf_tag}"

        typer.echo(
            typer.style(
                f"{'':>{idx_width + 2}}             └─ {detail}",
                dim=True,
            )
        )

        # --- Accumulate report row ---
        if report is not None:
            report_rows.append(
                _build_report_row(filepath, result, confidence, sha256_hex, elapsed_ms)
            )

    elapsed_total = time.perf_counter() - start_all

    # --- Summary ---
    typer.echo("")
    typer.echo(typer.style("  ── Summary " + "─" * 40, bold=True))
    typer.echo(
        f"  {typer.style('Scanned   ', fg=typer.colors.GREEN)}  {counts[DEST_SCANNED]:>5}"
    )
    typer.echo(
        f"  {typer.style('SW Missing', fg=typer.colors.MAGENTA)}  {counts[DEST_SW_MISSING]:>5}"
    )
    typer.echo(
        f"  {typer.style('Contested ', fg=typer.colors.YELLOW)}  {counts[DEST_CONTESTED]:>5}"
    )
    typer.echo(
        f"  {typer.style('Unknown   ', fg=typer.colors.CYAN)}  {counts[DEST_UNKNOWN]:>5}"
    )
    typer.echo(
        f"  {typer.style('Trash     ', fg=typer.colors.RED)}  {counts[DEST_TRASH]:>5}"
    )

    dry_run_note = (
        typer.style("  (dry run — nothing moved)", fg=typer.colors.YELLOW)
        if dry_run
        else ""
    )
    typer.echo(
        typer.style(f"\n  Total: {total}  •  {elapsed_total:.2f}s", dim=True)
        + dry_run_note
    )

    # --- Write report ---
    if report is not None and report_rows:
        try:
            _write_report(report_rows, report)
            typer.echo(
                typer.style(
                    f"\n  Report saved → {report}  ({len(report_rows)} rows)",
                    fg=typer.colors.CYAN,
                )
            )
        except OSError as exc:
            typer.echo(
                typer.style(
                    f"\n  Error writing report: {exc}",
                    fg=typer.colors.RED,
                    bold=True,
                ),
                err=True,
            )

    # --- Contextual tip for dry-run ---
    if dry_run:
        if organize:
            tip = (
                "  Tip: run with --move --organize to sort files into the "
                "manufacturer/family tree shown above."
            )
        else:
            tip = (
                "  Tip: run with --move to sort files into flat folders, or "
                "add --organize to sort by manufacturer/family (e.g. scanned/Bosch/EDC17/)."
            )
        typer.echo(typer.style(f"\n{tip}", fg=typer.colors.CYAN))

    typer.echo("")
