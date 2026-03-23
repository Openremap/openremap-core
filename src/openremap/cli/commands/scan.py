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

Useful for contributors testing a new extractor against a batch of real binaries.

Examples:
    openremap scan
    openremap scan ./my_bins/
    openremap scan ./my_bins/ --dry-run
    openremap scan ./my_bins/ --create-dirs
    openremap scan ./my_bins/ --dry-run --create-dirs
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated, Optional

import typer

from openremap.tuning.manufacturers import EXTRACTORS
from openremap.tuning.manufacturers.base import BaseManufacturerExtractor

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
    family = extraction.get("ecu_family") or "?"
    variant = extraction.get("ecu_variant") or ""
    hw = extraction.get("hardware_number") or ""
    key = extraction.get("match_key") or ""

    family_str = f"{family}/{variant}" if variant and variant != family else family

    if key:
        if sw:
            version_detail = f"sw: {sw}"
        elif cal:
            version_detail = f"cal_id: {cal} (sw absent by architecture)"
        else:
            version_detail = f"sw: {sw}"

        detail = (
            f"extractor: {extractor.__class__.__name__}  "
            f"family: {family_str}  {version_detail}"
            + (f"  hw: {hw}" if hw else "")
            + (f"  key: {key}" if key else "")
        )
        destination = DEST_SCANNED
    else:
        detail = (
            f"extractor: {extractor.__class__.__name__}  "
            f"family: {family_str}  sw: None"
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
            "--dry-run",
            "-n",
            help=(
                "Classify every file and print the results without moving anything. "
                "Useful for previewing what the scan would do."
            ),
        ),
    ] = False,
    create_dirs: Annotated[
        bool,
        typer.Option(
            "--create-dirs",
            help=(
                "Automatically create the five destination sub-folders inside the "
                "scan directory if they do not already exist."
            ),
        ),
    ] = False,
) -> None:
    """
    Batch-scan a directory of ECU binaries through all registered extractors.

    Each file is classified and optionally moved into one of five sub-folders
    inside the scan directory:

    \b
      scanned    — identified with a valid match_key
      sw_missing — identified but match_key could not be extracted
      contested  — claimed by more than one extractor
      unknown    — no extractor matched
      trash      — not a .bin or .ori file

    Run with --dry-run first to preview results without moving any files.
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

    dest = {name: directory / name for name in ALL_DEST}

    # --- Create destination folders if requested ---
    if create_dirs:
        for path in dest.values():
            path.mkdir(exist_ok=True)

    # --- Validate destination folders exist (skip for dry run — nothing gets moved) ---
    if not dry_run:
        missing_dirs = [name for name in ALL_DEST if not dest[name].is_dir()]
        if missing_dirs:
            typer.echo(
                typer.style(
                    f"\n  Error: missing destination folders: {', '.join(missing_dirs)}\n"
                    f"  Run with --create-dirs to create them automatically.",
                    fg=typer.colors.RED,
                    bold=True,
                ),
                err=True,
            )
            raise typer.Exit(code=1)

    # --- Collect candidate files — direct children only, skip sub-folders ---
    dest_names = set(ALL_DEST)
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
            typer.style("  [dry run — no files will be moved]", fg=typer.colors.YELLOW)
            if dry_run
            else ""
        )
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

    for idx, filepath in enumerate(candidates, start=1):
        label_idx = typer.style(f"[{idx:>{idx_width}}/{total}]", dim=True)
        ext = filepath.suffix.lower()

        # --- Wrong extension → trash ---
        if ext not in VALID_EXTENSIONS:
            if not dry_run:
                safe_move(filepath, dest[DEST_TRASH])
            counts[DEST_TRASH] += 1
            tag = typer.style("  TRASH      ", fg=typer.colors.RED)
            typer.echo(f"{label_idx}{tag}{filepath.name}")
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

        # --- Classify ---
        t0 = time.perf_counter()
        result = classify_file(data, filepath.name)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # --- Move (unless dry run) ---
        if not dry_run:
            safe_move(filepath, dest[result.destination])
        counts[result.destination] += 1

        colour, label = dest_colours[result.destination]
        tag = typer.style(label, fg=colour)
        timing = typer.style(f"  {elapsed_ms:6.1f} ms", dim=True)

        typer.echo(f"{label_idx}{tag}{filepath.name}{timing}")
        typer.echo(
            typer.style(
                f"{'':>{idx_width + 2}}             └─ {result.detail}",
                dim=True,
            )
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
    typer.echo("")
