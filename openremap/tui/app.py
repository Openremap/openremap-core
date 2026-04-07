"""
OpenRemap TUI — main application.

Seven panels:
  Identify  — identify a single ECU binary (calls the real engine)
  Scan      — batch-identify all binaries in a directory
  Cook      — diff two binaries to produce a recipe
  Tune      — validate → apply → verify (one-shot workflow)
  Validate  — validate before / check / after
  Families  — browse all registered ECU families
  About     — project info and CLI reference

Navigation:
  Mouse-click or keyboard shortcuts 1-7 switch panels.
  Q / Ctrl+C quits.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.message import Message
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Footer,
    Header,
    Input,
    Static,
)

from openremap.cli.commands.scan import (
    DEST_CONTESTED,
    DEST_SCANNED,
    DEST_SW_MISSING,
    DEST_TRASH,
    DEST_UNKNOWN,
    VALID_EXTENSIONS,
    ScanResult,
    classify_file,
    safe_move,
    _safe_folder_name,
)
from openremap.core.manufacturers import EXTRACTORS
from openremap.core.services.confidence import ConfidenceResult, score_identity
from openremap.core.services.identifier import identify_ecu
from openremap.core.services.patcher import ECUPatcher
from openremap.core.services.recipe_builder import ECUDiffAnalyzer
from openremap.core.services.validate_exists import ECUExistenceValidator, MatchStatus
from openremap.core.services.validate_patched import ECUPatchedValidator
from openremap.core.services.validate_strict import ECUStrictValidator


# ─────────────────────────────────────────────────────────────────────────────
# Native file / folder picker dialogs
# ─────────────────────────────────────────────────────────────────────────────


def _pick_file(
    start_dir: Optional[Path] = None,
    mode: str = "bin",  # "bin" | "json" | "any"
    title: str = "Select file",
) -> Optional[Path]:
    """
    Show a native file-picker dialog and return the selected Path, or None.

    Linux  : zenity --file-selection  →  kdialog --getopenfilename
    macOS  : osascript "choose file"
    Windows: tkinter.filedialog.askopenfilename
    """
    start = str(start_dir or _openremap_dir())
    env = os.environ.copy()

    if mode == "bin":
        zenity_filter = [
            "--file-filter",
            "ECU binaries | *.bin *.ori",
            "--file-filter",
            "All files | *",
        ]
        kdialog_filter = "*.bin *.ori"
    elif mode == "json":
        zenity_filter = [
            "--file-filter",
            "Recipe | *.openremap *.json",
            "--file-filter",
            "All files | *",
        ]
        kdialog_filter = "*.openremap *.json"
    else:
        zenity_filter = ["--file-filter", "All files | *"]
        kdialog_filter = "*"

    # ── Linux / BSD ───────────────────────────────────────────────────────
    if sys.platform not in ("win32", "darwin"):
        if shutil.which("zenity"):
            try:
                proc = subprocess.run(
                    [
                        "zenity",
                        "--file-selection",
                        "--title",
                        title,
                        "--filename",
                        start,
                    ]
                    + zenity_filter,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return Path(proc.stdout.strip())
                return None
            except (subprocess.TimeoutExpired, Exception):
                pass

        if shutil.which("kdialog"):
            try:
                proc = subprocess.run(
                    [
                        "kdialog",
                        "--getopenfilename",
                        start,
                        kdialog_filter,
                        "--title",
                        title,
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return Path(proc.stdout.strip())
                return None
            except (subprocess.TimeoutExpired, Exception):
                pass

        return None

    # ── macOS ─────────────────────────────────────────────────────────────
    if sys.platform == "darwin":
        try:
            proc = subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'POSIX path of (choose file with prompt "{title}")',
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return Path(proc.stdout.strip().rstrip("\n"))
            return None
        except (subprocess.TimeoutExpired, Exception):
            return None

    # ── Windows ───────────────────────────────────────────────────────────
    try:
        import tkinter as tk
        from tkinter import filedialog

        if mode == "bin":
            filetypes = [("ECU binaries", "*.bin *.ori"), ("All files", "*.*")]
        elif mode == "json":
            filetypes = [("Recipe", "*.openremap *.json"), ("All files", "*.*")]
        else:
            filetypes = [("All files", "*.*")]

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path_str = filedialog.askopenfilename(
            title=title,
            initialdir=start,
            filetypes=filetypes,
        )
        root.destroy()
        return Path(path_str) if path_str else None
    except Exception:
        return None


def _pick_directory(start_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Show a native folder-picker dialog and return the selected Path, or None.

    Linux  : zenity --file-selection --directory  →  kdialog --getexistingdirectory
    macOS  : osascript "choose folder"
    Windows: tkinter.filedialog.askdirectory
    """
    start = str(start_dir or _openremap_dir())
    env = os.environ.copy()

    # ── Linux / BSD ───────────────────────────────────────────────────────
    if sys.platform not in ("win32", "darwin"):
        if shutil.which("zenity"):
            try:
                proc = subprocess.run(
                    [
                        "zenity",
                        "--file-selection",
                        "--directory",
                        "--title",
                        "Select directory to scan",
                        "--filename",
                        start,
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return Path(proc.stdout.strip())
                return None
            except (subprocess.TimeoutExpired, Exception):
                pass

        if shutil.which("kdialog"):
            try:
                proc = subprocess.run(
                    [
                        "kdialog",
                        "--getexistingdirectory",
                        start,
                        "--title",
                        "Select directory to scan",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return Path(proc.stdout.strip())
                return None
            except (subprocess.TimeoutExpired, Exception):
                pass

        return None

    # ── macOS ─────────────────────────────────────────────────────────────
    if sys.platform == "darwin":
        try:
            proc = subprocess.run(
                [
                    "osascript",
                    "-e",
                    'POSIX path of (choose folder with prompt "Select directory")',
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return Path(proc.stdout.strip().rstrip("\n"))
            return None
        except (subprocess.TimeoutExpired, Exception):
            return None

    # ── Windows ───────────────────────────────────────────────────────────
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path_str = filedialog.askdirectory(
            title="Select directory to scan",
            initialdir=start,
        )
        root.destroy()
        return Path(path_str) if path_str else None
    except Exception:
        return None


def _openremap_dir() -> Path:
    """
    Return (and create if needed) the cross-platform OpenRemap working directory.

    Windows : C:\\Users\\<name>\\Documents\\OpenRemap
    macOS   : /Users/<name>/Documents/OpenRemap
    Linux   : ~/Documents/OpenRemap  (falls back to ~/OpenRemap if ~/Documents absent)
    """
    documents = Path.home() / "Documents"
    base = documents if documents.is_dir() else Path.home()
    folder = base / "OpenRemap"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _recipes_dir() -> Path:
    """Return (and create if needed) OpenRemap/recipes — default home for recipe files."""
    folder = _openremap_dir() / "recipes"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _tunes_dir() -> Path:
    """Return (and create if needed) OpenRemap/tunes — default home for tuned binaries."""
    folder = _openremap_dir() / "tunes"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _ecus_dir() -> Path:
    """Return (and create if needed) OpenRemap/ECUs — root for organised ECU binaries."""
    folder = _openremap_dir() / "ECUs"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _pick_save_file(
    suggested: Path,
    mode: str = "json",  # "json" | "bin"
    title: str = "Save as",
) -> Optional[Path]:
    """
    Show a native save-file dialog and return the chosen Path, or None.

    Linux  : zenity --file-selection --save
    macOS  : osascript "choose file name"
    Windows: tkinter.filedialog.asksaveasfilename
    """
    start = (
        str(suggested)
        if suggested != Path.home()
        else str(_openremap_dir() / suggested.name)
    )
    env = os.environ.copy()

    if mode == "json":
        zenity_filter = [
            "--file-filter",
            "Recipe | *.openremap",
            "--file-filter",
            "All files | *",
        ]
        kdialog_filter = "*.openremap"
        tk_filetypes = [("Recipe", "*.openremap"), ("All files", "*.*")]
        tk_defaultext = ".openremap"
    else:
        zenity_filter = [
            "--file-filter",
            "ECU binaries | *.bin *.ori",
            "--file-filter",
            "All files | *",
        ]
        kdialog_filter = "*.bin *.ori"
        tk_filetypes = [("ECU binaries", "*.bin *.ori"), ("All files", "*.*")]
        tk_defaultext = ".bin"

    # ── Linux / BSD ───────────────────────────────────────────────────────
    if sys.platform not in ("win32", "darwin"):
        if shutil.which("zenity"):
            try:
                proc = subprocess.run(
                    [
                        "zenity",
                        "--file-selection",
                        "--save",
                        "--confirm-overwrite",
                        "--title",
                        title,
                        "--filename",
                        start,
                    ]
                    + zenity_filter,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return Path(proc.stdout.strip())
                return None
            except (subprocess.TimeoutExpired, Exception):
                pass

        if shutil.which("kdialog"):
            try:
                proc = subprocess.run(
                    [
                        "kdialog",
                        "--getsavefilename",
                        start,
                        kdialog_filter,
                        "--title",
                        title,
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return Path(proc.stdout.strip())
                return None
            except (subprocess.TimeoutExpired, Exception):
                pass

        return None

    # ── macOS ─────────────────────────────────────────────────────────────
    if sys.platform == "darwin":
        try:
            proc = subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'POSIX path of (choose file name with prompt "{title}" default name "{suggested.name}")',
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return Path(proc.stdout.strip().rstrip("\n"))
            return None
        except (subprocess.TimeoutExpired, Exception):
            return None

    # ── Windows ───────────────────────────────────────────────────────────
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path_str = filedialog.asksaveasfilename(
            title=title,
            initialdir=str(suggested.parent),
            initialfile=suggested.name,
            defaultextension=tk_defaultext,
            filetypes=tk_filetypes,
        )
        root.destroy()
        return Path(path_str) if path_str else None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Messages
# ─────────────────────────────────────────────────────────────────────────────


class IdentifyDone(Message):
    def __init__(
        self, result: dict, confidence: ConfidenceResult, filename: str, path: Path
    ) -> None:
        self.result = result
        self.confidence = confidence
        self.filename = filename
        self.path = path
        super().__init__()


class IdentifyFailed(Message):
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__()


class ScanProgress(Message):
    def __init__(self, current: int, total: int, filename: str) -> None:
        self.current = current
        self.total = total
        self.filename = filename
        super().__init__()


class ScanDone(Message):
    def __init__(
        self,
        rows: list[tuple[str, dict, Optional[ConfidenceResult]]],
        classified: list[tuple[Path, ScanResult]],
    ) -> None:
        self.rows = rows
        self.classified = classified
        super().__init__()


class OrganizeDone(Message):
    def __init__(self, moved: int, errors: int, dest_counts: dict[str, int]) -> None:
        self.moved = moved
        self.errors = errors
        self.dest_counts = dest_counts
        super().__init__()


class OrganizeFailed(Message):
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__()


class CookDone(Message):
    def __init__(self, recipe: dict, output_path: Optional[Path]) -> None:
        self.recipe = recipe
        self.output_path = output_path
        super().__init__()


class CookFailed(Message):
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__()


class TuneDone(Message):
    def __init__(
        self,
        p1_ok: bool,
        p2_ok: bool,
        p3_ok: bool,
        p1_report: dict,
        p2_report: dict,
        p3_report: dict,
        output_path: Optional[Path],
    ) -> None:
        self.p1_ok = p1_ok
        self.p2_ok = p2_ok
        self.p3_ok = p3_ok
        self.p1_report = p1_report
        self.p2_report = p2_report
        self.p3_report = p3_report
        self.output_path = output_path
        super().__init__()


class TuneFailed(Message):
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__()


class ValidateDone(Message):
    def __init__(self, mode: str, report: dict) -> None:
        self.mode = mode
        self.report = report
        super().__init__()


class ValidateFailed(Message):
    def __init__(self, error: str) -> None:
        self.error = error
        super().__init__()


# ── picker messages ───────────────────────────────────────────────────────────


class FilePickedForIdentify(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class DirPickedForScan(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class FilePickedForCookOrig(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class FilePickedForCookMod(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class FilePickedForCookOutput(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class FilePickedForTuneTarget(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class FilePickedForTuneRecipe(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class FilePickedForTuneOutput(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class FilePickedForValidateBin(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class FilePickedForValidateRecipe(Message):
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


# ─────────────────────────────────────────────────────────────────────────────
# Shared rendering constants
# ─────────────────────────────────────────────────────────────────────────────

_DEST_CELL: dict[str, Text] = {
    DEST_SCANNED: Text("✓  scanned", style="bold green"),
    DEST_SW_MISSING: Text("⚠  unmatched", style="bold yellow"),
    DEST_CONTESTED: Text("✗  contested", style="bold red"),
    DEST_UNKNOWN: Text("?  unknown", style="dim"),
    DEST_TRASH: Text("⌫  unsupported", style="dim"),
}

_TIER_STYLE: dict[str, str] = {
    "High": "bold green",
    "Medium": "bold yellow",
    "Low": "bold magenta",
    "Suspicious": "bold red",
    "Unknown": "bold cyan",
}

_TIER_BADGE: dict[str, str] = {
    "High": "●●●●",
    "Medium": "●●●○",
    "Low": "●●○○",
    "Suspicious": "●○○○",
    "Unknown": "○○○○",
}

_NO_PICKER_MSG = (
    "No file dialog available.  Install zenity (Linux) or kdialog (KDE) and retry."
)


# ─────────────────────────────────────────────────────────────────────────────
# Identify panel
# ─────────────────────────────────────────────────────────────────────────────


class IdentifyPanel(Vertical):
    """Single-file ECU binary identification screen."""

    def compose(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("⚡  IDENTIFY", classes="page-title")
            yield Static(
                "Browse for a binary or type its path, then press IDENTIFY.",
                classes="page-desc",
            )
            yield Static("Binary path", classes="field-label")
            yield Input(placeholder="/path/to/ecu.bin", id="identify-input")
            with Horizontal(classes="btn-row"):
                yield Button("IDENTIFY", id="btn-identify", classes="btn-primary")
                yield Button(
                    "📂  Browse", id="btn-browse-identify", classes="btn-secondary"
                )
            with ScrollableContainer(id="identify-result"):
                yield Static(
                    Text(
                        "\n  No file loaded yet.\n"
                        "  Browse for a file or enter its path and press IDENTIFY.",
                        style="dim",
                    ),
                    id="identify-display",
                )

    # ── events ───────────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-identify":
            event.stop()
            self._start_identify()
        elif event.button.id == "btn-browse-identify":
            event.stop()
            self._browse_file()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "identify-input":
            self._start_identify()

    # ── message handlers ─────────────────────────────────────────────────────

    @on(IdentifyDone)
    def _handle_done(self, message: IdentifyDone) -> None:
        self.query_one("#btn-identify", Button).disabled = False
        self.query_one("#btn-browse-identify", Button).disabled = False
        self._render_result(message.result, message.confidence, message.filename)

    @on(IdentifyFailed)
    def _handle_failed(self, message: IdentifyFailed) -> None:
        self.query_one("#btn-identify", Button).disabled = False
        self.query_one("#btn-browse-identify", Button).disabled = False
        t = Text()
        t.append("\n  ✗  Identification failed\n\n", style="bold red")
        t.append(f"  {message.error}\n", style="red")
        self.query_one("#identify-display", Static).update(t)

    @on(FilePickedForIdentify)
    def _handle_file_picked(self, message: FilePickedForIdentify) -> None:
        self.query_one("#identify-input", Input).value = str(message.path)
        self._start_identify()

    # ── workers ──────────────────────────────────────────────────────────────

    @work(exclusive=True, thread=True)
    def _browse_file(self) -> None:
        path_str = self.query_one("#identify-input", Input).value.strip()
        if path_str:
            p = Path(path_str)
            start_dir: Optional[Path] = p.parent if p.exists() else None
        else:
            start_dir = _openremap_dir()

        picked = _pick_file(start_dir, mode="bin", title="Select ECU binary")

        if picked is not None:
            self.post_message(FilePickedForIdentify(picked))
        else:
            if not shutil.which("zenity") and not shutil.which("kdialog"):
                self.app.call_from_thread(
                    self.app.notify,
                    _NO_PICKER_MSG,
                    title="Browse",
                    severity="warning",
                )

    @work(exclusive=True, thread=True)
    def _do_identify(self, path: Path) -> None:
        try:
            if not path.exists():
                self.post_message(IdentifyFailed(f"File not found: {path}"))
                return
            if not path.is_file():
                self.post_message(IdentifyFailed(f"Not a file: {path}"))
                return
            data = path.read_bytes()
            if not data:
                self.post_message(IdentifyFailed("File is empty."))
                return
            result = identify_ecu(data=data, filename=path.name)
            confidence = score_identity(result, filename=path.name)
            self.post_message(IdentifyDone(result, confidence, path.name, path))
        except OSError as exc:
            self.post_message(IdentifyFailed(f"Read error: {exc}"))
        except Exception as exc:
            self.post_message(IdentifyFailed(f"Unexpected error: {exc}"))

    # ── internals ────────────────────────────────────────────────────────────

    def _start_identify(self) -> None:
        path_str = self.query_one("#identify-input", Input).value.strip()
        if not path_str:
            return
        self.query_one("#btn-identify", Button).disabled = True
        self.query_one("#btn-browse-identify", Button).disabled = True
        self.query_one("#identify-display", Static).update(
            Text("\n  Identifying…", style="dim")
        )
        self._do_identify(Path(path_str))

    def _render_result(
        self,
        result: dict,
        confidence: ConfidenceResult,
        filename: str,
    ) -> None:
        t = Text()
        W = 20

        t.append(f"\n  {filename}\n", style="bold #c8d1e0")
        family = result.get("ecu_family")
        mfr = result.get("manufacturer")
        if family and mfr:
            t.append(f"  {mfr}  ·  {family}\n\n", style="bold #ff6d00")
        else:
            t.append(
                "  Unknown ECU — no extractor matched this binary\n\n",
                style="bold yellow",
            )

        fields: list[tuple[str, Optional[str]]] = [
            ("Manufacturer", result.get("manufacturer")),
            ("ECU Family", result.get("ecu_family")),
            ("ECU Variant", result.get("ecu_variant")),
            ("Software Version", result.get("software_version")),
            ("Hardware Number", result.get("hardware_number")),
            ("Calibration ID", result.get("calibration_id")),
            ("Match Key", result.get("match_key")),
            (
                "File Size",
                f"{result['file_size']:,} bytes" if result.get("file_size") else None,
            ),
            (
                "SHA-256",
                result.get("sha256") or None,
            ),
        ]

        for label, value in fields:
            t.append(f"  {label:<{W}}", style="dim")
            if value is None:
                t.append("unknown\n", style="yellow")
            else:
                t.append(f"{value}\n", style="#c8d1e0")

        t.append("\n  ── Confidence ", style="dim")
        t.append("─" * 36 + "\n", style="dim")

        tier_style = _TIER_STYLE.get(confidence.tier, "bold white")
        badge = _TIER_BADGE.get(confidence.tier, "○○○○")
        t.append(f"  {'Tier':<{W}}", style="dim")
        t.append(f"{badge}  {confidence.tier.upper()}\n", style=tier_style)

        t.append(f"  {'Score':<{W}}", style="dim")
        t.append(f"{confidence.score:+d}\n", style="#c8d1e0")

        if confidence.signals:
            t.append("\n")
            for sig in confidence.signals:
                colour = "green" if sig.delta >= 0 else "red"
                marker = "  ▲ " if sig.delta >= 0 else "  ▼ "
                t.append(f"  {'':<{W}}", style="dim")
                t.append(marker, style=colour)
                t.append(f"{sig.label}  ", style="#c8d1e0")
                t.append(
                    f"({'+' if sig.delta >= 0 else ''}{sig.delta})\n",
                    style=colour,
                )

        if confidence.warnings:
            t.append("\n")
            for w in confidence.warnings:
                t.append(f"  ⚠  {w}\n", style="bold yellow")

        self.query_one("#identify-display", Static).update(t)


# ─────────────────────────────────────────────────────────────────────────────
# Scan panel
# ─────────────────────────────────────────────────────────────────────────────


class ScanPanel(Vertical):
    """Batch directory scan screen."""

    # Stores (Path, ScanResult) for every file in the last scan — used by organise.
    _classified: list[tuple[Path, ScanResult]] = []
    _organize_mode: str = "manufacturer"

    def compose(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("⬡  SCAN", classes="page-title")
            yield Static(
                "Browse for a directory or type its path, then press SCAN.",
                classes="page-desc",
            )
            yield Static("Directory path", classes="field-label")
            yield Input(placeholder="/path/to/bins/", id="scan-input")
            with Horizontal(classes="scan-action-row"):
                yield Button("SCAN", id="btn-scan", classes="btn-primary")
                yield Button(
                    "📂  Browse", id="btn-browse-scan", classes="btn-secondary"
                )
                yield Static("", classes="scan-action-spacer")
                yield Button(
                    "By Manufacturer",
                    id="mode-btn-manufacturer",
                    classes="mode-btn mode-btn-active",
                )
                yield Button("Detailed", id="mode-btn-detailed", classes="mode-btn")
                yield Button(
                    "▶  ORGANISE",
                    id="btn-organize",
                    classes="btn-organize",
                    disabled=True,
                )
            with Horizontal(classes="scan-status-row"):
                yield Static("", id="scan-status", classes="scan-status-left")
                yield Static("", id="organize-status", classes="scan-status-right")
            yield DataTable(id="scan-table", show_cursor=True, zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one("#scan-table", DataTable)
        table.add_columns(
            "File",
            "Manufacturer",
            "Family",
            "Software Version",
            "Confidence",
            "Category",
        )
        table.fixed_columns = 1

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-scan":
            event.stop()
            self._start_scan()
        elif event.button.id == "btn-browse-scan":
            event.stop()
            self._browse_dir()
        elif event.button.id == "btn-organize":
            event.stop()
            self._start_organize()
        elif event.button.id == "mode-btn-manufacturer":
            event.stop()
            self._set_organize_mode("manufacturer")
        elif event.button.id == "mode-btn-detailed":
            event.stop()
            self._set_organize_mode("detailed")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "scan-input":
            self._start_scan()

    # ── message handlers ─────────────────────────────────────────────────────

    @on(ScanProgress)
    def _handle_progress(self, message: ScanProgress) -> None:
        self.query_one("#scan-status", Static).update(
            Text(
                f"  Scanning {message.current} / {message.total}"
                f"  —  {message.filename}",
                style="dim",
            )
        )

    @on(ScanDone)
    def _handle_scan_done(self, message: ScanDone) -> None:
        self._classified = message.classified
        table = self.query_one("#scan-table", DataTable)
        for (filename, result, confidence), (_, scan_result) in zip(
            message.rows, message.classified
        ):
            mfr = result.get("manufacturer") or "—"
            family = result.get("ecu_family") or "—"
            sw = result.get("software_version") or "—"
            if confidence is None:
                tier_cell = Text("ERROR", style="bold red")
            else:
                style = _TIER_STYLE.get(confidence.tier, "white")
                badge = _TIER_BADGE.get(confidence.tier, "○○○○")
                tier_cell = Text(f"{badge}  {confidence.tier}", style=style)
            cat_cell = _DEST_CELL.get(scan_result.destination, Text("?", style="dim"))
            table.add_row(filename, mfr, family, sw, tier_cell, cat_cell)

        identified = sum(
            1 for _, r, _ in message.rows if r.get("ecu_family") is not None
        )
        total = len(message.rows)
        status = Text()
        status.append("  ✓  ", style="bold green")
        status.append(
            f"Done — {identified} / {total} files identified", style="#c8d1e0"
        )
        self.query_one("#scan-status", Static).update(status)
        self.query_one("#btn-scan", Button).disabled = False
        self.query_one("#btn-browse-scan", Button).disabled = False
        # Enable organise now that we have results
        if self._classified:
            self.query_one("#btn-organize", Button).disabled = False

    @on(OrganizeDone)
    def _handle_organize_done(self, message: OrganizeDone) -> None:
        self.query_one("#btn-organize", Button).disabled = False
        self.query_one("#btn-organize", Button).add_class("btn-organize-done")
        t = Text()
        t.append("  ✓  ", style="bold green")
        t.append(f"Organised {message.moved} file(s)", style="#c8d1e0")
        if message.errors:
            t.append(f"  —  {message.errors} error(s)", style="bold red")
        if message.dest_counts:
            t.append("  →  ", style="dim")
            parts = [f"{k}: {v}" for k, v in sorted(message.dest_counts.items())]
            t.append(", ".join(parts), style="dim")
        self.query_one("#organize-status", Static).update(t)

    @on(OrganizeFailed)
    def _handle_organize_failed(self, message: OrganizeFailed) -> None:
        self.query_one("#btn-organize", Button).disabled = False
        t = Text()
        t.append("  ✗  Organise failed  ", style="bold red")
        t.append(message.error, style="red")
        self.query_one("#organize-status", Static).update(t)

    @on(DirPickedForScan)
    def _handle_dir_picked(self, message: DirPickedForScan) -> None:
        self.query_one("#scan-input", Input).value = str(message.path)

    # ── workers ──────────────────────────────────────────────────────────────

    @work(exclusive=True, thread=True)
    def _browse_dir(self) -> None:
        path_str = self.query_one("#scan-input", Input).value.strip()
        if path_str:
            p = Path(path_str)
            start_dir: Optional[Path] = (
                p if p.is_dir() else p.parent if p.exists() else None
            )
        else:
            start_dir = _openremap_dir()

        picked = _pick_directory(start_dir)

        if picked is not None:
            self.post_message(DirPickedForScan(picked))
        else:
            if not shutil.which("zenity") and not shutil.which("kdialog"):
                self.app.call_from_thread(
                    self.app.notify,
                    _NO_PICKER_MSG,
                    title="Browse",
                    severity="warning",
                )

    @work(exclusive=True, thread=True)
    def _do_scan(self, directory: Path) -> None:
        # Collect ALL files so unsupported extensions are visible and can be
        # organised into an Unsupported folder instead of being left behind.
        files = sorted(f for f in directory.rglob("*") if f.is_file())
        total = len(files)
        rows: list[tuple[str, dict, Optional[ConfidenceResult]]] = []
        classified: list[tuple[Path, ScanResult]] = []

        for i, f in enumerate(files, 1):
            rel_name = (
                str(f.relative_to(directory))
                if str(f).startswith(str(directory))
                else f.name
            )
            self.post_message(ScanProgress(i, total, rel_name))

            # Case-insensitive extension check — .BIN / .ORI are accepted.
            ext = f.suffix.lower()
            if ext not in VALID_EXTENSIONS:
                rows.append((rel_name, {}, None))
                classified.append(
                    (f, ScanResult([], None, None, DEST_TRASH, "unsupported extension"))
                )
                continue

            try:
                data = f.read_bytes()
                if not data:
                    rows.append((rel_name, {}, None))
                    classified.append(
                        (f, ScanResult([], None, None, DEST_TRASH, "empty file"))
                    )
                    continue
                result = identify_ecu(data=data, filename=f.name)
                confidence = score_identity(result, filename=f.name)
                scan_result = classify_file(data=data, filename=f.name)
                rows.append((rel_name, result, confidence))
                classified.append((f, scan_result))
            except Exception:
                rows.append((rel_name, {}, None))
                # Create a minimal unknown result so the two lists stay in sync
                classified.append(
                    (f, ScanResult([], None, None, DEST_UNKNOWN, "read error"))
                )

        self.post_message(ScanDone(rows, classified))

    @work(exclusive=True, thread=True)
    def _do_organize(
        self, classified: list[tuple[Path, ScanResult]], mode: str
    ) -> None:
        ecus = _ecus_dir()
        moved = 0
        errors = 0
        dest_counts: dict[str, int] = {}

        for file_path, scan_result in classified:
            if not file_path.exists():
                errors += 1
                continue
            try:
                extraction = scan_result.extraction or {}
                dest: Path

                if scan_result.destination == DEST_SCANNED:
                    mfr = _safe_folder_name(extraction.get("manufacturer") or "Unknown")
                    if mode == "detailed":
                        family = _safe_folder_name(
                            extraction.get("ecu_family")
                            or extraction.get("ecu_variant")
                            or "Unknown"
                        )
                        dest = ecus / mfr / family
                    else:
                        dest = ecus / mfr

                elif scan_result.destination == DEST_SW_MISSING:
                    mfr = _safe_folder_name(extraction.get("manufacturer") or "Unknown")
                    dest = ecus / mfr / "Unmatched"

                elif scan_result.destination == DEST_CONTESTED:
                    dest = ecus / "Contested"

                elif scan_result.destination == DEST_UNKNOWN:
                    dest = ecus / "Unknown"

                else:  # DEST_TRASH
                    dest = ecus / "Unsupported"

                dest.mkdir(parents=True, exist_ok=True)
                safe_move(file_path, dest)
                moved += 1
                key = str(dest.relative_to(ecus))
                dest_counts[key] = dest_counts.get(key, 0) + 1

            except Exception:
                errors += 1

        self.post_message(OrganizeDone(moved, errors, dest_counts))

    # ── internals ────────────────────────────────────────────────────────────

    def _set_organize_mode(self, mode: str) -> None:
        self._organize_mode = mode
        for m in ("manufacturer", "detailed"):
            btn = self.query_one(f"#mode-btn-{m}", Button)
            if m == mode:
                btn.add_class("mode-btn-active")
            else:
                btn.remove_class("mode-btn-active")

    def _start_scan(self) -> None:
        path_str = self.query_one("#scan-input", Input).value.strip()
        if not path_str:
            return
        d = Path(path_str)
        if not d.is_dir():
            t = Text()
            t.append("  ✗  ", style="bold red")
            t.append(f"Not a directory: {path_str}", style="red")
            self.query_one("#scan-status", Static).update(t)
            return
        self._classified = []
        self.query_one("#scan-table", DataTable).clear()
        self.query_one("#btn-scan", Button).disabled = True
        self.query_one("#btn-browse-scan", Button).disabled = True
        # Reset organise bar for new scan
        self.query_one("#btn-organize", Button).disabled = True
        self.query_one("#btn-organize", Button).remove_class("btn-organize-done")
        self.query_one("#organize-status", Static).update("")
        self.query_one("#scan-status", Static).update(Text("  Scanning…", style="dim"))
        self._do_scan(d)

    def _start_organize(self) -> None:
        if not self._classified:
            return
        self.query_one("#btn-organize", Button).disabled = True
        self.query_one("#organize-status", Static).update(
            Text("  Organising…", style="dim")
        )
        self._do_organize(list(self._classified), self._organize_mode)


# ─────────────────────────────────────────────────────────────────────────────
# Cook panel
# ─────────────────────────────────────────────────────────────────────────────


class CookPanel(Vertical):
    """Diff two binaries to produce a recipe."""

    def compose(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("⚗  COOK", classes="page-title")
            yield Static(
                "Select an original and a modified binary, then press COOK.",
                classes="page-desc",
            )
            with Horizontal(classes="three-col"):
                with Vertical(classes="field-col"):
                    yield Static("Original binary", classes="field-label")
                    yield Input(placeholder="/path/to/stock.bin", id="cook-orig-input")
                    yield Button(
                        "📂  Browse original",
                        id="btn-browse-cook-orig",
                        classes="btn-secondary",
                    )
                with Vertical(classes="field-col"):
                    yield Static("Modified binary", classes="field-label")
                    yield Input(placeholder="/path/to/tuned.bin", id="cook-mod-input")
                    yield Button(
                        "📂  Browse modified",
                        id="btn-browse-cook-mod",
                        classes="btn-secondary",
                    )
                with Vertical(classes="field-col-last"):
                    yield Static("Output recipe", classes="field-label")
                    yield Input(
                        placeholder="/path/to/recipe.openremap", id="cook-output-input"
                    )
                    yield Button(
                        "💾  Save as…",
                        id="btn-browse-cook-output",
                        classes="btn-secondary",
                    )
            with Horizontal(classes="btn-row"):
                yield Button("COOK", id="btn-cook", classes="btn-primary")
            with ScrollableContainer(id="cook-result"):
                yield Static(
                    Text(
                        "\n  No recipe cooked yet.\n"
                        "  Select two binaries and press COOK.",
                        style="dim",
                    ),
                    id="cook-display",
                )

    # ── events ───────────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cook":
            event.stop()
            self._start_cook()
        elif event.button.id == "btn-browse-cook-orig":
            event.stop()
            self._browse_orig()
        elif event.button.id == "btn-browse-cook-mod":
            event.stop()
            self._browse_mod()
        elif event.button.id == "btn-browse-cook-output":
            event.stop()
            self._browse_output()

    # ── message handlers ─────────────────────────────────────────────────────

    @on(CookDone)
    def _handle_cook_done(self, message: CookDone) -> None:
        self.query_one("#btn-cook", Button).disabled = False
        self._render_cook_result(message.recipe, message.output_path)

    @on(CookFailed)
    def _handle_cook_failed(self, message: CookFailed) -> None:
        self.query_one("#btn-cook", Button).disabled = False
        t = Text()
        t.append("\n  ✗  Cook failed\n\n", style="bold red")
        t.append(f"  {message.error}\n", style="red")
        self.query_one("#cook-display", Static).update(t)

    @on(FilePickedForCookOrig)
    def _handle_orig_picked(self, message: FilePickedForCookOrig) -> None:
        self.query_one("#cook-orig-input", Input).value = str(message.path)
        # Auto-fill output into the OpenRemap folder if still empty
        out_input = self.query_one("#cook-output-input", Input)
        if not out_input.value.strip():
            default = _recipes_dir() / (message.path.stem + "_recipe.openremap")
            out_input.value = str(default)

    @on(FilePickedForCookMod)
    def _handle_mod_picked(self, message: FilePickedForCookMod) -> None:
        self.query_one("#cook-mod-input", Input).value = str(message.path)

    @on(FilePickedForCookOutput)
    def _handle_output_picked(self, message: FilePickedForCookOutput) -> None:
        self.query_one("#cook-output-input", Input).value = str(message.path)

    # ── workers ──────────────────────────────────────────────────────────────

    @work(exclusive=True, thread=True)
    def _browse_orig(self) -> None:
        path_str = self.query_one("#cook-orig-input", Input).value.strip()
        if path_str:
            p = Path(path_str)
            start_dir: Optional[Path] = p.parent if p.exists() else None
        else:
            start_dir = _openremap_dir()
        picked = _pick_file(
            start_dir, mode="bin", title="Select original (stock) binary"
        )
        if picked is not None:
            self.post_message(FilePickedForCookOrig(picked))
        elif not shutil.which("zenity") and not shutil.which("kdialog"):
            self.app.call_from_thread(
                self.app.notify,
                _NO_PICKER_MSG,
                title="Browse",
                severity="warning",
            )

    @work(exclusive=True, thread=True)
    def _browse_mod(self) -> None:
        path_str = self.query_one("#cook-mod-input", Input).value.strip()
        if path_str:
            p = Path(path_str)
            start_dir: Optional[Path] = p.parent if p.exists() else None
        else:
            orig_str = self.query_one("#cook-orig-input", Input).value.strip()
            if orig_str:
                p2 = Path(orig_str)
                start_dir = p2.parent if p2.exists() else _openremap_dir()
            else:
                start_dir = _openremap_dir()
        picked = _pick_file(
            start_dir, mode="bin", title="Select modified (tuned) binary"
        )
        if picked is not None:
            self.post_message(FilePickedForCookMod(picked))
        elif not shutil.which("zenity") and not shutil.which("kdialog"):
            self.app.call_from_thread(
                self.app.notify,
                _NO_PICKER_MSG,
                title="Browse",
                severity="warning",
            )

    @work(exclusive=True, thread=True)
    def _browse_output(self) -> None:
        out_str = self.query_one("#cook-output-input", Input).value.strip()
        orig_str = self.query_one("#cook-orig-input", Input).value.strip()
        if out_str:
            suggested = Path(out_str)
        elif orig_str:
            p = Path(orig_str)
            suggested = _recipes_dir() / (p.stem + "_recipe.openremap")
        else:
            suggested = _recipes_dir() / "recipe.openremap"
        picked = _pick_save_file(suggested, mode="json", title="Save recipe as…")
        if picked is not None:
            self.post_message(FilePickedForCookOutput(picked))
        elif not shutil.which("zenity") and not shutil.which("kdialog"):
            self.app.call_from_thread(
                self.app.notify,
                _NO_PICKER_MSG,
                title="Save as",
                severity="warning",
            )

    @work(exclusive=True, thread=True)
    def _do_cook(self, original: Path, modified: Path, output: Optional[Path]) -> None:
        try:
            original_data = original.read_bytes()
            modified_data = modified.read_bytes()
            analyzer = ECUDiffAnalyzer(
                original_data=original_data,
                modified_data=modified_data,
                original_filename=original.name,
                modified_filename=modified.name,
            )
            recipe = analyzer.build_recipe()
            if output:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(recipe, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            self.post_message(CookDone(recipe, output))
        except OSError as exc:
            self.post_message(CookFailed(f"File read error: {exc}"))
        except Exception as exc:
            self.post_message(CookFailed(str(exc)))

    # ── internals ────────────────────────────────────────────────────────────

    def _start_cook(self) -> None:
        orig_str = self.query_one("#cook-orig-input", Input).value.strip()
        mod_str = self.query_one("#cook-mod-input", Input).value.strip()
        out_str = self.query_one("#cook-output-input", Input).value.strip()

        if not orig_str or not mod_str:
            self.query_one("#cook-display", Static).update(
                Text(
                    "\n  ✗  Both original and modified paths are required.",
                    style="bold red",
                )
            )
            return

        orig = Path(orig_str)
        mod = Path(mod_str)
        # Default output: OpenRemap folder, named <orig_stem>_recipe.openremap
        out = (
            Path(out_str)
            if out_str
            else _recipes_dir() / (orig.stem + "_recipe.openremap")
        )

        for p, label in ((orig, "Original"), (mod, "Modified")):
            if not p.exists():
                self.query_one("#cook-display", Static).update(
                    Text(f"\n  ✗  {label} file not found: {p}", style="bold red")
                )
                return

        self.query_one("#btn-cook", Button).disabled = True
        self.query_one("#cook-display", Static).update(
            Text("\n  Cooking recipe…", style="dim")
        )
        self._do_cook(orig, mod, out)

    def _render_cook_result(self, recipe: dict, output_path: Optional[Path]) -> None:
        ecu = recipe.get("ecu", {})
        stats = recipe.get("statistics", {})
        meta = recipe.get("metadata", {})
        W = 22

        t = Text()
        t.append("\n  ✅  Recipe built successfully\n\n", style="bold green")

        rows = [
            ("ECU", f"{ecu.get('manufacturer', '?')}  ·  {ecu.get('ecu_family', '?')}"),
            ("Match Key", ecu.get("match_key", "n/a")),
            ("Format Version", meta.get("format_version", "?")),
            ("Instructions", f"{stats.get('total_changes', 0):,}"),
            ("Bytes Changed", f"{stats.get('total_bytes_changed', 0):,}"),
            ("Original", meta.get("original_file", "?")),
            ("Modified", meta.get("modified_file", "?")),
        ]
        for label, value in rows:
            t.append(f"  {label:<{W}}", style="dim")
            t.append(f"{value}\n", style="#c8d1e0")

        t.append("\n")
        if output_path:
            t.append(f"  Recipe saved to  ", style="dim")
            t.append(str(output_path) + "\n", style="bold #0ea5e9")
        else:
            t.append(
                "  No output path set — recipe was not saved to disk.\n",
                style="yellow",
            )

        t.append(
            "\n  ⚠  Remember to correct checksums before flashing.\n",
            style="bold yellow",
        )
        self.query_one("#cook-display", Static).update(t)


# ─────────────────────────────────────────────────────────────────────────────
# Tune panel
# ─────────────────────────────────────────────────────────────────────────────


class TunePanel(Vertical):
    """One-shot: validate → apply recipe → verify."""

    def compose(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("⟳  TUNE", classes="page-title")
            yield Static(
                "Select a target binary and a recipe, then press TUNE.",
                classes="page-desc",
            )
            with Horizontal(classes="three-col"):
                with Vertical(classes="field-col"):
                    yield Static("Target binary", classes="field-label")
                    yield Input(
                        placeholder="/path/to/target.bin", id="tune-target-input"
                    )
                    yield Button(
                        "📂  Browse target",
                        id="btn-browse-tune-target",
                        classes="btn-secondary",
                    )
                with Vertical(classes="field-col"):
                    yield Static("Recipe  (.openremap)", classes="field-label")
                    yield Input(
                        placeholder="/path/to/recipe.openremap", id="tune-recipe-input"
                    )
                    yield Button(
                        "📂  Browse recipe",
                        id="btn-browse-tune-recipe",
                        classes="btn-secondary",
                    )
                with Vertical(classes="field-col-last"):
                    yield Static("Output binary", classes="field-label")
                    yield Input(
                        placeholder="/path/to/output.bin", id="tune-output-input"
                    )
                    yield Button(
                        "💾  Save as…",
                        id="btn-browse-tune-output",
                        classes="btn-secondary",
                    )
            with Horizontal(classes="btn-row"):
                yield Button("TUNE", id="btn-tune", classes="btn-primary")
            with ScrollableContainer(id="tune-result"):
                yield Static(
                    Text(
                        "\n  No tune run yet.\n"
                        "  Select a target binary and a recipe, then press TUNE.",
                        style="dim",
                    ),
                    id="tune-display",
                )

    # ── events ───────────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-tune":
            event.stop()
            self._start_tune()
        elif event.button.id == "btn-browse-tune-target":
            event.stop()
            self._browse_target()
        elif event.button.id == "btn-browse-tune-recipe":
            event.stop()
            self._browse_recipe()
        elif event.button.id == "btn-browse-tune-output":
            event.stop()
            self._browse_tune_output()

    # ── message handlers ─────────────────────────────────────────────────────

    @on(TuneDone)
    def _handle_tune_done(self, message: TuneDone) -> None:
        self.query_one("#btn-tune", Button).disabled = False
        self._render_tune_result(message)

    @on(TuneFailed)
    def _handle_tune_failed(self, message: TuneFailed) -> None:
        self.query_one("#btn-tune", Button).disabled = False
        t = Text()
        t.append("\n  ✗  Tune failed\n\n", style="bold red")
        t.append(f"  {message.error}\n", style="red")
        self.query_one("#tune-display", Static).update(t)

    @on(FilePickedForTuneTarget)
    def _handle_target_picked(self, message: FilePickedForTuneTarget) -> None:
        self.query_one("#tune-target-input", Input).value = str(message.path)
        # Auto-fill output into the OpenRemap folder if still empty
        out_input = self.query_one("#tune-output-input", Input)
        if not out_input.value.strip():
            default = _tunes_dir() / (
                message.path.stem + "_tuned" + message.path.suffix
            )
            out_input.value = str(default)

    @on(FilePickedForTuneRecipe)
    def _handle_recipe_picked(self, message: FilePickedForTuneRecipe) -> None:
        self.query_one("#tune-recipe-input", Input).value = str(message.path)

    @on(FilePickedForTuneOutput)
    def _handle_tune_output_picked(self, message: FilePickedForTuneOutput) -> None:
        self.query_one("#tune-output-input", Input).value = str(message.path)

    # ── workers ──────────────────────────────────────────────────────────────

    @work(exclusive=True, thread=True)
    def _browse_target(self) -> None:
        path_str = self.query_one("#tune-target-input", Input).value.strip()
        if path_str:
            p = Path(path_str)
            start_dir: Optional[Path] = p.parent if p.exists() else None
        else:
            start_dir = _openremap_dir()
        picked = _pick_file(start_dir, mode="bin", title="Select target binary")
        if picked is not None:
            self.post_message(FilePickedForTuneTarget(picked))
        elif not shutil.which("zenity") and not shutil.which("kdialog"):
            self.app.call_from_thread(
                self.app.notify,
                _NO_PICKER_MSG,
                title="Browse",
                severity="warning",
            )

    @work(exclusive=True, thread=True)
    def _browse_recipe(self) -> None:
        path_str = self.query_one("#tune-recipe-input", Input).value.strip()
        if path_str:
            p = Path(path_str)
            start_dir: Optional[Path] = p.parent if p.exists() else None
        else:
            start_dir = _recipes_dir()
        picked = _pick_file(start_dir, mode="json", title="Select recipe")
        if picked is not None:
            self.post_message(FilePickedForTuneRecipe(picked))
        elif not shutil.which("zenity") and not shutil.which("kdialog"):
            self.app.call_from_thread(
                self.app.notify,
                _NO_PICKER_MSG,
                title="Browse",
                severity="warning",
            )

    @work(exclusive=True, thread=True)
    def _browse_tune_output(self) -> None:
        out_str = self.query_one("#tune-output-input", Input).value.strip()
        target_str = self.query_one("#tune-target-input", Input).value.strip()
        if out_str:
            suggested = Path(out_str)
        elif target_str:
            p = Path(target_str)
            suggested = _tunes_dir() / (p.stem + "_tuned" + p.suffix)
        else:
            suggested = _tunes_dir() / "output_tuned.bin"
        picked = _pick_save_file(suggested, mode="bin", title="Save tuned binary as…")
        if picked is not None:
            self.post_message(FilePickedForTuneOutput(picked))
        elif not shutil.which("zenity") and not shutil.which("kdialog"):
            self.app.call_from_thread(
                self.app.notify,
                _NO_PICKER_MSG,
                title="Save as",
                severity="warning",
            )

    @work(exclusive=True, thread=True)
    def _do_tune(
        self,
        target: Path,
        recipe_path: Path,
        output: Optional[Path],
    ) -> None:
        try:
            target_data = target.read_bytes()
        except OSError as exc:
            self.post_message(TuneFailed(f"Cannot read target: {exc}"))
            return
        try:
            recipe_dict = json.loads(recipe_path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.post_message(TuneFailed(f"Cannot read recipe: {exc}"))
            return

        output_path: Path = output or (
            target.parent / (target.stem + "_tuned" + target.suffix)
        )

        # ── Phase 1 — validate before ─────────────────────────────────────
        try:
            v1 = ECUStrictValidator(
                target_data=target_data,
                recipe=recipe_dict,
                target_name=target.name,
                recipe_name=recipe_path.name,
            )
            v1.validate_all()
            p1_report = v1.to_dict()
            p1_ok = p1_report.get("summary", {}).get("safe_to_patch", False)
        except Exception as exc:
            self.post_message(TuneFailed(f"Phase 1 error: {exc}"))
            return

        if not p1_ok:
            self.post_message(
                TuneDone(False, False, False, p1_report, {}, {}, output_path)
            )
            return

        # ── Phase 2 — apply ───────────────────────────────────────────────
        try:
            patcher = ECUPatcher(
                target_data=target_data,
                recipe=recipe_dict,
                target_name=target.name,
                recipe_name=recipe_path.name,
                skip_validation=True,
            )
            tuned_bytes = patcher.apply_all()
            p2_report = patcher.to_dict(patched_data=tuned_bytes)
            p2_ok = p2_report.get("summary", {}).get("patch_applied", False)
        except Exception as exc:
            self.post_message(TuneFailed(f"Phase 2 error: {exc}"))
            return

        if not p2_ok:
            self.post_message(
                TuneDone(p1_ok, False, False, p1_report, p2_report, {}, output_path)
            )
            return

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(tuned_bytes)
        except OSError as exc:
            self.post_message(TuneFailed(f"Cannot write output: {exc}"))
            return

        # ── Phase 3 — validate after ──────────────────────────────────────
        try:
            v3 = ECUPatchedValidator(
                patched_data=tuned_bytes,
                recipe=recipe_dict,
                patched_name=output_path.name,
                recipe_name=recipe_path.name,
            )
            v3.verify_all()
            p3_report = v3.to_dict()
            p3_ok = p3_report.get("summary", {}).get("patch_confirmed", False)
        except Exception as exc:
            self.post_message(TuneFailed(f"Phase 3 error: {exc}"))
            return

        self.post_message(
            TuneDone(p1_ok, p2_ok, p3_ok, p1_report, p2_report, p3_report, output_path)
        )

    # ── internals ────────────────────────────────────────────────────────────

    def _start_tune(self) -> None:
        target_str = self.query_one("#tune-target-input", Input).value.strip()
        recipe_str = self.query_one("#tune-recipe-input", Input).value.strip()
        out_str = self.query_one("#tune-output-input", Input).value.strip()

        if not target_str or not recipe_str:
            self.query_one("#tune-display", Static).update(
                Text(
                    "\n  ✗  Target binary and recipe are both required.",
                    style="bold red",
                )
            )
            return

        target = Path(target_str)
        recipe = Path(recipe_str)
        out = (
            Path(out_str)
            if out_str
            else _tunes_dir() / (target.stem + "_tuned" + target.suffix)
        )

        for p, label in ((target, "Target"), (recipe, "Recipe")):
            if not p.exists():
                self.query_one("#tune-display", Static).update(
                    Text(f"\n  ✗  {label} not found: {p}", style="bold red")
                )
                return

        self.query_one("#btn-tune", Button).disabled = True
        self.query_one("#tune-display", Static).update(
            Text("\n  Running tune…", style="dim")
        )
        self._do_tune(target, recipe, out)

    def _render_tune_result(self, msg: TuneDone) -> None:
        t = Text()
        t.append("\n")

        def _phase_line(num: int, label: str, ok: Optional[bool]) -> None:
            if ok is True:
                t.append(f"  ✅  Phase {num} — {label}\n", style="bold green")
            elif ok is False:
                t.append(f"  ❌  Phase {num} — {label}\n", style="bold red")
            else:
                t.append(f"  ○   Phase {num} — {label}\n", style="dim")

        p2_ran = bool(msg.p2_report)
        p3_ran = bool(msg.p3_report)
        all_ok = msg.p1_ok and msg.p2_ok and msg.p3_ok

        # ── 1. phase checklist (always visible at top) ────────────────────
        _phase_line(1, "Pre-flight check  (validate before)", msg.p1_ok)
        _phase_line(2, "Apply recipe", msg.p2_ok if p2_ran else None)
        _phase_line(
            3, "Post-tune verification  (validate after)", msg.p3_ok if p3_ran else None
        )

        t.append("\n")

        # ── 2. final status + warning (visible without scrolling) ─────────
        if all_ok:
            t.append("  ✅  Tune complete\n", style="bold green")
            t.append("  Output  ", style="dim")
            t.append(f"{msg.output_path}\n", style="bold #0ea5e9")

            W = 58
            border = "═" * W
            t.append(f"\n  ╔{border}╗\n", style="bold yellow")
            t.append(f"  ║  ⚠  CHECKSUM WARNING{'':<{W - 20}}║\n", style="bold yellow")
            t.append(f"  ║{'':<{W + 2}}║\n", style="yellow")
            t.append(
                f"  ║  This binary has NOT had its checksums corrected.{'':<{W - 50}}║\n",
                style="bold yellow",
            )
            t.append(
                f"  ║  Flashing without fixing them may damage the ECU.{'':<{W - 50}}║\n",
                style="yellow",
            )
            t.append(f"  ║{'':<{W + 2}}║\n", style="yellow")
            t.append(
                f"  ║  Correct checksums first using a dedicated tool:{'':<{W - 49}}║\n",
                style="yellow",
            )
            t.append(
                f"  ║    •  ECM Titanium    •  WinOLS    •  MPPS    •  Flex{'':<{W - 53}}║\n",
                style="bold yellow",
            )
            t.append(f"  ║{'':<{W + 2}}║\n", style="yellow")
            t.append(f"  ╚{border}╝\n", style="bold yellow")

        elif not msg.p1_ok:
            t.append(
                "  ❌  Pre-flight failed — binary does not match recipe.\n"
                "     Run Validate → Before to diagnose.\n",
                style="bold red",
            )
        elif not msg.p2_ok:
            t.append(
                "  ❌  Apply failed — some instructions could not be written.\n",
                style="bold red",
            )
        else:
            t.append(
                "  ⚠  Applied but post-tune verification failed.\n"
                "     Do NOT flash this binary.\n",
                style="bold red",
            )

        # ── 3. phase details (below the fold, scroll to read) ─────────────
        if any([msg.p1_report, msg.p2_report, msg.p3_report]):
            t.append("\n  ── Details " + "─" * 48 + "\n", style="dim")

        if msg.p1_report:
            s1 = msg.p1_report.get("summary", {})
            W = 22
            t.append("\n  ── Phase 1\n", style="dim")
            t.append(f"  {'Instructions':<{W}}", style="dim")
            t.append(f"{s1.get('total', 0):,}\n", style="#c8d1e0")
            t.append(f"  {'Passed':<{W}}", style="dim")
            passed = s1.get("passed", 0)
            total = s1.get("total", 0)
            t.append(
                str(passed) + "\n", style="green" if passed == total else "#c8d1e0"
            )
            failed = s1.get("failed", 0)
            if failed:
                t.append(f"  {'Failed':<{W}}", style="dim")
                t.append(f"{failed}\n", style="bold red")

        if msg.p2_report:
            s2 = msg.p2_report.get("summary", {})
            W = 22
            t.append("\n  ── Phase 2\n", style="dim")
            t.append(f"  {'Applied':<{W}}", style="dim")
            applied = s2.get("success", 0)
            total2 = s2.get("total", 0)
            t.append(
                f"{applied}/{total2}\n",
                style="green" if applied == total2 else "#c8d1e0",
            )
            shifted = s2.get("shifted", 0)
            if shifted:
                t.append(f"  {'Shifted (recovered)':<{W}}", style="dim")
                t.append(f"{shifted}\n", style="yellow")

        if msg.p3_report:
            s3 = msg.p3_report.get("summary", {})
            W = 22
            t.append("\n  ── Phase 3\n", style="dim")
            t.append(f"  {'Confirmed':<{W}}", style="dim")
            confirmed = s3.get("passed", 0)
            total3 = s3.get("total", 0)
            t.append(
                f"{confirmed}/{total3}\n",
                style="green" if confirmed == total3 else "red",
            )

        self.query_one("#tune-display", Static).update(t)


# ─────────────────────────────────────────────────────────────────────────────
# Validate panel
# ─────────────────────────────────────────────────────────────────────────────

_VALIDATE_MODES = ("before", "check", "after")
_VALIDATE_LABELS = {
    "before": "Before  — ob bytes at recorded offsets (run before tuning)",
    "check": "Check   — search entire binary for ob bytes (diagnose failures)",
    "after": "After   — confirm mb bytes were written (run after tuning)",
}
_VALIDATE_BIN_LABEL = {
    "before": "Target binary  (.bin or .ori)",
    "check": "Target binary  (.bin or .ori)",
    "after": "Tuned binary   (.bin or .ori)",
}


class ValidatePanel(Vertical):
    """Run validate before / check / after against a recipe."""

    _mode: str = "before"

    def compose(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("✔  VALIDATE", classes="page-title")
            yield Static(
                "Choose a mode, select a binary and a recipe, then press VALIDATE.",
                classes="page-desc",
            )
            # ── mode toggle ───────────────────────────────────────────────
            with Horizontal(classes="mode-row"):
                yield Button(
                    "Before", id="mode-btn-before", classes="mode-btn mode-btn-active"
                )
                yield Button("Check", id="mode-btn-check", classes="mode-btn")
                yield Button("After", id="mode-btn-after", classes="mode-btn")
            yield Static(
                _VALIDATE_LABELS["before"], id="validate-mode-desc", classes="mode-desc"
            )
            # ── inputs ────────────────────────────────────────────────────
            yield Static(
                _VALIDATE_BIN_LABEL["before"],
                id="validate-bin-label",
                classes="field-label",
            )
            yield Input(placeholder="/path/to/target.bin", id="validate-bin-input")
            with Horizontal(classes="btn-row"):
                yield Button(
                    "📂  Browse binary",
                    id="btn-browse-validate-bin",
                    classes="btn-secondary",
                )
            yield Static("Recipe  (.openremap)", classes="field-label")
            yield Input(
                placeholder="/path/to/recipe.openremap", id="validate-recipe-input"
            )
            with Horizontal(classes="btn-row"):
                yield Button(
                    "📂  Browse recipe",
                    id="btn-browse-validate-recipe",
                    classes="btn-secondary",
                )
            with Horizontal(classes="btn-row"):
                yield Button("VALIDATE", id="btn-validate", classes="btn-primary")
            with ScrollableContainer(id="validate-result"):
                yield Static(
                    Text(
                        "\n  No validation run yet.\n"
                        "  Choose a mode, fill in the paths, and press VALIDATE.",
                        style="dim",
                    ),
                    id="validate-display",
                )

    # ── events ───────────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid.startswith("mode-btn-"):
            event.stop()
            self._set_mode(bid[len("mode-btn-") :])
        elif bid == "btn-validate":
            event.stop()
            self._start_validate()
        elif bid == "btn-browse-validate-bin":
            event.stop()
            self._browse_bin()
        elif bid == "btn-browse-validate-recipe":
            event.stop()
            self._browse_recipe()

    # ── message handlers ─────────────────────────────────────────────────────

    @on(ValidateDone)
    def _handle_validate_done(self, message: ValidateDone) -> None:
        self.query_one("#btn-validate", Button).disabled = False
        self._render_validate_result(message.mode, message.report)

    @on(ValidateFailed)
    def _handle_validate_failed(self, message: ValidateFailed) -> None:
        self.query_one("#btn-validate", Button).disabled = False
        t = Text()
        t.append("\n  ✗  Validation error\n\n", style="bold red")
        t.append(f"  {message.error}\n", style="red")
        self.query_one("#validate-display", Static).update(t)

    @on(FilePickedForValidateBin)
    def _handle_bin_picked(self, message: FilePickedForValidateBin) -> None:
        self.query_one("#validate-bin-input", Input).value = str(message.path)

    @on(FilePickedForValidateRecipe)
    def _handle_recipe_picked(self, message: FilePickedForValidateRecipe) -> None:
        self.query_one("#validate-recipe-input", Input).value = str(message.path)

    # ── workers ──────────────────────────────────────────────────────────────

    @work(exclusive=True, thread=True)
    def _browse_bin(self) -> None:
        path_str = self.query_one("#validate-bin-input", Input).value.strip()
        if path_str:
            p = Path(path_str)
            start_dir: Optional[Path] = p.parent if p.exists() else None
        else:
            start_dir = _openremap_dir()
        picked = _pick_file(start_dir, mode="bin", title="Select ECU binary")
        if picked is not None:
            self.post_message(FilePickedForValidateBin(picked))
        elif not shutil.which("zenity") and not shutil.which("kdialog"):
            self.app.call_from_thread(
                self.app.notify,
                _NO_PICKER_MSG,
                title="Browse",
                severity="warning",
            )

    @work(exclusive=True, thread=True)
    def _browse_recipe(self) -> None:
        path_str = self.query_one("#validate-recipe-input", Input).value.strip()
        if path_str:
            p = Path(path_str)
            start_dir: Optional[Path] = p.parent if p.exists() else None
        else:
            start_dir = _recipes_dir()
        picked = _pick_file(start_dir, mode="json", title="Select recipe")
        if picked is not None:
            self.post_message(FilePickedForValidateRecipe(picked))
        elif not shutil.which("zenity") and not shutil.which("kdialog"):
            self.app.call_from_thread(
                self.app.notify,
                _NO_PICKER_MSG,
                title="Browse",
                severity="warning",
            )

    @work(exclusive=True, thread=True)
    def _do_validate(self, mode: str, bin_path: Path, recipe_path: Path) -> None:
        try:
            bin_data = bin_path.read_bytes()
        except OSError as exc:
            self.post_message(ValidateFailed(f"Cannot read binary: {exc}"))
            return
        try:
            recipe_dict = json.loads(recipe_path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.post_message(ValidateFailed(f"Cannot read recipe: {exc}"))
            return

        try:
            if mode == "before":
                v = ECUStrictValidator(
                    target_data=bin_data,
                    recipe=recipe_dict,
                    target_name=bin_path.name,
                    recipe_name=recipe_path.name,
                )
                v.validate_all()
                report = v.to_dict()

            elif mode == "check":
                v = ECUExistenceValidator(
                    target_data=bin_data,
                    recipe=recipe_dict,
                    target_name=bin_path.name,
                    recipe_name=recipe_path.name,
                )
                v.validate_all()
                report = v.to_dict()

            else:  # after
                v = ECUPatchedValidator(
                    patched_data=bin_data,
                    recipe=recipe_dict,
                    patched_name=bin_path.name,
                    recipe_name=recipe_path.name,
                )
                v.verify_all()
                report = v.to_dict()

        except Exception as exc:
            self.post_message(ValidateFailed(str(exc)))
            return

        self.post_message(ValidateDone(mode, report))

    # ── internals ────────────────────────────────────────────────────────────

    def _set_mode(self, mode: str) -> None:
        if mode not in _VALIDATE_MODES:
            return
        self._mode = mode
        for m in _VALIDATE_MODES:
            btn = self.query_one(f"#mode-btn-{m}", Button)
            if m == mode:
                btn.add_class("mode-btn-active")
            else:
                btn.remove_class("mode-btn-active")
        self.query_one("#validate-mode-desc", Static).update(_VALIDATE_LABELS[mode])
        self.query_one("#validate-bin-label", Static).update(_VALIDATE_BIN_LABEL[mode])

    def _start_validate(self) -> None:
        bin_str = self.query_one("#validate-bin-input", Input).value.strip()
        recipe_str = self.query_one("#validate-recipe-input", Input).value.strip()

        if not bin_str or not recipe_str:
            self.query_one("#validate-display", Static).update(
                Text(
                    "\n  ✗  Binary and recipe paths are both required.",
                    style="bold red",
                )
            )
            return

        bin_path = Path(bin_str)
        recipe_path = Path(recipe_str)

        for p, label in ((bin_path, "Binary"), (recipe_path, "Recipe")):
            if not p.exists():
                self.query_one("#validate-display", Static).update(
                    Text(f"\n  ✗  {label} not found: {p}", style="bold red")
                )
                return

        self.query_one("#btn-validate", Button).disabled = True
        self.query_one("#validate-display", Static).update(
            Text("\n  Validating…", style="dim")
        )
        self._do_validate(self._mode, bin_path, recipe_path)

    def _render_validate_result(self, mode: str, report: dict) -> None:  # noqa: C901
        t = Text()
        t.append("\n")
        W = 22

        if mode == "before":
            summary = report.get("summary", {})
            safe = summary.get("safe_to_patch", False)
            passed = summary.get("passed", 0)
            failed = summary.get("failed", 0)
            total = summary.get("total", 0)

            if safe:
                t.append("  ✅  Safe to tune\n\n", style="bold green")
            else:
                t.append("  ❌  NOT safe to tune\n\n", style="bold red")

            t.append(f"  {'Target':<{W}}", style="dim")
            t.append(f"{report.get('target_file', '?')}\n", style="#c8d1e0")
            t.append(f"  {'MD5':<{W}}", style="dim")
            t.append(f"{report.get('target_md5', '?')}\n", style="#c8d1e0")
            t.append(f"  {'Instructions':<{W}}", style="dim")
            t.append(f"{total:,}\n", style="#c8d1e0")
            t.append(f"  {'Passed':<{W}}", style="dim")
            t.append(f"{passed}\n", style="green" if passed == total else "#c8d1e0")
            if failed:
                t.append(f"  {'Failed':<{W}}", style="dim")
                t.append(f"{failed}\n", style="bold red")
                failed_results = [
                    r for r in report.get("results", []) if not r.get("passed", True)
                ]
                if failed_results:
                    t.append("\n  Failed instructions:\n", style="bold red")
                    for r in failed_results[:10]:
                        idx = r.get("index", r.get("instruction_index", "?"))
                        off = r.get("offset_expected_hex", r.get("offset", "?"))
                        msg = r.get(
                            "message", r.get("reason", "ob not found at offset")
                        )
                        t.append(f"    #{idx!s:>4}  {off}  — {msg}\n", style="red")
                    if len(failed_results) > 10:
                        t.append(
                            f"    … and {len(failed_results) - 10} more.\n",
                            style="dim",
                        )
            if not safe:
                t.append(
                    "\n  Tip: switch to Check mode to find ob bytes elsewhere.\n",
                    style="dim",
                )

        elif mode == "check":
            summary = report.get("summary", {})
            verdict = summary.get("verdict", "unknown")
            total = summary.get("total", 0)
            exact = summary.get("exact", 0)
            shifted = summary.get("shifted", 0)
            missing = summary.get("missing", 0)

            verdict_colour = {
                "safe_exact": "bold green",
                "shifted_recoverable": "bold yellow",
                "missing_unrecoverable": "bold red",
            }.get(verdict, "bold white")
            t.append(f"  Verdict: ", style="dim")
            t.append(verdict.replace("_", " ").upper() + "\n\n", style=verdict_colour)

            t.append(f"  {'Target':<{W}}", style="dim")
            t.append(f"{report.get('target_file', '?')}\n", style="#c8d1e0")
            t.append(f"  {'MD5':<{W}}", style="dim")
            t.append(f"{report.get('target_md5', '?')}\n", style="#c8d1e0")
            t.append(f"  {'Instructions':<{W}}", style="dim")
            t.append(f"{total:,}\n", style="#c8d1e0")
            t.append(f"  {'Exact':<{W}}", style="dim")
            t.append(f"{exact}\n", style="green" if exact else "#c8d1e0")
            if shifted:
                t.append(f"  {'Shifted':<{W}}", style="dim")
                t.append(f"{shifted}\n", style="yellow")
            if missing:
                t.append(f"  {'Missing':<{W}}", style="dim")
                t.append(f"{missing}\n", style="bold red")

            shifted_results = [
                r
                for r in report.get("results", [])
                if r.get("status") == MatchStatus.SHIFTED.value
            ]
            if shifted_results:
                t.append("\n  Shifted instructions:\n", style="bold yellow")
                for r in shifted_results:
                    shift_val = r.get("shift", 0)
                    direction = f"+{shift_val}" if shift_val >= 0 else str(shift_val)
                    t.append(
                        f"    #{r['instruction_index']:>4}  "
                        f"expected {r['offset_hex_expected']}  "
                        f"→  shift {direction}\n",
                        style="yellow",
                    )

            missing_results = [
                r
                for r in report.get("results", [])
                if r.get("status") == MatchStatus.MISSING.value
            ]
            if missing_results:
                t.append("\n  Missing instructions:\n", style="bold red")
                for r in missing_results:
                    t.append(
                        f"    #{r['instruction_index']:>4}  "
                        f"expected {r['offset_hex_expected']}  "
                        f"size {r['size']} bytes — not found\n",
                        style="red",
                    )

        else:  # after
            summary = report.get("summary", {})
            confirmed = summary.get("patch_confirmed", False)
            passed = summary.get("passed", 0)
            failed = summary.get("failed", 0)
            total = summary.get("total", 0)

            if confirmed:
                t.append(
                    "  ✅  Tune confirmed — all mb bytes verified\n\n",
                    style="bold green",
                )
            else:
                t.append("  ❌  Tune NOT confirmed\n\n", style="bold red")

            t.append(f"  {'Tuned file':<{W}}", style="dim")
            t.append(f"{report.get('patched_file', '?')}\n", style="#c8d1e0")
            t.append(f"  {'MD5':<{W}}", style="dim")
            t.append(f"{report.get('patched_md5', '?')}\n", style="#c8d1e0")
            t.append(f"  {'Instructions':<{W}}", style="dim")
            t.append(f"{total:,}\n", style="#c8d1e0")
            t.append(f"  {'Confirmed':<{W}}", style="dim")
            t.append(f"{passed}\n", style="green" if passed == total else "#c8d1e0")
            if failed:
                t.append(f"  {'Failed':<{W}}", style="dim")
                t.append(f"{failed}\n", style="bold red")
                failures = [
                    r for r in report.get("all_results", []) if not r.get("passed")
                ]
                if failures:
                    t.append("\n  Failed instructions:\n", style="bold red")
                    for r in failures:
                        t.append(
                            f"    #{r['instruction_index']:>4}  "
                            f"offset 0x{r['offset_hex']}  "
                            f"size {r['size']} bytes — {r['reason']}\n",
                            style="red",
                        )

        self.query_one("#validate-display", Static).update(t)


# ─────────────────────────────────────────────────────────────────────────────
# Families panel
# ─────────────────────────────────────────────────────────────────────────────


class FamiliesPanel(Vertical):
    """Browse all registered ECU families."""

    def compose(self) -> ComposeResult:
        with Vertical(classes="panel"):
            yield Static("≡  FAMILIES", classes="page-title")
            yield Static(
                "All ECU families currently registered in this installation.",
                classes="page-desc",
            )
            yield DataTable(id="families-table", show_cursor=True, zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one("#families-table", DataTable)
        col_mfr, col_family, _col_sub = table.add_columns(
            "Manufacturer", "Family", "# Sub-variants"
        )
        for extractor in EXTRACTORS:
            for family in extractor.supported_families:
                table.add_row(
                    extractor.name,
                    family,
                    str(len(extractor.supported_families)),
                )
        table.sort(col_mfr, col_family)


# ─────────────────────────────────────────────────────────────────────────────
# About panel
# ─────────────────────────────────────────────────────────────────────────────


class AboutPanel(Vertical):
    """Project information and CLI quick-reference."""

    def compose(self) -> ComposeResult:
        from importlib.metadata import PackageNotFoundError
        from importlib.metadata import version as _ver

        try:
            v = _ver("openremap")
        except PackageNotFoundError:
            v = "dev"

        extractors_count = len(EXTRACTORS)
        families_count = sum(len(e.supported_families) for e in EXTRACTORS)

        t = Text()

        t.append("\n  OpenRemap", style="bold #ff6d00")
        t.append(f"  v{v}\n", style="dim")
        t.append("  ─" * 26 + "\n\n", style="dim")

        t.append(
            "  ECU binary analysis and patching toolkit.\n"
            "  Diff, validate, and apply tuning recipes to automotive\n"
            "  ECU binaries — no running server required.\n\n",
            style="#c8d1e0",
        )

        t.append(f"  {'Registered extractors':<24}", style="dim")
        t.append(f"{extractors_count}\n", style="#c8d1e0")
        t.append(f"  {'Supported families':<24}", style="dim")
        t.append(f"{families_count}\n\n", style="#c8d1e0")

        t.append("  ─" * 26 + "\n\n", style="dim")
        t.append("  Links\n\n", style="bold #c8d1e0")
        t.append(f"  {'GitHub':<24}", style="dim")
        t.append("https://github.com/Openremap/openremap-core\n", style="bold #0ea5e9")
        t.append(f"  {'PyPI':<24}", style="dim")
        t.append("pip install openremap\n\n", style="bold #0ea5e9")

        t.append("  ─" * 26 + "\n\n", style="dim")
        t.append("  CLI Quick Reference\n\n", style="bold #c8d1e0")

        cli_commands = [
            ("identify", "openremap identify ecu.bin"),
            ("scan", "openremap scan ./bins/ --move --organize"),
            ("cook", "openremap cook stock.bin tuned.bin -o recipe.json"),
            ("tune", "openremap tune target.bin recipe.json"),
            ("validate", "openremap validate before target.bin recipe.json"),
            ("families", "openremap families"),
            ("workflow", "openremap workflow"),
        ]
        W = 12
        for label, cmd in cli_commands:
            t.append(f"  {label:<{W}}", style="dim")
            t.append(f"{cmd}\n", style="green")

        t.append("\n  ─" * 26 + "\n\n", style="dim")
        t.append(
            "  ⚠  Always correct checksums with a dedicated tool\n"
            "     (ECM Titanium, WinOLS, etc.) before flashing.\n"
            "     OpenRemap does NOT calculate or correct checksums.\n",
            style="bold yellow",
        )

        with ScrollableContainer(id="about-scroll"):
            yield Static(t, id="about-content")


# ─────────────────────────────────────────────────────────────────────────────
# Navigation
# ─────────────────────────────────────────────────────────────────────────────

_NAV: list[tuple[str, str, str]] = [
    ("identify", "⚡  Identify", "1"),
    ("scan", "⬡  Scan", "2"),
    ("cook", "⚗  Cook", "3"),
    ("tune", "⟳  Tune", "4"),
    ("validate", "✔  Validate", "5"),
    ("families", "≡  Families", "6"),
    ("about", "ℹ  About", "7"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Root application
# ─────────────────────────────────────────────────────────────────────────────


class OpenRemapTUI(App):
    CSS_PATH = str(pathlib.Path(__file__).parent / "theme.tcss")

    TITLE = "OpenRemap"
    SUB_TITLE = "ECU Toolkit"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("1", "nav('identify')", "Identify"),
        ("2", "nav('scan')", "Scan"),
        ("3", "nav('cook')", "Cook"),
        ("4", "nav('tune')", "Tune"),
        ("5", "nav('validate')", "Validate"),
        ("6", "nav('families')", "Families"),
        ("7", "nav('about')", "About"),
    ]

    _current_section: str = "identify"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)

        with Horizontal(id="main-layout"):
            # ── Sidebar ───────────────────────────────────────────────────
            with Vertical(id="sidebar"):
                yield Static(
                    Text.from_markup(
                        "[bold #ff6d00]⚡ OpenRemap[/]\n[dim]  ECU Toolkit[/]"
                    ),
                    id="brand",
                )
                with Vertical(id="nav-items"):
                    for section_id, label, _key in _NAV:
                        yield Button(
                            label,
                            id=f"nav-{section_id}",
                            classes="nav-item",
                        )
                yield Static("", classes="sidebar-spacer")
                yield Static(
                    Text("  v" + _get_version(), style="dim"),
                    id="sidebar-version",
                )

            # ── Content ───────────────────────────────────────────────────
            with ContentSwitcher(initial="identify", id="content"):
                yield IdentifyPanel(id="identify")
                yield ScanPanel(id="scan")
                yield CookPanel(id="cook")
                yield TunePanel(id="tune")
                yield ValidatePanel(id="validate")
                yield FamiliesPanel(id="families")
                yield AboutPanel(id="about")

        yield Footer()

    def on_mount(self) -> None:
        self._activate_nav("identify")
        # Ensure the OpenRemap working directories exist from the first launch
        _openremap_dir()
        _recipes_dir()
        _tunes_dir()
        _ecus_dir()

    # ── nav button clicks ─────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id.startswith("nav-"):
            section = btn_id[4:]
            self._switch_to(section)
            event.stop()

    # ── keyboard actions ──────────────────────────────────────────────────

    def action_nav(self, section: str) -> None:
        self._switch_to(section)

    # ── helpers ───────────────────────────────────────────────────────────

    def _switch_to(self, section: str) -> None:
        if section not in {sid for sid, _, _ in _NAV}:
            return
        self._current_section = section
        self.query_one(ContentSwitcher).current = section
        self._activate_nav(section)

    def _activate_nav(self, active: str) -> None:
        for section_id, _, _ in _NAV:
            btn = self.query_one(f"#nav-{section_id}", Button)
            if section_id == active:
                btn.add_class("nav-active")
            else:
                btn.remove_class("nav-active")


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _get_version() -> str:
    try:
        from importlib.metadata import version

        return version("openremap")
    except Exception:
        return "dev"
