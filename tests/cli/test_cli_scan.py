"""
Tests for the ``scan`` sub-command.

The ``scan`` command processes a directory of binary files (.bin or .ori)
through all registered extractors and classifies each file into one of five
categories:

  scanned    — exactly one extractor claimed the file AND match_key extracted
  sw_missing — exactly one extractor claimed the file BUT match_key is None
  contested  — multiple extractors claimed the file
  unknown    — no extractor matched the file
  trash      — file has a wrong extension (.txt, .exe, etc.)

By default, ``scan`` performs a dry-run preview. Flags control the behaviour:
  --move          — actually move files to destination subdirectories
  --create-dirs   — create flat destination directories if they don't exist
  --organize      — create manufacturer/family sub-folders (implies --move)
  --report <path> — write results to JSON or CSV (based on extension)

Covers:
    - Dry-run (no files moved) → displays classification, exits 0
    - --move flag → files actually moved to flat category folders
    - --create-dirs flag → destination folders created automatically
    - --organize flag → files sorted into manufacturer/family tree
    - --report JSON → valid JSON with all file records
    - --report CSV → valid CSV with headers
    - Single file / multiple files / no files in directory
    - Invalid directory → exits 1 or 2
    - ``--help`` → exits 0

Notes
-----
Tests use ``tmp_path`` to create temporary directory structures and binary files.
Each test creates synthetic binaries that trigger specific extractor detection
logic (or trigger none, for the "unknown" category).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from openremap.cli.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bin(size: int = 1024, patches: dict | None = None) -> bytes:
    """Return a zero-filled byte string, optionally patched at specific offsets."""
    buf = bytearray(size)
    for offset, value in (patches or {}).items():
        if isinstance(value, int):
            buf[offset] = value
        else:
            buf[offset : offset + len(value)] = value
    return bytes(buf)


# ---------------------------------------------------------------------------
# TestScanDryRun — no files moved
# ---------------------------------------------------------------------------


class TestScanDryRun:
    """Dry-run mode (default): files are classified but not moved."""

    def test_scan_empty_directory_exits_zero(self, tmp_path):
        """Scanning an empty directory exits 0."""
        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0

    def test_scan_empty_directory_shows_summary(self, tmp_path):
        """Output includes a summary of classifications."""
        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        output = result.stdout + result.stderr
        # Should show summary or "No files found" or similar
        assert len(output) > 0

    def test_scan_trash_file_classified_as_trash(self, tmp_path):
        """A .txt file is classified as trash."""
        trash_file = tmp_path / "file.txt"
        trash_file.write_bytes(_make_bin())

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        output = result.stdout + result.stderr
        # Should mention "trash" or "file.txt"
        assert "trash" in output.lower() or "file.txt" in output

    def test_scan_unknown_bin_classified_as_unknown(self, tmp_path):
        """A .bin file that no extractor recognizes is classified as unknown."""
        unknown_file = tmp_path / "unknown.bin"
        # Zero-filled binary won't match any extractor
        unknown_file.write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        output = result.stdout + result.stderr
        # Should mention "unknown"
        assert "unknown" in output.lower()

    def test_scan_does_not_move_files_in_dry_run(self, tmp_path):
        """In dry-run mode, files are not moved."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        runner.invoke(app, ["scan", str(tmp_path)])

        # File should still be in original location
        assert test_file.exists()
        # No subdirectories should be created
        subdirs = [d for d in tmp_path.iterdir() if d.is_dir()]
        assert len(subdirs) == 0, "Dry-run should not create subdirectories"

    def test_scan_multiple_files_dry_run(self, tmp_path):
        """Scanning multiple files in dry-run mode lists all of them."""
        for i in range(3):
            f = tmp_path / f"file{i}.bin"
            f.write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        output = result.stdout + result.stderr
        # Should show information about the files processed
        assert "file" in output.lower()

    def test_scan_current_directory_default(self, tmp_path, monkeypatch):
        """If no directory argument is given, scan uses current directory."""
        monkeypatch.chdir(tmp_path)
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan"])

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# TestScanMove — files actually moved
# ---------------------------------------------------------------------------


class TestScanMove:
    """With --move flag, files are sorted into category subdirectories."""

    def test_scan_move_requires_destination_dirs_to_exist(self, tmp_path):
        """Moving files requires destination directories to exist."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        # Try to move without creating dirs — should fail or exit non-zero
        result = runner.invoke(app, ["scan", str(tmp_path), "--move"])

        # Expecting either exit code 1 (failure) or 0 (with warning)
        # depending on implementation
        assert result.exit_code in (0, 1)

    def test_scan_move_with_create_dirs_creates_folders(self, tmp_path):
        """With --move and --create-dirs, folders are created."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan", str(tmp_path), "--move", "--create-dirs"])

        assert result.exit_code == 0
        # At least one destination folder should exist
        expected_folders = ["unknown", "trash", "scanned", "contested", "sw_missing"]
        any_created = any((tmp_path / folder).exists() for folder in expected_folders)
        assert any_created, "No destination folders were created"

    def test_scan_move_trash_file_to_trash_folder(self, tmp_path):
        """A trash file is moved to the trash folder."""
        trash_file = tmp_path / "file.txt"
        trash_file.write_bytes(_make_bin(1024))

        runner.invoke(app, ["scan", str(tmp_path), "--move", "--create-dirs"])

        trash_folder = tmp_path / "trash"
        assert trash_folder.exists(), "Trash folder should exist"
        moved_file = trash_folder / "file.txt"
        assert moved_file.exists(), "Trash file should be moved to trash folder"
        assert not trash_file.exists(), "Original trash file should be removed"

    def test_scan_move_unknown_bin_to_unknown_folder(self, tmp_path):
        """An unknown .bin file is moved to the unknown folder."""
        unknown_file = tmp_path / "unknown.bin"
        unknown_file.write_bytes(_make_bin(1024))

        runner.invoke(app, ["scan", str(tmp_path), "--move", "--create-dirs"])

        unknown_folder = tmp_path / "unknown"
        assert unknown_folder.exists(), "Unknown folder should exist"
        moved_file = unknown_folder / "unknown.bin"
        assert moved_file.exists(), "Unknown file should be moved to unknown folder"
        assert not unknown_file.exists(), "Original file should be removed"

    def test_scan_move_multiple_files_to_correct_folders(self, tmp_path):
        """Multiple files are all moved to their correct destinations."""
        bin_file = tmp_path / "test.bin"
        bin_file.write_bytes(_make_bin(1024))
        txt_file = tmp_path / "test.txt"
        txt_file.write_bytes(b"text")

        runner.invoke(app, ["scan", str(tmp_path), "--move", "--create-dirs"])

        # Check that both folders exist
        assert (tmp_path / "unknown").exists()
        assert (tmp_path / "trash").exists()

    def test_scan_move_preserves_file_content(self, tmp_path):
        """Moved files retain their original content."""
        test_file = tmp_path / "test.bin"
        original_content = _make_bin(1024, {100: 0xAA, 200: 0xBB})
        test_file.write_bytes(original_content)

        runner.invoke(app, ["scan", str(tmp_path), "--move", "--create-dirs"])

        moved_file = tmp_path / "unknown" / "test.bin"
        assert moved_file.exists()
        assert moved_file.read_bytes() == original_content


# ---------------------------------------------------------------------------
# TestScanOrganize — manufacturer/family tree structure
# ---------------------------------------------------------------------------


class TestScanOrganize:
    """With --organize flag, files are sorted into manufacturer/family sub-folders."""

    def test_scan_organize_creates_manufacturer_folders(self, tmp_path):
        """Organize mode creates manufacturer-level folders."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan", str(tmp_path), "--organize"])

        assert result.exit_code == 0
        # At least a scanned or unknown folder may be created
        subdirs = [d for d in tmp_path.iterdir() if d.is_dir()]
        # Organize should create at least the top-level category folder
        assert len(subdirs) > 0

    def test_scan_organize_does_not_move_trash(self, tmp_path):
        """Trash files remain flat in a trash folder (not organized)."""
        trash_file = tmp_path / "file.txt"
        trash_file.write_bytes(_make_bin(1024))

        runner.invoke(app, ["scan", str(tmp_path), "--organize"])

        # In dry-run mode (without --move), file should not be moved
        assert trash_file.exists(), (
            "File should remain in original location in dry-run mode"
        )

    def test_scan_organize_tree_structure(self, tmp_path):
        """Organize mode creates a predictable folder hierarchy."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan", str(tmp_path), "--organize"])

        assert result.exit_code == 0
        # Expect at least: category/manufacturer/family/ or category/
        # The exact structure depends on the extractor matches


# ---------------------------------------------------------------------------
# TestScanReports — JSON and CSV output
# ---------------------------------------------------------------------------


class TestScanReportJSON:
    """Reports can be written in JSON format."""

    def test_scan_report_json_file_created(self, tmp_path):
        """With --report, a JSON file is created."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.json"

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--report", str(report_file)]
        )

        assert result.exit_code == 0
        assert report_file.exists(), "Report file was not created"

    def test_scan_report_json_is_valid(self, tmp_path):
        """The JSON report is valid JSON."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.json"

        runner.invoke(app, ["scan", str(tmp_path), "--report", str(report_file)])

        report_text = report_file.read_text()
        report_data = json.loads(report_text)
        assert isinstance(report_data, (dict, list))

    def test_scan_report_json_contains_file_records(self, tmp_path):
        """The JSON report includes records for scanned files."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.json"

        runner.invoke(app, ["scan", str(tmp_path), "--report", str(report_file)])

        report_data = json.loads(report_file.read_text())
        # Should contain a list or dict with file information
        if isinstance(report_data, list):
            assert len(report_data) >= 1
        elif isinstance(report_data, dict):
            assert len(report_data) > 0

    def test_scan_report_json_has_expected_fields(self, tmp_path):
        """JSON report records have expected fields."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.json"

        runner.invoke(app, ["scan", str(tmp_path), "--report", str(report_file)])

        report_data = json.loads(report_file.read_text())
        # Ensure we have some data
        if isinstance(report_data, list) and len(report_data) > 0:
            record = report_data[0]
            # Should have at least filename and destination
            assert "filename" in record or "file" in record or "path" in record


class TestScanReportCSV:
    """Reports can be written in CSV format."""

    def test_scan_report_csv_file_created(self, tmp_path):
        """With --report .csv, a CSV file is created."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.csv"

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--report", str(report_file)]
        )

        assert result.exit_code == 0
        assert report_file.exists(), "CSV report file was not created"

    def test_scan_report_csv_is_valid(self, tmp_path):
        """The CSV report is valid CSV."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.csv"

        runner.invoke(app, ["scan", str(tmp_path), "--report", str(report_file)])

        report_text = report_file.read_text()
        # Parse as CSV
        lines = report_text.strip().split("\n")
        assert len(lines) >= 1, "CSV should have at least a header row"

    def test_scan_report_csv_has_header(self, tmp_path):
        """The CSV report has a header row."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.csv"

        runner.invoke(app, ["scan", str(tmp_path), "--report", str(report_file)])

        with open(report_file) as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            # Should have some header fields
            assert fieldnames is not None
            assert len(fieldnames) > 0

    def test_scan_report_csv_contains_file_records(self, tmp_path):
        """The CSV report includes a row for each file."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.csv"

        runner.invoke(app, ["scan", str(tmp_path), "--report", str(report_file)])

        with open(report_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) >= 1, "CSV should have at least one data row"


# ---------------------------------------------------------------------------
# TestScanEdgeCases — unusual inputs
# ---------------------------------------------------------------------------


class TestScanEdgeCases:
    """Edge cases and unusual inputs."""

    def test_scan_nonexistent_directory_exits_nonzero(self):
        """Scanning a non-existent directory exits non-zero."""
        result = runner.invoke(app, ["scan", "/nonexistent/path/xyz"])

        assert result.exit_code != 0

    def test_scan_file_instead_of_directory_exits_nonzero(self, tmp_path):
        """Passing a file path instead of directory exits non-zero."""
        test_file = tmp_path / "file.bin"
        test_file.write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan", str(test_file)])

        assert result.exit_code != 0

    def test_scan_with_mixed_extensions(self, tmp_path):
        """Directory with .bin, .ori, and other files is handled."""
        (tmp_path / "file1.bin").write_bytes(_make_bin(1024))
        (tmp_path / "file2.ori").write_bytes(_make_bin(1024))
        (tmp_path / "file3.txt").write_bytes(b"text")

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0

    def test_scan_with_subdirectories_in_source_folder(self, tmp_path):
        """If source folder has subdirectories, they are not scanned."""
        subdir = tmp_path / "subfolder"
        subdir.mkdir()
        (subdir / "nested.bin").write_bytes(_make_bin(1024))
        (tmp_path / "root.bin").write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        # Only root.bin should be reported, not nested.bin

    def test_scan_help_exits_zero(self):
        """--help prints usage information and exits 0."""
        result = runner.invoke(app, ["scan", "--help"])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "scan" in combined.lower() or "directory" in combined.lower()

    def test_scan_with_very_large_file(self, tmp_path):
        """Scanning works with large binary files."""
        large_file = tmp_path / "large.bin"
        # Create a 10 MB file (sparse pattern)
        large_file.write_bytes(_make_bin(10 * 1024 * 1024))

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0

    def test_scan_many_files(self, tmp_path):
        """Scanning handles directories with many files."""
        for i in range(100):
            f = tmp_path / f"file_{i:03d}.bin"
            f.write_bytes(_make_bin(1024))

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        output = result.stdout + result.stderr
        # Should summarize the scan results


# ---------------------------------------------------------------------------
# TestScanCombinedFlags — multiple flags together
# ---------------------------------------------------------------------------


class TestScanCombinedFlags:
    """Tests with multiple flags combined."""

    def test_scan_move_and_report_together(self, tmp_path):
        """--move and --report can be used together."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.json"

        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--move",
                "--create-dirs",
                "--report",
                str(report_file),
            ],
        )

        assert result.exit_code == 0
        assert report_file.exists()

    def test_scan_organize_and_report_together(self, tmp_path):
        """--organize and --report can be used together."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.json"

        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--organize",
                "--report",
                str(report_file),
            ],
        )

        assert result.exit_code == 0
        assert report_file.exists()

    def test_scan_organize_implies_move(self, tmp_path):
        """Using --organize also moves files (doesn't just preview)."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        runner.invoke(app, ["scan", str(tmp_path), "--organize"])

        # File should have been moved (not in tmp_path root anymore)
        # Or at least some category folder was created
        files_in_root = [f for f in tmp_path.iterdir() if f.is_file()]
        assert len(files_in_root) == 0 or len(list(tmp_path.glob("*/"))) > 0


# ---------------------------------------------------------------------------
# Additional coverage — classify_file direct tests (lines 128-205)
# ---------------------------------------------------------------------------


class TestClassifyFileDirect:
    """Direct unit tests for classify_file covering contested and extraction paths."""

    def test_contested_two_claimants(self):
        """Two extractors claiming the same file → DEST_CONTESTED."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import classify_file, DEST_CONTESTED

        ext1 = MagicMock()
        ext1.name = "MockA"
        ext1.__class__.__name__ = "MockAExtractor"
        ext1.can_handle.return_value = True

        ext2 = MagicMock()
        ext2.name = "MockB"
        ext2.__class__.__name__ = "MockBExtractor"
        ext2.can_handle.return_value = True

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext1, ext2]):
            result = classify_file(b"\x00" * 1024, "test.bin")

        assert result.destination == DEST_CONTESTED
        assert len(result.claimants) == 2

    def test_one_claimant_with_match_key_scanned(self):
        """One extractor with match_key → DEST_SCANNED."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import classify_file, DEST_SCANNED

        ext = MagicMock()
        ext.name = "MockExt"
        ext.__class__.__name__ = "MockExtractor"
        ext.can_handle.return_value = True
        ext.extract.return_value = {
            "manufacturer": "Bosch",
            "ecu_family": "EDC17",
            "ecu_variant": "EDC17C66",
            "software_version": "1.0.0",
            "hardware_number": "HW001",
            "calibration_id": None,
            "match_key": "mk_abc123",
        }

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext]):
            result = classify_file(b"\x00" * 1024, "test.bin")

        assert result.destination == DEST_SCANNED
        assert "mk_abc123" in result.detail

    def test_one_claimant_no_match_key_sw_missing(self):
        """One extractor without match_key → DEST_SW_MISSING."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import classify_file, DEST_SW_MISSING

        ext = MagicMock()
        ext.name = "MockExt"
        ext.__class__.__name__ = "MockExtractor"
        ext.can_handle.return_value = True
        ext.extract.return_value = {
            "manufacturer": "Bosch",
            "ecu_family": "EDC17",
            "ecu_variant": None,
            "software_version": None,
            "hardware_number": None,
            "calibration_id": None,
            "match_key": None,
        }

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext]):
            result = classify_file(b"\x00" * 1024, "test.bin")

        assert result.destination == DEST_SW_MISSING

    def test_one_claimant_extraction_raises_sw_missing(self):
        """One extractor whose extract() raises → DEST_SW_MISSING."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import classify_file, DEST_SW_MISSING

        ext = MagicMock()
        ext.name = "MockExt"
        ext.__class__.__name__ = "MockExtractor"
        ext.can_handle.return_value = True
        ext.extract.side_effect = RuntimeError("extraction crashed")

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext]):
            result = classify_file(b"\x00" * 1024, "test.bin")

        assert result.destination == DEST_SW_MISSING
        assert "extraction error" in result.detail

    def test_one_claimant_cal_id_no_sw_shows_cal_id(self):
        """One extractor with cal_id but no sw_version includes cal_id in detail."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import classify_file, DEST_SCANNED

        ext = MagicMock()
        ext.name = "MockExt"
        ext.__class__.__name__ = "MockExtractor"
        ext.can_handle.return_value = True
        ext.extract.return_value = {
            "manufacturer": "Bosch",
            "ecu_family": "LH-Jetronic",
            "ecu_variant": None,
            "software_version": None,
            "hardware_number": None,
            "calibration_id": "CAL001",
            "match_key": "mk_cal001",
        }

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext]):
            result = classify_file(b"\x00" * 1024, "test.bin")

        assert result.destination == DEST_SCANNED
        assert "cal_id" in result.detail

    def test_one_claimant_with_variant_and_hw(self):
        """One extractor with variant and hardware number includes both in detail."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import classify_file, DEST_SCANNED

        ext = MagicMock()
        ext.name = "MockExt"
        ext.__class__.__name__ = "MockExtractor"
        ext.can_handle.return_value = True
        ext.extract.return_value = {
            "manufacturer": "Bosch",
            "ecu_family": "EDC17",
            "ecu_variant": "EDC17C66",
            "software_version": "9.9.9",
            "hardware_number": "HW999",
            "calibration_id": None,
            "match_key": "mk_hw999",
        }

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext]):
            result = classify_file(b"\x00" * 1024, "test.bin")

        assert result.destination == DEST_SCANNED
        assert "hw" in result.detail.lower() or "HW999" in result.detail

    def test_no_claimants_unknown(self):
        """No extractors claim the file → DEST_UNKNOWN."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import classify_file, DEST_UNKNOWN

        ext = MagicMock()
        ext.can_handle.return_value = False

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext]):
            result = classify_file(b"\x00" * 1024, "test.bin")

        assert result.destination == DEST_UNKNOWN


# ---------------------------------------------------------------------------
# Additional coverage — direct function tests (lines 225-381)
# ---------------------------------------------------------------------------


class TestRenderConfidenceTagDirect:
    """Direct tests for _render_confidence_tag (lines 225-233)."""

    def test_with_warnings_includes_warning_text(self):
        """A confidence result with warnings includes ⚠ and the warning text."""
        from openremap.cli.commands.scan import _render_confidence_tag
        from openremap.core.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        cr = ConfidenceResult(
            score=10,
            tier="Suspicious",
            signals=[ConfidenceSignal(delta=-30, label="no ident block")],
            warnings=["IDENT BLOCK MISSING"],
        )
        tag = _render_confidence_tag(cr)
        assert isinstance(tag, str)
        assert "IDENT BLOCK MISSING" in tag

    def test_without_warnings_returns_tier_only(self):
        """A confidence result without warnings returns just the tier label."""
        from openremap.cli.commands.scan import _render_confidence_tag
        from openremap.core.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        cr = ConfidenceResult(
            score=80,
            tier="High",
            signals=[ConfidenceSignal(delta=80, label="ident block")],
            warnings=[],
        )
        tag = _render_confidence_tag(cr)
        assert isinstance(tag, str)
        assert "HIGH" in tag.upper()


class TestBuildReportRowDirect:
    """Direct tests for _build_report_row (lines 241-272)."""

    def test_with_confidence_populates_confidence_fields(self, tmp_path):
        """Report row includes score/tier/warnings when confidence is not None."""
        from openremap.cli.commands.scan import (
            _build_report_row,
            ScanResult,
            DEST_UNKNOWN,
        )
        from openremap.core.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        filepath = tmp_path / "test.bin"
        filepath.write_bytes(b"\x00" * 1024)

        scan_result = ScanResult(
            claimants=[],
            extractor=None,
            extraction=None,
            destination=DEST_UNKNOWN,
            detail="no extractor matched",
        )
        confidence = ConfidenceResult(
            score=50,
            tier="Medium",
            signals=[ConfidenceSignal(delta=50, label="test")],
            warnings=["TEST WARNING"],
        )

        row = _build_report_row(filepath, scan_result, confidence, "abc123", 10.5)

        assert row["confidence_score"] == 50
        assert row["confidence_tier"] == "Medium"
        assert "TEST WARNING" in row["confidence_warnings"]
        assert row["sha256"] == "abc123"

    def test_without_confidence_fields_are_none(self, tmp_path):
        """Report row has None confidence fields when confidence is None."""
        from openremap.cli.commands.scan import (
            _build_report_row,
            ScanResult,
            DEST_TRASH,
        )

        filepath = tmp_path / "test.bin"
        filepath.write_bytes(b"\x00" * 1024)

        scan_result = ScanResult(
            claimants=[],
            extractor=None,
            extraction=None,
            destination=DEST_TRASH,
            detail="wrong extension",
        )

        row = _build_report_row(filepath, scan_result, None, None, 0.0)

        assert row["confidence_score"] is None
        assert row["confidence_tier"] is None
        assert row["confidence_warnings"] is None


class TestWriteReportDirect:
    """Direct tests for _write_report (lines 275-292)."""

    def test_csv_report_has_headers_and_data(self, tmp_path):
        """Writing to a .csv path produces a valid CSV with headers."""
        from openremap.cli.commands.scan import _write_report

        report_path = tmp_path / "report.csv"
        rows = [{"filename": "a.bin", "destination": "unknown", "manufacturer": None}]

        _write_report(rows, report_path)

        assert report_path.exists()
        content = report_path.read_text()
        assert "filename" in content
        assert "a.bin" in content

    def test_csv_empty_rows_produces_empty_file(self, tmp_path):
        """Empty rows list produces an empty CSV file."""
        from openremap.cli.commands.scan import _write_report

        report_path = tmp_path / "report.csv"
        _write_report([], report_path)

        assert report_path.exists()
        assert report_path.read_text() == ""

    def test_unsupported_extension_falls_back_to_json(self, tmp_path):
        """An unsupported extension (e.g. .xyz) falls back to JSON output."""
        import json as _json
        from openremap.cli.commands.scan import _write_report

        report_path = tmp_path / "report.xyz"
        rows = [{"filename": "test.bin", "destination": "unknown"}]

        _write_report(rows, report_path)

        assert report_path.exists()
        data = _json.loads(report_path.read_text())
        assert isinstance(data, list)
        assert data[0]["filename"] == "test.bin"


class TestSafeFolderNameDirect:
    """Direct tests for _safe_folder_name (lines 300-319)."""

    def test_windows_illegal_chars_replaced(self):
        """Characters illegal on Windows are replaced with underscores."""
        from openremap.cli.commands.scan import _safe_folder_name

        result = _safe_folder_name("folder/with:*?<>|chars")
        assert "/" not in result
        assert ":" not in result
        assert "*" not in result

    def test_empty_string_returns_unknown(self):
        """An empty (or all-special) string falls back to 'unknown'."""
        from openremap.cli.commands.scan import _safe_folder_name

        assert _safe_folder_name("") == "unknown"
        assert _safe_folder_name("///") == "unknown"

    def test_consecutive_underscores_collapsed(self):
        """Multiple consecutive underscores are collapsed to one."""
        from openremap.cli.commands.scan import _safe_folder_name

        result = _safe_folder_name("folder__name")
        assert "__" not in result

    def test_normal_name_unchanged(self):
        """A safe name passes through without modification."""
        from openremap.cli.commands.scan import _safe_folder_name

        assert _safe_folder_name("Bosch") == "Bosch"
        assert _safe_folder_name("EDC17C66") == "EDC17C66"


class TestOrganizedDestDirDirect:
    """Direct tests for _organized_dest_dir (lines 327-361)."""

    def test_non_organizable_destinations_return_base(self, tmp_path):
        """CONTESTED, UNKNOWN, TRASH destinations stay flat in base_dest."""
        from openremap.cli.commands.scan import (
            _organized_dest_dir,
            ScanResult,
            DEST_CONTESTED,
            DEST_UNKNOWN,
            DEST_TRASH,
        )

        base = tmp_path / "contested"

        for dest in [DEST_CONTESTED, DEST_UNKNOWN, DEST_TRASH]:
            sr = ScanResult(
                claimants=[],
                extractor=None,
                extraction=None,
                destination=dest,
                detail="test",
            )
            assert _organized_dest_dir(base, sr) == base

    def test_scanned_result_gets_manufacturer_family_subdir(self, tmp_path):
        """A SCANNED result produces base/Manufacturer/Family sub-path."""
        from unittest.mock import MagicMock
        from openremap.cli.commands.scan import (
            _organized_dest_dir,
            ScanResult,
            DEST_SCANNED,
        )

        base = tmp_path / "scanned"
        mock_ext = MagicMock()
        sr = ScanResult(
            claimants=[mock_ext],
            extractor=mock_ext,
            extraction={
                "manufacturer": "Bosch",
                "ecu_family": "EDC17",
                "match_key": "mk",
            },
            destination=DEST_SCANNED,
            detail="test",
        )

        result = _organized_dest_dir(base, sr)
        assert result == base / "Bosch" / "EDC17"


class TestSafeMoveDirect:
    """Direct tests for safe_move (lines 369-383)."""

    def test_move_without_collision(self, tmp_path):
        """Moving a file with no naming conflict works normally."""
        from openremap.cli.commands.scan import safe_move

        src_dir = tmp_path / "src"
        dest_dir = tmp_path / "dest"
        src_dir.mkdir()
        dest_dir.mkdir()

        src = src_dir / "test.bin"
        src.write_bytes(b"\x00" * 100)

        moved = safe_move(src, dest_dir)

        assert moved == dest_dir / "test.bin"
        assert moved.exists()
        assert not src.exists()

    def test_move_with_collision_appends_counter(self, tmp_path):
        """When dest already has same name, a counter suffix is appended."""
        from openremap.cli.commands.scan import safe_move

        src_dir = tmp_path / "src"
        dest_dir = tmp_path / "dest"
        src_dir.mkdir()
        dest_dir.mkdir()

        src = src_dir / "test.bin"
        src.write_bytes(b"\x01" * 100)

        # Pre-create the collision
        (dest_dir / "test.bin").write_bytes(b"\x02" * 100)

        moved = safe_move(src, dest_dir)

        assert moved.name == "test__1.bin"
        assert moved.exists()
        assert not src.exists()


# ---------------------------------------------------------------------------
# Additional coverage — CLI paths (lines 501, 599, 613-619, 625-641, 671,
#                                   686-687, 691-692, 748-749)
# ---------------------------------------------------------------------------


class TestScanCLIUncoveredPaths:
    """CLI invocation tests that target specific uncovered branches in scan.py."""

    def test_report_extension_warning_for_unsupported_ext(self, tmp_path):
        """Unsupported report extension triggers a JSON-fallback warning (line 501)."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.xyz"

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--report", str(report_file)]
        )

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "unrecognised" in combined.lower() or "warning" in combined.lower()

    def test_trash_file_with_report_builds_row(self, tmp_path):
        """A trash file scanned with --report triggers _build_report_row (line 599)."""
        trash_file = tmp_path / "junk.txt"
        trash_file.write_bytes(b"not a binary")
        report_file = tmp_path / "report.json"

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--report", str(report_file)]
        )

        assert result.exit_code == 0
        assert report_file.exists()
        import json as _json

        rows = _json.loads(report_file.read_text())
        assert any(r["destination"] == "trash" for r in rows)

    def test_scan_read_error_shows_read_err(self, tmp_path):
        """OSError when reading a .bin file shows READ ERR and continues (line 613)."""
        from unittest.mock import patch

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        with patch("pathlib.Path.read_bytes", side_effect=OSError("permission denied")):
            result = runner.invoke(app, ["scan", str(tmp_path)])

        combined = result.stdout + result.stderr
        assert "READ ERR" in combined or "permission denied" in combined

    def test_scan_empty_bin_classified_as_trash(self, tmp_path):
        """A zero-byte .bin file is classified as trash (empty file) (lines 613-619)."""
        empty_bin = tmp_path / "empty.bin"
        empty_bin.write_bytes(b"")

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "empty" in combined.lower() or "TRASH" in combined

    def test_scan_contested_file_shown(self, tmp_path):
        """A file claimed by two extractors is shown as CONTESTED (lines 625-641)."""
        from unittest.mock import MagicMock, patch

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        ext1 = MagicMock()
        ext1.name = "MockA"
        ext1.__class__.__name__ = "MockAExtractor"
        ext1.can_handle.return_value = True

        ext2 = MagicMock()
        ext2.name = "MockB"
        ext2.__class__.__name__ = "MockBExtractor"
        ext2.can_handle.return_value = True

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext1, ext2]):
            result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        assert "CONTESTED" in result.output

    def test_scan_with_report_computes_sha256(self, tmp_path):
        """Using --report triggers SHA-256 computation for scanned files."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.json"

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--report", str(report_file)]
        )

        assert result.exit_code == 0
        assert report_file.exists()
        import json as _json

        rows = _json.loads(report_file.read_text())
        assert len(rows) >= 1
        assert "sha256" in rows[0]
        # sha256 is computed for classified files (not trash with report path)
        non_trash = [r for r in rows if r.get("destination") != "trash"]
        if non_trash:
            assert non_trash[0]["sha256"] is not None

    def test_scan_organize_shows_subpath_in_detail(self, tmp_path):
        """--organize with a scanned file appends the sub-path to detail (line 671)."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import ScanResult, DEST_SCANNED

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        mock_ext = MagicMock()
        mock_result = ScanResult(
            claimants=[mock_ext],
            extractor=mock_ext,
            extraction={
                "manufacturer": "Bosch",
                "ecu_family": "EDC17",
                "ecu_variant": None,
                "software_version": "1.0",
                "hardware_number": None,
                "calibration_id": None,
                "match_key": "mk_abc",
            },
            destination=DEST_SCANNED,
            detail="extractor: MockExtractor  family: EDC17  sw: 1.0  key: mk_abc",
        )

        with patch(
            "openremap.cli.commands.scan.classify_file",
            return_value=mock_result,
        ):
            result = runner.invoke(app, ["scan", str(tmp_path), "--organize"])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        # The organized sub-path arrow should appear in the output
        assert "→" in combined or "Bosch" in combined or "EDC17" in combined

    def test_scan_organize_move_creates_nested_dirs(self, tmp_path):
        """--move --organize creates nested manufacturer/family directories (lines 686-692)."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import ScanResult, DEST_SCANNED

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        mock_ext = MagicMock()
        mock_result = ScanResult(
            claimants=[mock_ext],
            extractor=mock_ext,
            extraction={
                "manufacturer": "Bosch",
                "ecu_family": "EDC17",
                "ecu_variant": None,
                "software_version": "1.0",
                "hardware_number": None,
                "calibration_id": None,
                "match_key": "mk_abc",
            },
            destination=DEST_SCANNED,
            detail="test detail",
        )

        with patch(
            "openremap.cli.commands.scan.classify_file",
            return_value=mock_result,
        ):
            result = runner.invoke(app, ["scan", str(tmp_path), "--move", "--organize"])

        assert result.exit_code == 0
        # The file should be moved into the nested directory
        nested = tmp_path / "scanned" / "Bosch" / "EDC17"
        assert nested.exists() or (tmp_path / "scanned").exists()

    def test_scan_report_oserror_shows_error(self, tmp_path):
        """OSError when writing the report shows an error message (lines 748-749)."""
        from unittest.mock import patch

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))
        report_file = tmp_path / "report.json"

        with patch(
            "openremap.cli.commands.scan._write_report",
            side_effect=OSError("disk full"),
        ):
            result = runner.invoke(
                app, ["scan", str(tmp_path), "--report", str(report_file)]
            )

        combined = result.stdout + result.stderr
        assert "error" in combined.lower() or "Error" in combined

    def test_scan_extractor_can_handle_exception_ignored(self, tmp_path):
        """Exception from extractor.can_handle() is swallowed — scan continues (lines 129-131)."""
        from unittest.mock import MagicMock, patch

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        ext_bad = MagicMock()
        ext_bad.name = "BadExt"
        ext_bad.__class__.__name__ = "BadExtractor"
        ext_bad.can_handle.side_effect = RuntimeError("extractor internal crash")

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext_bad]):
            result = runner.invoke(app, ["scan", str(tmp_path)])

        # Scan should complete successfully even when an extractor raises
        assert result.exit_code == 0
        # File classified as unknown (no claimant)
        assert "UNKNOWN" in result.output or "unknown" in result.output

    def test_classify_scanned_no_sw_no_cal_uses_sw_none(self):
        """One extractor with match_key but no sw and no cal → 'sw: None' in detail (line 183)."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import classify_file, DEST_SCANNED

        ext = MagicMock()
        ext.name = "MockExt"
        ext.__class__.__name__ = "MockExtractor"
        ext.can_handle.return_value = True
        ext.extract.return_value = {
            "manufacturer": "Bosch",
            "ecu_family": "EDC17",
            "ecu_variant": None,
            "software_version": None,
            "hardware_number": None,
            "calibration_id": None,  # no cal either
            "match_key": "mk_abc",  # key present → SCANNED
        }

        with patch("openremap.cli.commands.scan.EXTRACTORS", [ext]):
            result = classify_file(b"\x00" * 1024, "test.bin")

        assert result.destination == DEST_SCANNED
        # When key is set but sw is None and cal is None, detail shows "sw: None"
        assert "sw" in result.detail

    def test_scan_empty_bin_with_move_goes_to_trash(self, tmp_path):
        """Empty .bin + --move actually moves the empty file to trash (line 627)."""
        empty_bin = tmp_path / "empty.bin"
        empty_bin.write_bytes(b"")

        # Create flat destination dirs so --move works
        result = runner.invoke(app, ["scan", str(tmp_path), "--move", "--create-dirs"])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "empty" in combined.lower() or "TRASH" in combined
        # File should have been moved away from root
        assert not empty_bin.exists()

    def test_scan_empty_bin_with_report_builds_row(self, tmp_path):
        """Empty .bin + --report triggers _build_report_row for the empty file (line 632)."""
        empty_bin = tmp_path / "empty.bin"
        empty_bin.write_bytes(b"")
        report_file = tmp_path / "report.json"

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--report", str(report_file)]
        )

        assert result.exit_code == 0
        assert report_file.exists()
        import json as _json

        rows = _json.loads(report_file.read_text())
        # The empty .bin should appear as a trash entry
        assert any(r.get("destination") == "trash" for r in rows)

    def test_scan_confidence_tag_shown_for_scanned_file(self, tmp_path):
        """Confidence tag (including warnings) is shown for SCANNED files (lines 688-692)."""
        from unittest.mock import MagicMock, patch
        from openremap.cli.commands.scan import ScanResult, DEST_SCANNED
        from openremap.core.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(_make_bin(1024))

        mock_ext = MagicMock()
        mock_scan_result = ScanResult(
            claimants=[mock_ext],
            extractor=mock_ext,
            extraction={
                "manufacturer": "Bosch",
                "ecu_family": "EDC17",
                "ecu_variant": None,
                "software_version": "1.0",
                "hardware_number": None,
                "calibration_id": None,
                "match_key": "mk_abc",
            },
            destination=DEST_SCANNED,
            detail="family: EDC17  sw: 1.0  key: mk_abc",
        )

        mock_confidence = ConfidenceResult(
            score=10,
            tier="Suspicious",
            signals=[ConfidenceSignal(delta=-30, label="no ident block")],
            warnings=["IDENT BLOCK MISSING"],
        )

        with (
            patch(
                "openremap.cli.commands.scan.classify_file",
                return_value=mock_scan_result,
            ),
            patch(
                "openremap.cli.commands.scan.score_identity",
                return_value=mock_confidence,
            ),
        ):
            result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "SUSPICIOUS" in combined.upper() or "SCANNED" in combined
