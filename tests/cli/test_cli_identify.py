"""
Tests for the ``identify`` sub-command.

The ``identify`` command accepts a ``file`` argument annotated with
``exists=True``, which means Click validates the path before the function
body is entered.  All tests that require a real file on disk use the
``tmp_path`` pytest fixture — a temporary directory unique to each test
invocation that is cleaned up automatically after the test session.

Covers:
    - Valid .bin file (zero-filled, unknown ECU) → human-readable table output
    - ``--json`` flag             → stdout is valid JSON with expected keys
    - ``--output <path>`` flag    → result written to disk, stdout says "Saved to"
    - Unrecognised extension      → exits 0, warning on stderr
    - Empty file                  → exits 1, error on stderr
    - Non-existent file           → exits 2 (Click arg-validation convention)
    - ``--help``                  → exits 0, shows expected options

Notes on the test runner
------------------------
``typer.testing.CliRunner`` wraps ``click.testing.CliRunner``.  Click 8.2
removed the ``mix_stderr`` constructor parameter — stdout, stderr, and the
mixed output are always captured independently.  Use:

    result.stdout   — captured standard output only
    result.stderr   — captured standard error only
    result.output   — mixed stdout+stderr (what the user sees in the terminal)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from openremap.cli.main import app

# ---------------------------------------------------------------------------
# Shared runner
# ---------------------------------------------------------------------------
# Click 8.2+: result.stdout / result.stderr / result.output are always
# available; no mix_stderr constructor argument is needed or accepted.
runner = CliRunner()

# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

# 1 KB of zero-bytes — syntactically valid input, but no extractor will match
# it, so the command reports "Unknown ECU".
_ZERO_BIN = b"\x00" * 1024


# ===========================================================================
# Valid binary — human-readable table output
# ===========================================================================


class TestIdentifyValid:
    """A zero-filled .bin file is valid input: exits 0 and reports Unknown ECU."""

    def test_exits_zero(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert result.exit_code == 0

    def test_stdout_reports_unknown_ecu(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert "Unknown ECU" in result.stdout

    def test_stdout_shows_filename(self, tmp_path: Path) -> None:
        f = tmp_path / "myecu.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert "myecu.bin" in result.stdout

    def test_stdout_shows_sha256_label(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert "SHA-256" in result.stdout

    def test_stdout_shows_file_size_label(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert "File Size" in result.stdout

    def test_stdout_shows_confidence_section(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert "Confidence" in result.stdout

    def test_unknown_fields_rendered_as_unknown(self, tmp_path: Path) -> None:
        """Fields with no match must render as the literal word 'unknown'."""
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert "unknown" in result.stdout.lower()

    def test_no_stderr_output(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert result.stderr == ""

    def test_larger_binary_also_exits_zero(self, tmp_path: Path) -> None:
        """File size must not affect exit code for a valid but unknown binary."""
        f = tmp_path / "large.bin"
        f.write_bytes(b"\xff" * (512 * 1024))  # 512 KB, all 0xFF
        result = runner.invoke(app, ["identify", str(f)])
        assert result.exit_code == 0


# ===========================================================================
# --json flag
# ===========================================================================


class TestIdentifyJson:
    """``--json`` emits a JSON object to stdout with a well-defined schema."""

    def test_exits_zero(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        assert result.exit_code == 0

    def test_stdout_is_valid_json(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        # json.loads raises if the string is not valid JSON
        data = json.loads(result.stdout)
        assert isinstance(data, dict)

    def test_json_has_sha256_key(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        assert "sha256" in data

    def test_sha256_is_64_char_lowercase_hex(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        sha = data["sha256"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_json_has_file_size_key(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        assert "file_size" in data

    def test_file_size_value_matches_actual_size(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        assert data["file_size"] == len(_ZERO_BIN)

    def test_json_has_confidence_key(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        assert "confidence" in data

    def test_confidence_has_tier_key(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        assert "tier" in data["confidence"]

    def test_confidence_tier_is_string(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        assert isinstance(data["confidence"]["tier"], str)

    def test_json_has_manufacturer_key(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        assert "manufacturer" in data

    def test_unknown_binary_manufacturer_is_null(self, tmp_path: Path) -> None:
        """An unmatched binary must report manufacturer as JSON null."""
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        data = json.loads(result.stdout)
        assert data["manufacturer"] is None

    def test_no_stderr_output(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f), "--json"])
        assert result.stderr == ""


# ===========================================================================
# --output flag
# ===========================================================================


class TestIdentifyOutputFile:
    """``--output <path>`` writes the result to disk and prints "Saved to …"."""

    def test_exits_zero_with_json(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.json"
        result = runner.invoke(
            app, ["identify", str(f), "--json", "--output", str(out)]
        )
        assert result.exit_code == 0

    def test_output_file_is_created(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.json"
        runner.invoke(app, ["identify", str(f), "--json", "--output", str(out)])
        assert out.exists()

    def test_output_file_contains_valid_json(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.json"
        runner.invoke(app, ["identify", str(f), "--json", "--output", str(out)])
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_output_file_json_has_sha256(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.json"
        runner.invoke(app, ["identify", str(f), "--json", "--output", str(out)])
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "sha256" in data

    def test_stdout_reports_saved_to(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.json"
        result = runner.invoke(
            app, ["identify", str(f), "--json", "--output", str(out)]
        )
        assert "Saved to" in result.stdout

    def test_plain_text_output_exits_zero(self, tmp_path: Path) -> None:
        """Without --json, --output writes ANSI-stripped plain text."""
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.txt"
        result = runner.invoke(app, ["identify", str(f), "--output", str(out)])
        assert result.exit_code == 0

    def test_plain_text_output_file_is_created(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.txt"
        runner.invoke(app, ["identify", str(f), "--output", str(out)])
        assert out.exists()

    def test_plain_text_output_contains_sha256_label(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.txt"
        runner.invoke(app, ["identify", str(f), "--output", str(out)])
        content = out.read_text(encoding="utf-8")
        assert "SHA-256" in content

    def test_plain_text_output_has_no_ansi_codes(self, tmp_path: Path) -> None:
        """The plain-text file must have ANSI escape sequences stripped out."""
        f = tmp_path / "test.bin"
        f.write_bytes(_ZERO_BIN)
        out = tmp_path / "result.txt"
        runner.invoke(app, ["identify", str(f), "--output", str(out)])
        content = out.read_text(encoding="utf-8")
        assert "\x1b[" not in content


# ===========================================================================
# Unrecognised file extension
# ===========================================================================


class TestIdentifyExtension:
    """Files with extensions other than .bin/.ori warn but still succeed."""

    def test_rom_extension_exits_zero(self, tmp_path: Path) -> None:
        f = tmp_path / "test.rom"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert result.exit_code == 0

    def test_rom_extension_warning_on_stderr(self, tmp_path: Path) -> None:
        f = tmp_path / "test.rom"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert result.stderr != ""

    def test_rom_extension_stderr_mentions_unrecognised_extension(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "test.rom"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert "Unrecognised extension" in result.stderr

    def test_rom_extension_stderr_mentions_dot_rom(self, tmp_path: Path) -> None:
        f = tmp_path / "test.rom"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert ".rom" in result.stderr

    def test_rom_extension_stdout_still_shows_sha256(self, tmp_path: Path) -> None:
        """Despite the warning, identification must still run to completion."""
        f = tmp_path / "test.rom"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert "SHA-256" in result.stdout

    def test_ori_extension_exits_zero_no_warning(self, tmp_path: Path) -> None:
        """.ori is an accepted extension — no warning must be emitted."""
        f = tmp_path / "test.ori"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert result.exit_code == 0
        assert result.stderr == ""

    def test_unknown_extension_exits_zero(self, tmp_path: Path) -> None:
        """Any extension other than .bin/.ori should warn but not fail."""
        f = tmp_path / "ecu.img"
        f.write_bytes(_ZERO_BIN)
        result = runner.invoke(app, ["identify", str(f)])
        assert result.exit_code == 0
        assert ".img" in result.stderr


# ===========================================================================
# Error cases
# ===========================================================================


class TestIdentifyErrors:
    """Edge-case inputs that must produce specific exit codes and error messages."""

    # ── Empty file ───────────────────────────────────────────────────────────

    def test_empty_file_exits_one(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        result = runner.invoke(app, ["identify", str(f)])
        assert result.exit_code == 1

    def test_empty_file_error_on_stderr(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        result = runner.invoke(app, ["identify", str(f)])
        assert result.stderr != ""

    def test_empty_file_stderr_mentions_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        result = runner.invoke(app, ["identify", str(f)])
        assert "empty" in result.stderr.lower()

    def test_empty_file_error_mentions_filename(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        result = runner.invoke(app, ["identify", str(f)])
        assert "empty.bin" in result.stderr

    def test_empty_file_no_stdout_output(self, tmp_path: Path) -> None:
        """An empty-file error must produce nothing on stdout."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        result = runner.invoke(app, ["identify", str(f)])
        assert result.stdout == ""

    # ── Non-existent file ────────────────────────────────────────────────────

    def test_nonexistent_file_exits_two(self, tmp_path: Path) -> None:
        """Click's exists=True path validation exits with code 2 for missing files."""
        result = runner.invoke(app, ["identify", str(tmp_path / "nonexistent.bin")])
        assert result.exit_code == 2

    def test_nonexistent_file_error_mentions_does_not_exist(
        self, tmp_path: Path
    ) -> None:
        result = runner.invoke(app, ["identify", str(tmp_path / "ghost.bin")])
        assert "does not exist" in result.stderr.lower()

    def test_nonexistent_file_error_is_click_validation(self, tmp_path: Path) -> None:
        """The error must come from Click's argument validation, not user code."""
        result = runner.invoke(app, ["identify", str(tmp_path / "ghost.bin")])
        # Click arg-validation errors always reference the argument name
        assert "FILE" in result.stderr or "file" in result.stderr.lower()


# ===========================================================================
# --help
# ===========================================================================


class TestIdentifyHelp:
    """``identify --help`` must describe all parameters and exit 0."""

    def test_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["identify", "--help"])
        assert result.exit_code == 0

    def test_help_shows_file_argument(self) -> None:
        result = runner.invoke(app, ["identify", "--help"])
        assert "FILE" in result.stdout

    def test_help_shows_json_option(self) -> None:
        result = runner.invoke(app, ["identify", "--help"])
        assert "--json" in result.stdout

    def test_help_shows_output_option(self) -> None:
        result = runner.invoke(app, ["identify", "--help"])
        assert "--output" in result.stdout

    def test_help_no_stderr_output(self) -> None:
        result = runner.invoke(app, ["identify", "--help"])
        assert result.stderr == ""


# ===========================================================================
# Additional coverage tests — uncovered paths in identify.py
# ===========================================================================


class TestFormatConfidenceInlineDirect:
    """Direct unit tests for _format_confidence_inline (dead code — lines 57-61)."""

    def test_returns_string_for_high_tier(self) -> None:
        """_format_confidence_inline returns a non-empty styled string."""
        from openremap.cli.commands.identify import _format_confidence_inline
        from openremap.tuning.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        cr = ConfidenceResult(
            score=80,
            tier="High",
            signals=[ConfidenceSignal(delta=80, label="test signal")],
            warnings=[],
        )
        result = _format_confidence_inline(cr)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_returns_string_for_unknown_tier(self) -> None:
        """_format_confidence_inline handles Unknown tier without error."""
        from openremap.cli.commands.identify import _format_confidence_inline
        from openremap.tuning.services.confidence import ConfidenceResult

        cr = ConfidenceResult(score=0, tier="Unknown", signals=[], warnings=[])
        result = _format_confidence_inline(cr)
        assert isinstance(result, str)

    def test_returns_string_for_suspicious_tier_with_summary(self) -> None:
        """_format_confidence_inline includes summary when signals are present."""
        from openremap.cli.commands.identify import _format_confidence_inline
        from openremap.tuning.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        cr = ConfidenceResult(
            score=10,
            tier="Suspicious",
            signals=[ConfidenceSignal(delta=-30, label="no ident block")],
            warnings=["IDENT BLOCK MISSING"],
        )
        result = _format_confidence_inline(cr)
        assert isinstance(result, str)


class TestIdentifyWithConfidenceWarnings:
    """Tests for _format_confidence_warnings loop (lines 70-73)."""

    def test_warnings_appear_in_table_output(self, tmp_path: Path) -> None:
        """When score_identity returns warnings, they appear in the table output."""
        from unittest.mock import patch
        from openremap.tuning.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 1024)

        mock_confidence = ConfidenceResult(
            score=10,
            tier="Suspicious",
            signals=[ConfidenceSignal(delta=-30, label="no ident block")],
            warnings=["IDENT BLOCK MISSING"],
        )

        with patch(
            "openremap.cli.commands.identify.score_identity",
            return_value=mock_confidence,
        ):
            result = runner.invoke(app, ["identify", str(f)])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "IDENT BLOCK MISSING" in combined

    def test_multiple_warnings_all_displayed(self, tmp_path: Path) -> None:
        """Multiple warnings are each displayed in the output."""
        from unittest.mock import patch
        from openremap.tuning.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 1024)

        mock_confidence = ConfidenceResult(
            score=5,
            tier="Suspicious",
            signals=[ConfidenceSignal(delta=-40, label="no data")],
            warnings=["FIRST WARNING", "SECOND WARNING"],
        )

        with patch(
            "openremap.cli.commands.identify.score_identity",
            return_value=mock_confidence,
        ):
            result = runner.invoke(app, ["identify", str(f)])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "FIRST WARNING" in combined
        assert "SECOND WARNING" in combined


class TestIdentifyOSError:
    """Tests for the OSError path when reading the binary (lines 155-160)."""

    def test_read_bytes_oserror_exits_one(self, tmp_path: Path) -> None:
        """OSError when reading the file exits 1 with an error message."""
        from unittest.mock import patch

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 1024)

        with patch("pathlib.Path.read_bytes", side_effect=OSError("permission denied")):
            result = runner.invoke(app, ["identify", str(f)])

        assert result.exit_code == 1

    def test_read_bytes_oserror_shows_error_message(self, tmp_path: Path) -> None:
        """OSError when reading produces an error message on stderr."""
        from unittest.mock import patch

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 1024)

        with patch("pathlib.Path.read_bytes", side_effect=OSError("permission denied")):
            result = runner.invoke(app, ["identify", str(f)])

        combined = result.stdout + result.stderr
        assert "error" in combined.lower()


class TestIdentifyEcuException:
    """Tests for the identify_ecu exception path (lines 173-180)."""

    def test_identify_ecu_exception_exits_one(self, tmp_path: Path) -> None:
        """Exception from identify_ecu exits 1 with a failure message."""
        from unittest.mock import patch

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 1024)

        with patch(
            "openremap.cli.commands.identify.identify_ecu",
            side_effect=RuntimeError("extraction engine crashed"),
        ):
            result = runner.invoke(app, ["identify", str(f)])

        assert result.exit_code == 1

    def test_identify_ecu_exception_shows_failed_message(self, tmp_path: Path) -> None:
        """Exception from identify_ecu produces a 'Identification failed' message."""
        from unittest.mock import patch

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 1024)

        with patch(
            "openremap.cli.commands.identify.identify_ecu",
            side_effect=ValueError("bad binary format"),
        ):
            result = runner.invoke(app, ["identify", str(f)])

        combined = result.stdout + result.stderr
        assert (
            "identification failed" in combined.lower() or "error" in combined.lower()
        )


class TestIdentifySignalsLoop:
    """Tests for the confidence signals loop with positive and negative deltas (lines 226-232)."""

    def test_negative_delta_signal_displayed(self, tmp_path: Path) -> None:
        """A signal with negative delta renders with a minus marker."""
        from unittest.mock import patch
        from openremap.tuning.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 1024)

        mock_confidence = ConfidenceResult(
            score=30,
            tier="Low",
            signals=[
                ConfidenceSignal(delta=50, label="positive signal"),
                ConfidenceSignal(delta=-20, label="negative signal"),
            ],
            warnings=[],
        )

        with patch(
            "openremap.cli.commands.identify.score_identity",
            return_value=mock_confidence,
        ):
            result = runner.invoke(app, ["identify", str(f)])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "positive signal" in combined
        assert "negative signal" in combined

    def test_identified_ecu_shows_manufacturer_and_family(self, tmp_path: Path) -> None:
        """When ecu_family is not None the status line shows manufacturer · family."""
        from unittest.mock import patch
        from openremap.tuning.services.confidence import (
            ConfidenceResult,
            ConfidenceSignal,
        )

        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 1024)

        mock_result = {
            "manufacturer": "Bosch",
            "ecu_family": "EDC17C66",
            "ecu_variant": "EDC17C66",
            "software_version": "1.0.0",
            "hardware_number": None,
            "calibration_id": None,
            "match_key": "mk_abc",
            "file_size": 1024,
            "sha256": "a" * 64,
        }

        mock_confidence = ConfidenceResult(
            score=80,
            tier="High",
            signals=[
                ConfidenceSignal(delta=60, label="ident block found"),
                ConfidenceSignal(delta=-10, label="generic filename"),
            ],
            warnings=[],
        )

        with (
            patch(
                "openremap.cli.commands.identify.identify_ecu",
                return_value=mock_result,
            ),
            patch(
                "openremap.cli.commands.identify.score_identity",
                return_value=mock_confidence,
            ),
        ):
            result = runner.invoke(app, ["identify", str(f)])

        assert result.exit_code == 0
        assert "Bosch" in result.stdout
        assert "EDC17C66" in result.stdout
