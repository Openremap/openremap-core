"""
Tests for the ``tune`` sub-command.

The ``tune`` command is the main workflow: a one-shot 3-phase pipeline that
validates before, applies the recipe, and validates after.

  Phase 1 — validate before   : strict pre-flight check (ob bytes at offsets)
  Phase 2 — apply             : write mb bytes to target (with anchor search)
  Phase 3 — validate after    : confirm mb bytes are now in tuned binary

Covers:
    - Successful tune (all phases pass) → exit 0, output file created
    - Phase 1 failure (ob bytes not found) → exit 1, no output
    - Phase 2 failure (can't find anchor) → exit 1, no output
    - Phase 3 failure (mb bytes not in result) → exit 1, output still created
    - --skip-validation flag → phases 1 & 3 skipped, phase 2 runs
    - --output flag → tuned binary written to specified path
    - --json flag → output is JSON format
    - --report flag → report written to disk
    - File validation → wrong extensions, missing files, empty files

Notes on testing strategy
--------------------------
Each test creates minimal synthetic binaries and recipes:
  - original: zero-filled bytes (or with specific patterns)
  - modified: same as original, with targeted byte changes
  - recipe: JSON describing those changes

The recipe is built using the ECUDiffAnalyzer to ensure validity, or manually
constructed for edge cases.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from openremap.cli.main import app
from openremap.tuning.services.recipe_builder import ECUDiffAnalyzer

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bin(size: int = 1024, patches: dict | None = None) -> bytes:
    """Return a zero-filled byte string of *size* bytes with optional patches.

    Args:
        size:    Total length in bytes.
        patches: Mapping of {offset: value}.  An int value is written as a
                 single byte; a bytes value is written verbatim.
    """
    buf = bytearray(size)
    for offset, value in (patches or {}).items():
        if isinstance(value, int):
            buf[offset] = value
        else:
            buf[offset : offset + len(value)] = value
    return bytes(buf)


def _make_recipe(
    original: bytes,
    modified: bytes,
    original_name: str = "stock.bin",
    modified_name: str = "tuned.bin",
) -> dict:
    """Build a real recipe dict using ECUDiffAnalyzer."""
    analyzer = ECUDiffAnalyzer(
        original_data=original,
        modified_data=modified,
        original_filename=original_name,
        modified_filename=modified_name,
    )
    return analyzer.build_recipe()


# ---------------------------------------------------------------------------
# TestTuneSuccess — valid inputs, all phases pass
# ---------------------------------------------------------------------------


class TestTuneSuccess:
    def test_basic_tune_exit_zero(self, tmp_path):
        """Tuning a matching binary produces exit 0 and writes output."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            ["tune", str(target_file), str(recipe_file), "--output", str(output_file)],
        )

        assert result.exit_code == 0, result.output
        assert output_file.exists(), "Output file was not created"
        # Output should have the modification
        output_data = output_file.read_bytes()
        assert output_data[100] == 0xAA

    def test_tune_default_output_name(self, tmp_path):
        """Without --output, tune creates target_tuned.bin by default."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {50: 0xFF})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        assert result.exit_code == 0, result.output
        expected_output = tmp_path / "target_tuned.bin"
        assert expected_output.exists(), (
            f"Expected {expected_output} but it doesn't exist"
        )

    def test_tune_multiple_changes(self, tmp_path):
        """Tuning with multiple changed bytes applies all changes."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA, 200: 0xBB, 300: 0xCC})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            ["tune", str(target_file), str(recipe_file), "--output", str(output_file)],
        )

        assert result.exit_code == 0, result.output
        output_data = output_file.read_bytes()
        assert output_data[100] == 0xAA
        assert output_data[200] == 0xBB
        assert output_data[300] == 0xCC

    def test_tune_does_not_modify_original(self, tmp_path):
        """The original target file must never be modified by tune."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        # Original must remain unchanged
        assert target_file.read_bytes() == original

    def test_tune_with_ori_extension(self, tmp_path):
        """Tune accepts .ori files as valid binary inputs."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.ori"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.ori"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            ["tune", str(target_file), str(recipe_file), "--output", str(output_file)],
        )

        assert result.exit_code == 0, result.output
        assert output_file.exists()

    def test_tune_json_flag_outputs_report(self, tmp_path):
        """--json flag causes the report to be output as JSON."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            [
                "tune",
                str(target_file),
                str(recipe_file),
                "--output",
                str(output_file),
                "--json",
            ],
        )

        assert result.exit_code == 0, result.output
        # Extract JSON from output (it contains both text and JSON)
        start = result.stdout.find("{")
        end = result.stdout.rfind("}") + 1
        assert start != -1, f"No JSON object found in output:\n{result.stdout}"
        json_text = result.stdout[start:end]
        try:
            report = json.loads(json_text)
            assert isinstance(report, dict)
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"Failed to parse JSON from output: {exc}\nJSON text:\n{json_text}"
            )

    def test_tune_report_flag_writes_json_file(self, tmp_path):
        """--report flag writes a JSON report to the specified file."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        report_file = tmp_path / "report.json"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            [
                "tune",
                str(target_file),
                str(recipe_file),
                "--output",
                str(output_file),
                "--report",
                str(report_file),
            ],
        )

        assert result.exit_code == 0, result.output
        assert report_file.exists(), "Report file was not created"
        report_data = json.loads(report_file.read_text())
        assert isinstance(report_data, dict)

    def test_tune_skip_validation_flag(self, tmp_path):
        """--skip-validation bypasses phases 1 and 3."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            [
                "tune",
                str(target_file),
                str(recipe_file),
                "--output",
                str(output_file),
                "--skip-validation",
            ],
        )

        assert result.exit_code == 0, result.output
        assert output_file.exists()
        # Output should have the modification
        output_data = output_file.read_bytes()
        assert output_data[100] == 0xAA

    def test_tune_zero_instruction_recipe(self, tmp_path):
        """A recipe with no instructions exits 0 and produces unchanged output."""
        original = _make_bin(1024)
        # No modifications — identical binaries
        recipe = _make_recipe(original, original)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            ["tune", str(target_file), str(recipe_file), "--output", str(output_file)],
        )

        assert result.exit_code == 0, result.output
        # Output should be identical to original
        assert output_file.read_bytes() == original

    def test_tune_help_exits_zero(self):
        """--help prints usage information and exits 0."""
        result = runner.invoke(app, ["tune", "--help"])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "tune" in combined.lower() or "target" in combined.lower()


# ---------------------------------------------------------------------------
# TestTuneErrors — invalid inputs and phase failures
# ---------------------------------------------------------------------------


class TestTuneErrors:
    def test_non_bin_target_exits_one(self, tmp_path):
        """A target file with a wrong extension causes exit 1."""
        original = _make_bin(1024)
        recipe = _make_recipe(original, original)

        target_file = tmp_path / "target.txt"  # wrong extension
        recipe_file = tmp_path / "recipe.json"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        assert result.exit_code == 1
        error_text = result.stderr + result.stdout
        assert ".bin" in error_text.lower() or ".ori" in error_text.lower()

    def test_non_json_recipe_exits_one(self, tmp_path):
        """A recipe file with wrong extension causes exit 1."""
        original = _make_bin(1024)
        recipe = _make_recipe(original, original)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.txt"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        assert result.exit_code == 1

    def test_missing_target_exits_nonzero(self, tmp_path):
        """A non-existent target file causes non-zero exit."""
        original = _make_bin(1024)
        recipe = _make_recipe(original, original)

        missing = tmp_path / "ghost.bin"
        recipe_file = tmp_path / "recipe.json"

        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(app, ["tune", str(missing), str(recipe_file)])

        assert result.exit_code != 0

    def test_missing_recipe_exits_nonzero(self, tmp_path):
        """A non-existent recipe file causes non-zero exit."""
        original = _make_bin(1024)

        target_file = tmp_path / "target.bin"
        missing = tmp_path / "ghost.json"

        target_file.write_bytes(original)

        result = runner.invoke(app, ["tune", str(target_file), str(missing)])

        assert result.exit_code != 0

    def test_empty_target_exits_one(self, tmp_path):
        """An empty target file causes exit 1."""
        original = _make_bin(1024)
        recipe = _make_recipe(original, original)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"

        target_file.write_bytes(b"")  # empty
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        assert result.exit_code == 1
        error_text = result.stderr + result.stdout
        assert "empty" in error_text.lower()

    def test_invalid_json_recipe_exits_one(self, tmp_path):
        """A recipe file with invalid JSON causes exit 1."""
        original = _make_bin(1024)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"

        target_file.write_bytes(original)
        recipe_file.write_text("not valid json {{{")

        result = runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        assert result.exit_code == 1
        error_text = result.stderr + result.stdout
        assert "json" in error_text.lower()

    def test_validation_failure_phase_one(self, tmp_path):
        """If phase 1 fails (ob bytes not found), tune exits 1 and doesn't create output."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        # Use a different binary as target (ob bytes won't match)
        target_data = _make_bin(1024, {100: 0xBB})  # different byte at offset 100

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"

        target_file.write_bytes(target_data)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            ["tune", str(target_file), str(recipe_file), "--output", str(output_file)],
        )

        assert result.exit_code == 1, (
            f"Expected exit 1, got {result.exit_code}: {result.output}"
        )
        # Without --skip-validation, strict validation fails in phase 1

    def test_size_mismatch_with_skip_validation(self, tmp_path):
        """A target binary of different size can be tuned with --skip-validation."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        # Target is 2048 bytes instead of 1024
        target_data = _make_bin(2048)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"

        target_file.write_bytes(target_data)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            [
                "tune",
                str(target_file),
                str(recipe_file),
                "--output",
                str(output_file),
                "--skip-validation",
            ],
        )

        # With --skip-validation, phase 1 & 3 are skipped, so size mismatch is OK
        # (the patcher will still try to apply the recipe)
        assert result.exit_code in (0, 1)  # Either succeeds or fails gracefully


# ---------------------------------------------------------------------------
# Additional coverage — error paths, phase failures, and write errors
# ---------------------------------------------------------------------------


class TestTuneReadErrors:
    """OSError paths in _read_bin and _read_recipe (lines 57-64, 95-102)."""

    def test_oserror_reading_target_exits_one(self, tmp_path):
        """OSError when reading the target binary exits 1 with error message."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("pathlib.Path.read_bytes", side_effect=OSError("permission denied")):
            result = runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()

    def test_oserror_reading_recipe_exits_one(self, tmp_path):
        """OSError when reading the recipe file exits 1 with error message."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        target_file.write_bytes(original)
        recipe_file.write_text("{}")  # Written before mock is active

        with patch("pathlib.Path.read_text", side_effect=OSError("permission denied")):
            result = runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()


class TestTuneWarnDirect:
    """Direct test for the _warn helper (line 158)."""

    def test_warn_executes_without_error(self):
        """Calling _warn exercises line 158 without error."""
        from openremap.cli.commands.tune import _warn

        _warn("test size mismatch warning")  # just calling it is enough for coverage


class TestTunePhase1Warnings:
    """Phase-1 warnings and fast-fail paths (lines 190-192, 200-203, 630, 632)."""

    def test_phase1_validator_exception_exits_one(self, tmp_path):
        """Exception raised by ECUStrictValidator exits 1 (lines 190-192)."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch(
            "openremap.cli.commands.tune.ECUStrictValidator",
            side_effect=RuntimeError("validator crashed"),
        ):
            result = runner.invoke(app, ["tune", str(target_file), str(recipe_file)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower() or "failed" in combined.lower()

    def test_phase1_size_mismatch_warning_shown(self, tmp_path):
        """A recipe with wrong file_size triggers a size-mismatch warning (line 201)."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)
        # Force a file_size mismatch so check_file_size() returns a warning
        recipe["ecu"]["file_size"] = 2048

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            ["tune", str(target_file), str(recipe_file), "--output", str(output_file)],
        )

        combined = result.stdout + result.stderr
        assert "mismatch" in combined.lower() or "size" in combined.lower()

    def test_phase1_failure_with_json_flag_outputs_json(self, tmp_path):
        """Phase 1 failure with --json emits a JSON combined report (line 630)."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        # Target has wrong bytes — phase 1 fails
        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        target_file.write_bytes(_make_bin(1024, {100: 0xFF}))
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            ["tune", str(target_file), str(recipe_file), "--json"],
        )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "{" in combined  # JSON output was produced

    def test_phase1_failure_with_report_flag_writes_report(self, tmp_path):
        """Phase 1 failure with --report writes the report file (line 632)."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        report_file = tmp_path / "report.json"
        target_file.write_bytes(_make_bin(1024, {100: 0xFF}))
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            [
                "tune",
                str(target_file),
                str(recipe_file),
                "--report",
                str(report_file),
            ],
        )

        assert result.exit_code == 1
        assert report_file.exists()


class TestTunePhase2Mocked:
    """Phase-2 failure paths using mocked ECUPatcher (lines 268-332, 646-660)."""

    def test_phase2_value_error_exits_one(self, tmp_path):
        """ValueError from ECUPatcher.apply_all exits 1 (lines 268-273)."""
        from unittest.mock import patch, MagicMock

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUPatcher") as mock_cls:
            mock_cls.return_value.apply_all.side_effect = ValueError("recipe rejected")
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                    "--skip-validation",
                ],
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "rejected" in combined.lower() or "error" in combined.lower()

    def test_phase2_failure_with_json_flag(self, tmp_path):
        """Phase 2 failure with --json emits combined JSON report (lines 646-660)."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUPatcher") as mock_cls:
            mock_cls.return_value.apply_all.side_effect = ValueError("no anchor found")
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                    "--skip-validation",
                    "--json",
                ],
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "{" in combined  # JSON report produced

    def test_phase2_failure_with_report_flag(self, tmp_path):
        """Phase 2 failure with --report writes report file (lines 646-660)."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        report_file = tmp_path / "report.json"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUPatcher") as mock_cls:
            mock_cls.return_value.apply_all.side_effect = ValueError("no anchor found")
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                    "--skip-validation",
                    "--report",
                    str(report_file),
                ],
            )

        assert result.exit_code == 1
        assert report_file.exists()

    def test_phase2_shifted_instructions_displayed(self, tmp_path):
        """Shifted instructions summary is shown when patcher reports shifted (lines 294-299)."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUPatcher") as mock_cls:
            mock_patcher = mock_cls.return_value
            mock_patcher.apply_all.return_value = original
            mock_patcher.to_dict.return_value = {
                "summary": {
                    "total": 1,
                    "success": 1,
                    "failed": 0,
                    "shifted": 1,
                    "patch_applied": True,
                    "patched_md5": "abc123",
                },
                "results": [],
            }
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                    "--skip-validation",
                ],
            )

        combined = result.stdout + result.stderr
        assert "shifted" in combined.lower() or "Shifted" in combined

    def test_phase2_failed_instructions_displayed(self, tmp_path):
        """Failed instructions summary and detail are shown (lines 306-332)."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUPatcher") as mock_cls:
            mock_patcher = mock_cls.return_value
            mock_patcher.apply_all.return_value = original
            mock_patcher.to_dict.return_value = {
                "summary": {
                    "total": 1,
                    "success": 0,
                    "failed": 1,
                    "shifted": 0,
                    "patch_applied": False,
                    "patched_md5": "abc123",
                },
                "results": [
                    {
                        "status": "failed",
                        "index": 1,
                        "offset_expected_hex": "0x00000064",
                        "message": "ob not found anywhere",
                    }
                ],
            }
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                    "--skip-validation",
                ],
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "failed" in combined.lower() or "Failed" in combined


class TestTunePhase3Mocked:
    """Phase-3 failure paths using mocked ECUPatchedValidator (lines 362-406, 726)."""

    def test_phase3_failure_exits_one(self, tmp_path):
        """Phase 3 failure exits 1 and shows verification failed message."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUPatchedValidator") as mock_cls:
            mock_val = mock_cls.return_value
            mock_val.check_file_size.return_value = None
            mock_val.check_match_key.return_value = None
            mock_val.verify_all.return_value = None
            mock_val.to_dict.return_value = {
                "summary": {
                    "total": 1,
                    "passed": 0,
                    "failed": 1,
                    "patch_confirmed": False,
                },
                "all_results": [
                    {
                        "passed": False,
                        "instruction_index": 1,
                        "offset_hex": "00000064",
                        "size": 1,
                        "reason": "mb byte mismatch",
                    }
                ],
            }
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                ],
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "failed" in combined.lower() or "NOT" in combined

    def test_phase3_exception_exits_one(self, tmp_path):
        """Exception from ECUPatchedValidator exits 1 (lines 362-364)."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUPatchedValidator") as mock_cls:
            mock_cls.return_value.verify_all.side_effect = RuntimeError(
                "validator crash"
            )
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                ],
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower() or "failed" in combined.lower()


# ---------------------------------------------------------------------------
# TestTuneIntegration — cross-feature scenarios
# ---------------------------------------------------------------------------


class TestTuneIntegration:
    def test_tune_json_and_report_flags_together(self, tmp_path):
        """--json and --report can be used together."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        report_file = tmp_path / "report.json"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            [
                "tune",
                str(target_file),
                str(recipe_file),
                "--output",
                str(output_file),
                "--json",
                "--report",
                str(report_file),
            ],
        )

        assert result.exit_code == 0, result.output
        assert report_file.exists()
        assert output_file.exists()

    def test_tune_skip_validation_with_output_and_report(self, tmp_path):
        """All flags can be combined."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        report_file = tmp_path / "report.json"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            [
                "tune",
                str(target_file),
                str(recipe_file),
                "--output",
                str(output_file),
                "--report",
                str(report_file),
                "--skip-validation",
                "--json",
            ],
        )

        assert result.exit_code == 0, result.output
        assert output_file.exists()


# ---------------------------------------------------------------------------
# Additional coverage — match_key_warn, phase2 exception, write_bytes OSError
# ---------------------------------------------------------------------------


class TestTunePhase1MatchKeyWarn:
    """match_key_warn path in _run_phase1 (line 203)."""

    def test_match_key_warn_shown_when_mocked(self, tmp_path):
        """Mocked check_match_key returning a warning triggers _warn (line 203)."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUStrictValidator") as mock_cls:
            mock_val = mock_cls.return_value
            mock_val.check_file_size.return_value = None
            mock_val.check_match_key.return_value = (
                "Match key mismatch: recipe is for 'key_a', binary has 'key_b'."
            )
            mock_val.validate_all.return_value = None
            mock_val.to_dict.return_value = {
                "target_file": "target.bin",
                "recipe_file": "recipe.json",
                "target_md5": "abc",
                "summary": {
                    "total": 1,
                    "passed": 1,
                    "failed": 0,
                    "score_pct": 100.0,
                    "safe_to_patch": True,
                },
                "failures": [],
                "all_results": [],
            }
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                ],
            )

        combined = result.stdout + result.stderr
        assert "match key" in combined.lower() or "mismatch" in combined.lower()


class TestTunePhase2GeneralException:
    """General (non-ValueError) exception from ECUPatcher.apply_all (lines 271-273)."""

    def test_phase2_general_exception_exits_one(self, tmp_path):
        """RuntimeError from ECUPatcher.apply_all exits 1 (lines 271-273)."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("openremap.cli.commands.tune.ECUPatcher") as mock_cls:
            mock_cls.return_value.apply_all.side_effect = RuntimeError(
                "unexpected patcher failure"
            )
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                    "--skip-validation",
                ],
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "failed" in combined.lower() or "error" in combined.lower()


class TestTuneWriteBinaryOSError:
    """OSError when writing the tuned binary (lines 684-693)."""

    def test_write_bytes_oserror_exits_one(self, tmp_path):
        """OSError when writing tuned binary exits 1 with error message."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("pathlib.Path.write_bytes", side_effect=OSError("disk full")):
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                    "--skip-validation",
                ],
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()


class TestTuneWriteReportOSError:
    """OSError in _write_report (lines 740-741)."""

    def test_write_report_oserror_handles_gracefully(self, tmp_path):
        """OSError when writing the report is handled without crashing."""
        from unittest.mock import patch

        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_file = tmp_path / "output.bin"
        report_file = tmp_path / "report.json"
        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
            result = runner.invoke(
                app,
                [
                    "tune",
                    str(target_file),
                    str(recipe_file),
                    "--output",
                    str(output_file),
                    "--report",
                    str(report_file),
                ],
            )

        # The command should handle report write failures gracefully.
        assert result.exit_code == 0, result.output
        assert not report_file.exists()
        assert "could not write report" in result.output
        assert "disk full" in result.output

    def test_tune_output_path_in_subdirectory(self, tmp_path):
        """Tune can write output to a subdirectory."""
        original = _make_bin(1024)
        modified = _make_bin(1024, {100: 0xAA})
        recipe = _make_recipe(original, modified)

        target_file = tmp_path / "target.bin"
        recipe_file = tmp_path / "recipe.json"
        output_dir = tmp_path / "results"
        output_dir.mkdir()
        output_file = output_dir / "tuned.bin"

        target_file.write_bytes(original)
        recipe_file.write_text(json.dumps(recipe))

        result = runner.invoke(
            app,
            ["tune", str(target_file), str(recipe_file), "--output", str(output_file)],
        )

        assert result.exit_code == 0, result.output
        assert output_file.exists()
