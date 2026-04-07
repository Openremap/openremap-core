"""
Tests for `openremap validate before / check / after`.

Sub-commands are invoked via:
    runner.invoke(app, ["validate", "before", str(target), str(recipe)])
    runner.invoke(app, ["validate", "check",  str(target), str(recipe)])
    runner.invoke(app, ["validate", "after",  str(target), str(recipe)])

Exit-code contract (derived from the validate command source):
  before (human-readable mode):
    0  — all instructions matched ob at exact offsets ("Safe to tune")
    1  — one or more instructions failed; or wrong extension; or I/O error
    2  — file does not exist (Click enforces exists=True on both arguments)

  before (--json mode):
    0  — always; the report JSON is emitted and the command returns early
         before the human-readable exit-1 gate, even when validation fails

  check:
    0  — verdict is safe_exact or shifted_recoverable
    1  — verdict is missing_unrecoverable; or wrong extension / file missing

  after:
    0  — all mb bytes confirmed at their offsets
    1  — one or more mb bytes missing; or wrong extension / file missing
"""

import json

import pytest
from pathlib import Path
from typer.testing import CliRunner

from openremap.cli.main import app

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


def _write_recipe(
    path: Path,
    instructions: list | None = None,
    file_size: int = 1024,
) -> None:
    """Write a minimal but fully-valid format-4.0 recipe to *path*.

    Args:
        path:         Destination path (must have a .openremap extension).
        instructions: List of instruction dicts.  Defaults to one instruction
                      at offset 100, ob=``AA``, mb=``BB``.
        file_size:    Value recorded in ``ecu.file_size``; should match the
                      binary being validated to avoid spurious size warnings.
    """
    if instructions is None:
        instructions = [_instruction()]
    recipe = {
        "metadata": {
            "format_version": "4.0",
            "original_file": "stock.bin",
            "modified_file": "tuned.bin",
            "original_size": file_size,
            "modified_size": file_size,
            "context_size": 32,
            "description": "test recipe",
        },
        "ecu": {
            "manufacturer": None,
            "match_key": None,
            "ecu_family": None,
            "ecu_variant": None,
            "software_version": None,
            "hardware_number": None,
            "calibration_id": None,
            "file_size": file_size,
            "sha256": "abc",
        },
        "statistics": {"total_changes": len(instructions)},
        "instructions": instructions,
    }
    path.write_text(json.dumps(recipe, indent=2), encoding="utf-8")


def _instruction(
    offset: int = 100,
    ob: str = "AA",
    mb: str = "BB",
    ctx: str = "",
) -> dict:
    """Return a single recipe instruction dict.

    Args:
        offset: Byte offset in the binary.
        ob:     Original bytes as an uppercase hex string.
        mb:     Modified bytes as an uppercase hex string.
        ctx:    Context-before bytes as an uppercase hex string (may be empty).
    """
    ob = ob.upper()
    mb = mb.upper()
    size = len(bytes.fromhex(ob))
    return {
        "offset": offset,
        "offset_hex": f"{offset:X}",
        "size": size,
        "ob": ob,
        "mb": mb,
        "ctx": ctx.upper(),
        "context_after": "",
        "context_size": len(bytes.fromhex(ctx)) if ctx else 0,
        "description": f"{size} byte(s) at 0x{offset:X} modified",
    }


def _parse_json_from_stdout(stdout: str) -> dict:
    """Extract and parse the first top-level JSON object found in *stdout*.

    The validate commands print a heading line before the JSON body.
    We locate the outermost ``{…}`` block and parse that.
    """
    start = stdout.find("{")
    end = stdout.rfind("}") + 1
    assert start != -1, f"No JSON object found in stdout:\n{stdout}"
    return json.loads(stdout[start:end])


# ---------------------------------------------------------------------------
# TestValidateBeforeSuccess
# ---------------------------------------------------------------------------


class TestValidateBeforeSuccess:
    def test_matching_binary_exits_zero(self, tmp_path):
        """Binary with ob=AA at offset 100 passes pre-flight and exits 0."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        # ob = "AA" → byte 0xAA must be at offset 100
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        assert result.exit_code == 0, result.output

    def test_matching_binary_reports_safe_to_tune(self, tmp_path):
        """The human-readable output explicitly states 'Safe to tune'."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        assert "safe to tune" in result.stdout.lower(), (
            f"Expected 'Safe to tune' in output:\n{result.stdout}"
        )

    def test_json_flag_outputs_json_report(self, tmp_path):
        """--json emits the validation report as a JSON object and exits 0."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(
            app, ["validate", "before", str(target), str(recipe), "--json"]
        )

        assert result.exit_code == 0, result.output
        report = _parse_json_from_stdout(result.stdout)
        assert "summary" in report

    def test_json_flag_report_has_safe_to_patch_true(self, tmp_path):
        """With --json the summary.safe_to_patch flag is True on a matching binary."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(
            app, ["validate", "before", str(target), str(recipe), "--json"]
        )

        report = _parse_json_from_stdout(result.stdout)
        assert report["summary"]["safe_to_patch"] is True

    def test_json_flag_on_mismatch_still_exits_zero(self, tmp_path):
        """--json always exits 0, even when ob bytes are absent.

        The command returns the report JSON and exits before the human-readable
        exit-1 gate, so --json suppresses the non-zero exit on failure.
        """
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        # Byte at offset 100 is 0x00, not 0xAA — validation will fail
        target.write_bytes(_make_bin(1024))
        _write_recipe(recipe)

        result = runner.invoke(
            app, ["validate", "before", str(target), str(recipe), "--json"]
        )

        assert result.exit_code == 0, result.output
        report = _parse_json_from_stdout(result.stdout)
        assert report["summary"]["safe_to_patch"] is False

    def test_json_report_contains_target_and_recipe_filenames(self, tmp_path):
        """The JSON report includes target_file and recipe_file fields."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(
            app, ["validate", "before", str(target), str(recipe), "--json"]
        )

        report = _parse_json_from_stdout(result.stdout)
        assert "target_file" in report
        assert "recipe_file" in report

    def test_zero_instruction_recipe_exits_zero(self, tmp_path):
        """A recipe with no instructions is trivially safe: exits 0."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024))
        _write_recipe(recipe, instructions=[])

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        assert result.exit_code == 0, result.output

    def test_before_help_exits_zero(self):
        """validate before --help exits 0."""
        result = runner.invoke(app, ["validate", "before", "--help"])

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# TestValidateBeforeFailure
# ---------------------------------------------------------------------------


class TestValidateBeforeFailure:
    def test_mismatching_binary_exits_one(self, tmp_path):
        """Binary whose byte at offset 100 does not equal ob=AA exits 1.

        Note: in human-readable mode (no --json) the validate before command
        raises typer.Exit(code=1) when any instruction fails.  Use --json if
        you need a zero exit regardless of validation outcome.
        """
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        # Offset 100 is 0xFF, recipe expects 0xAA
        target.write_bytes(_make_bin(1024, {100: 0xFF}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        assert result.exit_code == 1

    def test_mismatching_binary_reports_not_safe(self, tmp_path):
        """The human-readable output states the binary is NOT safe to tune."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xFF}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        combined = result.stdout + result.stderr
        assert "not safe" in combined.lower() or "failed" in combined.lower(), (
            f"Expected failure message in output:\n{combined}"
        )

    def test_non_bin_target_exits_one(self, tmp_path):
        """Target file with wrong extension causes exit 1.

        The file must exist so Click's exists=True check passes; the command's
        own _read_bin helper then rejects the extension with exit 1.
        """
        target = tmp_path / "target.txt"  # wrong extension, file exists
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        assert result.exit_code == 1
        error_text = result.stderr + result.stdout
        assert "bin" in error_text.lower() or "ori" in error_text.lower()

    def test_non_json_recipe_exits_one(self, tmp_path):
        """Recipe file with wrong extension causes exit 1.

        The file must exist; _read_recipe then rejects the extension.
        """
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.txt"  # wrong extension, file exists
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        recipe.write_text(json.dumps({}), encoding="utf-8")

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        assert result.exit_code == 1
        error_text = result.stderr + result.stdout
        assert "openremap" in error_text.lower()

    def test_missing_target_exits_nonzero(self, tmp_path):
        """A non-existent target file causes a non-zero exit (Click exists=True)."""
        missing = tmp_path / "ghost.bin"
        recipe = tmp_path / "recipe.openremap"
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "before", str(missing), str(recipe)])

        assert result.exit_code != 0

    def test_missing_recipe_exits_nonzero(self, tmp_path):
        """A non-existent recipe file causes a non-zero exit (Click exists=True)."""
        target = tmp_path / "target.bin"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        missing = tmp_path / "ghost.openremap"

        result = runner.invoke(app, ["validate", "before", str(target), str(missing)])

        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# TestValidateCheck
# ---------------------------------------------------------------------------


class TestValidateCheck:
    def test_ob_at_exact_offset_exits_zero(self, tmp_path):
        """ob bytes found at the exact expected offset → verdict safe_exact → exit 0."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 0, result.output

    def test_ob_shifted_exits_zero(self, tmp_path):
        """ob bytes found but at a different offset → shifted_recoverable → exit 0.

        The patcher's ±2 KB anchor search can still recover shifted bytes;
        the check command therefore exits 0 (not 1) for shifted results.
        """
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        # ob = "AA" is at offset 200, not 100 — shifted by +100
        target.write_bytes(_make_bin(1024, {200: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 0, result.output

    def test_ob_missing_exits_one(self, tmp_path):
        """ob bytes absent from the entire binary → missing_unrecoverable → exit 1."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        # Binary is all zeros; ob=AA is nowhere in it
        target.write_bytes(_make_bin(1024))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 1

    def test_check_json_flag_exits_zero(self, tmp_path):
        """--json always exits 0 and emits a JSON report."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(
            app, ["validate", "check", str(target), str(recipe), "--json"]
        )

        assert result.exit_code == 0, result.output
        report = _parse_json_from_stdout(result.stdout)
        assert "summary" in report

    def test_check_json_report_has_verdict(self, tmp_path):
        """The JSON report from validate check includes a verdict field."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(
            app, ["validate", "check", str(target), str(recipe), "--json"]
        )

        report = _parse_json_from_stdout(result.stdout)
        assert "verdict" in report["summary"]
        assert report["summary"]["verdict"] == "safe_exact"

    def test_non_bin_target_exits_one(self, tmp_path):
        """Wrong target extension causes exit 1 (extension checked before search)."""
        target = tmp_path / "target.txt"  # wrong extension, file exists
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 1

    def test_non_json_recipe_exits_one(self, tmp_path):
        """Wrong recipe extension causes exit 1."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.txt"  # wrong extension, file exists
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        recipe.write_text(json.dumps({}), encoding="utf-8")

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 1

    def test_zero_instruction_recipe_exits_zero(self, tmp_path):
        """An empty recipe is trivially safe: no missing bytes → exit 0."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024))
        _write_recipe(recipe, instructions=[])

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 0, result.output

    def test_check_help_exits_zero(self):
        """validate check --help exits 0."""
        result = runner.invoke(app, ["validate", "check", "--help"])

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# TestValidateAfter
# ---------------------------------------------------------------------------


class TestValidateAfter:
    def test_patched_binary_exits_zero(self, tmp_path):
        """Binary with mb=BB at offset 100 confirms the patch and exits 0."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        # mb = "BB" → byte 0xBB must be at offset 100
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        assert result.exit_code == 0, result.output

    def test_patched_binary_reports_tune_confirmed(self, tmp_path):
        """The human-readable output states the tune was confirmed."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        combined = result.stdout + result.stderr
        assert "confirmed" in combined.lower(), (
            f"Expected 'confirmed' in output:\n{combined}"
        )

    def test_unpatched_binary_exits_one(self, tmp_path):
        """Binary that still has ob (not mb) at offset 100 fails confirmation → exit 1."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        # ob byte 0xAA is still at offset 100 — patch was never applied
        tuned.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        assert result.exit_code == 1

    def test_after_json_flag_exits_zero(self, tmp_path):
        """--json emits the verification report as JSON and exits 0."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        result = runner.invoke(
            app, ["validate", "after", str(tuned), str(recipe), "--json"]
        )

        assert result.exit_code == 0, result.output
        report = _parse_json_from_stdout(result.stdout)
        assert "summary" in report

    def test_after_json_report_has_patch_confirmed_true(self, tmp_path):
        """The JSON report summary.patch_confirmed flag is True for a patched binary."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        result = runner.invoke(
            app, ["validate", "after", str(tuned), str(recipe), "--json"]
        )

        report = _parse_json_from_stdout(result.stdout)
        assert report["summary"]["patch_confirmed"] is True

    def test_non_bin_tuned_file_exits_one(self, tmp_path):
        """Wrong extension on the tuned binary causes exit 1."""
        tuned = tmp_path / "target_tuned.txt"  # wrong extension, file exists
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        assert result.exit_code == 1
        error_text = result.stderr + result.stdout
        assert "bin" in error_text.lower() or "ori" in error_text.lower()

    def test_non_json_recipe_exits_one(self, tmp_path):
        """Wrong recipe extension causes exit 1."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.txt"  # wrong extension, file exists
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        recipe.write_text(json.dumps({}), encoding="utf-8")

        result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        assert result.exit_code == 1
        error_text = result.stderr + result.stdout
        assert "openremap" in error_text.lower()

    def test_after_help_exits_zero(self):
        """validate after --help exits 0."""
        result = runner.invoke(app, ["validate", "after", "--help"])

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# TestValidateHelp — top-level sub-app help
# ---------------------------------------------------------------------------


class TestValidateHelp:
    def test_validate_help_exits_zero(self):
        """validate --help exits 0 and lists all sub-commands."""
        result = runner.invoke(app, ["validate", "--help"])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "before" in combined.lower()
        assert "check" in combined.lower()
        assert "after" in combined.lower()


# ===========================================================================
# Additional coverage tests — uncovered paths in validate.py
# ===========================================================================


def _write_recipe_with_file_size(path, file_size: int, instructions=None) -> None:
    """Write a recipe with a specific ecu.file_size (for size-mismatch tests)."""
    import json as _json

    if instructions is None:
        instructions = [_instruction()]
    recipe = {
        "metadata": {
            "format_version": "4.0",
            "original_file": "stock.bin",
            "modified_file": "tuned.bin",
            "original_size": 1024,
            "modified_size": 1024,
            "context_size": 32,
            "description": "test",
        },
        "ecu": {
            "manufacturer": None,
            "match_key": None,
            "ecu_family": None,
            "ecu_variant": None,
            "software_version": None,
            "hardware_number": None,
            "calibration_id": None,
            "file_size": file_size,
            "sha256": "abc",
        },
        "statistics": {"total_changes": len(instructions)},
        "instructions": instructions,
    }
    path.write_text(_json.dumps(recipe, indent=2), encoding="utf-8")


class TestValidateReadErrors:
    """OSError and empty-file paths in _read_bin (lines 64-82)."""

    def test_read_bin_oserror_before_exits_one(self, tmp_path):
        """OSError reading the target binary exits 1 for 'validate before'."""
        from unittest.mock import patch

        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        with patch("pathlib.Path.read_bytes", side_effect=OSError("permission denied")):
            result = runner.invoke(
                app, ["validate", "before", str(target), str(recipe)]
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()

    def test_read_bin_empty_file_before_exits_one(self, tmp_path):
        """A zero-byte target file exits 1 with an error message."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(b"")
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "empty" in combined.lower()

    def test_read_bin_empty_file_check_exits_one(self, tmp_path):
        """A zero-byte target file exits 1 for 'validate check'."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(b"")
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "empty" in combined.lower()

    def test_read_bin_empty_file_after_exits_one(self, tmp_path):
        """A zero-byte tuned file exits 1 for 'validate after'."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(b"")
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "empty" in combined.lower()


class TestValidateReadRecipeErrors:
    """OSError and invalid-JSON paths in _read_recipe (lines 102-122)."""

    def test_read_recipe_oserror_exits_one(self, tmp_path):
        """OSError reading the recipe file exits 1 with error message."""
        from unittest.mock import patch

        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        with patch("pathlib.Path.read_text", side_effect=OSError("permission denied")):
            result = runner.invoke(
                app, ["validate", "before", str(target), str(recipe)]
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()

    def test_read_recipe_invalid_json_exits_one(self, tmp_path):
        """A recipe with invalid JSON exits 1 with a JSON parse error message."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        recipe.write_text("{ this is not valid json }", encoding="utf-8")

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "json" in combined.lower()

    def test_read_recipe_invalid_json_check_exits_one(self, tmp_path):
        """Invalid recipe JSON exits 1 for 'validate check'."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        recipe.write_text("not json at all", encoding="utf-8")

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 1


class TestValidateWriteJSON:
    """Output-file path and OSError in _write_json (lines 129-142)."""

    def test_before_with_output_file_creates_file(self, tmp_path):
        """validate before --output writes the JSON report to disk (lines 129-134)."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        output = tmp_path / "report.json"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(
            app,
            ["validate", "before", str(target), str(recipe), "--output", str(output)],
        )

        assert result.exit_code == 0
        assert output.exists()

    def test_check_with_output_file_creates_file(self, tmp_path):
        """validate check --output writes the JSON report to disk."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        output = tmp_path / "report.json"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(
            app,
            ["validate", "check", str(target), str(recipe), "--output", str(output)],
        )

        assert result.exit_code == 0
        assert output.exists()

    def test_after_with_output_file_creates_file(self, tmp_path):
        """validate after --output writes the JSON report to disk."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        output = tmp_path / "report.json"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        result = runner.invoke(
            app,
            ["validate", "after", str(tuned), str(recipe), "--output", str(output)],
        )

        assert result.exit_code == 0
        assert output.exists()

    def test_before_output_oserror_exits_one(self, tmp_path):
        """OSError writing the output JSON file exits 1 (lines 135-142)."""
        from unittest.mock import patch

        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        output = tmp_path / "report.json"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
            result = runner.invoke(
                app,
                [
                    "validate",
                    "before",
                    str(target),
                    str(recipe),
                    "--output",
                    str(output),
                ],
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()


class TestValidateWarnLine:
    """_warn_line output for size and match-key mismatches (lines 150, 154)."""

    def test_size_mismatch_warning_shown_in_before(self, tmp_path):
        """Recipe ecu.file_size mismatch shows size warning (line 150)."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        # Target is 1024 bytes; recipe declares 2048 — triggers size_warn
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe_with_file_size(recipe, file_size=2048)

        result = runner.invoke(app, ["validate", "before", str(target), str(recipe)])

        combined = result.stdout + result.stderr
        assert "size" in combined.lower() or "mismatch" in combined.lower()

    def test_match_key_mismatch_warning_shown_in_before(self, tmp_path):
        """Recipe ecu.match_key mismatch shows match-key warning (line 154)."""
        from unittest.mock import patch

        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        data = json.loads(recipe.read_text(encoding="utf-8"))
        data.setdefault("ecu", {})["match_key"] = "MISMATCH::KEY"
        recipe.write_text(json.dumps(data), encoding="utf-8")

        with patch(
            "openremap.core.services.validate_strict.identify_ecu",
            return_value={"match_key": "ACTUAL::KEY"},
        ):
            result = runner.invoke(
                app, ["validate", "before", str(target), str(recipe)]
            )

        combined = result.stdout + result.stderr
        assert "match key mismatch" in combined.lower()

    def test_size_mismatch_warning_shown_in_check(self, tmp_path):
        """validate check also shows size warning when file_size mismatches."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe_with_file_size(recipe, file_size=2048)

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        combined = result.stdout + result.stderr
        assert "size" in combined.lower() or "mismatch" in combined.lower()

    def test_size_mismatch_warning_shown_in_after(self, tmp_path):
        """validate after also shows size warning when file_size mismatches."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe_with_file_size(recipe, file_size=2048)

        result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        combined = result.stdout + result.stderr
        assert "size" in combined.lower() or "mismatch" in combined.lower()


class TestValidateBeforeException:
    """Exception path in _run_before (lines 194-203)."""

    def test_validator_exception_exits_one(self, tmp_path):
        """Exception from ECUStrictValidator exits 1 with error message."""
        from unittest.mock import patch

        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        with patch(
            "openremap.cli.commands.validate.ECUStrictValidator",
            side_effect=RuntimeError("validator internal error"),
        ):
            result = runner.invoke(
                app, ["validate", "before", str(target), str(recipe)]
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()


class TestValidateBeforeFailedResults:
    """Failed-instructions detail block in _run_before (lines 246-257)."""

    def test_failed_instructions_shown_when_results_key_present(self, tmp_path):
        """Mocked validator with 'results' key triggers failed-instructions display."""
        from unittest.mock import patch

        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        mock_report = {
            "target_file": "target.bin",
            "recipe_file": "recipe.openremap",
            "target_md5": "abc123",
            "summary": {
                "total": 1,
                "passed": 0,
                "failed": 1,
                "score_pct": 0.0,
                "safe_to_patch": False,
            },
            # Use "results" key (the key _run_before looks for)
            "results": [
                {
                    "instruction_index": 1,
                    "offset": 100,
                    "offset_expected_hex": "0x64",
                    "index": 1,
                    "passed": False,
                    "reason": "ob not found at offset",
                    "message": "ob not found at offset",
                }
            ],
            "all_results": [],
            "failures": [],
        }

        with patch("openremap.cli.commands.validate.ECUStrictValidator") as mock_cls:
            mock_val = mock_cls.return_value
            mock_val.check_file_size.return_value = None
            mock_val.check_match_key.return_value = None
            mock_val.validate_all.return_value = None
            mock_val.to_dict.return_value = mock_report

            result = runner.invoke(
                app, ["validate", "before", str(target), str(recipe)]
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "failed" in combined.lower() or "NOT" in combined

    def test_failed_instructions_more_than_ten_shows_summary_line(self, tmp_path):
        """More than ten failed results shows the truncated-summary message (line 257)."""
        from unittest.mock import patch

        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        results = []
        for i in range(12):
            results.append(
                {
                    "instruction_index": i + 1,
                    "offset": 100 + i,
                    "offset_expected_hex": hex(100 + i),
                    "index": i + 1,
                    "passed": False,
                    "reason": "ob not found at offset",
                    "message": "ob not found at offset",
                }
            )

        mock_report = {
            "target_file": "target.bin",
            "recipe_file": "recipe.openremap",
            "target_md5": "abc123",
            "summary": {
                "total": 12,
                "passed": 0,
                "failed": 12,
                "score_pct": 0.0,
                "safe_to_patch": False,
            },
            "results": results,
            "all_results": [],
            "failures": [],
        }

        with patch("openremap.cli.commands.validate.ECUStrictValidator") as mock_cls:
            mock_val = mock_cls.return_value
            mock_val.check_file_size.return_value = None
            mock_val.check_match_key.return_value = None
            mock_val.validate_all.return_value = None
            mock_val.to_dict.return_value = mock_report

            result = runner.invoke(
                app, ["validate", "before", str(target), str(recipe)]
            )

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "and 2 more" in combined.lower()
        assert "use --json for the full report" in combined.lower()


class TestValidateCheckException:
    """Exception path in _run_check (lines 306-315)."""

    def test_existence_validator_exception_exits_one(self, tmp_path):
        """Exception from ECUExistenceValidator exits 1 with error message."""
        from unittest.mock import patch

        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        with patch(
            "openremap.cli.commands.validate.ECUExistenceValidator",
            side_effect=RuntimeError("existence validator crashed"),
        ):
            result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()


class TestValidateCheckShiftedAndMissingDetail:
    """Shifted and missing instruction detail display in _run_check (lines 306-315)."""

    def test_shifted_instructions_display(self, tmp_path):
        """ob found at shifted offset → shifted detail is shown in output."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        # ob = "AA" at offset 100 in recipe, but binary has 0xAA at offset 200
        target.write_bytes(_make_bin(1024, {200: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 0
        combined = result.stdout + result.stderr
        assert "shifted" in combined.lower() or "SHIFTED" in combined

    def test_missing_instructions_display(self, tmp_path):
        """ob absent from the binary → missing detail is shown in output."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        # Binary is all zeros; ob=AA is nowhere
        target.write_bytes(_make_bin(1024))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "check", str(target), str(recipe)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "missing" in combined.lower() or "MISSING" in combined


class TestValidateAfterException:
    """Exception path in _run_after (lines 436-445)."""

    def test_patched_validator_exception_exits_one(self, tmp_path):
        """Exception from ECUPatchedValidator exits 1 with error message."""
        from unittest.mock import patch

        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        with patch(
            "openremap.cli.commands.validate.ECUPatchedValidator",
            side_effect=RuntimeError("patched validator crashed"),
        ):
            result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "error" in combined.lower()


class TestValidateAfterFailureDetail:
    """Failure detail display in _run_after (lines 436-445)."""

    def test_failure_details_shown_for_unpatched_binary(self, tmp_path):
        """Unpatched binary (ob still present) shows failure detail."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        # ob byte 0xAA is still at offset 100 — patch was never applied
        tuned.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "after", str(tuned), str(recipe)])

        assert result.exit_code == 1
        combined = result.stdout + result.stderr
        assert "failed" in combined.lower() or "NOT" in combined


class TestValidateDeprecatedAliases:
    """Deprecated alias commands (lines 693-700, 725-732, 758-765)."""

    def test_strict_alias_delegates_to_before(self, tmp_path):
        """'validate strict' shows deprecation note and runs before logic (lines 693-700)."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "strict", str(target), str(recipe)])

        combined = result.stdout + result.stderr
        # Must show the deprecation note
        assert "renamed" in combined.lower() or "before" in combined.lower()

    def test_strict_alias_exits_zero_on_match(self, tmp_path):
        """'validate strict' exits 0 when ob bytes match (delegates to before)."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "strict", str(target), str(recipe)])

        assert result.exit_code == 0, result.output

    def test_exists_alias_delegates_to_check(self, tmp_path):
        """'validate exists' shows deprecation note and runs check logic (lines 725-732)."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "exists", str(target), str(recipe)])

        combined = result.stdout + result.stderr
        assert "renamed" in combined.lower() or "check" in combined.lower()

    def test_exists_alias_exits_zero_on_exact_match(self, tmp_path):
        """'validate exists' exits 0 when ob bytes are found at exact offset."""
        target = tmp_path / "target.bin"
        recipe = tmp_path / "recipe.openremap"
        target.write_bytes(_make_bin(1024, {100: 0xAA}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "exists", str(target), str(recipe)])

        assert result.exit_code == 0, result.output

    def test_tuned_alias_delegates_to_after(self, tmp_path):
        """'validate tuned' shows deprecation note and runs after logic (lines 758-765)."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "tuned", str(tuned), str(recipe)])

        combined = result.stdout + result.stderr
        assert "renamed" in combined.lower() or "after" in combined.lower()

    def test_tuned_alias_exits_zero_on_confirmed_patch(self, tmp_path):
        """'validate tuned' exits 0 when mb bytes are confirmed at expected offset."""
        tuned = tmp_path / "target_tuned.bin"
        recipe = tmp_path / "recipe.openremap"
        tuned.write_bytes(_make_bin(1024, {100: 0xBB}))
        _write_recipe(recipe)

        result = runner.invoke(app, ["validate", "tuned", str(tuned), str(recipe)])

        assert result.exit_code == 0, result.output
