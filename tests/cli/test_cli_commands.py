"""
Tests for the ``commands``, ``workflow``, and ``families`` sub-commands.

All three are pure-output commands — no file I/O, no side effects.  Each must:
    - exit with code 0
    - print recognisable, human-readable text to stdout
    - produce nothing on stderr (except ``families --family <UNKNOWN>``)

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

import pytest
from typer.testing import CliRunner

from openremap.cli.main import app

# ---------------------------------------------------------------------------
# Shared runner
# ---------------------------------------------------------------------------
# Click 8.2+: result.stdout / result.stderr / result.output are always
# available; no mix_stderr constructor argument is needed or accepted.
runner = CliRunner()


# ===========================================================================
# openremap commands
# ===========================================================================


class TestCommandsCommand:
    """``openremap commands`` prints the one-line cheat-sheet and exits 0."""

    def test_exits_zero(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert result.exit_code == 0

    def test_stdout_contains_openremap(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "OpenRemap" in result.stdout

    def test_stdout_contains_command_reference(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "Command Reference" in result.stdout

    def test_stdout_contains_openremap_and_command_reference_together(self) -> None:
        """The header line reads 'OpenRemap — Command Reference'."""
        result = runner.invoke(app, ["commands"])
        assert "OpenRemap" in result.stdout and "Command Reference" in result.stdout

    def test_stdout_lists_workflow_entry(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "workflow" in result.stdout

    def test_stdout_lists_identify_entry(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "identify" in result.stdout

    def test_stdout_lists_families_entry(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "families" in result.stdout

    def test_stdout_lists_cook_entry(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "cook" in result.stdout

    def test_stdout_lists_tune_entry(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "tune" in result.stdout

    def test_stdout_lists_validate_entry(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "validate" in result.stdout

    def test_stdout_lists_scan_entry(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert "scan" in result.stdout

    def test_no_stderr_output(self) -> None:
        result = runner.invoke(app, ["commands"])
        assert result.stderr == ""


# ===========================================================================
# openremap workflow
# ===========================================================================


class TestWorkflowCommand:
    """``openremap workflow`` prints the full walkthrough guide and exits 0."""

    def test_exits_zero(self) -> None:
        result = runner.invoke(app, ["workflow"])
        assert result.exit_code == 0

    def test_stdout_contains_openremap(self) -> None:
        result = runner.invoke(app, ["workflow"])
        assert "OpenRemap" in result.stdout

    def test_stdout_contains_workflow_in_header(self) -> None:
        result = runner.invoke(app, ["workflow"])
        assert "Workflow" in result.stdout

    def test_stdout_contains_openremap_and_workflow_together(self) -> None:
        """The header line reads 'OpenRemap — Workflow Guide'."""
        result = runner.invoke(app, ["workflow"])
        assert "OpenRemap" in result.stdout and "Workflow" in result.stdout

    def test_stdout_mentions_identify_step(self) -> None:
        """The workflow guide must reference the identify command."""
        result = runner.invoke(app, ["workflow"])
        assert "identify" in result.stdout.lower()

    def test_stdout_mentions_cook_step(self) -> None:
        result = runner.invoke(app, ["workflow"])
        assert "cook" in result.stdout.lower()

    def test_stdout_mentions_tune_step(self) -> None:
        result = runner.invoke(app, ["workflow"])
        assert "tune" in result.stdout.lower()

    def test_stdout_mentions_validate_step(self) -> None:
        result = runner.invoke(app, ["workflow"])
        assert "validate" in result.stdout.lower()

    def test_stdout_contains_step_headers(self) -> None:
        """The walkthrough is divided into numbered steps."""
        result = runner.invoke(app, ["workflow"])
        assert "STEP" in result.stdout

    def test_no_stderr_output(self) -> None:
        result = runner.invoke(app, ["workflow"])
        assert result.stderr == ""


# ===========================================================================
# openremap families  (table — no --family flag)
# ===========================================================================


class TestFamiliesTable:
    """``openremap families`` (no flag) prints the full supported-family table."""

    def test_exits_zero(self) -> None:
        result = runner.invoke(app, ["families"])
        assert result.exit_code == 0

    def test_stdout_contains_table_header(self) -> None:
        result = runner.invoke(app, ["families"])
        assert "Supported ECU Families" in result.stdout

    def test_stdout_contains_edc17(self) -> None:
        result = runner.invoke(app, ["families"])
        assert "EDC17" in result.stdout

    def test_stdout_contains_edc16(self) -> None:
        result = runner.invoke(app, ["families"])
        assert "EDC16" in result.stdout

    def test_stdout_contains_edc15(self) -> None:
        result = runner.invoke(app, ["families"])
        assert "EDC15" in result.stdout

    def test_stdout_shows_column_headers(self) -> None:
        """The table must have FAMILY, ERA, SIZE, and NOTES column headers."""
        result = runner.invoke(app, ["families"])
        assert "FAMILY" in result.stdout
        assert "ERA" in result.stdout
        assert "SIZE" in result.stdout

    def test_no_stderr_output(self) -> None:
        result = runner.invoke(app, ["families"])
        assert result.stderr == ""


# ===========================================================================
# openremap families --family <NAME>  (detail view)
# ===========================================================================


class TestFamiliesDetailEDC17:
    """``openremap families --family EDC17`` prints the EDC17 detail view."""

    def test_exits_zero(self) -> None:
        result = runner.invoke(app, ["families", "--family", "EDC17"])
        assert result.exit_code == 0

    def test_stdout_contains_edc17(self) -> None:
        result = runner.invoke(app, ["families", "--family", "EDC17"])
        assert "EDC17" in result.stdout

    def test_stdout_shows_era(self) -> None:
        """EDC17 era starts in 2008."""
        result = runner.invoke(app, ["families", "--family", "EDC17"])
        assert "2008" in result.stdout

    def test_stdout_shows_sub_families(self) -> None:
        """Detail view must list at least one sub-family variant."""
        result = runner.invoke(app, ["families", "--family", "EDC17"])
        # EDC17C and EDC17CP are the two main sub-family groups
        assert "EDC17C" in result.stdout or "MEDC17" in result.stdout

    def test_stdout_shows_file_size(self) -> None:
        result = runner.invoke(app, ["families", "--family", "EDC17"])
        assert "MB" in result.stdout

    def test_alias_lowercase_works(self) -> None:
        """The --family flag is case-insensitive; 'edc17' must find EDC17."""
        result = runner.invoke(app, ["families", "--family", "edc17"])
        assert result.exit_code == 0
        assert "EDC17" in result.stdout

    def test_alias_medc17_works(self) -> None:
        """'MEDC17' is a registered alias for the EDC17 family entry."""
        result = runner.invoke(app, ["families", "--family", "MEDC17"])
        assert result.exit_code == 0
        assert "EDC17" in result.stdout

    def test_no_stderr_output(self) -> None:
        result = runner.invoke(app, ["families", "--family", "EDC17"])
        assert result.stderr == ""


class TestFamiliesDetailEDC16:
    """``openremap families --family EDC16`` prints the EDC16 detail view."""

    def test_exits_zero(self) -> None:
        result = runner.invoke(app, ["families", "--family", "EDC16"])
        assert result.exit_code == 0

    def test_stdout_contains_edc16(self) -> None:
        result = runner.invoke(app, ["families", "--family", "EDC16"])
        assert "EDC16" in result.stdout

    def test_stdout_shows_era(self) -> None:
        """EDC16 era starts in 2003."""
        result = runner.invoke(app, ["families", "--family", "EDC16"])
        assert "2003" in result.stdout

    def test_stdout_shows_sub_families(self) -> None:
        """Detail view must list at least one EDC16 sub-family variant."""
        result = runner.invoke(app, ["families", "--family", "EDC16"])
        # EDC16C8, EDC16C9 etc. are known sub-variants
        assert "EDC16C" in result.stdout

    def test_stdout_shows_file_size(self) -> None:
        result = runner.invoke(app, ["families", "--family", "EDC16"])
        assert "MB" in result.stdout or "KB" in result.stdout

    def test_alias_lowercase_works(self) -> None:
        """The --family flag is case-insensitive; 'edc16' must find EDC16."""
        result = runner.invoke(app, ["families", "--family", "edc16"])
        assert result.exit_code == 0
        assert "EDC16" in result.stdout

    def test_short_flag_works(self) -> None:
        """-f is the short form of --family."""
        result = runner.invoke(app, ["families", "-f", "EDC16"])
        assert result.exit_code == 0
        assert "EDC16" in result.stdout

    def test_no_stderr_output(self) -> None:
        result = runner.invoke(app, ["families", "--family", "EDC16"])
        assert result.stderr == ""


# ===========================================================================
# openremap families --family <UNKNOWN>  (error path)
# ===========================================================================


class TestFamiliesUnknown:
    """Requesting an unknown family name must report an error and exit non-zero."""

    def test_nonexistent_exits_one(self) -> None:
        # The families command explicitly raises typer.Exit(code=1) when the
        # family lookup returns None.  This is intentional — unknown family is
        # a user error, not a missing-argument error (which would be code 2).
        result = runner.invoke(app, ["families", "--family", "NONEXISTENT"])
        assert result.exit_code == 1

    def test_error_mentions_family_name(self) -> None:
        result = runner.invoke(app, ["families", "--family", "NONEXISTENT"])
        assert "NONEXISTENT" in result.stderr

    def test_error_goes_to_stderr_not_stdout(self) -> None:
        result = runner.invoke(app, ["families", "--family", "NONEXISTENT"])
        assert result.stdout == ""

    def test_error_hints_at_families_command(self) -> None:
        """The error output should suggest running 'openremap families'."""
        result = runner.invoke(app, ["families", "--family", "NONEXISTENT"])
        assert "families" in result.stderr

    def test_clearly_named_unknown_family_also_errors(self) -> None:
        """Any unrecognised name — not just 'NONEXISTENT' — must exit 1."""
        result = runner.invoke(app, ["families", "--family", "NOTAFAMILY123"])
        assert result.exit_code == 1
        assert "NOTAFAMILY123" in result.stderr
