"""
Tests for the root ``openremap`` CLI entry point.

Covers:
    - ``--version`` / ``-V``  →  prints "openremap X.Y.Z" and exits 0
    - ``--help``              →  prints help text and exits 0
    - no arguments            →  shows help (no_args_is_help=True, exits 2 per
                                 Click's convention for Groups with missing args)

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

import re
from importlib.metadata import version as _pkg_version

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
# --version / -V
# ---------------------------------------------------------------------------


class TestVersion:
    """``--version`` and ``-V`` must print the package version and exit 0."""

    def test_long_flag_exits_zero(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_short_flag_exits_zero(self) -> None:
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0

    def test_long_flag_prints_app_name(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.stdout.startswith("openremap ")

    def test_short_flag_prints_app_name(self) -> None:
        result = runner.invoke(app, ["-V"])
        assert result.stdout.startswith("openremap ")

    def test_version_string_matches_package_metadata(self) -> None:
        """The printed version must match ``importlib.metadata.version('openremap')``."""
        expected = _pkg_version("openremap")
        result = runner.invoke(app, ["--version"])
        assert expected in result.stdout

    def test_version_string_is_semver(self) -> None:
        """Version must look like MAJOR.MINOR.PATCH (e.g. '0.3.1')."""
        result = runner.invoke(app, ["--version"])
        assert re.search(r"openremap \d+\.\d+\.\d+", result.stdout)

    def test_short_flag_output_matches_long_flag(self) -> None:
        """-V and --version must produce identical output."""
        long_out = runner.invoke(app, ["--version"]).stdout
        short_out = runner.invoke(app, ["-V"]).stdout
        assert long_out == short_out

    def test_no_stderr_on_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.stderr == ""


# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------


class TestHelp:
    """``--help`` must print a useful help text and exit 0."""

    def test_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_help_shows_app_description(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "OpenRemap" in result.stdout

    def test_help_shows_usage_line(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "Usage" in result.stdout

    def test_help_lists_identify_command(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "identify" in result.stdout

    def test_help_lists_workflow_command(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "workflow" in result.stdout

    def test_help_lists_commands_command(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "commands" in result.stdout

    def test_help_lists_families_command(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "families" in result.stdout

    def test_help_lists_cook_command(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "cook" in result.stdout

    def test_help_lists_tune_command(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "tune" in result.stdout

    def test_help_lists_validate_command(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "validate" in result.stdout

    def test_help_shows_version_option(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "--version" in result.stdout

    def test_help_no_stderr_output(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.stderr == ""


# ---------------------------------------------------------------------------
# No arguments
# ---------------------------------------------------------------------------


class TestNoArgs:
    """
    Invoking without arguments triggers ``no_args_is_help=True``.

    Click's convention for a Group with no subcommand provided is exit code 2
    (the same code used for bad arguments).  The help text is still printed to
    stdout.
    """

    def test_no_args_exit_code(self) -> None:
        # Click exits 2 for Groups when no args are supplied and
        # no_args_is_help=True is set — this is the expected, stable behaviour.
        result = runner.invoke(app, [])
        assert result.exit_code == 2

    def test_no_args_shows_usage(self) -> None:
        result = runner.invoke(app, [])
        # Help output goes to stdout; error notice may go to stderr.
        # result.output is the combined view the user would see.
        assert "Usage" in result.output

    def test_no_args_shows_app_name_in_usage(self) -> None:
        result = runner.invoke(app, [])
        assert "openremap" in result.output.lower()

    def test_no_args_shows_commands_section(self) -> None:
        result = runner.invoke(app, [])
        # The commands panel lists the available sub-commands.
        assert "identify" in result.output or "commands" in result.output

    def test_no_args_output_resembles_help(self) -> None:
        """No-args output must share key tokens with explicit --help output."""
        no_args_out = runner.invoke(app, []).output
        help_out = runner.invoke(app, ["--help"]).stdout
        # Both must contain the usage line and at least one common command name.
        for token in ("openremap", "identify", "workflow"):
            assert token in no_args_out
            assert token in help_out


# ---------------------------------------------------------------------------
# __main__ block (main.py line 147)
# ---------------------------------------------------------------------------


class TestMainBlock:
    """Covers the ``if __name__ == '__main__': app()`` block (line 147)."""

    def test_main_block_invokes_app(self) -> None:
        """The __main__ block calls app() — patching Typer.__call__ intercepts it."""
        from unittest.mock import patch
        import openremap.cli.main as _mod

        # Patch typer.Typer.__call__ so that when app() is called inside the
        # `if __name__ == "__main__":` block, the call is intercepted rather
        # than launching the real CLI (which would hang or sys.exit).
        with patch("typer.Typer.__call__", return_value=None) as mock_call:
            ns = {"__name__": "__main__"}
            with open(_mod.__file__) as fh:
                source = fh.read()
            try:
                # compile() with the real file path lets pytest-cov track line 147
                exec(compile(source, _mod.__file__, "exec"), ns)  # noqa: S102
            except SystemExit:
                pass

        mock_call.assert_called_once()
