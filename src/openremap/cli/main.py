"""
OpenRemap CLI — root entry point.

Usage:
    openremap --help
    openremap identify ecu.bin
    openremap cook stock.bin stage1.bin --output recipe.json
    openremap validate strict target.bin recipe.json
    openremap validate exists target.bin recipe.json
    openremap validate patched patched.bin recipe.json
    openremap patch apply target.bin recipe.json --output patched.bin
    openremap scan ./my_bins/
    openremap scan ./my_bins/ --dry-run
"""

import typer

from openremap.cli.commands import patch, validate
from openremap.cli.commands.cook import cook
from openremap.cli.commands.identify import identify
from openremap.cli.commands.scan import scan

app = typer.Typer(
    name="openremap",
    help=(
        "OpenRemap — ECU binary analysis and patching toolkit.\n\n"
        "Diff, validate, and apply tuning recipes to automotive ECU binaries "
        "without a running API server."
    ),
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
)

# identify and cook are single-action commands — registered directly to avoid
# the Typer 0.12+ regression where @app.callback(invoke_without_command=True)
# with typer.Argument parameters fails when added via add_typer().
app.command(
    name="identify",
    help="Identify an ECU binary — manufacturer, family, software version, and more.",
    no_args_is_help=True,
)(identify)

app.command(
    name="cook",
    help="Cook a recipe by diffing an original and a modified ECU binary.",
    no_args_is_help=True,
)(cook)

# validate and patch have real sub-commands (strict / exists / patched, apply)
# and use @app.command() internally — add_typer works correctly for these.
app.add_typer(validate.app, name="validate")
app.add_typer(patch.app, name="patch")

app.command(
    name="scan",
    help=(
        "Batch-scan a directory of ECU binaries through all registered extractors.\n\n"
        "Each file is classified and optionally moved into one of five sub-folders: "
        "scanned, sw_missing, contested, unknown, or trash."
    ),
)(scan)


if __name__ == "__main__":
    app()
