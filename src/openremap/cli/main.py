"""
OpenRemap CLI — root entry point.

Usage:
    openremap --help
    openremap identify ecu.bin
    openremap analyze stock.bin stage1.bin --output recipe.json
    openremap validate strict target.bin recipe.json
    openremap validate exists target.bin recipe.json
    openremap validate patched patched.bin recipe.json
    openremap patch apply target.bin recipe.json --output patched.bin
    openremap scan ./my_bins/
    openremap scan ./my_bins/ --dry-run
"""

import typer

from openremap.cli.commands import cook, identify, patch, validate
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

app.add_typer(identify.app, name="identify")
app.add_typer(cook.app, name="cook")
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
