"""
OpenRemap TUI — entry point.

Called by the `openremap-tui` console script defined in pyproject.toml.
"""

from __future__ import annotations


def run() -> None:
    """Launch the OpenRemap Terminal User Interface."""
    from openremap.tui.app import OpenRemapTUI

    app = OpenRemapTUI()
    app.run()


if __name__ == "__main__":
    run()
