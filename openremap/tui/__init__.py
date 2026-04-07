"""
OpenRemap TUI package.

Provides the interactive terminal user interface for OpenRemap.

Entry point:
    openremap-tui          (registered in pyproject.toml)

Programmatic use:
    from openremap.tui import run
    run()
"""

from openremap.tui.main import run

__all__ = ["run"]
