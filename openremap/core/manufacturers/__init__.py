"""
Manufacturer extractor registry.

Each manufacturer package exposes its own ordered EXTRACTORS list.
This registry composes them in inter-manufacturer priority order —
first match wins when a binary is submitted.

Adding a new built-in manufacturer:
    1. Create src/openremap/tuning/manufacturers/<brand>/
    2. Implement extractors — subclass BaseManufacturerExtractor
    3. Expose EXTRACTORS: list[BaseManufacturerExtractor] in <brand>/__init__.py
    4. Import the package here and unpack it into BUILTIN_EXTRACTORS below

Inter-manufacturer priority rationale:
    Bosch first   — largest family count (18 extractors), strongest positive
                    signatures (ZZ markers, TSW strings, 1037/0261 part numbers).
    Siemens       — 6 extractors with strong 5WK9 / PPD / SID signatures that
                    are disjoint from Bosch.
    Delphi        — DEL header, HC12 pointer tables, GM part numbers.
                    Must run after Siemens because Multec S shares the 128 KB
                    size with Siemens Simtec 56 (Simtec 56 excludes non-Siemens
                    files, but ordering adds defence-in-depth).
    Marelli       — IAW / MJD families with AA55CC33 sync markers, MAG prefix,
                    byte-swapped AMERLL strings.  Runs last among the currently
                    implemented manufacturers because several Marelli extractors
                    use weaker heuristics (e.g. IAW 1AP has only a 3-byte "1ap"
                    anchor).
"""

from openremap.core.manufacturers.base import BaseManufacturerExtractor
from openremap.core.manufacturers import bosch
from openremap.core.manufacturers import siemens
from openremap.core.manufacturers import delphi
from openremap.core.manufacturers import marelli

# ---------------------------------------------------------------------------
# Built-in registry — inter-manufacturer order.
# Intra-manufacturer order is owned by each brand package.
# ---------------------------------------------------------------------------

BUILTIN_EXTRACTORS: list[BaseManufacturerExtractor] = [
    *bosch.EXTRACTORS,
    *siemens.EXTRACTORS,
    *delphi.EXTRACTORS,
    *marelli.EXTRACTORS,
]


def get_extractors() -> list[BaseManufacturerExtractor]:
    """Return the built-in ordered extractor list."""
    return BUILTIN_EXTRACTORS


# Backward compatibility — consumers that import EXTRACTORS directly
# still get the built-in list.
EXTRACTORS = BUILTIN_EXTRACTORS

__all__ = [
    "BUILTIN_EXTRACTORS",
    "EXTRACTORS",
    "BaseManufacturerExtractor",
    "get_extractors",
]
