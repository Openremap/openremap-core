"""
Manufacturer extractor registry.

Each manufacturer package exposes its own ordered EXTRACTORS list.
This registry composes them in inter-manufacturer priority order —
first match wins when a binary is submitted.

Adding a new manufacturer:
    1. Create src/openremap/tuning/manufacturers/<brand>/
    2. Implement extractors — subclass BaseManufacturerExtractor
    3. Expose EXTRACTORS: list[BaseManufacturerExtractor] in <brand>/__init__.py
    4. Import the package here and unpack it into EXTRACTORS below
"""

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor
from openremap.tuning.manufacturers import bosch

# ---------------------------------------------------------------------------
# Registry — inter-manufacturer order.
# Intra-manufacturer order is owned by each brand package.
# ---------------------------------------------------------------------------

EXTRACTORS: list[BaseManufacturerExtractor] = [
    *bosch.EXTRACTORS,
    # *siemens.EXTRACTORS,
    # *delphi.EXTRACTORS,
    # *marelli.EXTRACTORS,
    # *denso.EXTRACTORS,
    # *continental.EXTRACTORS,
]

__all__ = ["EXTRACTORS", "BaseManufacturerExtractor"]
