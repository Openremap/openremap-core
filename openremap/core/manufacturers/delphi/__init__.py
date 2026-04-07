"""
Delphi (Delco) ECU extractor registry.

Exposes an ordered EXTRACTORS list consumed by the top-level manufacturer
registry.  Intra-brand ordering:

  1. DelphiMultecExtractor   — Multec diesel (Opel 1.7DTI / 1.7TD, 68k CPU32)
                                Sizes: 212 992 (0x34000) or 262 144 (0x40000)
                                Positive: DEL header or ASCII-digit header +
                                structured ident block with 8-digit SW number.

  2. DelphiMultecSExtractor  — Multec S petrol (Opel Astra-G / Corsa, HC12)
                                Size: 131 072 (0x20000)
                                Positive: FF boot block + HC12 pointer table +
                                fixed-offset ident block at 0x3000.

  Ordering rationale:
    The two families have completely disjoint file sizes (208/256 KB vs 128 KB)
    so there is no collision risk.  Diesel is listed first because its header
    signatures (DEL / ASCII digits) are stronger positive anchors than the
    Multec S FF-boot-block heuristic.
"""

from openremap.core.manufacturers.base import BaseManufacturerExtractor
from openremap.core.manufacturers.delphi.multec.extractor import (
    DelphiMultecExtractor,
)
from openremap.core.manufacturers.delphi.multec_s.extractor import (
    DelphiMultecSExtractor,
)

# ---------------------------------------------------------------------------
# Registry — intra-brand priority order.
# ---------------------------------------------------------------------------

EXTRACTORS: list[BaseManufacturerExtractor] = [
    # 1. Multec diesel — strongest header signatures (DEL / digit header)
    DelphiMultecExtractor(),
    # 2. Multec S petrol — FF boot block + HC12 pointer table heuristic
    DelphiMultecSExtractor(),
]

__all__ = ["EXTRACTORS"]
