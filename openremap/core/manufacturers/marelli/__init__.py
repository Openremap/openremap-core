"""
Magneti Marelli extractor registry.

Exposes an ordered EXTRACTORS list consumed by the top-level manufacturer
registry.  Intra-brand priority order:

  1. IAW 1AV  — 64 KB, has plain-text "MARELLI" + "1AV" ident string.
                Strongest positive signature among the small IAW files.
  2. IAW 1AP  — 64 KB, almost no identifying text (only "1ap" at 0x5F8D).
                Must run AFTER IAW 1AV so the 1AV's stronger signature
                claims its files first; 1AP is the fallback for 64 KB
                Marelli bins that lack explicit MARELLI/iaw1av strings.
  3. IAW 4LV  — 512 KB, M68K byte-swapped strings, "AMERLL" (= MARELLI),
                55AA33CC footer markers.  Unique size and header magic
                (0x0E00E683) make collisions unlikely.
  4. MJD 6JF  — 448–452 KB (non-power-of-2 sizes), PowerPC, AA55CC33
                sync markers, "MAG" prefix in ident block.  Distinct size
                range prevents any overlap with the IAW extractors.

Design notes:
  - IAW 1AV before IAW 1AP is critical: both are 64 KB with an 0xFF
    header, but 1AV has "MARELLI" and "iaw1av" strings that 1AP excludes.
    If 1AP ran first its weaker detection could false-positive on 1AV bins
    (though it does exclude "MARELLI", the ordering adds defence-in-depth).
  - IAW 4LV and MJD 6JF have non-overlapping size gates so their relative
    order is less important, but 4LV is listed first because its header
    magic check (first 4 bytes) is faster than MJD's region-scan for
    AA55CC33.
"""

from openremap.core.manufacturers.marelli.iaw_1av.extractor import (
    MarelliIAW1AVExtractor,
)
from openremap.core.manufacturers.marelli.iaw_1ap.extractor import (
    MarelliIAW1APExtractor,
)
from openremap.core.manufacturers.marelli.iaw_4lv.extractor import (
    MarelliIAW4LVExtractor,
)
from openremap.core.manufacturers.marelli.mjd6jf.extractor import (
    MarelliMJD6JFExtractor,
)
from openremap.core.manufacturers.base import BaseManufacturerExtractor

# ---------------------------------------------------------------------------
# Registry — intra-brand priority order (first match wins).
# ---------------------------------------------------------------------------

EXTRACTORS: list[BaseManufacturerExtractor] = [
    # --- 64 KB IAW family (strongest signature first) ---
    MarelliIAW1AVExtractor(),  # 64 KB, plain "MARELLI" + "1AV"
    MarelliIAW1APExtractor(),  # 64 KB, only "1ap" tag — weakest sig
    # --- Larger IAW family ---
    MarelliIAW4LVExtractor(),  # 512 KB, M68K byte-swapped
    # --- MJD family ---
    MarelliMJD6JFExtractor(),  # 448–452 KB, PowerPC, Opel/Fiat diesel
]

__all__ = ["EXTRACTORS"]
