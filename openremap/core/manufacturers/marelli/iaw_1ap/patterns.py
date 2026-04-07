"""
Magneti Marelli IAW 1AP ECU binary identifier patterns and search regions.

Covers the Magneti Marelli IAW 1AP family:
  IAW 1AP — Peugeot/Citroën single-point fuel injection ECUs (~1996–2002)
             Peugeot 106 1.0/1.1/1.4, Peugeot 206 1.1/1.4,
             Citroën Saxo 1.0/1.1/1.4
             ST6 microcontroller, 64KB flash dump

These are ST6-based single-point injection ECUs with extremely sparse
identifying text.  The binary contains almost no ASCII strings — the only
reliable text identifier is the lowercase ``1ap`` family tag embedded at a
fixed offset near the end of the calibration data block.

Binary structure:

  Size            : 65,536 bytes (0x10000) — single ST6 flash dump.

  Flash zones:
    0x0000–0x000F : FF padding (16 bytes) — erased vector area
    0x0010–0x5F8F : Code + calibration (ST6 machine code)
    0x5F90–0x5FF7 : FF padding
    0x6000–0xFFFF : Data / lookup tables

  Family tag      : ``1ap`` (3 lowercase ASCII bytes) at fixed offset 0x5F8D.
                    Located right at the end of a calibration data block:
                    ``...33333333333331ap`` followed by 0xFF padding.

  Sync marker     : ``AA55CC33`` (4 bytes) at offset 0x4810.
                    Standard Marelli flash sync/validation marker.

  Calibration ID  : No explicit calibration ID string.  The 4 raw bytes
                    immediately following the AA55CC33 sync marker
                    (offset 0x4814–0x4817) are used as a hex-encoded
                    calibration fingerprint, e.g. "50960654".

  NO "MARELLI" string — this is how IAW 1AP is distinguished from IAW 1AV,
  which DOES contain "MARELLI" as an ASCII string.

Detection strategy:

  Phase 1 — Size gate: exactly 65,536 bytes (0x10000).
  Phase 2 — Header check: first 16 bytes all 0xFF (erased vector area).
  Phase 3 — Exclusion: reject if ANY exclusion signature is present.
             Excludes Bosch, Siemens, Delphi, and other Marelli families.
             Critically excludes ``MARELLI`` and ``iaw1av`` to distinguish
             from IAW 1AV which shares the same file size.
  Phase 4 — Family anchor: ``1ap`` (lowercase) found in range 0x5F80–0x5FA0.
  Phase 5 — Sync marker: ``AA55CC33`` present anywhere in the binary.

No false positives observed — the combination of size gate, FF header,
exclusion list, family anchor at a fixed offset, and sync marker is
extremely specific to IAW 1AP.
"""

import re
from typing import Dict

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# 0x10000 = 64KB — single ST6 flash dump (only supported size)

EXPECTED_SIZE: int = 0x10000

# ---------------------------------------------------------------------------
# Header validation
# ---------------------------------------------------------------------------
# The first 16 bytes of a valid IAW 1AP binary are all 0xFF (erased vector
# area).  This is a structural requirement — real ST6 code starts at 0x10.

HEADER_SIZE: int = 16
HEADER_FILL_BYTE: int = 0xFF

# ---------------------------------------------------------------------------
# Detection anchors
# ---------------------------------------------------------------------------
# Family tag: lowercase "1ap" — the ONLY identifying ASCII text in the binary.
# Must be found in the narrow window 0x5F80–0x5FA0.

FAMILY_ANCHOR: bytes = b"1ap"

# Sync marker: standard Marelli flash validation marker.
# Must be present somewhere in the binary.

SYNC_MARKER: bytes = b"\xaa\x55\xcc\x33"

# ---------------------------------------------------------------------------
# Sync marker offset for calibration ID extraction
# ---------------------------------------------------------------------------
# The 4 bytes immediately after the AA55CC33 marker (at offset 0x4814)
# are hex-encoded to produce the calibration fingerprint.

SYNC_MARKER_OFFSET: int = 0x4810
CAL_ID_OFFSET: int = SYNC_MARKER_OFFSET + 4
CAL_ID_LENGTH: int = 4

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these are found anywhere in the binary, reject immediately.
# Guards against accidentally claiming bins from other ECU families.
#
# Critically: ``MARELLI`` is excluded because IAW 1AP does NOT contain
# that string — IAW 1AV does.  This is the primary discriminator between
# the two families.

EXCLUSION_SIGNATURES: list[bytes] = [
    # Bosch families
    b"BOSCH",
    b"EDC",
    b"ME7.",
    b"MOTRONIC",
    # Siemens / Continental families
    b"5WK9",
    b"SIMOS",
    b"PPD",
    # Delphi families
    b"DELPHI",
    b"DEL  ",
    # Other Marelli families — critical for disambiguation
    b"MARELLI",  # IAW 1AV contains this; IAW 1AP does not
    b"iaw1av",  # Explicit IAW 1AV family tag
    b"6JF",  # MJD 6JF family
    b"MJD",  # MJD family prefix
    b"4LV",  # IAW 4LV family
]

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Tightly scoped regions for pattern searches and raw string extraction.

SEARCH_REGIONS: Dict[str, slice] = {
    # Narrow window around the expected family tag location (0x5F8D)
    "family_area": slice(0x5F80, 0x5FA0),
    # Area around the sync marker for calibration ID extraction
    "cal_marker": slice(0x4800, 0x4820),
    # Full binary — used for exclusion checks and sync marker search
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# Only one pattern: the family tag.  This ECU has almost no extractable
# text, so the pattern set is intentionally minimal.
#
# The family_tag pattern matches the lowercase "1ap" string that is the
# sole identifying ASCII text in the binary.

PATTERNS: Dict[str, bytes] = {
    # Lowercase family tag — the only reliable ASCII identifier
    # e.g. "1ap"
    "family_tag": rb"1ap",
}

# Map pattern names to their search regions
PATTERN_REGIONS: Dict[str, str] = {
    "family_tag": "family_area",
}

# ---------------------------------------------------------------------------
# Family constants
# ---------------------------------------------------------------------------

FAMILY_TAG: str = "IAW 1AP"
DEFAULT_FAMILY: str = "IAW 1AP"
DEFAULT_VARIANT: str = "IAW 1AP"
