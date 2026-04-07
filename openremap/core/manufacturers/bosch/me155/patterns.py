"""
Bosch ME1.5.5 ECU binary identifier patterns and search regions.

Covers the Bosch Motronic ME1.5.5 family:
  ME1.5.5 — Opel/Vauxhall petrol ECUs (Astra-G 2.0T Z20LET, Corsa-C 1.2 Z12XE,
             Corsa-C 1.2 Z12XEP, 1999–2005)
             CPU: Infineon/Siemens C167CR (same generation as ME7)
             ROM: 512KB external flash

  Identified by the ZZ ident block at offset 0x10000 with a printable ASCII
  byte immediately after "ZZ" (0x34 = '4' in all known samples), followed by
  the slash-delimited descriptor "/ME1.5.5/".

  This ECU family is distinct from:
    - Bosch M1.55 (M1x55 module) — Alfa Romeo, 128KB, Motorola 68K, different
      binary structure and detection anchor (b"M1.55" at 0x08005).
    - Bosch ME7 — same ZZ offset but non-printable byte after "ZZ" (0xFF/0x00/0x01).
      The ME7 extractor's Phase 3 guard rejects ME1.5.5 bins.

Binary structure:
  0x00000 – 0x0FFFF  : Code (C167 interrupt vector table at 0x00, then code)
  0x10000            : ZZ ident block — "ZZ4x/1/ME1.5.5/6/..." descriptor
  0x10000 – 0x1FFFF  : Ident block + calibration data
  0x20000+           : Extended code / calibration tables

  HW + SW numbers are stored as ASCII strings in the ident area.
  The HW number is preceded by a "2" byte: "20261XXXXXX" (found by searching
  for 0261 + 6 digits).
  The SW number is a standalone "1037XXXXXX" string.
"""

from typing import Dict


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # Combined HW+SW — ME1.5.5 stores them in the same ident area but not
    # always adjacent.  Search for each independently.
    "hardware_number": rb"0261\d{6}",
    # Software version — 1037 + 6 digits (10 chars)
    "software_version": rb"1037\d{6}",
    # Full ZZ variant descriptor string
    # e.g. "ZZ41/1/ME1.5.5/6/88.0//12g/09120701/150600/"
    "ecu_variant_string": rb"ZZ\d{2}/\d+/ME1\.5\.5/[\w/\.\-]{6,}",
    # ECU family — always "ME1.5.5"
    "ecu_family": rb"ME1\.5\.5",
    # Calibration ID — 5th slash field in ZZ descriptor
    # Formats: "88.0", "100.1", "16.1" (digits + dot + digit(s))
    # or alphanumeric: "515B", "0614", "12g"
    "calibration_id": rb"(?<=/)\d+\.\d+(?=/)|(?<=/)[A-Za-z0-9]{3,6}(?=//)",
}


# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # Ident block — 0x10000 to 0x20000 — ZZ descriptor, HW/SW
    "ident_block": slice(0x10000, 0x20000),
    # Extended — first 320KB
    "extended": slice(0x00000, 0x50000),
    # Full binary
    "full": slice(0x00000, None),
}


# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "hardware_number": "full",
    "software_version": "full",
    "ecu_variant_string": "ident_block",
    "ecu_family": "extended",
    "calibration_id": "ident_block",
}


# ---------------------------------------------------------------------------
# Detection constants
# ---------------------------------------------------------------------------

# Valid file sizes for ME1.5.5 binaries (512KB only observed so far)
VALID_FILE_SIZES: set[int] = {0x80000}

# Fixed offset where the ZZ ident block marker must appear.
# Same offset as ME7 — shared C167 flash layout.
ME155_ZZ_OFFSET: int = 0x10000

# The ZZ prefix bytes — same 2-byte anchor as ME7.
ME155_ZZ_PREFIX: bytes = b"ZZ"

# ME1.5.5 family confirmation string — must appear in the ZZ descriptor.
ME155_FAMILY_ANCHOR: bytes = b"/ME1.5.5/"

# Detection signatures — byte sequences that indicate ME1.5.5.
# The primary detection is done via ZZ + printable byte + family anchor,
# not via these signatures.
DETECTION_SIGNATURES: list[bytes] = [
    b"ME1.5.5",
]

# Exclusion signatures — if any of these are present, this is NOT ME1.5.5.
EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"EDC15",
    b"SB_V",
    b"Customer.",
    b"NR000",
    b"ME7.",  # ME7 family (different ECU)
    b"ME71",  # ME71 earliest variant
    b"ME731",  # ME731 Alfa Romeo
    b"MOTRONIC",  # ME7 MOTRONIC label — absent on ME1.5.5
    b"TSW ",  # EDC15 tool software string
    b"M1.55",  # Bosch M1.55 (different ECU, Alfa Romeo)
]
