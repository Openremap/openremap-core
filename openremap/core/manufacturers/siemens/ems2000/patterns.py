"""
Siemens EMS2000 ECU binary identifier patterns and search regions.

Covers the Siemens EMS2000 family:
  EMS2000 — Volvo S40/V40/S60/S70/V70 turbo petrol ECUs (1996–2004)

This is a "dark" ECU family — the binary is essentially pure machine code
and calibration data with almost no embedded ASCII metadata.  The S108xxxxx
Siemens part number appears only in the filename, NOT in the binary itself.

Detection relies on exclusion (it is NOT Bosch, NOT Delphi, NOT Marelli,
NOT any other known Siemens family) combined with a strict 256 KB size gate
and an optional header magic check.

Binary structure:
  0x00000 – 0x3FFFF : Pure machine code + calibration data (256 KB total)
  No ident block, no metadata headers, no embedded part numbers.

Typical vehicles:
  Volvo S40 / V40 / S60 / S70 / V70 (1996–2004)
  T4 / T5 turbo engines

Part numbers: S108xxxxx (Siemens format — filename only)

Pattern reference:

  VOLVO VIN           "YV1SW58D922XXXXXX"
    17-character VIN starting with the Volvo "YV1" prefix.
    May or may not be present in the binary — most EMS2000 dumps do NOT
    contain the VIN.  Included as a best-effort extraction target.
"""

from typing import Dict, List

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# Very few patterns — this is a dark bin family with almost no ASCII content.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Vehicle identification (best-effort)
    # ------------------------------------------------------------------
    # Volvo VIN — 17-character ISO 3779 identifier starting with "YV1"
    # e.g. "YV1SW58D922123456"
    # Most EMS2000 dumps do NOT contain the VIN; this is a long-shot.
    "volvo_vin": rb"YV1[A-Z0-9]{14}",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real EMS2000 binaries — 256 KB total, pure code/cal.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # First 4 KB — header area (machine code entry point, interrupt vectors)
    "header": slice(0x0000, 0x1000),
    # Full binary — only region that makes sense for a dark bin
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "volvo_vin": "full",
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# No positive signatures — detection is by exclusion only.
# EMS2000 binaries contain no consistent ASCII markers that can be used
# for positive identification.  The can_handle() logic relies entirely on:
#   1. Exact 256 KB file size
#   2. Absence of all known manufacturer signatures (exclusion list below)
#   3. Optional header magic match
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: List[bytes] = []

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these byte sequences are found anywhere in the binary, the file
# is NOT an EMS2000.  This list covers all known ECU manufacturers and
# Siemens sub-families that share the 256 KB size.
#
# Categories:
#   Bosch modern       : EDC17, MEDC17, MED17, ME7., BOSCH, 0261, 0281,
#                        MOTRONIC, SB_V, Customer.
#   Bosch legacy       : /M1., /M2., /M3., /M4., /M5.
#   Siemens SIMOS      : 5WP4, SIMOS, s21, cas21  (VAG SIMOS, not Volvo)
#   Siemens SID        : 5WS4, PM3, PO, SID80
#   Siemens PPD        : PPD, SN1, CASN, 03G906
#   Siemens Simtec     : 5WK9
#   Delphi / Delco     : DEL, DELCO, DELPHI
#   Marelli            : MAG, MARELLI, IAW
#   Denso              : DENSO
#   Siemens internal   : 111PM, 111PO, 111SN, 111s2, CAPM, CAPO
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: List[bytes] = [
    # Bosch modern
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME7.",
    b"BOSCH",
    b"0261",
    b"0281",
    b"MOTRONIC",
    b"SB_V",
    b"Customer.",
    # Bosch legacy family markers (slash-delimited DAMOS strings)
    b"/M1.",
    b"/M2.",
    b"/M3.",
    b"/M4.",
    b"/M5.",
    # Siemens SIMOS (VAG, not Volvo EMS)
    b"5WP4",
    b"SIMOS",
    b"s21",
    b"cas21",
    # Siemens SID
    b"5WS4",
    b"PM3",
    b"PO",
    b"SID80",
    # Siemens PPD
    b"PPD",
    b"SN1",
    b"CASN",
    b"03G906",
    # Siemens Simtec
    b"5WK9",
    # Delphi / Delco
    b"DEL",
    b"DELCO",
    b"DELPHI",
    # Marelli
    b"MAG",
    b"MARELLI",
    b"IAW",
    # Denso
    b"DENSO",
    # Siemens internal identifiers (other families)
    b"111PM",
    b"111PO",
    b"111SN",
    b"111s2",
    b"CAPM",
    b"CAPO",
]

# ---------------------------------------------------------------------------
# Known header magic
# ---------------------------------------------------------------------------
# The first 4 bytes of the one confirmed EMS2000 sample.
# This is NOT guaranteed to be consistent across all EMS2000 variants —
# it is used as a weak positive signal only.
# ---------------------------------------------------------------------------

EMS2000_HEADER: bytes = b"\xc0\xf0\x68\xa6"

# ---------------------------------------------------------------------------
# Size constraint
# ---------------------------------------------------------------------------
# All known EMS2000 binaries are exactly 256 KB (262144 bytes).
# This is the primary gate for can_handle().
# ---------------------------------------------------------------------------

EMS2000_FILE_SIZE: int = 262144
