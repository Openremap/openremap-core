"""
Siemens Simtec 56 ECU binary identifier patterns and search regions.

All regex patterns and search region definitions specific to Siemens Simtec 56
ECUs used in Opel/Vauxhall vehicles with X18XE and X20XEV engines (1995–2000).

Binary structure:
  File size: exactly 131 072 bytes (128 KB)
  Header:    \x02\x00\xb0\x20\xb2 — 8051/C166 LJMP reset vector
  CPU:       Intel 8051 / Siemens C166 derivative

Identification strategy:
  Simtec 56 binaries are positively identified by the combination of:
    1. Exact 128 KB file size (131 072 bytes)
    2. Presence of "5WK9" Siemens part number prefix
    3. Presence of "RS" or "RT" ident record with 8-digit GM part number
    4. 8051-style LJMP header bytes (\x02\x00\xb0)
    5. Absence of all Bosch / Delphi / Magneti Marelli signatures

Typical vehicles:
  Opel/Vauxhall Vectra B, Astra F/G, Omega B, Calibra
  Engines: X18XE (1.8L 16V), X20XEV (2.0L 16V Ecotec)

Pattern reference:

  IDENT RECORD        "RS90506365 0106577255425b5WK907302"
    Combined identification record containing GM part number, production
    serial, and Siemens ECU part number in a single continuous string.
    Format: R[ST] + 8-digit GM part + space + 14–16 char serial + 5WK9 + 4 digits + 2-digit checksum
    The RS/RT prefix distinguishes software revision tracks.
    This is the most reliable anchor for all sub-field extraction.

  SIEMENS PART NUMBER "5WK907302"  "5WK907402"
    Siemens hardware/software part number for the ECU unit.
    Format: 5WK9 + 4 digits (+ optional 2-digit checksum suffix).
    The "5WK9" prefix is a Siemens-wide identifier used across
    Simtec, SID, and other Siemens ECU families.

  GM PART NUMBER      "90506365"  "90464731"
    General Motors (Opel) part number from the RS/RT ident record.
    Format: 8 digits, always follows the R[ST] prefix directly.
    Identifies the vehicle application and calibration variant.

  SERIAL NUMBER       "0106577255425b"
    Production serial code from the ident record.
    Format: 12–16 digits followed by a lowercase letter.
    Unique per physical ECU unit — NOT used for matching.

  ENGINE CODE         "X18XE"  "X20XEV"
    Opel engine designation embedded in calibration data.
    Format: X + 2 digits + 2–3 uppercase letters.

  VIN                 "W0L0JBF19W5117067"
    17-character ISO 3779 Vehicle Identification Number.
    Starts with "W" (Germany — Opel manufacturing).

  CALIBRATION REF     "S96007"  "S96008"
    Short calibration reference code.
    Format: S + 5–6 digits.

  CALIBRATION CODE    "S001005674"  "S001000113"
    Extended calibration dataset code.
    Format: S001 + 6 digits.
"""

from typing import Dict, List

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# The ident_record pattern captures the full combined RS/RT identification
# string.  Sub-fields (GM part number, serial number) are extracted by
# the resolver in the extractor — NOT by separate regex patterns — because
# Python's `re` module does not support variable-length lookbehinds.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Combined identification record
    # ------------------------------------------------------------------
    # Full RS/RT ident record — the single most reliable identifier.
    # Format: R[ST] + 8-digit GM part + whitespace + 12–16 digit serial +
    #         lowercase letter + "5WK9" + 4–6 trailing digits
    # e.g. "RS90506365 0106577255425b5WK907302"  (5WK9 + 5 digits)
    #       "RT90464731 0106577255426j5WK907402"  (5WK9 + 5 digits)
    #
    # The trailing digits after 5WK9 encode a 4-digit variant number plus
    # a 1–2 digit checksum suffix.  All confirmed samples show 5 trailing
    # digits (4 variant + 1 check), but \d{4,6} is used for robustness
    # against undiscovered variants with a 2-digit checksum.
    #
    # Note: variable-length lookbehinds are not supported by Python's re
    # module, so gm_part_number and serial_number are parsed from the
    # ident_record match in the resolver rather than by separate patterns.
    "ident_record": rb"R[ST]\d{8}\s+\d{12,16}[a-z]5WK9\d{4,6}",
    # ------------------------------------------------------------------
    # Hardware / software identification
    # ------------------------------------------------------------------
    # Siemens part number — "5WK9" + 4 digits (core identifier)
    # e.g. "5WK90730"  "5WK90740"
    # The full part includes a 2-digit checksum suffix ("5WK907302") but
    # this pattern captures the stable 8-character core for matching.
    "siemens_part": rb"5WK9\d{4}",
    # ------------------------------------------------------------------
    # Engine and vehicle identification
    # ------------------------------------------------------------------
    # Opel engine code — X + 2 digits + 2–3 uppercase letters
    # e.g. "X18XE"  "X20XEV"
    "engine_code": rb"X\d{2}[A-Z]{2,3}",
    # Vehicle Identification Number — 17 chars starting with "W" (Opel/GM Europe)
    # e.g. "W0L0JBF19W5117067"  "W0L000038T7536405"
    "vin": rb"W[A-Z0-9]{16}",
    # ------------------------------------------------------------------
    # Calibration references
    # ------------------------------------------------------------------
    # Short calibration reference — S + 5–6 digits
    # e.g. "S96007"  "S96008"
    # Negative lookbehind prevents false positives on the "S" inside
    # RS/RT ident records (e.g. "RS90506365" → "S905063" without guard).
    "calibration_ref": rb"(?<![A-Za-z])S\d{5,6}",
    # Extended calibration dataset code — S001 + 6 digits
    # e.g. "S001005674"  "S001000113"
    # Same lookbehind guard as calibration_ref for consistency.
    "calibration_code": rb"(?<![A-Za-z])S001\d{6}",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real Siemens Simtec 56 binaries (128 KB).
#
# Key findings:
#   - Header region contains the 8051/C166 reset vector and initial code
#   - Ident area (first 32 KB) contains the RS/RT ident records and
#     calibration references in most samples
#   - Engine codes, VINs, and calibration data may appear anywhere
#   - Full binary search is used for all patterns due to the compact
#     128 KB size — performance impact is negligible
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # First 4 KB — header / reset vector area
    "header": slice(0x0000, 0x1000),
    # First 32 KB — ident area (RS/RT records, calibration refs)
    "ident_area": slice(0x0000, 0x8000),
    # Full binary — all 128 KB (compact enough to scan entirely)
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# All patterns search the full binary.  At 128 KB the file is small enough
# that full-file regex scans are effectively instantaneous.  This avoids
# missed identifiers due to unexpected offsets in variant binaries.
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "ident_record": "full",
    "siemens_part": "full",
    "engine_code": "full",
    "vin": "full",
    "calibration_ref": "full",
    "calibration_code": "full",
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by SiemensSimtec56Extractor.can_handle() to positively
# identify a binary as Siemens Simtec 56.
#
# "5WK9" is the canonical Siemens part number prefix shared across Simtec,
# SID, and other Siemens/Continental families.  The can_handle() method
# combines this with the RS/RT ident record check and the 128 KB size gate
# to disambiguate Simtec 56 from other 5WK9-bearing families.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: List[bytes] = [
    b"5WK9",
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these byte sequences are found anywhere in the binary, the file
# is NOT a Simtec 56 — even if it matches the size gate and contains 5WK9.
#
# This eliminates:
#   - Bosch families that may coincidentally be 128 KB (M1.55, M3.x, EDC3x)
#   - Delphi / Magneti Marelli ECUs
#   - Other Siemens families (SID, PPD) that share the 5WK9 prefix
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: List[bytes] = [
    b"EDC17",  # Bosch EDC17 diesel
    b"MEDC17",  # Bosch MEDC17 diesel
    b"ME7.",  # Bosch ME7 petrol
    b"BOSCH",  # Generic Bosch marker
    b"0261",  # Bosch hardware number prefix (petrol)
    b"MOTRONIC",  # Bosch Motronic label
    b"PM3",  # Bosch PM3 label (Porsche)
    b"PPD",  # Siemens PPD pump-injector diesel
]

# ---------------------------------------------------------------------------
# Header magic
# ---------------------------------------------------------------------------
# First 3 bytes of the 8051/C166 LJMP reset vector found in all known
# Simtec 56 binaries.  The full 5-byte sequence is \x02\x00\xb0\x20\xb2
# but only the first 3 bytes are checked as a weak positive signal —
# bytes 4–5 may vary across ROM revisions.
# ---------------------------------------------------------------------------

SIMTEC56_HEADER: bytes = b"\x02\x00\xb0"

# ---------------------------------------------------------------------------
# Ident record prefix
# ---------------------------------------------------------------------------
# The RS/RT ident record is the strongest positive anchor for Simtec 56.
# "RS" = standard software track, "RT" = alternate/test track.
# The prefix is followed by an 8-digit GM part number.
# ---------------------------------------------------------------------------

IDENT_PREFIXES: List[bytes] = [
    b"RS",
    b"RT",
]

# ---------------------------------------------------------------------------
# Size constraint
# ---------------------------------------------------------------------------
# All known Simtec 56 binaries are exactly 128 KB (131 072 bytes).
# This is the primary gate for can_handle().
# ---------------------------------------------------------------------------

SIMTEC56_FILE_SIZE: int = 131_072
