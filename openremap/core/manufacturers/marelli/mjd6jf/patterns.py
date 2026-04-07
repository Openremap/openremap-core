"""
Magneti Marelli MJD 6JF ECU binary identifier patterns and search regions.

All regex patterns and search region definitions specific to the Magneti
Marelli MJD 6JF diesel ECU family.

Pattern reference:

  SOFTWARE VERSION    "31315X375" or "31414X188"
    Marelli internal software calibration identifier.
    Format: 4–5 decimal digits + uppercase letter + 3 decimal digits.
    Located between two AA55CC33 sync markers in the identity block at
    ~0x6009A.  The leading "3" may be a prefix byte — the core version
    string is the portion matching the digit-letter-digit pattern.
    THIS IS THE PRIMARY MATCHING KEY.

  OEM PART NUMBER     "355190069 WJ" or "355196352 ZJ"
    GM / Opel / Vauxhall OEM part number for the ECU calibration.
    Format: 9 decimal digits + space + 2 uppercase letters.
    Located at ~0x600A8 in the identity block.

  MARELLI PART NUMBER "MAG  01246JO01D" or "MAG  01246JO01DDM04001"
    Magneti Marelli internal part number / reference.
    Format: "MAG" + 1–3 spaces + 8–20 alphanumeric characters.
    Located at ~0x600BC in the identity block.

  ENGINE CODE         "UZ13DT"
    Engine designation code embedded immediately before the first
    AA55CC33 sync marker at ~0x60090.
    Format: 2 uppercase letters + 2 decimal digits + 2 uppercase letters.

  CALIBRATION ID      "MUST_C5131" or "MUST_C4141"
    MUST calibration reference code.  The "C" + 4–5 digits portion
    after the underscore is the unique calibration sub-identifier.
    Located in the sub-family block at ~0x6E000–0x6F000.

  ECU FAMILY TAG      "6JF   MUST"
    Family identifier string followed by whitespace and the MUST prefix.
    Confirms the binary belongs to the MJD 6JF family.
    Located in the sub-family block at ~0x6E000–0x6F000.

  CALIBRATION REF     "M0400563M" or similar
    Additional Marelli calibration cross-reference.
    Format: "M" + 7 digits + uppercase letter.
    Located at ~0x600CC in the identity block.

Binary layout (two known file sizes):

  462848 bytes (0x71000) — Calibration-only dump
    0x00000–0x0000F : 16-byte ASCII header "C M D - M C D   "
    0x00010–0x60007 : 0xFF padding
    0x60000–0x70FFF : Calibration data + identity block

  458752 bytes (0x70000) — Full flash dump
    0x00000–0x5EFFF : PowerPC executable code (starts with 3D600040)
    0x60000–0x6FFFF : Calibration data + identity block
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# Naming convention mirrors the Bosch/Siemens extractor families — each
# key maps directly to an extraction field or detection signal.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Software / calibration identification
    # ------------------------------------------------------------------
    # Software version — digits + uppercase letter + digits.
    # e.g. "31315X375"  "31414X188"
    # The leading digit(s) before the 4-digit group may be a prefix;
    # the full match is kept for maximum fidelity.
    "software_version": rb"\d{4,5}[A-Z]\d{3}",
    # OEM (GM) part number — 9 decimal digits + space + 2 uppercase letters.
    # e.g. "355190069 WJ"  "355196352 ZJ"
    "oem_part_number": rb"\d{9}\s+[A-Z]{2}",
    # Marelli part number — "MAG" + 1–3 spaces + alphanumeric string.
    # e.g. "MAG  01246JO01D"  "MAG  01246JO01DDM04001"
    "marelli_part": rb"MAG\s{1,3}\w{8,20}",
    # Engine code — 2 uppercase letters + 2 digits + 2 uppercase letters.
    # e.g. "UZ13DT"
    "engine_code": rb"[A-Z]{2}\d{2}[A-Z]{2}",
    # MUST calibration ID — "MUST_" + letter + 4–5 digits.
    # e.g. "MUST_C5131"  "MUST_C4141"
    "calibration_id": rb"MUST_[A-Z]\d{4,5}",
    # ECU family tag — digit + "JF" + whitespace + "MUST".
    # e.g. "6JF   MUST"
    # Confirms MJD 6JF family membership.
    "ecu_family_tag": rb"\dJF\s{2,6}MUST",
    # Additional calibration cross-reference — "M" + 7 digits + letter.
    # e.g. "M0400563M"
    "calibration_ref": rb"M\d{7}[A-Z]",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real MJD 6JF binaries across two confirmed file
# sizes: 458752 (0x70000) and 462848 (0x71000) bytes.
#
# Key findings:
#   - The identity block lives at 0x60090 in both file variants.
#   - Software version, OEM part number, Marelli part number, engine code,
#     and calibration cross-references are all concentrated in 0x60000–0x61000.
#   - The sub-family tag ("6JF   MUST_C...") lives at ~0x6E000–0x6F000.
#   - PowerPC code occupies 0x00000–0x5EFFF in full flash dumps but
#     contains no identification strings relevant to extraction.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # Identity block — SW version, OEM part#, Marelli part#, engine code.
    "ident_block": slice(0x60000, 0x61000),
    # Calibration data area — sub-family tag, MUST calibration ID.
    "cal_data": slice(0x60000, 0x71000),
    # Full binary — fallback for any pattern that may appear anywhere.
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# Defines which region each pattern is searched in.
# Narrower regions = faster search = lower false-positive rate.
#
# Rationale:
#   - software_version, oem_part_number, marelli_part, engine_code,
#     calibration_ref: all live in the identity block at 0x60000–0x61000.
#   - calibration_id, ecu_family_tag: live in the sub-family block at
#     ~0x6E000–0x6F000, within the broader calibration data area.
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "software_version": "ident_block",
    "oem_part_number": "ident_block",
    "marelli_part": "ident_block",
    "engine_code": "ident_block",
    "calibration_ref": "ident_block",
    "calibration_id": "cal_data",
    "ecu_family_tag": "cal_data",
}

# ---------------------------------------------------------------------------
# Valid file sizes
# ---------------------------------------------------------------------------
# MJD 6JF binaries come in exactly two known sizes.
# This set is used as the first gate in can_handle() — any file whose
# length is not in this set is immediately rejected.
#
#   458752  (0x70000 / 448 KB) — Full flash dump (PowerPC code + cal data)
#   462848  (0x71000 / 452 KB) — Calibration-only dump (header + cal data)
# ---------------------------------------------------------------------------

VALID_FILE_SIZES: set[int] = {
    458752,  # 0x70000 — full flash dump
    462848,  # 0x71000 — calibration-only dump
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by MarelliMJD6JFExtractor.can_handle() to confirm
# that a binary belongs to the MJD 6JF family.
#
# After the size gate and exclusion check pass, ALL of the following
# conditions must be satisfied:
#
#   1. AA55CC33 sync marker present anywhere in the binary.
#   2. b"MAG" present in the identity block (0x60000–0x61000).
#   3. b"6JF" present in the calibration area (0x60000–0x70000).
#
# These are checked individually in can_handle() rather than as a simple
# signature list, because each has a different search scope.
# ---------------------------------------------------------------------------

SYNC_MARKER: bytes = b"\xaa\x55\xcc\x33"

MARELLI_SIGNATURE: bytes = b"MAG"

FAMILY_ANCHOR: bytes = b"6JF"

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# Byte sequences that, if present anywhere in the binary, indicate it
# belongs to a different ECU family and must NOT be claimed by MJD 6JF.
#
# These are checked BEFORE detection signatures — first exclusion hit
# causes immediate rejection.
#
# The list covers all major competing ECU families that could share
# similar file sizes or contain coincidental byte sequences:
#
#   Bosch families:   EDC17, MEDC17, EDC16, EDC15, ME7.x, BOSCH
#   Siemens families: 5WK9 (SID/SIMOS prefix), SIMOS, MOTRONIC
#   Marelli IAW:      IAW / iaw (different Marelli family)
#   Delphi:           DELPHI, DEL  (Delphi DCM/MT prefix)
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"EDC16",
    b"EDC15",
    b"ME7.",
    b"BOSCH",
    b"5WK9",
    b"SIMOS",
    b"MOTRONIC",
    b"IAW",
    b"iaw",
    b"DELPHI",
    b"DEL  ",
]
