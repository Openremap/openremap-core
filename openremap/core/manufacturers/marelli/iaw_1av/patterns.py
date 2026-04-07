"""
Magneti Marelli IAW 1AV ECU binary identifier patterns and search regions.

Covers the Magneti Marelli IAW 1AV family:
  IAW 1AV — single-point injection ECU used in VAG (Skoda/VW/Seat) vehicles
             with 1.0–1.6 litre naturally aspirated petrol engines (1996–2003).

Binary structure (65,536 bytes / 0x10000):
  0x0000 – 0x000F : Erased vector area — all 0xFF (16 bytes)
  0x0010           : Code start — machine opcodes begin here
  0x3D00 – 0x3E00 : Main ident block — contains the full identification string
  0x3D3C           : Main ident string (36 bytes):
                       "032906030AG MARELLI 1AV        F012"
                       Bytes  0–10 : VAG OEM part number (e.g. "032906030AG")
                       Byte   11   : space separator
                       Bytes 12–18 : manufacturer name "MARELLI"
                       Byte   19   : space separator
                       Bytes 20–22 : ECU family tag "1AV"
                       Bytes 23–30 : padding (8 spaces)
                       Bytes 31–34 : firmware/SW version (e.g. "F012")
  0x4400 – 0x4500 : Secondary identification area
  0x4431           : Lowercase family tag "iaw1av" (6 bytes, null-terminated)
  0xFFA0           : Sync marker AA55CC33

Pattern reference:

  IDENT RECORD        "032906030AG MARELLI 1AV        F012"
    Full identification string combining VAG OEM part number, manufacturer
    name, ECU family tag, and firmware/SW version.
    Format: <9 digits + 1–2 suffix letters> + space + "MARELLI" + space +
            <family tag> + padding + <FW version>.
    The most reliable single source of all key identifiers.

  OEM PART NUMBER     "032906030AG"
    VAG (VW/Skoda/Seat) OEM part number for the ECU.
    Format: 9 digits + 1–2 uppercase letter suffix.
    Immediately precedes the "MARELLI" manufacturer string.

  ECU FAMILY TAG      "1AV"
    ECU family identifier extracted from within the ident string.
    Always follows "MARELLI " with optional whitespace.
    Format: 1 digit + 2 uppercase letters.

  SOFTWARE VERSION    "F012"
    Firmware/software version code.
    Format: 1 uppercase letter + 3 digits.
    Follows the family tag and padding in the ident string.

  IAW TAG             "iaw1av"
    Lowercase family identifier found in the secondary ident area.
    Format: "iaw" + 1 digit + 2 lowercase letters.
    Serves as a secondary confirmation of the ECU family.
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Full ident record
    # ------------------------------------------------------------------
    # Combined identification string: VAG PN + MARELLI + family + FW version
    # e.g. "032906030AG MARELLI 1AV        F012"
    # Capturing group 1 = VAG OEM part number (9 digits + 1–2 suffix letters)
    # Capturing group 2 = ECU family tag (e.g. "1AV")
    # Capturing group 3 = firmware/SW version (e.g. "F012")
    "ident_record": rb"(\d{9}[A-Z]{1,2})\s+MARELLI\s+([\w.]+)\s+([\w]{3,6})",
    # ------------------------------------------------------------------
    # OEM part number
    # ------------------------------------------------------------------
    # VAG OEM part number — 9 digits + 1–2 uppercase letter suffix.
    # e.g. "032906030AG"
    # Anchored by a lookahead for the MARELLI manufacturer string.
    "oem_part_number": rb"\d{9}[A-Z]{1,2}(?=\s+MARELLI)",
    # ------------------------------------------------------------------
    # ECU family tag
    # ------------------------------------------------------------------
    # Family identifier following "MARELLI " in the ident string.
    # e.g. "1AV"
    # Capturing group 1 = family tag (1 digit + 2 uppercase letters).
    "ecu_family_tag": rb"MARELLI\s+(\d[A-Z]{2})",
    # ------------------------------------------------------------------
    # Firmware / software version
    # ------------------------------------------------------------------
    # Alphanumeric code after the family tag and padding.
    # e.g. "F012"
    # Capturing group 1 = version code (1 uppercase letter + 3 digits).
    "software_version": rb"MARELLI\s+\d[A-Z]{2}\s+([A-Z]\d{3})",
    # ------------------------------------------------------------------
    # Lowercase family identifier (secondary)
    # ------------------------------------------------------------------
    # e.g. "iaw1av"
    # No capturing groups — full match is the identifier.
    "iaw_tag": rb"iaw\d[a-z]{2}",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real IAW 1AV binaries (65,536 bytes).
#
# Key findings:
#   - Main ident string is always within 0x3D00–0x3E00.
#   - Secondary lowercase tag "iaw1av" is always within 0x4400–0x4500.
#   - Sync marker AA55CC33 is at 0xFFA0.
#   - Full-binary fallback for any patterns that don't have a fixed home.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # Main ident block — OEM PN, MARELLI, family, FW version
    "ident_area": slice(0x3D00, 0x3E00),
    # Secondary identification area — lowercase iaw tag
    "secondary": slice(0x4400, 0x4500),
    # Full binary — fallback for unrestricted searches
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    # Ident area (0x3D00–0x3E00) — primary identifiers
    "ident_record": "ident_area",
    "oem_part_number": "ident_area",
    "ecu_family_tag": "ident_area",
    "software_version": "ident_area",
    # Secondary area (0x4400–0x4500) — lowercase iaw tag
    "iaw_tag": "secondary",
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by MarelliIAW1AVExtractor.can_handle() to positively
# identify a binary as Magneti Marelli IAW 1AV.
#
# Strategy:
#   - b"MARELLI" must be present — definitive manufacturer anchor.
#   - b"1AV" must be present in the ident area (0x3D00–0x3E00) — family
#     confirmation.
#   - b"iaw1av" must be present — secondary family confirmation.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"MARELLI",  # Manufacturer name — must be present
    b"1AV",  # ECU family tag — must be in ident area
    b"iaw1av",  # Lowercase family identifier — secondary confirm
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these are found anywhere in the binary, it is NOT IAW 1AV.
# This prevents the IAW 1AV extractor from stealing bins that belong to
# Bosch, Siemens, Delphi, or other Marelli families.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"BOSCH",  # Bosch generic marker
    b"EDC",  # Bosch EDC diesel family
    b"ME7.",  # Bosch ME7 petrol family
    b"5WK9",  # Continental/Siemens part prefix
    b"SIMOS",  # Siemens SIMOS family
    b"PPD",  # Bosch PPD pump-injector diesel
    b"DELPHI",  # Delphi generic marker
    b"DEL  ",  # Delphi short marker (padded)
    b"MOTRONIC",  # Bosch Motronic label
    b"6JF",  # Marelli MJD 6JF family tag
    b"MJD",  # Marelli MJD diesel family
    b"4LV",  # Marelli IAW 4LV family tag
    b"MAG  ",  # Marelli alternate padded marker (non-1AV)
]

# ---------------------------------------------------------------------------
# Structural constants
# ---------------------------------------------------------------------------

# Expected file size for IAW 1AV binaries: exactly 64KB.
IAW_1AV_FILE_SIZE: int = 0x10000  # 65,536 bytes

# Erased vector area: first 16 bytes must all be 0xFF.
ERASED_HEADER_SIZE: int = 16
ERASED_HEADER_BYTE: int = 0xFF

# Ident area bounds for the "1AV" family anchor check in can_handle().
IDENT_AREA_START: int = 0x3D00
IDENT_AREA_END: int = 0x3E00
