"""
Delphi Multec S ECU binary identifier patterns and search regions.

All regex patterns, fixed-offset definitions, and search region definitions
specific to Delphi Multec S petrol ECUs used in Opel/Vauxhall vehicles with
various 4-cylinder engines (1996–2003).

Binary structure:
  File size: exactly 131 072 bytes (128 KB = 0x20000)
  CPU:       Motorola HC12 / HCS12 (68HC12)
  Layout:    Two 64 KiB banks with identical (mirrored) structure
    - Bank 1: 0x00000–0x0FFFF
    - Bank 2: 0x10000–0x1FFFF (mirror of Bank 1)
  Boot block: 0x0000–0x1FFF — erased (all 0xFF, 8 KiB)
  Data/code:  starts at 0x2000 with HC12 pointer tables
  Ident block: fixed offset 0x3000 (mirrored at 0x13000)

Ident block layout (relative to base 0x3000):
  +0x00  2 bytes   Header/checksum bytes (vary per file)
  +0x02  4 bytes   0xFF padding
  +0x06  2 bytes   Checksum bytes (vary per file)
  +0x08  1 byte    Separator (0xAB, 0xB7, etc. — varies per file)
  +0x09  8 bytes   SW number — 8 ASCII digits (e.g. "94072261")
  +0x11  2 bytes   Broadcast code — 2 uppercase ASCII letters (e.g. "FM")
  +0x13  2 bytes   Null separators (0x00 0x00)
  +0x15  8 bytes   GM/OEM part number — 8 ASCII digits (e.g. "16227049")
  +0x1D  1 byte    Space (0x20)
  +0x1E  2 bytes   Broadcast prefix — 2 uppercase letters (e.g. "MF")
  +0x20  4 bytes   Variant/family code — 4 uppercase letters (e.g. "CNHR")
  +0x24  1 byte    Null (0x00)
  +0x25  1 byte    Version byte (e.g. 0x05, 0x02)
  +0x26  6 bytes   D-number calibration reference (e.g. "D98003")
  +0x2C  6 bytes   Engine/HW suffix (e.g. "X16SZR", "X14XE " — may be
                    shorter than 6 chars, padded with space or followed by
                    data immediately)

Optional fields (present in some files only):
  +0x32  2 bytes   Separators (0x0A 0x01)
  +0x34  10 bytes  T-code (e.g. "T0098DXZ01") — NOT present in all files

Typical vehicles:
  Opel/Vauxhall Astra G, Corsa B/C, Vectra B, Zafira A
  Engines: X16SZR (1.6L 16V), X14XE (1.4L 16V), Z16SE, Z14XE, etc.

Identification strategy:
  Multec S binaries share the same 128 KB file size as Siemens Simtec 56.
  The Simtec 56 extractor runs first in the registry and already rejects
  non-Siemens files via 5WK9 / RS/RT checks.  The Multec S extractor uses
  a complementary set of structural checks:
    1. Exact 128 KB file size (131 072 bytes)
    2. First 8 KiB (0x0000–0x1FFF) must be all 0xFF (erased boot block)
    3. HC12 pointer table signature at 0x2000 (0x00 0x00 0x7E)
    4. Absence of all Bosch / Siemens / Marelli exclusion signatures
    5. Ident block validation at 0x3009: 8 ASCII digits + 2 uppercase letters
    6. GM part number validation at 0x3015: 8 ASCII digits
"""

from typing import Dict, List

# ---------------------------------------------------------------------------
# Fixed offsets — ident block
# ---------------------------------------------------------------------------
# All fields are at fixed byte positions relative to IDENT_BASE (0x3000).
# Offset-based extraction is more reliable than regex for this ECU family
# because all known Multec S binaries share an identical ident block layout.
#
# A mirrored copy exists at IDENT_MIRROR_BASE (0x13000) in Bank 2.
# ---------------------------------------------------------------------------

IDENT_BASE: int = 0x3000
IDENT_MIRROR_BASE: int = 0x13000

# SW number — 8 ASCII digits (e.g. "94072261", "93241261")
SW_OFFSET: int = 0x09
SW_LENGTH: int = 8

# Broadcast code — 2 uppercase ASCII letters following the SW number
# (e.g. "FM", "SJ")
BROADCAST_OFFSET: int = 0x11
BROADCAST_LENGTH: int = 2

# GM/OEM part number — 8 ASCII digits (e.g. "16227049", "16214239")
GM_PN_OFFSET: int = 0x15
GM_PN_LENGTH: int = 8

# Variant/family code — 4 uppercase ASCII letters (e.g. "CNHR", "BWJN")
VARIANT_OFFSET: int = 0x20
VARIANT_LENGTH: int = 4

# Version byte — single byte encoding a version number (e.g. 0x05, 0x02)
VERSION_OFFSET: int = 0x25
VERSION_LENGTH: int = 1

# D-number calibration reference — 6 ASCII chars starting with "D"
# (e.g. "D98003", "D96017")
D_NUMBER_OFFSET: int = 0x26
D_NUMBER_LENGTH: int = 6

# Engine/HW suffix — up to 6 ASCII chars starting with "X"
# (e.g. "X16SZR", "X14XE " — may be shorter, space-padded)
ENGINE_OFFSET: int = 0x2C
ENGINE_LENGTH: int = 6

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# These patterns serve as VALIDATION and FALLBACK mechanisms.  The primary
# extraction method for Multec S is offset-based (see fixed offsets above).
# The patterns are provided for use with the base class pattern engine
# (_run_all_patterns) to cross-check offset-based results and to catch
# fields that might appear at unexpected locations in variant binaries.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Software version — 8 digits + 2 uppercase letter broadcast code
    # ------------------------------------------------------------------
    # e.g. "94072261FM", "93241261SJ"
    # The full 10-char string is matched; the extractor extracts the
    # leading 8 digits as the software version.
    "software_version": rb"\d{8}[A-Z]{2}",
    # ------------------------------------------------------------------
    # OEM part number — 8 digits followed by space + 2 letters
    # ------------------------------------------------------------------
    # e.g. "16227049 MF", "16214239 JS"
    # The GM/Opel part number sits at a fixed offset and is always
    # followed by a space and a 2-letter broadcast prefix.
    "oem_part_number": rb"\d{8}\s[A-Z]{2}",
    # ------------------------------------------------------------------
    # Variant code — 4 uppercase letters after the broadcast prefix area
    # ------------------------------------------------------------------
    # e.g. "CNHR", "BWJN"
    # Captured via the combined GM PN + broadcast prefix + variant pattern.
    # The variant code is the 4-letter block immediately following the
    # 2-letter broadcast prefix at offset 0x301E.
    "variant_code": rb"\d{8}\s[A-Z]{2}[A-Z]{2}([A-Z]{4})",
    # ------------------------------------------------------------------
    # Calibration ID — D-number reference
    # ------------------------------------------------------------------
    # e.g. "D98003", "D96017"
    # Format: "D" followed by exactly 5 digits.
    # Negative lookbehind prevents matching inside longer alphanumeric
    # sequences.
    "calibration_id": rb"(?<![A-Za-z0-9])D\d{5}(?![0-9])",
    # ------------------------------------------------------------------
    # Engine code — engine/HW suffix
    # ------------------------------------------------------------------
    # e.g. "X16SZR", "X14XE"
    # Format: "X" + 2 digits + 2–4 uppercase letters.
    # Appears immediately after the D-number at offset 0x302C.
    "engine_code": rb"X\d{2}[A-Z]{2,4}",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real Delphi Multec S binaries (128 KB).
#
# Key findings:
#   - The ident block at 0x3000–0x30FF contains ALL key identification
#     fields at fixed offsets — this is the primary extraction region.
#   - A mirrored copy at 0x13000–0x130FF contains identical data in Bank 2.
#   - Additional strings (e.g. "8329OPELO_") may appear in the data/code
#     areas — full binary scan catches these.
#   - At 128 KB, full-file regex scans are effectively instantaneous.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # Primary ident block — contains all key identification fields
    "ident_block": slice(0x3000, 0x3100),
    # Mirrored ident block in Bank 2 — identical data
    "ident_mirror": slice(0x13000, 0x13100),
    # Full binary — all 128 KB (compact enough to scan entirely)
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# All patterns target the ident_block region since every field sits at a
# fixed offset within the 0x3000–0x30FF range.  Full-binary search is
# unnecessary for these patterns and would increase false-positive risk
# (e.g. engine codes appearing in calibration tables).
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "software_version": "ident_block",
    "oem_part_number": "ident_block",
    "variant_code": "ident_block",
    "calibration_id": "ident_block",
    "engine_code": "ident_block",
}

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these byte sequences are found anywhere in the binary, the file
# is NOT a Delphi Multec S — even if it matches the size gate and structural
# checks.
#
# This eliminates:
#   - Bosch families that may coincidentally be 128 KB (M1.55, M3.x, EDC3x,
#     ME7.x, Motronic)
#   - Siemens families (Simtec 56, SID, PPD, SIMOS) that share the same
#     128 KB file size
#   - Magneti Marelli ECUs
#   - Other Delphi families with different structures
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: List[bytes] = [
    b"BOSCH",  # Generic Bosch marker
    b"EDC15",  # Bosch EDC15 diesel family (not bare "EDC" — too short,
    b"EDC16",  #   matches random calibration table bytes like "CDEDC")
    b"EDC17",  # Bosch EDC17 diesel family
    b"MEDC17",  # Bosch MEDC17 diesel family
    b"ME7.",  # Bosch ME7 petrol
    b"5WK9",  # Siemens part number prefix (Simtec 56, SID, etc.)
    b"SIMOS",  # Siemens SIMOS petrol
    b"PPD1.",  # Siemens PPD pump-injector diesel (not bare "PPD" — too short)
    b"MARELLI",  # Magneti Marelli generic marker
    b"MAG  ",  # Magneti Marelli abbreviated marker (MAG + 2 spaces)
    b"MOTRONIC",  # Bosch Motronic label
    b"DEL ",  # Other Delphi family marker (note trailing space)
    b"1037\x33",  # Bosch SW prefix inside data (0x1037 + digit) — requires
    b"1037\x34",  #   a following ASCII digit to avoid matching random bytes.
    b"1037\x35",  #   Covers 10373xxxxx–10379xxxxx which is the real range.
    b"1037\x36",
    b"1037\x37",
    b"1037\x38",
    b"1037\x39",
    b"0261\x30",  # Bosch HW number prefix (0261 + leading digit 0)
    b"TSW ",  # Bosch EDC15 TSW label
]

# ---------------------------------------------------------------------------
# HC12 pointer table signature
# ---------------------------------------------------------------------------
# At offset 0x2000 (start of data/code after the erased boot block), all
# known Multec S binaries begin with HC12/HCS12 pointer table bytes.
#
# The first two bytes are always 0x00 0x00, and byte 0x2002 is always 0x7E.
# Byte 0x2003 varies between files (0x20 in CNHR, may differ in others),
# so only the first 3 bytes are checked.
# ---------------------------------------------------------------------------

HC12_POINTER_SIGNATURE: bytes = b"\x00\x00\x7e"
HC12_POINTER_OFFSET: int = 0x2000

# ---------------------------------------------------------------------------
# Boot block characteristics
# ---------------------------------------------------------------------------
# The first 8 KiB (0x0000–0x1FFF) of all known Multec S binaries are
# entirely 0xFF — an erased flash boot block.  For detection purposes,
# checking only the first 16 bytes is sufficient and fast.
# ---------------------------------------------------------------------------

BOOT_BLOCK_SIZE: int = 0x2000
BOOT_BLOCK_CHECK_LENGTH: int = 16
BOOT_BLOCK_FILL: bytes = b"\xff" * 16

# ---------------------------------------------------------------------------
# Ident block validation offsets
# ---------------------------------------------------------------------------
# For can_handle() validation, the following byte ranges at fixed offsets
# must contain expected character types:
#
#   0x3009–0x3010 (8 bytes): ASCII digits 0–9 (SW number)
#   0x3011–0x3012 (2 bytes): Uppercase ASCII letters A–Z (broadcast code)
#   0x3015–0x301C (8 bytes): ASCII digits 0–9 (GM part number)
#
# These are checked as absolute offsets into the binary data.
# ---------------------------------------------------------------------------

SW_CHECK_START: int = IDENT_BASE + SW_OFFSET  # 0x3009
SW_CHECK_END: int = IDENT_BASE + SW_OFFSET + SW_LENGTH  # 0x3011
BROADCAST_CHECK_START: int = IDENT_BASE + BROADCAST_OFFSET  # 0x3011
BROADCAST_CHECK_END: int = IDENT_BASE + BROADCAST_OFFSET + BROADCAST_LENGTH  # 0x3013
GM_PN_CHECK_START: int = IDENT_BASE + GM_PN_OFFSET  # 0x3015
GM_PN_CHECK_END: int = IDENT_BASE + GM_PN_OFFSET + GM_PN_LENGTH  # 0x301D

# ---------------------------------------------------------------------------
# Size constraint
# ---------------------------------------------------------------------------
# All known Delphi Multec S binaries are exactly 128 KB (131 072 bytes).
# This is the primary gate for can_handle().
# ---------------------------------------------------------------------------

MULTEC_S_FILE_SIZE: int = 131_072
