"""
Siemens SIMOS ECU binary identifier patterns and search regions.

All regex patterns and search region definitions specific to Siemens SIMOS ECUs.
Covers: SIMOS, SIMOS2, SIMOS3

Pattern reference:

  SIEMENS PART NUMBER  "5WP4860"  "5WP40123"
    Siemens hardware/software part number for the ECU.
    Format: 5WP4 + 3–5 digits.
    Unique per ECU hardware/software variant.

  SIMOS LABEL          "SIMOS   2441"
    ECU family string embedded in the binary.
    Format: "SIMOS" + whitespace + 4-digit sub-version.
    Rare — only found in a minority of SIMOS binaries.

  OEM IDENT STRING     "06A906019BH 1.6l R4/2V SIMOS   2441"
    Full OEM identification string combining VAG part number,
    engine displacement, cylinder configuration, and SIMOS label.
    Very rare — found in only one known binary.

  OEM PART NUMBER      "06A906019BH"  "047906019"
    VAG (VW/Audi/Skoda/Seat) part number for the ECU.
    Format: 0 + [46] + [7A] + "906" + 3 digits + optional 1–2 letter suffix.
    Identifies the vehicle application.

  PROJECT CODE         "s21_2441"  "s2114601"  "111s210"
    Internal Siemens project/software codes.
    Format: "s21" + digit or underscore + up to 6 alphanumeric chars.

  CALIBRATION DATASET  "cas21146.DAT"
    Siemens calibration dataset filename reference.
    Format: "cas21" + 3 digits + ".DAT"

  SERIAL CODE          "6577295501--"  "6577297701--"
    Production serial codes found in some SIMOS binaries.
    Format: "6577" + 6 digits (trailing dashes are not captured).

  ECU FAMILY           "SIMOS"
    Bare family identifier. Definitive when present, but many SIMOS
    binaries are "dark" — they contain no readable ASCII strings at all.

Binary sub-types by size:

  131 KB (131072 bytes) — SIMOS EEPROM (27c010.bin)
    Header prefix: \\x02 — 8051 reset vector style.
    Known variants: \\x02\\x58\\x95\\x05, \\x02\\x56\\x9f\\x05.
    Very sparse ASCII content.

  262 KB (262144 bytes) — SIMOS 2.x EEPROM dumps
    Header prefixes: \\xc0\\x64 (VW Golf 4), \\xfa\\x00 (Skoda Octavia).
    Very sparse ASCII — essentially no readable strings.
    Part numbers typically only in filenames, not in binary data.

  524 KB (524288 bytes) — SIMOS 3.x full flash
    Header prefix: \\xf0\\x30 — common to ALL 524KB bins.
    Known variants: \\xf0\\x30\\xe8\\x44, \\xf0\\x30\\x58\\x74,
                    \\xf0\\x30\\xa0\\x4c, \\xf0\\x30\\xc0\\x6c.
    Very sparse ASCII — most have no identifiable strings.
    Occasional SIMOS label and project code strings.
"""

from typing import Dict, List

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# SIMOS binaries are overwhelmingly "dark" — most contain no readable ASCII
# strings at all. When strings ARE present, they are definitive identifiers.
# The patterns below are designed to capture every known identifier format
# without false-positiving on noise in otherwise opaque binary data.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Hardware / software identification
    # ------------------------------------------------------------------
    # Siemens part number — "5WP4" + 3–5 digits
    # e.g. "5WP4860"  "5WP40123"
    "siemens_part": rb"5WP4\d{3,5}",
    # ------------------------------------------------------------------
    # ECU family and label
    # ------------------------------------------------------------------
    # SIMOS label — "SIMOS" + whitespace + 4-digit sub-version
    # e.g. "SIMOS   2441"
    "simos_label": rb"SIMOS\s+\d{4}",
    # Bare ECU family marker — just "SIMOS"
    "ecu_family": rb"SIMOS",
    # ------------------------------------------------------------------
    # OEM identification
    # ------------------------------------------------------------------
    # Full OEM ident string — VAG part + displacement + config + SIMOS label
    # e.g. "06A906019BH 1.6l R4/2V SIMOS   2441"
    "oem_ident": rb"[0-9][0-9A-Z]{2}\d{3}\d{3}[A-Z]{0,2}\s+\d\.\dl\s+R4/2V\s+SIMOS",
    # VAG OEM part number — 06A906xxx or 047906xxx style
    # e.g. "06A906019BH"  "047906019"
    "oem_part_number": rb"0[46][7A]906\d{3}[A-Z]{0,2}",
    # ------------------------------------------------------------------
    # Project / calibration references
    # ------------------------------------------------------------------
    # Internal project code — "s21" + digit/underscore + up to 6 alphanum
    # e.g. "s21_2441"  "s2114601"  "111s210"
    "project_code": rb"s21[\d_][A-Z0-9]{0,6}",
    # Calibration dataset filename — "cas21" + 3 digits + ".DAT"
    # e.g. "cas21146.DAT"
    "calibration_dataset": rb"cas21\d{3}\.DAT",
    # ------------------------------------------------------------------
    # Serial / production identification
    # ------------------------------------------------------------------
    # Serial code — "6577" + 6 digits
    # e.g. "6577295501"  "6577297701"
    "serial_code": rb"6577\d{6}",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real Siemens SIMOS binaries.
#
# Key findings:
#   - SIMOS binaries are overwhelmingly "dark" (no readable ASCII)
#   - When identifiers ARE present, they may appear anywhere in the binary
#   - The header region is used for magic-byte detection only
#   - All pattern searches use the full binary to maximise detection rate
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # First 4KB — header magic detection area
    "header": slice(0x0000, 0x1000),
    # First 64KB — ident area for structured data
    "ident_area": slice(0x0000, 0x10000),
    # Full binary — all patterns search here (SIMOS strings are sparse and
    # unpredictable in location)
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# All patterns search the full binary because SIMOS identifiers, when
# present, have no predictable fixed offset.
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "siemens_part": "full",
    "simos_label": "full",
    "oem_ident": "full",
    "oem_part_number": "full",
    "project_code": "full",
    "calibration_dataset": "full",
    "serial_code": "full",
    "ecu_family": "full",
}

# ---------------------------------------------------------------------------
# Header magic prefixes for detection
# ---------------------------------------------------------------------------
# Each SIMOS sub-type shares a common header prefix at offset 0, but the
# remaining bytes vary across vehicle models.  We match on the shortest
# prefix that is common to ALL known bins of that size class.
#
# 524 KB — all known bins start with \xf0\x30 (2-byte prefix)
#   \xf0\x30\xe8\x44 — VW Golf / Bora
#   \xf0\x30\x58\x74 — Seat Leon
#   \xf0\x30\xa0\x4c — Skoda Fabia
#   \xf0\x30\xc0\x6c — VW 1.6i / Beetle
#
# 262 KB — two distinct header families
#   \xc0\x64\xa8\x20 — VW Golf 4
#   \xfa\x00\x32\x04 — Skoda Octavia
#
# 131 KB — all known bins start with \x02 (1-byte prefix)
#   \x02\x58\x95\x05 — 27c010.bin variant A
#   \x02\x56\x9f\x05 — 27c010.bin variant B
# ---------------------------------------------------------------------------

SIMOS_524KB_HEADER: bytes = b"\xf0\x30"  # 2-byte prefix — common to ALL 524KB bins
SIMOS_262KB_HEADER: bytes = b"\xc0\x64"  # 2-byte prefix for 262KB type A
SIMOS_131KB_HEADER: bytes = b"\x02"  # 1-byte prefix for 131KB EEPROM

# Additional known header prefixes for 262KB bins
SIMOS_262KB_HEADERS: List[bytes] = [b"\xc0\x64", b"\xfa\x00"]  # Two known variants

# Map file size → primary header prefix for validation
HEADER_MAGIC_BY_SIZE: Dict[int, bytes] = {
    131072: SIMOS_131KB_HEADER,  # 131 KB — SIMOS EEPROM (1-byte prefix)
    262144: SIMOS_262KB_HEADER,  # 262 KB — SIMOS 2.x EEPROM (2-byte prefix)
    524288: SIMOS_524KB_HEADER,  # 524 KB — SIMOS 3.x full flash (2-byte prefix)
}

# Valid file sizes for SIMOS binaries
VALID_SIZES: set[int] = {131072, 262144, 524288}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by SIMOSExtractor.can_handle() to positively identify
# a binary as Siemens SIMOS. If ANY of these are found, the binary is SIMOS
# (assuming exclusions pass).
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: List[bytes] = [
    b"SIMOS",  # ECU family string — definitive
    b"5WP4",  # Siemens SIMOS part number prefix — definitive
    b"111s21",  # Project code with leading sequence number
    b"s21_",  # Project code with underscore separator
    b"cas21",  # Calibration dataset prefix
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# Byte sequences that indicate a binary belongs to a DIFFERENT manufacturer.
# If ANY of these are found, the binary is NOT SIMOS — even if it happens
# to match a size gate or header magic (e.g. a Bosch bin that is coincidentally
# 262KB).
#
# This list covers all known Bosch, Continental SID, and Delphi signatures
# that could cause false positives.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: List[bytes] = [
    b"EDC17",  # Bosch EDC17 diesel
    b"MEDC17",  # Bosch MEDC17 diesel
    b"MED17",  # Bosch MED17 petrol
    b"ME7.",  # Bosch ME7 petrol
    b"BOSCH",  # Generic Bosch marker
    b"0261",  # Bosch hardware number prefix (petrol)
    b"MOTRONIC",  # Bosch Motronic label
    b"PM3",  # Bosch PM3 label (Porsche)
    b"PPD",  # Bosch PPD pump-injector diesel
    b"5WS4",  # Continental SID part prefix
    b"5WK9",  # Continental part prefix
    b"SID80",  # Continental SID80x family
]

# ---------------------------------------------------------------------------
# ECU family resolution
# ---------------------------------------------------------------------------
# SIMOS family classification based on file size.
# Used when no explicit SIMOS label is found in the binary.
# ---------------------------------------------------------------------------

FAMILY_BY_SIZE: Dict[int, str] = {
    131072: "SIMOS",  # Generic — EEPROM, insufficient data to sub-classify
    262144: "SIMOS2",  # SIMOS 2.x EEPROM dumps
    524288: "SIMOS3",  # SIMOS 3.x full flash
}
