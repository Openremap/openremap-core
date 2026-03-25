"""
Bosch ECU binary identifier patterns and search regions.

All regex patterns and search region definitions specific to Bosch ECUs.
Covers: EDC17, MEDC17, MED17, ME17, EDC16, MED9, MD1

Pattern reference:

  HARDWARE NUMBER     "0 281 034 791"  or  "0281034791"
    Bosch part number for the ECU hardware unit.
    Format: 0 281 XXX XXX  (10 digits, sometimes space-separated)
    Unique per ECU hardware variant.

  SOFTWARE VERSION    "1037541778126241V0"  or  "SW:1037541778"
    Bosch internal software calibration identifier.
    The long numeric string (10+ digits) is unique per software revision.
    Two same-model cars with the same SW version share this string.
    THIS IS THE PRIMARY MATCHING KEY.

  ECU VARIANT         "EDC17C66"  "EDC17CP14"  "MEDC17.7"
    Specific hardware variant of the ECU controller.
    More precise than family — used as primary identifier in match_key.

  ECU FAMILY          "MEDC17"  "EDC17"  "MED17"  "ME17"  "MD1"
    Controller family — identifies the ECU generation.

  CALIBRATION VERSION "CV182500"
    Calibration version embedded in the authoritative variant string.
    Combined with ecu_variant gives exact tune baseline.

  DATASET NUMBER      "6229040100"
    Standalone 10-digit Bosch dataset reference number.

  SERIAL NUMBER       "20040524NR0000000227"
    ECU production date (YYYYMMDD) + serial number suffix.
    Unique per physical ECU unit — NOT used for matching.

  SW BASE VERSION     "SB_V18.00.02/1793"
    Operating system / base software version string.

  OEM PART NUMBER     "03L 906 018"  (VAG)   "A 651 900 00 00"  (Mercedes)
    Vehicle manufacturer part number stamped on the ECU.
    Format varies by OEM.
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# Naming convention:
#   "ecu_family_<name>"  — matches the ECU family string
#   "ecu_variant"        — matches the specific hardware variant
#   "ecu_variant_string" — matches the full authoritative variant descriptor
#   All other names      — specific field patterns
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Hardware identification
    # ------------------------------------------------------------------
    # Bosch hardware part number — "0281XXXXXX" with optional spaces/dots
    # e.g. "0 281 034 791"  "0281034791"
    "hardware_number": rb"0[\s\.]?281[\s\.]?\d{3}[\s\.]?\d{3}",
    # Alternative Bosch hardware reference format — e.g. "F01R00DE67"
    "bosch_hw_alt": rb"F[\s]?0[0-9][A-Z][\s]?[0-9]{2}[A-Z][\s]?[A-Z0-9]{3}",
    # HW label prefix — "HW:" or "HW " followed by part number
    "hw_label": rb"HW[\s:][\s]?[\w\s\.]{6,20}",
    # ------------------------------------------------------------------
    # Software / calibration identification
    # ------------------------------------------------------------------
    # Software version — Bosch internal numeric string (10+ chars)
    # e.g. "1037541778126241V0"  "10SW041803126266V1"
    # Format: 4 digits, optional letters, 6+ digits, optional suffix
    "software_version": rb"\d{4}[A-Z]{0,2}\d{6,}[A-Z0-9]{0,4}",
    # SW label prefix — "SW:" or "SW " followed by version digits
    "sw_label": rb"SW[\s:][\s]?\d{6,}",
    # SW base version — e.g. "SB_V18.00.02/1793"
    "sw_base_version": rb"SB_V\d+\.\d+\.\d+/\d+",
    # Calibration version embedded in variant string — e.g. "CV182500"
    "calibration_version": rb"CV\d{4,8}",
    # Calibration ID — standalone e.g. "8624 1V0"
    # Negative lookbehind/lookahead prevents matching substrings of SW version
    "calibration_id": rb"(?<!\d)\d{4,6}[\s][0-9][A-Z][0-9](?!\d)",
    # PSA calibration ID — embedded at offset 0x01 in PSA/Citroën EDC17 internal
    # flash dumps produced by PSA workshop tools (e.g. DiagBox, MPPS full-flash).
    # Format: "0800" + 2-digit year + 9 alphanumeric chars, total 15 chars.
    # Examples: "080017126333022"  "08001710227001C"  "08001505827522B"
    # The leading "0800" is a PSA-specific prefix — it never appears as a real
    # Bosch SW version (all genuine Bosch SW versions start with "1037").
    # Searched only in the first 16 bytes (header region) so it cannot
    # false-positive on any data elsewhere in the binary.
    "psa_calibration_id": rb"0800\d{2}[A-Z0-9]{9}",
    # Dataset number — standalone 10-digit numeric block
    # e.g. "6229040100"
    "dataset_number": rb"(?<![A-Z0-9])\d{10}(?![A-Z0-9\.])",
    # ------------------------------------------------------------------
    # ECU family and variant
    # ------------------------------------------------------------------
    # Specific EDC17 hardware variant — most precise identifier
    # e.g. "EDC17C66"  "EDC17CP14"  "EDC17U05"
    "ecu_variant": rb"EDC17[A-Z]{1,2}\d{1,3}",
    # Full authoritative variant descriptor string
    # e.g. "47/1/EDC17C66/1/P1262//P_1262_66V1__CV182500///"
    # This is the single most reliable source for ecu_variant + calibration_version
    "ecu_variant_string": rb"\d+/\d+/EDC17[A-Z0-9]+/[\w/\._\-]{10,}",
    # ECU family strings — ordered most specific to least specific
    # MEDC17 checked before EDC17 to avoid EDC17 matching inside MEDC17
    "ecu_family_medc17": rb"MEDC17(?:\d+(?:\.\d+)*)?",
    "ecu_family_edc17": rb"EDC17(?:[A-Z0-9]+(?:\.\d+)*)?",
    "ecu_family_med17": rb"MED17(?:\d+(?:\.\d+)*)?",
    "ecu_family_me17": rb"ME17(?:\d+(?:\.\d+)*)?",
    "ecu_family_md1": rb"MD1(?:[A-Z0-9]+(?:\.\d+)*)?",
    "ecu_family_edc16": rb"EDC16(?:[A-Z0-9]+(?:\.\d+)*)?",
    "ecu_family_med9": rb"MED9(?:\d+(?:\.\d+)*)?",
    # Customer/project label — e.g. "!Customer.MEDC17.V12"
    "customer_label": rb"[!]?Customer\.[\w\.]+",
    # ------------------------------------------------------------------
    # Serial / production identification
    # ------------------------------------------------------------------
    # ECU production serial — "YYYYMMDD" + "NR" + serial digits
    # e.g. "20040524NR0000000227"
    # Unique per physical ECU — NOT used for matching, only for display
    "serial_number": rb"\d{8}NR\d{7,13}",
    # ------------------------------------------------------------------
    # OEM (vehicle manufacturer) part numbers
    # ------------------------------------------------------------------
    # VAG (VW/Audi/Skoda/Seat) — e.g. "03L 906 018 AJ"  "03L906018"
    # Format: 0 + digit(2-9) + letter + 3 digits + 3 digits + optional suffix
    "vag_part_number": rb"(?<![A-Z0-9])0[2-9][A-Z][\s]?\d{3}[\s]?\d{3}(?:[\s]?[A-Z]{1,2})?(?![A-Z0-9])",
    # Mercedes-Benz — e.g. "A 651 900 00 00"
    # Must have spaces between all groups (strict format)
    "mercedes_part_number": rb"(?<![A-Z0-9])[A-Z][\s]\d{3}[\s]\d{3}[\s]\d{2}[\s]\d{2}(?![A-Z0-9])",
    # BMW — e.g. "12 14 7 626 350"
    "bmw_part_number": rb"(?<!\d)\d{2}[\s]\d{2}[\s]\d{1}[\s]\d{3}[\s]\d{3}(?!\d)",
}

# ---------------------------------------------------------------------------
# ECU family resolution order
# ---------------------------------------------------------------------------
# When multiple family patterns match, the first one in this list wins.
# Order matters — more specific families must come before broader ones.
# e.g. MEDC17 must come before EDC17 (EDC17 would also match inside "MEDC17")
# ---------------------------------------------------------------------------

FAMILY_RESOLUTION_ORDER = [
    "ecu_family_medc17",
    "ecu_family_edc17",
    "ecu_family_med17",
    "ecu_family_me17",
    "ecu_family_md1",
    "ecu_family_edc16",
    "ecu_family_med9",
]

# ---------------------------------------------------------------------------
# Canonical base family names
# ---------------------------------------------------------------------------
# Maps each family pattern key to the canonical base family name that should
# be stored in ecu_family. The full matched string (e.g. "MED9510",
# "MEDC17.7") goes to ecu_variant when it is longer than the base name.
#
# This separation ensures:
#   - ecu_family is always a stable, groupable name  ("MED9", "EDC17", …)
#   - ecu_variant carries the specific sub-version   ("MED9510", "MED91", …)
#   - scan --organize produces consistent folders     (Bosch/MED9/, …)
# ---------------------------------------------------------------------------

FAMILY_BASE_NAMES: dict[str, str] = {
    "ecu_family_medc17": "MEDC17",
    "ecu_family_edc17": "EDC17",
    "ecu_family_med17": "MED17",
    "ecu_family_me17": "ME17",
    "ecu_family_md1": "MD1",
    "ecu_family_edc16": "EDC16",
    "ecu_family_med9": "MED9",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real Bosch EDC17/MEDC17 binaries.
#
# Key findings:
#   - Software version and serial number live in the first 4KB header
#   - Dataset numbers and SW labels live in the first 64KB ident block
#   - ECU family strings and variant strings appear in the first 320KB
#   - Hardware numbers and OEM part numbers may appear anywhere
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # First 4KB — calibration dataset ID, serial number always here
    "header": slice(0x0000, 0x1000),
    # First 64KB — SW version, dataset number, customer label, SW/HW labels
    "ident_block": slice(0x0000, 0x10000),
    # First 320KB — ECU family strings, variant strings, calibration version
    "extended": slice(0x0000, 0x50000),
    # Full binary — hardware numbers, OEM part numbers (may appear anywhere)
    "full": slice(0x0000, None),
    # First 16 bytes — PSA calibration ID lives exclusively at offset 0x01-0x0F
    "psa_header": slice(0x0000, 0x0010),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# Defines which region each pattern is searched in.
# Narrower regions = faster search = lower latency on large files.
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    # Ident block (64KB)
    "serial_number": "ident_block",
    "dataset_number": "ident_block",
    "customer_label": "ident_block",
    "hw_label": "ident_block",
    # Full binary — SW version, label, family strings and variant strings may
    # all live past the 64KB / 320KB boundaries in large (2MB+) bins.
    # e.g. Audi Q5 03L906022NH: SW at ~0x18001a, family "EDC17_CP14" at 0x1a0a15
    # e.g. Audi A3 1.6FSI MED9: family "MED9510" at 0x1c21f5
    # Searching the full binary keeps family co-located with SW regardless of
    # flash layout. Performance impact is negligible — SW is already full-binary.
    "software_version": "full",
    "sw_label": "full",
    "ecu_variant": "full",
    "ecu_variant_string": "full",
    "ecu_family_medc17": "full",
    "ecu_family_edc17": "full",
    "ecu_family_med17": "full",
    "ecu_family_me17": "full",
    "ecu_family_md1": "full",
    "ecu_family_edc16": "full",
    "ecu_family_med9": "full",
    "calibration_version": "full",
    "sw_base_version": "full",
    "calibration_id": "full",
    "psa_calibration_id": "psa_header",
    # Full binary
    "hardware_number": "full",
    "bosch_hw_alt": "full",
    "vag_part_number": "full",
    "mercedes_part_number": "full",
    "bmw_part_number": "full",
}

# ---------------------------------------------------------------------------
# Known MCU hardware constants — never a software version
# ---------------------------------------------------------------------------
# These numeric strings are microcontroller chip identifiers baked into the
# OS/bootloader code. They appear as ASCII in every binary that uses that MCU,
# regardless of the calibration — picking them as software_version would give
# every file on the same MCU platform an identical match_key.
#
#   1037555072  — Infineon TC1793 MCU part number.
#                 Present at 0x0000401a in every PSA/Citroën EDC17 full
#                 internal flash dump. Identical across all calibrations.
#
# Add future MCU constants here as they are discovered.
# ---------------------------------------------------------------------------

MCU_CONSTANTS: set[str] = {
    "1037555072",  # Infineon TC1793 — PSA/Citroën EDC17 internal flash
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by BoschExtractor.can_handle() to quickly detect
# whether a binary belongs to Bosch.
# At least ONE of these must be present in the first 512KB of the binary.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"MEDC17",
    b"EDC17",
    b"MED17",
    b"MED9",
    b"MD1",
    b"ME17",
    b"Bosch",
    b"BOSCH",
    b"SB_V",  # SW base version prefix — Bosch exclusive
    b"NR000",  # Serial number prefix — Bosch exclusive
    b"Customer.",  # Customer label prefix — Bosch exclusive
    # NOTE: b"EDC16" intentionally removed — EDC16 bins are fully owned by
    # BoschEDC16Extractor which runs earlier in the registry. Including it
    # here caused every EDC16 bin to be double-claimed (contested).
]
