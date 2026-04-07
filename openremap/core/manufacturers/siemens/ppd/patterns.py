"""
Siemens PPD ECU binary identifier patterns and search regions.

All regex patterns and search region definitions specific to Siemens PPD ECUs.
Covers: PPD1.1, PPD1.2, PPD1.5

Pattern reference:

  SERIAL CODE         "6576286135"
    10-digit serial-like code found at the start of the ident record.
    Format: 6576 + 6 digits.
    Present in all known PPD binaries.

  SN PROJECT CODE     "SN100K5400000" or "SN000F7500000"
    Repeated project code blocks prefixed with "111SN" in the ident area.
    Format: SN + digit + 2-3 alphanumeric chars + 4-8 digits.
    Typically repeated three times in succession.

  CALIBRATION DATASET "CASN1K54.DAT" or "CASN0F75.DAT"
    Calibration dataset filename reference.
    Format: CASN + digit + 3-4 alphanumeric chars + ".DAT"

  OEM PART NUMBER     "03G906018DT" or "03G906018CD" or "03G906018"
    VAG (VW/Audi/Skoda/Seat) OEM part number specific to PPD diesel ECUs.
    Format: 03G906 + 3 digits + optional 1-2 letter suffix.

  OEM PART FULL       "03G906018DT R4 2.0l PPD1.2"
    Full authoritative ident string combining OEM part number, engine
    displacement, and PPD family identifier.

  ECU FAMILY          "PPD1.1" or "PPD1.2" or "PPD1.5"
    Siemens PPD family identifier — the definitive signature for detection.
    Format: PPD1. + single digit.

  HW/SW VERSION       "0431657628.90.02"
    Dot-delimited version string found in some PPD binaries.
    Format: 4 digits + 657628 + "." + 2 digits + "." + 2 digits.

  DISPLACEMENT        "R4 2.0l"
    Engine displacement string — inline-4 diesel.
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
    # ECU family identification — definitive PPD signature
    # ------------------------------------------------------------------
    # PPD family string — e.g. "PPD1.1"  "PPD1.2"  "PPD1.5"
    "ecu_family": rb"PPD1\.\d",
    # ------------------------------------------------------------------
    # Serial / ident codes
    # ------------------------------------------------------------------
    # 10-digit serial code at the start of the ident record
    # e.g. "6576286135"  "6576286149"  "6576286349"
    "serial_code": rb"6576\d{6}",
    # SN project code — repeated blocks in the ident area
    # e.g. "SN100K5400000"  "SN000F7500000"  "SN000F7600000"
    "sn_project_code": rb"SN[01]\d{2}[A-Z0-9]\d{4,8}",
    # ------------------------------------------------------------------
    # Calibration identification
    # ------------------------------------------------------------------
    # Calibration dataset filename reference
    # e.g. "CASN1K54.DAT"  "CASN0F75.DAT"  "CASN0F76.DAT"
    "calibration_dataset": rb"CASN\d[A-Z0-9]{3,4}\.DAT",
    # ------------------------------------------------------------------
    # OEM part numbers
    # ------------------------------------------------------------------
    # VAG OEM part number — specific to PPD diesel ECUs
    # e.g. "03G906018DT"  "03G906018CD"  "03G906018"
    "oem_part_number": rb"03G906\d{3}[A-Z]{0,2}",
    # Full authoritative ident string — OEM part + displacement + family
    # e.g. "03G906018DT R4 2.0l PPD1.2"
    "oem_part_full": rb"03G906\d{3}[A-Z]{0,2}T?\s+R4\s+\d\.\dl\s+PPD1\.\d",
    # ------------------------------------------------------------------
    # Version strings
    # ------------------------------------------------------------------
    # HW/SW version — dot-delimited version string
    # e.g. "0431657628.90.02"
    "hw_sw_version": rb"\d{4}657628\.\d{2}\.\d{2}",
    # ------------------------------------------------------------------
    # Engine displacement
    # ------------------------------------------------------------------
    # e.g. "R4 2.0l"
    "displacement": rb"R4\s+\d\.\dl",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real Siemens PPD1.x binaries.
# File sizes observed: 249856 (250 KB), 2097152 (2 MB), 2097154 (2 MB + 2).
#
# Key findings:
#   - The ident record (serial code, SN blocks, calibration dataset, OEM
#     part number, family string) lives within the first 320 KB.
#     In 250 KB bins the ident is near offset 0x0000; in 2 MB bins it
#     sits at offset 0x040000 (256 KB from start).
#   - The PPD1.x family string may appear anywhere in the binary —
#     searched across the full file for reliable detection.
#   - Header region (first 4 KB) used for raw ASCII string extraction.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # First 4 KB — raw ASCII strings for display
    "header": slice(0x0000, 0x1000),
    # First 320 KB — covers ident block at 0x40000 in 2MB files
    "ident_area": slice(0x0000, 0x50000),
    # Full binary — family string detection, fallback searches
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# Defines which region each pattern is searched in.
# Narrower regions = faster search = lower false-positive rate.
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    # Full binary — family string can appear anywhere
    "ecu_family": "full",
    # Ident area (320 KB) — all structured ident fields
    "serial_code": "ident_area",
    "sn_project_code": "ident_area",
    "calibration_dataset": "ident_area",
    "oem_part_number": "ident_area",
    "oem_part_full": "ident_area",
    "hw_sw_version": "ident_area",
    "displacement": "ident_area",
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by SiemensPPDExtractor.can_handle() to quickly detect
# whether a binary belongs to the Siemens PPD family.
# At least ONE of these must be present in the binary.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"PPD1.",  # Definitive PPD family identifier
    b"111SN",  # Repeated SN project code blocks
    b"CASN",  # Calibration dataset prefix
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# Byte sequences that indicate the binary belongs to a different manufacturer
# or ECU family. If ANY of these is found, the binary is rejected.
# Prevents false positives against Bosch ECU families that may share
# superficially similar numeric patterns.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",  # Bosch EDC17 family
    b"MEDC17",  # Bosch MEDC17 family
    b"MED17",  # Bosch MED17 family
    b"ME7.",  # Bosch ME7 family
    b"BOSCH",  # Generic Bosch manufacturer label
    b"PM3",  # Marelli PM3 family
]
