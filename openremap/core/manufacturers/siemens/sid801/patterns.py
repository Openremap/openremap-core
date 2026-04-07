"""
Siemens SID 801 / SID 801A ECU binary identifier patterns and search regions.

All regex patterns and search region definitions specific to Siemens SID 801
diesel ECU binaries.  Covers: SID801, SID801A

Pattern reference:

  HARDWARE NUMBER     "5WS40145A-T"  or  "5WS40036D-T"
    Siemens part number for the ECU hardware unit.
    Format: 5WS4 + 4–5 digits + optional letter suffix + "-T"
    The "5WS4" prefix is exclusive to Siemens diesel ECUs.
    Unique per ECU hardware variant.

  IDENT RECORD        "5WS40145A-T 244177913   04020028014941S220040001C0"
    Full identification record combining hardware number, 9-digit serial,
    date/serial block, and S-record version suffix.
    Located in the first 4 KB of the binary (header area).
    THIS IS THE PRIMARY SOURCE for both hardware_number and software_version.

  SOFTWARE VERSION    "244177913"  or  "234082572"
    9-digit serial number embedded immediately after the hardware number
    in the ident record.  Unique per software calibration revision.
    THIS IS THE PRIMARY MATCHING KEY.

  PROJECT CODE        "PM38101C00"  or  "PM33001C00"
    Siemens internal project/calibration code.
    Format: PM3 + 4–5 digits + optional alphanumeric suffix.
    Appears throughout the first 128 KB of the binary.

  CALIBRATION DATASET "CAPM3630.DAT"  or  "CAPM3930.DAT"
    Siemens calibration dataset file reference.
    Format: CAPM3 + 3–4 digits + ".DAT"
    Used as a secondary calibration identifier.

  S-RECORD REFERENCE  "S118430100"  or  "S120040001"  or  "S220040001C0"
    S-record version references embedded in the ident area.
    S118/S120 prefixes identify the software/calibration lineage.
    S220 prefixes identify the data version.

  PSA PART NUMBER     "9648608680"  or  "9653447180"
    PSA (Peugeot/Citroën) OEM part number.
    Format: 96 + 8 digits (10 digits total).
    Present when the ECU was supplied to PSA group vehicles.

  ECU FAMILY          "SID801"  or  "SID801A"
    Controller family identifier.
    SID801 = first generation, SID801A = revised variant.

  PM BLOCK REFERENCE  "111PM32xxxxx"
    Repeated calibration block markers referencing PM3 project codes.
    Appear in calibration data regions.
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# Naming convention:
#   "hardware_number"      — Siemens 5WS4 ECU part number
#   "ident_record"         — full identification record line
#   "software_version"     — 9-digit serial (extracted from ident_record)
#   "project_code"         — PM3 project/calibration code
#   "calibration_dataset"  — CAPM calibration dataset filename
#   "s_record_ref"         — S-record version reference
#   "psa_part_number"      — PSA OEM part number
#   "ecu_family"           — SID801 / SID801A family string
#   "pm_block_ref"         — 111PM3 calibration block marker
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Hardware identification
    # ------------------------------------------------------------------
    # Siemens hardware part number — "5WS4xxxxX-T"
    # e.g. "5WS40145A-T"  "5WS40045B-T"  "5WS40036D-T"  "5WS40155C-T"
    "hardware_number": rb"5WS4\d{4,5}[A-Z]?-T",
    # Full ident record — hardware number + 9-digit serial + date/version block
    # e.g. "5WS40145A-T 244177913   04020028014941S220040001C0"
    # The ident record is the single most reliable source for both the
    # hardware number and the software version (9-digit serial).
    # Note: the date/version block format is:
    #   17 digits + "S2" + 11 alphanumeric chars
    #   e.g. "04020028014941" (14 digits) ... varies slightly per variant.
    # We use a relaxed tail pattern to accommodate format variations.
    "ident_record": rb"5WS4\d{4,5}[A-Z]?-T\s+\d{9}\s+[\d]{11,17}S2[\dA-Z]{10,14}",
    # ------------------------------------------------------------------
    # Software / calibration identification
    # ------------------------------------------------------------------
    # Software version — 9-digit serial extracted as a standalone pattern.
    # Variable-length lookbehinds are not supported in Python's re module,
    # so we cannot use a lookbehind for the 5WS4 prefix here.  Instead,
    # the extractor resolves this field by parsing the ident_record match.
    # This standalone pattern serves as a fallback when no ident_record is
    # found — it matches any isolated 9-digit numeric block in the header.
    "software_version": rb"(?<!\d)\d{9}(?!\d)",
    # Project code — PM3 calibration/project reference
    # e.g. "PM38101C00"  "PM33001C00"  "PM363000"  "PM393000"
    "project_code": rb"PM3\d{4,5}[A-Z0-9]{0,3}",
    # Calibration dataset filename — CAPM reference
    # e.g. "CAPM3630.DAT"  "CAPM3930.DAT"
    "calibration_dataset": rb"CAPM3\d{3,4}\.DAT",
    # S-record version reference — S118, S120, S220 prefixes
    # e.g. "S118430100"  "S120040001"  "S220040001C0"
    "s_record_ref": rb"S[12][12]\d{7,10}[A-Z0-9]{0,2}",
    # PM block reference — "111PM3" calibration block markers
    # e.g. "111PM3210050"  "111PM3280000"
    "pm_block_ref": rb"111PM3\d{4,6}",
    # ------------------------------------------------------------------
    # OEM (vehicle manufacturer) part numbers
    # ------------------------------------------------------------------
    # PSA (Peugeot/Citroën) part number — "96XXXXXXXX"
    # e.g. "9648608680"  "9653447180"
    "psa_part_number": rb"(?<!\d)96\d{8}(?!\d)",
    # ------------------------------------------------------------------
    # ECU family
    # ------------------------------------------------------------------
    # SID801 / SID801A family string
    # SID803 is explicitly excluded via EXCLUSION_SIGNATURES (separate
    # extractor). The pattern matches SID801 and SID801A only.
    "ecu_family": rb"SID801A?",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real Siemens SID 801 / SID 801A binaries.
# All known files are exactly 512 KB (524288 bytes).
#
# Key findings:
#   - The ident record (5WS4xxxxX-T + serial) lives in the first 4 KB
#   - PM3 project codes appear throughout the first 128 KB
#   - S-record references appear in the first 64 KB
#   - PSA part numbers and ECU family strings may appear anywhere
#   - Calibration dataset references (CAPM) may appear anywhere
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # First 4 KB — ident record, hardware number, software version
    "header": slice(0x0000, 0x1000),
    # First 64 KB — S-record references, software version fallback
    "ident_area": slice(0x0000, 0x10000),
    # First 128 KB — PM3 project codes, PM block references
    "extended": slice(0x0000, 0x20000),
    # Full binary — PSA part numbers, ECU family, calibration dataset
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# Defines which region each pattern is searched in.
# Narrower regions = faster search = lower false-positive rate.
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    # Ident area (64 KB) — primary ident fields
    # Real SID801 bins place 5WS4 part numbers and ident records at ~0x3f80,
    # well beyond the 4 KB header region.
    "hardware_number": "ident_area",
    "ident_record": "ident_area",
    "software_version": "ident_area",
    # Extended (128 KB) — project codes and block references
    "project_code": "extended",
    "pm_block_ref": "extended",
    # Ident area (64 KB) — S-record references
    "s_record_ref": "ident_area",
    # Full binary — fields that may appear anywhere
    "calibration_dataset": "full",
    "psa_part_number": "full",
    "ecu_family": "full",
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by SiemensSID801Extractor.can_handle() to quickly
# detect whether a binary belongs to a Siemens SID 801 / SID 801A ECU.
#
# At least ONE of these must be present in the binary for positive detection.
# The size gate (exactly 524288 bytes) is checked first as a fast pre-filter.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"5WS4",  # Siemens hardware part number prefix — most reliable
    b"PM3",  # Siemens project code prefix — secondary confirmation
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# Byte sequences that indicate the binary belongs to a DIFFERENT ECU family.
# If ANY of these is found in the binary, can_handle() returns False even if
# detection signatures are present.
#
# This prevents false positives when:
#   - A Bosch binary happens to contain a "5WS4" or "PM3" byte sequence
#     in calibration data regions
#   - A SID803/SID803A binary (different Siemens family, different extractor)
#     shares some structural similarities with SID801
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",  # Bosch EDC17 family
    b"MEDC17",  # Bosch MEDC17 family
    b"MED17",  # Bosch MED17 family
    b"ME7.",  # Bosch ME7.x family
    b"SID803",  # Siemens SID803/SID803A — separate extractor
]

# ---------------------------------------------------------------------------
# File size constant
# ---------------------------------------------------------------------------
# All known SID 801 / SID 801A binaries are exactly 512 KB.
# This is used as a fast pre-filter in can_handle().
# ---------------------------------------------------------------------------

SID801_FILE_SIZE: int = 524288  # 512 KB = 0x80000

# ---------------------------------------------------------------------------
# Header magic bytes
# ---------------------------------------------------------------------------
# First 4 bytes of real SID801 binaries fall into two known types.
# Used as a fallback in can_handle() for "dark" bins that contain no
# embedded 5WS4 or PM3 signatures (the part number is only in the filename).
# ---------------------------------------------------------------------------

SID801_HEADER_TYPE_A: bytes = b"\xc0\xf0\xa0\x14"  # Dark bins (no embedded ident)
SID801_HEADER_TYPE_B: bytes = b"\xfa\x00\x46\x04"  # Bins with embedded 5WS4 ident
SID801_HEADERS: list[bytes] = [SID801_HEADER_TYPE_A, SID801_HEADER_TYPE_B]
