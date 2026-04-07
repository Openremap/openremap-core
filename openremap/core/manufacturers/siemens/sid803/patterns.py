"""
Siemens SID803 / SID803A ECU binary identifier patterns and search regions.

All regex patterns and search region definitions specific to the Siemens
SID803 and SID803A diesel ECU families.

Pattern reference:

  HARDWARE NUMBER     "5WS40262B-T"  or  "5WS40612B-T"
    Siemens/Continental part number for the ECU hardware unit.
    Format: 5WS4 + 4–5 digits + optional letter suffix + "-T"
    Present in SID803A (2 MB) files embedded in the header region.
    Absent from some smaller SID803 (458–462 KB) files.

  IDENT RECORD        "5WS40262B-T  00012345678901234"
    Hardware number followed by whitespace and a 14–17 digit serial /
    production identifier.  Located in the first 4 KB of 2 MB files.

  PROJECT CODE        "PO220"  "PO320"  "PO011"
    Siemens internal project reference codes.  PO + 3–5 decimal digits.
    Present in both SID803 and SID803A files.  The PO-prefix is the key
    differentiator from SID801 which uses PM3-prefixed project codes.

  PO BLOCK            "111PO220"  "111PO320"
    Repeated calibration / data block markers.  111 + PO + 3 digits.
    Present in both sub-groups across the full binary.

  S-RECORD REF        "S1200790100E0"  "S122001234AB"
    Siemens S-record references.  S12[02] + 6–9 digits + optional suffix.
    SID803 uses S120-series; SID803A uses S122-series (higher than SID801's
    S118/S120 range, which is the distinguishing marker).

  CALIBRATION DATASET "CAPO0001"  "CAPO1234"
    Calibration area project overlay identifiers.  CAPO + 4 decimal digits.
    Predominantly found in SID803A (2 MB) files.

  FOIX REFERENCE      "FOIXS160001225B0"
    Factory / OEM identification cross-reference.
    FOIX + S + 10–14 digits + optional alphanumeric suffix.
    Found in the ident area of SID803A files.

  ECU FAMILY          "SID803"  "SID803A"
    Explicit family string — may appear in the binary or the filename.
    Not always present in the raw binary data; the detection logic does
    not rely solely on this string.
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# Naming convention mirrors the Bosch extractor family — each key maps
# directly to an extraction field or detection signal.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Hardware identification
    # ------------------------------------------------------------------
    # Siemens/Continental hardware part number — "5WS4XXXX[X][L]-T"
    # e.g. "5WS40262B-T"  "5WS40612B-T"
    # Format: 5WS4 + 4–5 decimal digits + optional single letter + "-T"
    # Present in SID803A 2 MB files in the header region (0x0000–0x1000).
    "hardware_number": rb"5WS4\d{4,5}[A-Z]?-T",
    # Full ident record — hardware number + whitespace + serial digits.
    # e.g. "5WS40262B-T  00012345678901234"
    # The serial portion is 14–17 decimal digits and serves as the
    # production / software build identifier.
    "ident_record": rb"5WS4\d{4,5}[A-Z]?-T\s+\d{14,17}",
    # ------------------------------------------------------------------
    # Project / calibration identification
    # ------------------------------------------------------------------
    # Project code — PO + 3–5 decimal digits.
    # e.g. "PO011"  "PO220"  "PO320"
    # This is the PRIMARY differentiator from SID801 (which uses PM3).
    "project_code": rb"PO\d{3,5}",
    # PO block marker — 111 + PO + 3 digits.
    # e.g. "111PO220"  "111PO320"  "111PO011"
    # Repeated calibration / data block boundaries found across the
    # full binary in both SID803 and SID803A files.
    "po_block": rb"111PO\d{3}",
    # S-record reference — S12[02] + 6–9 digits + optional suffix.
    # e.g. "S1200790100E0"  "S122001234AB"
    # SID803 → S120 series;  SID803A → S122 series.
    # Higher series numbers than SID801's S118/S120 range.
    "s_record_ref": rb"S12[02]\d{6,9}[A-Z0-9]{0,2}",
    # Calibration dataset — CAPO + 4 decimal digits.
    # e.g. "CAPO0001"  "CAPO1234"
    # Calibration area project overlay markers, predominantly SID803A.
    "calibration_dataset": rb"CAPO\d{4}",
    # FOIX reference — factory / OEM identification cross-reference.
    # e.g. "FOIXS160001225B0"
    # Format: FOIX + S + 10–14 digits + optional alphanumeric suffix.
    "foix_ref": rb"FOIXS\d{10,14}[A-Z0-9]{0,4}",
    # ------------------------------------------------------------------
    # ECU family string
    # ------------------------------------------------------------------
    # Explicit SID803 or SID803A family token in the binary.
    # Not always present — detection does not rely solely on this.
    "ecu_family": rb"SID803A?",
}


# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real SID803 and SID803A binaries across three
# confirmed file sizes: 458752, 462848, and 2097152 bytes.
#
# Key findings:
#   - 5WS4 hardware ident records live at ~0x6300 in 2 MB (SID803A)
#     files — inside the first 64 KB but well beyond the 4 KB header.
#   - Project codes (PO), PO blocks (111PO), and S-record references
#     appear throughout the binary.  In smaller SID803 files (458–462 KB)
#     the S-record and PO blocks cluster around 0x040000 (~256 KB),
#     far beyond the ident area.
#   - FOIX references are concentrated in the ident area (first 64 KB).
#   - CAPO calibration datasets and the ecu_family string may appear
#     anywhere in the binary.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # First 4 KB — 5WS4 ident record in 2 MB (SID803A) files.
    "header": slice(0x0000, 0x1000),
    # First 64 KB — project codes, S-record refs, FOIX references.
    "ident_area": slice(0x0000, 0x10000),
    # First 128 KB — extended search area for smaller files.
    "extended": slice(0x0000, 0x20000),
    # Full binary — PO blocks, calibration datasets, family strings.
    "full": slice(0x0000, None),
}


# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# Defines which region each pattern is searched in.
# Narrower regions = faster search = lower false-positive rate.
#
# Rationale:
#   - hardware_number / ident_record: at ~0x6300 in 2 MB SID803A files,
#     within ident_area (64 KB) but beyond the 4 KB header.
#   - s_record_ref: in SID803A (2 MB) files clusters in ident_area
#     (~0x6000) but in smaller SID803 files (458–462 KB) appears at
#     ~0x040000 — must search full binary.
#   - foix_ref: clusters in ident area (first 64 KB).
#   - project_code / po_block / calibration_dataset / ecu_family:
#     may appear anywhere — search full binary.
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "hardware_number": "ident_area",
    "ident_record": "ident_area",
    "project_code": "full",
    "po_block": "full",
    "s_record_ref": "full",
    "calibration_dataset": "full",
    "foix_ref": "ident_area",
    "ecu_family": "full",
}


# ---------------------------------------------------------------------------
# Valid file sizes
# ---------------------------------------------------------------------------
# SID803 and SID803A binaries come in exactly three known sizes.
# This set is used as the first gate in can_handle() — any file whose
# length is not in this set is immediately rejected.
#
#   458752  (448 KB)  — SID803 smaller variant
#   462848  (452 KB)  — SID803 larger variant (4 KB padding difference)
#   2097152 (2 MB)    — SID803A full flash dump
# ---------------------------------------------------------------------------

VALID_FILE_SIZES: set[int] = {
    458752,  # 0x70000  — SID803 (448 KB)
    462848,  # 0x71000  — SID803 (452 KB)
    2097152,  # 0x200000 — SID803A (2 MB)
}

# SID803A is identified by the 2 MB file size.
SID803A_FILE_SIZE: int = 2097152


# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by SiemensSID803Extractor.can_handle() to quickly
# detect whether a binary belongs to the SID803/SID803A family.
#
# After the size gate passes, at least ONE of these must be present in the
# binary for a positive detection.  The signatures are ordered from most
# specific (lowest false-positive rate) to most general.
#
#   b"111PO"   — PO block marker, highly specific to SID803 family.
#   b"PO2"     — PO2xx project code prefix (PO220, PO220, …).
#   b"PO3"     — PO3xx project code prefix (PO320, PO320, …).
#   b"S122"    — S122-series S-record reference (SID803A specific).
#   b"SID803"  — Explicit family string (not always present).
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"111PO",
    b"PO2",
    b"PO3",
    b"S122",
    b"SID803",
]


# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# Byte sequences that, if present, indicate the binary belongs to a
# different ECU family and must NOT be claimed by SID803.
#
# These are checked BEFORE detection signatures — first exclusion hit
# causes immediate rejection.
#
#   b"EDC17"   — Bosch EDC17 family string.
#   b"MEDC17"  — Bosch MEDC17 family string.
#   b"MED17"   — Bosch MED17 family string.
#   b"ME7."    — Bosch ME7.x family string.
#   b"PM3"     — SID801 project code prefix.  PM3 is the strongest
#                negative signal: if PM3 is present the binary is
#                SID801, never SID803.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME7.",
    b"PM3",
]
