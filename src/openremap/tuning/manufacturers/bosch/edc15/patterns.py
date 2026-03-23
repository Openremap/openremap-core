"""
Bosch EDC15 ECU binary identifier patterns and search regions.

Covers the Bosch EDC15 family:
  EDC15C2   — early diesel common-rail, Alfa Romeo / Fiat / Lancia (1997–2001)
  EDC15C5   — mid-generation, VW/Audi/Seat/Skoda 1.9 TDI (1999–2004)
  EDC15C7   — VAG and PSA diesel common-rail (2000–2004)
  EDC15M    — Bosch EDC15 for petrol DI (rare)
  EDC15VM+  — variant used in some Renault / PSA applications

EDC15 predates EDC16 and EDC17 by a significant generation:
  - CPU: Motorola MPC555 or Infineon C167 (depending on variant)
  - No SB_V, Customer., NR000, or any EDC16/EDC17 strings
  - Fill byte: 0xC3 (characteristic — used as ROM blank/erased marker)
  - Two sub-formats are observed in the wild:

  FORMAT A — newer EDC15 (e.g. EDC15C5, EDC15C7):
    TSW string at 0x8000: 'TSW Vx.xx DDMMYY NNNN Cx/ESB/G40'
      TSW = Tool Software (Bosch internal bootstrap descriptor)
      This string is unique to EDC15 and is the primary detection anchor.
    HW number: plain ASCII '0281xxxxxx' surrounded by 0xC3 fill (~0x07Cxxx)
    SW version: plain ASCII '1037xxxxxx' surrounded by 0xC3 fill (~0x07Bxxx–0x07Fxxx)
    Multiple SW copies exist — the first occurrence in the last 256KB is
    authoritative (lowest offset, surrounded by 0xC3, not inside code).

  FORMAT B — older EDC15 (e.g. EDC15C2, some Alfa/Fiat bins):
    No TSW string.
    Ident block: ASCII string at ~0x050000–0x050040 of the form:
        'CC' + misc_bytes + '1037xxxxxx'
    SW is embedded as a plain '1037xxxxxx' substring in this block.
    HW number is NOT stored as plain ASCII in these bins — only SW is
    reliably extractable.
    Detection fallback: 0xC3 fill > 5% of file AND 1037\\d{6,10} present
    AND none of the modern Bosch exclusion signatures present.

Pattern reference:

  HARDWARE NUMBER     '0281010332'
    Bosch ECU hardware part number.
    Format: 0281 + 6 digits (10 digits total).
    Present as plain ASCII only in Format A bins.
    Preceded and followed by 0xC3 fill bytes in the data region.

  SOFTWARE VERSION    '1037366536'  '1037353311'
    Bosch internal software calibration identifier.
    Format: 1037 + 6–10 digits (10 digits total in all observed EDC15 bins).
    Present as plain ASCII in both formats.
    The primary matching key — unique per SW revision.
    Multiple copies may exist; the authoritative one is the first occurrence
    in the last 256KB of the file that is surrounded by 0xC3 or 0xFF fill.

  TSW STRING          'TSW V2.40 280700 1718 C7/ESB/G40'
    Bosch Tool Software version string.
    Unique to EDC15 — not present in any other Bosch family.
    Contains the ECU variant code after the last slash (e.g. 'G40').
    Used as primary detection anchor in Format A bins.

  ECU FAMILY          'EDC15'
    No explicit ECU family string is embedded in EDC15 binaries.
    The family is inferred from the detection pattern (TSW or fill+SW).
    Always returned as the fixed string 'EDC15'.
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Hardware identification
    # ------------------------------------------------------------------
    # Bosch ECU hardware part number — '0281' + 6 digits (10 total)
    # Present as plain ASCII in Format A bins only.
    # e.g. '0281010332'  '0281010360'  '0281001234'
    "hardware_number": rb"0281\d{6}",
    # ------------------------------------------------------------------
    # Software / calibration identification
    # ------------------------------------------------------------------
    # SW version — '1037' + 6–10 digits.
    # Present as plain ASCII in both Format A and Format B bins.
    # e.g. '1037366536'  '1037353311'  '1037351190'
    "software_version": rb"1037\d{6,10}",
    # ------------------------------------------------------------------
    # TSW string — Format A detection and variant info
    # ------------------------------------------------------------------
    # Full TSW descriptor string.
    # e.g. 'TSW V2.40 280700 1718 C7/ESB/G40'
    #       TSW Vx.xx = tool version
    #       DDMMYY    = build date
    #       NNNN      = build number
    #       Cx        = ECU hardware variant code
    #       ESB       = Bosch internal project code
    #       G40       = calibration dataset code
    "tsw_string": rb"TSW V\d+\.\d+[\s\x00]+\d{6}[\s\x00]+\d{3,4}[\s\x00]+[\w/]+",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real EDC15 binaries (3 samples, all 512KB = 0x80000).
#
# Key findings:
#   - TSW string is always at exactly 0x8000 in Format A bins.
#   - SW version (1037xxxxxx) appears multiple times; the authoritative
#     occurrence in Format A is in the range 0x60000–0x80000, surrounded
#     by 0xC3 fill. In Format B it appears around 0x50000.
#   - HW number (0281xxxxxx) appears once in the range 0x78000–0x80000.
#   - Searching the full file for SW is safe because deduplication picks
#     the first hit — which is always in the data region, not code.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # Fixed TSW location — only valid at exactly 0x8000
    "tsw_block": slice(0x8000, 0x8060),
    # Last 256KB — HW and SW data region in Format A bins
    "data_region": slice(0x40000, None),
    # Full binary — used for SW in Format B bins where the offset varies
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "tsw_string": "tsw_block",
    "hardware_number": "data_region",
    "software_version": "full",
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Used by BoschEDC15Extractor.can_handle() — FORMAT A primary anchor.
#
# 'TSW ' is unique to the Bosch EDC15 toolchain and has not been observed
# in any other ECU binary family.  It is the single most reliable positive
# detection marker for Format A EDC15 bins.
#
# Format B bins (no TSW) are detected by a secondary heuristic inside
# can_handle() — see BoschEDC15Extractor for details.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"TSW ",  # EDC15 Tool Software string — Format A anchor
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these are found in the first 512KB the binary is NOT EDC15.
# Prevents this extractor from claiming modern Bosch bins that share the
# 1037xxxxxx SW prefix (ME7, EDC16, EDC17 all use the same SW prefix).
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"SB_V",  # Modern Bosch SW base version — absent on EDC15
    b"Customer.",  # Modern Bosch customer label — absent on EDC15
    b"ME7.",  # ME7 family — different generation
    b"ME71",  # ME71 — different generation
    b"MOTRONIC",  # ME7 uses MOTRONIC label — EDC15 does not
    b"1350000M3",  # M3.1 family marker
    b"1530000M3",  # M3.3 family marker
]

# ---------------------------------------------------------------------------
# Format B detection constants
# ---------------------------------------------------------------------------
# Format B bins (older EDC15, e.g. Alfa 145 EDC15C2) have no TSW string.
# They are identified by two conditions checked together in can_handle():
#   1. 0xC3 fill byte represents at least EDC15_MIN_C3_RATIO of the file
#   2. At least one '1037xxxxxx' SW version string is present anywhere
#
# The C3 ratio threshold is set conservatively at 5% — all three observed
# EDC15 samples exceed this (10–35%), while modern Bosch bins (EDC17,
# MEDC17) are well below 0.2%.
# ---------------------------------------------------------------------------

EDC15_MIN_C3_RATIO: float = 0.05  # minimum fraction of 0xC3 bytes in the file
