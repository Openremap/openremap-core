"""
Bosch Motronic MP 9.0 ECU binary identifier patterns and search regions.

Covers the Bosch Motronic MP 9.0 family:
  MP9.0   — Bosch Motronic MP 9.0
             VW/Seat/Skoda 1.0–1.6L petrol engines (1996–2002)
             e.g. Seat Ibiza 1.4, VW Polo 1.4, Skoda Felicia 1.3
             64KB (0x10000) dumps

These are Motorola 68HC11-based ECUs — the Motronic MP 9.0 generation sits
between the earlier M1.x/M2.x and the later ME7 families.

Binary structure:

  64KB (0x10000 bytes) — e.g. Seat Ibiza 6K0906027E:
    Code area       : 0x0000 – 0xFBFF (executable + calibration data)
    Ident block     : ~0xFC3C (near end of binary, last 1 KB)
    Slash block     : ~0xFCBF (slash-delimited metadata string)
    ASCII table     : ~0xFEE8 (printable char lookup, always last)

Ident block format (at ~0xFC3C):

    [HW] [SW] MP9 000[OEM_PART]  MOTRONIC MP 9.0    S0xx

  Fields:
    [HW]        : "0261xxxxxx" — 10 digits, Bosch hardware part number
    [SW]        : "1037xxxxxx" — 10 digits, Bosch software version
    [OEM_PART]  : e.g. "6K0906027E" — VW/Seat/Skoda OEM ECU part number
    "MP9"       : family shorthand embedded between SW and OEM part
    "MOTRONIC MP 9.0" : full family label
    "S0xx"      : software release suffix (e.g. "S023")

Slash-delimited metadata block (at ~0xFCBF):

    xx/n/MP9.0/yy/zzzz.zz/DAMOSxx/xxxx-S/xxxxxx-S/ddmmyy/

  Fields:
    [1] : counter/revision (e.g. "53")
    [2] : variant index (e.g. "1")
    [3] : family (e.g. "MP9.0")
    [4] : sub-revision (e.g. "51")
    [5] : DAMOS version (e.g. "4007.01")
    [6] : DAMOS label (e.g. "DAMOS94")
    [7] : project code (e.g. "1832-S")
    [8] : project sub-code (e.g. "183205-S")
    [9] : date (e.g. "100497" = 10 Apr 1997)

Detection strategy:
  Primary   : b"MOTRONIC MP 9" in the last 1 KB — unique to MP9 family.
  Secondary : b"MP9" in the last 1 KB AND HW pattern "0261xxxxxx".
  Size gate : 64KB (0x10000) ONLY.
              Larger bins with MOTRONIC belong to other families (ME7, M5.x).

Exclusion:
  Bins are NOT MP9 if they contain any modern Bosch signature (EDC17,
  MEDC17, MED17, ME17, ME7., SB_V, Customer., NR000), EDC16/EDC15 markers,
  M5.x markers, or if they are larger than 64KB.

Verified samples:
  Seat Ibiza 6K0906027E  0261204593  -> MP9.0  sw=1037357494  oem=6K0906027E
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # The combined ident block near end of file:
    #   [HW] [SW] MP9 000[OEM_PART]  MOTRONIC MP 9.0    S0xx
    # Groups:
    #   1 = HW  "0261xxxxxx"
    #   2 = SW  "1037xxxxxx"
    #   3 = OEM part number (e.g. "6K0906027E")
    "ident_block": (
        rb"(0261\d{6})"  # group 1: HW number
        rb"\s+"
        rb"(1037\d{6})"  # group 2: SW version
        rb"\s+"
        rb"MP9\s+\d{3}"  # "MP9 000" separator
        rb"(\w{10,14})"  # group 3: OEM part number
        rb"\s+"
        rb"MOTRONIC\s+MP\s+9\.0"  # full family label
    ),
    # Slash-delimited metadata block
    # e.g. " 53/1/MP9.0/51/4007.01/DAMOS94/1832-S/183205-S/100497/"
    # Groups:
    #   1 = family (e.g. "MP9.0")
    #   2 = DAMOS version (e.g. "4007.01")
    "slash_block": (
        rb"\d{1,3}/\d/"
        rb"(MP9[\d\.]+)"  # group 1: family
        rb"/\d{1,3}/"
        rb"([\d\.]+)"  # group 2: DAMOS version
        rb"/DAMOS\d+"
    ),
    # Standalone hardware number fallback
    "hardware_number": rb"0261\d{6}",
    # Standalone software version fallback (strict 10-digit)
    "software_version": rb"1037\d{6}",
    # OEM part number fallback — VW/Seat/Skoda format
    # e.g. "6K0906027E", "030906027E"
    "oem_part_number": rb"[\dA-Z]{3}906\d{3}[A-Z]{1,2}",
    # ECU family string from slash block
    "ecu_family_string": rb"MP9[\d\.]+",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# The ident block and slash block are always in the last 1 KB of the binary.
# We search the last 2 KB (0x800 bytes) for safety margin.
# The full binary is used as a last-resort fallback.

SEARCH_REGIONS: Dict[str, slice] = {
    # Last 2 KB — ident block and slash-delimited metadata
    "ident_area": slice(-0x800, None),
    # Full binary — for any last-resort fallback
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "ident_block": "ident_area",
    "slash_block": "ident_area",
    "hardware_number": "ident_area",
    "software_version": "ident_area",
    "oem_part_number": "ident_area",
    "ecu_family_string": "ident_area",
}

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# 0x10000 = 64KB — the only known MP9 dump size.
# Nothing larger — 128KB+ with MOTRONIC belongs to M5.x / ME7 territory.

SUPPORTED_SIZES: set[int] = {0x10000}

# ---------------------------------------------------------------------------
# Detection signatures (primary positive anchors)
# ---------------------------------------------------------------------------
# b"MOTRONIC MP 9" is unique to MP9 — no other Bosch family uses this label.
# b"MP9" alone is used as a secondary anchor (combined with HW pattern).

PRIMARY_DETECTION_SIGNATURE: bytes = b"MOTRONIC MP 9"
SECONDARY_DETECTION_SIGNATURE: bytes = b"MP9"

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these are found in the first 64KB, reject immediately.
# Guards against accidentally claiming bins from other Bosch families.

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"EDC15",
    b"SB_V",  # modern Bosch SW base version — absent on MP9
    b"Customer.",  # modern Bosch customer label — absent on MP9
    b"NR000",  # modern Bosch serial prefix — absent on MP9
    b"ME7.",  # ME7 family string — MP9 predates ME7
    b"ME71",  # ME71 earliest ME7 variant
    b"TSW ",  # EDC15 toolchain marker
    b"ZZ\xff\xff",  # ME7 ident block marker — absent in MP9
    b"M5.",  # M5.x family — different Motronic generation
    b"M3.8",  # M3.8x family — different Motronic generation
]

# ---------------------------------------------------------------------------
# Family normalisation map
# ---------------------------------------------------------------------------
# All MP9 variants normalise to the single canonical family name.

FAMILY_NORMALISATION: Dict[str, str] = {
    "MP9.0": "MP9",
    "MP9.1": "MP9",
    "MP9": "MP9",
}
