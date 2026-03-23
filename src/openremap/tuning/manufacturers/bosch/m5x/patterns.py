"""
Bosch Motronic M5.x ECU binary identifier patterns and search regions.

Covers the Bosch Motronic M5.x / M3.8x family:
  M3.8    — Bosch Motronic M3.8 / M3.82 / M3.83 / M3.8.3
              VW/Audi 1.8T (AGU engine code), 128KB–256KB dumps (~1997–2001)
  M5.9    — Bosch Motronic M5.9 / M5.92
              VW/Audi 1.8T (AUM, APX, AWP engine codes), 256KB dumps (~2000–2004)

These are Motorola C167-based ECUs — the same CPU family as early ME7 — but
they predate the ME7 generation and use a different binary layout:

  - NO ZZ\xff\xff ident block at 0x10000 (that is ME7-specific)
  - NO MOTRONIC label in the first 512KB of the search area
  - NO ME7. / ME71 family string anywhere in the binary
  - The HW+SW+family info is in a single slash-delimited ASCII ident string
    located near the END of the binary (around 0xbf1e–0xbf22, regardless of
    whether the bin is 128KB or 256KB)
  - An independent "M5.9  03/***..." version string exists in the first 64KB

Binary structure:

  128KB (0x20000 bytes) — e.g. M3.82 bins (AGU, 8D0907557T):
    Ident string  : ~0xbf1e
    M5.x string   : ~0x0e88 (first 64KB)
    MOTR anchor   : ~0xbf1e  (within ident string)

  256KB (0x40000 bytes) — e.g. M5.9 bins (8D0907557P, 06A906018xx):
    Ident string  : ~0xbf22
    M5.x string   : ~0x1086–0x1404 (first 64KB)
    MOTR anchor   : ~0xbf22  (within ident string)

Ident string format (slash-delimited, located near end of binary):

  Format A (8D09xxx part numbers — some have garbage prefix bytes):
    [garbage][OEM_PART]  [engine_desc] MOTR    [rev][HW][SW]/[n]/[family]/[ver]/[dataset]/[damos]/...
    e.g. "8D0907557P  1.8L R4/5VT MOTR    D060261204258103735026955/1/M5.92/05/400201/DAMOS3A8/..."

  Format B (06A906018xx, 06A906032xx part numbers — clean prefix):
    [OEM_PART] [engine_desc] MOTR [HS] [rev][HW][SW]/[n]/[family]/[ver]/[dataset]/[damos]/...
    e.g. "06A906018AQ 1.8L R4/5VT MOTR HS D030261204678103735810858/1/M3.8.3/03/400303/DAMOS30P/..."

Fields in the slash-delimited block:
  [HW]     : "0261xxxxxx"  — 10 digits, Bosch hardware part number
  [SW_raw] : "1037xxxxxxxxxx" — always exactly 12 chars in M5.x/M3.8x bins
              The true SW version is always the FIRST 10 digits.
              The last 2 digits are a variant/checksum suffix appended by the
              toolchain and must be stripped: "103735026955" → "1037350269"
  [family] : "M5.9", "M5.92", "M3.82", "M3.83", "M3.8.3" etc.
              Normalised to the base family: "M5.9" or "M3.8"

SW suffix pattern (observed across all 9 samples):
  103735026955  → SW=1037350269  suffix=55
  103735745955  → SW=1037357459  suffix=55
  103735912755  → SW=1037359127  suffix=55
  103735876157  → SW=1037358761  suffix=57
  103735212757  → SW=1037352127  suffix=57
  103735810858  → SW=1037358108  suffix=58
  103735001056  → SW=1037350010  suffix=56
  103735952556  → SW=1037359525  suffix=56
  103735952256  → SW=1037359522  suffix=56

The suffix is always 2 digits; the separator between SW and the next field
is always '/' (confirmed across all samples). We therefore always read exactly
10 digits after '1037' from the ident string.

OEM part number extraction notes:
  Format A bins (8D09xxx) have non-ASCII garbage bytes immediately before the
  OEM string. The OEM part is the first clean alphanumeric run that precedes
  the engine displacement descriptor (" 1.8L").
  Format B bins (06A9xxx) have a clean OEM part at the start of the ident string.
  Both formats are handled by searching for the OEM pattern anchored before "1.8L".

Detection strategy (no false-positive risk confirmed on all current handled bins):
  Primary   : b"M5." string in the first 64KB  (M5.9 / M5.92 bins)
  Secondary : Combined ident pattern — MOTR anchor + HW + 12-digit SW + /n/M[35]
              This fires on BOTH M5.x AND M3.8x bins regardless of whether the
              explicit M5.x string is present.
  Sizes     : 128KB (0x20000) and 256KB (0x40000) ONLY.
              Larger bins (512KB+) with MOTR are ME7 territory — excluded by
              the size gate AND by the ZZ marker check.

Exclusion:
  Bins are NOT M5.x if they contain any modern Bosch signature (EDC17,
  MEDC17, MED17, ME17, SB_V, Customer., NR000), EDC16/EDC15 markers,
  or if they are larger than 256KB (those belong to ME7 / EDC15).
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # The combined ident block: MOTR anchor + rev_field + HW + SW(12) + slash + fields
    # This is the single most reliable source for HW, SW, and family.
    # Matches both Format A ("MOTR    D0x") and Format B ("MOTR HS Dxx")
    # Groups:
    #   1 = HW  "0261xxxxxx"
    #   2 = SW raw 12 digits "1037xxxxxxxxxx"   (strip last 2 for true SW)
    #   3 = revision/counter field after slash   e.g. "1"
    #   4 = family field after slash             e.g. "M5.92" / "M3.82" / "M3.8.3"
    "ident_block": (
        rb"MOTR(?:\s+HS)?\s+D\d{2}"
        rb"(0261\d{6})"
        rb"(1037\d{8})"  # exactly 12 digits total = 4 + 8
        rb"/(\d)/"
        rb"([A-Z0-9][0-9\.]{2,6})"  # family: M5.9 / M5.92 / M3.82 / M3.8.3 / M3.83
    ),
    # OEM (VAG) part number — anchored before the engine displacement string.
    # Handles both Format A (may have 1–3 garbage chars before) and Format B (clean).
    # The OEM part always ends with a letter suffix and precedes "  1.8L"
    # Matches: "06A906018AQ", "8D0907557P", "8D0907559"
    "oem_part_number": rb"([0-9][0-9A-Z]{7,13})\s{1,4}1\.8L",
    # Standalone M5.x / M3.8x family string in the first 64KB
    # Used as secondary detection anchor and family name source
    # Matches: "M5.9", "M5.92", "M3.8", "M3.82", "M3.83", "M3.8.3"
    "ecu_family_string": rb"M[35][\.]\d[\d\.]*\d",
    # Hardware number standalone fallback
    "hardware_number": rb"0261\d{6}",
    # Software version standalone fallback (strict 10-digit)
    "software_version": rb"1037\d{6}",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# The ident string is always near the end of the file regardless of size.
# In 128KB bins (0x20000): MOTR at ~0xbf1e → last 0x200 bytes of 0x20000
# In 256KB bins (0x40000): MOTR at ~0xbf22 → last 0x200 bytes of... wait.
#
# 0xbf22 is within the LAST 256KB of a 256KB file (= within the last 0x100
# bytes from end of the 0xbf22 region).  For a 0x40000 (256KB) file:
#   last 0x1000 = slice(0x3f000, None)  → covers ~0xbf00 if file were 0xc0000
# Actually 0xbf22 in a 256KB file = offset 0x3f22 from file start (but wait:
# 0x40000 = 262144, 0xbf22 = 48930 → that is NOT near the end).
#
# CORRECTION (from forensics):
#   In 256KB (0x40000) files, MOTR is at absolute offset 0xbf22.
#   0xbf22 = 48930 decimal, which is roughly the FIRST 50KB of the 256KB file.
#   So the ident string is in the first 64KB in ALL variants.
#
#   In 128KB (0x20000) files, MOTR is at absolute offset 0xbf1e = 48926,
#   which is also in the first 64KB (of a 128KB file, 48926 < 65536 = 0x10000).
#   Wait: 0x20000 = 131072.  0xbf1e = 48926.  48926 < 131072. Yes, first 64KB.
#
# So for BOTH sizes, the ident string is in the first 64KB (0x10000 bytes).
# The M5.x version string is also in the first 64KB.
# We search the full first 64KB for everything — it is a tight, safe window.

SEARCH_REGIONS: Dict[str, slice] = {
    # First 64KB — contains BOTH the ident string AND the M5.x version string
    "ident_area": slice(0x0000, 0x10000),
    # Full binary — for any last-resort fallback
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "ident_block": "ident_area",
    "oem_part_number": "ident_area",
    "ecu_family_string": "ident_area",
    "hardware_number": "ident_area",
    "software_version": "ident_area",
}

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# 0x20000 = 128KB  — M3.82 era (e.g. 8D0907557T, 06A906018D)
# 0x40000 = 256KB  — M5.9 / M3.8.3 era (e.g. 8D0907557P, 06A906018AQ)
# Nothing larger — 512KB+ with MOTR belongs to ME7 / EDC15.

SUPPORTED_SIZES: set[int] = {0x20000, 0x40000}

# ---------------------------------------------------------------------------
# Detection signatures (primary positive anchors)
# ---------------------------------------------------------------------------
# At least ONE must be present in the search area for can_handle() to proceed.
# "M5." covers M5.9 and M5.92.
# "M3.8" covers M3.8, M3.82, M3.83, M3.8.3.
# Both are absent from every currently-handled ME7 / EDC15 / EDC16 / EDC17 bin
# (confirmed by false-positive sweep across 119 currently-handled bins).

DETECTION_SIGNATURES: list[bytes] = [
    b"M5.",  # M5.9  M5.92
    b"M3.8",  # M3.8  M3.82  M3.83  M3.8.3
]

# ---------------------------------------------------------------------------
# Secondary detection pattern (ident block anchor)
# ---------------------------------------------------------------------------
# The MOTR + 12-digit-SW pattern is the strongest combined anchor.
# Used as a fallback when the M5./M3.8 string alone is not sufficient.
# This bytes prefix is present in EVERY M5.x/M3.8x bin and absent from all
# other known Bosch families of this era.

MOTR_ANCHOR: bytes = b"MOTR"

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these are found in the first 512KB, reject immediately.
# Guards against accidentally claiming larger Bosch bins.

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"EDC15",
    b"SB_V",  # modern Bosch SW base version — absent on M5.x
    b"Customer.",  # modern Bosch customer label — absent on M5.x
    b"NR000",  # modern Bosch serial prefix — absent on M5.x
    b"ME7.",  # ME7 family string — these bins predate ME7
    b"ME71",  # ME71 earliest ME7 variant
    b"TSW ",  # EDC15 toolchain marker
    b"ZZ\xff\xff",  # ME7 ident block marker — absent in M5.x/M3.8x
]

# ---------------------------------------------------------------------------
# Family normalisation map
# ---------------------------------------------------------------------------
# The raw family string from the ident block may include minor revision
# suffixes. Normalise to the two canonical base families for the match_key.

FAMILY_NORMALISATION: Dict[str, str] = {
    "M5.9": "M5.9",
    "M5.92": "M5.9",
    "M3.8": "M3.8",
    "M3.82": "M3.8",
    "M3.83": "M3.8",
    "M3.8.3": "M3.8",
}
