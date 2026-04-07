"""
Bosch Motronic M5.x ECU binary identifier patterns and search regions.

Covers the Bosch Motronic M5.x / M3.8x family:
  M3.8    — Bosch Motronic M3.8 / M3.82 / M3.83 / M3.8.3
              VW/Audi 1.8T (AGU engine code), 128KB–256KB dumps (~1997–2001)
  M3.8.1  — Bosch Motronic M3.8.1 (VR6 2.8L applications)
              VW Golf 3 / Transporter / Sharan VR6, 128KB dumps (~1995–2000)
  M5.9    — Bosch Motronic M5.9 / M5.92
              VW/Audi 1.8T (AUM, APX, AWP engine codes), 256KB–512KB dumps (~2000–2004)
              VW Golf MK3 2.0 ABA 115hp, 512KB dumps (~1995–1999)

These are Motorola C167-based ECUs — the same CPU family as early ME7 — but
they predate the ME7 generation and use a different binary layout:

  - NO ZZ\\xff\\xff ident block at 0x10000 (that is ME7-specific)
  - NO MOTRONIC label in the first 512KB of the search area (for Formats A/B)
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

  512KB (0x80000 bytes) — e.g. M5.9 bins (VW Golf MK3 2.0 ABA, 037906259):
    Ident string  : ~0xbf06–0xbf12
    M5.x string   : ~0x1103 (first 64KB)
    MOTRONIC anchor: ~0xbf12 (within ident string)

Ident string format (slash-delimited, located near end of binary):

  Format A (8D09xxx part numbers — some have garbage prefix bytes):
    [garbage][OEM_PART]  [engine_desc] MOTR    [rev][HW][SW]/[n]/[family]/[ver]/[dataset]/[damos]/...
    e.g. "8D0907557P  1.8L R4/5VT MOTR    D060261204258103735026955/1/M5.92/05/400201/DAMOS3A8/..."

  Format B (06A906018xx, 06A906032xx part numbers — clean prefix):
    [OEM_PART] [engine_desc] MOTR [HS] [rev][HW][SW]/[n]/[family]/[ver]/[dataset]/[damos]/...
    e.g. "06A906018AQ 1.8L R4/5VT MOTR HS D030261204678103735810858/1/M3.8.3/03/400303/DAMOS30P/..."
    e.g. "06A906018BT 1.8L R4/5VT MOTR HS V040261204683103735817156/1/M3.83/381/..."

  Format C (VR6 / Golf MK3 — MOTRONIC keyword, full family in label):
    [OEM_PART]  MOTRONIC [family]     [rev][HW][SW]/[n]/[family_short]/[ver]/[dataset]/[damos]/...
    e.g. "037906259   MOTRONIC M5.9       V070261203720103735553251/1/M5.9/03/161/DAMOS235/..."
    e.g. "021906256H  MOTRONIC M3.8.1     V030261203971103735522749/1/M3.81/03/175/DAMOS85/..."
    e.g. "071906018AE MOTRONIC M3.8.3     V010261206620103735237155/1/M3.83/03/5223.Sx/DAMOS50/..."

  Format D (VR6 Sharan — MOTOR keyword with PMC, 0xFF gap):
    [OEM_PART]     MOTOR    PMC [0xFF padding][HW][SW]/[n]/[family]/[ver]/[dataset]/[damos]/...
    e.g. "021906256Q     MOTOR    PMC \\xff\\xff\\xff\\xff\\xff\\xff\\xff0261203665222735564049/1/3.8.1/03/176/DAMOS81/..."

Fields in the slash-delimited block:
  [rev]    : Single uppercase letter + 2 digits (e.g. "D03", "D06", "V04")
              Not present in Format D (MOTOR PMC) — 0xFF gap instead.
  [HW]     : "0261xxxxxx"  — 10 digits, Bosch hardware part number
  [SW_raw] : 12 digits — always exactly 12 chars in M5.x/M3.8x bins
              The true SW version is always the FIRST 10 digits.
              The last 2 digits are a variant/checksum suffix appended by the
              toolchain and must be stripped: "103735026955" → "1037350269"
              Known prefixes: 1037, 2537, 2227 (not just 1037)
  [family] : "M5.9", "M5.92", "M3.82", "M3.83", "M3.8.3", "M3.81", "3.8.1"
              Normalised to the base family: "M5.9" or "M3.8"

SW prefix note:
  Most bins use the '1037' Bosch-standard SW prefix. However, certain VR6
  variants use different prefixes:
    1037 — standard Bosch (M5.9, M5.92, M3.82, M3.83, M3.8.3, some M3.8.1)
    2537 — VR6 Golf 3 variant (M3.8.1, 0261203969)
    2227 — VR6 Sharan variant (M3.8.1, 0261203665)
  All three are valid 10-digit SW versions after stripping the 2-digit suffix.

SW suffix pattern (observed across all samples):
  103735026955  → SW=1037350269  suffix=55
  103735745955  → SW=1037357459  suffix=55
  103735912755  → SW=1037359127  suffix=55
  103735876157  → SW=1037358761  suffix=57
  103735212757  → SW=1037352127  suffix=57
  103735810858  → SW=1037358108  suffix=58
  103735001056  → SW=1037350010  suffix=56
  103735952556  → SW=1037359525  suffix=56
  103735952256  → SW=1037359522  suffix=56
  103735553251  → SW=1037355532  suffix=51  (MK3 M5.9)
  103735876854  → SW=1037358768  suffix=54  (MK3 M5.9)
  253735593852  → SW=2537355938  suffix=52  (VR6 Golf 3)
  103735522749  → SW=1037355227  suffix=49  (VR6 Transporter)
  222735564049  → SW=2227355640  suffix=49  (VR6 Sharan)
  103735237155  → SW=1037352371  suffix=55  (Passat V5)

OEM part number extraction notes:
  Format A bins (8D09xxx) have non-ASCII garbage bytes immediately before the
  OEM string. The OEM part is the first clean alphanumeric run that precedes
  the engine displacement descriptor (" 1.8L").
  Format B bins (06A9xxx) have a clean OEM part at the start of the ident string.
  Both formats are handled by searching for the OEM pattern anchored before "1.8L".
  Format C/D bins (VR6, MK3) have the OEM part before "MOTRONIC" or "MOTOR".
  These are handled by the oem_before_motronic pattern.

Detection strategy (no false-positive risk confirmed on all current handled bins):
  Primary   : b"M5." string in the first 64KB  (M5.9 / M5.92 bins)
              b"M3.8" string in the first 64KB  (M3.8x bins, all sub-variants)
  Secondary : Combined ident pattern — MOTR/MOTRONIC/MOTOR anchor + HW + SW + /n/family
              This fires on ALL M5.x AND M3.8x bins regardless of whether the
              explicit M5.x/M3.8 string is present.
  Sizes     : 128KB (0x20000), 256KB (0x40000), 512KB (0x80000).

Exclusion:
  Bins are NOT M5.x if they contain any modern Bosch signature (EDC17,
  MEDC17, MED17, ME17, SB_V, Customer., NR000), EDC16/EDC15 markers, or
  the ME7 ZZ ident block.
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # The combined ident block: anchor + HW + SW(12) + slash + fields.
    # This is the single most reliable source for HW, SW, and family.
    #
    # Handles all four ident formats via alternation:
    #
    #   Format A: MOTR    D06  0261...1037.../1/M5.92/...
    #   Format B: MOTR HS D03  0261...1037.../1/M3.8.3/...
    #   Format C: MOTRONIC M5.9       V07  0261...1037.../1/M5.9/...
    #             MOTRONIC M3.8.1     V03  0261...1037.../1/M3.81/...
    #             MOTRONIC M3.8.3     V01  0261...1037.../1/M3.83/...
    #   Format D: MOTOR    PMC \xff+  0261...2227.../1/3.8.1/...
    #
    # Groups:
    #   1 = HW  "0261xxxxxx"  (10 digits)
    #   2 = SW raw 12 digits  (strip last 2 for true SW)
    #   3 = revision/counter field after first slash  e.g. "1"
    #   4 = family field after second slash  e.g. "M5.92" / "M3.82" / "M3.8.3" / "3.8.1"
    "ident_block": (
        rb"(?:"
        # Format C: MOTRONIC <family> <spaces> <rev_code>
        # e.g. "MOTRONIC M5.9       V07", "MOTRONIC M3.8.1     V03"
        rb"MOTRONIC\s+M[\d.]+\s+[A-Z]\d{2}"
        rb"|"
        # Format A/B: MOTR [HS] <rev_code>
        # e.g. "MOTR    D06", "MOTR HS D03", "MOTR HS V04"
        rb"MOTR(?:\s+HS)?\s+[A-Z]\d{2}"
        rb"|"
        # Format D: MOTOR    PMC <0xFF padding>
        # e.g. "MOTOR    PMC \xff\xff\xff\xff\xff\xff\xff"
        rb"MOTOR\s+PMC[\s\xff]+"
        rb")"
        rb"(0261\d{6})"  # group 1: HW number (10 digits)
        rb"(\d{12})"  # group 2: SW raw (12 digits, any prefix)
        rb"/(\d)/"  # group 3: revision counter
        rb"([A-Z0-9][0-9\.]{2,6})"  # group 4: family (M5.92, M3.81, 3.8.1 etc.)
    ),
    # OEM (VAG) part number — anchored before the engine displacement string.
    # Handles Format A (may have 1–3 garbage chars before) and Format B (clean).
    # The OEM part always ends with a letter suffix and precedes " 1.8L"
    # Matches: "06A906018AQ", "8D0907557P", "8D0907559"
    "oem_part_number": rb"([0-9][0-9A-Z]{7,13})\s{1,4}\d\.\d[Ll]",
    # OEM part number — alternative anchor before MOTRONIC or MOTOR keywords.
    # Handles Format C (VR6 / MK3) and Format D (Sharan VR6) where the OEM part
    # appears before "MOTRONIC" or "MOTOR" instead of before an engine displacement.
    # e.g. "021906256H  MOTRONIC M3.8.1", "037906259   MOTRONIC M5.9"
    # e.g. "021906256Q     MOTOR    PMC"
    # Group 1 captures the OEM part number.
    "oem_before_motronic": rb"([0-9][0-9A-Z]{7,13})\s{1,8}(?:MOTRONIC|MOTOR)\b",
    # Standalone M5.x / M3.8x family string in the first 64KB
    # Used as secondary detection anchor and family name source
    # Matches: "M5.9", "M5.92", "M3.8", "M3.82", "M3.83", "M3.8.3", "M3.81", "M3.8.1"
    "ecu_family_string": rb"M[35][\.]\d[\d\.]*\d",
    # Hardware number standalone fallback
    "hardware_number": rb"0261\d{6}",
    # Software version standalone fallback (strict 10-digit)
    # Accepts known prefixes: 1037, 1039, 2227, 2537
    "software_version": rb"(?:1037|1039|2227|2537)\d{6}",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# The ident string is always at absolute offset ~0xBF00–0xBF30, regardless
# of total file size. This falls within the first 64KB (0x10000) in ALL
# supported sizes (128KB, 256KB, 512KB).
#
#   In 128KB (0x20000) files, MOTR is at absolute offset ~0xbf1e = 48926
#   In 256KB (0x40000) files, MOTR is at absolute offset ~0xbf22 = 48930
#   In 512KB (0x80000) files, MOTRONIC is at absolute offset ~0xbf12 = 48914
#
# All are within the first 64KB (65536 bytes). The M5.x version string is
# also in the first 64KB. We search the full first 64KB for everything.

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
    "oem_before_motronic": "ident_area",
    "ecu_family_string": "ident_area",
    "hardware_number": "ident_area",
    "software_version": "ident_area",
}

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# 0x20000 = 128KB  — M3.82 era (e.g. 8D0907557T, 06A906018D)
#                     M3.8.1 VR6 (e.g. 021906256, 021906256H, 021906256Q)
# 0x40000 = 256KB  — M5.9 / M3.8.3 era (e.g. 8D0907557P, 06A906018AQ)
#                     M3.8.3 V5 (e.g. 071906018AE)
# 0x80000 = 512KB  — M5.9 Golf MK3 2.0 ABA (e.g. 037906259)

SUPPORTED_SIZES: set[int] = {0x20000, 0x40000, 0x80000}

# ---------------------------------------------------------------------------
# Detection signatures (primary positive anchors)
# ---------------------------------------------------------------------------
# At least ONE must be present in the search area for can_handle() to proceed.
# "M5." covers M5.9 and M5.92.
# "M3.8" covers M3.8, M3.82, M3.83, M3.8.3, M3.81, M3.8.1.
# Both are absent from every currently-handled ME7 / EDC15 / EDC16 / EDC17 bin
# (confirmed by false-positive sweep across 119 currently-handled bins).

DETECTION_SIGNATURES: list[bytes] = [
    b"M5.",  # M5.9  M5.92
    b"M3.8",  # M3.8  M3.82  M3.83  M3.8.3  M3.81  M3.8.1
]

# ---------------------------------------------------------------------------
# Secondary detection patterns (ident block anchors)
# ---------------------------------------------------------------------------
# Used as a fallback when the M5./M3.8 primary string alone is not sufficient.
# MOTR_ANCHOR covers Formats A, B, and C (MOTR is a substring of MOTRONIC).
# MOTOR_ANCHOR covers Format D (MOTOR    PMC) where the word MOTOR does NOT
# contain the substring MOTR (M-O-T-O-R vs M-O-T-R).

MOTR_ANCHOR: bytes = b"MOTR"
MOTOR_ANCHOR: bytes = b"MOTOR"

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
#
# Note: Format D (Sharan VR6) stores the family as "3.8.1" (without the M
# prefix). This is normalised to "M3.8" like all other M3.8x sub-variants.

FAMILY_NORMALISATION: Dict[str, str] = {
    "M5.9": "M5.9",
    "M5.92": "M5.9",
    "M3.8": "M3.8",
    "M3.82": "M3.8",
    "M3.83": "M3.8",
    "M3.8.3": "M3.8",
    "M3.81": "M3.8",
    "M3.8.1": "M3.8",
    "3.8.1": "M3.8",
}
