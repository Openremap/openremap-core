"""
Bosch Motronic M4.x ECU binary identifier patterns and search regions.

Covers the Bosch Motronic M4.x family:
  M4.3   — Volvo 850 / 960 / S70 / V70 petrol ECUs (1994–1998), 64KB dumps
  M4.4   — Volvo S60 / S70 / V70 / S80 petrol ECUs (1998–2002), 128KB dumps

These are Motorola 68xxx-based ECUs used predominantly in Volvo vehicles.
The binary structure shares heritage with other early Bosch Motronic families
but has key differences:

  - NO ZZ\xff\xff ident block (that is ME7-specific)
  - NO MOTRONIC label (that is M5.x / ME7 / MP9 territory)
  - NO reversed-digit ident encoding (M1.x / M3.x use reversed digits)
  - Family marker is M4.3 or M4.4 embedded in a DAMOS slash-delimited
    descriptor string (e.g. "44/1/M4.3/09/5033/DAMOS0C03//040398/")
  - HW and SW are encoded in SEQUENTIAL (direct) digit order in the ident
    block — NOT reversed like M1.x / M3.x

Binary structure:

  64KB (0x10000 bytes) — M4.3:
    DAMOS descriptor : slash-delimited, located at variable offset in the file
                       e.g. "44/1/M4.3/09/5033/DAMOS0C03//040398/"
    Ident block      : last ~8KB, contiguous digit run of 20–30+ digits
                       Format: <HW_10><SW_10><extra_digits>

  128KB (0x20000 bytes) — M4.4:
    DAMOS descriptor : slash-delimited, located at variable offset in the file
                       e.g. "47/1/M4.4/05/5044/DAMOS0C04//150699/"
    Ident block      : last ~8KB, contiguous digit run of 20–30+ digits
                       Format: <HW_10><SW_10><extra_digits>

Ident digit run format (SEQUENTIAL — not reversed):

    digits[0:10]  = hardware_number   (always starts with 0261)
    digits[10:20] = software_version  (starts with 1037, 1267, or 2227)
    digits[20:]   = calibration/dataset extra digits (variable length)

  An optional ".NN" two-digit decimal suffix may follow the digit run
  (e.g. "026120422510373552771270544.05"); it must be stripped before parsing.

Examples (from forensic analysis of Volvo corpus):

  M4.3 (64KB):
    Digit run : "026120422510373552771270544"
    HW        : "0261204225"
    SW        : "1037355277"
    Extra     : "1270544"

  M4.4 (128KB):
    Digit run : "026120423910373557801280422"
    HW        : "0261204239"
    SW        : "1037355780"
    Extra     : "1280422"

Detection strategy:

  Primary   : b"/M4.3/" or b"/M4.4/" DAMOS slash-delimited family token
              in the binary.  Extremely specific — the slashes make false
              positives near-impossible.
  Secondary : Long sequential digit run (20+ digits) starting with "0261"
              and followed by a valid SW prefix, found in the last ~8KB.
  Size gate : 64KB (0x10000) or 128KB (0x20000) ONLY.
              Larger bins belong to other families (ME7, EDC15, M5.x, etc.).

Exclusion:

  Bins are NOT M4.x if they contain any modern Bosch signature (EDC17,
  MEDC17, MED17, etc.), ME7 markers, MOTRONIC label, M5.x/M3.x markers,
  or EDC15/EDC16 identifiers.  These exclusions prevent any family
  overlap despite the shared 64KB/128KB size range.

Verified across Volvo M4.3 (64KB) and M4.4 (128KB) sample bins.
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # DAMOS slash-delimited descriptor containing M4.x family.
    # e.g. "44/1/M4.3/09/5033/DAMOS0C03//040398/"
    # Groups:
    #   1 = family     "M4.3" or "M4.4"
    #   2 = dataset    e.g. "5033"
    "damos_descriptor": (
        rb"\d{1,3}/\d+/"
        rb"(M4\.\d)"  # group 1: family
        rb"/\d{1,3}/"
        rb"(\d{3,6})"  # group 2: dataset code
    ),
    # Contiguous digit run (ident block) — 20–50 digits, optionally with .NN suffix.
    # Boundary assertions prevent matching a sub-string of a longer digit sequence.
    # Groups:
    #   0 (full match) = the entire digit run including optional suffix
    "ident_digits": rb"(?<!\d)\d{20,50}(?:\.\d{2})?(?!\d)",
    # Hardware number standalone fallback
    "hardware_number": rb"0261\d{6}",
    # Software version standalone fallback (all three known M4.x SW prefixes)
    "software_version": rb"(?:1037|1267|2227)\d{6}",
    # ECU family string (standalone, outside DAMOS context)
    "ecu_family_string": rb"M4\.\d",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# The ident digit run is always in the last ~8KB of the file for both
# M4.3 (64KB) and M4.4 (128KB) bins.  The DAMOS descriptor can appear at
# variable offsets throughout the file, so it is searched in the full binary.

SEARCH_REGIONS: Dict[str, slice] = {
    # Last ~8KB — ident block is always here
    "ident_area": slice(-0x2000, None),
    # Full binary — DAMOS descriptor, family string, and fallback patterns
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "damos_descriptor": "full",
    "ident_digits": "ident_area",
    "hardware_number": "ident_area",
    "software_version": "ident_area",
    "ecu_family_string": "full",
}

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# 0x10000 = 64KB  — M4.3 (Volvo 850 / 960 / early S70/V70)
# 0x20000 = 128KB — M4.4 (Volvo S60 / S70 / V70 / S80 / XC70)
# Nothing larger — 256KB+ belongs to M5.x / EDC15 / ME7 territory.

SUPPORTED_SIZES: set[int] = {0x10000, 0x20000}

# ---------------------------------------------------------------------------
# Detection signatures (primary positive anchors)
# ---------------------------------------------------------------------------
# "/M4.3/" and "/M4.4/" are 6-byte DAMOS family tokens surrounded by the
# slash delimiters of the descriptor string.  No other known Bosch family
# produces these byte sequences.  Combined with the size gate and exclusion
# set, these are definitive positive identifiers.

DETECTION_SIGNATURES: list[bytes] = [
    b"/M4.3/",  # M4.3 — Volvo 850 / 960 / early S70/V70 (64KB)
    b"/M4.4/",  # M4.4 — Volvo S60 / S70 / V70 / S80 (128KB)
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these are found in the first 512KB, reject immediately.
# Guards against accidentally claiming bins from every other known Bosch
# family that might share the 64KB or 128KB size range.

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",  # modern Bosch diesel
    b"MEDC17",  # modern Bosch diesel
    b"MED17",  # modern Bosch petrol
    b"ME17",  # modern Bosch petrol
    b"EDC16",  # older Bosch diesel (still not M4.x)
    b"EDC15",  # EDC15 diesel (512KB, TSW toolchain)
    b"SB_V",  # modern Bosch SW base version — absent on M4.x
    b"Customer.",  # modern Bosch customer label — absent on M4.x
    b"NR000",  # modern Bosch serial prefix — absent on M4.x
    b"ME7.",  # ME7 family string — M4.x predates ME7
    b"ME71",  # ME71 earliest ME7 variant
    b"MOTRONIC",  # M5.x / ME7 / MP9 MOTRONIC label — absent on M4.x
    b"TSW ",  # EDC15 toolchain marker
    b"ZZ\xff\xff",  # ME7 ident block marker — absent in M4.x
    b"M5.",  # M5.x family — different Motronic generation
    b"M3.8",  # M3.8x family — different Motronic generation
    b"1350000M3",  # M3.1 family marker
    b"1530000M3",  # M3.3 / MP7.2 family marker
    b"0000000M3",  # PSA MP3.2 / MP3.x-PSA marker
    b'"0000000M2.',  # M2.x family marker (Audi V8 / Porsche 964) — shares 64KB size
    b"M1.55",  # M1.55 (Alfa Romeo) — shares 128KB size
    b"M1.5.5",  # M1.5.5 (Opel) — shares 128KB size
    b"MOTRONIC MP 9",  # MP9 label — shares 64KB size
]

# ---------------------------------------------------------------------------
# Family normalisation map
# ---------------------------------------------------------------------------
# M4.x only has two known sub-families; both are their own canonical name.

FAMILY_NORMALISATION: Dict[str, str] = {
    "M4.3": "M4.3",
    "M4.4": "M4.4",
}

# ---------------------------------------------------------------------------
# Valid SW prefixes for M4.x ident digit runs
# ---------------------------------------------------------------------------
# The software_version field in the sequential ident digit run must start
# with one of these 4-digit prefixes.  All four are observed across the
# Volvo M4.x corpus.
#
#   1037 — standard Bosch Motronic SW numbering (most common)
#   1267 — older Bosch numbering scheme (shared with M3.x era)
#   2227 — alternative Bosch numbering scheme (shared with M3.x era)
#   2537 — Bosch SW numbering variant (Volvo 850 T5-R)

VALID_SW_PREFIXES: tuple[str, ...] = ("1037", "1267", "2227", "2537")
