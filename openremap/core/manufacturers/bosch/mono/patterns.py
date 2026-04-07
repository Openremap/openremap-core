"""
Bosch Mono-Motronic ECU binary identifier patterns and search regions.

Covers the Bosch Mono-Motronic (MA1.2 / MA1.2.3) family:
  Mono-Motronic — VW/Audi/Seat single-point fuel injection ECUs (~1989–1997)
                  VW Golf 2/3, Audi 80 B4, VW Passat B4, Seat Ibiza/Cordoba
                  8051-family CPU (SAB80C535/SAB80C515), 32KB or 64KB dumps

These are 8051-based single-point injection ECUs that predate the M2.x and
M5.x generations.  They use a completely different binary layout from all
other Bosch Motronic families:

  - NO ZZ\\xff\\xff ident block (ME7-specific)
  - NO reversed-digit ident encoding (M1.x / M3.x territory)
  - NO MOTRONIC label (M5.x / ME7 / M2.x / MP9 territory)
  - NO '"0000000M' family marker (M1.x / M2.x / M3.x territory)
  - The HW and SW are NOT embedded as 10-digit ASCII strings in the binary
  - The PMC (Programmable Map Computing) keyword is always present
  - The OEM part number is embedded as ASCII in a fixed-format ident block
  - 8051 LJMP instruction at offset 0: \\x02\\x05\\xNN (jump to 0x05xx)

Binary structure:

  32KB (0x8000 bytes) — single EPROM:
    Reset vector    : 0x0000 — LJMP 0x05xx (\\x02\\x05\\xNN)
    INT0 vector     : 0x0003 — LJMP \\x02\\xNN\\xNN
    Ident block     : variable offset (0x6D00–0x7000 typically)
    Calibration     : 0x7E00–0x7EFF (ASCII-like map data)
    Tail marker     : last 8 bytes — variant code + "057" + checksum

  64KB (0x10000 bytes) — two mirrored 32KB halves:
    Bank A          : 0x0000–0x7FFF  (primary)
    Bank B          : 0x8000–0xFFFF  (mirror of Bank A, minor cal diffs)
    Ident blocks at: Bank A offset + 0x8000 for Bank B

Ident block formats:

  Format A — MONO (R4 MONO variant, most bins):
    '<OEM_PART>  <disp> R4 MONO [<version>]  <D_code>PMC'
    e.g. "8A0907311H  1,8l R4 MONO 1.2.3  D51PMC"
    e.g. "1H0907311H  1,8l R4 MONO        D51PMC"
    Fields:
      OEM_PART : VAG part number (e.g. "8A0907311H", "1H0907311H")
      disp     : Engine displacement (e.g. "1,8l")
      R4       : Cylinder layout (inline-4)
      MONO     : System identifier
      version  : Optional software version (e.g. "1.2.3" or spaces)
      D_code   : Dataset/calibration prefix (e.g. "D51")
      PMC      : Programmable Map Computing keyword

  Format B — DGC (Digitale Gemisch Composition variant):
    '<OEM_PART>   <disp><OEM_PART>   <disp>DGCPMC'
    e.g. "3A0907311   1,8l3A0907311   1,8lDGCPMC"
    Fields:
      OEM_PART : VAG part number (e.g. "3A0907311"), duplicated
      disp     : Engine displacement (e.g. "1,8l"), duplicated
      DGC      : Digitale Gemisch Composition identifier
      PMC      : Programmable Map Computing keyword
    Note: the OEM+disp block is duplicated (16 bytes × 2).

  In Format A, the OEM part number immediately precedes the displacement.
  In Format B, the OEM part number is duplicated and the displacement
  immediately follows each OEM part occurrence.

Tail marker format (last 8–10 bytes of each 32KB bank):
    [\\x00] <checksum_byte> <variant_3chars> "057" <suffix_1char> <crc_2bytes>
    e.g. \\x00\\x57 "WAN057@" \\xa1\\x88
         \\x00\\x55 "UAN057\\"" \\xa1\\x14
         \\x00\\x76 "AB057R" \\xa2\\x56
    The "057" is a Bosch project code common to all Mono-Motronic variants.

OEM part number encoding:
  VAG Mono-Motronic parts always contain '907311' at positions 3-8 of the
  part number:
    xA0907311x  — Audi 80 (8A0...) / VW Passat (3A0...)
    xH0907311x  — VW Golf 3 (1H0...)
  The '907311' code is the VAG group code for single-point injection ECUs.
  The suffix letter (H, etc.) is optional.

Detection strategy:
  Phase 1 — Reject on any exclusion signature (modern Bosch, M1x/M2x/M3x/M5x).
  Phase 2 — Reject if file size is not 32KB or 64KB.
  Phase 3 — Accept if BOTH:
              a) 8051 LJMP header: data[0] == 0x02 AND data[1] == 0x05
              b) 'PMC' keyword is present in the binary
            OR:
              a) 8051 LJMP header: data[0] == 0x02 AND data[1] == 0x05
              b) '907311' VAG Mono part code is present in the binary

Exclusion safety:
  The 8051 LJMP header \\x02\\x05 at offset 0 is specific to Mono-Motronic
  ECUs — no other handled Bosch family starts with these bytes:
    - M1.x:     \\x85\\x0a\\xf0\\x30 (HC11 magic) or other non-\\x02\\x05 starts
    - M1.8:     \\x02\\x0f (LJMP 0x0Fxx — different high byte)
    - M3.x:     starts with \\xfd or other M3 patterns
    - M2.x:     MC68000 vectors (different CPU architecture entirely)
    - ME7/EDC:  C167 flash images (modern Bosch, excluded by signatures)
    - Legacy:   0x22, 0x0202+C28B, 0xC295, 0x0208, 0x7100, 0xC5C4, 0x815C

  The 'PMC' keyword also appears in M2.x Format A and M5.x Format D bins
  as part of "MOTOR    PMC".  These are excluded by the presence of
  '"0000000M2.' (M2.x) and 'MOTR' (M5.x) exclusion signatures, and by
  the 8051 LJMP header requirement (M2.x/M5.x do not start with \\x02\\x05).

No false positives observed against any file in scanned/ or sw_missing/.
"""

import re
from typing import Dict

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# 0x8000  = 32KB  — single EPROM (e.g. original.bin, Audi 80 8A0907311H)
# 0x10000 = 64KB  — mirrored 32KB halves (e.g. VW Golf 3 1H0907311H)

SUPPORTED_SIZES: frozenset[int] = frozenset({0x8000, 0x10000})

# ---------------------------------------------------------------------------
# 8051 LJMP header bytes
# ---------------------------------------------------------------------------
# All Mono-Motronic bins start with the 8051 LJMP instruction \\x02\\x05\\xNN,
# jumping to an address in the 0x0500 region.  The third byte is variable
# (the low byte of the jump target address).

HEADER_BYTE_0: int = 0x02  # 8051 LJMP opcode
HEADER_BYTE_1: int = 0x05  # High byte of LJMP target (0x05xx)

# ---------------------------------------------------------------------------
# Detection keywords
# ---------------------------------------------------------------------------
# PMC (Programmable Map Computing) is present in every Mono-Motronic binary.
# '907311' is the VAG group code for single-point injection ECUs.

PMC_KEYWORD: bytes = b"PMC"
VAG_MONO_GROUP_CODE: bytes = b"907311"

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these are found in the first 512KB, reject immediately.
# Guards against accidentally claiming bins from other Bosch families.

EXCLUSION_SIGNATURES: list[bytes] = [
    # Modern Bosch families
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"EDC15",
    b"SB_V",  # modern Bosch SW base version
    b"Customer.",  # modern Bosch customer label
    b"NR000",  # modern Bosch serial prefix
    b"ME7.",  # ME7 family string
    b"ME71",  # ME71 earliest ME7 variant
    b"TSW ",  # EDC15 toolchain marker
    b"ZZ\xff\xff",  # ME7 ident block marker
    # Motronic family markers (M1.x / M2.x / M3.x / M5.x)
    b'"0000000M',  # M1.x / M2.x / M3.x family marker prefix
    b"1350000M3",  # M3.1 family marker
    b"1530000M3",  # M3.3 family marker
    b"MOTRONIC",  # M5.x / ME7 / MP9 / M3.x label
    b"MOTR",  # M5.x ident anchor (substring of MOTRONIC)
    # Other injection systems
    b"LH-JET",  # LH-Jetronic
    b"LH24",  # LH-Jetronic Format A
    b"LH22",  # LH-Jetronic Format A
    b"DIGIFANT",  # Digifant (separate family, not Mono-Motronic)
    # M1.x primary detection magic
    b"\x85\x0a\xf0\x30",  # BoschM1xExtractor primary magic
]

# ---------------------------------------------------------------------------
# Ident block regex patterns
# ---------------------------------------------------------------------------

# Format A — MONO variant with optional version string:
#   "8A0907311H  1,8l R4 MONO 1.2.3  D51PMC"
#   "1H0907311H  1,8l R4 MONO        D51PMC"
#
# Groups:
#   1 = OEM part number  (e.g. "8A0907311H", "1H0907311H")
#   2 = displacement     (e.g. "1,8l")
#   3 = version string   (e.g. "1.2.3" or None — may be all spaces)
#   4 = D-code prefix    (e.g. "D51")

IDENT_FORMAT_A_RE = re.compile(
    rb"(\d[A-Z]\d907311[A-Z]{0,2})"  # group 1: OEM part (digit-letter-digit + 907311 + opt suffix)
    rb"\s{1,4}"  # spaces
    rb"(\d,\dl)"  # group 2: displacement (e.g. "1,8l")
    rb"\s+R4\s+MONO"  # " R4 MONO" keyword
    rb"\s+"  # space(s)
    rb"(\d+\.\d+(?:\.\d+)?)?"  # group 3: optional version (e.g. "1.2.3")
    rb"\s*"  # optional spaces
    rb"([A-Z]\d{2})"  # group 4: D-code (e.g. "D51")
    rb"PMC"  # PMC keyword
)

# Format B — DGC variant (Digitale Gemisch Composition):
#   "3A0907311   1,8l3A0907311   1,8lDGCPMC"
#   or with different spacing:
#   "3A0907311   1,8lDGCPMC"
#
# Groups:
#   1 = OEM part number  (e.g. "3A0907311")
#   2 = displacement     (e.g. "1,8l")

IDENT_FORMAT_B_RE = re.compile(
    rb"(\d[A-Z]\d907311[A-Z]{0,2})"  # group 1: OEM part (digit-letter-digit + 907311 + opt suffix)
    rb"\s{1,4}"  # spaces
    rb"(\d,\dl)"  # group 2: displacement (e.g. "1,8l")
    rb"[\s\S]{0,20}?"  # optional duplicate OEM+disp (up to 20 bytes)
    rb"DGC"  # DGC keyword
    rb"PMC"  # PMC keyword
)

# Generic OEM part fallback — search for any VAG 907311 part number.
# Used when neither Format A nor Format B matches.
#
# Group 1 = OEM part number (e.g. "8A0907311H", "3A0907311")

OEM_PART_FALLBACK_RE = re.compile(rb"(\d[A-Z]\d907311[A-Z]{0,2})")

# ---------------------------------------------------------------------------
# Tail marker pattern
# ---------------------------------------------------------------------------
# The last 8 bytes of each 32KB bank contain a variant marker:
#   <variant_2-3_chars> "057" <suffix_1char>
# e.g. "WAN057@", "UAN057\"", "AB057R"
#
# Group 1 = full tail marker string

TAIL_MARKER_RE = re.compile(rb"([A-Z]{2,3}057[A-Z@\"0-9])")

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# The ident block is located in the upper portion of the 32KB bank,
# typically between 0x5000 and 0x7000.  The tail marker is in the last
# 16 bytes.  For 64KB files, the primary bank is in the first 32KB half.

SEARCH_REGIONS: Dict[str, slice] = {
    # Ident search area — covers the full 32KB primary bank
    "ident_area": slice(0x0000, 0x8000),
    # Tail marker area — last 16 bytes of the primary 32KB bank
    "tail_area": slice(0x7FF0, 0x8000),
    # Full binary for exclusion checks
    "exclusion_area": slice(0x0000, 0x80000),
}

# ---------------------------------------------------------------------------
# Family resolution
# ---------------------------------------------------------------------------
# The ECU sub-family is determined by the ident block format and keywords.

FAMILY_MAP: Dict[str, str] = {
    "MONO": "Mono-Motronic",
    "DGC": "Mono-Motronic",
}

# Default family when no specific keyword is found but PMC is present
DEFAULT_FAMILY: str = "Mono-Motronic"
