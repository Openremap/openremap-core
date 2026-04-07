"""
Bosch EDC15 ECU binary identifier patterns and search regions.

Covers the Bosch EDC15 family:
  EDC15C2   — early diesel common-rail, Alfa Romeo / Fiat / Lancia (1997–2001)
  EDC15C3   — Volvo 5-cylinder diesel (D5 2.4D), 2001–2004
  EDC15C5   — mid-generation, VW/Audi/Seat/Skoda 1.9 TDI (1999–2004)
  EDC15C7   — VAG and PSA diesel common-rail (2000–2004)
  EDC15M    — Bosch EDC15 for petrol DI (rare)
  EDC15VM+  — variant used in some Renault / PSA applications

EDC15 predates EDC16 and EDC17 by a significant generation:
  - CPU: Motorola MPC555 or Infineon C167 (depending on variant)
  - No SB_V, Customer., NR000, or any EDC16/EDC17 strings
  - Fill byte: 0xC3 (characteristic — used as ROM blank/erased marker)
  - Five sub-formats are observed in the wild:

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

  FORMAT C — Volvo EDC15C3 (e.g. Volvo S60/V70/XC90 D5 2.4D):
    TSW string at 0x8000 with non-standard variant code:
      'TSW V0.80 080102 0950 15C11/G43/'
    Unlike Format A, these bins do NOT store the Bosch 1037xxxxxx SW number
    or 0281xxxxxx HW number as ASCII strings anywhere in the flash. Instead,
    Volvo stores its own OEM calibration identifier in a structured ident
    block at offset 0x7EC10.

    Ident block layout (at 0x7EC10, 26 bytes):
      02 04 02 0A 00 00          — fixed header (6 bytes)
      XX XX XX                   — 3-char OEM short code, ASCII (e.g. '762', '75v')
      XX XX XX                   — separator (3 bytes, variable)
      XX XX XX XX XX XX XX XX XX XX — 10-char calibration ID, ASCII
                                      (e.g. 'B341CS3200', 'B079EWS304')
      00 00 00 00 00 00          — null padding

    The 10-char calibration ID is the sole unique identifier available in
    these binaries. It is extracted as calibration_id and used as the
    match_key fallback (via match_key_fallback_field).

    Evidence these are Bosch EDC15C3:
      - Bosch HW numbers 0281010319, 0281011441 (from physical ECU labels)
      - TSW string present (unique to EDC15 toolchain)
      - 512KB file size, 0xC3 fill byte
      - Infineon C166/C167 opcodes (15C11 in TSW = C161/C167 core)

  FORMAT D — early EDC15 VP37/VP44 (e.g. VW T4 2.5 TDI, Golf 1.9 TDI):
    No TSW string.
    No '1037xxxxxx' SW version — uses alphanumeric SW codes instead.
    Bosch HW number '0281xxxxxx' at fixed offset 0x10046.
    Fill byte: 0xC3 (fill ratio 33–41%).
    File size: 512KB (0x80000).
    Structured ident blocks at offsets ~0x5EBA9 and ~0x76BA9 of the form:
        '<VAG_PN>  <engine> EDC  <variant>  <code> <bosch> <0281HW> <ALPHA_SW>HEX<VAG_PN>  <date>'
    e.g.:
        '074906018C  2,5l R5 EDC  SG  2520 28SA4060 0281010082 EBETT200HEX074906018C  0399'
    The alphanumeric SW code (e.g. 'EBETT200') is extracted as
    software_version. The HW number and OEM part number are also
    extracted from the same ident block.
    Detection: 0xC3 fill ratio >= 5% AND '0281xxxxxx' HW + alpha SW + 'HEX'
    pattern present in the binary.

  FORMAT E — EDC15 C167-based with low C3 fill (e.g. VW Bora/Golf/Lupo/Passat TDI):
    No TSW string.
    Bosch C167 flash bootstrap header 'PP22..00' present (after 'UU\\x00\\x00'
    preamble at offset 4, or at flash bank boundaries 0x8004, 0x78004).
    This 8-byte header is unique to the Bosch EDC15 C167 flash bootstrap
    loader and has never been observed in Siemens PPD/Simos or any other
    non-Bosch ECU binary.
    HW number '0281xxxxxx' and SW version '1037xxxxxx' both present as
    plain ASCII.
    Structured EDC ident blocks at various offsets of the form:
        '<VAG_PN>  <engine> Rx EDC  <variant>  <code> <0281HW> <FW_CODE>   <VAG_PN>  <date>'
    e.g.:
        '038906019BJ 1,9l R4 EDC  SG  0812 0281010176 F8DJT600   038906019BJ 0399'
        '045906019Q  1,2l R3 EDC  DS  0904 0281010258 F8EGJ300   045906019Q  0999'
    Fill byte: 0xC3 (but at only 4.1–4.6% of the file — below the 5%
    Format B threshold — because more flash is populated with data).
    File size: 512KB (0x80000).
    Detection: 'PP22..00' present in first 512KB AND '0281xxxxxx' HW present
    AND ('1037xxxxxx' SW present OR structured EDC ident block present).
    Siemens PPD/Simos/5WP signatures are excluded in Phase 1 as a safety
    guard, though these never co-occur with PP22..00 in practice.

Pattern reference:

  HARDWARE NUMBER     '0281010332'
    Bosch ECU hardware part number.
    Format: 0281 + 6 digits (10 digits total).
    Present as plain ASCII only in Format A bins.
    Preceded and followed by 0xC3 fill bytes in the data region.

  SOFTWARE VERSION    '1037366536'  '1037353311'
    Bosch internal software calibration identifier.
    Format: 1037 + 6–10 digits (10 digits total in all observed EDC15 bins).
    Present as plain ASCII in Format A and Format B.
    NOT present in Format C (Volvo EDC15C3) or Format D (early VP37/VP44) —
    these bins lack any 1037xxxxxx string entirely.
    The primary matching key — unique per SW revision.
    Multiple copies may exist; the authoritative one is the first occurrence
    in the last 256KB of the file that is surrounded by 0xC3 or 0xFF fill.

  ALPHA SW CODE       'EBETT200'  'EBEWU100'  'EBBTM100'
    Alphanumeric software code — Format D only.
    Found in structured ident blocks in early EDC15 (VP37/VP44) bins.
    Pattern: 'EB' + 2–4 uppercase letters + 3 digits (e.g. 'EBETT200').
    Used as software_version when no 1037xxxxxx string is present.

  VOLVO CALIBRATION ID  'B341CS3200'  'B079EWS304'
    Volvo OEM calibration identifier — Format C only.
    Found in a structured ident block at offset 0x7EC10.
    10-char alphanumeric ASCII string preceded by a 6-byte fixed header
    (02 04 02 0A 00 00), a 3-char short code, and a 3-byte separator.
    Used as calibration_id and match_key fallback when software_version
    is absent.

  TSW STRING          'TSW V2.40 280700 1718 C7/ESB/G40'
    Bosch Tool Software version string.
    Unique to EDC15 — not present in any other Bosch family.
    Contains the ECU variant code after the last slash (e.g. 'G40').
    Used as primary detection anchor in Format A and Format C bins.
    Format C TSW uses a different variant scheme: '15C11/G43/' instead
    of 'Cx/ESB/Gxx'.

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
    # NOT present in Format C (Volvo EDC15C3) or Format D (VP37/VP44) bins.
    # e.g. '1037366536'  '1037353311'  '1037351190'
    "software_version": rb"1037\d{6,10}",
    # ------------------------------------------------------------------
    # Format D — early EDC15 (VP37/VP44) alphanumeric SW code
    # ------------------------------------------------------------------
    # e.g. 'EBETT200', 'EBEWU100', 'EBBTM100'
    # Pattern: 2 uppercase letters ('EB') + 2-4 uppercase letters + 3 digits
    "alpha_sw_code": rb"(EB[A-Z]{2,4}\d{3})",
    # ------------------------------------------------------------------
    # TSW string — Format A / Format C detection and variant info
    # ------------------------------------------------------------------
    # Full TSW descriptor string.
    # e.g. 'TSW V2.40 280700 1718 C7/ESB/G40'   (Format A)
    #       'TSW V0.80 080102 0950 15C11/G43/'   (Format C — Volvo)
    #       TSW Vx.xx = tool version
    #       DDMMYY    = build date
    #       NNNN      = build number
    #       Cx        = ECU hardware variant code (Format A)
    #       15C11     = C166/C167 core designation (Format C)
    #       ESB       = Bosch internal project code
    #       G40/G43   = calibration dataset code
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
    # HW number at fixed offset 0x10046 in early EDC15 bins
    "hw_fixed_offset": slice(0x10040, 0x10060),
    # Volvo ident block — Format C (EDC15C3) calibration data at 0x7EC10
    # The structured block is 26 bytes: 6-byte header + 3-char short code
    # + 3-byte separator + 10-char calibration ID + 6-byte null padding.
    # We search a slightly wider window (0x7EC00–0x7ED00) for robustness.
    "volvo_ident_block": slice(0x7EC00, 0x7ED00),
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
# Volvo EDC15C3 ident block constants (Format C)
# ---------------------------------------------------------------------------
# The Volvo ident block is at a fixed offset (0x7EC10) in 512KB bins.
# It has a fixed 6-byte header followed by structured OEM data.
#
# Layout (starting at 0x7EC10):
#   Bytes 0–5:   02 04 02 0A 00 00   — fixed header
#   Bytes 6–8:   3-char ASCII short code (e.g. '762', '75v')
#   Bytes 9–11:  separator (variable binary, not ASCII)
#   Bytes 12–21: 10-char ASCII calibration ID (e.g. 'B341CS3200')
#   Bytes 22–27: null padding (00 00 00 00 00 00)
#
# The header bytes 02 04 02 0A are consistent across all observed Volvo
# EDC15C3 samples (S60, V70, XC90 D5 2.4D with HW 0281010319/0281011441).
# ---------------------------------------------------------------------------

VOLVO_IDENT_BLOCK_OFFSET: int = 0x7EC10

VOLVO_IDENT_BLOCK_HEADER: bytes = b"\x02\x04\x02\x0a"

# Offset of the 10-char calibration ID relative to the block start
# (i.e. relative to VOLVO_IDENT_BLOCK_OFFSET).
VOLVO_CAL_ID_OFFSET: int = 12  # bytes 12–21 within the block

VOLVO_CAL_ID_LENGTH: int = 10

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
    b"PPD",  # Siemens/VDO PPD diesel — NOT Bosch
    b"5WP",  # Siemens/VDO Simos part number prefix — NOT Bosch
    b"SIMOS",  # Siemens Simos family label — NOT Bosch
    b"Simos",  # Siemens Simos family label (mixed case) — NOT Bosch
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

# ---------------------------------------------------------------------------
# Format D detection constants
# ---------------------------------------------------------------------------
# Format D bins (early EDC15, VP37/VP44) have no TSW string and no
# 1037xxxxxx SW version. They use alphanumeric SW codes (e.g. 'EBETT200')
# embedded in structured ident blocks alongside the '0281xxxxxx' HW number.
#
# Detection: C3 fill ratio >= EDC15_MIN_C3_RATIO AND the structured ident
# pattern '0281xxxxxx' + alphanumeric SW code + 'HEX' suffix is present.
# ---------------------------------------------------------------------------

# Format D ident block pattern for early EDC15 (VP37/VP44)
# Matches the structured ident string containing OEM PN, engine, EDC, HW and alpha SW
# e.g. '074906018C  2,5l R5 EDC  SG  2520 28SA4060 0281010082 EBETT200HEX074906018C  0399'
EDC15_FORMAT_D_IDENT_RE: bytes = rb"(\w{9,12})\s+[\d,]+l\s+R\d\s+EDC\s+\w{2}\s+\d{4}\s+28SA\d{4}\s+(0281\d{6})\s+(EB[A-Z]{2,4}\d{3})HEX"

# ---------------------------------------------------------------------------
# Format E detection constants
# ---------------------------------------------------------------------------
# Format E bins are EDC15 C167-based ECUs (e.g. EDC15C5, EDC15C7) whose
# flash dumps have lower-than-usual 0xC3 fill (4.1–4.6%, below the 5%
# Format B threshold) because a larger portion of the flash is populated
# with calibration data.  They have NO TSW string at 0x8000.
#
# These bins are unambiguously identified by the conjunction of:
#   1. The Bosch C167 flash bootstrap header 'PP22..00' (bytes b'PP22..00')
#      present in the first 0x10000 bytes.  This 8-byte sequence is the
#      Infineon C167 program flash header written by the Bosch EDC15
#      bootstrap loader.  It has never been observed in any Siemens/VDO
#      (PPD, Simos) or other non-Bosch ECU binary.
#   2. A Bosch diesel HW number '0281xxxxxx' present anywhere in the file.
#   3. Either a '1037xxxxxx' Bosch SW version string OR a structured EDC
#      ident block containing 'Rx EDC' (engine-type + EDC label) is present.
#
# Additional safety: Siemens PPD, Simos and 5WP signatures are in the
# exclusion list (Phase 1) so any Siemens binary is rejected before
# reaching this phase.
#
# Real-world examples that match Format E:
#   VW Bora 1.9 TDI   0281001910  1037350172  (C3 ratio 4.3%)
#   VW Golf 4 1.9 TDI  0281010091  1037350875  (C3 ratio 4.5%)
#   VW Lupo 1.2 TDI   0281010258  1037352679  (C3 ratio 4.2%)
#   VW Passat 1.9 TDI  0281001691  1037350100  (C3 ratio 4.4%)
# ---------------------------------------------------------------------------

# The Bosch C167 flash bootstrap header — unique to EDC15 C167 flash images.
# Located at offset 4 in the binary (after 'UU\x00\x00' preamble), and
# repeated at the start of each flash bank (e.g. 0x8004, 0x78004).
EDC15_PP22_HEADER: bytes = b"PP22..00"

# Maximum offset to search for the PP22 header.  It typically appears at
# offset 4 in the binary (after the 'UU\x00\x00' preamble), but some
# dumps — e.g. VW Lupo 1.2 TDI — only have PP22 in the last flash bank
# header (at 0x78004).  Search the full 512KB to cover all bank positions.
EDC15_PP22_SEARCH_LIMIT: int = 0x80000

# Structured EDC ident block pattern (Format E) — matches the OEM ident
# string present in the flash data region.  Used as a secondary anchor
# when 1037xxxxxx SW is absent but the EDC ident block confirms the file
# is a Bosch EDC ECU.
# e.g. '038906019BJ 1,9l R4 EDC  SG  0812 0281010176 F8DJT600'
#       '045906019Q  1,2l R3 EDC  DS  0904 0281010258 F8EGJ300'
EDC15_FORMAT_E_IDENT_RE: bytes = (
    rb"\w{9,12}\s+[\d,]+l\s+R\d\s+EDC\s+\w{2}\s+\d{4}\s+0281\d{6}"
)
