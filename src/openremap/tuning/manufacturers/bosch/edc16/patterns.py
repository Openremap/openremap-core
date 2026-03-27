"""
Bosch EDC16 ECU binary identifier patterns and search regions.

Covers the Bosch EDC16 family:
  EDC16C8   — VW/Audi/Seat/Skoda 1.9 TDI and 2.4 JTD (2003–2006)
              e.g. Alfa 147/156/GT 1.9 JTDM, Alfa 156/166 2.4 JTD
  EDC16C39  — later variant, larger MCU (2005–2008)
              e.g. Alfa 159 2.4 JTDM, Alfa GT 1.9 JTD 150HP
  EDC16U1/U31 — VAG PD (Pumpe-Düse / unit-injector) engines (2004–2008)
              e.g. Audi A3/A4 1.9 TDI BKC/BKE, 2.0 TDI BKD (03G906016xx)
  EDC16C9   — Opel/GM Vectra-C, Signum, Astra-H diesel (2004–2006)
              e.g. Opel Vectra CDTI 120PS (0281013409, sw=1037A50286)
              active_start = 0xC0000; DECAFE at 0xC003D

EDC16 sits between EDC15 and EDC17 generationally:
  - CPU: Infineon TriCore TC1766 (C8) or TC1796 (C39/U-series)
  - No TSW string (that was EDC15-era toolchain only)
  - No SB_V, NR000, Customer. strings (those are EDC17+)
  - No 0xC3 fill (EDC15 characteristic) — fill byte is 0xFF
  - SW version stored as plain ASCII "1037xxxxxx" at a fixed offset
    within the active flash section (always active_start + 0x10)
  - HW number is NOT stored as plain ASCII anywhere in the binary
  - ECU family string embedded as slash-delimited descriptor when present:
    "EDC16C8/009/C277/ /110000_000/..."
    "EDC16C39/009/C456/ /010000_000/..."
    (absent in VAG PD variants — identified by layout alone)

Binary structure and file sizes:

  EDC16C8  — 1MB (0x100000 bytes), Alfa/VW common-rail:
    Header magic    : \xde\xca\xfe at 0x4003d and 0xe003d
                      (active_start + 0x3d)
    SW version      : Plain ASCII "1037xxxxxx" at 0x40010
                      (confirmed at 0xe0010 as second copy)
    ECU family str  : "EDC16C8/..." at ~0xe054b (varies slightly by tune)
    Active section  : starts at 0x40000 (last 768KB used)
    High fill       : 0xFF accounts for 70–90% of the file

  EDC16C39 — 2MB (0x200000 bytes), Alfa/VW common-rail:
    Header magic    : \xde\xca\xfe at 0x1c003d
    SW version      : Plain ASCII "1037xxxxxx" at 0x1c0010
    ECU family str  : "EDC16C39/..." at 0x1c0601 (fixed)
    Active section  : starts at 0x1c0000 (last 256KB used)
    High fill       : 0xFF accounts for 90%+ of the file

  EDC16C31/C35 — 2MB (0x200000 bytes), BMW diesel (E46/E60/E90 320d/120d/335d):
    Header magic    : \xde\xca\xfe at 0x4003d  (active_start=0x40000)
                      OR at 0xc003d (active_start=0xc0000, e.g. X6 30sd)
    SW version      : Plain ASCII "1037xxxxxx" at active_start + 0x10
    ECU family str  : "EDC16C31/..." or "EDC16C35/..." or "EDC16CP35/..."
    Active section  : starts at 0x40000 (most BMW C31/C35) or 0xc0000 (X6)
    High fill       : 0xFF accounts for 35–50% of the file
    Note            : physically the same MCU generation as C8/C39 but with
                      a BMW-specific flash sector map; the active section sits
                      at 0x40000 in the 2MB address space instead of 0x1c0000.

  EDC16 truncated — 983040 bytes (0xF0000 = 1MB - 64KB), BMW diesel:
    A 1MB EDC16C31/C35 image where the first 64KB boot sector was not
    captured by the read tool, leaving a file 64KB short of 1MB.
    Header magic    : \xde\xca\xfe at 0x3003d  (active_start=0x30000,
                      which maps to 0x40000 in the full 1MB address space)
    SW version      : Plain ASCII "1037xxxxxx" at 0x30010
    ECU family str  : "EDC16C31/..." or "EDC16C35/..."
    Active section  : starts at 0x30000 (= full-image 0x40000 minus 64KB)

  EDC16 VAG PD — 1MB (0x100000 bytes), Pumpe-Düse engines:
    Header magic    : \xde\xca\xfe at 0xd003d  (active_start + 0x3d)
                      Also mirrored at 0x3d and 0x8003d (boot/mirror sections)
    SW version      : Plain ASCII "1037xxxxxx" at 0xd0010
                      (active_start + 0x10); also mirrored at 0x10 and 0x80010
    ECU family str  : NOT present as plain ASCII in any observed PD bin
    Active section  : starts at 0xd0000
    Part numbers    : 03G906016xx (Audi A3/A4 1.9 TDI BKC/BKD/BKE, 2.0 TDI BKD)
    Distinction     : three DECAFE copies at 0x3d / 0x8003d / 0xd003d
                      (vs C8 which has copies at 0x3d / 0x8003d / 0xe003d)

  EDC16C9 — 1MB (0x100000 bytes), Opel/GM common-rail (Vectra-C/Signum/Astra-H):
    Header magic    : \xde\xca\xfe at 0xC003d  (active_start + 0x3d)
    SW version      : ASCII "1037xxxxxx" at 0xC0010; the 6-character suffix may
                      contain uppercase hex digits A–F (e.g. "1037A50286")
    ECU family str  : "EDC16C9/..." when present in calibration area
    Active section  : starts at 0xC0000
    DECAFE copies   : 0x3d / 0x8003d / 0xC003d
    Distinction     : third DECAFE copy at 0xC003d (vs C8 at 0xe003d,
                      PD at 0xd003d) is the Opel-layout discriminator

  EDC16 sector dump — 256KB (0x40000 bytes):
    A standalone calibration/active-section-only read. The file begins
    directly with the active section header — no prefix or padding.
    Header magic    : \xde\xca\xfe at 0x3d  (file start = active_start)
    SW version      : Plain ASCII "1037xxxxxx" at 0x10
    ECU family str  : not present in observed sector dumps
    Active section  : starts at 0x0 (entire file IS the active section)
    Observed for    : 03G906016xx part numbers (same PD engines as above,
                      different dump method — single-sector read only)

SW version offset formula (invariant across all layouts):
  active_start + 0x10  → SW version
  active_start + 0x3d  → \xde\xca\xfe magic

Both formats share the same "\xde\xca\xfe" header magic and the
"1037xxxxxx" SW format. The EDC16 family string, when present, is the
most authoritative source for the ecu_variant (e.g. "EDC16C8").

Pattern reference:

  SOFTWARE VERSION    "1037367333"  "1037383773"  "1037A50286"
    Bosch internal software calibration identifier.
    Format: 1037 + 6 alphanumeric characters (10 characters total).
    Stored as plain ASCII at active_start + 0x10 in every known variant.
    Note: the bytes immediately following the 10-character SW may be printable
    ASCII (e.g. "P379U8...") — the pattern must match exactly 6 characters
    after "1037" to avoid returning a 13-character false value.
    Note: Opel EDC16C9 bins use alphanumeric suffixes (uppercase hex
    digits A–F allowed), e.g. "1037A50286". Pattern uses [\\dA-Fa-f]{6,10}
    to cover both purely numeric and alphanumeric SW versions.
    The primary matching key.

  ECU FAMILY STRING   "EDC16C8/009/C277/..."
    Slash-delimited descriptor embedded in the calibration data area.
    The first token before the first slash is the ecu_variant.
    Not present in all bins (absent in VAG PD variants entirely).

  HARDWARE NUMBER     not stored as plain ASCII in any observed EDC16 binary.
    Always None — the HW number appears in the filename convention only.

Verified samples:
  Alfa 147 1.9JTDM 140HP  0281010455_1037367333.bin                       -> EDC16C8  sw=1037367333
  Alfa 159 2.4JTDM        0281013417_1037383773.bin                       -> EDC16C39 sw=1037383773
  A3 1.9TDI BKC           03G906016J_1037369261.bin                       -> EDC16 PD sw=1037369261
  A3 2.0TDI BKD           03G906016FF_1037370634.bin                      -> EDC16 PD sw=1037370634
  Opel Vectra CDTI 120PS  0281013409_1037A50286_Vectra_CDTI_120PS.bin     -> EDC16C9  sw=1037A50286
"""

from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # SW version — "1037"/"1039" + 6–10 alphanumeric hex characters
    # Stored as plain ASCII in both C8 and C39 bins at the fixed active offset.
    # [\dA-Fa-f] covers Opel EDC16C9 bins that use uppercase hex in the suffix
    # (e.g. "1037A50286") as well as all-numeric versions ("1037367333").
    # "1039" prefix covers PSA/Peugeot-Citroën EDC16C34 variants
    # (e.g. Peugeot 3008 1.6 HDI SW "1039398238").
    "software_version": rb"103[79][\dA-Fa-f]{6,10}",
    # ECU family slash-delimited descriptor
    # e.g. "EDC16C8/009/C277/ /110000_000/____________________/19810101/"
    #      "EDC16C39/009/C456/ /010000_000/____________________/19810101/"
    # The variant (first token) is extracted by the resolver.
    "ecu_family_string": rb"EDC16[A-Z0-9]+/[\w/_\- \.]{10,}",
    # Bare EDC16 family token — fallback when the full slash string is absent
    # Matches: EDC16C8  EDC16C39  EDC16U31  etc.
    "ecu_family": rb"EDC16[A-Z0-9]+",
}

# ---------------------------------------------------------------------------
# Fixed SW offsets by file size
# ---------------------------------------------------------------------------
# The SW version is always at active_section_start + 0x10.
# active_section_start is determined by the file size.
#
# Observed:
#   1MB (0x100000) — C8  : active_start = 0x40000
#   2MB (0x200000) — C39 : active_start = 0x1c0000
#
# The search region for SW is a tight 32-byte window around this offset
# to avoid false positives from "1037" substrings in code or calibration data.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Active section start offsets by file size
# ---------------------------------------------------------------------------
# Each EDC16 variant has its active (calibration) section at a fixed start.
# SW is always at active_start + 0x10; magic is at active_start + 0x3d.
#
# For 1MB bins FOUR layouts exist:
#   C8  layout : active_start = 0x40000  (DECAFE mirror at 0xe003d)
#   C9  layout : active_start = 0xc0000  (DECAFE at 0xc003d — Opel Vectra/Signum/Astra-H)
#   PD  layout : active_start = 0xd0000  (DECAFE mirror at 0x8003d / 0x3d)
#   C31 early  : active_start = 0x20000  (DECAFE at 0x2003d — BMW E46 320D M47TU, 2003–2005)
#                e.g. BMW 320D 150HP 0281010565 sw=1037361830
#                Family string near end of file at ~0x0fe63f ("EDC16C31/999/X000/...")
#
# Distinguishing C8 / C9 / PD / C31-early for 1MB bins:
#   C8       has DECAFE at 0xe003d  (0x40000 + 0xa0000 → +0x3d)
#   C9       has DECAFE at 0xc003d  (0xc0000 + 0x3d) — Opel-layout discriminator
#   PD       has DECAFE at 0xd003d  (0xd0000 + 0x3d) — NOT at 0xe003d
#   C31 early has DECAFE at 0x2003d  (0x20000 + 0x3d) — BMW E46-layout discriminator
#   C8 and C9 both have DECAFE at 0x3d and 0x8003d (boot/mirror sections).
#   The third copy position (0xe003d / 0xc003d / 0xd003d / 0x2003d) is the discriminator.
#
# ACTIVE_STARTS_BY_SIZE maps size → list of candidate active starts.
# The extractor tries each in order, accepting the first where DECAFE is
# present at active_start + 0x3d AND SW is readable at active_start + 0x10.
# ---------------------------------------------------------------------------

ACTIVE_STARTS_BY_SIZE: Dict[int, list] = {
    0x100000: [
        0x40000,
        0xC0000,
        0xD0000,
        0x20000,
    ],  # 1MB: C8 first, then C9 (Opel), then PD, then BMW E46 C31 early
    0x200000: [
        0x40000,
        0xC0000,
        0x1C0000,
    ],  # 2MB: BMW C31/C35 first, then X6, then Alfa C39 / PSA EDC16C34
    0x40000: [0x0000],  # 256KB sector dump: active section IS the file
    0xF0000: [0x30000],  # 983040: truncated C31/C35 (missing first 64KB)
}

# Legacy flat dicts kept for backward compatibility with extractor code
# that reads them directly. These reflect the primary (first-try) offsets only.
SW_OFFSET_BY_SIZE: Dict[int, int] = {
    0x100000: 0x40010,  # 1MB — C8 primary (PD handled via ACTIVE_STARTS_BY_SIZE)
    0x200000: 0x40010,  # 2MB — BMW C31/C35 primary (C39 handled via ACTIVE_STARTS_BY_SIZE)
    0x40000: 0x0010,  # 256KB sector dump
    0xF0000: 0x30010,  # 983040 truncated C31/C35
}

# Mirror SW offsets — secondary copy within same image.
# C8 1MB: mirrored at 0xe0010. PD 1MB: mirrored at 0x10 and 0x80010.
# For 256KB and truncated there is no mirror (single section).
SW_MIRROR_OFFSET_BY_SIZE: Dict[int, Optional[int]] = {
    0x100000: 0xE0010,  # 1MB C8 secondary copy (not valid for PD layout)
    0x200000: None,  # 2MB — ACTIVE_STARTS_BY_SIZE handles all candidates
    0x40000: None,  # 256KB — single section, no mirror
    0xF0000: None,  # 983040 truncated — single active section
}

# Window size around the fixed SW offset to search (covers 10-digit SW + slack)
SW_WINDOW: int = 16

# ---------------------------------------------------------------------------
# ECU family string search regions
# ---------------------------------------------------------------------------
# The EDC16 family string lives in the calibration data area of the active
# section. Searching the last 256KB (0x40000 bytes) covers C8, C9, C39, and
# VAG PD variants. For BMW EDC16C31/C35 2MB files the family string lives
# near the 0xC0000 mirror section (~0x0C06F3), outside the last-256KB window;
# the extractor handles this via Priority 2b in _resolve_ecu_variant() using
# a dynamically computed active-extended region (see "active_extended" below).
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # Last 256KB — EDC16 family string is always here in C8, C9, C39, VAG PD
    "cal_area": slice(-0x40000, None),
    # Full binary — used as last-resort SW fallback
    "full": slice(0x0000, None),
    # Active-extended — dynamically computed in extractor; documented here for reference.
    # For BMW C31/C35 2MB: active_start=0x40000, window=0x40000..0x140000
    # For BMW X6  C35 2MB: active_start=0xc0000,  window=0xc0000..0x1c0000
    # For Alfa C39     2MB: active_start=0x1c0000, window=0x1c0000..0x200000 (same as cal_area)
    # Not a real slice — the extractor builds data[active_start : active_start+0x100000].
    # "active_extended": <dynamically computed>,
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    # SW is extracted by fixed offset, not by region scan — these are fallbacks
    "software_version": "cal_area",
    # ECU family string is always in the calibration area
    "ecu_family_string": "cal_area",
    "ecu_family": "cal_area",
}

# ---------------------------------------------------------------------------
# Detection — header magic
# ---------------------------------------------------------------------------
# \xde\xca\xfe is a Bosch EDC16 header magic embedded in the active section
# header block. It appears at active_start + 0x3d in all observed bins:
#   1MB  C8  : 0x4003d  and mirrored at 0xe003d
#   2MB  C39 : 0x1c003d
#
# This 3-byte sequence does not appear in EDC15, ME7, EDC17 or M-series bins.
# It is the primary positive detection anchor for EDC16.
# ---------------------------------------------------------------------------

EDC16_HEADER_MAGIC: bytes = b"\xde\xca\xfe"

# Offsets where the magic must appear, indexed by file size
# Magic offsets per size — ALL known positions for each size.
# For detection we accept if ANY of these positions contains the magic.
# For layout discrimination the *third* copy position is the discriminator
# (see ACTIVE_STARTS_BY_SIZE above and extractor._detect_active_start()).
MAGIC_OFFSETS_BY_SIZE: Dict[int, list] = {
    0x100000: [
        0x4003D,
        0x8003D,
        0xC003D,
        0xD003D,
        0xE003D,
        0x2003D,  # BMW E46 320D EDC16C31 early layout (active_start=0x20000)
    ],  # 1MB: C8→0xe003d, EDC16C9 (Opel)→0xc003d, PD→0xd003d, BMW E46→0x2003d
    0x200000: [0x4003D, 0xC003D, 0x1C003D],  # 2MB: BMW C31/C35, X6, Alfa C39
    0x40000: [0x003D],  # 256KB sector dump
    0xF0000: [0x3003D],  # 983040 truncated C31/C35
}

# ---------------------------------------------------------------------------
# Detection — ECU family string bytes
# ---------------------------------------------------------------------------
# b"EDC16" as a direct bytes sequence is the strongest positive indicator
# after the magic check. Present in all observed bins except one partially
# erased dump (the mystery 0281010986 bin) where the cal area was wiped.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"EDC16",
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these are found in the first 512KB the binary is NOT EDC16.
# Guards against the EDC16 extractor claiming modern Bosch bins (EDC17,
# MEDC17) that share the "EDC16" substring as part of "EDC16..." in
# internal strings, and against EDC15 bins that share the 1037 SW prefix.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"SB_V",  # EDC17+ SW base version string — absent on EDC16
    b"NR000",  # EDC17+ serial number prefix — absent on EDC16
    b"Customer.",  # EDC17+ customer label — absent on EDC16
    b"ME7.",  # ME7 family string
    b"ME71",  # ME71 earliest variant
    b"MOTRONIC",  # ME7 label — absent on EDC16
    b"TSW ",  # EDC15 tool software string — absent on EDC16
]

# Supported file sizes — anything outside this set is rejected immediately.
#   0x100000 — 1MB      : EDC16C8, EDC16C9 (Opel) and EDC16 VAG PD
#   0x200000 — 2MB      : EDC16C39 (Alfa) and EDC16C31/C35 (BMW)
#   0x040000 — 256KB    : EDC16 sector/active-section-only dump
#   0x0F0000 — 983040   : EDC16C31/C35 truncated (missing first 64KB boot sector)
SUPPORTED_SIZES: set[int] = {0x100000, 0x200000, 0x40000, 0xF0000}
