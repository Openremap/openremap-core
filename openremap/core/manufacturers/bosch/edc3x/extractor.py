"""
Bosch EDC 3.x ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch EDC 3.x family:
  EDC3  — Early Bosch diesel ECUs (1993–2000), covering both VAG and non-VAG
           (BMW, etc.) applications of the same Bosch EDC 3.x hardware platform.

These are the generation *between* EDC1/EDC2 and EDC15. Two ident formats
exist depending on the vehicle manufacturer integration:

════════════════════════════════════════════════════════════════════════════
  FORMAT 1 — VAG ident block ("HEX" format)
════════════════════════════════════════════════════════════════════════════
  Used by: VAG TDI diesel ECUs (028906021xx, 038906018xx, 4B0907401xx, …)

  Two physically-distinct hardware sub-groups share the same ident layout:

    Group A — 256KB "VV33" binaries
      Files  : 028906021GC/GM/BD, 038906018BB/BA/AK
      Header : 0x0000 = 55 55 00 00 56 56 33 33 2e 2e  ("VV33..")
      Size   : always exactly 256KB (0x40000)
      Layout : dual-bank; active bank at 0x38000, secondary at 0x00000
      Ident  : approximately active_bank_start + 0x3056 (±500 bytes)

    Group B — 128KB / 512KB c3-fill binaries (no VV33 header at offset 0)
      Files  : 038906018AH (128KB), 4B0907401AA (128KB), 4B0907401AC (512KB)
      Header : 0x0000 area is 0xc3-filled, or begins with the alternate
               EDC3x header 55 00 56 33 2e 31 38 04 on some 128KB samples
      Sizes  : 128KB (0x20000) or 512KB (0x80000)
      Ident  : anywhere in the full binary (full-file regex scan)

  Ident block format (ASCII string in calibration area):

    [v]{OEM_PART}\\s+{displacement}[\\s/]{cylinders}\\s*EDC\\s+{SG|AG}\\s+{build}\\s+{HW_0281}\\s+{dataset}HEX{OEM_PART}\\s+{date}

  Real examples:
    v028906021GM 1,9l R4 EDC  SG  1421 0281001658 C86BM500HEX028906021GM 1096
    v028906021GC 1,9l R4 EDC  SG  1408 0281001668 C86CMK34HEX028906021GC 0397
    v038906018BA 1,9l R4 EDC  SG  1812 0281001756 E93DT200HEX038906018BA 0697
    4B0907401AC 2.5l/4VTEDC  AG  D62  0281010399 A15CEHK2HEX4B0907401AC 1299

  Fields extracted:
    OEM part number : first token, leading 'v' stripped  e.g. "028906021GM"
    HW number       : "0281xxxxxx" token                 e.g. "0281001658"
    Dataset code    : token immediately before "HEX"     e.g. "C86BM500"
      → returned as software_version (no 1037/2287 number exists here)

════════════════════════════════════════════════════════════════════════════
  FORMAT 2 — BMW numeric ident block ("5331xx" / "3150" format)
════════════════════════════════════════════════════════════════════════════
  Used by: BMW diesel ECUs of the same EDC 3.x hardware generation
           e.g. BMW 320D / E46 (0281001445), split-ROM chips (0281010205)

  Two sub-formats exist depending on the physical flash configuration:

    Sub-format 2A — 256KB single-chip BMW bins
      Size   : 256KB (0x40000)
      Fill   : 0xC3 (~20–25% of file)
      Header : no VV33 at offset 0; VV33..11 appears at 0x38004 (mid-file)
      SW block (at ~0x37fb0, surrounded by 0xC3 fill, terminated by U\\xaa):
               \\xc3{2+} [0+]{5331XX}x3  [0+]  {7-digit-cal}x6  U\\xaa
        - "5331XX" is a 6-char Bosch internal SW revision code (e.g. "5331A1",
          "5331C5"). It is stored three times with varying leading-zero padding.
        - The 7-digit calibration number immediately follows, repeated 6 times.
        - Sentinel: the ASCII bytes 'U' (0x55) followed by 0xAA.
      HW number : plain ASCII "0281xxxxxx" stored in the calibration tail region
                  (e.g. at ~0x3fc53), NOT in the SW block itself.

    Sub-format 2B — 128KB split-ROM chips (HI or LO)
      Size   : 128KB (0x20000) each chip; two chips together form the full ROM
      Fill   : 0xC3 (~21% of file)
      Header : ALT_VV33 (55 00 56 33 2e …) appears at 0x1c000 (mid-file, not
               at offset 0), so Phase 4 header-magic fallback does NOT trigger.
               Detection falls through to Phase 5 (0xC3 ratio > 15%).
      SW block (at ~0x1bfd8, surrounded by 0xC3 fill, terminated by UU or \\xaaU):
        HI chip: \\xc3{2+} [0+]{3150}x3  {7-digit-cal}x3  [\\xaaU]{2}
          - SW code "3150" (4 chars), cal e.g. "7687887"
        LO chip: \\xc3{2+} [0+]{53XX}x3  {7-digit-cal}x3  [UU]
          - SW code "53C0" (4 chars), cal reflects LO address space (e.g.
            "7887768" — a rotated/different view of the same ROM cal number)
      HW number : NOT stored as plain ASCII in either chip (only in filename).

  SW version strategy for Format 2:
    software_version = the 7-digit calibration number as stored in the binary
    (e.g. "7785098", "7786887", "7687887", "7887768").
    The internal "5331XX" code is returned as ecu_variant.
    No 1037/2287/2537 SW number exists in any EDC 3.x binary.

════════════════════════════════════════════════════════════════════════════
  FORMAT 3 — Opel calibration block
════════════════════════════════════════════════════════════════════════════
  Used by: Opel diesel ECUs (Astra/Vectra era), same EDC 3.x hardware platform
           e.g. 0281001634 (LLL/HHH chip variants, 001632h/001632l chips)

  The 7-digit calibration number is stored in the ident region and anchored
  by specific sentinel bytes immediately preceding the ASCII 'U' (0x55) byte:

    Pattern: (?:\\xff{4,}|\\xaa)U([A-Z]{1,2})(\\d{7})

  Where 0x55 (ASCII 'U') is the literal anchor, followed by 1–2 uppercase
  letters forming the internal SW code/bank designator, then the 7-digit
  calibration number directly.

  Real examples (from binary inspection):
    LLL chip: \\xff{7} U A 0770164 Loq^   (cal = "0770164", SW code = "A")
    HHH chip: \\xff{14} \\xaa U A A 0077770 0117733 ...
                                         (cal = "0770164", SW code = "A")

  Fields extracted:
    SW code (group 1)      : 1–2 uppercase letters  → ecu_variant
    Calibration (group 2)  : 7-digit number          → software_version
    HW number              : recovered via re.search(rb'0281\\d{6}', data)
                             → hardware_number (if present in binary)
    oem_part               : always None (not stored in this format)

  Detection: Opel EDC3 bins pass the Phase 5 (0xC3 fill ratio > 15%) check.
  The ident parser (Format 3) is invoked as a third fallback in extract()
  only when both VAG (Format 1) and BMW (Format 2) parsers find nothing.

════════════════════════════════════════════════════════════════════════════
  Detection strategy (five phases, shared across all formats)
════════════════════════════════════════════════════════════════════════════

  Phase 1 — Size gate.
             File must be exactly 128KB, 256KB, or 512KB. Any other size is
             rejected without scanning any bytes.

  Phase 2 — Exclusion check.
             Reject if any EXCLUSION_SIGNATURES byte string appears anywhere.
             Guards against EDC15 (TSW/SB_V/"EDC15"), ME7 ("ME7."/"MOTRONIC"),
             M5.x ("M5."/"MOTR"), M3.x ("1350000M3"/"1530000M3"), EDC16/EDC17.

  Phase 2b — EDC15 Format-B SW prefix check.
              Reject if "1037" appears anywhere — EDC3x pre-dates this scheme.

  Phase 3 (primary) — VAG ident pattern (IDENT_PATTERN_VAG).
              Full-binary regex scan. Covers all VAG bins with intact cal area.

  Phase 3b (primary) — BMW numeric ident pattern (IDENT_PATTERN_BMW_256 or
              IDENT_PATTERN_BMW_128). Full-binary scan for the 5331XX/3150
              repeating-block format. Covers all BMW bins with intact SW block.

  Phase 4 (fallback A) — EDC3x header magic at offset 0.
              VV33_MAGIC or ALT_VV33_MAGIC at data[:10]/data[:5]. Covers
              128KB bins whose cal area is absent but header is intact.
              NOTE: BMW 128KB split-ROM chips have ALT_VV33 mid-file (at
              0x1c000), not at offset 0, so this phase does NOT catch them.

  Phase 5 (fallback B) — High 0xC3 fill ratio (> 15%).
              Covers any remaining 128KB or 256KB bin that passed the size gate
              and exclusions but has no readable ident in either format. This
              is the catch-all for BMW 256KB bins and BMW 128KB split-ROM chips
              (both detected via c3-fill since their header is mid-file).

════════════════════════════════════════════════════════════════════════════
  Verified across all sample bins
════════════════════════════════════════════════════════════════════════════

  VAG (Format 1):
    028906021GC  0281001668  C86CMK34    EDC3  256KB (VV33 at offset 0)
    028906021GM  0281001658  C86BM500    EDC3  256KB (VV33 at offset 0)
    028906021BD  0281001439  C4GBM100    EDC3  256KB (VV33 at offset 0)
    038906018BB  0281001757  E93DM300    EDC3  256KB (VV33 at offset 0)
    038906018BA  0281001756  E93DT200    EDC3  256KB (VV33 at offset 0)
    038906018AK  0281001728  E93DU400    EDC3  256KB (no VV33, VAG ident ok)
    038906018AH  0281001693  —           EDC3  128KB (alt-VV33 at offset 0)
    4B0907401AA  0281010154  —           EDC3  128KB (c3-fill, no ident)
    4B0907401AC  0281010399  A15CEHK2    EDC3  512KB (c3-fill, VAG ident ok)

  BMW (Format 2):
    0281001445  5331A1  7785098  EDC3  256KB (c3-fill, BMW 5331xx block)
    0281001445  5331C5  7786887  EDC3  256KB (c3-fill, BMW 5331xx block)
    0281010205  3150    7687887  EDC3  128KB HI chip (c3-fill, 3150 block)
    0281010205  53C0    7887768  EDC3  128KB LO chip (c3-fill, 53xx block)

  Opel (Format 3):
    0281001634 LLL  A  0770164  EDC3  128KB (Opel Format 3, c3-fill)
    0281001634 HHH  A  0770164  EDC3  128KB (Opel Format 3, c3-fill)
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from openremap.core.manufacturers.base import (
    EXCLUSION_CLEAR,
    FILL_PATTERN,
    IDENT_BLOCK,
    MAGIC_MATCH,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# 128KB — Group B VAG (038906018AH, 4B0907401AA) and BMW split-ROM chips
# 256KB — Group A VAG "VV33" bins and BMW single-chip 256KB bins
# 512KB — Group B VAG large bins (4B0907401AC)
# ---------------------------------------------------------------------------

SUPPORTED_SIZES: frozenset[int] = frozenset({0x20000, 0x40000, 0x80000})

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: List[bytes] = [
    b"EDC15",  # EDC15 explicit family string
    b"EDC16",  # EDC16 explicit family string
    b"EDC17",  # EDC17 explicit family string
    b"ME7.",  # ME7 petrol family string
    b"SB_V",  # EDC15/EDC16 base-software version tag
    b"MOTRONIC",  # ME7 / M-series calibration area label
    b"1350000M3",  # M3.1 family marker
    b"1530000M3",  # M3.3 family marker
    b"M5.",  # M5.x family string
    b"MOTR",  # M5.x / M3.8x ident-block anchor
]

# ---------------------------------------------------------------------------
# EDC15 Format-B SW prefix exclusion
# ---------------------------------------------------------------------------
# EDC3x ROMs pre-date the 1037 SW numbering scheme entirely.
# Its presence always signals a Format-B EDC15 (or later) binary.
# ---------------------------------------------------------------------------

EDC15_SW_PREFIX: bytes = b"1037"

# ---------------------------------------------------------------------------
# VV33 / alternate-VV33 header magic
# ---------------------------------------------------------------------------
# VV33_MAGIC     — standard 256KB Group A header at offset 0 (bytes 0–9):
#   55 55 00 00 56 56 33 33 2e 2e
#
# ALT_VV33_MAGIC — alternate 128KB Group B header at offset 0 (bytes 0–4):
#   55 00 56 33 2e
#   Observed on 038906018AH 128KB single-bank VAG reads.
#   NOTE: BMW 128KB split-ROM chips also carry this magic but at 0x1c000
#   (mid-file), NOT at offset 0, so the Phase 4 offset-0 check correctly
#   does NOT trigger for them — they fall through to Phase 5 (c3-fill).
# ---------------------------------------------------------------------------

VV33_MAGIC: bytes = b"\x55\x55\x00\x00\x56\x56\x33\x33\x2e\x2e"
ALT_VV33_MAGIC: bytes = b"\x55\x00\x56\x33\x2e"

# ---------------------------------------------------------------------------
# 0xC3 fill detection threshold (Phase 5 fallback)
# ---------------------------------------------------------------------------
# EDC3x ROMs use 0xC3 as the erased/blank fill byte.
# Observed ratios:
#   VAG c3-fill bins         : 19–29%
#   BMW 256KB bins           : 21–24%
#   BMW 128KB split-ROM chips: ~21%
#   EDC15 Format-B bins      : 5–35% (excluded earlier by 1037 prefix check)
#   Other Bosch families     : < 5%
# ---------------------------------------------------------------------------

C3_FILL_THRESHOLD: float = 0.15

# ---------------------------------------------------------------------------
# VAG ident block regex (Format 1 — "HEX" format)
# ---------------------------------------------------------------------------
# Matches the structured ASCII ident string in VAG calibration areas.
#
# Capture groups:
#   1 : OEM part number  e.g. "028906021GM" / "4B0907401AC"
#   2 : HW number        e.g. "0281001658"  / "0281010399"
#   3 : dataset code     e.g. "C86BM500"    / "A15CEHK2"
# ---------------------------------------------------------------------------

IDENT_PATTERN_VAG: bytes = (
    rb"v?([0-9][A-Z0-9]{6,14})\s+"
    rb"[\d,\.]+l[\s/]\S*?\s*"
    rb"EDC\s+(?:SG|AG)\s+\S+\s+"
    rb"(0281\d{6})\s+"
    rb"([A-Z0-9]{6,12})HEX"
)

# ---------------------------------------------------------------------------
# BMW numeric ident block — literal anchors + windowed regexes
# ---------------------------------------------------------------------------
# Full-file regex scans over 0xC3-heavy binaries cause catastrophic
# backtracking: the engine tries every \xc3{2,} run (tens of thousands in a
# 256KB file) and at each one attempts to advance through digit groups to the
# sentinel.  On a 256KB BMW bin this takes ~3 seconds per pattern.
#
# The fix is a two-step approach:
#   1. bytes.find() — O(n) literal search for a unique byte sequence that
#      anchors the start of the SW block.  This takes < 0.2 ms on any size.
#   2. re.search() — applied only to a small fixed-size window (120 bytes)
#      starting just before the found anchor.  The regex can no longer
#      wander across the file, so it completes in microseconds.
#
# Sub-format 2A anchor — 256KB BMW single-chip bins (e.g. 0281001445):
#   The SW block always starts with at least two 0xC3 bytes immediately
#   followed by the ASCII string "00005331".  This 10-byte sequence is
#   unique: "5331" does not appear in any VAG EDC3x bin, and the 0xC3
#   prefix prevents false matches against code bytes.
#
# Sub-format 2B anchor — 128KB BMW split-ROM chips (e.g. 0281010205):
#   The HI chip uses "003150" repeated; the LO chip uses "0053C0" (or
#   similar "53xx" code).  The literal anchor is two 0xC3 bytes followed
#   by "003150" (HI) or "0053" (LO — broader, still unique in context).
#
# Window size: 120 bytes is sufficient to contain the full SW block
# (3 × code + separator + first cal occurrence + sentinel) in all observed
# samples.  A generous upper bound avoids truncation on future variants.
#
# ---------------------------------------------------------------------------
# Sub-format 2A (256KB, "5331xx"):
#   Anchor : b"\xc3\xc300005331"
#   Window : data[anchor_idx : anchor_idx + 120]
#   Regex  : captures SW code (group 1) and 7-digit cal number (group 2)
#            from within the already-anchored window.
# ---------------------------------------------------------------------------

BMW_256_ANCHOR: bytes = b"\xc3\xc300005331"

IDENT_PATTERN_BMW_256: re.Pattern = re.compile(
    rb"\xc3{2,}"
    rb"(?:0+)(5331[A-Z0-9]{2})"  # SW code x1
    rb"(?:0+)5331[A-Z0-9]{2}"  # SW code x2 (same, uncaptured)
    rb"(?:0+)5331[A-Z0-9]{2}"  # SW code x3 (same, uncaptured)
    rb"0{1,4}"  # separator zeros
    rb"(\d{7})"  # 7-digit calibration number (first occurrence)
    rb"\d+"  # remaining repetitions — greedy, safe within bounded window
    rb"U\xaa"  # sentinel
)

# ---------------------------------------------------------------------------
# Sub-format 2B (128KB, "3150" / "53xx"):
#   Anchor HI : b"\xc3\xc3003150"
#   Anchor LO : b"\xc3\xc30053"
#   Window    : data[anchor_idx : anchor_idx + 120]
#   Regex     : captures SW code (group 1) and 7-digit cal number (group 2).
# ---------------------------------------------------------------------------

BMW_128_ANCHOR_HI: bytes = b"\xc3\xc3003150"
BMW_128_ANCHOR_LO: bytes = b"\xc3\xc30053"

IDENT_PATTERN_BMW_128: re.Pattern = re.compile(
    rb"\xc3{2,}"
    rb"(?:0*)(3150|53[0-9A-F]{2})"  # SW code x1
    rb"(?:0*)(?:3150|53[0-9A-F]{2})"  # SW code x2 (uncaptured)
    rb"(?:0*)(?:3150|53[0-9A-F]{2})"  # SW code x3 (uncaptured)
    rb"(\d{7})"  # 7-digit calibration number (first occurrence)
    rb"\d+"  # remaining repetitions — greedy, safe within bounded window
    rb"[\xaaU]{2}"  # sentinel
)

# ---------------------------------------------------------------------------
# Opel calibration block regex (Format 3)
# ---------------------------------------------------------------------------
# Matches the Opel-style ident embedded in 128KB/256KB c3-fill bins.
#
# The calibration number and SW code/bank designator are anchored by a run
# of 0xFF bytes (≥ 4) or a single 0xAA byte, immediately followed by the
# ASCII 'U' (0x55) sentinel.
#
# Capture groups:
#   1 : SW code / bank designator  e.g. "A"       (1–2 uppercase letters)
#   2 : 7-digit calibration number e.g. "0770164"
#
# Real observations (two sentinel variants):
#   LLL chip: ... \xff{7} U  A  0770164 Loq^
#             sentinel = \xff{4+} U  (U is part of the sentinel)
#             group 1  = A  (SW code)
#             group 2  = 0770164
#
#   HHH chip: ... \xff{7} \xaa  A  0770164 Hiq_
#             sentinel = \xaa  (no U; \xaa precedes the SW code directly)
#             group 1  = A  (SW code)
#             group 2  = 0770164
#
# The alternation (?:\xff{4,}U|\xaa) handles both sentinel styles:
#   - \xff{4,}U  matches the LLL/LO-chip sentinel ending with ASCII 'U'
#   - \xaa       matches the HHH/HI-chip sentinel byte 0xAA
# ---------------------------------------------------------------------------

IDENT_PATTERN_OPEL: re.Pattern = re.compile(rb"(?:\xff{4,}U|\xaaU?)([A-Z]{1,2})(\d{7})")

# ---------------------------------------------------------------------------
# Opel 256KB doubled-char ident block (Format 4)
# ---------------------------------------------------------------------------
# Opel diesel 256KB bins store the calibration code in a doubled-char block
# at ~0x10020:
#   each ASCII char appears twice → de-double every 2 bytes
#   Format: [letter×2][digit×2]{7} → sw_code=letter, cal_id=7 digits
#
# Two sentinel variants exist depending on the ECU toolchain:
#   \x55\xaa  — bins with TSW at 0xC000 (Frontera / Vectra / Zafira early)
#   \xaa\x55  — bins with "ST W" at 0xC000 (Astra 2.0DTI, 0281001874)
# Both are accepted via the alternation (?:\x55\xaa|\xaa\x55).
#
# Regex uses back-references to enforce doubling:
#   group 1 = sw_code letter   groups 2–8 = individual cal digits
#
# Real examples:
#   0281001633 → 55 aa 41 41 30 30 37 37 37 37 30 30 31 31 36 36 34 34
#                → sentinel \x55\xaa  sw_code=A  cal=0770164
#   0281010026 → 55 aa 41 41 30 30 37 37 37 37 30 30 31 31 37 37 33 33
#                → sentinel \x55\xaa  sw_code=A  cal=0770173
#   0281001874 → aa 55 41 41 30 30 37 37 37 37 30 30 31 31 37 37 33 33
#                → sentinel \xaa\x55  sw_code=A  cal=0770173
# ---------------------------------------------------------------------------
IDENT_PATTERN_OPEL_256: re.Pattern = re.compile(
    rb"(?:\x55\xaa|\xaa\x55)"
    rb"([A-Z])\1"  # doubled letter prefix      → group 1
    rb"([A-Z0-9])\2"  # doubled cal char 1          → group 2
    rb"([A-Z0-9])\3"  # doubled cal char 2          → group 3
    rb"([A-Z0-9])\4"  # doubled cal char 3          → group 4
    rb"([A-Z0-9])\5"  # doubled cal char 4          → group 5
    rb"([A-Z0-9])\6"  # doubled cal char 5          → group 6
    rb"([A-Z0-9])\7"  # doubled cal char 6          → group 7
    rb"([A-Z0-9])\8"  # doubled cal char 7 (may be letter e.g. 'B') → group 8
)

OPEL_256_TSW_REGION: slice = slice(0xBFC0, 0xC040)

# ---------------------------------------------------------------------------
# Raw-strings region: last 512 bytes
# ---------------------------------------------------------------------------
RAW_STRINGS_TAIL: int = 512

# ---------------------------------------------------------------------------
# Split-ROM chip detection (16-bit paired chips)
# ---------------------------------------------------------------------------
# Some EDC3 ECUs use paired 128KB ROM chips (HI + LO) for a 16-bit data bus.
# Each chip alone contains only every other byte of the full 256KB ROM, so
# ASCII ident data spanning both bytes is unreadable from a single chip.
#
# Each chip carries a chip-specific marker near offset 0x8010:
#   \x55 A030024G Lo E    — LO chip (low-byte)
#   \xaa A030024G Hi E    — HI chip (high-byte)
#
# The marker format: [sentinel] [part_number] [Lo|Hi] [qualifier]
# ---------------------------------------------------------------------------
SPLIT_ROM_CHIP_PATTERN: re.Pattern = re.compile(
    rb"[\x55\xaa]([A-Z0-9]{6,10})(Lo|Hi|LO|HI|lo|hi)"
)


class BoschEDC3xExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch EDC 3.x ECU binaries.

    Handles VAG, BMW and Opel diesel ROMs from the 1993–2000 era.

    Three ident formats are supported:
      Format 1 — VAG "HEX" block (IDENT_PATTERN_VAG)
      Format 2 — BMW numeric block (IDENT_PATTERN_BMW_256 / IDENT_PATTERN_BMW_128)
      Format 3 — Opel calibration block (IDENT_PATTERN_OPEL)

    Detection uses up to five phases (see module docstring for full detail).
    """

    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["EDC3"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch EDC 3.x ECU ROM.

        Phase 1 — Size gate: 128KB / 256KB / 512KB only.
        Phase 2 — Exclusion: no EDC15 / ME7 / M5.x / EDC16 / EDC17 markers.
        Phase 2b — No 1037 SW prefix (EDC15 Format-B guard).
        Phase 2c — No Format-D EDC15 ident (alpha SW + HEX guard).
                   Rejects early EDC15 VP37/VP44 bins that carry alphanumeric
                   SW codes (e.g. 'EBETT200') instead of 1037 prefixes.
                   Without this guard those bins slip past Phase 2b and
                   get falsely claimed via the Phase 5 C3 fill catch-all.
        Phase 3 — Primary: VAG ident pattern (HEX block) anywhere in binary.
        Phase 3b — Primary: BMW numeric ident pattern (5331xx or 3150 block).
        Phase 4 — Fallback A: EDC3x header magic at offset 0.
        Phase 5 — Fallback B: high 0xC3 fill ratio (> 15%).
        """
        evidence: list[str] = []

        # Phase 1 — size gate
        if len(data) not in SUPPORTED_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 2 — exclusion check
        for excl in EXCLUSION_SIGNATURES:
            if excl in data:
                self._set_evidence()
                return False

        # Reject if TSW appears at the EDC15 Format-A offset — those are EDC15
        # bins, not EDC3x.  TSW at other offsets (e.g. 0xC000 Opel variant) is
        # acceptable and will be positively detected in Phase 6 below.
        if b"TSW" in data[0x7FC0:0x8060]:
            self._set_evidence()
            return False

        # Phase 2b — reject Format-B EDC15 bins that carry a 1037 SW number
        if EDC15_SW_PREFIX in data:
            self._set_evidence()
            return False

        # Phase 2c — reject Format-D EDC15 bins (early VP37/VP44) that carry
        # alphanumeric SW codes (e.g. 'EBETT200') instead of 1037 prefixes.
        # These bins have high 0xC3 fill (33–48%) and slip past Phase 2b,
        # so without this guard they fall through to Phase 5 (C3 fill
        # catch-all) and get falsely claimed as EDC3x.
        if re.search(rb"0281\d{6}\s+EB[A-Z]{2,4}\d{3}HEX", data):
            self._set_evidence()
            return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 3 — primary: VAG ident pattern
        vag_match = re.search(IDENT_PATTERN_VAG, data)
        if vag_match:
            oem, hw, dataset = (
                vag_match.group(1),
                vag_match.group(2),
                vag_match.group(3),
            )
            if oem and hw and dataset:
                evidence.append(IDENT_BLOCK)
                self._set_evidence(evidence)
                return True

        # Phase 3b — primary: BMW numeric ident patterns (windowed, fast)
        if self._find_bmw_sw_block(data) is not None:
            evidence.append(IDENT_BLOCK)
            self._set_evidence(evidence)
            return True

        # Phase 4 — fallback A: EDC3x header magic at offset 0
        if data[:10] == VV33_MAGIC or data[:5] == ALT_VV33_MAGIC:
            evidence.append(MAGIC_MATCH)
            self._set_evidence(evidence)
            return True

        # Phase 5 — fallback B: high 0xC3 fill ratio
        c3_ratio = data.count(b"\xc3") / len(data)
        if c3_ratio >= C3_FILL_THRESHOLD:
            evidence.append(FILL_PATTERN)
            self._set_evidence(evidence)
            return True

        # Phase 6 — Opel 256KB: TSW at 0xC000 (pre-EDC15 Opel toolchain)
        if len(data) == 0x40000 and b"TSW" in data[OPEL_256_TSW_REGION]:
            evidence.append("OPEL_TSW")
            self._set_evidence(evidence)
            return True

        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch EDC 3.x binary.

        Tries the VAG ident parser first, then the BMW ident parser, then
        the Opel ident parser. When all three fail (fallback-detected bins
        with no parseable ident), identification fields are returned as None.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # Raw ASCII strings from the last 512 bytes
        tail_region = slice(max(0, len(data) - RAW_STRINGS_TAIL), len(data))
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=tail_region,
            min_length=6,
            max_results=20,
        )

        result["ecu_family"] = "EDC3"
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["calibration_id"] = None

        # Try VAG ident first (Format 1)
        oem_part, hardware_number, software_version, ecu_variant = (
            self._parse_ident_vag(data)
        )

        # Fall back to BMW ident (Format 2) if VAG produced nothing
        if software_version is None and hardware_number is None:
            oem_part, hardware_number, software_version, ecu_variant = (
                self._parse_ident_bmw(data)
            )

        # Try Format 4 (Opel 256KB doubled-char) BEFORE Format 3.
        # Format 3's IDENT_PATTERN_OPEL can accidentally match the raw
        # doubled bytes (the \xaa\x55 sentinel at 0x10020 triggers
        # \xaaU? in the pattern) and return a corrupted cal ID such as
        # "0077770" instead of the correct de-doubled "0770173".
        # Format 4 is tried first for all files once VAG and BMW fail —
        # its back-reference regex is specific enough to avoid false
        # positives on BMW or VAG bins whose ident sits outside the
        # 0x10000–0x10100 window.  This replaces the old TSW-at-0xC000
        # routing that missed bins with "ST W" at 0xC000.
        if software_version is None and hardware_number is None:
            oem_part, hardware_number, software_version, ecu_variant = (
                self._parse_ident_opel_256(data)
            )

        # Fall back to Opel simple cal block (Format 3) if Format 4 also
        # found nothing (128KB split-ROM chips and other non-256KB Opel bins).
        if software_version is None and hardware_number is None:
            oem_part, hardware_number, software_version, ecu_variant = (
                self._parse_ident_opel(data)
            )

        # If no ident was found by any parser, check if this is a split-ROM chip.
        # Split-ROM chips contain only half the data (every other byte) so the
        # ASCII ident is unreadable, but we can identify the chip itself.
        if software_version is None and hardware_number is None:
            chip_part, chip_type = self._detect_split_rom_chip(data)
            if chip_part is not None:
                ecu_variant = f"split-ROM-{chip_type}"
                # Store the chip part number as a reference
                oem_part = chip_part

        result["oem_part_number"] = oem_part
        result["hardware_number"] = hardware_number
        result["software_version"] = software_version
        result["ecu_variant"] = ecu_variant

        result["match_key"] = self.build_match_key(
            ecu_family="EDC3",
            ecu_variant=None,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — VAG ident parser (Format 1)
    # -----------------------------------------------------------------------

    def _parse_ident_vag(
        self, data: bytes
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Parse the VAG-style "HEX" ident block.

        Returns (oem_part, hardware_number, software_version, ecu_variant).
        ecu_variant is always None for VAG bins (no internal code stored).
        Returns (None, None, None, None) if the pattern is not found.
        """
        match = re.search(IDENT_PATTERN_VAG, data)
        if not match:
            return None, None, None, None

        def _decode(idx: int) -> Optional[str]:
            raw = match.group(idx)
            if not raw:
                return None
            s = raw.decode("ascii", errors="ignore").strip()
            return s if s else None

        oem_part = _decode(1)
        hardware_number = _decode(2)
        dataset_code = _decode(3)

        return oem_part, hardware_number, dataset_code, None

    # -----------------------------------------------------------------------
    # Internal — BMW SW block finder (fast, anchor-based)
    # -----------------------------------------------------------------------

    def _find_bmw_sw_block(self, data: bytes) -> Optional[re.Match]:
        """
        Locate and match the BMW numeric SW block using a two-step strategy:

          1. bytes.find() on a unique literal anchor — O(n), < 0.2 ms on any
             supported file size.  Returns immediately if the anchor is absent,
             so non-BMW bins pay only the cost of a single failed find().

          2. re.search() on a 120-byte window starting at the anchor —
             the regex cannot wander across the file, eliminating the
             catastrophic backtracking that made full-file scans take ~3 s
             on 0xC3-heavy 256KB bins.

        Tries sub-format 2A (256KB, anchor b"\\xc3\\xc300005331") first,
        then sub-format 2B HI (anchor b"\\xc3\\xc3003150"), then 2B LO
        (anchor b"\\xc3\\xc30053").

        Returns the re.Match object on success, or None if no BMW SW block
        is found.
        """
        # Sub-format 2A — 256KB BMW single-chip bins
        idx = data.find(BMW_256_ANCHOR)
        if idx >= 0:
            m = IDENT_PATTERN_BMW_256.search(data, idx, idx + 120)
            if m:
                return m

        # Sub-format 2B — 128KB HI chip ("003150" anchor)
        idx = data.find(BMW_128_ANCHOR_HI)
        if idx >= 0:
            m = IDENT_PATTERN_BMW_128.search(data, idx, idx + 120)
            if m:
                return m

        # Sub-format 2B — 128KB LO chip ("0053xx" anchor)
        idx = data.find(BMW_128_ANCHOR_LO)
        if idx >= 0:
            m = IDENT_PATTERN_BMW_128.search(data, idx, idx + 120)
            if m:
                return m

        return None

    # -----------------------------------------------------------------------
    # Internal — BMW ident parser (Format 2)
    # -----------------------------------------------------------------------

    def _parse_ident_bmw(
        self, data: bytes
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Parse the BMW-style numeric ident block (Format 2).

        Delegates to _find_bmw_sw_block() for the fast anchor+window match,
        then extracts SW code (ecu_variant) and 7-digit cal number
        (software_version) from the match groups.

        The HW number (0281xxxxxx) is NOT embedded in the BMW SW block —
        it is stored as plain ASCII elsewhere in the calibration tail.
        A single re.search() over the full binary recovers it.

        For split-ROM LO chips (code "53C0") the calibration number reflects
        only the LO address space and will differ from the HI chip's value.
        Both are valid — software_version is whatever the chip itself stores.

        Returns (oem_part, hardware_number, software_version, ecu_variant).
        oem_part is always None (not embedded in BMW format).
        Returns (None, None, None, None) if no BMW SW block is found.
        """
        m = self._find_bmw_sw_block(data)
        if m is None:
            return None, None, None, None

        sw_code = m.group(1).decode("ascii", errors="ignore").strip()
        cal_number = m.group(2).decode("ascii", errors="ignore").strip()

        if not sw_code or not cal_number:
            return None, None, None, None

        # Recover HW number: first plain ASCII "0281xxxxxx" in the binary
        hardware_number: Optional[str] = None
        hw_match = re.search(rb"0281\d{6}", data)
        if hw_match:
            hardware_number = hw_match.group(0).decode("ascii", errors="ignore")

        return None, hardware_number, cal_number, sw_code

    # -----------------------------------------------------------------------
    # Internal — Opel 256KB doubled-char ident parser (Format 4)
    # -----------------------------------------------------------------------

    def _parse_ident_opel_256(
        self, data: bytes
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Parse the Opel 256KB doubled-char ident block (Format 4).

        Searches a 256-byte window at 0x10000–0x10100 for the doubled-char
        pattern anchored by 0x55 0xAA.  Each character is stored twice;
        back-references enforce this.  The 7-digit cal number and 1-letter
        SW code are extracted by de-doubling.

        HW number recovered from the last 64KB as plain ASCII.

        Returns (oem_part, hardware_number, software_version, ecu_variant).
        """
        window = data[0x10000:0x10100]
        m = IDENT_PATTERN_OPEL_256.search(window)
        if not m:
            return None, None, None, None

        sw_code = m.group(1).decode("ascii", errors="ignore")
        cal_id = "".join(
            m.group(i).decode("ascii", errors="ignore") for i in range(2, 9)
        )

        if not sw_code or not re.match(r"[A-Z0-9]{7}$", cal_id):
            return None, None, None, None

        hardware_number: Optional[str] = None
        hw_m = re.search(rb"028[01]\d{6}", data[-65536:])
        if hw_m:
            hardware_number = hw_m.group(0).decode("ascii", errors="ignore")

        return None, hardware_number, cal_id, sw_code

    # -----------------------------------------------------------------------
    # Internal — Opel ident parser (Format 3)
    # -----------------------------------------------------------------------

    def _detect_split_rom_chip(
        self, data: bytes
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect if this binary is a single chip from a 16-bit split-ROM pair.

        Returns (chip_part_number, chip_type) where chip_type is 'Lo' or 'Hi',
        or (None, None) if this is not a split-ROM chip.

        Only checks 128KB binaries in the region around 0x8000-0x8040
        where the chip marker is stored.
        """
        if len(data) != 0x20000:  # Only 128KB chips
            return None, None

        window = data[0x7FF0:0x8050]
        m = SPLIT_ROM_CHIP_PATTERN.search(window)
        if m is None:
            return None, None

        part_number = m.group(1).decode("ascii", errors="ignore")
        chip_type = m.group(2).decode("ascii", errors="ignore")
        return part_number, chip_type

    def _parse_ident_opel(
        self, data: bytes
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Parse the Opel-style calibration block (Format 3).

        Searches the full binary for IDENT_PATTERN_OPEL:
          (?:\\xff{4,}|\\xaa)U([A-Z]{1,2})(\\d{7})

        The 0x55 ('U') byte is a literal anchor; group 1 is the 1–2
        uppercase-letter SW code/bank designator (returned as ecu_variant);
        group 2 is the 7-digit calibration number (returned as
        software_version).

        Observed in real Opel EDC3 bins:
          LLL chip: \\xff{7} U A 0770164 Loq^  → SW code "A", cal "0770164"
          HHH chip: \\xff{14} \\xaa U A A ...  → SW code "A", cal "0770164"

        The HW number (0281xxxxxx), when present, is recovered as plain ASCII
        via a separate re.search() over the full binary — the same strategy
        used by _parse_ident_bmw().

        Returns (oem_part, hardware_number, software_version, ecu_variant).
        oem_part is always None (not embedded in this format).
        Returns (None, None, None, None) if no match is found.
        """
        m = IDENT_PATTERN_OPEL.search(data)
        if m is None:
            return None, None, None, None

        sw_code = m.group(1).decode("ascii", errors="ignore").strip()
        cal_number = m.group(2).decode("ascii", errors="ignore").strip()

        if not sw_code or not cal_number:
            return None, None, None, None

        # Recover HW number: first plain ASCII "0281xxxxxx" in the binary
        hardware_number: Optional[str] = None
        hw_match = re.search(rb"0281\d{6}", data)
        if hw_match:
            hardware_number = hw_match.group(0).decode("ascii", errors="ignore")

        return None, hardware_number, cal_number, sw_code
