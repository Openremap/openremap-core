"""
Bosch ME7 ECU binary identifier patterns and search regions.

Covers the Bosch Motronic ME7 family:
  ME71    — very early variant (no dot), e.g. Audi A6 1997
  ME7.1   — Audi/VW V6, W8, W12 engines (1998–2004)
  ME7.1.1 — updated ME7.1 variant (2000–2006)
  ME7.5   — VW/Audi 4-cylinder turbocharged engines (1998–2006)
  ME7.5.5 — revision of ME7.5 (2002+)
  ME7.5.10 — late production variant

All ME7.x ECUs use a Motorola 16-bit CPU (SAB C167CR family).
This is an older generation than EDC17/MEDC17 — none of the modern
Bosch signatures (SB_V, NR000, Customer.) are present.

Binary structure:
  0x00000 – 0x0FFFF  : Code / calibration (lower half)
  0x10000            : ZZ\xff\xff marker — start of ident block
                       Immediately followed by the slash-delimited variant string
  0x10000 – 0x1FFFF  : Ident block — SW version, HW number, OEM label
  0x20000+           : Extended code / data

Key identifier locations:
  Variant string     : 0x10004 (directly after ZZ\xff\xff marker)
  HW + SW block      : ~0x143xx – 0x184xx (varies by variant)
                       Stored as adjacent ASCII: "0261XXXXXXXX1037XXXXXXXX"
  MOTRONIC label     : Within ident block — "XXXXXXXX MOTRONIC ME7.x.x  NNNN"
                       Contains VAG OEM part number + family + revision code

Pattern reference:

  HARDWARE NUMBER     "0261207881"
    Bosch ECU hardware unit part number.
    Format: 0261 + 6 digits  (10 digits total).
    Always starts with "0261" for Bosch Motronic ME7 ECUs.
    Stored immediately before the SW version in the combined block.

  SOFTWARE VERSION    "1037368072"  or  "10373686044"
    Bosch internal software calibration identifier.
    Format: 1037 + 6–10 digits.
    The primary matching key — unique per tune revision.
    Note: some bins have an extended 11-digit form (e.g. 10373686044).

  ECU FAMILY          "ME7.1"  "ME7.5"  "ME7.1.1"  "ME71"
    Controller family string extracted from the variant string in the ZZ block.
    ME71 is the earliest variant (no dot notation).

  VARIANT STRING      "44/1/ME7.1.1/120/6428.AA//24F/Dst02o/050603/"
    Full slash-delimited descriptor stored directly after ZZ\xff\xff.
    Fields: revision/unknown/family/dataset/calibration_id//channel/date/

  OEM PART NUMBER     "022906032CS"  (VAG format)
    Vehicle manufacturer (VAG) part number — stamped on the ECU label.
    Appears in the MOTRONIC label: "<part> MOTRONIC ME7.x.x  <rev>"
    Format: digit + digit + letter + 6 digits + optional suffix

  CALIBRATION ID      "6428.AA"  "4013.00"  "C1105N"
    Dataset / calibration identifier from the variant string.
    Format: 4 digits + dot + 2 alphanumeric chars, or alphanumeric code.
    Unique per calibration variant.
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Hardware identification
    # ------------------------------------------------------------------
    # Bosch ME7 hardware part number — always "0261" + 6 digits (10 total)
    # e.g. "0261207881"  "0261206042"  "0261208728"
    # Often stored immediately before the SW version in the combined block.
    "hardware_number": rb"0261\d{6}",
    # ------------------------------------------------------------------
    # Software / calibration identification
    # ------------------------------------------------------------------
    # Combined HW + SW block — the most reliable source for both numbers.
    # In most ME7 bins the hardware number and software version are stored as a
    # single concatenated ASCII string with no separator:
    #   "0261XXXXXXXX1037XXXXXXXXXX"
    # e.g. "026120788110373686044"   (HW=0261207881, SW=10373686044)
    #      "02612074361037362287"    (HW=0261207436, SW=1037362287)
    #
    # In some bins (e.g. 4E0910559E) the two numbers are separated by a
    # single null byte:
    #   "0261208772\x001037381189"
    #
    # In ME731 (Alfa GT) bins the two numbers are separated by a space + null:
    #   "0261208571 \x001037368772"
    #
    # In ME7.3 Italian variants (Ferrari 360, possibly Alfa Romeo/Maserati)
    # the SW prefix is 1277 instead of 1037:
    #   "0261204841 \x001277356302"
    #
    # The separator group [\x00 ]? handles all three cases.
    # Capturing group 1 = HW (0261 + 6 digits)
    # Capturing group 2 = SW (1037 or 1277 + 6–10 digits)
    # Note: 1277 prefix is used by ME7.3 Italian variants (Ferrari, possibly
    # Alfa Romeo / Maserati).  e.g. HW 0261204841, SW 1277356302.
    "hw_sw_combined": rb"(0261\d{6})[\x00 ]?\x00?((?:1037|1277)\d{6,10})",
    # Standalone SW version — fallback for the rare bins where HW and SW
    # are stored separately (e.g. "006410010A0.bin" where SW appears alone).
    # No lookbehind here because in the standalone case it is not preceded
    # by the HW number directly.
    # ME7.3 Italian variants (Ferrari 360, possibly Alfa Romeo/Maserati)
    # use a 1277 prefix instead of 1037.
    "software_version": rb"(?:1037|1277)\d{6,10}",
    # Calibration ID from the variant string — e.g. "6428.AA"  "4013.00"  "C1105N"
    # Extracted from the slash-delimited block: .../family/dataset/cal_id//...
    # This pattern matches the 5th field (after 4 slashes) of the variant string.
    # Format 1: 4 digits + dot + 2 alphanumeric  e.g. "6428.AA"
    # Format 2: alphanumeric code                e.g. "C1105N"  "X505R"
    "calibration_id": rb"(?<=/)\d{4}\.[A-Z0-9]{2}(?=/)|(?<=/)[A-Z][A-Z0-9]{4,6}(?=/)",
    # ------------------------------------------------------------------
    # ECU family and variant string
    # ------------------------------------------------------------------
    # Full slash-delimited variant descriptor from the ZZ ident block.
    # e.g. "44/1/ME7.1.1/120/6428.AA//24F/Dst02o/050603/"
    #      "44/1/ME71/05/6001_01//prog16d/dat16d/180797/"
    #      "41/1/ME731/9/903_7/A14D//14D55x00/260803/"
    # Anchored to the numeric revision prefix (2–3 digits before first slash).
    # ME731 is an Alfa-specific label (no dot, 3 trailing digits) — the
    # character class [\w\.]+ covers both "ME7.1.1" and "ME731" forms.
    "ecu_variant_string": rb"\d{2,3}/\d+/ME7[\w\.]+/[\w/\._\-]{6,}",
    # ECU family — extracted from within the variant string or standalone.
    # Matches: ME7.1  ME7.5  ME7.1.1  ME7.5.5  ME7.5.10  ME71  ME731
    # ME731 = Alfa Romeo Motronic E7.3.1 — digit-only suffix, no dot.
    # The character class [\d\.]* followed by \d already covers ME731 because
    # '3', '1' are digits.  No change needed to this pattern.
    # MEDC17/ME17 are intentionally excluded — those belong to the other extractor.
    "ecu_family": rb"ME7[\d\.]*\d",
    # ------------------------------------------------------------------
    # OEM (vehicle manufacturer) identification
    # ------------------------------------------------------------------
    # MOTRONIC label — VAG part number immediately before "MOTRONIC ME7..."
    # e.g. "022906032CS MOTRONIC ME7.1.1    0006"
    # The VAG part number is 8–14 alphanumeric chars followed by spaces.
    # Captured as a full label so the resolver can split it.
    "motronic_label": rb"[0-9][0-9A-Z]{7,13}\s+MOTRONIC\s+ME7[\w\.]+\s+\d{4}",
    # VAG part number — standalone (without MOTRONIC context)
    # e.g. "022906032CS"  "4B0907551AA"  "8D0907551M"
    # Format mirrors the standard VAG ECU part number scheme.
    # Only used as fallback if motronic_label doesn't fire.
    "vag_part_number": rb"(?<![A-Z0-9])[0-9][0-9A-Z]{2}[\s]?\d{3}[\s]?\d{3}(?:[\s]?[A-Z]{1,2})?(?![A-Z0-9])",
}

# ---------------------------------------------------------------------------
# ECU family resolution order
# ---------------------------------------------------------------------------
# Not applicable for ME7 (only one family pattern) — kept for interface
# compatibility with the EDC17 extractor.
# ---------------------------------------------------------------------------

FAMILY_RESOLUTION_ORDER = [
    "ecu_family",
]

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# Based on analysis of real ME7.1 / ME7.5 / ME7.1.1 binaries.
#
# Key findings:
#   - ZZ\xff\xff marker is always at 0x10000 (1MB bins) or the equivalent
#     offset in 512KB bins.  The variant string follows directly at 0x10004.
#   - Combined HW+SW block is always within 0x10000 – 0x20000 (ident block).
#   - MOTRONIC label is within the ident block.
#   - ECU family string appears in the first 320KB (as part of the variant
#     string and in code strings).
#   - OEM part number may appear anywhere but is most reliably found in the
#     ident block.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # First 4KB — not heavily used by ME7 (no serial/dataset in header)
    "header": slice(0x0000, 0x1000),
    # Ident block — 0x10000 to 0x20000 — ZZ block, HW/SW, MOTRONIC label
    "ident_block": slice(0x10000, 0x20000),
    # Extended — first 320KB — family strings, variant strings
    "extended": slice(0x0000, 0x50000),
    # Full binary — for VAG part number fallback
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    # Extended (first 320KB) — hw_sw_combined must reach beyond ident_block
    # because some bins (e.g. 4E0910559E) store the block at ~0x22000
    "hw_sw_combined": "extended",
    # Ident block (0x10000–0x20000)
    "hardware_number": "ident_block",
    "software_version": "ident_block",
    "ecu_variant_string": "ident_block",
    "motronic_label": "ident_block",
    "calibration_id": "ident_block",
    # Extended (first 320KB) — family can appear in code strings too
    "ecu_family": "extended",
    # Full binary — VAG part number fallback
    "vag_part_number": "full",
}

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by BoschME7Extractor.can_handle() to quickly detect
# whether a binary belongs to the ME7 family.
#
# Strategy:
#   - "ME7." covers ME7.1, ME7.5, ME7.1.1, ME7.5.5, ME7.5.10 etc.
#   - "ME71" covers the early ME71 variant (no dot notation)
#   - "MOTRONIC" is a broad Bosch Motronic label — present in ME7 bins but
#     also in other families (MP9, M1.5.4, etc.).  can_handle() performs
#     contextual verification: "MOTRONIC" alone is NOT sufficient — the
#     binary must ALSO contain a "ME7" family substring.  See Phase 2b in
#     BoschME7Extractor.can_handle().
#
# At least ONE must be present in the first 512KB of the binary.
# The can_handle() check also verifies the absence of EDC17/MEDC17/MED17
# strings to avoid false positives on newer Bosch bins that happen to
# contain "ME7" as a substring in internal strings.
#
# NOTE: ZZ\xff\xff is intentionally NOT in this list.
# It is the canonical ME7 ident block marker but it must be checked at
# the fixed offset 0x10000 only — not searched across the full binary.
# Scanning for it anywhere in 512KB causes false positives on non-ME7
# binaries (e.g. Siemens SID801) that happen to contain ZZ\xff\xff as
# coincidental calibration table data at other offsets.
# The offset-anchored check lives in BoschME7Extractor.can_handle().
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"ME7.",  # ME7.1  ME7.5  ME7.1.1  ME7.5.5 ...
    b"ME71",  # ME71 — earliest variant (no dot)
    b"ME731",  # ME731 — Alfa Romeo Motronic E7.3.1 (Alfa GT, 156 petrol)
    #         Uses the slash-delimited descriptor like all ME7.x but
    #         has no dot in the family token, so "ME7." doesn't match it.
    #         ZZ marker at 0x10000 is 5a5a0001 instead of 5a5affffff —
    #         the first two bytes ('ZZ') are still present.
    b"MOTRONIC",  # Bosch Motronic label — present in most ME7 bins
    #         ⚠ Requires contextual verification in can_handle(): accepted
    #         only when b"ME7" is also present in the binary.  Without this
    #         guard, non-ME7 Motronic families (MP9.0, M1.5.4, M3.8.x …)
    #         are misidentified as ME7.
]

# Fixed offset where the ZZ ident block marker must appear in a genuine ME7
# binary. Checked directly in can_handle() — not via signature scan.
#
# The marker always starts with the two ASCII bytes b"ZZ" (0x5a 0x5a).
# The two bytes that follow vary by variant:
#   b"ZZ\xff\xff"  — standard ME7.1 / ME7.5 / ME7.1.1 / ME7.5.5
#   b"ZZ\x00\x01"  — ME731 (Alfa Romeo Motronic E7.3.1)
#   b"ZZ\x01\x02"  — early/pre-production ME7 (ERCOS V2.x RTOS, ~1996)
#                    No slash-delimited variant string, no 0261/1037 block.
#                    Identified and extracted by _is_early_me7() +
#                    _extract_early() in BoschME7Extractor — completely
#                    separate path from all production resolvers.
#
# can_handle() checks only the first two bytes of the marker so that all
# variants are accepted without listing every possible 4-byte combination.
ME7_ZZ_OFFSET: int = 0x10000
ME7_ZZ_MARKER: bytes = (
    b"ZZ\xff\xff"  # kept for backward compat; can_handle uses ZZ prefix only
)
ME7_ZZ_PREFIX: bytes = b"ZZ"  # the invariant two-byte anchor across all ME7 variants

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these are found in the first 512KB the binary is NOT ME7.
# This prevents the ME7 extractor from stealing bins that belong to the
# EDC17 / MEDC17 / MED17 extractor, which also uses "ME" prefix strings.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"SB_V",  # Bosch modern SW base version — not present on ME7
    b"Customer.",  # Bosch modern customer label — not present on ME7
]
