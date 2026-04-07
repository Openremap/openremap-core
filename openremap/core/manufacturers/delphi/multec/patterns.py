"""
Delphi Multec (diesel) ECU binary identifier patterns and search regions.

All regex patterns and search region definitions specific to Delphi Multec
diesel ECUs.  Covers Motorola 68k CPU32-based controllers used in Opel/
Vauxhall diesel applications (1990s–2000s).

Two structural variants share the same ident block format:

  Variant A — DHCR-type (212,992 bytes = 0x34000)
    Header starts with 6 ASCII digits (e.g. "363020").
    Code begins at offset 0x10 with 68k CPU32 opcodes.
    Ident block located around 0x296F0.

  Variant B — DMRW-type (262,144 bytes = 0x40000)
    Header starts with byte 0x11 followed by "DEL" (Delco signature).
    Boot pointer block at 0x40–0x4F; code starts at 0x60.
    Ident block located around 0x32410.

Ident block structure (identical for both variants):

  The block is preceded by a 16-byte repeating 4-byte pointer pattern
  (e.g. 4× 0x00028124 or 4× 0x0004015A).  Immediately after comes:

      <8-digit SW number> <space> <2-char broadcast> <4-char family> \x00

  Followed by flags, a D-number calibration reference, a version string,
  and a date stamp.

Pattern reference:

  SOFTWARE VERSION    "97231405"  "97306575"
    8 ASCII decimal digits forming the Delphi internal software revision.
    Anchored by the trailing broadcast+family pattern to avoid false
    positives against arbitrary 8-digit sequences in calibration data.
    THIS IS THE PRIMARY MATCHING KEY.

  BROADCAST CODE      "DG"  "EA"
    2 uppercase ASCII letters identifying the OBD-II broadcast source.
    Immediately follows the SW number + space separator.

  VARIANT CODE        "DHCR"  "DMRW"
    4 uppercase ASCII letters forming the ECU family/variant designator.
    Immediately follows the broadcast code with no separator.

  CALIBRATION ID      "D00021"  "D01011"
    Delphi calibration reference: uppercase 'D' + 5 decimal digits.
    Located in the ident block after the null-terminated family string.

  DELCO SERIAL        "0113386350"
    10-digit Delco Electronics production serial number.
    Present only in Variant B binaries, in the file header after "DEL  ".

  VERSION STRING      "Y17DIT"  "Y17DT"
    Engine/application version code following the D-number.
    Format: 'Y' + 2 digits + 2–4 uppercase letters (engine code).
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.finditer()
# against binary data.
#
# The ident block offset varies between Variant A (~0x296F0) and Variant B
# (~0x32410), so all patterns search the full binary by default.
#
# Every pattern uses a single capturing group to extract the field of
# interest.  The base class _search() method stores group(0) (the full
# match) — resolvers split/trim as needed.
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Software / calibration identification
    # ------------------------------------------------------------------
    # SW number: 8 ASCII digits at start of ident block.
    # Anchored by the space + 2-char broadcast + 4-char family + null
    # terminator that always follows — prevents matching arbitrary
    # 8-digit sequences in calibration tables or code.
    # e.g. "97231405 DGDHCR\x00"  →  captures "97231405"
    "software_version": rb"(\d{8}) [A-Z]{2}[A-Z]{4}\x00",
    # Broadcast code: 2 uppercase letters between SW number and family.
    # e.g. "97231405 DGDHCR\x00"  →  captures "DG"
    "broadcast_code": rb"\d{8} ([A-Z]{2})[A-Z]{4}\x00",
    # Variant code: 4 uppercase letters forming the ECU family designator.
    # e.g. "97231405 DGDHCR\x00"  →  captures "DHCR"
    "variant_code": rb"\d{8} [A-Z]{2}([A-Z]{4})\x00",
    # D-number: Delphi calibration reference — 'D' + 5 digits.
    # e.g. "D00021"  "D01011"
    "calibration_id": rb"(D\d{5})",
    # Delco serial (Variant B only): 10 digits after "DEL" + 1–3 spaces.
    # e.g. "DEL  0113386350"  →  captures "0113386350"
    "delco_serial": rb"DEL\s{1,3}(\d{10})",
    # Version string: engine/application code after the D-number.
    # Format: 'Y' + 2 digits + 2–4 uppercase letters.
    # e.g. "D00021Y17DIT"  →  captures "Y17DIT"
    # e.g. "D01011Y17DT"   →  captures "Y17DT"
    "version_string": rb"D\d{5}(Y\d{2}[A-Z]{2,4})",
}

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------
# The ident block offset varies significantly between variants:
#   Variant A: ~0x296F0  (in a 0x34000-byte file)
#   Variant B: ~0x32410  (in a 0x40000-byte file)
#
# Because there is no single bounded region that covers both variants
# without also including most of the binary, all patterns default to
# searching the full file.  The files are small (≤256KB) so a full scan
# is negligible in practice.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # File header — Delco serial and header digits live here
    "header": slice(0x0000, 0x0100),
    # Ident area — full file (ident offset varies by variant)
    "ident_area": slice(None),
    # Full binary — catch-all region
    "full": slice(0x0000, None),
}

# ---------------------------------------------------------------------------
# Pattern → search region mapping
# ---------------------------------------------------------------------------
# All patterns search the full binary because the ident block offset
# varies between Variant A and Variant B.  The binaries are at most 256KB
# so a full scan has negligible performance impact.
# ---------------------------------------------------------------------------

PATTERN_REGIONS: Dict[str, str] = {
    "software_version": "full",
    "broadcast_code": "full",
    "variant_code": "full",
    "calibration_id": "full",
    "delco_serial": "full",
    "version_string": "full",
}

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# Only two sizes are valid for Delphi Multec diesel binaries:
#   0x34000  (212,992 bytes) — Variant A (DHCR-type)
#   0x40000  (262,144 bytes) — Variant B (DMRW-type)
# ---------------------------------------------------------------------------

SUPPORTED_SIZES: frozenset[int] = frozenset({0x34000, 0x40000})

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these byte strings appear anywhere in the binary, the file
# cannot be a Delphi Multec ECU ROM.  This prevents false positives from:
#   - Bosch EDC/ME/MEDC/MD families (share some file sizes)
#   - Siemens/Continental SIMOS family
#   - Magneti Marelli ECUs
#   - Bosch Motronic (generic)
#   - Bosch PPD family (diesel, similar era)
#   - Siemens 5WK9 family
#   - Bosch part-number prefixes (0261 = petrol, 1037 = EDC15+)
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"BOSCH",
    b"EDC",
    b"ME7.",
    b"5WK9",
    b"SIMOS",
    b"PPD",
    b"MARELLI",
    b"MAG  ",
    b"MOTRONIC",
    b"ZZ",
    b"1037",
    b"0261",
]

# ---------------------------------------------------------------------------
# Ident block confirmation pattern
# ---------------------------------------------------------------------------
# The ident block signature that must exist somewhere in the last 40% of
# the file.  Format: 8 digits + space + 2 uppercase + 4 uppercase + null.
# e.g. "97231405 DGDHCR\x00"  "97306575 EADMRW\x00"
#
# This is used as the final positive-confirmation step in can_handle() to
# ensure the binary contains a genuine Multec ident record, not just a
# header that superficially resembles one.
# ---------------------------------------------------------------------------

IDENT_CONFIRMATION_PATTERN: bytes = rb"\d{8} [A-Z]{2}[A-Z]{4}\x00"
