"""
Magneti Marelli IAW 4LV ECU binary identifier patterns and search regions.

Covers the Magneti Marelli IAW 4LV family:
  IAW 4LV — multi-point fuel injection ECU used in VAG (Skoda/VW/Seat)
             vehicles with 1.4 16V naturally aspirated petrol engines
             (e.g. Skoda Fabia 1.4 16V 100HP).
             Motorola 68332/68336 microcontroller, 512KB flash dump.

CRITICAL — M68K byte-swapped strings:

  This ECU uses a Motorola 68332/68336 CPU.  All ASCII strings are stored
  with **adjacent bytes swapped in pairs** due to M68K 16-bit word
  addressing.  To read strings, every pair of bytes must be swapped.

  Examples:
    Raw bytes in file    After byte-swap    Meaning
    ─────────────────    ───────────────    ───────────────────
    AMERLL I             MARELLI            Manufacturer
    oBtoL4 V1r           Boot4LV r1         Bootloader ident
    63090643KB           036906034BK        VAG part number
    L4 V                 4LV                Family tag

  Because of byte-swapping, standard regex patterns cannot be applied
  directly to the raw binary data.  The extractor must byte-swap specific
  regions of the binary before running pattern searches.

Binary structure (524,288 bytes / 0x80000):

  0x00000–0x00007 : M68K reset vector / bootloader tag
                    First 4 bytes: 0E 00 E6 83
                    Next 4 bytes:  00 00 00 01
  0x00008–0x0000F : FF padding (8 bytes)
  0x00010–0x03F5F : FF padding (massive erased flash area)
  0x03F60–0x03FFF : Bootloader identification block (byte-swapped)
                    At ~0x3F6A: "AMERLL IoBtoL4 V1r"
                    → byte-swap → "MARELLI Boot4LV r1"
  0x04000–0x4FFFF : Code area (M68K machine code)
  0x50000–0x51FFF : Main identification block (byte-swapped)
                    At ~0x51458: "63090643KB  AMERLL IL4 V      3353"
                    → byte-swap → "036906034BK  MARELLI 4LV       3335"
  0x52000–0x7FEAF : Calibration data + lookup tables
  0x7FFB0–0x7FFFF : Footer block with three 55AA33CC sync markers
                    0x7FFB0: 55AA33CC + calibration data
                    0x7FFCA: 55AA33CC
                    0x7FFCE: HW ref (byte-swapped): 5D14C3NH → D5143CHN
                    0x7FFD8: 55AA33CC + byte-swapped VAG PN:
                             30966030B4 K → 036906034BK

  NOTE: The footer sync marker is 55AA33CC — the byte-swapped inverse of
  MJD 6JF's AA55CC33 marker.

Detection strategy:

  Phase 1 — Size gate: exactly 524,288 bytes (0x80000).
  Phase 2 — Header check: first 4 bytes == 0E 00 E6 83 (M68K boot vector).
  Phase 3 — Exclusion: reject if ANY exclusion signature is present in
            the raw (NOT byte-swapped) binary.
  Phase 4 — Byte-swapped Marelli: b"AMERLL" must be present anywhere
            in the binary (this is "MARELL" byte-swapped, the first 6
            chars of "MARELLI").
  Phase 5 — Footer marker: b"\\x55\\xAA\\x33\\xCC" must be present in the
            last 256 bytes of the file.

Pattern reference (all patterns are applied to BYTE-SWAPPED data):

  OEM PART NUMBER     "036906034BK"
    VAG OEM part number for the ECU calibration.
    Format: 9 decimal digits + 1–3 uppercase letter suffix.
    Located in the main ident block at ~0x51458, immediately preceding
    the "MARELLI" manufacturer string.
    THIS IS THE FALLBACK MATCHING KEY when software_version is absent.

  ECU FAMILY TAG      "4LV"
    ECU family identifier extracted from within the ident string.
    Always follows "MARELLI " with optional whitespace.
    Format: 1 digit + 2 uppercase letters.

  SOFTWARE VERSION    "3335"
    Firmware/software version or calibration code.
    Format: 4–8 alphanumeric characters.
    Follows the family tag and padding in the ident string.
    THIS IS THE PRIMARY MATCHING KEY.

  BOOT IDENT          "Boot4LV r1"
    Bootloader identification string in the boot block.
    Format: "Boot" + family tag + space + "r" + revision digit.

  FOOTER PART NUMBER  "036906034BK"
    VAG part number repeated in the footer area after the third
    55AA33CC sync marker.

  HARDWARE REF        "D5143CHN"
    Hardware reference code in the footer between the second and third
    55AA33CC markers.
    Format: 1 uppercase letter + 4 digits + 3 uppercase letters (typical).
"""

from typing import Dict

# ---------------------------------------------------------------------------
# Supported file size
# ---------------------------------------------------------------------------
# 0x80000 = 512KB — single M68K flash dump (only supported size).

EXPECTED_SIZE: int = 0x80000  # 524,288 bytes

# ---------------------------------------------------------------------------
# Header validation
# ---------------------------------------------------------------------------
# The first 4 bytes of a valid IAW 4LV binary are the M68K reset vector
# or bootloader tag: 0E 00 E6 83.

HEADER_MAGIC: bytes = b"\x0e\x00\xe6\x83"

# ---------------------------------------------------------------------------
# Detection anchors
# ---------------------------------------------------------------------------
# Byte-swapped Marelli signature: "AMERLL" is "MARELL" with adjacent bytes
# swapped.  The full "MARELLI" string becomes "AMERLL I" when byte-swapped
# (the trailing space and 'I' pair-swap to ' I').  Checking for "AMERLL"
# (first 6 bytes = 3 swapped pairs) is sufficient for detection.

BYTE_SWAPPED_MARELLI: bytes = b"AMERLL"

# Footer sync marker: 55 AA 33 CC.
# NOTE: this is the byte-reversed form of MJD 6JF's AA 55 CC 33 marker.
# Must be present in the last 256 bytes of the file.

FOOTER_SYNC_MARKER: bytes = b"\x55\xaa\x33\xcc"

# Number of trailing bytes to search for the footer sync marker.
FOOTER_SEARCH_SIZE: int = 256

# ---------------------------------------------------------------------------
# Byte-swap region boundaries (raw binary offsets)
# ---------------------------------------------------------------------------
# These define the regions of the raw binary that must be byte-swapped
# before pattern matching.  The extractor creates byte-swapped copies of
# these regions and then applies the regex patterns below.

BOOT_REGION_START: int = 0x3F00
BOOT_REGION_END: int = 0x4000

IDENT_REGION_START: int = 0x50000
IDENT_REGION_END: int = 0x52000

FOOTER_REGION_START: int = 0x7FF00
FOOTER_REGION_END: int = 0x80000

# ---------------------------------------------------------------------------
# Regex patterns — main ident block (applied to byte-swapped ident region)
# ---------------------------------------------------------------------------
# All patterns are raw bytes (rb"...") for direct use with re.search()
# or re.finditer() against BYTE-SWAPPED binary data.
#
# The main ident string after byte-swap looks like:
#   "036906034BK  MARELLI 4LV       3335"
#
# Each pattern uses a capturing group for the value of interest.
# ---------------------------------------------------------------------------

IDENT_PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # OEM part number
    # ------------------------------------------------------------------
    # VAG OEM part number — 9 digits + 1–3 uppercase letter suffix.
    # e.g. "036906034BK"
    # Anchored by a lookahead for the MARELLI manufacturer string to
    # avoid false positives from unrelated digit sequences.
    "oem_part_number": rb"(\d{9}[A-Z]{1,3})\s+MARELLI",
    # ------------------------------------------------------------------
    # ECU family tag
    # ------------------------------------------------------------------
    # Family identifier following "MARELLI " in the ident string.
    # e.g. "4LV"
    # Capturing group 1 = family tag (1 digit + 2 uppercase letters).
    "ecu_family_tag": rb"MARELLI\s+(\d[A-Z]{2})",
    # ------------------------------------------------------------------
    # Software / calibration version
    # ------------------------------------------------------------------
    # Alphanumeric code after the family tag and whitespace padding.
    # e.g. "3335"
    # Capturing group 1 = version code (4–8 word characters).
    "software_version": rb"MARELLI\s+\d[A-Z]{2}\s+(\w{4,8})",
}

# ---------------------------------------------------------------------------
# Regex patterns — footer block (applied to byte-swapped footer region)
# ---------------------------------------------------------------------------
# After byte-swapping the footer (0x7FF00–0x80000), the VAG part number
# and hardware reference become readable ASCII.
# ---------------------------------------------------------------------------

FOOTER_PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Footer VAG part number
    # ------------------------------------------------------------------
    # Repeated VAG OEM part number in the footer area.
    # e.g. "036906034BK"
    # Format: 9 decimal digits + 1–3 uppercase letter suffix.
    "footer_part_number": rb"(\d{9}[A-Z]{1,3})",
    # ------------------------------------------------------------------
    # Hardware reference
    # ------------------------------------------------------------------
    # Hardware reference code between the second and third sync markers.
    # e.g. "D5143CHN"
    # Format: 1 uppercase letter + 4 digits + 2–4 uppercase letters.
    "hardware_ref": rb"([A-Z]\d{4}[A-Z]{2,4})",
}

# ---------------------------------------------------------------------------
# Regex patterns — boot block (applied to byte-swapped boot region)
# ---------------------------------------------------------------------------
# After byte-swapping the boot region (0x3F00–0x4000), the bootloader
# ident string becomes readable: "MARELLI Boot4LV r1"
# ---------------------------------------------------------------------------

BOOT_PATTERNS: Dict[str, bytes] = {
    # ------------------------------------------------------------------
    # Bootloader identification
    # ------------------------------------------------------------------
    # Full boot ident string: "Boot" + family tag + space + revision.
    # e.g. "Boot4LV r1"
    # Capturing group 1 = family tag (e.g. "4LV").
    # Capturing group 2 = revision digit (e.g. "1").
    "boot_ident": rb"Boot(\d[A-Z]{2})\s+r(\d+)",
}

# ---------------------------------------------------------------------------
# Search regions (for raw_strings extraction on byte-swapped data)
# ---------------------------------------------------------------------------
# These are used with extract_raw_strings() after byte-swapping.
# The slice covers the entire byte-swapped buffer passed to the method.
# ---------------------------------------------------------------------------

SEARCH_REGIONS: Dict[str, slice] = {
    # Full extent of whatever buffer is passed (byte-swapped region)
    "full": slice(0, None),
}

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If ANY of these are found anywhere in the RAW (not byte-swapped) binary,
# reject immediately.  Guards against accidentally claiming bins from other
# ECU families.
#
# These are all checked as raw byte sequences because they would appear
# un-swapped in binaries that actually belong to those families (Bosch,
# Siemens, Delphi ECUs use different CPUs that don't byte-swap).
#
# NOTE: We do NOT exclude b"4LV" or b"MARELLI" here because they appear
# in byte-swapped form in IAW 4LV binaries (as "L4 V" and "AMERLL I").
# The exclusion list only contains signatures that would appear in their
# NATIVE (un-swapped) form in competing ECU families.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    # Bosch families — un-swapped ASCII in Bosch binaries
    b"BOSCH",
    b"EDC",
    b"ME7.",
    b"MOTRONIC",
    # Siemens / Continental families
    b"5WK9",
    b"SIMOS",
    b"PPD",
    # Delphi families
    b"DELPHI",
    # Other Marelli families that store strings WITHOUT byte-swapping
    # (different CPU architectures)
    b"MAG  ",  # MJD 6JF padded Marelli marker
    b"6JF",  # MJD 6JF family tag
    b"1AV",  # IAW 1AV family tag (un-swapped in those bins)
    b"1ap",  # IAW 1AP family tag (lowercase, un-swapped)
    b"ZZ",  # Bosch ZZ ident block marker
]

# ---------------------------------------------------------------------------
# Family constants
# ---------------------------------------------------------------------------

ECU_FAMILY: str = "IAW 4LV"
ECU_VARIANT: str = "IAW 4LV"
MANUFACTURER_NAME: str = "Magneti Marelli"
