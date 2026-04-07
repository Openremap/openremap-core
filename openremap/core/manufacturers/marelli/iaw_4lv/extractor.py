r"""
Magneti Marelli IAW 4LV ECU binary extractor.

Implements BaseManufacturerExtractor for the Magneti Marelli IAW 4LV family:
  IAW 4LV — multi-point fuel injection ECU used in VAG (Skoda/VW/Seat)
             vehicles with 1.4 16V naturally aspirated petrol engines
             (e.g. Skoda Fabia 1.4 16V 100HP).
             Motorola 68332/68336 microcontroller, 512KB (0x80000) flash dump.

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

  Because of byte-swapping, the standard ``_run_all_patterns()`` engine
  from BaseManufacturerExtractor cannot be used directly on the raw binary.
  Instead, the extractor byte-swaps specific regions of the binary and then
  runs regex searches on the swapped copies.

Binary structure (524,288 bytes / 0x80000):

  0x00000–0x00007 : M68K reset vector / bootloader tag
                    First 4 bytes: 0E 00 E6 83
  0x00008–0x0000F : FF padding (8 bytes)
  0x00010–0x03F5F : FF padding (massive erased flash area)
  0x03F60–0x03FFF : Bootloader ident block (byte-swapped)
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
                    0x7FFD8: 55AA33CC + byte-swapped VAG PN

Detection strategy (can_handle):

  Phase 1 — Size gate: exactly 524,288 bytes (0x80000).
  Phase 2 — Header check: first 4 bytes == 0E 00 E6 83 (M68K boot vector).
  Phase 3 — Exclusion: reject if ANY exclusion signature is present in the
            raw (NOT byte-swapped) binary.
  Phase 4 — Byte-swapped Marelli: b"AMERLL" (byte-swapped "MARELL") must
            be present anywhere in the full binary.
  Phase 5 — Footer marker: b"\x55\xAA\x33\xCC" must be present in the
            last 256 bytes of the file.

Extraction strategy:

  Step 1  — Compute file hashes and basic metadata.
  Step 2  — Byte-swap three key regions: boot, ident, footer.
  Step 3  — Extract raw ASCII strings from byte-swapped ident region.
  Step 4  — Search byte-swapped ident region for OEM PN, family tag,
            and software version.
  Step 5  — Search byte-swapped footer for part number and HW ref.
  Step 6  — Search byte-swapped boot region for bootloader ident.
  Step 7  — Set ECU family and variant.
  Step 8  — Set fields not present in IAW 4LV binaries.
  Step 9  — Build compound match key.

  Match key format: ``IAW 4LV::3335``
  Fallback: ``IAW 4LV::036906034BK`` (oem_part_number when SW is absent).

Verified sample:
  Skoda Fabia 1.4 16V 100HP — 524,288 bytes, header 0E00E683,
  byte-swapped MARELLI ident at ~0x51458, three 55AA33CC footer markers,
  OEM PN "036906034BK", SW version "3335".
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    EXCLUSION_CLEAR,
    HEADER_MATCH,
    MANUFACTURER_CONFIRM,
    SIZE_MATCH,
    SYNC_MARKER as SYNC_MARKER_TAG,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.marelli.iaw_4lv.patterns import (
    BOOT_PATTERNS,
    BOOT_REGION_END,
    BOOT_REGION_START,
    BYTE_SWAPPED_MARELLI,
    ECU_FAMILY,
    ECU_VARIANT,
    EXCLUSION_SIGNATURES,
    EXPECTED_SIZE,
    FOOTER_PATTERNS,
    FOOTER_REGION_END,
    FOOTER_REGION_START,
    FOOTER_SEARCH_SIZE,
    FOOTER_SYNC_MARKER,
    HEADER_MAGIC,
    IDENT_PATTERNS,
    IDENT_REGION_END,
    IDENT_REGION_START,
    MANUFACTURER_NAME,
)


class MarelliIAW4LVExtractor(BaseManufacturerExtractor):
    """
    Extractor for Magneti Marelli IAW 4LV ECU binaries.

    Handles: IAW 4LV (VAG M68K-based multi-point petrol injection).

    Detection is anchored on the M68K header magic (``0E 00 E6 83``), the
    byte-swapped Marelli signature (``AMERLL``), and the ``55AA33CC``
    footer sync marker.

    All string extraction requires byte-swapping specific regions of the
    binary before regex pattern matching, because the M68K 16-bit word
    addressing stores ASCII characters with adjacent bytes swapped in
    pairs.

    The ``match_key_fallback_field`` is set to ``"oem_part_number"`` so
    that a valid match key can be produced even when software_version
    cannot be extracted from the binary.
    """

    # Use oem_part_number as the fallback field for match_key when
    # software_version is absent.
    match_key_fallback_field = "oem_part_number"
    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return MANUFACTURER_NAME

    @property
    def supported_families(self) -> List[str]:
        return [ECU_FAMILY]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Magneti Marelli IAW 4LV ECU.

        Five-phase check:

          Phase 1 — Size gate.
            Reject if file size is not exactly 524,288 bytes (0x80000).

          Phase 2 — Header check.
            Reject if the first 4 bytes are not ``0E 00 E6 83``.  This is
            the M68K reset vector or bootloader tag that is characteristic
            of IAW 4LV flash dumps.

          Phase 3 — Exclusion.
            Reject if ANY known competitor or sibling signature is found
            anywhere in the raw (NOT byte-swapped) binary.  This prevents
            false positives against Bosch, Siemens, Delphi, and other
            Marelli families that may share the same file size.

          Phase 4 — Byte-swapped Marelli confirmation.
            Accept only if ``b"AMERLL"`` is present anywhere in the binary.
            This is "MARELL" (first 6 chars of "MARELLI") with adjacent
            bytes swapped — the characteristic M68K byte-swap pattern.

          Phase 5 — Footer marker.
            Accept only if ``b"\\x55\\xAA\\x33\\xCC"`` is present in the
            last 256 bytes of the file.  This is the IAW 4LV footer sync
            marker (note: byte-reversed from MJD 6JF's ``AA55CC33``).
        """
        evidence: list[str] = []

        # Phase 1 — size gate
        if len(data) != EXPECTED_SIZE:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 2 — header check: first 4 bytes must be M68K boot vector
        if data[:4] != HEADER_MAGIC:
            self._set_evidence()
            return False
        evidence.append(HEADER_MATCH)

        # Phase 3 — exclusion check (full binary, raw bytes)
        for excl in EXCLUSION_SIGNATURES:
            if excl in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 4 — byte-swapped Marelli: "AMERLL" must be present
        if BYTE_SWAPPED_MARELLI not in data:
            self._set_evidence()
            return False
        evidence.append(MANUFACTURER_CONFIRM)

        # Phase 5 — footer marker: 55AA33CC in last 256 bytes
        footer_tail = data[-FOOTER_SEARCH_SIZE:]
        if FOOTER_SYNC_MARKER not in footer_tail:
            self._set_evidence()
            return False
        evidence.append(SYNC_MARKER_TAG)

        self._set_evidence(evidence)
        return True

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Marelli IAW 4LV binary.

        Since all ASCII strings are stored with M68K byte-swapping, the
        extractor first creates byte-swapped copies of three key regions
        (boot block, ident block, footer block) and then searches those
        copies for patterns.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        # --- Step 1: Compute file hashes and basic metadata ---
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 2: Byte-swap key regions for string extraction ---
        boot_swapped = self._byte_swap(data[BOOT_REGION_START:BOOT_REGION_END])
        ident_swapped = self._byte_swap(data[IDENT_REGION_START:IDENT_REGION_END])
        footer_swapped = self._byte_swap(data[FOOTER_REGION_START:FOOTER_REGION_END])

        # --- Step 3: Extract raw ASCII strings from byte-swapped regions ---
        # Combine strings from all three swapped regions for comprehensive
        # raw_strings output.  The ident region is richest; boot and footer
        # provide supplementary identifiers.
        raw_strings: List[str] = []

        ident_strings = self.extract_raw_strings(
            data=ident_swapped,
            region=slice(0, None),
            min_length=8,
            max_results=15,
        )
        raw_strings.extend(ident_strings)

        boot_strings = self.extract_raw_strings(
            data=boot_swapped,
            region=slice(0, None),
            min_length=8,
            max_results=5,
        )
        raw_strings.extend(boot_strings)

        footer_strings = self.extract_raw_strings(
            data=footer_swapped,
            region=slice(0, None),
            min_length=6,
            max_results=5,
        )
        raw_strings.extend(footer_strings)

        result["raw_strings"] = raw_strings[:20]

        # --- Step 4: Search byte-swapped ident region for identifiers ---
        oem_part_number = self._extract_with_group(
            ident_swapped, IDENT_PATTERNS["oem_part_number"], group=1
        )
        result["oem_part_number"] = oem_part_number

        ecu_family_tag = self._extract_with_group(
            ident_swapped, IDENT_PATTERNS["ecu_family_tag"], group=1
        )

        software_version = self._extract_with_group(
            ident_swapped, IDENT_PATTERNS["software_version"], group=1
        )
        result["software_version"] = software_version

        # --- Step 5: Search byte-swapped footer for part number and HW ---
        footer_part_number = self._extract_with_group(
            footer_swapped, FOOTER_PATTERNS["footer_part_number"], group=1
        )

        hardware_ref = self._extract_with_group(
            footer_swapped, FOOTER_PATTERNS["hardware_ref"], group=1
        )
        result["hardware_number"] = hardware_ref

        # Cross-validate OEM PN: prefer ident region, fall back to footer
        if not oem_part_number and footer_part_number:
            result["oem_part_number"] = footer_part_number

        # --- Step 6: Search byte-swapped boot region for boot ident ---
        boot_match = re.search(BOOT_PATTERNS["boot_ident"], boot_swapped)
        if boot_match:
            boot_family = boot_match.group(1).decode("ascii", errors="ignore")
            # Use boot family tag as secondary confirmation if ident didn't
            # produce one.
            if not ecu_family_tag:
                ecu_family_tag = boot_family

        # --- Step 7: Set ECU family and variant ---
        # The ECU family is always "IAW 4LV" for this extractor.  The family
        # tag extracted from the binary (e.g. "4LV") confirms membership but
        # the canonical family name includes the "IAW " prefix.
        result["ecu_family"] = ECU_FAMILY
        result["ecu_variant"] = ECU_VARIANT

        # --- Step 8: Fields not present in IAW 4LV binaries ---
        result["calibration_id"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 9: Build compound match key ---
        # Primary: "IAW 4LV::3335" (using software_version).
        # Fallback: "IAW 4LV::036906034BK" (using oem_part_number).
        result["match_key"] = self.build_match_key(
            ecu_family=ECU_FAMILY,
            ecu_variant=ECU_VARIANT,
            software_version=software_version,
            fallback_value=result.get("oem_part_number"),
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — M68K byte-swap utility
    # -----------------------------------------------------------------------

    def _byte_swap(self, data: bytes) -> bytes:
        """
        Swap adjacent bytes in pairs (M68K 16-bit word addressing).

        The Motorola 68332/68336 stores 16-bit words with the high byte
        first (big-endian), but the flash dump tool reads bytes linearly.
        This results in every pair of adjacent bytes being swapped relative
        to the ASCII string order.

        Examples:
          Input:  b"AMERLL I"   → Output: b"MARELLI "
          Input:  b"63090643KB" → Output: b"036906034BK"  (trailing odd byte kept)

        If the data has an odd number of bytes, the last byte is kept as-is.

        Args:
            data: Raw bytes from the binary to byte-swap.

        Returns:
            New bytes object with every pair of adjacent bytes swapped.
        """
        result = bytearray(len(data))
        for i in range(0, len(data) - 1, 2):
            result[i] = data[i + 1]
            result[i + 1] = data[i]
        if len(data) % 2:
            result[-1] = data[-1]
        return bytes(result)

    # -----------------------------------------------------------------------
    # Internal — pattern extraction with capturing groups
    # -----------------------------------------------------------------------

    def _extract_with_group(
        self,
        data: bytes,
        pattern: bytes,
        group: int = 1,
    ) -> Optional[str]:
        """
        Search for a regex pattern in byte-swapped data and return a
        specific capturing group as a decoded ASCII string.

        Unlike the base class ``_search()`` which returns ``group(0)``
        (the full match), this method returns a specific capturing group.
        This is necessary because IAW 4LV patterns use capturing groups
        to isolate the value of interest from its context (e.g. extracting
        "036906034BK" from the full match "036906034BK  MARELLI").

        Args:
            data:    Byte-swapped binary region to search.
            pattern: Raw bytes regex pattern with capturing groups.
            group:   Index of the capturing group to return (1-based).

        Returns:
            Decoded ASCII string from the specified group, or None if the
            pattern did not match or the group could not be decoded.
        """
        try:
            match = re.search(pattern, data)
            if match:
                value = match.group(group).decode("ascii", errors="ignore").strip()
                if value:
                    return value
        except (IndexError, AttributeError):
            pass
        return None
