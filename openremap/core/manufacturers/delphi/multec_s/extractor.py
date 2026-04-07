"""
Delphi Multec S ECU binary extractor.

Covers the Delphi Multec S family used in Opel/Vauxhall petrol vehicles with
various 4-cylinder engines (1996–2003).  Typical vehicles include Astra G,
Corsa B/C, Vectra B, and Zafira A.

Binary characteristics:
  - File size: exactly 131 072 bytes (128 KB = 0x20000)
  - CPU: Motorola HC12 / HCS12 (68HC12)
  - Layout: two 64 KiB banks with identical (mirrored) structure
  - Boot block: 0x0000–0x1FFF — erased (all 0xFF, 8 KiB)
  - Data/code: starts at 0x2000 with HC12 pointer tables
  - Ident block: fixed offset 0x3000 (mirrored at 0x13000)

Detection strategy:
  1. Size gate: exactly 131 072 bytes (128 KB)
  2. Boot block: first 16 bytes must be all 0xFF (erased flash boot block)
  3. HC12 pointer table: bytes at 0x2000–0x2002 must be \\x00\\x00\\x7e
  4. Exclusion: reject if any Bosch / Siemens / Marelli signature is found
  5. Ident validation: 8 ASCII digits at 0x3009 + 2 uppercase letters at 0x3011
  6. GM part number: 8 ASCII digits at 0x3015

All field extraction is offset-based — the ident block layout is identical
across all known Multec S binaries.  Regex patterns from patterns.py serve
as validation cross-checks via the base class pattern engine.
"""

import hashlib
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BOOT_BLOCK,
    EXCLUSION_CLEAR,
    IDENT_BLOCK,
    POINTER_TABLE,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.delphi.multec_s.patterns import (
    BOOT_BLOCK_CHECK_LENGTH,
    BOOT_BLOCK_FILL,
    BROADCAST_CHECK_END,
    BROADCAST_CHECK_START,
    BROADCAST_LENGTH,
    BROADCAST_OFFSET,
    D_NUMBER_LENGTH,
    D_NUMBER_OFFSET,
    ENGINE_LENGTH,
    ENGINE_OFFSET,
    EXCLUSION_SIGNATURES,
    GM_PN_CHECK_END,
    GM_PN_CHECK_START,
    GM_PN_LENGTH,
    GM_PN_OFFSET,
    HC12_POINTER_OFFSET,
    HC12_POINTER_SIGNATURE,
    IDENT_BASE,
    MULTEC_S_FILE_SIZE,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SW_CHECK_END,
    SW_CHECK_START,
    SW_LENGTH,
    SW_OFFSET,
    VARIANT_LENGTH,
    VARIANT_OFFSET,
)


class DelphiMultecSExtractor(BaseManufacturerExtractor):
    """
    Extractor for Delphi Multec S petrol ECU binaries.

    Handles: Multec S

    Detection is based on a strict combination of:
      - Exact 128 KB file size (131 072 bytes)
      - Erased boot block (first 8 KiB all 0xFF)
      - HC12 pointer table signature at 0x2000
      - Ident block validation at 0x3009 (SW number + broadcast code)
      - GM part number validation at 0x3015
      - Absence of all Bosch / Siemens / Marelli exclusion signatures

    All field extraction uses fixed byte offsets into the ident block at
    0x3000.  Regex patterns are used only for validation cross-checks.
    """

    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Delphi"

    @property
    def supported_families(self) -> List[str]:
        return ["Multec S"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Delphi Multec S petrol ECU dump.

        Six-phase check:
          1. Size gate — must be exactly 131 072 bytes (128 KB).
          2. Boot block — first 16 bytes must be all 0xFF, confirming the
             erased 8 KiB boot block characteristic of Multec S.
          3. HC12 pointer table — bytes at 0x2000–0x2002 must match
             \\x00\\x00\\x7e (HC12/HCS12 pointer table start).
          4. Exclusion — reject if any known Bosch / Siemens / Marelli
             signature is found anywhere in the binary.
          5. SW number validation — 8 ASCII digits at offset 0x3009
             followed by 2 uppercase ASCII letters at 0x3011.
          6. GM part number validation — 8 ASCII digits at offset 0x3015.

        All six phases must pass for the binary to be claimed.
        """
        evidence: list[str] = []

        # --- Phase 1: Size gate ---
        if len(data) != MULTEC_S_FILE_SIZE:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # --- Phase 2: Boot block — erased flash (all 0xFF) ---
        if data[:BOOT_BLOCK_CHECK_LENGTH] != BOOT_BLOCK_FILL:
            self._set_evidence()
            return False
        evidence.append(BOOT_BLOCK)

        # --- Phase 3: HC12 pointer table signature at 0x2000 ---
        sig_start = HC12_POINTER_OFFSET
        sig_end = sig_start + len(HC12_POINTER_SIGNATURE)
        if data[sig_start:sig_end] != HC12_POINTER_SIGNATURE:
            self._set_evidence()
            return False
        evidence.append(POINTER_TABLE)

        # --- Phase 4: Exclusion signatures ---
        for sig in EXCLUSION_SIGNATURES:
            if sig in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # --- Phase 5: Ident block — SW number + broadcast code ---
        # 8 ASCII digits at 0x3009–0x3010
        if not all(0x30 <= b <= 0x39 for b in data[SW_CHECK_START:SW_CHECK_END]):
            self._set_evidence()
            return False
        # 2 uppercase ASCII letters at 0x3011–0x3012
        if not all(
            0x41 <= b <= 0x5A for b in data[BROADCAST_CHECK_START:BROADCAST_CHECK_END]
        ):
            self._set_evidence()
            return False
        evidence.append(IDENT_BLOCK)

        # --- Phase 6: GM part number — 8 ASCII digits at 0x3015 ---
        if not all(0x30 <= b <= 0x39 for b in data[GM_PN_CHECK_START:GM_PN_CHECK_END]):
            self._set_evidence()
            return False
        evidence.append("GM_PART_NUMBER")

        self._set_evidence(evidence)
        return True

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Delphi Multec S binary.

        All fields are extracted via fixed byte offsets into the ident block
        at 0x3000.  Regex patterns from patterns.py are run as validation
        cross-checks through the base class pattern engine.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "ecu_family": "Multec S",
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from ident block region ---
        raw_strings = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_block"],
            min_length=4,
            max_results=20,
        )
        result["raw_strings"] = raw_strings

        # --- Step 2: Run regex patterns for validation cross-checks ---
        raw_hits = self._run_patterns(data)

        # --- Step 3: Extract SW number (software version) at fixed offset ---
        software_version = self._read_ident_field(
            data, SW_OFFSET, SW_LENGTH, expect_digits=True
        )
        result["software_version"] = software_version

        # --- Step 4: Extract variant code (ecu_variant) at fixed offset ---
        ecu_variant = self._read_ident_field(
            data, VARIANT_OFFSET, VARIANT_LENGTH, expect_upper=True
        )
        result["ecu_variant"] = ecu_variant

        # --- Step 5: Extract D-number (calibration_id) at fixed offset ---
        calibration_id = self._read_ident_field(data, D_NUMBER_OFFSET, D_NUMBER_LENGTH)
        # Validate D-number format: starts with "D" followed by digits
        if calibration_id and not (
            calibration_id[0] == "D" and calibration_id[1:].isdigit()
        ):
            # Fall back to pattern-based extraction
            calibration_id = self._first_hit(raw_hits, "calibration_id")
        result["calibration_id"] = calibration_id

        # --- Step 6: Extract GM/OEM part number at fixed offset ---
        oem_part_number = self._read_ident_field(
            data, GM_PN_OFFSET, GM_PN_LENGTH, expect_digits=True
        )
        result["oem_part_number"] = oem_part_number

        # --- Step 7: Extract broadcast code ---
        broadcast_code = self._read_ident_field(
            data, BROADCAST_OFFSET, BROADCAST_LENGTH, expect_upper=True
        )
        # Broadcast code is informational — stored in calibration_version
        # as there is no dedicated field for it in the schema.
        result["calibration_version"] = broadcast_code

        # --- Step 8: Extract engine/HW suffix ---
        engine_suffix = self._read_engine_suffix(data)
        # Engine suffix is stored in sw_base_version as there is no
        # dedicated engine_code field in the schema.
        result["sw_base_version"] = engine_suffix

        # --- Step 9: Fields not present in Multec S binaries ---
        result["hardware_number"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 10: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family="Multec S",
            ecu_variant=None,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — pattern runner
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """
        Run all Multec S patterns against their assigned search regions.

        Delegates to the base class _run_all_patterns() utility.
        These results serve as validation cross-checks for the primary
        offset-based extraction.
        """
        return self._run_all_patterns(
            data=data,
            patterns=PATTERNS,
            pattern_regions=PATTERN_REGIONS,
            search_regions=SEARCH_REGIONS,
        )

    # -----------------------------------------------------------------------
    # Internal — fixed-offset field readers
    # -----------------------------------------------------------------------

    def _read_ident_field(
        self,
        data: bytes,
        offset: int,
        length: int,
        expect_digits: bool = False,
        expect_upper: bool = False,
    ) -> Optional[str]:
        """
        Read a field from the ident block at a fixed offset.

        Reads ``length`` bytes starting at ``IDENT_BASE + offset``, decodes
        as ASCII, strips whitespace, and optionally validates the content.

        Args:
            data:          Full binary data.
            offset:        Offset relative to IDENT_BASE (0x3000).
            length:        Number of bytes to read.
            expect_digits: If True, all bytes must be ASCII digits (0–9).
            expect_upper:  If True, all bytes must be uppercase letters (A–Z).

        Returns:
            Decoded and stripped ASCII string, or None if the field is empty,
            contains non-printable characters, or fails validation.
        """
        abs_start = IDENT_BASE + offset
        abs_end = abs_start + length

        if abs_end > len(data):
            return None

        raw = data[abs_start:abs_end]

        # Validate expected character types before decoding
        if expect_digits and not all(0x30 <= b <= 0x39 for b in raw):
            return None
        if expect_upper and not all(0x41 <= b <= 0x5A for b in raw):
            return None

        # Decode as ASCII — reject if any byte is non-printable
        try:
            value = raw.decode("ascii", errors="strict").strip()
        except (UnicodeDecodeError, ValueError):
            return None

        # Filter out empty strings and strings with non-printable chars
        if not value or not all(32 <= ord(c) <= 126 for c in value):
            return None

        return value

    def _read_engine_suffix(self, data: bytes) -> Optional[str]:
        """
        Read the engine/HW suffix from the ident block at fixed offset 0x2C.

        The engine suffix is up to 6 characters long but may be shorter
        (e.g. "X14XE" is 5 chars).  Trailing spaces, nulls, and non-
        printable bytes are stripped.

        The field always starts with "X" followed by 2 digits and 2–4
        uppercase letters (e.g. "X16SZR", "X14XE").

        Returns:
            Engine suffix string (e.g. "X16SZR", "X14XE"), or None if
            the field cannot be read or does not match the expected format.
        """
        abs_start = IDENT_BASE + ENGINE_OFFSET
        abs_end = abs_start + ENGINE_LENGTH

        if abs_end > len(data):
            return None

        raw = data[abs_start:abs_end]

        # Decode and strip trailing whitespace / nulls
        try:
            value = raw.decode("ascii", errors="replace").rstrip("\x00 \xff")
        except (UnicodeDecodeError, ValueError):
            return None

        if not value:
            return None

        # Validate engine code format: X + 2 digits + 2–4 uppercase letters
        if len(value) < 5 or len(value) > 6:
            return None
        if value[0] != "X":
            return None
        if not value[1:3].isdigit():
            return None
        if not value[3:].isalpha() or not value[3:].isupper():
            return None

        return value
