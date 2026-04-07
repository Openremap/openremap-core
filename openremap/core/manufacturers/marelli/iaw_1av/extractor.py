"""
Magneti Marelli IAW 1AV ECU binary extractor.

Implements BaseManufacturerExtractor for the Magneti Marelli IAW 1AV family:
  IAW 1AV — single-point injection ECU used in VAG (Skoda/VW/Seat) vehicles
             with 1.0–1.6 litre naturally aspirated petrol engines (1996–2003).

These are simple 8/16-bit microcontroller-based ECUs with a fixed 64KB
(65,536 byte) binary layout:

  0x0000 – 0x000F : Erased vector area — all 0xFF (16 bytes)
  0x0010           : Code start — machine opcodes
  0x3D00 – 0x3E00 : Main ident block — full identification string:
                       "<OEM_PN> MARELLI 1AV        <FW_VER>"
                       e.g. "032906030AG MARELLI 1AV        F012"
  0x4400 – 0x4500 : Secondary ident area — lowercase "iaw1av" tag
  0xFFA0           : Sync marker AA55CC33

Detection is straightforward: exact 64KB size, erased header, presence of
"MARELLI" and "1AV" in the ident area, presence of "iaw1av" as secondary
confirmation, and absence of all Bosch/Siemens/Delphi/other-Marelli
exclusion signatures.
"""

import hashlib
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    EXCLUSION_CLEAR,
    FAMILY_ANCHOR,
    HEADER_MATCH,
    MANUFACTURER_CONFIRM,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.marelli.iaw_1av.patterns import (
    DETECTION_SIGNATURES,
    ERASED_HEADER_BYTE,
    ERASED_HEADER_SIZE,
    EXCLUSION_SIGNATURES,
    IAW_1AV_FILE_SIZE,
    IDENT_AREA_END,
    IDENT_AREA_START,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
)


class MarelliIAW1AVExtractor(BaseManufacturerExtractor):
    """
    Extractor for Magneti Marelli IAW 1AV ECU binaries.
    Handles: IAW 1AV
    """

    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Magneti Marelli"

    @property
    def supported_families(self) -> List[str]:
        return ["IAW 1AV"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Magneti Marelli IAW 1AV ECU.

        Six-phase check:
          1. Size gate — binary must be exactly 65,536 bytes (0x10000).
             All known IAW 1AV binaries are exactly 64KB.  Rejecting other
             sizes eliminates the vast majority of non-IAW 1AV binaries
             before any content inspection.
          2. Header check — first 16 bytes must all be 0xFF.
             The IAW 1AV vector area is erased (all-FF) and code begins
             at offset 0x10.  This structural signature is cheap to verify
             and eliminates most other 64KB binaries.
          3. Exclusion — reject if any Bosch / Siemens / Delphi / other
             Marelli family signature is found anywhere in the binary.
             Prevents false positives on other ECU families that happen to
             share the 64KB size.
          4. Marelli confirmation — b"MARELLI" must be present somewhere
             in the binary.  This is the definitive manufacturer anchor.
          5. Family anchor — b"1AV" must be present in the ident area
             (0x3D00–0x3E00).  Confirms the specific ECU family within
             the Marelli product range.
          6. Secondary confirm — b"iaw1av" must be present somewhere in
             the binary.  The lowercase family tag provides a second,
             independent confirmation of the ECU family.
        """
        evidence: list[str] = []

        # Phase 1 — size gate: IAW 1AV binaries are exactly 64KB.
        if len(data) != IAW_1AV_FILE_SIZE:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 2 — header check: first 16 bytes must all be 0xFF.
        header = data[:ERASED_HEADER_SIZE]
        if not all(b == ERASED_HEADER_BYTE for b in header):
            self._set_evidence()
            return False
        evidence.append(HEADER_MATCH)

        # Phase 3 — exclusion: reject if any non-IAW-1AV signature is found.
        for excl in EXCLUSION_SIGNATURES:
            if excl in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 4 — Marelli confirmation: manufacturer name must be present.
        if b"MARELLI" not in data:
            self._set_evidence()
            return False
        evidence.append(MANUFACTURER_CONFIRM)

        # Phase 5 — family anchor: "1AV" must be in the ident area.
        ident_area = data[IDENT_AREA_START:IDENT_AREA_END]
        if b"1AV" not in ident_area:
            self._set_evidence()
            return False
        evidence.append(FAMILY_ANCHOR)

        # Phase 6 — secondary confirm: lowercase "iaw1av" must be present.
        if b"iaw1av" not in data:
            self._set_evidence()
            return False
        evidence.append("IAW1AV_CONFIRM")

        self._set_evidence(evidence)
        return True

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Magneti Marelli IAW 1AV
        ECU binary.

        Steps:
          1. Compute file hashes (MD5, SHA-256 of first 64KB).
          2. Extract raw printable ASCII strings from the ident area.
          3. Run all regex patterns against their assigned search regions.
          4. Resolve OEM part number from ident record or standalone pattern.
          5. Resolve ECU family tag (always "IAW 1AV" for this extractor).
          6. Resolve firmware/software version code.
          7. Resolve secondary iaw tag for confirmation.
          8. Set fields not applicable to IAW 1AV to None.
          9. Build compound match key (IAW 1AV::<software_version>).

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from ident area (display + fallback) ---
        raw_strings = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_area"],
            min_length=6,
            max_results=20,
        )
        result["raw_strings"] = raw_strings

        # --- Step 2: Run all patterns against their assigned regions ---
        raw_hits = self._run_patterns(data)

        # --- Step 3: Resolve OEM part number ---
        oem_part_number = self._resolve_oem_part_number(raw_hits)
        result["oem_part_number"] = oem_part_number

        # --- Step 4: Resolve ECU family ---
        ecu_family = self._resolve_ecu_family(raw_hits)
        result["ecu_family"] = ecu_family

        # --- Step 5: ECU variant — same as family for IAW 1AV ---
        result["ecu_variant"] = ecu_family

        # --- Step 6: Resolve software version ---
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 7: Fields not present in IAW 1AV binaries ---
        result["hardware_number"] = None
        result["calibration_id"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 8: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,  # same for IAW 1AV
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """Run all IAW 1AV patterns against their assigned search regions."""
        return self._run_all_patterns(
            data=data,
            patterns=PATTERNS,
            pattern_regions=PATTERN_REGIONS,
            search_regions=SEARCH_REGIONS,
        )

    def _resolve_oem_part_number(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> Optional[str]:
        """
        Resolve the VAG OEM part number.

        Priority:
          1. Standalone oem_part_number pattern (lookahead-anchored to MARELLI).
          2. First field of the ident_record (capturing group 1 contains
             the full match including the OEM PN — extract leading digits+letters).

        Returns:
            VAG OEM part number string, or None if not found.
        """
        # Direct hit from the lookahead-anchored pattern
        oem = self._first_hit(raw_hits, "oem_part_number")
        if oem:
            return oem

        # Fallback: extract from the full ident record match
        ident = self._first_hit(raw_hits, "ident_record")
        if ident:
            # The ident_record full match starts with the OEM PN
            # e.g. "032906030AG MARELLI 1AV        F012"
            # Split on whitespace and take the first token.
            parts = ident.split()
            if parts:
                return parts[0]

        return None

    def _resolve_ecu_family(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> str:
        """
        Resolve the ECU family string.

        Priority:
          1. ECU family tag extracted from the ident string (e.g. "1AV").
             Normalised to "IAW 1AV" for consistency with the Marelli
             product naming convention.
          2. IAW tag from the secondary area (e.g. "iaw1av").
             Normalised to "IAW 1AV".
          3. Fallback: "IAW 1AV" — this extractor only handles one family.

        Returns:
            ECU family string, always "IAW 1AV" for this extractor.
        """
        # Check for the family tag from the ident string
        family_tag = self._first_hit(raw_hits, "ecu_family_tag")
        if family_tag:
            # The full match is e.g. "MARELLI 1AV"; extract just the tag
            # after "MARELLI ".  The capturing group in the pattern yields
            # the full match (group 0), so we parse the tag from the end.
            tag = family_tag.split()[-1] if family_tag.split() else family_tag
            return f"IAW {tag}"

        # Fallback: check the secondary lowercase iaw tag
        iaw_tag = self._first_hit(raw_hits, "iaw_tag")
        if iaw_tag:
            # "iaw1av" → "IAW 1AV"
            # Extract the generation part after "iaw" and format it.
            gen = iaw_tag[3:].upper()  # "1av" → "1AV"
            return f"IAW {gen}"

        # Ultimate fallback — this extractor only handles IAW 1AV.
        return "IAW 1AV"

    def _resolve_software_version(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> Optional[str]:
        """
        Resolve the firmware/software version code.

        Priority:
          1. Dedicated software_version pattern (e.g. "MARELLI 1AV ... F012"
             — capturing group extracts "F012").
          2. Last field of the ident_record (the FW version is always the
             final non-space token in the ident string).

        Returns:
            Software version string (e.g. "F012"), or None if not found.
        """
        # Direct hit from the dedicated software_version pattern.
        # The pattern's full match (group 0) is the entire "MARELLI 1AV ... F012"
        # substring, so we extract the last whitespace-delimited token.
        sw_match = self._first_hit(raw_hits, "software_version")
        if sw_match:
            parts = sw_match.split()
            if parts:
                return parts[-1]

        # Fallback: extract from the full ident record match.
        ident = self._first_hit(raw_hits, "ident_record")
        if ident:
            # e.g. "032906030AG MARELLI 1AV        F012"
            parts = ident.split()
            if parts:
                return parts[-1]

        return None
