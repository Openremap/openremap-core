"""
Bosch Motronic MP 9.0 ECU binary extractor.

Identifies and extracts metadata from Bosch Motronic MP 9.0 petrol ECU
binaries — 64 KB dumps from VW/Seat/Skoda 1.0–1.6L engines (1996–2002).

Binary layout (64 KB = 0x10000 bytes):

    0x0000 – 0xFBFF   Code + calibration data (Motorola 68HC11)
    ~0xFC3C            Ident block: HW + SW + OEM part + family label
    ~0xFCBF            Slash-delimited metadata (family, DAMOS, date)
    ~0xFEE8            Printable ASCII lookup table (always last)

Ident block format:

    0261204593 1037357494 MP9 0006K0906027E  MOTRONIC MP 9.0    S023

Slash block format:

     53/1/MP9.0/51/4007.01/DAMOS94/1832-S/183205-S/100497/

Detection strategy:

    Phase 1 — Reject on any exclusion signature in the full 64 KB.
    Phase 2 — Reject if file size is not exactly 64 KB (0x10000).
    Phase 3 — Accept if b"MOTRONIC MP 9" is found in the last 2 KB.
    Phase 4 — Accept if b"MP9" AND a valid "0261xxxxxx" HW pattern
              are both present in the last 2 KB (fallback).

Verified samples:
    Seat Ibiza 6K0906027E  0261204593  -> MP9.0  sw=1037357494  oem=6K0906027E
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    DETECTION_SIGNATURE as _DETECTION_SIGNATURE_TAG,
    EXCLUSION_CLEAR,
    FAMILY_STRING,
    IDENT_BLOCK,
    SIZE_MATCH,
)
from openremap.core.manufacturers.bosch.mp9.patterns import (
    EXCLUSION_SIGNATURES,
    FAMILY_NORMALISATION,
    PATTERNS,
    PATTERN_REGIONS,
    PRIMARY_DETECTION_SIGNATURE,
    SEARCH_REGIONS,
    SECONDARY_DETECTION_SIGNATURE,
    SUPPORTED_SIZES,
)


class BoschMP9Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic MP 9.0 petrol ECU binaries.

    Handles 64 KB dumps from VW/Seat/Skoda 1.0–1.6L engines.
    The ident block and slash-delimited metadata reside in the last ~1 KB
    of the binary and follow a rigid, single-line ASCII format.

    Extraction priority:
        1. Combined ident_block regex → HW, SW, OEM part, family
        2. Slash block regex → family confirmation, DAMOS version
        3. Standalone fallback patterns → HW, SW, OEM part individually

    The match_key is built as ``MP9::<software_version>``.
    """

    detection_strength = DetectionStrength.STRONG

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["MP9", "MP9.0"]

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch Motronic MP 9.0 ECU.

        Four-phase check:

          Phase 1 — Reject on any exclusion signature in the full binary.
                    Guards against claiming ME7, M5.x, EDC15/16/17 bins.

          Phase 2 — Reject if file size is not exactly 64 KB (0x10000).
                    All known MP9 dumps are exactly 64 KB. Larger bins
                    with MOTRONIC belong to M5.x or ME7 families.

          Phase 3 — Accept if the primary signature b"MOTRONIC MP 9" is
                    found in the last 2 KB. This label is unique to MP9
                    and never appears in any other known Bosch family.

          Phase 4 — Fallback: accept if b"MP9" AND a valid 10-digit HW
                    pattern (0261xxxxxx) are both present in the last 2 KB.
                    Covers any variant where the full label might be
                    slightly different but the key markers are present.
        """
        evidence: list[str] = []

        # Phase 1 — exclusion check
        for excl in EXCLUSION_SIGNATURES:
            if excl in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 2 — size gate
        if len(data) not in SUPPORTED_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Search area: last 2 KB
        ident_area = data[-0x800:]

        # Phase 3 — primary detection signature
        if PRIMARY_DETECTION_SIGNATURE in ident_area:
            evidence.append(_DETECTION_SIGNATURE_TAG)
            self._set_evidence(evidence)
            return True

        # Phase 4 — secondary: MP9 + HW pattern
        if SECONDARY_DETECTION_SIGNATURE in ident_area:
            if re.search(rb"0261\d{6}", ident_area):
                evidence.append(FAMILY_STRING)
                evidence.append(IDENT_BLOCK)
                self._set_evidence(evidence)
                return True

        self._set_evidence()
        return False

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch MP 9.0 binary.

        Returns a dict compatible with ECUIdentifiersSchema.
        """
        file_size = len(data)
        md5 = hashlib.md5(data).hexdigest()
        sha256_first_64kb = hashlib.sha256(data[:0x10000]).hexdigest()

        # Run all patterns against their assigned search regions
        raw_hits = self._run_all_patterns(
            data, PATTERNS, PATTERN_REGIONS, SEARCH_REGIONS
        )

        # Parse the combined ident block first (highest fidelity)
        hw_from_ident, sw_from_ident, oem_from_ident = self._parse_ident_block(raw_hits)

        # Resolve individual fields with fallbacks
        ecu_family = self._resolve_ecu_family(raw_hits)
        software_version = sw_from_ident or self._resolve_software_version(raw_hits)
        hardware_number = hw_from_ident or self._resolve_hardware_number(raw_hits)
        oem_part_number = oem_from_ident or self._resolve_oem_part_number(raw_hits)

        # Normalise family for match key
        ecu_variant = ecu_family  # MP9 has no sub-variants
        normalised_family = FAMILY_NORMALISATION.get(ecu_family or "", ecu_family)

        match_key = self.build_match_key(
            ecu_family=normalised_family,
            ecu_variant=normalised_family,
            software_version=software_version,
        )

        # Extract raw printable strings from the ident area
        raw_strings = self.extract_raw_strings(
            data, SEARCH_REGIONS["ident_area"], min_length=8, max_results=20
        )

        return {
            "manufacturer": self.name,
            "file_size": file_size,
            "md5": md5,
            "sha256_first_64kb": sha256_first_64kb,
            "raw_strings": raw_strings,
            "ecu_family": normalised_family or "MP9",
            "ecu_variant": ecu_variant,
            "software_version": software_version,
            "hardware_number": hardware_number,
            "calibration_version": None,
            "sw_base_version": None,
            "serial_number": None,
            "dataset_number": None,
            "calibration_id": None,
            "oem_part_number": oem_part_number,
            "match_key": match_key,
        }

    # ------------------------------------------------------------------
    # Ident block parser
    # ------------------------------------------------------------------

    def _parse_ident_block(
        self, raw_hits: Dict[str, List[str]]
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse the combined ident block regex result.

        The ident_block pattern captures:
            group 1 = HW  (e.g. "0261204593")
            group 2 = SW  (e.g. "1037357494")
            group 3 = OEM (e.g. "6K0906027E")

        Returns (hw, sw, oem) — any may be None if the block was not found.
        """
        hit = self._first_hit(raw_hits, "ident_block")
        if not hit:
            return None, None, None

        # The full match contains all groups concatenated. We need to re-run
        # the regex to extract individual groups from the ident area.
        # Instead, extract the components via standalone patterns from the
        # combined match string.
        hw_match = re.search(r"(0261\d{6})", hit)
        sw_match = re.search(r"(1037\d{6})", hit)

        hw = hw_match.group(1) if hw_match else None
        sw = sw_match.group(1) if sw_match else None

        # OEM part is the alphanumeric token after "MP9 000"
        oem_match = re.search(r"MP9\s+\d{3}(\w{10,14})", hit)
        oem = oem_match.group(1) if oem_match else None

        return hw, sw, oem

    # ------------------------------------------------------------------
    # Individual field resolvers
    # ------------------------------------------------------------------

    def _resolve_ecu_family(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the ECU family name.

        Priority:
            1. Family string from slash block (e.g. "MP9.0")
            2. Standalone ecu_family_string pattern hit
            3. Default to "MP9" if the ident block matched at all
        """
        # Try slash block family first
        slash_hit = self._first_hit(raw_hits, "slash_block")
        if slash_hit:
            family_match = re.search(r"(MP9[\d\.]+)", slash_hit)
            if family_match:
                return family_match.group(1)

        # Standalone family string
        family_hit = self._first_hit(raw_hits, "ecu_family_string")
        if family_hit:
            return family_hit

        # Fallback — if we got this far and the ident block exists
        if self._first_hit(raw_hits, "ident_block"):
            return "MP9"

        return None

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Resolve the software version from standalone pattern fallback.

        The ident_block parser is preferred; this is the last resort.
        Returns the first 10-digit "1037xxxxxx" match.
        """
        hit = self._first_hit(raw_hits, "software_version")
        if hit:
            # Ensure we return exactly 10 characters
            match = re.match(r"(1037\d{6})", hit)
            if match:
                return match.group(1)
        return None

    def _resolve_hardware_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the hardware number from standalone pattern fallback.

        The ident_block parser is preferred; this is the last resort.
        Returns the first 10-digit "0261xxxxxx" match.
        """
        hit = self._first_hit(raw_hits, "hardware_number")
        if hit:
            match = re.match(r"(0261\d{6})", hit)
            if match:
                return match.group(1)
        return None

    def _resolve_oem_part_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the OEM (VAG) part number from standalone pattern fallback.

        The ident_block parser is preferred; this is the last resort.
        Returns the first match of the xxx906xxxX pattern.
        """
        hit = self._first_hit(raw_hits, "oem_part_number")
        return hit if hit else None
