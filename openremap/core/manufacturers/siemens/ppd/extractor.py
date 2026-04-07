"""
Siemens PPD ECU binary extractor.

Implements BaseManufacturerExtractor for the Siemens PPD1.x diesel ECU family:
PPD1.1, PPD1.2, PPD1.5

These ECUs were used in VAG 2.0 TDI PD (Pumpe-Düse / unit injector) engines
from approximately 2003–2008.  The Siemens/VDO PPD controller was later
succeeded by Continental SID families when common-rail injection replaced
the unit injector system.

Binary analysis reference:
  - File sizes observed: 249856 (250 KB), 2097152 (2 MB), 2097154 (2 MB + 2)
  - Ident record lives in the first 64 KB
  - Example ident record:
    6576286135--    111SN100K5400000111SN100K5400000111SN100K5400000
    CASN1K54.DAT    03G906018DT R4 2.0l PPD1.2
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    DETECTION_SIGNATURE,
    EXCLUSION_CLEAR,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.siemens.ppd.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
)


class SiemensPPDExtractor(BaseManufacturerExtractor):
    """
    Extractor for Siemens PPD1.x ECU binaries.
    Handles: PPD1.1, PPD1.2, PPD1.5
    """

    detection_strength = DetectionStrength.WEAK

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Siemens"

    @property
    def supported_families(self) -> List[str]:
        return ["PPD1.1", "PPD1.2", "PPD1.5"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if the binary belongs to the Siemens PPD1.x family.

        Detection strategy:
          1. Reject if ANY Bosch/Marelli exclusion signature is present —
             prevents false positives against Bosch EDC17 and similar families
             that share the VAG 03G906 part number prefix.
          2. Accept if at least ONE PPD detection signature is found.

        The exclusion check scans the first 512 KB (enough to cover all known
        Bosch ident areas).  The detection check scans the full binary because
        the PPD1.x family string may appear at variable offsets depending on
        the dump tool and flash layout.
        """
        evidence: list[str] = []

        # ------------------------------------------------------------------
        # Guard — reject Bosch and other manufacturer signatures.
        # Scans the first 512 KB for speed.
        # ------------------------------------------------------------------
        exclusion_region = data[:0x80000]
        for sig in EXCLUSION_SIGNATURES:
            if sig in exclusion_region:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # ------------------------------------------------------------------
        # Positive detection — at least one PPD signature must be present.
        # ------------------------------------------------------------------
        if any(sig in data for sig in DETECTION_SIGNATURES):
            evidence.append(DETECTION_SIGNATURE)
            self._set_evidence(evidence)
            return True

        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Siemens PPD binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from header (display + fallback) ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["header"],
            min_length=8,
            max_results=20,
        )

        # --- Step 2: Run all patterns against their assigned regions ---
        raw_hits = self._run_all_patterns(
            data, PATTERNS, PATTERN_REGIONS, SEARCH_REGIONS
        )

        # --- Step 3: Resolve ECU family ---
        ecu_family = self._resolve_ecu_family(raw_hits)
        result["ecu_family"] = ecu_family

        # --- Step 4: Resolve software version (serial code) ---
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 5: Resolve OEM part number ---
        oem_part_number = self._resolve_oem_part_number(raw_hits)
        result["oem_part_number"] = oem_part_number

        # --- Step 6: Resolve ECU variant (OEM part number) ---
        result["ecu_variant"] = oem_part_number

        # --- Step 7: Resolve calibration ID ---
        result["calibration_id"] = self._resolve_calibration_id(raw_hits)

        # --- Step 8: Resolve hardware number ---
        # PPD binaries do not embed a standalone hardware number.
        result["hardware_number"] = self._first_hit(raw_hits, "hw_sw_version")

        # --- Step 9: Resolve displacement ---
        result["displacement"] = self._first_hit(raw_hits, "displacement")

        # --- Step 10: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=oem_part_number,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_ecu_family(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the PPD family identifier.

        Returns the first matched PPD family string (e.g. "PPD1.2").
        Falls back to the generic "PPD1" if the family pattern matched
        but somehow produced an unexpected value.
        """
        family = self._first_hit(raw_hits, "ecu_family")
        if family:
            return family

        # Fallback: if oem_part_full matched, extract the family from it.
        full_hit = self._first_hit(raw_hits, "oem_part_full")
        if full_hit:
            m = re.search(rb"PPD1\.\d", full_hit.encode("ascii", errors="ignore"))
            if m:
                return m.group(0).decode("ascii")

        return None

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Resolve the software version from the serial code.

        The 10-digit serial code (e.g. "6576286135") is the primary
        matching identifier for PPD binaries — it is unique per software
        revision, analogous to the Bosch SW version string.

        Falls back to the hw_sw_version string if no serial code is found.
        """
        serial = self._first_hit(raw_hits, "serial_code")
        if serial:
            return serial

        # Fallback: dot-delimited version string
        return self._first_hit(raw_hits, "hw_sw_version")

    def _resolve_oem_part_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the VAG OEM part number.

        Prefers the standalone oem_part_number pattern.
        If the full authoritative ident string was matched, extracts the
        part number prefix from it as a fallback.
        """
        part = self._first_hit(raw_hits, "oem_part_number")
        if part:
            return part

        # Fallback: extract from the full ident string
        full_hit = self._first_hit(raw_hits, "oem_part_full")
        if full_hit:
            m = re.search(
                rb"03G906\d{3}[A-Z]{0,2}",
                full_hit.encode("ascii", errors="ignore"),
            )
            if m:
                return m.group(0).decode("ascii")

        return None

    def _resolve_calibration_id(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the calibration dataset identifier.

        Extracts the CASN reference (e.g. "CASN1K54.DAT") as the
        calibration ID.  Returns the full filename including .DAT suffix.
        """
        return self._first_hit(raw_hits, "calibration_dataset")
