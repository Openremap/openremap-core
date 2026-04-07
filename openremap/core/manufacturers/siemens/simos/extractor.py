"""
Siemens SIMOS ECU binary extractor.

Implements BaseManufacturerExtractor for Siemens SIMOS ECU families:
SIMOS, SIMOS2, SIMOS3

SIMOS ECUs were used primarily in VAG (VW/Audi/Skoda/Seat) petrol vehicles
from the late 1990s through the mid-2000s.  Three binary sub-types exist:

  A) 131 KB (131072 bytes) — SIMOS EEPROM (27c010 style)
     Header prefix: \\x02 (1 byte) — 8051 reset vector style.
     Known variants: \\x02\\x58\\x95\\x05, \\x02\\x56\\x9f\\x05.
     Very sparse ASCII — essentially no readable strings.

  B) 262 KB (262144 bytes) — SIMOS 2.x EEPROM dumps
     Header prefixes: \\xc0\\x64 (VW Golf 4), \\xfa\\x00 (Skoda Octavia).
     Very sparse ASCII — identifiers mostly live in filenames only.

  C) 524 KB (524288 bytes) — SIMOS 3.x full flash
     Header prefix: \\xf0\\x30 (2 bytes) — common to ALL 524KB bins.
     Known variants: \\xf0\\x30\\xe8\\x44, \\xf0\\x30\\x58\\x74,
                     \\xf0\\x30\\xa0\\x4c, \\xf0\\x30\\xc0\\x6c.
     Most bins are "dark" (no readable strings).  Rare exceptions carry
     a full OEM ident block with Siemens part number, SIMOS family label,
     VAG part number, project codes, and calibration dataset references.

Detection is medium-difficulty: most bins contain no ASCII identifiers at
all, so the extractor relies on a layered strategy of signature keywords,
header prefix matching, file-size gating, and explicit exclusion of all
known Bosch / SID / PPD / Simtec families.
"""

import hashlib
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    EXCLUSION_CLEAR,
    DETECTION_SIGNATURE,
    SIZE_MATCH,
    HEADER_MATCH,
)
from openremap.core.manufacturers.siemens.simos.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SIMOS_131KB_HEADER,
    SIMOS_262KB_HEADERS,
    SIMOS_524KB_HEADER,
    VALID_SIZES,
)


class SiemensSimosExtractor(BaseManufacturerExtractor):
    """
    Extractor for Siemens SIMOS ECU binaries.
    Handles: SIMOS, SIMOS2, SIMOS3
    """

    detection_strength = DetectionStrength.MODERATE

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Siemens"

    @property
    def supported_families(self) -> List[str]:
        return ["SIMOS", "SIMOS2", "SIMOS3"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if the binary belongs to a Siemens SIMOS ECU.

        Detection strategy (layered, fast-to-slow):
          1. Exclude any binary containing Bosch / SID / PPD / Simtec
             signatures — these are never SIMOS.
          2. If any DETECTION_SIGNATURES keyword is found in the binary,
             return True immediately.  Keywords like b"SIMOS", b"5WP4",
             b"111s21", b"s21_", b"cas21" are definitive.
          3. Fallback: if the file size is one of the three known SIMOS
             sizes (131KB, 262KB, 524KB) AND the header magic at offset 0
             matches the expected bytes for that size, return True.
          4. Otherwise return False.
        """
        evidence: list[str] = []
        size = len(data)

        # ------------------------------------------------------------------
        # Guard — reject binaries that belong to other manufacturers.
        # Only scan the first 512KB to keep the check fast.
        # ------------------------------------------------------------------
        scan_region = data[: min(size, 0x80000)]
        for sig in EXCLUSION_SIGNATURES:
            if sig in scan_region:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # ------------------------------------------------------------------
        # Positive check 1 — definitive keyword signatures.
        # These strings are exclusive to Siemens SIMOS binaries.
        # ------------------------------------------------------------------
        for sig in DETECTION_SIGNATURES:
            if sig in data:
                evidence.append(DETECTION_SIGNATURE)
                self._set_evidence(evidence)
                return True

        # ------------------------------------------------------------------
        # Positive check 2 — header prefix + size gate.
        # Many SIMOS bins are completely "dark" (no ASCII), so we fall back
        # to structural detection: known file size + matching header prefix.
        #
        # Real SIMOS bins share a common prefix but vary in the remaining
        # header bytes across vehicle models, so we match on the shortest
        # prefix common to all known bins of each size class.
        # ------------------------------------------------------------------
        if size in VALID_SIZES and len(data) >= 2:
            if size == 524288 and data[:2] == SIMOS_524KB_HEADER:
                evidence.append(SIZE_MATCH)
                evidence.append(HEADER_MATCH)
                self._set_evidence(evidence)
                return True
            if size == 262144:
                header2 = data[:2]
                if any(header2 == prefix for prefix in SIMOS_262KB_HEADERS):
                    evidence.append(SIZE_MATCH)
                    evidence.append(HEADER_MATCH)
                    self._set_evidence(evidence)
                    return True
            if size == 131072 and data[:1] == SIMOS_131KB_HEADER:
                evidence.append(SIZE_MATCH)
                evidence.append(HEADER_MATCH)
                self._set_evidence(evidence)
                return True

        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Siemens SIMOS binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """

        size = len(data)

        result: Dict = {
            "manufacturer": self.name,
            "file_size": size,
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from ident area (display + fallback) ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_area"],
            min_length=6,
            max_results=20,
        )

        # --- Step 2: Run all patterns against their assigned regions ---
        raw_hits = self._run_patterns(data)

        # --- Step 3: Resolve Siemens hardware part number (5WP4xxx) ---
        hardware_number = self._first_hit(raw_hits, "siemens_part")
        result["hardware_number"] = hardware_number

        # --- Step 4: Resolve ECU family ---
        ecu_family = self._resolve_ecu_family(raw_hits, size)
        result["ecu_family"] = ecu_family

        # --- Step 5: Resolve software version / serial code ---
        software_version = self._first_hit(raw_hits, "serial_code")
        result["software_version"] = software_version

        # --- Step 6: Resolve calibration ID ---
        calibration_id = self._resolve_calibration_id(raw_hits)
        result["calibration_id"] = calibration_id

        # --- Step 7: Resolve OEM part number ---
        result["oem_part_number"] = self._first_hit(raw_hits, "oem_part_number")

        # --- Step 8: Fill fields not applicable to SIMOS ---
        result["ecu_variant"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 9: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """Run all SIMOS patterns against their assigned search regions."""
        return self._run_all_patterns(
            data=data,
            patterns=PATTERNS,
            pattern_regions=PATTERN_REGIONS,
            search_regions=SEARCH_REGIONS,
        )

    def _resolve_ecu_family(
        self,
        raw_hits: Dict[str, List[str]],
        size: int,
    ) -> str:
        """
        Resolve the ECU family string.

        Priority:
          1. Specific SIMOS label from binary (e.g. "SIMOS   2441")
             → normalised to "SIMOS 2441".
          2. Generic "SIMOS" keyword from binary.
          3. Size-based inference:
               131KB → "SIMOS"   (EEPROM, generation unknown)
               262KB → "SIMOS2"  (SIMOS 2.x EEPROM)
               524KB → "SIMOS3"  (SIMOS 3.x full flash)
          4. Fallback: "SIMOS".
        """
        # Check for specific SIMOS label first (e.g. "SIMOS   2441")
        simos_label = self._first_hit(raw_hits, "simos_label")
        if simos_label:
            # Normalise internal whitespace: "SIMOS   2441" → "SIMOS 2441"
            return " ".join(simos_label.split())

        # Generic SIMOS keyword present?
        if self._first_hit(raw_hits, "ecu_family"):
            # Infer generation from file size when possible
            if size == 262144:
                return "SIMOS2"
            if size == 524288:
                return "SIMOS3"
            return "SIMOS"

        # No SIMOS string in binary — infer from size alone
        if size == 262144:
            return "SIMOS2"
        if size == 524288:
            return "SIMOS3"

        return "SIMOS"

    def _resolve_calibration_id(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> Optional[str]:
        """
        Resolve calibration identifier from project codes and dataset refs.

        Priority:
          1. Calibration dataset filename (e.g. "cas21146.DAT")
          2. Project code (e.g. "s21_2441", "s2114601")
        """
        cal_dataset = self._first_hit(raw_hits, "calibration_dataset")
        if cal_dataset:
            return cal_dataset

        project_code = self._first_hit(raw_hits, "project_code")
        if project_code:
            return project_code

        return None
