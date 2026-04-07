"""
Bosch ME1.5.5 ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Motronic ME1.5.5 family:
  ME1.5.5 — Opel/Vauxhall petrol ECUs (Astra-G 2.0T, Corsa-C 1.2 16V, 1999–2005)
             CPU: Infineon/Siemens C167CR
             ROM: 512KB external flash

  Binary layout is similar to ME7 (same ZZ ident block at 0x10000) but the
  ZZ descriptor uses printable ASCII after "ZZ" — e.g. "ZZ41/1/ME1.5.5/..."
  where byte 0x10002 is '4' (0x34).  The ME7 extractor correctly rejects
  these because its Phase 3 guard requires non-printable bytes after "ZZ".

  Detection fingerprint:
    1. File size = 512KB (0x80000)
    2. b"ZZ" at offset 0x10000
    3. Printable ASCII byte at 0x10002 (0x20–0x7E range)
    4. b"/ME1.5.5/" in the ident block (0x10000–0x10040)
    5. No exclusion signatures present

  SW version: "1037" + 6 digits (Bosch standard format).
  HW number:  "0261" + 6 digits (Bosch standard format).
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    EXCLUSION_CLEAR,
    FAMILY_ANCHOR,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.bosch.me155.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    ME155_FAMILY_ANCHOR,
    ME155_ZZ_OFFSET,
    ME155_ZZ_PREFIX,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    VALID_FILE_SIZES,
)


class BoschME155Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic ME1.5.5 ECU binaries.

    Handles:
      ME1.5.5 — Opel/Vauxhall petrol (Astra-G Z20LET, Corsa-C Z12XE/Z12XEP)
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
        return ["ME1.5.5"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch ME1.5.5 ECU.

        Four-phase check:
          0. Size gate — must be exactly 512KB (0x80000).
          1. Exclusion — reject if any EDC17/ME7/EDC15/etc. signature is found.
          2. ZZ marker — b"ZZ" at offset 0x10000 with a printable ASCII byte
             at 0x10002 (the distinguishing feature from ME7 which has
             non-printable bytes there).
          3. Family anchor — b"/ME1.5.5/" must appear in the ident area
             (0x10000–0x10040) to confirm this is ME1.5.5 specifically and
             not some other ECU that happens to have "ZZ" + printable at
             that offset.
        """
        evidence: list[str] = []

        # Phase 0 — size gate
        if len(data) not in VALID_FILE_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 1 — exclusion signatures
        # Search the first 256KB — sufficient for all known exclusion strings.
        scan_region = data[:0x40000]
        for excl in EXCLUSION_SIGNATURES:
            if excl in scan_region:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 2 — ZZ marker at 0x10000 with printable third byte
        zz_end = ME155_ZZ_OFFSET + len(ME155_ZZ_PREFIX)
        if len(data) <= zz_end + 1:
            self._set_evidence()
            return False
        if data[ME155_ZZ_OFFSET:zz_end] != ME155_ZZ_PREFIX:
            self._set_evidence()
            return False
        # Third byte must be printable ASCII — this is the key differentiator
        # from ME7, which has non-printable bytes (0xFF, 0x00, 0x01) here.
        third_byte = data[zz_end]
        if not (0x20 <= third_byte <= 0x7E):
            self._set_evidence()
            return False
        evidence.append("ZZ_MARKER")

        # Phase 3 — family anchor confirmation
        # The ZZ descriptor in the ident area must contain "/ME1.5.5/".
        ident_window = data[ME155_ZZ_OFFSET : ME155_ZZ_OFFSET + 0x40]
        if ME155_FAMILY_ANCHOR not in ident_window:
            self._set_evidence()
            return False
        evidence.append(FAMILY_ANCHOR)

        self._set_evidence(evidence)
        return True

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch ME1.5.5 ECU binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from ident block ---
        raw_strings = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_block"],
            min_length=8,
            max_results=20,
        )
        result["raw_strings"] = raw_strings

        # --- Step 2: Run all patterns against their assigned regions ---
        raw_hits = self._run_patterns(data)

        # --- Step 3: Resolve ECU family ---
        ecu_family = "ME1.5.5"
        result["ecu_family"] = ecu_family

        # --- Step 4: ME1.5.5 has no separate variant — family IS variant ---
        result["ecu_variant"] = ecu_family

        # --- Step 5: Resolve hardware number ---
        hardware_number = self._resolve_hardware_number(raw_hits)
        result["hardware_number"] = hardware_number

        # --- Step 6: Resolve software version ---
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 7: Resolve calibration ID ---
        result["calibration_id"] = self._resolve_calibration_id(raw_hits)

        # --- Step 8: Resolve OEM part number (not typically present) ---
        result["oem_part_number"] = None

        # --- Step 9: Fields not present in ME1.5.5 binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 10: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — pattern runner
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """Run all ME1.5.5 patterns against their assigned search regions."""
        return self._run_all_patterns(data, PATTERNS, PATTERN_REGIONS, SEARCH_REGIONS)

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_hardware_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the hardware part number (e.g. "0261206332").

        ME1.5.5 HW numbers are always exactly 10 digits starting with "0261".
        In the binary they are stored with a leading "2" byte ("20261xxxxxx")
        but the regex captures only the "0261xxxxxx" part.
        """
        hits = raw_hits.get("hardware_number", [])
        for hit in hits:
            # Validate it's exactly 10 digits starting with 0261
            if re.match(r"^0261\d{6}$", hit):
                return hit
        return None

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Resolve the software version string (e.g. "1037354961").

        All ME1.5.5 SW versions are exactly "1037" + 6 digits (10 chars).
        """
        hits = raw_hits.get("software_version", [])
        for hit in hits:
            if re.match(r"^1037\d{6}$", hit) and not re.match(r"^0+$", hit):
                return hit
        return None

    def _resolve_calibration_id(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the calibration ID from the ZZ descriptor string.

        The calibration ID is the 5th slash-delimited field in the ZZ descriptor:
          ZZ41/1/ME1.5.5/6/88.0//12g/...  → calibration_id = "88.0"
          ZZ43/1/ME1.5.5/6/100.1//0614/... → calibration_id = "100.1"
        """
        variant_hits = raw_hits.get("ecu_variant_string", [])
        for variant_str in variant_hits:
            parts = variant_str.split("/")
            # ZZ41/1/ME1.5.5/6/88.0//12g/... → index 4 = "88.0"
            # But the string starts with "ZZ41" not "/ZZ41", so:
            # parts[0]="ZZ41", [1]="1", [2]="ME1.5.5", [3]="6", [4]="88.0"
            if len(parts) >= 5:
                candidate = parts[4].strip()
                if candidate and len(candidate) >= 2:
                    return candidate

        # Fall back to standalone calibration_id pattern hits
        cal_hits = raw_hits.get("calibration_id", [])
        if cal_hits:
            return cal_hits[0]
        return None
