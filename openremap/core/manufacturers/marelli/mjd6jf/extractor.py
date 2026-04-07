"""
Magneti Marelli MJD 6JF ECU binary extractor.

Implements BaseManufacturerExtractor for the Magneti Marelli MJD 6JF diesel
ECU family, used in GM/Opel/Vauxhall diesel applications (e.g. Corsa D/E
1.3 CDTI with UZ13DT engine).

Two binary layouts are supported:

  462848 bytes (0x71000) — Calibration-only dump
    16-byte ASCII header "C M D - M C D   " followed by 0xFF padding,
    then calibration data from 0x60000 onward.

  458752 bytes (0x70000) — Full flash dump
    PowerPC executable code from 0x00000, calibration data from 0x60000.
    Contains PPCCMFPE300/PPCCMFPI300 CPU identifiers and Italian dev
    comments ("Progetto SW 6JF") in the code section.

Both layouts share an identical identity block at 0x60090 containing:
  - Engine code (e.g. "UZ13DT")
  - AA55CC33 sync markers bracketing the SW version
  - GM/OEM part number
  - Marelli part number
  - Calibration cross-references

A sub-family block at ~0x6E000 contains the "6JF   MUST_C..." tag.
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    EXCLUSION_CLEAR,
    FAMILY_ANCHOR as FAMILY_ANCHOR_TAG,
    MANUFACTURER_CONFIRM,
    SIZE_MATCH,
    SYNC_MARKER as SYNC_MARKER_TAG,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.marelli.mjd6jf.patterns import (
    EXCLUSION_SIGNATURES,
    FAMILY_ANCHOR,
    MARELLI_SIGNATURE,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SYNC_MARKER,
    VALID_FILE_SIZES,
)


class MarelliMJD6JFExtractor(BaseManufacturerExtractor):
    """
    Extractor for Magneti Marelli MJD 6JF ECU binaries.

    Handles: MJD 6JF (458752 and 462848 byte variants).
    Used in: GM/Opel/Vauxhall 1.3 CDTI diesel applications.

    Detection is anchored on:
      - File size gate (458752 or 462848 bytes)
      - Exclusion of all competing ECU families (Bosch, Siemens, Delphi, IAW)
      - AA55CC33 sync marker presence
      - b"MAG" in identity block (0x60000–0x61000)
      - b"6JF" family anchor in calibration area (0x60000–0x70000)
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
        return ["MJD 6JF"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary belongs to the Magneti Marelli MJD 6JF family.

        Five-phase check:

          Phase 1 — Size gate.
            Reject immediately if the file size is not one of the two known
            MJD 6JF sizes (458752 or 462848 bytes).  This eliminates the vast
            majority of non-MJD 6JF binaries with zero scan cost.

          Phase 2 — Exclusion signatures.
            Reject if any exclusion signature is found anywhere in the binary.
            The exclusion list covers all major competing ECU families:
              - Bosch (EDC17, MEDC17, EDC16, EDC15, ME7., BOSCH)
              - Siemens (5WK9, SIMOS, MOTRONIC)
              - Marelli IAW (IAW, iaw) — different Marelli family
              - Delphi (DELPHI, DEL  )
            This prevents false positives on binaries that happen to share
            the same file sizes (e.g. SID803 at 458752/462848 bytes).

          Phase 3 — Sync marker.
            The AA55CC33 sync marker must be present at least once in the
            binary.  This marker brackets the software version in the
            identity block and is unique to the Marelli MJD data structure.

          Phase 4 — Marelli confirmation.
            b"MAG" must be present in the identity block region
            (0x60000–0x61000).  This confirms a Magneti Marelli part number
            is embedded at the expected location.

          Phase 5 — Family anchor.
            b"6JF" must be present in the calibration area (0x60000–0x70000).
            This confirms the binary belongs specifically to the MJD 6JF
            family rather than another Marelli ECU type.

        This method is called for every registered extractor on every uploaded
        binary, so it is deliberately fast: no regex, only byte substring
        searches in bounded regions.
        """
        evidence: list[str] = []

        # ------------------------------------------------------------------
        # Phase 1 — Size gate.
        # ------------------------------------------------------------------
        if len(data) not in VALID_FILE_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # ------------------------------------------------------------------
        # Phase 2 — Exclusion signatures.
        # First hit → immediate rejection.
        # ------------------------------------------------------------------
        for sig in EXCLUSION_SIGNATURES:
            if sig in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # ------------------------------------------------------------------
        # Phase 3 — Sync marker (AA55CC33).
        # Must be present at least once anywhere in the binary.
        # ------------------------------------------------------------------
        if SYNC_MARKER not in data:
            self._set_evidence()
            return False
        evidence.append(SYNC_MARKER_TAG)

        # ------------------------------------------------------------------
        # Phase 4 — Marelli confirmation.
        # b"MAG" must be present in the identity block (0x60000–0x61000).
        # ------------------------------------------------------------------
        if MARELLI_SIGNATURE not in data[0x60000:0x61000]:
            self._set_evidence()
            return False
        evidence.append(MANUFACTURER_CONFIRM)

        # ------------------------------------------------------------------
        # Phase 5 — Family anchor.
        # b"6JF" must be present in the calibration area (0x60000–0x70000).
        # ------------------------------------------------------------------
        if FAMILY_ANCHOR not in data[0x60000:0x70000]:
            self._set_evidence()
            return False
        evidence.append(FAMILY_ANCHOR_TAG)

        self._set_evidence(evidence)
        return True

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Marelli MJD 6JF binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.

        Extraction pipeline:
          1. Mandatory fields — file_size, md5, sha256_first_64kb.
          2. Raw ASCII strings from the identity block (display + fallback).
          3. Run all regex patterns against their assigned search regions.
          4. Resolve software version.
          5. Resolve OEM part number.
          6. Resolve hardware number (Marelli part number).
          7. Resolve calibration ID (MUST code).
          8. Resolve ancillary fields (engine code, calibration ref).
          9. Set ECU family and variant.
         10. Build compound match key.
        """

        # --- Step 1: Mandatory fields ---
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 2: Raw ASCII strings from identity block (display + fallback) ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_block"],
            min_length=6,
            max_results=20,
        )

        # --- Step 3: Run all patterns against their assigned regions ---
        raw_hits = self._run_patterns(data)

        # --- Step 4: Resolve software version ---
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 5: Resolve OEM part number ---
        result["oem_part_number"] = self._resolve_oem_part_number(raw_hits)

        # --- Step 6: Resolve hardware number (Marelli part number) ---
        result["hardware_number"] = self._resolve_hardware_number(raw_hits)

        # --- Step 7: Resolve calibration ID (MUST code) ---
        result["calibration_id"] = self._resolve_calibration_id(raw_hits)

        # --- Step 8: Ancillary fields ---
        result["calibration_version"] = self._first_hit(raw_hits, "calibration_ref")
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 9: ECU family and variant ---
        ecu_family = "MJD 6JF"
        ecu_variant = self._resolve_ecu_variant(raw_hits)
        result["ecu_family"] = ecu_family
        result["ecu_variant"] = ecu_variant

        # --- Step 10: Build compound match key ---
        # Format: "MJD6JF::<software_version>"
        # The family part is collapsed (no space) for a clean match key.
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_variant,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """
        Run all MJD 6JF patterns against their assigned search regions.

        Delegates to the base class _run_all_patterns() utility.

        Args:
            data: Full binary data.

        Returns:
            Dict of pattern_name → list of matched strings.
        """
        return self._run_all_patterns(
            data=data,
            patterns=PATTERNS,
            pattern_regions=PATTERN_REGIONS,
            search_regions=SEARCH_REGIONS,
        )

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Resolve the software version from pattern hits.

        The software_version pattern matches strings like "31315X375" and
        "31414X188" — 4–5 digits + uppercase letter + 3 digits.

        Multiple hits may occur because the engine code pattern
        (e.g. "UZ13DT") uses a similar digit-letter structure.  The
        software version is distinguished by being purely numeric with
        a single embedded letter and being longer (8–9 characters total).

        If multiple hits are found, prefer the longest match (the SW
        version is typically 8–9 chars vs 6 chars for engine codes that
        might accidentally match).

        Returns:
            Software version string, or None if not found.
        """
        hits = raw_hits.get("software_version")
        if not hits:
            return None

        # Prefer the longest match — SW versions are 8–9 chars; accidental
        # matches on other numeric strings tend to be shorter.
        best = max(hits, key=len)
        return best

    def _resolve_oem_part_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the OEM (GM) part number from pattern hits.

        The oem_part_number pattern matches "355190069 WJ" format —
        9 digits + whitespace + 2 uppercase letter suffix.

        Returns:
            OEM part number string, or None if not found.
        """
        return self._first_hit(raw_hits, "oem_part_number")

    def _resolve_hardware_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the hardware/part number from pattern hits.

        For MJD 6JF, the Marelli part number (e.g. "MAG  01246JO01D")
        serves as the hardware identification reference.  The full
        matched string including the "MAG" prefix is returned.

        Returns:
            Marelli part number string, or None if not found.
        """
        return self._first_hit(raw_hits, "marelli_part")

    def _resolve_calibration_id(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the calibration ID from pattern hits.

        The calibration_id pattern matches "MUST_C5131" or "MUST_C4141"
        format.  The full matched string including the "MUST_" prefix is
        returned for maximum clarity.

        Returns:
            MUST calibration ID string, or None if not found.
        """
        return self._first_hit(raw_hits, "calibration_id")

    def _resolve_ecu_variant(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the ECU variant from pattern hits.

        The ecu_family_tag pattern matches "6JF   MUST" format.  If the
        calibration_id is also available, the variant is constructed as
        the sub-family string (e.g. "6JF MUST_C5131").  Otherwise, the
        family tag match is cleaned up and returned.

        For MJD 6JF, the variant is not strongly differentiated — most
        units share the same hardware platform.  The MUST code provides
        the closest thing to a variant identifier.

        Returns:
            ECU variant string, or None if not found.
        """
        cal_id = self._first_hit(raw_hits, "calibration_id")
        family_tag = self._first_hit(raw_hits, "ecu_family_tag")

        if cal_id:
            # Construct a clean variant: "MJD 6JF MUST_C5131"
            return f"MJD 6JF {cal_id}"

        if family_tag:
            # Clean up whitespace: "6JF   MUST" → "MJD 6JF"
            return "MJD 6JF"

        return None
