"""
Siemens SID803 / SID803A ECU binary extractor.

Implements BaseManufacturerExtractor for the Siemens SID803 and SID803A
diesel ECU families, used in PSA (Peugeot/Citroën), Ford, and Jaguar/Land
Rover diesel applications from the mid-2000s onward.

---------------------------------------------------------------------------
Binary structure — two sub-groups:
---------------------------------------------------------------------------

A) SID803 (smaller, 458–462 KB — file sizes 458752 / 462848):
   - PO project references (PO011, PO220, PO320)
   - T5_AA0Y1PO0AA00 records
   - 111POxxxxxx repeated calibration block markers
   - S120079010E0 S-record references
   - No embedded 5WS4 hardware part number in some files

B) SID803A (2 MB / 2097152 bytes):
   - 5WS4 hardware part numbers embedded in header (5WS40262B-T, 5WS40612B-T)
   - S122xxxxxx S-record references (higher series than SID801)
   - PO220, PO320 project codes
   - 111POxxxxxxxxx repeated blocks
   - FOIX references (FOIXS160001225B0)
   - CAPO calibration datasets
   - SID803A may appear in filename but not always in binary

---------------------------------------------------------------------------
Detection strategy:
---------------------------------------------------------------------------

  1. Size gate — file size must be one of 458752, 462848, or 2097152 bytes.
  2. Exclusion — reject if any exclusion signature is present (EDC17, MEDC17,
     MED17, ME7., PM3).  PM3 is the strongest negative: PM3 → SID801.
  3. Detection — accept if at least one detection signature is found in the
     first 512 KB: 111PO, PO2, PO3, S122, SID803.

---------------------------------------------------------------------------
Fields extracted:
---------------------------------------------------------------------------

  manufacturer        "Siemens"              fixed
  ecu_family          "SID803" or "SID803A"  resolved from file size + binary
  hardware_number     "5WS40262B-T"          from header (2 MB files) or None
  software_version    "00012345678901234"     serial from ident record or None
  calibration_id      "CAPO1234" / "PO220"   from CAPO or PO references
  calibration_dataset "CAPO1234"             from CAPO references or None
  s_record_ref        "S122001234AB"         first S-record reference or None
  foix_ref            "FOIXS160001225B0"     first FOIX reference or None
  match_key           "SID803A::00012345678901234"

---------------------------------------------------------------------------
Relationship to SID801:
---------------------------------------------------------------------------

  SID801 uses PM3-prefixed project codes.  SID803 uses PO-prefixed codes.
  If PM3 is present anywhere in the binary the file is SID801, not SID803.
  This is enforced by the PM3 exclusion signature.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    DETECTION_SIGNATURE,
    EXCLUSION_CLEAR,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.siemens.sid803.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SID803A_FILE_SIZE,
    VALID_FILE_SIZES,
)


class SiemensSID803Extractor(BaseManufacturerExtractor):
    """
    Extractor for Siemens SID803 / SID803A ECU binaries.

    Handles: SID803 (458–462 KB), SID803A (2 MB).
    Used in: PSA (Peugeot/Citroën), Ford, Jaguar/Land Rover diesel ECUs.

    Detection is anchored on:
      - File size gate (458752, 462848, or 2097152 bytes)
      - PO-prefixed project codes and 111PO block markers
      - S122 S-record references (SID803A)
      - PM3 exclusion (PM3 → SID801, never SID803)
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
        return ["SID803", "SID803A"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary belongs to the Siemens SID803/SID803A family.

        Three-phase check:

          Phase 1 — Size gate.
            Reject immediately if the file size is not one of the three known
            SID803/SID803A sizes (458752, 462848, 2097152).  This eliminates
            the vast majority of non-SID803 binaries with zero regex cost.

          Phase 2 — Exclusion signatures.
            Reject if any exclusion signature is found anywhere in the first
            512 KB.  The exclusion list contains:
              - Bosch family strings (EDC17, MEDC17, MED17, ME7.) — these
                Bosch binaries can coincidentally share some of the same
                file sizes.
              - PM3 — the SID801 project code prefix.  If PM3 is present the
                binary is SID801, never SID803.  This is the single strongest
                negative discriminator between the two Siemens diesel families.

          Phase 3 — Detection signatures.
            Accept if at least one detection signature (111PO, PO2, PO3,
            S122, SID803) is found in the first 512 KB.  These are ordered
            from most specific (lowest false-positive rate) to most general.

        This method is called for every registered extractor on every uploaded
        binary, so it is deliberately fast: no regex, only byte substring
        searches in a bounded region.
        """
        evidence: list[str] = []

        # ------------------------------------------------------------------
        # Phase 1 — Size gate.
        # ------------------------------------------------------------------
        if len(data) not in VALID_FILE_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Limit all substring searches to the first 512 KB.  For 458/462 KB
        # files this is effectively the full binary; for 2 MB files it avoids
        # scanning calibration tables that may contain coincidental matches.
        scan_region = data[:0x80000]

        # ------------------------------------------------------------------
        # Phase 2 — Exclusion signatures.
        # First hit → immediate rejection.
        # ------------------------------------------------------------------
        for sig in EXCLUSION_SIGNATURES:
            if sig in scan_region:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # ------------------------------------------------------------------
        # Phase 3 — Detection signatures.
        # First hit → accept.
        # ------------------------------------------------------------------
        for sig in DETECTION_SIGNATURES:
            if sig in scan_region:
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
        Extract all identifying information from a Siemens SID803/SID803A binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.

        Extraction pipeline:
          1. Mandatory fields — file_size, md5, sha256_first_64kb.
          2. Raw ASCII strings from the header region (display + fallback).
          3. Run all regex patterns against their assigned search regions.
          4. Resolve ECU family (SID803 vs SID803A).
          5. Resolve hardware number (5WS4 part, 2 MB files only).
          6. Resolve software version (serial from ident record).
          7. Resolve calibration ID (CAPO > PO project code fallback).
          8. Resolve ancillary fields (S-record ref, FOIX ref).
          9. Build compound match key.
        """

        # --- Step 1: Mandatory fields ---
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 2: Raw ASCII strings from header (display + fallback) ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["header"],
            min_length=8,
            max_results=20,
        )

        # --- Step 3: Run all patterns against their assigned regions ---
        raw_hits = self._run_all_patterns(
            data=data,
            patterns=PATTERNS,
            pattern_regions=PATTERN_REGIONS,
            search_regions=SEARCH_REGIONS,
        )

        # --- Step 4: Resolve ECU family ---
        ecu_family = self._resolve_ecu_family(data, raw_hits, filename)
        result["ecu_family"] = ecu_family

        # --- Step 5: Resolve hardware number ---
        hardware_number = self._resolve_hardware_number(raw_hits)
        result["hardware_number"] = hardware_number

        # --- Step 6: Resolve software version ---
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 7: Resolve calibration ID ---
        calibration_id = self._resolve_calibration_id(raw_hits)
        result["calibration_id"] = calibration_id

        # --- Step 8: Ancillary fields ---
        result["calibration_dataset"] = self._first_hit(raw_hits, "calibration_dataset")
        result["s_record_ref"] = self._first_hit(raw_hits, "s_record_ref")
        result["foix_ref"] = self._first_hit(raw_hits, "foix_ref")

        # Fields not present in SID803 binaries.
        result["ecu_variant"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["oem_part_number"] = None

        # --- Step 9: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=None,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Resolvers
    # -----------------------------------------------------------------------

    def _resolve_ecu_family(
        self,
        data: bytes,
        raw_hits: Dict[str, List[str]],
        filename: str,
    ) -> str:
        """
        Resolve the ECU family: "SID803" or "SID803A".

        Resolution order (first match wins):

          1. Explicit family string in the binary.
             If the binary contains "SID803A" → "SID803A".
             If it contains "SID803" (without trailing A) → "SID803".

          2. File size heuristic.
             2 MB (2097152) files are always SID803A.
             458/462 KB files are always SID803.

          3. Filename hint.
             If the filename contains "SID803A" (case-insensitive) → "SID803A".
             If it contains "SID803" → "SID803".

          4. Fallback: "SID803" (the more common sub-group).

        The file size heuristic is extremely reliable in practice — the two
        sub-groups do not share any file sizes — so steps 3–4 are rarely
        reached.
        """
        # --- Priority 1: Explicit family string in the binary ---
        family_hits = raw_hits.get("ecu_family", [])
        if family_hits:
            # Check for "SID803A" first (more specific) to avoid "SID803"
            # matching the prefix of "SID803A".
            for hit in family_hits:
                if "SID803A" in hit:
                    return "SID803A"
            # If we have hits but none contain "SID803A", it's plain SID803.
            return "SID803"

        # --- Priority 2: File size heuristic ---
        if len(data) == SID803A_FILE_SIZE:
            return "SID803A"
        if len(data) in VALID_FILE_SIZES:
            # 458752 or 462848 → SID803
            return "SID803"

        # --- Priority 3: Filename hint ---
        fn_upper = filename.upper()
        if "SID803A" in fn_upper:
            return "SID803A"
        if "SID803" in fn_upper:
            return "SID803"

        # --- Priority 4: Fallback ---
        return "SID803"

    def _resolve_hardware_number(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> Optional[str]:
        """
        Resolve the Siemens/Continental hardware part number.

        Returns the first 5WS4 hardware number match, or None if no match
        was found.

        The hardware number is present in SID803A (2 MB) files in the header
        region (0x0000–0x1000) but is absent from many smaller SID803
        (458–462 KB) files.  Returning None is a valid and expected outcome
        for SID803 files.

        Examples:
            "5WS40262B-T"  → Siemens part, SID803A
            "5WS40612B-T"  → Siemens part, SID803A
            None           → SID803 (no 5WS4 in binary)
        """
        return self._first_hit(raw_hits, "hardware_number")

    def _resolve_software_version(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> Optional[str]:
        """
        Resolve the software version (primary matching key).

        Resolution order (first match wins):

          1. Serial from ident record.
             The ident_record pattern captures a 5WS4 hardware number followed
             by whitespace and a 14–17 digit serial string.  The serial portion
             is extracted as the software version.
             Example: "5WS40262B-T  00012345678901234"
                      → software_version = "00012345678901234"

          2. S-record reference.
             If no ident record is present (common in smaller SID803 files),
             fall back to the first S-record reference as a coarser version
             identifier.
             Example: "S1200790100E0"  → software_version = "S1200790100E0"

        Returns None if neither source produces a hit.
        """
        # --- Priority 1: Serial from ident record ---
        ident_hit = self._first_hit(raw_hits, "ident_record")
        if ident_hit:
            serial = self._extract_serial_from_ident(ident_hit)
            if serial:
                return serial

        # --- Priority 2: S-record reference fallback ---
        s_record = self._first_hit(raw_hits, "s_record_ref")
        if s_record:
            return s_record

        return None

    def _resolve_calibration_id(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> Optional[str]:
        """
        Resolve the calibration identifier.

        Resolution order (first match wins):

          1. CAPO calibration dataset.
             e.g. "CAPO1234" — explicit calibration area project overlay.
             Predominantly found in SID803A (2 MB) files.

          2. PO project code fallback.
             e.g. "PO220", "PO320" — Siemens internal project reference.
             Present in both SID803 and SID803A files.

        Returns None if neither source produces a hit.
        """
        # --- Priority 1: CAPO calibration dataset ---
        capo = self._first_hit(raw_hits, "calibration_dataset")
        if capo:
            return capo

        # --- Priority 2: PO project code ---
        po = self._first_hit(raw_hits, "project_code")
        if po:
            return po

        return None

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_serial_from_ident(ident_record: str) -> Optional[str]:
        """
        Extract the serial / software build number from a full ident record.

        The ident record format is:
            "5WS4XXXXX[L]-T  DDDDDDDDDDDDDDD"
              ^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^
              hardware number   14–17 digit serial

        The serial portion is separated from the hardware number by one or
        more whitespace characters.  This method splits on whitespace and
        returns the last numeric token.

        Args:
            ident_record: Decoded ASCII ident record string.

        Returns:
            The serial portion as a string, or None if parsing fails.

        Examples:
            "5WS40262B-T  00012345678901234"  → "00012345678901234"
            "5WS40612B-T 12345678901234"      → "12345678901234"
        """
        parts = ident_record.split()
        if len(parts) >= 2:
            serial_candidate = parts[-1]
            # Validate: serial must be 14–17 decimal digits.
            if re.fullmatch(r"\d{14,17}", serial_candidate):
                return serial_candidate
        return None
