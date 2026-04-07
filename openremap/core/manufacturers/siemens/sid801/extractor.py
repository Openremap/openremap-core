"""
Siemens SID 801 / SID 801A ECU binary extractor.

Implements BaseManufacturerExtractor for the Siemens SID801 diesel ECU family,
used primarily in PSA (Peugeot/Citroën) and Ford vehicles with HDi engines
(DW10 / DW12 families, 2.0 HDi and 2.2 HDi).

Binary characteristics:
  - File size: exactly 512 KB (524288 bytes)
  - Hardware part numbers use the Siemens 5WS4 prefix
  - Ident record format: 5WS4xxxxX-T <9-digit serial> <date+serial>S2<version>
  - Project codes: PM3xxxxx
  - S-record references: S118xxxxxx, S120xxxxxx, S220xxxxxx
  - Calibration dataset files: CAPM3xxx.DAT

The analyzer.py is manufacturer-agnostic — it discovers this extractor
via the registry in manufacturers/__init__.py.
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    DETECTION_SIGNATURE,
    EXCLUSION_CLEAR,
    HEADER_MATCH,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.siemens.sid801.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SID801_FILE_SIZE,
    SID801_HEADERS,
)


class SiemensSID801Extractor(BaseManufacturerExtractor):
    """
    Extractor for Siemens SID 801 / SID 801A diesel ECU binaries.

    Handles: SID801, SID801A

    These ECUs are found in PSA (Peugeot/Citroën) and Ford HDi diesel
    vehicles from approximately 2001–2006.  The binaries are always exactly
    512 KB (524288 bytes) and contain a structured ident record in the first
    4 KB with the Siemens 5WS4 hardware part number, a 9-digit production
    serial, and an S2-prefixed software/calibration version string.

    Detection relies on:
      1. Exact file size (524288 bytes) — mandatory gate
      2. Presence of 5WS4 hardware prefix OR PM3 project code
      3. Absence of Bosch / SID803 exclusion signatures
    """

    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        """Human-readable manufacturer name."""
        return "Siemens"

    @property
    def supported_families(self) -> List[str]:
        """ECU families handled by this extractor."""
        return ["SID801", "SID801A"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary belongs to a Siemens SID 801 / SID 801A ECU.

        Detection strategy (all conditions must be met):
          1. File size must be exactly 524288 bytes (512 KB).
             Every known SID801/801A dump is this exact size — no exceptions.
             This is the cheapest check and eliminates >99% of non-SID801 bins.

          2. At least one detection signature must be present:
             - b"5WS4"  — Siemens diesel ECU hardware part number prefix
             - b"PM3"   — Siemens project code prefix
             These are searched in the first 128 KB only (both always appear
             in the header/ident area).

          3. No exclusion signature may be present:
             - b"EDC17", b"MEDC17", b"MED17", b"ME7." — Bosch families
             - b"SID803" — Continental/Siemens SID803 (different architecture)
             Exclusion signatures are searched across the full binary to avoid
             false positives from stray bytes in calibration data.

        Args:
            data: Raw bytes of the ECU binary file

        Returns:
            True if this extractor should handle the binary
        """
        evidence: list[str] = []

        # ------------------------------------------------------------------
        # Gate 1 — exact file size
        # ------------------------------------------------------------------
        if len(data) != SID801_FILE_SIZE:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # ------------------------------------------------------------------
        # Gate 2 — exclusion signatures (reject Bosch / SID803 bins)
        # ------------------------------------------------------------------
        for sig in EXCLUSION_SIGNATURES:
            if sig in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # ------------------------------------------------------------------
        # Gate 3 — at least one positive detection signature
        # ------------------------------------------------------------------
        # Search only the first 128 KB — both 5WS4 and PM3 always appear in
        # the header/ident area of genuine SID801 binaries.
        detection_region = data[:0x20000]
        if any(sig in detection_region for sig in DETECTION_SIGNATURES):
            evidence.append(DETECTION_SIGNATURE)
            self._set_evidence(evidence)
            return True

        # ------------------------------------------------------------------
        # Gate 4 — fallback: header magic detection for "dark" bins
        # ------------------------------------------------------------------
        # Some SID801 bins have no embedded 5WS4 or PM3 signatures at all
        # (the part number is only in the filename).  These can still be
        # identified by their distinctive first-4-byte header magic.
        if any(data[: len(hdr)] == hdr for hdr in SID801_HEADERS):
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
        Extract all identifying information from a Siemens SID801 binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.

        Extraction pipeline:
          1. Compute mandatory hash fields (md5, sha256_first_64kb)
          2. Extract raw ASCII strings from header (display + fallback)
          3. Run all regex patterns against their assigned search regions
          4. Resolve each field via dedicated resolver methods
          5. Build the compound match key
          6. Return the complete identification dict

        Args:
            data:     Raw bytes of the ECU binary file
            filename: Original filename — used for display only

        Returns:
            Dict compatible with ECUIdentifiersSchema
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

        # --- Step 3: Resolve hardware number ---
        # The 5WS4xxxxX-T part number identifies the ECU hardware revision.
        hardware_number = self._resolve_hardware_number(raw_hits)
        result["hardware_number"] = hardware_number

        # --- Step 4: Resolve software version ---
        # The 9-digit serial extracted from the ident record is the primary
        # matching key — it is unique per software calibration release.
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 5: Resolve ECU family ---
        # SID801 or SID801A — determined from explicit family string in the
        # binary, or inferred from the hardware number suffix.
        ecu_family = self._resolve_ecu_family(raw_hits, hardware_number)
        result["ecu_family"] = ecu_family

        # --- Step 6: Resolve calibration ID ---
        # From PM3 project codes or CAPM calibration dataset references.
        result["calibration_id"] = self._resolve_calibration_id(raw_hits)

        # --- Step 7: Resolve OEM part number ---
        # PSA part numbers (96xxxxxxxx format) if present.
        result["oem_part_number"] = self._first_hit(raw_hits, "psa_part_number")

        # --- Step 8: Resolve S-record reference ---
        # S118/S120/S220 references — stored in serial_number field as a
        # secondary identifier (these are internal Siemens build references,
        # not production serial numbers, but they serve a similar role).
        result["serial_number"] = self._first_hit(raw_hits, "s_record_ref")

        # --- Step 9: Fields not applicable to SID801 ---
        result["ecu_variant"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["dataset_number"] = None

        # --- Step 10: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_hardware_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the Siemens hardware part number (e.g. "5WS40145A-T").

        The 5WS4 prefix is unique to Siemens diesel ECUs.  The format is:
          5WS4  +  4-5 digits  +  optional letter suffix  +  "-T"

        Examples:
          "5WS40145A-T"   — SID801A, PSA 2.0 HDi
          "5WS40045B-T"   — SID801, PSA 2.0 HDi
          "5WS40036D-T"   — SID801, PSA 2.0 HDi (early revision)
          "5WS40155C-T"   — SID801A, Ford 2.0 TDCi

        Returns:
            The first matched 5WS4 part number string, or None.
        """
        return self._first_hit(raw_hits, "hardware_number")

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Resolve the software version — the 9-digit production serial.

        The serial is extracted from the ident record:
          "5WS40145A-T 244177913   04020028014941S220040001C0"
                       ^^^^^^^^^
                       this part

        Extraction strategy:
          1. Parse the full ident record and split out the 9-digit serial
             that follows the hardware number.  This is the most reliable
             source because the ident record format is highly structured.
          2. If no ident record matched, there is no reliable fallback —
             the serial is only meaningful in context of the ident record.

        The 9-digit serial is unique per software calibration release and
        serves as the primary matching key for recipe lookup.

        Returns:
            The 9-digit serial string, or None.
        """
        # Priority 1 — extract from full ident record
        ident = self._first_hit(raw_hits, "ident_record")
        if ident:
            # Ident record format:
            #   5WS4xxxxX-T  <spaces>  <9-digit serial>  <spaces>  <rest>
            # Split on whitespace — the serial is the second non-empty token.
            parts = ident.split()
            if len(parts) >= 2:
                serial = parts[1]
                # Validate: must be exactly 9 digits
                if re.match(r"^\d{9}$", serial):
                    return serial

        return None

    def _resolve_ecu_family(
        self,
        raw_hits: Dict[str, List[str]],
        hardware_number: Optional[str] = None,
    ) -> Optional[str]:
        """
        Resolve the ECU family — "SID801" or "SID801A".

        Priority:
          1. Explicit family string found in the binary (e.g. "SID801A").
             Searched via the ecu_family pattern across the full binary.
          2. Infer from hardware number: later 5WS4 revisions (higher part
             numbers) tend to be SID801A, but this is not a reliable rule.
             Default to "SID801" when no explicit family string is found.

        The distinction between SID801 and SID801A is primarily a hardware
        revision — the A variant has minor silicon/firmware improvements but
        the binary format is identical.

        Returns:
            "SID801" or "SID801A", or None if detection failed entirely.
        """
        # Priority 1 — explicit family string in the binary
        family_hit = self._first_hit(raw_hits, "ecu_family")
        if family_hit:
            # Normalise: "SID801" or "SID801A" (uppercase, no trailing junk)
            normalised = family_hit.upper().strip()
            if normalised in ("SID801", "SID801A"):
                return normalised
            # Partial match — e.g. "SID801" from "SID801A" truncated
            if normalised.startswith("SID801"):
                return normalised

        # Priority 2 — default to SID801 (base variant)
        # If we got this far, can_handle() already confirmed this is a SID801
        # family binary, so returning the base family name is safe.
        return "SID801"

    def _resolve_calibration_id(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the calibration identifier.

        Priority:
          1. PM3 project code — e.g. "PM38101C00", "PM33001C00", "PM363000"
             These are Siemens internal project/calibration codes embedded in
             the binary.  The PM3 prefix is unique to the SID801 family.
          2. CAPM calibration dataset reference — e.g. "CAPM3630.DAT"
             These reference the calibration data file used during production.
             Less specific than PM3 codes (multiple calibrations may share
             the same CAPM dataset), so used only as a fallback.

        Returns:
            The calibration identifier string, or None.
        """
        # Priority 1 — PM3 project code
        pm3 = self._first_hit(raw_hits, "project_code")
        if pm3:
            return pm3

        # Priority 2 — CAPM dataset reference
        capm = self._first_hit(raw_hits, "calibration_dataset")
        if capm:
            return capm

        return None

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"manufacturer={self.name!r} "
            f"families={self.supported_families}>"
        )
