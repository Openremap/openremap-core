"""
Siemens EMS2000 ECU binary extractor.

Covers the Siemens EMS2000 family used in Volvo S40/V40/S60/S70/V70
(1996–2004) with T4/T5 turbo engines.  Part numbers follow the Siemens
S108xxxxx format but are found only in the filename — never embedded in
the binary itself.

This is a "dark" ECU family:
  - Almost no readable ASCII strings in the binary
  - No metadata headers, no embedded part numbers, no version strings
  - The binary is essentially pure machine code + calibration data
  - Identification relies on exclusion (not Bosch, not Delphi, etc.)
    combined with a strict 256 KB size gate

Detection confidence is LOW — the extractor exists primarily to prevent
EMS2000 bins from being classified as "Unknown" while acknowledging that
very little useful metadata can be extracted from them.
"""

import hashlib
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    EXCLUSION_CLEAR,
    HEADER_MATCH,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.siemens.ems2000.patterns import (
    EMS2000_HEADER,
    EXCLUSION_SIGNATURES,
    PATTERNS,
    PATTERN_REGIONS,
    SEARCH_REGIONS,
)

# ---------------------------------------------------------------------------
# Expected file size — exactly 256 KB (262 144 bytes)
# ---------------------------------------------------------------------------
EMS2000_FILE_SIZE: int = 262_144


class SiemensEMS2000Extractor(BaseManufacturerExtractor):
    """
    Extractor for Siemens EMS2000 ECU binaries.

    Detection strategy (exclusion-based, low confidence):
      1. Size gate: exactly 262 144 bytes (256 KB)
      2. Reject if ANY known manufacturer signature is found in the binary
      3. Accept if the first 4 bytes match the known EMS2000 header magic
      4. Otherwise reject — very conservative, we only claim what we're
         sure about

    Extraction is intentionally minimal — almost nothing can be pulled
    from these binaries beyond file-level hashes and the family label.
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
        return ["EMS2000"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Siemens EMS2000 ECU dump.

        Three-phase check:
          1. Size gate — must be exactly 262 144 bytes.
          2. Exclusion — reject if any known manufacturer signature is
             found anywhere in the binary.  This eliminates Bosch, Delphi,
             Marelli, Denso, and other Siemens families (SIMOS, SID, PPD,
             Simtec) that happen to share the same file size.
          3. Header magic — accept only if the first 4 bytes match the
             known EMS2000 header (\\xc0\\xf0\\x68\\xa6).

        This is deliberately very conservative.  We would rather miss an
        EMS2000 bin than falsely claim a non-EMS2000 bin.
        """
        evidence: list[str] = []

        # --- Phase 1: Size gate ---
        if len(data) != EMS2000_FILE_SIZE:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # --- Phase 2: Exclusion signatures ---
        # Search the full binary for any signature that belongs to another
        # manufacturer or another Siemens family.  If ANY match is found
        # this binary is definitively not EMS2000.
        for sig in EXCLUSION_SIGNATURES:
            if sig in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # --- Phase 3: Header magic ---
        if data[:4] == EMS2000_HEADER:
            evidence.append(HEADER_MATCH)
            self._set_evidence(evidence)
            return True

        # No positive identification possible — reject.
        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract identifying information from a Siemens EMS2000 binary.

        Because EMS2000 binaries contain almost no embedded metadata, most
        fields will be None.  The extractor provides:
          - File-level identifiers (size, MD5, SHA-256 of first 64 KB)
          - Manufacturer and family labels
          - Raw ASCII strings (will typically be very sparse or empty)
          - Volvo VIN if one happens to be present

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "ecu_family": "EMS2000",
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from header region ---
        # EMS2000 binaries are extremely sparse in ASCII — this will usually
        # return an empty or near-empty list, but we run it for consistency
        # with all other extractors.
        raw_strings = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["header"],
            min_length=8,
            max_results=20,
        )
        result["raw_strings"] = raw_strings

        # --- Step 2: Run patterns (only volvo_vin currently) ---
        raw_hits = self._run_all_patterns(
            data=data,
            patterns=PATTERNS,
            pattern_regions=PATTERN_REGIONS,
            search_regions=SEARCH_REGIONS,
        )

        # --- Step 3: Resolve Volvo VIN if present ---
        volvo_vin = self._first_hit(raw_hits, "volvo_vin")

        # --- Step 4: Populate extraction fields ---
        # Almost everything is None for EMS2000 — the binary simply does
        # not contain these identifiers.
        result["hardware_number"] = None
        result["software_version"] = None
        result["ecu_variant"] = None
        result["calibration_id"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = volvo_vin  # VIN stored here if found
        result["dataset_number"] = None
        result["oem_part_number"] = None

        # --- Step 5: Build compound match key ---
        # Will always be None because software_version is None and there
        # is no fallback field configured.
        result["match_key"] = self.build_match_key(
            ecu_family="EMS2000",
            ecu_variant=None,
            software_version=None,
        )

        return result
