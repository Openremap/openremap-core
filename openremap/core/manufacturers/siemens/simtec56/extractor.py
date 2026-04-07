"""
Siemens Simtec 56 ECU binary extractor.

Covers the Siemens Simtec 56 family used in Opel/Vauxhall vehicles with
X18XE and X20XEV engines (1995–2000).  Typical vehicles include Vectra B,
Astra F/G, Omega B, and Calibra.

Binary characteristics:
  - File size: exactly 131 072 bytes (128 KB)
  - CPU: Intel 8051 / Siemens C166 derivative
  - Header: \\x02\\x00\\xb0 — 8051-style LJMP reset vector
  - Identification: RS/RT ident record containing GM part number,
    production serial, and Siemens 5WK9 part number in a single
    continuous ASCII string

Detection strategy:
  1. Size gate: exactly 131 072 bytes (128 KB)
  2. Exclusion: reject if any Bosch / Delphi / Marelli signature is found
  3. Positive: require "5WK9" Siemens part prefix in the binary
  4. Positive: require RS/RT ident record prefix (R[ST] + 8-digit GM part)
  5. Weak positive: header magic \\x02\\x00\\xb0 (8051 LJMP)

All sub-field extraction (GM part number, serial number) is performed by
parsing the full ident_record match rather than by separate lookbehind
patterns — Python's ``re`` module does not support variable-length
lookbehinds.
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    DETECTION_SIGNATURE,
    EXCLUSION_CLEAR,
    HEADER_MATCH,
    IDENT_BLOCK,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.siemens.simtec56.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    IDENT_PREFIXES,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SIMTEC56_FILE_SIZE,
    SIMTEC56_HEADER,
)

# ---------------------------------------------------------------------------
# Compiled regex for splitting the ident record into sub-fields.
#
# Groups:
#   1  prefix      — "RS" or "RT"
#   2  gm_part     — 8-digit GM/Opel part number
#   3  serial      — 12–16 digits + trailing lowercase letter
#   4  siemens_part — "5WK9" + 4 digits
#   5  checksum    — 1–2 digit checksum suffix
#
# Example input:  "RS90506365 0106577255425b5WK907302"
#   group(1) = "RS"
#   group(2) = "90506365"
#   group(3) = "0106577255425b"
#   group(4) = "5WK90730"
#   group(5) = "2"
#
# All confirmed samples show 5 trailing digits after 5WK9 (4 variant + 1
# check digit).  The checksum group uses \d{1,2} for robustness against
# undiscovered variants that may carry a 2-digit checksum.
# ---------------------------------------------------------------------------
_IDENT_SPLIT_RE = re.compile(
    r"(R[ST])"  # 1: prefix
    r"(\d{8})"  # 2: GM part number
    r"\s+"  #    whitespace separator
    r"(\d{12,16}[a-z])"  # 3: serial number
    r"(5WK9\d{4})"  # 4: Siemens part (core 8 chars)
    r"(\d{1,2})"  # 5: checksum (1–2 digits)
)


class SiemensSimtec56Extractor(BaseManufacturerExtractor):
    """
    Extractor for Siemens Simtec 56 ECU binaries.

    Handles: Simtec56

    Detection is based on a strict combination of:
      - Exact 128 KB file size
      - Presence of 5WK9 Siemens part prefix
      - Presence of RS/RT ident record with 8-digit GM part number
      - 8051-style LJMP header magic
      - Absence of all Bosch / Delphi / Marelli exclusion signatures
    """

    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Siemens"

    @property
    def supported_families(self) -> List[str]:
        return ["Simtec56"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Siemens Simtec 56 ECU dump.

        Five-phase check:
          1. Size gate — must be exactly 131 072 bytes (128 KB).
          2. Exclusion — reject if any known Bosch / Delphi / Marelli
             signature is found anywhere in the binary.
          3. Detection signature — at least one of the DETECTION_SIGNATURES
             (currently just b"5WK9") must be present.
          4. Ident record — at least one RS/RT prefix followed by an
             8-digit GM part number must be present.  This distinguishes
             Simtec 56 from other 5WK9-bearing families (SID801, etc.)
             that do not use the RS/RT ident format.
          5. Header magic — the first 3 bytes must match the 8051 LJMP
             reset vector (\\x02\\x00\\xb0).  This is a weak secondary
             confirmation — not sufficient on its own.

        All five phases must pass for the binary to be claimed.
        """
        evidence: list[str] = []

        # --- Phase 1: Size gate ---
        if len(data) != SIMTEC56_FILE_SIZE:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # --- Phase 2: Exclusion signatures ---
        for sig in EXCLUSION_SIGNATURES:
            if sig in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # --- Phase 3: Detection signatures ---
        if not any(sig in data for sig in DETECTION_SIGNATURES):
            self._set_evidence()
            return False
        evidence.append(DETECTION_SIGNATURE)

        # --- Phase 4: RS/RT ident record prefix ---
        # Look for R[ST] followed by 8 digits — the canonical Simtec 56
        # ident record anchor.  A bare "5WK9" is not specific enough
        # because other Siemens families (SID801, SID803, etc.) also use
        # the 5WK9 prefix but have completely different ident formats.
        has_ident = any(prefix in data for prefix in IDENT_PREFIXES)
        if not has_ident:
            self._set_evidence()
            return False
        evidence.append(IDENT_BLOCK)

        # --- Phase 5: Header magic ---
        if data[:3] != SIMTEC56_HEADER:
            self._set_evidence()
            return False
        evidence.append(HEADER_MATCH)

        self._set_evidence(evidence)
        return True

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Siemens Simtec 56 binary.

        The ident_record pattern is the primary extraction anchor.  Sub-fields
        (GM part number, serial number, Siemens part) are split from the full
        match using a compiled regex rather than separate lookbehind patterns.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "ecu_family": "Simtec56",
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from header region ---
        raw_strings = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["header"],
            min_length=8,
            max_results=20,
        )
        result["raw_strings"] = raw_strings

        # --- Step 2: Run all patterns against their assigned regions ---
        raw_hits = self._run_patterns(data)

        # --- Step 3: Resolve fields from the ident record ---
        ident_fields = self._split_ident_record(raw_hits)

        # --- Step 4: Resolve hardware number (Siemens part) ---
        # Priority: ident record → standalone siemens_part pattern
        hardware_number = self._resolve_hardware_number(raw_hits, ident_fields)
        result["hardware_number"] = hardware_number

        # --- Step 5: Resolve software version (serial from ident record) ---
        software_version = ident_fields.get("serial")
        result["software_version"] = software_version

        # --- Step 6: Resolve OEM part number (GM part from ident record) ---
        oem_part_number = ident_fields.get("gm_part")
        result["oem_part_number"] = oem_part_number

        # --- Step 7: Resolve serial number ---
        result["serial_number"] = ident_fields.get("serial")

        # --- Step 8: Resolve calibration ID ---
        # Prefer the extended calibration_code (S001xxxxxx) over the short
        # calibration_ref (Sxxxxx) because it is more specific.
        result["calibration_id"] = self._resolve_calibration_id(raw_hits)

        # --- Step 9: Fields not present in Simtec 56 binaries ---
        result["ecu_variant"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["dataset_number"] = None

        # --- Step 10: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family="Simtec56",
            ecu_variant=None,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — pattern runner
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """
        Run all Simtec 56 patterns against their assigned search regions.

        Delegates to the base class _run_all_patterns() utility.
        No special overrides are needed — the 128 KB binary is small enough
        that the default max_results=5 cap is sufficient for all patterns.
        """
        return self._run_all_patterns(
            data=data,
            patterns=PATTERNS,
            pattern_regions=PATTERN_REGIONS,
            search_regions=SEARCH_REGIONS,
        )

    # -----------------------------------------------------------------------
    # Internal — ident record splitter
    # -----------------------------------------------------------------------

    def _split_ident_record(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> Dict[str, Optional[str]]:
        """
        Parse the full RS/RT ident record into sub-fields.

        The ident_record pattern captures the entire combined string:
          "RS90506365 0106577255425b5WK907302"

        This method splits it into:
          prefix       — "RS" or "RT"
          gm_part      — "90506365"     (8-digit GM/Opel part number)
          serial       — "0106577255425b" (production serial)
          siemens_part — "5WK90730"     (Siemens part, core 8 chars)
          checksum     — "02"           (2-digit checksum suffix)

        Returns a dict of field names → values.  All values are None if
        the ident record was not found or could not be parsed.
        """
        empty: Dict[str, Optional[str]] = {
            "prefix": None,
            "gm_part": None,
            "serial": None,
            "siemens_part": None,
            "checksum": None,
        }

        ident_str = self._first_hit(raw_hits, "ident_record")
        if not ident_str:
            return empty

        m = _IDENT_SPLIT_RE.search(ident_str)
        if not m:
            return empty

        return {
            "prefix": m.group(1),
            "gm_part": m.group(2),
            "serial": m.group(3),
            "siemens_part": m.group(4),
            "checksum": m.group(5),
        }

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_hardware_number(
        self,
        raw_hits: Dict[str, List[str]],
        ident_fields: Dict[str, Optional[str]],
    ) -> Optional[str]:
        """
        Resolve the Siemens hardware/software part number.

        Priority:
          1. siemens_part from the ident record (most authoritative — it is
             anchored to the RS/RT context and cannot be a false positive)
          2. Standalone siemens_part pattern hit (fallback — may match
             other "5WK9" occurrences in the binary)

        Returns the 8-character core part number (e.g. "5WK90730") without
        the 2-digit checksum suffix.
        """
        # Priority 1: from ident record
        ident_part = ident_fields.get("siemens_part")
        if ident_part:
            return ident_part

        # Priority 2: standalone pattern
        return self._first_hit(raw_hits, "siemens_part")

    def _resolve_calibration_id(
        self,
        raw_hits: Dict[str, List[str]],
    ) -> Optional[str]:
        """
        Resolve the calibration identifier.

        Priority:
          1. Extended calibration code (S001xxxxxx) — more specific, preferred
          2. Short calibration reference (Sxxxxx/Sxxxxxx) — fallback

        Returns the first matched calibration string, or None.
        """
        # Priority 1: extended calibration code
        cal_code = self._first_hit(raw_hits, "calibration_code")
        if cal_code:
            return cal_code

        # Priority 2: short calibration reference
        return self._first_hit(raw_hits, "calibration_ref")
