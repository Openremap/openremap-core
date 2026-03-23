"""
Bosch EDC15 ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch EDC15 family:
  EDC15C2   — early diesel common-rail, Alfa Romeo / Fiat / Lancia (1997–2001)
  EDC15C5   — mid-generation, VW/Audi/Seat/Skoda 1.9 TDI (1999–2004)
  EDC15C7   — VAG and PSA diesel common-rail (2000–2004)
  EDC15M    — petrol DI variant (rare)
  EDC15VM+  — Renault / PSA applications

EDC15 is a generation before EDC16 and EDC17. Two binary formats exist:

  FORMAT A — newer EDC15 (EDC15C5, EDC15C7):
    - TSW string at 0x8000: 'TSW Vx.xx DDMMYY NNNN Cx/ESB/G40'
    - HW number plain ASCII '0281xxxxxx' in last 256KB surrounded by 0xC3
    - SW version plain ASCII '1037xxxxxx' in last 256KB surrounded by 0xC3
    - Fill byte: 0xC3

  FORMAT B — older EDC15 (EDC15C2, some Alfa/Fiat bins):
    - No TSW string
    - SW version '1037xxxxxx' embedded in an ident block around 0x50000
    - HW number not stored as plain ASCII — only SW is extractable
    - Fill byte: 0xC3 (still present, >5% of file)
    - Detection: 0xC3 fill ratio > 5% AND 1037\\d{6,10} present
                 AND no modern Bosch exclusion signatures
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor
from openremap.tuning.manufacturers.bosch.edc15.patterns import (
    DETECTION_SIGNATURES,
    EDC15_MIN_C3_RATIO,
    EXCLUSION_SIGNATURES,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
)


class BoschEDC15Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch EDC15 ECU binaries.
    Handles Format A (TSW string present) and Format B (older, no TSW).
    """

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["EDC15C2", "EDC15C5", "EDC15C7", "EDC15M", "EDC15VM+", "EDC15"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch EDC15 ECU.

        Three-phase check:
          1. Reject immediately if any exclusion signature is found — modern
             Bosch families (EDC16, EDC17, ME7 etc.) share the 1037xxxxxx SW
             prefix and must be excluded before any positive check.
          2. Accept (Format A) if the TSW string is present at 0x8000.
             TSW is unique to the EDC15 toolchain and is the strongest anchor.
          3. Accept (Format B) if both conditions hold:
               a. 0xC3 fill byte accounts for at least EDC15_MIN_C3_RATIO
                  of the total file size.
               b. At least one '1037xxxxxx' SW version string is present
                  anywhere in the binary.
             Together these two conditions identify older EDC15 bins that
             lack the TSW marker but share the same fill byte and SW format.
        """
        search_area = data[:0x80000]

        # Phase 1 — reject on any exclusion signature
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                return False

        # Phase 2 — Format A: TSW string at 0x8000 relative to the start of
        # every 512KB bank. A 512KB single-bank bin has TSW at absolute 0x8000
        # (bank 0). A 1MB dual-bank bin also has TSW at 0x88000 (bank 1).
        num_banks = max(1, len(data) // 0x80000)
        if any(
            sig in data[bank * 0x80000 + 0x8000 : bank * 0x80000 + 0x8060]
            for bank in range(num_banks)
            for sig in DETECTION_SIGNATURES
        ):
            return True

        # Phase 3 — Format B: 0xC3 fill ratio + 1037xxxxxx SW present
        c3_ratio = data.count(b"\xc3") / len(data) if data else 0.0
        if c3_ratio >= EDC15_MIN_C3_RATIO:
            if re.search(rb"1037\d{6,10}", data):
                return True

        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch EDC15 ECU binary.

        Returns a dict fully compatible with ECUIdentitySchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw strings from the data region ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["data_region"],
            min_length=8,
            max_results=20,
        )

        # --- Step 2: ECU family — always EDC15, no variant string in binary ---
        result["ecu_family"] = "EDC15"
        result["ecu_variant"] = None

        # --- Step 3: Run patterns ---
        raw_hits = self._run_patterns(data)

        # --- Step 4: Resolve SW version ---
        software_version = self._resolve_software_version(raw_hits, data)
        result["software_version"] = software_version

        # --- Step 5: Resolve HW number (Format A only) ---
        hardware_number = self._resolve_hardware_number(raw_hits, software_version)
        result["hardware_number"] = hardware_number

        # --- Step 6: Fields not present in EDC15 binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["calibration_id"] = None
        result["oem_part_number"] = None

        # --- Step 7: Build match key ---
        result["match_key"] = self.build_match_key(
            ecu_family="EDC15",
            ecu_variant=None,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — pattern runner
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        return self._run_all_patterns(data, PATTERNS, PATTERN_REGIONS, SEARCH_REGIONS)

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]], data: bytes
    ) -> Optional[str]:
        """
        Resolve the software version string (e.g. '1037366536').

        EDC15 bins contain multiple copies of the SW string. The authoritative
        one is selected by a two-pass strategy:

          Pass 1 — prefer hits that are surrounded by 0xC3 fill bytes on both
                   sides. These are in the calibration data region, not in code.
                   Among those, pick the one at the lowest offset (first written).

          Pass 2 — if no C3-surrounded hit exists (Format B bins where the SW
                   appears inside a mixed ident block), return the first hit
                   from the raw pattern matches, which is already the lowest
                   offset occurrence.

        Rejects all-zero strings.
        """
        hits = raw_hits.get("software_version", [])
        if not hits:
            return None

        # Build a list of all raw match positions by re-scanning the full binary.
        # _search() returns decoded strings but loses position info, so we need
        # to rescan to apply the C3 surroundings filter.
        sw_pat = rb"1037\d{6,10}"
        candidates_c3: List[str] = []
        candidates_any: List[str] = []

        seen: set = set()
        for m in re.finditer(sw_pat, data, re.IGNORECASE):
            val = m.group(0).decode("ascii", errors="ignore").strip()
            if not val or re.match(r"^0+$", val) or val in seen:
                continue
            seen.add(val)
            candidates_any.append(val)

            # Check C3 surroundings: at least 4 of the 6 bytes before and after
            # must be 0xC3 or 0xFF (fill bytes)
            pre = data[max(0, m.start() - 6) : m.start()]
            post = data[m.end() : m.end() + 6]
            fill = sum(1 for b in pre + post if b in (0xC3, 0xFF))
            if fill >= 6:
                candidates_c3.append(val)

        if candidates_c3:
            return candidates_c3[0]

        if candidates_any:
            return candidates_any[0]

        return None

    def _resolve_hardware_number(
        self,
        raw_hits: Dict[str, List[str]],
        software_version: Optional[str],
    ) -> Optional[str]:
        """
        Resolve the hardware part number (e.g. '0281010332').

        Only present in Format A bins as plain ASCII.
        Filters out any hit that is a substring of the software version.
        Returns the first valid hit, or None.
        """
        hits = raw_hits.get("hardware_number", [])
        if not hits:
            return None

        sw = software_version or ""
        for hit in hits:
            if hit not in sw:
                return hit

        return None
