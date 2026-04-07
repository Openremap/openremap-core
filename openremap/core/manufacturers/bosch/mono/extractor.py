r"""
Bosch Mono-Motronic ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Mono-Motronic family:
  Mono-Motronic — VW/Audi/Seat single-point fuel injection ECUs (~1989–1997)
                  VW Golf 2/3, Audi 80 B4, VW Passat B4, Seat Ibiza/Cordoba
                  8051-family CPU (SAB80C535/SAB80C515), 32KB or 64KB dumps

These are 8051-based single-point injection ECUs that predate the M2.x and
M5.x generations.  They use a completely different binary layout from all
other Bosch Motronic families:

  - NO ZZ\xff\xff ident block (ME7-specific)
  - NO reversed-digit ident encoding (M1.x / M3.x territory)
  - NO MOTRONIC label (M5.x / ME7 / M2.x / MP9 territory)
  - NO '"0000000M' family marker (M1.x / M2.x / M3.x territory)
  - The HW and SW are NOT embedded as 10-digit ASCII strings in the binary
  - The PMC (Programmable Map Computing) keyword is always present
  - The OEM part number is embedded as ASCII in a fixed-format ident block
  - 8051 LJMP instruction at offset 0: \x02\x05\xNN (jump to 0x05xx)

Binary sizes:
  0x8000  (32KB)  — single EPROM (e.g. Audi 80 8A0907311H)
  0x10000 (64KB)  — two mirrored 32KB halves (e.g. VW Golf 3 1H0907311H)

Ident block formats:

  Format A — MONO (R4 MONO variant, most bins):
    '<OEM_PART>  <disp> R4 MONO [<version>]  <D_code>PMC'
    e.g. "8A0907311H  1,8l R4 MONO 1.2.3  D51PMC"
    e.g. "1H0907311H  1,8l R4 MONO        D51PMC"

  Format B — DGC (Digitale Gemisch Composition variant):
    '<OEM_PART>   <disp>[<OEM_PART>   <disp>]DGCPMC'
    e.g. "3A0907311   1,8l3A0907311   1,8lDGCPMC"

Detection strategy:

  Phase 1 — Reject on any exclusion signature (modern Bosch, M1x/M2x/M3x/M5x).
  Phase 2 — Reject if file size is not 32KB or 64KB.
  Phase 3 — Accept if 8051 LJMP header (\x02\x05 at offset 0) AND
            'PMC' keyword present in binary.
  Phase 4 — Accept if 8051 LJMP header AND '907311' VAG Mono part code
            present in binary (fallback for bins where PMC is damaged/missing).

Verified sample set:
  original.bin                                  -> oem=8A0907311H   family=Mono-Motronic  (Format A, MONO 1.2.3)
  VW GOLF3 1.8-90hp-0261200784-1H0907311H.bin   -> oem=1H0907311H   family=Mono-Motronic  (Format A, MONO)
  Golf 3 90PS 0 261 203 593-594 original.bin    -> oem=3A0907311    family=Mono-Motronic  (Format B, DGC)
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    EXCLUSION_CLEAR,
    HEADER_MATCH,
    SIZE_MATCH,
)
from openremap.core.manufacturers.bosch.mono.patterns import (
    DEFAULT_FAMILY,
    EXCLUSION_SIGNATURES,
    HEADER_BYTE_0,
    HEADER_BYTE_1,
    IDENT_FORMAT_A_RE,
    IDENT_FORMAT_B_RE,
    OEM_PART_FALLBACK_RE,
    PMC_KEYWORD,
    SEARCH_REGIONS,
    SUPPORTED_SIZES,
    TAIL_MARKER_RE,
    VAG_MONO_GROUP_CODE,
)


class BoschMonoExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Mono-Motronic ECU binaries.
    Handles: Mono-Motronic (MA1.2, MA1.2.3, DGC/PMC variants).

    Detection is anchored on the 8051 LJMP header (\\x02\\x05) at offset 0
    combined with the PMC keyword or VAG 907311 group code.

    The OEM part number is the primary extracted identifier.  HW and SW
    numbers are not stored as ASCII in these binaries.
    """

    # Use oem_part_number as the fallback field for match_key when
    # software_version is absent (which it always is for Mono-Motronic).
    match_key_fallback_field = "oem_part_number"
    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["Mono-Motronic"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch Mono-Motronic ECU.

        Four-phase check:

          Phase 1 — Exclusion.
            Reject immediately if any exclusion signature is found in the
            first 512KB.  Guards against all modern Bosch families, M1.x,
            M2.x, M3.x, M5.x, LH-Jetronic, and Digifant.

          Phase 2 — Size gate.
            Reject if file size is not exactly 32KB or 64KB.

          Phase 3 — Primary: 8051 LJMP header + PMC keyword.
            Accept if data[0] == 0x02 AND data[1] == 0x05 (8051 LJMP to
            the 0x05xx reset handler) AND the 'PMC' keyword is present
            anywhere in the binary.

          Phase 4 — Fallback: 8051 LJMP header + VAG 907311 group code.
            Accept if the header matches AND the '907311' VAG part code
            is present.  Covers bins where PMC might be missing but the
            VAG part number is still readable.
        """
        sz = len(data)
        evidence: list[str] = []

        # Phase 1 — exclusion check (first 512KB)
        search_area = data[SEARCH_REGIONS["exclusion_area"]]
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 2 — size gate
        if sz not in SUPPORTED_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Header check: 8051 LJMP at offset 0 targeting 0x05xx
        if sz < 2 or data[0] != HEADER_BYTE_0 or data[1] != HEADER_BYTE_1:
            self._set_evidence()
            return False
        evidence.append(HEADER_MATCH)

        # Phase 3 — PMC keyword
        if PMC_KEYWORD in data:
            evidence.append("PMC_KEYWORD")
            self._set_evidence(evidence)
            return True

        # Phase 4 — VAG 907311 group code fallback
        if VAG_MONO_GROUP_CODE in data:
            evidence.append("VAG_GROUP_CODE")
            self._set_evidence(evidence)
            return True

        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch Mono-Motronic binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from the primary 32KB bank ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_area"],
            min_length=8,
            max_results=20,
        )

        # --- Step 2: Resolve ECU family and sub-variant ---
        ecu_family, mono_version, d_code, displacement = self._resolve_ident(data)
        result["ecu_family"] = ecu_family
        result["ecu_variant"] = ecu_family

        # --- Step 3: Resolve OEM part number ---
        oem_part = self._resolve_oem_part_number(data)
        result["oem_part_number"] = oem_part

        # --- Step 4: HW and SW — not available as ASCII in Mono-Motronic ---
        result["hardware_number"] = None
        result["software_version"] = None

        # --- Step 5: Calibration-related fields ---
        result["calibration_id"] = d_code
        result["calibration_version"] = mono_version
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 6: Tail marker (variant code, informational only) ---
        tail_marker = self._resolve_tail_marker(data)
        # Not stored as a separate field — included in raw_strings if present.

        # --- Step 7: Build match key ---
        # Since there is no standard software_version, the match_key_fallback_field
        # mechanism uses oem_part_number as the version component.
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,
            software_version=None,
            fallback_value=oem_part,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — ident block parser
    # -----------------------------------------------------------------------

    def _resolve_ident(
        self, data: bytes
    ) -> tuple[str, Optional[str], Optional[str], Optional[str]]:
        """
        Parse the ident block and resolve family, version, D-code, and
        displacement.

        Tries Format A (MONO) first, then Format B (DGC).

        Returns:
            (ecu_family, mono_version, d_code, displacement)
            where mono_version is e.g. "1.2.3" or None,
            d_code is e.g. "D51" or None,
            displacement is e.g. "1,8l" or None.
        """
        ident_area = data[SEARCH_REGIONS["ident_area"]]

        # --- Format A: MONO variant ---
        m = IDENT_FORMAT_A_RE.search(ident_area)
        if m:
            displacement = m.group(2).decode("ascii", errors="ignore").strip()
            version_raw = m.group(3)
            mono_version = (
                version_raw.decode("ascii", errors="ignore").strip()
                if version_raw
                else None
            )
            d_code = m.group(4).decode("ascii", errors="ignore").strip()
            return DEFAULT_FAMILY, mono_version, d_code, displacement

        # --- Format B: DGC variant ---
        m = IDENT_FORMAT_B_RE.search(ident_area)
        if m:
            displacement = m.group(2).decode("ascii", errors="ignore").strip()
            return DEFAULT_FAMILY, None, None, displacement

        # --- Fallback: PMC keyword present but no structured ident ---
        return DEFAULT_FAMILY, None, None, None

    # -----------------------------------------------------------------------
    # Internal — OEM part number resolver
    # -----------------------------------------------------------------------

    def _resolve_oem_part_number(self, data: bytes) -> Optional[str]:
        """
        Extract the VAG OEM part number from the ident block.

        Tries Format A, then Format B, then a generic fallback regex
        searching for any VAG 907311 part number.

        Returns:
            OEM part number string (e.g. "8A0907311H", "3A0907311"),
            or None if not found.
        """
        ident_area = data[SEARCH_REGIONS["ident_area"]]

        # Format A: MONO variant — group 1 is OEM part
        m = IDENT_FORMAT_A_RE.search(ident_area)
        if m:
            return m.group(1).decode("ascii", errors="ignore").strip()

        # Format B: DGC variant — group 1 is OEM part
        m = IDENT_FORMAT_B_RE.search(ident_area)
        if m:
            return m.group(1).decode("ascii", errors="ignore").strip()

        # Generic fallback — any VAG 907311 part
        m = OEM_PART_FALLBACK_RE.search(ident_area)
        if m:
            return m.group(1).decode("ascii", errors="ignore").strip()

        return None

    # -----------------------------------------------------------------------
    # Internal — tail marker resolver
    # -----------------------------------------------------------------------

    def _resolve_tail_marker(self, data: bytes) -> Optional[str]:
        """
        Extract the tail variant marker from the last 16 bytes.

        The tail marker is a 6-7 character string containing a 2-3 letter
        Bosch variant prefix followed by "057" and a suffix character.
        e.g. "WAN057@", "UAN057\\"", "AB057R"

        Returns:
            Tail marker string, or None if not found.
        """
        tail_area = data[SEARCH_REGIONS["tail_area"]]
        m = TAIL_MARKER_RE.search(tail_area)
        if m:
            return m.group(1).decode("ascii", errors="ignore").strip()
        return None
