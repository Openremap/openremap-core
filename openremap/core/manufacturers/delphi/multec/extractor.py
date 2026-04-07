"""
Delphi Multec (diesel) ECU binary extractor.

Implements BaseManufacturerExtractor for the Delphi Multec family:
  Multec — Delphi/Delco diesel ECUs used in Opel/Vauxhall vehicles (late 1990s–2000s)
            e.g. 97231405 DGDHCR, 97306575 EADMRW

These are Motorola 68k CPU32-based ECUs. Two structural variants exist but
share an identical ident block format:

  Variant A — DHCR-type (212,992 bytes = 0x34000)
    Header: 6 ASCII digits at offset 0x0 (e.g. "363020"), followed by 0x13
    separator. Code starts at offset 0x10 with 68k opcodes.
    Ident block at ~0x296F0.

  Variant B — DMRW-type (262,144 bytes = 0x40000)
    Header: byte 0x11 at offset 0, then "DEL" + spaces + 10-digit Delco
    serial (e.g. "DEL  0113386350"). Code starts at offset 0x60.
    Ident block at ~0x32410.

Ident block structure (both variants):

  Preceded by a 16-byte repeating 4-byte pointer pattern, then:
    [8 ASCII digits] [space] [2 uppercase letters] [4 uppercase letters] [null]
  Followed by flags, D-number (e.g. "D00021"), version string (e.g. "Y17DIT"),
  and date code.

  Fields extracted:
    SW number       — 8 ASCII digits (e.g. "97231405")
    Broadcast code  — 2 uppercase letters (e.g. "DG", "EA")
    Family code     — 4 uppercase letters (e.g. "DHCR", "DMRW") → ecu_variant
    D-number        — calibration reference (e.g. "D00021") → calibration_id
    Delco serial    — 10 digits after "DEL  " (Variant B only) → serial_number
    Version string  — e.g. "Y17DIT", "Y17DT" → stored in raw_hits

Detection strategy (four-phase):

  Phase 1 — Size gate.
            File must be exactly 212,992 (0x34000) or 262,144 (0x40000) bytes.

  Phase 2 — Exclusion check.
            Reject if any signature from another manufacturer is found.

  Phase 3 — Positive header check.
            At least one of:
              a. Variant A: first 6 bytes are all ASCII digits.
              b. Variant B: byte 0 == 0x11 AND bytes 1-3 == b"DEL".

  Phase 4 — Ident confirmation.
            The pattern {8-digit}{space}{2-alpha}{4-alpha}{null} must exist
            somewhere in the last 40% of the file.

Verified across sample binaries:

  97231405  DGDHCR  D00021  Y17DIT  Variant A  212,992 bytes
  97306575  EADMRW  D01011  Y17DT   Variant B  262,144 bytes
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    EXCLUSION_CLEAR,
    HEADER_MATCH,
    IDENT_BLOCK,
    SIZE_MATCH,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.delphi.multec.patterns import (
    EXCLUSION_SIGNATURES,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SUPPORTED_SIZES,
)


class DelphiMultecExtractor(BaseManufacturerExtractor):
    """
    Extractor for Delphi Multec diesel ECU binaries.

    Handles Motorola 68k CPU32-based Multec diesel controllers used in
    Opel/Vauxhall vehicles. Two structural variants (DHCR-type at 212KB
    and DMRW-type at 256KB) are supported, both sharing an identical
    ident block format with 8-digit SW number, broadcast code, and
    4-character family code.
    """

    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Delphi"

    @property
    def supported_families(self) -> List[str]:
        return ["Multec"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Delphi Multec diesel ECU ROM.

        Four-phase check:

          Phase 1 — Size gate.
                    File must be exactly 212,992 bytes (0x34000) or
                    262,144 bytes (0x40000). These are the only two known
                    Multec diesel binary sizes. All Bosch, Siemens, and
                    Marelli ECU families that overlap these sizes are caught
                    by the exclusion check in Phase 2.

          Phase 2 — Exclusion check.
                    Reject if any signature belonging to another manufacturer
                    is found anywhere in the binary. Prevents false positives
                    from Bosch EDC/ME7, Siemens SIMOS, Marelli, or other
                    Delphi families that may share the same file sizes.

          Phase 3 — Positive header check.
                    At least one of the two variant signatures must match:
                      a. Variant A: bytes 0-5 are all ASCII digits (0x30-0x39).
                      b. Variant B: byte 0 == 0x11 AND bytes 1-3 == b"DEL".

          Phase 4 — Ident confirmation.
                    The ident block pattern (8 digits, space, 2 uppercase
                    letters, 4 uppercase letters, null byte) must appear
                    somewhere in the last 40% of the file. This confirms the
                    binary contains a valid Multec ident structure and is not
                    a corrupt or unrelated file that happens to pass the
                    header check.

        Args:
            data: Raw bytes of the ECU binary file.

        Returns:
            True if this extractor should handle the binary.
        """
        evidence: list[str] = []

        # Phase 1 — size gate (fastest check, no byte scanning)
        size = len(data)
        if size not in SUPPORTED_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 2 — exclusion check (reject binaries from other manufacturers)
        for excl in EXCLUSION_SIGNATURES:
            if excl in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 3 — positive header check (at least one variant must match)
        variant_a = len(data) >= 6 and all(0x30 <= b <= 0x39 for b in data[0:6])
        variant_b = len(data) >= 4 and data[0:1] == b"\x11" and data[1:4] == b"DEL"

        if not (variant_a or variant_b):
            self._set_evidence()
            return False
        if variant_a:
            evidence.append(HEADER_MATCH)  # variant A all-digit header
        if variant_b:
            evidence.append(HEADER_MATCH)  # variant B \x11DEL header

        # Phase 4 — ident confirmation in the last 40% of the file
        tail_start = size - int(size * 0.4)
        tail_data = data[tail_start:]
        ident_pattern = rb"\d{8} [A-Z]{2}[A-Z]{4}\x00"
        if not re.search(ident_pattern, tail_data):
            self._set_evidence()
            return False
        evidence.append(IDENT_BLOCK)

        self._set_evidence(evidence)
        return True

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Delphi Multec binary.

        All fields are derived from the structured ident block and the file
        header. The ident block contains the SW number, broadcast code,
        family code, D-number, and version string. The Delco serial number
        is only present in Variant B (DMRW-type) headers.

        Returns a dict fully compatible with ECUIdentifiersSchema:

            manufacturer       : "Delphi"
            file_size          : int — raw byte length (212992 or 262144)
            md5                : str — hex MD5 of the full binary
            sha256_first_64kb  : str — hex SHA-256 of the first 64KB
            ecu_family         : "Multec"
            ecu_variant        : str — 4-char family code, e.g. "DHCR", "DMRW"
            software_version   : str — 8-digit SW number, e.g. "97231405"
            hardware_number    : None — not stored as a separate field
            calibration_id     : str — D-number, e.g. "D00021"
            calibration_version: None — not present in this format
            sw_base_version    : None — not present in this format
            serial_number      : str — Delco serial (Variant B only), or None
            dataset_number     : None — not present in this format
            oem_part_number    : None — not directly available
            match_key          : str — "MULTEC::<software_version>"
            raw_strings        : list — printable ASCII strings from header

        Args:
            data:     Raw bytes of the ECU binary file.
            filename: Original filename — used for display only; not parsed.

        Returns:
            Dict compatible with ECUIdentifiersSchema.
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
            data=data,
            patterns=PATTERNS,
            pattern_regions=PATTERN_REGIONS,
            search_regions=SEARCH_REGIONS,
        )

        # --- Step 3: Resolve software version ---
        # The SW number is the 8-digit string from the ident block.
        # The pattern captures the full match "97231405 DGDHCR\x00" — we
        # need to extract just the 8-digit prefix from the captured group.
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 4: Resolve ECU variant ---
        # The 4-char family code (e.g. "DHCR", "DMRW") from the ident block.
        ecu_variant = self._resolve_variant_code(raw_hits)
        result["ecu_variant"] = ecu_variant

        # --- Step 5: Fixed fields ---
        result["ecu_family"] = "Multec"

        # --- Step 6: Resolve calibration ID (D-number) ---
        result["calibration_id"] = self._first_hit(raw_hits, "calibration_id")

        # --- Step 7: Resolve serial number (Variant B Delco serial only) ---
        result["serial_number"] = self._resolve_serial_number(raw_hits)

        # --- Step 8: Fields not present in Multec binaries ---
        result["hardware_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["dataset_number"] = None
        result["oem_part_number"] = None

        # --- Step 9: Build match key ---
        # Format: "MULTEC::<software_version>"
        result["match_key"] = self.build_match_key(
            ecu_family="Multec",
            ecu_variant=None,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Resolve the software version from the ident block pattern hits.

        The "software_version" pattern captures the full ident match including
        the trailing broadcast+family codes, e.g. "97231405 DGDHCR\\x00".
        We extract just the leading 8-digit SW number.

        If the full match pattern did not fire, falls back to extracting the
        first 8 digits from any available hit.

        Returns:
            The 8-digit SW number string, or None if not found.
        """
        hit = self._first_hit(raw_hits, "software_version")
        if hit:
            # The pattern captures the full match; extract the 8-digit prefix.
            # The hit is decoded ASCII, so we can use a simple regex.
            match = re.match(r"(\d{8})", hit)
            if match:
                return match.group(1)
        return None

    def _resolve_variant_code(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the ECU variant (4-char family code) from pattern hits.

        The "variant_code" pattern captures the full ident match including
        the leading digits and broadcast code, e.g. "97231405 DGDHCR\\x00".
        We extract just the 4-character family code.

        Returns:
            The 4-character family code (e.g. "DHCR", "DMRW"), or None.
        """
        hit = self._first_hit(raw_hits, "variant_code")
        if hit:
            # The hit is the full match decoded to ASCII; extract the 4-char
            # family code using the known ident block structure.
            match = re.search(r"\d{8} [A-Z]{2}([A-Z]{4})", hit)
            if match:
                return match.group(1)
        return None

    def _resolve_serial_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the Delco serial number from pattern hits.

        Only present in Variant B (DMRW-type) binaries. The "delco_serial"
        pattern captures the full match "DEL  0113386350"; we extract just
        the 10-digit serial number.

        Returns:
            The 10-digit Delco serial number string, or None if not present.
        """
        hit = self._first_hit(raw_hits, "delco_serial")
        if hit:
            # Extract the 10-digit serial from the full match
            match = re.search(r"(\d{10})", hit)
            if match:
                return match.group(1)
        return None
