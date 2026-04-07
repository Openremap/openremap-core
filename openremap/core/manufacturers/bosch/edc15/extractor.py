"""
Bosch EDC15 ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch EDC15 family:
  EDC15C2   — early diesel common-rail, Alfa Romeo / Fiat / Lancia (1997–2001)
  EDC15C3   — Volvo 5-cylinder diesel (D5 2.4D), 2001–2004
  EDC15C5   — mid-generation, VW/Audi/Seat/Skoda 1.9 TDI (1999–2004)
  EDC15C7   — VAG and PSA diesel common-rail (2000–2004)
  EDC15M    — petrol DI variant (rare)
  EDC15VM+  — Renault / PSA applications

EDC15 is a generation before EDC16 and EDC17. Five binary formats exist:

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

  FORMAT C — Volvo EDC15C3 (e.g. Volvo S60/V70/XC90 D5 2.4D):
    - TSW string at 0x8000 with non-standard variant: '15C11/G43/'
    - NO '1037xxxxxx' SW number or '0281xxxxxx' HW number in flash
    - Volvo OEM calibration ID in structured ident block at 0x7EC10
    - Ident block: 6-byte header (02 04 02 0A 00 00) + 3-char short code
      + 3-byte separator + 10-char calibration ID (e.g. 'B341CS3200')
    - calibration_id used as match_key fallback when SW is absent

  FORMAT D — early EDC15 VP37/VP44 (e.g. VW T4 2.5 TDI, Golf 1.9 TDI):
    - No TSW string
    - No '1037xxxxxx' SW version — uses alphanumeric SW codes instead
    - Bosch HW number '0281xxxxxx' at fixed offset 0x10046
    - Fill byte: 0xC3 (fill ratio 33–41%)
    - File size: 512KB (0x80000)
    - Structured ident blocks at offsets ~0x5EBA9 and ~0x76BA9:
        '<VAG_PN>  <engine> EDC  <var> <code> <bosch> <0281HW> <ALPHA_SW>HEX<VAG_PN>  <date>'
    - Alphanumeric SW code (e.g. 'EBETT200') extracted as software_version
    - HW number and OEM part number extracted from same ident block
    - Detection: 0xC3 fill ratio >= 5% AND '0281\\d{6}\\s+EB[A-Z]{2,4}\\d{3}HEX'

  FORMAT E — EDC15 C167-based with low C3 fill (e.g. VW Bora/Golf/Lupo/Passat TDI):
    - No TSW string
    - Bosch C167 flash bootstrap header 'PP22..00' present (at offset 4
      after 'UU\\x00\\x00' preamble, or at flash bank boundaries 0x8004,
      0x78004).  This header is unique to Bosch EDC15 C167 flash and never
      appears in Siemens PPD/Simos or any other non-Bosch ECU binary.
    - HW number '0281xxxxxx' and SW version '1037xxxxxx' both present
    - Structured EDC ident blocks:
        '<VAG_PN>  <engine> Rx EDC  <var> <code> <0281HW> <FW_CODE>   <VAG_PN>  <date>'
    - Fill byte: 0xC3 (but only 4.1–4.6% — below the 5% Format B threshold)
    - File size: 512KB (0x80000)
    - Detection: 'PP22..00' in first 512KB AND '0281xxxxxx' HW present
                 AND ('1037xxxxxx' SW present OR structured EDC ident block present)
    - Siemens PPD/Simos/5WP signatures excluded in Phase 1 as safety guard
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    EXCLUSION_CLEAR,
    FILL_PATTERN,
)
from openremap.core.manufacturers.bosch.edc15.patterns import (
    DETECTION_SIGNATURES,
    EDC15_FORMAT_E_IDENT_RE,
    EDC15_MIN_C3_RATIO,
    EDC15_PP22_HEADER,
    EDC15_PP22_SEARCH_LIMIT,
    EXCLUSION_SIGNATURES,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    VOLVO_CAL_ID_LENGTH,
    VOLVO_CAL_ID_OFFSET,
    VOLVO_IDENT_BLOCK_HEADER,
    VOLVO_IDENT_BLOCK_OFFSET,
)


class BoschEDC15Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch EDC15 ECU binaries.
    Handles Format A (TSW string present), Format B (older, no TSW),
    Format C (Volvo EDC15C3 — TSW present but no 1037/0281 strings),
    and Format D (early VP37/VP44 — alphanumeric SW codes, no TSW or 1037).
    """

    # Opt in: when software_version is absent (Format C / Volvo EDC15C3),
    # use calibration_id as the version component of the match key.
    match_key_fallback_field = "calibration_id"
    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return [
            "EDC15C2",
            "EDC15C3",
            "EDC15C5",
            "EDC15C7",
            "EDC15M",
            "EDC15VM+",
            "EDC15",
        ]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch EDC15 ECU.

        Five-phase check:
          1. Reject immediately if any exclusion signature is found — modern
             Bosch families (EDC16, EDC17, ME7 etc.) share the 1037xxxxxx SW
             prefix and must be excluded before any positive check.
             Siemens PPD / Simos / 5WP signatures are also excluded here.
          2. Accept (Format A) if the TSW string is present at 0x8000.
             TSW is unique to the EDC15 toolchain and is the strongest anchor.
          3. Accept (Format B) if both conditions hold:
               a. 0xC3 fill byte accounts for at least EDC15_MIN_C3_RATIO
                  of the total file size.
               b. At least one '1037xxxxxx' SW version string is present
                  anywhere in the binary.
             Together these two conditions identify older EDC15 bins that
             lack the TSW marker but share the same fill byte and SW format.
          4. Accept (Format D) if both conditions hold:
               a. 0xC3 fill ratio >= EDC15_MIN_C3_RATIO (reuses Phase 3).
               b. The structured ident pattern '0281xxxxxx' HW + alphanumeric
                  SW code + 'HEX' suffix is present in the binary.
             These are early EDC15 VP37/VP44 bins that use alphanumeric SW
             codes (e.g. 'EBETT200') instead of '1037xxxxxx'.
          5. Accept (Format E) if ALL of the following hold:
               a. The Bosch C167 flash bootstrap header 'PP22..00' is present
                  in the first 64KB of the binary.
               b. A Bosch diesel HW number '0281xxxxxx' is present.
               c. Either a '1037xxxxxx' SW version string OR a structured
                  EDC ident block ('Rx EDC ... 0281xxxxxx') is present.
             These are EDC15 C167-based bins whose C3 fill ratio (4.1–4.6%)
             falls just below the Format B threshold.  The PP22 header is
             unique to Bosch EDC15 C167 flash and never appears in Siemens
             PPD/Simos files.
        """
        search_area = data[:0x80000]

        evidence: list[str] = []

        # Phase 1 — reject on any exclusion signature
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 2 — Format A: TSW string at 0x8000 relative to the start of
        # every 512KB bank. A 512KB single-bank bin has TSW at absolute 0x8000
        # (bank 0). A 1MB dual-bank bin also has TSW at 0x88000 (bank 1).
        num_banks = max(1, len(data) // 0x80000)
        if any(
            sig in data[bank * 0x80000 + 0x8000 : bank * 0x80000 + 0x8060]
            for bank in range(num_banks)
            for sig in DETECTION_SIGNATURES
        ):
            evidence.append("TSW_STRING")
            self._set_evidence(evidence)
            return True

        # Phase 3 — Format B: 0xC3 fill ratio + 1037xxxxxx SW present
        c3_ratio = data.count(b"\xc3") / len(data) if data else 0.0
        if c3_ratio >= EDC15_MIN_C3_RATIO:
            if re.search(rb"1037\d{6,10}", data):
                evidence.append(FILL_PATTERN)
                evidence.append("SW_STRING")
                self._set_evidence(evidence)
                return True

        # Phase 4 — Format D: early EDC15 (VP37/VP44) with alphanumeric SW codes
        # These bins have C3 fill >= threshold AND 0281xxxxxx HW AND
        # alphanumeric SW codes (e.g. EBETT200) instead of 1037xxxxxx.
        if c3_ratio >= EDC15_MIN_C3_RATIO:
            if re.search(rb"0281\d{6}\s+EB[A-Z]{2,4}\d{3}HEX", data):
                evidence.append(FILL_PATTERN)
                evidence.append("FORMAT_D_IDENT")
                self._set_evidence(evidence)
                return True

        # Phase 5 — Format E: PP22 header + 0281 HW + (1037 SW or EDC ident)
        # These are C167-based EDC15 bins with C3 fill just below the
        # Format B threshold (4.1–4.6%).  The PP22..00 header is the Bosch
        # C167 flash bootstrap signature — unique to EDC15, never found in
        # Siemens PPD/Simos files.
        if EDC15_PP22_HEADER in data[:EDC15_PP22_SEARCH_LIMIT]:
            has_hw = bool(re.search(rb"0281\d{6}", data))
            if has_hw:
                has_sw = bool(re.search(rb"1037\d{6,10}", data))
                has_edc_ident = bool(re.search(EDC15_FORMAT_E_IDENT_RE, data))
                if has_sw or has_edc_ident:
                    evidence.append("PP22_HEADER")
                    evidence.append("HW_STRING")
                    if has_sw:
                        evidence.append("SW_STRING")
                    else:
                        evidence.append("EDC_IDENT")
                    self._set_evidence(evidence)
                    return True

        self._set_evidence()
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

        # --- Step 5b: Format D fallback (early EDC15 VP37/VP44) ---
        # When no 1037xxxxxx SW is found, try the structured ident block
        # with alphanumeric SW codes.
        if software_version is None:
            d_hw, d_sw, d_oem = self._resolve_format_d_fields(data)
            if d_sw is not None:
                software_version = d_sw
                result["software_version"] = software_version
                if d_hw is not None and hardware_number is None:
                    hardware_number = d_hw
                    result["hardware_number"] = hardware_number
                if d_oem is not None:
                    result["oem_part_number"] = d_oem

        # --- Step 6: Volvo EDC15C3 calibration ID (Format C) ---
        # When SW is absent, try to extract the Volvo OEM calibration ID
        # from the structured ident block at 0x7EC10.
        calibration_id = self._resolve_volvo_calibration_id(data)
        result["calibration_id"] = calibration_id

        # --- Step 7: Fields not present in EDC15 binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        # oem_part_number may already be set by Format D (Step 5b) —
        # only default to None if not already populated.
        if "oem_part_number" not in result:
            result["oem_part_number"] = None

        # --- Step 8: Build match key ---
        # When software_version is present (Format A/B), it is used directly.
        # When absent (Format C / Volvo), calibration_id is used as fallback
        # via match_key_fallback_field = "calibration_id".
        result["match_key"] = self.build_match_key(
            ecu_family="EDC15",
            ecu_variant=None,
            software_version=software_version,
            fallback_value=calibration_id,
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

    def _resolve_volvo_calibration_id(self, data: bytes) -> Optional[str]:
        """
        Extract the Volvo OEM calibration ID from the Format C ident block.

        The ident block is at a fixed offset (0x7EC10) in 512KB EDC15C3 bins.
        Structure:
          Bytes 0–3:   02 04 02 0A     — fixed header (matched for validation)
          Bytes 4–5:   00 00           — padding
          Bytes 6–8:   3-char ASCII short code (e.g. '762', '75v')
          Bytes 9–11:  separator (variable binary)
          Bytes 12–21: 10-char ASCII calibration ID (e.g. 'B341CS3200')

        Returns the 10-char calibration ID if the header matches and the
        calibration ID is valid printable ASCII, otherwise None.
        """
        block_end = VOLVO_IDENT_BLOCK_OFFSET + VOLVO_CAL_ID_OFFSET + VOLVO_CAL_ID_LENGTH
        if len(data) < block_end:
            return None

        block = data[VOLVO_IDENT_BLOCK_OFFSET:]

        # Validate the fixed header bytes
        if block[: len(VOLVO_IDENT_BLOCK_HEADER)] != VOLVO_IDENT_BLOCK_HEADER:
            return None

        # Extract the 10-char calibration ID
        cal_id_bytes = block[
            VOLVO_CAL_ID_OFFSET : VOLVO_CAL_ID_OFFSET + VOLVO_CAL_ID_LENGTH
        ]

        # Validate: must be printable ASCII, at least one letter present
        try:
            cal_id = cal_id_bytes.decode("ascii")
        except (UnicodeDecodeError, ValueError):
            return None

        if not all(32 <= ord(c) <= 126 for c in cal_id):
            return None

        # Require at least one letter — pure digits or pure non-alpha is not
        # a valid Volvo calibration ID.
        if not any(c.isalpha() for c in cal_id):
            return None

        return cal_id.strip() or None

    def _resolve_format_d_fields(
        self, data: bytes
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extract HW, alphanumeric SW code, and OEM part number from Format D
        (early EDC15, VP37/VP44) structured ident blocks.

        The ident block format is:
            '<VAG_PN>  <engine> EDC  <variant>  <code> <bosch_code> <0281HW> <ALPHA_SW>HEX<VAG_PN>  <date>'
        e.g.:
            '074906018C  2,5l R5 EDC  SG  2520 28SA4060 0281010082 EBETT200HEX074906018C  0399'

        Multiple ident blocks may exist (SG=standard, AG=replacement).
        Returns the first match.

        Returns:
            (hardware_number, alpha_sw_code, oem_part_number) — any may be None.
        """
        m = re.search(
            rb"\w{9,12}\s+[\d,]+l\s+R\d\s+EDC\s+\w{2}\s+\d{4}\s+\w{6,10}\s+(0281\d{6})\s+(EB[A-Z]{2,4}\d{3})HEX([0-9A-Z]{9,12})",
            data,
        )
        if not m:
            return None, None, None

        hw = m.group(1).decode("ascii", errors="ignore").strip()
        sw = m.group(2).decode("ascii", errors="ignore").strip()
        oem = m.group(3).decode("ascii", errors="ignore").strip()

        return hw, sw, oem

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
