r"""
Bosch Motronic M3.x ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Motronic M3.x family:
  M3.1      — BMW DME 403 era (1989–1993), 32KB bins
  M3.3      — BMW DME 413 era (1992–1999), 32KB or 64KB bins
  MP3.2     — PSA/Citroën Bosch MP3.2 (e.g. Citroën ZX 2.0 16V 0261200218), 32KB
  MP7.2     — PSA/Citroën Bosch MP7.2 (M3.3 variant, e.g. Citroën Saxo 1.6i VTS), 256KB
  MP3.x-PSA — Other PSA bins using the 0000000M3 marker but without explicit sub-family

These are early Motorola 68xxx-based ECUs, predating the ME7 generation by
several years. The binary structure is completely different from ME7/EDC17:

  - No ZZ\xff\xff ident block, no SB_V, no Customer., no MOTRONIC label
  - Family marker is either b'1350000M3' (M3.1), b'1530000M3' (M3.3),
    or b'0000000M3' (PSA MP3.2 / MP3.x-PSA)
    preceded by fill bytes (\xfd) or a 'Z' byte
  - HW and SW numbers are encoded in the ident number in reversed digit order:
      hw = ident_clean[0:10][::-1]   -> 10-digit Bosch HW  (starts with 0261)
      sw = ident_clean[10:20][::-1]  -> 10-digit SW version (starts with 1267 or 2227)
  - DME code (calibration ID) is stored as 'NNN/NNN NNNN' in the last 1KB
  - RT code appears a few bytes after the ident number

Binary regions by sub-family:

  M3.1 (32KB = 0x8000 bytes):
    Family marker   : ~0x005C–0x0070 (near start of file)
    Ident block     : last 2KB, ~0x7DF6–0x7E16
                      Format: long numeric string \d{28,40}(?:\.\d{2})?
    DME code        : last 1KB (data[-1024:])
                      Format: \d{3}/\d{3} \d{4}  — always '011/135 NNNN'
    RT code         : a few bytes after the ident number
                      Format: \d{5}RT\d{4}

  M3.3 (32KB or 64KB = 0x8000 or 0x10000 bytes):
    Family marker   : 64KB bins at 0x4002; 32KB bins at ~0x0084
                      Often preceded by 'Z': b'Z1530000M3'
    Ident block     : last 1KB
                      DME code immediately followed by ident number:
                      Format: (\d{3}/\d{3} \d{4})(\d{28,40}(?:\.\d{2})?)
    RT code         : same pattern as M3.1
    Easter egg      : b'Gute Fahrt!' — present in some 64KB M3.3 bins only

  MP3.2 / MP3.x-PSA (32KB = 0x8000 bytes):
    Family marker   : b'0000000M3' embedded at ~0x1FF2 (the '0000000' prefix is
                      shared with the trailing zeros of the ident digit string)
    Ident block     : ~0x1FDD — a run of ASCII digit bytes ending just before 'M'
                      Format: 27+ consecutive digits; first 20 decoded as HW+SW
                      hw = digits[0:10][::-1]  → starts with 0261
                      sw = digits[10:20][::-1] → starts with 1267 or 2227
    Calibration     : anywhere in the file
                      Format: \d+/\d+/MP[\d.]+/[^\x00\xff\r\n]{5,100}

  MP7.2 (256KB — M3.3 variant):
    Family marker   : b'1530000M3' (same as M3.3)
    Sub-family tag  : b'MP7.2' present in the binary
    Ident block     : last 1KB (same M3.3 method)
                      The last 1KB may be all 0xFF → ident returns None, None
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Byte sequences used by BoschM3xExtractor.can_handle() to quickly confirm
# that a binary belongs to the M3.x family.
#
# Strategy:
#   - b'1350000M3' is the canonical family marker for M3.1 bins
#   - b'1530000M3' is the canonical family marker for M3.3 / MP7.2 bins
#   - b'0000000M3' is the PSA-specific marker for MP3.2 / MP3.x-PSA bins
#
# At least ONE must be present in the first 512KB of the binary.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"1350000M3",  # M3.1 family marker (DME 403 era, 1989–1993)
    b"1530000M3",  # M3.3 / MP7.2 family marker (DME 413 era, 1992–1999)
    b"0000000M3",  # PSA MP3.2 / MP3.x-PSA marker (e.g. Citroën ZX 2.0 16V)
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these are found in the first 512KB the binary is NOT M3.x.
# Prevents this extractor from claiming ME7, EDC17, MEDC17 or any other
# modern Bosch bin that could share a numeric substring with M3.x markers.
#
# NOTE: b"1037" is intentionally absent from this list.
#   Rationale: ME7 bins are already excluded by b"ME7.", b"ME71", and
#   b"MOTRONIC" (all present below).  PSA Bosch MP7.2 bins (M3.3 variant)
#   carry the string "1037xxxxxx" as part of their own SW ident (e.g.
#   Citroën Saxo 1.6i VTS, 256KB, contains b"1530000M3" AND "10373508120000…"),
#   so including b"1037" here would incorrectly reject valid MP7.2 bins.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",  # modern Bosch diesel
    b"MEDC17",  # modern Bosch diesel
    b"MED17",  # modern Bosch petrol
    b"ME17",  # modern Bosch petrol
    b"EDC16",  # older Bosch diesel (still not M3.x)
    b"SB_V",  # modern Bosch SW base version — absent on M3.x
    b"Customer.",  # modern Bosch customer label — absent on M3.x
    b"ME7.",  # ME7 family — M3.x predates ME7
    b"ME71",  # ME71 (earliest ME7 variant) — not M3.x
    b"MOTRONIC",  # ME7 uses the MOTRONIC label; M3.x does not
    # b"1037" is deliberately excluded — see module-level comment above
]


class BoschM3xExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic M3.x ECU binaries.

    Handles:
      - M3.1       (32KB, DME 403 era)
      - M3.3       (32KB or 64KB, DME 413 era)
      - MP3.2      (PSA/Citroën, 32KB, marker b'0000000M3' + b'MP3.2' tag)
      - MP7.2      (PSA/Citroën, 256KB, marker b'1530000M3' + b'MP7.2' tag)
      - MP3.x-PSA  (other PSA bins using b'0000000M3' without explicit sub-family)

    Key insight — HW and SW are encoded in the ident number in reversed order:
        ident_clean = ident_num.split('.')[0]
        hw = ident_clean[0:10][::-1]   # first 10 digits reversed -> 0261xxxxxx
        sw = ident_clean[10:20][::-1]  # next  10 digits reversed -> 1267xxxxxx or 2227xxxxxx
    """

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["M3.1", "M3.3", "MP3.2", "MP7.2", "MP3.x-PSA"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch Motronic M3.x family ECU.

        Two-phase check:
          1. Reject immediately if any modern Bosch / ME7 / Siemens exclusion
             signature is found — those belong to other extractors.
          2. Accept if at least one M3.x detection signature is found in the
             first 512KB.

        The exclusion phase runs first to prevent false positives on modern
        bins that might incidentally contain numeric substrings matching the
        M3.x family markers.
        """
        search_area = data[:0x80000]

        # Phase 1 — reject if any exclusion signature is present
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                return False

        # Phase 2 — accept if any M3.x family marker is present
        return any(sig in search_area for sig in DETECTION_SIGNATURES)

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch M3.x ECU binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from the last 512 bytes of file ---
        raw_strings = self.extract_raw_strings(
            data=data,
            region=slice(-512, None),
            min_length=8,
            max_results=20,
        )
        result["raw_strings"] = raw_strings

        # --- Step 2: Determine M3.x sub-family ---
        ecu_family = self._resolve_ecu_family(data)
        result["ecu_family"] = ecu_family

        # --- Step 3: M3.x has no separate ecu_variant (family IS the variant) ---
        result["ecu_variant"] = ecu_family

        # --- Steps 4–6: Resolve HW, SW, and calibration ID ---
        # MP7.2 stores its ident as direct ASCII (not reversed-digit format), so
        # it uses a dedicated extraction path rather than the shared ident mechanism.
        if ecu_family == "MP7.2":
            hardware_number, software_version, cal_id = self._extract_mp72_fields(data)
        else:
            ident_num, dme_code = self._resolve_ident_and_dme(data, ecu_family)
            hardware_number = self._resolve_hardware_number(ident_num)
            software_version = self._resolve_software_version(ident_num)
            cal_id = dme_code

        result["hardware_number"] = hardware_number
        result["software_version"] = software_version
        result["calibration_id"] = cal_id

        # --- Step 7: Fields not present in M3.x binaries ---
        result["oem_part_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 8: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,  # same for M3.x
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — sub-family resolution
    # -----------------------------------------------------------------------

    def _resolve_ecu_family(self, data: bytes) -> Optional[str]:
        """
        Determine the M3.x sub-family for this binary.

        Detection markers and precedence:
          - b'1350000M3'                         -> M3.1 (DME 403 era, always 32KB)
          - b'1530000M3' + b'MP7.2'              -> MP7.2 (PSA/Citroën, 256KB)
          - b'1530000M3'                          -> M3.3 (DME 413 era, 32KB or 64KB)
          - b'0000000M3' + b'MP3.2'              -> MP3.2 (PSA/Citroën, 32KB)
          - b'0000000M3'                          -> MP3.x-PSA (other PSA bins)

        The markers are searched within the first 512KB to match the
        same search window used by can_handle().
        """
        search_area = data[:0x80000]

        if b"1350000M3" in search_area:
            return "M3.1"

        if b"1530000M3" in search_area:
            if b"MP7.2" in search_area:
                return "MP7.2"
            return "M3.3"

        if b"0000000M3" in search_area:
            if b"MP3.2" in search_area:
                return "MP3.2"
            return "MP3.x-PSA"

        # Fallback — family unknown but accepted by can_handle()
        return None

    # -----------------------------------------------------------------------
    # Internal — ident number and DME code resolution
    # -----------------------------------------------------------------------

    def _resolve_ident_and_dme(
        self, data: bytes, ecu_family: Optional[str]
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve the raw ident number string and DME code for the binary.

        Dispatch table:
          M3.1                      -> _resolve_m31_ident_and_dme
          MP3.2, MP3.x-PSA          -> _resolve_psa_mp3x_ident_and_dme
          MP7.2, M3.3, None/other   -> _resolve_m33_ident_and_dme

        Returns:
            (ident_num, dme_code) — either or both may be None if not found.
        """
        if ecu_family == "M3.1":
            return self._resolve_m31_ident_and_dme(data)

        if ecu_family in ("MP3.2", "MP3.x-PSA"):
            return self._resolve_psa_mp3x_ident_and_dme(data)

        # MP7.2, M3.3, or unknown — use the standard M3.3 last-1KB method.
        # MP7.2 bins may have the last 1KB filled with 0xFF, in which case
        # this returns (None, None) and the match_key falls back to None.
        return self._resolve_m33_ident_and_dme(data)

    def _resolve_m31_ident_and_dme(
        self, data: bytes
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve ident number and DME code for M3.1 (32KB) binaries.

        Ident number is stored in the last 2KB as a standalone numeric string.
        DME code ('011/135 NNNN') is stored in the last 1KB separately.
        """
        ident_num: Optional[str] = None
        dme_code: Optional[str] = None

        # --- Ident number: search last 2KB for standalone long numeric string ---
        last_2kb = data[-2048:]
        ident_pattern = rb"\d{28,40}(?:\.\d{2})?"
        m = re.search(ident_pattern, last_2kb)
        if m:
            ident_num = m.group(0).decode("ascii", errors="ignore").strip()

        # --- DME code: search last 1KB for NNN/NNN NNNN format ---
        last_1kb = data[-1024:]
        dme_pattern = rb"\d{3}/\d{3} \d{4}"
        m = re.search(dme_pattern, last_1kb)
        if m:
            dme_code = m.group(0).decode("ascii", errors="ignore").strip()

        return ident_num, dme_code

    def _resolve_m33_ident_and_dme(
        self, data: bytes
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve ident number and DME code for M3.3 (32KB or 64KB) binaries.

        In M3.3 the DME code and ident number are packed together in the last 1KB:
            'NNN/NNN NNNN' immediately followed by \\d{28,40}(?:\\.\\d{2})?
        A combined regex extracts both in one pass (most reliable).

        Fallback: if the combined pattern fails, search for each field
        individually — covers the edge case where some 32KB M3.3 bins store
        the fields a few bytes apart.

        MP7.2 bins may have the last 1KB filled with 0xFF; in that case both
        fields return None (correct — no SW version stored there).
        """
        ident_num: Optional[str] = None
        dme_code: Optional[str] = None

        last_1kb = data[-1024:]

        # --- Primary: combined DME + ident block ---
        combined_pattern = rb"(\d{3}/\d{3} \d{4})(\d{28,40}(?:\.\d{2})?)"
        m = re.search(combined_pattern, last_1kb)
        if m:
            dme_code = m.group(1).decode("ascii", errors="ignore").strip()
            ident_num = m.group(2).decode("ascii", errors="ignore").strip()
            return ident_num, dme_code

        # --- Fallback: search last 2KB for each field independently ---
        last_2kb = data[-2048:]

        ident_pattern = rb"\d{28,40}(?:\.\d{2})?"
        m = re.search(ident_pattern, last_2kb)
        if m:
            ident_num = m.group(0).decode("ascii", errors="ignore").strip()

        dme_pattern = rb"\d{3}/\d{3} \d{4}"
        m = re.search(dme_pattern, last_2kb)
        if m:
            dme_code = m.group(0).decode("ascii", errors="ignore").strip()

        return ident_num, dme_code

    def _extract_mp72_fields(
        self, data: bytes
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extract HW, SW, and calibration block for Bosch MP7.2 (PSA) binaries.

        MP7.2 bins store the ECU identification in a completely different layout
        from the standard M3.x reversed-digit format:

          - Hardware number: the 10-digit Bosch HW number (starts with '0261')
            appears as a direct ASCII string repeated consecutively in the body
            of the binary (e.g. '0261206214' × N at offset 0x00FD1B on the
            Citroën Saxo 1.6i VTS).

          - Software version: a 10-digit Bosch SW number ('1037xxxxxx' or
            '2227xxxxxx') is embedded inside the PSA calibration block, after
            the date field and some padding zeros.

          - Calibration block: the full PSA-format string
            '<num>/<num>/MP7.2/<fields>/<checksum>/<date>/<long_ident_block>'
            stored as ASCII somewhere in the middle of the file.

        Example calibration block (Citroën Saxo 1.6i VTS 0261206214 SW 1037350812):
            '45/1/MP7.2/3/14/123/DAM0C03//0C550AF5/220399/  ...000010373508120000...'
            (SW '1037350812' is embedded after padding zeros inside this string)

        The last 1–2 KB of MP7.2 bins are typically filled with 0xFF, which is
        why the standard M3.3 ident-search path returns (None, None) for these files.

        Returns:
            (hardware_number, software_version, calibration_id) — any may be None.
        """
        hw: Optional[str] = None
        sw: Optional[str] = None
        cal: Optional[str] = None

        # --- HW: the hardware number is repeated consecutively as plain ASCII ---
        # Pattern: '0261xxxxxx' appearing at least twice in a row.
        hw_match = re.search(rb"(0261\d{6})\1", data)
        if hw_match:
            hw = hw_match.group(1).decode("ascii")

        # --- Cal block + SW: locate the PSA calibration string ---
        cal_pattern = rb"\d+/\d+/MP[\d.]+/[^\x00\xff\r\n]{10,250}"
        cal_match = re.search(cal_pattern, data)
        if cal_match:
            cal = cal_match.group(0).decode("ascii", errors="ignore").strip()
            # SW is a 10-digit Bosch number embedded in the cal block after
            # the date field and some zero-padding.
            sw_match = re.search(rb"(1037\d{6}|2227\d{6})", cal_match.group(0))
            if sw_match:
                sw = sw_match.group(1).decode("ascii")

        return hw, sw, cal

    def _resolve_psa_mp3x_ident_and_dme(
        self, data: bytes
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve ident number and DME code for PSA MP3.2 / MP3.x-PSA binaries.

        PSA/Citroën bins using the b'0000000M3' marker store their ident as a
        run of ASCII digit bytes immediately preceding the 'M' of the marker.
        The '0000000' portion of the marker is itself the last 7 digits of
        the ident run — they overlap.

        Layout A — MP3.2 / later PSA (Citroën ZX 2.0 16V, 0261200218):
            offset 0x1FDD:  =  8  1  2  0  0  2  1  6  2  0  0  9  3  7  5
            offset 0x1FED:  3  7  6  2  1  0  0  0  0  0  0  0  M  3  .  X
            (where '=' is a non-digit delimiter)

        Ident digits (27 total):
            digits[0:10]  = '8120021620'  → reversed → '0261200218'  (HW)
            digits[10:20] = '0937537621'  → reversed → '1267357390'  (SW)
            digits[20:27] = '0000000'     (padding/overlap with marker)

        In this layout the 27-digit run is contiguous and ends at the marker,
        so the backward walk from the marker collects all 27 digits in one pass.

        Layout B — MP3.1 / early PSA (Peugeot 106 M3.1, e.g. 0261200203):
            offset 0x1EFA:  9f 3b 03 9f 19 01 XX XX   (8-byte header, non-ASCII)
            offset 0x1F02:  3  0  2  0  0  2  1  6  2  0  3  4  2  7  5  3  7  6  2  1
            offset 0x1F16:  ff ff ff ...               (0xFF fill)
            ...
            offset 0x4F27:  22                         (0x22 = '"', non-digit)
            offset 0x4F28:  0  0  0  0  0  0  0  M  3  .  X ...  (marker)

        In this layout the 20-digit ident is stored at a fixed file offset
        with non-ASCII code bytes between it and the marker. The backward walk
        from the marker stops immediately at the '"' byte (0x22), yielding only
        '0000000' (7 chars) — fewer than the 20 needed. A whole-file scan is
        required as a fallback.

        Algorithm:
          1. Find b'0000000M3' in data.
          2. Walk backward from marker_pos+7 (the byte just before 'M'),
             collecting consecutive ASCII digit bytes.
          3. If ≥ 20 digits were collected (Layout A), use that run as ident_num.
          4. Otherwise (Layout B fallback): scan the whole file for exactly-20-
             digit runs (not preceded or followed by another digit). For each,
             attempt to decode HW (digits[0:10][::-1]) and SW (digits[10:20][::-1])
             and accept the first run where HW starts with '0261' and SW starts
             with a recognised prefix ('1267' or '2227').
          5. Search the whole file for the PSA calibration block
             (\\d+/\\d+/MP[\\d.]+/[^\\x00\\xff\\r\\n]{5,100}) and use it as dme_code.

        Returns:
            (ident_num, dme_code) — either or both may be None if not found.
        """
        ident_num: Optional[str] = None
        dme_code: Optional[str] = None

        # --- Step 1: locate the PSA family marker ---
        marker = b"0000000M3"
        marker_pos = data.find(marker)
        if marker_pos < 0:
            return None, None

        # --- Step 2: walk backward from just before 'M' collecting digits ---
        # marker_pos + 7 is the index of 'M' in '0000000M3'
        end = marker_pos + 7  # exclusive end; data[end] == ord('M')
        start = end
        while start > 0 and chr(data[start - 1]).isdigit():
            start -= 1

        digit_run = data[start:end].decode("ascii", errors="ignore")

        # Need at least 20 digits to decode both HW (first 10) and SW (next 10)
        if len(digit_run) >= 20:
            ident_num = digit_run

        # --- Step 2b: Layout B fallback for early MP3.1 bins ---
        # In early PSA bins (e.g. Peugeot 106, MP3.1) the 20-digit ident is
        # stored at a fixed file offset far from the marker, separated by
        # non-ASCII opcode bytes. The backward walk above only captures the 7
        # zeros embedded in the marker itself, so ident_num is still None here.
        # Scan the whole file for a run of exactly 20 consecutive ASCII digits
        # (not preceded or followed by another digit) that decodes to a valid
        # Bosch HW number (reversed digits[0:10] starts with '0261') and a
        # recognised SW prefix (reversed digits[10:20] starts with '1267' or '2227').
        if ident_num is None:
            for fm in re.finditer(rb"(?<![0-9])[0-9]{20}(?![0-9])", data):
                digits = fm.group(0).decode("ascii")
                hw_candidate = digits[0:10][::-1]
                sw_candidate = digits[10:20][::-1]
                if hw_candidate.startswith("0261") and sw_candidate.startswith(
                    ("1267", "2227")
                ):
                    ident_num = digits
                    break

        # --- Step 3: search for PSA calibration block anywhere in the file ---
        cal_pattern = rb"\d+/\d+/MP[\d.]+/[^\x00\xff\r\n]{5,100}"
        m = re.search(cal_pattern, data)
        if m:
            dme_code = m.group(0).decode("ascii", errors="ignore").strip()

        return ident_num, dme_code

    # -----------------------------------------------------------------------
    # Internal — HW / SW decoding from reversed ident number
    # -----------------------------------------------------------------------

    def _resolve_hardware_number(self, ident_num: Optional[str]) -> Optional[str]:
        """
        Decode the Bosch hardware part number from the raw ident number.

        The ident number encodes HW in reversed digit order:
            ident_clean = ident_num.split('.')[0]   # strip optional .XX suffix
            hw          = ident_clean[0:10][::-1]   # first 10 digits reversed

        A valid Bosch M3.x hardware number always starts with '0261' and is
        exactly 10 digits long. If the decoded value does not match this
        format the extraction is considered failed and None is returned.

        Args:
            ident_num: Raw ident string, e.g. '18002162001267xxxxxxxx...'

        Returns:
            10-digit hardware number string starting with '0261', or None.
        """
        if not ident_num:
            return None

        # Strip the optional .XX decimal suffix before reversing
        ident_clean = ident_num.split(".")[0]

        # Need at least 10 digits for the HW segment
        if len(ident_clean) < 10:
            return None

        hw = ident_clean[0:10][::-1]

        # Validate — must be all digits and start with '0261'
        if not hw.isdigit() or not hw.startswith("0261"):
            return None

        return hw

    def _resolve_software_version(self, ident_num: Optional[str]) -> Optional[str]:
        """
        Decode the Bosch software version from the raw ident number.

        The ident number encodes SW in reversed digit order:
            ident_clean = ident_num.split('.')[0]   # strip optional .XX suffix
            sw          = ident_clean[10:20][::-1]  # next 10 digits reversed

        Valid Bosch M3.x software versions start with:
          - '1267' — standard BMW and PSA Bosch numbering scheme
          - '2227' — older PSA Bosch numbering scheme (e.g. Citroën ZX early bins)

        If the decoded value does not match one of these prefixes the
        extraction is considered failed and None is returned.

        Args:
            ident_num: Raw ident string, e.g. '18002162001267xxxxxxxx...'

        Returns:
            10-digit software version string starting with '1267' or '2227',
            or None.
        """
        if not ident_num:
            return None

        # Strip the optional .XX decimal suffix before reversing
        ident_clean = ident_num.split(".")[0]

        # Need at least 20 digits to reach the SW segment
        if len(ident_clean) < 20:
            return None

        sw = ident_clean[10:20][::-1]

        # Validate — must be all digits and start with a recognised SW prefix
        if not sw.isdigit() or not sw.startswith(("1267", "2227")):
            return None

        return sw
