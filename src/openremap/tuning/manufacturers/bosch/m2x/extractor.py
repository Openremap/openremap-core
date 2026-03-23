r"""
Bosch Motronic M2.x ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Motronic M2.x family:
  M2.9  — VW/Audi 4-cylinder and VR6 petrol engines (~1993–1999)
           e.g. Golf ABA 2.0 8V, Golf VR6, Passat VR6, Audi A4 1.8

These are Motorola MC68000 / MC68HC16-based ECUs, sitting between the
older M1.x/M3.x generation and the ME7 generation.

Binary structure (all M2.x, 64KB = 0x10000 bytes):

  Family marker   : ASCII string '"0000000M2.9 '
                    Located in the code region (variable offset, typically
                    0x5000–0x7500).  Always preceded by a double-quote byte
                    and followed by non-printable opcode bytes.
                    The double-quote + 7 zeros + 'M2.9' is unique to this
                    family and is the primary detection anchor.

  MOTOR label     : The authoritative HW+SW+OEM ident block.
                    Format A (standard, most bins):
                      '<VAG_PART>    MOTOR    PMC <HW_10><SW_10>'
                    Format B (Porsche 964 / M2.3, 32KB):
                      'M<rev>MOTRONIC<model_4><part_8><HW_10><XX><SW_10>'

                    In Format A bins the label is consistently located at a
                    fixed region near the end of ROM:
                      64KB bins: 0xBF00–0xCFFF  (most at 0xCF01–0xCF11)
                      32KB bins: 0x7F00–0x7FFF  (most at 0x7F02–0x7F11)

                    The region between the VAG part number and 'MOTOR' is
                    padded with spaces (4–5 spaces minimum).

  HW number       : 10-digit ASCII, starts with '0261', embedded in MOTOR
                    label immediately after 'PMC '.
                    e.g. '0261203219'

  SW version      : 10-digit ASCII, starts with '1267' or '2227', immediately
                    following HW in the MOTOR label.
                    e.g. '1267358109'  '2227355905'

  VAG part number : Alphanumeric string immediately before 'MOTOR' in label.
                    e.g. '021906258BK'  '037906258AA'  '021906258A'

  Porsche 964 (M2.3, 32KB):
                    Has 'MOTRONIC' instead of 'MOTOR    PMC'.
                    Format: 'M00MOTRONIC9646<part_8><HW_10><XX><SW_10>'
                    No slash-delimited variant string.

HW / SW format:
  HW always starts with '0261' (Bosch Motronic hardware prefix).
  SW starts with '1267' (standard M2.x) or '2227' (some M2.9 variants).
  Both are exactly 10 ASCII digits — no reversal needed (unlike M1.x/M3.x).

Verified across all sample bins:
  0261203219_soft109.bin       -> hw=0261203219 sw=1267358109 oem=021906258BK  (M2.9)
  ABA_OBD1_AA.BIN              -> hw=0261203501 sw=1267358108 oem=037906258AA  (M2.9)
  ABA_OBD1_AE.bin              -> hw=0261204018 sw=2227355905 oem=037906258AE  (M2.9)
  ABA_OBD1_AH.bin              -> hw=0261203726 sw=1267358666 oem=037906258AH  (M2.9)
  VR6_0261203117...bin         -> hw=0261203117 sw=1267357529 oem=021906258AF  (M2.9)
  VW golf 2.8 VR6 AAA...bin   -> hw=0261200496 sw=1267357205 oem=021906258A   (M2.9)
  1992_964C2...bin             -> hw=0261200473 sw=1267357006 oem=18124030     (M2.3/Porsche 964)
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# The '"0000000M2.' byte sequence is present in every M2.x bin and is
# unique to this family — absent from all M1.x, M3.x, ME7, EDC17 bins.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b'"0000000M2.',  # canonical M2.x family marker
]

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these appear in the first 512KB, the binary is NOT M2.x.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"SB_V",  # modern Bosch SW base version — absent on M2.x
    b"Customer.",  # modern Bosch customer label — absent on M2.x
    b"ME7.",  # ME7 family
    b"ME71",  # ME71 earliest variant
    b"ZZ\xff\xff",  # ME7 ident block marker
    b"1350000M3",  # M3.1 family marker
    b"1530000M3",  # M3.3 family marker
    b'"0000000M1',  # M1.x family marker
    b'"0000000M3',  # M3.x family marker
]

# ---------------------------------------------------------------------------
# MOTOR label search region
# ---------------------------------------------------------------------------
# In 64KB bins the MOTOR label sits between 0xBF00 and 0xCFFF — i.e. up to
# 20KB from the end of the file.  Searching the last 20KB covers all known
# variants with no false positives.
# In 32KB bins (Porsche 964 M2.3) it is in the upper 512 bytes (0x7F00–).
# The last 20KB window covers both.
# ---------------------------------------------------------------------------

MOTOR_LABEL_REGION: slice = slice(-0x5000, None)  # last 20KB


class BoschM2xExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic M2.x ECU binaries.
    Handles: M2.9 (VW/Audi) and M2.3 (Porsche 964).

    HW and SW are stored as plain ASCII in the MOTOR label block — no
    reversed-digit encoding like M1.x/M3.x.

    Two label formats:
      Format A (standard):  '<VAG_PART>    MOTOR    PMC <HW><SW>'
      Format B (Porsche):   'M<rev>MOTRONIC<model><part><HW><XX><SW>'
    """

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["M2.9", "M2.3"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch Motronic M2.x family ECU.

        Three-phase check:
          1. Reject immediately if any modern Bosch / ME7 / M1.x / M3.x
             exclusion signature is found.
          2. Accept if the M2.x family marker ('"0000000M2.') is found —
             this covers all standard VW/Audi M2.9 bins.
          3. Accept if a MOTRONIC label is present without the M2.x marker —
             this covers the Porsche 964 M2.3 bins which use the MOTRONIC
             label format but have no explicit '"0000000M2.' string.
             The MOTRONIC label is verified by the presence of the
             'M00MOTRONIC' or 'M<rev>MOTRONIC' prefix specific to M2.x/M2.3,
             combined with the absence of ME7 strings (already excluded above).
        """
        search_area = data[:0x80000]

        # Phase 1 — reject if any exclusion signature is present
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                return False

        # Phase 2 — accept if the canonical M2.x family marker is found
        if any(sig in search_area for sig in DETECTION_SIGNATURES):
            return True

        # Phase 3 — Porsche 964 M2.3: MOTRONIC label without '"0000000M2.'
        # The label always starts with 'M' + 2 digits + 'MOTRONIC' and is
        # followed by a 4-digit model code, a 7-digit OEM part fragment, and
        # a 10-digit HW number starting with '0261'.
        # e.g. 'M00MOTRONIC9646181240302612004731267357006'
        #       M00 + MOTRONIC + 9646(model,4) + 1812403(part,7) + 0261200473(HW,10) + ...
        # This pattern is unique to M2.3 among the families we handle, since
        # ME7 MOTRONIC labels follow a completely different format (excluded
        # above via ME7. / ZZ\xff\xff signatures).
        if re.search(rb"M\d{2}MOTRONIC\d{4}\d{7}0261\d{6}", search_area):
            return True

        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch M2.x ECU binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from the MOTOR label region ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=MOTOR_LABEL_REGION,
            min_length=8,
            max_results=20,
        )

        # --- Step 2: Resolve ECU family ---
        ecu_family = self._resolve_ecu_family(data)
        result["ecu_family"] = ecu_family

        # --- Step 3: M2.x has no separate ecu_variant (family IS the variant) ---
        result["ecu_variant"] = ecu_family

        # --- Step 4: Parse the MOTOR label for all ident fields ---
        hw, sw, oem = self._parse_motor_label(data)

        result["hardware_number"] = hw
        result["software_version"] = sw
        result["oem_part_number"] = oem

        # --- Step 5: Fields not present in M2.x binaries ---
        result["calibration_id"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 6: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,
            software_version=sw,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — ECU family resolution
    # -----------------------------------------------------------------------

    def _resolve_ecu_family(self, data: bytes) -> Optional[str]:
        """
        Resolve the ECU family string: 'M2.9' or 'M2.3'.

        The family marker '"0000000M2.x' is searched in the first 512KB.
        The digit after 'M2.' is extracted to form the sub-family string.

        For the Porsche 964 (which uses 'MOTRONIC' without the M2 marker)
        the family falls back to 'M2.3' when the MOTRONIC label is present
        and no explicit M2.x marker is found.
        """
        search_area = data[:0x80000]

        m = re.search(rb'"0000000M2\.(\d)', search_area)
        if m:
            digit = m.group(1).decode("ascii")
            return f"M2.{digit}"

        # Porsche 964 fallback — has MOTRONIC label but no M2.x marker
        if b"MOTRONIC" in search_area:
            return "M2.3"

        return None

    # -----------------------------------------------------------------------
    # Internal — MOTOR label parser
    # -----------------------------------------------------------------------

    def _parse_motor_label(
        self, data: bytes
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse the MOTOR ident label and return (hw, sw, oem_part).

        Tries Format A first (standard VW/Audi M2.9), then Format B
        (Porsche 964 / M2.3 MOTRONIC variant).

        Returns:
            Tuple of (hardware_number, software_version, oem_part_number).
            Any element may be None if not found.
        """
        search_region = data[MOTOR_LABEL_REGION]

        # --- Format A: '<VAG_PART>    MOTOR    PMC <HW_10><SW_10>' ---
        # The VAG part number is 8–14 alphanumeric chars.
        # Between the part and 'MOTOR' there are 2–8 spaces.
        # 'PMC' is followed by a single space, then HW+SW (concatenated or
        # space-separated depending on sub-variant).
        # SW starts with 1267 or 2227 (some M2.9 AE variants).
        #
        # Some bins (e.g. the VW VR6 AAA variant) have 1–4 non-alphanumeric
        # junk bytes immediately before the part number (e.g. b'\\/').
        # The [^\x20-\x7e]{0,4} prefix absorbs those without capturing them.
        #
        # M2.4 bins (Audi 100 / S6 4.2 V8) use a slightly different label:
        #   '<VAG_PART>     MOTOR D02PMC <HW_10> <SW_10>'
        # There is an intermediate token ('D02' or similar) between MOTOR and
        # PMC, and the HW and SW are separated by a single space rather than
        # being concatenated. The pattern handles both forms:
        #   - \S*? between MOTOR\s+ and PMC allows any short intermediate token
        #   - [ ]? between HW and SW allows the optional space separator
        m_a = re.search(
            rb"[^\x20-\x7e]{0,4}([0-9][0-9A-Z]{7,13})\s{2,8}MOTOR\s+\S*?PMC\s+(0261\d{6})[ ]?((?:1267|2227)\d{6})",
            search_region,
        )
        if m_a:
            oem = m_a.group(1).decode("ascii", errors="ignore").strip()
            hw = m_a.group(2).decode("ascii", errors="ignore")
            sw = m_a.group(3).decode("ascii", errors="ignore")
            return hw, sw, oem

        # --- Format B: 'M<rev>MOTRONIC<model_4><part_7><HW_10><SW_10>' ---
        # e.g. 'M00MOTRONIC9646181240302612004731267357006'
        # model_4 = 4-digit vehicle model code (e.g. 9646 = Porsche 964 6cyl)
        # part_7  = 7-digit OEM part number fragment (e.g. 1812403)
        # HW_10   = 0261xxxxxx (10 digits, starts with 0261)
        # SW_10   = 1267xxxxxx (10 digits, immediately after HW, no separator)
        # Total after 'MOTRONIC': 4+7+10+10 = 31 chars.
        m_b = re.search(
            rb"M\d{2}MOTRONIC(\d{4})(\d{7})(0261\d{6})(1267\d{6})",
            search_region,
        )
        if m_b:
            oem = m_b.group(2).decode("ascii", errors="ignore")
            hw = m_b.group(3).decode("ascii", errors="ignore")
            sw = m_b.group(4).decode("ascii", errors="ignore")
            return hw, sw, oem

        return None, None, None
