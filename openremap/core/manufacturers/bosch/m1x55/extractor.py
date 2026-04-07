"""
Bosch Motronic M1.55 ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Motronic M1.55 family:
  M1.55  — Alfa Romeo 155 / 156 / GT / Spider petrol engines (1994–2002)
            e.g. 2.0 TS (16V), 1.8 TS, 2.5 V6 variants

M1.55 is a transitional generation sitting between the older M1.x (HC11-based,
32KB) and the M3.x / M5.x families. It uses a Motorola 68K-derivative CPU and
a 128KB (0x20000 bytes) flash ROM. Unlike M1.3/M1.7 it is NOT a 32KB HC11 ROM,
and unlike M5.x it does NOT use the MOTR ident block or a 12-digit SW prefix.

Binary structure (128KB = 0x20000 bytes):

  0x00000 – 0x07FFF  (32KB) : Code section A — Motorola 68K instructions
                               First 4 bytes: 02 be f2 02 (reset vector area)
                               NOT the HC11 magic (85 0a f0 30) used by M1.3/M1.7
  0x08000 – 0x0FFFF  (32KB) : Code section B + family descriptor
                               Descriptor at exactly 0x08005 (5 bytes in):
                               e.g. "56/1/M1.55/9/5033/DAMOS161/16DZ204S_E/..."
  0x10000 – 0x17FFF  (32KB) : Code section C (calibration tables, lookups)
  0x18000 – 0x1FFFF  (32KB) : 0xFF erased — not used
                               Exception: last ~1KB (0x1FB00–0x1FFFF) contains
                               the HW + SW + checksum ident block

Ident block (near end of file, ~0x1FBC2):
  Format: "<HW> <SW> <checksum>   "
  e.g.    "0261204270 1037359650 46739438   "
  HW      : "0261" + 6 digits  (Bosch Motronic hardware part number)
  SW      : "1037" + 6–10 digits (Bosch internal software calibration ID)
  checksum: 6–10 digit Bosch internal checksum — not used for identification

Family descriptor (at 0x08005, fixed offset):
  Slash-delimited string, same format used across all Bosch M-series families.
  e.g. "56/1/M1.55/9/5033/DAMOS161/16DZ204S_E/16DZ204S_E/280798/"
  Fields:
    [0] revision  : e.g. "56"
    [1] sub       : e.g. "1"
    [2] family    : e.g. "M1.55"   ← ecu_family
    [3] n         : e.g. "9"
    [4] dataset   : e.g. "5033"    ← dataset_number
    [5] DAMOS ref : e.g. "DAMOS161"
    [6] ECU var   : e.g. "16DZ204S_E"  ← ecu_variant / calibration_id
    [7] ECU var 2 : e.g. "16DZ204S_E"  (usually same as [6])
    [8] date      : e.g. "280798"  (DDMMYY)

Detection strategy:
  1. Reject if any modern Bosch / ME7 / EDC exclusion signature is present.
  2. Reject if file size is not exactly 128KB (0x20000).
  3. Accept if the M1.55 family string b"M1.55" is present in the first 64KB.
     M1.55 is the only known sub-variant of the 128KB Motorola-based Alfa ECUs;
     no other Bosch extractor accepts 128KB bins with this family token
     (M5x excludes b"1037", M1x requires the HC11 header magic and 32KB size).

Verified across 2 sample bins:
  Alfa 156 2.0 155HP 0261204270 1037359650   -> M1.55  hw=0261204270  sw=1037359650
  OkAlfa649B (Alfa 156 / GT)  0261204947 1037359649 -> M1.55  hw=0261204947  sw=1037359649
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    EXCLUSION_CLEAR,
    FAMILY_STRING,
    SIZE_MATCH,
)

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

# The M1.55 family token — present at a fixed offset (0x08005) in every
# known Alfa bin and nowhere in any other Bosch family binary.
DETECTION_SIGNATURE: bytes = b"M1.55"

# Opel M1.5.5 family token — same 128KB size, different dot notation.
# Located in the DAMOS descriptor at ~0x0D82F (not 0x08005).
# e.g. "47/1/M1.5.5/06/100.0/DAMOS++/3007/300703/260799"
DETECTION_SIGNATURE_OPEL: bytes = b"M1.5.5"

# Supported file size — M1.55 and M1.5.5 bins are always exactly 128KB.
SUPPORTED_SIZE: int = 0x20000  # 128KB

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these are present the binary cannot be M1.55.
# Guards against false positives on:
#   - Modern Bosch diesel (EDC16, EDC17, MEDC17) that share the "M1" substring
#   - ME7 / MOTRONIC (petrol, same era but different CPU and layout)
#   - EDC15 (TSW toolchain string)
#   - M3.x (family markers 1350000M3 / 1530000M3)
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"EDC15",
    b"SB_V",
    b"NR000",
    b"Customer.",
    b"ME7.",
    b"ME71",
    b"ME731",
    b"MOTRONIC",
    b"TSW ",
    b"1350000M3",
    b"1530000M3",
]

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Family descriptor — slash-delimited, always starts at 0x08005.
# We search a narrow window (0x8000–0x8200) to avoid any accidental match.
DESCRIPTOR_REGION: slice = slice(0x8000, 0x8200)
DESCRIPTOR_PATTERN: bytes = (
    rb"M1\.\d+/\d+/\d+/[^\x00/]{4,}/[^\x00/]{4,}/[^\x00/]{4,}/\d{6}/"
)

# HW + SW ident block near end of file.
# Format: "0261XXXXXX 1037XXXXXXXXXX NNNNNNNN"
# The two numbers are separated by a single space; the checksum follows.
IDENT_REGION: slice = slice(-0x800, None)  # last 2KB — ident block always here
HW_SW_PATTERN: bytes = rb"(0261\d{6}) (1037\d{6,10})"

# ---------------------------------------------------------------------------
# Opel M1.5.5 ident block (middle of file, ~0xD801)
# ---------------------------------------------------------------------------
# Format: "<sw8> <prefix><hw10><checksum><variant>  <build>"
# e.g.   "90532609 RY026120405828SA4143  B97003"
#   sw8    : 8-digit GM/Opel internal SW number  e.g. "90532609"
#   prefix : 2-char dataset code                 e.g. "RY"
#   hw10   : 10-digit Bosch HW number            e.g. "0261204058"
#
# Group 1 = software_version (8-digit GM number)
# Group 2 = hardware_number  (0261xxxxxx)
# ---------------------------------------------------------------------------
OPEL_M155_IDENT_REGION: slice = slice(0xD000, 0xE000)
OPEL_M155_IDENT_PATTERN: bytes = rb"(\d{8}) [A-Z]{2}(0261\d{6})"


class BoschM1x55Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic M1.55 ECU binaries.
    Handles Alfa Romeo 128KB petrol ECU bins from the mid-1990s to early 2000s.
    """

    detection_strength = DetectionStrength.MODERATE

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["M1.55", "M1.5.5"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch Motronic M1.55 or M1.5.5 ECU.

        Three-phase check:
          1. Reject immediately if any exclusion signature is present in the
             first 512KB — prevents claiming EDC/ME7/M3.x bins that might
             incidentally contain the "M1" substring.
          2. Reject if file size is not exactly 128KB (0x20000).
             Both M1.55 and M1.5.5 bins are always this size.
          3. Accept if the b"M1.55" family token is present in the first 64KB
             (Alfa Romeo variants), OR if b"M1.5.5" is present anywhere in
             the binary (Opel variants — token is at ~0x0D82F, past 64KB mark).
        """
        evidence: list[str] = []
        search_area = data[:0x80000]

        # Phase 1 — exclusion check
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 2 — size gate
        if len(data) != SUPPORTED_SIZE:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 3 — family token: Alfa M1.55 (first 64KB) or Opel M1.5.5 (anywhere)
        if DETECTION_SIGNATURE in data[:0x10000]:
            evidence.append(FAMILY_STRING)
            self._set_evidence(evidence)
            return True
        if DETECTION_SIGNATURE_OPEL in data:
            evidence.append(FAMILY_STRING)
            self._set_evidence(evidence)
            return True

        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch M1.55 ECU binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw strings from the ident region ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=IDENT_REGION,
            min_length=8,
            max_results=20,
        )

        # --- Step 2: Detect variant (Alfa M1.55 vs Opel M1.5.5) ---
        is_opel = DETECTION_SIGNATURE_OPEL in data

        if is_opel:
            # Opel M1.5.5 — DAMOS descriptor at ~0xD82F, GM-style ident block
            ecu_family = "M1.5.5"
            ecu_variant = None
            dataset_number = None
            calibration_id = None
        else:
            # Alfa M1.55 — slash-delimited descriptor at 0x8005
            descriptor = self._parse_descriptor(data)
            ecu_family = descriptor.get("family") or "M1.55"
            ecu_variant = descriptor.get("ecu_variant")
            dataset_number = descriptor.get("dataset")
            calibration_id = descriptor.get("ecu_variant")  # same field, dual use

        result["ecu_family"] = ecu_family
        result["ecu_variant"] = ecu_variant
        result["dataset_number"] = dataset_number
        result["calibration_id"] = calibration_id

        # --- Step 3: HW and SW from the appropriate ident block ---
        if is_opel:
            hardware_number, software_version = self._parse_opel_m155_ident(data)
        else:
            hardware_number, software_version = self._parse_hw_sw(data)
        result["hardware_number"] = hardware_number
        result["software_version"] = software_version

        # --- Step 4: Fields not present in M1.55 binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["oem_part_number"] = None

        # --- Step 5: Build match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=result["ecu_family"],
            ecu_variant=result["ecu_variant"],
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — descriptor parser
    # -----------------------------------------------------------------------

    def _parse_descriptor(self, data: bytes) -> Dict[str, Optional[str]]:
        """
        Parse the slash-delimited family descriptor from the binary.

        The descriptor is located in the 0x8000–0x8200 region.
        Format: "<rev>/<sub>/<family>/<n>/<dataset>/<damos>/<variant>/<variant2>/<date>/"
        e.g.   "56/1/M1.55/9/5033/DAMOS161/16DZ204S_E/16DZ204S_E/280798/"

        Returns a dict with keys: family, dataset, ecu_variant.
        All values are None if the descriptor is not found.
        """
        empty: Dict[str, Optional[str]] = {
            "family": None,
            "dataset": None,
            "ecu_variant": None,
        }

        region = data[DESCRIPTOR_REGION]
        m = re.search(DESCRIPTOR_PATTERN, region)
        if not m:
            # Fallback: try to find any "M1.XX" token
            m2 = re.search(rb"M1\.\d+", region)
            if m2:
                empty["family"] = m2.group(0).decode("ascii", errors="ignore")
            return empty

        raw = m.group(0).decode("ascii", errors="ignore")
        # The match starts at "M1.xx/" — prepend the two fixed fields
        # that precede it (revision + sub) by searching back for them.
        # Instead of relying on offset maths, look for the full descriptor
        # starting from one or two fields before M1.
        full_m = re.search(
            rb"\d{2}/\d+/M1\.\d+/\d+/(\d+)/[^\x00/]{4,}/([^\x00/]{4,})/[^\x00/]{4,}/\d{6}/",
            region,
        )
        if full_m:
            dataset = full_m.group(1).decode("ascii", errors="ignore").strip()
            ecu_variant = full_m.group(2).decode("ascii", errors="ignore").strip()
        else:
            # Parse from the partial match (starts at M1.)
            parts = raw.split("/")
            # parts[0]=M1.xx, [1]=n, [2]=dataset, [3]=damos, [4]=variant, ...
            dataset = parts[2] if len(parts) > 2 else None
            ecu_variant = parts[4] if len(parts) > 4 else None

        # Family token
        family_m = re.search(rb"M1\.\d+", region)
        family = (
            family_m.group(0).decode("ascii", errors="ignore") if family_m else "M1.55"
        )

        return {
            "family": family,
            "dataset": dataset,
            "ecu_variant": ecu_variant,
        }

    # -----------------------------------------------------------------------
    # Internal — HW / SW resolver
    # -----------------------------------------------------------------------

    def _parse_opel_m155_ident(
        self, data: bytes
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Parse the Opel M1.5.5 ident block located at ~0xD801.

        Format: "<sw8> <prefix2><hw10><checksum2><variant>  <build>"
        e.g.   "90532609 RY026120405828SA4143  B97003"

        Group 1 = 8-digit GM/Opel internal SW number → software_version
        Group 2 = 10-digit Bosch HW number (0261xxxxxx) → hardware_number

        The ident is duplicated at 0xD801 and 0x1D801; searching the
        OPEL_M155_IDENT_REGION (0xD000–0xE000) finds the first copy.

        Returns (hardware_number, software_version), either may be None.
        """
        region = data[OPEL_M155_IDENT_REGION]
        m = re.search(OPEL_M155_IDENT_PATTERN, region)
        if not m:
            return None, None

        sw = m.group(1).decode("ascii", errors="ignore").strip()
        hw = m.group(2).decode("ascii", errors="ignore").strip()

        software_version = sw if sw and not re.match(r"^0+$", sw) else None
        hardware_number = hw if hw and not re.match(r"^0+$", hw) else None

        return hardware_number, software_version

    def _parse_hw_sw(self, data: bytes) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve the hardware part number and software version from the ident
        block near the end of the file.

        The ident block contains a space-separated triple:
            "<HW> <SW> <checksum>"
        e.g. "0261204270 1037359650 46739438"

        Both numbers are stored as plain ASCII.
        Returns (hardware_number, software_version) — either may be None.
        """
        region = data[IDENT_REGION]
        m = re.search(HW_SW_PATTERN, region)
        if not m:
            return None, None

        hw = m.group(1).decode("ascii", errors="ignore").strip()
        sw = m.group(2).decode("ascii", errors="ignore").strip()

        hardware_number = hw if hw and not re.match(r"^0+$", hw) else None
        software_version = sw if sw and not re.match(r"^0+$", sw) else None

        return hardware_number, software_version
