"""
Bosch ME9 ECU binary extractor.

Covers: Bosch Motronic ME9 — 2 MB full flash dumps.

Used in: VW / Audi 1.8T 20v gasoline engines (engine codes AGU, AEB, APU, ARZ,
AWT, AWM and similar early-2000s VAG turbocharged petrol applications).

---------------------------------------------------------------------------
Binary structure (confirmed on 0261209352_1037383785):
---------------------------------------------------------------------------

  Offset 0x0000–0x3FFF  OS kernel / RAM-loader code
    0x0001594C          "Bosch.Common.RamLoader.Me9.0001"   ← detection anchor
  Offset 0x2600         HW part-number record
    0x00002600          "0261209352"  — Bosch ECU hardware part number
  Offset 0x4000–0x4FFF  Calibration ident block
    0x0000461D          \x22 "1037393302" \x01\x01 "//1037383785"
                                               └── calibration SW  (tune, primary)
                          └── OS/program SW  (secondary)
  Offset 0x2800–0x28FF  Calibration slot descriptors
    0x00002840          "@CV56047 …"  — calibration version tag
  Offset 0x8038A        "1037501230"  — bootloader SW (between \\xff bytes)
  Offset 0x80000–       Calibration data (map tables, fill patterns)

---------------------------------------------------------------------------
Ident record format (at ~0x461D):
---------------------------------------------------------------------------

  Byte   Content
  ─────  ────────────────────────────────────────────────────────────────
  0x22   ASCII " — record-start sentinel (Bosch internal convention)
  [10]   ASCII digits — OS/program SW, always "1037XXXXXX"
  0x01   separator byte 1
  0x01   separator byte 2
  0x2F   ASCII /
  0x2F   ASCII /
  [10]   ASCII digits — calibration SW, always "1037XXXXXX"
  …      additional fields (HW ref, calibration tag) follow after binary gaps

---------------------------------------------------------------------------
Fields extracted:
---------------------------------------------------------------------------

  ecu_family          "ME9"           fixed
  ecu_variant         None            no sub-variant ASCII string in binary
  software_version    "1037383785"    calibration SW (after "//"); PRIMARY KEY
  calibration_id      "1037393302"    OS/program SW (after 0x22 sentinel)
  hardware_number     "0261209352"    Bosch ECU unit part number
  calibration_version "CV56047"       calibration version tag from slot header
  match_key           "ME9::1037383785"
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    DETECTION_SIGNATURE,
    EXCLUSION_CLEAR,
)

# ---------------------------------------------------------------------------
# Detection constants
# ---------------------------------------------------------------------------

# Primary detection anchor — unique to ME9.  Both pure ME9 and MED9 share
# this RAM-loader string, so we additionally gate on the absence of b"MED9".
_ME9_ANCHOR: bytes = b"Bosch.Common.RamLoader.Me9"

# MED9 bins (MED9510, MED91, …) also carry the RamLoader string.
# Reject any binary that contains the MED9 family marker — those are handled
# by BoschExtractor which identifies them as MED9.
_MED9_MARKER: bytes = b"MED9"

# ---------------------------------------------------------------------------
# Extraction patterns
#
# All patterns use exactly one capturing group — group(1) is the value.
# ---------------------------------------------------------------------------

# ECU variant — extracted from the RAM-loader identity string.
# The RamLoader string "Bosch.Common.RamLoader.Me9.0001" contains the variant
# token "Me9.0001" after the last dot-separated "RamLoader." prefix.
# group(1) = b"Me9.0001"  (upper-cased to "ME9.0001" in the resolver)
_PAT_VARIANT: bytes = rb"RamLoader\.(Me9[\w.]+)"

# Calibration SW — follows the "//" field separator in the ME9 ident record.
# Example:  b"//1037383785"  →  group(1) = b"1037383785"
# This is the PRIMARY matching key (identifies the specific tune revision).
_PAT_CAL_SW: bytes = rb"//(1037[0-9]{6,10})"

# OS / program SW — follows the 0x22 (ASCII '"') sentinel in the ident record.
# Example:  b'"1037393302'  →  group(1) = b"1037393302"
_PAT_OS_SW: bytes = rb"\x22(1037[0-9]{6,10})"

# Fallback SW — any isolated 1037-prefixed numeric string.
# Used when the ident record is not cleanly present (partial / corrupted dump).
_PAT_SW_FALLBACK: bytes = rb"(?<![0-9])(1037[0-9]{6,10})(?![0-9])"

# Bosch ECU hardware part number — always "0261XXXXXX" (10 decimal digits).
# In ME9 binaries the HW number is always embedded inside compound records
# with no clean left boundary (e.g. "402612093521039S…" or "c330261209352\x08"),
# so a lookbehind on the left would reject every real occurrence.
# A lookahead on the right is sufficient: the HW digits are always followed
# by a non-digit byte (control char, null, or letter).
_PAT_HW: bytes = rb"(0261[0-9]{6})(?![0-9])"

# Calibration version tag — "CV" followed by 4–8 decimal digits.
# Slot-header entries at 0x2800 use the format "@CVxxxxx\x20…".
# Example:  b"@CV56047 "  →  group(1) = b"56047"
# Zero-filled empty slots ("CV00000") are rejected in the resolver below.
_PAT_CAL_VER: bytes = rb"CV([1-9][0-9]{3,7})"

# ---------------------------------------------------------------------------
# Search regions
# ---------------------------------------------------------------------------

# The OS/program SW, calibration SW, HW number, and calibration version all
# live within the first 640 KB of the binary.  Scanning beyond this region
# would only pick up the bootloader SW at 0x8038A which is not needed for
# identification.
_REGION_IDENT: slice = slice(0x0000, 0xA0000)  # 640 KB

# HW number and calibration slot headers appear in the first 32 KB.
# Narrowing this region avoids spurious 0261-matches in calibration tables.
_REGION_HW: slice = slice(0x0000, 0x8000)  # 32 KB

# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


class BoschME9Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic ME9 ECU full flash dumps.

    Handles: ME9.0, ME9.1 — 2 MB full flash images.
    Used in: VW / Audi 1.8T 20v (AGU, AEB, APU, ARZ, AWT, AWM …).

    Detection is anchored on the unique RAM-loader string
    "Bosch.Common.RamLoader.Me9" which is present in every ME9 binary and
    in no other Bosch ECU family (with the exception of MED9 derivatives,
    which are explicitly excluded by checking for the b"MED9" marker).
    """

    detection_strength = DetectionStrength.WEAK

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["ME9"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch ME9 ECU full flash dump.

        Two-phase check:
          1. Reject immediately if b"MED9" is present — MED9 bins (MED9510,
             MED91, …) share the RAM-loader string but are owned by
             BoschExtractor.
          2. Accept if the ME9 RAM-loader anchor is found in the first 2 MB.
        """
        evidence: list[str] = []

        # Phase 1 — exclusion: reject if MED9 marker is present
        if _MED9_MARKER in data:
            self._set_evidence()
            return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 2 — accept on ME9 RAM-loader anchor
        if _ME9_ANCHOR in data[:0x200000]:
            evidence.append(DETECTION_SIGNATURE)
            self._set_evidence(evidence)
            return True

        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch ME9 flash dump.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from the ident region (display only) ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=_REGION_HW,
            min_length=8,
            max_results=20,
        )

        # --- Step 2: ECU family and variant ---
        # The variant is extracted from the RAM-loader identity string:
        #   "Bosch.Common.RamLoader.Me9.0001"  →  ecu_variant = "ME9.0001"
        # It is upper-cased for display consistency.  The match key is keyed
        # on the family ("ME9") rather than the variant so it stays stable
        # across different loader revisions of the same hardware platform.
        result["ecu_family"] = "ME9"
        variant_raw = self._find_group1(data, _PAT_VARIANT, slice(0, 0x200000))
        result["ecu_variant"] = variant_raw.upper() if variant_raw else None

        # --- Step 3: Software versions from the ident record ---
        #
        # The ME9 ident record at ~0x461D stores two 1037-prefixed SW numbers:
        #   '"1037393302\x01\x01//1037383785'
        #     ^^^^^^^^^^              ^^^^^^^^^^ calibration (tune) SW — PRIMARY
        #     OS/program SW — stored as calibration_id
        #
        # If the ident record is not cleanly present (corrupted / partial dump),
        # fall back to any isolated 1037-prefixed string in the ident region.
        cal_sw: Optional[str] = self._find_group1(data, _PAT_CAL_SW, _REGION_IDENT)
        os_sw: Optional[str] = self._find_group1(data, _PAT_OS_SW, _REGION_IDENT)

        if cal_sw is None:
            # Fallback: pick the first isolated 1037 string that is not the OS SW.
            for m in re.finditer(_PAT_SW_FALLBACK, data[_REGION_IDENT]):
                candidate = m.group(1).decode("ascii", errors="ignore").strip()
                if candidate and candidate != os_sw:
                    cal_sw = candidate
                    break

        result["software_version"] = cal_sw
        result["calibration_id"] = os_sw

        # --- Step 4: Hardware number ---
        result["hardware_number"] = self._find_group1(data, _PAT_HW, _REGION_HW)

        # --- Step 5: Calibration version ---
        cal_ver_digits = self._find_group1(data, _PAT_CAL_VER, _REGION_IDENT)
        result["calibration_version"] = (
            f"CV{cal_ver_digits}" if cal_ver_digits else None
        )

        # --- Step 6: Fields not present in ME9 binaries ---
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["oem_part_number"] = None

        # --- Step 7: Build compound match key ---
        # The match key is intentionally keyed on ecu_family ("ME9"), not
        # ecu_variant ("ME9.0001"), so that the same calibration SW produces
        # an identical match key regardless of which loader revision is present.
        # → "ME9::1037383785"
        result["match_key"] = self.build_match_key(
            ecu_family="ME9",
            ecu_variant=None,
            software_version=cal_sw,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _find_group1(
        self,
        data: bytes,
        pattern: bytes,
        region: slice,
    ) -> Optional[str]:
        """
        Search `region` of `data` for `pattern` and return capturing group 1
        decoded as ASCII, or None if no match.

        Group 0 is the full match (including any sentinel prefix); group 1 is
        the value proper.  All patterns in this extractor are written with
        exactly one capturing group.
        """
        m = re.search(pattern, data[region])
        if m:
            try:
                value = m.group(1).decode("ascii", errors="ignore").strip()
                return value if value else None
            except (IndexError, AttributeError):
                pass
        return None
