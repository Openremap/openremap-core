"""
Bosch EDC16 ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch EDC16 family:
  EDC16C8   — VW/Audi/Seat/Skoda 1.9 TDI, Alfa 147/156/GT 1.9 JTDM (2003–2006)
  EDC16C39  — Alfa 159 2.4 JTDM, Alfa GT 1.9 JTD 150HP (2005–2008)
  EDC16 VAG PD — Audi A3/A4 1.9 TDI BKC/BKE, 2.0 TDI BKD (03G906016xx, 2004–2008)
  EDC16 sector dump — 256KB active-section-only read of any of the above

EDC16 sits between EDC15 and EDC17. Key differences from both:
  - No TSW string (EDC15 era toolchain marker — absent here)
  - No SB_V, NR000, Customer. strings (EDC17+ only)
  - No 0xC3 fill — erased flash is 0xFF
  - SW version stored as plain ASCII "1037xxxxxx" (always exactly 10 digits)
    at active_start + 0x10 — invariant across ALL known EDC16 layouts
  - HW number is NOT stored as plain ASCII anywhere in the binary
  - ECU family identified via slash-delimited string when present:
    "EDC16C8/009/C277/..." — absent in VAG PD variants
  - Unique detection anchor: \xde\xca\xfe at active_start + 0x3d

Binary structure by variant:

  EDC16C8  (1MB = 0x100000 bytes), common-rail (Alfa/VW):
    active_start       : 0x40000
    \xde\xca\xfe magic : 0x4003d  (also mirrored at 0xe003d)
    SW version         : plain ASCII "1037xxxxxx" at 0x40010  (mirror 0xe0010)
    ECU family string  : "EDC16C8/..." at ~0xe054b
    Three DECAFE copies: 0x003d / 0x8003d / 0xe003d

  EDC16C39 (2MB = 0x200000 bytes), common-rail (Alfa/VW):
    active_start       : 0x1c0000
    \xde\xca\xfe magic : 0x1c003d
    SW version         : plain ASCII "1037xxxxxx" at 0x1c0010
    ECU family string  : "EDC16C39/..." at 0x1c0601
    Three DECAFE copies: 0x003d / 0x8003d / 0x1c003d (approx)

  EDC16 VAG PD (1MB = 0x100000 bytes), Pumpe-Düse (unit injector):
    active_start       : 0xd0000
    \xde\xca\xfe magic : 0xd003d
    SW version         : plain ASCII "1037xxxxxx" at 0xd0010  (mirror 0x0010 / 0x80010)
    ECU family string  : NOT present as plain ASCII
    Three DECAFE copies: 0x003d / 0x8003d / 0xd003d
    Discriminator vs C8: third copy at 0xd003d not 0xe003d

  EDC16 sector dump (256KB = 0x40000 bytes):
    A standalone active-section-only read. The file begins directly with
    the active section header — no prefix, no padding. Observed for the
    same VAG PD part numbers (03G906016xx) when only the calibration
    sector was read from flash.
    active_start       : 0x0000  (entire file IS the active section)
    \xde\xca\xfe magic : 0x003d
    SW version         : plain ASCII "1037xxxxxx" at 0x0010

SW version extraction rule (invariant):
  Read active_start + 0x10, match exactly rb"1037\\d{6}" (10 digits total).
  The bytes immediately following are printable ASCII in some PD bins
  (e.g. "P379U8") — using a 6-digit suffix match prevents returning a
  spurious 13-digit value like "1037370634379".

Active-start detection algorithm (_detect_active_start):
  For each candidate active_start in ACTIVE_STARTS_BY_SIZE[file_size]:
    1. Check magic is present at active_start + 0x3d
    2. Check SW is readable (10-digit 1037xxxxxx) at active_start + 0x10
  Return the first candidate that satisfies both conditions.
  This keeps detection deterministic and false-positive-safe.

Verified across all sample bins:
  Alfa 147 1.9JTDM 140HP 0281010455 367333   -> EDC16C8   sw=1037367333
  Alfa 156 1.9JTD  0281011425        370469   -> EDC16C8   sw=1037370469
  Alfa 156 2.4JTDM 0281010988        369430   -> EDC16C8   sw=1037369430
  Alfa 159 2.4JTDM 0281013417        383773   -> EDC16C39  sw=1037383773
  Alfa GT  1.9JTD  0281012298        377778   -> EDC16C39  sw=1037377778
  Alfa 156 1.9JTD  0281010986        367332   -> EDC16?    sw=None (XOR-encoded)
  A3 1.9TDI BKC 03G906016J  1037369261        -> EDC16 PD  sw=1037369261
  A3 2.0TDI BKD 03G906016FF 1037370634        -> EDC16 PD  sw=1037370634
  A3 2.0TDI BKD 03G906016G  1037369819        -> EDC16 PD  sw=1037369819
  A4 1.9TDI BKE 03G906016FE 1037372733 256KB  -> EDC16 PD  sw=1037372733
  A  2.0TDI     03G906016JE 1037372733 256KB  -> EDC16 PD  sw=1037372733
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor
from openremap.tuning.manufacturers.bosch.edc16.patterns import (
    ACTIVE_STARTS_BY_SIZE,
    DETECTION_SIGNATURES,
    EDC16_HEADER_MAGIC,
    EXCLUSION_SIGNATURES,
    MAGIC_OFFSETS_BY_SIZE,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SUPPORTED_SIZES,
    SW_MIRROR_OFFSET_BY_SIZE,
    SW_OFFSET_BY_SIZE,
    SW_WINDOW,
)


class BoschEDC16Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch EDC16 ECU binaries.

    Handles:
      EDC16C8   (1MB, active at 0x40000)
      EDC16C39  (2MB, active at 0x1c0000)
      EDC16 VAG PD (1MB, active at 0xd0000)
      EDC16 sector dump (256KB, active at 0x0)

    SW version is read from active_start + 0x10 — the active section is
    detected first via the \xde\xca\xfe magic at active_start + 0x3d.
    HW number is never stored as plain ASCII in EDC16 binaries — always None.
    """

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["EDC16C8", "EDC16C39", "EDC16U31", "EDC16U1", "EDC16"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch EDC16 family ECU.

        Three-phase check:
          1. Reject immediately if any exclusion signature is found in the
             first 512KB — prevents claiming EDC17/MEDC17/ME7/EDC15 bins.
          2. Reject if the file size is not one of the known EDC16 sizes
             (256KB, 1MB, or 2MB). All EDC16 bins are exactly one of these.
          3. Accept if the \xde\xca\xfe header magic is present at ANY of the
             known magic offsets for this file size. Falls back to accepting
             on the b"EDC16" family string if no magic offset is reachable.

        The active-section layout (C8 vs PD for 1MB bins) is resolved later
        in _detect_active_start() during extraction — detection only needs
        to confirm the file is EDC16, not which sub-variant it is.
        """
        search_area = data[:0x80000]

        # Phase 1 — reject on any exclusion signature
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                return False

        # Phase 2 — reject unknown file sizes
        if len(data) not in SUPPORTED_SIZES:
            return False

        # Phase 3a — accept on \xde\xca\xfe magic at any known offset
        for offset in MAGIC_OFFSETS_BY_SIZE.get(len(data), []):
            end = offset + len(EDC16_HEADER_MAGIC)
            if len(data) >= end and data[offset:end] == EDC16_HEADER_MAGIC:
                return True

        # Phase 3b — fallback: accept on EDC16 family string
        if any(sig in data for sig in DETECTION_SIGNATURES):
            return True

        # Phase 4 — encrypted / scrambled EDC16C8 layout fingerprint.
        #
        # Some 1MB EDC16C8 bins (observed: Alfa 156 1.9JTD 0281010986) have
        # their entire calibration header byte-scrambled: the \xde\xca\xfe
        # magic and the plain-text SW string are both unreadable.  Phase 3
        # therefore produces no match.  However the flash sector layout is
        # physically fixed and cannot be scrambled:
        #
        #   0x000000 – 0x03FFFF  (256KB) : boot / ROM code  — dense data,
        #                                  < 60% 0xFF fill
        #   0x040000 – 0x0DFFFF  (576KB) : erased sectors   — ≥ 95% 0xFF
        #   0x0E0000 – 0x0FFFFF  (128KB) : calibration data — < 60% 0xFF
        #
        # All three conditions together are specific enough to accept with
        # confidence.  No other known 1MB Bosch family produces this pattern.
        # SW version will be None (scrambled) — the file is still EDC16C8.
        if len(data) == 0x100000:
            boot = data[0x000000:0x040000]
            erased = data[0x040000:0x0E0000]
            cal = data[0x0E0000:0x100000]
            boot_ff = boot.count(0xFF) / len(boot)
            erased_ff = erased.count(0xFF) / len(erased)
            cal_ff = cal.count(0xFF) / len(cal)
            if boot_ff < 0.60 and erased_ff >= 0.95 and cal_ff < 0.60:
                return True

        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch EDC16 ECU binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Detect active section start ---
        active_start = self._detect_active_start(data)

        # --- Step 2: Raw ASCII strings from the calibration area ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["cal_area"],
            min_length=8,
            max_results=20,
        )

        # --- Step 3: Resolve ECU family and variant ---
        ecu_variant = self._resolve_ecu_variant(data)
        result["ecu_family"] = ecu_variant or "EDC16"
        result["ecu_variant"] = ecu_variant

        # --- Step 4: Resolve SW version from detected active section ---
        software_version = self._resolve_software_version(data, active_start)
        result["software_version"] = software_version

        # --- Step 5: HW number not stored as plain ASCII in EDC16 ---
        result["hardware_number"] = None

        # --- Step 6: Fields not present in EDC16 binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["calibration_id"] = None
        result["oem_part_number"] = None

        # --- Step 7: Build match key ---
        result["match_key"] = self.build_match_key(
            ecu_family="EDC16",
            ecu_variant=ecu_variant,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — active section detector
    # -----------------------------------------------------------------------

    def _detect_active_start(self, data: bytes) -> Optional[int]:
        """
        Detect the active section start offset for this binary.

        For each candidate active_start in ACTIVE_STARTS_BY_SIZE[file_size],
        confirms two conditions:
          1. \xde\xca\xfe is present at active_start + 0x3d
          2. A valid "1037xxxxxx" (exactly 10 digits) SW string is readable
             at active_start + 0x10

        Returns the first candidate that satisfies both, or None if no
        candidate matches (e.g. XOR-encoded / erased cal area).

        This is called before _resolve_software_version so that the SW
        resolver receives a confirmed offset rather than guessing.
        """
        size = len(data)
        candidates = ACTIVE_STARTS_BY_SIZE.get(size, [])

        for active_start in candidates:
            # Condition 1: magic present at active_start + 0x3d
            magic_off = active_start + 0x3D
            magic_end = magic_off + len(EDC16_HEADER_MAGIC)
            if magic_end > size:
                continue
            if data[magic_off:magic_end] != EDC16_HEADER_MAGIC:
                continue

            # Condition 2: valid 10-digit SW at active_start + 0x10
            sw_off = active_start + 0x10
            if self._read_sw_at(data, sw_off) is not None:
                return active_start

        return None

    # -----------------------------------------------------------------------
    # Internal — ECU variant resolver
    # -----------------------------------------------------------------------

    def _resolve_ecu_variant(self, data: bytes) -> Optional[str]:
        """
        Resolve the ECU variant string (e.g. "EDC16C8", "EDC16C39", "EDC16U31").

        Priority:
          1. Parse the first token from the slash-delimited family descriptor:
             "EDC16C8/009/C277/ /..." → "EDC16C8"
             This string lives in the calibration area of the active section
             and is the most authoritative source.
          2. Fall back to the bare EDC16 family token regex — matches
             "EDC16C8", "EDC16C39", "EDC16U31" etc. without slash context.

        Returns None if no EDC16 family string is found. This is expected for
        VAG PD bins and sector dumps where the family string is absent.
        """
        cal_area = data[SEARCH_REGIONS["cal_area"]]

        # Priority 1 — full slash-delimited descriptor
        m = re.search(PATTERNS["ecu_family_string"], cal_area)
        if m:
            full = m.group(0).decode("ascii", errors="ignore")
            return full.split("/")[0].strip()

        # Priority 2 — bare family token
        m = re.search(PATTERNS["ecu_family"], cal_area)
        if m:
            return m.group(0).decode("ascii", errors="ignore").strip()

        return None

    # -----------------------------------------------------------------------
    # Internal — SW version resolver
    # -----------------------------------------------------------------------

    def _resolve_software_version(
        self, data: bytes, active_start: Optional[int]
    ) -> Optional[str]:
        """
        Resolve the software version string (e.g. "1037367333").

        Strategy (in priority order):

          1. If active_start was detected, read SW at active_start + 0x10.
             This is always tried first — it is the authoritative location.

          2. If active_start is None (layout not detected), try the legacy
             fixed offsets from SW_OFFSET_BY_SIZE and SW_MIRROR_OFFSET_BY_SIZE.
             This covers edge cases where the magic is absent but the SW
             string is still present (e.g. partially erased bins).

          3. Fallback full cal-area scan. Last resort — accepts the first
             10-digit 1037xxxxxx hit anywhere in the last 256KB.

        The SW regex always matches exactly 10 digits ("1037" + 6 digits).
        This prevents the extractor from returning spurious 13-digit values
        that occur when printable ASCII bytes immediately follow the SW number
        in VAG PD bins (e.g. "1037370634379U85" → we return "1037370634").
        """
        size = len(data)

        # Priority 1 — active_start + 0x10
        if active_start is not None:
            sw_off = active_start + 0x10
            hit = self._read_sw_at(data, sw_off)
            if hit:
                return hit

        # Priority 2 — legacy fixed offsets (primary + mirror)
        primary_offset = SW_OFFSET_BY_SIZE.get(size)
        mirror_offset = SW_MIRROR_OFFSET_BY_SIZE.get(size)

        if primary_offset is not None:
            hit = self._read_sw_at(data, primary_offset)
            if hit:
                return hit

        if mirror_offset is not None:
            hit = self._read_sw_at(data, mirror_offset)
            if hit:
                return hit

        # Priority 3 — fallback cal-area scan
        cal_area = data[SEARCH_REGIONS["cal_area"]]
        m = re.search(PATTERNS["software_version"], cal_area)
        if m:
            val = m.group(0).decode("ascii", errors="ignore").strip()
            if val and not re.match(r"^0+$", val):
                return val

        return None

    def _read_sw_at(self, data: bytes, offset: int) -> Optional[str]:
        """
        Attempt to read a "1037xxxxxx" SW version (exactly 10 digits) from
        a fixed offset.

        Reads SW_WINDOW bytes starting at the given offset and searches for
        the SW pattern within that window. Always uses the strict 10-digit
        pattern (rb"1037\\d{6}") to avoid matching the printable suffix bytes
        that follow the SW number in some VAG PD bin headers.

        Returns the 10-digit SW version string, or None if:
          - The offset is out of range
          - No match is found
          - The match is all zeros
        """
        start = max(0, offset - 2)
        end = min(len(data), offset + SW_WINDOW)
        if start >= len(data):
            return None

        window = data[start:end]

        # Always use exactly 6 digits after "1037" — never more.
        # This prevents "103737063437" from being returned when the bytes
        # immediately following are printable ASCII in VAG PD bin headers.
        m = re.search(rb"1037\d{6}", window)
        if not m:
            return None

        val = m.group(0).decode("ascii", errors="ignore").strip()
        if not val or re.match(r"^0+$", val):
            return None

        return val
