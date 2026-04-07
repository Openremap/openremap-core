"""
Bosch EDC16 ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch EDC16 family:
  EDC16C8   — VW/Audi/Seat/Skoda 1.9 TDI, Alfa 147/156/GT 1.9 JTDM (2003–2006)
  EDC16C9   — Opel/GM Vectra-C, Signum, Astra-H diesel (2004–2006)
              e.g. Opel Vectra CDTI 120PS (0281013409, sw=1037A50286)
  EDC16C31/C35 — BMW diesel engines (E46/E60/E87/E90 320d/520d/120d, X6 30sd) (2004–2009)
              e.g. BMW 120D 163HP 0281012754, BMW 520D 150HP 0281013251
              active_start = 0x40000 (2MB) or 0x30000 (983040-byte truncated read)
              family string lives near 0xC0000 mirror section (~0x0C06F3), not at end
  EDC16C39  — Alfa 159 2.4 JTDM, Alfa GT 1.9 JTD 150HP (2005–2008)
  EDC16 VAG PD — Audi A3/A4 1.9 TDI BKC/BKE, 2.0 TDI BKD (03G906016xx, 2004–2008)
  EDC16 half-flash dump — 512KB partial read, VAG PD (e.g. 03G906021LL Seat Leon 2.0 TDI)
  EDC16 sector dump — 256KB active-section-only read of any of the above

EDC16 sits between EDC15 and EDC17. Key differences from both:
  - No TSW string (EDC15 era toolchain marker — absent here)
  - No SB_V, NR000, Customer. strings (EDC17+ only)
  - No 0xC3 fill — erased flash is 0xFF
  - SW version stored as plain ASCII "1037xxxxxx" (always exactly 10 characters)
    at active_start + 0x10 — invariant across ALL known EDC16 layouts;
    suffix is normally all-digits but may contain uppercase hex A–F in
    Opel EDC16C9 bins (e.g. "1037A50286")
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

  EDC16C9  (1MB = 0x100000 bytes), Opel/GM common-rail (Vectra-C/Signum/Astra-H):
    active_start       : 0xc0000
    \xde\xca\xfe magic : 0xc003d  (active_start + 0x3d)
    SW version         : ASCII "1037xxxxxx" at 0xc0010; suffix may contain A–F
                         e.g. "1037A50286" (Opel EDC16C9-specific alphanumeric SW)
    ECU family string  : "EDC16C9/..." when present in calibration area
    Three DECAFE copies: 0x003d / 0x8003d / 0xc003d
    Discriminator vs C8: third copy at 0xc003d (not 0xe003d) is the Opel discriminator

  EDC16 sector dump (256KB = 0x40000 bytes):
    A standalone active-section-only read. The file begins directly with
    the active section header — no prefix, no padding. Observed for the
    same VAG PD part numbers (03G906016xx) when only the calibration
    sector was read from flash.
    active_start       : 0x0000  (entire file IS the active section)
    \xde\xca\xfe magic : 0x003d
    SW version         : plain ASCII "1037xxxxxx" at 0x0010

SW version extraction rule (invariant):
  Read active_start + 0x10, match rb"1037[\\dA-Fa-f]{6}" (10 characters total).
  Digits and uppercase hex A–F are both accepted to cover Opel EDC16C9 bins
  that use alphanumeric SW versions (e.g. "1037A50286"). Matching exactly 6
  suffix characters prevents returning spurious extended values when printable
  bytes immediately follow the SW number (e.g. "1037370634379" → "1037370634").

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
  Seat Leon 2.0TDI 140HP 03G906021LL  512KB   -> EDC16 PD  sw=1037381350
  0281013409_1037A50286_Vectra_CDTI_120PS.bin  -> EDC16C9   sw=1037A50286
  BMW 120D 163HP 0281012754 379332    2MB      -> EDC16C31  sw=1037379332
  BMW 520D 150HP 0281013251 379332    983040B  -> EDC16C31  sw=1037379332
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    EXCLUSION_CLEAR,
    FAMILY_STRING,
    LAYOUT_FINGERPRINT,
    MAGIC_MATCH,
    SIZE_MATCH,
)
from openremap.core.manufacturers.bosch.edc16.patterns import (
    ACTIVE_STARTS_BY_SIZE,
    DETECTION_SIGNATURES,
    EDC16_HEADER_MAGIC,
    EXCLUSION_SIGNATURES,
    MAGIC_OFFSETS_BY_SIZE,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SIZE_TOLERANCE,
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
      EDC16C9   (1MB, active at 0xc0000) — Opel Vectra-C/Signum/Astra-H
      EDC16C31/C35 (2MB, active at 0x40000) — BMW E46/E60/E87/E90 320d/520d/120d
      EDC16C31/C35 (2MB, active at 0xc0000) — BMW X6 30sd
      EDC16C31/C35 (983040B, active at 0x30000) — BMW truncated read
      EDC16C39  (2MB, active at 0x1c0000)
      EDC16 VAG PD (1MB, active at 0xd0000)
      EDC16 half-flash dump (512KB, active at 0x0) — VAG PD extended read
      EDC16 sector dump (256KB, active at 0x0)

    SW version is read from active_start + 0x10 — the active section is
    detected first via the \xde\xca\xfe magic at active_start + 0x3d.
    HW number may be present as plain ASCII in some variants (Opel EDC16C9,
    some VAG PD and BMW C31/C35 bins). Searched in multiple regions with
    boundary-safe patterns.
    """

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    detection_strength = DetectionStrength.STRONG

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return [
            "EDC16C8",
            "EDC16C9",
            "EDC16C31",
            "EDC16C34",
            "EDC16C35",
            "EDC16C36",
            "EDC16CP33",
            "EDC16CP34",
            "EDC16CP35",
            "EDC16C39",
            "EDC16U31",
            "EDC16U1",
            "EDC16",
        ]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch EDC16 family ECU.

        Four-phase check:
          1. Reject immediately if any exclusion signature is found anywhere
             in the binary — prevents claiming EDC17/MEDC17/ME7/EDC15 bins.
             The full binary is searched (not just the first 512KB) because
             some families (e.g. ME7.1.1 in 1MB bins) store their identity
             strings entirely in the upper half of the file.
          2. Reject if the file size is not one of the known EDC16 sizes
             (256KB, 1MB, or 2MB) — UNLESS the file is a raw active-section
             dump at offset 0 (DECAFE present at 0x3D with valid SW at 0x10).
             Some extended or concatenated dumps (e.g. Peugeot partner
             1037383736, 632KB) are genuine EDC16 sector dumps whose total
             size falls outside the standard set due to extra appended data.
          3. Accept if the \xde\xca\xfe header magic is present at ANY of the
             known magic offsets for this file size. Falls back to accepting
             on the b"EDC16" family string if no magic offset is reachable.
          4. Accept raw active-section dumps of non-standard size: DECAFE at
             0x3D (active_start = 0) and a valid SW string at 0x10.

        The active-section layout (C8 vs PD for 1MB bins) is resolved later
        in _detect_active_start() during extraction — detection only needs
        to confirm the file is EDC16, not which sub-variant it is.
        """
        evidence: list[str] = []

        # Search the full binary for exclusion signatures.  Earlier versions
        # searched only data[:0x80000] (first 512KB), but ME7.1.1 bins
        # (e.g. VW Golf 5 R32 3.2 VR6, 1MB) store all identity strings
        # (ME7., MOTRONIC) in the upper half (0xE0000+).  The narrow window
        # missed them, letting Phase 4's flash-layout heuristic falsely
        # accept the file as scrambled EDC16C8.
        search_area = data

        # Phase 1 — reject on any exclusion signature
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 2 — reject unknown file sizes, with two exceptions:
        #   a) Raw active-section dump at offset 0 (DECAFE at 0x3D).
        #   b) Trailing-byte tolerance — read tools may append CR+LF, padding,
        #      or tool-specific checksums at the end of a dump.  If the file
        #      is at most SIZE_TOLERANCE bytes larger than a known supported
        #      size, treat it as that size for detection and layout purposes.
        if len(data) not in SUPPORTED_SIZES:
            snapped = self._snap_size(len(data))
            _raw_sector = len(data) >= 0x40 and data[0x3D:0x40] == EDC16_HEADER_MAGIC
            if snapped is None and not _raw_sector:
                self._set_evidence()
                return False
        evidence.append(SIZE_MATCH)

        # Phase 3a — accept on \xde\xca\xfe magic at any known offset.
        # Use the snapped size for the lookup so that files with trailing
        # bytes (e.g. 2MB + 2 CR/LF bytes) still resolve to the correct
        # set of magic offsets.
        lookup_size = self._snap_size(len(data)) or len(data)
        for offset in MAGIC_OFFSETS_BY_SIZE.get(lookup_size, []):
            end = offset + len(EDC16_HEADER_MAGIC)
            if len(data) >= end and data[offset:end] == EDC16_HEADER_MAGIC:
                evidence.append(MAGIC_MATCH)
                self._set_evidence(evidence)
                return True

        # Phase 3b — fallback: accept on EDC16 family string
        if any(sig in data for sig in DETECTION_SIGNATURES):
            evidence.append(FAMILY_STRING)
            self._set_evidence(evidence)
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
        #
        # Defence-in-depth: even though Phase 1 now searches the full binary
        # for exclusion signatures (which would already reject ME7 bins),
        # we explicitly guard against ME7 here as a safety net.  ME7.1.1
        # bins (e.g. VW Golf 5 R32 3.2 VR6) share an identical flash
        # layout (code at bottom, erased gap, cal+ident at top) and would
        # otherwise pass the fill-ratio thresholds.
        if len(data) == 0x100000:
            boot = data[0x000000:0x040000]
            erased = data[0x040000:0x0E0000]
            cal = data[0x0E0000:0x100000]
            boot_ff = boot.count(0xFF) / len(boot)
            erased_ff = erased.count(0xFF) / len(erased)
            cal_ff = cal.count(0xFF) / len(cal)
            if boot_ff < 0.60 and erased_ff >= 0.95 and cal_ff < 0.60:
                # Guard: reject if ME7 family strings are present anywhere
                # in the binary.  ME7.1.1 1MB bins have an identical sector
                # layout but are not EDC16.
                _me7_sigs = [b"ME7.", b"ME 7.", b"ME71", b"ME731", b"MOTRONIC"]
                if any(sig in data for sig in _me7_sigs):
                    self._set_evidence()
                    return False
                evidence.append(LAYOUT_FINGERPRINT)
                self._set_evidence(evidence)
                return True

        self._set_evidence()
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
        ecu_variant = self._resolve_ecu_variant(data, active_start)
        result["ecu_family"] = "EDC16"
        result["ecu_variant"] = ecu_variant

        # --- Step 4: Resolve SW version from detected active section ---
        software_version = self._resolve_software_version(data, active_start)
        result["software_version"] = software_version

        # --- Step 5: HW number — search multiple regions (active header,
        #     cal area, mirror offsets) for Bosch HW part numbers.
        result["hardware_number"] = self._resolve_hardware_number(data, active_start)

        # --- Step 6: Fields not present in EDC16 binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["calibration_id"] = None
        result["oem_part_number"] = self._resolve_oem_part_number(data)

        # --- Step 7: Build match key ---
        result["match_key"] = self.build_match_key(
            ecu_family="EDC16",
            ecu_variant=ecu_variant,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — size snapping
    # -----------------------------------------------------------------------

    @staticmethod
    def _snap_size(raw_size: int) -> Optional[int]:
        """
        Map a raw file size to the nearest supported EDC16 size.

        Returns the matching entry from SUPPORTED_SIZES if ``raw_size``
        is at most SIZE_TOLERANCE bytes larger than a known size.  Only
        positive excess is accepted (the binary may have trailing padding
        or CR+LF but never fewer bytes than expected).

        Returns None if no supported size is within tolerance.
        """
        if raw_size in SUPPORTED_SIZES:
            return raw_size
        for supported in sorted(SUPPORTED_SIZES):
            excess = raw_size - supported
            if 0 < excess <= SIZE_TOLERANCE:
                return supported
        return None

    # -----------------------------------------------------------------------
    # Internal — active section detector
    # -----------------------------------------------------------------------

    def _detect_active_start(self, data: bytes) -> Optional[int]:
        """
        Detect the active section start offset for this binary.

        For each candidate active_start in ACTIVE_STARTS_BY_SIZE[file_size],
        confirms two conditions:
          1. \xde\xca\xfe is present at active_start + 0x3d
          2. A valid SW string is readable at active_start + 0x10.
             Accepted prefixes: "1037" (standard Bosch) and "1039" (PSA/Peugeot
             EDC16C34, e.g. Peugeot 3008 1.6 HDI).

        Returns the first candidate that satisfies both, or None if no
        candidate matches (e.g. XOR-encoded / erased cal area).

        For non-standard file sizes (e.g. extended or concatenated dumps that
        passed the raw-sector exception in can_handle), falls back to trying
        active_start = 0x0, which corresponds to DECAFE at 0x3D — the layout
        used by 256KB sector-only dumps and extended variants thereof.

        This is called before _resolve_software_version so that the SW
        resolver receives a confirmed offset rather than guessing.
        """
        size = len(data)
        snapped = self._snap_size(size)
        # Use snapped size for dict lookup — trailing bytes do not affect
        # the internal flash layout.  For genuinely non-standard sizes
        # fall back to active_start = 0x0 (raw sector dump).
        candidates = ACTIVE_STARTS_BY_SIZE.get(snapped or size, [0x0])

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

    def _resolve_ecu_variant(
        self, data: bytes, active_start: Optional[int] = None
    ) -> Optional[str]:
        """
        Resolve the ECU variant string (e.g. "EDC16C8", "EDC16C39", "EDC16U31").

        Priority:
          1. Parse the first token from the slash-delimited family descriptor:
             "EDC16C8/009/C277/ /..." → "EDC16C8"
             This string lives in the calibration area of the active section
             and is the most authoritative source.
          2. Fall back to the bare EDC16 family token regex — matches
             "EDC16C8", "EDC16C39", "EDC16U31" etc. without slash context.
          2b. Search the active region extended window (active_start to
             active_start+0x100000). This catches BMW EDC16C31/C35 2MB bins
             where the family string lives near the 0xC0000 mirror section
             (~0x0C06F3), which is outside the last-256KB cal_area window.
          3. Full-file bare-token scan — last resort so nothing returns None
             when the string is somewhere unexpected.

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

        # Priority 2b — search around active_start (covers BMW C31/C35 2MB where the
        # family string lives near the 0xC0000 mirror section, not at file end).
        # We search from active_start to active_start+0x100000 (1MB window) which
        # is wide enough to reach the 0xC06F3 region for active_start=0x40000.
        if active_start is not None:
            region_end = min(len(data), active_start + 0x100000)
            active_region = data[active_start:region_end]
            m = re.search(PATTERNS["ecu_family_string"], active_region)
            if m:
                full = m.group(0).decode("ascii", errors="ignore")
                return full.split("/")[0].strip()
            m = re.search(PATTERNS["ecu_family"], active_region)
            if m:
                return m.group(0).decode("ascii", errors="ignore").strip()

        # Priority 3 — full-file bare token scan (last resort)
        m = re.search(PATTERNS["ecu_family"], data)
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

        The SW regex matches exactly 10 characters ("1037" + 6 alphanumeric
        hex chars). Digits and uppercase A–F are both accepted to accommodate
        Opel EDC16C9 bins that use alphanumeric SW versions (e.g. "1037A50286").
        Matching exactly 6 suffix characters prevents returning spurious extended
        values when printable ASCII bytes immediately follow the SW number in
        VAG PD bin headers (e.g. "1037370634379U85" → we return "1037370634").
        """
        size = len(data)
        snapped = self._snap_size(size)
        lookup_size = snapped or size

        # Priority 1 — active_start + 0x10
        if active_start is not None:
            sw_off = active_start + 0x10
            hit = self._read_sw_at(data, sw_off)
            if hit:
                return hit

        # Priority 2 — legacy fixed offsets (primary + mirror)
        primary_offset = SW_OFFSET_BY_SIZE.get(lookup_size)
        mirror_offset = SW_MIRROR_OFFSET_BY_SIZE.get(lookup_size)

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

    # -----------------------------------------------------------------------
    # Internal — HW number resolver
    # -----------------------------------------------------------------------

    def _resolve_hardware_number(
        self, data: bytes, active_start: Optional[int] = None
    ) -> Optional[str]:
        """
        Attempt to recover the Bosch hardware part number (e.g. "0281013409").

        Many EDC16 variants embed the 10-digit HW number as plain ASCII in
        one or more regions of the binary:
          - Opel EDC16C9 (Vectra-C, Signum, Astra-H) in the cal area
          - BMW EDC16C31/C35 in the active header or extended active window
          - Some VAG PD bins in mirror regions

        Strategy — search multiple regions in priority order:
          1. Active header window (active_start .. active_start + 0x800)
          2. Calibration area (last 256 KB)
          3. Active extended window (active_start .. active_start + 0x100000)
             for large (2 MB) BMW bins
          4. Boot sector (0x0000 .. active_start) — catches BMW EDC16C31/C35
             bins where the HW number lives in the boot area (e.g. at 0xBE27
             for 2MB or 0x65E7 for 1MB)
          5. Full binary — last resort fallback

        Within each region, try patterns in priority order:
          a. Standard Bosch diesel HW: 0281 + 6 digits
          b. Bosch petrol HW: 0261 + 6 digits
          c. Broader Bosch HW with optional spaces/dots: 0.281.xxx.xxx

        Accept the first match where surrounding bytes are non-digit.
        Normalize by removing spaces and dots. Reject all-zero values.

        Returns:
            10-character HW number string (e.g. "0281013409"), or None.
        """
        size = len(data)

        # -- Build search regions in priority order --------------------------
        regions: list[bytes] = []

        # 1. Active header window
        if active_start is not None:
            end = min(active_start + 0x800, size)
            if active_start < size:
                regions.append(data[active_start:end])

        # 2. Cal area (last 256 KB)
        regions.append(data[SEARCH_REGIONS["cal_area"]])

        # 3. Active extended window (for 2 MB BMW bins)
        if active_start is not None and size >= 0x200000:
            end = min(active_start + 0x100000, size)
            if active_start < size:
                regions.append(data[active_start:end])

        # 4. Boot sector (before active_start) — BMW EDC16C31/C35 bins store
        #    the HW number in the boot area at offsets like 0xBE27 (2MB) or
        #    0x65E7 (1MB), well beyond the narrow mirror windows.
        if active_start is not None and active_start > 0:
            regions.append(data[0x0000:active_start])

        # 5. Full binary — last resort; the 0281/0261 patterns are specific
        #    enough (10-digit Bosch part number bounded by non-digits) that
        #    false positives across the full file are extremely unlikely.
        regions.append(data)

        # -- Patterns in priority order --------------------------------------
        patterns = [
            rb"(?<!\d)(0281\d{6})(?!\d)",  # standard Bosch diesel
            rb"(?<!\d)(0261\d{6})(?!\d)",  # Bosch petrol
            rb"(?<!\d)(0[\s\.]?281[\s\.]?\d{3}[\s\.]?\d{3})(?!\d)",  # spaced
        ]

        for region in regions:
            for pat in patterns:
                m = re.search(pat, region)
                if m:
                    raw = m.group(1).decode("ascii", errors="ignore")
                    val = raw.replace(" ", "").replace(".", "").strip()
                    if val and not re.match(r"^0+$", val):
                        return val

        return None

    # -----------------------------------------------------------------------
    # Internal — OEM part number resolver
    # -----------------------------------------------------------------------

    def _resolve_oem_part_number(self, data: bytes) -> Optional[str]:
        """
        Attempt to extract an OEM (vehicle-manufacturer) part number.

        Searches the full binary for common OEM part number formats:
          - VAG: e.g. "03G906016J", "03L 906 018 AJ"
          - BMW: e.g. "12 14 7 626 350"

        Returns:
            Normalized OEM part number string, or None.
        """
        # VAG pattern: 0[2-9]X NNN NNN [XX]  (with optional spaces)
        m = re.search(
            rb"(?<![A-Z0-9])0[2-9][A-Z][\s]?\d{3}[\s]?\d{3}(?:[\s]?[A-Z]{1,2})?(?![A-Z0-9])",
            data,
        )
        if m:
            val = m.group(0).decode("ascii", errors="ignore")
            return val.replace(" ", "").strip()

        # BMW pattern: NN NN N NNN NNN
        m = re.search(
            rb"(?<!\d)\d{2}[\s]\d{2}[\s]\d{1}[\s]\d{3}[\s]\d{3}(?!\d)",
            data,
        )
        if m:
            val = m.group(0).decode("ascii", errors="ignore")
            return val.replace(" ", "").strip()

        return None

    def _read_sw_at(self, data: bytes, offset: int) -> Optional[str]:
        """
        Attempt to read a SW version string (exactly 10 characters) from
        a fixed offset.

        Reads SW_WINDOW bytes starting at the given offset and searches for
        the SW pattern within that window. Always uses the strict 10-character
        pattern to avoid matching the printable suffix bytes that follow the SW
        number in some VAG PD bin headers.

        Accepted SW prefixes:
          "1037" — standard Bosch (VW/Audi/BMW/Alfa and most others)
          "1039" — PSA/Peugeot-Citroën EDC16C34 variant
                   (e.g. Peugeot 3008 1.6 HDI: SW "1039398238")

        Hex digits A–F are allowed in the 6-char suffix to cover Opel EDC16C9
        alphanumeric SW versions (e.g. "1037A50286").

        Returns the 10-character SW version string, or None if:
          - The offset is out of range
          - No match is found
          - The match is all zeros
        """
        start = max(0, offset - 2)
        end = min(len(data), offset + SW_WINDOW)
        if start >= len(data):
            return None

        window = data[start:end]

        # Match exactly 6 alphanumeric hex chars after the 4-char prefix.
        # Accepted prefixes: "1037" (standard Bosch) and "1039" (PSA EDC16C34).
        # Using exactly 6 suffix chars prevents spurious extended matches when
        # printable ASCII follows immediately (e.g. VAG PD header "1037370634379").
        m = re.search(rb"103[79][\dA-Fa-f]{6}", window)
        if not m:
            return None

        val = m.group(0).decode("ascii", errors="ignore").strip()
        if not val or re.match(r"^0+$", val):
            return None

        return val
