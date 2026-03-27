r"""
Bosch Motronic M1.x ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Motronic M1.x family:
  M1.3  — BMW 3/5/7-series 4 and 6-cylinder petrol engines (~1987–1993)
  M1.7  — BMW 3/5/7-series 4 and 6-cylinder petrol engines (~1989–1996)
  M1.x  — Generic fallback for M1-era bins with no explicit sub-variant string

These are Motorola 68HC11-based ECUs, predating the M3.x generation.
They use the same reversed-digit ident encoding as M3.x but have a completely
different binary layout — the ident block is located near the 8KB mark in the
ROM (offset ~0x1E02–0x1F02) rather than at the end of the file.

Binary structure (all variants, 32KB = 0x8000 bytes):

  ROM header      : bytes 0x00–0x03 = \x85\x0a\xf0\x30 (Motorola HC11 reset vector area)
                    This 4-byte magic is unique to the M1.x family and is the
                    primary detection anchor. It is absent from all M3.x, ME7,
                    EDC17 and modern Bosch bins.

  Family marker   : ASCII string '"0000000M1.7 ' or '"0000000M1.3 '
                    Located in the upper half of the ROM (~0x7500–0x79xx).
                    Preceded by 7 non-printable opcode bytes (\xa3\xf0\xd0...).
                    Absent from some bins (generic M1.x fallback applies).

  Ident block     : Long ASCII numeric string at ~0x1E02–0x1F02
                    Format: \d{20,40}(?:\.\d{2})?
                    Always exactly ONE match per file — no false positives observed.
                    Encodes both HW and SW in reversed-digit order (see below).
                    Reliably found within slice(0x1800, 0x2100).

  RT code         : ASCII string e.g. '07826RT3557' or '81026RT2882'
                    Located ~0xC0 bytes after the ident block (~0x1EC0–0x1FC0).
                    Present in most but not all bins (BMW_179.bin has none).
                    Not used for identification — display only.

  No DME code     : Unlike M3.x, M1.x bins do NOT contain a 'NNN/NNN NNNN'
                    DME type string. calibration_id is derived from the RT code
                    when present, otherwise None.

HW / SW encoding — identical to M3.x:

    ident_clean = ident_num.split('.')[0]   # strip optional .NN decimal suffix
    hw          = ident_clean[0:10][::-1]   # first 10 digits reversed -> 0261xxxxxx
    sw          = ident_clean[10:20][::-1]  # next  10 digits reversed -> 1267xxxxxx

Detection — primary path (all originally-known bins):

    The 4-byte ROM header magic \x85\x0a\xf0\x30 at offset 0 is the primary
    and strongest positive anchor.  It is unique to M1.x and absent from every
    other known Bosch family.

Detection — fallback path (BMW M1.7 and Opel M1.x bins without the standard header magic):

    A subset of BMW M1.7 bins (observed: E36 318i 1.8i 0261200520, E36 318is
    0261203590 32KB, E36 316 0261203660 64KB) do NOT have the \x85\x0a\xf0\x30
    magic at offset 0 — their first bytes differ (e.g. \x00\x0a\xf0\x30,
    \x85\x99\x35\xd3, \x02\x00\x73\x02).  They are still unmistakably M1.x:

      - The '"0000000M1.7' family marker is present in the upper ROM region.
      - The file size is exactly 32KB or 64KB.
      - A valid reversed-digit ident (hw=0261xxxxxx, sw=1267xxxxxx) decodes
        correctly from the standard ident region (or, for the 64KB variant,
        from the last 4KB with a small FF-byte gap between the two digit runs).

    The BMW fallback (Phase 2b) fires when all three of the above conditions
    hold simultaneously.  Opel M1.x petrol ECUs (Phase 2c) use the identical
    reversed-digit ident encoding but carry no ROM header magic AND no BMW
    family marker; they are also accepted when the file is exactly 32KB or 64KB
    and the ident decodes to the 0261/1267 prefixes that uniquely identify
    Bosch M1.x petrol ECUs regardless of manufacturer.

64KB variant — split ident:

    The 64KB BMW E36 316 (0261203660) stores its ident in the last 4KB of the
    ROM, split across two contiguous digit runs separated by exactly 2–3 \xff
    bytes:

      run1: 27 ASCII digits   e.g. '066302162000785376215589371'
      gap:  2–3 \xff bytes
      run2:  3 ASCII digits   e.g. '571'
      suffix: optional '.NN'

    Concatenating run1+run2 before decoding yields the correct 30-digit ident:
      hw = concat[0:10][::-1] = '0261203660'
      sw = concat[10:20][::-1] = '1267358700'

    This gap-tolerant search is used ONLY when the standard contiguous pattern
    finds nothing, and ONLY for files that already passed the family-marker
    and size gates.

Verified across all known sample bins:
    318i_175_soft1267356378.bin         -> hw=0261200175  sw=1267356378  (M1.7, magic)
    318i_ecu990_soft070.bin             -> hw=0261200990  sw=1267357070  (M1.7, magic)
    STOCK282.BIN                        -> hw=0261203282  sw=1267357626  (M1.7, magic)
    BMW_179.bin                         -> hw=0261200179  sw=1267356334  (M1.3, magic)
    Bmw 850i ...0261200352...bin        -> hw=0261200352  sw=1267356566  (M1.3, magic)
    stock173.bin                        -> hw=0261200173  sw=1267355705  (M1.3, magic)
    153stock.bin                        -> hw=0261200153  sw=1267355408  (M1.x, magic)
    BMW_0261200153_1267355367.bin       -> hw=0261200153  sw=1267355367  (M1.x, magic)
    BMW_E32_750i_156.BIN                -> hw=0261200156  sw=1267356101  (M1.x, magic)
    BMW 318 E36 1.8i 0261200520 ...ori  -> hw=0261200520  sw=1267356585  (M1.7, fallback)
    Bmw E36 318is 0261203590 ...ori     -> hw=0261203590  sw=1267358597  (M1.7, fallback)
    BMW E36 316 0261203660 ...ori       -> hw=0261203660  sw=1267358700  (M1.7, fallback, gap)
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# The 4-byte ROM header magic is present at offset 0x00 in every M1.x bin
# and is absent from all other known families (M3.x, ME7, EDC17, MEDC17).
# Used by can_handle() as the primary positive detection anchor.
# ---------------------------------------------------------------------------

DETECTION_MAGIC: bytes = b"\x85\x0a\xf0\x30"

# ---------------------------------------------------------------------------
# Family sub-variant markers
# ---------------------------------------------------------------------------
# ASCII strings embedded in the ROM that identify the precise sub-variant.
# Format: double-quote + seven zeros + 'M1.' + digit + space
# e.g.  b'"0000000M1.7 '   b'"0000000M1.3 '
#
# Bins that contain neither marker are handled as the generic 'M1.x' family.
# ---------------------------------------------------------------------------

FAMILY_MARKERS: Dict[bytes, str] = {
    b'"0000000M1.7': "M1.7",
    b'"0000000M1.3': "M1.3",
}

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these are present the binary cannot be M1.x.  The header-magic
# check alone is sufficient in practice, but these guards make the intent
# explicit and protect against any future edge case.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"ME17",
    b"EDC16",
    b"SB_V",
    b"Customer.",
    b"ME7.",
    b"ME71",
    b"MOTRONIC",
    b"1350000M3",  # M3.1 family marker
    b"1530000M3",  # M3.3 family marker
    b"0000000M3",  # M3.x PSA family marker (MP3.2, MP3.x-PSA — Citroën ZX etc.)
    b'"0000000M2',  # M2.x family marker (M2.3, M2.7, M2.8, M2.81, M2.9)
]

# ---------------------------------------------------------------------------
# Ident block search regions
# ---------------------------------------------------------------------------
# Primary region: the long numeric ident string is always located between
# 0x1800 and 0x2100 in the ROM (verified across all 9 originally-known sample
# bins — offsets observed: 0x1E02 and 0x1F02).  Searching this narrow window
# avoids any accidental match against numeric calibration table data elsewhere
# in the ROM.
#
# Fallback region for 64KB BMW bins: some 64KB BMW M1.7 variants store their
# ident in the last 4KB of the file (analogous to M3.x layout).  When the
# standard IDENT_REGION yields no valid decode, _resolve_ident_num() falls
# back to IDENT_REGION_64KB_TAIL.
# ---------------------------------------------------------------------------

IDENT_REGION: slice = slice(0x1800, 0x2100)

# Last 4KB — used as fallback for 64KB BMW M1.7 bins where the ident sits
# near the top of the second bank rather than at the standard 0x1800 offset.
IDENT_REGION_64KB_TAIL: slice = slice(-4096, None)

# ---------------------------------------------------------------------------
# Fallback detection constants
# ---------------------------------------------------------------------------
# Used by can_handle() Phase 2b — the family-marker fallback path.
#
# A subset of BMW M1.7 32KB and 64KB bins lack the standard \x85\x0a\xf0\x30
# ROM header magic.  They are still unambiguously M1.x because they carry the
# '"0000000M1.7' (or M1.3) family marker and a valid reversed-digit ident.
#
# The fallback is restricted to files whose size is in FALLBACK_VALID_SIZES
# (same set as the original magic-based path) to ensure no larger file from a
# different family can slip through.
#
# GAP_IDENT_PATTERN matches two digit runs separated by 1–8 \xff bytes —
# the exact structure observed in the 64KB E36 316 bin (27 digits + 2 FF +
# 3 digits).  The groups are concatenated before decoding.
# ---------------------------------------------------------------------------

FALLBACK_VALID_SIZES: frozenset[int] = frozenset({0x8000, 0x10000})  # 32KB, 64KB

# Matches a split ident: run1 (25–30 digits) + small FF gap + run2 (2–5 digits)
GAP_IDENT_PATTERN: bytes = rb"(\d{25,30})\xff{1,8}(\d{2,5})"


class BoschM1xExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic M1.x ECU binaries.
    Handles: M1.3, M1.7, and generic M1.x (no explicit sub-variant).

    Detection is anchored on the 4-byte ROM header magic \\x85\\x0a\\xf0\\x30
    which is unique to this family.  Sub-variant (M1.3 / M1.7) is resolved
    from the '"0000000M1.x' ASCII marker embedded in the upper ROM region.

    HW and SW are decoded from the ident block using the same reversed-digit
    scheme as BoschM3xExtractor:
        hw = ident_clean[0:10][::-1]   ->  '0261xxxxxx'
        sw = ident_clean[10:20][::-1]  ->  '1267xxxxxx'
    """

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["M1.7", "M1.3", "M1.x"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch Motronic M1.x ECU.

        Multi-phase check (Phase 1, 2a, 2b, 2c):

          Phase 1 — Exclusion.
            Reject immediately if any exclusion signature is found in the
            first 512KB.  Guards against modern Bosch, M3.x, and any other
            family that might share numeric substrings with M1.x ident data.

          Phase 2a — Primary: ROM header magic.
            Accept if the 4-byte magic \\x85\\x0a\\xf0\\x30 is present at
            offset 0.  This is the strongest possible anchor — exclusive to
            M1.x and absent from every other known Bosch family.

          Phase 2b — BMW M1.7 fallback: family marker present, no header magic.
            A subset of BMW M1.7 32KB/64KB bins lack the standard header
            magic but carry the '"0000000M1.7' or '"0000000M1.3' family
            marker.  Accepted when the file is 32KB or 64KB and a valid
            reversed-digit ident (hw starts with '0261', sw starts with
            '1267') decodes from IDENT_REGION (primary),
            IDENT_REGION_64KB_TAIL (fallback for 64KB), or via the
            gap-tolerant GAP_IDENT_PATTERN that joins two digit runs
            separated by a small run of \\xff bytes.

          Phase 2c — Opel M1.x fallback: no family marker, valid 0261/1267 ident.
            Opel M1.x petrol ECUs use the same reversed-digit ident encoding
            as BMW M1.x but carry neither the ROM header magic nor the BMW
            family marker.  Accepted by the same size gate (32KB or 64KB)
            and _fallback_ident_valid() check because hw=0261xxxxxx and
            sw=1267xxxxxx uniquely identify M1.x petrol ECUs regardless of
            manufacturer.
        """
        search_area = data[:0x80000]

        # Phase 1 — reject on any exclusion signature
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                return False

        # Phase 2a — primary: ROM header magic at offset 0
        if data[:4] == DETECTION_MAGIC:
            return True

        # Phase 2b/2c — size gate + ident fallback (BMW and Opel M1.x variants)
        #
        # Some BMW M1.7 bins lack the standard ROM header magic — they are still
        # identified by the '"0000000M1.7' family marker + valid ident (Phase 2b).
        #
        # Opel M1.x petrol ECUs use the identical reversed-digit ident encoding
        # but carry no ROM header magic AND no BMW family marker (Phase 2c).
        # They are accepted by the same _fallback_ident_valid() check because that
        # method already requires hw=0261xxxxxx and sw=1267xxxxxx, which uniquely
        # identifies M1.x petrol ECUs regardless of manufacturer.
        #
        # Both variants must be exactly 32KB or 64KB in size.
        if len(data) not in FALLBACK_VALID_SIZES:
            return False

        return self._fallback_ident_valid(data)

    # -----------------------------------------------------------------------
    # Internal — fallback ident validity check (used by can_handle Phase 2b/2c)
    # -----------------------------------------------------------------------

    def _fallback_ident_valid(self, data: bytes) -> bool:
        """
        Return True if a valid reversed-digit ident can be decoded from data.

        Tries three strategies in order of preference:

          1. Standard contiguous pattern in IDENT_REGION (0x1800–0x2100).
          2. Standard contiguous pattern in IDENT_REGION_64KB_TAIL (last 4KB).
          3. Gap-tolerant pattern (GAP_IDENT_PATTERN) in IDENT_REGION_64KB_TAIL
             — for 64KB bins where the ident is split by a short \\xff run.

        In all cases the decoded hw must start with '0261' and sw with '1267'.
        These two prefixes together uniquely identify Bosch M1.x/M3.x petrol
        ECUs and have not been observed in any other Bosch family binary.
        """
        for region in (IDENT_REGION, IDENT_REGION_64KB_TAIL):
            chunk = data[region]
            # Strategy 1 / 2: standard contiguous ident
            m = re.search(rb"\d{20,40}(?:\.\d{2})?", chunk)
            if m:
                raw = m.group(0).decode("ascii", errors="ignore")
                clean = raw.split(".")[0]
                if len(clean) >= 20:
                    hw = clean[0:10][::-1]
                    sw = clean[10:20][::-1]
                    if hw.startswith("0261") and sw.startswith("1267"):
                        return True

        # Strategy 3: gap-tolerant pattern in the last 4KB only
        chunk = data[IDENT_REGION_64KB_TAIL]
        m = re.search(GAP_IDENT_PATTERN, chunk)
        if m:
            combined = (m.group(1) + m.group(2)).decode("ascii", errors="ignore")
            if len(combined) >= 20:
                hw = combined[0:10][::-1]
                sw = combined[10:20][::-1]
                if hw.startswith("0261") and sw.startswith("1267"):
                    return True

        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch M1.x ECU binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from the ident region ---
        # The ident region (0x1800–0x2100) contains the most useful human-
        # readable strings for display purposes.
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=IDENT_REGION,
            min_length=8,
            max_results=20,
        )

        # --- Step 2: Resolve ECU sub-family (M1.3 / M1.7 / M1.x) ---
        ecu_family = self._resolve_ecu_family(data)
        result["ecu_family"] = ecu_family

        # --- Step 3: M1.x has no separate ecu_variant (family IS the variant) ---
        result["ecu_variant"] = ecu_family

        # --- Step 4: Locate and decode the ident block ---
        ident_num = self._resolve_ident_num(data)

        # --- Step 5: Decode HW and SW from the reversed ident number ---
        hardware_number = self._resolve_hardware_number(ident_num)
        result["hardware_number"] = hardware_number

        software_version = self._resolve_software_version(ident_num)
        result["software_version"] = software_version

        # --- Step 6: RT code becomes the calibration ID (when present) ---
        result["calibration_id"] = self._resolve_rt_code(data)

        # --- Step 7: Fields not present in M1.x binaries ---
        result["oem_part_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 8: Build compound match key ---
        # build_match_key() calls .upper() on the family part, which would
        # turn 'M1.x' into 'M1.X'.  We normalise the sentinel value before
        # passing it down so the key reads 'M1.x' consistently.
        family_for_key = "M1.x" if ecu_family == "M1.x" else ecu_family
        result["match_key"] = self._build_m1x_match_key(
            ecu_family=family_for_key,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — match key builder (preserves lowercase 'x' in M1.x)
    # -----------------------------------------------------------------------

    def _build_m1x_match_key(
        self,
        ecu_family: Optional[str],
        software_version: Optional[str],
    ) -> Optional[str]:
        """
        Build the compound match key for M1.x binaries.

        Identical in structure to the base-class build_match_key() except
        that the family segment is uppercased only up to the dot, preserving
        the lowercase 'x' sentinel in 'M1.x':

            'M1.7::1267356378'
            'M1.3::1267355705'
            'M1.x::1267355408'   <- lowercase x preserved

        Returns None if software_version is missing.
        """
        if not software_version:
            return None

        # Preserve the exact casing of the family string — M1.3, M1.7, M1.x
        parts = [ecu_family or "M1.x"]
        parts.append(software_version.upper())

        return "::".join(parts)

    # -----------------------------------------------------------------------
    # Internal — sub-family resolution
    # -----------------------------------------------------------------------

    def _resolve_ecu_family(self, data: bytes) -> str:
        """
        Determine the M1.x sub-variant from the embedded family marker.

        The marker is a fixed ASCII string of the form '"0000000M1.x '
        (double-quote + seven zeros + 'M1.' + digit + space) found in the
        upper half of the ROM (~0x7500–0x79xx).

        Checks FAMILY_MARKERS in definition order.  Returns the generic
        sentinel 'M1.x' if no explicit marker is found — this covers the
        bins (e.g. 153stock.bin, BMW_E32_750i_156.BIN) that lack the string
        but are otherwise structurally identical to the labelled variants.

        Returns:
            'M1.7', 'M1.3', or 'M1.x'
        """
        for marker, family in FAMILY_MARKERS.items():
            if marker in data:
                return family
        return "M1.x"

    # -----------------------------------------------------------------------
    # Internal — ident block
    # -----------------------------------------------------------------------

    def _resolve_ident_num(self, data: bytes) -> Optional[str]:
        """
        Locate and return the raw ident number string from the ROM.

        The ident block is a contiguous ASCII decimal string of 20–40 digits
        optionally followed by a two-decimal-place version suffix (e.g. '.10').

        Three strategies are tried in order:

          1. Standard contiguous pattern in IDENT_REGION (0x1800–0x2100).
             Covers all magic-detected bins and the two 32KB BMW M1.7 fallback
             bins (0261200520, 0261203590), which keep their ident at the same
             absolute offset despite their different ROM header.

          2. Standard contiguous pattern in IDENT_REGION_64KB_TAIL (last 4KB).
             Covers any 64KB variant where the ident migrated to the top bank.

          3. Gap-tolerant join in IDENT_REGION_64KB_TAIL via GAP_IDENT_PATTERN.
             The 64KB BMW E36 316 (0261203660) stores a 27-digit run followed
             by 2–3 \\xff bytes and then a 3-digit continuation.  Concatenating
             the two groups before decoding yields the correct 30-digit ident:
               hw = concat[0:10][::-1] = '0261203660'
               sw = concat[10:20][::-1] = '1267358700'

        Minimum length is 20 digits (not 28) to cover the short-form M1.7
        Alfa 155 1.8TS bins where the ident encodes only HW + SW:
            e.g. '63500216203697537621'  (20 digits)
                 hw = '6350021620'[::-1] = '0261200536'
                 sw = '3697537621'[::-1] = '1267357963'

        Returns:
            Raw ident string e.g. '571002162087365376211314371100072.10',
            or None if not found in any region.
        """
        # Strategy 1 and 2: standard contiguous search
        for region in (IDENT_REGION, IDENT_REGION_64KB_TAIL):
            chunk = data[region]
            m = re.search(rb"\d{20,40}(?:\.\d{2})?", chunk)
            if m:
                candidate = m.group(0).decode("ascii", errors="ignore").strip()
                # Only accept if it decodes a valid hw/sw pair; otherwise keep
                # searching so a stray numeric run doesn't shadow the real ident.
                clean = candidate.split(".")[0]
                if len(clean) >= 20:
                    hw = clean[0:10][::-1]
                    sw = clean[10:20][::-1]
                    if hw.startswith("0261") and sw.startswith("1267"):
                        return candidate

        # Strategy 3: gap-tolerant join (64KB split-ident variant)
        chunk = data[IDENT_REGION_64KB_TAIL]
        m = re.search(GAP_IDENT_PATTERN, chunk)
        if m:
            combined = (
                (m.group(1) + m.group(2)).decode("ascii", errors="ignore").strip()
            )
            if len(combined) >= 20:
                hw = combined[0:10][::-1]
                sw = combined[10:20][::-1]
                if hw.startswith("0261") and sw.startswith("1267"):
                    return combined

        # Final fallback: accept any contiguous run in the primary region
        # (preserves original behaviour for magic-detected bins whose ident
        # does not satisfy the 0261/1267 prefix check — e.g. future variants)
        chunk = data[IDENT_REGION]
        m = re.search(rb"\d{20,40}(?:\.\d{2})?", chunk)
        if m:
            return m.group(0).decode("ascii", errors="ignore").strip()

        return None

    # -----------------------------------------------------------------------
    # Internal — HW / SW decoding from reversed ident number
    # -----------------------------------------------------------------------

    def _resolve_hardware_number(self, ident_num: Optional[str]) -> Optional[str]:
        """
        Decode the Bosch hardware part number from the raw ident number.

        Encoding:
            ident_clean = ident_num.split('.')[0]
            hw          = ident_clean[0:10][::-1]

        A valid M1.x hardware number is exactly 10 digits and starts with
        '0261'.  Returns None if the decoded value fails this check.

        Args:
            ident_num: Raw ident string from the ROM.

        Returns:
            10-digit hardware number string, or None.
        """
        if not ident_num:
            return None

        ident_clean = ident_num.split(".")[0]
        if len(ident_clean) < 10:
            return None

        hw = ident_clean[0:10][::-1]

        if not hw.isdigit() or not hw.startswith("0261"):
            return None

        return hw

    def _resolve_software_version(self, ident_num: Optional[str]) -> Optional[str]:
        """
        Decode the Bosch software version from the raw ident number.

        Encoding:
            ident_clean = ident_num.split('.')[0]
            sw          = ident_clean[10:20][::-1]

        A valid M1.x software version is exactly 10 digits and starts with
        '1267'.  Returns None if the decoded value fails this check.

        The minimum ident length of 20 covers the short-form bins (e.g. Alfa
        155 1.8TS) that encode only HW + SW without trailing fields.

        Args:
            ident_num: Raw ident string from the ROM.

        Returns:
            10-digit software version string, or None.
        """
        if not ident_num:
            return None

        ident_clean = ident_num.split(".")[0]
        if len(ident_clean) < 20:
            return None

        sw = ident_clean[10:20][::-1]

        if not sw.isdigit() or not sw.startswith("1267"):
            return None

        return sw

    # -----------------------------------------------------------------------
    # Internal — RT code (calibration ID)
    # -----------------------------------------------------------------------

    def _resolve_rt_code(self, data: bytes) -> Optional[str]:
        """
        Locate the RT code and return it as the calibration ID.

        The RT code is an ASCII string of the form 'NNNNNRTNNNN'
        (5 digits + 'RT' + 4 digits), located ~0xC0 bytes after the ident
        block (~0x1EC0–0x1FC0).  It is present in most M1.x bins but absent
        in some (e.g. BMW_179.bin).

        For 32KB bins the RT code sits at ~0x1FC0 within the standard
        slice(0x1C00, 0x2100) window.  For 64KB fallback bins the ident and
        RT code are in the second bank, so the RT is searched in the last
        512 bytes of the file as a secondary location.

        Returns:
            RT code string e.g. '07826RT3557', or None if not found.
        """
        # Primary window: standard location in the ident region
        m = re.search(rb"\d{5}RT\d{4}", data[0x1C00:0x2100])
        if m:
            return m.group(0).decode("ascii", errors="ignore").strip()

        # Secondary window: last 512 bytes (covers 64KB fallback bins)
        m = re.search(rb"\d{5}RT\d{4}", data[-512:])
        if m:
            return m.group(0).decode("ascii", errors="ignore").strip()

        return None
