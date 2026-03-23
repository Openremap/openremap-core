"""
Bosch Motronic M5.x / M3.8x ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Motronic M5.x family:
  M3.8    — Bosch Motronic M3.8 / M3.82 / M3.83 / M3.8.3
              VW/Audi 1.8T (AGU engine code), 128KB–256KB dumps (~1997–2001)
  M5.9    — Bosch Motronic M5.9 / M5.92
              VW/Audi 1.8T (AUM, APX, AWP engine codes), 256KB dumps (~2000–2004)

These are Motorola C167-based ECUs — the same CPU family as early ME7 — but
they predate the ME7 generation and use a completely different binary layout:

  - NO ZZ\xff\xff ident block at 0x10000 (that is ME7-specific)
  - NO MOTRONIC label or ME7./ME71 family string in the search area
  - NO modern Bosch signatures (SB_V, Customer., NR000, EDC16, EDC17)
  - HW + SW + family are embedded in a single slash-delimited ASCII ident
    string located in the first 64KB of the binary (~0xbf1e for 128KB bins,
    ~0xbf22 for 256KB bins — both within the first 0x10000 bytes)
  - A standalone M5.x version string (e.g. "M5.9  03/*** AT  HS  D") also
    lives in the first 64KB and serves as the primary detection anchor

Binary sizes:
  0x20000 (128KB) — M3.82 era, e.g. 8D0907557T, 06A906018D
  0x40000 (256KB) — M5.9 / M3.8.3 era, e.g. 8D0907557P, 06A906018AQ/AR/CG

Ident string structure (located near 0xbf1x in the first 64KB):

  Format A — 8D09xxx OEM part numbers (may have 1–4 garbage bytes prefix):
    e.g. b'\\xff\\xff ZZdR D068D0907557P  1.8L R4/5VT MOTR    D060261204258103735026955/1/M5.92/05/...'
    OEM part = "8D0907557P" (first clean alphanumeric run before " 1.8L")

  Format B — 06A9xxx OEM part numbers (clean prefix):
    e.g. b'\\x98\\x11... 06A906018AQ 1.8L R4/5VT MOTR HS D030261204678103735810858/1/M3.8.3/03/...'
    OEM part = "06A906018AQ"

  Slash-delimited fields after the HW+SW block:
    [0] = revision counter   e.g. "1"
    [1] = family string      e.g. "M5.92" / "M3.82" / "M3.8.3"
    [2] = sub-version        e.g. "05" / "03"
    [3] = dataset code       e.g. "400201" / "400303"
    [4] = DAMOS name         e.g. "DAMOS3A8" / "DAMOS30P"
    ...

SW length note:
  The raw SW field in the ident string is ALWAYS exactly 12 digits, e.g.:
    "103735026955"  → true SW = "1037350269"  (first 10 digits)
  The last 2 digits are a toolchain-appended suffix and must be stripped.
  This is confirmed across all 9 observed M5.x/M3.8x samples.

Verified across all sample bins:
  8D0907557P  0261204258  -> M5.92  sw=1037350269  oem=8D0907557P
  8D0907557T  0261204185  -> M3.82  sw=1037358761  oem=8D0907557T
  8D0907559   0261204963  -> M5.92  sw=1037359127  oem=8D0907559
  06A906018AQ 0261204678  -> M3.8.3 sw=1037358108  oem=06A906018AQ
  06A906018AQ 0261204678  -> M3.8.3 sw=1037350010  oem=06A906018AQ
  06A906018AQ 0261204678  -> M3.8.3 sw=1037359525  oem=06A906018AQ
  06A906018AR 0261204679  -> M3.8.3 sw=1037359522  oem=06A906018AR
  06A906018CG 0261206518  -> M3.83  sw=1037352127  oem=06A906018CG
  06A906018D  0261204254  -> M3.82  sw=1037357459  oem=06A906018D
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor
from openremap.tuning.manufacturers.bosch.m5x.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    FAMILY_NORMALISATION,
    MOTR_ANCHOR,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
    SUPPORTED_SIZES,
)


class BoschM5xExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic M5.x / M3.8x ECU binaries.
    Handles: M3.8, M3.82, M3.83, M3.8.3, M5.9, M5.92.

    All identification data is extracted from the single slash-delimited
    ASCII ident string located in the first 64KB of the binary.
    """

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["M5.9", "M5.92", "M3.8", "M3.82", "M3.83", "M3.8.3"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch Motronic M5.x / M3.8x ECU.

        Four-phase check:

          Phase 1 — Reject on any exclusion signature in first 512KB.
                    Guards against claiming ME7, EDC15, EDC16, EDC17 bins.
                    Includes ZZ\\xff\\xff (ME7 ident marker) as a hard reject.

          Phase 2 — Reject if file size is not 128KB or 256KB.
                    ME7 and EDC15 use larger sizes; anything smaller is
                    pre-EDC15 territory handled by other extractors.

          Phase 3 — Accept on any primary detection signature (M5. / M3.8)
                    found in the first 64KB AND the combined ident block
                    pattern (MOTR + HW + 12-digit SW + /n/family) is also
                    present in the first 64KB.
                    Requiring both prevents false positives from any bin
                    that happens to contain "M5." or "M3.8" as calibration
                    data without being a genuine M5.x ECU.

          Phase 4 — Accept on the combined ident block pattern alone.
                    Covers the rare M3.82 bins that don't contain an
                    explicit M5.x standalone string but have a clear
                    MOTR + HW + 12-digit SW + /n/M3. ident block.
                    Stricter pattern required here to avoid false positives.
        """
        search_area = data[:0x80000]
        ident_area = data[:0x10000]

        # Phase 1 — exclusion check
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                return False

        # Phase 2 — size gate
        if len(data) not in SUPPORTED_SIZES:
            return False

        # Check for the combined ident block (MOTR + HW + 12-digit SW + /n/family)
        has_ident = bool(re.search(PATTERNS["ident_block"], ident_area))

        # Phase 3 — primary signature + ident block
        has_primary = any(sig in ident_area for sig in DETECTION_SIGNATURES)
        if has_primary and has_ident:
            return True

        # Phase 4 — ident block alone (M3.8x bins without explicit M5. string)
        # Require the MOTR anchor to be present as an additional guard
        if has_ident and MOTR_ANCHOR in ident_area:
            return True

        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch M5.x / M3.8x binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from the ident area ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_area"],
            min_length=8,
            max_results=20,
        )

        # --- Step 2: Parse the ident block (single authoritative source) ---
        ident = self._parse_ident_block(data)

        # --- Step 3: Resolve ECU family ---
        ecu_family = self._resolve_ecu_family(ident, data)
        result["ecu_family"] = ecu_family
        result["ecu_variant"] = ecu_family

        # --- Step 4: Resolve SW version (strip 2-digit suffix) ---
        software_version = self._resolve_software_version(ident, data)
        result["software_version"] = software_version

        # --- Step 5: Resolve HW number ---
        hardware_number = self._resolve_hardware_number(ident, data)
        result["hardware_number"] = hardware_number

        # --- Step 6: Resolve OEM part number ---
        result["oem_part_number"] = self._resolve_oem_part_number(data)

        # --- Step 7: Fields not present in M5.x binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["calibration_id"] = None

        # --- Step 8: Build match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — ident block parser
    # -----------------------------------------------------------------------

    def _parse_ident_block(self, data: bytes) -> Optional[re.Match]:
        """
        Find and return the regex match object for the ident block.

        The ident block is always in the first 64KB. Returns None if not
        found (should not happen for any bin that passed can_handle).
        """
        ident_area = data[SEARCH_REGIONS["ident_area"]]
        return re.search(PATTERNS["ident_block"], ident_area)

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_ecu_family(
        self, ident: Optional[re.Match], data: bytes
    ) -> Optional[str]:
        """
        Resolve the ECU family string and normalise it.

        Priority:
          1. Field 4 of the ident block (most authoritative):
             e.g. "M5.92" → normalised to "M5.9"
                  "M3.8.3" → normalised to "M3.8"
          2. Standalone ecu_family_string in the ident area (secondary):
             e.g. "M5.9" from "M5.9  03/*** AT  HS  D"
          3. Raw family name from ident block without normalisation.

        Returns the normalised family name, or the raw name if not in the
        normalisation map, or None if nothing is found.
        """
        raw_family: Optional[str] = None

        # Priority 1 — ident block group 4
        if ident:
            raw_family = ident.group(4).decode("ascii", errors="ignore").strip()

        # Priority 2 — standalone family string
        if not raw_family:
            ident_area = data[SEARCH_REGIONS["ident_area"]]
            m = re.search(PATTERNS["ecu_family_string"], ident_area)
            if m:
                raw_family = m.group(0).decode("ascii", errors="ignore").strip()

        if not raw_family:
            return None

        # Normalise — strip trailing dots/dashes then look up canonical name
        cleaned = raw_family.rstrip(".-_")
        return FAMILY_NORMALISATION.get(cleaned, cleaned)

    def _resolve_software_version(
        self, ident: Optional[re.Match], data: bytes
    ) -> Optional[str]:
        """
        Resolve the software version string (always exactly 10 digits).

        In M5.x / M3.8x bins the raw SW field in the ident block is always
        12 digits — the first 10 are the true SW, the last 2 are a
        toolchain-appended suffix that must be stripped.

        Priority:
          1. Group 2 of the ident block match (raw 12-digit field) — strip to 10.
          2. Standalone software_version pattern (strict 10-digit match) in
             the ident area — fallback for unusual layouts.

        Rejects all-zero strings.
        """
        # Priority 1 — ident block (12-digit raw → strip to 10)
        if ident:
            raw = ident.group(2).decode("ascii", errors="ignore").strip()
            if raw and not re.match(r"^0+$", raw):
                return raw[:10]  # always strip the 2-digit suffix

        # Priority 2 — standalone strict 10-digit match
        ident_area = data[SEARCH_REGIONS["ident_area"]]
        m = re.search(PATTERNS["software_version"], ident_area)
        if m:
            val = m.group(0).decode("ascii", errors="ignore").strip()
            if val and not re.match(r"^0+$", val):
                return val

        return None

    def _resolve_hardware_number(
        self, ident: Optional[re.Match], data: bytes
    ) -> Optional[str]:
        """
        Resolve the hardware part number (always "0261xxxxxx", 10 digits).

        Priority:
          1. Group 1 of the ident block match — most reliable.
          2. Standalone hardware_number pattern in the ident area — fallback.
        """
        # Priority 1 — ident block group 1
        if ident:
            val = ident.group(1).decode("ascii", errors="ignore").strip()
            if val:
                return val

        # Priority 2 — standalone pattern
        ident_area = data[SEARCH_REGIONS["ident_area"]]
        m = re.search(PATTERNS["hardware_number"], ident_area)
        if m:
            return m.group(0).decode("ascii", errors="ignore").strip()

        return None

    def _resolve_oem_part_number(self, data: bytes) -> Optional[str]:
        """
        Resolve the OEM (VAG) part number from the ident string.

        The OEM part is the first alphanumeric token that appears immediately
        before the engine displacement descriptor (" 1.8L") in the ident area.

        Format A bins (8D09xxx) sometimes have 1–2 numeric garbage bytes
        immediately before the OEM part in the binary stream, causing the
        regex to capture e.g. "068D0907557P" or "038D0907559" instead of
        the true "8D0907557P" / "8D0907559".

        Format B bins (06A906018xx, 03G906016xx) are always clean — the OEM
        part number is captured exactly as-is, e.g. "06A906018AQ".

        Garbage detection rule (Format A only):
          A garbage-prefixed candidate has the form  /d{1,2} + <real_part>
          where the REAL part starts with a single digit immediately followed
          by a LETTER at position 1 (e.g. "8D...", "4B...", "4A...", "4Z...").
          Valid Format B parts start with TWO digits before the first letter
          (e.g. "06A...", "03G...", "8D..." has letter at pos 1 — but that is
          a clean match, not a garbage-prefixed one).

          Concretely: strip a 1–2 digit prefix ONLY when ALL of these hold:
            1. candidate[0] is a digit  (always true given the regex)
            2. candidate[1] is a digit  (the first garbage digit)
            3. candidate[2] is a digit  (second garbage digit OR real part start)
            4. candidate[3] is a LETTER (letter of the real part, e.g. "D" in "8D")

          This fires on  "068D..."  (pos 0='0',1='6',2='8',3='D') → strip "06"
          and            "038D..."  (pos 0='0',1='3',2='8',3='D') → strip "03"
          but NOT on     "06A..."   (pos 3='9', not a letter at pos 3 after strip)
          and NOT on     "8D0..."   (pos 1='D', already a letter — clean match).

        Returns None if no match is found.
        """
        ident_area = data[SEARCH_REGIONS["ident_area"]]
        m = re.search(PATTERNS["oem_part_number"], ident_area)
        if not m:
            return None

        candidate = m.group(1).decode("ascii", errors="ignore").strip()

        # Must contain at least one letter — rules out all-digit false hits
        if not any(c.isalpha() for c in candidate):
            return None

        # Must be at least 8 chars — rules out short garbage matches
        if len(candidate) < 8:
            return None

        # Format A garbage-prefix strip.
        # Condition: positions 0,1,2 are all digits AND position 3 is a letter.
        # That is the signature of a 2-digit garbage prefix followed by a
        # single-digit + letter VAG part (e.g. "068D..." → real = "8D...").
        # Valid Format B parts (e.g. "06A...") have a letter at position 2,
        # so they never satisfy the "pos 3 is a letter" after a 2-digit strip.
        if (
            len(candidate) >= 4
            and candidate[0].isdigit()
            and candidate[1].isdigit()
            and candidate[2].isdigit()
            and candidate[3].isalpha()
        ):
            remainder = candidate[2:]  # strip the 2-digit garbage prefix
            if len(remainder) >= 8 and any(c.isalpha() for c in remainder):
                candidate = remainder

        return candidate
