"""
Bosch ECU binary extractor.

Implements BaseManufacturerExtractor for all Bosch ECU families:
EDC17, MEDC17, MED17, ME17, EDC16, MED9, MD1

The analyzer.py is manufacturer-agnostic.
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    EXCLUSION_CLEAR,
    DETECTION_SIGNATURE,
)
from openremap.core.manufacturers.bosch.edc17.patterns import (
    DETECTION_SIGNATURES,
    FAMILY_BASE_NAMES,
    FAMILY_RESOLUTION_ORDER,
    MCU_CONSTANTS,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
)


class BoschExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch ECU binaries.
    Handles: EDC17, MEDC17, MED17, ME17, EDC16, MED9, MD1
    """

    # Opt in to calibration_id fallback for match_key.
    # Used when software_version is absent (e.g. PSA/Citroën EDC17 internal
    # flash dumps where the MCU constant 1037555072 is rejected and the PSA
    # calibration_id is the sole unique identifier).
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
        return ["EDC17", "MEDC17", "MED17", "ME17", "EDC16", "MED9", "MD1"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if at least one Bosch signature is found in the binary,
        and the binary is not owned by an earlier, more-specific extractor.

        Fast check — only scans bounded regions, no regex needed.

        Exclusion guards (in priority order):
          1. EDC16 bins — rejected by two independent checks:
               a. File size is one of the three known EDC16 sizes (256KB /
                  1MB / 2MB) AND the \xde\xca\xfe header magic is present at
                  any of the standard active-section offsets for that size.
                  This is the same anchor that BoschEDC16Extractor uses as
                  its primary positive signal, so the two extractors are now
                  strictly disjoint.
               b. Safety net: if the magic check somehow misses (partially
                  erased bin), any EDC16 family string in the first 512KB
                  still causes rejection here.
             Both guards are needed because b"EDC16" was intentionally removed
             from DETECTION_SIGNATURES to prevent double-claiming, so we must
             never accidentally accept a real EDC16 bin via another signature
             (e.g. b"Bosch" embedded in the calibration area).
          2. EDC15 bins — rejected by the TSW string at the bank boundary.
             BoschEDC15Extractor runs before this extractor in the registry;
             this check is a safety net only.
        """
        evidence: list[str] = []

        # ------------------------------------------------------------------
        # Guard 1a — reject EDC16 bins via \xde\xca\xfe magic + size check.
        # EDC16 active-section magic offsets, keyed by file size:
        #   256KB (0x40000) : 0x003d
        #   1MB   (0x100000): 0x4003d, 0x8003d, 0xd003d, 0xe003d
        #   2MB   (0x200000): 0x1c003d
        # ------------------------------------------------------------------
        _EDC16_MAGIC = b"\xde\xca\xfe"
        _EDC16_MAGIC_OFFSETS: dict[int, list[int]] = {
            0x040000: [0x0003D],
            0x100000: [0x4003D, 0x8003D, 0xD003D, 0xE003D],
            0x200000: [0x1C003D],
        }
        size = len(data)
        if size in _EDC16_MAGIC_OFFSETS:
            magic_end = len(_EDC16_MAGIC)
            for offset in _EDC16_MAGIC_OFFSETS[size]:
                if data[offset : offset + magic_end] == _EDC16_MAGIC:
                    self._set_evidence()
                    return False

        # ------------------------------------------------------------------
        # Guard 1b — EDC16 safety net: reject on EDC16 family string.
        # Catches partially-erased bins where the magic is gone but the
        # family descriptor is still readable.
        # ------------------------------------------------------------------
        if b"EDC16" in data[:0x80000]:
            self._set_evidence()
            return False

        # ------------------------------------------------------------------
        # Guard 2 — reject EDC15 bins via TSW string at the bank boundary.
        # ------------------------------------------------------------------
        num_banks = max(1, len(data) // 0x80000)
        if any(
            b"TSW " in data[bank * 0x80000 + 0x8000 : bank * 0x80000 + 0x8060]
            for bank in range(num_banks)
        ):
            self._set_evidence()
            return False

        # ------------------------------------------------------------------
        # Guard 3 — reject pure Bosch ME9 full flash dumps.
        # ME9 and MED9 ECUs share the same "RamLoader.Me9.0001" bootloader
        # string, so the presence of that string alone is not enough to
        # reject. Only reject when the RamLoader string is present AND no
        # MED9 family content exists — MED9 bins always contain b"MED9"
        # (e.g. "MED9510/..." or "MED91/...") while pure ME9 bins do not.
        # ------------------------------------------------------------------
        if b"RamLoader.Me9" in data[:0x200000] and b"MED9" not in data:
            self._set_evidence()
            return False

        # ------------------------------------------------------------------
        # Guard 4 — reject Magneti Marelli ECUs with a ZZ ident block at
        # 0x10000.  Marelli ME1.5.5 (and related IAW families) place a
        # slash-delimited descriptor starting with "ZZ" at the same fixed
        # offset used by Bosch ME7, but the byte immediately after "ZZ" is
        # a printable ASCII character (e.g. "ZZ43/1/ME1.5.5/...").  All
        # genuine Bosch ME7 variants use a non-printable third byte
        # (\xff, \x00, or \x01).  A Marelli bin can pass Guards 1–3 and
        # then trigger on a coincidental b"MD1" byte sequence in calibration
        # data — this guard prevents that false positive.
        # ------------------------------------------------------------------
        if (
            len(data) > 0x10002
            and data[0x10000:0x10002] == b"ZZ"
            and 0x20 <= data[0x10002] <= 0x7E
        ):
            self._set_evidence()
            return False

        # ------------------------------------------------------------------
        # Guard 5 — reject Bosch ME7 family files.
        # ME7.x / ME71 / ME731 / MOTRONIC are exclusive to BoschME7Extractor.
        # Large ME7 variants (e.g. ME7.6.2 for Opel Corsa D, 832KB) carry a
        # generic manufacturer label ("BOSCH0100") that triggers the b"BOSCH"
        # detection signature here.  Checking for ME7 family strings across
        # the full binary prevents a false-positive CONTESTED classification
        # when BoschME7Extractor has already claimed the file correctly.
        # ME7 family strings never appear in genuine EDC17 / MEDC17 / MD1
        # binaries — they use a completely different toolchain and naming
        # convention.
        # ------------------------------------------------------------------
        _ME7_FAMILY_SIGNATURES: tuple[bytes, ...] = (
            b"ME7.",  # ME7.1  ME7.5  ME7.1.1  ME7.5.5  ME7.5.10  ME7.6.2
            b"ME71",  # earliest production variant (no dot notation)
            b"ME731",  # Alfa Romeo Motronic E7.3.1
            b"MOTRONIC",  # Bosch Motronic label — present in most ME7 bins
        )
        if any(sig in data for sig in _ME7_FAMILY_SIGNATURES):
            self._set_evidence()
            return False

        # All exclusion guards passed
        evidence.append(EXCLUSION_CLEAR)

        if any(sig in data for sig in DETECTION_SIGNATURES):
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
        Extract all identifying information from a Bosch ECU binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
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
        raw_hits = self._run_patterns(data)

        # --- Step 3: Resolve ECU variant ---
        ecu_variant = self._resolve_ecu_variant(raw_hits)
        result["ecu_variant"] = ecu_variant

        # --- Step 4: Resolve ECU family ---
        # ecu_variant is passed as a fallback: if no explicit family string is
        # found in the binary, the family is inferred from the variant name
        # (e.g. "EDC17C66" → "EDC17"). This covers binaries where the family
        # token is absent or lives past the search region boundary.
        ecu_family = self._resolve_ecu_family(raw_hits, ecu_variant=ecu_variant)
        result["ecu_family"] = ecu_family

        # --- Step 5: Resolve calibration version ---
        result["calibration_version"] = self._first_hit(raw_hits, "calibration_version")

        # --- Step 6: Resolve SW base version ---
        result["sw_base_version"] = self._first_hit(raw_hits, "sw_base_version")

        # --- Step 7: Resolve serial number ---
        result["serial_number"] = self._first_hit(raw_hits, "serial_number")

        # --- Step 8: Resolve dataset number ---
        result["dataset_number"] = self._resolve_dataset_number(raw_hits)

        # --- Step 9: Resolve software version ---
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 10: Resolve hardware number ---
        hardware_number = self._resolve_hardware_number(raw_hits)
        result["hardware_number"] = hardware_number

        # --- Step 11: Resolve calibration ID ---
        # PSA cal ID takes priority — it is the sole unique identifier in PSA
        # internal flash dumps and must not be overwritten by the generic pattern.
        psa_cal_id = self._first_hit(raw_hits, "psa_calibration_id")
        result["calibration_id"] = psa_cal_id or self._first_hit(
            raw_hits, "calibration_id"
        )

        # --- Step 12: Resolve OEM part number ---
        result["oem_part_number"] = self._resolve_oem_part_number(raw_hits)

        # --- Step 13: Build compound match key ---
        # For PSA internal flash dumps the calibration_id IS the unique
        # identifier — software_version is None (MCU constant was rejected).
        # Use the fallback mechanism so build_match_key() can produce a key.
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_variant,
            software_version=software_version,
            fallback_value=psa_cal_id,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — pattern runner
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """
        Run all Bosch patterns against their assigned search regions.

        Overrides the default max_results=5 cap for software_version — large
        2MB MED9/MD1 full flash bins contain many garbage digit runs before
        the real 1037-prefixed SW string, and 5 results are not enough to
        reach it. All other patterns keep the default cap.
        """
        raw_hits = self._run_all_patterns(
            data, PATTERNS, PATTERN_REGIONS, SEARCH_REGIONS
        )
        # Re-run SW with a higher cap so the real 1037 string is not crowded
        # out by garbage hits earlier in the file.
        raw_hits["software_version"] = self._search(
            data, PATTERNS["software_version"], SEARCH_REGIONS["full"], max_results=25
        )
        return raw_hits

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_ecu_variant(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the specific ECU hardware variant (e.g. "EDC17C66", "MED9510").

        Priority:
          1. Extract from authoritative variant string
             e.g. "47/1/EDC17C66/1/P1262//..." -> "EDC17C66"
             This is the most reliable source.
          2. Fall back to bare ecu_variant regex hits (EDC17Cxx).
             These can match project/config names like "P_000_EDC17C01.10.0.0"
             so they are used only when no authoritative string is found.
          3. Fall back to the full family-pattern match when it contains
             sub-version digits (e.g. "MED9510", "MED91", "MEDC17.7").
             This promotes the specific version string to variant so that
             ecu_family can hold only the canonical base name ("MED9",
             "MEDC17", etc.) rather than the full versioned string.
        """
        # Priority 1 — authoritative variant string
        if "ecu_variant_string" in raw_hits:
            for variant_str in raw_hits["ecu_variant_string"]:
                match = re.search(
                    rb"EDC17[A-Z]{1,2}\d{1,3}",
                    variant_str.encode("ascii", errors="ignore"),
                )
                if match:
                    return match.group().decode("ascii").rstrip(".-_")

        # Priority 2 — bare EDC17Cxx regex hit
        if "ecu_variant" in raw_hits:
            return raw_hits["ecu_variant"][0].rstrip(".-_")

        # Priority 3 — full family-pattern match that includes sub-version digits.
        # The family resolver normalises these to their base name; the full
        # string (e.g. "MED9510", "MED91", "MEDC17.7") belongs here as variant.
        for family_key in FAMILY_RESOLUTION_ORDER:
            if family_key in raw_hits:
                full = raw_hits[family_key][0].rstrip(".-_")
                base = FAMILY_BASE_NAMES.get(family_key, "")
                # Only promote to variant when the matched string is longer
                # than the bare base name — "MED9510" > "MED9", "MEDC17.7" > "MEDC17".
                if base and len(full) > len(base):
                    return full
                break  # base name only — no useful variant to promote

        return None

    def _resolve_ecu_family(
        self,
        raw_hits: Dict[str, List[str]],
        ecu_variant: Optional[str] = None,
    ) -> Optional[str]:
        """
        Resolve the canonical ECU family name (e.g. "MEDC17", "EDC17", "MED9").

        Always returns the base family name — never a sub-versioned string.
        Sub-version details (e.g. "MED9510", "MEDC17.7") belong in ecu_variant.

        Priority:
          1. Canonical base name from FAMILY_BASE_NAMES, keyed by which
             family pattern matched. Most specific first (MEDC17 before EDC17).
          2. Infer from ecu_variant when no family pattern matched at all —
             e.g. "EDC17C66" → "EDC17". Covers bins where the family token
             is absent or lies past the 320 KB search region boundary.

        Consistency guard:
          When the pattern-resolved family and the variant-derived family
          disagree (e.g. pattern found "MEDC17" inside a Customer label but
          the authoritative variant string says "EDC17C66"), the variant-
          derived family wins.  The authoritative variant string
          (``47/1/EDC17C66/...``) is a first-class Bosch hardware identifier
          and is more reliable than a regex hit that may have matched inside
          a project/customer label (``Customer.MEDC17.V12``).
        """
        # --- Derive family from variant (if available) ---
        variant_family: Optional[str] = None
        if ecu_variant:
            for prefix in ("MEDC17", "EDC17", "MED17", "ME17", "MD1", "MED9"):
                if ecu_variant.upper().startswith(prefix):
                    variant_family = prefix
                    break

        # --- Priority 1 — normalise matched family string to its base name ---
        pattern_family: Optional[str] = None
        for family_key in FAMILY_RESOLUTION_ORDER:
            if family_key in raw_hits:
                pattern_family = FAMILY_BASE_NAMES.get(
                    family_key,
                    raw_hits[family_key][0].rstrip(".-_"),
                )
                break

        # --- Consistency guard ---
        # When both sources resolved but they disagree, prefer the variant-
        # derived family.  Example: pattern says "MEDC17" (from a Customer
        # label) but variant is "EDC17C66" → family should be "EDC17".
        if pattern_family and variant_family:
            if pattern_family != variant_family:
                return variant_family
            return pattern_family

        # --- Priority 2 — one or neither resolved ---
        return pattern_family or variant_family

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Resolve the software version string.

        Priority:
          1. Explicit SW label — "SW:XXXXXXXXXX" (most authoritative)
          2. Bare numeric match from software_version pattern

        Selection strategy among bare candidates:
          a. Prefer any candidate that starts with "1037" — Bosch's canonical
             internal SW prefix. Among those, pick the longest (up to 18 chars).
          b. If no "1037" candidate exists, fall back to the longest candidate,
             capped at 18 characters to avoid picking up garbage digit runs
             (e.g. repeating-digit fill patterns in calibration data areas).
        Bosch SW versions are typically 10–18 characters.
        Rejects all-zero strings.

        MCU constants (see MCU_CONSTANTS in patterns.py) are always rejected
        regardless of prefix — they are chip hardware identifiers baked into
        the OS code, identical across every calibration on the same MCU platform.
        """
        candidates: List[str] = []

        # Priority 1 — explicit SW label
        if "sw_label" in raw_hits:
            for hit in raw_hits["sw_label"]:
                bare = re.sub(r"^SW[\s:][\s]?", "", hit, flags=re.IGNORECASE).strip()
                if bare and bare not in candidates:
                    candidates.append(bare)

        # Priority 2 — bare numeric match
        if "software_version" in raw_hits:
            for hit in raw_hits["software_version"]:
                if not re.match(r"^0+$", hit) and hit not in candidates:
                    # Reject known MCU hardware constants — they are chip IDs,
                    # not calibration versions, and are identical across every
                    # calibration on the same MCU platform (e.g. TC1793 = 1037555072).
                    if hit in MCU_CONSTANTS:
                        continue
                    # Reject PSA calibration IDs — "0800YY..." strings belong
                    # in calibration_id only. They are not Bosch SW versions
                    # and would produce wrong match_keys if used as sw here.
                    if re.match(r"^0800\d{2}[A-Z0-9]{9}$", hit):
                        continue
                    # Reject sequential digit runs — e.g. "0123456789" is part
                    # of ASCII lookup tables baked into the OS code. A real
                    # Bosch SW version is never a monotone sequential sequence.
                    if re.match(r"^0123456789", hit):
                        continue
                    # Reject repeating-digit fill patterns — e.g. "3333333333".
                    # PSA/Citroën EDC17 internal flash dumps contain large
                    # regions of identical fill bytes (commonly 0x33 = ASCII '3'
                    # or 0x22 = ASCII '2'). The software_version regex matches
                    # these runs as valid candidates. A real Bosch SW version
                    # always contains varied digits, so any string composed
                    # entirely of a single repeated digit is guaranteed noise.
                    digits_only = re.sub(r"[^0-9]", "", hit)
                    if digits_only and len(set(digits_only)) == 1:
                        continue
                    # Reject calibration-table garbage from wiped ident blocks.
                    # When a tuner erases the SW ident region the pattern engine
                    # falls back to calibration map data, which produces strings
                    # like "15678999999999" (nine 9s) or "976555544345544C"
                    # (four 5s).  Real Bosch SW versions are pseudo-random
                    # 10-digit codes — they never contain a run of 4 or more
                    # consecutive identical digits.
                    if re.search(r"(\d)\1{3,}", digits_only):
                        continue
                    # Enforce minimum length — real Bosch SW versions are always
                    # at least 10 characters. Shorter hits are noise from
                    # calibration data regions or partial pattern overlaps.
                    if len(hit) < 10:
                        continue
                    candidates.append(hit)

        if not candidates:
            return None

        # Prefer canonical Bosch "1037"-prefixed SW versions (most authoritative).
        # All EDC17 / MEDC17 / MED17 / ME17 / MD1 / MED9 calibrations use the
        # "1037" prefix without exception.  If no "1037" candidate survived the
        # filters above it means the ident block was wiped or is unreadable —
        # returning None is more honest than producing a garbage match key from
        # calibration table data.
        bosch_canonical = [c for c in candidates if c.startswith("1037")]

        if not bosch_canonical:
            return None

        if bosch_canonical:
            # Remove prefix-extension false matches.
            # These occur when a real SW string (e.g. "1037381976") is stored
            # in the binary with no null separator before the next field
            # (e.g. OEM part number "03C906056CP"), causing the regex to
            # greedily produce "103738197603C906" by absorbing the leading
            # digits of the OEM string.
            #
            # Detection: if candidate A starts with candidate B and the
            # character immediately following B in A is a digit, then A is
            # just B with extra digits from the adjacent field — remove A.
            def _is_digit_extension(longer: str, shorter: str) -> bool:
                if longer == shorter or not longer.startswith(shorter):
                    return False
                next_char = longer[len(shorter)]
                return next_char.isdigit()

            cleaned = [
                c
                for c in bosch_canonical
                if not any(
                    _is_digit_extension(c, other)
                    for other in bosch_canonical
                    if other != c
                )
            ]
            bosch_canonical = cleaned or bosch_canonical

            # Among remaining candidates pick the longest, capped at 18 chars
            # to avoid picking up garbage digit runs.
            return max(bosch_canonical, key=lambda c: len(c) if len(c) <= 18 else 0)

        # Fallback — longest candidate, capped at 18 chars
        valid = [c for c in candidates if len(c) <= 18]
        if valid:
            return max(valid, key=len)

        # Last resort — shortest of whatever remains (least likely to be garbage)
        return min(candidates, key=len)

    def _resolve_hardware_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the hardware part number (e.g. "0281034791").

        Priority:
          1. Explicit HW label — "HW:XXXXXXXXXX"
          2. Standard Bosch format — "0281XXXXXX"
          3. Alternative Bosch format — "F01R00DE67"

        Normalised: spaces and dots removed.
        """
        candidates: List[str] = []

        if "hw_label" in raw_hits:
            for hit in raw_hits["hw_label"]:
                bare = re.sub(r"^HW[\s:][\s]?", "", hit, flags=re.IGNORECASE).strip()
                if bare:
                    candidates.append(bare)

        if "hardware_number" in raw_hits:
            candidates.extend(raw_hits["hardware_number"])

        if not candidates and "bosch_hw_alt" in raw_hits:
            candidates.extend(raw_hits["bosch_hw_alt"])

        if not candidates:
            return None

        # Normalise — remove spaces and dots
        return re.sub(r"[\s\.]", "", candidates[0])

    def _resolve_dataset_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the dataset number (e.g. "6229040100").

        Filters out hits that are false positives:
          1. Any hit that is a substring of the software version — avoids the
             10-digit pattern matching inside longer SW version strings.
          2. Any hit that starts with "1037" — this prefix belongs exclusively
             to Bosch internal SW/calibration tool references (e.g. the
             TC1793 MCU template ID "1037555072" present in newer 0x0800-prefix
             EDC17 bins). Real Bosch dataset numbers never start with "1037".
        """
        if "dataset_number" not in raw_hits:
            return None

        sw_version = self._first_hit(raw_hits, "software_version") or ""

        for hit in raw_hits["dataset_number"]:
            if hit in sw_version:
                continue
            if hit.startswith("1037"):
                continue
            return hit

        return None

    def _resolve_oem_part_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the OEM (vehicle manufacturer) part number.

        Checks VAG, Mercedes, BMW patterns in that order.
        Returns the first match found.
        bosch_hw_alt is intentionally excluded — it's a hardware number,
        not an OEM part number.
        """
        for key in ("vag_part_number", "mercedes_part_number", "bmw_part_number"):
            hit = self._first_hit(raw_hits, key)
            if hit:
                return hit
        return None
