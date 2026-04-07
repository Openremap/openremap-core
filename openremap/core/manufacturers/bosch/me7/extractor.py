"""
Bosch ME7 ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Motronic ME7 family:
  ME7 early — pre-production / engineering build, ERCOS V2.x RTOS, 1996–1997
               ZZ\x01\x02 marker at 0x10000 (non-standard variant byte).
               No slash-delimited variant string, no 0261/1037 ident block.
               Identified by ERCOS string at 0x200 and early ECU label:
                 "<part>   <engine_desc>   <rev_code>\x80\x80"
               e.g. "8D0907551   2,7l V6/5VT         D04\x80\x80"
               software_version = rev_code (e.g. "D04") — only identifier.
  ME71     — earliest production variant (no dot notation), 1997
  ME7.1    — Audi/VW V6, W8, W12 engines, 1998–2004
  ME7.1.1  — updated ME7.1, 2000–2006
  ME7.5    — VW/Audi 4-cylinder turbo engines, 1998–2006
  ME7.5.5  — revision of ME7.5, 2002+
  ME7.5.10 — late production variant

These are older Motorola C167-based ECUs and have a completely different
binary structure from the newer EDC17/MEDC17 generation:

  - No SB_V, NR000, Customer. or EDC17 strings
  - ZZ marker at 0x10000 (variant byte differs by sub-family, see below)
  - HW number always starts with 0261 (10 digits total)  [production only]
  - SW version starts with 1037 or 1277 (10–11 digits)  [production only]
  - HW and SW are stored as a concatenated ASCII block in the ident region
  - MOTRONIC label carries the VAG OEM part number and family string

ZZ marker variants:
  ZZ\xff\xff  — standard production ME7.1 / ME7.5 / ME7.1.1 / ME7.5.5
  ZZ\x00\x01  — ME731 (Alfa Romeo Motronic E7.3.1)
  ZZ\x01\x02  — early/pre-production ME7 (ERCOS V2.x, 1996)
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
from openremap.core.manufacturers.bosch.me7.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    FAMILY_RESOLUTION_ORDER,
    ME7_ZZ_MARKER,
    ME7_ZZ_OFFSET,
    ME7_ZZ_PREFIX,
    PATTERN_REGIONS,
    PATTERNS,
    SEARCH_REGIONS,
)


class BoschME7Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic ME7 ECU binaries.
    Handles: ME7, ME7.0, ME71, ME7.1, ME7.1.1, ME7.5, ME7.5.5, ME7.5.10
    """

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
            "ME7",
            "ME7.0",
            "ME7early",
            "ME71",
            "ME731",
            "ME7.1",
            "ME7.1.1",
            "ME7.3",
            "ME7.5",
            "ME7.5.5",
            "ME7.5.10",
            "ME7.6.2",
        ]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch ME7 family ECU.

        Six-phase check:
          0. Reject immediately if the binary is smaller than 64KB (0x10000).
             The ME7 ZZ ident block is anchored at offset 0x10000, so no
             genuine ME7 binary can be smaller than this.  This size gate
             also eliminates false positives from pre-ME7 legacy binaries
             (e.g. Bosch M2.x Porsche 964 Carrera 2, 32KB) that happen to
             contain the 'MOTRONIC' detection signature but are not ME7.
          1. Reject immediately if any modern Bosch (EDC17/MEDC17) exclusion
             signature is found — those belong to the BoschExtractor.
          2. Accept if at least one ME7 string signature is found anywhere
             in the full binary (ME7., ME71, ME731, MOTRONIC).  The search
             is not bounded to the first 512KB because some large ME7
             variants (e.g. ME7.6.2 for Opel Corsa D, 832KB) store the
             family identifier past the 512KB mark.
          3. Accept if the ZZ ident block marker is present at the fixed offset
             0x10000 — checked by exact position only, never scanned across the
             full binary.  Scanning ZZ anywhere causes false positives on
             non-ME7 binaries that contain that byte sequence as coincidental
             calibration data.

             Only the first two bytes (b"ZZ") are checked rather than the full
             four-byte sequence b"ZZ\xff\xff".  The two bytes that follow "ZZ"
             vary by ME7 sub-variant:
               b"ZZ\xff\xff"  — standard ME7.1 / ME7.5 / ME7.1.1 / ME7.5.5
               b"ZZ\x00\x01"  — ME731 (Alfa Romeo Motronic E7.3.1)
               b"ZZ\x01\x02"  — early/pre-production ME7 (ERCOS V2.x, 1996)
             Anchoring on just b"ZZ" at the fixed offset is safe against
             other Bosch families, but Magneti Marelli ME1.5.5 ECUs also
             place a ZZ ident block at 0x10000 using the format
             "ZZ43/1/ME1.5.5/..." — where the third byte is a printable
             ASCII digit (0x34).  All genuine ME7 variants have a
             non-printable third byte:
               b"ZZ\xff\xff"  — standard ME7.1 / ME7.5 / ME7.1.1 / ME7.5.5
               b"ZZ\x00\x01"  — ME731 (Alfa Romeo Motronic E7.3.1)
               b"ZZ\x01\x02"  — early/pre-production ME7 (ERCOS V2.x, 1996)
             The guard `not (0x20 <= byte3 <= 0x7E)` rejects the Marelli
             format while accepting all known ME7 variants.
          4. Accept PSA ME7 calibration sector (64KB, ZZ at offset 0).
             Single-sector extracts from PSA (Peugeot-Citroën) ME7 ECUs
             (e.g. Peugeot 206 1.6i) where only the calibration sector
             starting at 0x10000 in the full dump was captured.  These
             64KB files begin with the ZZ marker at offset 0 and contain
             the \\xC8-prefixed HW+SW ident block.
          5. Accept PSA ME7.4.x calibration sector (256KB, SW at 0x1A).
             Calibration-only sector dumps from Bosch ME7.4.x PSA-variant
             ECUs (e.g. Peugeot 207 THP 1.6 150HP) where SW is stored at
             a fixed offset 0x1A, preceded by the record marker \\x02\\x00.
        """
        evidence: list[str] = []

        # Phase 0 — size gate: ME7 ZZ ident block lives at 0x10000, so any
        # genuine ME7 binary must be at least 64KB.  Pre-ME7 legacy binaries
        # (M1.x 32KB, M2.x Porsche 964 32KB, M3.x 32KB, KE-Jetronic ≤32KB)
        # are all ≤ 32KB and cannot be ME7.  Rejecting them here prevents the
        # 'MOTRONIC' string in their ident from triggering Phase 2 below.
        if len(data) < ME7_ZZ_OFFSET:  # < 0x10000 = 64KB
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Search the full binary — ME7.6.2 and other large variants place the
        # family string past 512KB, so bounding the search would miss them.
        # The exclusion signatures (EDC17, SB_V, Customer. …) are equally
        # reliable as guards across the full file.
        search_area = data

        # Phase 1 — reject if this is a newer Bosch family
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 2a — accept on specific ME7 family signatures
        # "ME 7." (with space) covers early Volvo ME 7.0 bins where the
        # family token is stored as "ME 7.0" in a Volvo OEM metadata field
        # rather than the standard "ME7.x" format.  These bins (e.g. Volvo
        # S60 2.0T 163HP, 1MB, ~2000 era) lack the ZZ block at 0x10000 and
        # have no MOTRONIC label — this string is the only reliable anchor.
        me7_specific = [b"ME7.", b"ME 7.", b"ME71", b"ME731"]
        if any(sig in search_area for sig in me7_specific):
            evidence.append(FAMILY_STRING)
            self._set_evidence(evidence)
            return True

        # Phase 2b — MOTRONIC label is present, but only accept if ME7 family
        # is also present.  "MOTRONIC" alone appears in other Bosch families
        # (MP9, M1.5.4, etc.) that should not be claimed by this extractor.
        if b"MOTRONIC" in search_area and b"ME7" in search_area:
            evidence.append("MOTRONIC_CONFIRM")
            self._set_evidence(evidence)
            return True

        # Phase 3 — accept on ZZ prefix at its fixed ident-block offset only.
        # Guard: the byte immediately after "ZZ" must be non-printable ASCII.
        # All real ME7 variants use \xff, \x00, or \x01 at that position.
        # Magneti Marelli ME1.5.5 ECUs also have "ZZ" at 0x10000 but follow
        # it with printable digits ("ZZ43/1/ME1.5.5/...") — those must not
        # be claimed here.
        if len(data) > ME7_ZZ_OFFSET + len(ME7_ZZ_PREFIX) + 1:
            if data[
                ME7_ZZ_OFFSET : ME7_ZZ_OFFSET + len(ME7_ZZ_PREFIX)
            ] == ME7_ZZ_PREFIX and not (
                0x20 <= data[ME7_ZZ_OFFSET + len(ME7_ZZ_PREFIX)] <= 0x7E
            ):
                evidence.append("ZZ_MARKER")
                self._set_evidence(evidence)
                return True

        # Phase 4 — PSA ME7 calibration sector (64KB, ZZ at offset 0).
        # These are single-sector dumps from PSA ME7 ECUs where the
        # calibration sector (normally at 0x10000 in a full dump) was
        # extracted as a standalone 64KB file.  The ZZ marker appears at
        # offset 0 rather than 0x10000.
        if self._is_psa_sector_64kb(data):
            evidence.append("PSA_SECTOR_64KB")
            self._set_evidence(evidence)
            return True

        # Phase 5 — PSA ME7.4.x calibration sector (256KB, SW at 0x1A).
        # PSA-variant ME7.4 ECUs store SW at a fixed offset in 256KB
        # calibration-only sector dumps.  Must not be M5.x/M3.8x —
        # those also use 256KB but have MOTR + slash ident (already
        # excluded: MOTRONIC in Phase 2, M5./M3.8 not in excl but M5x
        # extractor picks them up via MOTR anchor and size gate).
        if self._is_psa_sector_256kb(data):
            evidence.append("PSA_SECTOR_256KB")
            self._set_evidence(evidence)
            return True

        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch ME7 ECU binary.

        Dispatches to:
          - _extract_psa_sector_256kb() for PSA ME7.4.x 256KB sector dumps
            (SW at fixed offset 0x1A, no ZZ, no MOTRONIC).
          - _extract_early() for pre-production ERCOS binaries
            (ZZ\x01\x02 at 0x10000).
          - Standard production path for all other ME7 variants.

        The PSA 64KB sector format (ZZ at offset 0) uses the standard
        production path because hw_sw_combined in the "extended" region
        already covers the full 64KB file and finds HW+SW correctly.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Dispatch: PSA ME7.4.x 256KB calibration sector ---
        # Must be checked before the early ME7 path — completely different
        # header format (no ZZ ident block, SW at 0x1A, PowerPC header).
        if self._is_psa_sector_256kb(data):
            return self._extract_psa_sector_256kb(data, result)

        # --- Dispatch: early pre-production vs standard production ---
        if self._is_early_me7(data):
            return self._extract_early(data, result)

        # --- Step 1: Raw ASCII strings from ident block ---
        raw_strings = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_block"],
            min_length=8,
            max_results=20,
        )
        result["raw_strings"] = raw_strings

        # --- Step 2: Run all patterns against their assigned regions ---
        raw_hits = self._run_patterns(data)

        # --- Step 2b: Full-file fallback for large / atypical ME7 binaries ---
        # ME7.6.2 (Opel Corsa D, 832KB) and similar variants store the ident
        # block past the normal extended search window (0x00000–0x50000).
        # When the combined HW+SW block and the family string are both absent
        # from the standard regions, retry with a full-file scan so these bins
        # still yield correct hw, sw, and ecu_family values.
        if not raw_hits.get("hw_sw_combined") and not raw_hits.get("hardware_number"):
            full_hw_sw = [
                m.group(0).decode("ascii", errors="ignore")
                for m in re.finditer(PATTERNS["hw_sw_combined"], data)
            ]
            if full_hw_sw:
                raw_hits["hw_sw_combined"] = full_hw_sw

        if not raw_hits.get("ecu_family"):
            full_fam = [
                m.group(0).decode("ascii", errors="ignore")
                for m in re.finditer(PATTERNS["ecu_family"], data)
            ]
            if full_fam:
                raw_hits["ecu_family"] = full_fam

        # Inject raw_strings into raw_hits so resolvers can access them
        # without needing a separate parameter on every method.
        raw_hits["_raw_strings"] = raw_strings

        # --- Step 3: Resolve ECU family ---
        ecu_family = self._resolve_ecu_family(raw_hits)
        result["ecu_family"] = ecu_family

        # --- Step 4: ME7 has no separate ecu_variant (family IS the variant) ---
        result["ecu_variant"] = ecu_family

        # --- Step 5: Resolve hardware number ---
        hardware_number = self._resolve_hardware_number(raw_hits)
        result["hardware_number"] = hardware_number

        # --- Step 6: Resolve software version ---
        software_version = self._resolve_software_version(raw_hits)
        result["software_version"] = software_version

        # --- Step 7: Resolve calibration ID ---
        result["calibration_id"] = self._resolve_calibration_id(raw_hits)

        # --- Step 8: Resolve OEM part number ---
        oem_part_number = self._resolve_oem_part_number(raw_hits)
        result["oem_part_number"] = oem_part_number

        # --- Step 9: Fields not present in ME7 binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 10: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,  # same for ME7
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — PSA ME7 sector detection helpers
    # -----------------------------------------------------------------------

    # Pattern for 64KB PSA ME7 calibration sector: \xC8-prefixed HW+SW block.
    # The \xC8 byte immediately precedes the HW number in PSA sector dumps.
    # e.g. b"\xC8 0261206942\x00 1037353507\x00"
    _PSA_SECTOR_64KB_PAT: bytes = rb"\xc8(0261\d{6})\x00(1037\d{6})"

    def _is_psa_sector_64kb(self, data: bytes) -> bool:
        """
        Return True if this is a 64KB PSA ME7 calibration sector extract.

        These are single-sector dumps from PSA (Peugeot-Citroën) ME7 ECUs
        (e.g. Peugeot 206 1.6i 16v, HW 0261206xxx / 0261208xxx) where only
        the calibration sector — which sits at 0x10000 in a full dump — was
        captured as a standalone file.

        Fingerprint (all three must be true):
          1. Size = 64KB (0x10000) exactly.
          2. ZZ marker at offset 0x0 with non-printable third byte.
          3. \\xC8-prefixed HW+SW pattern found anywhere in the file.
        """
        if len(data) != 0x10000:
            return False
        if data[:2] != ME7_ZZ_PREFIX:
            return False
        if len(data) < 3 or (0x20 <= data[2] <= 0x7E):  # third byte non-printable
            return False
        return bool(re.search(self._PSA_SECTOR_64KB_PAT, data))

    def _is_psa_sector_256kb(self, data: bytes) -> bool:
        """
        Return True if this is a 256KB PSA ME7.4.x calibration sector dump.

        These are calibration-only sector dumps from Bosch ME7.4.x PSA-variant
        ECUs (e.g. Peugeot 207 THP 1.6 150HP, Bosch ME7.4.5/ME7.4.6).  The
        file contains only calibration table data with a compact header — no
        ZZ marker, no MOTRONIC label, no HW number.

        The SW version is stored as plain ASCII at the fixed offset 0x1A,
        preceded by the two-byte record marker \\x02\\x00 at offset 0x18.

        Fingerprint (all three must be true):
          1. Size = 256KB (0x40000) exactly.
          2. \\x02\\x00 at offset 0x18 (record marker).
          3. Valid 1037-prefixed 10-digit SW at offset 0x1A.
        """
        if len(data) != 0x40000:
            return False
        if data[0x18:0x1A] != b"\x02\x00":
            return False
        return bool(re.match(rb"1037\d{6}", data[0x1A : 0x1A + 10]))

    def _extract_psa_sector_256kb(self, data: bytes, result: Dict) -> Dict:
        """
        Extract identifying information from a 256KB PSA ME7.4.x calibration sector.

        These Bosch ME7.4.x PSA-variant binaries (e.g. Peugeot 207 THP 1.6
        150HP) store the SW version at a fixed offset 0x1A in the file header.
        No HW number, no slash-delimited variant string, and no MOTRONIC label
        are present — the file is a pure calibration sector dump with a compact
        PowerPC-style header.

        Header layout (first 0x30 bytes):
          0x00–0x0F  : PowerPC code / address words (non-printable)
          0x10–0x17  : Additional header words
          0x18–0x19  : Record marker \\x02\\x00
          0x1A–0x23  : SW version ASCII "1037XXXXXX" (10 bytes)
          0x24–…     : \\xAF fill bytes then calibration table data

        Fields populated:
          ecu_family      = "ME7"
          ecu_variant     = "ME7"
          software_version = 10-digit string extracted from offset 0x1A
          hardware_number  = None (not present in this format)
          match_key        = "ME7::1037XXXXXX"
        """
        ecu_family = "ME7"

        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=slice(0x0000, 0x0100),
            min_length=8,
            max_results=10,
        )

        result["ecu_family"] = ecu_family
        result["ecu_variant"] = ecu_family

        # SW version is plain ASCII at the fixed offset 0x1A.
        sw_raw = data[0x1A : 0x1A + 10]
        try:
            sw_candidate = sw_raw.decode("ascii")
            software_version = (
                sw_candidate if re.match(r"^1037\d{6}$", sw_candidate) else None
            )
        except (UnicodeDecodeError, ValueError):
            software_version = None

        result["software_version"] = software_version
        result["hardware_number"] = None
        result["calibration_id"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["oem_part_number"] = None

        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — early ME7 detection and extraction
    # -----------------------------------------------------------------------

    # ZZ variant byte pair that marks an early/pre-production ME7 binary.
    # Standard production is ZZ\xff\xff; ME731 Alfa is ZZ\x00\x01.
    _EARLY_ZZ_MARKER: bytes = b"ZZ\x01\x02"

    # ERCOS RTOS version string — present at 0x200 in all known early bins.
    # Used as a secondary confirmation gate (belt-and-suspenders with ZZ\x01\x02).
    _ERCOS_ANCHOR: bytes = b"ERCOS"

    # Offset where ERCOS string lives in early ME7 binaries.
    _ERCOS_OFFSET: int = 0x200

    # Early ECU label pattern:
    #   group 1 — VAG OEM part number  e.g. "8D0907551"
    #   group 2 — engine descriptor    e.g. "2,7l V6/5VT"  (informational)
    #   group 3 — revision code        e.g. "D04"  (used as software_version)
    # Terminated by \x80 or \x00 (field separator in early EPROM layout).
    _EARLY_LABEL_RE = re.compile(
        rb"([0-9][A-Z0-9]{8,11})"  # OEM part number (9–12 chars)
        rb"\s{2,}"  # 2+ separator spaces
        rb"([\w,\./]+(?:\s[\w/]+)*)"  # engine descriptor
        rb"\s{3,}"  # 3+ separator spaces
        rb"([A-Z]\d{2})"  # revision code  e.g. D04
        rb"[\x80\x00]",  # field terminator
    )

    def _is_early_me7(self, data: bytes) -> bool:
        """
        Return True if this is a pre-production ME7 binary (ERCOS / ZZ\x01\x02).

        Two independent conditions must both be true — belt-and-suspenders so
        that a coincidental ZZ\x01\x02 at 0x10000 in an unrelated binary never
        triggers the early path:

          1. ZZ\x01\x02 at the fixed ident-block offset 0x10000.
          2. The ERCOS RTOS string is present at 0x200.

        Neither condition alone is sufficient:
          - ZZ\x01\x02 at 0x10000 could theoretically appear in calibration
            data of some other binary.
          - ERCOS could in principle appear in a non-ME7 binary (unlikely but
            possible in a raw flash image containing OS code).
        Together they form an unambiguous fingerprint for this ECU generation.
        """
        if len(data) <= ME7_ZZ_OFFSET + 4:
            return False
        if data[ME7_ZZ_OFFSET : ME7_ZZ_OFFSET + 4] != self._EARLY_ZZ_MARKER:
            return False
        if len(data) <= self._ERCOS_OFFSET + len(self._ERCOS_ANCHOR):
            return False
        if (
            data[self._ERCOS_OFFSET : self._ERCOS_OFFSET + len(self._ERCOS_ANCHOR)]
            != self._ERCOS_ANCHOR
        ):
            return False
        return True

    def _extract_early(self, data: bytes, result: Dict) -> Dict:
        """
        Extract identifying information from a pre-production ME7 binary.

        These binaries (ERCOS V2.x, ~1996) predate the standard production
        ident block format.  There is no slash-delimited variant string and
        no 0261/1037 HW+SW block.  The only structured identifier is the
        early ECU label:

            "<oem_part>   <engine_desc>   <rev_code>\x80\x80"
            e.g. "8D0907551   2,7l V6/5VT         D04\x80\x80"

        Fields populated:
            ecu_family       = "ME7early"
            ecu_variant      = "ME7early"
            oem_part_number  = VAG part number from label  e.g. "8D0907551"
            software_version = revision code from label    e.g. "D04"
            hardware_number  = None  (not present in this format)
            calibration_id   = None  (not present in this format)

        The match_key is built from ecu_family + software_version using the
        standard base-class builder:  "ME7EARLY::D04"

        This method is completely self-contained — it never calls any of the
        production resolvers (_resolve_ecu_family, _resolve_hardware_number,
        etc.) so there is zero risk of cross-contamination with the
        production extraction path.
        """
        ecu_family = "ME7early"

        # Raw strings from ident block — informational, stored for debugging.
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["ident_block"],
            min_length=8,
            max_results=20,
        )

        result["ecu_family"] = ecu_family
        result["ecu_variant"] = ecu_family

        # Search the ident block (0x10000–0x20000) for the early label.
        # The label is always within this region in known binaries.
        ident_block = data[0x10000:0x20000] if len(data) >= 0x20000 else data[0x10000:]
        m = self._EARLY_LABEL_RE.search(ident_block)

        if m:
            oem_part = m.group(1).decode("ascii", errors="ignore").strip()
            software_version = m.group(3).decode("ascii", errors="ignore").strip()
        else:
            oem_part = None
            software_version = None

        result["oem_part_number"] = oem_part
        result["software_version"] = software_version
        result["hardware_number"] = None  # not present in early format
        result["calibration_id"] = None  # not present in early format
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — pattern runner
    # -----------------------------------------------------------------------

    def _run_patterns(self, data: bytes) -> Dict[str, List[str]]:
        """
        Run all ME7 patterns against their assigned search regions.
        Delegates to the shared engine on BaseManufacturerExtractor.
        """
        return self._run_all_patterns(data, PATTERNS, PATTERN_REGIONS, SEARCH_REGIONS)

    # -----------------------------------------------------------------------
    # Internal — field resolvers
    # -----------------------------------------------------------------------

    def _resolve_ecu_family(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the ECU family string: e.g. "ME7.1", "ME7.5", "ME7.1.1", "ME71".

        Priority:
          1. Extract from the authoritative variant string (most reliable).
             The family is always the 3rd slash-delimited field.
             e.g. "44/1/ME7.1.1/120/..." -> "ME7.1.1"
          2. Fall back to bare ecu_family regex hits.
          3. Return "ME7" as a last-resort fallback — can_handle() already
             confirmed this is an ME7 binary, so "ME7" is always correct
             even when the specific variant string is absent or unreadable
             (e.g. Citroen C2 1.6 VTS bins where no ASCII family token exists).
        """
        # Priority 1 — authoritative variant string
        if "ecu_variant_string" in raw_hits:
            for variant_str in raw_hits["ecu_variant_string"]:
                parts = variant_str.split("/")
                if len(parts) >= 3:
                    candidate = parts[2].strip()
                    # Must look like ME7x or ME7.x
                    if re.match(r"^ME7[\d\.]*\d$", candidate, re.IGNORECASE):
                        return candidate

        # Priority 2 — bare regex hit
        if "ecu_family" in raw_hits:
            return raw_hits["ecu_family"][0].rstrip(".-_")

        # Priority 3 — last resort: can_handle() guarantees ME7, so "ME7" is
        # always a valid family name even without a readable family string.
        return "ME7"

    def _resolve_hardware_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the hardware part number (e.g. "0261207881").

        ME7 hardware numbers are always exactly 10 digits starting with "0261".

        Priority:
          1. Combined HW+SW block — group 1 of hw_sw_combined match.
             This is the most reliable source: the HW and SW are stored
             adjacent with no separator so there is no ambiguity.
          2. Standalone hardware_number regex hit — fallback for the rare
             bins where the numbers are stored separately.
        """
        # Priority 1 — combined block (group 1 = HW)
        combined_hits = raw_hits.get("hw_sw_combined")
        if combined_hits:
            # Each hit is stored as "HW[optional-null]SW" — strip null and split
            for hit in combined_hits:
                clean = hit.replace("\x00", "")
                m = re.match(r"^(0261\d{6})\s*((?:1037|1277)\d{6,10})$", clean)
                if m:
                    return m.group(1)

        # Priority 2 — standalone hardware_number hit
        hits = raw_hits.get("hardware_number")
        return hits[0] if hits else None

    def _resolve_software_version(
        self, raw_hits: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Resolve the software version string (e.g. "1037368072", "10373686044").

        All ME7 SW versions start with "1037" and are 10–11 digits total.
        ME7.3 Italian variants (Ferrari, possibly Alfa Romeo/Maserati) use
        the "1277" prefix instead of "1037".

        Priority:
          1. Combined HW+SW block — group 2 of hw_sw_combined match.
             Unambiguous because it is always immediately after the HW number.
          2. Standalone software_version regex hit — fallback.

        If multiple candidates exist, prefer the longest (extended form).
        Rejects any hit that is all-zeros.
        """
        candidates: List[str] = []

        # Priority 1 — combined block (group 2 = SW)
        combined_hits = raw_hits.get("hw_sw_combined")
        if combined_hits:
            for hit in combined_hits:
                clean = hit.replace("\x00", "")
                m = re.match(r"^(0261\d{6})\s*((?:1037|1277)\d{6,10})$", clean)
                if m:
                    sw = m.group(2)
                    if sw not in candidates:
                        candidates.append(sw)

        # Priority 2 — standalone software_version hits
        sw_hits = raw_hits.get("software_version", [])
        for h in sw_hits:
            if not re.match(r"^0+$", h) and h not in candidates:
                candidates.append(h)

        if not candidates:
            return None

        # Prefer the shortest valid form — the 10-digit standard "1037xxxxxx"
        # is always authoritative.  Longer candidates (e.g. "10373687720000")
        # are artifacts of null-byte padding being counted as digit characters
        # by the standalone regex; the combined-block hit is always exact.
        return min(candidates, key=len)

    def _resolve_calibration_id(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the calibration ID (e.g. "6428.AA", "4013.00", "C1105N").

        Priority:
          1. Extract from the authoritative variant string (5th slash field).
          2. Fall back to the bare calibration_id pattern hits.
        """
        # Priority 1 — parse from variant string
        if "ecu_variant_string" in raw_hits:
            for variant_str in raw_hits["ecu_variant_string"]:
                parts = variant_str.split("/")
                # Variant string format: rev/unk/family/dataset/cal_id//...
                # cal_id is the 5th field (index 4)
                if len(parts) >= 5:
                    candidate = parts[4].strip()
                    if candidate and len(candidate) >= 4:
                        return candidate

        # Priority 2 — bare pattern hit
        return self._first_hit(raw_hits, "calibration_id")

    def _resolve_oem_part_number(self, raw_hits: Dict[str, List[str]]) -> Optional[str]:
        """
        Resolve the OEM (VAG) part number.

        Priority:
          1. Extract from MOTRONIC label — most reliable source.
             The VAG part number is always the first token before "MOTRONIC".
             e.g. "022906032CS MOTRONIC ME7.1.1    0006" -> "022906032CS"
          2. Extract from the non-MOTRONIC ECU label used by some ME7.5 bins.
             Format: "<part>   <engine-desc>   <rev>"
             e.g. "4B0906018AR 1.8L R4/5VT         0006" -> "4B0906018AR"
             The part number must contain at least one letter — this filters
             out all-digit garbage matches from calibration table data.
          3. Fall back to standalone vag_part_number hits, filtered to only
             accept strings that look like real VAG part numbers:
             - Must contain at least one letter (not all-numeric)
             - Must not consist of a single repeated digit (e.g. "833333333")
             - Must be at least 9 characters long
        """
        # Priority 1 — MOTRONIC label
        if "motronic_label" in raw_hits:
            for label in raw_hits["motronic_label"]:
                match = re.match(r"^([0-9][0-9A-Z]{7,13})\s+MOTRONIC", label)
                if match:
                    return match.group(1)

        # Priority 2 — non-MOTRONIC ECU label (ME7.5 style)
        # These bins use a label like "4B0906018AR 1.8L R4/5VT  0006"
        # The raw_strings from the ident block are the best source here.
        raw_strings = raw_hits.get("_raw_strings", [])
        for s in raw_strings:
            # Must start with a digit, have 9–14 alphanumeric chars before whitespace,
            # and contain at least one letter (so it's a real part number, not data)
            m = re.match(r"^([0-9][0-9A-Z]{8,13})\s", s)
            if m:
                candidate = m.group(1)
                if any(c.isalpha() for c in candidate):
                    return candidate

        # Priority 3 — standalone VAG part number, filtered
        for hit in raw_hits.get("vag_part_number", []):
            # Must contain at least one letter
            if not any(c.isalpha() for c in hit):
                continue
            # Must not be a single repeated digit pattern (e.g. "833333333")
            if re.match(r"^(\d)\1{5,}$", hit):
                continue
            # Must be at least 9 characters
            if len(hit) < 9:
                continue
            return hit

        return None
