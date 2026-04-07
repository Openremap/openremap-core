"""
Bosch Motronic M4.x ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch Motronic M4.x family:
  M4.3   — Volvo 850 / 960 / S70 / V70 petrol ECUs (1994–1998), 64KB dumps
  M4.4   — Volvo S60 / S70 / V70 / S80 petrol ECUs (1998–2002), 128KB dumps

These are Motorola 68xxx-based ECUs used almost exclusively in Volvo vehicles
of the 1990s and early 2000s.  The binary layout is related to other early
Bosch Motronic families but with key structural differences:

  - NO ZZ\\xff\\xff ident block (that is ME7-specific)
  - NO MOTRONIC label (M5.x / ME7 / MP9 territory)
  - NO reversed-digit ident encoding (M1.x / M3.x reverse HW and SW digits)
  - Family marker is M4.3 or M4.4 inside a DAMOS slash-delimited descriptor
    string (e.g. "44/1/M4.3/09/5033/DAMOS0C03//040398/")
  - HW and SW are encoded in SEQUENTIAL (direct) digit order in a contiguous
    ident digit run in the last ~8 KB of the binary — NOT reversed like M3.x

Binary sizes:
  0x10000 (64KB)  — M4.3 (Volvo 850, 960 era)
  0x20000 (128KB) — M4.4 (Volvo S60, S70, V70, S80 era)

Ident digit run format (SEQUENTIAL — not reversed):

  The ident block is a contiguous run of 20–50 ASCII digit bytes located in
  the last ~8 KB of the file, optionally followed by a ".NN" two-digit suffix.

    digits[0:10]  = hardware_number   (starts with "0261")
    digits[10:20] = software_version  (starts with "1037", "1267", or "2227")
    digits[20:]   = calibration / dataset extra digits (variable length)

  Example (M4.3, 64KB):
    Digit run: "026120422510373552771270544"
    HW = "0261204225"
    SW = "1037355277"
    calibration_id = "1270544"

  Example (M4.4, 128KB):
    Digit run: "026120423910373557801280422"
    HW = "0261204239"
    SW = "1037355780"
    calibration_id = "1280422"

DAMOS descriptor format (slash-delimited, located anywhere in the binary):

  "NN/N/M4.X/VV/DDDD/DAMOSxx/.../DDMMYY/"

  Fields:
    [0] revision    e.g. "44"
    [1] sub         e.g. "1"
    [2] family      e.g. "M4.3" or "M4.4"   ← ecu_family
    [3] version     e.g. "09"
    [4] dataset     e.g. "5033"              ← dataset_number
    [5] DAMOS label e.g. "DAMOS0C03"
    ...

Detection strategy:

    Phase 1 — Reject on any exclusion signature in the binary.
    Phase 2 — Reject if file size is not exactly 64 KB or 128 KB.
    Phase 3 — Accept if "/M4.3/" or "/M4.4/" DAMOS family token is found.
    Phase 4 — Accept if a valid sequential ident digit run (20+ digits,
              HW starts "0261", SW starts with valid prefix) is found in
              the last ~8 KB.
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    EXCLUSION_CLEAR,
    FAMILY_STRING,
    IDENT_BLOCK,
    SIZE_MATCH,
)
from openremap.core.manufacturers.bosch.m4x.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    SUPPORTED_SIZES,
    VALID_SW_PREFIXES,
)

# ---------------------------------------------------------------------------
# Pre-compiled patterns (module-level for speed)
# ---------------------------------------------------------------------------

# Ident digit run — 20-50 contiguous ASCII digits, optional .NN suffix.
# Lookbehind/lookahead ensure we match the full standalone run, not a
# substring of a longer numeric sequence.
_IDENT_DIGIT_RE = re.compile(rb"(?<!\d)\d{20,50}(?:\.\d{2})?(?!\d)")

# DAMOS descriptor — captures family and dataset from the slash-delimited
# string.  e.g. "44/1/M4.3/09/5033/DAMOS0C03//040398/"
#   group 1 = family  (M4.3 or M4.4)
#   group 2 = dataset (3-6 digit code)
_DAMOS_RE = re.compile(rb"\d{1,3}/\d+/(M4\.\d)/(\d{1,3})/(\d{3,6})")

# Full DAMOS string — used for raw metadata capture.
_DAMOS_FULL_RE = re.compile(rb"\d{1,3}/\d+/M4\.\d/[^\x00\xff\r\n]{5,150}")


class BoschM4xExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch Motronic M4.x ECU binaries (Volvo 850 / 960 / S-V70).

    Handles:
      - M4.3  (64KB,  Volvo 850/960 era, 1994–1998)
      - M4.4  (128KB, Volvo S60/S70/V70/S80 era, 1998–2002)

    Key insight — HW and SW are encoded in SEQUENTIAL digit order (direct),
    which is the opposite of the M1.x / M3.x families that use reversed digits:
        ident_clean = digit_run.split('.')[0]
        hw = ident_clean[0:10]    # first 10 digits → 0261xxxxxx
        sw = ident_clean[10:20]   # next  10 digits → 1037xxxxxx / 1267xxxxxx / 2227xxxxxx
        cal = ident_clean[20:]    # remainder        → calibration / dataset extra

    The match_key fallback mechanism is enabled: when software_version is
    absent (unusual but possible for corrupted or partial dumps), the
    calibration_id is used as the version component of the match key.
    """

    # Opt-in fallback — use calibration_id when software_version is absent.
    match_key_fallback_field: Optional[str] = "calibration_id"
    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["M4.3", "M4.4"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch Motronic M4.x family ECU.

        Four-phase check:

          Phase 1 — Reject if file size is not exactly 64 KB or 128 KB.
                    M4.3 is always 64 KB; M4.4 is always 128 KB.

          Phase 2 — Accept if a DAMOS family token ("/M4.3/" or "/M4.4/")
                    is found anywhere in the binary.  These slash-delimited
                    tokens are unique to M4.x and never appear in any other
                    known Bosch family.  This is the highest-confidence
                    positive signal and takes priority over exclusion checks,
                    because coincidental byte sequences (e.g. ZZ\\xff\\xff in
                    calibration table data) can produce false exclusions on
                    genuine M4.x bins.

          Phase 3 — Reject on any exclusion signature in the first 512 KB.
                    Guards against claiming ME7, EDC15, EDC16, EDC17 bins
                    and other Motronic families (M5.x, M3.x, MP9, etc.).
                    Only applies to the fallback detection path (Phase 4)
                    since DAMOS-detected bins are already accepted.

          Phase 4 — Fallback: accept if a valid sequential ident digit run
                    is found in the last ~8 KB.  The run must be ≥ 20 digits,
                    with the first 10 digits starting with "0261" (Bosch HW
                    prefix) and the next 10 starting with a recognised SW
                    prefix ("1037", "1267", "2227", or "2537").
        """
        evidence: list[str] = []

        # Phase 1 — size gate (cheapest check)
        if len(data) not in SUPPORTED_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 2 — DAMOS family token (definitive positive — overrides
        # exclusions because tokens like ZZ\xff\xff can false-match in
        # M4.x calibration table data)
        if any(sig in data for sig in DETECTION_SIGNATURES):
            evidence.append(FAMILY_STRING)
            self._set_evidence(evidence)
            return True

        # Phase 3 — exclusion check (only for fallback detection path)
        search_area = data[:0x80000]  # first 512 KB — covers full file
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 4 — sequential ident digit run in last ~8 KB
        tail = data[-0x2000:]
        m = _IDENT_DIGIT_RE.search(tail)
        if m:
            raw = m.group(0).decode("ascii", errors="ignore")
            digits = raw.split(".")[0]
            # Handle leading prefix digits before the 0261 HW start
            if not digits.startswith("0261"):
                idx = digits.find("0261")
                if 0 < idx <= 4:
                    digits = digits[idx:]
            if len(digits) >= 20:
                hw_candidate = digits[0:10]
                sw_candidate = digits[10:20]
                if hw_candidate.startswith("0261") and sw_candidate.startswith(
                    VALID_SW_PREFIXES
                ):
                    evidence.append(IDENT_BLOCK)
                    self._set_evidence(evidence)
                    return True

        self._set_evidence()
        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch M4.x ECU binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from the last ~8 KB ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=slice(-0x2000, None),
            min_length=8,
            max_results=20,
        )

        # --- Step 2: Parse ident digit run (HW + SW + calibration) ---
        hardware_number, software_version, calibration_id = self._parse_ident_digits(
            data
        )
        result["hardware_number"] = hardware_number
        result["software_version"] = software_version
        result["calibration_id"] = calibration_id

        # --- Step 3: Resolve ECU family ---
        ecu_family = self._resolve_ecu_family(data)
        result["ecu_family"] = ecu_family
        result["ecu_variant"] = ecu_family  # M4.x has no separate variant

        # --- Step 4: Resolve dataset number from DAMOS descriptor ---
        result["dataset_number"] = self._resolve_dataset_number(data)

        # --- Step 5: Fields not present in M4.x binaries ---
        result["oem_part_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None

        # --- Step 6: Build compound match key ---
        result["match_key"] = self.build_match_key(
            ecu_family=ecu_family,
            ecu_variant=ecu_family,
            software_version=software_version,
            fallback_value=calibration_id,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — ident digit run parser
    # -----------------------------------------------------------------------

    def _parse_ident_digits(
        self, data: bytes
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse the contiguous digit run from the ident block.

        Search strategy:
          1. Search the last ~8 KB first (standard M4.x ident location).
          2. If no valid ident found, fall back to searching the full binary.
             This handles edge-case M4.4 bins where the ident block is at an
             early offset (e.g. mirrored 64KB layout in a 128KB chip).

        The M4.x ident block stores HW and SW in SEQUENTIAL (direct) order —
        NOT reversed like the M1.x / M3.x families:

            digits[0:10]  → hardware_number  (must start with "0261")
            digits[10:20] → software_version (must start with recognised prefix)
            digits[20:]   → calibration extra digits (variable length, may be empty)

        An optional ".NN" two-digit suffix is stripped before parsing.

        Returns:
            (hardware_number, software_version, calibration_id) — any may be None.
        """
        # Try last ~8 KB first (standard location)
        result = self._try_parse_ident_from_region(data[-0x2000:])
        if result is not None:
            return result

        # Fallback: search the full binary for a valid ident digit run.
        # Iterate all matches and return the first that passes validation.
        for m in _IDENT_DIGIT_RE.finditer(data):
            result = self._validate_ident_match(m)
            if result is not None:
                return result

        return None, None, None

    def _try_parse_ident_from_region(
        self, region: bytes
    ) -> Optional[tuple[Optional[str], Optional[str], Optional[str]]]:
        """
        Search a byte region for the first valid ident digit run.

        Returns (hw, sw, cal) if found, or None if no valid match.
        """
        m = _IDENT_DIGIT_RE.search(region)
        if not m:
            return None
        return self._validate_ident_match(m)

    def _validate_ident_match(
        self, m: re.Match[bytes]
    ) -> Optional[tuple[Optional[str], Optional[str], Optional[str]]]:
        """
        Validate and parse a single ident digit regex match.

        Returns (hw, sw, cal) if valid, or None if the match fails validation.
        """
        raw = m.group(0).decode("ascii", errors="ignore").strip()

        # Strip optional .NN suffix
        ident_clean = raw.split(".")[0]

        # Handle leading prefix digits before the 0261 HW start
        if not ident_clean.startswith("0261"):
            idx = ident_clean.find("0261")
            if idx > 0 and idx <= 4:
                ident_clean = ident_clean[idx:]
            else:
                return None

        if len(ident_clean) < 20:
            return None

        hw = ident_clean[0:10]
        sw = ident_clean[10:20]
        extra = ident_clean[20:] if len(ident_clean) > 20 else None

        # Validate HW — must be all digits starting with "0261"
        if not hw.isdigit() or not hw.startswith("0261"):
            return None

        # Validate SW — must be all digits starting with a recognised prefix
        if not sw.isdigit() or not sw.startswith(VALID_SW_PREFIXES):
            return None

        # Validate extra — only return if non-empty and all digits
        if extra is not None and (not extra or not extra.isdigit()):
            extra = None

        return hw, sw, extra

    # -----------------------------------------------------------------------
    # Internal — ECU family resolution
    # -----------------------------------------------------------------------

    def _resolve_ecu_family(self, data: bytes) -> Optional[str]:
        """
        Determine the M4.x sub-family for this binary.

        Priority:
          1. DAMOS descriptor family field (most authoritative):
             Searches the full binary for the DAMOS slash-delimited string
             containing "M4.3" or "M4.4" and extracts the family token.

          2. File-size heuristic (fallback when DAMOS is absent):
             64 KB  → M4.3  (all known M4.3 dumps are exactly 64 KB)
             128 KB → M4.4  (all known M4.4 dumps are exactly 128 KB)

        Returns the family string ("M4.3" or "M4.4"), or None if neither
        detection path succeeds.
        """
        # Priority 1 — DAMOS descriptor
        m = _DAMOS_RE.search(data)
        if m:
            family = m.group(1).decode("ascii", errors="ignore").strip()
            if family:
                return family

        # Priority 2 — file-size heuristic
        if len(data) == 0x10000:
            return "M4.3"
        if len(data) == 0x20000:
            return "M4.4"

        return None

    # -----------------------------------------------------------------------
    # Internal — dataset number resolution
    # -----------------------------------------------------------------------

    def _resolve_dataset_number(self, data: bytes) -> Optional[str]:
        """
        Resolve the dataset number from the DAMOS descriptor.

        The dataset code is the third slash-delimited field after the family
        marker in the DAMOS string:

            "44/1/M4.3/09/**5033**/DAMOS0C03/..."
                              ^^^^
                          dataset_number

        Returns the dataset code string, or None if not found.
        """
        m = _DAMOS_RE.search(data)
        if not m:
            return None

        dataset = m.group(3).decode("ascii", errors="ignore").strip()
        if dataset and not re.match(r"^0+$", dataset):
            return dataset

        return None
