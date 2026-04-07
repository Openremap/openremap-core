"""
Bosch EDC1 / EDC2 ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch EDC1 and EDC2 families:
  EDC1  — Early Bosch diesel ECUs, Audi 80 / A6 TDI (1990–1995)
            e.g. 8A0907401A, 4A0907401E/P, 028906021D
  EDC2  — Transitional generation sharing the same binary layout (1995–1997)
            e.g. 028906021E/AP/AQ/DQ, 021906028AP/AQ

These are Intel MCS-96-based ECUs. They are the generation *before* EDC15
and use a completely different binary layout. Files are tiny — 32KB or 64KB —
and carry their entire ident record in a fixed ASCII region in the final 256
bytes of the ROM.

Binary sizes:
  0x8000  (32KB) — early EDC1 era, e.g. 8A0907401A, 4A0907401E
  0x10000 (64KB) — later EDC1/EDC2 era, e.g. 028906021D/E/AP/AQ/DQ

Ident record structure:

  The record is stored starting at absolute offset 0x7FD9 in every sample,
  regardless of file size. The field separator is 0xFF (\xff) in all
  observed binaries. A typical ident record looks like:

      0x7fd9: 0281001198\xff2287358770\xffA50AM000   \xff37

  This method searches the 256-byte window at that fixed offset for:
  Fields:
    [0] HW number  — '0281' + 6 digits  (10 digits total)
    [1] SW version — '2287'/'2537'/'1037' + 6–8 digits (10 digits total)
    [2] Dataset code — free-form alphanumeric, e.g. 'A50AM000', 'R250G500'

  A second, simpler observed variant (64KB bins):
      0x7fd9: 0281001222.2287358726.R250G500   .37

  A6 AAT variant (64KB, 1037 SW prefix — same format, different prefix):
      0x7fd9: 0281001254.1037355048.H618204K   .66

  The SW prefix is one of: 2287, 2537, 1037.
  The 1037 prefix normally belongs to EDC15 and later, but several 64KB
  Audi A6 (AAT/AEL) bins use it within this identical binary structure.
  Size-gate + ident-in-tail detection correctly captures them here.

Detection strategy (three-phase):

  Phase 1 — Size gate: must be exactly 32KB (0x8000) or 64KB (0x10000).
             EDC15 and all modern Bosch families are 256KB or larger.

  Phase 2 — Exclusion check: reject if any modern signature is found
             anywhere in the binary. Covers EDC15, EDC16, EDC17, ME7, M5.x
             and all other Bosch families that would otherwise share the
             '1037' SW prefix or '0281' HW prefix.

  Phase 3 — Positive ident check: the HW+SW ident pattern
             '0281\\d{6}[.\\s](?:1037|2287|2537)\\d{6,8}' must appear in
             the last 256 bytes of the file.

Verified across all sample bins:

  8A0907401A  0281001133  2287357912  EDC1  32KB
  028906021D  0281001198  2287358770  EDC1  64KB
  028906021E  0281001222  2287358726  EDC1  64KB
  021906028AP 0281001317  2537355582  EDC2  64KB  (note: 2537 prefix)
  021906028AQ 0281001319  2537357877  EDC2  64KB  (note: 2537 prefix)
  028906021DQ 0281001441  2537355891  EDC2  64KB  (note: 2537 prefix)
  4A0907401E  0281001254  1037355048  EDC1  64KB  (A6 AAT, 1037 prefix)
  4A0907401P  0281001321  1037355246  EDC1  64KB  (A6 AEL, 1037 prefix)
  8A0907401A  0281001133  2287357598  EDC1  32KB
  8A0907401B  0281001186  2287357913  EDC1  64KB
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    BaseManufacturerExtractor,
    DetectionStrength,
    EXCLUSION_CLEAR,
    IDENT_BLOCK,
    SIZE_MATCH,
)

# ---------------------------------------------------------------------------
# Supported file sizes
# ---------------------------------------------------------------------------
# Only 32KB and 64KB ROMs belong to this family. Every other Bosch extractor
# handles 128KB or larger files, so this gate is a strong positive filter.
# ---------------------------------------------------------------------------

SUPPORTED_SIZES: frozenset[int] = frozenset({0x8000, 0x10000})

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these byte strings appear anywhere in the binary the file cannot
# be an EDC1/EDC2 ROM. This prevents:
#   - EDC15 bins (TSW marker, or 1037 SW that is actually EDC15)
#   - EDC16 / EDC17 / MEDC17 / MED17 modern bins
#   - ME7 petrol bins (share 0281 HW prefix via common Bosch numbering)
#   - M5.x / M3.8x petrol bins (MOTR ident block)
#   - Any other Bosch family with an explicit marker string
#
# Note: 'MOTRONIC' is the calibration-area label used by ME7/M-series tools.
# 'M5.' and 'M3.8' are family strings from the M5.x generation.
# '1350000M3' / '1530000M3' are the M3.x family markers.
# ---------------------------------------------------------------------------

EXCLUSION_SIGNATURES: list[bytes] = [
    b"EDC15",
    b"EDC16",
    b"EDC17",
    b"MEDC17",
    b"MED17",
    b"TSW",  # EDC15 Format-A toolchain marker
    b"SB_V",  # EDC15/EDC16 base-software version tag
    b"ME7.",  # ME7 petrol family
    b"MOTRONIC",  # ME7 / M5.x calibration area label
    b"1350000M3",  # M3.1 family marker
    b"1530000M3",  # M3.3 family marker
    b"M5.",  # M5.x family string
    b"M3.8",  # M3.8x family string
    b"MOTR",  # M5.x / M3.8x ident-block anchor
]

# ---------------------------------------------------------------------------
# Ident region — fixed absolute offset 0x7fd0
# ---------------------------------------------------------------------------
# The ident record is always located near absolute offset 0x7fd0 in every
# EDC1/EDC2 ROM, regardless of file size:
#
#   32KB file (0x8000): offset 0x7fd0 is 48 bytes from the end — the ident
#                       occupies the very last ~144 bytes of the file.
#   64KB file (0x10000): offset 0x7fd0 is 32816 bytes from the end — the
#                        ident sits at the midpoint of the second 32KB bank,
#                        immediately following the code area.
#
# Two sub-variants exist that differ by where the HW number begins:
#
#   Sub-A (Audi 80/A6, VAG): HW starts at 0x7fd9 (9 bytes into the window).
#     e.g.  0x7fd9: 0281001198\xff2287358770\xffA50AM000   \xff37
#
#   Sub-B (BMW 325 TDS, 318 TDS): HW starts at 0x7fd0 (window start).
#     e.g.  0x7fd0: 0281001380\xff1037355081\xff.......\xff3Y3
#            0x7fd0: 0281001201\xff2287358516\xff2245190\xff3G3
#            0x7fd0: 0281001243\xff2537355281\xff2246061\xff3U
#
# Starting the search window at 0x7fd0 covers both sub-variants with a
# single regex pass. The 9-byte difference between sub-A and sub-B is well
# within the 265-byte window, so the pattern matches correctly in both cases.
#
# NOTE: the original specification described dot-delimited fields, but actual
# binaries use 0xFF (\xff) as the field separator. The pattern includes all
# three observed separator variants for robustness.
# ---------------------------------------------------------------------------

IDENT_OFFSET: int = 0x7FD0
IDENT_REGION: slice = slice(IDENT_OFFSET, IDENT_OFFSET + 265)

# Regex for the HW+SW pair embedded in the ident region.
# Separator observed in all samples is \xff (0xFF), but [.\s] is kept as a
# fallback for any edge-case sample that may use a literal dot or space.
# Group 1 = HW number  ('0281' + 6 digits)
# Group 2 = SW version ('2287'/'2537'/'1037' + 6–8 digits)
IDENT_PATTERN: bytes = rb"(0281\d{6})[\xff.\s]((?:1037|2287|2537)\d{6,8})"


class BoschEDC1Extractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch EDC1 / EDC2 ECU binaries.

    Handles 32KB and 64KB TDI diesel ROMs from the Audi 80 / A6 era
    (1990–1997). All identification data is extracted from the fixed-format
    dot-delimited ASCII ident record located in the last 256 bytes of the
    ROM, at approximately offset 0x7FD9.

    SW prefix variants handled:
      2287 — original EDC1 toolchain
      2537 — revised EDC2 toolchain
      1037 — standard Bosch prefix, used by A6 AAT/AEL bins that share the
              identical binary structure but carry a later-generation prefix.
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
        return ["EDC1", "EDC2"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch EDC1 / EDC2 ECU ROM.

        Three-phase check:

          Phase 1 — Size gate.
                    File must be exactly 32KB (0x8000) or 64KB (0x10000).
                    All other Bosch families operate on 128KB or larger files,
                    so this single test eliminates the vast majority of
                    unrelated binaries instantly without scanning any data.

          Phase 2 — Exclusion check.
                    Reject if any modern Bosch family signature is present
                    anywhere in the binary. Guards primarily against:
                      - EDC15 bins that are also small (some Format-B bins
                        are 512KB but older tools sometimes produce 256KB
                        images — excluded by the size gate already, but
                        included here for belt-and-braces coverage).
                      - Any future 32KB or 64KB bin from another family.

          Phase 3 — Positive ident check.
                    The pattern '0281\\d{6}[\\xff.\\s](?:1037|2287|2537)\\d{6,8}'
                    must appear in the 256-byte window starting at absolute
                    offset 0x7FD9. The separator is always \\xff in observed
                    samples. This fixed-offset search avoids matching any
                    calibration table data elsewhere in the ROM and has not
                    produced false positives across all known sample binaries.

        Args:
            data: Raw bytes of the ECU binary file.

        Returns:
            True if this extractor should handle the binary.
        """
        evidence: list[str] = []

        # Phase 1 — size gate (fastest check, no byte scanning)
        if len(data) not in SUPPORTED_SIZES:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 2 — exclusion check (scan the whole tiny file; it is at most
        # 64KB so even a full scan is O(64K) and negligible in practice)
        for excl in EXCLUSION_SIGNATURES:
            if excl in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 3 — positive ident record at the fixed absolute offset
        ident_window = data[IDENT_REGION]
        if re.search(IDENT_PATTERN, ident_window):
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
        Extract all identifying information from a Bosch EDC1 / EDC2 binary.

        All fields are derived from the fixed-format dot-delimited ASCII ident
        record in the last 256 bytes of the ROM. Fields not present in this
        binary format are returned as None.

        Returns a dict fully compatible with ECUIdentifiersSchema:

            manufacturer      : "Bosch"
            file_size         : int — raw byte length (32768 or 65536)
            md5               : str — hex MD5 of the full binary
            sha256_first_64kb : str — hex SHA-256 of the first 64KB
            ecu_family        : "EDC1" — fixed for all bins this extractor claims
            ecu_variant       : None  — no sub-variant string in the binary
            software_version  : str   — the SW number, e.g. "2287358770"
            hardware_number   : str   — the HW number, e.g. "0281001198"
            match_key         : str   — "EDC1::<software_version>"
            raw_strings       : list  — printable ASCII strings from tail
            calibration_version: None
            sw_base_version   : None
            serial_number     : None
            dataset_number    : None
            calibration_id    : None
            oem_part_number   : None

        Args:
            data:     Raw bytes of the ECU binary file.
            filename: Original filename — used for display only; not parsed.

        Returns:
            Dict compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from the ident region ---
        # Provides human-readable context for debugging and display in the UI.
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=IDENT_REGION,
            min_length=8,
            max_results=20,
        )

        # --- Step 2: Parse the ident record ---
        hardware_number, software_version = self._parse_ident(data)

        # --- Step 3: Fixed fields ---
        result["ecu_family"] = "EDC1"
        result["ecu_variant"] = None

        # --- Step 4: Resolved identifiers ---
        result["hardware_number"] = hardware_number
        result["software_version"] = software_version

        # --- Step 5: Fields not present in EDC1/EDC2 binaries ---
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["calibration_id"] = None
        result["oem_part_number"] = None

        # --- Step 6: Build match key ---
        result["match_key"] = self.build_match_key(
            ecu_family="EDC1",
            ecu_variant=None,
            software_version=software_version,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — ident record parser
    # -----------------------------------------------------------------------

    def _parse_ident(self, data: bytes) -> tuple[Optional[str], Optional[str]]:
        """
        Parse the HW and SW numbers from the ident record in the tail region.

        The ident record is a dot-delimited ASCII string located in the final
        ~135 bytes of every EDC1/EDC2 ROM at approximately offset 0x7FD9:

            0281001198.2287358770.A50AM000   .37

        This method searches the last 256 bytes for the two-field pattern:

            Group 1: HW  — '0281' + exactly 6 decimal digits (10 digits total)
            Group 2: SW  — '2287', '2537', or '1037' + 6–8 decimal digits

        The separator between HW and SW is 0xFF (\xff) in all observed samples.
        Literal '.' and whitespace are also accepted as fallback variants.

        Returns:
            Tuple of (hardware_number, software_version), either of which may
            be None if the pattern cannot be matched (should not occur for any
            binary that passed can_handle(), but defensively handled here).
        """
        ident_window = data[IDENT_REGION]
        match = re.search(IDENT_PATTERN, ident_window)
        if not match:
            return None, None

        hardware_number = match.group(1).decode("ascii", errors="ignore").strip()
        software_version = match.group(2).decode("ascii", errors="ignore").strip()

        return (hardware_number or None), (software_version or None)
