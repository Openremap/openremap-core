r"""
Bosch LH-Jetronic ECU binary extractor.

Implements BaseManufacturerExtractor for the Bosch LH-Jetronic family:
  LH-Jetronic  — Bosch fuel injection system, ~1982–1995
                  e.g. Porsche 928 S4, Volvo 940, BMW 5-series (E34),
                       Mercedes W124/W126, Saab 900/9000

These are Motorola 6800/6802-based ECUs. The entire ROM (program code +
calibration data) is contained in a single socketed EPROM chip.

Part number prefixes:
  0280-000-xxx  — Standard LH-Jetronic ECU ROM
  0280-002-xxx  — Later variant with extended ident block (LH-JET string)

Binary structure:

  Size            : 16KB (0x4000) or 32KB (0x8000).
                    Some 32KB bins only use the first 16KB — the upper half
                    is zero-filled (erased EPROM state).

  Header          : Bytes 0x00–0x01 carry a Motorola 6800 page/address byte:
                      \x01\x60  — most 0280-000-xxx bins
                      \x01\x40  — Porsche 928 variant (0280-002-xxx)
                      \x00\x60  — minor variant
                    Bytes 0x02–0x0F are typically \xff (erased EPROM fill).

  Ident block     : Located near the end of the used ROM region.
                    Two distinct formats depending on the part series:

  Format A (0280-000-xxx):
    Anchor bytes  : \xd5\x28 — a fixed 2-byte delimiter present in all
                    Format A bins, always within the last 1KB of used ROM.
    Structure     : \xd5\x28\x<type> <4 binary bytes> \x00\x00 <ASCII_ident>
                    type = 0x05 or 0x09 (sub-format indicator)
                    ASCII_ident is 10–16 chars, e.g.:
                      '1012621LH241rp'   (ECU_id + LH_variant + revision)
                      '9146179  P01'     (ECU_id + spaces + cal_version)
                      '1010309LH244QF'   (ECU_id + LH_variant + suffix)
                    The ASCII ident IS the calibration_id for this format.
                    No hardware_number or software_version stored as such.

  Format B (0280-002-xxx, LH-JET):
    Structure     : <HW_10><SW_10><CAL_3>LH-JET  <APP_10><X>
                    located at a fixed offset near end of ROM (typically
                    the last 64–256 bytes before trailing \xff padding).
                    HW_10  = '0280' + 6 digits (Bosch hardware part number)
                    SW_10  = '2287' + 6 digits (Bosch software version)
                    CAL_3  = 3-char calibration variant, e.g. 'L01'
                    LH-JET = literal family identifier
                    APP_10 = 10-digit application/OEM code
                    X      = 1-digit revision suffix

Fields extracted per format:

  Format A:
    ecu_family      = 'LH-Jetronic'
    hardware_number = None
    software_version= None
    calibration_id  = ASCII ident string, e.g. '9146179  P01'

  Format B:
    ecu_family      = 'LH-Jetronic'
    hardware_number = '0280xxxxxx' (10 digits)
    software_version= '2287xxxxxx' (10 digits)
    calibration_id  = 3-char code, e.g. 'L01'

Verified across all sample bins:
  0280-000-560.BIN              -> cal_id='1012621LH241rp'          (Format A)
  0280-000-913.BIN              -> cal_id='9146179  P01'            (Format A)
  0280-000-937.BIN              -> cal_id='1010309LH244QF'          (Format A)
  0280-000-954.BIN              -> cal_id='6842448  P04'            (Format A)
  0280-000-962.BIN              -> cal_id='9135591  P03'            (Format A)
  Bensin 984 chip...bin         -> cal_id='9125465  001'            (Format A)
  0280 002 506_89_90_928GT.bin  -> hw=0280002506 sw=2287356486 cal=L01 (Format B)
  gt-91_0280.002.509.bin        -> hw=0280002509 sw=2287356878 cal=L01 (Format B)
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------
# Format A: \xd5\x28 is a fixed anchor present in every Format A bin,
#   always within the last 1KB of the used ROM region.
# Format B: b'LH-JET' is the literal family string present in every
#   Format B bin (0280-002-xxx series).
#
# At least ONE must be present for can_handle() to return True.
# ---------------------------------------------------------------------------

DETECTION_SIGNATURES: list[bytes] = [
    b"LH-JET",  # Format B — 0280-002-xxx (explicit family string)
    b"LH24",  # Format A variant — LH 2.4x embedded in ASCII ident
    b"LH22",  # Format A variant — LH 2.2x embedded in ASCII ident
]

# The Format A anchor is searched only in the last 1KB, not the full file.
FORMAT_A_ANCHOR: bytes = b"\xd5\x28"

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# If any of these appear in the first 512KB the binary is NOT LH-Jetronic.
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
    b"ZZ\xff\xff",
    b"1350000M3",
    b"1530000M3",
    b'"0000000M',  # M1.x, M2.x, M3.x family markers
]


class BoschLHExtractor(BaseManufacturerExtractor):
    """
    Extractor for Bosch LH-Jetronic ECU binaries.
    Handles: LH-Jetronic (0280-000-xxx Format A, 0280-002-xxx Format B).

    Format A bins contain only a calibration ID in their ASCII ident block.
    Format B bins contain a full hardware number, software version, and
    calibration ID embedded in the LH-JET ident string.

    Format A has no software_version by architecture — the calibration_id is
    the only unique identifier available.  ``match_key_fallback_field`` opts
    this extractor into the base-class fallback so that Format A bins still
    produce a valid match key (using calibration_id as the version component).
    Format B bins are unaffected: software_version is present and always wins.
    """

    # Opt in: when software_version is absent (Format A only), use calibration_id
    # as the version component of the match key.
    match_key_fallback_field = "calibration_id"

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return ["LH-Jetronic"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Bosch LH-Jetronic ECU.

        Three-phase check:
          1. Reject if any exclusion signature is found in first 512KB.
          2. Accept if any strong positive detection signature is found
             (LH-JET, LH24x, LH22x).
          3. Accept if the Format A anchor \\xd5\\x28 is found in the
             last 1KB AND the file starts with a known LH header byte.
        """
        search_area = data[:0x80000]

        # Phase 1 — reject if any exclusion signature is present
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                return False

        # Phase 2 — accept on strong positive signatures
        if any(sig in search_area for sig in DETECTION_SIGNATURES):
            return True

        # Phase 3 — Format A anchor in last 1KB + LH header byte
        if FORMAT_A_ANCHOR in data[-1024:]:
            # LH-Jetronic ROMs start with \x01\x60, \x01\x40, or \x00\x60.
            # This guards against the anchor appearing in unrelated binaries.
            if len(data) >= 2 and data[0] in (0x00, 0x01):
                return True

        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Bosch LH-Jetronic binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from last 512 bytes of used region ---
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=self._used_region(data),
            min_length=6,
            max_results=20,
        )

        # --- Step 2: ECU family is always LH-Jetronic for this extractor ---
        result["ecu_family"] = "LH-Jetronic"
        result["ecu_variant"] = "LH-Jetronic"

        # --- Step 3: Try Format B first (richer ident block) ---
        hw, sw, cal_id = self._parse_format_b(data)

        # --- Step 4: Fall back to Format A ---
        if cal_id is None:
            cal_id = self._parse_format_a(data)

        result["hardware_number"] = hw
        result["software_version"] = sw
        result["calibration_id"] = cal_id

        # --- Step 5: Fields not present in LH-Jetronic binaries ---
        result["oem_part_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 6: Build compound match key ---
        # Format B: sw is present — used directly, fallback_value ignored.
        # Format A: sw is None AND hw is None — base class uses calibration_id
        #           as fallback because match_key_fallback_field = "calibration_id".
        #
        # The hw guard is critical: in Format B, hw and sw are parsed together
        # from the same _parse_format_b() block.  If a sw pattern failure ever
        # causes sw=None while hw is still found, that bin is a broken Format B
        # read — NOT a Format A.  Passing cal_id as fallback_value only when
        # hw is also None ensures a degraded Format B never silently produces a
        # Format A key (e.g. LH-JETRONIC::L01) and collides with real Format A
        # entries in the database.  A broken Format B with sw=None and hw!=None
        # produces match_key=None and lands in sw_missing for investigation.
        result["match_key"] = self.build_match_key(
            ecu_family="LH-Jetronic",
            ecu_variant="LH-Jetronic",
            software_version=sw,
            fallback_value=cal_id if hw is None else None,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — used region helper
    # -----------------------------------------------------------------------

    def _used_region(self, data: bytes) -> slice:
        """
        Return a slice covering the last 512 bytes of the used ROM region.

        Some 32KB bins only use the first 16KB (upper half is 0x00-filled).
        This finds the last non-zero byte to anchor the search to the actual
        end of the programmed data rather than the physical end of the file.
        """
        # Walk backwards to find the last non-zero, non-fill byte.
        for i in range(len(data) - 1, max(len(data) - 0x8000, 0), -1):
            if data[i] not in (0x00, 0xFF):
                end = i + 1
                start = max(0, end - 512)
                return slice(start, end)

        # Fallback — use the physical end
        return slice(-512, None)

    # -----------------------------------------------------------------------
    # Internal — Format B parser (0280-002-xxx, LH-JET string)
    # -----------------------------------------------------------------------

    def _parse_format_b(
        self, data: bytes
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse the Format B ident block and return (hw, sw, cal_id).

        Format: <HW_10><SW_10><CAL_3>LH-JET
          HW_10  = '0280' + 6 digits
          SW_10  = '2287' + 6 digits
          CAL_3  = 3 alphanumeric chars (calibration variant, e.g. 'L01')

        The block is located in the last 512 bytes of the used ROM region.
        Returns (None, None, None) if the pattern is not found.
        """
        region = data[self._used_region(data)]

        m = re.search(
            rb"(0280\d{6})(2287\d{6})([A-Z0-9]{3})LH-JET",
            region,
        )
        if not m:
            return None, None, None

        hw = m.group(1).decode("ascii")
        sw = m.group(2).decode("ascii")
        cal_id = m.group(3).decode("ascii")
        return hw, sw, cal_id

    # -----------------------------------------------------------------------
    # Internal — Format A parser (0280-000-xxx, \xd5\x28 anchor)
    # -----------------------------------------------------------------------

    def _parse_format_a(self, data: bytes) -> Optional[str]:
        """
        Parse the Format A ident block and return the calibration_id string.

        Format: \\xd5\\x28\\x<type> <4 binary bytes> \\x00\\x00 <ASCII_ident>
          The ASCII ident is the calibration ID, e.g. '9146179  P01'.

        The \\xd5\\x28 anchor is searched across the entire file rather than
        only the last 1KB.  Some 32KB bins only use the first 16KB and
        zero-pad the upper half — in those bins the anchor sits at ~0x3FE2,
        which is outside the last 1KB of the 32KB file.  Searching the full
        file via rfind() still finds the last (and only) occurrence reliably.
        """
        idx = data.rfind(FORMAT_A_ANCHOR)
        if idx < 0:
            return None

        # Structure starting at the anchor (0-indexed from anchor start):
        #   [0] = \xd5  (anchor byte 1)
        #   [1] = \x28  (anchor byte 2)
        #   [2] = type byte (0x05 or 0x09)
        #   [3] = binary byte 1
        #   [4] = binary byte 2
        #   [5] = binary byte 3
        #   [6] = \x00
        #   [7] = \x00
        #   [8..] = ASCII ident string
        #
        # Verified on all sample bins: ASCII ident starts at anchor + 8.
        after = data[idx + 8 :]
        if len(after) < 6:
            return None

        # Restrict to alphanumeric characters and spaces only.
        # Trailing checksum bytes (e.g. 0x5e='^', 0x7b='{') are valid printable
        # ASCII but are not part of the ident string — stopping at the first
        # non-alphanumeric/non-space character trims them cleanly.
        m = re.match(rb"([0-9A-Za-z/ ]{6,16})", after)
        if not m:
            return None

        return m.group(1).decode("ascii", errors="ignore").strip() or None
