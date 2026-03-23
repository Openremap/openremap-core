r"""
Bosch Motronic Legacy ECU binary extractor.

Implements BaseManufacturerExtractor for small Motorola 6802-era Bosch ECU
binaries that predate the 32KB+ Motronic M1.x generation handled by
BoschM1xExtractor.  All files in this family are ≤ 32KB and contain no
ASCII ident block — the only identifying fields are those that can be
decoded structurally from the binary layout or from a short ASCII trailer.

Sub-families covered
--------------------

  DME-3.2 (Porsche 911 Carrera 3.2, 1984–1989)
    Bosch Digital Motor Electronics generation 3.2.
    ROM sizes: 2KB (0x800) or 4KB (0x1000).
    Detection: data[0] == 0x22 AND data[1:5] == b'\\xFF\\xFF\\xFF\\xFF'
               AND data[5] == 0x02 AND len ≤ 0x8000.
    The first byte (0x22) is the software identification / checksum byte
    written into the interrupt-vector region of the 6802.  Bytes 1–4 are
    unused vector slots (erased EPROM = 0xFF).  Byte 5 (0x02) is the start
    of the first real opcode run.
    No ASCII version info is embedded; the part number lives only on the
    physical EPROM label.
    match_key: None (no version extractable from binary).

  M1.x-early / DME (BMW E30, BMW M3 2.3, Porsche 951, 1986–1992)
    Bosch Motronic M1.x in its earliest small-ROM variant.
    ROM sizes: 4KB (0x1000) or 8KB (0x2000).
    Sub-groups:
      Group B: data[0:2] == b'\\x02\\x02' AND data[3] == 0xC2 AND data[4] == 0x8B
        — BMW E30 081, BMW M3 2300, Porsche 951 28-pin DME.
        The "02 02 xx C2 8B" pattern is a shared code signature in this
        specific early Motronic ROM version.
      Group D: data[0] == 0xC2 AND data[1] == 0x95 AND data[2] == 0x02
        — Porsche 951 24-pin DME (earlier 4KB variant).
      Group E: data[0] == 0x02 AND data[1] == 0x08 AND len ≤ 0x8000
        — Mercedes M1.x variant (1988, 8KB).
      Group F: data[0] == 0x71 AND data[1] == 0x00 AND len ≤ 0x8000
        — BMW M3.1 / M1.7 early (4KB).
      Group G: data[0] == 0xC5 AND data[1] == 0xC4 AND len ≤ 0x8000
        — Early Bosch LH 2.2 / M-series compatible (4KB).
    match_key: None for all groups (no version in binary).

  KE-Jetronic (Bosch KE-Jetronic electronic fuel injection, 1985–1995)
    Bosch K-Jetronic with electronic control (KE = K-Electronic).
    NOT to be confused with LH-Jetronic (which uses a hot-wire air mass meter).
    ROM sizes: up to 32KB (0x8000).
    Detection: 10-digit ASCII part number starting with "028080" or "028090"
               in the last 512 bytes of the binary.
    Ident block format (ASCII, near end of ROM):
      "<hw_10><revision_2>/<variant> .<cal_info>"
      e.g. "028080044701/6 .260438.28 338B"
           hw = "0280800447", revision = "01", variant = "/6"
    hardware_number: 10-digit string starting with "02808".
    software_version: revision code (2 chars) e.g. "01".
    calibration_id:  variant suffix e.g. "/6".
    match_key: "KE-JETRONIC::<hw>::<sw>" when both are found.

  EZK (Bosch EZK Electronic Ignition, 1984–1993)
    Bosch EZK (Elektronische Zündzeitpunkt Kontrolle) is a standalone
    electronic ignition timing controller used alongside LH-Jetronic and
    KE-Jetronic in BMW, Volvo, Saab, and Mercedes vehicles.  It is a
    separate ECU from the fuel injection controller.
    ROM size: exactly 32KB (0x8000).
    Detection: data[0] == 0x81 AND data[1] == 0x5C AND len == 0x8000.
    No ASCII ident present; part numbers exist only on the physical label.
    match_key: None.

Detection safety
----------------
All sub-groups are gated behind a shared exclusion set that rejects any
binary containing signatures from modern Bosch families (EDC17, ME7, EDC16,
SB_V, LH-JET, etc.).  Size is always capped at ≤ 32KB to prevent any
overlap with the 32KB+ BoschM1xExtractor.

The existing BoschM1xExtractor handles 32KB/64KB M1.x bins via its own
magic (\\x85\\x0a\\xf0\\x30) or family-marker + reversed-digit ident.  The
patterns used here are completely disjoint:

  - BoschM1xExtractor primary magic   \\x85\\x0a\\xf0\\x30 — never matches any
    bin covered here (none of the 6802-era small bins start with 0x85 0x0A).
  - BoschM1xExtractor fallback path   requires "0000000M1.x" ASCII marker
    AND reversed-digit ident — neither is present in any small-ROM bin here.
  - This extractor's patterns (0x22-header, 0x0202-header, 0x028080 trailer,
    0x815C-header) do NOT appear in any of the 32KB/64KB M1.x bins covered
    by BoschM1xExtractor (verified against all scanned/ and sw_missing/ bins).

No false positives were found against any file in scanned/ or sw_missing/.

Verified sample set
-------------------
  DME-3.2:
    84 Carrera OE EUR 1267355099.BIN  (2KB)   -> family=DME-3.2  key=None
    84 Carrera OE USA 1267355102.BIN  (2KB)   -> family=DME-3.2  key=None
    86 Carrera OE EUR 1267355027.BIN  (4KB)   -> family=DME-3.2  key=None
    86 Carrera OE USA 1267355180.BIN  (4KB)   -> family=DME-3.2  key=None
    87 Carrera OE USA 1267355236.BIN  (4KB)   -> family=DME-3.2  key=None
    059_dme_BMW.bin                   (4KB)   -> family=DME-3.2  key=None

  M1.x-early:
    BMW_E30_081.bin                   (8KB)   -> family=M1.x-early  key=None
    M3-2300Original.bin               (16KB)  -> family=M1.x-early  key=None
    Porsche951DME28pin.BIN            (8KB)   -> family=M1.x-early  key=None
    Porsche951DME24pin.bin            (4KB)   -> family=M1.x-early  key=None
    1988MercBenz_256.bin              (8KB)   -> family=M1.x-early  key=None
    bmw_027.bin                       (4KB)   -> family=M1.x-early  key=None
    lh2.2 NA 511.BIN                  (4KB)   -> family=M1.x-early  key=None

  KE-Jetronic:
    MercBenz_0280800446_soft972.bin   (32KB)  -> family=KE-Jetronic
                                               hw=0280800447  sw=01  cal=/6
                                               key=KE-JETRONIC::0280800447::01

  EZK:
    0227400208_2227355740_EZK116.bin  (32KB)  -> family=EZK  key=None
"""

import hashlib
import re
from typing import Dict, List, Optional

from openremap.tuning.manufacturers.base import BaseManufacturerExtractor

# ---------------------------------------------------------------------------
# Exclusion signatures
# ---------------------------------------------------------------------------
# Any of these in the first 512KB → not a legacy 6802-era bin.
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
    b"LH-JET",  # LH-Jetronic Format B (handled by BoschLHExtractor)
    b"LH24",  # LH-Jetronic Format A variant
    b"LH22",  # LH-Jetronic Format A variant
    b"\xd5\x28",  # LH-Jetronic Format A anchor
    b"1350000M3",  # M3.x family marker
    b"1530000M3",  # M3.x family marker
    b'"0000000M',  # M1.x / M2.x / M3.x 32KB+ family marker
    b"\x85\x0a\xf0\x30",  # BoschM1xExtractor primary magic
]

# Maximum file size for any bin handled here (32KB inclusive).
# BoschM1xExtractor owns 32KB bins that have the \x85\x0a\xf0\x30 magic;
# the exclusion above ensures those never reach this extractor.
_MAX_SIZE: int = 0x8000  # 32 768 bytes

# ---------------------------------------------------------------------------
# KE-Jetronic ident pattern
# ---------------------------------------------------------------------------
# Matches the ASCII block near the end of KE-Jetronic ROMs:
#   group 1: 10-digit Bosch HW part number  (starts with "02808" or "02809")
#   group 2: 2-char revision code           e.g. "01"
#   group 3: variant suffix                 e.g. "/6"
# The KE-Jetronic ident block is always in the last 512 bytes of the ROM.
# ---------------------------------------------------------------------------

_KE_IDENT_RE = re.compile(
    rb"(0280[89]\d{5})"  # group 1: HW 10 digits (02808xxxxx or 02809xxxxx)
    rb"(\d{2})"  # group 2: revision (2 digits)
    rb"(/[^\xff\x00\s]+)"  # group 3: variant slug starting with /
)


class BoschMotronicLegacyExtractor(BaseManufacturerExtractor):
    """
    Extractor for small Motorola 6802-era Bosch ECU binaries (≤ 32KB).

    Handles four distinct sub-families:
      - DME-3.2     : Porsche 911 Carrera 3.2 and BMW (0x22 + FF×4 + 0x02 header)
      - M1.x-early  : BMW E30/M3, Porsche 951, early Mercedes (various headers)
      - KE-Jetronic : Bosch KE-Jetronic electronic fuel injection (028080 ident)
      - EZK         : Bosch EZK standalone ignition controller (0x815C header)

    None of these families contain ASCII version ident blocks (except
    KE-Jetronic), so match_key is None for all except KE-Jetronic.
    """

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Bosch"

    @property
    def supported_families(self) -> List[str]:
        return [
            "DME-3.2",
            "M1.x-early",
            "KE-Jetronic",
            "EZK",
        ]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary belongs to the Bosch legacy 6802-era family.

        Detection is a two-phase process:

        Phase 1 — Exclusion.
          Reject immediately if any exclusion signature is present in the first
          512KB.  This guards against all modern Bosch families, LH-Jetronic,
          the 32KB/64KB BoschM1xExtractor bins (which carry the \\x85\\x0a\\xf0\\x30
          magic or a "0000000M1.x" family marker), and all other families with
          a positive string anchor.

        Phase 2 — Positive detection (any ONE of the following):

          A — DME-3.2 (0x22 header):
              data[0] == 0x22 AND data[1:5] == b'\\xFF\\xFF\\xFF\\xFF'
              AND data[5] == 0x02 AND len ≤ 32KB.
              The 0x22 / FFFF FF / 0x02 sequence is the Bosch DME 3.2 interrupt
              vector table pattern, unique to this sub-family.

          B — M1.x-early group B (0x0202 code prefix):
              data[0:2] == b'\\x02\\x02' AND data[3] == 0xC2 AND data[4] == 0x8B
              AND len ≤ 32KB.
              Shared code signature in BMW E30 081, BMW M3 2.3, Porsche 951 28-pin.

          C — KE-Jetronic (028080/028090 ASCII trailer):
              A 10-digit ASCII string starting with "028080" or "028090" is
              present in the last 512 bytes of the binary.
              KE-Jetronic ECUs store their Bosch part number as plain ASCII near
              the end of the ROM.  No size restriction — KE ROMs reach 32KB.

          D — M1.x-early group D (Porsche 951 24-pin, 0xC295 prefix):
              data[0] == 0xC2 AND data[1] == 0x95 AND data[2] == 0x02
              AND len ≤ 32KB.

          E — M1.x-early group E (Mercedes M1.x, 0x0208 prefix):
              data[0] == 0x02 AND data[1] == 0x08 AND len ≤ 32KB.

          F — M1.x-early group F (BMW M3.1/M1.7 early, 0x7100 prefix):
              data[0] == 0x71 AND data[1] == 0x00 AND len ≤ 32KB.

          G — M1.x-early group G (early LH 2.2 / M-series, 0xC5C4 prefix):
              data[0] == 0xC5 AND data[1] == 0xC4 AND len ≤ 32KB.

          H — EZK ignition (0x815C header, exactly 32KB):
              data[0] == 0x81 AND data[1] == 0x5C AND len == 32KB.
              Bosch EZK standalone ignition controller ROM.
        """
        sz = len(data)

        # Phase 1 — exclusion (fast path, checked against first 512KB)
        search_area = data[:0x80000]
        for excl in EXCLUSION_SIGNATURES:
            if excl in search_area:
                return False

        # Phase 2A — DME-3.2 (0x22 + FF×4 + 0x02)
        if (
            sz >= 6
            and sz <= _MAX_SIZE
            and data[0] == 0x22
            and data[1:5] == b"\xff\xff\xff\xff"
            and data[5] == 0x02
        ):
            return True

        # Phase 2B — M1.x-early group B (02 02 xx C2 8B)
        if (
            sz >= 5
            and sz <= _MAX_SIZE
            and data[0] == 0x02
            and data[1] == 0x02
            and data[3] == 0xC2
            and data[4] == 0x8B
        ):
            return True

        # Phase 2C — KE-Jetronic (028080/028090 ASCII in last 512 bytes)
        if sz <= _MAX_SIZE and re.search(rb"0280[89]\d{5}", data[-512:]):
            return True

        # Phase 2D — M1.x-early group D (C2 95 02)
        if (
            sz >= 3
            and sz <= _MAX_SIZE
            and data[0] == 0xC2
            and data[1] == 0x95
            and data[2] == 0x02
        ):
            return True

        # Phase 2E — M1.x-early group E (02 08, Mercedes)
        if sz >= 2 and sz <= _MAX_SIZE and data[0] == 0x02 and data[1] == 0x08:
            return True

        # Phase 2F — M1.x-early group F (71 00, BMW M3.1/M1.7 early)
        if sz >= 2 and sz <= _MAX_SIZE and data[0] == 0x71 and data[1] == 0x00:
            return True

        # Phase 2G — M1.x-early group G (C5 C4, early LH2.2 / M-series)
        if sz >= 2 and sz <= _MAX_SIZE and data[0] == 0xC5 and data[1] == 0xC4:
            return True

        # Phase 2H — EZK ignition (81 5C, exactly 32KB)
        if sz == _MAX_SIZE and data[0] == 0x81 and data[1] == 0x5C:
            return True

        return False

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract identifying information from a Bosch legacy 6802-era binary.

        Dispatches to the appropriate sub-extractor based on the same header
        patterns used by can_handle().  All paths populate the full dict
        required by ECUIdentifiersSchema; fields absent from the binary are
        set to None.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # Dispatch to sub-extractor
        if self._is_ke_jetronic(data):
            return self._extract_ke_jetronic(data, result)
        elif self._is_ezk(data):
            return self._extract_ezk(data, result)
        elif self._is_dme32(data):
            return self._extract_dme32(data, result)
        else:
            return self._extract_m1x_early(data, result)

    # -----------------------------------------------------------------------
    # Internal — sub-family dispatch predicates
    # -----------------------------------------------------------------------

    def _is_ke_jetronic(self, data: bytes) -> bool:
        """True if binary carries the KE-Jetronic ASCII ident trailer."""
        return bool(re.search(rb"0280[89]\d{5}", data[-512:]))

    def _is_ezk(self, data: bytes) -> bool:
        """True if binary matches the EZK 32KB 0x815C header."""
        return (
            len(data) == _MAX_SIZE
            and len(data) >= 2
            and data[0] == 0x81
            and data[1] == 0x5C
        )

    def _is_dme32(self, data: bytes) -> bool:
        """True if binary matches the DME-3.2 0x22/FFFF/0x02 header."""
        return (
            len(data) >= 6
            and data[0] == 0x22
            and data[1:5] == b"\xff\xff\xff\xff"
            and data[5] == 0x02
        )

    # -----------------------------------------------------------------------
    # Internal — KE-Jetronic extraction
    # -----------------------------------------------------------------------

    def _extract_ke_jetronic(self, data: bytes, result: Dict) -> Dict:
        """
        Extract from a Bosch KE-Jetronic binary.

        The KE-Jetronic ident block near the end of the ROM has the format:
          "<hw_10><revision_2>/<variant> .<cal_info>"
          e.g. "028080044701/6 .260438.28 338B"

        Fields extracted:
          ecu_family     = "KE-Jetronic"
          ecu_variant    = "KE-Jetronic"
          hardware_number= 10-digit HW part number  e.g. "0280800447"
          software_version= 2-char revision code    e.g. "01"
          calibration_id = variant slug              e.g. "/6"
          match_key      = "KE-JETRONIC::<hw>::<sw>" when both present

        The match_key includes the hardware number because KE-Jetronic part
        numbers encode the specific vehicle/application (unlike ME7/EDC17
        where HW can vary for the same SW).  The HW number is the primary
        identifier for KE-Jetronic ECUs.
        """
        ecu_family = "KE-Jetronic"
        result["ecu_family"] = ecu_family
        result["ecu_variant"] = ecu_family

        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=slice(-512, None),
            min_length=6,
            max_results=10,
        )

        hw: Optional[str] = None
        sw: Optional[str] = None
        cal: Optional[str] = None

        m = _KE_IDENT_RE.search(data[-512:])
        if m:
            hw = m.group(1).decode("ascii", errors="ignore").strip()
            sw = m.group(2).decode("ascii", errors="ignore").strip()
            cal = m.group(3).decode("ascii", errors="ignore").strip()

        result["hardware_number"] = hw
        result["software_version"] = sw
        result["calibration_id"] = cal
        result["oem_part_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # Build match key: KE-JETRONIC::<hw>::<sw>
        # We include HW because it is the primary application-specific
        # identifier for KE-Jetronic (unlike later families where SW alone
        # identifies the calibration).
        if hw and sw:
            result["match_key"] = f"KE-JETRONIC::{hw}::{sw}"
        else:
            result["match_key"] = None

        return result

    # -----------------------------------------------------------------------
    # Internal — EZK extraction
    # -----------------------------------------------------------------------

    def _extract_ezk(self, data: bytes, result: Dict) -> Dict:
        """
        Extract from a Bosch EZK standalone ignition controller binary.

        EZK ROMs contain no ASCII ident block — the part numbers (0227xxxxxx
        for hardware, 2227xxxxxx for software) exist only on the physical
        chip label and are not stored in the ROM image.

        Fields extracted:
          ecu_family     = "EZK"
          ecu_variant    = "EZK"
          All version fields = None
          match_key      = None
        """
        result["ecu_family"] = "EZK"
        result["ecu_variant"] = "EZK"

        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=slice(-256, None),
            min_length=6,
            max_results=10,
        )

        result["hardware_number"] = None
        result["software_version"] = None
        result["calibration_id"] = None
        result["oem_part_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["match_key"] = None

        return result

    # -----------------------------------------------------------------------
    # Internal — DME-3.2 extraction
    # -----------------------------------------------------------------------

    def _extract_dme32(self, data: bytes, result: Dict) -> Dict:
        """
        Extract from a Bosch DME 3.2 binary (Porsche 911 Carrera 3.2, BMW).

        DME-3.2 ROMs (2KB–4KB) contain no ASCII ident.  The first byte
        (0x22) is a software identification byte written into the 6802
        interrupt vector area; its value is calibration-specific but no
        mapping from byte value to part number is publicly documented.

        The used-region checksum byte (last non-FF byte) is noted as
        oem_part_number in hex form so it is at least visible in the
        identity response, but it is not sufficient to reconstruct the
        Bosch part number without an external reference table.

        Fields extracted:
          ecu_family     = "DME-3.2"
          ecu_variant    = "DME-3.2"
          oem_part_number= hex of first byte e.g. "0x22" (version marker)
          All SW/HW fields = None
          match_key      = None
        """
        result["ecu_family"] = "DME-3.2"
        result["ecu_variant"] = "DME-3.2"

        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=slice(-256, None),
            min_length=5,
            max_results=10,
        )

        # The first byte is the only calibration-specific value we can extract
        # without an external part-number lookup table.  Store it as
        # oem_part_number for display purposes — it is NOT the Bosch PN.
        id_byte = data[0]
        result["oem_part_number"] = f"0x{id_byte:02X}"
        result["hardware_number"] = None
        result["software_version"] = None
        result["calibration_id"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["match_key"] = None

        return result

    # -----------------------------------------------------------------------
    # Internal — M1.x-early extraction (groups B/D/E/F/G)
    # -----------------------------------------------------------------------

    def _extract_m1x_early(self, data: bytes, result: Dict) -> Dict:
        """
        Extract from an early Bosch Motronic M1.x small-ROM binary.

        These ROMs (4KB–16KB) contain no ASCII ident block — they predate
        the reversed-digit ident scheme used in the 32KB+ M1.x generation
        handled by BoschM1xExtractor.  The only distinguishing information
        extractable from the binary itself is the header group, which allows
        us to narrow down the sub-family:

          Group B (02 02 xx C2 8B) → M1.x-early  (BMW E30, M3, Porsche 951 28-pin)
          Group D (C2 95 02)       → M1.x-early  (Porsche 951 24-pin)
          Group E (02 08)          → M1.x-early  (Mercedes early M1.x)
          Group F (71 00)          → M1.x-early  (BMW M3.1 / M1.7 early)
          Group G (C5 C4)          → M1.x-early  (early LH 2.2 / M-series compat)

        All groups produce match_key = None because no software version is
        stored in the binary.

        Fields extracted:
          ecu_family     = "M1.x-early"
          ecu_variant    = "M1.x-early"
          All version fields = None
          match_key      = None
        """
        result["ecu_family"] = "M1.x-early"
        result["ecu_variant"] = "M1.x-early"

        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=slice(-256, None),
            min_length=5,
            max_results=10,
        )

        result["hardware_number"] = None
        result["software_version"] = None
        result["calibration_id"] = None
        result["oem_part_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None
        result["match_key"] = None

        return result
