r"""
Magneti Marelli IAW 1AP ECU binary extractor.

Implements BaseManufacturerExtractor for the Magneti Marelli IAW 1AP family:
  IAW 1AP — Peugeot/Citroën single-point fuel injection ECUs (~1996–2002)
            Peugeot 106 1.0/1.1/1.4i, Peugeot 206 1.1/1.4i,
            Citroën Saxo 1.0/1.1/1.4i, Citroën C3 1.1/1.4i
            ST6 microcontroller (ST62T65C), 64KB (0x10000) internal flash

These are ST6-based single-point injection ECUs from Magneti Marelli.  The
entire program (code + calibration) is contained in a single 64KB flash
dump.  They are EXTREMELY sparse on identifying text — almost no printable
ASCII strings exist in the binary.

Binary structure:

  Size            : 65,536 bytes (0x10000) — always exactly 64KB.

  Header          : Bytes 0x00–0x0F are all 0xFF (erased vector area).
                    Code begins at offset 0x10 with ST6 machine opcodes.

  Code + cal      : 0x0010–0x5F8F — ST6 machine code and calibration data.
                    The only identifying ASCII text is the 3-byte family
                    tag ``1ap`` (lowercase) at fixed offset 0x5F8D, sitting
                    at the very end of the calibration data block:
                      ...33333333333331ap  followed by 0xFF padding.

  FF padding      : 0x5F90–0x5FF7 — erased flash fill (all 0xFF).

  Data / tables   : 0x6000–0xFFFF — lookup tables and map data.

  Sync marker     : 4-byte sequence ``AA 55 CC 33`` at offset 0x4810.
                    Followed by calibration fingerprint bytes.

Detection strategy (can_handle):

  This is a very minimal ECU with almost no identifying strings.  Detection
  must be strict to avoid false positives against other 64KB binaries.

  Phase 1 — Size gate: exactly 65,536 bytes (0x10000).
  Phase 2 — Header check: first 16 bytes must all be 0xFF.
  Phase 3 — Exclusion: reject if ANY known competitor/sibling signature
            is found.  Critically, ``MARELLI`` is excluded because IAW 1AP
            does NOT contain that string — IAW 1AV does, and this is the
            primary way to distinguish them.
  Phase 4 — Family anchor: ``b"1ap"`` (lowercase!) must be present in the
            range 0x5F80–0x5FA0.
  Phase 5 — Sync marker: ``AA 55 CC 33`` must be present somewhere in the
            binary.

Extraction:

  Since this ECU has almost no extractable text:
    - ecu_family        = "IAW 1AP"
    - software_version  = None  (not stored in binary)
    - hardware_number   = None  (not stored in binary)
    - oem_part_number   = None  (not stored in binary)
    - calibration_id    = 8 hex chars from the 4 bytes after the AA55CC33
                          sync marker at offset 0x4810, e.g. "50960654"

  The ``match_key_fallback_field`` is set to ``"calibration_id"`` so that
  the match key can be built without software_version.

  Match key format: ``IAW 1AP::50960654``

Verified sample:
  Peugeot 206 1.4i — 65,536 bytes, family tag "1ap" at 0x5F8D,
                      sync marker AA55CC33 at 0x4810,
                      calibration fingerprint bytes 50 96 06 54 after marker.
"""

import hashlib
from typing import Dict, List, Optional

from openremap.core.manufacturers.base import (
    EXCLUSION_CLEAR,
    FAMILY_ANCHOR as FAMILY_ANCHOR_TAG,
    HEADER_MATCH,
    SIZE_MATCH,
    SYNC_MARKER as SYNC_MARKER_TAG,
    BaseManufacturerExtractor,
    DetectionStrength,
)
from openremap.core.manufacturers.marelli.iaw_1ap.patterns import (
    EXCLUSION_SIGNATURES,
    EXPECTED_SIZE,
    FAMILY_ANCHOR,
    FAMILY_TAG,
    PATTERNS,
    SEARCH_REGIONS,
    SYNC_MARKER,
    SYNC_MARKER_OFFSET,
)


class MarelliIAW1APExtractor(BaseManufacturerExtractor):
    """
    Extractor for Magneti Marelli IAW 1AP ECU binaries.
    Handles: IAW 1AP (Peugeot/Citroën ST6-based single-point injection).

    Detection is anchored on the 0xFF header, the lowercase ``1ap`` family
    tag at offset 0x5F8D, and the ``AA55CC33`` sync marker.

    The calibration_id (hex-encoded bytes after the sync marker) is the
    only unique identifier available.  ``match_key_fallback_field`` opts
    this extractor into the base-class fallback so that a valid match key
    is always produced.
    """

    # Use calibration_id as the fallback field for match_key when
    # software_version is absent (which it always is for IAW 1AP).
    match_key_fallback_field = "calibration_id"
    detection_strength = DetectionStrength.STRONG

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Magneti Marelli"

    @property
    def supported_families(self) -> List[str]:
        return ["IAW 1AP"]

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------

    def can_handle(self, data: bytes) -> bool:
        """
        Return True if this binary is a Magneti Marelli IAW 1AP ECU.

        Five-phase check:

          Phase 1 — Size gate.
            Reject if file size is not exactly 65,536 bytes (0x10000).

          Phase 2 — Header check.
            Reject if the first 16 bytes are not all 0xFF.  IAW 1AP bins
            have an erased vector area at the start of flash.

          Phase 3 — Exclusion.
            Reject if ANY known competitor or sibling signature is found
            anywhere in the binary.  This is critical for distinguishing
            IAW 1AP from IAW 1AV (which contains ``MARELLI``) and from
            all other 64KB ECU families.

          Phase 4 — Family anchor.
            Accept only if the lowercase ``1ap`` tag is found in the range
            0x5F80–0x5FA0.  This is the only identifying ASCII text in the
            entire binary.

          Phase 5 — Sync marker.
            Accept only if the ``AA55CC33`` sync marker is present somewhere
            in the binary.  This provides a second structural confirmation.
        """
        evidence: list[str] = []

        # Phase 1 — size gate
        if len(data) != EXPECTED_SIZE:
            self._set_evidence()
            return False
        evidence.append(SIZE_MATCH)

        # Phase 2 — header check: first 16 bytes must all be 0xFF
        if data[:16] != b"\xff" * 16:
            self._set_evidence()
            return False
        evidence.append(HEADER_MATCH)

        # Phase 3 — exclusion check (full binary)
        for excl in EXCLUSION_SIGNATURES:
            if excl in data:
                self._set_evidence()
                return False
        evidence.append(EXCLUSION_CLEAR)

        # Phase 4 — family anchor: "1ap" in the range 0x5F80–0x5FA0
        family_area = data[SEARCH_REGIONS["family_area"]]
        if FAMILY_ANCHOR not in family_area:
            self._set_evidence()
            return False
        evidence.append(FAMILY_ANCHOR_TAG)

        # Phase 5 — sync marker: AA55CC33 must be present
        if SYNC_MARKER not in data:
            self._set_evidence()
            return False
        evidence.append(SYNC_MARKER_TAG)

        self._set_evidence(evidence)
        return True

    # -----------------------------------------------------------------------
    # Extraction
    # -----------------------------------------------------------------------

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        """
        Extract all identifying information from a Marelli IAW 1AP binary.

        Returns a dict fully compatible with ECUIdentifiersSchema.
        """
        result: Dict = {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
        }

        # --- Step 1: Raw ASCII strings from full binary ---
        # IAW 1AP is extremely sparse — lower min_length to catch "1ap"
        result["raw_strings"] = self.extract_raw_strings(
            data=data,
            region=SEARCH_REGIONS["full"],
            min_length=3,
            max_results=20,
        )

        # --- Step 2: ECU family is always IAW 1AP for this extractor ---
        result["ecu_family"] = FAMILY_TAG
        result["ecu_variant"] = FAMILY_TAG

        # --- Step 3: Run regex patterns for the family tag ---
        raw_hits = self._run_all_patterns(
            data=data,
            patterns=PATTERNS,
            pattern_regions={"family_tag": "family_area"},
            search_regions=SEARCH_REGIONS,
        )

        # --- Step 4: Calibration ID — hex-encoded bytes after sync marker ---
        calibration_id = self._extract_calibration_id(data)
        result["calibration_id"] = calibration_id

        # --- Step 5: Fields not present in IAW 1AP binaries ---
        result["software_version"] = None
        result["hardware_number"] = None
        result["oem_part_number"] = None
        result["calibration_version"] = None
        result["sw_base_version"] = None
        result["serial_number"] = None
        result["dataset_number"] = None

        # --- Step 6: Build compound match key ---
        # software_version is always None for IAW 1AP — the base class
        # fallback mechanism uses calibration_id as the version component
        # because match_key_fallback_field = "calibration_id".
        result["match_key"] = self.build_match_key(
            ecu_family=FAMILY_TAG,
            ecu_variant=FAMILY_TAG,
            software_version=None,
            fallback_value=calibration_id,
        )

        return result

    # -----------------------------------------------------------------------
    # Internal — calibration ID extractor
    # -----------------------------------------------------------------------

    def _extract_calibration_id(self, data: bytes) -> Optional[str]:
        """
        Extract the calibration ID from the 4 bytes after the AA55CC33
        sync marker.

        The sync marker is expected at offset 0x4810.  The 4 bytes
        immediately following it (offsets 0x4814–0x4817) are hex-encoded
        to produce an 8-character calibration fingerprint string.

        Example:
          Bytes at 0x4814: 50 96 06 54
          Result: "50960654"

        Falls back to scanning the full binary for the sync marker if it
        is not at the expected fixed offset.

        Returns:
            8-character hex string (e.g. "50960654"), or None if the sync
            marker cannot be found or there are insufficient bytes after it.
        """
        # Try the expected fixed offset first
        idx = SYNC_MARKER_OFFSET
        if (
            idx + len(SYNC_MARKER) + 4 <= len(data)
            and data[idx : idx + len(SYNC_MARKER)] == SYNC_MARKER
        ):
            cal_bytes = data[idx + len(SYNC_MARKER) : idx + len(SYNC_MARKER) + 4]
            return cal_bytes.hex()

        # Fallback — scan the full binary for the sync marker
        idx = data.find(SYNC_MARKER)
        if idx < 0:
            return None

        if idx + len(SYNC_MARKER) + 4 > len(data):
            return None

        cal_bytes = data[idx + len(SYNC_MARKER) : idx + len(SYNC_MARKER) + 4]
        return cal_bytes.hex()
