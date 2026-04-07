"""
Tests for BoschLHExtractor (LH-Jetronic Format A and Format B).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * Format A anchor (\\xd5\\x28) in last 1KB + LH header byte (Phase 3)
      * Format A ident containing LH24 detection signature (Phase 2)
      * Format B LH-JET marker present (Phase 2)
      * LH22 / LH24 standalone markers
  - can_handle() — False paths:
      * wrong size (512 bytes)
      * all-zero 16KB / 32KB with no signatures
      * exclusion signatures block detection even with LH marker present
      * Phase 3 rejects when first byte is not 0x00 or 0x01
  - extract() Format A:
      * required keys present
      * manufacturer == 'Bosch'
      * ecu_family == 'LH-Jetronic'
      * calibration_id extracted from ASCII ident (not None)
      * hardware_number and software_version are None (Format A has neither)
      * file_size == len(data)
      * sha256_first_64kb matches hashlib
  - extract() Format B:
      * required keys present
      * hardware_number starts with '0280'
      * software_version starts with '2287'
      * calibration_id == 'L01'
      * match_key not None (sw present)
  - Determinism and filename independence
"""

import hashlib

from openremap.core.manufacturers.bosch.lh.extractor import BoschLHExtractor

EXTRACTOR = BoschLHExtractor()

# Keys that every extract() result must contain (minimal set for these tests).
REQUIRED_EXTRACT_KEYS = {
    "manufacturer",
    "match_key",
    "ecu_family",
    "ecu_variant",
    "software_version",
    "hardware_number",
    "calibration_id",
    "file_size",
    "sha256_first_64kb",
}


# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------


def make_lh_format_a_bin() -> bytes:
    """
    16KB LH-Jetronic Format A binary.

    Header byte 0x01 at offset 0 (triggers Phase 3 LH header check).
    Format A anchor (\\xd5\\x28) at 0x3F00 — within the last 1KB (0x3C00–0x4000).
    Ident string placed at anchor + 8, matching the layout the parser expects:

      [anchor+0] \\xd5  anchor byte 1
      [anchor+1] \\x28  anchor byte 2
      [anchor+2] 0x05  type byte
      [anchor+3..5]    3 binary bytes
      [anchor+6..7]    \\x00\\x00
      [anchor+8..]     ASCII ident  <-- parser reads from here

    The ident "1012621LH241rp" also contains the "LH24" detection signature,
    so Phase 2 fires first; Phase 3 still works independently.
    """
    buf = bytearray(0x4000)
    buf[0:2] = b"\x01\x60"  # standard LH-Jetronic header

    anchor_pos = 0x3F00  # last 1KB of 16KB file starts at 0x3C00
    ident = b"1012621LH241rp"

    buf[anchor_pos : anchor_pos + 2] = b"\xd5\x28"  # anchor
    buf[anchor_pos + 2] = 0x05  # type byte
    buf[anchor_pos + 3 : anchor_pos + 6] = b"\x01\x02\x03"  # 3 binary bytes
    buf[anchor_pos + 6 : anchor_pos + 8] = b"\x00\x00"  # zero pair
    buf[anchor_pos + 8 : anchor_pos + 8 + len(ident)] = ident  # ident at +8

    return bytes(buf)


def make_lh_format_b_bin() -> bytes:
    """
    32KB LH-Jetronic Format B binary (0280-002-xxx series).

    Header \\x01\\x40 (Porsche 928 GT variant).
    Block at 0x7F00 in format:  HW_10 + SW_10 + CAL_3 + 'LH-JET'
    The "LH-JET" literal is a DETECTION_SIGNATURE → Phase 2 fires.
    _parse_format_b() extracts hw='0280002506', sw='2287356486', cal='L01'.
    """
    buf = bytearray(0x8000)
    buf[0:2] = b"\x01\x40"  # Porsche 928 variant header

    block = b"0280002506" + b"2287356486" + b"L01" + b"LH-JET"
    pos = 0x7F00
    buf[pos : pos + len(block)] = block

    return bytes(buf)


def make_clean_16kb() -> bytes:
    """All-zero 16KB — no LH signatures anywhere."""
    return bytes(0x4000)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_name_is_bosch(self):
        assert EXTRACTOR.name == "Bosch"

    def test_name_is_string(self):
        assert isinstance(EXTRACTOR.name, str)

    def test_supported_families_is_list(self):
        assert isinstance(EXTRACTOR.supported_families, list)

    def test_supported_families_not_empty(self):
        assert len(EXTRACTOR.supported_families) > 0

    def test_lh_jetronic_in_supported_families(self):
        assert "LH-Jetronic" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschLHExtractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# can_handle — True
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    def test_format_a_bin_accepted(self):
        assert EXTRACTOR.can_handle(make_lh_format_a_bin()) is True

    def test_format_b_bin_accepted(self):
        assert EXTRACTOR.can_handle(make_lh_format_b_bin()) is True

    def test_lh_jet_string_alone_accepted(self):
        """b'LH-JET' is a primary detection signature — Phase 2 fires."""
        buf = bytearray(0x4000)
        buf[0:2] = b"\x01\x60"
        buf[0x3800 : 0x3800 + len(b"LH-JET")] = b"LH-JET"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_lh24_string_triggers_phase2(self):
        """b'LH24' in DETECTION_SIGNATURES → accepted without anchor."""
        buf = bytearray(0x4000)
        buf[0:2] = b"\x01\x60"
        buf[0x3800:0x3804] = b"LH24"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_lh22_string_triggers_phase2(self):
        """b'LH22' in DETECTION_SIGNATURES → accepted without anchor."""
        buf = bytearray(0x4000)
        buf[0:2] = b"\x01\x60"
        buf[0x3800:0x3804] = b"LH22"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_phase3_anchor_with_header_byte_0x01(self):
        """
        Phase 3: Format A anchor in last 1KB + first byte 0x01.
        No detection signature present — relies purely on Phase 3.
        """
        buf = bytearray(0x4000)
        buf[0] = 0x01
        # Anchor somewhere in last 1KB (0x3C00–0x3FFF), no ident sig
        buf[0x3C10:0x3C12] = b"\xd5\x28"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_phase3_anchor_with_header_byte_0x00(self):
        """Phase 3 also accepts first byte == 0x00."""
        buf = bytearray(0x4000)
        buf[0] = 0x00
        buf[0x3D00:0x3D02] = b"\xd5\x28"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_32kb_format_b_lh_jet_in_32kb(self):
        """LH-JET in a 32KB file with header is accepted."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x01\x40"
        buf[0x7FE0 : 0x7FE0 + len(b"LH-JET")] = b"LH-JET"
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle — False
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    def test_512_byte_binary_rejected(self):
        """Tiny binary with no signatures is rejected."""
        assert EXTRACTOR.can_handle(bytes(512)) is False

    def test_all_zero_16kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x4000)) is False

    def test_all_zero_32kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x8000)) is False

    def test_empty_binary_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_edc17_exclusion_blocks_lh_jet(self):
        """Exclusion signature EDC17 overrides LH-JET detection."""
        buf = bytearray(0x4000)
        buf[0:2] = b"\x01\x60"
        buf[0x3800 : 0x3800 + len(b"LH-JET")] = b"LH-JET"
        buf[0x0100:0x0106] = b"EDC17\x00"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_exclusion_blocks_lh_jet(self):
        """ME7. exclusion overrides LH-JET detection."""
        buf = bytearray(0x4000)
        buf[0:2] = b"\x01\x60"
        buf[0x3800 : 0x3800 + len(b"LH-JET")] = b"LH-JET"
        buf[0x0200:0x0204] = b"ME7."
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_motronic_exclusion_rejects_binary(self):
        """MOTRONIC in binary overrides LH-JET."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x01\x60"
        buf[0x7F00 : 0x7F00 + len(b"LH-JET")] = b"LH-JET"
        buf[0x1000:0x1008] = b"MOTRONIC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m3x_marker_exclusion_rejects_binary(self):
        """M3.x family marker is an exclusion signature."""
        buf = bytearray(0x4000)
        buf[0x0100:0x0109] = b"1530000M3"
        buf[0x3800 : 0x3800 + len(b"LH-JET")] = b"LH-JET"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m1x_family_marker_exclusion(self):
        """'"0000000M' exclusion signature blocks LH detection."""
        buf = bytearray(0x4000)
        buf[0x0200:0x0209] = b'"0000000M'
        buf[0x3800 : 0x3800 + len(b"LH-JET")] = b"LH-JET"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_phase3_rejects_when_first_byte_not_lh_header(self):
        """Phase 3 requires first byte in (0x00, 0x01); 0x85 is rejected."""
        buf = bytearray(0x4000)
        buf[0] = 0x85  # M1.x header — NOT an LH header byte
        buf[0x3C10:0x3C12] = b"\xd5\x28"
        # No detection signature either — Phase 2 also fails
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_anchor_outside_last_1kb_phase3_fails(self):
        """
        \\xd5\\x28 at offset 0x1000 is NOT in the last 1KB of a 16KB file,
        so Phase 3 does not fire.  No detection signature → rejected.
        """
        buf = bytearray(0x4000)
        buf[0:2] = b"\x01\x60"
        buf[0x1000:0x1002] = b"\xd5\x28"
        # Anchor is at 0x1000, last 1KB is 0x3C00–0x4000 → not found there
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# extract() — Format A
# ---------------------------------------------------------------------------


class TestExtractFormatA:
    """Format A: calibration_id extracted from ASCII ident; no hw/sw."""

    def setup_method(self):
        self.data = make_lh_format_a_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_all_required_keys_present(self):
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in self.result, f"Missing required key: {key!r}"

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_ecu_family_is_lh_jetronic(self):
        assert self.result["ecu_family"] == "LH-Jetronic"

    def test_ecu_family_contains_lh(self):
        assert "LH" in self.result["ecu_family"]

    def test_calibration_id_is_not_none(self):
        assert self.result["calibration_id"] is not None

    def test_calibration_id_contains_ident_prefix(self):
        # The ident string starts with "1012621"
        assert "1012621" in self.result["calibration_id"]

    def test_hardware_number_is_none_format_a(self):
        """Format A bins carry no hardware number."""
        assert self.result["hardware_number"] is None

    def test_software_version_is_none_format_a(self):
        """Format A bins carry no software version."""
        assert self.result["software_version"] is None

    def test_file_size_matches_data_length(self):
        assert self.result["file_size"] == len(self.data)

    def test_file_size_is_16kb(self):
        assert self.result["file_size"] == 0x4000

    def test_sha256_first_64kb_is_hex_string(self):
        sha = self.result["sha256_first_64kb"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        int(sha, 16)  # must be valid hex

    def test_sha256_first_64kb_matches_hashlib(self):
        expected = hashlib.sha256(self.data[:0x10000]).hexdigest()
        assert self.result["sha256_first_64kb"] == expected


# ---------------------------------------------------------------------------
# extract() — Format B
# ---------------------------------------------------------------------------


class TestExtractFormatB:
    """Format B: hw, sw, and cal_id all extracted from LH-JET ident block."""

    def setup_method(self):
        self.data = make_lh_format_b_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_all_required_keys_present(self):
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in self.result, f"Missing required key: {key!r}"

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_ecu_family_is_lh_jetronic(self):
        assert self.result["ecu_family"] == "LH-Jetronic"

    def test_hardware_number_starts_with_0280(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert hw.startswith("0280")

    def test_hardware_number_exact_value(self):
        assert self.result["hardware_number"] == "0280002506"

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_software_version_starts_with_2287(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert sw.startswith("2287")

    def test_software_version_exact_value(self):
        assert self.result["software_version"] == "2287356486"

    def test_software_version_is_10_digits(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert len(sw) == 10
        assert sw.isdigit()

    def test_calibration_id_is_not_none(self):
        assert self.result["calibration_id"] is not None

    def test_calibration_id_exact_value(self):
        assert self.result["calibration_id"] == "L01"

    def test_file_size_is_32kb(self):
        assert self.result["file_size"] == 0x8000

    def test_file_size_matches_data_length(self):
        assert self.result["file_size"] == len(self.data)

    def test_sha256_first_64kb_matches_hashlib(self):
        expected = hashlib.sha256(self.data[:0x10000]).hexdigest()
        assert self.result["sha256_first_64kb"] == expected

    def test_match_key_not_none_when_sw_present(self):
        """Format B has a software_version so the match key can be built."""
        assert self.result["match_key"] is not None

    def test_match_key_contains_lh(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert "LH" in mk.upper()

    def test_match_key_contains_software_version(self):
        mk = self.result["match_key"]
        sw = self.result["software_version"]
        assert mk is not None and sw is not None
        assert sw in mk


# ---------------------------------------------------------------------------
# Determinism and filename independence
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_format_a_is_deterministic(self):
        data = make_lh_format_a_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1["manufacturer"] == r2["manufacturer"]
        assert r1["ecu_family"] == r2["ecu_family"]
        assert r1["calibration_id"] == r2["calibration_id"]
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]

    def test_format_b_is_deterministic(self):
        data = make_lh_format_b_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["calibration_id"] == r2["calibration_id"]

    def test_filename_does_not_affect_identification(self):
        data = make_lh_format_b_bin()
        r1 = EXTRACTOR.extract(data, filename="original.bin")
        r2 = EXTRACTOR.extract(data, filename="renamed_copy.bin")
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_different_binaries_differ(self):
        r1 = EXTRACTOR.extract(make_lh_format_a_bin())
        r2 = EXTRACTOR.extract(make_lh_format_b_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]


# ---------------------------------------------------------------------------
# Coverage: lh/extractor.py lines 285, 338, 354, 362
# ---------------------------------------------------------------------------


class TestCoverageLhParserEdges:
    """Cover four uncovered return paths in _used_region and _parse_format_a."""

    # ------------------------------------------------------------------
    # Line 285 — _used_region: fallback slice(-512, None)
    # ------------------------------------------------------------------

    def test_used_region_fallback_when_all_bytes_are_fill(self):
        """Line 285: return slice(-512, None) when every byte is 0x00 or 0xFF.

        _used_region walks backwards looking for the last non-zero, non-FF
        byte.  If every byte in the search window is a fill byte the loop
        exhausts without finding one and falls to the bare 'return slice(-512,
        None)' fallback.
        """
        # 16 KB all-zero binary — every byte is 0x00 (fill)
        data = bytes(0x4000)
        region = EXTRACTOR._used_region(data)
        assert region == slice(-512, None)

    def test_used_region_fallback_all_ff(self):
        """Line 285: also fires for all-0xFF binaries."""
        data = bytes([0xFF] * 0x4000)
        region = EXTRACTOR._used_region(data)
        assert region == slice(-512, None)

    # ------------------------------------------------------------------
    # Line 338 — _parse_format_a: return None when anchor is absent
    # ------------------------------------------------------------------

    def test_parse_format_a_returns_none_when_no_anchor(self):
        """Line 338: return None when the Format-A anchor \\xd5\\x28 is absent."""
        # All-zero 16KB binary has no anchor → rfind returns -1 → return None
        data = bytes(0x4000)
        result = EXTRACTOR._parse_format_a(data)
        assert result is None

    def test_parse_format_a_returns_none_for_empty_data(self):
        """Line 338: also fires for empty input."""
        result = EXTRACTOR._parse_format_a(b"")
        assert result is None

    # ------------------------------------------------------------------
    # Line 354 — _parse_format_a: return None when len(after) < 6
    # ------------------------------------------------------------------

    def test_parse_format_a_returns_none_when_anchor_too_close_to_end(self):
        """Line 354: return None when anchor is so near the end that after < 6 bytes.

        The parser reads the ident from anchor+8 onward.  If the anchor sits
        at the very end of the file there are fewer than 6 bytes remaining
        → the 'if len(after) < 6: return None' guard fires.
        """
        # Place the anchor (\xd5\x28) at position len-2, so after = data[len+6:]
        # which is empty (< 6 bytes).
        buf = bytearray(0x4000)
        buf[-2] = 0xD5
        buf[-1] = 0x28
        result = EXTRACTOR._parse_format_a(bytes(buf))
        assert result is None

    # ------------------------------------------------------------------
    # Line 362 — _parse_format_a: return None when regex does not match
    # ------------------------------------------------------------------

    def test_parse_format_a_returns_none_when_ident_starts_with_invalid_char(self):
        """Line 362: regex miss returns None when ident does not begin alnum/slash/space."""
        buf = bytearray(0x4000)
        anchor_pos = 0x3F00
        buf[anchor_pos : anchor_pos + 2] = b"\xd5\x28"
        buf[anchor_pos + 2] = 0x05
        buf[anchor_pos + 3 : anchor_pos + 6] = b"\x01\x02\x03"
        buf[anchor_pos + 6 : anchor_pos + 8] = b"\x00\x00"
        buf[anchor_pos + 8 : anchor_pos + 15] = b"^LH24AB"

        result = EXTRACTOR._parse_format_a(bytes(buf))
        assert result is None

    def test_parse_format_a_returns_none_when_anchor_at_end_minus_5(self):
        """Line 354: anchor at end-5 leaves only 3 bytes after anchor+8 → < 6."""
        buf = bytearray(0x4000)
        # Anchor at index (len-5): after = data[(len-5)+8:] = data[len+3:] = b""
        pos = len(buf) - 5
        buf[pos] = 0xD5
        buf[pos + 1] = 0x28
        result = EXTRACTOR._parse_format_a(bytes(buf))
        assert result is None

    # ------------------------------------------------------------------
    # Line 362 — _parse_format_a: return (stripped result) or None
    # ------------------------------------------------------------------

    def test_parse_format_a_returns_none_when_ident_is_only_spaces(self):
        """Line 362: 'or None' branch fires when the matched ident strips to ''.

        The regex [0-9A-Za-z/ ]{6,16} includes the space character, so six
        consecutive spaces satisfy the match but strip to an empty string,
        causing the 'or None' to return None.
        """
        buf = bytearray(0x4000)
        anchor_pos = 0x3F00
        buf[anchor_pos] = 0xD5
        buf[anchor_pos + 1] = 0x28
        buf[anchor_pos + 2] = 0x05  # type byte
        buf[anchor_pos + 3 : anchor_pos + 6] = b"\x01\x02\x03"  # 3 binary bytes
        buf[anchor_pos + 6 : anchor_pos + 8] = b"\x00\x00"  # zero pair
        # Six spaces at anchor+8 — match succeeds but strip → ''
        buf[anchor_pos + 8 : anchor_pos + 14] = b"      "
        buf[anchor_pos + 14] = 0x00  # non-alphanumeric terminator
        result = EXTRACTOR._parse_format_a(bytes(buf))
        assert result is None
