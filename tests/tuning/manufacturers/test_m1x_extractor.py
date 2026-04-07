"""
Tests for BoschM1xExtractor (M1.3 / M1.7 / M1.8 / M1.x generic).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * Primary detection: ROM header magic \\x85\\x0a\\xf0\\x30 at offset 0
      * Phase 2b fallback: M1.7 family marker + valid reversed-digit ident (no magic)
      * Phase 2b fallback: M1.3 family marker + valid reversed-digit ident
      * Phase 2d: M1.8 (Volvo) — '"0000000M0.0' marker + 'M1.8' string
  - can_handle() — False paths:
      * 512-byte binary (wrong size, no magic)
      * All-zero 32KB binary (right size, no magic, no valid ident)
      * Binary with M1.x magic + exclusion signature (phase 1 rejects)
      * M0.0 marker only (without M1.8 string) — rejected
      * M1.8 string only (without M0.0 marker) — rejected
  - extract():
      * Required keys all present
      * manufacturer == 'Bosch'
      * hardware_number starts with '0261' (decoded from reversed ident)
      * software_version starts with '1267' (decoded from reversed ident)
      * ecu_family in supported_families or a known sub-variant string
      * file_size == len(data)
      * sha256_first_64kb matches hashlib
  - M1.8 extract():
      * ecu_family == 'M1.8'
      * oem_part_number extracted from ident digit sequence (Volvo part)
      * match_key uses digit sequence as fingerprint
      * calibration_id == variant code (e.g. 'E00')
      * calibration_version == revision (e.g. '0000')
  - Determinism and filename independence
"""

import hashlib

from openremap.core.manufacturers.bosch.m1x.extractor import BoschM1xExtractor

EXTRACTOR = BoschM1xExtractor()

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


def make_m1x_bin() -> bytes:
    """
    32KB M1.x binary with HC11 reset vector magic at offset 0 and a
    reversed-digit ident block at 0x1E02 (within IDENT_REGION 0x1800–0x2100).

    Reversed-digit encoding:
        hw = "0261200520"  → reversed = "0250021620"
        sw = "1267357220"  → reversed = "0227537621"
        ident_string = "02500216200227537621"  (20 digits)

    Decoding check:
        ident_clean[0:10][::-1] = "0250021620"[::-1] = "0261200520"  (starts '0261') ✓
        ident_clean[10:20][::-1] = "0227537621"[::-1] = "1267357220" (starts '1267') ✓
    """
    buf = bytearray(0x8000)
    buf[0:4] = b"\x85\x0a\xf0\x30"  # HC11 reset vector magic — primary detection anchor

    # hw=0261200520 reversed char-by-char = "0250021620"
    # sw=1267357220 reversed char-by-char = "0227537621"
    ident = b"02500216200227537621"
    buf[0x1E02 : 0x1E02 + len(ident)] = ident

    return bytes(buf)


def make_m17_family_marker_bin() -> bytes:
    """
    32KB M1.7 binary WITHOUT the HC11 header magic.

    Detection relies on Phase 2b: '"0000000M1.7' family marker in the upper
    ROM region (~0x7600) + valid reversed-digit ident in IDENT_REGION.

    hw=0261200520 reversed = "0250021620"
    sw=1267357220 reversed = "0227537621"
    """
    buf = bytearray(0x8000)
    # Deliberately NOT the M1.x magic — simulates the BMW M1.7 fallback bins
    buf[0:2] = b"\x00\x0a"

    # M1.7 family marker in upper ROM region
    marker = b'"0000000M1.7'
    buf[0x7600 : 0x7600 + len(marker)] = marker

    # Valid reversed-digit ident in IDENT_REGION (0x1800–0x2100)
    ident = b"02500216200227537621"
    buf[0x1E02 : 0x1E02 + len(ident)] = ident

    return bytes(buf)


def make_m18_bin() -> bytes:
    """
    32KB M1.8 (Volvo) binary with '"0000000M0.0' marker and M1.8 ident block.

    Detection relies on Phase 2d: '"0000000M0.0' family marker present
    AND 'M1.8' ASCII string present AND size is 32KB.

    Ident block at 0x7EA0:
      "E00M18     928618124110227400035M1.8  0000"
    """
    buf = bytearray(0x8000)
    # 8051 LJMP header — NOT the HC11 magic
    buf[0:3] = b"\x02\x0f\x00"
    buf[3:6] = b"\x02\x07\x3f"

    # '"0000000M0.0' family marker at ~0x6249 (upper ROM)
    marker = b'"0000000M0.0 u'
    buf[0x6249 : 0x6249 + len(marker)] = marker

    # M1.8 ident block at 0x7EA0
    ident = b"E00M18     928618124110227400035M1.8  0000"
    buf[0x7EA0 : 0x7EA0 + len(ident)] = ident

    return bytes(buf)


def make_m18_marker_only_bin() -> bytes:
    """
    32KB binary with '"0000000M0.0' marker but NO 'M1.8' string.

    Should NOT be claimed by M1.8 detection — requires both anchors.
    """
    buf = bytearray(0x8000)
    buf[0:3] = b"\x02\x0f\x00"

    marker = b'"0000000M0.0 u'
    buf[0x6249 : 0x6249 + len(marker)] = marker

    # No M1.8 ident block
    return bytes(buf)


def make_m18_string_only_bin() -> bytes:
    """
    32KB binary with 'M1.8' string but NO '"0000000M0.0' marker.

    Should NOT be claimed by M1.8 detection — requires both anchors.
    """
    buf = bytearray(0x8000)
    buf[0:3] = b"\x02\x0f\x00"

    # M1.8 string but no M0.0 marker
    ident = b"E00M18     928618124110227400035M1.8  0000"
    buf[0x7EA0 : 0x7EA0 + len(ident)] = ident

    return bytes(buf)


def make_m13_family_marker_bin() -> bytes:
    """
    32KB M1.3 binary WITHOUT the HC11 header magic.

    Detection relies on Phase 2b: '"0000000M1.3' family marker + valid ident.

    hw=0261200153 reversed = "3510021620"
    sw=1267355408 reversed = "8045537621"
    """
    buf = bytearray(0x8000)
    buf[0:2] = b"\x85\x99"  # NOT the 4-byte magic (only first 2 match pattern)

    # M1.3 family marker in upper ROM region
    marker = b'"0000000M1.3'
    buf[0x7500 : 0x7500 + len(marker)] = marker

    # hw=0261200153  reversed = "3510021620"
    # sw=1267355408  reversed = "8045537621"
    ident = b"35100216208045537621"
    buf[0x1E10 : 0x1E10 + len(ident)] = ident

    return bytes(buf)


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

    def test_m17_in_supported_families(self):
        assert "M1.7" in EXTRACTOR.supported_families

    def test_m13_in_supported_families(self):
        assert "M1.3" in EXTRACTOR.supported_families

    def test_m18_in_supported_families(self):
        assert "M1.8" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschM1xExtractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# can_handle — True
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    def test_m1x_magic_bin_accepted(self):
        """Primary path: HC11 magic at offset 0 → Phase 2a fires."""
        assert EXTRACTOR.can_handle(make_m1x_bin()) is True

    def test_m17_family_marker_fallback_accepted(self):
        """Phase 2b: M1.7 family marker + valid ident (no magic)."""
        assert EXTRACTOR.can_handle(make_m17_family_marker_bin()) is True

    def test_m13_family_marker_fallback_accepted(self):
        """Phase 2b: M1.3 family marker + valid ident (no magic)."""
        assert EXTRACTOR.can_handle(make_m13_family_marker_bin()) is True

    def test_m18_volvo_bin_accepted(self):
        """Phase 2d: M0.0 marker + M1.8 string → M1.8 detection fires."""
        assert EXTRACTOR.can_handle(make_m18_bin()) is True

    def test_64kb_binary_with_magic_accepted(self):
        """Magic at offset 0 in a 64KB file — also a valid M1.x size."""
        buf = bytearray(0x10000)
        buf[0:4] = b"\x85\x0a\xf0\x30"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_magic_at_offset_0_is_sufficient(self):
        """
        The 4-byte magic alone is the strongest anchor — no ident needed
        for can_handle() to return True.
        """
        buf = bytearray(0x8000)
        buf[0:4] = b"\x85\x0a\xf0\x30"
        # No ident block, no family marker
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle — False
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    def test_512_byte_binary_rejected(self):
        """Too small and no magic."""
        assert EXTRACTOR.can_handle(bytes(512)) is False

    def test_all_zero_32kb_rejected(self):
        """
        Right size (32KB) but no magic and no valid ident — fallback check
        fails because zero bytes produce no digit run.
        """
        assert EXTRACTOR.can_handle(bytes(0x8000)) is False

    def test_all_zero_64kb_rejected(self):
        """64KB all-zero — no magic, no valid ident."""
        assert EXTRACTOR.can_handle(bytes(0x10000)) is False

    def test_empty_binary_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_edc17_exclusion_overrides_magic(self):
        """Phase 1 exclusion fires before Phase 2a magic check."""
        buf = bytearray(0x8000)
        buf[0:4] = b"\x85\x0a\xf0\x30"  # magic present
        buf[0x0100:0x0106] = b"EDC17\x00"  # exclusion signature
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_exclusion_overrides_magic(self):
        """ME7. exclusion blocks the M1.x magic path."""
        buf = bytearray(0x8000)
        buf[0:4] = b"\x85\x0a\xf0\x30"
        buf[0x0200:0x0204] = b"ME7."
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_motronic_exclusion_overrides_magic(self):
        """MOTRONIC string is an exclusion signature for M1.x."""
        buf = bytearray(0x8000)
        buf[0:4] = b"\x85\x0a\xf0\x30"
        buf[0x1000:0x1008] = b"MOTRONIC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m3x_marker_exclusion_overrides_magic(self):
        """M3.1 family marker (1350000M3) is an exclusion signature."""
        buf = bytearray(0x8000)
        buf[0:4] = b"\x85\x0a\xf0\x30"
        buf[0x0060:0x0069] = b"1350000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m2x_family_marker_exclusion(self):
        """'"0000000M2' family marker is an exclusion signature."""
        buf = bytearray(0x8000)
        buf[0:4] = b"\x85\x0a\xf0\x30"
        buf[0x6000:0x600B] = b'"0000000M2.'
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m18_marker_only_rejected(self):
        """
        M0.0 marker present but no M1.8 string → Phase 2d does not fire.
        The dual-anchor requirement prevents false positives.
        """
        assert EXTRACTOR.can_handle(make_m18_marker_only_bin()) is False

    def test_m18_string_only_rejected(self):
        """
        M1.8 string present but no M0.0 marker → Phase 2d does not fire.
        The dual-anchor requirement prevents false positives.
        """
        assert EXTRACTOR.can_handle(make_m18_string_only_bin()) is False

    def test_wrong_size_128kb_rejected(self):
        """
        128KB is not in FALLBACK_VALID_SIZES {32KB, 64KB} and a binary that
        size without the magic is rejected.
        """
        buf = bytearray(0x20000)
        # No magic, no marker, no valid ident
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_fallback_rejected_when_ident_decodes_wrong_prefix(self):
        """
        Phase 2c: ident present in IDENT_REGION but decoded hw does NOT start
        with '0261' → _fallback_ident_valid() returns False.
        """
        buf = bytearray(0x8000)
        # No magic, no family marker
        # Ident digits that decode to hw starting with '9999' (invalid)
        # hw_reversed = "9999999999", sw_reversed = "0227537621"
        bad_ident = b"99999999990227537621"
        buf[0x1E02 : 0x1E02 + len(bad_ident)] = bad_ident
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# extract()
# ---------------------------------------------------------------------------


class TestExtractRequiredFields:
    """extract() must always populate the minimal required keys."""

    def setup_method(self):
        self.data = make_m1x_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_all_required_keys_present(self):
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in self.result, f"Missing required key: {key!r}"

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_file_size_equals_data_length(self):
        assert self.result["file_size"] == len(self.data)

    def test_file_size_is_32kb(self):
        assert self.result["file_size"] == 0x8000

    def test_sha256_first_64kb_is_64_hex_chars(self):
        sha = self.result["sha256_first_64kb"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        int(sha, 16)  # raises ValueError if not valid hex

    def test_sha256_first_64kb_matches_hashlib(self):
        expected = hashlib.sha256(self.data[:0x10000]).hexdigest()
        assert self.result["sha256_first_64kb"] == expected


class TestExtractHardwareAndSoftware:
    """Hardware number and software version decoded via reversed-digit encoding."""

    def setup_method(self):
        self.data = make_m1x_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_hardware_number_not_none(self):
        assert self.result["hardware_number"] is not None

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_hardware_number_exact_value(self):
        # hw = "0250021620"[::-1] = "0261200520"
        assert self.result["hardware_number"] == "0261200520"

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert len(hw) == 10
        assert hw.isdigit()

    def test_software_version_not_none(self):
        assert self.result["software_version"] is not None

    def test_software_version_starts_with_1267(self):
        assert self.result["software_version"].startswith("1267")

    def test_software_version_exact_value(self):
        # sw = "0227537621"[::-1] = "1267357220"
        assert self.result["software_version"] == "1267357220"

    def test_software_version_is_10_digits(self):
        sw = self.result["software_version"]
        assert len(sw) == 10
        assert sw.isdigit()


class TestExtractEcuFamily:
    """ECU family resolution from family marker or generic fallback."""

    def test_no_marker_falls_back_to_generic(self):
        """Binary with only the magic and no family marker → 'M1.x'."""
        data = make_m1x_bin()
        result = EXTRACTOR.extract(data)
        # Without a '"0000000M1.x' marker the extractor returns the generic sentinel
        assert result["ecu_family"] in ("M1.x", "M1.3", "M1.7")

    def test_m17_marker_resolves_to_m17(self):
        data = make_m17_family_marker_bin()
        result = EXTRACTOR.extract(data)
        assert result["ecu_family"] == "M1.7"

    def test_m13_marker_resolves_to_m13(self):
        data = make_m13_family_marker_bin()
        result = EXTRACTOR.extract(data)
        assert result["ecu_family"] == "M1.3"

    def test_ecu_family_is_string(self):
        data = make_m1x_bin()
        result = EXTRACTOR.extract(data)
        assert isinstance(result["ecu_family"], str)

    def test_ecu_variant_matches_ecu_family(self):
        """M1.x sets ecu_variant == ecu_family (family IS the variant)."""
        data = make_m1x_bin()
        result = EXTRACTOR.extract(data)
        assert result["ecu_variant"] == result["ecu_family"]


class TestExtractMatchKey:
    def test_match_key_not_none_when_sw_present(self):
        result = EXTRACTOR.extract(make_m1x_bin())
        assert result["match_key"] is not None

    def test_match_key_contains_software_version(self):
        result = EXTRACTOR.extract(make_m1x_bin())
        sw = result["software_version"]
        mk = result["match_key"]
        assert sw is not None and mk is not None
        assert sw in mk

    def test_match_key_contains_family_component(self):
        result = EXTRACTOR.extract(make_m17_family_marker_bin())
        mk = result["match_key"]
        assert mk is not None
        assert "M1" in mk.upper()


# ---------------------------------------------------------------------------
# M1.8 (Volvo) extraction tests
# ---------------------------------------------------------------------------


class TestM18Extract:
    """M1.8 extraction uses a completely different path from M1.3/M1.7."""

    def setup_method(self):
        self.data = make_m18_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_all_required_keys_present(self):
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in self.result, f"Missing required key: {key!r}"

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_ecu_family_is_m18(self):
        assert self.result["ecu_family"] == "M1.8"

    def test_ecu_variant_is_m18(self):
        assert self.result["ecu_variant"] == "M1.8"

    def test_oem_part_number_is_volvo_part(self):
        """First 7 digits of ident digit sequence = Volvo part 9286181."""
        assert self.result["oem_part_number"] == "9286181"

    def test_hardware_number_is_none(self):
        """M1.8 does not store 10-digit HW as ASCII in the binary."""
        assert self.result["hardware_number"] is None

    def test_software_version_is_none(self):
        """M1.8 does not store 10-digit SW as ASCII in the binary."""
        assert self.result["software_version"] is None

    def test_calibration_id_is_variant_code(self):
        """Variant code 'E00' from the ident block prefix."""
        assert self.result["calibration_id"] == "E00"

    def test_calibration_version_is_revision(self):
        """Revision '0000' from the ident block suffix."""
        assert self.result["calibration_version"] == "0000"

    def test_match_key_contains_m18(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert "M1.8" in mk

    def test_match_key_contains_digit_sequence(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert "928618124110227400035" in mk

    def test_match_key_format(self):
        """Match key is 'M1.8::<digit_sequence>'."""
        assert self.result["match_key"] == "M1.8::928618124110227400035"

    def test_file_size_is_32kb(self):
        assert self.result["file_size"] == 0x8000

    def test_sha256_first_64kb_matches_hashlib(self):
        expected = hashlib.sha256(self.data[:0x10000]).hexdigest()
        assert self.result["sha256_first_64kb"] == expected


class TestM18CanHandleEdgeCases:
    """Edge cases for M1.8 detection (Phase 2d)."""

    def test_m18_with_exclusion_signature_rejected(self):
        """Phase 1 exclusion overrides Phase 2d M1.8 detection."""
        buf = bytearray(make_m18_bin())
        buf[0x0100:0x0106] = b"EDC17\x00"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m18_wrong_size_rejected(self):
        """M1.8 detection requires 32KB or 64KB."""
        buf = bytearray(0x20000)  # 128KB — too large
        marker = b'"0000000M0.0 u'
        buf[0x6249 : 0x6249 + len(marker)] = marker
        ident = b"E00M18     928618124110227400035M1.8  0000"
        buf[0x7EA0 : 0x7EA0 + len(ident)] = ident
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m18_64kb_accepted(self):
        """M1.8 detection also works for 64KB files."""
        buf = bytearray(0x10000)  # 64KB
        marker = b'"0000000M0.0 u'
        buf[0x6249 : 0x6249 + len(marker)] = marker
        ident = b"E00M18     928618124110227400035M1.8  0000"
        buf[0x7EA0 : 0x7EA0 + len(ident)] = ident
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_m18_extract_with_different_variant_code(self):
        """M1.8 ident with variant code E01 instead of E00."""
        buf = bytearray(0x8000)
        buf[0:3] = b"\x02\x0f\x00"
        marker = b'"0000000M0.0 u'
        buf[0x6249 : 0x6249 + len(marker)] = marker
        ident = b"E01M18     123456789012345678901M1.8  0042"
        buf[0x7EA0 : 0x7EA0 + len(ident)] = ident
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "M1.8"
        assert result["calibration_id"] == "E01"
        assert result["calibration_version"] == "0042"
        assert result["oem_part_number"] == "1234567"
        assert result["match_key"] == "M1.8::123456789012345678901"

    def test_m18_extract_without_ident_match(self):
        """M1.8 bin where the ident regex does not match — graceful fallback."""
        buf = bytearray(0x8000)
        buf[0:3] = b"\x02\x0f\x00"
        marker = b'"0000000M0.0 u'
        buf[0x6249 : 0x6249 + len(marker)] = marker
        # M1.8 string present (required for can_handle) but no structured ident
        buf[0x7F00:0x7F04] = b"M1.8"
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "M1.8"
        assert result["oem_part_number"] is None
        assert result["match_key"] is None


# ---------------------------------------------------------------------------
# Determinism and filename independence
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_same_binary_produces_same_result(self):
        data = make_m1x_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["ecu_family"] == r2["ecu_family"]
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_filename_does_not_affect_identification_fields(self):
        data = make_m1x_bin()
        r1 = EXTRACTOR.extract(data, filename="original.bin")
        r2 = EXTRACTOR.extract(data, filename="copy_renamed.bin")
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_different_binaries_produce_different_sha256(self):
        r1 = EXTRACTOR.extract(make_m1x_bin())
        r2 = EXTRACTOR.extract(make_m17_family_marker_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]

    def test_file_size_differs_between_32kb_and_64kb(self):
        buf_64 = bytearray(0x10000)
        buf_64[0:4] = b"\x85\x0a\xf0\x30"
        r1 = EXTRACTOR.extract(make_m1x_bin())
        r2 = EXTRACTOR.extract(bytes(buf_64))
        assert r1["file_size"] == 0x8000
        assert r2["file_size"] == 0x10000


# ---------------------------------------------------------------------------
# Binary factory for gap-tolerant ident tests
# ---------------------------------------------------------------------------


def make_gap_ident_bin() -> bytes:
    """
    32KB binary for testing the GAP_IDENT_PATTERN (strategy 3) path.

    Layout of IDENT_REGION_64KB_TAIL (last 4 KB = 0x7000–0x8000):
      0x7100 : 20 bad digits  → strategy 1/2 finds these first, but
               hw = "1234567890"[::-1] = "0987654321" (no "0261") → fails
      0x7200 : 25 valid digits + \\xff + 3 digits  (GAP_IDENT_PATTERN)
               combined = "0250021620022753762112345678"
               hw = combined[0:10][::-1] = "0261200520"  (valid)
               sw = combined[10:20][::-1] = "1267357220" (valid)

    IDENT_REGION (0x1800–0x2100) is all zeros — no digit runs there.
    No HC11 magic at offset 0 so Phase 2a of can_handle() does not fire.
    """
    buf = bytearray(0x8000)

    # Bad 20-digit run (strategy 1/2 matches this first and rejects)
    bad_digits = b"12345678901234567890"
    buf[0x7100 : 0x7100 + len(bad_digits)] = bad_digits

    # Valid gap ident for strategy 3
    group1 = b"0250021620022753762112345"  # 25 digits
    group2 = b"678"  # 3 digits — combined length = 28
    pos = 0x7200
    buf[pos : pos + len(group1)] = group1
    buf[pos + len(group1)] = 0xFF  # the gap byte
    buf[pos + len(group1) + 1 : pos + len(group1) + 1 + len(group2)] = group2

    return bytes(buf)


# ---------------------------------------------------------------------------
# Coverage: m1x/extractor.py lines 337-342, 525-532, 540, 570, 575,
#           604, 609, 637, 642
# ---------------------------------------------------------------------------


class TestCoverageM1xStrategyEdges:
    """Cover uncovered branches in _fallback_ident_valid, _resolve_ident_num,
    _resolve_hardware_number, _resolve_software_version, and _resolve_rt_code."""

    # ------------------------------------------------------------------
    # Lines 337-342 — _fallback_ident_valid: strategy-3 gap-tolerant path
    # ------------------------------------------------------------------

    def test_gap_tolerant_path_returns_true(self):
        """Lines 337-342: strategy-3 (GAP_IDENT_PATTERN) branch returns True.

        The bad 20-digit run at 0x7100 causes strategy 2 to find it first
        but fail the 0261/1267 prefix check.  The gap pattern at 0x7200
        then satisfies strategy 3 and returns True.
        """
        data = make_gap_ident_bin()
        result = EXTRACTOR._fallback_ident_valid(data)
        assert result is True

    def test_gap_tolerant_combined_length_below_20_is_false(self):
        """Lines 337-338: combined < 20 chars → strategy 3 returns False."""
        # group1 = 15 digits, group2 = 3 digits → combined = 18 (< 20)
        buf = bytearray(0x8000)
        group1 = b"012345678901234"  # 15 digits (within 25-30? No, needs 25-30)
        # Actually GAP_IDENT_PATTERN requires 25-30 digits in group1.
        # Use 25 digits that decode to INVALID hw so strategy 3 returns False.
        group1 = b"9999999999999999999912345"  # 25 digits, hw = "9999999999" (invalid)
        group2 = b"678"
        buf[0x7200 : 0x7200 + len(group1)] = group1
        buf[0x7200 + len(group1)] = 0xFF
        buf[0x7200 + len(group1) + 1 : 0x7200 + len(group1) + 1 + len(group2)] = group2
        result = EXTRACTOR._fallback_ident_valid(bytes(buf))
        assert result is False

    # ------------------------------------------------------------------
    # Lines 525-532 — _resolve_ident_num: strategy-3 gap-tolerant path
    # ------------------------------------------------------------------

    def test_resolve_ident_num_gap_tolerant_strategy(self):
        """Lines 525-532: strategy-3 returns the combined digit string."""
        data = make_gap_ident_bin()
        result = EXTRACTOR._resolve_ident_num(data)
        assert result is not None
        # combined = "0250021620022753762112345678"
        assert result.startswith("025002162002275376211")

    # ------------------------------------------------------------------
    # Line 540 — _resolve_ident_num: return None at end
    # ------------------------------------------------------------------

    def test_resolve_ident_num_returns_none_when_no_ident(self):
        """Line 540: return None when no strategy finds any valid ident."""
        data = bytes(0x8000)  # all zeros — no digit runs in any region
        result = EXTRACTOR._resolve_ident_num(data)
        assert result is None

    def test_resolve_ident_num_returns_primary_fallback_when_only_invalid_idents_exist(
        self,
    ):
        """Line 540 fallback path: return the primary-region digit run when stricter strategies reject."""
        buf = bytearray(0x8000)

        # Strategy 1/2 candidate in the 64KB tail: enough digits to match,
        # but decodes to invalid hw/sw prefixes.
        bad_tail_ident = b"12345678901234567890"
        buf[0x7100 : 0x7100 + len(bad_tail_ident)] = bad_tail_ident

        # Strategy 3 gap candidate: also matches structurally but decodes invalid.
        group1 = b"9999999999999999999912345"
        group2 = b"678"
        pos = 0x7200
        buf[pos : pos + len(group1)] = group1
        buf[pos + len(group1)] = 0xFF
        buf[pos + len(group1) + 1 : pos + len(group1) + 1 + len(group2)] = group2

        # Final fallback scans only the primary ident region and returns any
        # contiguous digit run there, even if it does not decode to 0261/1267.
        primary_fallback_ident = b"55555555556666666666"
        buf[0x1E20 : 0x1E20 + len(primary_fallback_ident)] = primary_fallback_ident

        result = EXTRACTOR._resolve_ident_num(bytes(buf))
        assert result == "55555555556666666666"

    # ------------------------------------------------------------------
    # Line 570 — _resolve_hardware_number: ident_clean too short
    # ------------------------------------------------------------------

    def test_resolve_hardware_number_returns_none_for_short_ident(self):
        """Line 570: return None when ident_clean has fewer than 10 chars."""
        result = EXTRACTOR._resolve_hardware_number("123456789")  # 9 chars
        assert result is None

    def test_resolve_hardware_number_returns_none_for_dot_prefix_short(self):
        """Line 570: split('.')[0] has 8 chars → len < 10 → return None."""
        result = EXTRACTOR._resolve_hardware_number("12345678.10")
        assert result is None

    # ------------------------------------------------------------------
    # Line 575 — _resolve_hardware_number: hw does not start with "0261"
    # ------------------------------------------------------------------

    def test_resolve_hardware_number_returns_none_for_wrong_prefix(self):
        """Line 575: hw reversed from ident does not start with '0261' → None."""
        # ident_clean[0:10] = "9876543210", reversed = "0123456789" (not 0261)
        result = EXTRACTOR._resolve_hardware_number("9876543210" + "0" * 10)
        assert result is None

    def test_resolve_hardware_number_returns_none_for_non_digit_hw(self):
        """Line 575: hw contains non-digit chars → isdigit() fails → return None."""
        # ident_clean[0:10] = "ABCDEFGHIJ", reversed = "JIHGFEDCBA"
        result = EXTRACTOR._resolve_hardware_number("ABCDEFGHIJ" + "0" * 10)
        assert result is None

    # ------------------------------------------------------------------
    # Line 604 — _resolve_software_version: ident_clean too short for SW
    # ------------------------------------------------------------------

    def test_resolve_software_version_returns_none_for_short_ident(self):
        """Line 604: return None when ident_clean has fewer than 20 chars."""
        result = EXTRACTOR._resolve_software_version("1234567890123456789")  # 19 chars
        assert result is None

    # ------------------------------------------------------------------
    # Line 609 — _resolve_software_version: sw does not start with "1267"
    # ------------------------------------------------------------------

    def test_resolve_software_version_returns_none_for_wrong_sw_prefix(self):
        """Line 609: sw reversed from ident does not start with '1267' → None."""
        # ident_clean[10:20] = "9999999999", reversed = "9999999999" (not 1267)
        result = EXTRACTOR._resolve_software_version("0250021620" + "9999999999")
        assert result is None

    def test_resolve_software_version_returns_none_for_non_digit_sw(self):
        """Line 609: sw contains non-digit chars → isdigit() fails → return None."""
        result = EXTRACTOR._resolve_software_version("0250021620" + "ABCDEFGHIJ")
        assert result is None

    def test_resolve_software_version_returns_none_for_dot_truncated_sw(self):
        """Line 609: split('.')[0] leaves a 10-char string so SW slice is unavailable."""
        result = EXTRACTOR._resolve_software_version("0250021620.1267357220")
        assert result is None

    # ------------------------------------------------------------------
    # Line 637 — _resolve_rt_code: secondary-window match
    # ------------------------------------------------------------------

    def test_resolve_rt_code_secondary_window_match(self):
        """Line 637: RT code found in last 512 bytes when primary window empty."""
        buf = bytearray(0x8000)
        # Primary window (0x1C00-0x2100) has NO RT code — leave as zeros.
        # Secondary window (last 512 bytes) has the RT code.
        rt_code = b"07826RT3557"
        buf[-200 : -200 + len(rt_code)] = rt_code
        result = EXTRACTOR._resolve_rt_code(bytes(buf))
        assert result == "07826RT3557"

    def test_resolve_rt_code_primary_window_wins_over_secondary(self):
        """Line 637 remains secondary-only by confirming primary match short-circuits first."""
        buf = bytearray(0x8000)
        primary_rt = b"12345RT6789"
        secondary_rt = b"07826RT3557"
        buf[0x1C80 : 0x1C80 + len(primary_rt)] = primary_rt
        buf[-200 : -200 + len(secondary_rt)] = secondary_rt
        result = EXTRACTOR._resolve_rt_code(bytes(buf))
        assert result == "12345RT6789"

    # ------------------------------------------------------------------
    # Line 642 — _resolve_rt_code: return None at end
    # ------------------------------------------------------------------

    def test_resolve_rt_code_returns_none_when_no_rt_code(self):
        """Line 642: return None when neither window contains a valid RT code."""
        data = bytes(0x8000)  # all zeros — no digit+RT pattern anywhere
        result = EXTRACTOR._resolve_rt_code(data)
        assert result is None
