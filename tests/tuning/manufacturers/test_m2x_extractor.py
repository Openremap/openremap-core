"""
Tests for BoschM2xExtractor (M2.9 / M2.3 / M2.7 / M2.8 / M2.81).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * M2.9 family marker b'"0000000M2.' present (Phase 2)
      * Porsche 964 M2.3 MOTRONIC label without family marker (Phase 3)
      * Marker present in various offsets within the 512KB search area
  - can_handle() — False paths:
      * 512-byte binary (too small, no marker)
      * all-zero 64KB with no M2.x marker
      * exclusion signatures block detection even with marker present
      * M3.x family marker in same binary → rejected
  - extract():
      * All required keys present
      * manufacturer == 'Bosch'
      * hardware_number starts with '0261' (from MOTOR label Format A)
      * software_version starts with '1267' (from MOTOR label Format A)
      * oem_part_number extracted
      * ecu_family resolved from M2.x sub-family marker
      * file_size == len(data)
      * sha256_first_64kb matches hashlib
      * match_key not None when SW present
  - Determinism and filename independence
"""

import hashlib

from openremap.tuning.manufacturers.bosch.m2x.extractor import BoschM2xExtractor

EXTRACTOR = BoschM2xExtractor()

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


def make_m2x_bin() -> bytes:
    """
    64KB M2.x binary with M2.9 family marker and Format A MOTOR label.

    Family marker '"0000000M2.9 ' at 0x6000 (within code region 0x5000–0x7500).
    MOTOR label at 0xCF01 — within MOTOR_LABEL_REGION (last 20KB of 64KB file):
        MOTOR_LABEL_REGION = slice(-0x5000, None)
        last 20KB starts at offset 65536 - 20480 = 45056 = 0xB000
        0xCF01 = 53249 > 45056  → within region ✓

    Format A MOTOR label:
        '021906258BK    MOTOR    PMC 02612032191267358109'
        oem  = '021906258BK'
        hw   = '0261203219'
        sw   = '1267358109'

    Regex used by _parse_motor_label Format A:
        [non-printable]{0,4}  (oem_8-14)  spaces{2-8}  MOTOR  spaces+  PMC  space+  (hw)  [ ]? (sw)
    """
    buf = bytearray(0x10000)  # 64KB

    # Phase 2 detection: canonical M2.x family marker
    marker = b'"0000000M2.9 '
    buf[0x6000 : 0x6000 + len(marker)] = marker

    # Format A MOTOR label — hw concatenated directly with sw (no space)
    motor = b"021906258BK    MOTOR    PMC 02612032191267358109"
    buf[0xCF01 : 0xCF01 + len(motor)] = motor

    return bytes(buf)


def make_m23_porsche_bin() -> bytes:
    """
    32KB Porsche 964 M2.3 binary detected via Phase 3 MOTRONIC label.

    No '"0000000M2.' marker present — Phase 2 does not fire.
    Phase 3 fires on: rb"M\\d{2}MOTRONIC\\d{4}\\d{7}0261\\d{6}"

    Label: 'M00MOTRONIC9646181240302612004731267357006'
      M\\d{2}   = 'M00'
      MOTRONIC  = 'MOTRONIC'
      \\d{4}    = '9646'  (vehicle model code: 964 6-cyl)
      \\d{7}    = '1812403'  (OEM part fragment)
      0261\\d{6}= '0261200473'  (Bosch HW number)
    Followed by SW '1267357006' (not part of Phase 3 detection pattern).
    """
    buf = bytearray(0x8000)  # 32KB

    # No M2.x family marker — deliberately omitted to exercise Phase 3
    # Porsche 964 Format B MOTRONIC label
    label = b"M00MOTRONIC9646181240302612004731267357006"
    pos = 0x7F00
    buf[pos : pos + len(label)] = label

    return bytes(buf)


def make_m28_opel_bin() -> bytes:
    """
    64KB Opel M2.8 binary with Format C ident block (0xFF-padded, no MOTOR label).

    Detection still relies on '"0000000M2.' family marker (Phase 2).
    _parse_motor_label Format C pattern:
        rb"\\xff{3,} (0261\\d{6}) ((?:1267|2227)\\d{6}) "
    hw = '0261203080', sw = '1267358003'
    """
    buf = bytearray(0x10000)  # 64KB
    buf = bytearray(b"\xff" * 0x10000)  # fill with 0xFF

    # Family marker
    marker = b'"0000000M2.8 '
    buf[0x6000 : 0x6000 + len(marker)] = marker

    # Format C ident: \xff{3+} <HW_10> <SW_10> <trailing>
    opel_block = b"\xff\xff\xff 0261203080 1267358003 M28 000"
    pos = 0xCE00
    buf[pos : pos + len(opel_block)] = opel_block

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

    def test_m29_in_supported_families(self):
        assert "M2.9" in EXTRACTOR.supported_families

    def test_m23_in_supported_families(self):
        assert "M2.3" in EXTRACTOR.supported_families

    def test_m28_in_supported_families(self):
        assert "M2.8" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschM2xExtractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# can_handle — True
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    def test_m2x_standard_bin_accepted(self):
        """Phase 2: canonical M2.x family marker present."""
        assert EXTRACTOR.can_handle(make_m2x_bin()) is True

    def test_porsche_964_m23_accepted(self):
        """Phase 3: MOTRONIC label without family marker."""
        assert EXTRACTOR.can_handle(make_m23_porsche_bin()) is True

    def test_opel_m28_bin_accepted(self):
        """Phase 2: M2.8 family marker present."""
        assert EXTRACTOR.can_handle(make_m28_opel_bin()) is True

    def test_m29_marker_alone_sufficient(self):
        """Family marker in a plain 32KB file — no MOTOR label needed."""
        buf = bytearray(0x8000)
        buf[0x5000 : 0x5000 + len(b'"0000000M2.9')] = b'"0000000M2.9'
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_m2x_marker_at_start_of_search_area(self):
        """Family marker near the beginning of the file is still found."""
        buf = bytearray(0x10000)
        buf[0x0010 : 0x0010 + len(b'"0000000M2.')] = b'"0000000M2.'
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_m2x_marker_128kb_bin_accepted(self):
        """128KB Opel M2.8/M2.81 bin — M2.x marker within first 512KB."""
        buf = bytearray(0x20000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_motronic_phase3_with_different_model_code(self):
        """Phase 3 MOTRONIC pattern accepts various model codes."""
        buf = bytearray(0x8000)
        # Different model code (e.g. 9646 → 9000) and part fragment
        label = b"M01MOTRONIC9000999999902611234561267000001"
        buf[0x7000 : 0x7000 + len(label)] = label
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle — False
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    def test_512_byte_binary_rejected(self):
        """Too small and no marker."""
        assert EXTRACTOR.can_handle(bytes(512)) is False

    def test_all_zero_64kb_rejected(self):
        """64KB all-zero — no M2.x marker, no MOTRONIC pattern."""
        assert EXTRACTOR.can_handle(bytes(0x10000)) is False

    def test_all_zero_32kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x8000)) is False

    def test_empty_binary_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_edc17_exclusion_overrides_m2x_marker(self):
        """Phase 1 exclusion: EDC17 blocks M2.x marker detection."""
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x0100:0x0106] = b"EDC17\x00"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_medc17_exclusion_overrides_m2x_marker(self):
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x0200:0x0207] = b"MEDC17\x00"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_exclusion_overrides_m2x_marker(self):
        """ME7. exclusion signature blocks M2.x detection."""
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x0300:0x0304] = b"ME7."
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_sb_v_exclusion_rejects_binary(self):
        """SB_V is a modern Bosch marker — always an exclusion."""
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x1000:0x1004] = b"SB_V"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_zz_ff_ff_exclusion(self):
        """ZZ\\xff\\xff is an ME7 ident marker — exclusion for M2.x."""
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x0400:0x0404] = b"ZZ\xff\xff"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m3x_marker_1530000m3_exclusion(self):
        """M3.3 family marker (1530000M3) is an exclusion signature."""
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x4002:0x400B] = b"1530000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m3x_marker_1350000m3_exclusion(self):
        """M3.1 family marker (1350000M3) is an exclusion signature."""
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x0050:0x0059] = b"1350000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m1x_family_marker_exclusion(self):
        """'"0000000M1' is an M1.x family marker — exclusion for M2.x."""
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x7500:0x750B] = b'"0000000M1.'
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_customer_dot_exclusion(self):
        """'Customer.' is a modern Bosch label — exclusion signature."""
        buf = bytearray(0x10000)
        buf[0x6000 : 0x6000 + len(b'"0000000M2.')] = b'"0000000M2.'
        buf[0x1500:0x150A] = b"Customer.\x00"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# extract() — Format A (standard M2.9)
# ---------------------------------------------------------------------------


class TestExtractFormatA:
    """Standard Format A MOTOR label extraction for M2.9 bins."""

    def setup_method(self):
        self.data = make_m2x_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_all_required_keys_present(self):
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in self.result, f"Missing required key: {key!r}"

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_hardware_number_not_none(self):
        assert self.result["hardware_number"] is not None

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_hardware_number_exact_value(self):
        assert self.result["hardware_number"] == "0261203219"

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_software_version_not_none(self):
        assert self.result["software_version"] is not None

    def test_software_version_starts_with_1267(self):
        assert self.result["software_version"].startswith("1267")

    def test_software_version_exact_value(self):
        assert self.result["software_version"] == "1267358109"

    def test_software_version_is_10_digits(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert len(sw) == 10
        assert sw.isdigit()

    def test_oem_part_number_extracted(self):
        oem = self.result.get("oem_part_number")
        assert oem is not None
        assert "021906258" in oem

    def test_file_size_equals_data_length(self):
        assert self.result["file_size"] == len(self.data)

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000

    def test_sha256_first_64kb_is_64_hex_chars(self):
        sha = self.result["sha256_first_64kb"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        int(sha, 16)  # raises ValueError if not valid hex

    def test_sha256_first_64kb_matches_hashlib(self):
        expected = hashlib.sha256(self.data[:0x10000]).hexdigest()
        assert self.result["sha256_first_64kb"] == expected

    def test_match_key_not_none_when_sw_present(self):
        """Software version is present → match key can be built."""
        assert self.result["match_key"] is not None

    def test_match_key_contains_software_version(self):
        mk = self.result["match_key"]
        sw = self.result["software_version"]
        assert mk is not None and sw is not None
        assert sw in mk

    def test_match_key_contains_m2_family(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert "M2" in mk.upper()

    def test_ecu_family_is_string(self):
        assert isinstance(self.result["ecu_family"], str)

    def test_ecu_family_contains_m2(self):
        assert "M2" in self.result["ecu_family"]

    def test_ecu_variant_matches_ecu_family(self):
        """M2.x sets ecu_variant == ecu_family."""
        assert self.result["ecu_variant"] == self.result["ecu_family"]

    def test_calibration_id_is_none(self):
        """M2.x binaries do not carry a calibration_id field."""
        assert self.result["calibration_id"] is None


# ---------------------------------------------------------------------------
# extract() — Format A with SW starting with 2227
# ---------------------------------------------------------------------------


class TestExtractFormatA2227Sw:
    """Some M2.9 AE variants use SW starting with 2227 instead of 1267."""

    def _make_2227_bin(self) -> bytes:
        buf = bytearray(0x10000)
        marker = b'"0000000M2.9 '
        buf[0x6000 : 0x6000 + len(marker)] = marker
        # SW starts with 2227 (AE variant)
        motor = b"037906258AE    MOTOR    PMC 02612040182227355905"
        buf[0xCF01 : 0xCF01 + len(motor)] = motor
        return bytes(buf)

    def test_software_version_starts_with_2227(self):
        data = self._make_2227_bin()
        result = EXTRACTOR.extract(data)
        sw = result["software_version"]
        assert sw is not None
        assert sw.startswith("2227")

    def test_hardware_number_starts_with_0261(self):
        data = self._make_2227_bin()
        result = EXTRACTOR.extract(data)
        hw = result["hardware_number"]
        assert hw is not None
        assert hw.startswith("0261")


# ---------------------------------------------------------------------------
# extract() — Format C (Opel M2.8, 0xFF-padded ident)
# ---------------------------------------------------------------------------


class TestExtractFormatCOpel:
    """Opel M2.8 Format C: HW and SW in a 0xFF-padded block, no MOTOR label."""

    def setup_method(self):
        self.data = make_m28_opel_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_all_required_keys_present(self):
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in self.result, f"Missing required key: {key!r}"

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_hardware_number_starts_with_0261(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert hw.startswith("0261")

    def test_hardware_number_exact_value(self):
        assert self.result["hardware_number"] == "0261203080"

    def test_software_version_starts_with_1267(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert sw.startswith("1267")

    def test_software_version_exact_value(self):
        assert self.result["software_version"] == "1267358003"

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000


# ---------------------------------------------------------------------------
# extract() — binary with marker but no MOTOR label
# ---------------------------------------------------------------------------


class TestExtractNoMotorLabel:
    """When the MOTOR label is absent, HW and SW should be None."""

    def _make_marker_only_bin(self) -> bytes:
        buf = bytearray(0x10000)
        marker = b'"0000000M2.9 '
        buf[0x6000 : 0x6000 + len(marker)] = marker
        # Deliberately no MOTOR label or ident block
        return bytes(buf)

    def test_hardware_number_none_without_motor_label(self):
        data = self._make_marker_only_bin()
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] is None

    def test_software_version_none_without_motor_label(self):
        data = self._make_marker_only_bin()
        result = EXTRACTOR.extract(data)
        assert result["software_version"] is None

    def test_manufacturer_still_bosch(self):
        data = self._make_marker_only_bin()
        result = EXTRACTOR.extract(data)
        assert result["manufacturer"] == "Bosch"

    def test_file_size_still_correct(self):
        data = self._make_marker_only_bin()
        result = EXTRACTOR.extract(data)
        assert result["file_size"] == len(data)


# ---------------------------------------------------------------------------
# Determinism and filename independence
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_same_binary_produces_same_result(self):
        data = make_m2x_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["ecu_family"] == r2["ecu_family"]
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_filename_does_not_affect_identification_fields(self):
        data = make_m2x_bin()
        r1 = EXTRACTOR.extract(data, filename="original.bin")
        r2 = EXTRACTOR.extract(data, filename="renamed_copy.bin")
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_different_binaries_differ_in_sha256(self):
        r1 = EXTRACTOR.extract(make_m2x_bin())
        r2 = EXTRACTOR.extract(make_m23_porsche_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]

    def test_different_binaries_differ_in_file_size(self):
        r1 = EXTRACTOR.extract(make_m2x_bin())
        r2 = EXTRACTOR.extract(make_m23_porsche_bin())
        assert r1["file_size"] != r2["file_size"]
        assert r1["file_size"] == 0x10000
        assert r2["file_size"] == 0x8000


# ---------------------------------------------------------------------------
# Coverage: m2x/extractor.py lines 290-295 and 385-390
# ---------------------------------------------------------------------------


class TestCoverageM2xFallbackEdges:
    """Cover the DAMOS-style family fallback and Format-D motor-label parser."""

    # ------------------------------------------------------------------
    # Lines 290-295 — _resolve_ecu_family: DAMOS /M2.xx/ fallback
    # ------------------------------------------------------------------

    def test_damos_fallback_returns_m2_family(self):
        """Lines 290-295: '/M2.81/' pattern triggers DAMOS fallback → 'M2.8'."""
        # Build a 64KB binary that has the DAMOS ident '/M2.81/' in the first
        # 512KB search area but NO canonical '"0000000M2.' marker and no
        # 'MOTRONIC' string, so only the DAMOS branch fires.
        buf = bytearray(0x10000)
        buf[0x5000:0x5007] = b"/M2.81/"
        result = EXTRACTOR._resolve_ecu_family(bytes(buf))
        assert result == "M2.8"

    def test_damos_fallback_first_digit_only(self):
        """Lines 290-295: multi-digit DAMOS variant normalised to first digit."""
        buf = bytearray(0x10000)
        buf[0x4000:0x4008] = b"/M2.99/"
        result = EXTRACTOR._resolve_ecu_family(bytes(buf))
        assert result == "M2.9"

    def test_damos_fallback_single_digit_variant(self):
        """Lines 290-295: single-digit DAMOS variant returned verbatim."""
        buf = bytearray(0x10000)
        buf[0x3000:0x3006] = b"/M2.7/"
        result = EXTRACTOR._resolve_ecu_family(bytes(buf))
        assert result == "M2.7"

    def test_no_marker_no_motronic_no_damos_returns_none(self):
        """_resolve_ecu_family returns None when no marker is found at all."""
        buf = bytearray(0x10000)
        result = EXTRACTOR._resolve_ecu_family(bytes(buf))
        assert result is None

    # ------------------------------------------------------------------
    # Lines 385-390 — _parse_motor_label: Format D (reversed-string ident)
    # ------------------------------------------------------------------

    def test_format_d_dx_reversed_ident_extracted(self):
        """Lines 385-390: 'dx' + reversed HW/SW digits → Format D extracts hw/sw.

        Opel M2.7 32KB bins store 'dx' + group1(10 digits) + group2(10 digits)
        where each 10-digit group is the HW or SW number reversed char-by-char.

          group1 = '4103021620'  →  [::-1] = '0261203014'  (hw, starts '0261')
          group2 = '0227537621'  →  [::-1] = '1267357220'  (sw, starts '1267')
        """
        buf = bytearray(0x10000)
        # MOTOR_LABEL_REGION is slice(-0x5000, None) — last 20KB of the file.
        # For a 64KB binary that is data[0xB000:]. Place the dx block at 0xC000.
        dx_block = b"dx" + b"4103021620" + b"0227537621"
        buf[0xC000 : 0xC000 + len(dx_block)] = dx_block
        hw, sw, oem = EXTRACTOR._parse_motor_label(bytes(buf))
        assert hw == "0261203014"
        assert sw == "1267357220"
        assert oem is None

    def test_format_d_2227_sw_prefix_accepted(self):
        """Lines 385-390: Format D also accepts '2227'-prefixed SW versions."""
        buf = bytearray(0x10000)
        # sw = '2227357220' → reversed = '0227537222'[::-1] = '2227357220'
        # group2 must reverse to start with '2227'
        # '2227357220'[::-1] = '0227537222' → group2 = '0227537222'
        dx_block = b"dx" + b"4103021620" + b"0227537222"
        buf[0xC000 : 0xC000 + len(dx_block)] = dx_block
        hw, sw, oem = EXTRACTOR._parse_motor_label(bytes(buf))
        assert hw == "0261203014"
        assert sw == "2227357220"
        assert oem is None

    def test_format_d_invalid_hw_prefix_falls_through_to_none(self):
        """Lines 385-390: Format D match with invalid hw prefix → falls to (None×3)."""
        buf = bytearray(0x10000)
        # group1 reversed = '9999999999' (no '0261') → Format D check fails
        dx_block = b"dx" + b"9999999999" + b"0227537621"
        buf[0xC000 : 0xC000 + len(dx_block)] = dx_block
        hw, sw, oem = EXTRACTOR._parse_motor_label(bytes(buf))
        assert hw is None
        assert sw is None
        assert oem is None
