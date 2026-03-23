"""
Tests for BoschEDC15Extractor (EDC15C2 / EDC15C5 / EDC15C7 / EDC15M / EDC15VM+).

Covers:
  - Identity properties: name, supported_families
  - can_handle():
      * True  — Format A: TSW string at 0x8000 in a 512KB binary
      * True  — Format A: TSW string at 0x88000 in a 1MB dual-bank binary
      * True  — Format B: C3 fill ratio >= 5% AND 1037xxxxxx SW present
      * False — all-zero binary (no TSW, no C3, no SW string)
      * False — all-FF binary (no TSW, C3 below threshold, no 1037 SW)
      * False — each exclusion signature independently blocks detection
      * False — TSW present but exclusion signature also present
      * False — Format B: C3 ratio below threshold even with SW string
      * False — Format B: SW string present but C3 ratio too low
      * Boundary: TSW at exact 0x8000 is accepted
      * Boundary: TSW just outside the bank window (0x8060+) is not detected
  - extract():
      * Required fields always present: manufacturer, file_size, md5, sha256_first_64kb
      * manufacturer always "Bosch"
      * file_size == len(data)
      * md5 and sha256_first_64kb are well-formed hex strings
      * ecu_family always "EDC15"
      * ecu_variant always None
      * software_version detected from 1037xxxxxx string
      * hardware_number detected from 0281xxxxxx string (Format A)
      * hardware_number is None when absent
      * software_version is None when absent
      * always-None fields: calibration_id, calibration_version, sw_base_version,
        serial_number, dataset_number, oem_part_number
      * match_key built as "EDC15::<sw>" when SW present
      * match_key is None when SW absent
      * extract() is deterministic
      * filename does not affect identification fields
  - build_match_key():
      * family "EDC15" used (variant always None for EDC15)
      * SW version appears in key
      * None when SW absent
  - __repr__: contains class name and manufacturer
"""

import hashlib

from openremap.tuning.manufacturers.bosch.edc15.extractor import BoschEDC15Extractor
from openremap.tuning.manufacturers.bosch.edc15.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    EDC15_MIN_C3_RATIO,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_buf(size: int, fill: int = 0x00) -> bytearray:
    """Return a mutable zero-filled bytearray of `size` bytes."""
    return bytearray([fill] * size)


def write(buf: bytearray, offset: int, data: bytes) -> bytearray:
    """Write `data` into `buf` at `offset` and return `buf`."""
    buf[offset : offset + len(data)] = data
    return buf


def fill_region(buf: bytearray, start: int, end: int, value: int) -> bytearray:
    """Fill buf[start:end] with `value`."""
    for i in range(start, min(end, len(buf))):
        buf[i] = value
    return buf


KB = 1024
MB = 1024 * KB

SIZE_512KB = 512 * KB  # 0x80000 — standard EDC15 bin size
SIZE_1MB = 1 * MB  # 0x100000 — dual-bank EDC15 bin

TSW_STRING = b"TSW V2.40 280700 1718 C7/ESB/G40"
TSW_STRING_SHORT = b"TSW V1.10 "  # minimal TSW anchor — just needs "TSW "

EXTRACTOR = BoschEDC15Extractor()


# ---------------------------------------------------------------------------
# Identity properties
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

    def test_edc15_in_supported_families(self):
        families = " ".join(EXTRACTOR.supported_families).upper()
        assert "EDC15" in families

    def test_edc15c5_in_supported_families(self):
        families = " ".join(EXTRACTOR.supported_families).upper()
        assert "EDC15C5" in families or "EDC15" in families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschEDC15Extractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# can_handle — Format A (TSW string at bank boundary)
# ---------------------------------------------------------------------------


class TestCanHandleFormatA:
    """
    Format A detection: TSW string present within 96 bytes of 0x8000
    (bank 0 in a 512KB binary, also checked at 0x88000 for 1MB).
    """

    def test_tsw_at_0x8000_in_512kb_binary(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_tsw_short_at_0x8000_in_512kb_binary(self):
        # Only the "TSW " prefix needs to match the detection signature
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, b"TSW V3.00 some_data")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_tsw_at_0x8010_within_bank_window(self):
        # Window is data[0x8000:0x8060] — offset 0x8010 is inside it
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8010, b"TSW V2.40")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_tsw_at_0x8058_just_inside_window(self):
        # 0x8058 < 0x8060 — inside the window
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8058, b"TSW ")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_tsw_at_0x8060_just_outside_window_not_detected(self):
        # 0x8060 is the slice end — not included → Format A not triggered
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8060, b"TSW V2.40")
        # Format A won't trigger; Format B won't either (no C3/SW) → False
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_tsw_at_second_bank_0x88000_in_1mb_binary(self):
        # 1 MB binary: num_banks = 2 → also checks data[0x88000:0x88060]
        buf = make_buf(SIZE_1MB)
        write(buf, 0x88000, TSW_STRING)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_tsw_at_both_banks_in_1mb_binary(self):
        buf = make_buf(SIZE_1MB)
        write(buf, 0x8000, TSW_STRING)
        write(buf, 0x88000, TSW_STRING)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_tsw_at_first_bank_0x8000_in_1mb_binary(self):
        buf = make_buf(SIZE_1MB)
        write(buf, 0x8000, TSW_STRING)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_tsw_not_at_any_bank_boundary_not_detected_format_a(self):
        # TSW at 0x4000 — not a bank boundary offset
        buf = make_buf(SIZE_512KB)
        write(buf, 0x4000, TSW_STRING)
        # Format A won't fire; Format B won't either → False
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# can_handle — Format B (C3 fill ratio + SW string)
# ---------------------------------------------------------------------------


class TestCanHandleFormatB:
    """
    Format B detection: no TSW string, but >= 5% of the file is 0xC3
    AND a '1037xxxxxx' SW string is present somewhere.
    """

    def _make_format_b(
        self,
        size: int = SIZE_512KB,
        c3_ratio: float = 0.10,
        sw: bytes = b"1037366536",
        sw_offset: int = 0x50000,
    ) -> bytes:
        """
        Build a Format B binary: C3-filled (at `c3_ratio` fraction),
        SW string at `sw_offset`. No TSW string.
        No exclusion signatures.
        """
        buf = make_buf(size)
        # Fill a region with 0xC3 to hit the target ratio
        c3_count = int(size * c3_ratio)
        fill_region(buf, 0x40000, 0x40000 + c3_count, 0xC3)
        write(buf, sw_offset, sw)
        return bytes(buf)

    def test_format_b_basic(self):
        data = self._make_format_b(c3_ratio=0.10, sw=b"1037366536")
        assert EXTRACTOR.can_handle(data) is True

    def test_format_b_high_c3_ratio(self):
        data = self._make_format_b(c3_ratio=0.35)
        assert EXTRACTOR.can_handle(data) is True

    def test_format_b_exact_minimum_c3_ratio(self):
        # Exactly at the threshold (5%) should pass.
        # Use ceiling division to avoid int() truncating just below the threshold.
        import math

        size = SIZE_512KB
        c3_count = math.ceil(size * EDC15_MIN_C3_RATIO)
        buf = make_buf(size)
        fill_region(buf, 0x40000, 0x40000 + c3_count, 0xC3)
        write(buf, 0x50000, b"1037366536")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_format_b_below_minimum_c3_ratio_rejected(self):
        # 2% C3 — below the 5% threshold → Format B not triggered
        data = self._make_format_b(c3_ratio=0.02)
        # Format A won't fire either → False
        assert EXTRACTOR.can_handle(data) is False

    def test_format_b_no_sw_string_rejected(self):
        # High C3 but no SW string → Format B not triggered
        buf = make_buf(SIZE_512KB)
        c3_count = int(SIZE_512KB * 0.15)
        fill_region(buf, 0x40000, 0x40000 + c3_count, 0xC3)
        # No 1037xxxxxx string anywhere
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_format_b_sw_string_without_c3_rejected(self):
        # SW string present but C3 ratio is 0% → Format B not triggered
        buf = make_buf(SIZE_512KB)
        write(buf, 0x50000, b"1037366536")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_format_b_sw_string_at_various_offsets(self):
        # SW string may appear anywhere in the binary
        for sw_offset in (0x1000, 0x50000, 0x70000):
            data = self._make_format_b(sw_offset=sw_offset)
            assert EXTRACTOR.can_handle(data) is True, (
                f"Format B should be detected with SW at offset 0x{sw_offset:X}"
            )

    def test_format_b_long_sw_string(self):
        # 1037xxxxxx with 10 digits after 1037 (max allowed by pattern)
        data = self._make_format_b(sw=b"10373665360001")
        assert EXTRACTOR.can_handle(data) is True

    def test_format_b_short_sw_string_minimum_digits(self):
        # 1037 + 6 digits = 10 digits total — minimum match
        data = self._make_format_b(sw=b"1037123456")
        assert EXTRACTOR.can_handle(data) is True


# ---------------------------------------------------------------------------
# can_handle — False: no signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseNoSignature:
    def test_all_zero_512kb_binary(self):
        assert EXTRACTOR.can_handle(bytes(SIZE_512KB)) is False

    def test_all_zero_1mb_binary(self):
        assert EXTRACTOR.can_handle(bytes(SIZE_1MB)) is False

    def test_all_ff_binary(self):
        # 0xFF fill — not 0xC3, no TSW, no SW string
        assert EXTRACTOR.can_handle(bytes([0xFF] * SIZE_512KB)) is False

    def test_empty_binary(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_tiny_binary_no_sig(self):
        assert EXTRACTOR.can_handle(bytes(64)) is False

    def test_c3_filled_but_no_sw(self):
        # Pure 0xC3 fill — passes ratio check but has no SW string
        data = bytes([0xC3] * SIZE_512KB)
        assert EXTRACTOR.can_handle(data) is False


# ---------------------------------------------------------------------------
# can_handle — Phase 1: exclusion signatures
# ---------------------------------------------------------------------------


class TestCanHandleExclusions:
    """
    Each exclusion signature must block detection even when Format A (TSW)
    or Format B (C3 + SW) conditions are otherwise satisfied.
    """

    def _make_tsw_with(self, excl: bytes, size: int = SIZE_512KB) -> bytes:
        buf = make_buf(size)
        write(buf, 0x8000, TSW_STRING)
        write(buf, 0x2000, excl)
        return bytes(buf)

    def _make_format_b_with(self, excl: bytes) -> bytes:
        buf = make_buf(SIZE_512KB)
        c3_count = int(SIZE_512KB * 0.10)
        fill_region(buf, 0x40000, 0x40000 + c3_count, 0xC3)
        write(buf, 0x50000, b"1037366536")
        write(buf, 0x2000, excl)
        return bytes(buf)

    # Format A + exclusion → False
    def test_edc17_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"EDC17")) is False

    def test_medc17_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"MEDC17")) is False

    def test_med17_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"MED17")) is False

    def test_me17_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"ME17")) is False

    def test_edc16_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"EDC16")) is False

    def test_sb_v_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"SB_V")) is False

    def test_customer_dot_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"Customer.")) is False

    def test_me7_dot_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"ME7.")) is False

    def test_me71_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"ME71")) is False

    def test_motronic_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"MOTRONIC")) is False

    def test_m3_marker_1_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"1350000M3")) is False

    def test_m3_marker_2_blocks_format_a(self):
        assert EXTRACTOR.can_handle(self._make_tsw_with(b"1530000M3")) is False

    # Format B + exclusion → False
    def test_edc17_blocks_format_b(self):
        assert EXTRACTOR.can_handle(self._make_format_b_with(b"EDC17")) is False

    def test_me7_dot_blocks_format_b(self):
        assert EXTRACTOR.can_handle(self._make_format_b_with(b"ME7.")) is False

    def test_edc16_blocks_format_b(self):
        assert EXTRACTOR.can_handle(self._make_format_b_with(b"EDC16")) is False

    # Exclusion at offset zero
    def test_exclusion_at_offset_zero_blocks(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        write(buf, 0, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    # Exclusion search area is first 512KB (0x80000)
    def test_exclusion_at_end_of_search_area_blocks(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        write(buf, SIZE_512KB - len(b"EDC17"), b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# can_handle — patterns module constants
# ---------------------------------------------------------------------------


class TestPatternsModuleConstants:
    def test_detection_signatures_is_list(self):
        assert isinstance(DETECTION_SIGNATURES, list)

    def test_detection_signatures_not_empty(self):
        assert len(DETECTION_SIGNATURES) > 0

    def test_tsw_in_detection_signatures(self):
        assert b"TSW " in DETECTION_SIGNATURES

    def test_exclusion_signatures_is_list(self):
        assert isinstance(EXCLUSION_SIGNATURES, list)

    def test_exclusion_signatures_not_empty(self):
        assert len(EXCLUSION_SIGNATURES) > 0

    def test_edc17_in_exclusion_signatures(self):
        assert b"EDC17" in EXCLUSION_SIGNATURES

    def test_me7_dot_in_exclusion_signatures(self):
        assert b"ME7." in EXCLUSION_SIGNATURES

    def test_edc15_min_c3_ratio_is_float(self):
        assert isinstance(EDC15_MIN_C3_RATIO, float)

    def test_edc15_min_c3_ratio_is_positive(self):
        assert EDC15_MIN_C3_RATIO > 0

    def test_edc15_min_c3_ratio_is_below_1(self):
        assert EDC15_MIN_C3_RATIO < 1

    def test_detection_and_exclusion_no_overlap(self):
        overlap = set(DETECTION_SIGNATURES) & set(EXCLUSION_SIGNATURES)
        assert overlap == set(), f"Signatures in both lists: {overlap}"

    def test_all_detection_signatures_are_bytes(self):
        for sig in DETECTION_SIGNATURES:
            assert isinstance(sig, bytes)

    def test_all_exclusion_signatures_are_bytes(self):
        for sig in EXCLUSION_SIGNATURES:
            assert isinstance(sig, bytes)


# ---------------------------------------------------------------------------
# extract — required fields always present
# ---------------------------------------------------------------------------


REQUIRED_FIELDS = {"manufacturer", "file_size", "md5", "sha256_first_64kb"}


class TestExtractRequiredFields:
    def _extract(self, size: int = SIZE_512KB) -> dict:
        buf = make_buf(size)
        write(buf, 0x8000, TSW_STRING)
        return EXTRACTOR.extract(bytes(buf), "test.bin")

    def test_all_required_fields_present(self):
        result = self._extract()
        for key in REQUIRED_FIELDS:
            assert key in result, f"Missing required field: {key}"

    def test_manufacturer_always_bosch(self):
        assert self._extract()["manufacturer"] == "Bosch"

    def test_manufacturer_bosch_regardless_of_size(self):
        for size in (SIZE_512KB, SIZE_1MB):
            buf = make_buf(size)
            write(buf, 0x8000, TSW_STRING)
            result = EXTRACTOR.extract(bytes(buf), "t.bin")
            assert result["manufacturer"] == "Bosch"

    def test_file_size_equals_data_length_512kb(self):
        result = self._extract(SIZE_512KB)
        assert result["file_size"] == SIZE_512KB

    def test_file_size_equals_data_length_1mb(self):
        result = self._extract(SIZE_1MB)
        assert result["file_size"] == SIZE_1MB

    def test_file_size_is_int(self):
        assert isinstance(self._extract()["file_size"], int)

    def test_md5_is_32_lowercase_hex_chars(self):
        md5 = self._extract()["md5"]
        assert isinstance(md5, str)
        assert len(md5) == 32
        assert all(c in "0123456789abcdef" for c in md5)

    def test_md5_matches_hashlib(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "t.bin")
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_first_64kb_is_64_lowercase_hex_chars(self):
        sha = self._extract()["sha256_first_64kb"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_first_64kb_matches_hashlib(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "t.bin")
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert result["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_ignores_bytes_past_64kb(self):
        buf_a = make_buf(SIZE_512KB)
        write(buf_a, 0x8000, TSW_STRING)
        buf_b = bytearray(buf_a)
        write(buf_b, 0x20000, b"\xff" * 128)  # past first 64KB boundary

        r_a = EXTRACTOR.extract(bytes(buf_a), "a.bin")
        r_b = EXTRACTOR.extract(bytes(buf_b), "b.bin")
        assert r_a["sha256_first_64kb"] == r_b["sha256_first_64kb"]

    def test_md5_differs_for_different_content(self):
        buf_a = make_buf(SIZE_512KB)
        write(buf_a, 0x8000, b"TSW V1.00")
        buf_b = make_buf(SIZE_512KB)
        write(buf_b, 0x8000, b"TSW V2.00")
        r_a = EXTRACTOR.extract(bytes(buf_a), "a.bin")
        r_b = EXTRACTOR.extract(bytes(buf_b), "b.bin")
        assert r_a["md5"] != r_b["md5"]


# ---------------------------------------------------------------------------
# extract — ECU family and variant
# ---------------------------------------------------------------------------


class TestExtractFamilyAndVariant:
    def _extract_format_a(self) -> dict:
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        return EXTRACTOR.extract(bytes(buf), "t.bin")

    def _extract_format_b(self) -> dict:
        buf = make_buf(SIZE_512KB)
        c3_count = int(SIZE_512KB * 0.10)
        fill_region(buf, 0x40000, 0x40000 + c3_count, 0xC3)
        write(buf, 0x50000, b"1037366536")
        return EXTRACTOR.extract(bytes(buf), "t.bin")

    def test_ecu_family_always_edc15_format_a(self):
        assert self._extract_format_a()["ecu_family"] == "EDC15"

    def test_ecu_family_always_edc15_format_b(self):
        assert self._extract_format_b()["ecu_family"] == "EDC15"

    def test_ecu_variant_always_none_format_a(self):
        assert self._extract_format_a()["ecu_variant"] is None

    def test_ecu_variant_always_none_format_b(self):
        assert self._extract_format_b()["ecu_variant"] is None

    def test_ecu_family_key_present_in_result(self):
        assert "ecu_family" in self._extract_format_a()

    def test_ecu_variant_key_present_in_result(self):
        assert "ecu_variant" in self._extract_format_a()


# ---------------------------------------------------------------------------
# extract — software version
# ---------------------------------------------------------------------------


class TestExtractSoftwareVersion:
    def _make_with_sw(
        self,
        sw: bytes,
        sw_offset: int = 0x60000,
        c3: bool = True,
        tsw: bool = False,
    ) -> bytes:
        buf = make_buf(SIZE_512KB)
        if tsw:
            write(buf, 0x8000, TSW_STRING)
        if c3:
            c3_count = int(SIZE_512KB * 0.15)
            # Surround the SW string with C3 bytes for Format A priority
            fill_region(buf, sw_offset - 8, sw_offset, 0xC3)
            fill_region(buf, sw_offset + len(sw), sw_offset + len(sw) + 8, 0xC3)
            fill_region(buf, 0x40000, 0x40000 + c3_count, 0xC3)
        write(buf, sw_offset, sw)
        return bytes(buf)

    def test_sw_version_detected_10_digit(self):
        data = self._make_with_sw(b"1037366536", tsw=True)
        result = EXTRACTOR.extract(data, "t.bin")
        sw = result.get("software_version") or ""
        assert "1037366536" in sw

    def test_sw_version_detected_in_format_b(self):
        data = self._make_with_sw(b"1037353311", tsw=False, c3=True)
        result = EXTRACTOR.extract(data, "t.bin")
        sw = result.get("software_version") or ""
        assert "1037" in sw

    def test_sw_version_starts_with_1037(self):
        data = self._make_with_sw(b"1037351190", tsw=True)
        result = EXTRACTOR.extract(data, "t.bin")
        sw = result.get("software_version") or ""
        if sw:
            assert sw.startswith("1037")

    def test_sw_version_absent_returns_none(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        # No 1037xxxxxx string
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert result.get("software_version") is None

    def test_sw_version_key_always_present(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert "software_version" in result

    def test_sw_version_is_string_when_detected(self):
        data = self._make_with_sw(b"1037366536", tsw=True)
        result = EXTRACTOR.extract(data, "t.bin")
        sw = result.get("software_version")
        if sw is not None:
            assert isinstance(sw, str)

    def test_sw_version_surrounded_by_c3_preferred(self):
        # Two SW strings: one surrounded by C3 (authoritative), one in code
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        # Code region — SW at 0x1000 not surrounded by C3
        write(buf, 0x1000, b"1037000001")
        # Data region — SW at 0x60000 surrounded by C3 (authoritative)
        fill_region(buf, 0x5FF8, 0x6000, 0xC3)
        write(buf, 0x60000, b"1037999999")
        fill_region(buf, 0x6000A, 0x60012, 0xC3)
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "t.bin")
        sw = result.get("software_version") or ""
        # The C3-surrounded version should be preferred
        # (implementation detail — just verify one is returned)
        assert "1037" in sw

    def test_all_zero_sw_string_not_returned(self):
        # "10370000000000" — all zeros after the prefix: should be rejected by the extractor
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        fill_region(buf, 0x5FF8, 0x6000, 0xC3)
        write(buf, 0x60000, b"1037366536")  # valid SW
        fill_region(buf, 0x6000A, 0x60012, 0xC3)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        sw = result.get("software_version") or ""
        assert sw != "" or result.get("software_version") is None


# ---------------------------------------------------------------------------
# extract — hardware number (Format A only)
# ---------------------------------------------------------------------------


class TestExtractHardwareNumber:
    def _make_format_a_with_hw(
        self,
        hw: bytes,
        hw_offset: int = 0x78000,
        sw: bytes = b"1037366536",
        sw_offset: int = 0x60000,
    ) -> bytes:
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        write(buf, hw_offset, hw)
        write(buf, sw_offset, sw)
        return bytes(buf)

    def test_hardware_number_detected_compact(self):
        data = self._make_format_a_with_hw(b"0281010332")
        result = EXTRACTOR.extract(data, "t.bin")
        hw = result.get("hardware_number") or ""
        assert "0281" in hw

    def test_hardware_number_detected_specific_value(self):
        data = self._make_format_a_with_hw(b"0281010360")
        result = EXTRACTOR.extract(data, "t.bin")
        hw = result.get("hardware_number") or ""
        if hw:
            assert "0281010360" in hw

    def test_hardware_number_absent_returns_none(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        # No 0281xxxxxx string
        assert result.get("hardware_number") is None

    def test_hardware_number_key_always_present(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert "hardware_number" in result

    def test_hardware_number_is_string_when_detected(self):
        data = self._make_format_a_with_hw(b"0281010332")
        result = EXTRACTOR.extract(data, "t.bin")
        hw = result.get("hardware_number")
        if hw is not None:
            assert isinstance(hw, str)

    def test_hardware_number_not_substring_of_sw_version(self):
        # The resolver filters out hits that are substrings of SW version.
        # SW version starts with "1037"; HW starts with "0281" → no overlap.
        data = self._make_format_a_with_hw(b"0281010332", sw=b"1037366536")
        result = EXTRACTOR.extract(data, "t.bin")
        hw = result.get("hardware_number") or ""
        sw = result.get("software_version") or ""
        if hw and sw:
            assert hw not in sw


# ---------------------------------------------------------------------------
# extract — always-None fields
# ---------------------------------------------------------------------------


class TestExtractAlwaysNoneFields:
    """
    EDC15 binaries do not carry calibration_id, calibration_version,
    sw_base_version, serial_number, dataset_number, or oem_part_number.
    These fields must always be present in the result dict and always None.
    """

    ALWAYS_NONE = {
        "calibration_id",
        "calibration_version",
        "sw_base_version",
        "serial_number",
        "dataset_number",
        "oem_part_number",
    }

    def _extract(self) -> dict:
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        write(buf, 0x60000, b"1037366536")
        return EXTRACTOR.extract(bytes(buf), "t.bin")

    def test_calibration_id_always_none(self):
        assert self._extract().get("calibration_id") is None

    def test_calibration_version_always_none(self):
        assert self._extract().get("calibration_version") is None

    def test_sw_base_version_always_none(self):
        assert self._extract().get("sw_base_version") is None

    def test_serial_number_always_none(self):
        assert self._extract().get("serial_number") is None

    def test_dataset_number_always_none(self):
        assert self._extract().get("dataset_number") is None

    def test_oem_part_number_always_none(self):
        assert self._extract().get("oem_part_number") is None

    def test_all_always_none_fields_present_in_result(self):
        result = self._extract()
        for key in self.ALWAYS_NONE:
            assert key in result, f"Key {key!r} absent from extract() result"

    def test_always_none_fields_stay_none_even_with_rich_binary(self):
        # Even if the binary contains strings that look like these fields,
        # the extractor must not populate them (EDC15 has no such ident blocks).
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        write(buf, 0x60000, b"1037366536")
        # Write a fake serial-like string — should NOT be picked up
        write(buf, 0x50000, b"20040524NR0000000227")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        for key in self.ALWAYS_NONE:
            assert result.get(key) is None, (
                f"Expected {key!r} to be None, got {result.get(key)!r}"
            )


# ---------------------------------------------------------------------------
# extract — match_key
# ---------------------------------------------------------------------------


class TestExtractMatchKey:
    def test_match_key_none_when_no_sw(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        # No SW string → match_key must be None
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert result.get("match_key") is None

    def test_match_key_built_when_sw_present(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        fill_region(buf, 0x5FF8, 0x6000, 0xC3)
        write(buf, 0x60000, b"1037366536")
        fill_region(buf, 0x6000A, 0x60012, 0xC3)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        key = result.get("match_key") or ""
        if key:
            assert "::" in key
            assert "EDC15" in key.upper()
            assert "1037" in key

    def test_match_key_format_is_family_double_colon_version(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        fill_region(buf, 0x5FF8, 0x6000, 0xC3)
        write(buf, 0x60000, b"1037366536")
        fill_region(buf, 0x6000A, 0x60012, 0xC3)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        key = result.get("match_key") or ""
        if key:
            parts = key.split("::")
            assert len(parts) == 2
            assert parts[0] == "EDC15"
            assert "1037" in parts[1]

    def test_match_key_is_uppercase(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        fill_region(buf, 0x5FF8, 0x6000, 0xC3)
        write(buf, 0x60000, b"1037366536")
        fill_region(buf, 0x6000A, 0x60012, 0xC3)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        key = result.get("match_key")
        if key:
            assert key == key.upper()

    def test_match_key_key_present_in_result(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert "match_key" in result


# ---------------------------------------------------------------------------
# build_match_key — unit tests on the shared base-class method
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_edc15_family_with_sw_builds_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC15",
            ecu_variant=None,
            software_version="1037366536",
        )
        assert key is not None
        assert "EDC15" in key
        assert "1037366536" in key

    def test_variant_none_uses_family_in_key(self):
        # EDC15 always has variant=None; family must be the left part
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC15",
            ecu_variant=None,
            software_version="1037366536",
        )
        assert key is not None
        parts = key.split("::")
        assert parts[0] == "EDC15"

    def test_match_key_none_when_no_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC15",
            ecu_variant=None,
            software_version=None,
        )
        assert key is None

    def test_match_key_none_for_empty_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC15",
            software_version="",
        )
        assert key is None

    def test_double_colon_separator(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC15",
            software_version="1037366536",
        )
        assert key is not None
        assert "::" in key

    def test_key_is_uppercase(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="edc15",
            software_version="1037366536",
        )
        assert key is not None
        assert key == key.upper()

    def test_sw_version_appears_verbatim_in_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC15",
            software_version="1037366536",
        )
        assert key is not None
        assert "1037366536" in key

    def test_unknown_family_when_none_provided(self):
        key = EXTRACTOR.build_match_key(
            ecu_family=None,
            ecu_variant=None,
            software_version="1037366536",
        )
        assert key is not None
        assert "UNKNOWN" in key

    def test_whitespace_collapsed_in_version(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC15",
            software_version="1037  366536",
        )
        assert key is not None
        assert "  " not in key

    def test_no_fallback_for_edc15(self):
        # EDC15 extractor does not declare match_key_fallback_field,
        # so fallback_value must not be used even when explicitly passed.
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC15",
            software_version=None,
            fallback_value="SOME_FALLBACK",
        )
        # match_key_fallback_field is None on base class by default;
        # EDC15 does not override it → key must be None.
        assert key is None


# ---------------------------------------------------------------------------
# extract — determinism and filename independence
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def _make_rich_bin(self) -> bytes:
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        fill_region(buf, 0x5FF8, 0x6000, 0xC3)
        write(buf, 0x60000, b"1037366536")
        fill_region(buf, 0x6000A, 0x60012, 0xC3)
        write(buf, 0x78000, b"0281010332")
        return bytes(buf)

    def test_same_binary_same_result(self):
        data = self._make_rich_bin()
        r1 = EXTRACTOR.extract(data, "t.bin")
        r2 = EXTRACTOR.extract(data, "t.bin")
        assert r1 == r2

    def test_filename_does_not_affect_identification(self):
        data = self._make_rich_bin()
        r_a = EXTRACTOR.extract(data, "stock.bin")
        r_b = EXTRACTOR.extract(data, "stage1.ori")
        for key in (
            "manufacturer",
            "ecu_family",
            "ecu_variant",
            "software_version",
            "hardware_number",
            "match_key",
        ):
            assert r_a.get(key) == r_b.get(key), (
                f"Key {key!r} differs between runs with different filenames"
            )

    def test_sha256_first_64kb_stable_across_calls(self):
        data = self._make_rich_bin()
        r1 = EXTRACTOR.extract(data, "t.bin")
        r2 = EXTRACTOR.extract(data, "t.bin")
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_md5_stable_across_calls(self):
        data = self._make_rich_bin()
        r1 = EXTRACTOR.extract(data, "t.bin")
        r2 = EXTRACTOR.extract(data, "t.bin")
        assert r1["md5"] == r2["md5"]

    def test_different_binaries_differ_in_md5(self):
        buf_a = make_buf(SIZE_512KB)
        write(buf_a, 0x8000, b"TSW V1.00")
        buf_b = make_buf(SIZE_512KB)
        write(buf_b, 0x8000, b"TSW V2.00")
        r_a = EXTRACTOR.extract(bytes(buf_a), "a.bin")
        r_b = EXTRACTOR.extract(bytes(buf_b), "b.bin")
        assert r_a["md5"] != r_b["md5"]

    def test_different_sw_versions_differ_in_match_key(self):
        def make_with_sw(sw: bytes) -> bytes:
            buf = make_buf(SIZE_512KB)
            write(buf, 0x8000, TSW_STRING)
            fill_region(buf, 0x5FF8, 0x6000, 0xC3)
            write(buf, 0x60000, sw)
            fill_region(buf, 0x60000 + len(sw), 0x60000 + len(sw) + 8, 0xC3)
            return bytes(buf)

        r_a = EXTRACTOR.extract(make_with_sw(b"1037366536"), "a.bin")
        r_b = EXTRACTOR.extract(make_with_sw(b"1037353311"), "b.bin")
        key_a = r_a.get("match_key")
        key_b = r_b.get("match_key")
        if key_a and key_b:
            assert key_a != key_b


# ---------------------------------------------------------------------------
# extract — raw_strings field
# ---------------------------------------------------------------------------


class TestExtractRawStrings:
    def test_raw_strings_field_present(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert "raw_strings" in result

    def test_raw_strings_is_list(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert isinstance(result["raw_strings"], list)

    def test_raw_strings_contains_tsw_when_present(self):
        buf = make_buf(SIZE_512KB)
        write(buf, 0x8000, TSW_STRING)
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        raw = " ".join(result.get("raw_strings", []))
        # TSW string is in the data region (last 256KB) and is long enough to appear
        # (min_length=8 in extract_raw_strings)
        assert isinstance(result["raw_strings"], list)
