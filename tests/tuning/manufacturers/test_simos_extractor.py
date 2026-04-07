"""
Tests for SiemensSimosExtractor (SIMOS / SIMOS2 / SIMOS3).

Covers:
  - Identity properties: name, supported_families
  - can_handle():
      * True  — each detection signature independently (SIMOS, 5WP4, 111s21,
                s21_, cas21) at various sizes
      * True  — header magic + size gate for all three size classes
                (131KB, 262KB, 524KB) when no ASCII signatures present
      * True  — short prefix matching (\\xf0\\x30 for 524KB)
      * False — empty binary
      * False — wrong file size with valid signature
      * False — correct size but no signatures and no header magic
      * False — exclusion signatures (0261, MOTRONIC, 5WS4, etc.)
  - extract():
      * Required fields always present: manufacturer, file_size, md5,
        sha256_first_64kb
      * manufacturer always "Siemens"
      * file_size == len(data)
      * md5 and sha256_first_64kb are well-formed hex strings
      * ecu_family detected correctly (SIMOS, SIMOS2, SIMOS3) from
        explicit label or size-based inference
      * hardware_number from 5WP4 Siemens part
      * software_version from serial code (6577xxxxxx)
      * calibration_id from cas21 dataset or s21 project code
      * oem_part_number from VAG part number
      * match_key built as FAMILY::VERSION
      * match_key is None when no version found
      * extract() is deterministic
      * filename does not affect identification fields
  - build_match_key():
      * family and sw produce correct key
      * variant takes precedence over family
      * None returned when no version component
  - __repr__: contains class name and manufacturer
"""

import hashlib

from openremap.core.manufacturers.siemens.simos.extractor import (
    SiemensSimosExtractor,
)
from openremap.core.manufacturers.siemens.simos.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    PATTERNS,
    PATTERN_REGIONS,
    SEARCH_REGIONS,
    SIMOS_131KB_HEADER,
    SIMOS_262KB_HEADERS,
    SIMOS_524KB_HEADER,
    VALID_SIZES,
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


KB = 1024
MB = 1024 * KB

# Valid SIMOS sizes
SIZE_131KB = 131072  # 128 KB — SIMOS EEPROM
SIZE_262KB = 262144  # 256 KB — SIMOS 2.x EEPROM
SIZE_524KB = 524288  # 512 KB — SIMOS 3.x full flash

# Realistic ident fragments from real SIMOS binaries
SIMOS_LABEL = b"SIMOS   2441"
OEM_IDENT = b"06A906019BH 1.6l R4/2V SIMOS   2441"
OEM_PART = b"06A906019BH"
OEM_PART_ALT = b"047906019"
PROJECT_CODE_A = b"s21_2441"
PROJECT_CODE_B = b"s2114601"
PROJECT_BLOCK = b"111s210"
CAL_DATASET = b"cas21146.DAT"
SERIAL_CODE = b"6577295501"
SIEMENS_PART = b"5WP4860"

EXTRACTOR = SiemensSimosExtractor()


# ---------------------------------------------------------------------------
# Identity properties
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_name_is_siemens(self):
        assert EXTRACTOR.name == "Siemens"

    def test_name_is_string(self):
        assert isinstance(EXTRACTOR.name, str)

    def test_supported_families_is_list(self):
        assert isinstance(EXTRACTOR.supported_families, list)

    def test_supported_families_not_empty(self):
        assert len(EXTRACTOR.supported_families) > 0

    def test_simos_in_supported_families(self):
        assert "SIMOS" in EXTRACTOR.supported_families

    def test_simos2_in_supported_families(self):
        assert "SIMOS2" in EXTRACTOR.supported_families

    def test_simos3_in_supported_families(self):
        assert "SIMOS3" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for fam in EXTRACTOR.supported_families:
            assert isinstance(fam, str), f"Family {fam!r} is not a string"

    def test_repr_contains_manufacturer(self):
        r = repr(EXTRACTOR)
        assert "Siemens" in r

    def test_repr_contains_class_name(self):
        r = repr(EXTRACTOR)
        assert "SiemensSimosExtractor" in r


# ---------------------------------------------------------------------------
# can_handle() — positive detection via keyword signatures
# ---------------------------------------------------------------------------


class TestCanHandleTrueSignatures:
    """Detection signatures present → True (regardless of size, if no exclusion)."""

    def _make(self, sig: bytes, size: int = SIZE_524KB, offset: int = 0x100) -> bytes:
        buf = make_buf(size)
        write(buf, offset, sig)
        return bytes(buf)

    def test_simos_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"SIMOS"))

    def test_5wp4_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"5WP4860"))

    def test_5wp4_short(self):
        assert EXTRACTOR.can_handle(self._make(b"5WP4"))

    def test_111s21_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"111s21"))

    def test_s21_underscore_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"s21_"))

    def test_cas21_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"cas21"))

    def test_full_simos_label(self):
        assert EXTRACTOR.can_handle(self._make(SIMOS_LABEL))

    def test_full_oem_ident(self):
        assert EXTRACTOR.can_handle(self._make(OEM_IDENT))

    def test_full_cal_dataset(self):
        assert EXTRACTOR.can_handle(self._make(CAL_DATASET))

    def test_project_code_a(self):
        assert EXTRACTOR.can_handle(self._make(PROJECT_CODE_A))

    def test_project_block(self):
        assert EXTRACTOR.can_handle(self._make(PROJECT_BLOCK))

    def test_signature_at_offset_zero(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0, b"SIMOS")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_signature_in_131kb_binary(self):
        assert EXTRACTOR.can_handle(self._make(b"SIMOS", size=SIZE_131KB))

    def test_signature_in_262kb_binary(self):
        assert EXTRACTOR.can_handle(self._make(b"SIMOS", size=SIZE_262KB))

    def test_signature_in_arbitrary_size_binary(self):
        """Keyword signatures work regardless of file size."""
        assert EXTRACTOR.can_handle(self._make(b"SIMOS", size=1 * MB))

    def test_multiple_signatures_still_true(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x500, b"5WP4860")
        write(buf, 0x1000, PROJECT_CODE_A)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_signature_near_end_of_binary(self):
        buf = make_buf(SIZE_524KB)
        offset = SIZE_524KB - len(b"SIMOS") - 5
        write(buf, offset, b"SIMOS")
        assert EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — positive detection via header magic + size gate
# ---------------------------------------------------------------------------


class TestCanHandleTrueHeaderMagic:
    """Header magic + valid size → True (no keyword signatures needed)."""

    def test_524kb_f030_header(self):
        """524KB binary with \\xf0\\x30 header → True."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_524kb_f030_full_4byte_variant(self):
        """524KB with \\xf0\\x30\\xe8\\x44 header variant → True."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, b"\xf0\x30\xe8\x44")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_524kb_f030_another_variant(self):
        """524KB with \\xf0\\x30\\x58\\x74 header variant → True."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, b"\xf0\x30\x58\x74")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_524kb_f030_a04c_variant(self):
        """524KB with \\xf0\\x30\\xa0\\x4c header variant → True."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, b"\xf0\x30\xa0\x4c")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_524kb_f030_c06c_variant(self):
        """524KB with \\xf0\\x30\\xc0\\x6c header variant → True."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, b"\xf0\x30\xc0\x6c")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_262kb_c064_header(self):
        """262KB binary with \\xc0\\x64 header → True."""
        buf = make_buf(SIZE_262KB)
        write(buf, 0, b"\xc0\x64")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_262kb_fa00_header(self):
        """262KB binary with \\xfa\\x00 header → True."""
        buf = make_buf(SIZE_262KB)
        write(buf, 0, b"\xfa\x00")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_131kb_02_header(self):
        """131KB binary with \\x02 header prefix → True."""
        buf = make_buf(SIZE_131KB)
        write(buf, 0, SIMOS_131KB_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_131kb_02_variant_a(self):
        """131KB with \\x02\\x58\\x95\\x05 header → True."""
        buf = make_buf(SIZE_131KB)
        write(buf, 0, b"\x02\x58\x95\x05")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_131kb_02_variant_b(self):
        """131KB with \\x02\\x56\\x9f\\x05 header → True."""
        buf = make_buf(SIZE_131KB)
        write(buf, 0, b"\x02\x56\x9f\x05")
        assert EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: empty / wrong size / no signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseNoSignature:
    """No detection signatures and no matching header magic → False."""

    def test_empty_binary(self):
        assert not EXTRACTOR.can_handle(b"")

    def test_1_byte_binary(self):
        assert not EXTRACTOR.can_handle(b"\x00")

    def test_too_small_binary(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(64)))

    def test_all_zero_131kb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_131KB)))

    def test_all_zero_262kb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_262KB)))

    def test_all_zero_524kb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_524KB)))

    def test_all_ff_524kb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_524KB, fill=0xFF)))

    def test_wrong_header_131kb(self):
        """131KB with wrong first byte → False."""
        buf = make_buf(SIZE_131KB)
        write(buf, 0, b"\x03")  # wrong — should be \x02
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_wrong_header_262kb(self):
        """262KB with non-matching 2-byte header → False."""
        buf = make_buf(SIZE_262KB)
        write(buf, 0, b"\xaa\xbb")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_wrong_header_524kb(self):
        """524KB with non-matching 2-byte header → False."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, b"\xf1\x30")  # close but wrong
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_valid_header_wrong_size(self):
        """Correct 524KB header but wrong size → False."""
        buf = make_buf(SIZE_524KB + 1)
        write(buf, 0, SIMOS_524KB_HEADER)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_valid_header_wrong_size_256kb_header_in_512kb(self):
        """262KB header in a 512KB binary → no header match → False."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, b"\xc0\x64")  # 262KB header
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_ascii_noise_no_signature(self):
        buf = make_buf(SIZE_524KB)
        noise = b"This is just some text with no ECU signatures at all." * 200
        write(buf, 0x100, noise[:0x5000])
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_wrong_size_with_simos_signature(self):
        """SIMOS keyword should still work at arbitrary sizes IF no exclusion."""
        # Actually SIMOS keyword works at any size — this test verifies that
        # header-only detection does NOT work at wrong size.
        buf = make_buf(300 * KB)  # non-standard size
        write(buf, 0, SIMOS_524KB_HEADER)  # right header, wrong size
        # No keyword signatures either
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: exclusion signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseExclusion:
    """Exclusion signatures override positive detection → False."""

    def _make_with_exclusion(
        self, exclusion_sig: bytes, size: int = SIZE_524KB
    ) -> bytes:
        buf = make_buf(size)
        write(buf, 0x100, b"SIMOS")  # positive detection
        write(buf, 0x5000, exclusion_sig)  # exclusion
        return bytes(buf)

    def test_0261_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"0261"))

    def test_motronic_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MOTRONIC"))

    def test_5ws4_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"5WS4"))

    def test_5wk9_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"5WK9"))

    def test_sid80_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"SID80"))

    def test_edc17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"EDC17"))

    def test_medc17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MEDC17"))

    def test_med17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MED17"))

    def test_me7_dot_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"ME7."))

    def test_bosch_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"BOSCH"))

    def test_pm3_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"PM3"))

    def test_ppd_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"PPD"))

    def test_exclusion_overrides_multiple_detections(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, b"5WP4860")
        write(buf, 0x300, PROJECT_CODE_A)
        write(buf, 0x5000, b"0261")  # exclusion
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_overrides_header_magic_detection(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        write(buf, 0x5000, b"MOTRONIC")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_start_of_binary(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0, b"5WS4")  # exclusion at offset 0
        write(buf, 0x100, b"SIMOS")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_end_of_scan_region(self):
        """Exclusion scans first 512 KB."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x7FFF0, b"5WK9")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_all_exclusion_signatures_reject(self):
        """Every exclusion signature causes rejection."""
        for sig in EXCLUSION_SIGNATURES:
            data = self._make_with_exclusion(sig)
            assert not EXTRACTOR.can_handle(data), f"Exclusion {sig!r} should reject"


# ---------------------------------------------------------------------------
# can_handle() — boundary cases
# ---------------------------------------------------------------------------


class TestCanHandleBoundary:
    def test_valid_sizes_constant_has_three_entries(self):
        assert len(VALID_SIZES) == 3

    def test_131072_in_valid_sizes(self):
        assert SIZE_131KB in VALID_SIZES

    def test_262144_in_valid_sizes(self):
        assert SIZE_262KB in VALID_SIZES

    def test_524288_in_valid_sizes(self):
        assert SIZE_524KB in VALID_SIZES

    def test_simos_keyword_works_at_non_standard_size(self):
        """Keyword detection works regardless of file size (no size gate)."""
        buf = make_buf(2 * MB)
        write(buf, 0x100, b"SIMOS")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_5wp4_at_non_standard_size(self):
        buf = make_buf(768 * KB)
        write(buf, 0x100, b"5WP4860")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_header_magic_only_works_at_valid_size(self):
        """Header magic detection requires a matching size."""
        for bad_size in [
            SIZE_131KB - 1,
            SIZE_131KB + 1,
            SIZE_262KB - 1,
            SIZE_262KB + 1,
            SIZE_524KB - 1,
            SIZE_524KB + 1,
        ]:
            buf = make_buf(bad_size)
            write(buf, 0, b"\x02")  # 131KB header
            assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# extract() — required fields
# ---------------------------------------------------------------------------


class TestExtractRequiredFields:
    """All required fields present and correctly computed."""

    def _extract(self, data: bytes = None) -> dict:
        if data is None:
            buf = make_buf(SIZE_524KB)
            write(buf, 0, SIMOS_524KB_HEADER)
            write(buf, 0x100, b"SIMOS")
            data = bytes(buf)
        return EXTRACTOR.extract(data, "test.bin")

    def test_all_required_fields_present(self):
        result = self._extract()
        for key in ("manufacturer", "file_size", "md5", "sha256_first_64kb"):
            assert key in result, f"Missing required field: {key}"

    def test_manufacturer_always_siemens(self):
        assert self._extract()["manufacturer"] == "Siemens"

    def test_manufacturer_siemens_for_dark_bin(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["manufacturer"] == "Siemens"

    def test_file_size_equals_data_length_524kb(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["file_size"] == SIZE_524KB

    def test_file_size_equals_data_length_262kb(self):
        buf = make_buf(SIZE_262KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["file_size"] == SIZE_262KB

    def test_file_size_equals_data_length_131kb(self):
        buf = make_buf(SIZE_131KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["file_size"] == SIZE_131KB

    def test_md5_is_32_hex_chars(self):
        result = self._extract()
        assert len(result["md5"]) == 32
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_is_lowercase_hex(self):
        result = self._extract()
        assert result["md5"] == result["md5"].lower()

    def test_md5_matches_hashlib(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_first_64kb_is_64_hex_chars(self):
        result = self._extract()
        sha = result["sha256_first_64kb"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_first_64kb_matches_hashlib(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert result["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_ignores_bytes_past_64kb(self):
        buf1 = make_buf(SIZE_524KB)
        write(buf1, 0x100, b"SIMOS")
        buf2 = make_buf(SIZE_524KB)
        write(buf2, 0x100, b"SIMOS")
        write(buf2, 0x20000, b"COMPLETELY_DIFFERENT_DATA_PAST_64KB")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_md5_changes_with_different_content(self):
        buf1 = make_buf(SIZE_524KB)
        write(buf1, 0x100, b"SIMOS")
        buf2 = make_buf(SIZE_524KB, fill=0x01)
        write(buf2, 0x100, b"SIMOS")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# extract() — ECU family resolution
# ---------------------------------------------------------------------------


class TestExtractEcuFamily:
    def test_family_simos3_for_524kb_with_simos_string(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SIMOS3"

    def test_family_simos2_for_262kb_with_simos_string(self):
        buf = make_buf(SIZE_262KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SIMOS2"

    def test_family_simos_for_131kb_with_simos_string(self):
        buf = make_buf(SIZE_131KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SIMOS"

    def test_family_simos3_for_524kb_no_string(self):
        """Size-based inference when no SIMOS string present."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SIMOS3"

    def test_family_simos2_for_262kb_no_string(self):
        buf = make_buf(SIZE_262KB)
        write(buf, 0, b"\xc0\x64")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SIMOS2"

    def test_family_simos_for_131kb_no_string(self):
        buf = make_buf(SIZE_131KB)
        write(buf, 0, SIMOS_131KB_HEADER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SIMOS"

    def test_family_from_simos_label(self):
        """Specific SIMOS label string normalised correctly."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, SIMOS_LABEL)  # "SIMOS   2441"
        result = EXTRACTOR.extract(bytes(buf))
        # Label normalised: "SIMOS   2441" → "SIMOS 2441"
        assert "SIMOS" in result["ecu_family"]

    def test_family_default_for_non_standard_size(self):
        """Non-standard size with SIMOS string → "SIMOS" (default)."""
        buf = make_buf(1 * MB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SIMOS"

    def test_family_simos2_for_262kb_with_5wp4(self):
        """5WP4 keyword but no bare SIMOS string → size-based inference."""
        buf = make_buf(SIZE_262KB)
        write(buf, 0x100, b"5WP4860")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SIMOS2"


# ---------------------------------------------------------------------------
# extract() — hardware number (Siemens 5WP4 part)
# ---------------------------------------------------------------------------


class TestExtractHardwareNumber:
    def test_hw_detected_5wp4(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SIEMENS_PART)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is not None
        assert "5WP4" in result["hardware_number"]

    def test_hw_specific_value(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, b"5WP40123")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is not None
        assert result["hardware_number"].startswith("5WP4")

    def test_hw_none_when_no_part_number(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is None

    def test_hw_none_for_dark_bin(self):
        """Dark bin (header magic only, no ASCII) → None."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is None


# ---------------------------------------------------------------------------
# extract() — software version (serial code 6577xxxxxx)
# ---------------------------------------------------------------------------


class TestExtractSoftwareVersion:
    def test_sw_from_serial_code(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] == "6577295501"

    def test_sw_different_serial_code(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, b"6577297701")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] == "6577297701"

    def test_sw_none_when_no_serial_code(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] is None

    def test_sw_none_for_dark_bin(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] is None


# ---------------------------------------------------------------------------
# extract() — calibration ID
# ---------------------------------------------------------------------------


class TestExtractCalibrationId:
    def test_cal_from_dataset(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, CAL_DATASET)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] == "cas21146.DAT"

    def test_cal_from_project_code(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, PROJECT_CODE_A)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] is not None

    def test_cal_dataset_takes_priority_over_project_code(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, CAL_DATASET)
        write(buf, 0x300, PROJECT_CODE_A)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] == "cas21146.DAT"

    def test_cal_none_when_no_hits(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] is None


# ---------------------------------------------------------------------------
# extract() — OEM part number
# ---------------------------------------------------------------------------


class TestExtractOemPartNumber:
    def test_oem_part_detected(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, OEM_PART)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["oem_part_number"] is not None
        assert "906" in result["oem_part_number"]

    def test_oem_part_alt(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, OEM_PART_ALT)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["oem_part_number"] is not None

    def test_oem_part_none_when_absent(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["oem_part_number"] is None


# ---------------------------------------------------------------------------
# extract() — not-applicable fields
# ---------------------------------------------------------------------------


class TestExtractNotApplicableFields:
    def _extract(self) -> dict:
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        return EXTRACTOR.extract(bytes(buf))

    def test_ecu_variant_is_none(self):
        assert self._extract()["ecu_variant"] is None

    def test_calibration_version_is_none(self):
        assert self._extract()["calibration_version"] is None

    def test_sw_base_version_is_none(self):
        assert self._extract()["sw_base_version"] is None

    def test_serial_number_is_none(self):
        assert self._extract()["serial_number"] is None

    def test_dataset_number_is_none(self):
        assert self._extract()["dataset_number"] is None


# ---------------------------------------------------------------------------
# extract() — match key
# ---------------------------------------------------------------------------


class TestExtractMatchKey:
    def test_match_key_built_when_sw_present(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is not None

    def test_match_key_format_is_family_double_colon_version(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_match_key_starts_with_simos3_for_524kb(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert key.startswith("SIMOS3::")

    def test_match_key_starts_with_simos2_for_262kb(self):
        buf = make_buf(SIZE_262KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert key.startswith("SIMOS2::")

    def test_match_key_starts_with_simos_for_131kb(self):
        buf = make_buf(SIZE_131KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert key.startswith("SIMOS::")

    def test_match_key_none_when_no_sw(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is None

    def test_match_key_none_for_dark_bin(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is None

    def test_match_key_uses_uppercase(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert key == key.upper()


# ---------------------------------------------------------------------------
# extract() — raw strings
# ---------------------------------------------------------------------------


class TestExtractRawStrings:
    def test_raw_strings_is_list(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        result = EXTRACTOR.extract(bytes(buf))
        assert isinstance(result["raw_strings"], list)

    def test_raw_strings_limited_to_20(self):
        buf = make_buf(SIZE_524KB)
        for i in range(30):
            offset = 0x100 + i * 20
            if offset + 16 < 0x10000:
                write(buf, offset, b"LONGSTR%02d_ABCDE" % i)
        result = EXTRACTOR.extract(bytes(buf))
        assert len(result["raw_strings"]) <= 20

    def test_raw_strings_empty_for_dark_bin(self):
        """Dark bins typically have very few or no readable ASCII strings."""
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        result = EXTRACTOR.extract(bytes(buf))
        # May be empty or near-empty
        assert isinstance(result["raw_strings"], list)


# ---------------------------------------------------------------------------
# build_match_key()
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_family_and_sw_produces_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SIMOS3",
            software_version="6577295501",
        )
        assert key == "SIMOS3::6577295501"

    def test_family_and_sw_simos2(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SIMOS2",
            software_version="6577297701",
        )
        assert key == "SIMOS2::6577297701"

    def test_family_and_sw_simos(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SIMOS",
            software_version="6577295501",
        )
        assert key == "SIMOS::6577295501"

    def test_none_returned_when_no_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SIMOS3",
            software_version=None,
        )
        assert key is None

    def test_none_returned_when_empty_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SIMOS3",
            software_version="",
        )
        assert key is None

    def test_unknown_used_when_no_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family=None,
            software_version="6577295501",
        )
        assert key == "UNKNOWN::6577295501"

    def test_key_is_uppercase(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="simos3",
            software_version="abc123",
        )
        assert key == key.upper()

    def test_double_colon_separator(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SIMOS3",
            software_version="VERSION",
        )
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_variant_takes_precedence_over_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SIMOS3",
            ecu_variant="SIMOS_CUSTOM",
            software_version="6577295501",
        )
        assert key.startswith("SIMOS_CUSTOM::")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_same_binary_produces_same_result(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        data = bytes(buf)
        r1 = EXTRACTOR.extract(data, "file.bin")
        r2 = EXTRACTOR.extract(data, "file.bin")
        assert r1 == r2

    def test_filename_does_not_change_identification(self):
        buf = make_buf(SIZE_524KB)
        write(buf, 0x100, b"SIMOS")
        write(buf, 0x200, SERIAL_CODE)
        data = bytes(buf)
        r1 = EXTRACTOR.extract(data, "foo.bin")
        r2 = EXTRACTOR.extract(data, "bar.bin")
        for key in (
            "manufacturer",
            "file_size",
            "md5",
            "sha256_first_64kb",
            "ecu_family",
            "hardware_number",
            "software_version",
            "calibration_id",
            "match_key",
        ):
            assert r1[key] == r2[key], f"Field {key!r} differs by filename"

    def test_different_content_produces_different_md5(self):
        buf1 = make_buf(SIZE_524KB)
        write(buf1, 0x100, b"SIMOS")
        buf2 = make_buf(SIZE_524KB, fill=0x01)
        write(buf2, 0x100, b"SIMOS")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# Full realistic extraction (524KB SIMOS3 with identifiers)
# ---------------------------------------------------------------------------


class TestFullRealisticExtraction:
    def _make_full_binary(self) -> bytes:
        buf = make_buf(SIZE_524KB)
        write(buf, 0, SIMOS_524KB_HEADER)
        write(buf, 0x100, OEM_IDENT)
        write(buf, 0x200, SIEMENS_PART)
        write(buf, 0x300, SERIAL_CODE)
        write(buf, 0x400, PROJECT_CODE_A)
        write(buf, 0x500, CAL_DATASET)
        write(buf, 0x600, OEM_PART)
        return bytes(buf)

    def test_all_core_fields_populated(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data, "SIMOS3_test.bin")
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] is not None
        assert "SIMOS" in result["ecu_family"]
        assert result["hardware_number"] is not None
        assert result["software_version"] is not None
        assert result["calibration_id"] is not None
        assert result["oem_part_number"] is not None
        assert result["match_key"] is not None

    def test_md5_and_sha256_present(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data)
        assert result["md5"] is not None
        assert result["sha256_first_64kb"] is not None

    def test_raw_strings_is_list(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data)
        assert isinstance(result["raw_strings"], list)

    def test_file_size_is_524kb(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data)
        assert result["file_size"] == SIZE_524KB


# ---------------------------------------------------------------------------
# Minimal dark bin extraction
# ---------------------------------------------------------------------------


class TestDarkBinExtraction:
    """Dark bins (no ASCII) produce minimal but valid extraction results."""

    def _make_dark_bin(self, size: int, header: bytes) -> bytes:
        buf = make_buf(size)
        write(buf, 0, header)
        return bytes(buf)

    def test_dark_524kb_basic_fields(self):
        data = self._make_dark_bin(SIZE_524KB, SIMOS_524KB_HEADER)
        result = EXTRACTOR.extract(data)
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] == "SIMOS3"
        assert result["file_size"] == SIZE_524KB
        assert result["md5"] is not None
        assert result["sha256_first_64kb"] is not None

    def test_dark_262kb_basic_fields(self):
        data = self._make_dark_bin(SIZE_262KB, b"\xc0\x64")
        result = EXTRACTOR.extract(data)
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] == "SIMOS2"
        assert result["file_size"] == SIZE_262KB

    def test_dark_131kb_basic_fields(self):
        data = self._make_dark_bin(SIZE_131KB, SIMOS_131KB_HEADER)
        result = EXTRACTOR.extract(data)
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] == "SIMOS"
        assert result["file_size"] == SIZE_131KB

    def test_dark_bin_most_fields_none(self):
        data = self._make_dark_bin(SIZE_524KB, SIMOS_524KB_HEADER)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] is None
        assert result["software_version"] is None
        assert result["calibration_id"] is None
        assert result["oem_part_number"] is None
        assert result["match_key"] is None
        assert result["ecu_variant"] is None
        assert result["serial_number"] is None


# ---------------------------------------------------------------------------
# Patterns module validation
# ---------------------------------------------------------------------------


class TestPatternsModule:
    def test_detection_signatures_is_list(self):
        assert isinstance(DETECTION_SIGNATURES, list)

    def test_detection_signatures_not_empty(self):
        assert len(DETECTION_SIGNATURES) > 0

    def test_simos_in_detection_signatures(self):
        assert b"SIMOS" in DETECTION_SIGNATURES

    def test_5wp4_in_detection_signatures(self):
        assert b"5WP4" in DETECTION_SIGNATURES

    def test_111s21_in_detection_signatures(self):
        assert b"111s21" in DETECTION_SIGNATURES

    def test_s21_underscore_in_detection_signatures(self):
        assert b"s21_" in DETECTION_SIGNATURES

    def test_cas21_in_detection_signatures(self):
        assert b"cas21" in DETECTION_SIGNATURES

    def test_exclusion_signatures_is_list(self):
        assert isinstance(EXCLUSION_SIGNATURES, list)

    def test_exclusion_signatures_not_empty(self):
        assert len(EXCLUSION_SIGNATURES) > 0

    def test_0261_in_exclusion_signatures(self):
        assert b"0261" in EXCLUSION_SIGNATURES

    def test_motronic_in_exclusion_signatures(self):
        assert b"MOTRONIC" in EXCLUSION_SIGNATURES

    def test_5ws4_in_exclusion_signatures(self):
        assert b"5WS4" in EXCLUSION_SIGNATURES

    def test_5wk9_in_exclusion_signatures(self):
        assert b"5WK9" in EXCLUSION_SIGNATURES

    def test_sid80_in_exclusion_signatures(self):
        assert b"SID80" in EXCLUSION_SIGNATURES

    def test_ppd_in_exclusion_signatures(self):
        assert b"PPD" in EXCLUSION_SIGNATURES

    def test_all_detection_signatures_are_bytes(self):
        for sig in DETECTION_SIGNATURES:
            assert isinstance(sig, bytes), f"Signature {sig!r} is not bytes"

    def test_all_exclusion_signatures_are_bytes(self):
        for sig in EXCLUSION_SIGNATURES:
            assert isinstance(sig, bytes), f"Signature {sig!r} is not bytes"

    def test_detection_and_exclusion_have_no_overlap(self):
        det_set = set(DETECTION_SIGNATURES)
        exc_set = set(EXCLUSION_SIGNATURES)
        assert det_set.isdisjoint(exc_set)

    def test_valid_sizes_is_set(self):
        assert isinstance(VALID_SIZES, set)

    def test_valid_sizes_has_three_entries(self):
        assert len(VALID_SIZES) == 3

    def test_simos_524kb_header_is_2_bytes(self):
        assert len(SIMOS_524KB_HEADER) == 2
        assert SIMOS_524KB_HEADER == b"\xf0\x30"

    def test_simos_131kb_header_is_1_byte(self):
        assert len(SIMOS_131KB_HEADER) == 1
        assert SIMOS_131KB_HEADER == b"\x02"

    def test_simos_262kb_headers_has_two_variants(self):
        assert isinstance(SIMOS_262KB_HEADERS, list)
        assert len(SIMOS_262KB_HEADERS) == 2

    def test_search_regions_have_header(self):
        assert "header" in SEARCH_REGIONS

    def test_search_regions_have_full(self):
        assert "full" in SEARCH_REGIONS

    def test_search_regions_have_ident_area(self):
        assert "ident_area" in SEARCH_REGIONS

    def test_patterns_is_dict(self):
        assert isinstance(PATTERNS, dict)

    def test_pattern_regions_is_dict(self):
        assert isinstance(PATTERN_REGIONS, dict)

    def test_siemens_part_pattern_in_patterns(self):
        assert "siemens_part" in PATTERNS

    def test_ecu_family_pattern_in_patterns(self):
        assert "ecu_family" in PATTERNS

    def test_serial_code_pattern_in_patterns(self):
        assert "serial_code" in PATTERNS

    def test_simos_label_pattern_in_patterns(self):
        assert "simos_label" in PATTERNS

    def test_all_pattern_regions_reference_valid_regions(self):
        for name, region_key in PATTERN_REGIONS.items():
            assert region_key in SEARCH_REGIONS, (
                f"Pattern {name!r} references unknown region {region_key!r}"
            )
