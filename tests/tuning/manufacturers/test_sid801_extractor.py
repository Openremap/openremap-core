"""
Tests for SiemensSID801Extractor (SID801 / SID801A).

Covers:
  - Identity properties: name, supported_families
  - can_handle():
      * True  — 5WS4 hardware prefix, PM3 project code
      * False — wrong file size (too small, too large, empty, near-miss)
      * False — correct size but no detection signatures
      * False — correct size with exclusion signatures (EDC17, MEDC17, MED17,
                ME7., SID803)
      * True  — detection signature in header area with correct size
      * False — exclusion overrides detection even when both present
  - extract():
      * Required fields always present: manufacturer, file_size, md5,
        sha256_first_64kb
      * manufacturer always "Siemens"
      * file_size == len(data)
      * md5 and sha256_first_64kb are well-formed hex strings
      * hardware_number detected from 5WS4 ident record
      * software_version (9-digit serial) extracted from ident record
      * ecu_family detected as SID801 or SID801A
      * calibration_id from PM3 project code or CAPM dataset reference
      * oem_part_number from PSA 96xxxxxxxx part number
      * serial_number from S-record reference
      * match_key built as FAMILY::VERSION
      * match_key is None when no software_version found
  - build_match_key():
      * family and sw produce correct key
      * None returned when no version component available
  - Determinism:
      * Same binary → same result
      * Filename does not affect identification
  - Field resolvers:
      * _resolve_hardware_number returns first 5WS4 hit
      * _resolve_software_version extracts serial from ident record
      * _resolve_software_version returns None with no ident record
      * _resolve_ecu_family prioritises explicit family string
      * _resolve_ecu_family defaults to SID801 when no explicit string
      * _resolve_calibration_id prioritises PM3 over CAPM
  - __repr__: contains class name and manufacturer
"""

import hashlib
import re

from openremap.core.manufacturers.siemens.sid801.extractor import (
    SiemensSID801Extractor,
)
from openremap.core.manufacturers.siemens.sid801.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    PATTERNS,
    PATTERN_REGIONS,
    SEARCH_REGIONS,
    SID801_FILE_SIZE,
)


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------


def make_bin(size: int = SID801_FILE_SIZE, fill: int = 0x00) -> bytearray:
    """Return a mutable bytearray of `size` bytes set to `fill`."""
    return bytearray([fill] * size)


def write(buf: bytearray, offset: int, data: bytes) -> bytearray:
    """Write `data` at `offset` in `buf` and return `buf`."""
    buf[offset : offset + len(data)] = data
    return buf


# ---------------------------------------------------------------------------
# Sizes (bytes)
# ---------------------------------------------------------------------------

KB = 1024
MB = 1024 * KB

# SID801 expected size — exactly 512 KB
SIZE_SID801 = SID801_FILE_SIZE  # 524288
assert SIZE_SID801 == 512 * KB

# Realistic ident records from real SID801 binaries
IDENT_RECORD_A = b"5WS40145A-T 244177913   04020028014941S220040001C0"
IDENT_RECORD_B = b"5WS40045B-T 234082572   03020023120054S220040001C0"
IDENT_RECORD_C = b"5WS40036D-T 226472424   02100016202138S218432001D0"

EXTRACTOR = SiemensSID801Extractor()


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

    def test_sid801_in_supported_families(self):
        assert "SID801" in EXTRACTOR.supported_families

    def test_sid801a_in_supported_families(self):
        assert "SID801A" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for fam in EXTRACTOR.supported_families:
            assert isinstance(fam, str)

    def test_repr_contains_manufacturer(self):
        r = repr(EXTRACTOR)
        assert "Siemens" in r

    def test_repr_contains_class_name(self):
        r = repr(EXTRACTOR)
        assert "SiemensSID801Extractor" in r


# ---------------------------------------------------------------------------
# can_handle() — positive detection
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """Binary is correct size and contains at least one detection signature."""

    def _make_sid801_with(self, sig: bytes, offset: int = 0x100) -> bytes:
        buf = make_bin()
        write(buf, offset, sig)
        return bytes(buf)

    def test_5ws4_signature(self):
        assert EXTRACTOR.can_handle(self._make_sid801_with(b"5WS4"))

    def test_pm3_signature(self):
        assert EXTRACTOR.can_handle(self._make_sid801_with(b"PM3"))

    def test_full_hardware_number(self):
        assert EXTRACTOR.can_handle(self._make_sid801_with(b"5WS40145A-T"))

    def test_full_ident_record(self):
        assert EXTRACTOR.can_handle(self._make_sid801_with(IDENT_RECORD_A))

    def test_pm3_project_code(self):
        assert EXTRACTOR.can_handle(self._make_sid801_with(b"PM38101C00"))

    def test_multiple_signatures_still_true(self):
        buf = make_bin()
        write(buf, 0x100, b"5WS40145A-T")
        write(buf, 0x5000, b"PM38101C00")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_signature_at_offset_zero(self):
        buf = make_bin()
        write(buf, 0, b"5WS40036D-T")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_signature_near_end_of_detection_region(self):
        # Detection region is first 128 KB — place signature near the end
        buf = make_bin()
        offset = 0x1FFF0
        write(buf, offset, b"5WS4")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_pm3_near_end_of_detection_region(self):
        buf = make_bin()
        offset = 0x1FFFD  # 0x20000 - 3 = last position where PM3 fits
        write(buf, offset, b"PM3")
        assert EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: wrong size
# ---------------------------------------------------------------------------


class TestCanHandleFalseWrongSize:
    """Size gate must reject binaries that are not exactly 524288 bytes."""

    def test_empty_binary(self):
        assert not EXTRACTOR.can_handle(b"")

    def test_1_byte_binary(self):
        assert not EXTRACTOR.can_handle(b"\x00")

    def test_256kb_with_signature(self):
        buf = make_bin(256 * KB)
        write(buf, 0x100, b"5WS40145A-T")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_1mb_with_signature(self):
        buf = make_bin(1 * MB)
        write(buf, 0x100, b"5WS40145A-T")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_2mb_with_signature(self):
        buf = make_bin(2 * MB)
        write(buf, 0x100, b"5WS40145A-T")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_one_byte_less_than_512kb(self):
        buf = make_bin(SIZE_SID801 - 1)
        write(buf, 0x100, b"5WS40145A-T")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_one_byte_more_than_512kb(self):
        buf = make_bin(SIZE_SID801 + 1)
        write(buf, 0x100, b"5WS40145A-T")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_128kb_with_pm3(self):
        buf = make_bin(128 * KB)
        write(buf, 0x100, b"PM38101C00")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_64kb(self):
        buf = make_bin(64 * KB)
        write(buf, 0x100, b"5WS4")
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: no signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseNoSignature:
    """Correct size but no detection signature → False."""

    def test_all_zero_binary(self):
        assert not EXTRACTOR.can_handle(bytes(make_bin()))

    def test_all_ff_binary(self):
        assert not EXTRACTOR.can_handle(bytes(make_bin(fill=0xFF)))

    def test_random_like_bytes_no_signature(self):
        # Fill with a repeating pattern that avoids any detection string
        buf = make_bin()
        pattern = b"ABCDEFGH" * (SIZE_SID801 // 8)
        buf[: len(pattern)] = pattern[:SIZE_SID801]
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_ascii_noise_no_signature(self):
        buf = make_bin()
        noise = b"This is just some text with no ECU signatures at all." * 100
        write(buf, 0x100, noise[:0x1000])
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_signature_outside_detection_region(self):
        # Place signature at 0x30000 (past the 128 KB detection region)
        buf = make_bin()
        write(buf, 0x30000, b"5WS40145A-T")
        # Also place PM3 past region
        write(buf, 0x30100, b"PM38101C00")
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: exclusion signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseExclusion:
    """Exclusion signatures override positive detection → False."""

    def _make_with_exclusion(self, exclusion_sig: bytes) -> bytes:
        buf = make_bin()
        write(buf, 0x100, b"5WS40145A-T")  # positive detection
        write(buf, 0x50000, exclusion_sig)  # exclusion signature
        return bytes(buf)

    def test_edc17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"EDC17"))

    def test_medc17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MEDC17"))

    def test_med17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MED17"))

    def test_me7_dot_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"ME7."))

    def test_sid803_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"SID803"))

    def test_exclusion_overrides_multiple_detections(self):
        buf = make_bin()
        write(buf, 0x100, b"5WS40145A-T")
        write(buf, 0x200, b"PM38101C00")
        write(buf, 0x300, b"5WS40036D-T")
        write(buf, 0x60000, b"EDC17")  # exclusion
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_start_of_binary(self):
        buf = make_bin()
        write(buf, 0x000, b"SID803")
        write(buf, 0x100, b"5WS40145A-T")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_end_of_binary(self):
        buf = make_bin()
        write(buf, 0x100, b"5WS40145A-T")
        write(buf, SIZE_SID801 - 10, b"EDC17")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_all_exclusion_signatures_defined(self):
        """Every exclusion signature rejects when present."""
        for sig in EXCLUSION_SIGNATURES:
            data = self._make_with_exclusion(sig)
            assert not EXTRACTOR.can_handle(data), f"Exclusion {sig!r} should reject"


# ---------------------------------------------------------------------------
# extract() — required fields
# ---------------------------------------------------------------------------


class TestExtractRequiredFields:
    """All required fields present and correctly computed."""

    def _extract(self, data: bytes = None) -> dict:
        if data is None:
            buf = make_bin()
            write(buf, 0x100, IDENT_RECORD_A)
            data = bytes(buf)
        return EXTRACTOR.extract(data, "test.bin")

    def test_all_required_fields_present(self):
        result = self._extract()
        for key in ("manufacturer", "file_size", "md5", "sha256_first_64kb"):
            assert key in result, f"Missing required field: {key}"

    def test_manufacturer_always_siemens(self):
        assert self._extract()["manufacturer"] == "Siemens"

    def test_file_size_equals_data_length(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "test.bin")
        assert result["file_size"] == len(data)

    def test_file_size_is_512kb(self):
        assert self._extract()["file_size"] == SIZE_SID801

    def test_md5_is_32_hex_chars(self):
        md5 = self._extract()["md5"]
        assert len(md5) == 32
        assert re.match(r"^[0-9a-f]{32}$", md5)

    def test_md5_is_lowercase_hex(self):
        md5 = self._extract()["md5"]
        assert md5 == md5.lower()

    def test_md5_matches_hashlib(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "test.bin")
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_first_64kb_is_64_hex_chars(self):
        sha = self._extract()["sha256_first_64kb"]
        assert len(sha) == 64
        assert re.match(r"^[0-9a-f]{64}$", sha)

    def test_sha256_first_64kb_matches_hashlib(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "test.bin")
        assert result["sha256_first_64kb"] == hashlib.sha256(data[:0x10000]).hexdigest()

    def test_sha256_first_64kb_uses_only_first_64kb(self):
        buf1 = make_bin()
        write(buf1, 0x100, IDENT_RECORD_A)
        buf2 = bytearray(buf1)
        # Change a byte after the first 64 KB
        buf2[0x10001] = 0xAB
        result1 = EXTRACTOR.extract(bytes(buf1), "test1.bin")
        result2 = EXTRACTOR.extract(bytes(buf2), "test2.bin")
        # sha256_first_64kb should be the same
        assert result1["sha256_first_64kb"] == result2["sha256_first_64kb"]
        # But md5 of the full file should differ
        assert result1["md5"] != result2["md5"]

    def test_md5_changes_with_different_content(self):
        buf1 = make_bin()
        write(buf1, 0x100, IDENT_RECORD_A)
        buf2 = make_bin()
        write(buf2, 0x100, IDENT_RECORD_B)
        r1 = EXTRACTOR.extract(bytes(buf1), "a.bin")
        r2 = EXTRACTOR.extract(bytes(buf2), "b.bin")
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# extract() — hardware_number
# ---------------------------------------------------------------------------


class TestExtractHardwareNumber:
    def test_hardware_number_detected_from_ident_a(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["hardware_number"] == "5WS40145A-T"

    def test_hardware_number_detected_from_ident_b(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_B)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["hardware_number"] == "5WS40045B-T"

    def test_hardware_number_detected_from_ident_c(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_C)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["hardware_number"] == "5WS40036D-T"

    def test_hardware_number_standalone(self):
        buf = make_bin()
        write(buf, 0x100, b"5WS40155C-T")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["hardware_number"] == "5WS40155C-T"

    def test_hardware_number_absent_returns_none(self):
        # Binary with PM3 only, no 5WS4
        buf = make_bin()
        write(buf, 0x100, b"PM38101C00")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["hardware_number"] is None

    def test_hardware_number_without_letter_suffix(self):
        buf = make_bin()
        write(buf, 0x100, b"5WS40145-T")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["hardware_number"] == "5WS40145-T"

    def test_hardware_number_five_digit_variant(self):
        buf = make_bin()
        write(buf, 0x100, b"5WS401456B-T")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["hardware_number"] == "5WS401456B-T"


# ---------------------------------------------------------------------------
# extract() — software_version
# ---------------------------------------------------------------------------


class TestExtractSoftwareVersion:
    def test_sw_version_from_ident_record_a(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["software_version"] == "244177913"

    def test_sw_version_from_ident_record_b(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_B)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["software_version"] == "234082572"

    def test_sw_version_from_ident_record_c(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_C)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["software_version"] == "226472424"

    def test_sw_version_absent_when_no_ident_record(self):
        buf = make_bin()
        write(buf, 0x100, b"PM38101C00")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["software_version"] is None

    def test_sw_version_absent_when_hw_only(self):
        # Only hardware number, no full ident record
        buf = make_bin()
        write(buf, 0x100, b"5WS40145A-T")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["software_version"] is None

    def test_sw_version_is_nine_digits(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        sw = result["software_version"]
        assert sw is not None
        assert re.match(r"^\d{9}$", sw)


# ---------------------------------------------------------------------------
# extract() — ecu_family
# ---------------------------------------------------------------------------


class TestExtractEcuFamily:
    def test_family_sid801_when_explicit(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x60000, b"SID801")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["ecu_family"] == "SID801"

    def test_family_sid801a_when_explicit(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x60000, b"SID801A")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["ecu_family"] == "SID801A"

    def test_family_defaults_to_sid801(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["ecu_family"] == "SID801"

    def test_family_sid801a_not_confused_with_sid803(self):
        # SID803 is excluded by EXCLUSION_SIGNATURES in can_handle(),
        # but even in extract(), SID801A should be detected correctly
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x60000, b"SID801A")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["ecu_family"] == "SID801A"
        assert result["ecu_family"] != "SID803"


# ---------------------------------------------------------------------------
# extract() — calibration_id
# ---------------------------------------------------------------------------


class TestExtractCalibrationId:
    def test_pm3_project_code_detected(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x5000, b"PM38101C00")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["calibration_id"] == "PM38101C00"

    def test_pm3_short_project_code(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x5000, b"PM363000")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["calibration_id"] == "PM363000"

    def test_capm_dataset_used_as_fallback(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x40000, b"CAPM3630.DAT")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["calibration_id"] == "CAPM3630.DAT"

    def test_pm3_takes_priority_over_capm(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x5000, b"PM38101C00")
        write(buf, 0x40000, b"CAPM3630.DAT")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["calibration_id"] == "PM38101C00"

    def test_calibration_id_absent_returns_none(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["calibration_id"] is None

    def test_capm3930_dataset(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x40000, b"CAPM3930.DAT")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["calibration_id"] == "CAPM3930.DAT"


# ---------------------------------------------------------------------------
# extract() — oem_part_number (PSA)
# ---------------------------------------------------------------------------


class TestExtractOemPartNumber:
    def test_psa_part_number_detected(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x30000, b"9648608680")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["oem_part_number"] == "9648608680"

    def test_psa_part_number_different(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x30000, b"9653447180")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["oem_part_number"] == "9653447180"

    def test_psa_part_number_absent_returns_none(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["oem_part_number"] is None


# ---------------------------------------------------------------------------
# extract() — serial_number (S-record reference)
# ---------------------------------------------------------------------------


class TestExtractSerialNumber:
    def test_s_record_s220_detected(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x2000, b"S220040001C0")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["serial_number"] is not None
        assert result["serial_number"].startswith("S")

    def test_s_record_s118_detected(self):
        buf = make_bin()
        # Use HW number only — IDENT_RECORD_A contains "S220040001C0" which
        # also matches the s_record_ref pattern and would win (lower offset).
        write(buf, 0x100, b"5WS40145A-T")
        write(buf, 0x2000, b"S118430100AB")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["serial_number"] is not None
        assert "S118" in result["serial_number"]

    def test_s_record_s120_detected(self):
        buf = make_bin()
        # Use HW number only — avoid S220 in ident record shadowing S120.
        write(buf, 0x100, b"5WS40145A-T")
        write(buf, 0x2000, b"S120040001AB")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["serial_number"] is not None
        assert "S120" in result["serial_number"]

    def test_serial_number_absent_returns_none(self):
        buf = make_bin()
        # Use HW number only — IDENT_RECORD_A contains "S220040001C0"
        # which the s_record_ref pattern matches as a valid S-record ref.
        write(buf, 0x100, b"5WS40145A-T")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["serial_number"] is None


# ---------------------------------------------------------------------------
# extract() — match_key
# ---------------------------------------------------------------------------


class TestExtractMatchKey:
    def test_match_key_built_when_sw_present(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["match_key"] is not None

    def test_match_key_format_is_family_double_colon_version(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["match_key"] == "SID801::244177913"

    def test_match_key_with_sid801a(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x60000, b"SID801A")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["match_key"] == "SID801A::244177913"

    def test_match_key_none_when_no_sw(self):
        buf = make_bin()
        write(buf, 0x100, b"PM38101C00")  # no ident record
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["match_key"] is None

    def test_match_key_with_different_serial(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_B)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["match_key"] == "SID801::234082572"

    def test_match_key_uses_uppercase(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["match_key"] == result["match_key"].upper()


# ---------------------------------------------------------------------------
# extract() — fields not applicable to SID801
# ---------------------------------------------------------------------------


class TestExtractNotApplicableFields:
    def _extract(self) -> dict:
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        return EXTRACTOR.extract(bytes(buf), "test.bin")

    def test_ecu_variant_is_none(self):
        assert self._extract()["ecu_variant"] is None

    def test_calibration_version_is_none(self):
        assert self._extract()["calibration_version"] is None

    def test_sw_base_version_is_none(self):
        assert self._extract()["sw_base_version"] is None

    def test_dataset_number_is_none(self):
        assert self._extract()["dataset_number"] is None


# ---------------------------------------------------------------------------
# extract() — raw_strings
# ---------------------------------------------------------------------------


class TestExtractRawStrings:
    def test_raw_strings_is_list(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert isinstance(result["raw_strings"], list)

    def test_raw_strings_contains_ident(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        # The ident record should appear in raw_strings
        assert len(result["raw_strings"]) >= 1
        found = any("5WS40145A-T" in s for s in result["raw_strings"])
        assert found

    def test_raw_strings_limited_to_20(self):
        buf = make_bin()
        # Fill header with many distinct strings
        for i in range(30):
            offset = 0x10 + i * 32
            s = f"TestString{i:03d}ABCDEF".encode("ascii")
            write(buf, offset, s)
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert len(result["raw_strings"]) <= 20


# ---------------------------------------------------------------------------
# build_match_key() — unit tests on the method directly
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_family_and_sw_produces_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID801",
            software_version="244177913",
        )
        assert key == "SID801::244177913"

    def test_family_and_sw_sid801a(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID801A",
            software_version="234082572",
        )
        assert key == "SID801A::234082572"

    def test_none_returned_when_no_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID801",
            software_version=None,
        )
        assert key is None

    def test_none_returned_when_empty_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID801",
            software_version="",
        )
        assert key is None

    def test_unknown_used_when_no_family(self):
        key = EXTRACTOR.build_match_key(
            software_version="244177913",
        )
        assert key == "UNKNOWN::244177913"

    def test_key_is_uppercase(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="sid801",
            software_version="244177913",
        )
        assert key == key.upper()

    def test_double_colon_separator(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID801",
            software_version="244177913",
        )
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_variant_takes_precedence_over_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID801",
            ecu_variant="SID801A-REV2",
            software_version="244177913",
        )
        assert key.startswith("SID801A-REV2::")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_same_binary_produces_same_result(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x5000, b"PM38101C00")
        data = bytes(buf)
        result1 = EXTRACTOR.extract(data, "test.bin")
        result2 = EXTRACTOR.extract(data, "test.bin")
        assert result1 == result2

    def test_filename_does_not_change_identification(self):
        buf = make_bin()
        write(buf, 0x100, IDENT_RECORD_A)
        data = bytes(buf)
        result1 = EXTRACTOR.extract(data, "original.bin")
        result2 = EXTRACTOR.extract(data, "renamed_copy.bin")
        assert result1 == result2

    def test_different_content_produces_different_md5(self):
        buf1 = make_bin()
        write(buf1, 0x100, IDENT_RECORD_A)
        buf2 = make_bin()
        write(buf2, 0x100, IDENT_RECORD_C)
        r1 = EXTRACTOR.extract(bytes(buf1), "a.bin")
        r2 = EXTRACTOR.extract(bytes(buf2), "b.bin")
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# Full realistic extraction — integration-style
# ---------------------------------------------------------------------------


class TestFullRealisticExtraction:
    """
    Simulate a realistic SID801 binary with all metadata embedded and verify
    all fields are extracted correctly.
    """

    def _make_full_binary(self) -> bytes:
        buf = make_bin()
        # Ident record in header area
        write(buf, 0x100, IDENT_RECORD_A)
        # PM3 project code
        write(buf, 0x5000, b"PM38101C00")
        # S-record reference
        write(buf, 0x3000, b"S118430100AB")
        # PSA part number
        write(buf, 0x30000, b"9648608680")
        # CAPM dataset reference
        write(buf, 0x40000, b"CAPM3630.DAT")
        # SID801A family string
        write(buf, 0x60000, b"SID801A")
        # PM block reference
        write(buf, 0x8000, b"111PM3210050")
        return bytes(buf)

    def test_all_fields_populated(self):
        result = EXTRACTOR.extract(self._make_full_binary(), "full_test.bin")
        assert result["manufacturer"] == "Siemens"
        assert result["file_size"] == SIZE_SID801
        assert result["hardware_number"] == "5WS40145A-T"
        assert result["software_version"] == "244177913"
        assert result["ecu_family"] == "SID801A"
        assert result["calibration_id"] == "PM38101C00"
        assert result["oem_part_number"] == "9648608680"
        assert result["match_key"] == "SID801A::244177913"

    def test_md5_and_sha256_present(self):
        result = EXTRACTOR.extract(self._make_full_binary(), "full_test.bin")
        assert len(result["md5"]) == 32
        assert len(result["sha256_first_64kb"]) == 64

    def test_raw_strings_present(self):
        result = EXTRACTOR.extract(self._make_full_binary(), "full_test.bin")
        assert isinstance(result["raw_strings"], list)
        assert len(result["raw_strings"]) >= 1


# ---------------------------------------------------------------------------
# Patterns — sanity checks
# ---------------------------------------------------------------------------


class TestPatterns:
    """Verify that pattern definitions compile and match expected strings."""

    def test_all_patterns_compile(self):
        for name, pattern in PATTERNS.items():
            try:
                re.compile(pattern)
            except re.error as e:
                raise AssertionError(f"Pattern {name!r} failed to compile: {e}")

    def test_all_pattern_regions_have_valid_region(self):
        for name, region_key in PATTERN_REGIONS.items():
            assert region_key in SEARCH_REGIONS, (
                f"Pattern {name!r} references unknown region {region_key!r}"
            )

    def test_all_patterns_have_a_region(self):
        for name in PATTERNS:
            assert name in PATTERN_REGIONS, f"Pattern {name!r} has no region mapping"

    def test_hardware_number_pattern_matches_5ws4(self):
        pattern = PATTERNS["hardware_number"]
        assert re.search(pattern, b"5WS40145A-T")
        assert re.search(pattern, b"5WS40045B-T")
        assert re.search(pattern, b"5WS40036D-T")
        assert re.search(pattern, b"5WS40155C-T")
        assert re.search(pattern, b"5WS40145-T")  # no letter suffix

    def test_hardware_number_pattern_no_false_positive(self):
        pattern = PATTERNS["hardware_number"]
        assert not re.search(pattern, b"5WS3999A-T")  # wrong prefix
        assert not re.search(pattern, b"6WS40145A-T")  # wrong first digit

    def test_project_code_pattern_matches_pm3(self):
        pattern = PATTERNS["project_code"]
        assert re.search(pattern, b"PM38101C00")
        assert re.search(pattern, b"PM33001C00")
        assert re.search(pattern, b"PM363000")
        assert re.search(pattern, b"PM393000")

    def test_calibration_dataset_pattern_matches_capm(self):
        pattern = PATTERNS["calibration_dataset"]
        assert re.search(pattern, b"CAPM3630.DAT")
        assert re.search(pattern, b"CAPM3930.DAT")

    def test_s_record_pattern_matches_references(self):
        pattern = PATTERNS["s_record_ref"]
        assert re.search(pattern, b"S118430100AB")
        assert re.search(pattern, b"S120040001AB")
        assert re.search(pattern, b"S220040001C0")

    def test_psa_part_number_pattern_matches(self):
        pattern = PATTERNS["psa_part_number"]
        assert re.search(pattern, b"9648608680")
        assert re.search(pattern, b"9653447180")

    def test_ecu_family_pattern_matches_sid801(self):
        pattern = PATTERNS["ecu_family"]
        m1 = re.search(pattern, b"SID801")
        assert m1 and m1.group() == b"SID801"

    def test_ecu_family_pattern_matches_sid801a(self):
        pattern = PATTERNS["ecu_family"]
        m = re.search(pattern, b"SID801A")
        assert m and m.group() == b"SID801A"

    def test_ecu_family_pattern_no_sid803(self):
        pattern = PATTERNS["ecu_family"]
        # SID803 should NOT match the SID801 family pattern
        m = re.search(pattern, b"SID803")
        # SID803 contains "SID80" but not "SID801" — the pattern is SID801A?
        # which requires the '1' after '80', so SID803 should not match.
        assert m is None

    def test_pm_block_ref_pattern_matches(self):
        pattern = PATTERNS["pm_block_ref"]
        assert re.search(pattern, b"111PM3210050")
        assert re.search(pattern, b"111PM3280000")


# ---------------------------------------------------------------------------
# Constants sanity checks
# ---------------------------------------------------------------------------


class TestConstants:
    def test_sid801_file_size_is_512kb(self):
        assert SID801_FILE_SIZE == 512 * 1024

    def test_detection_signatures_not_empty(self):
        assert len(DETECTION_SIGNATURES) > 0

    def test_exclusion_signatures_not_empty(self):
        assert len(EXCLUSION_SIGNATURES) > 0

    def test_search_regions_have_header(self):
        assert "header" in SEARCH_REGIONS

    def test_search_regions_have_full(self):
        assert "full" in SEARCH_REGIONS

    def test_header_region_is_4kb(self):
        header = SEARCH_REGIONS["header"]
        assert header.start == 0
        assert header.stop == 0x1000

    def test_ident_area_region_is_64kb(self):
        ident = SEARCH_REGIONS["ident_area"]
        assert ident.start == 0
        assert ident.stop == 0x10000

    def test_extended_region_is_128kb(self):
        ext = SEARCH_REGIONS["extended"]
        assert ext.start == 0
        assert ext.stop == 0x20000

    def test_full_region_covers_all(self):
        full = SEARCH_REGIONS["full"]
        assert full.start == 0
        assert full.stop is None


# ---------------------------------------------------------------------------
# Resolver unit tests — called via extractor internals
# ---------------------------------------------------------------------------


class TestResolverHardwareNumber:
    def test_returns_first_hit(self):
        raw_hits = {"hardware_number": ["5WS40145A-T", "5WS40045B-T"]}
        result = EXTRACTOR._resolve_hardware_number(raw_hits)
        assert result == "5WS40145A-T"

    def test_returns_none_when_no_hits(self):
        raw_hits = {}
        result = EXTRACTOR._resolve_hardware_number(raw_hits)
        assert result is None


class TestResolverSoftwareVersion:
    def test_extracts_serial_from_ident_record(self):
        raw_hits = {
            "ident_record": ["5WS40145A-T 244177913   04020028014941S220040001C0"]
        }
        result = EXTRACTOR._resolve_software_version(raw_hits)
        assert result == "244177913"

    def test_returns_none_when_no_ident_record(self):
        raw_hits = {}
        result = EXTRACTOR._resolve_software_version(raw_hits)
        assert result is None

    def test_returns_none_when_ident_has_no_serial(self):
        # Malformed ident record with only one token
        raw_hits = {"ident_record": ["5WS40145A-T"]}
        result = EXTRACTOR._resolve_software_version(raw_hits)
        assert result is None

    def test_returns_none_when_serial_is_not_9_digits(self):
        # 8 digits instead of 9
        raw_hits = {"ident_record": ["5WS40145A-T 24417791 rest"]}
        result = EXTRACTOR._resolve_software_version(raw_hits)
        assert result is None

    def test_different_ident_records(self):
        raw_hits = {
            "ident_record": ["5WS40036D-T 226472424   02100016202138S218432001D0"]
        }
        result = EXTRACTOR._resolve_software_version(raw_hits)
        assert result == "226472424"


class TestResolverEcuFamily:
    def test_explicit_sid801(self):
        raw_hits = {"ecu_family": ["SID801"]}
        result = EXTRACTOR._resolve_ecu_family(raw_hits)
        assert result == "SID801"

    def test_explicit_sid801a(self):
        raw_hits = {"ecu_family": ["SID801A"]}
        result = EXTRACTOR._resolve_ecu_family(raw_hits)
        assert result == "SID801A"

    def test_defaults_to_sid801_when_no_family_hit(self):
        raw_hits = {}
        result = EXTRACTOR._resolve_ecu_family(raw_hits)
        assert result == "SID801"

    def test_normalises_to_uppercase(self):
        raw_hits = {"ecu_family": ["sid801a"]}
        result = EXTRACTOR._resolve_ecu_family(raw_hits)
        assert result == "SID801A"


class TestResolverCalibrationId:
    def test_pm3_priority(self):
        raw_hits = {
            "project_code": ["PM38101C00"],
            "calibration_dataset": ["CAPM3630.DAT"],
        }
        result = EXTRACTOR._resolve_calibration_id(raw_hits)
        assert result == "PM38101C00"

    def test_capm_fallback(self):
        raw_hits = {"calibration_dataset": ["CAPM3630.DAT"]}
        result = EXTRACTOR._resolve_calibration_id(raw_hits)
        assert result == "CAPM3630.DAT"

    def test_none_when_no_hits(self):
        raw_hits = {}
        result = EXTRACTOR._resolve_calibration_id(raw_hits)
        assert result is None


# ---------------------------------------------------------------------------
# Registry integration — SID801 appears in the Siemens EXTRACTORS list
# ---------------------------------------------------------------------------


class TestRegistryIntegration:
    def test_sid801_in_siemens_extractors(self):
        from openremap.core.manufacturers.siemens import EXTRACTORS

        names = [type(e).__name__ for e in EXTRACTORS]
        assert "SiemensSID801Extractor" in names

    def test_sid801_in_global_extractors(self):
        from openremap.core.manufacturers import EXTRACTORS

        names = [type(e).__name__ for e in EXTRACTORS]
        assert "SiemensSID801Extractor" in names

    def test_sid801_before_sid803_in_registry(self):
        from openremap.core.manufacturers.siemens import EXTRACTORS

        names = [type(e).__name__ for e in EXTRACTORS]
        idx801 = names.index("SiemensSID801Extractor")
        idx803 = names.index("SiemensSID803Extractor")
        assert idx801 < idx803, "SID801 must come before SID803 in the registry"

    def test_no_duplicate_extractors(self):
        from openremap.core.manufacturers.siemens import EXTRACTORS

        names = [type(e).__name__ for e in EXTRACTORS]
        assert len(names) == len(set(names)), "Duplicate extractors in registry"
