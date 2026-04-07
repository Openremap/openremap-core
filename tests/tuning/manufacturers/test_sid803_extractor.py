"""
Tests for SiemensSID803Extractor (SID803 / SID803A).

Covers:
  - Identity properties: name, supported_families
  - can_handle():
      * True  — each detection signature independently (111PO, PO2, PO3,
                S122, SID803) at all three valid sizes
      * True  — 5WS4 hardware number in 2 MB buffer
      * True  — SID803A string in 2 MB buffer
      * False — empty binary
      * False — wrong file size (128 KB, 256 KB, 512 KB, 1 MB, off-by-one)
      * False — correct size but no detection signatures (all-zero)
      * False — exclusion signatures (EDC17, MEDC17, MED17, ME7., PM3)
  - extract():
      * Required fields always present: manufacturer, file_size, md5,
        sha256_first_64kb
      * manufacturer always "Siemens"
      * file_size == len(data)
      * md5 and sha256_first_64kb are well-formed hex strings
      * ecu_family detected as SID803 or SID803A
      * hardware_number detected from 5WS4 ident record (2 MB only)
      * software_version extracted from ident record serial
      * calibration_id from CAPO or PO project code
      * match_key built as FAMILY::VERSION
      * match_key is None when no version found
      * extract() is deterministic
      * filename does not affect identification fields
  - build_match_key():
      * family and sw produce correct key
      * None returned when no version component
  - __repr__: contains class name and manufacturer
"""

import hashlib

from openremap.core.manufacturers.siemens.sid803.extractor import (
    SiemensSID803Extractor,
)
from openremap.core.manufacturers.siemens.sid803.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    PATTERNS,
    PATTERN_REGIONS,
    SEARCH_REGIONS,
    SID803A_FILE_SIZE,
    VALID_FILE_SIZES,
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

# Valid SID803/SID803A sizes
SIZE_448KB = 458752
SIZE_452KB = 462848
SIZE_2MB = 2097152

# Realistic ident records for SID803A (2 MB) binaries
IDENT_RECORD_A = b"5WS40262B-T  00012345678901234"
IDENT_RECORD_B = b"5WS40612B-T 12345678901234"

EXTRACTOR = SiemensSID803Extractor()


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

    def test_sid803_in_supported_families(self):
        assert "SID803" in EXTRACTOR.supported_families

    def test_sid803a_in_supported_families(self):
        assert "SID803A" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for fam in EXTRACTOR.supported_families:
            assert isinstance(fam, str), f"Family {fam!r} is not a string"

    def test_repr_contains_manufacturer(self):
        r = repr(EXTRACTOR)
        assert "Siemens" in r

    def test_repr_contains_class_name(self):
        r = repr(EXTRACTOR)
        assert "SiemensSID803Extractor" in r


# ---------------------------------------------------------------------------
# can_handle() — positive detection: 448 KB
# ---------------------------------------------------------------------------


class TestCanHandleTrue448KB:
    """Correct 448 KB size with detection signatures → True."""

    def _make(self, sig: bytes, offset: int = 0x100) -> bytes:
        buf = make_buf(SIZE_448KB)
        write(buf, offset, sig)
        return bytes(buf)

    def test_111po_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"111PO"))

    def test_po2_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PO220"))

    def test_po3_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PO320"))

    def test_s122_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"S122"))

    def test_sid803_string(self):
        assert EXTRACTOR.can_handle(self._make(b"SID803"))

    def test_sid803a_string(self):
        assert EXTRACTOR.can_handle(self._make(b"SID803A"))

    def test_signature_at_offset_zero(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0, b"111PO220")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_multiple_signatures_still_true(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x5000, b"SID803")
        assert EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — positive detection: 452 KB
# ---------------------------------------------------------------------------


class TestCanHandleTrue452KB:
    """Correct 452 KB size with detection signatures → True."""

    def _make(self, sig: bytes, offset: int = 0x100) -> bytes:
        buf = make_buf(SIZE_452KB)
        write(buf, offset, sig)
        return bytes(buf)

    def test_111po_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"111PO"))

    def test_po2_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PO2"))

    def test_po3_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PO3"))

    def test_s122_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"S122"))

    def test_sid803_string(self):
        assert EXTRACTOR.can_handle(self._make(b"SID803"))


# ---------------------------------------------------------------------------
# can_handle() — positive detection: 2 MB
# ---------------------------------------------------------------------------


class TestCanHandleTrue2MB:
    """Correct 2 MB size with detection signatures → True."""

    def _make(self, sig: bytes, offset: int = 0x100) -> bytes:
        buf = make_buf(SIZE_2MB)
        write(buf, offset, sig)
        return bytes(buf)

    def test_111po_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"111PO"))

    def test_po2_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PO2"))

    def test_s122_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"S122"))

    def test_sid803_string(self):
        assert EXTRACTOR.can_handle(self._make(b"SID803"))

    def test_sid803a_string(self):
        assert EXTRACTOR.can_handle(self._make(b"SID803A"))

    def test_5ws4_hardware_number_in_header(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"5WS40262B-T")
        write(buf, 0x200, b"111PO220")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_full_ident_record_with_po_block(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x500, b"111PO320")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_signature_within_scan_region(self):
        # Scan region is first 512 KB — place near its end
        buf = make_buf(SIZE_2MB)
        write(buf, 0x7FFF0, b"PO220")
        assert EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: wrong file size
# ---------------------------------------------------------------------------


class TestCanHandleFalseWrongSize:
    """Size gate must reject non-matching file sizes."""

    def test_empty_binary(self):
        assert not EXTRACTOR.can_handle(b"")

    def test_1_byte_binary(self):
        assert not EXTRACTOR.can_handle(b"\x00")

    def test_128kb_with_signature(self):
        buf = make_buf(128 * KB)
        write(buf, 0x100, b"111PO220")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_256kb_with_signature(self):
        buf = make_buf(256 * KB)
        write(buf, 0x100, b"PO220")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_512kb_with_signature(self):
        buf = make_buf(512 * KB)
        write(buf, 0x100, b"111PO220")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_1mb_with_signature(self):
        buf = make_buf(1 * MB)
        write(buf, 0x100, b"SID803")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_448kb_minus_one(self):
        buf = make_buf(SIZE_448KB - 1)
        write(buf, 0x100, b"111PO")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_448kb_plus_one(self):
        buf = make_buf(SIZE_448KB + 1)
        write(buf, 0x100, b"111PO")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_452kb_minus_one(self):
        buf = make_buf(SIZE_452KB - 1)
        write(buf, 0x100, b"111PO")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_452kb_plus_one(self):
        buf = make_buf(SIZE_452KB + 1)
        write(buf, 0x100, b"111PO")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_2mb_minus_one(self):
        buf = make_buf(SIZE_2MB - 1)
        write(buf, 0x100, b"111PO")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_2mb_plus_one(self):
        buf = make_buf(SIZE_2MB + 1)
        write(buf, 0x100, b"111PO")
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: no detection signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseNoSignature:
    """Correct size but no detection signatures → False."""

    def test_all_zero_448kb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_448KB)))

    def test_all_zero_452kb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_452KB)))

    def test_all_zero_2mb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_2MB)))

    def test_all_ff_448kb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_448KB, fill=0xFF)))

    def test_all_ff_2mb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_2MB, fill=0xFF)))

    def test_ascii_noise_no_signature(self):
        buf = make_buf(SIZE_448KB)
        noise = b"This is just some text with no ECU signatures at all." * 200
        write(buf, 0x100, noise[: SIZE_448KB - 0x200])
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: exclusion signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseExclusion:
    """Exclusion signatures override positive detection → False."""

    def _make_with_exclusion(
        self, exclusion_sig: bytes, size: int = SIZE_448KB
    ) -> bytes:
        buf = make_buf(size)
        write(buf, 0x100, b"111PO220")  # positive detection
        write(buf, 0x5000, exclusion_sig)  # exclusion
        return bytes(buf)

    def test_edc17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"EDC17"))

    def test_medc17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MEDC17"))

    def test_med17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MED17"))

    def test_me7_dot_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"ME7."))

    def test_pm3_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"PM3"))

    def test_pm3_exclusion_with_sid803_signature(self):
        """PM3 is the strongest negative: SID801 uses PM3, SID803 uses PO."""
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"SID803")
        write(buf, 0x5000, b"PM3")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_overrides_multiple_detections(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x200, b"SID803")
        write(buf, 0x300, b"S122")
        write(buf, 0x5000, b"EDC17")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_start_of_binary(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0, b"PM3")
        write(buf, 0x100, b"111PO220")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_end_of_scan_region(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        write(buf, SIZE_448KB - 10, b"ME7.")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_in_2mb_binary(self):
        assert not EXTRACTOR.can_handle(
            self._make_with_exclusion(b"PM3", size=SIZE_2MB)
        )

    def test_all_exclusion_signatures_reject(self):
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
            buf = make_buf(SIZE_448KB)
            write(buf, 0x100, b"111PO220")
            data = bytes(buf)
        return EXTRACTOR.extract(data, "test.bin")

    def test_all_required_fields_present(self):
        result = self._extract()
        for key in ("manufacturer", "file_size", "md5", "sha256_first_64kb"):
            assert key in result, f"Missing required field: {key}"

    def test_manufacturer_always_siemens(self):
        assert self._extract()["manufacturer"] == "Siemens"

    def test_file_size_equals_data_length_448kb(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["file_size"] == SIZE_448KB

    def test_file_size_equals_data_length_2mb(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["file_size"] == SIZE_2MB

    def test_md5_is_32_hex_chars(self):
        result = self._extract()
        assert len(result["md5"]) == 32
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_matches_hashlib(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_first_64kb_is_64_hex_chars(self):
        result = self._extract()
        sha = result["sha256_first_64kb"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_first_64kb_matches_hashlib(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert result["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_ignores_bytes_past_64kb(self):
        buf1 = make_buf(SIZE_448KB)
        write(buf1, 0x100, b"111PO220")
        buf2 = make_buf(SIZE_448KB)
        write(buf2, 0x100, b"111PO220")
        write(buf2, 0x20000, b"DIFFERENT_CONTENT_HERE")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_md5_changes_with_different_content(self):
        buf1 = make_buf(SIZE_448KB)
        write(buf1, 0x100, b"111PO220")
        buf2 = make_buf(SIZE_448KB)
        write(buf2, 0x100, b"111PO320")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# extract() — ECU family resolution
# ---------------------------------------------------------------------------


class TestExtractEcuFamily:
    def test_family_sid803_for_448kb(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SID803"

    def test_family_sid803_for_452kb(self):
        buf = make_buf(SIZE_452KB)
        write(buf, 0x100, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SID803"

    def test_family_sid803a_for_2mb(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SID803A"

    def test_family_sid803a_when_explicit_string(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x500, b"SID803A")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SID803A"

    def test_family_sid803_when_explicit_string_no_a(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x500, b"SID803")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SID803"

    def test_family_sid803a_explicit_overrides_small_size(self):
        """If the string says SID803A, trust it even for smaller files."""
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x500, b"SID803A")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "SID803A"


# ---------------------------------------------------------------------------
# extract() — hardware number
# ---------------------------------------------------------------------------


class TestExtractHardwareNumber:
    def test_hw_detected_in_2mb_header(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x500, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] == "5WS40262B-T"

    def test_hw_detected_different_part(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, IDENT_RECORD_B)
        write(buf, 0x500, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] == "5WS40612B-T"

    def test_hw_none_in_448kb(self):
        """SID803 (448 KB) files typically lack 5WS4 numbers."""
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is None

    def test_hw_standalone_5ws4_in_header(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"5WS40999A-T")
        write(buf, 0x500, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] == "5WS40999A-T"


# ---------------------------------------------------------------------------
# extract() — software version
# ---------------------------------------------------------------------------


class TestExtractSoftwareVersion:
    def test_sw_from_ident_record(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x500, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        # Ident record A serial: "00012345678901234" (17 digits)
        assert result["software_version"] == "00012345678901234"

    def test_sw_from_s_record_fallback(self):
        """When no ident record, fall back to S-record reference."""
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x200, b"S1200790100E0")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] is not None

    def test_sw_none_when_no_ident_or_srecord(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] is None


# ---------------------------------------------------------------------------
# extract() — calibration ID
# ---------------------------------------------------------------------------


class TestExtractCalibrationId:
    def test_capo_dataset_detected(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x500, b"CAPO1234")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] == "CAPO1234"

    def test_po_project_code_fallback(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x500, b"PO320")
        result = EXTRACTOR.extract(bytes(buf))
        # calibration_id should be the PO project code
        assert result["calibration_id"] is not None

    def test_capo_takes_priority_over_po(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"111PO220")
        write(buf, 0x500, b"CAPO5678")
        write(buf, 0x600, b"PO320")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] == "CAPO5678"

    def test_calibration_id_none_when_no_hits(self):
        buf = make_buf(SIZE_2MB)
        # Use SID803 string for detection but no calibration data
        write(buf, 0x100, b"SID803")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] is None


# ---------------------------------------------------------------------------
# extract() — match key
# ---------------------------------------------------------------------------


class TestExtractMatchKey:
    def test_match_key_built_when_sw_present(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x500, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is not None

    def test_match_key_format_is_family_double_colon_version(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x500, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_match_key_none_when_no_sw(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is None

    def test_match_key_uses_uppercase(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x500, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert key == key.upper()

    def test_match_key_with_sid803a_family(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, IDENT_RECORD_A)
        write(buf, 0x500, b"111PO220")
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert key.startswith("SID803A::")


# ---------------------------------------------------------------------------
# extract() — not-applicable fields
# ---------------------------------------------------------------------------


class TestExtractNotApplicableFields:
    def _extract(self) -> dict:
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
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

    def test_oem_part_number_is_none(self):
        assert self._extract()["oem_part_number"] is None


# ---------------------------------------------------------------------------
# build_match_key()
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_family_and_sw_produces_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID803",
            software_version="00012345678901234",
        )
        assert key == "SID803::00012345678901234"

    def test_family_and_sw_sid803a(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID803A",
            software_version="12345678901234",
        )
        assert key == "SID803A::12345678901234"

    def test_none_returned_when_no_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID803",
            software_version=None,
        )
        assert key is None

    def test_none_returned_when_empty_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID803",
            software_version="",
        )
        assert key is None

    def test_unknown_used_when_no_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family=None,
            software_version="12345678901234",
        )
        assert key == "UNKNOWN::12345678901234"

    def test_key_is_uppercase(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="sid803a",
            software_version="abc123",
        )
        assert key == key.upper()

    def test_double_colon_separator(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID803",
            software_version="VERSION",
        )
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_variant_takes_precedence_over_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="SID803",
            ecu_variant="SID803A_SPECIAL",
            software_version="12345678901234",
        )
        assert key.startswith("SID803A_SPECIAL::")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_same_binary_produces_same_result(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        data = bytes(buf)
        r1 = EXTRACTOR.extract(data, "file.bin")
        r2 = EXTRACTOR.extract(data, "file.bin")
        assert r1 == r2

    def test_filename_does_not_change_identification(self):
        buf = make_buf(SIZE_448KB)
        write(buf, 0x100, b"111PO220")
        data = bytes(buf)
        r1 = EXTRACTOR.extract(data, "foo.bin")
        r2 = EXTRACTOR.extract(data, "bar.bin")
        # Core identification fields must be identical
        for key in (
            "manufacturer",
            "file_size",
            "md5",
            "sha256_first_64kb",
            "hardware_number",
            "software_version",
            "calibration_id",
        ):
            assert r1[key] == r2[key], f"Field {key!r} differs by filename"

    def test_different_content_produces_different_md5(self):
        buf1 = make_buf(SIZE_448KB)
        write(buf1, 0x100, b"111PO220")
        buf2 = make_buf(SIZE_448KB, fill=0x01)
        write(buf2, 0x100, b"111PO320")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# Patterns module validation
# ---------------------------------------------------------------------------


class TestPatternsModule:
    def test_detection_signatures_is_list(self):
        assert isinstance(DETECTION_SIGNATURES, list)

    def test_detection_signatures_not_empty(self):
        assert len(DETECTION_SIGNATURES) > 0

    def test_exclusion_signatures_is_list(self):
        assert isinstance(EXCLUSION_SIGNATURES, list)

    def test_exclusion_signatures_not_empty(self):
        assert len(EXCLUSION_SIGNATURES) > 0

    def test_valid_file_sizes_is_set(self):
        assert isinstance(VALID_FILE_SIZES, set)

    def test_valid_file_sizes_has_three_entries(self):
        assert len(VALID_FILE_SIZES) == 3

    def test_448kb_in_valid_sizes(self):
        assert SIZE_448KB in VALID_FILE_SIZES

    def test_452kb_in_valid_sizes(self):
        assert SIZE_452KB in VALID_FILE_SIZES

    def test_2mb_in_valid_sizes(self):
        assert SIZE_2MB in VALID_FILE_SIZES

    def test_sid803a_file_size_is_2mb(self):
        assert SID803A_FILE_SIZE == SIZE_2MB

    def test_111po_in_detection_signatures(self):
        assert b"111PO" in DETECTION_SIGNATURES

    def test_pm3_in_exclusion_signatures(self):
        assert b"PM3" in EXCLUSION_SIGNATURES

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

    def test_search_regions_have_header(self):
        assert "header" in SEARCH_REGIONS

    def test_search_regions_have_full(self):
        assert "full" in SEARCH_REGIONS

    def test_patterns_is_dict(self):
        assert isinstance(PATTERNS, dict)

    def test_pattern_regions_is_dict(self):
        assert isinstance(PATTERN_REGIONS, dict)

    def test_all_pattern_regions_reference_valid_regions(self):
        for name, region_key in PATTERN_REGIONS.items():
            assert region_key in SEARCH_REGIONS, (
                f"Pattern {name!r} references unknown region {region_key!r}"
            )


# ---------------------------------------------------------------------------
# Full realistic extraction (2 MB SID803A)
# ---------------------------------------------------------------------------


class TestFullRealisticExtraction:
    def _make_full_binary(self) -> bytes:
        buf = make_buf(SIZE_2MB)
        # Header region — ident record
        write(buf, 0x100, IDENT_RECORD_A)
        # Project codes and block markers
        write(buf, 0x500, b"111PO220")
        write(buf, 0x600, b"PO220")
        # S-record reference
        write(buf, 0x200, b"S1220012345AB")
        # Calibration dataset
        write(buf, 0x1000, b"CAPO0001")
        # FOIX reference
        write(buf, 0x2000, b"FOIXS16000122500")
        # Family string
        write(buf, 0x3000, b"SID803A")
        return bytes(buf)

    def test_all_core_fields_populated(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data, "SID803A_test.bin")
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] == "SID803A"
        assert result["hardware_number"] == "5WS40262B-T"
        assert result["software_version"] == "00012345678901234"
        assert result["calibration_id"] is not None
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
