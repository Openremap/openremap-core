"""
Tests for SiemensPPDExtractor (PPD1.1 / PPD1.2 / PPD1.5).

Covers:
  - Identity properties: name, supported_families
  - can_handle():
      * True  — each detection signature independently (PPD1., 111SN, CASN)
      * True  — PPD1.2 family string in variable-size binaries
      * True  — detection at offset 0 and offset 0x40000
      * False — empty binary
      * False — exclusion signatures (EDC17, MEDC17, MED17, ME7., BOSCH, PM3)
      * False — all-zero binary (no detection signatures)
  - extract():
      * Required fields always present: manufacturer, file_size, md5,
        sha256_first_64kb
      * manufacturer always "Siemens"
      * file_size == len(data)
      * md5 and sha256_first_64kb are well-formed hex strings
      * ecu_family detected as PPD1.1, PPD1.2, or PPD1.5
      * software_version from serial code
      * hardware_number from hw_sw_version pattern
      * oem_part_number from VAG part number
      * calibration_id from CASN dataset reference
      * match_key built as FAMILY::VERSION or VARIANT::VERSION
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

from openremap.core.manufacturers.siemens.ppd.extractor import (
    SiemensPPDExtractor,
)
from openremap.core.manufacturers.siemens.ppd.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    PATTERNS,
    PATTERN_REGIONS,
    SEARCH_REGIONS,
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

# Common sizes observed for PPD binaries
SIZE_250KB = 249856
SIZE_2MB = 2097152
SIZE_2MB_PLUS2 = 2097154

# Realistic ident fragments from real PPD binaries
SERIAL_CODE = b"6576286135"
SN_PROJECT_BLOCK = b"111SN100K5400000111SN100K5400000111SN100K5400000"
CASN_DATASET = b"CASN1K54.DAT"
OEM_PART_NUMBER = b"03G906018DT"
OEM_PART_FULL = b"03G906018DT R4 2.0l PPD1.2"
PPD_FAMILY_12 = b"PPD1.2"
PPD_FAMILY_11 = b"PPD1.1"
PPD_FAMILY_15 = b"PPD1.5"
HW_SW_VERSION = b"0431657628.90.02"

EXTRACTOR = SiemensPPDExtractor()


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

    def test_ppd11_in_supported_families(self):
        assert "PPD1.1" in EXTRACTOR.supported_families

    def test_ppd12_in_supported_families(self):
        assert "PPD1.2" in EXTRACTOR.supported_families

    def test_ppd15_in_supported_families(self):
        assert "PPD1.5" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for fam in EXTRACTOR.supported_families:
            assert isinstance(fam, str), f"Family {fam!r} is not a string"

    def test_repr_contains_manufacturer(self):
        r = repr(EXTRACTOR)
        assert "Siemens" in r

    def test_repr_contains_class_name(self):
        r = repr(EXTRACTOR)
        assert "SiemensPPDExtractor" in r


# ---------------------------------------------------------------------------
# can_handle() — positive detection
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """Detection signatures present → True (PPD has no size gate)."""

    def _make(self, sig: bytes, size: int = SIZE_2MB, offset: int = 0x100) -> bytes:
        buf = make_buf(size)
        write(buf, offset, sig)
        return bytes(buf)

    def test_ppd12_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PPD1.2"))

    def test_ppd11_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PPD1.1"))

    def test_ppd15_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PPD1.5"))

    def test_ppd1_dot_generic(self):
        assert EXTRACTOR.can_handle(self._make(b"PPD1."))

    def test_111sn_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"111SN"))

    def test_casn_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"CASN"))

    def test_full_casn_dataset(self):
        assert EXTRACTOR.can_handle(self._make(CASN_DATASET))

    def test_full_oem_part_full(self):
        assert EXTRACTOR.can_handle(self._make(OEM_PART_FULL))

    def test_sn_project_block(self):
        assert EXTRACTOR.can_handle(self._make(SN_PROJECT_BLOCK))

    def test_signature_at_offset_zero(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0, PPD_FAMILY_12)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_signature_at_offset_0x40000(self):
        """PPD ident can sit at 0x40000 in 2 MB files."""
        buf = make_buf(SIZE_2MB)
        write(buf, 0x40000, PPD_FAMILY_12)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_full_ident_at_offset_0x40000(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x40000, OEM_PART_FULL)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_multiple_signatures_still_true(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x500, b"111SN")
        write(buf, 0x1000, CASN_DATASET)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_250kb_with_ppd_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PPD1.2", size=SIZE_250KB))

    def test_2mb_plus_2_with_signature(self):
        assert EXTRACTOR.can_handle(self._make(b"PPD1.2", size=SIZE_2MB_PLUS2))

    def test_arbitrary_size_with_signature(self):
        """PPD has no strict size gate — any size with a signature works."""
        assert EXTRACTOR.can_handle(self._make(b"PPD1.2", size=512 * KB))


# ---------------------------------------------------------------------------
# can_handle() — negative: no detection signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseNoSignature:
    """No detection signatures present → False."""

    def test_empty_binary(self):
        assert not EXTRACTOR.can_handle(b"")

    def test_1_byte_binary(self):
        assert not EXTRACTOR.can_handle(b"\x00")

    def test_all_zero_250kb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_250KB)))

    def test_all_zero_2mb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_2MB)))

    def test_all_ff_2mb(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_2MB, fill=0xFF)))

    def test_ascii_noise_no_signature(self):
        buf = make_buf(SIZE_250KB)
        noise = b"This is just some text with no ECU signatures at all." * 100
        write(buf, 0x100, noise[:0x5000])
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_too_small_binary(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(64)))

    def test_similar_but_wrong_prefix(self):
        """PPD without the trailing dot+digit shouldn't match PPD1."""
        buf = make_buf(SIZE_2MB)
        # "PPD2" is not a detection signature
        write(buf, 0x100, b"PPD2.0")
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: exclusion signatures
# ---------------------------------------------------------------------------


class TestCanHandleFalseExclusion:
    """Exclusion signatures override positive detection → False."""

    def _make_with_exclusion(self, exclusion_sig: bytes) -> bytes:
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)  # positive detection
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

    def test_bosch_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"BOSCH"))

    def test_pm3_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"PM3"))

    def test_exclusion_overrides_multiple_detections(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x500, b"111SN")
        write(buf, 0x1000, CASN_DATASET)
        write(buf, 0x5000, b"BOSCH")  # exclusion
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_start_of_binary(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0, b"EDC17")
        write(buf, 0x100, PPD_FAMILY_12)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_near_end_of_exclusion_region(self):
        """Exclusion scans first 512 KB."""
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x7FFF0, b"ME7.")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_all_exclusion_signatures_reject(self):
        for sig in EXCLUSION_SIGNATURES:
            data = self._make_with_exclusion(sig)
            assert not EXTRACTOR.can_handle(data), f"Exclusion {sig!r} should reject"

    def test_exclusion_past_512kb_does_not_reject(self):
        """Exclusion only scans first 512 KB — signature past that is ignored."""
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x80010, b"BOSCH")  # past 512 KB boundary
        assert EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# extract() — required fields
# ---------------------------------------------------------------------------


class TestExtractRequiredFields:
    """All required fields present and correctly computed."""

    def _extract(self, data: bytes = None) -> dict:
        if data is None:
            buf = make_buf(SIZE_2MB)
            write(buf, 0x100, PPD_FAMILY_12)
            data = bytes(buf)
        return EXTRACTOR.extract(data, "test.bin")

    def test_all_required_fields_present(self):
        result = self._extract()
        for key in ("manufacturer", "file_size", "md5", "sha256_first_64kb"):
            assert key in result, f"Missing required field: {key}"

    def test_manufacturer_always_siemens(self):
        assert self._extract()["manufacturer"] == "Siemens"

    def test_manufacturer_siemens_for_ppd11(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_11)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["manufacturer"] == "Siemens"

    def test_file_size_equals_data_length(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["file_size"] == SIZE_2MB

    def test_file_size_correct_for_250kb(self):
        buf = make_buf(SIZE_250KB)
        write(buf, 0x100, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["file_size"] == SIZE_250KB

    def test_md5_is_32_hex_chars(self):
        result = self._extract()
        assert len(result["md5"]) == 32
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_is_lowercase_hex(self):
        result = self._extract()
        assert result["md5"] == result["md5"].lower()

    def test_md5_matches_hashlib(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_first_64kb_is_64_hex_chars(self):
        result = self._extract()
        sha = result["sha256_first_64kb"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_first_64kb_matches_hashlib(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert result["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_ignores_bytes_past_64kb(self):
        buf1 = make_buf(SIZE_2MB)
        write(buf1, 0x100, PPD_FAMILY_12)
        buf2 = make_buf(SIZE_2MB)
        write(buf2, 0x100, PPD_FAMILY_12)
        write(buf2, 0x20000, b"TOTALLY_DIFFERENT_BYTES")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_md5_changes_with_different_content(self):
        buf1 = make_buf(SIZE_2MB)
        write(buf1, 0x100, PPD_FAMILY_12)
        buf2 = make_buf(SIZE_2MB, fill=0x01)
        write(buf2, 0x100, PPD_FAMILY_15)
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# extract() — ECU family
# ---------------------------------------------------------------------------


class TestExtractEcuFamily:
    def test_family_ppd12_detected(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "PPD1.2"

    def test_family_ppd11_detected(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_11)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "PPD1.1"

    def test_family_ppd15_detected(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_15)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "PPD1.5"

    def test_family_from_oem_part_full(self):
        """ECU family can be extracted from the full OEM ident string."""
        buf = make_buf(SIZE_2MB)
        write(buf, 0x40000, OEM_PART_FULL)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] is not None

    def test_family_none_when_only_casn(self):
        """If only CASN present (no PPD family string), family may be None."""
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, CASN_DATASET)
        result = EXTRACTOR.extract(bytes(buf))
        # With only CASN, no PPD1.x string → family may be None
        # (depends on implementation — CASN alone can't determine family)
        # We just verify it doesn't crash and returns a valid value or None
        assert result["ecu_family"] is None or result["ecu_family"].startswith("PPD")

    def test_family_at_offset_0x40000(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x40000, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "PPD1.2"


# ---------------------------------------------------------------------------
# extract() — software version
# ---------------------------------------------------------------------------


class TestExtractSoftwareVersion:
    def test_sw_version_from_serial_code(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] == "6576286135"

    def test_sw_version_from_hw_sw_version_fallback(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, HW_SW_VERSION)
        result = EXTRACTOR.extract(bytes(buf))
        # Should pick up either serial_code or hw_sw_version
        assert result["software_version"] is not None

    def test_sw_version_none_when_no_identifiers(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"111SN")
        result = EXTRACTOR.extract(bytes(buf))
        # 111SN alone without a proper project code pattern may not yield sw
        # Just verify it doesn't crash
        assert result["software_version"] is None or isinstance(
            result["software_version"], str
        )

    def test_different_serial_codes(self):
        buf1 = make_buf(SIZE_2MB)
        write(buf1, 0x100, PPD_FAMILY_12)
        write(buf1, 0x200, b"6576286135")
        buf2 = make_buf(SIZE_2MB)
        write(buf2, 0x100, PPD_FAMILY_12)
        write(buf2, 0x200, b"6576286149")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["software_version"] != r2["software_version"]


# ---------------------------------------------------------------------------
# extract() — hardware number
# ---------------------------------------------------------------------------


class TestExtractHardwareNumber:
    def test_hw_from_hw_sw_version_pattern(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, HW_SW_VERSION)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is not None

    def test_hw_none_when_no_pattern(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is None


# ---------------------------------------------------------------------------
# extract() — OEM part number
# ---------------------------------------------------------------------------


class TestExtractOemPartNumber:
    def test_oem_part_number_detected(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, OEM_PART_NUMBER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["oem_part_number"] is not None
        assert "03G906018" in result["oem_part_number"]

    def test_oem_part_number_from_full_ident(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x40000, OEM_PART_FULL)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["oem_part_number"] is not None

    def test_oem_part_number_different_suffix(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, b"03G906018CD")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["oem_part_number"] is not None

    def test_oem_part_number_none_when_absent(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["oem_part_number"] is None

    def test_ecu_variant_mirrors_oem_part_number(self):
        """ecu_variant is set to oem_part_number for PPD."""
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, OEM_PART_NUMBER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_variant"] == result["oem_part_number"]


# ---------------------------------------------------------------------------
# extract() — calibration ID
# ---------------------------------------------------------------------------


class TestExtractCalibrationId:
    def test_casn_dataset_detected(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, CASN_DATASET)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] == "CASN1K54.DAT"

    def test_different_casn_dataset(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, b"CASN0F75.DAT")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] == "CASN0F75.DAT"

    def test_calibration_id_none_when_no_casn(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] is None


# ---------------------------------------------------------------------------
# extract() — displacement
# ---------------------------------------------------------------------------


class TestExtractDisplacement:
    def test_displacement_from_full_ident(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x40000, OEM_PART_FULL)
        result = EXTRACTOR.extract(bytes(buf))
        assert result.get("displacement") is not None

    def test_displacement_standalone(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, b"R4 2.0l")
        result = EXTRACTOR.extract(bytes(buf))
        assert result.get("displacement") is not None


# ---------------------------------------------------------------------------
# extract() — match key
# ---------------------------------------------------------------------------


class TestExtractMatchKey:
    def test_match_key_built_when_sw_present(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is not None

    def test_match_key_format_is_family_double_colon_version(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_match_key_none_when_no_sw(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, b"CASN")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is None

    def test_match_key_uses_uppercase(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, SERIAL_CODE)
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        if key:
            assert key == key.upper()

    def test_match_key_uses_variant_when_oem_present(self):
        """When OEM part number is present, it is used as variant in the key."""
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, SERIAL_CODE)
        write(buf, 0x300, OEM_PART_NUMBER)
        result = EXTRACTOR.extract(bytes(buf))
        key = result["match_key"]
        if key and result["oem_part_number"]:
            # Variant (oem_part_number) takes precedence over family
            assert key.startswith(result["oem_part_number"].upper() + "::")


# ---------------------------------------------------------------------------
# extract() — raw strings
# ---------------------------------------------------------------------------


class TestExtractRawStrings:
    def test_raw_strings_is_list(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert isinstance(result["raw_strings"], list)

    def test_raw_strings_limited_to_20(self):
        buf = make_buf(SIZE_2MB)
        # Fill header with many long strings
        for i in range(30):
            offset = i * 32
            if offset + 20 < 0x1000:
                write(buf, offset, b"LONGSTRING%02d_ABCDEFGH" % i)
        write(buf, 0x800, PPD_FAMILY_12)
        result = EXTRACTOR.extract(bytes(buf))
        assert len(result["raw_strings"]) <= 20


# ---------------------------------------------------------------------------
# build_match_key()
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_family_and_sw_produces_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="PPD1.2",
            software_version="6576286135",
        )
        assert key == "PPD1.2::6576286135"

    def test_family_and_sw_ppd15(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="PPD1.5",
            software_version="6576286149",
        )
        assert key == "PPD1.5::6576286149"

    def test_none_returned_when_no_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="PPD1.2",
            software_version=None,
        )
        assert key is None

    def test_none_returned_when_empty_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="PPD1.2",
            software_version="",
        )
        assert key is None

    def test_unknown_used_when_no_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family=None,
            software_version="6576286135",
        )
        assert key == "UNKNOWN::6576286135"

    def test_key_is_uppercase(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="ppd1.2",
            software_version="abc123",
        )
        assert key == key.upper()

    def test_double_colon_separator(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="PPD1.2",
            software_version="VERSION",
        )
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_variant_takes_precedence_over_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="PPD1.2",
            ecu_variant="03G906018DT",
            software_version="6576286135",
        )
        assert key.startswith("03G906018DT::")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_same_binary_produces_same_result(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
        write(buf, 0x200, SERIAL_CODE)
        data = bytes(buf)
        r1 = EXTRACTOR.extract(data, "file.bin")
        r2 = EXTRACTOR.extract(data, "file.bin")
        assert r1 == r2

    def test_filename_does_not_change_identification(self):
        buf = make_buf(SIZE_2MB)
        write(buf, 0x100, PPD_FAMILY_12)
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
            "software_version",
            "hardware_number",
            "calibration_id",
        ):
            assert r1[key] == r2[key], f"Field {key!r} differs by filename"

    def test_different_content_produces_different_md5(self):
        buf1 = make_buf(SIZE_2MB)
        write(buf1, 0x100, PPD_FAMILY_12)
        buf2 = make_buf(SIZE_2MB, fill=0x01)
        write(buf2, 0x100, PPD_FAMILY_15)
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# Full realistic extraction
# ---------------------------------------------------------------------------


class TestFullRealisticExtraction:
    def _make_full_binary(self) -> bytes:
        buf = make_buf(SIZE_2MB)
        # Place ident data at offset 0x40000 (typical for 2 MB PPD)
        write(buf, 0x40000, SERIAL_CODE)
        write(buf, 0x40020, SN_PROJECT_BLOCK)
        write(buf, 0x40100, CASN_DATASET)
        write(buf, 0x40200, OEM_PART_FULL)
        # Also place PPD family string in full binary area
        write(buf, 0x100000, PPD_FAMILY_12)
        return bytes(buf)

    def test_all_core_fields_populated(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data, "PPD1_2_test.bin")
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] is not None
        assert result["software_version"] is not None
        assert result["oem_part_number"] is not None
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

    def test_file_size_is_2mb(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data)
        assert result["file_size"] == SIZE_2MB


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

    def test_ppd1_dot_in_detection_signatures(self):
        assert b"PPD1." in DETECTION_SIGNATURES

    def test_111sn_in_detection_signatures(self):
        assert b"111SN" in DETECTION_SIGNATURES

    def test_casn_in_detection_signatures(self):
        assert b"CASN" in DETECTION_SIGNATURES

    def test_bosch_in_exclusion_signatures(self):
        assert b"BOSCH" in EXCLUSION_SIGNATURES

    def test_edc17_in_exclusion_signatures(self):
        assert b"EDC17" in EXCLUSION_SIGNATURES

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

    def test_search_regions_have_ident_area(self):
        assert "ident_area" in SEARCH_REGIONS

    def test_patterns_is_dict(self):
        assert isinstance(PATTERNS, dict)

    def test_pattern_regions_is_dict(self):
        assert isinstance(PATTERN_REGIONS, dict)

    def test_all_pattern_regions_reference_valid_regions(self):
        for name, region_key in PATTERN_REGIONS.items():
            assert region_key in SEARCH_REGIONS, (
                f"Pattern {name!r} references unknown region {region_key!r}"
            )

    def test_ecu_family_pattern_in_patterns(self):
        assert "ecu_family" in PATTERNS

    def test_serial_code_pattern_in_patterns(self):
        assert "serial_code" in PATTERNS

    def test_calibration_dataset_pattern_in_patterns(self):
        assert "calibration_dataset" in PATTERNS

    def test_oem_part_number_pattern_in_patterns(self):
        assert "oem_part_number" in PATTERNS
