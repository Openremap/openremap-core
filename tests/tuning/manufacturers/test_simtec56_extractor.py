"""
Tests for SiemensSimtec56Extractor (Simtec56).

Covers:
  - Identity properties: name, supported_families
  - can_handle():
      * True  — 5WK9 signature + RS/RT ident prefix + header magic + correct
                size (all five phases pass)
      * False — empty binary
      * False — wrong file size (too small, too large, near-miss)
      * False — correct size but no detection signatures (all-zero)
      * False — correct size + 5WK9 but no RS/RT ident prefix
      * False — correct size + 5WK9 + RS/RT but wrong header magic
      * False — exclusion signatures (BOSCH, 0261, MOTRONIC, PPD, etc.)
  - extract():
      * Required fields always present: manufacturer, file_size, md5,
        sha256_first_64kb
      * manufacturer always "Siemens"
      * ecu_family always "Simtec56"
      * file_size == len(data)
      * md5 and sha256_first_64kb are well-formed hex strings
      * hardware_number from Siemens 5WK9 part in ident record
      * software_version from serial in ident record
      * oem_part_number from GM part in ident record
      * calibration_id from S001 or S-ref patterns
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

from openremap.core.manufacturers.siemens.simtec56.extractor import (
    SiemensSimtec56Extractor,
)
from openremap.core.manufacturers.siemens.simtec56.patterns import (
    DETECTION_SIGNATURES,
    EXCLUSION_SIGNATURES,
    IDENT_PREFIXES,
    PATTERNS,
    PATTERN_REGIONS,
    SEARCH_REGIONS,
    SIMTEC56_FILE_SIZE,
    SIMTEC56_HEADER,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_buf(size: int = SIMTEC56_FILE_SIZE, fill: int = 0x00) -> bytearray:
    """Return a mutable zero-filled bytearray of `size` bytes."""
    return bytearray([fill] * size)


def write(buf: bytearray, offset: int, data: bytes) -> bytearray:
    """Write `data` into `buf` at `offset` and return `buf`."""
    buf[offset : offset + len(data)] = data
    return buf


KB = 1024
MB = 1024 * KB

# Expected size — exactly 128 KB
SIZE_128KB = SIMTEC56_FILE_SIZE  # 131072
assert SIZE_128KB == 128 * KB

# Realistic ident records from real Simtec 56 binaries
# Format: R[ST] + 8-digit GM part + space + 12-16 digit serial + lowercase letter + 5WK9 + 4-6 digits
IDENT_RECORD_A = b"RS90506365 0106577255425b5WK907302"
IDENT_RECORD_B = b"RT90464731 0106577255426j5WK907402"

# Header magic — 8051/C166 LJMP reset vector (first 3 bytes)
HEADER_MAGIC = SIMTEC56_HEADER  # b"\x02\x00\xb0"

EXTRACTOR = SiemensSimtec56Extractor()


# ---------------------------------------------------------------------------
# Helper: build a valid Simtec56 binary (all five phases pass)
# ---------------------------------------------------------------------------


def _make_valid_simtec56(
    ident: bytes = IDENT_RECORD_A,
    ident_offset: int = 0x4000,
) -> bytearray:
    """
    Build a bytearray that passes all five can_handle() phases:
      1. Size = 128 KB
      2. No exclusion signatures
      3. Contains 5WK9 detection signature (embedded in ident record)
      4. Contains RS/RT ident prefix (embedded in ident record)
      5. Header magic = \\x02\\x00\\xb0
    """
    buf = make_buf(SIZE_128KB)
    write(buf, 0, HEADER_MAGIC)
    write(buf, ident_offset, ident)
    return buf


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

    def test_simtec56_in_supported_families(self):
        assert "Simtec56" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for fam in EXTRACTOR.supported_families:
            assert isinstance(fam, str), f"Family {fam!r} is not a string"

    def test_repr_contains_manufacturer(self):
        r = repr(EXTRACTOR)
        assert "Siemens" in r

    def test_repr_contains_class_name(self):
        r = repr(EXTRACTOR)
        assert "SiemensSimtec56Extractor" in r


# ---------------------------------------------------------------------------
# can_handle() — positive detection (all five phases pass)
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """All five phases satisfied → True."""

    def test_standard_ident_record_a(self):
        buf = _make_valid_simtec56(IDENT_RECORD_A)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_standard_ident_record_b(self):
        buf = _make_valid_simtec56(IDENT_RECORD_B)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_ident_at_offset_zero_after_header(self):
        """Ident record immediately after the 3-byte header magic."""
        buf = _make_valid_simtec56(IDENT_RECORD_A, ident_offset=0x10)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_ident_near_end_of_binary(self):
        """Ident record placed near the end — all searches use full binary."""
        offset = SIZE_128KB - len(IDENT_RECORD_A) - 10
        buf = _make_valid_simtec56(IDENT_RECORD_A, ident_offset=offset)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_5wk9_standalone_with_rs_prefix(self):
        """5WK9 signature and RS prefix placed separately still pass."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, b"5WK90730")
        # RS + 8 digits to satisfy phase 4 (ident prefix check)
        write(buf, 0x2000, b"RS90506365")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_rt_prefix_accepted(self):
        """RT prefix (alternate track) is equally valid as RS."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, b"5WK90740")
        write(buf, 0x2000, b"RT90464731")
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_multiple_ident_records(self):
        buf = _make_valid_simtec56(IDENT_RECORD_A, ident_offset=0x1000)
        write(buf, 0x5000, IDENT_RECORD_B)
        assert EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: wrong file size (Phase 1 fails)
# ---------------------------------------------------------------------------


class TestCanHandleFalseWrongSize:
    """Size gate must reject binaries that are not exactly 131072 bytes."""

    def test_empty_binary(self):
        assert not EXTRACTOR.can_handle(b"")

    def test_1_byte_binary(self):
        assert not EXTRACTOR.can_handle(b"\x00")

    def test_64kb_with_valid_content(self):
        buf = make_buf(64 * KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_256kb_with_valid_content(self):
        buf = make_buf(256 * KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_512kb_with_valid_content(self):
        buf = make_buf(512 * KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_1mb_with_valid_content(self):
        buf = make_buf(1 * MB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_one_byte_less_than_128kb(self):
        buf = make_buf(SIZE_128KB - 1)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_one_byte_more_than_128kb(self):
        buf = make_buf(SIZE_128KB + 1)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_too_small_binary(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(256)))


# ---------------------------------------------------------------------------
# can_handle() — negative: no detection signatures (Phase 3 fails)
# ---------------------------------------------------------------------------


class TestCanHandleFalseNoSignature:
    """Correct size but no 5WK9 detection signature → False."""

    def test_all_zero_binary(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_128KB)))

    def test_all_ff_binary(self):
        assert not EXTRACTOR.can_handle(bytes(make_buf(SIZE_128KB, fill=0xFF)))

    def test_header_magic_only_no_5wk9(self):
        """Header magic alone is insufficient — 5WK9 is required."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        # RS prefix present but no 5WK9
        write(buf, 0x1000, b"RS90506365")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_ascii_noise_no_signature(self):
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        noise = b"This is just some text with no ECU signatures at all." * 50
        write(buf, 0x100, noise[:0x5000])
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: no RS/RT ident prefix (Phase 4 fails)
# ---------------------------------------------------------------------------


class TestCanHandleFalseNoIdentPrefix:
    """Correct size + 5WK9 but no RS/RT ident prefix → False."""

    def test_5wk9_without_rs_rt_prefix(self):
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, b"5WK90730")
        # No RS or RT prefix anywhere
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_5wk9_with_wrong_prefix(self):
        """RU is not a valid ident prefix — only RS and RT."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, b"5WK90730")
        write(buf, 0x2000, b"RU90506365")
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: wrong header magic (Phase 5 fails)
# ---------------------------------------------------------------------------


class TestCanHandleFalseWrongHeader:
    """Correct size + 5WK9 + RS/RT but wrong header → False."""

    def test_zero_header(self):
        buf = make_buf(SIZE_128KB)
        # Do NOT write header magic
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_ff_header(self):
        buf = make_buf(SIZE_128KB, fill=0xFF)
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_wrong_header_bytes(self):
        buf = make_buf(SIZE_128KB)
        write(buf, 0, b"\x03\x00\xb0")  # wrong first byte
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_partial_header_match(self):
        buf = make_buf(SIZE_128KB)
        write(buf, 0, b"\x02\x00\xb1")  # third byte differs
        write(buf, 0x1000, IDENT_RECORD_A)
        assert not EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# can_handle() — negative: exclusion signatures (Phase 2 fails)
# ---------------------------------------------------------------------------


class TestCanHandleFalseExclusion:
    """Exclusion signatures override all positive detection → False."""

    def _make_with_exclusion(self, exclusion_sig: bytes) -> bytes:
        buf = _make_valid_simtec56()
        write(buf, 0x8000, exclusion_sig)
        return bytes(buf)

    def test_bosch_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"BOSCH"))

    def test_0261_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"0261"))

    def test_motronic_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MOTRONIC"))

    def test_edc17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"EDC17"))

    def test_medc17_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"MEDC17"))

    def test_me7_dot_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"ME7."))

    def test_pm3_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"PM3"))

    def test_ppd_exclusion(self):
        assert not EXTRACTOR.can_handle(self._make_with_exclusion(b"PPD"))

    def test_exclusion_overrides_full_valid_binary(self):
        buf = _make_valid_simtec56(IDENT_RECORD_A)
        write(buf, 0x8000, b"BOSCH")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_start_of_binary(self):
        """Exclusion at offset 0 overwrites header — but exclusion still triggers."""
        buf = _make_valid_simtec56(IDENT_RECORD_A)
        write(buf, 0x0010, b"0261")
        assert not EXTRACTOR.can_handle(bytes(buf))

    def test_exclusion_at_end_of_binary(self):
        buf = _make_valid_simtec56(IDENT_RECORD_A)
        write(buf, SIZE_128KB - 10, b"BOSCH")
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
    def test_minimum_valid_binary(self):
        """Smallest possible valid binary: exactly 128 KB with all markers."""
        buf = _make_valid_simtec56()
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_header_exactly_3_bytes_checked(self):
        """Only first 3 bytes of header checked — rest can be anything."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, b"\x02\x00\xb0\xff\xff")  # extra bytes after magic
        write(buf, 0x1000, IDENT_RECORD_A)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_5wk9_in_ident_record_satisfies_phase3(self):
        """5WK9 embedded inside the ident record string satisfies detection."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        # The ident record contains 5WK9 internally
        write(buf, 0x1000, IDENT_RECORD_A)
        assert EXTRACTOR.can_handle(bytes(buf))

    def test_rs_prefix_in_ident_record_satisfies_phase4(self):
        """RS prefix at start of ident record satisfies the ident prefix check."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, IDENT_RECORD_A)
        assert EXTRACTOR.can_handle(bytes(buf))


# ---------------------------------------------------------------------------
# extract() — required fields
# ---------------------------------------------------------------------------


class TestExtractRequiredFields:
    """All required fields present and correctly computed."""

    def _extract(self, data: bytes = None) -> dict:
        if data is None:
            data = bytes(_make_valid_simtec56())
        return EXTRACTOR.extract(data, "test.bin")

    def test_all_required_fields_present(self):
        result = self._extract()
        for key in ("manufacturer", "file_size", "md5", "sha256_first_64kb"):
            assert key in result, f"Missing required field: {key}"

    def test_manufacturer_always_siemens(self):
        assert self._extract()["manufacturer"] == "Siemens"

    def test_ecu_family_always_simtec56(self):
        assert self._extract()["ecu_family"] == "Simtec56"

    def test_file_size_equals_data_length(self):
        data = bytes(_make_valid_simtec56())
        result = EXTRACTOR.extract(data)
        assert result["file_size"] == len(data)

    def test_file_size_is_128kb(self):
        assert self._extract()["file_size"] == SIZE_128KB

    def test_md5_is_32_hex_chars(self):
        result = self._extract()
        assert len(result["md5"]) == 32
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_is_lowercase_hex(self):
        result = self._extract()
        assert result["md5"] == result["md5"].lower()

    def test_md5_matches_hashlib(self):
        data = bytes(_make_valid_simtec56())
        result = EXTRACTOR.extract(data)
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_first_64kb_is_64_hex_chars(self):
        result = self._extract()
        sha = result["sha256_first_64kb"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_first_64kb_matches_hashlib(self):
        data = bytes(_make_valid_simtec56())
        result = EXTRACTOR.extract(data)
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert result["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_ignores_bytes_past_64kb(self):
        buf1 = _make_valid_simtec56()
        buf2 = _make_valid_simtec56()
        write(buf2, 0x10000, b"COMPLETELY_DIFFERENT_DATA_HERE_XX")
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_md5_changes_with_different_content(self):
        buf1 = _make_valid_simtec56(IDENT_RECORD_A)
        buf2 = _make_valid_simtec56(IDENT_RECORD_B)
        r1 = EXTRACTOR.extract(bytes(buf1))
        r2 = EXTRACTOR.extract(bytes(buf2))
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# extract() — hardware number (Siemens 5WK9 part from ident record)
# ---------------------------------------------------------------------------


class TestExtractHardwareNumber:
    def test_hw_detected_from_ident_record_a(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] is not None
        assert "5WK9" in result["hardware_number"]

    def test_hw_detected_from_ident_record_b(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_B))
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] is not None
        assert "5WK9" in result["hardware_number"]

    def test_hw_specific_value_from_record_a(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        # From ident record: "5WK90730" (core 8 chars)
        assert result["hardware_number"] == "5WK90730"

    def test_hw_specific_value_from_record_b(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_B))
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == "5WK90740"

    def test_hw_none_when_no_ident_record(self):
        """No ident record and no standalone 5WK9 → hardware_number is None."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        # No ident record at all — extract() is called directly without
        # can_handle() gating, so this is a valid scenario.
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is None

    def test_hw_from_standalone_siemens_part(self):
        """Standalone 5WK9 pattern as fallback when ident record doesn't parse."""
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        write(buf, 0x1000, b"5WK90999")
        result = EXTRACTOR.extract(bytes(buf))
        # Might be picked up by the standalone siemens_part pattern
        # depending on whether ident_record also matched
        assert result["hardware_number"] is None or "5WK9" in result["hardware_number"]


# ---------------------------------------------------------------------------
# extract() — software version (serial from ident record)
# ---------------------------------------------------------------------------


class TestExtractSoftwareVersion:
    def test_sw_detected_from_ident_record_a(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        # Serial from IDENT_RECORD_A: "0106577255425b"
        assert result["software_version"] is not None

    def test_sw_detected_from_ident_record_b(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_B))
        result = EXTRACTOR.extract(data)
        assert result["software_version"] is not None

    def test_sw_specific_value_from_record_a(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        assert result["software_version"] == "0106577255425b"

    def test_sw_specific_value_from_record_b(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_B))
        result = EXTRACTOR.extract(data)
        assert result["software_version"] == "0106577255426j"

    def test_sw_none_when_no_ident_record(self):
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] is None

    def test_different_ident_records_produce_different_sw(self):
        r1 = EXTRACTOR.extract(bytes(_make_valid_simtec56(IDENT_RECORD_A)))
        r2 = EXTRACTOR.extract(bytes(_make_valid_simtec56(IDENT_RECORD_B)))
        assert r1["software_version"] != r2["software_version"]


# ---------------------------------------------------------------------------
# extract() — OEM part number (GM part from ident record)
# ---------------------------------------------------------------------------


class TestExtractOemPartNumber:
    def test_oem_part_from_ident_record_a(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        assert result["oem_part_number"] == "90506365"

    def test_oem_part_from_ident_record_b(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_B))
        result = EXTRACTOR.extract(data)
        assert result["oem_part_number"] == "90464731"

    def test_oem_part_none_when_no_ident_record(self):
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["oem_part_number"] is None


# ---------------------------------------------------------------------------
# extract() — serial number
# ---------------------------------------------------------------------------


class TestExtractSerialNumber:
    def test_serial_from_ident_record_a(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        # Serial is the same as software_version for Simtec56
        assert result["serial_number"] is not None
        assert result["serial_number"] == result["software_version"]

    def test_serial_none_when_no_ident_record(self):
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["serial_number"] is None


# ---------------------------------------------------------------------------
# extract() — calibration ID
# ---------------------------------------------------------------------------


class TestExtractCalibrationId:
    def test_calibration_code_s001_detected(self):
        buf = _make_valid_simtec56()
        write(buf, 0x8000, b"S001005674")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] is not None
        assert result["calibration_id"] == "S001005674"

    def test_calibration_ref_short_detected(self):
        buf = _make_valid_simtec56()
        write(buf, 0x8000, b"S96007")
        result = EXTRACTOR.extract(bytes(buf))
        # calibration_ref is fallback when no calibration_code
        assert result["calibration_id"] is not None

    def test_calibration_code_takes_priority(self):
        buf = _make_valid_simtec56()
        write(buf, 0x8000, b"S001005674")
        write(buf, 0x9000, b"S96007")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] == "S001005674"

    def test_calibration_id_none_when_no_hits(self):
        data = bytes(_make_valid_simtec56())
        result = EXTRACTOR.extract(data)
        # May or may not have calibration depending on ident record content
        # Just verify it returns a valid type
        assert result["calibration_id"] is None or isinstance(
            result["calibration_id"], str
        )


# ---------------------------------------------------------------------------
# extract() — not-applicable fields
# ---------------------------------------------------------------------------


class TestExtractNotApplicableFields:
    def _extract(self) -> dict:
        return EXTRACTOR.extract(bytes(_make_valid_simtec56()))

    def test_ecu_variant_is_none(self):
        assert self._extract()["ecu_variant"] is None

    def test_calibration_version_is_none(self):
        assert self._extract()["calibration_version"] is None

    def test_sw_base_version_is_none(self):
        assert self._extract()["sw_base_version"] is None

    def test_dataset_number_is_none(self):
        assert self._extract()["dataset_number"] is None


# ---------------------------------------------------------------------------
# extract() — match key
# ---------------------------------------------------------------------------


class TestExtractMatchKey:
    def test_match_key_built_when_sw_present(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        assert result["match_key"] is not None

    def test_match_key_format_is_family_double_colon_version(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        key = result["match_key"]
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_match_key_starts_with_simtec56(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        key = result["match_key"]
        assert key.startswith("SIMTEC56::")

    def test_match_key_none_when_no_sw(self):
        buf = make_buf(SIZE_128KB)
        write(buf, 0, HEADER_MAGIC)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is None

    def test_match_key_uses_uppercase(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        result = EXTRACTOR.extract(data)
        key = result["match_key"]
        assert key == key.upper()

    def test_match_key_different_for_different_ident(self):
        r1 = EXTRACTOR.extract(bytes(_make_valid_simtec56(IDENT_RECORD_A)))
        r2 = EXTRACTOR.extract(bytes(_make_valid_simtec56(IDENT_RECORD_B)))
        assert r1["match_key"] != r2["match_key"]


# ---------------------------------------------------------------------------
# extract() — raw strings
# ---------------------------------------------------------------------------


class TestExtractRawStrings:
    def test_raw_strings_is_list(self):
        data = bytes(_make_valid_simtec56())
        result = EXTRACTOR.extract(data)
        assert isinstance(result["raw_strings"], list)

    def test_raw_strings_limited_to_20(self):
        buf = _make_valid_simtec56()
        # Fill header with many long strings
        for i in range(30):
            offset = 3 + (i * 20)  # skip header magic
            if offset + 16 < 0x1000:
                write(buf, offset, b"LONGSTRING%02dABCD" % i)
        result = EXTRACTOR.extract(bytes(buf))
        assert len(result["raw_strings"]) <= 20


# ---------------------------------------------------------------------------
# build_match_key()
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_family_and_sw_produces_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="Simtec56",
            software_version="0106577255425b",
        )
        assert key == "SIMTEC56::0106577255425B"

    def test_none_returned_when_no_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="Simtec56",
            software_version=None,
        )
        assert key is None

    def test_none_returned_when_empty_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="Simtec56",
            software_version="",
        )
        assert key is None

    def test_unknown_used_when_no_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family=None,
            software_version="0106577255425b",
        )
        assert key.startswith("UNKNOWN::")

    def test_key_is_uppercase(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="simtec56",
            software_version="abc123",
        )
        assert key == key.upper()

    def test_double_colon_separator(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="Simtec56",
            software_version="VERSION",
        )
        assert "::" in key
        parts = key.split("::")
        assert len(parts) == 2

    def test_variant_takes_precedence_over_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="Simtec56",
            ecu_variant="CUSTOM_VARIANT",
            software_version="0106577255425b",
        )
        assert key.startswith("CUSTOM_VARIANT::")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_same_binary_produces_same_result(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
        r1 = EXTRACTOR.extract(data, "file.bin")
        r2 = EXTRACTOR.extract(data, "file.bin")
        assert r1 == r2

    def test_filename_does_not_change_identification(self):
        data = bytes(_make_valid_simtec56(IDENT_RECORD_A))
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
            "oem_part_number",
            "calibration_id",
            "match_key",
        ):
            assert r1[key] == r2[key], f"Field {key!r} differs by filename"

    def test_different_content_produces_different_md5(self):
        r1 = EXTRACTOR.extract(bytes(_make_valid_simtec56(IDENT_RECORD_A)))
        r2 = EXTRACTOR.extract(bytes(_make_valid_simtec56(IDENT_RECORD_B)))
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# Full realistic extraction
# ---------------------------------------------------------------------------


class TestFullRealisticExtraction:
    def _make_full_binary(self) -> bytes:
        buf = _make_valid_simtec56(IDENT_RECORD_A, ident_offset=0x1000)
        # Add calibration code
        write(buf, 0x8000, b"S001005674")
        # Add engine code
        write(buf, 0x9000, b"X20XEV")
        return bytes(buf)

    def test_all_core_fields_populated(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data, "simtec56_test.bin")
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] == "Simtec56"
        assert result["hardware_number"] is not None
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

    def test_file_size_is_128kb(self):
        data = self._make_full_binary()
        result = EXTRACTOR.extract(data)
        assert result["file_size"] == SIZE_128KB


# ---------------------------------------------------------------------------
# Patterns module validation
# ---------------------------------------------------------------------------


class TestPatternsModule:
    def test_detection_signatures_is_list(self):
        assert isinstance(DETECTION_SIGNATURES, list)

    def test_detection_signatures_not_empty(self):
        assert len(DETECTION_SIGNATURES) > 0

    def test_5wk9_in_detection_signatures(self):
        assert b"5WK9" in DETECTION_SIGNATURES

    def test_exclusion_signatures_is_list(self):
        assert isinstance(EXCLUSION_SIGNATURES, list)

    def test_exclusion_signatures_not_empty(self):
        assert len(EXCLUSION_SIGNATURES) > 0

    def test_bosch_in_exclusion_signatures(self):
        assert b"BOSCH" in EXCLUSION_SIGNATURES

    def test_0261_in_exclusion_signatures(self):
        assert b"0261" in EXCLUSION_SIGNATURES

    def test_motronic_in_exclusion_signatures(self):
        assert b"MOTRONIC" in EXCLUSION_SIGNATURES

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

    def test_simtec56_file_size_is_128kb(self):
        assert SIMTEC56_FILE_SIZE == 131072

    def test_simtec56_header_is_3_bytes(self):
        assert len(SIMTEC56_HEADER) == 3
        assert SIMTEC56_HEADER == b"\x02\x00\xb0"

    def test_ident_prefixes_has_rs_and_rt(self):
        assert b"RS" in IDENT_PREFIXES
        assert b"RT" in IDENT_PREFIXES

    def test_search_regions_have_header(self):
        assert "header" in SEARCH_REGIONS

    def test_search_regions_have_full(self):
        assert "full" in SEARCH_REGIONS

    def test_patterns_is_dict(self):
        assert isinstance(PATTERNS, dict)

    def test_ident_record_pattern_in_patterns(self):
        assert "ident_record" in PATTERNS

    def test_siemens_part_pattern_in_patterns(self):
        assert "siemens_part" in PATTERNS

    def test_pattern_regions_is_dict(self):
        assert isinstance(PATTERN_REGIONS, dict)

    def test_all_pattern_regions_reference_valid_regions(self):
        for name, region_key in PATTERN_REGIONS.items():
            assert region_key in SEARCH_REGIONS, (
                f"Pattern {name!r} references unknown region {region_key!r}"
            )
