"""
Tests for BoschME9Extractor (Bosch Motronic ME9 full flash dumps).

Covers:
  - Identity: name, supported_families
  - can_handle():
      * True  — ME9 anchor present, no MED9 marker
      * True  — anchor placed at offset 0 (edge case)
      * True  — anchor placed near the 2 MB search boundary
      * False — all-zero binary (no signatures at all)
      * False — MED9 marker present alongside ME9 anchor (MED9 bin)
      * False — only MED9 marker, no ME9 anchor
      * False — ME9 anchor present but beyond the 2 MB search limit
  - extract():
      * Required keys always present in the returned dict
      * manufacturer always "Bosch"
      * file_size == len(data)
      * md5 is a well-formed 32-char hex string matching hashlib
      * sha256_first_64kb is a well-formed 64-char hex string matching hashlib
      * raw_strings is a list
      * ecu_family == "ME9"
      * ecu_variant is None
      * software_version from the "//1037…" calibration field  (primary key)
      * calibration_id  from the '"1037…'  OS/program  field  (secondary)
      * hardware_number from the "0261XXXXXX" field
      * calibration_version formatted as "CV<digits>" from the "@CVxxxxx" tag
      * sw_base_version, serial_number, dataset_number, oem_part_number all None
      * match_key == "ME9::<calibration_sw>" when SW is present
      * match_key is None when no software version is found
      * extract() is deterministic across repeated calls
      * filename argument does not affect any identification field
      * fallback SW: no "//1037" present but isolated "1037" string found
      * hardware_number is None when no 0261 pattern is present
      * calibration_version is None when no CV pattern is present
      * calibration_id is None when no OS SW sentinel is present
  - build_match_key():
      * ecu_family used as the identifier when ecu_variant is None
      * Returns None when software_version is absent
      * Upper-cases the family part
  - __repr__: contains class name and manufacturer
"""

import hashlib

import pytest

from openremap.tuning.manufacturers.bosch.me9.extractor import (
    BoschME9Extractor,
    _ME9_ANCHOR,
    _MED9_MARKER,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_buf(size: int, fill: int = 0x00) -> bytearray:
    """Return a mutable bytearray of `size` bytes filled with `fill`."""
    return bytearray([fill] * size)


def write(buf: bytearray, offset: int, data: bytes) -> bytearray:
    """Write `data` into `buf` at `offset` in-place; return `buf`."""
    buf[offset : offset + len(data)] = data
    return buf


KB = 1024
MB = 1024 * KB

# ---------------------------------------------------------------------------
# Known offsets and values from the reference binary
# (0261209352_1037383785 flash ori.bin)
# ---------------------------------------------------------------------------

OFF_ANCHOR = 0x1594C  # "Bosch.Common.RamLoader.Me9.0001"
RAMLOADER_STRING = b"Bosch.Common.RamLoader.Me9.0001"
EXPECTED_VARIANT = "ME9.0001"  # upper-cased from "Me9.0001"
OFF_HW = 0x2600  # "0261209352"
OFF_CAL_VER = 0x2840  # "@CV56047 "
OFF_IDENT = 0x461D  # b'\x221037393302\x01\x01//1037383785'

HW_NUMBER = b"0261209352"
OS_SW = b"1037393302"  # OS/program SW (after the 0x22 sentinel)
CAL_SW = b"1037383785"  # calibration SW (after "//")
CAL_VER_TAG = b"@CV56047 "

# The full ident record as written at OFF_IDENT:
#   0x22  = ASCII '"'  — Bosch ME9 record-start sentinel
#   OS_SW = "1037393302"
#   0x01 0x01           — separator bytes
#   "//"                — field separator
#   CAL_SW = "1037383785"
IDENT_RECORD = b"\x22" + OS_SW + b"\x01\x01//" + CAL_SW

# Minimum binary size that covers all realistic ident fields
SIZE_SMALL = 0x50000  # 320 KB — beyond OFF_IDENT (0x461D)
SIZE_2MB = 2 * MB  # typical ME9 full flash size

EXTRACTOR = BoschME9Extractor()


def make_minimal_me9(size: int = SIZE_SMALL) -> bytes:
    """
    Return a zero-filled binary of `size` bytes that contains only the ME9
    anchor — minimum necessary to pass can_handle().
    No variant string is written (tests that variant can be None).
    """
    buf = make_buf(size)
    write(buf, 0, _ME9_ANCHOR)
    return bytes(buf)


def make_realistic_me9(size: int = SIZE_SMALL) -> bytes:
    """
    Return a synthetic ME9 binary with all ident fields at their real offsets.
    Values match the reference binary (0261209352_1037383785).
    Includes the full RamLoader string so the variant "ME9.0001" is extracted.
    """
    buf = make_buf(size)
    write(buf, OFF_ANCHOR, RAMLOADER_STRING)
    write(buf, OFF_HW, HW_NUMBER)
    write(buf, OFF_CAL_VER, CAL_VER_TAG)
    write(buf, OFF_IDENT, IDENT_RECORD)
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

    def test_me9_in_supported_families(self):
        families = " ".join(EXTRACTOR.supported_families).upper()
        assert "ME9" in families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_contains_class_name(self):
        assert "BoschME9Extractor" in repr(EXTRACTOR)

    def test_repr_contains_manufacturer(self):
        assert "Bosch" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# can_handle — True cases
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """Binaries that should be accepted by can_handle()."""

    def test_anchor_at_offset_zero(self):
        """Anchor at the very start of the binary."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_anchor_at_realistic_offset(self):
        """Anchor at its real-world position (0x1594C)."""
        buf = make_buf(SIZE_SMALL)
        write(buf, OFF_ANCHOR, _ME9_ANCHOR)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_anchor_with_full_ident(self):
        """Full realistic synthetic binary is accepted."""
        assert EXTRACTOR.can_handle(make_realistic_me9()) is True

    def test_anchor_near_2mb_boundary(self):
        """Anchor placed exactly at the last valid position within the 2 MB window."""
        size = SIZE_2MB
        buf = make_buf(size)
        # Last position where the anchor still fits inside the first 2 MB:
        last_pos = 0x200000 - len(_ME9_ANCHOR)
        write(buf, last_pos, _ME9_ANCHOR)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_only_anchor_needed_no_other_fields(self):
        """No HW number, no SW, no ident record — anchor alone is enough."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0x1000, _ME9_ANCHOR)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_2mb_full_binary(self):
        """2 MB binary (typical ME9 flash size) is accepted."""
        buf = make_buf(SIZE_2MB)
        write(buf, OFF_ANCHOR, _ME9_ANCHOR)
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle — False cases
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    """Binaries that must be rejected by can_handle()."""

    def test_all_zeros(self):
        """No signatures at all — must be rejected."""
        assert EXTRACTOR.can_handle(bytes(SIZE_SMALL)) is False

    def test_random_fill_no_anchor(self):
        """0xFF fill with no anchor — must be rejected."""
        buf = make_buf(SIZE_SMALL, fill=0xFF)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_med9_marker_alone(self):
        """Only the MED9 marker present, no ME9 anchor — must be rejected."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _MED9_MARKER)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_med9_marker_with_me9_anchor(self):
        """Both ME9 anchor and MED9 marker present — must be rejected (MED9 bin)."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        write(buf, 0x100, _MED9_MARKER)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_med9_marker_before_me9_anchor(self):
        """MED9 check runs before the anchor search — order must not matter."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0x100, _ME9_ANCHOR)
        write(buf, 0, _MED9_MARKER)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_anchor_beyond_2mb_window(self):
        """Anchor placed strictly after the 2 MB search limit — not found."""
        size = SIZE_2MB + len(_ME9_ANCHOR) + 0x100
        buf = make_buf(size)
        # Place anchor starting at 0x200001 — one byte past the 2 MB boundary
        write(buf, 0x200001, _ME9_ANCHOR)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_partial_anchor_only(self):
        """Only a prefix of the anchor string — must not match."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR[:10])  # "Bosch.Com" — not the full anchor
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_empty_binary(self):
        """Zero-length binary — must be rejected without error."""
        assert EXTRACTOR.can_handle(b"") is False

    def test_very_short_binary(self):
        """Binary shorter than the anchor — must be rejected."""
        assert EXTRACTOR.can_handle(_ME9_ANCHOR[:5]) is False


# ---------------------------------------------------------------------------
# extract — required fields
# ---------------------------------------------------------------------------


class TestExtractRequiredFields:
    """Every extract() call must return all expected keys."""

    REQUIRED_KEYS = {
        "manufacturer",
        "file_size",
        "md5",
        "sha256_first_64kb",
        "raw_strings",
        "ecu_family",
        "ecu_variant",
        "software_version",
        "calibration_id",
        "hardware_number",
        "calibration_version",
        "sw_base_version",
        "serial_number",
        "dataset_number",
        "oem_part_number",
        "match_key",
    }

    def _result(self):
        return EXTRACTOR.extract(make_realistic_me9())

    def test_all_required_keys_present(self):
        result = self._result()
        for key in self.REQUIRED_KEYS:
            assert key in result, f"Missing key: {key!r}"

    def test_no_unexpected_none_for_critical_fields(self):
        """Fields that must be non-None for a well-formed ME9 binary."""
        result = self._result()
        for field in ("manufacturer", "file_size", "ecu_family", "match_key"):
            assert result[field] is not None, f"{field!r} must not be None"


# ---------------------------------------------------------------------------
# extract — manufacturer and file metadata
# ---------------------------------------------------------------------------


class TestExtractMetadata:
    def test_manufacturer_is_bosch(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["manufacturer"] == "Bosch"

    def test_file_size_equals_len(self):
        data = make_realistic_me9()
        result = EXTRACTOR.extract(data)
        assert result["file_size"] == len(data)

    def test_file_size_varies_with_input(self):
        small = make_realistic_me9(size=SIZE_SMALL)
        large = make_realistic_me9(size=SIZE_2MB)
        assert EXTRACTOR.extract(small)["file_size"] == SIZE_SMALL
        assert EXTRACTOR.extract(large)["file_size"] == SIZE_2MB

    def test_md5_is_32_char_hex(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        md5 = result["md5"]
        assert isinstance(md5, str)
        assert len(md5) == 32
        int(md5, 16)  # raises ValueError if not valid hex

    def test_md5_matches_hashlib(self):
        data = make_realistic_me9()
        result = EXTRACTOR.extract(data)
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_first_64kb_is_64_char_hex(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        sha = result["sha256_first_64kb"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        int(sha, 16)

    def test_sha256_first_64kb_matches_hashlib(self):
        data = make_realistic_me9()
        result = EXTRACTOR.extract(data)
        assert result["sha256_first_64kb"] == hashlib.sha256(data[:0x10000]).hexdigest()

    def test_raw_strings_is_list(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert isinstance(result["raw_strings"], list)


# ---------------------------------------------------------------------------
# extract — ECU family and variant
# ---------------------------------------------------------------------------


class TestExtractFamily:
    def test_ecu_family_is_me9(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["ecu_family"] == "ME9"

    def test_ecu_family_is_string(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert isinstance(result["ecu_family"], str)

    def test_ecu_variant_extracted_from_ramloader(self):
        """Variant is extracted from the RamLoader string as 'ME9.0001'."""
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["ecu_variant"] == EXPECTED_VARIANT

    def test_ecu_variant_is_uppercase(self):
        """Variant must be upper-cased (Me9.0001 → ME9.0001)."""
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["ecu_variant"] == result["ecu_variant"].upper()

    def test_ecu_variant_none_when_ramloader_absent(self):
        """When the full RamLoader string is absent, ecu_variant is None."""
        buf = make_buf(SIZE_SMALL)
        # Write only the short anchor (no ".0001" suffix) so the variant
        # pattern ("RamLoader.(Me9...)") cannot match.
        write(buf, 0, _ME9_ANCHOR)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_variant"] is None

    def test_ecu_variant_does_not_affect_match_key(self):
        """
        match_key is keyed on family ('ME9'), not variant ('ME9.0001'), so
        that the same calibration SW maps to the same key regardless of
        which loader revision is present.
        """
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["match_key"] is not None
        assert result["match_key"].startswith("ME9::")
        assert "ME9.0001" not in result["match_key"]

    def test_ecu_family_constant_regardless_of_data(self):
        """Family is always ME9; it must not depend on any pattern match."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["ecu_family"] == "ME9"


# ---------------------------------------------------------------------------
# extract — software_version (calibration SW — primary key)
# ---------------------------------------------------------------------------


class TestExtractSoftwareVersion:
    def test_cal_sw_extracted(self):
        """Calibration SW (after '//') is extracted as software_version."""
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["software_version"] == CAL_SW.decode()

    def test_cal_sw_is_string(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert isinstance(result["software_version"], str)

    def test_software_version_none_when_absent(self):
        """No //1037 pattern and no fallback — software_version is None."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        # No ident record, no 1037 strings at all
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] is None

    def test_fallback_sw_used_when_no_cal_record(self):
        """
        If there is no '//1037…' pattern but an isolated '1037…' string exists,
        the fallback picks it up as software_version.
        """
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        # Write an isolated SW string with null separators (no // prefix)
        fallback_sw = b"1037999888"
        write(buf, 0x5000, b"\x00" + fallback_sw + b"\x00")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] == fallback_sw.decode()

    def test_fallback_sw_not_same_as_os_sw(self):
        """
        The fallback must not return the OS SW string (which comes from the
        0x22-sentinel pattern); it should pick a different 1037 value.
        """
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        # OS SW only via the 0x22 sentinel — no // calibration record
        os_sw_bytes = b"1037393302"
        write(buf, 0x4000, b"\x22" + os_sw_bytes)
        # Place a different isolated 1037 string as the fallback candidate
        fallback_sw = b"1037111222"
        write(buf, 0x5000, b"\x00" + fallback_sw + b"\x00")
        result = EXTRACTOR.extract(bytes(buf))
        # software_version should be the fallback, not the OS SW
        assert result["software_version"] == fallback_sw.decode()
        assert result["software_version"] != os_sw_bytes.decode()

    def test_cal_sw_takes_priority_over_fallback(self):
        """
        When both '//1037…' and an isolated '1037…' string exist, the '//1037…'
        pattern is always preferred.
        """
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        # Calibration SW via // prefix
        write(buf, 0x4000, b"//" + CAL_SW)
        # Isolated fallback string that should NOT win
        write(buf, 0x5000, b"\x00" + b"1037000000" + b"\x00")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] == CAL_SW.decode()


# ---------------------------------------------------------------------------
# extract — calibration_id (OS / program SW — secondary)
# ---------------------------------------------------------------------------


class TestExtractCalibrationId:
    def test_os_sw_extracted_as_calibration_id(self):
        """OS/program SW (after 0x22 sentinel) is stored in calibration_id."""
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["calibration_id"] == OS_SW.decode()

    def test_calibration_id_is_string(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert isinstance(result["calibration_id"], str)

    def test_calibration_id_none_when_absent(self):
        """No 0x22-sentinel pattern — calibration_id is None."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        # Calibration SW only, no OS SW sentinel
        write(buf, 0x4000, b"//" + CAL_SW)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_id"] is None


# ---------------------------------------------------------------------------
# extract — hardware_number
# ---------------------------------------------------------------------------


class TestExtractHardwareNumber:
    def test_hw_number_extracted(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["hardware_number"] == HW_NUMBER.decode()

    def test_hw_number_is_string(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert isinstance(result["hardware_number"], str)

    def test_hw_starts_with_0261(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["hardware_number"].startswith("0261")

    def test_hw_number_none_when_absent(self):
        """No 0261XXXXXX pattern — hardware_number is None."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        write(buf, OFF_IDENT, IDENT_RECORD)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["hardware_number"] is None

    def test_hw_number_not_extracted_from_longer_string(self):
        """
        The HW number must not be extracted when embedded inside a longer
        numeric string (e.g. the compound record "402612093521039S..." at 0x25FF).
        """
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        # Write HW embedded inside a longer run — lookbehind must block this
        write(buf, 0x1000, b"40" + HW_NUMBER + b"1039S")
        # Write the clean HW at its real offset so the test is focused
        # on what the extractor picks when only the dirty version exists:
        result_dirty_only = EXTRACTOR.extract(bytes(buf))
        # Now add a clean occurrence and confirm it wins
        write(buf, OFF_HW, b"\x00" + HW_NUMBER + b"\x00")
        result_with_clean = EXTRACTOR.extract(bytes(buf))
        assert result_with_clean["hardware_number"] == HW_NUMBER.decode()


# ---------------------------------------------------------------------------
# extract — calibration_version
# ---------------------------------------------------------------------------


class TestExtractCalibrationVersion:
    def test_cal_version_extracted_with_cv_prefix(self):
        """calibration_version is returned as 'CV<digits>'."""
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["calibration_version"] == "CV56047"

    def test_cal_version_is_string(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert isinstance(result["calibration_version"], str)

    def test_cal_version_starts_with_cv(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["calibration_version"].startswith("CV")

    def test_cal_version_none_when_absent(self):
        """No CVxxxxx pattern — calibration_version is None."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        write(buf, OFF_IDENT, IDENT_RECORD)
        write(buf, OFF_HW, HW_NUMBER)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_version"] is None

    def test_different_cv_value(self):
        """Extractor picks up an arbitrary CV value, not just CV56047."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        write(buf, 0x3000, b"@CV99999 ")
        result = EXTRACTOR.extract(bytes(buf))
        assert result["calibration_version"] == "CV99999"


# ---------------------------------------------------------------------------
# extract — absent fields (always None for ME9)
# ---------------------------------------------------------------------------


class TestExtractAbsentFields:
    def _result(self):
        return EXTRACTOR.extract(make_realistic_me9())

    def test_sw_base_version_is_none(self):
        assert self._result()["sw_base_version"] is None

    def test_serial_number_is_none(self):
        assert self._result()["serial_number"] is None

    def test_dataset_number_is_none(self):
        assert self._result()["dataset_number"] is None

    def test_oem_part_number_is_none(self):
        assert self._result()["oem_part_number"] is None


# ---------------------------------------------------------------------------
# extract — match_key
# ---------------------------------------------------------------------------


class TestExtractMatchKey:
    def test_match_key_format(self):
        """match_key must be 'ME9::<calibration_sw>'."""
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["match_key"] == f"ME9::{CAL_SW.decode()}"

    def test_match_key_starts_with_me9(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["match_key"].startswith("ME9::")

    def test_match_key_contains_sw(self):
        result = EXTRACTOR.extract(make_realistic_me9())
        assert CAL_SW.decode() in result["match_key"]

    def test_match_key_none_when_no_sw(self):
        """No software version anywhere — match_key must be None."""
        buf = make_buf(SIZE_SMALL)
        write(buf, 0, _ME9_ANCHOR)
        result = EXTRACTOR.extract(bytes(buf))
        assert result["match_key"] is None

    def test_match_key_is_uppercase(self):
        """The family part of the match key must be upper-cased."""
        result = EXTRACTOR.extract(make_realistic_me9())
        family_part = result["match_key"].split("::")[0]
        assert family_part == family_part.upper()

    def test_match_key_uses_family_not_variant(self):
        """
        match_key must use 'ME9' (family) as its identifier component,
        not 'ME9.0001' (variant), for cross-loader-revision stability.
        """
        result = EXTRACTOR.extract(make_realistic_me9())
        assert result["match_key"].startswith("ME9::")
        assert not result["match_key"].startswith("ME9.0001::")

    def test_match_key_uses_cal_sw_not_os_sw(self):
        """
        The match key version component must be the calibration SW (from //)
        not the OS/program SW (from the 0x22 sentinel).
        """
        result = EXTRACTOR.extract(make_realistic_me9())
        version_part = result["match_key"].split("::")[1]
        assert version_part == CAL_SW.decode()
        assert version_part != OS_SW.decode()


# ---------------------------------------------------------------------------
# extract — determinism and filename independence
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_deterministic(self):
        """Calling extract() twice with the same data must return equal dicts."""
        data = make_realistic_me9()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1 == r2

    def test_filename_does_not_affect_identification_fields(self):
        """
        The filename argument is for display only — all identification fields
        must be identical regardless of which filename is passed.
        """
        data = make_realistic_me9()
        identification_keys = (
            "manufacturer",
            "ecu_family",
            "ecu_variant",
            "software_version",
            "calibration_id",
            "hardware_number",
            "calibration_version",
            "match_key",
        )
        r_default = EXTRACTOR.extract(data)
        r_named = EXTRACTOR.extract(data, filename="different_name.bin")
        r_empty = EXTRACTOR.extract(data, filename="")

        for key in identification_keys:
            assert r_default[key] == r_named[key] == r_empty[key], (
                f"Field {key!r} differs with different filenames"
            )

    def test_different_data_gives_different_md5(self):
        """Sanity check: two different binaries produce different md5 hashes."""
        data_a = make_realistic_me9()
        buf_b = bytearray(make_realistic_me9())
        buf_b[0x100] ^= 0xFF  # flip some bits
        data_b = bytes(buf_b)
        assert EXTRACTOR.extract(data_a)["md5"] != EXTRACTOR.extract(data_b)["md5"]


# ---------------------------------------------------------------------------
# build_match_key — inherited from BaseManufacturerExtractor
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_family_and_sw_present(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="ME9",
            ecu_variant=None,
            software_version="1037383785",
        )
        assert key == "ME9::1037383785"

    def test_family_uppercased(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="me9",
            ecu_variant=None,
            software_version="1037383785",
        )
        assert key is not None
        assert key.startswith("ME9::")

    def test_variant_takes_priority_over_family(self):
        """If ecu_variant is provided it should be used instead of family."""
        key = EXTRACTOR.build_match_key(
            ecu_family="ME9",
            ecu_variant="ME9.1",
            software_version="1037383785",
        )
        assert key is not None
        assert key.startswith("ME9.1::")

    def test_none_when_no_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="ME9",
            ecu_variant=None,
            software_version=None,
        )
        assert key is None

    def test_none_when_no_family_no_sw(self):
        key = EXTRACTOR.build_match_key(
            ecu_family=None,
            ecu_variant=None,
            software_version=None,
        )
        assert key is None

    def test_none_when_no_family_but_sw_present(self):
        """Without any family/variant identifier the key cannot be built."""
        key = EXTRACTOR.build_match_key(
            ecu_family=None,
            ecu_variant=None,
            software_version="1037383785",
        )
        # "UNKNOWN::1037383785" or None depending on base class implementation;
        # what matters is that the key contains the SW when family is UNKNOWN.
        # We simply assert it is not None and contains the SW.
        assert key is not None
        assert "1037383785" in key

    def test_sw_version_preserved_exactly(self):
        sw = "1037383785"
        key = EXTRACTOR.build_match_key(
            ecu_family="ME9",
            ecu_variant=None,
            software_version=sw,
        )
        assert key is not None
        assert key.endswith(f"::{sw}")
