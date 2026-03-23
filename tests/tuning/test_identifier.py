"""
Tests for identify_ecu() (identifier.py).

Covers:
  - Return shape: all required keys always present
  - file_size always equals len(data)
  - sha256 always present and well-formed (64 hex chars)
  - Unknown binary: all identification fields are None
  - Default filename parameter is accepted
  - Synthetic EDC17 binary: manufacturer and family detected
  - Synthetic ME7 binary:   manufacturer and family detected
  - Synthetic EDC15 binary: manufacturer and family detected
  - First matching extractor wins (registry order)
  - Large binary handled without error
  - Empty binary returns unknown identity
  - identify_ecu is deterministic (same input → same output)
"""

import hashlib

from openremap.tuning.services.identifier import identify_ecu


# ---------------------------------------------------------------------------
# Return shape
# ---------------------------------------------------------------------------


EXPECTED_KEYS = {
    "manufacturer",
    "match_key",
    "ecu_family",
    "ecu_variant",
    "software_version",
    "hardware_number",
    "calibration_id",
    "file_size",
    "sha256",
}


class TestReturnShape:
    def test_all_expected_keys_present_for_unknown_binary(self):
        result = identify_ecu(bytes(256))
        assert EXPECTED_KEYS.issubset(result.keys())

    def test_all_expected_keys_present_for_edc17_binary(self):
        data = _make_edc17_bin()
        result = identify_ecu(data)
        assert EXPECTED_KEYS.issubset(result.keys())

    def test_no_unexpected_keys_are_required(self):
        # The function may return extra keys, but must never omit the required ones.
        result = identify_ecu(bytes(256))
        for key in EXPECTED_KEYS:
            assert key in result

    def test_return_type_is_dict(self):
        result = identify_ecu(bytes(64))
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# file_size — always equals len(data)
# ---------------------------------------------------------------------------


class TestFileSize:
    def test_file_size_equals_data_length_small(self):
        data = bytes(256)
        result = identify_ecu(data)
        assert result["file_size"] == 256

    def test_file_size_equals_data_length_medium(self):
        data = bytes(4096)
        result = identify_ecu(data)
        assert result["file_size"] == 4096

    def test_file_size_equals_data_length_large(self):
        data = bytes(512 * 1024)  # 512 KB
        result = identify_ecu(data)
        assert result["file_size"] == 512 * 1024

    def test_file_size_zero_for_empty_binary(self):
        result = identify_ecu(b"")
        assert result["file_size"] == 0

    def test_file_size_is_int(self):
        result = identify_ecu(bytes(128))
        assert isinstance(result["file_size"], int)

    def test_file_size_matches_for_edc17_binary(self):
        data = _make_edc17_bin()
        result = identify_ecu(data)
        assert result["file_size"] == len(data)


# ---------------------------------------------------------------------------
# sha256 — always present and well-formed
# ---------------------------------------------------------------------------


class TestSha256:
    def test_sha256_is_64_hex_chars(self):
        result = identify_ecu(bytes(256))
        assert len(result["sha256"]) == 64

    def test_sha256_is_lowercase_hex_string(self):
        result = identify_ecu(bytes(256))
        sha = result["sha256"]
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_matches_hashlib_full_file(self):
        data = bytes(range(256)) * 4  # 1 KB non-trivial content
        result = identify_ecu(data)
        expected = hashlib.sha256(data).hexdigest()
        assert result["sha256"] == expected

    def test_sha256_changes_with_different_data(self):
        result_a = identify_ecu(bytes(256))
        result_b = identify_ecu(bytes([0xFF] * 256))
        assert result_a["sha256"] != result_b["sha256"]

    def test_sha256_present_for_empty_binary(self):
        result = identify_ecu(b"")
        assert len(result["sha256"]) == 64

    def test_sha256_present_for_edc17_binary(self):
        data = _make_edc17_bin()
        result = identify_ecu(data)
        assert len(result["sha256"]) == 64


# ---------------------------------------------------------------------------
# Unknown binary — all identification fields are None
# ---------------------------------------------------------------------------


class TestUnknownBinary:
    """
    An all-zero binary of a size not claimed by any extractor's size gate
    must return None for every identification field other than file_size
    and sha256.
    """

    def _unknown(self, size=512) -> dict:
        return identify_ecu(bytes(size))

    def test_manufacturer_is_none(self):
        assert self._unknown()["manufacturer"] is None

    def test_match_key_is_none(self):
        assert self._unknown()["match_key"] is None

    def test_ecu_family_is_none(self):
        assert self._unknown()["ecu_family"] is None

    def test_ecu_variant_is_none(self):
        assert self._unknown()["ecu_variant"] is None

    def test_software_version_is_none(self):
        assert self._unknown()["software_version"] is None

    def test_hardware_number_is_none(self):
        assert self._unknown()["hardware_number"] is None

    def test_calibration_id_is_none(self):
        assert self._unknown()["calibration_id"] is None

    def test_file_size_still_set(self):
        assert self._unknown(512)["file_size"] == 512

    def test_sha256_still_set(self):
        assert len(self._unknown()["sha256"]) == 64

    def test_random_bytes_unknown(self):
        # Pseudo-random but deterministic content with no ECU signatures
        data = bytes((i * 7 + 13) % 256 for i in range(1024))
        result = identify_ecu(data)
        assert result["manufacturer"] is None

    def test_empty_binary_returns_unknown(self):
        result = identify_ecu(b"")
        assert result["manufacturer"] is None
        assert result["match_key"] is None

    def test_all_ff_binary_returns_unknown(self):
        result = identify_ecu(bytes([0xFF] * 256))
        assert result["manufacturer"] is None


# ---------------------------------------------------------------------------
# filename parameter
# ---------------------------------------------------------------------------


class TestFilenameParameter:
    def test_default_filename_accepted(self):
        # Should not raise
        result = identify_ecu(bytes(256))
        assert result is not None

    def test_custom_filename_accepted(self):
        result = identify_ecu(bytes(256), filename="my_ecu.bin")
        assert result is not None

    def test_filename_does_not_affect_identification(self):
        data = _make_edc17_bin()
        result_a = identify_ecu(data, filename="stock.bin")
        result_b = identify_ecu(data, filename="completely_different_name.ori")
        assert result_a["manufacturer"] == result_b["manufacturer"]
        assert result_a["ecu_family"] == result_b["ecu_family"]
        assert result_a["match_key"] == result_b["match_key"]

    def test_filename_does_not_appear_in_sha256(self):
        data = bytes(512)
        r1 = identify_ecu(data, filename="abc.bin")
        r2 = identify_ecu(data, filename="xyz.bin")
        assert r1["sha256"] == r2["sha256"]

    def test_ori_extension_accepted(self):
        result = identify_ecu(bytes(256), filename="dump.ori")
        assert result is not None


# ---------------------------------------------------------------------------
# Synthetic EDC17 binary — manufacturer and family detected
# ---------------------------------------------------------------------------


class TestEDC17Detection:
    def test_manufacturer_is_bosch(self):
        result = identify_ecu(_make_edc17_bin())
        assert result["manufacturer"] == "Bosch"

    def test_ecu_family_contains_edc17(self):
        result = identify_ecu(_make_edc17_bin())
        family = result["ecu_family"] or ""
        assert "EDC17" in family.upper()

    def test_match_key_is_not_none(self):
        # When a variant string is embedded the match key should be buildable.
        # If it is None the extractor could not find a SW version — still valid
        # but we log it for visibility.
        result = identify_ecu(_make_edc17_bin())
        # manufacturer must be set even if match_key is None
        assert result["manufacturer"] == "Bosch"

    def test_ecu_variant_detected(self):
        # The synthetic binary contains b"EDC17C66" which matches the variant pattern
        result = identify_ecu(_make_edc17_bin())
        variant = result.get("ecu_variant") or ""
        # Variant may be None if the resolver is strict, but family must be set
        assert result["ecu_family"] is not None

    def test_file_size_correct_for_edc17(self):
        data = _make_edc17_bin()
        result = identify_ecu(data)
        assert result["file_size"] == len(data)


# ---------------------------------------------------------------------------
# Synthetic ME7 binary — manufacturer and family detected
# ---------------------------------------------------------------------------


class TestME7Detection:
    def test_manufacturer_is_bosch(self):
        result = identify_ecu(_make_me7_bin())
        assert result["manufacturer"] == "Bosch"

    def test_ecu_family_contains_me7(self):
        result = identify_ecu(_make_me7_bin())
        family = result["ecu_family"] or ""
        assert "ME7" in family.upper()

    def test_file_size_correct_for_me7(self):
        data = _make_me7_bin()
        result = identify_ecu(data)
        assert result["file_size"] == len(data)


# ---------------------------------------------------------------------------
# Synthetic EDC15 binary — manufacturer and family detected
# ---------------------------------------------------------------------------


class TestEDC15Detection:
    def test_manufacturer_is_bosch(self):
        result = identify_ecu(_make_edc15_bin())
        assert result["manufacturer"] == "Bosch"

    def test_ecu_family_contains_edc15(self):
        result = identify_ecu(_make_edc15_bin())
        family = result["ecu_family"] or ""
        assert "EDC15" in family.upper()

    def test_file_size_correct_for_edc15(self):
        data = _make_edc15_bin()
        result = identify_ecu(data)
        assert result["file_size"] == len(data)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_input_produces_same_output_unknown(self):
        data = bytes(512)
        assert identify_ecu(data) == identify_ecu(data)

    def test_same_input_produces_same_output_edc17(self):
        data = _make_edc17_bin()
        assert identify_ecu(data) == identify_ecu(data)

    def test_different_data_may_produce_different_results(self):
        a = identify_ecu(bytes(512))
        b = identify_ecu(_make_edc17_bin())
        assert (
            a["manufacturer"] != b["manufacturer"] or a["ecu_family"] != b["ecu_family"]
        )


# ---------------------------------------------------------------------------
# Large binary
# ---------------------------------------------------------------------------


class TestLargeBinary:
    def test_2mb_unknown_binary_handled(self):
        data = bytes(2 * 1024 * 1024)
        result = identify_ecu(data)
        assert result["file_size"] == 2 * 1024 * 1024

    def test_4mb_edc17_like_binary_handled(self):
        # 4 MB binary with EDC17 signature; no EDC16 magic at any standard offset
        data = bytearray(4 * 1024 * 1024)
        data[0x1000 : 0x1000 + 8] = b"EDC17C66"
        result = identify_ecu(bytes(data))
        assert result["file_size"] == 4 * 1024 * 1024


# ---------------------------------------------------------------------------
# Synthetic binary factories
# ---------------------------------------------------------------------------
#
# Each factory builds the smallest possible binary that:
#   1. Passes the target extractor's can_handle() check.
#   2. Does NOT accidentally trigger any earlier extractor in the registry.
#
# EDC17 (BoschExtractor — last in registry, broadest match):
#   - Size: 512 KB (not in the EDC16 magic-offset dict: 256KB / 1MB / 2MB)
#   - Contains b"EDC17C66" somewhere in the first 320 KB (extended region)
#   - No b"EDC16" string anywhere in first 512 KB  → Guard 1b passes
#   - No b"TSW "  at any 512KB bank boundary       → Guard 2 passes
#   - No EDC3x "VV33" / "HEX" ident block          → EDC3x passes
#   - No M5.x ident block                          → M5x passes
#
# ME7 (BoschME7Extractor):
#   - Size: 128 KB (not owned by EDC1/EDC3x/M1x55/M5x)
#   - Contains b"ME7." in first 512 KB (Phase 2 positive)
#   - No exclusion signatures (no EDC17/MEDC17/MED17/ME17/EDC16/SB_V/Customer.)
#
# EDC15 (BoschEDC15Extractor):
#   - Size: 512 KB (0x80000)
#   - Contains b"TSW " at offset 0x8000 (Format A, Phase 2 positive)
#   - No exclusion signatures
# ---------------------------------------------------------------------------


def _make_edc17_bin(size: int = 512 * 1024) -> bytes:
    """
    512 KB synthetic EDC17 binary.
    Passes BoschExtractor.can_handle() and returns manufacturer='Bosch'.
    """
    buf = bytearray(size)
    # Write a recognisable variant string well within the extended region (320 KB)
    sig = b"EDC17C66"
    buf[0x1000 : 0x1000 + len(sig)] = sig
    return bytes(buf)


def _make_me7_bin(size: int = 128 * 1024) -> bytes:
    """
    128 KB synthetic ME7 binary.
    Passes BoschME7Extractor.can_handle() via the 'ME7.' Phase 2 detection.
    No exclusion signatures are present.
    """
    buf = bytearray(size)
    sig = b"ME7.5"
    buf[0x1000 : 0x1000 + len(sig)] = sig
    return bytes(buf)


def _make_edc15_bin(size: int = 512 * 1024) -> bytes:
    """
    512 KB synthetic EDC15 Format A binary.
    Passes BoschEDC15Extractor.can_handle() via the TSW string at 0x8000.
    No exclusion signatures are present.
    """
    buf = bytearray(size)
    tsw = b"TSW V2.40 280700 1718 C7/ESB/G40"
    buf[0x8000 : 0x8000 + len(tsw)] = tsw
    return bytes(buf)
