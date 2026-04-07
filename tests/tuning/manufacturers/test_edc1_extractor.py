"""
Tests for BoschEDC1Extractor (EDC1 / EDC2 tiny diesel ROMs).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * 32KB Sub-A variant (2287 prefix, ident at 0x7FD9)
      * 64KB Sub-A variant (2287 prefix, ident at 0x7FD9)
      * 64KB EDC2 bin (2537 prefix)
      * 64KB A6 AAT bin (1037 prefix)
      * 64KB Sub-B variant (ident at window start 0x7FD0)
  - can_handle() — False paths:
      * Empty binary
      * All-zero 32KB / 64KB
      * All-FF 32KB / 64KB (valid size but no ident)
      * Wrong sizes (16KB, 48KB, 128KB, 256KB)
      * Ident at wrong offset (outside IDENT_REGION)
      * No ident in valid-size bin
      * Partial ident (HW present, no SW)
      * Wrong HW prefix (0282 instead of 0281)
      * Wrong SW prefix (1234 instead of 1037/2287/2537)
  - can_handle() — Exclusions:
      * Every EXCLUSION_SIGNATURES entry blocks an otherwise-valid bin
      * Exclusion at offset 0 caught
      * Exclusion near end of bin caught
      * Exclusion overrides valid 32KB and 64KB bins
  - _parse_ident():
      * Returns (hw, sw) for all five binary variants
      * hw always starts with "0281" and is 10 digits
      * sw starts with 2287 / 2537 / 1037 per variant
      * Returns (None, None) for all-FF / all-zero / empty data
      * Dot separator variant accepted
      * Space separator variant accepted
  - extract() — required keys always present for all variants
  - extract() — 32KB full extraction (HW, SW, family, match_key)
  - extract() — 64KB full extraction
  - extract() — EDC2 64KB (2537 prefix)
  - extract() — A6 AAT 64KB (1037 prefix)
  - extract() — Sub-B 64KB (ident at window start)
  - extract() — null fields always None (calibration_version, sw_base_version, etc.)
  - extract() — hashing (md5 and sha256_first_64kb correctness)
  - match_key format: "EDC1::<SW>", None when SW absent, always uppercase
  - Determinism and filename independence
"""

import hashlib

import pytest

from openremap.core.manufacturers.bosch.edc1.extractor import (
    EXCLUSION_SIGNATURES,
    IDENT_OFFSET,
    IDENT_PATTERN,
    IDENT_REGION,
    SUPPORTED_SIZES,
    BoschEDC1Extractor,
)

EXTRACTOR = BoschEDC1Extractor()

# All keys that extract() must return.
REQUIRED_EXTRACT_KEYS = {
    "manufacturer",
    "match_key",
    "ecu_family",
    "ecu_variant",
    "software_version",
    "hardware_number",
    "calibration_version",
    "sw_base_version",
    "serial_number",
    "dataset_number",
    "calibration_id",
    "oem_part_number",
    "file_size",
    "md5",
    "sha256_first_64kb",
    "raw_strings",
}

# ---------------------------------------------------------------------------
# Reference field values (from documented sample bins)
# ---------------------------------------------------------------------------

# Sub-A 32KB — 8A0907401A style, 2287 prefix
_EDC1_32KB_HW = "0281001133"
_EDC1_32KB_SW = "2287357912"

# Sub-A 64KB — 028906021D style, 2287 prefix
_EDC1_64KB_HW = "0281001198"
_EDC1_64KB_SW = "2287358770"

# EDC2 64KB — 021906028AP style, 2537 prefix
_EDC2_HW = "0281001317"
_EDC2_SW = "2537355582"

# A6 AAT 64KB — 4A0907401E style, 1037 prefix
_EDC1_A6_HW = "0281001254"
_EDC1_A6_SW = "1037355048"

# Sub-B 64KB — BMW 325 TDS style, ident at window start (0x7FD0)
_EDC1_SUBB_HW = "0281001380"
_EDC1_SUBB_SW = "1037355081"

# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------


def _make_bin_with_ident(size: int, ident: bytes, offset: int) -> bytes:
    """Create a binary of `size` bytes (0xFF-filled) with `ident` at `offset`."""
    data = bytearray(b"\xff" * size)
    data[offset : offset + len(ident)] = ident
    return bytes(data)


def make_edc1_32kb_bin() -> bytes:
    """32KB Sub-A variant: HW/SW ident at 0x7FD9, 2287 prefix."""
    ident = b"0281001133\xff2287357912\xffA50AM000\xff37"
    return _make_bin_with_ident(0x8000, ident, 0x7FD9)


def make_edc1_64kb_bin() -> bytes:
    """64KB Sub-A variant: HW/SW ident at 0x7FD9, 2287 prefix."""
    ident = b"0281001198\xff2287358770\xffA50AM000\xff37"
    return _make_bin_with_ident(0x10000, ident, 0x7FD9)


def make_edc2_64kb_bin() -> bytes:
    """64KB EDC2: HW/SW ident at 0x7FD9, 2537 prefix."""
    ident = b"0281001317\xff2537355582\xffDAT000001\xff37"
    return _make_bin_with_ident(0x10000, ident, 0x7FD9)


def make_edc1_a6_64kb_bin() -> bytes:
    """64KB A6 AAT variant: HW/SW ident at 0x7FD9, 1037 prefix."""
    ident = b"0281001254\xff1037355048\xffH618204K\xff66"
    return _make_bin_with_ident(0x10000, ident, 0x7FD9)


def make_edc1_subB_64kb_bin() -> bytes:
    """64KB Sub-B variant: ident at window start (0x7FD0), 1037 prefix."""
    ident = b"0281001380\xff1037355081\xffDAMOS000\xff3Y3"
    return _make_bin_with_ident(0x10000, ident, 0x7FD0)


def _inject_exclusion(data: bytes, excl: bytes) -> bytes:
    """Inject an exclusion signature into a copy of `data` at offset 0."""
    arr = bytearray(data)
    arr[0 : len(excl)] = excl
    return bytes(arr)


# ---------------------------------------------------------------------------
# TestIdentity
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

    def test_edc1_in_supported_families(self):
        assert "EDC1" in EXTRACTOR.supported_families

    def test_edc2_in_supported_families(self):
        assert "EDC2" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        assert all(isinstance(f, str) for f in EXTRACTOR.supported_families)

    def test_repr_is_string(self):
        assert isinstance(repr(EXTRACTOR), str)

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschEDC1Extractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# TestCanHandleTrue
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """can_handle() must return True for every valid EDC1/EDC2 variant."""

    def test_32kb_2287_accepted(self):
        assert EXTRACTOR.can_handle(make_edc1_32kb_bin()) is True

    def test_64kb_2287_accepted(self):
        assert EXTRACTOR.can_handle(make_edc1_64kb_bin()) is True

    def test_64kb_2537_edc2_accepted(self):
        assert EXTRACTOR.can_handle(make_edc2_64kb_bin()) is True

    def test_64kb_1037_a6_accepted(self):
        assert EXTRACTOR.can_handle(make_edc1_a6_64kb_bin()) is True

    def test_64kb_subB_accepted(self):
        assert EXTRACTOR.can_handle(make_edc1_subB_64kb_bin()) is True

    def test_can_handle_returns_bool(self):
        assert isinstance(EXTRACTOR.can_handle(make_edc1_64kb_bin()), bool)

    def test_32kb_is_in_supported_sizes(self):
        assert 0x8000 in SUPPORTED_SIZES

    def test_64kb_is_in_supported_sizes(self):
        assert 0x10000 in SUPPORTED_SIZES


# ---------------------------------------------------------------------------
# TestCanHandleFalse
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    """can_handle() must return False for every non-EDC1 input."""

    def test_empty_binary_rejected(self):
        assert not EXTRACTOR.can_handle(b"")

    def test_all_zero_32kb_rejected(self):
        assert not EXTRACTOR.can_handle(b"\x00" * 0x8000)

    def test_all_zero_64kb_rejected(self):
        assert not EXTRACTOR.can_handle(b"\x00" * 0x10000)

    def test_all_ff_32kb_no_ident_rejected(self):
        # Correct size but no ident → Phase 3 fails
        assert not EXTRACTOR.can_handle(b"\xff" * 0x8000)

    def test_all_ff_64kb_no_ident_rejected(self):
        assert not EXTRACTOR.can_handle(b"\xff" * 0x10000)

    def test_16kb_size_rejected(self):
        assert not EXTRACTOR.can_handle(b"\xff" * 0x4000)

    def test_48kb_size_rejected(self):
        assert not EXTRACTOR.can_handle(b"\xff" * 0xC000)

    def test_128kb_size_rejected(self):
        assert not EXTRACTOR.can_handle(b"\xff" * 0x20000)

    def test_256kb_size_rejected(self):
        assert not EXTRACTOR.can_handle(b"\xff" * 0x40000)

    def test_512kb_size_rejected(self):
        assert not EXTRACTOR.can_handle(b"\xff" * 0x80000)

    def test_ident_at_offset_zero_not_detected(self):
        # A valid ident placed at offset 0 is outside IDENT_REGION → rejected.
        data = bytearray(b"\xff" * 0x10000)
        ident = b"0281001198\xff2287358770"
        data[0 : len(ident)] = ident
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_ident_just_before_region_not_detected(self):
        # Ident ending just before IDENT_OFFSET is not in the search window.
        data = bytearray(b"\xff" * 0x10000)
        ident = b"0281001198\xff2287358770"
        # Place ident so it ends at IDENT_OFFSET - 1 (entirely before window)
        end = IDENT_OFFSET - 1
        start = end - len(ident)
        data[start:end] = ident
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_partial_ident_hw_only_rejected(self):
        # Only HW present, no SW — pattern requires both
        data = bytearray(b"\xff" * 0x10000)
        data[0x7FD9 : 0x7FD9 + 10] = b"0281001198"
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_wrong_hw_prefix_0282_rejected(self):
        data = bytearray(b"\xff" * 0x10000)
        ident = b"0282001198\xff2287358770"
        data[0x7FD9 : 0x7FD9 + len(ident)] = ident
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_wrong_sw_prefix_1234_rejected(self):
        data = bytearray(b"\xff" * 0x10000)
        ident = b"0281001198\xff1234567890"
        data[0x7FD9 : 0x7FD9 + len(ident)] = ident
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_wrong_sw_prefix_0281_rejected(self):
        # SW starting with 0281 is a HW number, not a SW prefix
        data = bytearray(b"\xff" * 0x10000)
        ident = b"0281001198\xff0281001200"
        data[0x7FD9 : 0x7FD9 + len(ident)] = ident
        assert not EXTRACTOR.can_handle(bytes(data))


# ---------------------------------------------------------------------------
# TestCanHandleExclusions
# ---------------------------------------------------------------------------


class TestCanHandleExclusions:
    """Every EXCLUSION_SIGNATURES entry must block an otherwise-valid bin."""

    def _valid_buf(self) -> bytes:
        return make_edc1_64kb_bin()

    def test_exclusion_signatures_list_not_empty(self):
        assert len(EXCLUSION_SIGNATURES) >= 10

    @pytest.mark.parametrize("excl", EXCLUSION_SIGNATURES)
    def test_each_exclusion_sig_rejects_valid_bin(self, excl):
        data = _inject_exclusion(self._valid_buf(), excl)
        assert not EXTRACTOR.can_handle(data)

    def test_edc15_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"EDC15"))

    def test_edc16_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"EDC16"))

    def test_edc17_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"EDC17"))

    def test_tsw_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"TSW"))

    def test_me7_dot_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"ME7."))

    def test_motronic_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(
            _inject_exclusion(self._valid_buf(), b"MOTRONIC")
        )

    def test_motr_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"MOTR"))

    def test_m5_dot_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"M5."))

    def test_exclusion_at_end_still_caught(self):
        data = bytearray(self._valid_buf())
        excl = b"EDC16"
        data[-len(excl) :] = excl
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_exclusion_at_offset_zero_caught(self):
        data = _inject_exclusion(self._valid_buf(), b"EDC17")
        assert not EXTRACTOR.can_handle(data)

    def test_exclusion_overrides_32kb_valid_bin(self):
        data = _inject_exclusion(make_edc1_32kb_bin(), b"EDC17")
        assert not EXTRACTOR.can_handle(data)

    def test_exclusion_overrides_edc2_valid_bin(self):
        data = _inject_exclusion(make_edc2_64kb_bin(), b"MEDC17")
        assert not EXTRACTOR.can_handle(data)

    def test_exclusion_overrides_a6_valid_bin(self):
        data = _inject_exclusion(make_edc1_a6_64kb_bin(), b"EDC15")
        assert not EXTRACTOR.can_handle(data)


# ---------------------------------------------------------------------------
# TestParseIdent
# ---------------------------------------------------------------------------


class TestParseIdent:
    """Unit tests for BoschEDC1Extractor._parse_ident()."""

    def test_returns_hw_and_sw_for_32kb_bin(self):
        hw, sw = EXTRACTOR._parse_ident(make_edc1_32kb_bin())
        assert hw == _EDC1_32KB_HW
        assert sw == _EDC1_32KB_SW

    def test_returns_hw_and_sw_for_64kb_bin(self):
        hw, sw = EXTRACTOR._parse_ident(make_edc1_64kb_bin())
        assert hw == _EDC1_64KB_HW
        assert sw == _EDC1_64KB_SW

    def test_returns_hw_and_sw_for_edc2(self):
        hw, sw = EXTRACTOR._parse_ident(make_edc2_64kb_bin())
        assert hw == _EDC2_HW
        assert sw == _EDC2_SW

    def test_returns_hw_and_sw_for_a6_1037(self):
        hw, sw = EXTRACTOR._parse_ident(make_edc1_a6_64kb_bin())
        assert hw == _EDC1_A6_HW
        assert sw == _EDC1_A6_SW

    def test_returns_hw_and_sw_for_subB(self):
        hw, sw = EXTRACTOR._parse_ident(make_edc1_subB_64kb_bin())
        assert hw == _EDC1_SUBB_HW
        assert sw == _EDC1_SUBB_SW

    def test_hw_starts_with_0281_64kb(self):
        hw, _ = EXTRACTOR._parse_ident(make_edc1_64kb_bin())
        assert hw is not None
        assert hw.startswith("0281")

    def test_hw_starts_with_0281_32kb(self):
        hw, _ = EXTRACTOR._parse_ident(make_edc1_32kb_bin())
        assert hw is not None
        assert hw.startswith("0281")

    def test_hw_is_exactly_10_digits_64kb(self):
        hw, _ = EXTRACTOR._parse_ident(make_edc1_64kb_bin())
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_hw_is_exactly_10_digits_32kb(self):
        hw, _ = EXTRACTOR._parse_ident(make_edc1_32kb_bin())
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_sw_2287_prefix_for_64kb(self):
        _, sw = EXTRACTOR._parse_ident(make_edc1_64kb_bin())
        assert sw is not None
        assert sw.startswith("2287")

    def test_sw_2537_prefix_for_edc2(self):
        _, sw = EXTRACTOR._parse_ident(make_edc2_64kb_bin())
        assert sw is not None
        assert sw.startswith("2537")

    def test_sw_1037_prefix_for_a6(self):
        _, sw = EXTRACTOR._parse_ident(make_edc1_a6_64kb_bin())
        assert sw is not None
        assert sw.startswith("1037")

    def test_sw_1037_prefix_for_subB(self):
        _, sw = EXTRACTOR._parse_ident(make_edc1_subB_64kb_bin())
        assert sw is not None
        assert sw.startswith("1037")

    def test_returns_none_none_for_all_ff_64kb(self):
        hw, sw = EXTRACTOR._parse_ident(b"\xff" * 0x10000)
        assert hw is None
        assert sw is None

    def test_returns_none_none_for_all_ff_32kb(self):
        hw, sw = EXTRACTOR._parse_ident(b"\xff" * 0x8000)
        assert hw is None
        assert sw is None

    def test_returns_none_none_for_empty(self):
        hw, sw = EXTRACTOR._parse_ident(b"")
        assert hw is None
        assert sw is None

    def test_returns_none_none_for_all_zero_64kb(self):
        hw, sw = EXTRACTOR._parse_ident(b"\x00" * 0x10000)
        assert hw is None
        assert sw is None

    def test_dot_separator_variant_accepted(self):
        data = bytearray(b"\xff" * 0x10000)
        ident = b"0281001198.2287358770.A50AM000.37"
        data[0x7FD9 : 0x7FD9 + len(ident)] = ident
        hw, sw = EXTRACTOR._parse_ident(bytes(data))
        assert hw == "0281001198"
        assert sw == "2287358770"

    def test_space_separator_variant_accepted(self):
        data = bytearray(b"\xff" * 0x10000)
        ident = b"0281001198 2287358770 A50AM000 37"
        data[0x7FD9 : 0x7FD9 + len(ident)] = ident
        hw, sw = EXTRACTOR._parse_ident(bytes(data))
        assert hw == "0281001198"
        assert sw == "2287358770"

    def test_parse_returns_tuple_of_two(self):
        result = EXTRACTOR._parse_ident(make_edc1_64kb_bin())
        assert len(result) == 2

    def test_both_values_are_strings_when_present(self):
        hw, sw = EXTRACTOR._parse_ident(make_edc1_64kb_bin())
        assert isinstance(hw, str)
        assert isinstance(sw, str)


# ---------------------------------------------------------------------------
# TestExtractRequiredKeys
# ---------------------------------------------------------------------------


class TestExtractRequiredKeys:
    """extract() must always return every required key, regardless of variant."""

    def _check(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data)

    def test_required_keys_32kb(self):
        result = self._check(make_edc1_32kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_64kb(self):
        result = self._check(make_edc1_64kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_edc2(self):
        result = self._check(make_edc2_64kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_a6(self):
        result = self._check(make_edc1_a6_64kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_subB(self):
        result = self._check(make_edc1_subB_64kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_manufacturer_always_bosch_64kb(self):
        assert self._check(make_edc1_64kb_bin())["manufacturer"] == "Bosch"

    def test_manufacturer_always_bosch_32kb(self):
        assert self._check(make_edc1_32kb_bin())["manufacturer"] == "Bosch"

    def test_manufacturer_always_bosch_edc2(self):
        assert self._check(make_edc2_64kb_bin())["manufacturer"] == "Bosch"

    def test_file_size_equals_data_length_64kb(self):
        data = make_edc1_64kb_bin()
        assert self._check(data)["file_size"] == len(data)

    def test_file_size_equals_data_length_32kb(self):
        data = make_edc1_32kb_bin()
        assert self._check(data)["file_size"] == len(data)

    def test_raw_strings_is_list_64kb(self):
        assert isinstance(self._check(make_edc1_64kb_bin())["raw_strings"], list)

    def test_raw_strings_is_list_32kb(self):
        assert isinstance(self._check(make_edc1_32kb_bin())["raw_strings"], list)


# ---------------------------------------------------------------------------
# TestExtractEDC1_32KB
# ---------------------------------------------------------------------------


class TestExtractEDC1_32KB:
    """Full extraction checks for the 32KB Sub-A EDC1 bin."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_edc1_32kb_bin())

    def test_ecu_family_is_edc1(self):
        assert self.result["ecu_family"] == "EDC1"

    def test_ecu_variant_is_none(self):
        assert self.result["ecu_variant"] is None

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _EDC1_32KB_HW

    def test_hardware_number_starts_with_0281(self):
        assert self.result["hardware_number"] is not None
        assert self.result["hardware_number"].startswith("0281")

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_software_version(self):
        assert self.result["software_version"] == _EDC1_32KB_SW

    def test_software_version_starts_with_2287(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert sw.startswith("2287")

    def test_file_size_is_32kb(self):
        assert self.result["file_size"] == 0x8000

    def test_match_key_format(self):
        assert self.result["match_key"] == f"EDC1::{_EDC1_32KB_SW}"

    def test_match_key_is_uppercase(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk == mk.upper()

    def test_raw_strings_not_empty(self):
        # The ident block sits in the IDENT_REGION; HW and SW appear as strings.
        assert len(self.result["raw_strings"]) > 0


# ---------------------------------------------------------------------------
# TestExtractEDC1_64KB
# ---------------------------------------------------------------------------


class TestExtractEDC1_64KB:
    """Full extraction checks for the 64KB Sub-A EDC1 bin (2287 prefix)."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_edc1_64kb_bin())

    def test_ecu_family_is_edc1(self):
        assert self.result["ecu_family"] == "EDC1"

    def test_ecu_variant_is_none(self):
        assert self.result["ecu_variant"] is None

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _EDC1_64KB_HW

    def test_software_version(self):
        assert self.result["software_version"] == _EDC1_64KB_SW

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000

    def test_match_key_format(self):
        assert self.result["match_key"] == f"EDC1::{_EDC1_64KB_SW}"

    def test_match_key_is_uppercase(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk == mk.upper()

    def test_match_key_prefix_is_edc1(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk.startswith("EDC1::")

    def test_match_key_suffix_is_sw(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk.endswith(_EDC1_64KB_SW)

    def test_match_key_separator_is_double_colon(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert "::" in mk

    def test_raw_strings_not_empty(self):
        assert len(self.result["raw_strings"]) > 0


# ---------------------------------------------------------------------------
# TestExtractEDC2
# ---------------------------------------------------------------------------


class TestExtractEDC2:
    """Full extraction checks for the 64KB EDC2 bin (2537 prefix)."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_edc2_64kb_bin())

    def test_ecu_family_is_edc1(self):
        # EDC2 bins still return "EDC1" — the extractor uses a fixed family string.
        assert self.result["ecu_family"] == "EDC1"

    def test_ecu_variant_is_none(self):
        assert self.result["ecu_variant"] is None

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _EDC2_HW

    def test_software_version(self):
        assert self.result["software_version"] == _EDC2_SW

    def test_software_version_starts_with_2537(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert sw.startswith("2537")

    def test_match_key_format(self):
        assert self.result["match_key"] == f"EDC1::{_EDC2_SW}"

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000


# ---------------------------------------------------------------------------
# TestExtractEDC1_A6
# ---------------------------------------------------------------------------


class TestExtractEDC1_A6:
    """Full extraction checks for the 64KB A6 AAT bin (1037 prefix)."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_edc1_a6_64kb_bin())

    def test_ecu_family_is_edc1(self):
        assert self.result["ecu_family"] == "EDC1"

    def test_ecu_variant_is_none(self):
        assert self.result["ecu_variant"] is None

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _EDC1_A6_HW

    def test_software_version(self):
        assert self.result["software_version"] == _EDC1_A6_SW

    def test_software_version_starts_with_1037(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert sw.startswith("1037")

    def test_match_key_format(self):
        assert self.result["match_key"] == f"EDC1::{_EDC1_A6_SW}"

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000


# ---------------------------------------------------------------------------
# TestExtractSubBVariant
# ---------------------------------------------------------------------------


class TestExtractSubBVariant:
    """Extraction for the Sub-B 64KB bin (ident starting at window start 0x7FD0)."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_edc1_subB_64kb_bin())

    def test_ecu_family_is_edc1(self):
        assert self.result["ecu_family"] == "EDC1"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _EDC1_SUBB_HW

    def test_software_version(self):
        assert self.result["software_version"] == _EDC1_SUBB_SW

    def test_match_key_format(self):
        assert self.result["match_key"] == f"EDC1::{_EDC1_SUBB_SW}"

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000


# ---------------------------------------------------------------------------
# TestExtractNullFields
# ---------------------------------------------------------------------------


class TestExtractNullFields:
    """Fields not present in EDC1/EDC2 binaries must always be None."""

    def _r64(self) -> dict:
        return EXTRACTOR.extract(make_edc1_64kb_bin())

    def _r32(self) -> dict:
        return EXTRACTOR.extract(make_edc1_32kb_bin())

    def _redc2(self) -> dict:
        return EXTRACTOR.extract(make_edc2_64kb_bin())

    def test_calibration_version_is_none_64kb(self):
        assert self._r64()["calibration_version"] is None

    def test_calibration_version_is_none_32kb(self):
        assert self._r32()["calibration_version"] is None

    def test_calibration_version_is_none_edc2(self):
        assert self._redc2()["calibration_version"] is None

    def test_sw_base_version_is_none_64kb(self):
        assert self._r64()["sw_base_version"] is None

    def test_sw_base_version_is_none_32kb(self):
        assert self._r32()["sw_base_version"] is None

    def test_serial_number_is_none_64kb(self):
        assert self._r64()["serial_number"] is None

    def test_serial_number_is_none_32kb(self):
        assert self._r32()["serial_number"] is None

    def test_dataset_number_is_none_64kb(self):
        assert self._r64()["dataset_number"] is None

    def test_dataset_number_is_none_32kb(self):
        assert self._r32()["dataset_number"] is None

    def test_calibration_id_is_none_64kb(self):
        assert self._r64()["calibration_id"] is None

    def test_calibration_id_is_none_32kb(self):
        assert self._r32()["calibration_id"] is None

    def test_calibration_id_is_none_edc2(self):
        assert self._redc2()["calibration_id"] is None

    def test_oem_part_number_is_none_64kb(self):
        assert self._r64()["oem_part_number"] is None

    def test_oem_part_number_is_none_32kb(self):
        assert self._r32()["oem_part_number"] is None

    def test_ecu_variant_is_none_64kb(self):
        assert self._r64()["ecu_variant"] is None

    def test_ecu_variant_is_none_edc2(self):
        assert self._redc2()["ecu_variant"] is None

    def test_sw_base_version_is_none_edc2(self):
        assert self._redc2()["sw_base_version"] is None

    def test_serial_number_is_none_a6(self):
        assert EXTRACTOR.extract(make_edc1_a6_64kb_bin())["serial_number"] is None


# ---------------------------------------------------------------------------
# TestExtractHashing
# ---------------------------------------------------------------------------


class TestExtractHashing:
    """md5 and sha256_first_64kb must be computed correctly."""

    def _r(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data)

    def test_md5_is_32_hex_chars_64kb(self):
        result = self._r(make_edc1_64kb_bin())
        assert len(result["md5"]) == 32

    def test_md5_only_hex_digits_64kb(self):
        result = self._r(make_edc1_64kb_bin())
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_correct_64kb(self):
        data = make_edc1_64kb_bin()
        assert self._r(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_32kb(self):
        data = make_edc1_32kb_bin()
        assert self._r(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_edc2(self):
        data = make_edc2_64kb_bin()
        assert self._r(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_is_64_hex_chars_64kb(self):
        result = self._r(make_edc1_64kb_bin())
        assert len(result["sha256_first_64kb"]) == 64

    def test_sha256_covers_first_64kb_only_for_64kb_bin(self):
        data = make_edc1_64kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._r(data)["sha256_first_64kb"] == expected

    def test_sha256_correct_32kb(self):
        # For a 32KB bin data[:0x10000] returns the full 32KB.
        data = make_edc1_32kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._r(data)["sha256_first_64kb"] == expected

    def test_sha256_correct_edc2(self):
        data = make_edc2_64kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._r(data)["sha256_first_64kb"] == expected

    def test_different_bins_different_md5(self):
        r1 = self._r(make_edc1_32kb_bin())
        r2 = self._r(make_edc1_64kb_bin())
        assert r1["md5"] != r2["md5"]

    def test_32kb_and_64kb_different_sha256(self):
        r1 = self._r(make_edc1_32kb_bin())
        r2 = self._r(make_edc1_64kb_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]

    def test_edc2_and_a6_different_md5(self):
        r1 = self._r(make_edc2_64kb_bin())
        r2 = self._r(make_edc1_a6_64kb_bin())
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# TestMatchKey
# ---------------------------------------------------------------------------


class TestMatchKey:
    """match_key must be formatted correctly, uppercase, and None when SW absent."""

    def _r(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data)

    def test_match_key_is_none_when_no_ident(self):
        # All-FF 64KB bin → no ident → sw=None → match_key=None
        result = EXTRACTOR.extract(b"\xff" * 0x10000)
        assert result["match_key"] is None

    def test_match_key_is_none_when_no_ident_32kb(self):
        result = EXTRACTOR.extract(b"\xff" * 0x8000)
        assert result["match_key"] is None

    def test_match_key_format_64kb(self):
        assert self._r(make_edc1_64kb_bin())["match_key"] == f"EDC1::{_EDC1_64KB_SW}"

    def test_match_key_format_32kb(self):
        assert self._r(make_edc1_32kb_bin())["match_key"] == f"EDC1::{_EDC1_32KB_SW}"

    def test_match_key_format_edc2(self):
        assert self._r(make_edc2_64kb_bin())["match_key"] == f"EDC1::{_EDC2_SW}"

    def test_match_key_format_a6(self):
        assert self._r(make_edc1_a6_64kb_bin())["match_key"] == f"EDC1::{_EDC1_A6_SW}"

    def test_match_key_format_subB(self):
        assert (
            self._r(make_edc1_subB_64kb_bin())["match_key"] == f"EDC1::{_EDC1_SUBB_SW}"
        )

    def test_match_key_is_always_uppercase_64kb(self):
        mk = self._r(make_edc1_64kb_bin())["match_key"]
        assert mk is not None
        assert mk == mk.upper()

    def test_match_key_is_always_uppercase_edc2(self):
        mk = self._r(make_edc2_64kb_bin())["match_key"]
        assert mk is not None
        assert mk == mk.upper()

    def test_different_sw_gives_different_match_key(self):
        mk1 = self._r(make_edc1_32kb_bin())["match_key"]
        mk2 = self._r(make_edc2_64kb_bin())["match_key"]
        assert mk1 != mk2

    def test_match_key_prefix_is_edc1_64kb(self):
        mk = self._r(make_edc1_64kb_bin())["match_key"]
        assert mk is not None
        assert mk.startswith("EDC1::")

    def test_match_key_suffix_is_sw_64kb(self):
        result = self._r(make_edc1_64kb_bin())
        mk = result["match_key"]
        sw = result["software_version"]
        assert mk is not None and sw is not None
        assert mk.endswith(sw)

    def test_match_key_contains_double_colon_separator(self):
        mk = self._r(make_edc1_64kb_bin())["match_key"]
        assert mk is not None
        assert "::" in mk

    def test_match_key_has_exactly_one_separator(self):
        mk = self._r(make_edc1_64kb_bin())["match_key"]
        assert mk is not None
        assert mk.count("::") == 1


# ---------------------------------------------------------------------------
# TestDeterminism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """extract() must be deterministic and filename-independent."""

    def test_same_binary_same_result_64kb(self):
        data = make_edc1_64kb_bin()
        assert EXTRACTOR.extract(data) == EXTRACTOR.extract(data)

    def test_same_binary_same_result_32kb(self):
        data = make_edc1_32kb_bin()
        assert EXTRACTOR.extract(data) == EXTRACTOR.extract(data)

    def test_same_binary_same_result_edc2(self):
        data = make_edc2_64kb_bin()
        assert EXTRACTOR.extract(data) == EXTRACTOR.extract(data)

    def test_filename_does_not_affect_64kb_fields(self):
        data = make_edc1_64kb_bin()
        r1 = EXTRACTOR.extract(data, "file_a.bin")
        r2 = EXTRACTOR.extract(data, "totally_different_name.bin")
        for key in ("hardware_number", "software_version", "ecu_family", "match_key"):
            assert r1[key] == r2[key]

    def test_filename_does_not_affect_32kb_fields(self):
        data = make_edc1_32kb_bin()
        r1 = EXTRACTOR.extract(data, "original.bin")
        r2 = EXTRACTOR.extract(data, "copy.bin")
        for key in ("hardware_number", "software_version", "match_key"):
            assert r1[key] == r2[key]

    def test_different_binaries_produce_different_md5(self):
        r1 = EXTRACTOR.extract(make_edc1_32kb_bin())
        r2 = EXTRACTOR.extract(make_edc1_64kb_bin())
        assert r1["md5"] != r2["md5"]

    def test_file_size_reflects_actual_binary_size_32kb(self):
        assert EXTRACTOR.extract(make_edc1_32kb_bin())["file_size"] == 0x8000

    def test_file_size_reflects_actual_binary_size_64kb(self):
        assert EXTRACTOR.extract(make_edc1_64kb_bin())["file_size"] == 0x10000

    def test_can_handle_then_extract_32kb_consistent(self):
        data = make_edc1_32kb_bin()
        assert EXTRACTOR.can_handle(data)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == _EDC1_32KB_HW
        assert result["software_version"] == _EDC1_32KB_SW

    def test_can_handle_then_extract_64kb_consistent(self):
        data = make_edc1_64kb_bin()
        assert EXTRACTOR.can_handle(data)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == _EDC1_64KB_HW
        assert result["software_version"] == _EDC1_64KB_SW

    def test_can_handle_then_extract_edc2_consistent(self):
        data = make_edc2_64kb_bin()
        assert EXTRACTOR.can_handle(data)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == _EDC2_HW
        assert result["software_version"] == _EDC2_SW

    def test_can_handle_then_extract_a6_consistent(self):
        data = make_edc1_a6_64kb_bin()
        assert EXTRACTOR.can_handle(data)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == _EDC1_A6_HW
        assert result["software_version"] == _EDC1_A6_SW

    def test_can_handle_then_extract_subB_consistent(self):
        data = make_edc1_subB_64kb_bin()
        assert EXTRACTOR.can_handle(data)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == _EDC1_SUBB_HW
        assert result["software_version"] == _EDC1_SUBB_SW
