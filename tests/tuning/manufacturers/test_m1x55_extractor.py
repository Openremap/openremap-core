"""
Tests for BoschM1x55Extractor (Alfa Romeo M1.55 and Opel M1.5.5 petrol ECUs).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * Alfa Romeo M1.55 bin (descriptor at 0x8005, HW/SW ident in last 2KB)
      * Alfa M1.55 without HW/SW ident (detection does not require ident)
      * Second Alfa M1.55 variant (different descriptor values)
      * Opel M1.5.5 bin (M1.5.5 token anywhere, opel ident block)
      * Bin with M1.55 token at exactly the boundary (first 64KB)
  - can_handle() — False paths:
      * Empty binary
      * All-zero 128KB
      * All-FF 128KB (correct size, but no detection signature)
      * 256KB size rejected
      * 64KB size rejected
      * 32KB size rejected
      * M1.55 token placed beyond the first 64KB threshold — rejected
      * Neither M1.55 nor M1.5.5 present — rejected
  - can_handle() — Exclusions:
      * Every EXCLUSION_SIGNATURES entry blocks an otherwise-valid bin
      * Exclusion at offset 0 still caught
      * Exclusion near end of bin still caught
  - _parse_descriptor():
      * Returns family, dataset, ecu_variant for full "56/1/M1.55/..." format
      * Returns correct values for partial "M1.55/..." format (full_m fallback)
      * Returns just family for token-only input (no slashes after M1.xx)
      * Returns all-None for all-FF / all-zero / empty data
      * Returns all-None for empty DESCRIPTOR_REGION
  - _parse_hw_sw():
      * Returns (hw, sw) for Alfa ident in last 2KB
      * Returns (None, None) for all-FF / all-zero / empty data
      * hw starts with "0261", is 10 digits; sw starts with "1037"
  - _parse_opel_m155_ident():
      * Returns (hw, sw) for Opel ident in OPEL_M155_IDENT_REGION
      * Returns (None, None) for all-FF / all-zero / empty data
      * hw is 10-digit "0261..." string; sw is 8-digit GM number
  - extract() — required keys always present for Alfa and Opel
  - extract() — Alfa M1.55 full extraction (HW, SW, family, variant, dataset,
      calibration_id, match_key)
  - extract() — second Alfa M1.55 variant
  - extract() — Opel M1.5.5 full extraction (HW, SW, family=M1.5.5,
      variant=None, dataset=None, calibration_id=None, match_key)
  - extract() — null fields always None (calibration_version, sw_base_version,
      serial_number, oem_part_number) for both Alfa and Opel
  - extract() — hashing (md5 and sha256_first_64kb correctness)
  - match_key format, None when SW absent, always uppercase
  - Determinism and filename independence
"""

import hashlib

import pytest

from openremap.tuning.manufacturers.bosch.m1x55.extractor import (
    DESCRIPTOR_PATTERN,
    DESCRIPTOR_REGION,
    DETECTION_SIGNATURE,
    DETECTION_SIGNATURE_OPEL,
    EXCLUSION_SIGNATURES,
    HW_SW_PATTERN,
    IDENT_REGION,
    OPEL_M155_IDENT_PATTERN,
    OPEL_M155_IDENT_REGION,
    SUPPORTED_SIZE,
    BoschM1x55Extractor,
)

EXTRACTOR = BoschM1x55Extractor()

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

# Alfa Romeo M1.55 — Alfa 156 2.0 155HP
_ALFA_DESCRIPTOR = b"56/1/M1.55/9/5033/DAMOS161/16DZ204S_E/16DZ204S_E/280798/"
_ALFA_HW = "0261204270"
_ALFA_SW = "1037359650"
_ALFA_ECU_VARIANT = "16DZ204S_E"
_ALFA_DATASET = "5033"
_ALFA_IDENT = b"0261204270 1037359650 46739438   "
# match_key uses ecu_variant (priority over ecu_family) as family_part
_ALFA_MATCH_KEY = "16DZ204S_E::1037359650"

# Alfa Romeo M1.55 — second variant (Alfa 156 / GT)
_ALFA2_DESCRIPTOR = b"47/1/M1.55/8/5122/DAMOS161/16DZ204S_F/16DZ204S_F/040898/"
_ALFA2_HW = "0261204947"
_ALFA2_SW = "1037359649"
_ALFA2_ECU_VARIANT = "16DZ204S_F"
_ALFA2_DATASET = "5122"
_ALFA2_IDENT = b"0261204947 1037359649 46739438   "

# Opel M1.5.5
_OPEL_HW = "0261204058"
_OPEL_SW = "90532609"
_OPEL_IDENT = b"90532609 RY0261204058AB12"
_OPEL_MATCH_KEY = "M1.5.5::90532609"

# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------

# Descriptor region starts at 0x8000; descriptors are placed 5 bytes in
# (0x8005) to match the documented fixed-offset layout.
_DESCRIPTOR_OFFSET = 0x8005

# Ident block is in the last 2KB. We place it at a comfortable offset within
# that region (0x1FC00 = 0x20000 - 0x400).
_IDENT_OFFSET = 0x1FC00

# Opel sig is at the documented position ~0xD82F (inside first 64KB but
# outside the Alfa detection check, which needs DETECTION_SIGNATURE in [:0x10000]).
_OPEL_SIG_OFFSET = 0xD82F

# Opel ident block is in OPEL_M155_IDENT_REGION (0xD000–0xE000); 0xD801
# matches the documented position for the first copy.
_OPEL_IDENT_OFFSET = 0xD801


def make_alfa_m155_bin() -> bytes:
    """Canonical 128KB Alfa Romeo M1.55 bin with full descriptor + HW/SW ident."""
    data = bytearray(b"\xff" * SUPPORTED_SIZE)
    data[_DESCRIPTOR_OFFSET : _DESCRIPTOR_OFFSET + len(_ALFA_DESCRIPTOR)] = (
        _ALFA_DESCRIPTOR
    )
    data[_IDENT_OFFSET : _IDENT_OFFSET + len(_ALFA_IDENT)] = _ALFA_IDENT
    return bytes(data)


def make_alfa_m155_bin_no_ident() -> bytes:
    """128KB Alfa M1.55 with descriptor but NO HW/SW ident block."""
    data = bytearray(b"\xff" * SUPPORTED_SIZE)
    data[_DESCRIPTOR_OFFSET : _DESCRIPTOR_OFFSET + len(_ALFA_DESCRIPTOR)] = (
        _ALFA_DESCRIPTOR
    )
    return bytes(data)


def make_alfa2_m155_bin() -> bytes:
    """128KB second Alfa M1.55 variant with different descriptor and ident."""
    data = bytearray(b"\xff" * SUPPORTED_SIZE)
    data[_DESCRIPTOR_OFFSET : _DESCRIPTOR_OFFSET + len(_ALFA2_DESCRIPTOR)] = (
        _ALFA2_DESCRIPTOR
    )
    data[_IDENT_OFFSET : _IDENT_OFFSET + len(_ALFA2_IDENT)] = _ALFA2_IDENT
    return bytes(data)


def make_opel_m155_bin() -> bytes:
    """128KB Opel M1.5.5 bin with detection token + Opel ident block."""
    data = bytearray(b"\xff" * SUPPORTED_SIZE)
    # Place the Opel detection token
    data[_OPEL_SIG_OFFSET : _OPEL_SIG_OFFSET + len(DETECTION_SIGNATURE_OPEL)] = (
        DETECTION_SIGNATURE_OPEL
    )
    # Place the Opel ident inside OPEL_M155_IDENT_REGION
    data[_OPEL_IDENT_OFFSET : _OPEL_IDENT_OFFSET + len(_OPEL_IDENT)] = _OPEL_IDENT
    return bytes(data)


def make_token_only_bin() -> bytes:
    """128KB bin with only b"M1.55" in the first 64KB — no descriptor, no ident."""
    data = bytearray(b"\xff" * SUPPORTED_SIZE)
    # Place the Alfa token just past the DESCRIPTOR_REGION so the full
    # descriptor regex won't match (there are no slashes around the token).
    tok_offset = 0x9000
    data[tok_offset : tok_offset + len(DETECTION_SIGNATURE)] = DETECTION_SIGNATURE
    return bytes(data)


def make_partial_descriptor_bin() -> bytes:
    """128KB bin with M1.55/... descriptor (no leading 56/1/ revision fields).

    The DESCRIPTOR_PATTERN matches, but the full_m regex (requiring \\d{2}/\\d+/)
    does not. The extractor falls back to splitting the raw match string.
    """
    data = bytearray(b"\xff" * SUPPORTED_SIZE)
    partial = b"M1.55/9/5033/DAMOS161/16DZ204S_E/16DZ204S_E/280798/"
    data[_DESCRIPTOR_OFFSET : _DESCRIPTOR_OFFSET + len(partial)] = partial
    data[_IDENT_OFFSET : _IDENT_OFFSET + len(_ALFA_IDENT)] = _ALFA_IDENT
    return bytes(data)


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

    def test_m155_in_supported_families(self):
        assert "M1.55" in EXTRACTOR.supported_families

    def test_m155_opel_in_supported_families(self):
        assert "M1.5.5" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        assert all(isinstance(f, str) for f in EXTRACTOR.supported_families)

    def test_repr_is_string(self):
        assert isinstance(repr(EXTRACTOR), str)

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschM1x55Extractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# TestCanHandleTrue
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """can_handle() must return True for every valid M1.55 / M1.5.5 input."""

    def test_alfa_m155_accepted(self):
        assert EXTRACTOR.can_handle(make_alfa_m155_bin()) is True

    def test_alfa_m155_no_ident_accepted(self):
        # Detection does not require the HW/SW ident block.
        assert EXTRACTOR.can_handle(make_alfa_m155_bin_no_ident()) is True

    def test_alfa2_m155_accepted(self):
        assert EXTRACTOR.can_handle(make_alfa2_m155_bin()) is True

    def test_opel_m155_accepted(self):
        assert EXTRACTOR.can_handle(make_opel_m155_bin()) is True

    def test_token_only_bin_accepted(self):
        # b"M1.55" anywhere in the first 64KB is enough.
        assert EXTRACTOR.can_handle(make_token_only_bin()) is True

    def test_m155_token_at_last_byte_of_first_64kb_accepted(self):
        # Token ending exactly at offset 0xFFFF is still within the detection window.
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        tok = DETECTION_SIGNATURE
        offset = 0x10000 - len(tok)  # last possible position
        data[offset : offset + len(tok)] = tok
        assert EXTRACTOR.can_handle(bytes(data)) is True

    def test_opel_token_beyond_64kb_accepted(self):
        # M1.5.5 is checked with "in data" (not restricted to first 64KB).
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        offset = 0x18000  # well beyond 64KB
        tok = DETECTION_SIGNATURE_OPEL
        data[offset : offset + len(tok)] = tok
        assert EXTRACTOR.can_handle(bytes(data)) is True

    def test_can_handle_returns_bool(self):
        assert isinstance(EXTRACTOR.can_handle(make_alfa_m155_bin()), bool)


# ---------------------------------------------------------------------------
# TestCanHandleFalse
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    """can_handle() must return False for every non-M1.55 input."""

    def test_empty_binary_rejected(self):
        assert not EXTRACTOR.can_handle(b"")

    def test_all_zero_128kb_rejected(self):
        assert not EXTRACTOR.can_handle(b"\x00" * SUPPORTED_SIZE)

    def test_all_ff_128kb_no_token_rejected(self):
        # Correct size, no detection token.
        assert not EXTRACTOR.can_handle(b"\xff" * SUPPORTED_SIZE)

    def test_256kb_size_rejected(self):
        data = bytearray(b"\xff" * 0x40000)
        # Inject a token so only the size gate blocks it
        data[0x8005 : 0x8005 + len(DETECTION_SIGNATURE)] = DETECTION_SIGNATURE
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_64kb_size_rejected(self):
        data = bytearray(b"\xff" * 0x10000)
        data[0x8005 : 0x8005 + len(DETECTION_SIGNATURE)] = DETECTION_SIGNATURE
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_32kb_size_rejected(self):
        assert not EXTRACTOR.can_handle(b"\xff" * 0x8000)

    def test_512kb_size_rejected(self):
        assert not EXTRACTOR.can_handle(b"\xff" * 0x80000)

    def test_m155_token_beyond_first_64kb_rejected(self):
        # b"M1.55" at offset 0x10001 is past the detection window.
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        offset = 0x10001
        data[offset : offset + len(DETECTION_SIGNATURE)] = DETECTION_SIGNATURE
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_m155_token_in_second_half_rejected(self):
        # Token at 0x18000 (second half) does not satisfy Alfa detection,
        # and no M1.5.5 token is present → rejected.
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        data[0x18000 : 0x18000 + len(DETECTION_SIGNATURE)] = DETECTION_SIGNATURE
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_no_detection_token_128kb_rejected(self):
        # Correct size but neither M1.55 nor M1.5.5 token.
        assert not EXTRACTOR.can_handle(b"\x00" * SUPPORTED_SIZE)

    def test_m15_token_lookalike_not_accepted(self):
        # "M1.5" is not "M1.55" and not "M1.5.5" — should not be accepted.
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        data[0x8005:0x800A] = b"M1.5 "
        assert not EXTRACTOR.can_handle(bytes(data))


# ---------------------------------------------------------------------------
# TestCanHandleExclusions
# ---------------------------------------------------------------------------


class TestCanHandleExclusions:
    """Every EXCLUSION_SIGNATURES entry must block an otherwise-valid bin."""

    def _valid_buf(self) -> bytes:
        return make_alfa_m155_bin()

    def test_exclusion_signatures_list_not_empty(self):
        assert len(EXCLUSION_SIGNATURES) >= 10

    @pytest.mark.parametrize("excl", EXCLUSION_SIGNATURES)
    def test_each_exclusion_sig_rejects_valid_bin(self, excl):
        data = _inject_exclusion(self._valid_buf(), excl)
        assert not EXTRACTOR.can_handle(data)

    def test_edc17_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"EDC17"))

    def test_edc15_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"EDC15"))

    def test_edc16_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"EDC16"))

    def test_me7_dot_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"ME7."))

    def test_motronic_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(
            _inject_exclusion(self._valid_buf(), b"MOTRONIC")
        )

    def test_tsw_space_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(_inject_exclusion(self._valid_buf(), b"TSW "))

    def test_m3_marker_1350000_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(
            _inject_exclusion(self._valid_buf(), b"1350000M3")
        )

    def test_m3_marker_1530000_exclusion_explicit(self):
        assert not EXTRACTOR.can_handle(
            _inject_exclusion(self._valid_buf(), b"1530000M3")
        )

    def test_exclusion_at_offset_zero_caught(self):
        data = _inject_exclusion(self._valid_buf(), b"EDC17")
        assert not EXTRACTOR.can_handle(data)

    def test_exclusion_near_end_still_caught(self):
        data = bytearray(self._valid_buf())
        excl = b"EDC16"
        data[-len(excl) :] = excl
        assert not EXTRACTOR.can_handle(bytes(data))

    def test_exclusion_overrides_alfa2_valid_bin(self):
        assert not EXTRACTOR.can_handle(
            _inject_exclusion(make_alfa2_m155_bin(), b"MEDC17")
        )

    def test_exclusion_overrides_opel_valid_bin(self):
        assert not EXTRACTOR.can_handle(
            _inject_exclusion(make_opel_m155_bin(), b"EDC15")
        )


# ---------------------------------------------------------------------------
# TestParseDescriptor
# ---------------------------------------------------------------------------


class TestParseDescriptor:
    """Unit tests for BoschM1x55Extractor._parse_descriptor()."""

    def test_returns_family_for_alfa_bin(self):
        result = EXTRACTOR._parse_descriptor(make_alfa_m155_bin())
        assert result["family"] == "M1.55"

    def test_returns_dataset_for_alfa_bin(self):
        result = EXTRACTOR._parse_descriptor(make_alfa_m155_bin())
        assert result["dataset"] == _ALFA_DATASET

    def test_returns_ecu_variant_for_alfa_bin(self):
        result = EXTRACTOR._parse_descriptor(make_alfa_m155_bin())
        assert result["ecu_variant"] == _ALFA_ECU_VARIANT

    def test_returns_family_for_alfa2_bin(self):
        result = EXTRACTOR._parse_descriptor(make_alfa2_m155_bin())
        assert result["family"] == "M1.55"

    def test_returns_dataset_for_alfa2_bin(self):
        result = EXTRACTOR._parse_descriptor(make_alfa2_m155_bin())
        assert result["dataset"] == _ALFA2_DATASET

    def test_returns_ecu_variant_for_alfa2_bin(self):
        result = EXTRACTOR._parse_descriptor(make_alfa2_m155_bin())
        assert result["ecu_variant"] == _ALFA2_ECU_VARIANT

    def test_partial_descriptor_returns_family(self):
        # "M1.55/..." without leading revision fields → DESCRIPTOR_PATTERN matches
        # but full_m fails → extractor parses from the partial raw match.
        result = EXTRACTOR._parse_descriptor(make_partial_descriptor_bin())
        assert result["family"] == "M1.55"

    def test_partial_descriptor_returns_dataset(self):
        result = EXTRACTOR._parse_descriptor(make_partial_descriptor_bin())
        assert result["dataset"] == _ALFA_DATASET

    def test_partial_descriptor_returns_ecu_variant(self):
        result = EXTRACTOR._parse_descriptor(make_partial_descriptor_bin())
        assert result["ecu_variant"] == _ALFA_ECU_VARIANT

    def test_token_only_returns_family_from_fallback(self):
        # Only b"M1.55" in DESCRIPTOR_REGION (no slashes) → DESCRIPTOR_PATTERN
        # fails → fallback rb"M1\.\d+" matches → family set, rest None.
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        data[0x8010:0x8015] = DETECTION_SIGNATURE  # "M1.55" in region
        result = EXTRACTOR._parse_descriptor(bytes(data))
        assert result["family"] == "M1.55"

    def test_token_only_dataset_is_none(self):
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        data[0x8010:0x8015] = DETECTION_SIGNATURE
        result = EXTRACTOR._parse_descriptor(bytes(data))
        assert result["dataset"] is None

    def test_token_only_ecu_variant_is_none(self):
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        data[0x8010:0x8015] = DETECTION_SIGNATURE
        result = EXTRACTOR._parse_descriptor(bytes(data))
        assert result["ecu_variant"] is None

    def test_all_ff_returns_all_none(self):
        result = EXTRACTOR._parse_descriptor(b"\xff" * SUPPORTED_SIZE)
        assert result["family"] is None
        assert result["dataset"] is None
        assert result["ecu_variant"] is None

    def test_all_zero_returns_all_none(self):
        result = EXTRACTOR._parse_descriptor(b"\x00" * SUPPORTED_SIZE)
        assert result["family"] is None
        assert result["dataset"] is None
        assert result["ecu_variant"] is None

    def test_empty_data_returns_all_none(self):
        result = EXTRACTOR._parse_descriptor(b"")
        assert result["family"] is None
        assert result["dataset"] is None
        assert result["ecu_variant"] is None

    def test_returns_dict(self):
        result = EXTRACTOR._parse_descriptor(make_alfa_m155_bin())
        assert isinstance(result, dict)

    def test_dict_has_expected_keys(self):
        result = EXTRACTOR._parse_descriptor(make_alfa_m155_bin())
        assert "family" in result
        assert "dataset" in result
        assert "ecu_variant" in result


# ---------------------------------------------------------------------------
# TestParseHwSw
# ---------------------------------------------------------------------------


class TestParseHwSw:
    """Unit tests for BoschM1x55Extractor._parse_hw_sw()."""

    def test_returns_hw_for_alfa_bin(self):
        hw, _ = EXTRACTOR._parse_hw_sw(make_alfa_m155_bin())
        assert hw == _ALFA_HW

    def test_returns_sw_for_alfa_bin(self):
        _, sw = EXTRACTOR._parse_hw_sw(make_alfa_m155_bin())
        assert sw == _ALFA_SW

    def test_returns_hw_for_alfa2_bin(self):
        hw, _ = EXTRACTOR._parse_hw_sw(make_alfa2_m155_bin())
        assert hw == _ALFA2_HW

    def test_returns_sw_for_alfa2_bin(self):
        _, sw = EXTRACTOR._parse_hw_sw(make_alfa2_m155_bin())
        assert sw == _ALFA2_SW

    def test_hw_starts_with_0261(self):
        hw, _ = EXTRACTOR._parse_hw_sw(make_alfa_m155_bin())
        assert hw is not None
        assert hw.startswith("0261")

    def test_hw_is_10_digits(self):
        hw, _ = EXTRACTOR._parse_hw_sw(make_alfa_m155_bin())
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_sw_starts_with_1037(self):
        _, sw = EXTRACTOR._parse_hw_sw(make_alfa_m155_bin())
        assert sw is not None
        assert sw.startswith("1037")

    def test_returns_none_none_for_all_ff(self):
        hw, sw = EXTRACTOR._parse_hw_sw(b"\xff" * SUPPORTED_SIZE)
        assert hw is None
        assert sw is None

    def test_returns_none_none_for_all_zero(self):
        hw, sw = EXTRACTOR._parse_hw_sw(b"\x00" * SUPPORTED_SIZE)
        assert hw is None
        assert sw is None

    def test_returns_none_none_for_empty(self):
        hw, sw = EXTRACTOR._parse_hw_sw(b"")
        assert hw is None
        assert sw is None

    def test_returns_none_none_when_no_ident_block(self):
        # Descriptor present but no HW/SW ident → (None, None)
        hw, sw = EXTRACTOR._parse_hw_sw(make_alfa_m155_bin_no_ident())
        assert hw is None
        assert sw is None

    def test_returns_tuple_of_two(self):
        result = EXTRACTOR._parse_hw_sw(make_alfa_m155_bin())
        assert len(result) == 2

    def test_both_strings_when_present(self):
        hw, sw = EXTRACTOR._parse_hw_sw(make_alfa_m155_bin())
        assert isinstance(hw, str)
        assert isinstance(sw, str)


# ---------------------------------------------------------------------------
# TestParseOpelIdent
# ---------------------------------------------------------------------------


class TestParseOpelIdent:
    """Unit tests for BoschM1x55Extractor._parse_opel_m155_ident()."""

    def test_returns_hw_for_opel_bin(self):
        hw, _ = EXTRACTOR._parse_opel_m155_ident(make_opel_m155_bin())
        assert hw == _OPEL_HW

    def test_returns_sw_for_opel_bin(self):
        _, sw = EXTRACTOR._parse_opel_m155_ident(make_opel_m155_bin())
        assert sw == _OPEL_SW

    def test_hw_starts_with_0261(self):
        hw, _ = EXTRACTOR._parse_opel_m155_ident(make_opel_m155_bin())
        assert hw is not None
        assert hw.startswith("0261")

    def test_hw_is_10_digits(self):
        hw, _ = EXTRACTOR._parse_opel_m155_ident(make_opel_m155_bin())
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_sw_is_8_digits(self):
        _, sw = EXTRACTOR._parse_opel_m155_ident(make_opel_m155_bin())
        assert sw is not None
        assert len(sw) == 8
        assert sw.isdigit()

    def test_returns_none_none_for_all_ff(self):
        hw, sw = EXTRACTOR._parse_opel_m155_ident(b"\xff" * SUPPORTED_SIZE)
        assert hw is None
        assert sw is None

    def test_returns_none_none_for_all_zero(self):
        hw, sw = EXTRACTOR._parse_opel_m155_ident(b"\x00" * SUPPORTED_SIZE)
        assert hw is None
        assert sw is None

    def test_returns_none_none_for_empty(self):
        hw, sw = EXTRACTOR._parse_opel_m155_ident(b"")
        assert hw is None
        assert sw is None

    def test_returns_none_none_for_alfa_bin(self):
        # Alfa bin has no Opel ident in OPEL_M155_IDENT_REGION
        hw, sw = EXTRACTOR._parse_opel_m155_ident(make_alfa_m155_bin())
        assert hw is None
        assert sw is None

    def test_returns_tuple_of_two(self):
        result = EXTRACTOR._parse_opel_m155_ident(make_opel_m155_bin())
        assert len(result) == 2

    def test_ident_outside_region_not_detected(self):
        # Ident placed outside OPEL_M155_IDENT_REGION (0xD000–0xE000).
        data = bytearray(b"\xff" * SUPPORTED_SIZE)
        ident = _OPEL_IDENT
        offset = 0x5000  # outside region
        data[offset : offset + len(ident)] = ident
        hw, sw = EXTRACTOR._parse_opel_m155_ident(bytes(data))
        assert hw is None
        assert sw is None


# ---------------------------------------------------------------------------
# TestExtractRequiredKeys
# ---------------------------------------------------------------------------


class TestExtractRequiredKeys:
    """extract() must always return every required key, regardless of variant."""

    def _check(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data)

    def test_required_keys_alfa(self):
        result = self._check(make_alfa_m155_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_alfa_no_ident(self):
        result = self._check(make_alfa_m155_bin_no_ident())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_alfa2(self):
        result = self._check(make_alfa2_m155_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_opel(self):
        result = self._check(make_opel_m155_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_manufacturer_always_bosch_alfa(self):
        assert self._check(make_alfa_m155_bin())["manufacturer"] == "Bosch"

    def test_manufacturer_always_bosch_opel(self):
        assert self._check(make_opel_m155_bin())["manufacturer"] == "Bosch"

    def test_file_size_equals_data_length_alfa(self):
        data = make_alfa_m155_bin()
        assert self._check(data)["file_size"] == len(data)

    def test_file_size_equals_data_length_opel(self):
        data = make_opel_m155_bin()
        assert self._check(data)["file_size"] == len(data)

    def test_file_size_is_128kb_alfa(self):
        assert self._check(make_alfa_m155_bin())["file_size"] == SUPPORTED_SIZE

    def test_file_size_is_128kb_opel(self):
        assert self._check(make_opel_m155_bin())["file_size"] == SUPPORTED_SIZE

    def test_raw_strings_is_list_alfa(self):
        assert isinstance(self._check(make_alfa_m155_bin())["raw_strings"], list)

    def test_raw_strings_is_list_opel(self):
        assert isinstance(self._check(make_opel_m155_bin())["raw_strings"], list)


# ---------------------------------------------------------------------------
# TestExtractAlfa
# ---------------------------------------------------------------------------


class TestExtractAlfa:
    """Full extraction checks for the canonical Alfa Romeo M1.55 bin."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_alfa_m155_bin())

    def test_ecu_family_is_m155(self):
        assert self.result["ecu_family"] == "M1.55"

    def test_ecu_variant_is_descriptor_variant(self):
        assert self.result["ecu_variant"] == _ALFA_ECU_VARIANT

    def test_dataset_number(self):
        assert self.result["dataset_number"] == _ALFA_DATASET

    def test_calibration_id_equals_ecu_variant(self):
        # extract() sets calibration_id = descriptor["ecu_variant"]
        assert self.result["calibration_id"] == _ALFA_ECU_VARIANT

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _ALFA_HW

    def test_hardware_number_starts_with_0261(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert hw.startswith("0261")

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_software_version(self):
        assert self.result["software_version"] == _ALFA_SW

    def test_software_version_starts_with_1037(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert sw.startswith("1037")

    def test_match_key(self):
        assert self.result["match_key"] == _ALFA_MATCH_KEY

    def test_match_key_is_uppercase(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk == mk.upper()

    def test_match_key_uses_ecu_variant_as_family_part(self):
        # build_match_key prefers ecu_variant over ecu_family
        mk = self.result["match_key"]
        assert mk is not None
        assert mk.startswith(_ALFA_ECU_VARIANT + "::")

    def test_match_key_suffix_is_sw(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk.endswith(_ALFA_SW)

    def test_match_key_separator_is_double_colon(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert "::" in mk

    def test_raw_strings_not_empty(self):
        # The HW/SW ident sits in the last 2KB (IDENT_REGION); both numbers appear.
        assert len(self.result["raw_strings"]) > 0

    def test_file_size_is_128kb(self):
        assert self.result["file_size"] == SUPPORTED_SIZE


# ---------------------------------------------------------------------------
# TestExtractAlfa2
# ---------------------------------------------------------------------------


class TestExtractAlfa2:
    """Extraction for the second Alfa M1.55 variant."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_alfa2_m155_bin())

    def test_ecu_family_is_m155(self):
        assert self.result["ecu_family"] == "M1.55"

    def test_ecu_variant_is_alfa2_variant(self):
        assert self.result["ecu_variant"] == _ALFA2_ECU_VARIANT

    def test_dataset_number(self):
        assert self.result["dataset_number"] == _ALFA2_DATASET

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _ALFA2_HW

    def test_software_version(self):
        assert self.result["software_version"] == _ALFA2_SW

    def test_match_key_uses_alfa2_variant(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk.startswith(_ALFA2_ECU_VARIANT + "::")
        assert mk.endswith(_ALFA2_SW)

    def test_match_key_differs_from_alfa1(self):
        alfa1_mk = EXTRACTOR.extract(make_alfa_m155_bin())["match_key"]
        assert self.result["match_key"] != alfa1_mk


# ---------------------------------------------------------------------------
# TestExtractAlfaNoIdent
# ---------------------------------------------------------------------------


class TestExtractAlfaNoIdent:
    """Extraction for an Alfa M1.55 bin that has a descriptor but no HW/SW ident."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_alfa_m155_bin_no_ident())

    def test_ecu_family_is_m155(self):
        assert self.result["ecu_family"] == "M1.55"

    def test_ecu_variant_from_descriptor(self):
        assert self.result["ecu_variant"] == _ALFA_ECU_VARIANT

    def test_dataset_number_from_descriptor(self):
        assert self.result["dataset_number"] == _ALFA_DATASET

    def test_hardware_number_is_none(self):
        assert self.result["hardware_number"] is None

    def test_software_version_is_none(self):
        assert self.result["software_version"] is None

    def test_match_key_is_none_without_sw(self):
        # No software_version → build_match_key returns None
        assert self.result["match_key"] is None


# ---------------------------------------------------------------------------
# TestExtractOpel
# ---------------------------------------------------------------------------


class TestExtractOpel:
    """Full extraction checks for the Opel M1.5.5 bin."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_opel_m155_bin())

    def test_ecu_family_is_m155_opel(self):
        assert self.result["ecu_family"] == "M1.5.5"

    def test_ecu_variant_is_none(self):
        # Opel path does not populate ecu_variant
        assert self.result["ecu_variant"] is None

    def test_dataset_number_is_none(self):
        assert self.result["dataset_number"] is None

    def test_calibration_id_is_none(self):
        assert self.result["calibration_id"] is None

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _OPEL_HW

    def test_hardware_number_starts_with_0261(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert hw.startswith("0261")

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_software_version(self):
        assert self.result["software_version"] == _OPEL_SW

    def test_software_version_is_8_digits(self):
        sw = self.result["software_version"]
        assert sw is not None
        assert len(sw) == 8
        assert sw.isdigit()

    def test_match_key(self):
        assert self.result["match_key"] == _OPEL_MATCH_KEY

    def test_match_key_uses_ecu_family_as_family_part(self):
        # ecu_variant is None, so build_match_key falls back to ecu_family
        mk = self.result["match_key"]
        assert mk is not None
        assert mk.startswith("M1.5.5::")

    def test_match_key_suffix_is_sw(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk.endswith(_OPEL_SW)

    def test_match_key_is_uppercase(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert mk == mk.upper()

    def test_file_size_is_128kb(self):
        assert self.result["file_size"] == SUPPORTED_SIZE


# ---------------------------------------------------------------------------
# TestExtractNullFields
# ---------------------------------------------------------------------------


class TestExtractNullFields:
    """Fields absent from M1.55 / M1.5.5 binaries must always be None."""

    def _alfa(self) -> dict:
        return EXTRACTOR.extract(make_alfa_m155_bin())

    def _opel(self) -> dict:
        return EXTRACTOR.extract(make_opel_m155_bin())

    def test_calibration_version_is_none_alfa(self):
        assert self._alfa()["calibration_version"] is None

    def test_calibration_version_is_none_opel(self):
        assert self._opel()["calibration_version"] is None

    def test_sw_base_version_is_none_alfa(self):
        assert self._alfa()["sw_base_version"] is None

    def test_sw_base_version_is_none_opel(self):
        assert self._opel()["sw_base_version"] is None

    def test_serial_number_is_none_alfa(self):
        assert self._alfa()["serial_number"] is None

    def test_serial_number_is_none_opel(self):
        assert self._opel()["serial_number"] is None

    def test_oem_part_number_is_none_alfa(self):
        assert self._alfa()["oem_part_number"] is None

    def test_oem_part_number_is_none_opel(self):
        assert self._opel()["oem_part_number"] is None

    def test_calibration_version_is_none_alfa2(self):
        assert EXTRACTOR.extract(make_alfa2_m155_bin())["calibration_version"] is None

    def test_sw_base_version_is_none_alfa2(self):
        assert EXTRACTOR.extract(make_alfa2_m155_bin())["sw_base_version"] is None

    def test_serial_number_is_none_alfa2(self):
        assert EXTRACTOR.extract(make_alfa2_m155_bin())["serial_number"] is None

    def test_oem_part_number_is_none_alfa2(self):
        assert EXTRACTOR.extract(make_alfa2_m155_bin())["oem_part_number"] is None

    def test_ecu_variant_is_none_opel(self):
        assert self._opel()["ecu_variant"] is None

    def test_dataset_number_is_none_opel(self):
        assert self._opel()["dataset_number"] is None

    def test_calibration_id_is_none_opel(self):
        assert self._opel()["calibration_id"] is None


# ---------------------------------------------------------------------------
# TestExtractHashing
# ---------------------------------------------------------------------------


class TestExtractHashing:
    """md5 and sha256_first_64kb must be computed correctly."""

    def _r(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data)

    def test_md5_is_32_hex_chars_alfa(self):
        result = self._r(make_alfa_m155_bin())
        assert len(result["md5"]) == 32

    def test_md5_only_hex_digits_alfa(self):
        result = self._r(make_alfa_m155_bin())
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_correct_alfa(self):
        data = make_alfa_m155_bin()
        assert self._r(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_alfa2(self):
        data = make_alfa2_m155_bin()
        assert self._r(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_opel(self):
        data = make_opel_m155_bin()
        assert self._r(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_is_64_hex_chars_alfa(self):
        assert len(self._r(make_alfa_m155_bin())["sha256_first_64kb"]) == 64

    def test_sha256_covers_first_64kb_only(self):
        data = make_alfa_m155_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._r(data)["sha256_first_64kb"] == expected

    def test_sha256_correct_alfa2(self):
        data = make_alfa2_m155_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._r(data)["sha256_first_64kb"] == expected

    def test_sha256_correct_opel(self):
        data = make_opel_m155_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._r(data)["sha256_first_64kb"] == expected

    def test_different_bins_different_md5(self):
        r1 = self._r(make_alfa_m155_bin())
        r2 = self._r(make_alfa2_m155_bin())
        assert r1["md5"] != r2["md5"]

    def test_alfa_and_opel_different_md5(self):
        r1 = self._r(make_alfa_m155_bin())
        r2 = self._r(make_opel_m155_bin())
        assert r1["md5"] != r2["md5"]

    def test_alfa_and_opel_different_sha256(self):
        r1 = self._r(make_alfa_m155_bin())
        r2 = self._r(make_opel_m155_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]


# ---------------------------------------------------------------------------
# TestMatchKey
# ---------------------------------------------------------------------------


class TestMatchKey:
    """match_key must be formatted correctly, uppercase, and None when SW absent."""

    def _r(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data)

    def test_match_key_is_none_when_no_sw_and_no_ident(self):
        # Token-only bin: descriptor has no ecu_variant as variant, no HW/SW ident
        # → sw=None → match_key=None
        result = EXTRACTOR.extract(make_alfa_m155_bin_no_ident())
        assert result["match_key"] is None

    def test_match_key_alfa_format(self):
        assert self._r(make_alfa_m155_bin())["match_key"] == _ALFA_MATCH_KEY

    def test_match_key_alfa2_format(self):
        result = self._r(make_alfa2_m155_bin())
        expected = f"{_ALFA2_ECU_VARIANT}::{_ALFA2_SW}"
        assert result["match_key"] == expected

    def test_match_key_opel_format(self):
        assert self._r(make_opel_m155_bin())["match_key"] == _OPEL_MATCH_KEY

    def test_match_key_alfa_is_uppercase(self):
        mk = self._r(make_alfa_m155_bin())["match_key"]
        assert mk is not None
        assert mk == mk.upper()

    def test_match_key_opel_is_uppercase(self):
        mk = self._r(make_opel_m155_bin())["match_key"]
        assert mk is not None
        assert mk == mk.upper()

    def test_match_key_contains_double_colon_alfa(self):
        mk = self._r(make_alfa_m155_bin())["match_key"]
        assert mk is not None
        assert "::" in mk

    def test_match_key_contains_double_colon_opel(self):
        mk = self._r(make_opel_m155_bin())["match_key"]
        assert mk is not None
        assert "::" in mk

    def test_match_key_has_exactly_one_separator_alfa(self):
        mk = self._r(make_alfa_m155_bin())["match_key"]
        assert mk is not None
        assert mk.count("::") == 1

    def test_alfa_and_opel_match_keys_differ(self):
        mk_alfa = self._r(make_alfa_m155_bin())["match_key"]
        mk_opel = self._r(make_opel_m155_bin())["match_key"]
        assert mk_alfa != mk_opel

    def test_alfa1_and_alfa2_match_keys_differ(self):
        mk1 = self._r(make_alfa_m155_bin())["match_key"]
        mk2 = self._r(make_alfa2_m155_bin())["match_key"]
        assert mk1 != mk2


# ---------------------------------------------------------------------------
# TestDeterminism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """extract() must be deterministic and filename-independent."""

    def test_same_binary_same_result_alfa(self):
        data = make_alfa_m155_bin()
        assert EXTRACTOR.extract(data) == EXTRACTOR.extract(data)

    def test_same_binary_same_result_opel(self):
        data = make_opel_m155_bin()
        assert EXTRACTOR.extract(data) == EXTRACTOR.extract(data)

    def test_same_binary_same_result_alfa2(self):
        data = make_alfa2_m155_bin()
        assert EXTRACTOR.extract(data) == EXTRACTOR.extract(data)

    def test_filename_does_not_affect_alfa_fields(self):
        data = make_alfa_m155_bin()
        r1 = EXTRACTOR.extract(data, "alfa_156.bin")
        r2 = EXTRACTOR.extract(data, "copy_of_file.bin")
        for key in ("hardware_number", "software_version", "ecu_family", "match_key"):
            assert r1[key] == r2[key]

    def test_filename_does_not_affect_opel_fields(self):
        data = make_opel_m155_bin()
        r1 = EXTRACTOR.extract(data, "opel.bin")
        r2 = EXTRACTOR.extract(data, "renamed.bin")
        for key in ("hardware_number", "software_version", "ecu_family", "match_key"):
            assert r1[key] == r2[key]

    def test_different_binaries_produce_different_md5(self):
        r1 = EXTRACTOR.extract(make_alfa_m155_bin())
        r2 = EXTRACTOR.extract(make_opel_m155_bin())
        assert r1["md5"] != r2["md5"]

    def test_file_size_reflects_actual_binary_size_alfa(self):
        assert EXTRACTOR.extract(make_alfa_m155_bin())["file_size"] == SUPPORTED_SIZE

    def test_file_size_reflects_actual_binary_size_opel(self):
        assert EXTRACTOR.extract(make_opel_m155_bin())["file_size"] == SUPPORTED_SIZE

    def test_can_handle_then_extract_alfa_consistent(self):
        data = make_alfa_m155_bin()
        assert EXTRACTOR.can_handle(data)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == _ALFA_HW
        assert result["software_version"] == _ALFA_SW
        assert result["ecu_family"] == "M1.55"

    def test_can_handle_then_extract_alfa2_consistent(self):
        data = make_alfa2_m155_bin()
        assert EXTRACTOR.can_handle(data)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == _ALFA2_HW
        assert result["software_version"] == _ALFA2_SW

    def test_can_handle_then_extract_opel_consistent(self):
        data = make_opel_m155_bin()
        assert EXTRACTOR.can_handle(data)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] == _OPEL_HW
        assert result["software_version"] == _OPEL_SW
        assert result["ecu_family"] == "M1.5.5"
