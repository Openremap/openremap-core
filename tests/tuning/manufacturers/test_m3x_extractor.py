"""
Tests for BoschM3xExtractor (M3.1 / M3.3 / MP3.2 / MP7.2 / MP3.x-PSA).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * b'1350000M3' detection signature  (M3.1)
      * b'1530000M3' detection signature  (M3.3 / MP7.2)
      * b'0000000M3' detection signature  (MP3.2 / MP3.x-PSA)
  - can_handle() — False paths:
      * Empty binary
      * All-zero binary (no detection signature)
      * Every exclusion signature blocks detection
  - _resolve_ecu_family() — all five sub-families + None fallback
  - extract() — M3.1 sub-extractor:
      * HW / SW decoded from reversed-digit ident in last 2KB
      * DME code from last 1KB
      * match_key == "M3.1::<sw>"
      * Ident with optional .XX decimal suffix correctly stripped
      * No ident / no DME → hw=sw=cal=None, match_key=None
  - extract() — M3.3 combined path (32KB and 64KB):
      * DME immediately followed by ident in last 1KB → combined regex succeeds
      * HW / SW / cal correctly decoded
  - extract() — M3.3 fallback path:
      * DME and ident separated by non-digit bytes in last 2KB
      * Combined regex fails, fallback searches each field independently
  - extract() — M3.3 all-0xFF last 1KB:
      * hw=sw=cal=None, match_key=None (real MP7.2 / empty bin scenario)
  - extract() — MP7.2 sub-extractor:
      * HW detected from repeated consecutive pattern (0261xxxxxx × 2)
      * SW detected from PSA calibration block
      * cal_id is the full PSA calibration string
      * match_key == "MP7.2::<sw>"
      * Graceful None when HW repeated pattern absent
      * Graceful None when cal block absent or SW not in cal block
  - extract() — MP3.2 Layout A (backward walk ≥ 20 digits):
      * Digits immediately before marker → walk collects 27-char run
      * HW / SW decoded from first 20 chars of run
      * PSA cal block used as cal_id
  - extract() — MP3.2 Layout B (backward walk < 20 digits, file-wide fallback):
      * Non-digit byte before marker → walk yields only 7 zeros
      * File-wide scan finds isolated 20-digit run validated by HW/SW prefixes
  - extract() — MP3.x-PSA:
      * Same ident logic as MP3.2 but ecu_family == "MP3.x-PSA"
  - extract() — required keys always present for every sub-family
  - extract() — hash correctness (md5, sha256_first_64kb)
  - _resolve_hardware_number() edge cases (None, too short, wrong prefix, dot suffix)
  - _resolve_software_version() edge cases (None, too short, wrong prefix, 2227 prefix)
  - Determinism and filename independence
"""

import hashlib

import pytest

from openremap.core.manufacturers.bosch.m3x.extractor import BoschM3xExtractor

EXTRACTOR = BoschM3xExtractor()

# Required keys every extract() call must return.
REQUIRED_EXTRACT_KEYS = {
    "manufacturer",
    "match_key",
    "ecu_family",
    "ecu_variant",
    "software_version",
    "hardware_number",
    "calibration_id",
    "oem_part_number",
    "file_size",
    "md5",
    "sha256_first_64kb",
}

# ---------------------------------------------------------------------------
# Ident encoding reference
# ---------------------------------------------------------------------------
# For hw = "0261200520", sw = "1267357220":
#   hw_reversed = "0250021620"   (ident_clean[0:10])
#   sw_reversed = "0227537621"   (ident_clean[10:20])
#   28-digit ident = "0250021620" + "0227537621" + "00000000"
#              = b"0250021620022753762100000000"
_IDENT_28 = b"0250021620022753762100000000"
_HW_EXPECTED = "0261200520"
_SW_EXPECTED = "1267357220"

# For hw = "0261200218", sw = "1267357390"  (PSA Layout A):
#   hw_reversed = "8120021620"   (ident_clean[0:10])
#   sw_reversed = "0937537621"   (ident_clean[10:20])
_PSA_IDENT_27 = (
    b"81200216200937537621"  # 20 digits before marker; marker adds 7 zeros → 27 total
)
_PSA_HW_EXPECTED = "0261200218"
_PSA_SW_EXPECTED = "1267357390"

# For Layout B / isolated 20-digit run: hw="0261200203", sw="1267357220"
#   hw_reversed = "3020021620"
#   sw_reversed = "0227537621"
_PSA_B_IDENT_20 = b"30200216200227537621"
_PSA_B_HW_EXPECTED = "0261200203"
_PSA_B_SW_EXPECTED = "1267357220"

# PSA calibration block (dme_code for PSA families)
_PSA_CAL = b"18/3/MP3.2/ABCDE"
_PSA_CAL_STR = "18/3/MP3.2/ABCDE"

# MP7.2 fields
_MP72_HW_BYTES = b"02612062140261206214"  # "0261206214" repeated twice
_MP72_HW_EXPECTED = "0261206214"
_MP72_SW_EXPECTED = "1037350812"
_MP72_CAL = b"45/1/MP7.2/3/14/1037350812"
_MP72_CAL_STR = "45/1/MP7.2/3/14/1037350812"


# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------


def make_m31_bin(with_ident: bool = True, dot_suffix: bool = False) -> bytes:
    """
    M3.1: 32KB, marker b'1350000M3' at 0x005C.

    Ident placed in last 2KB (but NOT in last 1KB) at position -1800.
    DME code placed in last 1KB at position -800.

    Args:
        with_ident: if False, leaves last 2KB all-zero (no ident / no DME).
        dot_suffix: if True, appends ".05" to the ident (tests suffix stripping).
    """
    buf = bytearray(0x8000)  # 32KB
    buf[0x005C : 0x005C + 9] = b"1350000M3"

    if with_ident:
        ident = _IDENT_28 + (b".05" if dot_suffix else b"")
        buf[-1800 : -1800 + len(ident)] = ident
        buf[-800 : -800 + 12] = b"011/135 4321"

    return bytes(buf)


def make_m33_32kb_bin(with_ident: bool = True) -> bytes:
    """
    M3.3: 32KB, marker b'1530000M3' at 0x0084.

    Combined DME+ident block placed in last 1KB at position -800 so the
    combined regex fires on the first pass (DME immediately before ident).
    """
    buf = bytearray(0x8000)
    buf[0x0084 : 0x0084 + 9] = b"1530000M3"

    if with_ident:
        block = b"012/413 5678" + _IDENT_28
        buf[-800 : -800 + len(block)] = block

    return bytes(buf)


def make_m33_64kb_bin() -> bytes:
    """
    M3.3: 64KB, marker b'1530000M3' at 0x4002 (typical for 64KB M3.3 bins).
    Combined DME+ident block in last 1KB.
    """
    buf = bytearray(0x10000)
    buf[0x4002 : 0x4002 + 9] = b"1530000M3"
    block = b"013/413 9876" + _IDENT_28
    buf[-800 : -800 + len(block)] = block
    return bytes(buf)


def make_m33_fallback_bin() -> bytes:
    """
    M3.3: 32KB, DME and ident separated (non-adjacent) in last 1KB.

    Combined regex fails; fallback searches last 2KB for each field
    independently.
    """
    buf = bytearray(0x8000)
    buf[0x0084 : 0x0084 + 9] = b"1530000M3"
    # DME at -800, separated from ident by ~388 NUL bytes
    buf[-800 : -800 + 12] = b"012/413 5678"
    # Ident at -400, not adjacent to DME
    buf[-400 : -400 + 28] = _IDENT_28
    return bytes(buf)


def make_m33_all_ff_bin() -> bytes:
    """
    M3.3: 32KB, last 1KB filled with 0xFF.

    Simulates bins where the trailing region is erased EPROM — no ident
    or DME can be decoded → hw=sw=cal=None.
    """
    buf = bytearray(0x8000)
    buf[0x0084 : 0x0084 + 9] = b"1530000M3"
    buf[-1024:] = b"\xff" * 1024
    return bytes(buf)


def make_mp72_bin(
    with_hw: bool = True, with_cal: bool = True, sw_in_cal: bool = True
) -> bytes:
    """
    MP7.2: 256KB, b'1530000M3' + b'MP7.2' markers.

    HW: "0261206214" stored twice in a row at 0x1000.
    Cal block: PSA format containing SW "1037350812" at 0x2000.
    Last 1KB: all 0xFF (typical MP7.2).

    Args:
        with_hw:    if False, omit the repeated HW pattern.
        with_cal:   if False, omit the cal block entirely.
        sw_in_cal:  if False, write a cal block that has no "1037"/"2227" SW number.
    """
    buf = bytearray(0x40000)  # 256KB
    buf[0x0100:0x0109] = b"1530000M3"
    buf[0x0200:0x0205] = b"MP7.2"

    if with_hw:
        buf[0x1000:0x1014] = _MP72_HW_BYTES  # "0261206214" × 2

    if with_cal:
        cal = _MP72_CAL if sw_in_cal else b"45/1/MP7.2/3/14/ABCDEFGHIJ"
        buf[0x2000 : 0x2000 + len(cal)] = cal

    # Real MP7.2 bins have the last 1KB full of 0xFF
    buf[-1024:] = b"\xff" * 1024
    return bytes(buf)


def make_mp32_layout_a_bin() -> bytes:
    """
    MP3.2 Layout A: 32KB, b'0000000M3' at 0x1FF2.

    Twenty digits placed immediately before the marker.
    Backward walk from 'M' collects: 20 digits + the 7 zeros of the
    marker prefix = 27-digit run → ident_num = 27-char string.

    hw = _PSA_HW_EXPECTED, sw = _PSA_SW_EXPECTED.
    """
    buf = bytearray(0x8000)
    marker_off = 0x1FF2
    buf[marker_off : marker_off + 9] = b"0000000M3"

    # 20 digits immediately before the marker start
    buf[marker_off - 20 : marker_off] = _PSA_IDENT_27  # exactly 20 bytes
    buf[marker_off - 21] = 0xFF  # non-digit delimiter before the 20-digit run

    # MP3.2 sub-family tag
    buf[0x0100:0x0105] = b"MP3.2"

    # PSA calibration block (used as dme_code)
    buf[0x0300 : 0x0300 + len(_PSA_CAL)] = _PSA_CAL

    return bytes(buf)


def make_mp32_layout_b_bin() -> bytes:
    """
    MP3.2 Layout B (fallback): 32KB, b'0000000M3' at 0x4F28.

    A non-digit byte (0x22 = '"') sits immediately before the marker,
    so the backward walk only collects the 7 zeros of the marker prefix
    (7 chars < 20) — the Layout B fallback scan is triggered.

    An isolated 20-digit ident at 0x1F02 (bounded by 0xFF delimiters)
    carries hw=_PSA_B_HW_EXPECTED, sw=_PSA_B_SW_EXPECTED.
    """
    buf = bytearray(0x8000)
    marker_off = 0x4F28
    buf[marker_off : marker_off + 9] = b"0000000M3"
    buf[marker_off - 1] = 0x22  # '"' — not a digit, stops backward walk

    # Isolated 20-digit ident with non-digit boundaries
    buf[0x1F01] = 0xFF
    buf[0x1F02:0x1F16] = _PSA_B_IDENT_20  # 20 bytes
    buf[0x1F16] = 0xFF

    buf[0x0100:0x0105] = b"MP3.2"
    buf[0x0200 : 0x0200 + len(_PSA_CAL)] = _PSA_CAL

    return bytes(buf)


def make_mp3x_psa_bin() -> bytes:
    """
    MP3.x-PSA: identical layout to MP3.2 Layout A but without the b'MP3.2' tag.
    ecu_family resolves to "MP3.x-PSA".
    """
    buf = bytearray(0x8000)
    marker_off = 0x1FF2
    buf[marker_off : marker_off + 9] = b"0000000M3"
    buf[marker_off - 20 : marker_off] = _PSA_IDENT_27
    buf[marker_off - 21] = 0xFF
    # NO MP3.2 tag
    psa_cal = b"18/3/MP3.1/ABCDE"
    buf[0x0300 : 0x0300 + len(psa_cal)] = psa_cal
    return bytes(buf)


def _inject_exclusion(buf: bytearray, sig: bytes, offset: int = 0x0200) -> bytearray:
    """Write an exclusion signature at a given offset into a mutable buffer."""
    buf[offset : offset + len(sig)] = sig
    return buf


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

    def test_m31_in_supported_families(self):
        assert "M3.1" in EXTRACTOR.supported_families

    def test_m33_in_supported_families(self):
        assert "M3.3" in EXTRACTOR.supported_families

    def test_mp32_in_supported_families(self):
        assert "MP3.2" in EXTRACTOR.supported_families

    def test_mp72_in_supported_families(self):
        assert "MP7.2" in EXTRACTOR.supported_families

    def test_mp3x_psa_in_supported_families(self):
        assert "MP3.x-PSA" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschM3xExtractor" in repr(EXTRACTOR)

    def test_repr_is_string(self):
        assert isinstance(repr(EXTRACTOR), str)


# ---------------------------------------------------------------------------
# can_handle() — True paths
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    def test_m31_marker_accepted(self):
        buf = bytearray(0x8000)
        buf[0x005C:0x0065] = b"1350000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_m33_marker_accepted(self):
        buf = bytearray(0x8000)
        buf[0x0084:0x008D] = b"1530000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_psa_marker_accepted(self):
        buf = bytearray(0x8000)
        buf[0x1000:0x1009] = b"0000000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_mp72_256kb_with_m33_marker_accepted(self):
        assert EXTRACTOR.can_handle(make_mp72_bin()) is True

    def test_m31_marker_at_different_offset(self):
        """Detection searches first 512KB so any position within that is fine."""
        buf = bytearray(0x8000)
        buf[0x7000:0x7009] = b"1350000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_multiple_detection_sigs_still_true(self):
        """Having more than one detection signature is valid."""
        buf = bytearray(0x10000)
        buf[0x0100:0x0109] = b"1350000M3"
        buf[0x0200:0x0209] = b"1530000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_full_m31_bin_accepted(self):
        assert EXTRACTOR.can_handle(make_m31_bin()) is True

    def test_full_m33_32kb_bin_accepted(self):
        assert EXTRACTOR.can_handle(make_m33_32kb_bin()) is True

    def test_full_m33_64kb_bin_accepted(self):
        assert EXTRACTOR.can_handle(make_m33_64kb_bin()) is True

    def test_full_mp72_bin_accepted(self):
        assert EXTRACTOR.can_handle(make_mp72_bin()) is True

    def test_full_mp32_layout_a_accepted(self):
        assert EXTRACTOR.can_handle(make_mp32_layout_a_bin()) is True

    def test_full_mp32_layout_b_accepted(self):
        assert EXTRACTOR.can_handle(make_mp32_layout_b_bin()) is True

    def test_full_mp3x_psa_accepted(self):
        assert EXTRACTOR.can_handle(make_mp3x_psa_bin()) is True


# ---------------------------------------------------------------------------
# can_handle() — False paths
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    def test_empty_binary_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_all_zero_32kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x8000)) is False

    def test_all_zero_64kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x10000)) is False

    def test_all_ff_32kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\xff" * 0x8000) is False

    def test_random_ascii_no_marker_rejected(self):
        buf = bytearray(0x8000)
        buf[0x0100:0x0110] = b"HELLO WORLD 1234"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_partial_m31_marker_rejected(self):
        """'1350000M' without the trailing '3' must not trigger detection."""
        buf = bytearray(0x8000)
        buf[0x0100:0x0108] = b"1350000M"  # 8 bytes, not 9
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_detection_sig_beyond_512kb_ignored(self):
        """Detection only searches first 512KB (0x80000 bytes)."""
        buf = bytearray(0x90000)  # 576KB
        # Place marker just past the 512KB search boundary
        buf[0x80010:0x80019] = b"1350000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# can_handle() — Exclusion signatures
# ---------------------------------------------------------------------------


class TestCanHandleExclusions:
    """Phase 1 exclusions must suppress any M3.x positive detection."""

    def _base(self) -> bytearray:
        """Valid M3.1 base buffer to inject exclusions into."""
        return bytearray(make_m31_bin())

    def test_edc17_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_medc17_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"MEDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_med17_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"MED17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me17_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"ME17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc16_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"EDC16")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_sb_v_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"SB_V")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_customer_dot_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"Customer.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_dot_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"ME7.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me71_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"ME71")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_motronic_exclusion(self):
        buf = self._base()
        _inject_exclusion(buf, b"MOTRONIC")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_m33_marker(self):
        buf = bytearray(make_m33_32kb_bin())
        _inject_exclusion(buf, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_psa_marker(self):
        buf = bytearray(make_mp32_layout_a_bin())
        _inject_exclusion(buf, b"MOTRONIC")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_at_offset_zero(self):
        """Exclusion at the very first byte must still be caught."""
        buf = bytearray(make_m31_bin())
        buf[0:5] = b"EDC17"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# _resolve_ecu_family() — direct unit tests
# ---------------------------------------------------------------------------


class TestResolveEcuFamily:
    def test_m31_marker_resolves_to_m31(self):
        buf = bytearray(0x8000)
        buf[0x005C:0x0065] = b"1350000M3"
        assert EXTRACTOR._resolve_ecu_family(bytes(buf)) == "M3.1"

    def test_m33_marker_no_mp72_tag_resolves_to_m33(self):
        buf = bytearray(0x8000)
        buf[0x0084:0x008D] = b"1530000M3"
        assert EXTRACTOR._resolve_ecu_family(bytes(buf)) == "M3.3"

    def test_m33_marker_plus_mp72_tag_resolves_to_mp72(self):
        buf = bytearray(0x8000)
        buf[0x0084:0x008D] = b"1530000M3"
        buf[0x0100:0x0105] = b"MP7.2"
        assert EXTRACTOR._resolve_ecu_family(bytes(buf)) == "MP7.2"

    def test_psa_marker_no_mp32_tag_resolves_to_mp3x_psa(self):
        buf = bytearray(0x8000)
        buf[0x1000:0x1009] = b"0000000M3"
        assert EXTRACTOR._resolve_ecu_family(bytes(buf)) == "MP3.x-PSA"

    def test_psa_marker_plus_mp32_tag_resolves_to_mp32(self):
        buf = bytearray(0x8000)
        buf[0x1000:0x1009] = b"0000000M3"
        buf[0x0100:0x0105] = b"MP3.2"
        assert EXTRACTOR._resolve_ecu_family(bytes(buf)) == "MP3.2"

    def test_m31_marker_takes_priority_over_m33(self):
        """M3.1 check is first; if both markers present, M3.1 wins."""
        buf = bytearray(0x8000)
        buf[0x005C:0x0065] = b"1350000M3"
        buf[0x0084:0x008D] = b"1530000M3"
        assert EXTRACTOR._resolve_ecu_family(bytes(buf)) == "M3.1"

    def test_no_marker_returns_none(self):
        assert EXTRACTOR._resolve_ecu_family(b"") is None

    def test_all_zero_returns_none(self):
        assert EXTRACTOR._resolve_ecu_family(bytes(0x8000)) is None


# ---------------------------------------------------------------------------
# extract() — required keys always present
# ---------------------------------------------------------------------------

_ALL_SUB_FAMILY_CASES = [
    make_m31_bin(),
    make_m33_32kb_bin(),
    make_m33_64kb_bin(),
    make_m33_fallback_bin(),
    make_mp72_bin(),
    make_mp32_layout_a_bin(),
    make_mp32_layout_b_bin(),
    make_mp3x_psa_bin(),
]
_ALL_SUB_FAMILY_IDS = [
    "m31",
    "m33_32kb",
    "m33_64kb",
    "m33_fallback",
    "mp72",
    "mp32_layout_a",
    "mp32_layout_b",
    "mp3x_psa",
]


class TestExtractRequiredKeys:
    @pytest.mark.parametrize("data", _ALL_SUB_FAMILY_CASES, ids=_ALL_SUB_FAMILY_IDS)
    def test_all_required_keys_present(self, data: bytes):
        result = EXTRACTOR.extract(data)
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in result, f"Missing required key: {key!r}"

    @pytest.mark.parametrize("data", _ALL_SUB_FAMILY_CASES, ids=_ALL_SUB_FAMILY_IDS)
    def test_manufacturer_always_bosch(self, data: bytes):
        assert EXTRACTOR.extract(data)["manufacturer"] == "Bosch"

    @pytest.mark.parametrize("data", _ALL_SUB_FAMILY_CASES, ids=_ALL_SUB_FAMILY_IDS)
    def test_file_size_equals_data_length(self, data: bytes):
        assert EXTRACTOR.extract(data)["file_size"] == len(data)

    @pytest.mark.parametrize("data", _ALL_SUB_FAMILY_CASES, ids=_ALL_SUB_FAMILY_IDS)
    def test_oem_part_number_is_none(self, data: bytes):
        assert EXTRACTOR.extract(data)["oem_part_number"] is None

    @pytest.mark.parametrize("data", _ALL_SUB_FAMILY_CASES, ids=_ALL_SUB_FAMILY_IDS)
    def test_ecu_variant_equals_ecu_family(self, data: bytes):
        """M3.x has no separate ecu_variant — it mirrors ecu_family."""
        result = EXTRACTOR.extract(data)
        assert result["ecu_variant"] == result["ecu_family"]


# ---------------------------------------------------------------------------
# extract() — hash correctness
# ---------------------------------------------------------------------------


class TestExtractHashing:
    def _check(self, data: bytes):
        result = EXTRACTOR.extract(data)
        assert result["md5"] == hashlib.md5(data).hexdigest()
        assert result["sha256_first_64kb"] == hashlib.sha256(data[:0x10000]).hexdigest()

    def test_hashes_m31(self):
        self._check(make_m31_bin())

    def test_hashes_m33_32kb(self):
        self._check(make_m33_32kb_bin())

    def test_hashes_m33_64kb(self):
        self._check(make_m33_64kb_bin())

    def test_hashes_mp72(self):
        self._check(make_mp72_bin())

    def test_hashes_mp32_layout_a(self):
        self._check(make_mp32_layout_a_bin())

    def test_md5_is_32_hex_chars(self):
        result = EXTRACTOR.extract(make_m31_bin())
        md5 = result["md5"]
        assert isinstance(md5, str) and len(md5) == 32
        int(md5, 16)  # raises if not valid hex

    def test_sha256_is_64_hex_chars(self):
        result = EXTRACTOR.extract(make_m33_32kb_bin())
        sha = result["sha256_first_64kb"]
        assert isinstance(sha, str) and len(sha) == 64
        int(sha, 16)

    def test_sha256_first_64kb_caps_at_64kb(self):
        """For a 256KB MP7.2 binary, sha256 covers only the first 64KB."""
        data = make_mp72_bin()
        result = EXTRACTOR.extract(data)
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert result["sha256_first_64kb"] == expected
        # Verify it is NOT the hash of the full file (which is larger)
        full_hash = hashlib.sha256(data).hexdigest()
        assert result["sha256_first_64kb"] != full_hash

    def test_different_binaries_different_md5(self):
        r1 = EXTRACTOR.extract(make_m31_bin())
        r2 = EXTRACTOR.extract(make_m33_32kb_bin())
        assert r1["md5"] != r2["md5"]


# ---------------------------------------------------------------------------
# extract() — M3.1 sub-extractor
# ---------------------------------------------------------------------------


class TestExtractM31:
    def setup_method(self):
        self.data = make_m31_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_m31(self):
        assert self.result["ecu_family"] == "M3.1"

    def test_ecu_variant_is_m31(self):
        assert self.result["ecu_variant"] == "M3.1"

    def test_hardware_number_decoded(self):
        assert self.result["hardware_number"] == _HW_EXPECTED

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert len(hw) == 10 and hw.isdigit()

    def test_software_version_decoded(self):
        assert self.result["software_version"] == _SW_EXPECTED

    def test_software_version_starts_with_1267(self):
        assert self.result["software_version"].startswith("1267")

    def test_software_version_is_10_digits(self):
        sw = self.result["software_version"]
        assert len(sw) == 10 and sw.isdigit()

    def test_calibration_id_is_dme_code(self):
        assert self.result["calibration_id"] == "011/135 4321"

    def test_match_key_format(self):
        assert self.result["match_key"] == f"M3.1::{_SW_EXPECTED}"

    def test_match_key_is_uppercase(self):
        mk = self.result["match_key"]
        assert mk is not None and mk == mk.upper()

    def test_file_size_is_32kb(self):
        assert self.result["file_size"] == 0x8000

    def test_raw_strings_is_list(self):
        assert isinstance(self.result.get("raw_strings"), list)


class TestExtractM31DotSuffix:
    """Ident number with optional .XX decimal suffix is handled correctly."""

    def setup_method(self):
        self.data = make_m31_bin(dot_suffix=True)
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_m31(self):
        assert self.result["ecu_family"] == "M3.1"

    def test_hardware_number_still_decoded(self):
        """Dot suffix must be stripped before reversing digits."""
        assert self.result["hardware_number"] == _HW_EXPECTED

    def test_software_version_still_decoded(self):
        assert self.result["software_version"] == _SW_EXPECTED

    def test_match_key_unaffected_by_suffix(self):
        assert self.result["match_key"] == f"M3.1::{_SW_EXPECTED}"


class TestExtractM31NoIdent:
    """M3.1 binary with no ident / no DME → all version fields None."""

    def setup_method(self):
        self.data = make_m31_bin(with_ident=False)
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_still_m31(self):
        assert self.result["ecu_family"] == "M3.1"

    def test_hardware_number_is_none(self):
        assert self.result["hardware_number"] is None

    def test_software_version_is_none(self):
        assert self.result["software_version"] is None

    def test_calibration_id_is_none(self):
        assert self.result["calibration_id"] is None

    def test_match_key_is_none(self):
        assert self.result["match_key"] is None


# ---------------------------------------------------------------------------
# extract() — M3.3 combined path
# ---------------------------------------------------------------------------


class TestExtractM33Combined:
    """M3.3 32KB: DME immediately before ident → combined regex fires."""

    def setup_method(self):
        self.data = make_m33_32kb_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_m33(self):
        assert self.result["ecu_family"] == "M3.3"

    def test_hardware_number_decoded(self):
        assert self.result["hardware_number"] == _HW_EXPECTED

    def test_software_version_decoded(self):
        assert self.result["software_version"] == _SW_EXPECTED

    def test_calibration_id_is_dme_code(self):
        assert self.result["calibration_id"] == "012/413 5678"

    def test_match_key_format(self):
        assert self.result["match_key"] == f"M3.3::{_SW_EXPECTED}"

    def test_file_size_is_32kb(self):
        assert self.result["file_size"] == 0x8000


class TestExtractM3364KB:
    """M3.3 64KB: marker at 0x4002, same ident/DME decoding as 32KB."""

    def setup_method(self):
        self.data = make_m33_64kb_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_m33(self):
        assert self.result["ecu_family"] == "M3.3"

    def test_hardware_number_decoded(self):
        assert self.result["hardware_number"] == _HW_EXPECTED

    def test_software_version_decoded(self):
        assert self.result["software_version"] == _SW_EXPECTED

    def test_calibration_id_is_dme_code(self):
        assert self.result["calibration_id"] == "013/413 9876"

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000

    def test_match_key_contains_family(self):
        assert self.result["match_key"].startswith("M3.3::")


# ---------------------------------------------------------------------------
# extract() — M3.3 fallback path
# ---------------------------------------------------------------------------


class TestExtractM33Fallback:
    """
    M3.3: DME and ident separated by NUL bytes → combined regex fails,
    fallback searches last 2KB for each field independently.
    """

    def setup_method(self):
        self.data = make_m33_fallback_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_m33(self):
        assert self.result["ecu_family"] == "M3.3"

    def test_hardware_number_decoded_via_fallback(self):
        assert self.result["hardware_number"] == _HW_EXPECTED

    def test_software_version_decoded_via_fallback(self):
        assert self.result["software_version"] == _SW_EXPECTED

    def test_calibration_id_decoded_via_fallback(self):
        assert self.result["calibration_id"] == "012/413 5678"

    def test_match_key_built(self):
        assert self.result["match_key"] == f"M3.3::{_SW_EXPECTED}"


# ---------------------------------------------------------------------------
# extract() — M3.3 all-0xFF last 1KB
# ---------------------------------------------------------------------------


class TestExtractM33AllFF:
    """M3.3 with erased-EPROM trailing region → no ident decodable."""

    def setup_method(self):
        self.data = make_m33_all_ff_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_m33(self):
        assert self.result["ecu_family"] == "M3.3"

    def test_hardware_number_is_none(self):
        assert self.result["hardware_number"] is None

    def test_software_version_is_none(self):
        assert self.result["software_version"] is None

    def test_calibration_id_is_none(self):
        assert self.result["calibration_id"] is None

    def test_match_key_is_none(self):
        assert self.result["match_key"] is None


# ---------------------------------------------------------------------------
# extract() — MP7.2 sub-extractor
# ---------------------------------------------------------------------------


class TestExtractMP72:
    """MP7.2: HW from repeated pattern, SW from PSA cal block."""

    def setup_method(self):
        self.data = make_mp72_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_mp72(self):
        assert self.result["ecu_family"] == "MP7.2"

    def test_hardware_number_decoded(self):
        assert self.result["hardware_number"] == _MP72_HW_EXPECTED

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_software_version_decoded(self):
        assert self.result["software_version"] == _MP72_SW_EXPECTED

    def test_software_version_starts_with_1037(self):
        assert self.result["software_version"].startswith("1037")

    def test_calibration_id_is_psa_cal_string(self):
        assert self.result["calibration_id"] == _MP72_CAL_STR

    def test_match_key_format(self):
        assert self.result["match_key"] == f"MP7.2::{_MP72_SW_EXPECTED}"

    def test_file_size_is_256kb(self):
        assert self.result["file_size"] == 0x40000


class TestExtractMP72MissingFields:
    """MP7.2 when HW or SW or cal block is absent."""

    def test_no_repeated_hw_pattern_hw_is_none(self):
        data = make_mp72_bin(with_hw=False)
        result = EXTRACTOR.extract(data)
        assert result["hardware_number"] is None

    def test_no_cal_block_sw_and_cal_are_none(self):
        data = make_mp72_bin(with_cal=False)
        result = EXTRACTOR.extract(data)
        assert result["software_version"] is None
        assert result["calibration_id"] is None

    def test_cal_block_without_sw_prefix_sw_is_none(self):
        """Cal block present but no 1037/2227 prefix → SW = None."""
        data = make_mp72_bin(sw_in_cal=False)
        result = EXTRACTOR.extract(data)
        assert result["software_version"] is None
        # Cal block itself IS present
        assert result["calibration_id"] is not None

    def test_no_hw_no_sw_match_key_is_none(self):
        data = make_mp72_bin(with_hw=False, with_cal=False)
        result = EXTRACTOR.extract(data)
        assert result["match_key"] is None

    def test_ecu_family_still_mp72_when_fields_absent(self):
        data = make_mp72_bin(with_hw=False, with_cal=False)
        result = EXTRACTOR.extract(data)
        assert result["ecu_family"] == "MP7.2"


class TestExtractMP722227SW:
    """MP7.2 with a 2227xxxxxx-prefixed SW number."""

    def test_2227_sw_prefix_decoded(self):
        buf = bytearray(0x40000)
        buf[0x0100:0x0109] = b"1530000M3"
        buf[0x0200:0x0205] = b"MP7.2"
        buf[0x1000:0x1014] = _MP72_HW_BYTES  # same HW
        cal_2227 = b"45/1/MP7.2/3/14/2227350812"
        buf[0x2000 : 0x2000 + len(cal_2227)] = cal_2227
        buf[-1024:] = b"\xff" * 1024
        result = EXTRACTOR.extract(bytes(buf))
        assert result["software_version"] == "2227350812"
        assert result["software_version"].startswith("2227")


# ---------------------------------------------------------------------------
# extract() — MP3.2 Layout A
# ---------------------------------------------------------------------------


class TestExtractMP32LayoutA:
    """MP3.2 Layout A: backward walk from marker collects ≥ 20 digits."""

    def setup_method(self):
        self.data = make_mp32_layout_a_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_mp32(self):
        assert self.result["ecu_family"] == "MP3.2"

    def test_hardware_number_decoded(self):
        assert self.result["hardware_number"] == _PSA_HW_EXPECTED

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_software_version_decoded(self):
        assert self.result["software_version"] == _PSA_SW_EXPECTED

    def test_software_version_starts_with_1267(self):
        assert self.result["software_version"].startswith("1267")

    def test_calibration_id_is_psa_cal_block(self):
        assert self.result["calibration_id"] == _PSA_CAL_STR

    def test_match_key_format(self):
        assert self.result["match_key"] == f"MP3.2::{_PSA_SW_EXPECTED}"

    def test_match_key_uppercase(self):
        mk = self.result["match_key"]
        assert mk is not None and mk == mk.upper()


# ---------------------------------------------------------------------------
# extract() — MP3.2 Layout B (file-wide fallback scan)
# ---------------------------------------------------------------------------


class TestExtractMP32LayoutB:
    """
    MP3.2 Layout B: non-digit before marker → backward walk yields < 20 digits.
    File-wide scan finds the isolated 20-digit ident.
    """

    def setup_method(self):
        self.data = make_mp32_layout_b_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_mp32(self):
        assert self.result["ecu_family"] == "MP3.2"

    def test_hardware_number_decoded_via_fallback(self):
        assert self.result["hardware_number"] == _PSA_B_HW_EXPECTED

    def test_software_version_decoded_via_fallback(self):
        assert self.result["software_version"] == _PSA_B_SW_EXPECTED

    def test_calibration_id_present(self):
        assert self.result["calibration_id"] is not None

    def test_match_key_built(self):
        assert self.result["match_key"] == f"MP3.2::{_PSA_B_SW_EXPECTED}"


# ---------------------------------------------------------------------------
# extract() — MP3.x-PSA sub-extractor
# ---------------------------------------------------------------------------


class TestExtractMP3xPSA:
    """MP3.x-PSA: same ident logic as MP3.2, but ecu_family differs."""

    def setup_method(self):
        self.data = make_mp3x_psa_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_mp3x_psa(self):
        assert self.result["ecu_family"] == "MP3.x-PSA"

    def test_hardware_number_decoded(self):
        assert self.result["hardware_number"] == _PSA_HW_EXPECTED

    def test_software_version_decoded(self):
        assert self.result["software_version"] == _PSA_SW_EXPECTED

    def test_match_key_contains_family(self):
        mk = self.result["match_key"]
        assert mk is not None and "MP3.X-PSA" in mk

    def test_ecu_variant_equals_ecu_family(self):
        assert self.result["ecu_variant"] == "MP3.x-PSA"


# ---------------------------------------------------------------------------
# _resolve_hardware_number() — direct edge-case tests
# ---------------------------------------------------------------------------


class TestResolveHardwareNumber:
    """
    Direct tests for the private _resolve_hardware_number() method.
    These cover edge cases that are hard to exercise through full binaries.
    """

    def test_none_input_returns_none(self):
        assert EXTRACTOR._resolve_hardware_number(None) is None

    def test_empty_string_returns_none(self):
        assert EXTRACTOR._resolve_hardware_number("") is None

    def test_nine_digit_ident_too_short_returns_none(self):
        assert EXTRACTOR._resolve_hardware_number("123456789") is None

    def test_valid_28_digit_ident_returns_hw(self):
        ident = _IDENT_28.decode("ascii")
        assert EXTRACTOR._resolve_hardware_number(ident) == _HW_EXPECTED

    def test_dot_suffix_stripped_before_decoding(self):
        ident = _IDENT_28.decode("ascii") + ".05"
        assert EXTRACTOR._resolve_hardware_number(ident) == _HW_EXPECTED

    def test_hw_wrong_prefix_returns_none(self):
        # first 10 digits reversed = "9999999999" → does not start "0261"
        bad_ident = "9999999999" + "0" * 18
        assert EXTRACTOR._resolve_hardware_number(bad_ident) is None

    def test_hw_not_all_digits_returns_none(self):
        # Inject a non-digit into the first 10-char segment after reversal
        # "AAAA021620" reversed = "0261200AAAA" → startswith "0261" but not isdigit
        # Build via direct manipulation: reversed "AAAA021620"
        ident = "0261200AAA" + "0" * 18  # reversed first 10 = "AAA0021620" (has 'A')
        assert EXTRACTOR._resolve_hardware_number(ident) is None

    def test_exactly_10_digit_ident_hw_only_no_sw(self):
        """10 chars: HW segment decodes but SW is not checked here."""
        ident = "0250021620"  # reversed → "0261200520"
        hw = EXTRACTOR._resolve_hardware_number(ident)
        assert hw == "0261200520"


# ---------------------------------------------------------------------------
# _resolve_software_version() — direct edge-case tests
# ---------------------------------------------------------------------------


class TestResolveSoftwareVersion:
    def test_none_input_returns_none(self):
        assert EXTRACTOR._resolve_software_version(None) is None

    def test_empty_string_returns_none(self):
        assert EXTRACTOR._resolve_software_version("") is None

    def test_nineteen_digit_ident_too_short_returns_none(self):
        assert EXTRACTOR._resolve_software_version("1" * 19) is None

    def test_valid_28_digit_ident_returns_sw(self):
        ident = _IDENT_28.decode("ascii")
        assert EXTRACTOR._resolve_software_version(ident) == _SW_EXPECTED

    def test_dot_suffix_stripped_before_decoding(self):
        ident = _IDENT_28.decode("ascii") + ".05"
        assert EXTRACTOR._resolve_software_version(ident) == _SW_EXPECTED

    def test_sw_wrong_prefix_returns_none(self):
        # SW segment (digits[10:20]) reversed = "9999999999" → invalid prefix
        bad_ident = "0250021620" + "9999999999" + "00000000"
        assert EXTRACTOR._resolve_software_version(bad_ident) is None

    def test_sw_1267_prefix_accepted(self):
        ident = _IDENT_28.decode("ascii")
        sw = EXTRACTOR._resolve_software_version(ident)
        assert sw is not None and sw.startswith("1267")

    def test_sw_2227_prefix_accepted(self):
        # Build ident where SW segment[10:20][::-1] starts with "2227"
        # sw = "2227000000"  → reversed segment = "0000007222"
        # hw = "0261200520"  → reversed segment = "0250021620"
        ident_2227 = "0250021620" + "0000007222" + "00000000"
        sw = EXTRACTOR._resolve_software_version(ident_2227)
        assert sw == "2227000000"
        assert sw.startswith("2227")

    def test_sw_not_all_digits_returns_none(self):
        # SW segment with non-digit characters
        ident = "0250021620" + "AAAAAAAAAA" + "00000000"
        assert EXTRACTOR._resolve_software_version(ident) is None


# ---------------------------------------------------------------------------
# extract() — match_key behaviour
# ---------------------------------------------------------------------------


class TestMatchKey:
    def test_match_key_none_when_sw_absent(self):
        result = EXTRACTOR.extract(make_m31_bin(with_ident=False))
        assert result["match_key"] is None

    def test_match_key_built_when_sw_present_m31(self):
        result = EXTRACTOR.extract(make_m31_bin())
        mk = result["match_key"]
        assert mk is not None
        assert _SW_EXPECTED in mk

    def test_match_key_built_when_sw_present_m33(self):
        result = EXTRACTOR.extract(make_m33_32kb_bin())
        assert result["match_key"] == f"M3.3::{_SW_EXPECTED}"

    def test_match_key_uses_ecu_family_as_prefix(self):
        result = EXTRACTOR.extract(make_m31_bin())
        assert result["match_key"].startswith("M3.1::")

    def test_match_key_is_uppercase(self):
        result = EXTRACTOR.extract(make_mp32_layout_a_bin())
        mk = result["match_key"]
        assert mk is not None and mk == mk.upper()

    def test_match_key_none_for_mp72_without_sw(self):
        result = EXTRACTOR.extract(make_mp72_bin(with_cal=False))
        assert result["match_key"] is None

    def test_different_sw_produces_different_match_key(self):
        r1 = EXTRACTOR.extract(make_m33_32kb_bin())
        r2 = EXTRACTOR.extract(make_m33_64kb_bin())
        # Both have same ident (_IDENT_28) but different DME codes; SW is same.
        # Use different ident to get distinct keys — patch via m31 vs m33.
        r_m31 = EXTRACTOR.extract(make_m31_bin())
        r_mp32 = EXTRACTOR.extract(make_mp32_layout_a_bin())
        # MP3.2 has different SW (_PSA_SW_EXPECTED), M3.1 has _SW_EXPECTED
        assert r_m31["match_key"] != r_mp32["match_key"]


# ---------------------------------------------------------------------------
# Determinism and filename independence
# ---------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.parametrize("data", _ALL_SUB_FAMILY_CASES, ids=_ALL_SUB_FAMILY_IDS)
    def test_same_binary_same_result(self, data: bytes):
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        for key in REQUIRED_EXTRACT_KEYS:
            assert r1[key] == r2[key], f"Non-deterministic key: {key!r}"

    def test_filename_does_not_affect_m31_fields(self):
        data = make_m31_bin()
        r1 = EXTRACTOR.extract(data, filename="original.bin")
        r2 = EXTRACTOR.extract(data, filename="renamed_copy.bin")
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["match_key"] == r2["match_key"]
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_filename_does_not_affect_mp72_fields(self):
        data = make_mp72_bin()
        r1 = EXTRACTOR.extract(data, filename="saxo.bin")
        r2 = EXTRACTOR.extract(data, filename="saxo_backup.bin")
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]

    def test_different_binaries_produce_different_sha256(self):
        r1 = EXTRACTOR.extract(make_m31_bin())
        r2 = EXTRACTOR.extract(make_m33_32kb_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]

    def test_file_size_reflects_actual_binary_size(self):
        r_32 = EXTRACTOR.extract(make_m31_bin())
        r_64 = EXTRACTOR.extract(make_m33_64kb_bin())
        r_256 = EXTRACTOR.extract(make_mp72_bin())
        assert r_32["file_size"] == 0x8000
        assert r_64["file_size"] == 0x10000
        assert r_256["file_size"] == 0x40000


# ---------------------------------------------------------------------------
# _resolve_psa_mp3x_ident_and_dme() — marker-absent guard
# ---------------------------------------------------------------------------


class TestResolvePsaMp3xIdentAndDme:
    """
    Direct tests for the private _resolve_psa_mp3x_ident_and_dme() method.
    Covers the early-return guard (line 492) that fires when the
    b'0000000M3' marker is not present in the data at all.
    This path is unreachable via extract() in normal use because
    _resolve_ecu_family() only routes MP3.2 / MP3.x-PSA binaries here,
    and those always contain the marker.
    """

    def test_marker_absent_returns_none_none(self):
        """No b'0000000M3' in data → (None, None) returned immediately."""
        result = EXTRACTOR._resolve_psa_mp3x_ident_and_dme(bytes(0x8000))
        assert result == (None, None)

    def test_empty_data_returns_none_none(self):
        result = EXTRACTOR._resolve_psa_mp3x_ident_and_dme(b"")
        assert result == (None, None)

    def test_marker_present_returns_tuple(self):
        """Sanity-check: with marker present, the method returns a 2-tuple."""
        data = make_mp32_layout_a_bin()
        ident_num, dme_code = EXTRACTOR._resolve_psa_mp3x_ident_and_dme(data)
        assert ident_num is not None
