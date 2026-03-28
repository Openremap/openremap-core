"""
Tests for BoschM5xExtractor (M5.9 / M5.92 / M3.8 / M3.82 / M3.83 / M3.8.3).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * Phase 3: M5.92 bin (M5. primary sig + ident block)
      * Phase 3: M3.8.3 bin (M3.8 primary sig + ident block)
      * Phase 3: M3.82 128KB bin
      * Phase 3: M3.83 256KB bin
      * Phase 4: ident block present + MOTR anchor, but NO M5./M3.8 primary sig
  - can_handle() — False paths:
      * Empty binary
      * All-zero 128KB / 256KB
      * Wrong sizes (32KB, 64KB, 512KB)
      * Primary sig present but no ident block → Phase 3 & 4 both fail
      * Ident block/primary sig beyond ident_area (first 64KB) ignored
  - can_handle() — Exclusions:
      * Every EXCLUSION_SIGNATURES entry blocks an otherwise-valid bin
      * Exclusion at offset 0 still caught
  - _parse_ident_block():
      * Returns re.Match for valid ident; None otherwise
      * Match groups carry HW / SW_raw / revision / family correctly
  - _resolve_ecu_family():
      * Priority 1: ident block group(4) normalised via FAMILY_NORMALISATION
      * All sub-families (M5.92→M5.9, M3.82→M3.8, M3.83→M3.8, M3.8.3→M3.8)
      * Unknown family not in FAMILY_NORMALISATION returned as-is
      * Trailing dot in family string stripped by rstrip(".-_") before lookup
      * Priority 2: standalone ecu_family_string pattern in ident area
      * None when ident absent and no standalone string found
  - _resolve_software_version():
      * Priority 1: 12-digit raw from ident block → first 10 returned (strip suffix)
      * Priority 2: standalone 1037xxxxxx in ident area
      * None when both absent
  - _resolve_hardware_number():
      * Priority 1: ident block group(1)
      * Priority 2: standalone 0261xxxxxx in ident area
      * None when both absent
  - _resolve_oem_part_number():
      * Format B clean (06A9xxx) → returned as-is
      * Format A clean (8D0xxx) → returned as-is
      * Format A with 2-digit garbage prefix → stripped correctly
      * No '1.8L' marker → None
      * All-digit candidate (no alpha) → None
  - extract() — required keys always present (all sub-families)
  - extract() — M5.92 full extraction (HW / SW / OEM / family / match_key)
  - extract() — M5.92 with garbage OEM prefix correctly stripped
  - extract() — M3.8.3 full extraction (Format B / MOTR HS variant)
  - extract() — M3.82 128KB (128KB size, garbage OEM stripped)
  - extract() — M3.83 full extraction
  - extract() — Phase 4 bin (family 'M6.9' returned as-is)
  - extract() — standalone-only (no ident block; resolvers use Priority-2 fallbacks)
  - extract() — null fields always None (calibration_version, sw_base_version, etc.)
  - extract() — hashing (md5 and sha256_first_64kb correctness)
  - match_key format, None when SW absent, always uppercase
  - Determinism and filename independence
"""

import hashlib

import re
from unittest.mock import MagicMock, patch

import pytest

from openremap.tuning.manufacturers.bosch.m5x.extractor import BoschM5xExtractor
from openremap.tuning.manufacturers.bosch.m5x.patterns import EXCLUSION_SIGNATURES

EXTRACTOR = BoschM5xExtractor()

# Keys that must always be present in the extract() return dict.
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
# Reference ident strings and expected parsed values
# ---------------------------------------------------------------------------

# M5.92 — Format A (no HS keyword, clean OEM, 256KB)
# ident_block pattern: MOTR + whitespace + D + 2 digits + HW(10) + SW(12) + /rev/ + family
_M592_IDENT = (
    b"8D0907557P  1.8L R4/5VT MOTR    D06"
    b"0261204258"  # HW — 10 digits starting with 0261
    b"103735026955"  # SW raw — 12 digits; true SW = first 10 = "1037350269"
    b"/1/M5.92/05/400201"
)
_M592_HW = "0261204258"
_M592_SW = "1037350269"  # raw[:10], strips last 2 ("55")
_M592_OEM = "8D0907557P"

# M5.92 — Format A with 2-digit garbage OEM prefix
# candidate "068D0907557P": indices 0='0', 1='6', 2='8', 3='D' → strip 2 → "8D0907557P"
_M592_GARBAGE_IDENT = (
    b"068D0907557P  1.8L R4/5VT MOTR    D060261204258103735026955/1/M5.92/05/400201"
)

# M3.8.3 — Format B (MOTR HS, clean OEM, 256KB)
_M383_IDENT = (
    b"06A906018AQ 1.8L R4/5VT MOTR HS D03"
    b"0261204678"
    b"103735810858"  # true SW = "1037358108"
    b"/1/M3.8.3/03/400303"
)
_M383_HW = "0261204678"
_M383_SW = "1037358108"  # raw[:10], strips last 2 ("58")
_M383_OEM = "06A906018AQ"

# M3.82 — Format A with 2-digit garbage OEM prefix, 128KB
# candidate "038D0907557T": indices 0='0', 1='3', 2='8', 3='D' → strip 2 → "8D0907557T"
_M382_IDENT = (
    b"038D0907557T  1.8L R4/5VT MOTR    D03"
    b"0261204185"
    b"103735876157"  # true SW = "1037358761"
    b"/1/M3.82/05/400101"
)
_M382_HW = "0261204185"
_M382_SW = "1037358761"  # raw[:10], strips last 2 ("57")
_M382_OEM = "8D0907557T"  # stripped from "038D0907557T"

# M3.83 — Format B (MOTR HS, clean OEM, 256KB)
_M383_ALT_IDENT = (
    b"06A906018CG 1.8L R4/5VT MOTR HS D03"
    b"0261206518"
    b"103735212757"  # true SW = "1037352127"
    b"/1/M3.83/03/400501"
)
_M383_ALT_HW = "0261206518"
_M383_ALT_SW = "1037352127"  # raw[:10], strips last 2 ("57")
_M383_ALT_OEM = "06A906018CG"

# Phase 4 ident — family "M6.9": not M5.x or M3.8x so no primary sig fires,
# but ident_block regex still matches ([A-Z0-9][0-9.]{2,6} matches "M6.9").
_PHASE4_IDENT = b"MOTR    D060261204258103735026955/1/M6.9/05/400201"

# Trailing-dot family ident — group(4) = "M5.9." → rstrip(".") = "M5.9"
_TRAILING_DOT_IDENT = (
    b"8D0907557P  1.8L R4/5VT MOTR    D060261204258103735026955/1/M5.9./05/400201"
)


# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------


def make_m592_256kb_bin(
    with_ident: bool = True,
    with_primary: bool = True,
) -> bytes:
    """
    M5.92, 256KB (0x40000).

    Primary sig b"M5.9" placed at 0x0500 (inside ident area = first 64KB).
    Ident block placed at 0x1000 (also inside first 64KB).

    Args:
        with_ident:   inject the ident block (default True).
        with_primary: inject the b"M5.9" primary detection sig (default True).
    """
    buf = bytearray(0x40000)
    if with_primary:
        buf[0x0500:0x0504] = b"M5.9"
    if with_ident:
        buf[0x1000 : 0x1000 + len(_M592_IDENT)] = _M592_IDENT
    return bytes(buf)


def make_m592_garbage_oem_256kb_bin() -> bytes:
    """M5.92, 256KB, Format A — 2-digit garbage OEM prefix to be stripped."""
    buf = bytearray(0x40000)
    buf[0x0500:0x0504] = b"M5.9"
    buf[0x1000 : 0x1000 + len(_M592_GARBAGE_IDENT)] = _M592_GARBAGE_IDENT
    return bytes(buf)


def make_m383_256kb_bin() -> bytes:
    """M3.8.3, 256KB (0x40000). Format B (MOTR HS). Clean OEM."""
    buf = bytearray(0x40000)
    buf[0x0500:0x0504] = b"M3.8"
    buf[0x1000 : 0x1000 + len(_M383_IDENT)] = _M383_IDENT
    return bytes(buf)


def make_m382_128kb_bin() -> bytes:
    """M3.82, 128KB (0x20000). Format A — garbage OEM prefix."""
    buf = bytearray(0x20000)
    buf[0x0500:0x0504] = b"M3.8"
    buf[0x1000 : 0x1000 + len(_M382_IDENT)] = _M382_IDENT
    return bytes(buf)


def make_m383_alt_256kb_bin() -> bytes:
    """M3.83, 256KB. Format B (MOTR HS). Clean OEM."""
    buf = bytearray(0x40000)
    buf[0x0500:0x0504] = b"M3.8"
    buf[0x1000 : 0x1000 + len(_M383_ALT_IDENT)] = _M383_ALT_IDENT
    return bytes(buf)


def make_phase4_bin() -> bytes:
    """
    Phase-4-only bin: 256KB with a valid ident_block but NO primary sig.

    Family "M6.9" matches ident_block group(4) pattern [A-Z0-9][0-9.]{2,6}
    but neither b"M5." nor b"M3.8" appears in ident_area → has_primary=False.

    Phase 3 fails; Phase 4 accepts via has_ident=True + MOTR anchor.
    """
    buf = bytearray(0x40000)
    buf[0x1000 : 0x1000 + len(_PHASE4_IDENT)] = _PHASE4_IDENT
    return bytes(buf)


def make_trailing_dot_family_bin() -> bytes:
    """
    256KB bin whose ident block contains family "M5.9." (trailing dot).
    Tests that _resolve_ecu_family() strips the dot via rstrip(".-_").
    """
    buf = bytearray(0x40000)
    buf[0x0500:0x0504] = b"M5.9"
    buf[0x1000 : 0x1000 + len(_TRAILING_DOT_IDENT)] = _TRAILING_DOT_IDENT
    return bytes(buf)


def make_standalone_only_bin() -> bytes:
    """
    256KB bin with standalone detection strings but NO ident block.

    Placed inside ident_area (first 64KB):
      0x0500: b"M5.92"       matches ecu_family_string pattern
      0x0600: b"0261204258"  matches hardware_number pattern
      0x0700: b"1037350269"  matches software_version pattern

    can_handle() returns False (no ident block → Phase 3 and 4 both fail).
    Used to test _resolve_*() Priority-2 standalone fallback paths directly.
    """
    buf = bytearray(0x40000)
    buf[0x0500:0x0505] = b"M5.92"
    buf[0x0600:0x060A] = b"0261204258"
    buf[0x0700:0x070A] = b"1037350269"
    return bytes(buf)


def _inject_exclusion(buf: bytearray, sig: bytes, offset: int = 0x0200) -> bytearray:
    """Write an exclusion signature into a mutable buffer at the given offset."""
    buf[offset : offset + len(sig)] = sig
    return buf


# ---------------------------------------------------------------------------
# TestIdentity
# ---------------------------------------------------------------------------


class TestIdentity:
    """Verify name, supported_families, and __repr__ of the extractor."""

    def test_name_is_bosch(self):
        assert EXTRACTOR.name == "Bosch"

    def test_name_is_string(self):
        assert isinstance(EXTRACTOR.name, str)

    def test_supported_families_is_list(self):
        assert isinstance(EXTRACTOR.supported_families, list)

    def test_supported_families_not_empty(self):
        assert len(EXTRACTOR.supported_families) > 0

    def test_m59_in_supported_families(self):
        assert "M5.9" in EXTRACTOR.supported_families

    def test_m592_in_supported_families(self):
        assert "M5.92" in EXTRACTOR.supported_families

    def test_m38_in_supported_families(self):
        assert "M3.8" in EXTRACTOR.supported_families

    def test_m382_in_supported_families(self):
        assert "M3.82" in EXTRACTOR.supported_families

    def test_m383_in_supported_families(self):
        assert "M3.83" in EXTRACTOR.supported_families

    def test_m383_dot_in_supported_families(self):
        assert "M3.8.3" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        assert all(isinstance(f, str) for f in EXTRACTOR.supported_families)

    def test_repr_is_string(self):
        assert isinstance(repr(EXTRACTOR), str)

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschM5xExtractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# TestCanHandleTrue
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """
    Verify can_handle() returns True for valid M5.x / M3.8x binaries.

    Phase 3 — accepted when primary sig (M5. or M3.8) AND ident_block present
               in the ident area (first 64KB).
    Phase 4 — accepted when ident_block + MOTR anchor present, no primary sig.
    """

    def test_m592_256kb_accepted(self):
        assert EXTRACTOR.can_handle(make_m592_256kb_bin()) is True

    def test_m383_256kb_accepted(self):
        assert EXTRACTOR.can_handle(make_m383_256kb_bin()) is True

    def test_m382_128kb_accepted(self):
        assert EXTRACTOR.can_handle(make_m382_128kb_bin()) is True

    def test_m383_alt_256kb_accepted(self):
        assert EXTRACTOR.can_handle(make_m383_alt_256kb_bin()) is True

    def test_m592_garbage_oem_accepted(self):
        assert EXTRACTOR.can_handle(make_m592_garbage_oem_256kb_bin()) is True

    def test_trailing_dot_family_bin_accepted(self):
        assert EXTRACTOR.can_handle(make_trailing_dot_family_bin()) is True

    def test_phase4_bin_accepted(self):
        """Phase 4: family 'M6.9' gives no primary sig but ident_block present."""
        assert EXTRACTOR.can_handle(make_phase4_bin()) is True

    def test_m5_primary_sig_in_ident_block_is_sufficient(self):
        """
        When no standalone primary sig is injected, the 'M5.' substring inside
        the ident block itself (e.g. from 'M5.92') counts as a primary sig.
        """
        data = make_m592_256kb_bin(with_primary=False)
        assert EXTRACTOR.can_handle(data) is True

    def test_m38_primary_sig_from_ident_block_is_sufficient(self):
        """'M3.8' appears as a substring of 'M3.8.3' in the ident block."""
        buf = bytearray(0x40000)
        buf[0x1000 : 0x1000 + len(_M383_IDENT)] = _M383_IDENT
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_both_primary_sigs_present_still_accepted(self):
        """Having both M5. and M3.8 in ident_area is perfectly valid."""
        buf = bytearray(0x40000)
        buf[0x0400:0x0404] = b"M5.9"
        buf[0x0410:0x0414] = b"M3.8"
        buf[0x1000 : 0x1000 + len(_M592_IDENT)] = _M592_IDENT
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# TestCanHandleFalse
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    """Verify can_handle() returns False for invalid / non-M5x binaries."""

    def test_empty_binary_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_all_zero_128kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\x00" * 0x20000) is False

    def test_all_zero_256kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\x00" * 0x40000) is False

    def test_all_ff_128kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\xff" * 0x20000) is False

    def test_all_ff_256kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\xff" * 0x40000) is False

    def test_512kb_size_rejected(self):
        """512KB belongs to ME7 — excluded by size gate (Phase 2)."""
        buf = bytearray(0x80000)
        buf[0x0500:0x0504] = b"M5.9"
        buf[0x1000 : 0x1000 + len(_M592_IDENT)] = _M592_IDENT
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_64kb_size_rejected(self):
        buf = bytearray(0x10000)
        buf[0x0500:0x0504] = b"M5.9"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_32kb_size_rejected(self):
        buf = bytearray(0x8000)
        buf[0x0100:0x0104] = b"M5.9"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_primary_sig_only_no_ident_rejected(self):
        """Phase 3 needs has_primary AND has_ident; Phase 4 needs has_ident."""
        data = make_m592_256kb_bin(with_ident=False)
        assert EXTRACTOR.can_handle(data) is False

    def test_ident_block_only_no_primary_and_no_motr_rejected(self):
        """
        A buffer with the ident_block pattern but MOTR stripped can't pass Phase 4.
        (Contrived case: verifies MOTR_ANCHOR check in Phase 4.)
        Since the ident_block regex starts with MOTR, having the block means
        MOTR is present; this test uses a zero buffer with no ident block at all.
        """
        # 256KB of zeros, no ident block, no primary → all phases fail
        assert EXTRACTOR.can_handle(b"\x00" * 0x40000) is False

    def test_ident_block_beyond_ident_area_not_detected(self):
        """Ident block placed after first 64KB is outside search region."""
        buf = bytearray(0x40000)
        buf[0x0500:0x0504] = b"M5.9"
        ident_offset = 0x10100  # beyond ident_area slice(0, 0x10000)
        buf[ident_offset : ident_offset + len(_M592_IDENT)] = _M592_IDENT
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_primary_sig_beyond_ident_area_ignored(self):
        """Primary sig placed after first 64KB is outside ident_area."""
        buf = bytearray(0x40000)
        buf[0x10001:0x10005] = b"M5.9"  # beyond 0x10000
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_random_repeated_ascii_256kb_rejected(self):
        buf = bytearray(0x40000)
        for i in range(0, 0x40000, 8):
            buf[i : i + 8] = b"ABCDEFGH"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# TestCanHandleExclusions
# ---------------------------------------------------------------------------


class TestCanHandleExclusions:
    """
    Each entry in EXCLUSION_SIGNATURES must block can_handle() even when
    all positive indicators (primary sig + ident block) are present.
    Phase 1 (exclusion check) runs before any positive detection.
    """

    def _valid_m592_buf(self) -> bytearray:
        return bytearray(make_m592_256kb_bin())

    @pytest.mark.parametrize(
        "sig",
        EXCLUSION_SIGNATURES,
        ids=[s.decode("ascii", errors="replace").strip() for s in EXCLUSION_SIGNATURES],
    )
    def test_exclusion_sig_rejects_valid_bin(self, sig):
        buf = self._valid_m592_buf()
        _inject_exclusion(buf, sig, offset=0x0200)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc17_exclusion_explicit(self):
        buf = self._valid_m592_buf()
        _inject_exclusion(buf, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_dot_exclusion_explicit(self):
        buf = self._valid_m592_buf()
        _inject_exclusion(buf, b"ME7.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_zz_ff_ff_exclusion(self):
        """ZZ\\xff\\xff is the ME7 ident block marker — hard reject."""
        buf = self._valid_m592_buf()
        _inject_exclusion(buf, b"ZZ\xff\xff")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_tsw_space_exclusion(self):
        """b'TSW ' is an EDC15 toolchain marker."""
        buf = self._valid_m592_buf()
        _inject_exclusion(buf, b"TSW ")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_at_offset_zero(self):
        buf = self._valid_m592_buf()
        _inject_exclusion(buf, b"EDC17", offset=0)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_near_end_of_bin_still_caught(self):
        """Exclusion sig within first 512KB search area is always caught."""
        buf = self._valid_m592_buf()
        _inject_exclusion(buf, b"EDC16", offset=0x3F000)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_m592_valid_bin(self):
        """Phase 1 runs before Phase 3 — exclusion always wins."""
        buf = self._valid_m592_buf()
        _inject_exclusion(buf, b"SB_V")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_m383_valid_bin(self):
        buf = bytearray(make_m383_256kb_bin())
        _inject_exclusion(buf, b"Customer.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_m382_128kb_valid_bin(self):
        buf = bytearray(make_m382_128kb_bin())
        _inject_exclusion(buf, b"NR000")
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# TestParseIdentBlock
# ---------------------------------------------------------------------------


class TestParseIdentBlock:
    """Verify the ident block parser returns the correct match or None."""

    def test_returns_match_for_m592_ident(self):
        assert EXTRACTOR._parse_ident_block(make_m592_256kb_bin()) is not None

    def test_returns_match_for_m383_ident(self):
        assert EXTRACTOR._parse_ident_block(make_m383_256kb_bin()) is not None

    def test_returns_match_for_m382_128kb_ident(self):
        assert EXTRACTOR._parse_ident_block(make_m382_128kb_bin()) is not None

    def test_returns_match_for_m383_alt_ident(self):
        assert EXTRACTOR._parse_ident_block(make_m383_alt_256kb_bin()) is not None

    def test_returns_match_for_phase4_ident(self):
        assert EXTRACTOR._parse_ident_block(make_phase4_bin()) is not None

    def test_returns_none_for_all_zero_256kb(self):
        assert EXTRACTOR._parse_ident_block(b"\x00" * 0x40000) is None

    def test_returns_none_for_empty_data(self):
        assert EXTRACTOR._parse_ident_block(b"") is None

    def test_returns_none_when_no_ident_block(self):
        """standalone-only bin has no ident block."""
        assert EXTRACTOR._parse_ident_block(make_standalone_only_bin()) is None

    def test_match_group1_is_hw_m592(self):
        m = EXTRACTOR._parse_ident_block(make_m592_256kb_bin())
        assert m is not None
        assert m.group(1).decode("ascii") == _M592_HW

    def test_match_group1_is_hw_m383(self):
        m = EXTRACTOR._parse_ident_block(make_m383_256kb_bin())
        assert m is not None
        assert m.group(1).decode("ascii") == _M383_HW

    def test_match_group2_is_12_digit_sw_raw(self):
        m = EXTRACTOR._parse_ident_block(make_m592_256kb_bin())
        assert m is not None
        raw = m.group(2).decode("ascii")
        assert len(raw) == 12 and raw.startswith("1037")

    def test_match_group2_starts_with_1037(self):
        m = EXTRACTOR._parse_ident_block(make_m383_256kb_bin())
        assert m is not None
        assert m.group(2).decode("ascii").startswith("1037")

    def test_match_group3_is_revision_digit(self):
        m = EXTRACTOR._parse_ident_block(make_m592_256kb_bin())
        assert m is not None
        assert m.group(3).decode("ascii").isdigit()

    def test_match_group4_is_m592_family(self):
        m = EXTRACTOR._parse_ident_block(make_m592_256kb_bin())
        assert m is not None
        assert m.group(4).decode("ascii") == "M5.92"

    def test_match_group4_is_m383_family(self):
        m = EXTRACTOR._parse_ident_block(make_m383_256kb_bin())
        assert m is not None
        assert m.group(4).decode("ascii") == "M3.8.3"

    def test_match_group4_is_m382_family(self):
        m = EXTRACTOR._parse_ident_block(make_m382_128kb_bin())
        assert m is not None
        assert m.group(4).decode("ascii") == "M3.82"

    def test_match_group4_is_m383_alt_family(self):
        m = EXTRACTOR._parse_ident_block(make_m383_alt_256kb_bin())
        assert m is not None
        assert m.group(4).decode("ascii") == "M3.83"

    def test_match_group4_is_m69_family(self):
        m = EXTRACTOR._parse_ident_block(make_phase4_bin())
        assert m is not None
        assert m.group(4).decode("ascii") == "M6.9"


# ---------------------------------------------------------------------------
# TestResolveEcuFamily
# ---------------------------------------------------------------------------


class TestResolveEcuFamily:
    """
    Verify ECU family resolution:
    Priority 1 — ident block group(4) normalised via FAMILY_NORMALISATION.
    Priority 2 — standalone ecu_family_string pattern in ident_area.
    Fallback   — None.
    """

    def _ident(self, data: bytes):
        return EXTRACTOR._parse_ident_block(data)

    # ---- Priority 1: ident block ----

    def test_m592_normalises_to_m59(self):
        data = make_m592_256kb_bin()
        assert EXTRACTOR._resolve_ecu_family(self._ident(data), data) == "M5.9"

    def test_m383_normalises_to_m38(self):
        data = make_m383_256kb_bin()
        assert EXTRACTOR._resolve_ecu_family(self._ident(data), data) == "M3.8"

    def test_m382_normalises_to_m38(self):
        data = make_m382_128kb_bin()
        assert EXTRACTOR._resolve_ecu_family(self._ident(data), data) == "M3.8"

    def test_m383_alt_normalises_to_m38(self):
        data = make_m383_alt_256kb_bin()
        assert EXTRACTOR._resolve_ecu_family(self._ident(data), data) == "M3.8"

    def test_unknown_family_returned_as_is(self):
        """'M6.9' is not in FAMILY_NORMALISATION → returned unchanged."""
        data = make_phase4_bin()
        assert EXTRACTOR._resolve_ecu_family(self._ident(data), data) == "M6.9"

    def test_trailing_dot_stripped_then_normalised(self):
        """Family 'M5.9.' → rstrip('.') = 'M5.9' → FAMILY_NORMALISATION → 'M5.9'."""
        data = make_trailing_dot_family_bin()
        assert EXTRACTOR._resolve_ecu_family(self._ident(data), data) == "M5.9"

    # ---- Priority 2: standalone ecu_family_string ----

    def test_standalone_m592_resolves_to_m59(self):
        """ident=None, ident_area has 'M5.92' → ecu_family_string matches → 'M5.9'."""
        data = make_standalone_only_bin()
        assert EXTRACTOR._resolve_ecu_family(None, data) == "M5.9"

    def test_standalone_m382_resolves_to_m38(self):
        buf = bytearray(0x40000)
        buf[0x0500:0x0505] = b"M3.82"
        assert EXTRACTOR._resolve_ecu_family(None, bytes(buf)) == "M3.8"

    def test_standalone_m383_resolves_to_m38(self):
        buf = bytearray(0x40000)
        buf[0x0500:0x0505] = b"M3.83"
        assert EXTRACTOR._resolve_ecu_family(None, bytes(buf)) == "M3.8"

    def test_standalone_m383_dot_resolves_to_m38(self):
        buf = bytearray(0x40000)
        buf[0x0500:0x0506] = b"M3.8.3"
        assert EXTRACTOR._resolve_ecu_family(None, bytes(buf)) == "M3.8"

    # ---- Fallback: None ----

    def test_no_ident_no_standalone_returns_none(self):
        assert EXTRACTOR._resolve_ecu_family(None, b"\x00" * 0x40000) is None

    def test_empty_data_returns_none(self):
        assert EXTRACTOR._resolve_ecu_family(None, b"") is None

    def test_ident_priority_over_standalone(self):
        """Ident block takes priority; standalone strings are never consulted."""
        data = make_m592_256kb_bin()
        result = EXTRACTOR._resolve_ecu_family(self._ident(data), data)
        assert result == "M5.9"


# ---------------------------------------------------------------------------
# TestResolveSoftwareVersion
# ---------------------------------------------------------------------------


class TestResolveSoftwareVersion:
    """
    Verify SW version resolution:
    Priority 1 — 12-digit raw from ident block → first 10 digits returned.
    Priority 2 — standalone 1037xxxxxx in ident_area.
    Fallback   — None.
    """

    def _ident(self, data: bytes):
        return EXTRACTOR._parse_ident_block(data)

    def test_m592_strips_last_2_digits(self):
        data = make_m592_256kb_bin()
        assert EXTRACTOR._resolve_software_version(self._ident(data), data) == _M592_SW

    def test_m383_strips_last_2_digits(self):
        data = make_m383_256kb_bin()
        assert EXTRACTOR._resolve_software_version(self._ident(data), data) == _M383_SW

    def test_m382_strips_last_2_digits(self):
        data = make_m382_128kb_bin()
        assert EXTRACTOR._resolve_software_version(self._ident(data), data) == _M382_SW

    def test_m383_alt_strips_last_2_digits(self):
        data = make_m383_alt_256kb_bin()
        assert (
            EXTRACTOR._resolve_software_version(self._ident(data), data) == _M383_ALT_SW
        )

    def test_sw_starts_with_1037(self):
        data = make_m592_256kb_bin()
        result = EXTRACTOR._resolve_software_version(self._ident(data), data)
        assert result is not None
        assert result.startswith("1037")

    def test_sw_is_exactly_10_digits(self):
        data = make_m592_256kb_bin()
        result = EXTRACTOR._resolve_software_version(self._ident(data), data)
        assert result is not None
        assert result.isdigit() and len(result) == 10

    def test_standalone_fallback_returns_sw(self):
        """ident=None → standalone 1037xxxxxx matched from ident_area."""
        data = make_standalone_only_bin()
        assert EXTRACTOR._resolve_software_version(None, data) == "1037350269"

    def test_no_ident_no_standalone_returns_none(self):
        assert EXTRACTOR._resolve_software_version(None, b"\x00" * 0x40000) is None

    def test_empty_data_returns_none(self):
        assert EXTRACTOR._resolve_software_version(None, b"") is None


# ---------------------------------------------------------------------------
# TestResolveHardwareNumber
# ---------------------------------------------------------------------------


class TestResolveHardwareNumber:
    """
    Verify HW number resolution:
    Priority 1 — ident block group(1).
    Priority 2 — standalone 0261xxxxxx in ident_area.
    Fallback   — None.
    """

    def _ident(self, data: bytes):
        return EXTRACTOR._parse_ident_block(data)

    def test_m592_hw_from_ident_block(self):
        data = make_m592_256kb_bin()
        assert EXTRACTOR._resolve_hardware_number(self._ident(data), data) == _M592_HW

    def test_m383_hw_from_ident_block(self):
        data = make_m383_256kb_bin()
        assert EXTRACTOR._resolve_hardware_number(self._ident(data), data) == _M383_HW

    def test_m382_hw_from_ident_block(self):
        data = make_m382_128kb_bin()
        assert EXTRACTOR._resolve_hardware_number(self._ident(data), data) == _M382_HW

    def test_m383_alt_hw_from_ident_block(self):
        data = make_m383_alt_256kb_bin()
        assert (
            EXTRACTOR._resolve_hardware_number(self._ident(data), data) == _M383_ALT_HW
        )

    def test_hw_starts_with_0261(self):
        data = make_m592_256kb_bin()
        result = EXTRACTOR._resolve_hardware_number(self._ident(data), data)
        assert result is not None
        assert result.startswith("0261")

    def test_hw_is_exactly_10_digits(self):
        data = make_m592_256kb_bin()
        result = EXTRACTOR._resolve_hardware_number(self._ident(data), data)
        assert result is not None
        assert result.isdigit() and len(result) == 10

    def test_standalone_fallback_returns_hw(self):
        """ident=None → standalone 0261xxxxxx matched from ident_area."""
        data = make_standalone_only_bin()
        assert EXTRACTOR._resolve_hardware_number(None, data) == "0261204258"

    def test_no_ident_no_standalone_returns_none(self):
        assert EXTRACTOR._resolve_hardware_number(None, b"\x00" * 0x40000) is None

    def test_empty_data_returns_none(self):
        assert EXTRACTOR._resolve_hardware_number(None, b"") is None


# ---------------------------------------------------------------------------
# TestResolveOemPartNumber
# ---------------------------------------------------------------------------


class TestResolveOemPartNumber:
    """
    Verify OEM part number extraction and Format A garbage-prefix stripping.

    Pattern: ([0-9][0-9A-Z]{7,13})\\s{1,4}1\\.8L
    Garbage strip: if candidate[0,1,2] are digits AND candidate[3] is alpha,
                   strip the first 2 chars (e.g. "068D..." → "8D...").
    Guards: must contain at least one alpha char; must be >= 8 chars total.
    """

    def test_format_b_clean_oem_returned_as_is(self):
        """'06A906018AQ' has no garbage prefix — returned unchanged."""
        data = make_m383_256kb_bin()
        assert EXTRACTOR._resolve_oem_part_number(data) == _M383_OEM

    def test_format_b_alt_clean_oem_returned_as_is(self):
        data = make_m383_alt_256kb_bin()
        assert EXTRACTOR._resolve_oem_part_number(data) == _M383_ALT_OEM

    def test_format_a_clean_8d_oem_returned_as_is(self):
        """
        '8D0907557P': candidate[0]='8' (digit), candidate[1]='D' (alpha) →
        strip condition requires candidate[1] to be a digit → fails → no strip.
        """
        data = make_m592_256kb_bin()
        assert EXTRACTOR._resolve_oem_part_number(data) == _M592_OEM

    def test_format_a_garbage_068_stripped(self):
        """'068D0907557P': indices 0='0',1='6',2='8',3='D' → strip 2 → '8D0907557P'."""
        data = make_m592_garbage_oem_256kb_bin()
        assert EXTRACTOR._resolve_oem_part_number(data) == "8D0907557P"

    def test_format_a_garbage_038_stripped(self):
        """'038D0907557T': indices 0='0',1='3',2='8',3='D' → strip 2 → '8D0907557T'."""
        data = make_m382_128kb_bin()
        assert EXTRACTOR._resolve_oem_part_number(data) == _M382_OEM

    def test_no_18l_marker_returns_none(self):
        """Phase 4 ident string has no '1.8L' → pattern never matches."""
        data = make_phase4_bin()
        assert EXTRACTOR._resolve_oem_part_number(data) is None

    def test_all_zero_data_returns_none(self):
        assert EXTRACTOR._resolve_oem_part_number(b"\x00" * 0x40000) is None

    def test_empty_data_returns_none(self):
        assert EXTRACTOR._resolve_oem_part_number(b"") is None

    def test_all_digit_candidate_returns_none(self):
        """Candidate with no alpha chars is rejected by the no-alpha guard."""
        buf = bytearray(0x40000)
        buf[0x1000:0x100A] = b"0261204258"  # 10 digits, no letters
        buf[0x100A:0x1010] = b"  1.8L"
        assert EXTRACTOR._resolve_oem_part_number(bytes(buf)) is None

    def test_oem_with_single_space_before_18l(self):
        """Pattern allows 1–4 spaces before '1.8L'."""
        buf = bytearray(0x40000)
        entry = b"06A906018AQ 1.8L"
        buf[0x1000 : 0x1000 + len(entry)] = entry
        assert EXTRACTOR._resolve_oem_part_number(bytes(buf)) == "06A906018AQ"

    def test_oem_with_four_spaces_before_18l(self):
        buf = bytearray(0x40000)
        entry = b"8D0907557P    1.8L"
        buf[0x1000 : 0x1000 + len(entry)] = entry
        assert EXTRACTOR._resolve_oem_part_number(bytes(buf)) == "8D0907557P"

    def test_06a_not_garbage_stripped(self):
        """
        '06A906018AQ': candidate[2]='A' is NOT a digit → strip condition fails
        → returned as-is (not stripped).
        """
        data = make_m383_256kb_bin()
        result = EXTRACTOR._resolve_oem_part_number(data)
        assert result == "06A906018AQ"
        assert not result.startswith("A")  # confirm no strip happened

    def test_short_candidate_with_alpha_returns_none(self):
        """
        Cover the len(candidate) < 8 guard (line 380 of extractor.py).

        The regex always captures ≥ 8 chars so this guard is unreachable in
        normal operation.  A mock match with a 6-char group(1) exercises the
        branch: has alpha ('D') so it passes the alpha check, but length 6 < 8
        → returns None.
        """
        mock_m = MagicMock()
        mock_m.group.return_value = b"8D0907"  # 6 chars, has alpha, < 8

        target = "openremap.tuning.manufacturers.bosch.m5x.extractor.re.search"
        with patch(target, return_value=mock_m):
            result = EXTRACTOR._resolve_oem_part_number(b"\x00" * 0x40000)

        assert result is None


# ---------------------------------------------------------------------------
# TestExtractRequiredKeys
# ---------------------------------------------------------------------------


class TestExtractRequiredKeys:
    """extract() must always return every key in REQUIRED_EXTRACT_KEYS."""

    def _check(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data, filename="test.bin")

    def test_required_keys_m592(self):
        result = self._check(make_m592_256kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_m383(self):
        result = self._check(make_m383_256kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_m382_128kb(self):
        result = self._check(make_m382_128kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_m383_alt(self):
        result = self._check(make_m383_alt_256kb_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_phase4(self):
        result = self._check(make_phase4_bin())
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_manufacturer_always_bosch(self):
        result = self._check(make_m592_256kb_bin())
        assert result["manufacturer"] == "Bosch"

    def test_manufacturer_always_bosch_m383(self):
        result = self._check(make_m383_256kb_bin())
        assert result["manufacturer"] == "Bosch"

    def test_file_size_equals_data_length(self):
        data = make_m592_256kb_bin()
        assert self._check(data)["file_size"] == len(data)

    def test_file_size_128kb(self):
        data = make_m382_128kb_bin()
        assert self._check(data)["file_size"] == 0x20000

    def test_file_size_256kb(self):
        data = make_m592_256kb_bin()
        assert self._check(data)["file_size"] == 0x40000

    def test_raw_strings_is_list(self):
        result = self._check(make_m592_256kb_bin())
        assert isinstance(result["raw_strings"], list)

    def test_ecu_variant_equals_ecu_family(self):
        result = self._check(make_m592_256kb_bin())
        assert result["ecu_variant"] == result["ecu_family"]

    def test_ecu_variant_equals_ecu_family_m383(self):
        result = self._check(make_m383_256kb_bin())
        assert result["ecu_variant"] == result["ecu_family"]


# ---------------------------------------------------------------------------
# TestExtractM592
# ---------------------------------------------------------------------------


class TestExtractM592:
    """Full extraction for a clean M5.92 256KB bin (Format A, clean OEM)."""

    def setup_method(self):
        self.data = make_m592_256kb_bin()
        self.result = EXTRACTOR.extract(self.data, filename="test_m592.bin")

    def test_ecu_family_is_m59(self):
        assert self.result["ecu_family"] == "M5.9"

    def test_ecu_variant_is_m59(self):
        assert self.result["ecu_variant"] == "M5.9"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _M592_HW

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_hardware_number_is_10_digits(self):
        assert self.result["hardware_number"].isdigit()
        assert len(self.result["hardware_number"]) == 10

    def test_software_version(self):
        assert self.result["software_version"] == _M592_SW

    def test_software_version_starts_with_1037(self):
        assert self.result["software_version"].startswith("1037")

    def test_software_version_is_10_digits(self):
        assert self.result["software_version"].isdigit()
        assert len(self.result["software_version"]) == 10

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == _M592_OEM

    def test_file_size_is_256kb(self):
        assert self.result["file_size"] == 0x40000

    def test_match_key_format(self):
        assert self.result["match_key"] == f"M5.9::{_M592_SW}"

    def test_match_key_is_uppercase(self):
        assert self.result["match_key"] == self.result["match_key"].upper()

    def test_raw_strings_not_empty(self):
        assert len(self.result["raw_strings"]) > 0

    def test_raw_strings_contain_motr(self):
        combined = " ".join(self.result["raw_strings"])
        assert "MOTR" in combined


# ---------------------------------------------------------------------------
# TestExtractM592GarbageOem
# ---------------------------------------------------------------------------


class TestExtractM592GarbageOem:
    """
    M5.92 256KB with 2-digit garbage OEM prefix.
    Verifies _resolve_oem_part_number() strips the prefix correctly.
    """

    def setup_method(self):
        self.data = make_m592_garbage_oem_256kb_bin()
        self.result = EXTRACTOR.extract(self.data, filename="garbage_oem.bin")

    def test_ecu_family_is_m59(self):
        assert self.result["ecu_family"] == "M5.9"

    def test_oem_garbage_stripped(self):
        assert self.result["oem_part_number"] == "8D0907557P"

    def test_hardware_number_unaffected(self):
        assert self.result["hardware_number"] == _M592_HW

    def test_software_version_unaffected(self):
        assert self.result["software_version"] == _M592_SW

    def test_match_key_unaffected_by_oem(self):
        assert self.result["match_key"] == f"M5.9::{_M592_SW}"


# ---------------------------------------------------------------------------
# TestExtractM383
# ---------------------------------------------------------------------------


class TestExtractM383:
    """Full extraction for M3.8.3 256KB bin (Format B / MOTR HS)."""

    def setup_method(self):
        self.data = make_m383_256kb_bin()
        self.result = EXTRACTOR.extract(self.data, filename="test_m383.bin")

    def test_ecu_family_is_m38(self):
        assert self.result["ecu_family"] == "M3.8"

    def test_ecu_variant_is_m38(self):
        assert self.result["ecu_variant"] == "M3.8"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _M383_HW

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_software_version(self):
        assert self.result["software_version"] == _M383_SW

    def test_software_version_is_10_digits(self):
        assert self.result["software_version"].isdigit()
        assert len(self.result["software_version"]) == 10

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == _M383_OEM

    def test_file_size_is_256kb(self):
        assert self.result["file_size"] == 0x40000

    def test_match_key_format(self):
        assert self.result["match_key"] == f"M3.8::{_M383_SW}"

    def test_match_key_is_uppercase(self):
        assert self.result["match_key"] == self.result["match_key"].upper()


# ---------------------------------------------------------------------------
# TestExtractM382_128KB
# ---------------------------------------------------------------------------


class TestExtractM382_128KB:
    """Full extraction for M3.82 128KB bin (Format A, garbage OEM prefix)."""

    def setup_method(self):
        self.data = make_m382_128kb_bin()
        self.result = EXTRACTOR.extract(self.data, filename="test_m382_128k.bin")

    def test_file_size_is_128kb(self):
        assert self.result["file_size"] == 0x20000

    def test_ecu_family_is_m38(self):
        assert self.result["ecu_family"] == "M3.8"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _M382_HW

    def test_software_version(self):
        assert self.result["software_version"] == _M382_SW

    def test_oem_garbage_prefix_stripped(self):
        """'038D0907557T' → strip 2 digits → '8D0907557T'."""
        assert self.result["oem_part_number"] == _M382_OEM

    def test_match_key_format(self):
        assert self.result["match_key"] == f"M3.8::{_M382_SW}"

    def test_match_key_is_uppercase(self):
        assert self.result["match_key"] == self.result["match_key"].upper()

    def test_ecu_variant_equals_ecu_family(self):
        assert self.result["ecu_variant"] == self.result["ecu_family"]


# ---------------------------------------------------------------------------
# TestExtractM383Alt
# ---------------------------------------------------------------------------


class TestExtractM383Alt:
    """Full extraction for M3.83 256KB bin (Format B / MOTR HS)."""

    def setup_method(self):
        self.data = make_m383_alt_256kb_bin()
        self.result = EXTRACTOR.extract(self.data, filename="test_m383_alt.bin")

    def test_ecu_family_is_m38(self):
        """M3.83 normalises to M3.8."""
        assert self.result["ecu_family"] == "M3.8"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _M383_ALT_HW

    def test_software_version(self):
        assert self.result["software_version"] == _M383_ALT_SW

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == _M383_ALT_OEM

    def test_match_key_format(self):
        assert self.result["match_key"] == f"M3.8::{_M383_ALT_SW}"


# ---------------------------------------------------------------------------
# TestExtractPhase4
# ---------------------------------------------------------------------------


class TestExtractPhase4:
    """
    Extraction for a Phase-4 bin: family 'M6.9' not in FAMILY_NORMALISATION
    so it is returned as-is. No OEM (no '1.8L' in ident string).
    """

    def setup_method(self):
        self.data = make_phase4_bin()
        self.result = EXTRACTOR.extract(self.data, filename="test_phase4.bin")

    def test_ecu_family_unknown_returned_as_is(self):
        assert self.result["ecu_family"] == "M6.9"

    def test_ecu_variant_equals_ecu_family(self):
        assert self.result["ecu_variant"] == "M6.9"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == "0261204258"

    def test_software_version(self):
        assert self.result["software_version"] == "1037350269"

    def test_oem_part_number_is_none(self):
        """No '1.8L' string in the Phase 4 ident block."""
        assert self.result["oem_part_number"] is None

    def test_match_key_uses_unknown_family(self):
        assert self.result["match_key"] == "M6.9::1037350269"

    def test_file_size_is_256kb(self):
        assert self.result["file_size"] == 0x40000


# ---------------------------------------------------------------------------
# TestExtractStandaloneOnly
# ---------------------------------------------------------------------------


class TestExtractStandaloneOnly:
    """
    Bin with no ident block — resolvers fall back to Priority-2 standalone
    patterns for family, HW, and SW.

    Note: can_handle() returns False for this bin (no ident block) but
    extract() can still be called directly to exercise the fallback paths.
    """

    def setup_method(self):
        self.data = make_standalone_only_bin()
        self.result = EXTRACTOR.extract(self.data, filename="standalone.bin")

    def test_ecu_family_from_standalone(self):
        """'M5.92' in ident_area → ecu_family_string match → normalised 'M5.9'."""
        assert self.result["ecu_family"] == "M5.9"

    def test_hardware_number_from_standalone(self):
        assert self.result["hardware_number"] == "0261204258"

    def test_software_version_from_standalone(self):
        assert self.result["software_version"] == "1037350269"

    def test_oem_part_number_is_none(self):
        """No '1.8L' string → None."""
        assert self.result["oem_part_number"] is None

    def test_match_key_built_from_standalone(self):
        assert self.result["match_key"] == "M5.9::1037350269"

    def test_ecu_variant_equals_ecu_family(self):
        assert self.result["ecu_variant"] == self.result["ecu_family"]


# ---------------------------------------------------------------------------
# TestExtractNullFields
# ---------------------------------------------------------------------------


class TestExtractNullFields:
    """
    Fields not present in M5.x binaries must always be None in every extract()
    call regardless of which sub-family the bin belongs to.
    """

    def _result(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data, filename="null_check.bin")

    def test_calibration_version_is_none_m592(self):
        assert self._result(make_m592_256kb_bin())["calibration_version"] is None

    def test_calibration_version_is_none_m383(self):
        assert self._result(make_m383_256kb_bin())["calibration_version"] is None

    def test_sw_base_version_is_none(self):
        assert self._result(make_m592_256kb_bin())["sw_base_version"] is None

    def test_serial_number_is_none(self):
        assert self._result(make_m592_256kb_bin())["serial_number"] is None

    def test_dataset_number_is_none(self):
        assert self._result(make_m592_256kb_bin())["dataset_number"] is None

    def test_calibration_id_is_none(self):
        assert self._result(make_m592_256kb_bin())["calibration_id"] is None

    def test_calibration_id_is_none_m383(self):
        assert self._result(make_m383_256kb_bin())["calibration_id"] is None

    def test_calibration_id_is_none_m382(self):
        assert self._result(make_m382_128kb_bin())["calibration_id"] is None

    def test_sw_base_version_is_none_m383(self):
        assert self._result(make_m383_256kb_bin())["sw_base_version"] is None

    def test_serial_number_is_none_m382(self):
        assert self._result(make_m382_128kb_bin())["serial_number"] is None


# ---------------------------------------------------------------------------
# TestExtractHashing
# ---------------------------------------------------------------------------


class TestExtractHashing:
    """Verify md5 and sha256_first_64kb correctness for multiple bins."""

    def _check(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data, filename="hash_check.bin")

    def test_md5_is_32_hex_chars_m592(self):
        result = self._check(make_m592_256kb_bin())
        assert len(result["md5"]) == 32
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_correct_m592(self):
        data = make_m592_256kb_bin()
        assert self._check(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_m383(self):
        data = make_m383_256kb_bin()
        assert self._check(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_m382(self):
        data = make_m382_128kb_bin()
        assert self._check(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_is_64_hex_chars(self):
        result = self._check(make_m592_256kb_bin())
        assert len(result["sha256_first_64kb"]) == 64
        assert all(c in "0123456789abcdef" for c in result["sha256_first_64kb"])

    def test_sha256_covers_only_first_64kb(self):
        data = make_m592_256kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._check(data)["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_correct_m383(self):
        data = make_m383_256kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._check(data)["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_correct_m382_128kb(self):
        data = make_m382_128kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._check(data)["sha256_first_64kb"] == expected

    def test_different_bins_different_md5(self):
        r1 = self._check(make_m592_256kb_bin())
        r2 = self._check(make_m383_256kb_bin())
        assert r1["md5"] != r2["md5"]

    def test_128kb_and_256kb_different_sha256(self):
        r1 = self._check(make_m382_128kb_bin())
        r2 = self._check(make_m592_256kb_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]


# ---------------------------------------------------------------------------
# TestMatchKey
# ---------------------------------------------------------------------------


class TestMatchKey:
    """Verify build_match_key() behaviour as invoked by extract()."""

    def _result(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data, filename="mk.bin")

    def test_match_key_none_when_no_sw_no_ident(self):
        """All-zero 256KB has no SW → match_key must be None."""
        result = self._result(b"\x00" * 0x40000)
        assert result["match_key"] is None

    def test_match_key_format_m592(self):
        result = self._result(make_m592_256kb_bin())
        assert result["match_key"] == f"M5.9::{_M592_SW}"

    def test_match_key_format_m383(self):
        result = self._result(make_m383_256kb_bin())
        assert result["match_key"] == f"M3.8::{_M383_SW}"

    def test_match_key_format_m382(self):
        result = self._result(make_m382_128kb_bin())
        assert result["match_key"] == f"M3.8::{_M382_SW}"

    def test_match_key_format_m383_alt(self):
        result = self._result(make_m383_alt_256kb_bin())
        assert result["match_key"] == f"M3.8::{_M383_ALT_SW}"

    def test_match_key_is_always_uppercase(self):
        result = self._result(make_m592_256kb_bin())
        assert result["match_key"] == result["match_key"].upper()

    def test_match_key_is_always_uppercase_m383(self):
        result = self._result(make_m383_256kb_bin())
        assert result["match_key"] == result["match_key"].upper()

    def test_different_sw_gives_different_match_key(self):
        r1 = self._result(make_m592_256kb_bin())
        r2 = self._result(make_m383_256kb_bin())
        assert r1["match_key"] != r2["match_key"]

    def test_match_key_separator_is_double_colon(self):
        result = self._result(make_m592_256kb_bin())
        assert "::" in result["match_key"]

    def test_match_key_prefix_is_family(self):
        result = self._result(make_m592_256kb_bin())
        prefix, _ = result["match_key"].split("::")
        assert prefix == "M5.9"

    def test_match_key_suffix_is_sw(self):
        result = self._result(make_m592_256kb_bin())
        _, suffix = result["match_key"].split("::")
        assert suffix == _M592_SW


# ---------------------------------------------------------------------------
# TestDeterminism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """extract() must be deterministic; filename must not affect field values."""

    def test_same_binary_same_result_m592(self):
        data = make_m592_256kb_bin()
        r1 = EXTRACTOR.extract(data, filename="a.bin")
        r2 = EXTRACTOR.extract(data, filename="a.bin")
        assert r1 == r2

    def test_same_binary_same_result_m383(self):
        data = make_m383_256kb_bin()
        r1 = EXTRACTOR.extract(data, filename="b.bin")
        r2 = EXTRACTOR.extract(data, filename="b.bin")
        assert r1 == r2

    def test_filename_does_not_affect_m592_fields(self):
        data = make_m592_256kb_bin()
        r1 = EXTRACTOR.extract(data, filename="foo.bin")
        r2 = EXTRACTOR.extract(data, filename="completely_different_name.bin")
        assert r1["ecu_family"] == r2["ecu_family"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["oem_part_number"] == r2["oem_part_number"]
        assert r1["match_key"] == r2["match_key"]

    def test_filename_does_not_affect_m383_fields(self):
        data = make_m383_256kb_bin()
        r1 = EXTRACTOR.extract(data, filename="orig.bin")
        r2 = EXTRACTOR.extract(data, filename="copy.bin")
        assert r1["software_version"] == r2["software_version"]
        assert r1["hardware_number"] == r2["hardware_number"]

    def test_different_binaries_produce_different_md5(self):
        r1 = EXTRACTOR.extract(make_m592_256kb_bin(), filename="x.bin")
        r2 = EXTRACTOR.extract(make_m383_256kb_bin(), filename="x.bin")
        assert r1["md5"] != r2["md5"]

    def test_file_size_reflects_actual_binary_size_256kb(self):
        data = make_m592_256kb_bin()
        assert EXTRACTOR.extract(data, filename="x.bin")["file_size"] == len(data)

    def test_file_size_reflects_actual_binary_size_128kb(self):
        data = make_m382_128kb_bin()
        assert EXTRACTOR.extract(data, filename="x.bin")["file_size"] == len(data)

    def test_can_handle_then_extract_m592_consistent(self):
        """can_handle() True → extract() fields are non-None."""
        data = make_m592_256kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data, filename="x.bin")
        assert result["ecu_family"] is not None
        assert result["software_version"] is not None
        assert result["hardware_number"] is not None

    def test_can_handle_then_extract_m383_consistent(self):
        data = make_m383_256kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data, filename="x.bin")
        assert result["ecu_family"] is not None
        assert result["software_version"] is not None

    def test_can_handle_then_extract_m382_consistent(self):
        data = make_m382_128kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data, filename="x.bin")
        assert result["ecu_family"] is not None
        assert result["software_version"] is not None
