"""
Tests for BoschM4xExtractor (M4.3 / M4.4 — Volvo 850 / 960 / S70 / V70 / S60 / S80).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * Phase 3: M4.3 bin (DAMOS "/M4.3/" token + ident)
      * Phase 3: M4.4 bin (DAMOS "/M4.4/" token + ident)
      * Phase 3: DAMOS-only (no ident digit run) → accepted via DAMOS token
      * Phase 4: ident-only (no DAMOS) → accepted via sequential digit run
      * Phase 4: ident with .NN suffix accepted
      * Phase 4: 1267 and 2227 SW prefixes accepted
  - can_handle() — False paths:
      * Empty binary
      * All-zero 64KB / 128KB
      * All-FF 64KB / 128KB
      * Wrong sizes (32KB, 256KB, 512KB)
      * No DAMOS and no valid ident → rejected
      * Short ident (< 20 digits) without DAMOS → rejected
      * Bad HW prefix in ident without DAMOS → rejected
      * Bad SW prefix in ident without DAMOS → rejected
  - can_handle() — Exclusions:
      * Every EXCLUSION_SIGNATURES entry blocks an otherwise-valid bin
      * Exclusion at offset 0 still caught
      * Exclusion near end of bin still caught
  - _parse_ident_digits():
      * Returns (hw, sw, cal) for valid M4.3 ident
      * Returns (hw, sw, cal) for valid M4.4 ident
      * Strips .NN suffix before parsing
      * Returns (hw, sw, None) when extra digits absent (exactly 20 digits)
      * Returns (None, None, None) for short ident (< 20)
      * Returns (None, None, None) for bad HW prefix
      * Returns (None, None, None) for bad SW prefix
      * Returns (None, None, None) for all-zero data
  - _resolve_ecu_family():
      * Priority 1: DAMOS descriptor → "M4.3" / "M4.4"
      * Priority 2: file-size heuristic → 64KB = "M4.3", 128KB = "M4.4"
      * None when neither path fires (should not happen after can_handle)
  - _resolve_dataset_number():
      * Extracts dataset code from DAMOS descriptor
      * Returns None when no DAMOS present
  - extract() — required keys always present (both sub-families)
  - extract() — M4.3 full extraction (HW / SW / cal / family / match_key)
  - extract() — M4.4 full extraction
  - extract() — ident-only (no DAMOS; family from size heuristic)
  - extract() — ident with .NN suffix (suffix stripped correctly)
  - extract() — 1267 SW prefix
  - extract() — 2227 SW prefix
  - extract() — DAMOS-only (no ident; HW/SW/cal all None, match_key None)
  - extract() — null fields always None (oem_part_number, calibration_version, etc.)
  - extract() — hashing (md5 and sha256_first_64kb correctness)
  - match_key format, None when SW absent, always uppercase, fallback to cal_id
  - Determinism and filename independence
"""

import hashlib
import re

import pytest

from openremap.core.manufacturers.bosch.m4x.extractor import BoschM4xExtractor
from openremap.core.manufacturers.bosch.m4x.patterns import EXCLUSION_SIGNATURES

EXTRACTOR = BoschM4xExtractor()

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

# M4.3 — 64KB Volvo 850 / 960 era
_M43_DAMOS = b"44/1/M4.3/09/5033/DAMOS0C03//040398/"
_M43_IDENT = b"026120422510373552771270544"
_M43_HW = "0261204225"
_M43_SW = "1037355277"
_M43_CAL = "1270544"
_M43_DATASET = "5033"

# M4.4 — 128KB Volvo S60 / S70 / V70 / S80 era
_M44_DAMOS = b"47/1/M4.4/05/5044/DAMOS0C04//150699/"
_M44_IDENT = b"026120423910373557801280422"
_M44_HW = "0261204239"
_M44_SW = "1037355780"
_M44_CAL = "1280422"
_M44_DATASET = "5044"

# Ident with .NN suffix (M4.3)
_M43_IDENT_SUFFIX = b"026120422510373552771270544.05"

# Ident with 1267 SW prefix
_M43_IDENT_1267 = b"02612042251267355277"
_M43_SW_1267 = "1267355277"

# Ident with 2227 SW prefix
_M43_IDENT_2227 = b"02612042252227355277"
_M43_SW_2227 = "2227355277"

# Minimal 20-digit ident (no extra/cal digits)
_M43_IDENT_MINIMAL = b"02612042251037355277"

# Ident with 2537 SW prefix (Volvo 850 T5-R variant)
_M43_IDENT_2537 = b"02612042252537355277"
_M43_SW_2537 = "2537355277"

# Ident with leading prefix digits before 0261 (seen in some M4.3 bins)
_M43_IDENT_LEADING = b"02026120404122273558991275232"
_M43_LEADING_HW = "0261204041"
_M43_LEADING_SW = "2227355899"
_M43_LEADING_CAL = "1275232"

# Deep-offset ident (placed ~5KB from end, outside old 2KB search window)
_M43_IDENT_DEEP = b"026120054812673586381275104"
_M43_DEEP_HW = "0261200548"
_M43_DEEP_SW = "1267358638"
_M43_DEEP_CAL = "1275104"

# Early-offset ident (placed at 0x1703 — near start of file, outside last 8KB).
# Reproduces the Volvo 960 B6304 204HP layout where the ident block is near the
# beginning of the 128KB file and must be found via full-binary fallback search.
_M44_IDENT_EARLY = b"026120423910373557801270422"
_M44_EARLY_HW = "0261204239"
_M44_EARLY_SW = "1037355780"
_M44_EARLY_CAL = "1270422"


# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------


def make_m43_64kb_bin(
    with_damos: bool = True,
    with_ident: bool = True,
) -> bytes:
    """
    M4.3, 64KB (0x10000).

    DAMOS descriptor placed at 0x3000.
    Ident digit run placed at offset -0x200 from end of file.
    """
    buf = bytearray(0x10000)
    if with_damos:
        buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
    if with_ident:
        offset = len(buf) - 0x200
        buf[offset : offset + len(_M43_IDENT)] = _M43_IDENT
    return bytes(buf)


def make_m44_128kb_bin(
    with_damos: bool = True,
    with_ident: bool = True,
) -> bytes:
    """
    M4.4, 128KB (0x20000).

    DAMOS descriptor placed at 0x8000.
    Ident digit run placed at offset -0x200 from end of file.
    """
    buf = bytearray(0x20000)
    if with_damos:
        buf[0x8000 : 0x8000 + len(_M44_DAMOS)] = _M44_DAMOS
    if with_ident:
        offset = len(buf) - 0x200
        buf[offset : offset + len(_M44_IDENT)] = _M44_IDENT
    return bytes(buf)


def make_ident_only_m43_bin() -> bytes:
    """M4.3 64KB with ident only, no DAMOS descriptor."""
    return make_m43_64kb_bin(with_damos=False, with_ident=True)


def make_ident_only_m44_bin() -> bytes:
    """M4.4 128KB with ident only, no DAMOS descriptor."""
    return make_m44_128kb_bin(with_damos=False, with_ident=True)


def make_damos_only_m43_bin() -> bytes:
    """M4.3 64KB with DAMOS descriptor only, no ident digit run."""
    return make_m43_64kb_bin(with_damos=True, with_ident=False)


def make_damos_only_m44_bin() -> bytes:
    """M4.4 128KB with DAMOS descriptor only, no ident digit run."""
    return make_m44_128kb_bin(with_damos=True, with_ident=False)


def make_ident_with_suffix_bin() -> bytes:
    """M4.3 64KB with .NN suffix on the ident digit run."""
    buf = bytearray(0x10000)
    buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
    offset = len(buf) - 0x200
    buf[offset : offset + len(_M43_IDENT_SUFFIX)] = _M43_IDENT_SUFFIX
    return bytes(buf)


def make_1267_sw_bin() -> bytes:
    """M4.3 64KB with 1267 SW prefix in ident digit run."""
    buf = bytearray(0x10000)
    buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
    offset = len(buf) - 0x200
    buf[offset : offset + len(_M43_IDENT_1267)] = _M43_IDENT_1267
    return bytes(buf)


def make_2227_sw_bin() -> bytes:
    """M4.3 64KB with 2227 SW prefix in ident digit run."""
    buf = bytearray(0x10000)
    buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
    offset = len(buf) - 0x200
    buf[offset : offset + len(_M43_IDENT_2227)] = _M43_IDENT_2227
    return bytes(buf)


def make_minimal_ident_bin() -> bytes:
    """M4.3 64KB with exactly 20-digit ident (no extra cal digits)."""
    buf = bytearray(0x10000)
    buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
    offset = len(buf) - 0x200
    buf[offset : offset + len(_M43_IDENT_MINIMAL)] = _M43_IDENT_MINIMAL
    return bytes(buf)


def make_2537_sw_bin() -> bytes:
    """M4.3 64KB with 2537 SW prefix in ident digit run."""
    buf = bytearray(0x10000)
    buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
    offset = len(buf) - 0x200
    buf[offset : offset + len(_M43_IDENT_2537)] = _M43_IDENT_2537
    return bytes(buf)


def make_deep_offset_ident_bin(with_damos: bool = True) -> bytes:
    """M4.3 64KB with ident digit run at ~5KB from end (offset 0xEC18)."""
    buf = bytearray(0x10000)
    if with_damos:
        buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
    offset = 0xEC18  # ~5KB from end of 64KB file
    buf[offset : offset + len(_M43_IDENT_DEEP)] = _M43_IDENT_DEEP
    return bytes(buf)


def make_leading_prefix_ident_bin(with_damos: bool = True) -> bytes:
    """M4.3 64KB with leading prefix digits before 0261 in ident run."""
    buf = bytearray(0x10000)
    if with_damos:
        buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
    offset = 0xEC18  # deep offset like real-world files
    buf[offset : offset + len(_M43_IDENT_LEADING)] = _M43_IDENT_LEADING
    return bytes(buf)


def make_early_offset_ident_bin() -> bytes:
    """M4.4 128KB with ident at early offset 0x1703 (not in last 8KB).

    Reproduces the Volvo 960 B6304 204HP layout where the ident block is
    near the start of the file (~5.7KB from beginning), with the DAMOS
    descriptor near the end.  The ident is located via full-binary fallback
    search after the standard last-8KB search finds nothing.
    """
    buf = bytearray(0x20000)
    # DAMOS near end of file (like real Volvo 960 B6304 at ~0x1FF10)
    damos_offset = 0x1FF10
    buf[damos_offset : damos_offset + len(_M44_DAMOS)] = _M44_DAMOS
    # Ident at early offset (like real file at 0x1703)
    buf[0x1703 : 0x1703 + len(_M44_IDENT_EARLY)] = _M44_IDENT_EARLY
    return bytes(buf)


def _inject_exclusion(buf: bytearray, sig: bytes, offset: int = 0x0200) -> bytearray:
    """Write an exclusion signature into a mutable buffer at the given offset."""
    buf[offset : offset + len(sig)] = sig
    return buf


# ===========================================================================
# Identity
# ===========================================================================


class TestIdentity:
    """BoschM4xExtractor identity properties."""

    def test_name_is_bosch(self):
        assert EXTRACTOR.name == "Bosch"

    def test_name_is_string(self):
        assert isinstance(EXTRACTOR.name, str)

    def test_supported_families_is_list(self):
        assert isinstance(EXTRACTOR.supported_families, list)

    def test_supported_families_not_empty(self):
        assert len(EXTRACTOR.supported_families) > 0

    def test_m43_in_supported_families(self):
        assert "M4.3" in EXTRACTOR.supported_families

    def test_m44_in_supported_families(self):
        assert "M4.4" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        assert all(isinstance(f, str) for f in EXTRACTOR.supported_families)

    def test_repr_is_string(self):
        assert isinstance(repr(EXTRACTOR), str)

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschM4xExtractor" in repr(EXTRACTOR)

    def test_match_key_fallback_field_is_calibration_id(self):
        assert EXTRACTOR.match_key_fallback_field == "calibration_id"


# ===========================================================================
# can_handle — True paths
# ===========================================================================


class TestCanHandleTrue:
    """Binaries that must be accepted by can_handle()."""

    def test_m43_64kb_accepted(self):
        assert EXTRACTOR.can_handle(make_m43_64kb_bin()) is True

    def test_m44_128kb_accepted(self):
        assert EXTRACTOR.can_handle(make_m44_128kb_bin()) is True

    def test_damos_only_m43_accepted(self):
        """DAMOS present but no ident → Phase 3 accepts."""
        assert EXTRACTOR.can_handle(make_damos_only_m43_bin()) is True

    def test_damos_only_m44_accepted(self):
        """DAMOS present but no ident → Phase 3 accepts."""
        assert EXTRACTOR.can_handle(make_damos_only_m44_bin()) is True

    def test_ident_only_m43_accepted(self):
        """Ident present but no DAMOS → Phase 4 accepts."""
        assert EXTRACTOR.can_handle(make_ident_only_m43_bin()) is True

    def test_ident_only_m44_accepted(self):
        """Ident present but no DAMOS → Phase 4 accepts."""
        assert EXTRACTOR.can_handle(make_ident_only_m44_bin()) is True

    def test_ident_with_suffix_accepted(self):
        assert EXTRACTOR.can_handle(make_ident_with_suffix_bin()) is True

    def test_1267_sw_prefix_accepted(self):
        """1267 SW prefix fires Phase 4 (or Phase 3 via DAMOS)."""
        assert EXTRACTOR.can_handle(make_1267_sw_bin()) is True

    def test_2227_sw_prefix_accepted(self):
        """2227 SW prefix fires Phase 4 (or Phase 3 via DAMOS)."""
        assert EXTRACTOR.can_handle(make_2227_sw_bin()) is True

    def test_minimal_ident_accepted(self):
        """Exactly 20-digit ident (no extra cal digits) accepted."""
        assert EXTRACTOR.can_handle(make_minimal_ident_bin()) is True

    def test_ident_only_1267_no_damos_accepted(self):
        """Phase 4 fires on 1267 prefix without DAMOS."""
        buf = bytearray(0x10000)
        offset = len(buf) - 0x200
        buf[offset : offset + len(_M43_IDENT_1267)] = _M43_IDENT_1267
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_ident_only_2227_no_damos_accepted(self):
        buf = bytearray(0x10000)
        offset = len(buf) - 0x200
        buf[offset : offset + len(_M43_IDENT_2227)] = _M43_IDENT_2227
        data = bytes(buf)
        assert EXTRACTOR.can_handle(data) is True

    def test_deep_offset_ident_accepted_via_damos(self):
        """Ident at ~5KB from end accepted when DAMOS token present (Phase 3)."""
        assert EXTRACTOR.can_handle(make_deep_offset_ident_bin(with_damos=True)) is True

    def test_deep_offset_ident_accepted_via_phase4(self):
        """Ident at ~5KB from end accepted even without DAMOS (Phase 4)."""
        assert (
            EXTRACTOR.can_handle(make_deep_offset_ident_bin(with_damos=False)) is True
        )

    def test_leading_prefix_ident_accepted_via_damos(self):
        """Leading prefix digits before 0261 accepted when DAMOS present."""
        assert (
            EXTRACTOR.can_handle(make_leading_prefix_ident_bin(with_damos=True)) is True
        )

    def test_leading_prefix_ident_accepted_via_phase4(self):
        """Leading prefix digits before 0261 accepted even without DAMOS."""
        assert (
            EXTRACTOR.can_handle(make_leading_prefix_ident_bin(with_damos=False))
            is True
        )

    def test_2537_sw_prefix_accepted(self):
        buf = bytearray(0x10000)
        offset = len(buf) - 0x200
        buf[offset : offset + len(_M43_IDENT_2537)] = _M43_IDENT_2537
        data = bytes(buf)
        assert EXTRACTOR.can_handle(data) is True


# ===========================================================================
# can_handle — False paths
# ===========================================================================


class TestCanHandleFalse:
    """Binaries that must be rejected by can_handle()."""

    def test_empty_binary_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_all_zero_64kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x10000)) is False

    def test_all_zero_128kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x20000)) is False

    def test_all_ff_64kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\xff" * 0x10000) is False

    def test_all_ff_128kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\xff" * 0x20000) is False

    def test_wrong_size_32kb_rejected(self):
        buf = bytearray(0x8000)
        buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_wrong_size_256kb_rejected(self):
        buf = bytearray(0x40000)
        buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_wrong_size_512kb_rejected(self):
        buf = bytearray(0x80000)
        buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_no_damos_no_ident_rejected(self):
        """No DAMOS token and no valid ident → both Phase 3 & 4 fail."""
        assert EXTRACTOR.can_handle(bytes(0x10000)) is False

    def test_short_ident_rejected_without_damos(self):
        """Short ident (< 20 digits) and no DAMOS → rejected."""
        buf = bytearray(0x10000)
        short = b"0261204225103735"  # only 16 digits
        offset = len(buf) - 0x200
        buf[offset : offset + len(short)] = short
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_bad_hw_prefix_rejected_without_damos(self):
        """Ident with wrong HW prefix and no DAMOS → rejected."""
        buf = bytearray(0x10000)
        bad_ident = b"99991042251037355277"
        offset = len(buf) - 0x200
        buf[offset : offset + len(bad_ident)] = bad_ident
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_bad_sw_prefix_rejected_without_damos(self):
        """Ident with unrecognised SW prefix and no DAMOS → rejected."""
        buf = bytearray(0x10000)
        bad_ident = b"02612042259999355277"  # SW prefix 9999
        offset = len(buf) - 0x200
        buf[offset : offset + len(bad_ident)] = bad_ident
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_random_repeated_ascii_64kb_rejected(self):
        buf = bytearray(b"ABCDEFGH" * (0x10000 // 8))
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ===========================================================================
# can_handle — Exclusions
# ===========================================================================


class TestCanHandleExclusions:
    """Exclusion signatures must block ident-only bins (fallback detection path).

    DAMOS-detected bins bypass exclusions because the DAMOS family token
    ("/M4.3/" or "/M4.4/") is an authoritative positive signal — coincidental
    byte sequences in calibration table data (e.g. ZZ\\xff\\xff) must not
    override a genuine DAMOS identification.
    """

    def _ident_only_m43_buf(self) -> bytearray:
        """M4.3 bin with ident digit run only — no DAMOS descriptor."""
        return bytearray(make_ident_only_m43_bin())

    def _ident_only_m44_buf(self) -> bytearray:
        """M4.4 bin with ident digit run only — no DAMOS descriptor."""
        return bytearray(make_ident_only_m44_bin())

    # --- Exclusions block ident-only (fallback) detection path ---

    @pytest.mark.parametrize("sig", EXCLUSION_SIGNATURES)
    def test_exclusion_sig_rejects_ident_only_bin(self, sig):
        """Every exclusion signature must block an ident-only bin."""
        buf = self._ident_only_m43_buf()
        _inject_exclusion(buf, sig)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc17_exclusion_explicit(self):
        buf = self._ident_only_m43_buf()
        _inject_exclusion(buf, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_dot_exclusion_explicit(self):
        buf = self._ident_only_m43_buf()
        _inject_exclusion(buf, b"ME7.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_motronic_exclusion_explicit(self):
        buf = self._ident_only_m43_buf()
        _inject_exclusion(buf, b"MOTRONIC")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_zz_ff_ff_exclusion_ident_only(self):
        """ZZ\\xff\\xff blocks ident-only bins (ME7 marker in fallback path)."""
        buf = self._ident_only_m43_buf()
        buf[0x0100:0x0104] = b"ZZ\xff\xff"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_at_offset_zero(self):
        buf = self._ident_only_m43_buf()
        _inject_exclusion(buf, b"EDC17", offset=0)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_near_end_of_bin_still_caught(self):
        buf = self._ident_only_m43_buf()
        _inject_exclusion(buf, b"SB_V", offset=len(buf) - 10)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_blocks_ident_only_m43(self):
        buf = self._ident_only_m43_buf()
        _inject_exclusion(buf, b"MEDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_blocks_ident_only_m44(self):
        buf = self._ident_only_m44_buf()
        _inject_exclusion(buf, b"EDC15")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m1_55_exclusion(self):
        """M1.55 exclusion prevents claiming Alfa Romeo bins."""
        buf = self._ident_only_m43_buf()
        _inject_exclusion(buf, b"M1.55")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    # --- DAMOS-detected bins bypass exclusions (authoritative positive) ---

    @pytest.mark.parametrize("sig", EXCLUSION_SIGNATURES)
    def test_damos_bin_bypasses_exclusion(self, sig):
        """A bin with a genuine DAMOS token must NOT be rejected by exclusions.

        Real-world case: Volvo 960 B6304 M4.4 has coincidental ZZ\\xff\\xff
        bytes in calibration table data — should still be detected via DAMOS.
        """
        buf = bytearray(make_m43_64kb_bin())  # has both DAMOS and ident
        _inject_exclusion(buf, sig)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_damos_m44_bypasses_zz_ff_ff(self):
        """M4.4 bin with DAMOS and coincidental ZZ\\xff\\xff is still accepted.

        Reproduces the Volvo 960 B6304 204HP false-exclusion bug.
        """
        buf = bytearray(make_m44_128kb_bin())
        buf[0x3200:0x3206] = b"ZZZ\xff\xff\xff"  # calibration table data
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_damos_m43_bypasses_edc17(self):
        """M4.3 bin with DAMOS is not rejected by coincidental EDC17 bytes."""
        buf = bytearray(make_m43_64kb_bin())
        _inject_exclusion(buf, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_damos_m44_bypasses_motronic(self):
        """M4.4 bin with DAMOS is not rejected by coincidental MOTRONIC bytes."""
        buf = bytearray(make_m44_128kb_bin())
        _inject_exclusion(buf, b"MOTRONIC")
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ===========================================================================
# _parse_ident_digits
# ===========================================================================


class TestParseIdentDigits:
    """Direct tests for the sequential-digit ident parser."""

    def test_m43_returns_hw_sw_cal(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(make_m43_64kb_bin())
        assert hw == _M43_HW
        assert sw == _M43_SW
        assert cal == _M43_CAL

    def test_m44_returns_hw_sw_cal(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(make_m44_128kb_bin())
        assert hw == _M44_HW
        assert sw == _M44_SW
        assert cal == _M44_CAL

    def test_hw_starts_with_0261(self):
        hw, _, _ = EXTRACTOR._parse_ident_digits(make_m43_64kb_bin())
        assert hw is not None
        assert hw.startswith("0261")

    def test_hw_is_exactly_10_digits(self):
        hw, _, _ = EXTRACTOR._parse_ident_digits(make_m43_64kb_bin())
        assert hw is not None
        assert len(hw) == 10
        assert hw.isdigit()

    def test_sw_starts_with_1037(self):
        _, sw, _ = EXTRACTOR._parse_ident_digits(make_m43_64kb_bin())
        assert sw is not None
        assert sw.startswith("1037")

    def test_sw_is_exactly_10_digits(self):
        _, sw, _ = EXTRACTOR._parse_ident_digits(make_m43_64kb_bin())
        assert sw is not None
        assert len(sw) == 10
        assert sw.isdigit()

    def test_cal_is_all_digits(self):
        _, _, cal = EXTRACTOR._parse_ident_digits(make_m43_64kb_bin())
        assert cal is not None
        assert cal.isdigit()

    def test_suffix_stripped_hw_correct(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(make_ident_with_suffix_bin())
        assert hw == _M43_HW

    def test_suffix_stripped_sw_correct(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(make_ident_with_suffix_bin())
        assert sw == _M43_SW

    def test_suffix_stripped_cal_correct(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(make_ident_with_suffix_bin())
        assert cal == _M43_CAL

    def test_minimal_ident_no_cal(self):
        """Exactly 20 digits → hw + sw but no extra cal digits."""
        hw, sw, cal = EXTRACTOR._parse_ident_digits(make_minimal_ident_bin())
        assert hw == _M43_HW
        assert sw == _M43_SW
        assert cal is None

    def test_1267_sw_prefix(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(make_1267_sw_bin())
        assert sw == _M43_SW_1267

    def test_2227_sw_prefix(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(make_2227_sw_bin())
        assert sw == _M43_SW_2227

    def test_short_ident_returns_none(self):
        buf = bytearray(0x10000)
        short = b"0261204225103735"  # 16 digits — too short
        offset = len(buf) - 0x200
        buf[offset : offset + len(short)] = short
        hw, sw, cal = EXTRACTOR._parse_ident_digits(bytes(buf))
        assert hw is None
        assert sw is None
        assert cal is None

    def test_bad_hw_prefix_returns_none(self):
        buf = bytearray(0x10000)
        bad = b"99991042251037355277"
        offset = len(buf) - 0x200
        buf[offset : offset + len(bad)] = bad
        hw, sw, cal = EXTRACTOR._parse_ident_digits(bytes(buf))
        assert hw is None

    def test_bad_sw_prefix_returns_none(self):
        buf = bytearray(0x10000)
        bad = b"02612042259999355277"
        offset = len(buf) - 0x200
        buf[offset : offset + len(bad)] = bad
        hw, sw, cal = EXTRACTOR._parse_ident_digits(bytes(buf))
        assert sw is None

    def test_all_zero_data_returns_none(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(bytes(0x10000))
        assert hw is None
        assert sw is None
        assert cal is None

    def test_empty_data_returns_none(self):
        hw, sw, cal = EXTRACTOR._parse_ident_digits(b"")
        assert hw is None
        assert sw is None
        assert cal is None

    def test_deep_offset_ident_returns_hw(self):
        """Ident digit run at ~5KB from end is still found and parsed."""
        data = make_deep_offset_ident_bin(with_damos=False)
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert hw == _M43_DEEP_HW

    def test_deep_offset_ident_returns_sw(self):
        data = make_deep_offset_ident_bin(with_damos=False)
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert sw == _M43_DEEP_SW

    def test_deep_offset_ident_returns_cal(self):
        data = make_deep_offset_ident_bin(with_damos=False)
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert cal == _M43_DEEP_CAL

    def test_leading_prefix_stripped_hw_correct(self):
        """Leading '02' before 0261 is stripped; HW parsed correctly."""
        data = make_leading_prefix_ident_bin(with_damos=False)
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert hw == _M43_LEADING_HW

    def test_leading_prefix_stripped_sw_correct(self):
        data = make_leading_prefix_ident_bin(with_damos=False)
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert sw == _M43_LEADING_SW

    def test_leading_prefix_stripped_cal_correct(self):
        data = make_leading_prefix_ident_bin(with_damos=False)
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert cal == _M43_LEADING_CAL

    def test_2537_sw_prefix(self):
        data = make_2537_sw_bin()
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert sw == _M43_SW_2537

    def test_2537_sw_starts_with_2537(self):
        data = make_2537_sw_bin()
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert sw.startswith("2537")

    def test_leading_prefix_too_far_returns_none(self):
        """Leading prefix > 4 digits before 0261 should be rejected."""
        buf = bytearray(0x10000)
        bad = b"9999902612042251037355277"  # 5 leading digits before 0261
        offset = len(buf) - 0x200
        buf[offset : offset + len(bad)] = bad
        hw, sw, cal = EXTRACTOR._parse_ident_digits(bytes(buf))
        assert hw is None

    def test_early_offset_ident_returns_hw(self):
        """Ident at offset 0x1703 (outside last 8KB) is found via full-binary fallback."""
        data = make_early_offset_ident_bin()
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert hw == _M44_EARLY_HW

    def test_early_offset_ident_returns_sw(self):
        """Early-offset ident SW is parsed correctly via fallback search."""
        data = make_early_offset_ident_bin()
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert sw == _M44_EARLY_SW

    def test_early_offset_ident_returns_cal(self):
        """Early-offset ident calibration is parsed correctly via fallback search."""
        data = make_early_offset_ident_bin()
        hw, sw, cal = EXTRACTOR._parse_ident_digits(data)
        assert cal == _M44_EARLY_CAL

    def test_early_offset_with_zz_ff_ff_still_extracts(self):
        """Volvo 960 B6304 scenario: early ident + coincidental ZZ\\xff\\xff."""
        buf = bytearray(make_early_offset_ident_bin())
        buf[0x3200:0x3206] = b"ZZZ\xff\xff\xff"  # calibration table data
        hw, sw, cal = EXTRACTOR._parse_ident_digits(bytes(buf))
        assert hw == _M44_EARLY_HW
        assert sw == _M44_EARLY_SW
        assert cal == _M44_EARLY_CAL


# ===========================================================================
# _resolve_ecu_family
# ===========================================================================


class TestResolveEcuFamily:
    """Direct tests for ECU family resolution."""

    def test_m43_from_damos(self):
        assert EXTRACTOR._resolve_ecu_family(make_m43_64kb_bin()) == "M4.3"

    def test_m44_from_damos(self):
        assert EXTRACTOR._resolve_ecu_family(make_m44_128kb_bin()) == "M4.4"

    def test_m43_from_size_fallback(self):
        """No DAMOS → size heuristic picks M4.3 for 64KB."""
        assert EXTRACTOR._resolve_ecu_family(make_ident_only_m43_bin()) == "M4.3"

    def test_m44_from_size_fallback(self):
        """No DAMOS → size heuristic picks M4.4 for 128KB."""
        assert EXTRACTOR._resolve_ecu_family(make_ident_only_m44_bin()) == "M4.4"

    def test_damos_priority_over_size(self):
        """DAMOS family takes priority even when size would suggest otherwise."""
        # Create a 128KB bin but inject M4.3 DAMOS (unusual but tests priority)
        buf = bytearray(0x20000)
        buf[0x3000 : 0x3000 + len(_M43_DAMOS)] = _M43_DAMOS
        assert EXTRACTOR._resolve_ecu_family(bytes(buf)) == "M4.3"

    def test_none_for_unsupported_size_without_damos(self):
        """Neither DAMOS nor size heuristic → None."""
        buf = bytes(0x8000)  # 32KB
        assert EXTRACTOR._resolve_ecu_family(buf) is None

    def test_all_zero_64kb_returns_m43_via_size(self):
        """Even all-zero 64KB → size heuristic returns M4.3."""
        assert EXTRACTOR._resolve_ecu_family(bytes(0x10000)) == "M4.3"


# ===========================================================================
# _resolve_dataset_number
# ===========================================================================


class TestResolveDatasetNumber:
    """Direct tests for dataset number resolution from DAMOS descriptor."""

    def test_m43_dataset(self):
        assert EXTRACTOR._resolve_dataset_number(make_m43_64kb_bin()) == _M43_DATASET

    def test_m44_dataset(self):
        assert EXTRACTOR._resolve_dataset_number(make_m44_128kb_bin()) == _M44_DATASET

    def test_no_damos_returns_none(self):
        assert EXTRACTOR._resolve_dataset_number(make_ident_only_m43_bin()) is None

    def test_empty_data_returns_none(self):
        assert EXTRACTOR._resolve_dataset_number(b"") is None


# ===========================================================================
# extract() — required keys
# ===========================================================================


class TestExtractRequiredKeys:
    """All required keys must be present in every extract() result."""

    def _check(self, data):
        result = EXTRACTOR.extract(data)
        assert REQUIRED_EXTRACT_KEYS.issubset(result.keys())

    def test_required_keys_m43(self):
        self._check(make_m43_64kb_bin())

    def test_required_keys_m44(self):
        self._check(make_m44_128kb_bin())

    def test_required_keys_ident_only_m43(self):
        self._check(make_ident_only_m43_bin())

    def test_required_keys_damos_only_m43(self):
        self._check(make_damos_only_m43_bin())

    def test_required_keys_ident_suffix(self):
        self._check(make_ident_with_suffix_bin())

    def test_required_keys_1267(self):
        self._check(make_1267_sw_bin())

    def test_required_keys_2227(self):
        self._check(make_2227_sw_bin())

    def test_manufacturer_always_bosch(self):
        result = EXTRACTOR.extract(make_m43_64kb_bin())
        assert result["manufacturer"] == "Bosch"

    def test_manufacturer_always_bosch_m44(self):
        result = EXTRACTOR.extract(make_m44_128kb_bin())
        assert result["manufacturer"] == "Bosch"

    def test_file_size_equals_data_length_64kb(self):
        data = make_m43_64kb_bin()
        result = EXTRACTOR.extract(data)
        assert result["file_size"] == len(data)

    def test_file_size_equals_data_length_128kb(self):
        data = make_m44_128kb_bin()
        result = EXTRACTOR.extract(data)
        assert result["file_size"] == len(data)

    def test_raw_strings_is_list(self):
        result = EXTRACTOR.extract(make_m43_64kb_bin())
        assert isinstance(result["raw_strings"], list)

    def test_ecu_variant_equals_ecu_family_m43(self):
        result = EXTRACTOR.extract(make_m43_64kb_bin())
        assert result["ecu_variant"] == result["ecu_family"]

    def test_ecu_variant_equals_ecu_family_m44(self):
        result = EXTRACTOR.extract(make_m44_128kb_bin())
        assert result["ecu_variant"] == result["ecu_family"]


# ===========================================================================
# extract() — M4.3 full extraction
# ===========================================================================


class TestExtractM43:
    """Full extraction tests for M4.3 (64KB) bins."""

    def setup_method(self):
        self.data = make_m43_64kb_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_m43(self):
        assert self.result["ecu_family"] == "M4.3"

    def test_ecu_variant_is_m43(self):
        assert self.result["ecu_variant"] == "M4.3"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _M43_HW

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert len(hw) == 10
        assert hw.isdigit()

    def test_software_version(self):
        assert self.result["software_version"] == _M43_SW

    def test_software_version_starts_with_1037(self):
        assert self.result["software_version"].startswith("1037")

    def test_software_version_is_10_digits(self):
        sw = self.result["software_version"]
        assert len(sw) == 10
        assert sw.isdigit()

    def test_calibration_id(self):
        assert self.result["calibration_id"] == _M43_CAL

    def test_calibration_id_is_all_digits(self):
        assert self.result["calibration_id"].isdigit()

    def test_dataset_number(self):
        assert self.result["dataset_number"] == _M43_DATASET

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000

    def test_match_key_format(self):
        assert self.result["match_key"] == f"M4.3::{_M43_SW}"

    def test_match_key_is_uppercase(self):
        assert self.result["match_key"] == self.result["match_key"].upper()

    def test_raw_strings_not_empty(self):
        assert len(self.result["raw_strings"]) > 0


# ===========================================================================
# extract() — M4.4 full extraction
# ===========================================================================


class TestExtractM44:
    """Full extraction tests for M4.4 (128KB) bins."""

    def setup_method(self):
        self.data = make_m44_128kb_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_m44(self):
        assert self.result["ecu_family"] == "M4.4"

    def test_ecu_variant_is_m44(self):
        assert self.result["ecu_variant"] == "M4.4"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _M44_HW

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_software_version(self):
        assert self.result["software_version"] == _M44_SW

    def test_software_version_is_10_digits(self):
        sw = self.result["software_version"]
        assert len(sw) == 10
        assert sw.isdigit()

    def test_calibration_id(self):
        assert self.result["calibration_id"] == _M44_CAL

    def test_dataset_number(self):
        assert self.result["dataset_number"] == _M44_DATASET

    def test_file_size_is_128kb(self):
        assert self.result["file_size"] == 0x20000

    def test_match_key_format(self):
        assert self.result["match_key"] == f"M4.4::{_M44_SW}"

    def test_match_key_is_uppercase(self):
        assert self.result["match_key"] == self.result["match_key"].upper()


# ===========================================================================
# extract() — ident-only (no DAMOS; family from size heuristic)
# ===========================================================================


class TestExtractIdentOnly:
    """Extraction with ident digit run present but no DAMOS descriptor."""

    def setup_method(self):
        self.result_m43 = EXTRACTOR.extract(make_ident_only_m43_bin())
        self.result_m44 = EXTRACTOR.extract(make_ident_only_m44_bin())

    def test_m43_family_from_size(self):
        assert self.result_m43["ecu_family"] == "M4.3"

    def test_m44_family_from_size(self):
        assert self.result_m44["ecu_family"] == "M4.4"

    def test_m43_hw(self):
        assert self.result_m43["hardware_number"] == _M43_HW

    def test_m44_hw(self):
        assert self.result_m44["hardware_number"] == _M44_HW

    def test_m43_sw(self):
        assert self.result_m43["software_version"] == _M43_SW

    def test_m44_sw(self):
        assert self.result_m44["software_version"] == _M44_SW

    def test_m43_dataset_none(self):
        assert self.result_m43["dataset_number"] is None

    def test_m44_dataset_none(self):
        assert self.result_m44["dataset_number"] is None

    def test_m43_match_key(self):
        assert self.result_m43["match_key"] == f"M4.3::{_M43_SW}"

    def test_m44_match_key(self):
        assert self.result_m44["match_key"] == f"M4.4::{_M44_SW}"


# ===========================================================================
# extract() — ident with .NN suffix
# ===========================================================================


class TestExtractIdentSuffix:
    """Extraction with .NN suffix on the ident digit run."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_ident_with_suffix_bin())

    def test_hw_correct(self):
        assert self.result["hardware_number"] == _M43_HW

    def test_sw_correct(self):
        assert self.result["software_version"] == _M43_SW

    def test_cal_correct(self):
        assert self.result["calibration_id"] == _M43_CAL

    def test_match_key_unaffected_by_suffix(self):
        assert self.result["match_key"] == f"M4.3::{_M43_SW}"


# ===========================================================================
# extract() — alternate SW prefixes (1267 and 2227)
# ===========================================================================


class TestExtract1267SwPrefix:
    """Extraction with 1267 SW prefix."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_1267_sw_bin())

    def test_sw_prefix_1267(self):
        assert self.result["software_version"] == _M43_SW_1267

    def test_sw_starts_with_1267(self):
        assert self.result["software_version"].startswith("1267")

    def test_hw_unaffected(self):
        assert self.result["hardware_number"] == _M43_HW

    def test_match_key_uses_1267_sw(self):
        assert self.result["match_key"] == f"M4.3::{_M43_SW_1267}"


class TestExtract2227SwPrefix:
    """Extraction with 2227 SW prefix."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_2227_sw_bin())

    def test_sw_prefix_2227(self):
        assert self.result["software_version"] == _M43_SW_2227

    def test_sw_starts_with_2227(self):
        assert self.result["software_version"].startswith("2227")

    def test_match_key_uses_2227_sw(self):
        assert self.result["match_key"] == f"M4.3::{_M43_SW_2227}"


class TestExtract2537SwPrefix:
    """Extraction with 2537 SW prefix (Volvo 850 T5-R variant)."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_2537_sw_bin())

    def test_sw_prefix_2537(self):
        assert self.result["software_version"] == _M43_SW_2537

    def test_sw_starts_with_2537(self):
        assert self.result["software_version"].startswith("2537")

    def test_hw_unaffected(self):
        assert self.result["hardware_number"] == _M43_HW

    def test_match_key_uses_2537_sw(self):
        assert self.result["match_key"] == f"M4.3::{_M43_SW_2537}"


# ===========================================================================
# extract() — minimal ident (exactly 20 digits, no calibration extra)
# ===========================================================================


class TestExtractMinimalIdent:
    """Extraction with exactly 20-digit ident (no extra cal digits)."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_minimal_ident_bin())

    def test_hw(self):
        assert self.result["hardware_number"] == _M43_HW

    def test_sw(self):
        assert self.result["software_version"] == _M43_SW

    def test_cal_is_none(self):
        assert self.result["calibration_id"] is None

    def test_match_key_uses_sw(self):
        assert self.result["match_key"] == f"M4.3::{_M43_SW}"


# ===========================================================================
# extract() — deep-offset ident (~5KB from end, outside old 2KB window)
# ===========================================================================


class TestExtractDeepOffsetIdent:
    """Extraction with ident digit run at ~5KB from end of 64KB file."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_deep_offset_ident_bin(with_damos=True))

    def test_hw(self):
        assert self.result["hardware_number"] == _M43_DEEP_HW

    def test_sw(self):
        assert self.result["software_version"] == _M43_DEEP_SW

    def test_cal(self):
        assert self.result["calibration_id"] == _M43_DEEP_CAL

    def test_ecu_family(self):
        assert self.result["ecu_family"] == "M4.3"

    def test_match_key(self):
        assert self.result["match_key"] == f"M4.3::{_M43_DEEP_SW}"

    def test_match_key_not_none(self):
        """Regression: previously None because ident was outside 2KB window."""
        assert self.result["match_key"] is not None


class TestExtractDeepOffsetIdentNoDAMOS:
    """Deep-offset ident without DAMOS — family from size heuristic."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_deep_offset_ident_bin(with_damos=False))

    def test_hw(self):
        assert self.result["hardware_number"] == _M43_DEEP_HW

    def test_sw(self):
        assert self.result["software_version"] == _M43_DEEP_SW

    def test_family_from_size(self):
        assert self.result["ecu_family"] == "M4.3"

    def test_dataset_none_without_damos(self):
        assert self.result["dataset_number"] is None


# ===========================================================================
# extract() — leading prefix digits before 0261 in ident run
# ===========================================================================


class TestExtractLeadingPrefixIdent:
    """Extraction with leading prefix digits before 0261 (e.g. '020261...')."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_leading_prefix_ident_bin(with_damos=True))

    def test_hw(self):
        assert self.result["hardware_number"] == _M43_LEADING_HW

    def test_sw(self):
        assert self.result["software_version"] == _M43_LEADING_SW

    def test_cal(self):
        assert self.result["calibration_id"] == _M43_LEADING_CAL

    def test_ecu_family(self):
        assert self.result["ecu_family"] == "M4.3"

    def test_match_key(self):
        assert self.result["match_key"] == f"M4.3::{_M43_LEADING_SW}"

    def test_match_key_not_none(self):
        """Regression: previously None because leading digits broke 0261 alignment."""
        assert self.result["match_key"] is not None


# ===========================================================================
# extract() — DAMOS-only (no ident; HW/SW/cal all None)
# ===========================================================================


class TestExtractDamosOnly:
    """Extraction with DAMOS present but no ident digit run."""

    def setup_method(self):
        self.result = EXTRACTOR.extract(make_damos_only_m43_bin())

    def test_ecu_family(self):
        assert self.result["ecu_family"] == "M4.3"

    def test_hw_is_none(self):
        assert self.result["hardware_number"] is None

    def test_sw_is_none(self):
        assert self.result["software_version"] is None

    def test_cal_is_none(self):
        assert self.result["calibration_id"] is None

    def test_dataset_present(self):
        assert self.result["dataset_number"] == _M43_DATASET

    def test_match_key_is_none(self):
        """No SW and no cal → match_key is None."""
        assert self.result["match_key"] is None


# ===========================================================================
# extract() — null fields
# ===========================================================================


class TestExtractNullFields:
    """Fields that should always be None in M4.x binaries."""

    def _result(self, data):
        return EXTRACTOR.extract(data)

    def test_oem_part_number_is_none_m43(self):
        assert self._result(make_m43_64kb_bin())["oem_part_number"] is None

    def test_oem_part_number_is_none_m44(self):
        assert self._result(make_m44_128kb_bin())["oem_part_number"] is None

    def test_calibration_version_is_none_m43(self):
        assert self._result(make_m43_64kb_bin())["calibration_version"] is None

    def test_calibration_version_is_none_m44(self):
        assert self._result(make_m44_128kb_bin())["calibration_version"] is None

    def test_sw_base_version_is_none(self):
        assert self._result(make_m43_64kb_bin())["sw_base_version"] is None

    def test_serial_number_is_none(self):
        assert self._result(make_m43_64kb_bin())["serial_number"] is None

    def test_serial_number_is_none_m44(self):
        assert self._result(make_m44_128kb_bin())["serial_number"] is None


# ===========================================================================
# extract() — hashing
# ===========================================================================


class TestExtractHashing:
    """Hashing fields must be computed correctly."""

    def _check(self, data):
        return EXTRACTOR.extract(data)

    def test_md5_is_32_hex_chars_m43(self):
        result = self._check(make_m43_64kb_bin())
        assert re.match(r"^[0-9a-f]{32}$", result["md5"])

    def test_md5_correct_m43(self):
        data = make_m43_64kb_bin()
        result = self._check(data)
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_m44(self):
        data = make_m44_128kb_bin()
        result = self._check(data)
        assert result["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_is_64_hex_chars(self):
        result = self._check(make_m43_64kb_bin())
        assert re.match(r"^[0-9a-f]{64}$", result["sha256_first_64kb"])

    def test_sha256_covers_only_first_64kb(self):
        data = make_m43_64kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        result = self._check(data)
        assert result["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_correct_m44(self):
        data = make_m44_128kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        result = self._check(data)
        assert result["sha256_first_64kb"] == expected

    def test_different_bins_different_md5(self):
        r1 = self._check(make_m43_64kb_bin())
        r2 = self._check(make_m44_128kb_bin())
        assert r1["md5"] != r2["md5"]

    def test_64kb_and_128kb_different_sha256(self):
        r1 = self._check(make_m43_64kb_bin())
        r2 = self._check(make_m44_128kb_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]


# ===========================================================================
# match_key
# ===========================================================================


class TestMatchKey:
    """Match key format and edge cases."""

    def _result(self, data):
        return EXTRACTOR.extract(data)

    def test_match_key_none_when_no_sw_no_cal(self):
        """No ident at all (DAMOS-only) → match_key None."""
        result = self._result(make_damos_only_m43_bin())
        assert result["match_key"] is None

    def test_match_key_format_m43(self):
        result = self._result(make_m43_64kb_bin())
        assert result["match_key"] == f"M4.3::{_M43_SW}"

    def test_match_key_format_m44(self):
        result = self._result(make_m44_128kb_bin())
        assert result["match_key"] == f"M4.4::{_M44_SW}"

    def test_match_key_is_always_uppercase(self):
        result = self._result(make_m43_64kb_bin())
        assert result["match_key"] == result["match_key"].upper()

    def test_match_key_is_always_uppercase_m44(self):
        result = self._result(make_m44_128kb_bin())
        assert result["match_key"] == result["match_key"].upper()

    def test_different_sw_gives_different_match_key(self):
        r1 = self._result(make_m43_64kb_bin())
        r2 = self._result(make_m44_128kb_bin())
        assert r1["match_key"] != r2["match_key"]

    def test_match_key_separator_is_double_colon(self):
        result = self._result(make_m43_64kb_bin())
        assert "::" in result["match_key"]

    def test_match_key_prefix_is_family(self):
        result = self._result(make_m43_64kb_bin())
        prefix = result["match_key"].split("::")[0]
        assert prefix == "M4.3"

    def test_match_key_suffix_is_sw(self):
        result = self._result(make_m43_64kb_bin())
        suffix = result["match_key"].split("::")[1]
        assert suffix == _M43_SW

    def test_match_key_fallback_to_cal_id(self):
        """
        When SW is absent but calibration_id is present, the fallback
        mechanism uses cal_id as the match_key version component.

        Build a bin where:
          - DAMOS is present (family = M4.3)
          - Ident digit run is present (HW + SW + cal)
          - Then corrupt the SW field to make _parse_ident_digits return None for SW
          - Actually, easier: build a bin where the ident has cal but we
            mock SW to None... Let's test the build_match_key fallback directly.
        """
        # Test the fallback path via build_match_key directly
        mk = EXTRACTOR.build_match_key(
            ecu_family="M4.3",
            ecu_variant="M4.3",
            software_version=None,
            fallback_value="1270544",
        )
        assert mk == "M4.3::1270544"


# ===========================================================================
# Determinism
# ===========================================================================


class TestDeterminism:
    """Repeated extraction of the same binary yields identical results."""

    def test_same_binary_same_result_m43(self):
        data = make_m43_64kb_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1 == r2

    def test_same_binary_same_result_m44(self):
        data = make_m44_128kb_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1 == r2

    def test_filename_does_not_affect_m43_fields(self):
        data = make_m43_64kb_bin()
        r1 = EXTRACTOR.extract(data, filename="volvo_850.bin")
        r2 = EXTRACTOR.extract(data, filename="unknown.ori")
        # All identifying fields should be identical
        for key in (
            "ecu_family",
            "hardware_number",
            "software_version",
            "calibration_id",
            "match_key",
            "md5",
        ):
            assert r1[key] == r2[key], f"Mismatch on field {key}"

    def test_filename_does_not_affect_m44_fields(self):
        data = make_m44_128kb_bin()
        r1 = EXTRACTOR.extract(data, filename="volvo_s60.bin")
        r2 = EXTRACTOR.extract(data, filename="test.ori")
        for key in ("ecu_family", "hardware_number", "software_version", "match_key"):
            assert r1[key] == r2[key], f"Mismatch on field {key}"

    def test_different_binaries_produce_different_md5(self):
        r1 = EXTRACTOR.extract(make_m43_64kb_bin())
        r2 = EXTRACTOR.extract(make_m44_128kb_bin())
        assert r1["md5"] != r2["md5"]

    def test_file_size_reflects_actual_binary_size_64kb(self):
        data = make_m43_64kb_bin()
        assert EXTRACTOR.extract(data)["file_size"] == 0x10000

    def test_file_size_reflects_actual_binary_size_128kb(self):
        data = make_m44_128kb_bin()
        assert EXTRACTOR.extract(data)["file_size"] == 0x20000

    def test_can_handle_then_extract_m43_consistent(self):
        data = make_m43_64kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data)
        assert result["ecu_family"] == "M4.3"
        assert result["hardware_number"] == _M43_HW
        assert result["software_version"] == _M43_SW

    def test_can_handle_then_extract_m44_consistent(self):
        data = make_m44_128kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data)
        assert result["ecu_family"] == "M4.4"
        assert result["hardware_number"] == _M44_HW
        assert result["software_version"] == _M44_SW

    def test_can_handle_then_extract_ident_only_consistent(self):
        data = make_ident_only_m43_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data)
        assert result["ecu_family"] == "M4.3"
        assert result["hardware_number"] == _M43_HW
