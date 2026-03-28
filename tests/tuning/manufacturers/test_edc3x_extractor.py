"""
Tests for BoschEDC3xExtractor (VAG / BMW / Opel EDC 3.x diesel ROMs).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — Phase 1 (size gate): 128KB/256KB/512KB accepted, others rejected
  - can_handle() — Phase 2 (exclusions): all 10 EXCLUSION_SIGNATURES block detection
  - can_handle() — Phase 2b guards: TSW at EDC15 offset and b"1037" anywhere reject
  - can_handle() — Phase 3 (VAG ident): primary regex scan accepts all VAG bins
  - can_handle() — Phase 3b (BMW ident): anchor+window strategy accepts BMW bins
  - can_handle() — Phase 4 (VV33 header magic): fallback for header-intact bins
  - can_handle() — Phase 5 (C3 fill ratio > 15%): fallback for fill-detected bins
  - can_handle() — Phase 6 (Opel TSW at 0xC000): 256KB Opel diesel bins
  - _find_bmw_sw_block(): unit tests for all three anchor sub-formats
  - _parse_ident_vag(): VAG HEX-block parser — groups, leading-v strip, AG variant
  - _parse_ident_bmw(): BMW numeric parser — SW code, 7-digit cal, HW recovery
  - _parse_ident_opel_256(): Opel doubled-char parser — sentinel variants, de-doubling
  - _parse_ident_opel(): Opel simple cal parser — \xff+U and \xaa sentinel variants
  - extract() — required keys always present for every format
  - extract() — VAG 256KB full extraction (HW / dataset-as-SW / OEM / match_key)
  - extract() — VAG 512KB with AG variant
  - extract() — BMW 256KB (5331A1 SW code, 7-digit cal, HW from tail)
  - extract() — BMW 128KB HI chip (3150 block)
  - extract() — BMW 128KB LO chip (53C0 block, HW absent)
  - extract() — Opel 128KB (Format 3, \xff+U sentinel)
  - extract() — Opel 256KB (Format 4, doubled-char block)
  - extract() — fallback-detected bin with no parseable ident
  - extract() — null fields always None (calibration_id, sw_base_version, etc.)
  - extract() — hashing (md5 and sha256_first_64kb correctness)
  - match_key format, None when SW absent, always uppercase, ecu_variant excluded
  - Determinism and filename independence
"""

import hashlib

import pytest

from openremap.tuning.manufacturers.bosch.edc3x.extractor import (
    ALT_VV33_MAGIC,
    BMW_128_ANCHOR_HI,
    BMW_128_ANCHOR_LO,
    BMW_256_ANCHOR,
    EXCLUSION_SIGNATURES,
    OPEL_256_TSW_REGION,
    VV33_MAGIC,
    BoschEDC3xExtractor,
)

EXTRACTOR = BoschEDC3xExtractor()

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
# Reference field values (from verified sample bins)
# ---------------------------------------------------------------------------

# VAG 256KB (SG variant) — 028906021GM / 0281001658 / C86BM500
_VAG_IDENT = (
    b"v028906021GM 1,9l R4 EDC  SG  1421 0281001658 C86BM500HEX028906021GM 1096"
)
_VAG_OEM = "028906021GM"
_VAG_HW = "0281001658"
_VAG_DATASET = "C86BM500"  # returned as software_version

# VAG 512KB (AG variant) — 4B0907401AC / 0281010399 / A15CEHK2
_VAG_AG_IDENT = (
    b"4B0907401AC 2.5l/4VTEDC  AG  D62  0281010399 A15CEHK2HEX4B0907401AC 1299"
)
_VAG_AG_OEM = "4B0907401AC"
_VAG_AG_HW = "0281010399"
_VAG_AG_DATASET = "A15CEHK2"

# BMW 256KB (5331A1) — 0281001445 / 7785098
_BMW_256_HW = b"0281001445"
_BMW_256_SW_CODE = "5331A1"
_BMW_256_CAL = "7785098"

# BMW 128KB HI chip (3150) — 7687887
_BMW_128_HI_SW_CODE = "3150"
_BMW_128_HI_CAL = "7687887"

# BMW 128KB LO chip (53C0) — 7887768
_BMW_128_LO_SW_CODE = "53C0"
_BMW_128_LO_CAL = "7887768"

# Opel 128KB (Format 3) — LLL chip, \xff+U sentinel
_OPEL_128_HW = b"0281001634"
_OPEL_128_SW_CODE = "A"
_OPEL_128_CAL = "0770164"

# Opel 256KB (Format 4) — doubled-char block
_OPEL_256_HW = b"0281001633"
_OPEL_256_SW_CODE = "A"
_OPEL_256_CAL = "0770164"

# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------

# BMW SW blocks (pre-built byte sequences for reuse in factories and unit tests)

_BMW_256_BLOCK = (
    b"\xc3\xc3"  # anchor start (matches BMW_256_ANCHOR prefix)
    b"00005331A1"  # 0000 padding + SW code x1
    b"00005331A1"  # SW code x2
    b"00005331A1"  # SW code x3
    b"0"  # separator zero
    b"7785098"  # 7-digit cal x1
    b"77850987785098"  # cal x2 + x3 (greedy \d+ consumes these)
    b"U\xaa"  # sentinel
)

_BMW_128_HI_BLOCK = (
    b"\xc3\xc3"  # anchor start
    b"003150"  # 00 padding + SW code x1
    b"003150"  # SW code x2
    b"003150"  # SW code x3
    b"7687887"  # 7-digit cal x1
    b"76878877687887"  # cal x2 + x3
    b"\xaaU"  # sentinel [\xaaU]{2}
)

_BMW_128_LO_BLOCK = (
    b"\xc3\xc3"  # anchor start
    b"0053C0"  # 00 padding + SW code x1
    b"0053C0"  # SW code x2
    b"0053C0"  # SW code x3
    b"7887768"  # 7-digit cal x1
    b"78877687887768"  # cal x2 + x3
    b"UU"  # sentinel [\xaaU]{2} — U=0x55
)

# Opel 256KB doubled-char ident block
# cal="0770164", sw_code="A" → sentinel \x55\xaa + AA + 00 77 77 00 11 66 44
_OPEL_256_IDENT_BLOCK = (
    b"\x55\xaa"  # sentinel (\x55\xaa variant)
    + b"AA"  # doubled 'A' (sw_code)
    + b"00"  # doubled '0'
    + b"77"  # doubled '7'
    + b"77"  # doubled '7'
    + b"00"  # doubled '0'
    + b"11"  # doubled '1'
    + b"66"  # doubled '6'
    + b"44"  # doubled '4'
)

# Opel 256KB doubled-char ident block (alternate \xaa\x55 sentinel)
_OPEL_256_IDENT_BLOCK_ALT = b"\xaa\x55" + _OPEL_256_IDENT_BLOCK[2:]


def make_vag_256kb_bin() -> bytes:
    """VAG 256KB: VV33 header at offset 0, VAG SG ident at 0x2000."""
    buf = bytearray(0x40000)
    buf[0:10] = VV33_MAGIC
    buf[0x2000 : 0x2000 + len(_VAG_IDENT)] = _VAG_IDENT
    return bytes(buf)


def make_vag_128kb_bin() -> bytes:
    """VAG 128KB: ALT_VV33 header at offset 0, VAG ident at 0x1000."""
    buf = bytearray(0x20000)
    buf[0:5] = ALT_VV33_MAGIC
    buf[0x1000 : 0x1000 + len(_VAG_IDENT)] = _VAG_IDENT
    return bytes(buf)


def make_vag_512kb_bin() -> bytes:
    """VAG 512KB: VAG AG ident at 0x2000 (no header magic needed)."""
    buf = bytearray(0x80000)
    buf[0x2000 : 0x2000 + len(_VAG_AG_IDENT)] = _VAG_AG_IDENT
    return bytes(buf)


def make_bmw_256kb_bin() -> bytes:
    """
    BMW 256KB: all-C3 fill with 5331A1 SW block at 0x37F00.

    The BMW_256_ANCHOR (\\xc3\\xc300005331) is present at 0x37F00.
    HW number 0281001445 is stored as plain ASCII at 0x3FC50 (calibration tail).
    """
    buf = bytearray(b"\xc3" * 0x40000)
    buf[0x37F00 : 0x37F00 + len(_BMW_256_BLOCK)] = _BMW_256_BLOCK
    buf[0x3FC50 : 0x3FC50 + len(_BMW_256_HW)] = _BMW_256_HW
    return bytes(buf)


def make_bmw_128kb_hi_bin() -> bytes:
    """BMW 128KB HI chip: all-C3 fill with 3150 SW block at 0x1BF00."""
    buf = bytearray(b"\xc3" * 0x20000)
    buf[0x1BF00 : 0x1BF00 + len(_BMW_128_HI_BLOCK)] = _BMW_128_HI_BLOCK
    # HW number NOT stored as plain ASCII in 128KB split-ROM chips
    return bytes(buf)


def make_bmw_128kb_lo_bin() -> bytes:
    """BMW 128KB LO chip: all-C3 fill with 53C0 SW block at 0x1BF00."""
    buf = bytearray(b"\xc3" * 0x20000)
    buf[0x1BF00 : 0x1BF00 + len(_BMW_128_LO_BLOCK)] = _BMW_128_LO_BLOCK
    return bytes(buf)


def make_opel_128kb_bin() -> bytes:
    """Opel 128KB (Format 3, LLL chip): C3 fill + \\xff{7}+U sentinel at 0x1C000."""
    buf = bytearray(b"\xc3" * 0x20000)
    ident = b"\xff" * 7 + b"U" + b"A" + b"0770164"
    buf[0x1C000 : 0x1C000 + len(ident)] = ident
    buf[0x1F000 : 0x1F000 + len(_OPEL_128_HW)] = _OPEL_128_HW
    return bytes(buf)


def make_opel_128kb_xaa_bin() -> bytes:
    """Opel 128KB (Format 3, HHH-style): C3 fill + \\xaaU sentinel at 0x1C000."""
    buf = bytearray(b"\xc3" * 0x20000)
    ident = b"\xaa" + b"U" + b"A" + b"0770164"
    buf[0x1C000 : 0x1C000 + len(ident)] = ident
    buf[0x1F000 : 0x1F000 + len(_OPEL_128_HW)] = _OPEL_128_HW
    return bytes(buf)


def make_opel_256kb_bin() -> bytes:
    """
    Opel 256KB (Format 4): doubled-char ident at 0x10000, TSW in Opel region.

    Detection: Phase 6 (TSW at 0xBFD0, within OPEL_256_TSW_REGION).
    C3 ratio is ~0% so Phase 5 does not fire.
    """
    buf = bytearray(0x40000)
    buf[0x10000 : 0x10000 + len(_OPEL_256_IDENT_BLOCK)] = _OPEL_256_IDENT_BLOCK
    # TSW inside OPEL_256_TSW_REGION (0xBFC0:0xC040) — not in EDC15 position
    buf[0xBFD0:0xBFD3] = b"TSW"
    buf[0x30000 : 0x30000 + len(_OPEL_256_HW)] = _OPEL_256_HW
    return bytes(buf)


def make_vv33_header_only_256kb_bin() -> bytes:
    """256KB with VV33 magic at offset 0 only — no ident, low C3. Phase 4."""
    buf = bytearray(0x40000)
    buf[0:10] = VV33_MAGIC
    return bytes(buf)


def make_alt_vv33_header_only_128kb_bin() -> bytes:
    """128KB with ALT_VV33 magic at offset 0 only — no ident. Phase 4."""
    buf = bytearray(0x20000)
    buf[0:5] = ALT_VV33_MAGIC
    return bytes(buf)


def make_c3_fallback_128kb_bin() -> bytes:
    """128KB with 30% C3 fill, no ident and no header magic. Phase 5."""
    buf = bytearray(0x20000)
    c3_count = int(0x20000 * 0.30)
    buf[:c3_count] = b"\xc3" * c3_count
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

    def test_edc3_in_supported_families(self):
        assert "EDC3" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_is_string(self):
        assert isinstance(repr(EXTRACTOR), str)

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschEDC3xExtractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# can_handle() — Phase 1: size gate
# ---------------------------------------------------------------------------


class TestCanHandlePhase1Size:
    def test_128kb_accepted(self):
        assert EXTRACTOR.can_handle(make_vag_128kb_bin()) is True

    def test_256kb_accepted(self):
        assert EXTRACTOR.can_handle(make_vag_256kb_bin()) is True

    def test_512kb_accepted(self):
        assert EXTRACTOR.can_handle(make_vag_512kb_bin()) is True

    def test_empty_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_64kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x10000)) is False

    def test_32kb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x8000)) is False

    def test_1mb_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x100000)) is False

    def test_all_zero_128kb_no_ident_rejected(self):
        """All-zero 128KB: passes Phase 1 but fails all subsequent phases."""
        assert EXTRACTOR.can_handle(bytes(0x20000)) is False

    def test_all_zero_256kb_no_ident_rejected(self):
        assert EXTRACTOR.can_handle(bytes(0x40000)) is False


# ---------------------------------------------------------------------------
# can_handle() — Phase 2: exclusion signatures
# ---------------------------------------------------------------------------


class TestCanHandlePhase2Exclusions:
    """Each exclusion signature must block an otherwise-valid VAG bin."""

    def _base(self) -> bytearray:
        return bytearray(make_vag_256kb_bin())

    @pytest.mark.parametrize("sig", EXCLUSION_SIGNATURES)
    def test_each_exclusion_rejects_valid_bin(self, sig):
        buf = self._base()
        _inject_exclusion(buf, sig, offset=0x0400)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc15_explicit(self):
        buf = self._base()
        _inject_exclusion(buf, b"EDC15")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc16_explicit(self):
        buf = self._base()
        _inject_exclusion(buf, b"EDC16")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc17_explicit(self):
        buf = self._base()
        _inject_exclusion(buf, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_dot_explicit(self):
        buf = self._base()
        _inject_exclusion(buf, b"ME7.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_motronic_explicit(self):
        buf = self._base()
        _inject_exclusion(buf, b"MOTRONIC")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_motr_explicit(self):
        buf = self._base()
        _inject_exclusion(buf, b"MOTR")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m5_dot_explicit(self):
        buf = self._base()
        _inject_exclusion(buf, b"M5.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_at_offset_zero(self):
        buf = self._base()
        buf[0:5] = b"EDC17"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_near_end_of_file(self):
        buf = self._base()
        buf[-10:-5] = b"EDC15"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_vag_ident(self):
        """Exclusion must win even when VAG ident is present."""
        buf = bytearray(make_vag_256kb_bin())
        _inject_exclusion(buf, b"SB_V")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_bmw_ident(self):
        buf = bytearray(make_bmw_256kb_bin())
        _inject_exclusion(buf, b"EDC16")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_vv33_header(self):
        buf = bytearray(make_vv33_header_only_256kb_bin())
        _inject_exclusion(buf, b"EDC17", offset=0x0100)
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# can_handle() — Phase 2b guards
# ---------------------------------------------------------------------------


class TestCanHandlePhase2bGuards:
    """TSW at EDC15 position and 1037 SW prefix must reject otherwise-valid bins."""

    def test_tsw_at_edc15_offset_rejects_vag_bin(self):
        """TSW anywhere within data[0x7FC0:0x8060] signals an EDC15 bin."""
        buf = bytearray(make_vag_256kb_bin())
        buf[0x7FC0:0x7FC3] = b"TSW"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_tsw_at_edc15_offset_start(self):
        buf = bytearray(make_vag_256kb_bin())
        buf[0x7FC0:0x7FC3] = b"TSW"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_tsw_at_edc15_offset_end(self):
        buf = bytearray(make_vag_256kb_bin())
        buf[0x805D:0x8060] = b"TSW"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_tsw_outside_edc15_region_not_rejected(self):
        """TSW at the Opel 0xC000 offset must NOT be treated as EDC15."""
        buf = bytearray(make_opel_256kb_bin())
        # TSW is at 0xBFD0 (within OPEL_256_TSW_REGION, outside EDC15 region)
        # — the bin should still be accepted via Phase 6.
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_1037_prefix_rejects_vag_bin(self):
        """1037 SW prefix signals a Format-B EDC15 bin; must be rejected."""
        buf = bytearray(make_vag_256kb_bin())
        buf[0x1000:0x1004] = b"1037"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_1037_prefix_rejects_c3_bin(self):
        buf = bytearray(make_c3_fallback_128kb_bin())
        buf[0x1000:0x1004] = b"1037"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_1037_prefix_anywhere_rejects(self):
        buf = bytearray(make_vag_256kb_bin())
        buf[0x3F000:0x3F004] = b"1037"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# can_handle() — Phase 3: VAG ident pattern
# ---------------------------------------------------------------------------


class TestCanHandlePhase3VagIdent:
    def test_vag_256kb_accepted(self):
        assert EXTRACTOR.can_handle(make_vag_256kb_bin()) is True

    def test_vag_128kb_accepted(self):
        assert EXTRACTOR.can_handle(make_vag_128kb_bin()) is True

    def test_vag_512kb_accepted(self):
        assert EXTRACTOR.can_handle(make_vag_512kb_bin()) is True

    def test_vag_ident_sg_variant_accepted(self):
        """SG sub-variant (most VAG bins)."""
        buf = bytearray(0x40000)
        buf[0x2000 : 0x2000 + len(_VAG_IDENT)] = _VAG_IDENT
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_vag_ident_ag_variant_accepted(self):
        """AG sub-variant (4B0907401AC type)."""
        buf = bytearray(0x80000)
        buf[0x2000 : 0x2000 + len(_VAG_AG_IDENT)] = _VAG_AG_IDENT
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_vag_ident_without_leading_v_accepted(self):
        """Pattern is v? — leading 'v' is optional."""
        ident_no_v = _VAG_AG_IDENT  # starts with '4', not 'v'
        buf = bytearray(0x80000)
        buf[0x1000 : 0x1000 + len(ident_no_v)] = ident_no_v
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_256kb_with_only_vag_ident_accepted(self):
        """Phase 3 alone is sufficient — no header magic required."""
        buf = bytearray(0x40000)
        buf[0x5000 : 0x5000 + len(_VAG_IDENT)] = _VAG_IDENT
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle() — Phase 3b: BMW numeric ident
# ---------------------------------------------------------------------------


class TestCanHandlePhase3bBmwIdent:
    def test_bmw_256kb_accepted(self):
        assert EXTRACTOR.can_handle(make_bmw_256kb_bin()) is True

    def test_bmw_128kb_hi_accepted(self):
        assert EXTRACTOR.can_handle(make_bmw_128kb_hi_bin()) is True

    def test_bmw_128kb_lo_accepted(self):
        assert EXTRACTOR.can_handle(make_bmw_128kb_lo_bin()) is True

    def test_bmw_256_find_sw_block_returns_match(self):
        """_find_bmw_sw_block must return a re.Match for the 256KB bin."""
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_256kb_bin())
        assert m is not None

    def test_bmw_128_hi_find_sw_block_returns_match(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_128kb_hi_bin())
        assert m is not None

    def test_bmw_128_lo_find_sw_block_returns_match(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_128kb_lo_bin())
        assert m is not None

    def test_no_bmw_block_returns_none(self):
        assert EXTRACTOR._find_bmw_sw_block(bytes(0x40000)) is None

    def test_vag_bin_no_bmw_block(self):
        assert EXTRACTOR._find_bmw_sw_block(make_vag_256kb_bin()) is None


# ---------------------------------------------------------------------------
# can_handle() — Phase 4: VV33 / ALT_VV33 header magic at offset 0
# ---------------------------------------------------------------------------


class TestCanHandlePhase4VV33Header:
    def test_vv33_magic_256kb_accepted(self):
        assert EXTRACTOR.can_handle(make_vv33_header_only_256kb_bin()) is True

    def test_alt_vv33_magic_128kb_accepted(self):
        assert EXTRACTOR.can_handle(make_alt_vv33_header_only_128kb_bin()) is True

    def test_vv33_magic_wrong_offset_not_detected(self):
        """VV33 must be at offset 0 — mid-file occurrence does not fire Phase 4."""
        buf = bytearray(0x40000)
        buf[0x1000 : 0x1000 + len(VV33_MAGIC)] = VV33_MAGIC
        # No C3 fill, no VAG/BMW ident → all phases fail → rejected
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_alt_vv33_magic_wrong_offset_not_phase4(self):
        """ALT_VV33 mid-file (as in BMW 128KB split-ROM) must NOT trigger Phase 4."""
        buf = bytearray(0x20000)
        buf[0x1C000 : 0x1C000 + len(ALT_VV33_MAGIC)] = ALT_VV33_MAGIC
        # No C3 fill or ident → rejected
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_partial_vv33_magic_not_accepted(self):
        """Only the first 9 of 10 VV33 bytes — must not trigger Phase 4."""
        buf = bytearray(0x40000)
        buf[0 : len(VV33_MAGIC) - 1] = VV33_MAGIC[:-1]
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# can_handle() — Phase 5: high 0xC3 fill ratio
# ---------------------------------------------------------------------------


class TestCanHandlePhase5C3Fill:
    def test_c3_fallback_128kb_accepted(self):
        assert EXTRACTOR.can_handle(make_c3_fallback_128kb_bin()) is True

    def test_all_c3_128kb_accepted(self):
        """100% C3 fill — far above the 15% threshold."""
        assert EXTRACTOR.can_handle(b"\xc3" * 0x20000) is True

    def test_all_c3_256kb_accepted(self):
        assert EXTRACTOR.can_handle(b"\xc3" * 0x40000) is True

    def test_c3_below_threshold_256kb_rejected(self):
        """1% C3 fill — below the 15% threshold, no other phase matches."""
        buf = bytearray(0x40000)
        count = int(0x40000 * 0.01)
        buf[:count] = b"\xc3" * count
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_c3_at_exactly_threshold_rejected(self):
        """C3 ratio must be strictly > 15%, not >= 15%."""
        buf = bytearray(0x40000)
        count = int(0x40000 * 0.15)
        buf[:count] = b"\xc3" * count
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_c3_just_above_threshold_accepted(self):
        buf = bytearray(0x40000)
        count = int(0x40000 * 0.16)
        buf[:count] = b"\xc3" * count
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle() — Phase 6: Opel 256KB TSW at 0xC000 region
# ---------------------------------------------------------------------------


class TestCanHandlePhase6Opel:
    def test_opel_256kb_accepted_via_phase6(self):
        """Opel 256KB: no C3 fill, no VV33, TSW in OPEL_256_TSW_REGION."""
        assert EXTRACTOR.can_handle(make_opel_256kb_bin()) is True

    def test_tsw_at_opel_region_start_accepted(self):
        buf = bytearray(0x40000)
        start = OPEL_256_TSW_REGION.start
        buf[start : start + 3] = b"TSW"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_tsw_at_opel_region_near_end_accepted(self):
        buf = bytearray(0x40000)
        offset = OPEL_256_TSW_REGION.stop - 4
        buf[offset : offset + 3] = b"TSW"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_phase6_does_not_fire_for_128kb(self):
        """Phase 6 is 256KB-only; 128KB with Opel TSW still requires another phase."""
        buf = bytearray(0x20000)
        # TSW in Opel region equivalent for 128KB — but Phase 6 guard is 256KB only
        # Phase 5 is also absent (no C3) → rejected
        buf[0xBFD0:0xBFD3] = b"TSW"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# _find_bmw_sw_block() — direct unit tests
# ---------------------------------------------------------------------------


class TestFindBmwSwBlock:
    """Unit tests for the anchor+window BMW SW block finder."""

    def test_256kb_block_found(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_256kb_bin())
        assert m is not None

    def test_256kb_group1_is_sw_code(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_256kb_bin())
        assert m is not None
        assert m.group(1) == b"5331A1"

    def test_256kb_group2_is_cal_number(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_256kb_bin())
        assert m is not None
        assert m.group(2) == b"7785098"

    def test_128kb_hi_block_found(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_128kb_hi_bin())
        assert m is not None

    def test_128kb_hi_group1_is_3150(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_128kb_hi_bin())
        assert m is not None
        assert m.group(1) == b"3150"

    def test_128kb_hi_group2_is_cal(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_128kb_hi_bin())
        assert m is not None
        assert m.group(2) == b"7687887"

    def test_128kb_lo_block_found(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_128kb_lo_bin())
        assert m is not None

    def test_128kb_lo_group1_is_53c0(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_128kb_lo_bin())
        assert m is not None
        assert m.group(1) == b"53C0"

    def test_128kb_lo_group2_is_cal(self):
        m = EXTRACTOR._find_bmw_sw_block(make_bmw_128kb_lo_bin())
        assert m is not None
        assert m.group(2) == b"7887768"

    def test_empty_data_returns_none(self):
        assert EXTRACTOR._find_bmw_sw_block(b"") is None

    def test_vag_bin_returns_none(self):
        assert EXTRACTOR._find_bmw_sw_block(make_vag_256kb_bin()) is None

    def test_all_zeros_returns_none(self):
        assert EXTRACTOR._find_bmw_sw_block(bytes(0x40000)) is None

    def test_anchor_present_but_window_malformed_returns_none(self):
        """Anchor found but regex does not match within the 120-byte window."""
        buf = bytearray(b"\xc3" * 0x40000)
        # Place only the raw anchor bytes with no valid block following
        buf[0x37F00 : 0x37F00 + len(BMW_256_ANCHOR)] = BMW_256_ANCHOR
        # Rest of window is still C3 — regex won't match → None
        assert EXTRACTOR._find_bmw_sw_block(bytes(buf)) is None


# ---------------------------------------------------------------------------
# _parse_ident_vag() — direct unit tests
# ---------------------------------------------------------------------------


class TestParseIdentVag:
    def test_sg_variant_oem(self):
        oem, hw, sw, variant = EXTRACTOR._parse_ident_vag(make_vag_256kb_bin())
        assert oem == _VAG_OEM

    def test_sg_variant_hw(self):
        oem, hw, sw, variant = EXTRACTOR._parse_ident_vag(make_vag_256kb_bin())
        assert hw == _VAG_HW

    def test_sg_variant_dataset_as_sw(self):
        oem, hw, sw, variant = EXTRACTOR._parse_ident_vag(make_vag_256kb_bin())
        assert sw == _VAG_DATASET

    def test_sg_variant_ecu_variant_is_none(self):
        """VAG format never provides an ecu_variant."""
        oem, hw, sw, variant = EXTRACTOR._parse_ident_vag(make_vag_256kb_bin())
        assert variant is None

    def test_ag_variant_oem(self):
        oem, hw, sw, variant = EXTRACTOR._parse_ident_vag(make_vag_512kb_bin())
        assert oem == _VAG_AG_OEM

    def test_ag_variant_hw(self):
        oem, hw, sw, variant = EXTRACTOR._parse_ident_vag(make_vag_512kb_bin())
        assert hw == _VAG_AG_HW

    def test_ag_variant_dataset(self):
        oem, hw, sw, variant = EXTRACTOR._parse_ident_vag(make_vag_512kb_bin())
        assert sw == _VAG_AG_DATASET

    def test_leading_v_stripped_from_oem(self):
        """Regex strips the leading 'v' — OEM should not start with 'v'."""
        oem, _, _, _ = EXTRACTOR._parse_ident_vag(make_vag_256kb_bin())
        assert oem is not None
        assert not oem.startswith("v")

    def test_hw_starts_with_0281(self):
        _, hw, _, _ = EXTRACTOR._parse_ident_vag(make_vag_256kb_bin())
        assert hw is not None
        assert hw.startswith("0281")

    def test_hw_is_10_digits(self):
        _, hw, _, _ = EXTRACTOR._parse_ident_vag(make_vag_256kb_bin())
        assert hw is not None
        assert len(hw) == 10 and hw.isdigit()

    def test_no_ident_returns_all_none(self):
        result = EXTRACTOR._parse_ident_vag(bytes(0x40000))
        assert result == (None, None, None, None)

    def test_empty_data_returns_all_none(self):
        assert EXTRACTOR._parse_ident_vag(b"") == (None, None, None, None)

    def test_bmw_bin_returns_all_none(self):
        """BMW SW block does not match the VAG HEX pattern."""
        assert EXTRACTOR._parse_ident_vag(make_bmw_256kb_bin()) == (
            None,
            None,
            None,
            None,
        )


# ---------------------------------------------------------------------------
# _parse_ident_bmw() — direct unit tests
# ---------------------------------------------------------------------------


class TestParseIdentBmw:
    def test_256kb_sw_code(self):
        _, _, sw, variant = EXTRACTOR._parse_ident_bmw(make_bmw_256kb_bin())
        assert variant == _BMW_256_SW_CODE

    def test_256kb_cal_as_sw(self):
        _, _, sw, _ = EXTRACTOR._parse_ident_bmw(make_bmw_256kb_bin())
        assert sw == _BMW_256_CAL

    def test_256kb_hw_recovered(self):
        _, hw, _, _ = EXTRACTOR._parse_ident_bmw(make_bmw_256kb_bin())
        assert hw == _BMW_256_HW.decode()

    def test_256kb_oem_is_none(self):
        """BMW format never stores an OEM part number."""
        oem, _, _, _ = EXTRACTOR._parse_ident_bmw(make_bmw_256kb_bin())
        assert oem is None

    def test_128kb_hi_sw_code(self):
        _, _, _, variant = EXTRACTOR._parse_ident_bmw(make_bmw_128kb_hi_bin())
        assert variant == _BMW_128_HI_SW_CODE

    def test_128kb_hi_cal(self):
        _, _, sw, _ = EXTRACTOR._parse_ident_bmw(make_bmw_128kb_hi_bin())
        assert sw == _BMW_128_HI_CAL

    def test_128kb_hi_hw_is_none(self):
        """HW is not stored as plain ASCII in 128KB split-ROM chips."""
        _, hw, _, _ = EXTRACTOR._parse_ident_bmw(make_bmw_128kb_hi_bin())
        assert hw is None

    def test_128kb_lo_sw_code(self):
        _, _, _, variant = EXTRACTOR._parse_ident_bmw(make_bmw_128kb_lo_bin())
        assert variant == _BMW_128_LO_SW_CODE

    def test_128kb_lo_cal(self):
        _, _, sw, _ = EXTRACTOR._parse_ident_bmw(make_bmw_128kb_lo_bin())
        assert sw == _BMW_128_LO_CAL

    def test_no_bmw_block_returns_all_none(self):
        assert EXTRACTOR._parse_ident_bmw(bytes(0x40000)) == (None, None, None, None)

    def test_vag_bin_returns_all_none(self):
        assert EXTRACTOR._parse_ident_bmw(make_vag_256kb_bin()) == (
            None,
            None,
            None,
            None,
        )

    def test_cal_is_7_digits(self):
        _, _, sw, _ = EXTRACTOR._parse_ident_bmw(make_bmw_256kb_bin())
        assert sw is not None
        assert len(sw) == 7 and sw.isdigit()


# ---------------------------------------------------------------------------
# _parse_ident_opel_256() — direct unit tests
# ---------------------------------------------------------------------------


class TestParseIdentOpel256:
    def test_sw_code_decoded(self):
        _, _, sw, variant = EXTRACTOR._parse_ident_opel_256(make_opel_256kb_bin())
        assert variant == _OPEL_256_SW_CODE

    def test_cal_decoded(self):
        _, _, sw, _ = EXTRACTOR._parse_ident_opel_256(make_opel_256kb_bin())
        assert sw == _OPEL_256_CAL

    def test_hw_recovered_from_last_64kb(self):
        _, hw, _, _ = EXTRACTOR._parse_ident_opel_256(make_opel_256kb_bin())
        assert hw == _OPEL_256_HW.decode()

    def test_oem_is_always_none(self):
        oem, _, _, _ = EXTRACTOR._parse_ident_opel_256(make_opel_256kb_bin())
        assert oem is None

    def test_alternate_sentinel_xaa_x55(self):
        """\\xaa\\x55 sentinel variant must also be decoded correctly."""
        buf = bytearray(0x40000)
        buf[0x10000 : 0x10000 + len(_OPEL_256_IDENT_BLOCK_ALT)] = (
            _OPEL_256_IDENT_BLOCK_ALT
        )
        buf[0x30000 : 0x30000 + len(_OPEL_256_HW)] = _OPEL_256_HW
        _, _, sw, variant = EXTRACTOR._parse_ident_opel_256(bytes(buf))
        assert sw == _OPEL_256_CAL
        assert variant == _OPEL_256_SW_CODE

    def test_no_ident_returns_all_none(self):
        assert EXTRACTOR._parse_ident_opel_256(bytes(0x40000)) == (
            None,
            None,
            None,
            None,
        )

    def test_ident_outside_window_not_found(self):
        """The parser only searches data[0x10000:0x10100] — ident outside is missed."""
        buf = bytearray(0x40000)
        # Place ident at 0x11000, outside the 256-byte window
        buf[0x11000 : 0x11000 + len(_OPEL_256_IDENT_BLOCK)] = _OPEL_256_IDENT_BLOCK
        oem, hw, sw, variant = EXTRACTOR._parse_ident_opel_256(bytes(buf))
        assert sw is None

    def test_cal_is_7_alphanumeric(self):
        _, _, sw, _ = EXTRACTOR._parse_ident_opel_256(make_opel_256kb_bin())
        assert sw is not None
        assert len(sw) == 7 and sw.isalnum()

    def test_vag_bin_returns_all_none(self):
        assert EXTRACTOR._parse_ident_opel_256(make_vag_256kb_bin()) == (
            None,
            None,
            None,
            None,
        )


# ---------------------------------------------------------------------------
# _parse_ident_opel() — direct unit tests
# ---------------------------------------------------------------------------


class TestParseIdentOpel:
    def test_xff_u_sentinel_sw_code(self):
        _, _, sw, variant = EXTRACTOR._parse_ident_opel(make_opel_128kb_bin())
        assert variant == _OPEL_128_SW_CODE

    def test_xff_u_sentinel_cal(self):
        _, _, sw, _ = EXTRACTOR._parse_ident_opel(make_opel_128kb_bin())
        assert sw == _OPEL_128_CAL

    def test_xff_u_sentinel_hw(self):
        _, hw, _, _ = EXTRACTOR._parse_ident_opel(make_opel_128kb_bin())
        assert hw == _OPEL_128_HW.decode()

    def test_xaa_u_sentinel_variant(self):
        """\\xaaU sentinel (HHH-style) must also parse correctly."""
        _, _, sw, variant = EXTRACTOR._parse_ident_opel(make_opel_128kb_xaa_bin())
        assert sw == _OPEL_128_CAL
        assert variant == _OPEL_128_SW_CODE

    def test_xaa_alone_sentinel(self):
        """\\xaa without following U must also match (U is optional in pattern)."""
        buf = bytearray(b"\xc3" * 0x20000)
        ident = b"\xaa" + b"A" + b"0770164"
        buf[0x1C000 : 0x1C000 + len(ident)] = ident
        buf[0x1F000 : 0x1F000 + len(_OPEL_128_HW)] = _OPEL_128_HW
        _, _, sw, variant = EXTRACTOR._parse_ident_opel(bytes(buf))
        assert sw == "0770164"
        assert variant == "A"

    def test_oem_is_always_none(self):
        oem, _, _, _ = EXTRACTOR._parse_ident_opel(make_opel_128kb_bin())
        assert oem is None

    def test_no_ident_returns_all_none(self):
        assert EXTRACTOR._parse_ident_opel(bytes(0x20000)) == (None, None, None, None)

    def test_empty_data_returns_all_none(self):
        assert EXTRACTOR._parse_ident_opel(b"") == (None, None, None, None)

    def test_cal_is_7_digits(self):
        _, _, sw, _ = EXTRACTOR._parse_ident_opel(make_opel_128kb_bin())
        assert sw is not None
        assert len(sw) == 7 and sw.isdigit()

    def test_vag_bin_returns_all_none(self):
        """VAG HEX ident does not satisfy the Opel pattern."""
        assert EXTRACTOR._parse_ident_opel(make_vag_256kb_bin()) == (
            None,
            None,
            None,
            None,
        )


# ---------------------------------------------------------------------------
# extract() — required keys always present
# ---------------------------------------------------------------------------


class TestExtractRequiredKeys:
    def _check(self, data: bytes) -> None:
        result = EXTRACTOR.extract(data)
        missing = REQUIRED_EXTRACT_KEYS - set(result.keys())
        assert not missing, f"Missing keys: {missing}"

    def test_required_keys_vag_256kb(self):
        self._check(make_vag_256kb_bin())

    def test_required_keys_vag_128kb(self):
        self._check(make_vag_128kb_bin())

    def test_required_keys_vag_512kb(self):
        self._check(make_vag_512kb_bin())

    def test_required_keys_bmw_256kb(self):
        self._check(make_bmw_256kb_bin())

    def test_required_keys_bmw_128kb_hi(self):
        self._check(make_bmw_128kb_hi_bin())

    def test_required_keys_bmw_128kb_lo(self):
        self._check(make_bmw_128kb_lo_bin())

    def test_required_keys_opel_128kb(self):
        self._check(make_opel_128kb_bin())

    def test_required_keys_opel_256kb(self):
        self._check(make_opel_256kb_bin())

    def test_required_keys_c3_fallback(self):
        self._check(make_c3_fallback_128kb_bin())

    def test_required_keys_vv33_header_only(self):
        self._check(make_vv33_header_only_256kb_bin())

    def test_manufacturer_always_bosch(self):
        for data in (make_vag_256kb_bin(), make_bmw_256kb_bin(), make_opel_128kb_bin()):
            assert EXTRACTOR.extract(data)["manufacturer"] == "Bosch"

    def test_ecu_family_always_edc3(self):
        for data in (
            make_vag_256kb_bin(),
            make_bmw_256kb_bin(),
            make_opel_128kb_bin(),
            make_c3_fallback_128kb_bin(),
        ):
            assert EXTRACTOR.extract(data)["ecu_family"] == "EDC3"

    def test_raw_strings_is_list(self):
        result = EXTRACTOR.extract(make_vag_256kb_bin())
        assert isinstance(result["raw_strings"], list)

    def test_file_size_256kb(self):
        result = EXTRACTOR.extract(make_vag_256kb_bin())
        assert result["file_size"] == 0x40000

    def test_file_size_128kb(self):
        result = EXTRACTOR.extract(make_vag_128kb_bin())
        assert result["file_size"] == 0x20000

    def test_file_size_512kb(self):
        result = EXTRACTOR.extract(make_vag_512kb_bin())
        assert result["file_size"] == 0x80000


# ---------------------------------------------------------------------------
# extract() — VAG 256KB full extraction
# ---------------------------------------------------------------------------


class TestExtractVag256:
    def setup_method(self):
        self.result = EXTRACTOR.extract(make_vag_256kb_bin())

    def test_ecu_family(self):
        assert self.result["ecu_family"] == "EDC3"

    def test_ecu_variant_is_none(self):
        """VAG format has no internal SW code — ecu_variant is None."""
        assert self.result["ecu_variant"] is None

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _VAG_HW

    def test_hardware_number_starts_with_0281(self):
        assert self.result["hardware_number"].startswith("0281")

    def test_hardware_number_is_10_digits(self):
        assert len(self.result["hardware_number"]) == 10
        assert self.result["hardware_number"].isdigit()

    def test_software_version_is_dataset_code(self):
        assert self.result["software_version"] == _VAG_DATASET

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == _VAG_OEM

    def test_match_key_format(self):
        assert self.result["match_key"] == f"EDC3::{_VAG_DATASET}"

    def test_match_key_is_uppercase(self):
        assert self.result["match_key"] == self.result["match_key"].upper()

    def test_manufacturer(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_file_size(self):
        assert self.result["file_size"] == 0x40000

    def test_raw_strings_is_list(self):
        assert isinstance(self.result["raw_strings"], list)


# ---------------------------------------------------------------------------
# extract() — VAG 512KB (AG variant)
# ---------------------------------------------------------------------------


class TestExtractVag512:
    def setup_method(self):
        self.result = EXTRACTOR.extract(make_vag_512kb_bin())

    def test_ecu_family(self):
        assert self.result["ecu_family"] == "EDC3"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _VAG_AG_HW

    def test_software_version(self):
        assert self.result["software_version"] == _VAG_AG_DATASET

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == _VAG_AG_OEM

    def test_ecu_variant_is_none(self):
        assert self.result["ecu_variant"] is None

    def test_file_size(self):
        assert self.result["file_size"] == 0x80000

    def test_match_key_format(self):
        assert self.result["match_key"] == f"EDC3::{_VAG_AG_DATASET}"


# ---------------------------------------------------------------------------
# extract() — BMW 256KB
# ---------------------------------------------------------------------------


class TestExtractBmw256:
    def setup_method(self):
        self.result = EXTRACTOR.extract(make_bmw_256kb_bin())

    def test_ecu_family(self):
        assert self.result["ecu_family"] == "EDC3"

    def test_ecu_variant_is_sw_code(self):
        assert self.result["ecu_variant"] == _BMW_256_SW_CODE

    def test_software_version_is_7_digit_cal(self):
        assert self.result["software_version"] == _BMW_256_CAL

    def test_software_version_is_7_digits(self):
        assert len(self.result["software_version"]) == 7
        assert self.result["software_version"].isdigit()

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _BMW_256_HW.decode()

    def test_hardware_number_starts_with_0281(self):
        assert self.result["hardware_number"].startswith("0281")

    def test_oem_part_number_is_none(self):
        """BMW format never embeds an OEM part number."""
        assert self.result["oem_part_number"] is None

    def test_match_key_uses_edc3_prefix(self):
        assert self.result["match_key"].startswith("EDC3::")

    def test_match_key_uses_cal_not_sw_code(self):
        """match_key uses software_version (cal number), not ecu_variant."""
        assert self.result["match_key"] == f"EDC3::{_BMW_256_CAL}"

    def test_file_size(self):
        assert self.result["file_size"] == 0x40000


# ---------------------------------------------------------------------------
# extract() — BMW 128KB HI chip
# ---------------------------------------------------------------------------


class TestExtractBmw128Hi:
    def setup_method(self):
        self.result = EXTRACTOR.extract(make_bmw_128kb_hi_bin())

    def test_ecu_variant_is_3150(self):
        assert self.result["ecu_variant"] == _BMW_128_HI_SW_CODE

    def test_software_version(self):
        assert self.result["software_version"] == _BMW_128_HI_CAL

    def test_hardware_number_is_none(self):
        """HW not stored as plain ASCII in 128KB split-ROM chips."""
        assert self.result["hardware_number"] is None

    def test_oem_part_number_is_none(self):
        assert self.result["oem_part_number"] is None

    def test_match_key(self):
        assert self.result["match_key"] == f"EDC3::{_BMW_128_HI_CAL}"

    def test_file_size(self):
        assert self.result["file_size"] == 0x20000


# ---------------------------------------------------------------------------
# extract() — BMW 128KB LO chip
# ---------------------------------------------------------------------------


class TestExtractBmw128Lo:
    def setup_method(self):
        self.result = EXTRACTOR.extract(make_bmw_128kb_lo_bin())

    def test_ecu_variant_is_53c0(self):
        assert self.result["ecu_variant"] == _BMW_128_LO_SW_CODE

    def test_software_version(self):
        assert self.result["software_version"] == _BMW_128_LO_CAL

    def test_hardware_number_is_none(self):
        assert self.result["hardware_number"] is None

    def test_oem_part_number_is_none(self):
        assert self.result["oem_part_number"] is None

    def test_match_key(self):
        assert self.result["match_key"] == f"EDC3::{_BMW_128_LO_CAL}"

    def test_lo_and_hi_cal_differ(self):
        """LO and HI chips store different cal numbers."""
        hi = EXTRACTOR.extract(make_bmw_128kb_hi_bin())["software_version"]
        lo = EXTRACTOR.extract(make_bmw_128kb_lo_bin())["software_version"]
        assert hi != lo


# ---------------------------------------------------------------------------
# extract() — Opel 128KB (Format 3)
# ---------------------------------------------------------------------------


class TestExtractOpel128:
    def setup_method(self):
        self.result = EXTRACTOR.extract(make_opel_128kb_bin())

    def test_ecu_variant(self):
        assert self.result["ecu_variant"] == _OPEL_128_SW_CODE

    def test_software_version(self):
        assert self.result["software_version"] == _OPEL_128_CAL

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _OPEL_128_HW.decode()

    def test_hardware_number_starts_with_0281(self):
        assert self.result["hardware_number"].startswith("0281")

    def test_oem_part_number_is_none(self):
        assert self.result["oem_part_number"] is None

    def test_match_key(self):
        assert self.result["match_key"] == f"EDC3::{_OPEL_128_CAL}"

    def test_file_size(self):
        assert self.result["file_size"] == 0x20000

    def test_xaa_variant_same_result(self):
        """\\xaa sentinel variant (HHH-style) must produce identical fields."""
        result_xaa = EXTRACTOR.extract(make_opel_128kb_xaa_bin())
        assert result_xaa["software_version"] == self.result["software_version"]
        assert result_xaa["ecu_variant"] == self.result["ecu_variant"]


# ---------------------------------------------------------------------------
# extract() — Opel 256KB (Format 4)
# ---------------------------------------------------------------------------


class TestExtractOpel256:
    def setup_method(self):
        self.result = EXTRACTOR.extract(make_opel_256kb_bin())

    def test_ecu_variant(self):
        assert self.result["ecu_variant"] == _OPEL_256_SW_CODE

    def test_software_version(self):
        assert self.result["software_version"] == _OPEL_256_CAL

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _OPEL_256_HW.decode()

    def test_oem_part_number_is_none(self):
        assert self.result["oem_part_number"] is None

    def test_match_key(self):
        assert self.result["match_key"] == f"EDC3::{_OPEL_256_CAL}"

    def test_file_size(self):
        assert self.result["file_size"] == 0x40000

    def test_cal_matches_opel_128kb(self):
        """Same calibration number as the 128KB Opel chip."""
        result_128 = EXTRACTOR.extract(make_opel_128kb_bin())
        assert self.result["software_version"] == result_128["software_version"]


# ---------------------------------------------------------------------------
# extract() — fallback-detected bins with no parseable ident
# ---------------------------------------------------------------------------


class TestExtractFallbackNoIdent:
    """Bins detected via VV33 header or C3 fill but with no parseable ident."""

    def test_vv33_header_only_software_version_is_none(self):
        result = EXTRACTOR.extract(make_vv33_header_only_256kb_bin())
        assert result["software_version"] is None

    def test_vv33_header_only_hardware_number_is_none(self):
        result = EXTRACTOR.extract(make_vv33_header_only_256kb_bin())
        assert result["hardware_number"] is None

    def test_vv33_header_only_oem_is_none(self):
        result = EXTRACTOR.extract(make_vv33_header_only_256kb_bin())
        assert result["oem_part_number"] is None

    def test_vv33_header_only_ecu_variant_is_none(self):
        result = EXTRACTOR.extract(make_vv33_header_only_256kb_bin())
        assert result["ecu_variant"] is None

    def test_vv33_header_only_match_key_is_none(self):
        result = EXTRACTOR.extract(make_vv33_header_only_256kb_bin())
        assert result["match_key"] is None

    def test_c3_fallback_software_version_is_none(self):
        result = EXTRACTOR.extract(make_c3_fallback_128kb_bin())
        assert result["software_version"] is None

    def test_c3_fallback_ecu_family_still_edc3(self):
        result = EXTRACTOR.extract(make_c3_fallback_128kb_bin())
        assert result["ecu_family"] == "EDC3"

    def test_c3_fallback_match_key_is_none(self):
        result = EXTRACTOR.extract(make_c3_fallback_128kb_bin())
        assert result["match_key"] is None


# ---------------------------------------------------------------------------
# extract() — null fields (always None for EDC3x)
# ---------------------------------------------------------------------------


class TestExtractNullFields:
    def _result(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data)

    def test_calibration_version_none_vag(self):
        assert self._result(make_vag_256kb_bin())["calibration_version"] is None

    def test_calibration_version_none_bmw(self):
        assert self._result(make_bmw_256kb_bin())["calibration_version"] is None

    def test_sw_base_version_none_vag(self):
        assert self._result(make_vag_256kb_bin())["sw_base_version"] is None

    def test_sw_base_version_none_opel(self):
        assert self._result(make_opel_128kb_bin())["sw_base_version"] is None

    def test_serial_number_none(self):
        assert self._result(make_vag_256kb_bin())["serial_number"] is None

    def test_dataset_number_none(self):
        assert self._result(make_bmw_256kb_bin())["dataset_number"] is None

    def test_calibration_id_none_vag(self):
        assert self._result(make_vag_256kb_bin())["calibration_id"] is None

    def test_calibration_id_none_bmw(self):
        assert self._result(make_bmw_256kb_bin())["calibration_id"] is None

    def test_calibration_id_none_opel_128(self):
        assert self._result(make_opel_128kb_bin())["calibration_id"] is None

    def test_calibration_id_none_opel_256(self):
        assert self._result(make_opel_256kb_bin())["calibration_id"] is None


# ---------------------------------------------------------------------------
# extract() — hashing
# ---------------------------------------------------------------------------


class TestExtractHashing:
    def test_md5_is_32_hex_chars_vag(self):
        result = EXTRACTOR.extract(make_vag_256kb_bin())
        assert len(result["md5"]) == 32
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_correct_vag(self):
        data = make_vag_256kb_bin()
        assert EXTRACTOR.extract(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_bmw(self):
        data = make_bmw_256kb_bin()
        assert EXTRACTOR.extract(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_opel_128(self):
        data = make_opel_128kb_bin()
        assert EXTRACTOR.extract(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_is_64_hex_chars(self):
        result = EXTRACTOR.extract(make_vag_256kb_bin())
        assert len(result["sha256_first_64kb"]) == 64

    def test_sha256_covers_first_64kb_only(self):
        data = make_vag_256kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert EXTRACTOR.extract(data)["sha256_first_64kb"] == expected

    def test_sha256_correct_bmw(self):
        data = make_bmw_256kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert EXTRACTOR.extract(data)["sha256_first_64kb"] == expected

    def test_sha256_correct_opel_256(self):
        data = make_opel_256kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert EXTRACTOR.extract(data)["sha256_first_64kb"] == expected

    def test_different_bins_different_md5(self):
        vag = EXTRACTOR.extract(make_vag_256kb_bin())["md5"]
        bmw = EXTRACTOR.extract(make_bmw_256kb_bin())["md5"]
        assert vag != bmw

    def test_128kb_and_256kb_different_sha256(self):
        vag_256 = EXTRACTOR.extract(make_vag_256kb_bin())["sha256_first_64kb"]
        vag_128 = EXTRACTOR.extract(make_vag_128kb_bin())["sha256_first_64kb"]
        assert vag_256 != vag_128


# ---------------------------------------------------------------------------
# match_key
# ---------------------------------------------------------------------------


class TestMatchKey:
    def _result(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data)

    def test_vag_match_key_format(self):
        assert self._result(make_vag_256kb_bin())["match_key"] == "EDC3::C86BM500"

    def test_vag_ag_match_key_format(self):
        assert self._result(make_vag_512kb_bin())["match_key"] == "EDC3::A15CEHK2"

    def test_bmw_256_match_key_format(self):
        assert self._result(make_bmw_256kb_bin())["match_key"] == "EDC3::7785098"

    def test_bmw_128_hi_match_key_format(self):
        assert self._result(make_bmw_128kb_hi_bin())["match_key"] == "EDC3::7687887"

    def test_bmw_128_lo_match_key_format(self):
        assert self._result(make_bmw_128kb_lo_bin())["match_key"] == "EDC3::7887768"

    def test_opel_128_match_key_format(self):
        assert self._result(make_opel_128kb_bin())["match_key"] == "EDC3::0770164"

    def test_opel_256_match_key_format(self):
        assert self._result(make_opel_256kb_bin())["match_key"] == "EDC3::0770164"

    def test_match_key_none_when_sw_absent(self):
        assert self._result(make_vv33_header_only_256kb_bin())["match_key"] is None

    def test_match_key_none_for_c3_fallback(self):
        assert self._result(make_c3_fallback_128kb_bin())["match_key"] is None

    def test_match_key_always_uppercase(self):
        for data in (
            make_vag_256kb_bin(),
            make_vag_512kb_bin(),
            make_bmw_256kb_bin(),
        ):
            key = self._result(data)["match_key"]
            assert key == key.upper(), f"match_key not uppercase: {key!r}"

    def test_match_key_separator_is_double_colon(self):
        key = self._result(make_vag_256kb_bin())["match_key"]
        assert "::" in key

    def test_match_key_prefix_is_edc3(self):
        for data in (make_vag_256kb_bin(), make_bmw_256kb_bin(), make_opel_128kb_bin()):
            key = self._result(data)["match_key"]
            assert key.startswith("EDC3::"), f"Unexpected prefix: {key!r}"

    def test_match_key_ecu_variant_not_used_as_prefix(self):
        """build_match_key receives ecu_variant=None — prefix is always 'EDC3'."""
        result = self._result(make_bmw_256kb_bin())
        assert result["ecu_variant"] == "5331A1"  # variant is set...
        assert result["match_key"].startswith("EDC3::")  # ...but not in match_key

    def test_different_sw_produces_different_match_key(self):
        vag_key = self._result(make_vag_256kb_bin())["match_key"]
        bmw_key = self._result(make_bmw_256kb_bin())["match_key"]
        assert vag_key != bmw_key


# ---------------------------------------------------------------------------
# Determinism and filename independence
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_binary_same_result_vag(self):
        data = make_vag_256kb_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1["md5"] == r2["md5"]
        assert r1["match_key"] == r2["match_key"]
        assert r1["hardware_number"] == r2["hardware_number"]

    def test_same_binary_same_result_bmw(self):
        data = make_bmw_256kb_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1["software_version"] == r2["software_version"]
        assert r1["ecu_variant"] == r2["ecu_variant"]

    def test_filename_does_not_affect_vag_fields(self):
        data = make_vag_256kb_bin()
        r1 = EXTRACTOR.extract(data, filename="original.bin")
        r2 = EXTRACTOR.extract(data, filename="renamed_copy.bin")
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["match_key"] == r2["match_key"]

    def test_filename_does_not_affect_bmw_fields(self):
        data = make_bmw_256kb_bin()
        r1 = EXTRACTOR.extract(data, filename="bmw_a.bin")
        r2 = EXTRACTOR.extract(data, filename="bmw_b.bin")
        assert r1["ecu_variant"] == r2["ecu_variant"]
        assert r1["software_version"] == r2["software_version"]

    def test_different_binaries_produce_different_md5(self):
        vag_md5 = EXTRACTOR.extract(make_vag_256kb_bin())["md5"]
        bmw_md5 = EXTRACTOR.extract(make_bmw_256kb_bin())["md5"]
        assert vag_md5 != bmw_md5

    def test_file_size_reflects_actual_binary_length_256kb(self):
        data = make_vag_256kb_bin()
        assert EXTRACTOR.extract(data)["file_size"] == len(data)

    def test_file_size_reflects_actual_binary_length_128kb(self):
        data = make_bmw_128kb_hi_bin()
        assert EXTRACTOR.extract(data)["file_size"] == len(data)

    def test_file_size_reflects_actual_binary_length_512kb(self):
        data = make_vag_512kb_bin()
        assert EXTRACTOR.extract(data)["file_size"] == len(data)

    def test_can_handle_then_extract_vag_consistent(self):
        data = make_vag_256kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data)
        assert result["ecu_family"] == "EDC3"
        assert result["hardware_number"] == _VAG_HW
        assert result["software_version"] == _VAG_DATASET

    def test_can_handle_then_extract_bmw_consistent(self):
        data = make_bmw_256kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data)
        assert result["ecu_variant"] == _BMW_256_SW_CODE
        assert result["software_version"] == _BMW_256_CAL

    def test_can_handle_then_extract_opel_consistent(self):
        data = make_opel_128kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data)
        assert result["software_version"] == _OPEL_128_CAL
        assert result["ecu_variant"] == _OPEL_128_SW_CODE


# ---------------------------------------------------------------------------
# Coverage: edc3x/extractor.py lines 615, 706, 746, 793
# ---------------------------------------------------------------------------


class TestCoverageEdc3xParserEdges:
    """
    Cover defensive None-return branches in the three internal ident parsers.
    All branches are guarded by decoded-string emptiness checks that cannot be
    triggered by real binary data, so each test uses unittest.mock to inject a
    match object with empty or None groups.
    """

    # ------------------------------------------------------------------
    # Line 615 — _parse_ident_vag: _decode() returns None for a None group
    # ------------------------------------------------------------------

    def test_parse_ident_vag_decode_returns_none_for_none_group(self):
        """Line 615: _decode(idx) returns None when match.group(idx) is None."""
        from unittest.mock import MagicMock, patch

        mock_match = MagicMock()

        # group(1)=OEM part (bytes), group(2)=None → hw_number becomes None,
        # group(3)=dataset code (bytes).
        def _side(idx):
            if idx == 1:
                return b"028906021GM"
            if idx == 2:
                return None  # triggers line 615
            return b"C86BM500"

        mock_match.group.side_effect = _side

        with patch(
            "openremap.tuning.manufacturers.bosch.edc3x.extractor.re.search",
            return_value=mock_match,
        ):
            oem, hw, ds, ev = EXTRACTOR._parse_ident_vag(b"dummy data" * 100)

        assert hw is None
        assert ev is None  # ecu_variant always None for VAG

    # ------------------------------------------------------------------
    # Line 706 — _parse_ident_bmw: returns (None×4) for empty sw_code
    # ------------------------------------------------------------------

    def test_parse_ident_bmw_empty_sw_code_returns_all_none(self):
        """Line 706: returns (None, None, None, None) when sw_code decodes to ''."""
        from unittest.mock import MagicMock, patch

        mock_match = MagicMock()
        # group(1) is bytes > 127 → errors='ignore' drops them → decoded string is ''
        mock_match.group.side_effect = lambda idx: (
            b"\x80\x81\x82\x83\x84\x85" if idx == 1 else b"7785098"
        )

        with patch.object(
            type(EXTRACTOR), "_find_bmw_sw_block", return_value=mock_match
        ):
            result = EXTRACTOR._parse_ident_bmw(b"\xc3" * 0x40000)

        assert result == (None, None, None, None)

    def test_parse_ident_bmw_empty_cal_number_returns_all_none(self):
        """Line 706: returns (None, None, None, None) when cal_number decodes to ''."""
        from unittest.mock import MagicMock, patch

        mock_match = MagicMock()
        # group(2) is bytes > 127 → errors='ignore' drops them → cal_number is ''
        mock_match.group.side_effect = lambda idx: (
            b"5331A1" if idx == 1 else b"\x80\x81\x82\x83\x84\x85\x86"
        )

        with patch.object(
            type(EXTRACTOR), "_find_bmw_sw_block", return_value=mock_match
        ):
            result = EXTRACTOR._parse_ident_bmw(b"\xc3" * 0x40000)

        assert result == (None, None, None, None)

    # ------------------------------------------------------------------
    # Line 746 — _parse_ident_opel_256: returns (None×4) for invalid cal_id
    # ------------------------------------------------------------------

    def test_parse_ident_opel_256_invalid_cal_id_returns_all_none(self):
        """Line 746: returns (None×4) when cal_id fails [A-Z0-9]{7}$ check."""
        from unittest.mock import MagicMock, patch

        mock_match = MagicMock()
        # group(1)=sw_code (uppercase letter), groups 2-8 = lowercase letters
        # → cal_id = "aaaaaaa" which fails [A-Z0-9]{7}$
        mock_match.group.side_effect = lambda idx: b"A" if idx == 1 else b"a"

        # Python 3.14: re.Pattern.search is read-only; patch the module attribute
        mock_pattern = MagicMock()
        mock_pattern.search.return_value = mock_match

        with patch(
            "openremap.tuning.manufacturers.bosch.edc3x.extractor.IDENT_PATTERN_OPEL_256",
            new=mock_pattern,
        ):
            data = bytearray(0x40000)  # 256 KB so window at 0x10000 exists
            result = EXTRACTOR._parse_ident_opel_256(bytes(data))

        assert result == (None, None, None, None)

    def test_parse_ident_opel_256_empty_sw_code_returns_all_none(self):
        """Line 746: returns (None×4) when sw_code decodes to empty string."""
        from unittest.mock import MagicMock, patch

        mock_match = MagicMock()
        # group(1) = bytes > 127 → errors='ignore' drops them → sw_code = ''
        mock_match.group.side_effect = lambda idx: b"\x80\x81" if idx == 1 else b"0"

        mock_pattern = MagicMock()
        mock_pattern.search.return_value = mock_match

        with patch(
            "openremap.tuning.manufacturers.bosch.edc3x.extractor.IDENT_PATTERN_OPEL_256",
            new=mock_pattern,
        ):
            data = bytearray(0x40000)
            result = EXTRACTOR._parse_ident_opel_256(bytes(data))

        assert result == (None, None, None, None)

    # ------------------------------------------------------------------
    # Line 793 — _parse_ident_opel: returns (None×4) for empty sw_code
    # ------------------------------------------------------------------

    def test_parse_ident_opel_empty_sw_code_returns_all_none(self):
        """Line 793: returns (None×4) when sw_code decodes to empty string."""
        from unittest.mock import MagicMock, patch

        mock_match = MagicMock()
        # group(1) = bytes > 127 → errors='ignore' drops them → sw_code = ''
        mock_match.group.side_effect = lambda idx: (
            b"\x80\x81" if idx == 1 else b"0770164"
        )

        # Python 3.14: re.Pattern.search is read-only; patch the module attribute
        mock_pattern = MagicMock()
        mock_pattern.search.return_value = mock_match

        with patch(
            "openremap.tuning.manufacturers.bosch.edc3x.extractor.IDENT_PATTERN_OPEL",
            new=mock_pattern,
        ):
            result = EXTRACTOR._parse_ident_opel(b"\xff" * 0x20000)

        assert result == (None, None, None, None)

    def test_parse_ident_opel_empty_cal_number_returns_all_none(self):
        """Line 793: returns (None×4) when cal_number decodes to empty string."""
        from unittest.mock import MagicMock, patch

        mock_match = MagicMock()
        # group(2) = bytes > 127 → errors='ignore' drops them → cal_number = ''
        mock_match.group.side_effect = lambda idx: (
            b"A" if idx == 1 else b"\x80\x81\x82\x83\x84\x85\x86"
        )

        mock_pattern = MagicMock()
        mock_pattern.search.return_value = mock_match

        with patch(
            "openremap.tuning.manufacturers.bosch.edc3x.extractor.IDENT_PATTERN_OPEL",
            new=mock_pattern,
        ):
            result = EXTRACTOR._parse_ident_opel(b"\xff" * 0x20000)

        assert result == (None, None, None, None)
