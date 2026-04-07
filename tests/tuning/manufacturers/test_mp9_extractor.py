"""
Tests for BoschMP9Extractor (Motronic MP 9.0).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * Phase 3: primary sig b"MOTRONIC MP 9" in last 2 KB
      * Phase 4: secondary sig b"MP9" + HW pattern "0261xxxxxx" in last 2 KB
  - can_handle() — False paths:
      * Empty binary
      * Wrong sizes (32KB, 128KB, 256KB, 512KB)
      * All-zero 64KB
      * No detection signatures present
  - can_handle() — Exclusions:
      * Every EXCLUSION_SIGNATURES entry blocks an otherwise-valid bin
  - extract() — full extraction:
      * ecu_family, ecu_variant, hardware_number, software_version,
        oem_part_number, match_key, file_size, md5, sha256, raw_strings
      * null fields (calibration_version, sw_base_version, etc.) are None
  - match_key format, None when SW absent, always uppercase
  - Determinism and filename independence
"""

import hashlib

import pytest

from openremap.core.manufacturers.bosch.mp9.extractor import BoschMP9Extractor
from openremap.core.manufacturers.bosch.mp9.patterns import EXCLUSION_SIGNATURES

EXTRACTOR = BoschMP9Extractor()

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

# Full ident block (placed at 0xF800 — within last 0x800 bytes of 0x10000)
_IDENT_BLOCK = b"0261204593 1037357494 MP9 0006K0906027E  MOTRONIC MP 9.0    S023"

# Slash-delimited metadata block
_SLASH_BLOCK = b" 53/1/MP9.0/51/4007.01/DAMOS94/1832-S/183205-S/100497/"

_HW = "0261204593"
_SW = "1037357494"
_OEM = "6K0906027E"


# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------


def make_mp9_64kb_bin(
    with_ident: bool = True,
    with_slash: bool = True,
) -> bytes:
    """
    Full valid MP9 binary, 64 KB (0x10000).

    Ident block placed at 0xF800 (inside last 0x800 bytes = ident_area).
    Slash block placed immediately after the ident block.

    Args:
        with_ident: inject the full ident block (default True).
        with_slash: inject the slash-delimited metadata (default True).
    """
    buf = bytearray(0x10000)
    if with_ident:
        buf[0xF800 : 0xF800 + len(_IDENT_BLOCK)] = _IDENT_BLOCK
    if with_slash:
        slash_offset = 0xF800 + len(_IDENT_BLOCK) + 4
        buf[slash_offset : slash_offset + len(_SLASH_BLOCK)] = _SLASH_BLOCK
    return bytes(buf)


def make_mp9_minimal_bin() -> bytes:
    """
    Valid but minimal MP9 binary — only the primary detection signature.

    Contains b"MOTRONIC MP 9" in the last 2 KB but no structured ident block.
    This triggers Phase 3 detection but yields limited extraction data.
    """
    buf = bytearray(0x10000)
    sig = b"MOTRONIC MP 9.0"
    buf[0xFC00 : 0xFC00 + len(sig)] = sig
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

    def test_mp9_in_supported_families(self):
        assert "MP9" in EXTRACTOR.supported_families

    def test_mp90_in_supported_families(self):
        assert "MP9.0" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        assert all(isinstance(f, str) for f in EXTRACTOR.supported_families)

    def test_repr_is_string(self):
        assert isinstance(repr(EXTRACTOR), str)

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschMP9Extractor" in repr(EXTRACTOR)


# ---------------------------------------------------------------------------
# TestCanHandleTrue
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """
    Verify can_handle() returns True for valid MP9 binaries.

    Phase 3 — accepted when primary sig b"MOTRONIC MP 9" in last 2 KB.
    Phase 4 — accepted when b"MP9" + HW pattern "0261xxxxxx" in last 2 KB.
    """

    def test_full_mp9_64kb_accepted(self):
        assert EXTRACTOR.can_handle(make_mp9_64kb_bin()) is True

    def test_minimal_mp9_accepted(self):
        """Phase 3: primary sig alone in last 2 KB is sufficient."""
        assert EXTRACTOR.can_handle(make_mp9_minimal_bin()) is True

    def test_ident_block_contains_primary_sig(self):
        """Ident block includes 'MOTRONIC MP 9.0' so Phase 3 fires."""
        data = make_mp9_64kb_bin(with_slash=False)
        assert EXTRACTOR.can_handle(data) is True

    def test_phase4_mp9_plus_hw_pattern(self):
        """Phase 4: b'MP9' + 0261xxxxxx in last 2 KB, no full MOTRONIC label."""
        buf = bytearray(0x10000)
        buf[0xF900:0xF903] = b"MP9"
        buf[0xF920:0xF92A] = b"0261204593"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_phase4_secondary_sig_with_different_hw(self):
        """Phase 4 works with any valid 0261xxxxxx HW pattern."""
        buf = bytearray(0x10000)
        buf[0xF900:0xF903] = b"MP9"
        buf[0xF920:0xF92A] = b"0261999999"
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_both_primary_and_secondary_present(self):
        """Having both primary and secondary sigs is still accepted."""
        data = make_mp9_64kb_bin()
        assert b"MOTRONIC MP 9" in data[-0x800:]
        assert b"MP9" in data[-0x800:]
        assert EXTRACTOR.can_handle(data) is True


# ---------------------------------------------------------------------------
# TestCanHandleFalse
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    """Verify can_handle() returns False for invalid / non-MP9 binaries."""

    def test_empty_binary_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_32kb_rejected(self):
        buf = bytearray(0x8000)
        buf[0x7900:0x790D] = b"MOTRONIC MP 9"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_128kb_rejected(self):
        """128KB belongs to other families — rejected by size gate."""
        buf = bytearray(0x20000)
        buf[0x1F900:0x1F90D] = b"MOTRONIC MP 9"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_256kb_rejected(self):
        """256KB belongs to M5.x / ME7 — rejected by size gate."""
        buf = bytearray(0x40000)
        buf[0x3F900:0x3F90D] = b"MOTRONIC MP 9"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_512kb_rejected(self):
        """512KB belongs to ME7 — rejected by size gate."""
        buf = bytearray(0x80000)
        buf[0x7F900:0x7F90D] = b"MOTRONIC MP 9"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_all_zero_64kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\x00" * 0x10000) is False

    def test_all_ff_64kb_rejected(self):
        assert EXTRACTOR.can_handle(b"\xff" * 0x10000) is False

    def test_no_sigs_64kb_rejected(self):
        """64KB of random data with no detection sigs."""
        buf = bytearray(0x10000)
        for i in range(0, 0x10000, 8):
            buf[i : i + 8] = b"ABCDEFGH"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_mp9_sig_only_no_hw_pattern_rejected(self):
        """Phase 4 requires BOTH b'MP9' AND 0261xxxxxx. MP9 alone is not enough."""
        buf = bytearray(0x10000)
        buf[0xF900:0xF903] = b"MP9"
        # No 0261xxxxxx pattern, and no MOTRONIC MP 9 either
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_hw_pattern_only_no_mp9_sig_rejected(self):
        """HW pattern without any MP9/MOTRONIC sig is not enough."""
        buf = bytearray(0x10000)
        buf[0xF920:0xF92A] = b"0261204593"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_primary_sig_outside_last_2kb_ignored(self):
        """Primary sig placed before the last 2 KB is outside the search area."""
        buf = bytearray(0x10000)
        # Place at 0x0100 — well outside last 2 KB (0xF800–0xFFFF)
        buf[0x0100:0x010D] = b"MOTRONIC MP 9"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_secondary_sigs_outside_last_2kb_ignored(self):
        """Secondary sigs placed outside last 2 KB are not detected."""
        buf = bytearray(0x10000)
        buf[0x0100:0x0103] = b"MP9"
        buf[0x0200:0x020A] = b"0261204593"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# TestCanHandleExclusions
# ---------------------------------------------------------------------------


class TestCanHandleExclusions:
    """
    Each entry in EXCLUSION_SIGNATURES must block can_handle() even when
    all positive indicators (ident block + primary sig) are present.
    Phase 1 (exclusion check) runs before any positive detection.
    """

    def _valid_buf(self) -> bytearray:
        return bytearray(make_mp9_64kb_bin())

    @pytest.mark.parametrize(
        "sig",
        EXCLUSION_SIGNATURES,
        ids=[s.decode("ascii", errors="replace").strip() for s in EXCLUSION_SIGNATURES],
    )
    def test_exclusion_sig_rejects_valid_bin(self, sig):
        buf = self._valid_buf()
        _inject_exclusion(buf, sig, offset=0x0200)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc17_exclusion_explicit(self):
        buf = self._valid_buf()
        _inject_exclusion(buf, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_dot_exclusion_explicit(self):
        buf = self._valid_buf()
        _inject_exclusion(buf, b"ME7.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m5_dot_exclusion_explicit(self):
        buf = self._valid_buf()
        _inject_exclusion(buf, b"M5.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_zz_ff_ff_exclusion(self):
        """ZZ\\xff\\xff is the ME7 ident block marker — hard reject."""
        buf = self._valid_buf()
        _inject_exclusion(buf, b"ZZ\xff\xff")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_tsw_space_exclusion(self):
        """b'TSW ' is an EDC15 toolchain marker."""
        buf = self._valid_buf()
        _inject_exclusion(buf, b"TSW ")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_at_offset_zero(self):
        buf = self._valid_buf()
        _inject_exclusion(buf, b"EDC17", offset=0)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_near_end_of_bin_still_caught(self):
        """Exclusion sig near end of binary is still found by Phase 1."""
        buf = self._valid_buf()
        _inject_exclusion(buf, b"EDC16", offset=0xF000)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_overrides_valid_bin(self):
        """Phase 1 runs before Phase 3 — exclusion always wins."""
        buf = self._valid_buf()
        _inject_exclusion(buf, b"SB_V")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_customer_dot_exclusion(self):
        buf = self._valid_buf()
        _inject_exclusion(buf, b"Customer.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_nr000_exclusion(self):
        buf = self._valid_buf()
        _inject_exclusion(buf, b"NR000")
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# TestExtract
# ---------------------------------------------------------------------------


class TestExtract:
    """Full extraction test for a valid MP9 binary."""

    def setup_method(self):
        self.data = make_mp9_64kb_bin()
        self.result = EXTRACTOR.extract(self.data, filename="6K0906027E.bin")

    def test_required_keys_present(self):
        assert REQUIRED_EXTRACT_KEYS.issubset(self.result.keys())

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_ecu_family_is_mp9(self):
        assert self.result["ecu_family"] == "MP9"

    def test_ecu_variant_is_mp90(self):
        assert self.result["ecu_variant"] == "MP9.0"

    def test_hardware_number(self):
        assert self.result["hardware_number"] == _HW

    def test_hardware_number_starts_with_0261(self):
        assert self.result["hardware_number"].startswith("0261")

    def test_hardware_number_is_10_digits(self):
        hw = self.result["hardware_number"]
        assert len(hw) == 10
        assert hw.isdigit()

    def test_software_version(self):
        assert self.result["software_version"] == _SW

    def test_software_version_starts_with_1037(self):
        assert self.result["software_version"].startswith("1037")

    def test_software_version_is_10_digits(self):
        sw = self.result["software_version"]
        assert len(sw) == 10
        assert sw.isdigit()

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == _OEM

    def test_match_key_format(self):
        assert self.result["match_key"] == f"MP9::{_SW}"

    def test_match_key_separator_is_double_colon(self):
        assert "::" in self.result["match_key"]

    def test_match_key_is_uppercase(self):
        assert self.result["match_key"] == self.result["match_key"].upper()

    def test_file_size_is_65536(self):
        assert self.result["file_size"] == 65536

    def test_file_size_equals_data_length(self):
        assert self.result["file_size"] == len(self.data)

    def test_md5_is_32_hex_chars(self):
        md5 = self.result["md5"]
        assert len(md5) == 32
        assert all(c in "0123456789abcdef" for c in md5)

    def test_md5_correct(self):
        expected = hashlib.md5(self.data).hexdigest()
        assert self.result["md5"] == expected

    def test_sha256_is_64_hex_chars(self):
        sha = self.result["sha256_first_64kb"]
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_sha256_correct(self):
        expected = hashlib.sha256(self.data[:0x10000]).hexdigest()
        assert self.result["sha256_first_64kb"] == expected

    def test_raw_strings_is_list(self):
        assert isinstance(self.result["raw_strings"], list)

    def test_raw_strings_not_empty(self):
        assert len(self.result["raw_strings"]) > 0

    def test_calibration_version_is_none(self):
        assert self.result["calibration_version"] is None

    def test_sw_base_version_is_none(self):
        assert self.result["sw_base_version"] is None

    def test_serial_number_is_none(self):
        assert self.result["serial_number"] is None

    def test_dataset_number_is_none(self):
        assert self.result["dataset_number"] is None

    def test_calibration_id_is_none(self):
        assert self.result["calibration_id"] is None


# ---------------------------------------------------------------------------
# TestExtractMinimal
# ---------------------------------------------------------------------------


class TestExtractMinimal:
    """
    Extract from a minimal binary (primary sig only, no structured ident block).

    The extractor should still return a valid dict with correct file_size,
    hashes, and family. Fields that depend on the ident block may be None.
    """

    def setup_method(self):
        self.data = make_mp9_minimal_bin()
        self.result = EXTRACTOR.extract(self.data, filename="minimal.bin")

    def test_required_keys_present(self):
        assert REQUIRED_EXTRACT_KEYS.issubset(self.result.keys())

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_ecu_family_is_mp9(self):
        assert self.result["ecu_family"] == "MP9"

    def test_file_size_is_65536(self):
        assert self.result["file_size"] == 65536

    def test_md5_correct(self):
        expected = hashlib.md5(self.data).hexdigest()
        assert self.result["md5"] == expected

    def test_sha256_correct(self):
        expected = hashlib.sha256(self.data[:0x10000]).hexdigest()
        assert self.result["sha256_first_64kb"] == expected

    def test_raw_strings_is_list(self):
        assert isinstance(self.result["raw_strings"], list)

    def test_calibration_version_is_none(self):
        assert self.result["calibration_version"] is None

    def test_sw_base_version_is_none(self):
        assert self.result["sw_base_version"] is None

    def test_serial_number_is_none(self):
        assert self.result["serial_number"] is None

    def test_dataset_number_is_none(self):
        assert self.result["dataset_number"] is None

    def test_calibration_id_is_none(self):
        assert self.result["calibration_id"] is None


# ---------------------------------------------------------------------------
# TestExtractNullFields
# ---------------------------------------------------------------------------


class TestExtractNullFields:
    """
    Fields not present in MP9 binaries must always be None in every extract()
    call regardless of binary variant.
    """

    def _result(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data, filename="null_check.bin")

    def test_calibration_version_is_none_full(self):
        assert self._result(make_mp9_64kb_bin())["calibration_version"] is None

    def test_calibration_version_is_none_minimal(self):
        assert self._result(make_mp9_minimal_bin())["calibration_version"] is None

    def test_sw_base_version_is_none_full(self):
        assert self._result(make_mp9_64kb_bin())["sw_base_version"] is None

    def test_serial_number_is_none_full(self):
        assert self._result(make_mp9_64kb_bin())["serial_number"] is None

    def test_dataset_number_is_none_full(self):
        assert self._result(make_mp9_64kb_bin())["dataset_number"] is None

    def test_calibration_id_is_none_full(self):
        assert self._result(make_mp9_64kb_bin())["calibration_id"] is None

    def test_calibration_id_is_none_minimal(self):
        assert self._result(make_mp9_minimal_bin())["calibration_id"] is None

    def test_sw_base_version_is_none_minimal(self):
        assert self._result(make_mp9_minimal_bin())["sw_base_version"] is None

    def test_serial_number_is_none_minimal(self):
        assert self._result(make_mp9_minimal_bin())["serial_number"] is None


# ---------------------------------------------------------------------------
# TestExtractHashing
# ---------------------------------------------------------------------------


class TestExtractHashing:
    """Verify md5 and sha256_first_64kb correctness."""

    def _check(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data, filename="hash_check.bin")

    def test_md5_is_32_hex_chars(self):
        result = self._check(make_mp9_64kb_bin())
        assert len(result["md5"]) == 32
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_correct_full(self):
        data = make_mp9_64kb_bin()
        assert self._check(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_md5_correct_minimal(self):
        data = make_mp9_minimal_bin()
        assert self._check(data)["md5"] == hashlib.md5(data).hexdigest()

    def test_sha256_is_64_hex_chars(self):
        result = self._check(make_mp9_64kb_bin())
        assert len(result["sha256_first_64kb"]) == 64
        assert all(c in "0123456789abcdef" for c in result["sha256_first_64kb"])

    def test_sha256_correct_full(self):
        data = make_mp9_64kb_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._check(data)["sha256_first_64kb"] == expected

    def test_sha256_correct_minimal(self):
        data = make_mp9_minimal_bin()
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert self._check(data)["sha256_first_64kb"] == expected

    def test_different_bins_different_md5(self):
        r1 = self._check(make_mp9_64kb_bin())
        r2 = self._check(make_mp9_minimal_bin())
        assert r1["md5"] != r2["md5"]

    def test_different_bins_different_sha256(self):
        r1 = self._check(make_mp9_64kb_bin())
        r2 = self._check(make_mp9_minimal_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]


# ---------------------------------------------------------------------------
# TestMatchKey
# ---------------------------------------------------------------------------


class TestMatchKey:
    """Verify build_match_key() behaviour as invoked by extract()."""

    def _result(self, data: bytes) -> dict:
        return EXTRACTOR.extract(data, filename="mk.bin")

    def test_match_key_format(self):
        result = self._result(make_mp9_64kb_bin())
        assert result["match_key"] == f"MP9::{_SW}"

    def test_match_key_none_when_no_sw(self):
        """All-zero 64KB has no SW → match_key must be None."""
        result = self._result(b"\x00" * 0x10000)
        assert result["match_key"] is None

    def test_match_key_is_always_uppercase(self):
        result = self._result(make_mp9_64kb_bin())
        assert result["match_key"] == result["match_key"].upper()

    def test_match_key_is_always_uppercase_minimal(self):
        result = self._result(make_mp9_minimal_bin())
        mk = result["match_key"]
        if mk is not None:
            assert mk == mk.upper()

    def test_match_key_separator_is_double_colon(self):
        result = self._result(make_mp9_64kb_bin())
        assert "::" in result["match_key"]

    def test_match_key_prefix_is_family(self):
        result = self._result(make_mp9_64kb_bin())
        prefix, _ = result["match_key"].split("::")
        assert prefix == "MP9"

    def test_match_key_suffix_is_sw(self):
        result = self._result(make_mp9_64kb_bin())
        _, suffix = result["match_key"].split("::")
        assert suffix == _SW

    def test_different_sw_gives_different_match_key(self):
        """Two binaries with different SW must have different match_keys."""
        buf2 = bytearray(0x10000)
        alt_ident = b"0261204593 1037999999 MP9 0006K0906027E  MOTRONIC MP 9.0    S023"
        buf2[0xF800 : 0xF800 + len(alt_ident)] = alt_ident
        r1 = self._result(make_mp9_64kb_bin())
        r2 = self._result(bytes(buf2))
        assert r1["match_key"] != r2["match_key"]


# ---------------------------------------------------------------------------
# TestDeterminism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """extract() must be deterministic; filename must not affect field values."""

    def test_same_binary_same_result(self):
        data = make_mp9_64kb_bin()
        r1 = EXTRACTOR.extract(data, filename="a.bin")
        r2 = EXTRACTOR.extract(data, filename="a.bin")
        assert r1 == r2

    def test_same_binary_same_result_minimal(self):
        data = make_mp9_minimal_bin()
        r1 = EXTRACTOR.extract(data, filename="b.bin")
        r2 = EXTRACTOR.extract(data, filename="b.bin")
        assert r1 == r2

    def test_filename_does_not_affect_fields(self):
        data = make_mp9_64kb_bin()
        r1 = EXTRACTOR.extract(data, filename="foo.bin")
        r2 = EXTRACTOR.extract(data, filename="completely_different_name.bin")
        assert r1["ecu_family"] == r2["ecu_family"]
        assert r1["software_version"] == r2["software_version"]
        assert r1["hardware_number"] == r2["hardware_number"]
        assert r1["oem_part_number"] == r2["oem_part_number"]
        assert r1["match_key"] == r2["match_key"]

    def test_filename_does_not_affect_minimal_fields(self):
        data = make_mp9_minimal_bin()
        r1 = EXTRACTOR.extract(data, filename="orig.bin")
        r2 = EXTRACTOR.extract(data, filename="copy.bin")
        assert r1["ecu_family"] == r2["ecu_family"]
        assert r1["md5"] == r2["md5"]

    def test_different_binaries_produce_different_md5(self):
        r1 = EXTRACTOR.extract(make_mp9_64kb_bin(), filename="x.bin")
        r2 = EXTRACTOR.extract(make_mp9_minimal_bin(), filename="x.bin")
        assert r1["md5"] != r2["md5"]

    def test_file_size_reflects_actual_binary_size(self):
        data = make_mp9_64kb_bin()
        assert EXTRACTOR.extract(data, filename="x.bin")["file_size"] == len(data)

    def test_can_handle_then_extract_consistent(self):
        """can_handle() True → extract() fields are non-None."""
        data = make_mp9_64kb_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data, filename="x.bin")
        assert result["ecu_family"] is not None
        assert result["software_version"] is not None
        assert result["hardware_number"] is not None

    def test_can_handle_then_extract_minimal_consistent(self):
        data = make_mp9_minimal_bin()
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data, filename="x.bin")
        assert result["ecu_family"] is not None
