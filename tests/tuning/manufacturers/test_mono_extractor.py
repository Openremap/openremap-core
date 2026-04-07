"""
Tests for BoschMonoExtractor (Mono-Motronic / MA1.2 / MA1.2.3).

Covers:
  - Identity: name, supported_families, repr
  - can_handle() — True paths:
      * Phase 3: 8051 LJMP header (\\x02\\x05) + PMC keyword (Format A, 32KB)
      * Phase 3: 8051 LJMP header + PMC keyword (Format B, DGC variant, 64KB)
      * Phase 4: 8051 LJMP header + VAG 907311 group code fallback
  - can_handle() — False paths:
      * Empty binary
      * Wrong size (128KB)
      * All-zero 32KB binary (right size, no PMC, no 907311)
      * Wrong header byte (0x85 instead of 0x02)
      * Correct header but no PMC and no 907311
      * Phase 1 exclusion signatures override positive detection
      * Each exclusion signature individually tested
  - extract() Format A (MONO variant):
      * Required keys all present
      * manufacturer == 'Bosch'
      * ecu_family == 'Mono-Motronic'
      * oem_part_number correctly parsed (e.g. '8A0907311H')
      * calibration_id == D-code (e.g. 'D51')
      * calibration_version == MONO version (e.g. '1.2.3')
      * hardware_number is None (not in binary)
      * software_version is None (not in binary)
      * match_key uses oem_part_number as fallback
  - extract() Format A without version:
      * oem_part_number parsed correctly
      * calibration_version is None (version field is spaces)
  - extract() Format B (DGC variant):
      * oem_part_number parsed from DGC ident
      * calibration_id is None (no D-code in DGC format)
  - extract() fallback (PMC present, no structured ident):
      * Graceful degradation — no crash, fields are None
  - Determinism and filename independence
  - match_key_fallback_field is set correctly
  - No false positives against other Bosch families (synthetic)
"""

import hashlib

from openremap.core.manufacturers.bosch.mono.extractor import BoschMonoExtractor

EXTRACTOR = BoschMonoExtractor()

# Keys that every extract() result must contain (minimal set for these tests).
REQUIRED_EXTRACT_KEYS = {
    "manufacturer",
    "match_key",
    "ecu_family",
    "ecu_variant",
    "software_version",
    "hardware_number",
    "calibration_id",
    "calibration_version",
    "file_size",
    "sha256_first_64kb",
}


# ---------------------------------------------------------------------------
# Binary factories
# ---------------------------------------------------------------------------


def make_mono_format_a_bin() -> bytes:
    """
    32KB Mono-Motronic binary — Format A (MONO variant, with version).

    Layout:
      0x0000 : 8051 LJMP header \\x02\\x05\\xB6\\x02\\x03\\x68
      0x6D00 : Ident block "8A0907311H  1,8l R4 MONO 1.2.3  D51PMC"

    Expected extraction:
      oem_part_number    = "8A0907311H"
      calibration_id     = "D51"
      calibration_version= "1.2.3"
      ecu_family         = "Mono-Motronic"
      match_key           = "MONO-MOTRONIC::8A0907311H"
    """
    buf = bytearray(0x8000)
    # 8051 LJMP header: LJMP 0x05B6 ; LJMP 0x0368
    buf[0:6] = b"\x02\x05\xb6\x02\x03\x68"

    # Ident block at 0x6D00
    ident = b"8A0907311H  1,8l R4 MONO 1.2.3  D51PMC"
    buf[0x6D00 : 0x6D00 + len(ident)] = ident

    return bytes(buf)


def make_mono_format_a_no_version_bin() -> bytes:
    """
    64KB Mono-Motronic binary — Format A (MONO variant, without version).

    Two mirrored 32KB halves.  The ident block has spaces where the version
    would be (e.g. VW Golf 3 1H0907311H — MONO without explicit version).

    Layout:
      0x0000 : 8051 LJMP header \\x02\\x05\\xA9\\x02\\x02\\xCD
      0x6E52 : Ident (Bank A) "1H0907311H  1,8l R4 MONO        D51PMC"
      0xEE52 : Ident (Bank B, mirror)

    Expected extraction:
      oem_part_number    = "1H0907311H"
      calibration_id     = "D51"
      calibration_version= None  (spaces, not a version)
      ecu_family         = "Mono-Motronic"
    """
    buf = bytearray(0x10000)
    # 8051 LJMP header
    buf[0:6] = b"\x02\x05\xa9\x02\x02\xcd"

    # Ident block in Bank A at 0x6E52
    ident = b"1H0907311H  1,8l R4 MONO        D51PMC"
    buf[0x6E52 : 0x6E52 + len(ident)] = ident

    # Mirror in Bank B
    buf[0xEE52 : 0xEE52 + len(ident)] = ident

    return bytes(buf)


def make_mono_format_b_bin() -> bytes:
    """
    64KB Mono-Motronic binary — Format B (DGC variant).

    Layout:
      0x0000 : 8051 LJMP header \\x02\\x05\\x83\\x02\\x02\\xEF
      0x5000 : Ident "3A0907311   1,8l3A0907311   1,8lDGCPMC"
      0xD000 : Ident (Bank B, mirror)

    Expected extraction:
      oem_part_number    = "3A0907311"
      calibration_id     = None  (no D-code in DGC format)
      calibration_version= None  (no MONO version string)
      ecu_family         = "Mono-Motronic"
    """
    buf = bytearray(0x10000)
    # 8051 LJMP header
    buf[0:6] = b"\x02\x05\x83\x02\x02\xef"

    # Ident block in Bank A at 0x5000
    ident = b"3A0907311   1,8l3A0907311   1,8lDGCPMC"
    buf[0x5000 : 0x5000 + len(ident)] = ident

    # Mirror in Bank B
    buf[0xD000 : 0xD000 + len(ident)] = ident

    return bytes(buf)


def make_mono_pmc_only_bin() -> bytes:
    """
    32KB binary with 8051 LJMP header + PMC keyword but no structured ident.

    Tests the fallback path where PMC triggers detection but no ident regex
    matches.

    Expected extraction:
      oem_part_number    = None
      calibration_id     = None
      calibration_version= None
      ecu_family         = "Mono-Motronic"
      match_key          = None  (no OEM part for fallback)
    """
    buf = bytearray(0x8000)
    buf[0:6] = b"\x02\x05\xb6\x02\x03\x68"

    # PMC keyword at arbitrary offset (not in structured ident format)
    buf[0x4000:0x4003] = b"PMC"

    return bytes(buf)


def make_mono_907311_only_bin() -> bytes:
    """
    32KB binary with 8051 LJMP header + VAG 907311 group code but no PMC.

    Tests Phase 4 fallback detection via the VAG group code alone.
    """
    buf = bytearray(0x8000)
    buf[0:6] = b"\x02\x05\xb6\x02\x03\x68"

    # OEM part number containing 907311 but no PMC keyword
    oem = b"1H0907311H"
    buf[0x6D00 : 0x6D00 + len(oem)] = oem

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

    def test_mono_motronic_in_supported_families(self):
        assert "Mono-Motronic" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_contains_bosch(self):
        assert "Bosch" in repr(EXTRACTOR)

    def test_repr_contains_class_name(self):
        assert "BoschMonoExtractor" in repr(EXTRACTOR)

    def test_match_key_fallback_field_is_oem_part_number(self):
        """Mono-Motronic uses oem_part_number as the match_key fallback."""
        assert EXTRACTOR.match_key_fallback_field == "oem_part_number"


# ---------------------------------------------------------------------------
# can_handle — True
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    def test_format_a_32kb_accepted(self):
        """Phase 3: 8051 header + PMC keyword (Format A, 32KB)."""
        assert EXTRACTOR.can_handle(make_mono_format_a_bin()) is True

    def test_format_a_no_version_64kb_accepted(self):
        """Phase 3: 8051 header + PMC keyword (Format A no-version, 64KB)."""
        assert EXTRACTOR.can_handle(make_mono_format_a_no_version_bin()) is True

    def test_format_b_dgc_64kb_accepted(self):
        """Phase 3: 8051 header + PMC keyword (Format B DGC, 64KB)."""
        assert EXTRACTOR.can_handle(make_mono_format_b_bin()) is True

    def test_pmc_only_accepted(self):
        """Phase 3: 8051 header + PMC keyword (no structured ident)."""
        assert EXTRACTOR.can_handle(make_mono_pmc_only_bin()) is True

    def test_907311_fallback_accepted(self):
        """Phase 4: 8051 header + VAG 907311 group code (no PMC)."""
        assert EXTRACTOR.can_handle(make_mono_907311_only_bin()) is True

    def test_minimal_32kb_with_pmc_accepted(self):
        """Minimal 32KB file: just the LJMP header + PMC."""
        buf = bytearray(0x8000)
        buf[0] = 0x02
        buf[1] = 0x05
        buf[0x1000:0x1003] = b"PMC"
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle — False
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    def test_empty_binary_rejected(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_small_binary_rejected(self):
        """512 bytes — not 32KB or 64KB."""
        assert EXTRACTOR.can_handle(bytes(512)) is False

    def test_all_zero_32kb_rejected(self):
        """32KB all-zero: header byte 0 is 0x00 (not 0x02), no PMC."""
        assert EXTRACTOR.can_handle(bytes(0x8000)) is False

    def test_wrong_header_byte_0_rejected(self):
        """Header byte 0 is 0x85 (M1.x magic), not 0x02."""
        buf = bytearray(0x8000)
        buf[0] = 0x85
        buf[1] = 0x05
        buf[0x1000:0x1003] = b"PMC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_wrong_header_byte_1_rejected(self):
        """Header byte 1 is 0x0F (M1.8-style), not 0x05."""
        buf = bytearray(0x8000)
        buf[0] = 0x02
        buf[1] = 0x0F
        buf[0x1000:0x1003] = b"PMC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_correct_header_no_pmc_no_907311_rejected(self):
        """8051 LJMP header but no PMC and no 907311 → rejected."""
        buf = bytearray(0x8000)
        buf[0] = 0x02
        buf[1] = 0x05
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_wrong_size_128kb_rejected(self):
        """128KB — outside the Mono-Motronic size gate."""
        buf = bytearray(0x20000)
        buf[0] = 0x02
        buf[1] = 0x05
        buf[0x1000:0x1003] = b"PMC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_wrong_size_16kb_rejected(self):
        """16KB — too small for Mono-Motronic."""
        buf = bytearray(0x4000)
        buf[0] = 0x02
        buf[1] = 0x05
        buf[0x1000:0x1003] = b"PMC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    # --- Exclusion signatures ---

    def test_edc17_exclusion(self):
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0100:0x0105] = b"EDC17"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_me7_exclusion(self):
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0100:0x0104] = b"ME7."
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_motronic_exclusion(self):
        """MOTRONIC label (M5.x / ME7 territory) is an exclusion."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0200:0x0208] = b"MOTRONIC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_motr_exclusion(self):
        """MOTR ident anchor (M5.x) is an exclusion."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0200:0x0204] = b"MOTR"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m1x_family_marker_exclusion(self):
        """'"0000000M' family marker is an exclusion (M1.x/M2.x/M3.x)."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x6000:0x6009] = b'"0000000M'
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m3x_family_marker_exclusion(self):
        """M3.1 marker (1350000M3) is an exclusion."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0060:0x0069] = b"1350000M3"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_zz_marker_exclusion(self):
        """ZZ\\xff\\xff (ME7 ident marker) is an exclusion."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0100:0x0104] = b"ZZ\xff\xff"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m1x_magic_exclusion(self):
        """M1.x detection magic \\x85\\x0a\\xf0\\x30 is an exclusion."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x2000:0x2004] = b"\x85\x0a\xf0\x30"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_digifant_exclusion(self):
        """DIGIFANT string is an exclusion (separate family)."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0500:0x0508] = b"DIGIFANT"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_lh_jetronic_exclusion(self):
        """LH-JET string is an exclusion."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0500:0x0506] = b"LH-JET"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_sbv_exclusion(self):
        """SB_V (modern Bosch SW base version) is an exclusion."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0500:0x0504] = b"SB_V"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# extract() — Format A (MONO with version)
# ---------------------------------------------------------------------------


class TestExtractFormatA:
    """Extract from a Format A bin with MONO version string."""

    def setup_method(self):
        self.data = make_mono_format_a_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_all_required_keys_present(self):
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in self.result, f"Missing required key: {key!r}"

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"

    def test_ecu_family_is_mono_motronic(self):
        assert self.result["ecu_family"] == "Mono-Motronic"

    def test_ecu_variant_equals_ecu_family(self):
        assert self.result["ecu_variant"] == self.result["ecu_family"]

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == "8A0907311H"

    def test_calibration_id_is_d_code(self):
        assert self.result["calibration_id"] == "D51"

    def test_calibration_version_is_mono_version(self):
        assert self.result["calibration_version"] == "1.2.3"

    def test_hardware_number_is_none(self):
        assert self.result["hardware_number"] is None

    def test_software_version_is_none(self):
        assert self.result["software_version"] is None

    def test_file_size_equals_data_length(self):
        assert self.result["file_size"] == len(self.data)

    def test_file_size_is_32kb(self):
        assert self.result["file_size"] == 0x8000

    def test_sha256_first_64kb_is_64_hex_chars(self):
        sha = self.result["sha256_first_64kb"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        int(sha, 16)  # raises ValueError if not valid hex

    def test_sha256_first_64kb_matches_hashlib(self):
        expected = hashlib.sha256(self.data[:0x10000]).hexdigest()
        assert self.result["sha256_first_64kb"] == expected

    def test_match_key_not_none(self):
        assert self.result["match_key"] is not None

    def test_match_key_contains_mono_motronic(self):
        mk = self.result["match_key"]
        assert "MONO-MOTRONIC" in mk

    def test_match_key_contains_oem_part(self):
        mk = self.result["match_key"]
        assert "8A0907311H" in mk

    def test_match_key_format(self):
        assert self.result["match_key"] == "MONO-MOTRONIC::8A0907311H"

    def test_md5_is_32_hex_chars(self):
        md5 = self.result["md5"]
        assert isinstance(md5, str)
        assert len(md5) == 32
        int(md5, 16)

    def test_raw_strings_is_list(self):
        assert isinstance(self.result["raw_strings"], list)


# ---------------------------------------------------------------------------
# extract() — Format A without version
# ---------------------------------------------------------------------------


class TestExtractFormatANoVersion:
    """Extract from a Format A bin without MONO version (spaces instead)."""

    def setup_method(self):
        self.data = make_mono_format_a_no_version_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_mono_motronic(self):
        assert self.result["ecu_family"] == "Mono-Motronic"

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == "1H0907311H"

    def test_calibration_id_is_d_code(self):
        assert self.result["calibration_id"] == "D51"

    def test_calibration_version_is_none(self):
        """No version in the ident block — spaces where version would be."""
        assert self.result["calibration_version"] is None

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000

    def test_match_key_contains_oem_part(self):
        mk = self.result["match_key"]
        assert mk is not None
        assert "1H0907311H" in mk


# ---------------------------------------------------------------------------
# extract() — Format B (DGC variant)
# ---------------------------------------------------------------------------


class TestExtractFormatB:
    """Extract from a Format B bin (DGC variant)."""

    def setup_method(self):
        self.data = make_mono_format_b_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_mono_motronic(self):
        assert self.result["ecu_family"] == "Mono-Motronic"

    def test_oem_part_number(self):
        assert self.result["oem_part_number"] == "3A0907311"

    def test_calibration_id_is_none(self):
        """DGC format has no D-code."""
        assert self.result["calibration_id"] is None

    def test_calibration_version_is_none(self):
        """DGC format has no MONO version string."""
        assert self.result["calibration_version"] is None

    def test_file_size_is_64kb(self):
        assert self.result["file_size"] == 0x10000

    def test_match_key_format(self):
        assert self.result["match_key"] == "MONO-MOTRONIC::3A0907311"


# ---------------------------------------------------------------------------
# extract() — Fallback (PMC only, no structured ident)
# ---------------------------------------------------------------------------


class TestExtractFallback:
    """Extract from a binary with PMC but no structured ident block."""

    def setup_method(self):
        self.data = make_mono_pmc_only_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_all_required_keys_present(self):
        for key in REQUIRED_EXTRACT_KEYS:
            assert key in self.result, f"Missing required key: {key!r}"

    def test_ecu_family_is_mono_motronic(self):
        assert self.result["ecu_family"] == "Mono-Motronic"

    def test_oem_part_number_is_none(self):
        assert self.result["oem_part_number"] is None

    def test_calibration_id_is_none(self):
        assert self.result["calibration_id"] is None

    def test_calibration_version_is_none(self):
        assert self.result["calibration_version"] is None

    def test_match_key_is_none(self):
        """No OEM part → no fallback value → match_key is None."""
        assert self.result["match_key"] is None

    def test_manufacturer_is_bosch(self):
        assert self.result["manufacturer"] == "Bosch"


# ---------------------------------------------------------------------------
# extract() — 907311 fallback detection (Phase 4)
# ---------------------------------------------------------------------------


class TestExtract907311Fallback:
    """Extract from a binary detected via 907311 group code (no PMC)."""

    def setup_method(self):
        self.data = make_mono_907311_only_bin()
        self.result = EXTRACTOR.extract(self.data)

    def test_ecu_family_is_mono_motronic(self):
        assert self.result["ecu_family"] == "Mono-Motronic"

    def test_oem_part_number_via_fallback_regex(self):
        """OEM part found via the generic 907311 fallback regex."""
        assert self.result["oem_part_number"] == "1H0907311H"


# ---------------------------------------------------------------------------
# Determinism and filename independence
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_binary_produces_same_result(self):
        data = make_mono_format_a_bin()
        r1 = EXTRACTOR.extract(data)
        r2 = EXTRACTOR.extract(data)
        assert r1["oem_part_number"] == r2["oem_part_number"]
        assert r1["ecu_family"] == r2["ecu_family"]
        assert r1["match_key"] == r2["match_key"]
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_filename_does_not_affect_identification_fields(self):
        data = make_mono_format_a_bin()
        r1 = EXTRACTOR.extract(data, filename="original.bin")
        r2 = EXTRACTOR.extract(data, filename="copy_renamed.bin")
        assert r1["oem_part_number"] == r2["oem_part_number"]
        assert r1["ecu_family"] == r2["ecu_family"]
        assert r1["sha256_first_64kb"] == r2["sha256_first_64kb"]

    def test_different_binaries_produce_different_sha256(self):
        r1 = EXTRACTOR.extract(make_mono_format_a_bin())
        r2 = EXTRACTOR.extract(make_mono_format_b_bin())
        assert r1["sha256_first_64kb"] != r2["sha256_first_64kb"]

    def test_file_size_differs_between_32kb_and_64kb(self):
        r1 = EXTRACTOR.extract(make_mono_format_a_bin())
        r2 = EXTRACTOR.extract(make_mono_format_a_no_version_bin())
        assert r1["file_size"] == 0x8000
        assert r2["file_size"] == 0x10000


# ---------------------------------------------------------------------------
# Cross-family false positive guards (synthetic binaries)
# ---------------------------------------------------------------------------


class TestCrossFamilyGuards:
    """
    Verify that synthetic binaries mimicking other Bosch families
    are NOT claimed by the Mono extractor.
    """

    def test_m1x_magic_not_claimed(self):
        """M1.x HC11 magic at offset 0 — different header bytes."""
        buf = bytearray(0x8000)
        buf[0:4] = b"\x85\x0a\xf0\x30"
        buf[0x1000:0x1003] = b"PMC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m2x_marker_not_claimed(self):
        """M2.x with '"0000000M2.' marker — excluded by family marker."""
        buf = bytearray(0x10000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x5000:0x500B] = b'"0000000M2.'
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_m5x_with_motronic_not_claimed(self):
        """M5.x-like bin with MOTRONIC label — excluded."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x2000:0x2008] = b"MOTRONIC"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_digifant_not_claimed(self):
        """Digifant bin — excluded by DIGIFANT string."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x4000:0x4008] = b"DIGIFANT"
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc15_not_claimed(self):
        """EDC15 bin — excluded by EDC15 string."""
        buf = bytearray(0x8000)
        buf[0:2] = b"\x02\x05"
        buf[0x1000:0x1003] = b"PMC"
        buf[0x0500:0x0505] = b"EDC15"
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# Tail marker extraction
# ---------------------------------------------------------------------------


class TestTailMarker:
    """Test tail marker resolution (informational — not stored as a field)."""

    def test_tail_marker_resolved_from_format_a_bin(self):
        """Tail marker can be extracted when present."""
        buf = bytearray(make_mono_format_a_bin())
        # Insert a tail marker at 0x7FF7
        buf[0x7FF7:0x7FFE] = b"WAN057@"
        data = bytes(buf)
        marker = EXTRACTOR._resolve_tail_marker(data)
        assert marker == "WAN057@"

    def test_tail_marker_none_when_absent(self):
        """No tail marker in the last 16 bytes → returns None."""
        data = make_mono_pmc_only_bin()
        marker = EXTRACTOR._resolve_tail_marker(data)
        assert marker is None


# ---------------------------------------------------------------------------
# OEM part boundary precision
# ---------------------------------------------------------------------------


class TestOemPartBoundary:
    """
    Verify the OEM part regex correctly handles bytes adjacent to the
    part number without capturing them.
    """

    def test_preceding_alpha_not_captured(self):
        """
        When the ident block is preceded by ASCII letters (e.g. 'LL'),
        the regex must NOT capture them as part of the OEM part.
        """
        buf = bytearray(0x8000)
        buf[0:6] = b"\x02\x05\xa9\x02\x02\xcd"
        # Simulate the real VW Golf 3 layout: "LL1H0907311H  1,8l R4 MONO        D51PMC"
        ident = b"LL1H0907311H  1,8l R4 MONO        D51PMC"
        buf[0x6E50 : 0x6E50 + len(ident)] = ident
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        assert result["oem_part_number"] == "1H0907311H"

    def test_preceding_calibration_bytes_not_captured(self):
        """
        When preceded by non-printable calibration data followed by
        printable chars, only the true OEM part is captured.
        """
        buf = bytearray(0x8000)
        buf[0:6] = b"\x02\x05\xb6\x02\x03\x68"
        # "\xff\xfe\xfd8A0907311H  1,8l R4 MONO 1.2.3  D51PMC"
        prefix = b"\xff\xfe\xfd"
        ident = b"8A0907311H  1,8l R4 MONO 1.2.3  D51PMC"
        offset = 0x6D00
        buf[offset : offset + len(prefix)] = prefix
        buf[offset + len(prefix) : offset + len(prefix) + len(ident)] = ident
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        assert result["oem_part_number"] == "8A0907311H"

    def test_oem_part_without_suffix_letter(self):
        """OEM part with no suffix letter: '3A0907311' (9 chars)."""
        buf = bytearray(0x8000)
        buf[0:6] = b"\x02\x05\x83\x02\x02\xef"
        ident = b"3A0907311   1,8lDGCPMC"
        buf[0x5000 : 0x5000 + len(ident)] = ident
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        assert result["oem_part_number"] == "3A0907311"

    def test_oem_part_with_two_letter_suffix(self):
        """OEM part with two-letter suffix: '1H0907311AB' (11 chars)."""
        buf = bytearray(0x8000)
        buf[0:6] = b"\x02\x05\xb6\x02\x03\x68"
        ident = b"1H0907311AB  1,8l R4 MONO 1.2.3  D51PMC"
        buf[0x6D00 : 0x6D00 + len(ident)] = ident
        data = bytes(buf)
        result = EXTRACTOR.extract(data)
        assert result["oem_part_number"] == "1H0907311AB"
