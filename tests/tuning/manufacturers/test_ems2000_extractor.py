"""
Tests for SiemensEMS2000Extractor.

Covers:
  - Identity properties: name, supported_families
  - can_handle():
      * True  — correct size + header magic + no exclusion signatures
      * False — wrong size (too small, too large, zero)
      * False — correct size but exclusion signature present
      * False — correct size but wrong header magic
      * False — correct size + header magic but exclusion signature present
      * Boundary: each exclusion signature independently causes rejection
  - extract():
      * Required fields always present: manufacturer, file_size, md5, sha256_first_64kb
      * manufacturer always "Siemens"
      * ecu_family always "EMS2000"
      * file_size == len(data)
      * md5 and sha256_first_64kb are well-formed hex strings
      * hardware_number is None (not embedded)
      * software_version is None (not embedded)
      * ecu_variant is None (not embedded)
      * calibration_id is None (not embedded)
      * match_key is None (no software_version to build from)
      * serial_number populated if Volvo VIN found
      * raw_strings is a list
      * extract() is deterministic
      * filename does not affect identification fields
  - build_match_key():
      * Always None for EMS2000 (no software_version)
  - __repr__: contains class name and manufacturer
"""

import hashlib
import re

from openremap.core.manufacturers.siemens.ems2000.extractor import (
    SiemensEMS2000Extractor,
    EMS2000_FILE_SIZE,
)
from openremap.core.manufacturers.siemens.ems2000.patterns import (
    EMS2000_HEADER,
    EXCLUSION_SIGNATURES,
    PATTERNS,
    SEARCH_REGIONS,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_buf(size: int, fill: int = 0x00) -> bytearray:
    """Return a mutable buffer of `size` bytes filled with `fill`."""
    return bytearray([fill] * size)


def write(buf: bytearray, offset: int, data: bytes) -> bytearray:
    """Write `data` into `buf` at `offset` and return `buf`."""
    buf[offset : offset + len(data)] = data
    return buf


KB = 1024
MB = 1024 * KB

EXTRACTOR = SiemensEMS2000Extractor()


def _make_valid_ems2000() -> bytearray:
    """
    Build a minimal valid EMS2000 binary: correct size + header magic, no
    exclusion signatures.
    """
    buf = make_buf(EMS2000_FILE_SIZE, fill=0xFF)
    write(buf, 0, EMS2000_HEADER)
    return buf


# ---------------------------------------------------------------------------
# Identity properties
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_name_is_siemens(self):
        assert EXTRACTOR.name == "Siemens"

    def test_supported_families(self):
        families = EXTRACTOR.supported_families
        assert isinstance(families, list)
        assert "EMS2000" in families

    def test_supported_families_length(self):
        assert len(EXTRACTOR.supported_families) == 1


# ---------------------------------------------------------------------------
# can_handle() — True cases
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    def test_valid_ems2000_header_magic(self):
        """Correct size + header magic + no exclusions → True."""
        buf = _make_valid_ems2000()
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_valid_zero_filled_with_header(self):
        """Zero-filled binary with header magic is accepted (no exclusion
        signatures consist solely of zero bytes)."""
        buf = make_buf(EMS2000_FILE_SIZE, fill=0x00)
        write(buf, 0, EMS2000_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_valid_arbitrary_fill_with_header(self):
        """Arbitrary fill byte (0xAB) with header magic — accepted as long
        as no exclusion signature appears."""
        buf = make_buf(EMS2000_FILE_SIZE, fill=0xAB)
        write(buf, 0, EMS2000_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_valid_with_non_exclusion_ascii(self):
        """Binary containing random ASCII that is NOT an exclusion signature
        should still be accepted."""
        buf = _make_valid_ems2000()
        # Write something innocuous that's not in the exclusion list
        write(buf, 0x1000, b"HELLO WORLD 12345")
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle() — False cases
# ---------------------------------------------------------------------------


class TestCanHandleFalse:
    def test_empty_binary(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_too_small(self):
        buf = make_buf(EMS2000_FILE_SIZE - 1, fill=0xFF)
        write(buf, 0, EMS2000_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_too_large(self):
        buf = make_buf(EMS2000_FILE_SIZE + 1, fill=0xFF)
        write(buf, 0, EMS2000_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_double_size(self):
        buf = make_buf(EMS2000_FILE_SIZE * 2, fill=0xFF)
        write(buf, 0, EMS2000_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_half_size(self):
        buf = make_buf(EMS2000_FILE_SIZE // 2, fill=0xFF)
        write(buf, 0, EMS2000_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_wrong_header_magic(self):
        """Correct size but wrong header magic → False."""
        buf = make_buf(EMS2000_FILE_SIZE, fill=0xFF)
        write(buf, 0, b"\xde\xad\xbe\xef")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_no_header_all_ff(self):
        """Correct size, all 0xFF, no header magic → False."""
        buf = make_buf(EMS2000_FILE_SIZE, fill=0xFF)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_all_zeros_no_header(self):
        """Correct size, all zeros, no header magic → False."""
        buf = make_buf(EMS2000_FILE_SIZE, fill=0x00)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_header_at_wrong_offset(self):
        """Header magic present but not at offset 0 → False."""
        buf = make_buf(EMS2000_FILE_SIZE, fill=0xFF)
        write(buf, 4, EMS2000_HEADER)  # offset 4, not 0
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_header_at_end(self):
        """Header magic at the very end of the file → False."""
        buf = make_buf(EMS2000_FILE_SIZE, fill=0xFF)
        write(buf, EMS2000_FILE_SIZE - len(EMS2000_HEADER), EMS2000_HEADER)
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# can_handle() — Exclusion signatures
# ---------------------------------------------------------------------------


class TestCanHandleExclusions:
    """Every exclusion signature must independently cause rejection."""

    def test_each_exclusion_signature_rejects(self):
        """Iterate ALL exclusion signatures and verify each one rejects."""
        for sig in EXCLUSION_SIGNATURES:
            buf = _make_valid_ems2000()
            # Place exclusion signature in the middle of the binary
            offset = EMS2000_FILE_SIZE // 2
            write(buf, offset, sig)
            assert EXTRACTOR.can_handle(bytes(buf)) is False, (
                f"Exclusion signature {sig!r} did not cause rejection"
            )

    def test_exclusion_bosch_edc17(self):
        buf = _make_valid_ems2000()
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_bosch_motronic(self):
        buf = _make_valid_ems2000()
        write(buf, 0x2000, b"MOTRONIC")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_bosch_0261(self):
        buf = _make_valid_ems2000()
        write(buf, 0x5000, b"0261")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_bosch_0281(self):
        buf = _make_valid_ems2000()
        write(buf, 0x5000, b"0281")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_siemens_simos(self):
        buf = _make_valid_ems2000()
        write(buf, 0x3000, b"SIMOS")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_siemens_5wp4(self):
        buf = _make_valid_ems2000()
        write(buf, 0x4000, b"5WP4")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_siemens_5ws4(self):
        buf = _make_valid_ems2000()
        write(buf, 0x4000, b"5WS4")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_siemens_5wk9(self):
        buf = _make_valid_ems2000()
        write(buf, 0x4000, b"5WK9")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_siemens_sid80(self):
        buf = _make_valid_ems2000()
        write(buf, 0x4000, b"SID80")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_siemens_ppd(self):
        buf = _make_valid_ems2000()
        write(buf, 0x4000, b"PPD")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_siemens_pm3(self):
        buf = _make_valid_ems2000()
        write(buf, 0x4000, b"PM3")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_delphi(self):
        buf = _make_valid_ems2000()
        write(buf, 0x6000, b"DELPHI")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_delco(self):
        buf = _make_valid_ems2000()
        write(buf, 0x6000, b"DELCO")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_del(self):
        buf = _make_valid_ems2000()
        write(buf, 0x6000, b"DEL")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_marelli(self):
        buf = _make_valid_ems2000()
        write(buf, 0x7000, b"MARELLI")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_mag(self):
        buf = _make_valid_ems2000()
        write(buf, 0x7000, b"MAG")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_iaw(self):
        buf = _make_valid_ems2000()
        write(buf, 0x7000, b"IAW")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_denso(self):
        buf = _make_valid_ems2000()
        write(buf, 0x8000, b"DENSO")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_bosch_label(self):
        buf = _make_valid_ems2000()
        write(buf, 0x9000, b"BOSCH")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_at_offset_zero_after_header(self):
        """Exclusion signature immediately after the header magic."""
        buf = _make_valid_ems2000()
        write(buf, len(EMS2000_HEADER), b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_at_very_end(self):
        """Exclusion signature at the last bytes of the file."""
        buf = _make_valid_ems2000()
        sig = b"BOSCH"
        write(buf, EMS2000_FILE_SIZE - len(sig), sig)
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_multiple_exclusions(self):
        """Multiple exclusion signatures present — still rejected."""
        buf = _make_valid_ems2000()
        write(buf, 0x1000, b"EDC17")
        write(buf, 0x2000, b"MOTRONIC")
        write(buf, 0x3000, b"BOSCH")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_111pm(self):
        buf = _make_valid_ems2000()
        write(buf, 0xA000, b"111PM")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_111po(self):
        buf = _make_valid_ems2000()
        write(buf, 0xA000, b"111PO")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_111sn(self):
        buf = _make_valid_ems2000()
        write(buf, 0xA000, b"111SN")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_111s2(self):
        buf = _make_valid_ems2000()
        write(buf, 0xA000, b"111s2")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_capm(self):
        buf = _make_valid_ems2000()
        write(buf, 0xB000, b"CAPM")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_capo(self):
        buf = _make_valid_ems2000()
        write(buf, 0xB000, b"CAPO")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_casn(self):
        buf = _make_valid_ems2000()
        write(buf, 0xB000, b"CASN")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_03g906(self):
        buf = _make_valid_ems2000()
        write(buf, 0xC000, b"03G906")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_sbv(self):
        buf = _make_valid_ems2000()
        write(buf, 0xD000, b"SB_V")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_customer_dot(self):
        buf = _make_valid_ems2000()
        write(buf, 0xD000, b"Customer.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_s21(self):
        buf = _make_valid_ems2000()
        write(buf, 0xE000, b"s21")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_cas21(self):
        buf = _make_valid_ems2000()
        write(buf, 0xE000, b"cas21")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_sn1(self):
        buf = _make_valid_ems2000()
        write(buf, 0xF000, b"SN1")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_me7_dot(self):
        buf = _make_valid_ems2000()
        write(buf, 0xF000, b"ME7.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_medc17(self):
        buf = _make_valid_ems2000()
        write(buf, 0xF000, b"MEDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_med17(self):
        buf = _make_valid_ems2000()
        write(buf, 0xF000, b"MED17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_slash_m1_dot(self):
        buf = _make_valid_ems2000()
        write(buf, 0x10000, b"/M1.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_slash_m2_dot(self):
        buf = _make_valid_ems2000()
        write(buf, 0x10000, b"/M2.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_slash_m3_dot(self):
        buf = _make_valid_ems2000()
        write(buf, 0x10000, b"/M3.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_slash_m4_dot(self):
        buf = _make_valid_ems2000()
        write(buf, 0x10000, b"/M4.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_slash_m5_dot(self):
        buf = _make_valid_ems2000()
        write(buf, 0x10000, b"/M5.")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_exclusion_po(self):
        buf = _make_valid_ems2000()
        write(buf, 0x11000, b"PO")
        assert EXTRACTOR.can_handle(bytes(buf)) is False


# ---------------------------------------------------------------------------
# extract() — Required fields
# ---------------------------------------------------------------------------


class TestExtractRequiredFields:
    def test_manufacturer_is_siemens(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["manufacturer"] == "Siemens"

    def test_ecu_family_is_ems2000(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["ecu_family"] == "EMS2000"

    def test_file_size_matches(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["file_size"] == EMS2000_FILE_SIZE

    def test_md5_is_valid_hex(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        md5 = result["md5"]
        assert isinstance(md5, str)
        assert len(md5) == 32
        assert re.fullmatch(r"[0-9a-f]{32}", md5)

    def test_md5_is_correct(self):
        buf = _make_valid_ems2000()
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "ems2000.bin")
        expected_md5 = hashlib.md5(data).hexdigest()
        assert result["md5"] == expected_md5

    def test_sha256_first_64kb_is_valid_hex(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        sha = result["sha256_first_64kb"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        assert re.fullmatch(r"[0-9a-f]{64}", sha)

    def test_sha256_first_64kb_is_correct(self):
        buf = _make_valid_ems2000()
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "ems2000.bin")
        expected_sha = hashlib.sha256(data[:0x10000]).hexdigest()
        assert result["sha256_first_64kb"] == expected_sha

    def test_raw_strings_is_list(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert isinstance(result["raw_strings"], list)


# ---------------------------------------------------------------------------
# extract() — Fields expected to be None
# ---------------------------------------------------------------------------


class TestExtractNoneFields:
    """Most fields are None for EMS2000 — no embedded metadata."""

    def test_hardware_number_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["hardware_number"] is None

    def test_software_version_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["software_version"] is None

    def test_ecu_variant_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["ecu_variant"] is None

    def test_calibration_id_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["calibration_id"] is None

    def test_calibration_version_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["calibration_version"] is None

    def test_sw_base_version_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["sw_base_version"] is None

    def test_dataset_number_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["dataset_number"] is None

    def test_oem_part_number_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["oem_part_number"] is None

    def test_match_key_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["match_key"] is None

    def test_serial_number_is_none_when_no_vin(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["serial_number"] is None


# ---------------------------------------------------------------------------
# extract() — Volvo VIN extraction
# ---------------------------------------------------------------------------


class TestExtractVolvoVin:
    def test_vin_extracted_when_present(self):
        buf = _make_valid_ems2000()
        vin = b"YV1SW58D922123456"
        write(buf, 0x20000, vin)
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["serial_number"] == "YV1SW58D922123456"

    def test_vin_at_start_of_binary(self):
        buf = _make_valid_ems2000()
        # Place VIN right after the header magic
        vin = b"YV1LW36F4Y2012345"
        write(buf, len(EMS2000_HEADER), vin)
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["serial_number"] == "YV1LW36F4Y2012345"

    def test_vin_at_end_of_binary(self):
        buf = _make_valid_ems2000()
        vin = b"YV1TS92D412345678"
        write(buf, EMS2000_FILE_SIZE - len(vin), vin)
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["serial_number"] == "YV1TS92D412345678"

    def test_no_vin_serial_is_none(self):
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["serial_number"] is None

    def test_non_volvo_vin_not_extracted(self):
        """VINs not starting with YV1 should not be extracted."""
        buf = _make_valid_ems2000()
        write(buf, 0x20000, b"WVWZZZ3CZWE123456")
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["serial_number"] is None


# ---------------------------------------------------------------------------
# extract() — Determinism and filename independence
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_deterministic(self):
        """Two calls with the same data produce the same result."""
        buf = _make_valid_ems2000()
        data = bytes(buf)
        result1 = EXTRACTOR.extract(data, "ems2000.bin")
        result2 = EXTRACTOR.extract(data, "ems2000.bin")
        assert result1 == result2

    def test_filename_does_not_affect_identification(self):
        """Different filenames produce the same identification fields."""
        buf = _make_valid_ems2000()
        data = bytes(buf)
        result_a = EXTRACTOR.extract(data, "Volvo S40 T4 1.9T.ori")
        result_b = EXTRACTOR.extract(data, "unknown.bin")
        # All identification fields must match
        for key in [
            "manufacturer",
            "ecu_family",
            "ecu_variant",
            "hardware_number",
            "software_version",
            "calibration_id",
            "match_key",
            "file_size",
            "md5",
            "sha256_first_64kb",
        ]:
            assert result_a[key] == result_b[key], (
                f"Field {key!r} differs: {result_a[key]!r} vs {result_b[key]!r}"
            )

    def test_different_data_produces_different_hashes(self):
        buf_a = _make_valid_ems2000()
        buf_b = _make_valid_ems2000()
        buf_b[0x100] = 0x42  # Change one byte
        result_a = EXTRACTOR.extract(bytes(buf_a), "a.bin")
        result_b = EXTRACTOR.extract(bytes(buf_b), "b.bin")
        assert result_a["md5"] != result_b["md5"]
        assert result_a["sha256_first_64kb"] != result_b["sha256_first_64kb"]


# ---------------------------------------------------------------------------
# extract() — Raw strings
# ---------------------------------------------------------------------------


class TestExtractRawStrings:
    def test_raw_strings_empty_for_clean_binary(self):
        """A binary filled with 0xFF has no printable ASCII strings."""
        buf = _make_valid_ems2000()
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert result["raw_strings"] == []

    def test_raw_strings_captures_long_ascii(self):
        """A long ASCII string in the header region is captured."""
        buf = _make_valid_ems2000()
        write(buf, 0x0100, b"SOME LONG TEST STRING HERE")
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert any("SOME LONG TEST STRING" in s for s in result["raw_strings"])

    def test_raw_strings_ignores_short_strings(self):
        """Strings shorter than 8 characters are not captured."""
        buf = _make_valid_ems2000()
        write(buf, 0x0100, b"SHORT")  # 5 chars
        result = EXTRACTOR.extract(bytes(buf), "ems2000.bin")
        assert not any("SHORT" in s for s in result["raw_strings"])


# ---------------------------------------------------------------------------
# build_match_key()
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_match_key_always_none(self):
        """EMS2000 has no software_version, so match_key is always None."""
        key = EXTRACTOR.build_match_key(
            ecu_family="EMS2000",
            ecu_variant=None,
            software_version=None,
        )
        assert key is None

    def test_match_key_with_sw_version_would_work(self):
        """If sw was somehow provided, build_match_key would produce a key
        (validates the method is not overridden to always return None)."""
        key = EXTRACTOR.build_match_key(
            ecu_family="EMS2000",
            ecu_variant=None,
            software_version="HYPOTHETICAL_VER",
        )
        assert key == "EMS2000::HYPOTHETICAL_VER"

    def test_match_key_variant_takes_precedence(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EMS2000",
            ecu_variant="EMS2001",
            software_version="V1",
        )
        assert key == "EMS2001::V1"

    def test_match_key_family_used_when_no_variant(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EMS2000",
            ecu_variant=None,
            software_version="V1",
        )
        assert key == "EMS2000::V1"


# ---------------------------------------------------------------------------
# __repr__
# ---------------------------------------------------------------------------


class TestRepr:
    def test_repr_contains_class_name(self):
        r = repr(EXTRACTOR)
        assert "SiemensEMS2000Extractor" in r

    def test_repr_contains_manufacturer(self):
        r = repr(EXTRACTOR)
        assert "Siemens" in r

    def test_repr_contains_ems2000(self):
        r = repr(EXTRACTOR)
        assert "EMS2000" in r


# ---------------------------------------------------------------------------
# Integration: can_handle / extract round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_can_handle_then_extract(self):
        """If can_handle() returns True, extract() must succeed without error."""
        buf = _make_valid_ems2000()
        data = bytes(buf)
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data, "test.bin")
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] == "EMS2000"
        assert result["file_size"] == EMS2000_FILE_SIZE

    def test_extract_with_vin_round_trip(self):
        """Full round-trip with a Volvo VIN embedded."""
        buf = _make_valid_ems2000()
        write(buf, 0x30000, b"YV1CZ592751234567")
        data = bytes(buf)
        assert EXTRACTOR.can_handle(data) is True
        result = EXTRACTOR.extract(data, "volvo_s40.ori")
        assert result["manufacturer"] == "Siemens"
        assert result["ecu_family"] == "EMS2000"
        assert result["serial_number"] == "YV1CZ592751234567"
        assert result["match_key"] is None  # No SW version → no match key


# ---------------------------------------------------------------------------
# Patterns module constants validation
# ---------------------------------------------------------------------------


class TestPatternsModule:
    def test_detection_signatures_is_empty(self):
        """EMS2000 has no positive detection signatures."""
        from openremap.core.manufacturers.siemens.ems2000.patterns import (
            DETECTION_SIGNATURES,
        )

        assert DETECTION_SIGNATURES == []

    def test_exclusion_signatures_is_not_empty(self):
        assert len(EXCLUSION_SIGNATURES) > 0

    def test_exclusion_signatures_count(self):
        """Sanity check: we have a comprehensive exclusion list."""
        # At least 30 exclusion signatures to cover all known manufacturers
        assert len(EXCLUSION_SIGNATURES) >= 30

    def test_header_magic_is_4_bytes(self):
        assert len(EMS2000_HEADER) == 4

    def test_header_magic_value(self):
        assert EMS2000_HEADER == b"\xc0\xf0\x68\xa6"

    def test_file_size_constant(self):
        from openremap.core.manufacturers.siemens.ems2000.patterns import (
            EMS2000_FILE_SIZE as PATT_FILE_SIZE,
        )

        assert PATT_FILE_SIZE == 262144

    def test_patterns_dict_has_volvo_vin(self):
        assert "volvo_vin" in PATTERNS

    def test_search_regions_has_full(self):
        assert "full" in SEARCH_REGIONS

    def test_search_regions_has_header(self):
        assert "header" in SEARCH_REGIONS
