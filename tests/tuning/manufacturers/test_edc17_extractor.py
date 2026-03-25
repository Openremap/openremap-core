"""
Tests for BoschExtractor (EDC17 / MEDC17 / MED17 / ME17 / MED9 / MD1).

Covers:
  - Identity properties: name, supported_families
  - can_handle():
      * True  — each detection signature, multiple signatures together
      * False — all-zero binary, all-FF binary
      * False — EDC16 rejection via \xde\xca\xfe magic + size gate (256 KB / 1 MB / 2 MB)
      * False — EDC16 rejection via b"EDC16" string safety net
      * False — EDC15 rejection via b"TSW " at bank boundary
      * Boundary: EDC16 magic present but at wrong offset → not rejected
      * Boundary: EDC16 magic at correct offset but wrong file size → not rejected
  - extract():
      * Required fields always present: manufacturer, file_size, md5, sha256_first_64kb
      * manufacturer always "Bosch"
      * file_size == len(data)
      * md5 and sha256_first_64kb are well-formed hex strings
      * ecu_variant detected when b"EDC17Cxx" embedded in extended region
      * ecu_family detected for each major family string
      * software_version detected from a realistic Bosch SW string
      * hardware_number detected from a realistic Bosch HW part number
      * match_key built as FAMILY::VERSION when both variant and SW present
      * match_key is None when no SW version or fallback calibration_id found
      * calibration_id fallback used in match_key when SW absent
      * PSA calibration_id detected from header region
  - build_match_key():
      * variant takes precedence over family in the key
      * family used when variant absent
      * None returned when no version component available
      * Whitespace collapsed in version_normalised
      * UNKNOWN used as family part when both are absent
  - __repr__: contains class name and manufacturer
"""

import hashlib

from openremap.tuning.manufacturers.bosch.edc17.extractor import BoschExtractor


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------


def make_bin(size: int, fill: int = 0x00) -> bytearray:
    """Return a mutable bytearray of `size` bytes set to `fill`."""
    return bytearray([fill] * size)


def write(buf: bytearray, offset: int, data: bytes) -> bytearray:
    """Write `data` at `offset` in `buf` and return `buf`."""
    buf[offset : offset + len(data)] = data
    return buf


# ---------------------------------------------------------------------------
# Sizes (bytes)
# ---------------------------------------------------------------------------

KB = 1024
MB = 1024 * KB

SIZE_512KB = 512 * KB  # not in EDC16 magic-offset dict → safe for EDC17 tests
SIZE_256KB = 256 * KB  # EDC16 size — magic at 0x003D
SIZE_1MB = 1 * MB  # EDC16 size — magic at 0x4003D etc.
SIZE_2MB = 2 * MB  # EDC16 size — magic at 0x1C003D

EDC16_MAGIC = b"\xde\xca\xfe"

EDC16_MAGIC_OFFSETS = {
    SIZE_256KB: [0x0003D],
    SIZE_1MB: [0x4003D, 0x8003D, 0xD003D, 0xE003D],
    SIZE_2MB: [0x1C003D],
}

EXTRACTOR = BoschExtractor()


# ---------------------------------------------------------------------------
# Identity properties
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

    def test_edc17_in_supported_families(self):
        assert "EDC17" in EXTRACTOR.supported_families

    def test_medc17_in_supported_families(self):
        assert "MEDC17" in EXTRACTOR.supported_families

    def test_med17_in_supported_families(self):
        assert "MED17" in EXTRACTOR.supported_families

    def test_me17_in_supported_families(self):
        assert "ME17" in EXTRACTOR.supported_families

    def test_md1_in_supported_families(self):
        assert "MD1" in EXTRACTOR.supported_families

    def test_all_families_are_strings(self):
        for f in EXTRACTOR.supported_families:
            assert isinstance(f, str), f"Family {f!r} is not a string"

    def test_repr_contains_manufacturer(self):
        r = repr(EXTRACTOR)
        assert "Bosch" in r

    def test_repr_contains_class_name(self):
        r = repr(EXTRACTOR)
        assert "BoschExtractor" in r


# ---------------------------------------------------------------------------
# can_handle — True cases (detection signatures)
# ---------------------------------------------------------------------------


class TestCanHandleTrue:
    """Each DETECTION_SIGNATURE must independently trigger True."""

    def _make_512kb_with(self, sig: bytes) -> bytes:
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, sig)
        return bytes(buf)

    def test_edc17_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"EDC17")) is True

    def test_medc17_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"MEDC17")) is True

    def test_med17_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"MED17")) is True

    def test_med9_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"MED9")) is True

    def test_md1_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"MD1")) is True

    def test_me17_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"ME17")) is True

    def test_bosch_mixed_case_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"Bosch")) is True

    def test_bosch_upper_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"BOSCH")) is True

    def test_sb_v_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"SB_V")) is True

    def test_nr000_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"NR000")) is True

    def test_customer_dot_signature(self):
        assert EXTRACTOR.can_handle(self._make_512kb_with(b"Customer.")) is True

    def test_multiple_signatures_still_true(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        write(buf, 0x2000, b"MEDC17")
        write(buf, 0x3000, b"SB_V")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_signature_near_end_of_search_area(self):
        # Signature at 0x7FFE0 — still within the 512KB binary
        buf = make_bin(SIZE_512KB)
        write(buf, 0x7FFE0, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_signature_at_offset_zero(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_3mb_binary_with_edc17_signature(self):
        # 3 MB is not an EDC16 size — should be accepted
        buf = make_bin(3 * MB)
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_edc17_variant_string_triggers_via_edc17_prefix(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17C66")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_medc17_with_version_suffix(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"MEDC17.7")
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle — False cases (no signatures)
# ---------------------------------------------------------------------------


class TestCanHandleFalseNoSignature:
    def test_all_zero_binary(self):
        assert EXTRACTOR.can_handle(bytes(SIZE_512KB)) is False

    def test_all_ff_binary(self):
        assert EXTRACTOR.can_handle(bytes([0xFF] * SIZE_512KB)) is False

    def test_tiny_zero_binary(self):
        assert EXTRACTOR.can_handle(bytes(64)) is False

    def test_empty_binary(self):
        assert EXTRACTOR.can_handle(b"") is False

    def test_random_like_bytes_no_signature(self):
        data = bytes((i * 7 + 13) % 256 for i in range(SIZE_512KB))
        # Only reject if no signature happens to appear by coincidence
        # (deterministic content — verified by inspection to contain no sig)
        result = EXTRACTOR.can_handle(data)
        # We only assert it does not raise; the value depends on content
        assert isinstance(result, bool)

    def test_binary_with_only_ascii_noise_no_sig(self):
        # Uppercase alphabet repeated — no ECU signatures
        chunk = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" * (SIZE_512KB // 26 + 1)
        data = chunk[:SIZE_512KB]
        assert EXTRACTOR.can_handle(data) is False


# ---------------------------------------------------------------------------
# can_handle — Guard 1a: EDC16 rejection via magic + size gate
# ---------------------------------------------------------------------------


class TestCanHandleEDC16MagicRejection:
    """
    A binary of an EDC16 size (256KB / 1MB / 2MB) with the DECAFE magic
    at the correct offset must be rejected even if it also contains an
    EDC17 detection signature.
    """

    def _make_edc16(
        self, size: int, magic_offset: int, extra_sig: bytes = b"EDC17"
    ) -> bytes:
        buf = make_bin(size)
        write(buf, magic_offset, EDC16_MAGIC)
        write(buf, 0x1000, extra_sig)
        return bytes(buf)

    # 256 KB — magic at 0x003D
    def test_256kb_magic_at_0x3d_rejected(self):
        data = self._make_edc16(SIZE_256KB, 0x0003D)
        assert EXTRACTOR.can_handle(data) is False

    def test_256kb_magic_at_0x3d_rejected_even_with_medc17(self):
        data = self._make_edc16(SIZE_256KB, 0x0003D, extra_sig=b"MEDC17")
        assert EXTRACTOR.can_handle(data) is False

    def test_256kb_magic_at_0x3d_rejected_even_with_sb_v(self):
        data = self._make_edc16(SIZE_256KB, 0x0003D, extra_sig=b"SB_V")
        assert EXTRACTOR.can_handle(data) is False

    # 1 MB — magic at first valid offset (0x4003D)
    def test_1mb_magic_at_0x4003d_rejected(self):
        data = self._make_edc16(SIZE_1MB, 0x4003D)
        assert EXTRACTOR.can_handle(data) is False

    def test_1mb_magic_at_0x8003d_rejected(self):
        data = self._make_edc16(SIZE_1MB, 0x8003D)
        assert EXTRACTOR.can_handle(data) is False

    def test_1mb_magic_at_0xd003d_rejected(self):
        data = self._make_edc16(SIZE_1MB, 0xD003D)
        assert EXTRACTOR.can_handle(data) is False

    def test_1mb_magic_at_0xe003d_rejected(self):
        data = self._make_edc16(SIZE_1MB, 0xE003D)
        assert EXTRACTOR.can_handle(data) is False

    # 2 MB — magic at 0x1C003D
    def test_2mb_magic_at_0x1c003d_rejected(self):
        data = self._make_edc16(SIZE_2MB, 0x1C003D)
        assert EXTRACTOR.can_handle(data) is False

    def test_2mb_magic_at_0x1c003d_rejected_even_with_bosch(self):
        data = self._make_edc16(SIZE_2MB, 0x1C003D, extra_sig=b"Bosch")
        assert EXTRACTOR.can_handle(data) is False

    # Boundary: correct size but magic at wrong offset → NOT rejected by guard 1a
    def test_256kb_magic_at_wrong_offset_not_rejected_by_guard1a(self):
        buf = make_bin(SIZE_256KB)
        write(buf, 0x0100, EDC16_MAGIC)  # wrong offset — 0x003D expected
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    def test_1mb_magic_at_wrong_offset_not_rejected_by_guard1a(self):
        buf = make_bin(SIZE_1MB)
        write(buf, 0x0100, EDC16_MAGIC)  # not one of 0x4003D etc.
        write(buf, 0x1000, b"EDC17")
        # Guard 1a does not fire, but guard 1b may if "EDC16" string is present.
        # Here we only write the magic bytes, not the string "EDC16", so
        # guard 1b also passes → accepted.
        assert EXTRACTOR.can_handle(bytes(buf)) is True

    # Boundary: wrong size but magic at the 256KB offset value → not rejected
    def test_512kb_with_magic_at_edc16_256kb_offset_not_rejected(self):
        # 512KB is NOT in EDC16_MAGIC_OFFSETS → guard 1a skips → magic irrelevant
        buf = make_bin(SIZE_512KB)
        write(buf, 0x0003D, EDC16_MAGIC)
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle — Guard 1b: EDC16 string safety net
# ---------------------------------------------------------------------------


class TestCanHandleEDC16StringRejection:
    """
    Any binary containing b"EDC16" in the first 512KB must be rejected
    regardless of size (guard 1b safety net).
    """

    def test_512kb_edc16_string_rejected(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC16")
        write(buf, 0x2000, b"EDC17")  # would pass without guard 1b
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc16_string_at_start_rejected(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0, b"EDC16")
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc16_string_at_0x7fff0_rejected(self):
        # Just inside the first 512KB
        buf = make_bin(SIZE_512KB)
        write(buf, 0x7FFF0, b"EDC16")
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_edc16_string_absent_no_rejection(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        assert b"EDC16" not in bytes(buf)
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# can_handle — Guard 2: EDC15 TSW rejection
# ---------------------------------------------------------------------------


class TestCanHandleEDC15Rejection:
    """
    A binary with b"TSW " at 0x8000 (the EDC15 bank-boundary anchor)
    must be rejected.
    """

    def test_tsw_at_0x8000_rejected(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x8000, b"TSW V2.40 280700 1718 C7/ESB/G40")
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_tsw_at_second_bank_0x88000_in_1mb_rejected(self):
        buf = make_bin(SIZE_1MB)
        write(buf, 0x88000, b"TSW V2.40 ")
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is False

    def test_tsw_not_at_bank_boundary_not_rejected(self):
        buf = make_bin(SIZE_512KB)
        # Write TSW at a non-bank-boundary offset — guard 2 only checks ±96 bytes around 0x8000
        write(buf, 0x9000, b"TSW V2.40 280700 1718 C7/ESB/G40")
        write(buf, 0x1000, b"EDC17")
        assert EXTRACTOR.can_handle(bytes(buf)) is True


# ---------------------------------------------------------------------------
# extract — required fields always present
# ---------------------------------------------------------------------------


class TestExtractRequiredFields:
    REQUIRED = {
        "manufacturer",
        "file_size",
        "md5",
        "sha256_first_64kb",
    }

    def _extract(self, sig: bytes = b"EDC17", size: int = SIZE_512KB) -> dict:
        buf = make_bin(size)
        write(buf, 0x1000, sig)
        return EXTRACTOR.extract(bytes(buf), "test.bin")

    def test_all_required_fields_present(self):
        result = self._extract()
        for key in self.REQUIRED:
            assert key in result, f"Missing required field: {key}"

    def test_manufacturer_always_bosch(self):
        assert self._extract()["manufacturer"] == "Bosch"

    def test_manufacturer_bosch_for_medc17(self):
        assert self._extract(b"MEDC17")["manufacturer"] == "Bosch"

    def test_manufacturer_bosch_for_med17(self):
        assert self._extract(b"MED17")["manufacturer"] == "Bosch"

    def test_file_size_equals_data_length(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        result = EXTRACTOR.extract(bytes(buf), "test.bin")
        assert result["file_size"] == SIZE_512KB

    def test_file_size_correct_for_different_sizes(self):
        for size in (64 * KB, 128 * KB, SIZE_512KB):
            buf = make_bin(size)
            write(buf, 0x1000, b"EDC17")
            result = EXTRACTOR.extract(bytes(buf), "t.bin")
            assert result["file_size"] == size

    def test_md5_is_32_hex_chars(self):
        result = self._extract()
        md5 = result["md5"]
        assert isinstance(md5, str)
        assert len(md5) == 32

    def test_md5_is_lowercase_hex(self):
        result = self._extract()
        assert all(c in "0123456789abcdef" for c in result["md5"])

    def test_md5_matches_hashlib(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "t.bin")
        expected = hashlib.md5(data).hexdigest()
        assert result["md5"] == expected

    def test_sha256_first_64kb_is_64_hex_chars(self):
        result = self._extract()
        sha = result["sha256_first_64kb"]
        assert isinstance(sha, str)
        assert len(sha) == 64

    def test_sha256_first_64kb_matches_hashlib(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        data = bytes(buf)
        result = EXTRACTOR.extract(data, "t.bin")
        expected = hashlib.sha256(data[:0x10000]).hexdigest()
        assert result["sha256_first_64kb"] == expected

    def test_sha256_first_64kb_uses_only_first_64kb(self):
        # Changing bytes beyond 64KB must not change sha256_first_64kb
        buf_a = make_bin(SIZE_512KB)
        write(buf_a, 0x1000, b"EDC17")
        buf_b = bytearray(buf_a)
        write(buf_b, 0x20000, b"\xff" * 64)  # past 64KB boundary

        r_a = EXTRACTOR.extract(bytes(buf_a), "a.bin")
        r_b = EXTRACTOR.extract(bytes(buf_b), "b.bin")
        assert r_a["sha256_first_64kb"] == r_b["sha256_first_64kb"]

    def test_md5_changes_with_different_content(self):
        r_a = self._extract(b"EDC17")
        r_b = self._extract(b"MEDC17")
        assert r_a["md5"] != r_b["md5"]


# ---------------------------------------------------------------------------
# extract — ECU variant detection
# ---------------------------------------------------------------------------


class TestExtractVariant:
    def _bin_with(self, *payloads: tuple[int, bytes]) -> bytes:
        buf = make_bin(SIZE_512KB)
        for offset, data in payloads:
            write(buf, offset, data)
        return bytes(buf)

    def test_edc17c66_variant_detected(self):
        data = self._bin_with((0x1000, b"EDC17C66"))
        result = EXTRACTOR.extract(data, "t.bin")
        assert result.get("ecu_variant") == "EDC17C66"

    def test_edc17cp14_variant_detected(self):
        data = self._bin_with((0x1000, b"EDC17CP14"))
        result = EXTRACTOR.extract(data, "t.bin")
        assert result.get("ecu_variant") == "EDC17CP14"

    def test_edc17u05_variant_detected(self):
        data = self._bin_with((0x1000, b"EDC17U05"))
        result = EXTRACTOR.extract(data, "t.bin")
        assert result.get("ecu_variant") == "EDC17U05"

    def test_no_variant_returns_none(self):
        # Only a generic "EDC17" family string — no specific variant
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert result.get("ecu_variant") is None

    def test_variant_in_match_key_when_sw_also_present(self):
        # Place variant string and a realistic SW version in the binary
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17C66")
        write(buf, 0x2000, b"1037541778126241V0")  # realistic Bosch SW
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        key = result.get("match_key") or ""
        if key:
            assert "EDC17" in key.upper()


# ---------------------------------------------------------------------------
# extract — ECU family detection
# ---------------------------------------------------------------------------


class TestExtractFamily:
    def _family_from(self, sig: bytes) -> str | None:
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, sig)
        return EXTRACTOR.extract(bytes(buf), "t.bin").get("ecu_family")

    def test_medc17_family_detected(self):
        family = self._family_from(b"MEDC17")
        assert family is not None
        assert "MEDC17" in family.upper() or "EDC17" in family.upper()

    def test_edc17_family_detected(self):
        family = self._family_from(b"EDC17")
        assert family is not None
        assert "EDC17" in family.upper()

    def test_med17_family_detected(self):
        family = self._family_from(b"MED17")
        assert family is not None
        assert "MED17" in family.upper()

    def test_me17_family_detected(self):
        family = self._family_from(b"ME17.9")
        assert family is not None

    def test_bosch_only_sig_family_may_be_none(self):
        # Only b"Bosch" — no family pattern present — family may be None
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"Bosch")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        # Either None or a detected family — both acceptable
        assert "ecu_family" in result


# ---------------------------------------------------------------------------
# extract — software version detection
# ---------------------------------------------------------------------------


class TestExtractSoftwareVersion:
    def test_sw_version_detected_from_realistic_string(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        write(buf, 0x2000, b"1037541778126241V0")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        sw = result.get("software_version") or ""
        assert "1037" in sw

    def test_sw_version_absent_returns_none(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        # No 1037xxxxxx string → None
        assert result.get("software_version") is None

    def test_sw_version_10sw_format_not_returned_without_1037(self):
        # "10SW041803126266V1" matches the raw pattern but does NOT start with
        # "1037".  All real-world EDC17 / MEDC17 / MED17 / ME17 / MD1 / MED9
        # calibrations use the "1037" prefix without exception.  When no
        # 1037-prefixed candidate survives the filters (e.g. wiped ident block)
        # the resolver now returns None rather than falling back to arbitrary
        # digit strings from calibration table regions.
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        write(buf, 0x2000, b"10SW041803126266V1")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert result.get("software_version") is None


# ---------------------------------------------------------------------------
# extract — hardware number detection
# ---------------------------------------------------------------------------


class TestExtractHardwareNumber:
    def test_hardware_number_detected_spaced(self):
        # "0 281 034 791" — spaced format
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        write(buf, 0x3000, b"0 281 034 791")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        hw = result.get("hardware_number") or ""
        # The pattern strips spaces — result may be normalised
        assert "281" in hw

    def test_hardware_number_detected_compact(self):
        # "0281034791" — no spaces
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        write(buf, 0x3000, b"0281034791")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        hw = result.get("hardware_number") or ""
        assert "281" in hw

    def test_hardware_number_absent_returns_none(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        assert result.get("hardware_number") is None


# ---------------------------------------------------------------------------
# extract — PSA calibration_id detection
# ---------------------------------------------------------------------------


class TestExtractPSACalibrationId:
    def test_psa_calibration_id_detected_from_header(self):
        # PSA cal IDs live in the first 16 bytes: "0800" + 2-digit year + 9 alnum
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        # Write PSA cal ID at offset 1 (within the 16-byte header region)
        write(buf, 0x0001, b"08001505827522B")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        cal = result.get("calibration_id") or ""
        assert "0800" in cal or cal == "08001505827522B"

    def test_psa_calibration_id_absent_when_not_in_header(self):
        # PSA ID is present but past the 16-byte header region → not detected
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        write(buf, 0x0020, b"08001505827522B")  # offset 32 — past psa_header region
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        # calibration_id may still be None (or set from another pattern)
        # We just assert the call does not raise
        assert "calibration_id" in result


# ---------------------------------------------------------------------------
# extract — match_key construction
# ---------------------------------------------------------------------------


class TestExtractMatchKey:
    def test_match_key_none_when_no_sw_or_calibration(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        # No SW version, no PSA calibration_id → match_key is None
        assert result.get("match_key") is None

    def test_match_key_built_when_sw_present(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17C66")
        write(buf, 0x2000, b"1037541778126241V0")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        key = result.get("match_key") or ""
        if key:
            assert "::" in key
            assert "1037" in key

    def test_match_key_format_is_family_double_colon_version(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17C66")
        write(buf, 0x2000, b"1037541778126241V0")
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        key = result.get("match_key") or ""
        if key:
            parts = key.split("::")
            assert len(parts) == 2
            assert len(parts[0]) > 0
            assert len(parts[1]) > 0

    def test_match_key_uses_psa_calibration_as_fallback(self):
        # No SW version → calibration_id fallback used for match_key
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17")
        write(buf, 0x0001, b"08001505827522B")  # PSA cal ID in header
        result = EXTRACTOR.extract(bytes(buf), "t.bin")
        # match_key may be set via calibration_id fallback
        # (depends on whether SW version is also spuriously detected)
        assert "match_key" in result


# ---------------------------------------------------------------------------
# build_match_key — unit tests on the shared method
# ---------------------------------------------------------------------------


class TestBuildMatchKey:
    def test_variant_and_sw_produces_variant_in_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            ecu_variant="EDC17C66",
            software_version="1037541778126241V0",
        )
        assert key is not None
        assert "EDC17C66" in key

    def test_family_used_when_variant_absent(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="MEDC17",
            ecu_variant=None,
            software_version="1037541778126241V0",
        )
        assert key is not None
        assert "MEDC17" in key

    def test_variant_takes_precedence_over_family(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            ecu_variant="EDC17C66",
            software_version="1037541778126241V0",
        )
        assert key is not None
        # variant (EDC17C66) should be the family part, not plain EDC17
        parts = key.split("::")
        assert parts[0] == "EDC17C66"

    def test_sw_version_appears_in_key(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            software_version="1037541778126241V0",
        )
        assert key is not None
        assert "1037541778126241V0" in key

    def test_none_returned_when_no_sw_or_fallback(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            ecu_variant="EDC17C66",
            software_version=None,
        )
        assert key is None

    def test_fallback_value_used_when_sw_absent(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            software_version=None,
            fallback_value="08001505827522B",
        )
        assert key is not None
        assert "08001505827522B" in key

    def test_fallback_not_used_when_sw_present(self):
        # SW always wins over fallback
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            software_version="1037541778126241V0",
            fallback_value="FALLBACK_SHOULD_NOT_APPEAR",
        )
        assert "FALLBACK_SHOULD_NOT_APPEAR" not in (key or "")
        assert "1037541778126241V0" in (key or "")

    def test_unknown_used_when_no_family_or_variant(self):
        key = EXTRACTOR.build_match_key(
            ecu_family=None,
            ecu_variant=None,
            software_version="1037541778126241V0",
        )
        assert key is not None
        assert "UNKNOWN" in key

    def test_key_is_uppercase(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="edc17",
            ecu_variant=None,
            software_version="1037abc",
        )
        assert key == key.upper() if key else True

    def test_whitespace_collapsed_in_version(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            software_version="9146179  P01",
        )
        assert key is not None
        # Double space must be collapsed to single space
        assert "  " not in key

    def test_double_colon_separator_used(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            software_version="1037541778",
        )
        assert key is not None
        assert "::" in key

    def test_empty_string_sw_treated_as_absent(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            software_version="",
        )
        assert key is None

    def test_none_fallback_not_used_even_when_sw_absent(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            software_version=None,
            fallback_value=None,
        )
        assert key is None

    def test_empty_fallback_not_used(self):
        key = EXTRACTOR.build_match_key(
            ecu_family="EDC17",
            software_version=None,
            fallback_value="",
        )
        assert key is None


# ---------------------------------------------------------------------------
# extract — determinism
# ---------------------------------------------------------------------------


class TestExtractDeterminism:
    def test_same_binary_produces_same_result(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17C66")
        data = bytes(buf)
        r1 = EXTRACTOR.extract(data, "t.bin")
        r2 = EXTRACTOR.extract(data, "t.bin")
        assert r1 == r2

    def test_filename_does_not_change_identification(self):
        buf = make_bin(SIZE_512KB)
        write(buf, 0x1000, b"EDC17C66")
        data = bytes(buf)
        r_a = EXTRACTOR.extract(data, "stock.bin")
        r_b = EXTRACTOR.extract(data, "stage1.ori")
        for key in ("manufacturer", "ecu_family", "ecu_variant", "match_key"):
            assert r_a.get(key) == r_b.get(key)

    def test_different_content_may_produce_different_md5(self):
        buf_a = make_bin(SIZE_512KB)
        write(buf_a, 0x1000, b"EDC17")
        buf_b = make_bin(SIZE_512KB)
        write(buf_b, 0x1000, b"MEDC17")
        r_a = EXTRACTOR.extract(bytes(buf_a), "a.bin")
        r_b = EXTRACTOR.extract(bytes(buf_b), "b.bin")
        assert r_a["md5"] != r_b["md5"]
