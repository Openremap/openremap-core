"""
Recipe-creation safety test suite for ECUDiffAnalyzer / cook pipeline.

Questions answered exhaustively
--------------------------------
  1. Are we protected when the user accidentally cooks two different ECU
     families?  (identity mismatch guard)

  2. Are we protected when the two binaries have different sizes?
     (size mismatch hard error)

  3. What does the raw diff actually capture?
     (VIN, checksums, IMMO, serial numbers — all included, no filtering)

  4. Are cook_warnings surfaced correctly and embedded in the recipe?

  5. Does the diff engine behave correctly at boundaries and edge cases?

Test classes
------------
  TestSizeMatchGuard            — hard error on size mismatch, passes on equal
  TestIdentityMatchGuard        — warns on family mismatch, silent on unknown
  TestCookWarningsAPI           — cook_warnings() populated & embedded in recipe
  TestRawDiffScope              — VIN, checksum, IMMO bytes all captured
  TestDiffDoesNotFilterAnything — every changed byte ends up in the recipe
  TestBuildRecipeGuardOrder     — size error raised before identity check runs
  TestCookCLISizeMismatch       — CLI exits 1 on size mismatch
  TestCookCLIIdentityWarning    — CLI prints warning on identity mismatch
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from tests.conftest import make_bin_with
from openremap.cli.commands.cook import app as cook_app
from openremap.core.services.recipe_builder import ECUDiffAnalyzer


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _build(size: int, patches: dict | None = None) -> bytes:
    """Zero-filled binary of *size* bytes with optional byte placements."""
    buf = bytearray(size)
    for off, val in (patches or {}).items():
        if isinstance(val, int):
            buf[off] = val
        else:
            buf[off : off + len(val)] = val
    return bytes(buf)


def _analyzer(
    original: bytes,
    modified: bytes,
    orig_name: str = "original.bin",
    mod_name: str = "modified.bin",
    context_size: int = 16,
) -> ECUDiffAnalyzer:
    return ECUDiffAnalyzer(
        original_data=original,
        modified_data=modified,
        original_filename=orig_name,
        modified_filename=mod_name,
        context_size=context_size,
    )


runner = CliRunner()


# ===========================================================================
# 1 — Size mismatch guard (hard error)
# ===========================================================================


class TestSizeMatchGuard:
    """
    build_recipe() must raise ValueError immediately when the two binaries
    are not the same size.  No diff must be run, no recipe must be produced.
    """

    def test_raises_on_size_mismatch(self):
        orig = _build(1024)
        mod = _build(512)
        with pytest.raises(ValueError, match="size mismatch"):
            _analyzer(orig, mod).build_recipe()

    def test_raises_when_modified_is_larger(self):
        orig = _build(512)
        mod = _build(1024)
        with pytest.raises(ValueError, match="size mismatch"):
            _analyzer(orig, mod).build_recipe()

    def test_raises_when_modified_is_one_byte_shorter(self):
        orig = _build(512)
        mod = _build(511)
        with pytest.raises(ValueError):
            _analyzer(orig, mod).build_recipe()

    def test_raises_when_modified_is_one_byte_longer(self):
        orig = _build(512)
        mod = _build(513)
        with pytest.raises(ValueError):
            _analyzer(orig, mod).build_recipe()

    def test_no_changes_set_when_size_error_raised(self):
        """find_changes() must not run — changes list stays empty."""
        orig = _build(1024)
        mod = _build(512)
        a = _analyzer(orig, mod)
        with pytest.raises(ValueError):
            a.build_recipe()
        assert a.changes == []

    def test_error_message_contains_both_sizes(self):
        orig = _build(1024)
        mod = _build(768)
        with pytest.raises(ValueError) as exc_info:
            _analyzer(orig, mod).build_recipe()
        msg = str(exc_info.value)
        assert "1,024" in msg or "1024" in msg
        assert "768" in msg

    def test_equal_sizes_does_not_raise(self):
        orig = _build(1024)
        mod = _build(1024)
        # Should not raise — recipe with zero instructions returned
        recipe = _analyzer(orig, mod).build_recipe()
        assert recipe["instructions"] == []

    def test_check_size_match_returns_none_when_equal(self):
        orig = _build(512)
        mod = _build(512)
        assert _analyzer(orig, mod).check_size_match() is None

    def test_check_size_match_returns_string_when_different(self):
        orig = _build(512)
        mod = _build(256)
        result = _analyzer(orig, mod).check_size_match()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_empty_binaries_equal_size_does_not_raise(self):
        recipe = _analyzer(b"", b"").build_recipe()
        assert recipe["instructions"] == []


# ===========================================================================
# 2 — Identity match guard (warning, not fatal)
# ===========================================================================


class TestIdentityMatchGuard:
    """
    When both binaries can be identified and their match_keys differ,
    check_identity_match() must return a warning string.
    When identification fails on either side, it must return None silently.
    """

    def test_returns_none_when_both_unidentified(self):
        """Unknown binaries → cannot compare → no warning."""
        orig = _build(512)
        mod = _build(512)
        a = _analyzer(orig, mod)
        assert a.check_identity_match() is None

    def test_returns_none_when_original_unidentified(self):
        orig = _build(512)
        mod = _build(512, {0: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[{"match_key": None}, {"match_key": "EDC17::12345"}],
        ):
            a = _analyzer(orig, mod)
            assert a.check_identity_match() is None

    def test_returns_none_when_modified_unidentified(self):
        orig = _build(512)
        mod = _build(512, {0: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[{"match_key": "ME7::99999"}, {"match_key": None}],
        ):
            a = _analyzer(orig, mod)
            assert a.check_identity_match() is None

    def test_returns_warning_string_when_keys_differ(self):
        orig = _build(512)
        mod = _build(512, {0: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[
                {"match_key": "ME7::11111", "ecu_family": "ME7"},
                {"match_key": "EDC17::22222", "ecu_family": "EDC17"},
            ],
        ):
            a = _analyzer(orig, mod)
            result = a.check_identity_match()
            assert isinstance(result, str)
            assert "ME7::11111" in result
            assert "EDC17::22222" in result

    def test_warning_mentions_both_families(self):
        orig = _build(512)
        mod = _build(512, {0: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[
                {"match_key": "ME7::11111", "ecu_family": "ME7"},
                {"match_key": "EDC17::22222", "ecu_family": "EDC17"},
            ],
        ):
            a = _analyzer(orig, mod)
            msg = a.check_identity_match()
            assert "ME7" in msg
            assert "EDC17" in msg

    def test_returns_none_when_keys_match(self):
        orig = _build(512)
        mod = _build(512, {100: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[
                {"match_key": "ME7::11111", "ecu_family": "ME7"},
                {"match_key": "ME7::11111", "ecu_family": "ME7"},
            ],
        ):
            a = _analyzer(orig, mod)
            assert a.check_identity_match() is None

    def test_returns_none_when_identify_ecu_raises(self):
        orig = _build(512)
        mod = _build(512, {0: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=RuntimeError("identification failed"),
        ):
            a = _analyzer(orig, mod)
            assert a.check_identity_match() is None

    def test_identity_mismatch_is_not_fatal(self):
        """A mismatch warning must NOT prevent build_recipe() from running."""
        orig = _build(512)
        mod = _build(512, {100: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[
                {"match_key": "ME7::11111", "ecu_family": "ME7"},
                {"match_key": "EDC17::22222", "ecu_family": "EDC17"},
                # third call from extract_ecu_identifiers inside build_recipe
                {
                    "match_key": "ME7::11111",
                    "ecu_family": "ME7",
                    "ecu_variant": None,
                    "manufacturer": "Bosch",
                    "software_version": None,
                    "hardware_number": None,
                    "calibration_id": None,
                    "file_size": 512,
                    "sha256": "abc",
                },
            ],
        ):
            a = _analyzer(orig, mod)
            recipe = a.build_recipe()  # must not raise
            assert recipe is not None


# ===========================================================================
# 3 — cook_warnings() API and embedding in recipe
# ===========================================================================


class TestCookWarningsAPI:
    """
    cook_warnings() must return the list of warnings from the last
    build_recipe() call.  Warnings must also appear in recipe["ecu"]["cook_warnings"].
    """

    def test_cook_warnings_empty_when_no_issues(self):
        orig = _build(512)
        mod = _build(512, {100: 0xAA})
        a = _analyzer(orig, mod)
        a.build_recipe()
        assert a.cook_warnings() == []

    def test_cook_warnings_contains_identity_warning(self):
        orig = _build(512)
        mod = _build(512, {100: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[
                {"match_key": "ME7::A", "ecu_family": "ME7"},
                {"match_key": "EDC17::B", "ecu_family": "EDC17"},
                {
                    "match_key": "ME7::A",
                    "ecu_family": "ME7",
                    "ecu_variant": None,
                    "manufacturer": "Bosch",
                    "software_version": None,
                    "hardware_number": None,
                    "calibration_id": None,
                    "file_size": 512,
                    "sha256": "x",
                },
            ],
        ):
            a = _analyzer(orig, mod)
            a.build_recipe()
            warnings = a.cook_warnings()
            assert len(warnings) == 1
            assert "ME7::A" in warnings[0]
            assert "EDC17::B" in warnings[0]

    def test_cook_warnings_embedded_in_recipe_ecu_block(self):
        orig = _build(512)
        mod = _build(512, {100: 0xFF})
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[
                {"match_key": "ME7::A", "ecu_family": "ME7"},
                {"match_key": "EDC17::B", "ecu_family": "EDC17"},
                {
                    "match_key": "ME7::A",
                    "ecu_family": "ME7",
                    "ecu_variant": None,
                    "manufacturer": "Bosch",
                    "software_version": None,
                    "hardware_number": None,
                    "calibration_id": None,
                    "file_size": 512,
                    "sha256": "x",
                },
            ],
        ):
            a = _analyzer(orig, mod)
            recipe = a.build_recipe()
            assert "cook_warnings" in recipe["ecu"]
            assert len(recipe["ecu"]["cook_warnings"]) == 1

    def test_cook_warnings_empty_list_embedded_when_clean(self):
        orig = _build(512)
        mod = _build(512, {100: 0xAA})
        a = _analyzer(orig, mod)
        recipe = a.build_recipe()
        assert recipe["ecu"]["cook_warnings"] == []

    def test_cook_warnings_cleared_between_build_recipe_calls(self):
        """Warnings from a previous call must not bleed into the next."""
        orig = _build(512)
        mod = _build(512, {100: 0xFF})

        identity_responses_round1 = [
            {"match_key": "ME7::A", "ecu_family": "ME7"},
            {"match_key": "EDC17::B", "ecu_family": "EDC17"},
            {
                "match_key": "ME7::A",
                "ecu_family": "ME7",
                "ecu_variant": None,
                "manufacturer": "Bosch",
                "software_version": None,
                "hardware_number": None,
                "calibration_id": None,
                "file_size": 512,
                "sha256": "x",
            },
        ]
        identity_responses_round2 = [
            {"match_key": None},
            {"match_key": None},
            {
                "match_key": None,
                "ecu_family": None,
                "ecu_variant": None,
                "manufacturer": None,
                "software_version": None,
                "hardware_number": None,
                "calibration_id": None,
                "file_size": 512,
                "sha256": "y",
            },
        ]
        all_responses = identity_responses_round1 + identity_responses_round2

        a = _analyzer(orig, mod)
        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=all_responses,
        ):
            a.build_recipe()
            assert len(a.cook_warnings()) == 1

            a.build_recipe()
            assert a.cook_warnings() == []

    def test_cook_warnings_returns_copy_not_internal_list(self):
        """Mutating the returned list must not affect the internal state."""
        orig = _build(512)
        mod = _build(512, {100: 0xAA})
        a = _analyzer(orig, mod)
        a.build_recipe()
        w1 = a.cook_warnings()
        w1.append("injected")
        w2 = a.cook_warnings()
        assert "injected" not in w2


# ===========================================================================
# 4 — Raw diff captures everything — no filtering
# ===========================================================================


class TestRawDiffScope:
    """
    The diff engine is a raw byte comparison of the ENTIRE binary.
    VIN numbers, checksums, IMMO data, serial numbers — every changed byte
    ends up in the recipe.  These tests document and verify that behaviour.
    """

    def test_vin_bytes_captured_when_changed(self):
        """
        Simulate a VIN region at a known offset.  Changing it in the
        modified binary must produce instructions covering those bytes.
        """
        VIN_OFFSET = 0x200
        orig_vin = b"WBA3A5C50DF123456"  # fake VIN, 17 bytes
        tuned_vin = b"WBA3A5C50DF999999"  # different last digits

        orig = _build(8192, {VIN_OFFSET: orig_vin})
        mod = _build(8192, {VIN_OFFSET: tuned_vin})
        # Also change a map byte to simulate a real tune
        mod = bytearray(mod)
        mod[0x1000] = 0xFF
        mod = bytes(mod)

        recipe = _analyzer(orig, mod).build_recipe()
        changed_offsets = {inst["offset"] for inst in recipe["instructions"]}

        # The VIN region must appear in the recipe — no filtering
        vin_region_covered = any(
            inst["offset"] < VIN_OFFSET + 17
            and inst["offset"] + inst["size"] > VIN_OFFSET
            for inst in recipe["instructions"]
        )
        assert vin_region_covered, (
            "VIN bytes were not captured in the recipe. "
            "Raw diff must include ALL changed bytes."
        )

    def test_checksum_bytes_captured_when_changed(self):
        """
        Simulate a checksum correction at a known offset.
        This is what WinOLS does automatically when you save a tuned binary.
        The resulting recipe will contain checksum instructions that are
        DANGEROUS to apply to a different binary (checksum depends on full content).
        """
        CHECKSUM_OFFSET = 0x10
        orig = _build(8192)
        mod = bytearray(_build(8192))
        mod[0x1000] = 0xAA  # map change
        mod[CHECKSUM_OFFSET] = 0xBB  # checksum "corrected"
        mod = bytes(mod)

        recipe = _analyzer(orig, mod).build_recipe()
        checksum_covered = any(
            inst["offset"] <= CHECKSUM_OFFSET <= inst["offset"] + inst["size"]
            for inst in recipe["instructions"]
        )
        assert checksum_covered, (
            "Checksum bytes were not captured in the recipe. "
            "Raw diff captures everything including checksums."
        )

    def test_serial_number_bytes_captured_when_changed(self):
        """Simulate an ECU serial number region being different."""
        SERIAL_OFFSET = 0x40
        orig = _build(1024, {SERIAL_OFFSET: b"\x01\x02\x03\x04"})
        mod = _build(1024, {SERIAL_OFFSET: b"\xff\xfe\xfd\xfc"})

        recipe = _analyzer(orig, mod).build_recipe()
        serial_covered = any(
            inst["offset"] <= SERIAL_OFFSET
            for inst in recipe["instructions"]
            if inst["offset"] <= SERIAL_OFFSET < inst["offset"] + inst["size"]
        )
        # All 4 serial bytes must be in the recipe
        all_instructions_bytes = set()
        for inst in recipe["instructions"]:
            for i in range(inst["size"]):
                all_instructions_bytes.add(inst["offset"] + i)

        for i in range(4):
            assert SERIAL_OFFSET + i in all_instructions_bytes

    def test_immo_byte_change_captured(self):
        """Immobilizer bytes, if changed, appear in the recipe."""
        IMMO_OFFSET = 0x80
        orig = _build(1024, {IMMO_OFFSET: 0xAA})
        mod = _build(1024, {IMMO_OFFSET: 0xBB})

        recipe = _analyzer(orig, mod).build_recipe()
        offsets_in_recipe = set()
        for inst in recipe["instructions"]:
            for i in range(inst["size"]):
                offsets_in_recipe.add(inst["offset"] + i)

        assert IMMO_OFFSET in offsets_in_recipe

    def test_only_changed_bytes_in_recipe(self):
        """Bytes that are IDENTICAL between original and modified must NOT appear."""
        orig = _build(1024, {100: 0xAA})
        mod = _build(1024, {100: 0xBB})  # only byte 100 differs

        recipe = _analyzer(orig, mod).build_recipe()
        # Only offset 100 should be covered
        for inst in recipe["instructions"]:
            start = inst["offset"]
            end = inst["offset"] + inst["size"]
            assert start <= 100 < end, (
                f"Unexpected instruction at offset {start} — only byte 100 was changed"
            )

    def test_map_change_and_checksum_change_both_captured(self):
        """
        In a real tune, WinOLS modifies the map AND corrects the checksum.
        Both must appear in the recipe — this test documents that behaviour
        and makes clear the user must strip checksum instructions before
        applying the recipe to a different binary.
        """
        MAP_OFFSET = 0x400
        CHECKSUM_OFFSET = 0x008

        orig = _build(4096)
        mod = bytearray(_build(4096))
        mod[MAP_OFFSET] = 0xDE  # map byte changed
        mod[CHECKSUM_OFFSET] = 0xAD  # checksum "corrected" by tool
        mod = bytes(mod)

        recipe = _analyzer(orig, mod).build_recipe()

        all_bytes = set()
        for inst in recipe["instructions"]:
            for i in range(inst["size"]):
                all_bytes.add(inst["offset"] + i)

        assert MAP_OFFSET in all_bytes, "Map change not captured"
        assert CHECKSUM_OFFSET in all_bytes, "Checksum change not captured"
        assert len(recipe["instructions"]) >= 1


# ===========================================================================
# 5 — Diff engine captures every changed byte without exception
# ===========================================================================


class TestDiffDoesNotFilterAnything:
    """
    Explicit verification that the diff engine is purely positional — it
    has no concept of 'skip regions', 'safe zones', or byte categories.
    Every changed byte position, regardless of what it represents, ends up
    in the recipe.
    """

    def test_single_changed_byte_produces_one_instruction(self):
        orig = _build(512, {200: 0xAA})
        mod = _build(512, {200: 0xBB})
        recipe = _analyzer(orig, mod).build_recipe()
        assert len(recipe["instructions"]) == 1
        assert recipe["instructions"][0]["offset"] == 200

    def test_two_far_apart_changes_produce_two_instructions(self):
        orig = _build(512, {10: 0xAA, 500: 0xBB})
        mod = _build(512, {10: 0xCC, 500: 0xDD})
        recipe = _analyzer(orig, mod).build_recipe()
        assert len(recipe["instructions"]) == 2

    def test_zero_changes_produces_empty_instructions(self):
        data = _build(512)
        recipe = _analyzer(data, data).build_recipe()
        assert recipe["instructions"] == []

    def test_all_bytes_changed_captured(self):
        """Every byte position with a difference is accounted for."""
        orig = bytes([0x00] * 256)
        mod = bytes([0xFF] * 256)
        recipe = _analyzer(orig, mod).build_recipe()
        total_bytes_in_recipe = sum(inst["size"] for inst in recipe["instructions"])
        assert total_bytes_in_recipe == 256

    def test_ob_in_instruction_matches_original_bytes(self):
        orig = _build(512, {100: b"\xaa\xbb\xcc"})
        mod = _build(512, {100: b"\x11\x22\x33"})
        recipe = _analyzer(orig, mod).build_recipe()
        inst = next(i for i in recipe["instructions"] if i["offset"] == 100)
        assert inst["ob"] == "AABBCC"
        assert inst["mb"] == "112233"

    def test_instruction_offset_is_absolute(self):
        """Offset is the absolute byte position in the binary, not relative."""
        OFFSET = 0x3A000
        orig = _build(0x40000, {OFFSET: 0xAA})
        mod = _build(0x40000, {OFFSET: 0xBB})
        recipe = _analyzer(orig, mod).build_recipe()
        assert recipe["instructions"][0]["offset"] == OFFSET


# ===========================================================================
# 6 — Guard order: size error raised before identity check runs
# ===========================================================================


class TestBuildRecipeGuardOrder:
    """
    The size check is a hard gate that must run first.
    Even if the identity check would also trigger, the size error is raised
    before identify_ecu() is ever called.
    """

    def test_size_error_raised_before_identity_check(self):
        """identify_ecu must never be called when sizes differ."""
        orig = _build(1024)
        mod = _build(512)  # wrong size
        a = _analyzer(orig, mod)

        call_count = {"n": 0}

        def counting_identify(data, filename):
            call_count["n"] += 1
            return {"match_key": "FAKE::KEY", "ecu_family": "FAKE"}

        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=counting_identify,
        ):
            with pytest.raises(ValueError, match="size mismatch"):
                a.build_recipe()

        assert call_count["n"] == 0, (
            "identify_ecu() was called despite a size mismatch — "
            "size guard must run first and abort immediately."
        )

    def test_identity_check_runs_when_sizes_match(self):
        """When sizes match, identity check must run (identify_ecu called)."""
        orig = _build(512)
        mod = _build(512, {100: 0xFF})
        a = _analyzer(orig, mod)

        call_count = {"n": 0}

        def counting_identify(data, filename):
            call_count["n"] += 1
            return {"match_key": None}

        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=counting_identify,
        ):
            a.build_recipe()

        assert call_count["n"] >= 2, (
            "identify_ecu() was not called for both binaries during identity check."
        )


# ===========================================================================
# 7 — Cook CLI: size mismatch causes exit code 1
# ===========================================================================


class TestCookCLISizeMismatch:
    """
    The cook CLI must exit with code 1 and print an error when the two
    binary files have different sizes.
    """

    def _write_bin(
        self, tmp_path: Path, name: str, size: int, patches: dict | None = None
    ) -> Path:
        p = tmp_path / name
        data = bytearray(size)
        for off, val in (patches or {}).items():
            if isinstance(val, int):
                data[off] = val
            else:
                data[off : off + len(val)] = val
        p.write_bytes(bytes(data))
        return p

    def test_exit_code_1_on_size_mismatch(self, tmp_path):
        orig = self._write_bin(tmp_path, "orig.bin", 1024)
        mod = self._write_bin(tmp_path, "mod.bin", 512)
        result = runner.invoke(cook_app, [str(orig), str(mod)])
        assert result.exit_code == 1

    def test_error_message_mentions_size(self, tmp_path):
        orig = self._write_bin(tmp_path, "orig.bin", 1024)
        mod = self._write_bin(tmp_path, "mod.bin", 512)
        result = runner.invoke(cook_app, [str(orig), str(mod)])
        assert (
            "size" in result.output.lower() or "size" in (result.stderr or "").lower()
        )

    def test_no_recipe_file_written_on_size_mismatch(self, tmp_path):
        orig = self._write_bin(tmp_path, "orig.bin", 1024)
        mod = self._write_bin(tmp_path, "mod.bin", 512)
        output = tmp_path / "out.openremap"
        runner.invoke(cook_app, [str(orig), str(mod), "--output", str(output)])
        assert not output.exists()

    def test_exit_code_0_on_same_size(self, tmp_path):
        orig = self._write_bin(tmp_path, "orig.bin", 1024)
        mod = self._write_bin(tmp_path, "mod.bin", 1024, {100: 0xAA})
        result = runner.invoke(cook_app, [str(orig), str(mod)])
        assert result.exit_code == 0


# ===========================================================================
# 8 — Cook CLI: identity mismatch prints warning but exits 0
# ===========================================================================


class TestCookCLIIdentityWarning:
    """
    When both binaries are identifiable and their match_keys differ, the
    cook CLI must print a warning but still exit 0 (warning, not fatal)
    and produce a recipe.
    """

    def _write_bin(self, tmp_path: Path, name: str, data: bytes) -> Path:
        p = tmp_path / name
        p.write_bytes(data)
        return p

    def test_identity_mismatch_warning_printed(self, tmp_path):
        orig = self._write_bin(tmp_path, "orig.bin", _build(512))
        mod = self._write_bin(tmp_path, "mod.bin", _build(512, {100: 0xFF}))

        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[
                {"match_key": "ME7::11111", "ecu_family": "ME7"},
                {"match_key": "EDC17::22222", "ecu_family": "EDC17"},
                {
                    "match_key": "ME7::11111",
                    "ecu_family": "ME7",
                    "ecu_variant": None,
                    "manufacturer": "Bosch",
                    "software_version": None,
                    "hardware_number": None,
                    "calibration_id": None,
                    "file_size": 512,
                    "sha256": "abc",
                },
            ],
        ):
            result = runner.invoke(cook_app, [str(orig), str(mod)])

        combined = result.output + (result.stderr or "")
        assert "warning" in combined.lower() or "mismatch" in combined.lower()

    def test_identity_mismatch_still_exits_zero(self, tmp_path):
        orig = self._write_bin(tmp_path, "orig.bin", _build(512))
        mod = self._write_bin(tmp_path, "mod.bin", _build(512, {100: 0xFF}))

        with patch(
            "openremap.core.services.recipe_builder.identify_ecu",
            side_effect=[
                {"match_key": "ME7::11111", "ecu_family": "ME7"},
                {"match_key": "EDC17::22222", "ecu_family": "EDC17"},
                {
                    "match_key": "ME7::11111",
                    "ecu_family": "ME7",
                    "ecu_variant": None,
                    "manufacturer": "Bosch",
                    "software_version": None,
                    "hardware_number": None,
                    "calibration_id": None,
                    "file_size": 512,
                    "sha256": "abc",
                },
            ],
        ):
            result = runner.invoke(cook_app, [str(orig), str(mod)])

        assert result.exit_code == 0

    def test_no_warning_when_both_unidentified(self, tmp_path):
        orig = self._write_bin(tmp_path, "orig.bin", _build(512))
        mod = self._write_bin(tmp_path, "mod.bin", _build(512, {100: 0xFF}))
        # No patch — identify_ecu returns no match_key for unknown bins
        result = runner.invoke(cook_app, [str(orig), str(mod)])
        combined = result.output + (result.stderr or "")
        assert "mismatch" not in combined.lower()
        assert result.exit_code == 0
