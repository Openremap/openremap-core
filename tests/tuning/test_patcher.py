"""
Tests for ECUPatcher (patcher.py).

Covers:
  - apply_all: single instruction exact, multi instruction, no-ctx fallback,
               ctx+ob anchor search, shifted instruction within window
  - apply_all: strict pre-flight raises ValueError on ob mismatch
  - apply_all: raises ValueError when any instruction fails (ctx+ob not found)
  - apply_all: partial writes are never returned (all-or-nothing guarantee)
  - skip_validation=True bypasses strict pre-flight
  - Frozen snapshot: earlier writes do not corrupt context of later instructions
  - preflight_warnings: file size mismatch, SW version absent
  - score: total / success / failed counts
  - to_dict: top-level shape, summary fields, per-result fields
  - PatchResult fields: status, offset_expected, offset_found, shift, message
  - Edge cases: empty instructions, instructions with empty ctx
"""

import pytest

from tests.conftest import make_bin, make_bin_with, make_recipe, make_instruction
from openremap.tuning.services.patcher import ECUPatcher, PatchStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_patcher(
    target: bytes,
    instructions: list,
    ecu: dict | None = None,
    target_name: str = "target.bin",
    recipe_name: str = "recipe.json",
    skip_validation: bool = True,
) -> ECUPatcher:
    """
    Build an ECUPatcher with skip_validation=True by default so that most
    tests focus on the apply logic rather than pre-flight validation.
    Switch to skip_validation=False only in tests that specifically exercise
    the pre-flight validator.
    """
    recipe = make_recipe(instructions, ecu=ecu)
    return ECUPatcher(
        target_data=target,
        recipe=recipe,
        target_name=target_name,
        recipe_name=recipe_name,
        skip_validation=skip_validation,
    )


def ctx_before(data: bytes, offset: int, size: int = 8) -> str:
    """Return `size` bytes immediately before `offset` as uppercase hex."""
    start = max(0, offset - size)
    return data[start:offset].hex().upper()


# ---------------------------------------------------------------------------
# apply_all — single instruction, no ctx (direct fallback)
# ---------------------------------------------------------------------------


class TestApplyAllNoCtx:
    def test_single_byte_patch_no_ctx(self):
        orig = make_bin_with(512, {200: 0xAA})
        inst = make_instruction(200, "AA", "BB", ctx="")
        patcher = make_patcher(bytes(orig), [inst])
        result = patcher.apply_all()
        assert result[200] == 0xBB

    def test_multi_byte_patch_no_ctx(self):
        orig = make_bin_with(512, {100: 0xDE, 101: 0xAD, 102: 0xBE, 103: 0xEF})
        inst = make_instruction(100, "DEADBEEF", "CAFEBABE", ctx="")
        patcher = make_patcher(bytes(orig), [inst])
        result = patcher.apply_all()
        assert result[100:104] == bytes.fromhex("CAFEBABE")

    def test_patch_at_offset_zero_no_ctx(self):
        orig = make_bin_with(256, {0: 0xAA})
        inst = make_instruction(0, "AA", "FF", ctx="")
        patcher = make_patcher(bytes(orig), [inst])
        result = patcher.apply_all()
        assert result[0] == 0xFF

    def test_patch_at_last_byte_no_ctx(self):
        orig = make_bin_with(256, {255: 0x42})
        inst = make_instruction(255, "42", "99", ctx="")
        patcher = make_patcher(bytes(orig), [inst])
        result = patcher.apply_all()
        assert result[255] == 0x99

    def test_surrounding_bytes_unchanged_after_single_byte_patch(self):
        orig = make_bin_with(512, {200: 0xAA})
        inst = make_instruction(200, "AA", "BB", ctx="")
        patcher = make_patcher(bytes(orig), [inst])
        result = patcher.apply_all()
        # Everything except offset 200 must be identical to the original
        assert result[:200] == bytes(orig)[:200]
        assert result[201:] == bytes(orig)[201:]

    def test_no_ctx_fails_when_ob_not_at_expected_offset(self):
        # Without ctx the fallback reads the snapshot at the exact offset.
        # If ob doesn't match, _find returns -1 → instruction fails → ValueError.
        orig = make_bin(256)  # all zeros; ob=AA is not at offset 100
        inst = make_instruction(100, "AA", "BB", ctx="")
        patcher = make_patcher(bytes(orig), [inst])
        with pytest.raises(ValueError):
            patcher.apply_all()


# ---------------------------------------------------------------------------
# apply_all — single instruction, with ctx (anchor search)
# ---------------------------------------------------------------------------


class TestApplyAllWithCtx:
    def test_single_instruction_exact_with_ctx(self):
        # Build a binary with a recognisable pattern before the change offset
        orig = bytearray(512)
        # Write a unique context sequence at bytes 192–199
        for i, b in enumerate(b"\x11\x22\x33\x44\x55\x66\x77\x88"):
            orig[192 + i] = b
        orig[200] = 0xAA  # the byte to patch
        orig = bytes(orig)

        ctx = orig[192:200].hex().upper()
        inst = make_instruction(200, "AA", "BB", ctx=ctx)
        patcher = make_patcher(orig, [inst])
        result = patcher.apply_all()
        assert result[200] == 0xBB

    def test_ctx_search_finds_ob_when_exact(self):
        orig = bytearray(512)
        orig[50:54] = b"\xde\xad\xbe\xef"
        orig[54] = 0xCC
        orig = bytes(orig)

        ctx = orig[50:54].hex().upper()  # DEADBEEF
        inst = make_instruction(54, "CC", "DD", ctx=ctx)
        patcher = make_patcher(orig, [inst])
        result = patcher.apply_all()
        assert result[54] == 0xDD

    def test_ctx_anchor_fails_when_pattern_absent(self):
        # ctx+ob pattern does not exist anywhere near the expected offset
        orig = make_bin(512)
        inst = make_instruction(200, "AA", "BB", ctx="DEADBEEF")
        patcher = make_patcher(bytes(orig), [inst])
        with pytest.raises(ValueError, match="(?i)failed"):
            patcher.apply_all()

    def test_only_target_offset_written_not_ctx_bytes(self):
        orig = bytearray(512)
        orig[90:94] = b"\x11\x22\x33\x44"
        orig[94] = 0xAA
        orig = bytes(orig)

        ctx = orig[90:94].hex().upper()
        inst = make_instruction(94, "AA", "BB", ctx=ctx)
        patcher = make_patcher(orig, [inst])
        result = patcher.apply_all()

        # ctx bytes at 90–93 must be untouched
        assert result[90:94] == b"\x11\x22\x33\x44"
        # ob at 94 must be rewritten to mb
        assert result[94] == 0xBB


# ---------------------------------------------------------------------------
# apply_all — multiple instructions
# ---------------------------------------------------------------------------


class TestApplyAllMultiple:
    def test_two_instructions_both_applied(self):
        orig = make_bin_with(1024, {100: 0xAA, 600: 0xBB})
        ctx1 = ctx_before(orig, 100)
        ctx2 = ctx_before(orig, 600)
        patcher = make_patcher(
            orig,
            [
                make_instruction(100, "AA", "CC", ctx=ctx1),
                make_instruction(600, "BB", "DD", ctx=ctx2),
            ],
        )
        result = patcher.apply_all()
        assert result[100] == 0xCC
        assert result[600] == 0xDD

    def test_five_instructions_all_applied(self):
        offsets = [50, 200, 400, 700, 900]
        orig = bytearray(1024)
        for off in offsets:
            orig[off] = 0xAA
        orig = bytes(orig)

        instructions = [
            make_instruction(off, "AA", "BB", ctx=ctx_before(orig, off))
            for off in offsets
        ]
        patcher = make_patcher(orig, instructions)
        result = patcher.apply_all()
        for off in offsets:
            assert result[off] == 0xBB, f"Offset {off} not patched"

    def test_instructions_applied_against_original_snapshot(self):
        """
        Earlier writes must NOT affect context of later instructions.
        The patcher keeps an immutable snapshot for all searches.
        """
        orig = bytearray(512)
        # Context for instruction 2 overlaps the write target of instruction 1
        orig[100] = 0xAA  # instruction 1 changes this to 0xFF
        orig[101] = 0xBB  # instruction 2 uses 0xAA at 100 as its ctx
        orig = bytes(orig)

        ctx_inst1 = ctx_before(orig, 100)
        # ctx for inst2 includes byte 100 (which inst1 will overwrite)
        ctx_inst2 = orig[100:101].hex().upper()  # "AA"

        instructions = [
            make_instruction(100, "AA", "FF", ctx=ctx_inst1),
            make_instruction(101, "BB", "CC", ctx=ctx_inst2),
        ]
        patcher = make_patcher(orig, instructions)
        result = patcher.apply_all()

        # Both instructions must succeed because searches use the frozen snapshot
        assert result[100] == 0xFF
        assert result[101] == 0xCC

    def test_empty_instructions_returns_original_bytes(self):
        orig = make_bin_with(256, {100: 0xAA})
        patcher = make_patcher(orig, [])
        result = patcher.apply_all()
        assert result == orig

    def test_return_value_is_bytes_not_bytearray(self):
        orig = make_bin(256)
        patcher = make_patcher(orig, [])
        result = patcher.apply_all()
        assert isinstance(result, bytes)

    def test_result_same_length_as_original(self):
        orig = make_bin(1024)
        patcher = make_patcher(orig, [])
        result = patcher.apply_all()
        assert len(result) == len(orig)


# ---------------------------------------------------------------------------
# apply_all — failure handling (ctx+ob not found)
# ---------------------------------------------------------------------------


class TestApplyAllFailures:
    def test_single_failed_instruction_raises_value_error(self):
        orig = make_bin(512)
        # ctx+ob pattern does not exist
        inst = make_instruction(200, "FF", "00", ctx="DEADBEEF")
        patcher = make_patcher(orig, [inst])
        with pytest.raises(ValueError):
            patcher.apply_all()

    def test_error_message_mentions_failed_instruction(self):
        orig = make_bin(512)
        inst = make_instruction(200, "FF", "00", ctx="DEADBEEF")
        patcher = make_patcher(orig, [inst])
        with pytest.raises(ValueError) as exc_info:
            patcher.apply_all()
        assert "failed" in str(exc_info.value).lower()

    def test_one_failure_among_many_raises(self):
        orig = make_bin_with(1024, {100: 0xAA})
        ctx = ctx_before(orig, 100)
        instructions = [
            make_instruction(100, "AA", "BB", ctx=ctx),  # will succeed
            make_instruction(500, "FF", "00", ctx="DEADBEEF"),  # will fail
        ]
        patcher = make_patcher(orig, instructions)
        with pytest.raises(ValueError):
            patcher.apply_all()

    def test_partial_result_not_returned_on_failure(self):
        # Even if instruction 1 succeeds, the output must not be returned
        # when instruction 2 fails.
        orig = make_bin_with(512, {50: 0xAA})
        ctx = ctx_before(orig, 50)
        instructions = [
            make_instruction(50, "AA", "BB", ctx=ctx),  # succeeds
            make_instruction(200, "FF", "00", ctx="CAFEBABE"),  # fails
        ]
        patcher = make_patcher(orig, instructions)
        with pytest.raises(ValueError):
            patcher.apply_all()

    def test_results_recorded_before_raising(self):
        orig = make_bin_with(512, {50: 0xAA})
        ctx = ctx_before(orig, 50)
        instructions = [
            make_instruction(50, "AA", "BB", ctx=ctx),
            make_instruction(200, "FF", "00", ctx="CAFEBABE"),
        ]
        patcher = make_patcher(orig, instructions)
        try:
            patcher.apply_all()
        except ValueError:
            pass
        assert len(patcher.results) == 2
        assert patcher.results[0].status == PatchStatus.SUCCESS
        assert patcher.results[1].status == PatchStatus.FAILED


# ---------------------------------------------------------------------------
# apply_all — strict pre-flight validation
# ---------------------------------------------------------------------------


class TestStrictPreFlight:
    def test_pre_flight_raises_when_ob_not_at_offset(self):
        # Binary is all zeros; recipe expects 0xFF at offset 100
        orig = make_bin(512)
        inst = make_instruction(100, "FF", "00")
        patcher = make_patcher(orig, [inst], skip_validation=False)
        with pytest.raises(ValueError, match="(?i)strict pre-flight|validation failed"):
            patcher.apply_all()

    def test_pre_flight_passes_when_ob_matches(self):
        orig = make_bin_with(512, {100: 0xAA})
        ctx = ctx_before(orig, 100)
        inst = make_instruction(100, "AA", "BB", ctx=ctx)
        patcher = make_patcher(orig, [inst], skip_validation=False)
        result = patcher.apply_all()
        assert result[100] == 0xBB

    def test_skip_validation_true_bypasses_strict_check(self):
        # ob does NOT match (binary has 0x00, recipe says 0xFF)
        # but skip_validation=True means no pre-flight → goes to apply stage
        orig = make_bin(512)
        inst = make_instruction(100, "FF", "00", ctx="")
        # With skip_validation=True the patcher tries to apply directly.
        # The no-ctx fallback reads the snapshot at offset 100: finds 0x00,
        # not 0xFF, so offset=-1 → apply fails → raises, but NOT from
        # strict pre-flight — it fails at the apply stage.
        patcher = make_patcher(orig, [inst], skip_validation=True)
        with pytest.raises(ValueError):
            patcher.apply_all()

    def test_multiple_ob_mismatches_all_reported(self):
        orig = make_bin(512)
        instructions = [
            make_instruction(100, "FF", "00"),
            make_instruction(200, "EE", "00"),
        ]
        patcher = make_patcher(orig, instructions, skip_validation=False)
        with pytest.raises(ValueError) as exc_info:
            patcher.apply_all()
        msg = str(exc_info.value)
        # Both failing offsets should be mentioned
        assert "2" in msg  # "2/2 instruction(s)"


# ---------------------------------------------------------------------------
# Shifted instruction (ctx+ob found within ±EXACT_WINDOW at a different offset)
# ---------------------------------------------------------------------------


class TestShiftedInstruction:
    def test_shifted_instruction_applied_at_found_offset(self):
        """
        The recipe records offset 300 but the actual ctx+ob pattern is at 310.
        The patcher must find and apply it at 310, within ±2048 bytes.
        """
        orig = bytearray(1024)
        # Write ctx at 306..309, then ob at 310
        orig[306:310] = b"\xca\xfe\xba\xbe"
        orig[310] = 0xAA
        orig = bytes(orig)

        ctx = "CAFEBABE"  # 4 bytes immediately before the actual ob
        # Recipe says offset=300, but real pattern is at 310 (shift=+10)
        inst = make_instruction(300, "AA", "BB", ctx=ctx)
        patcher = make_patcher(orig, [inst])
        result = patcher.apply_all()

        # The write must happen at the actual found offset (310)
        assert result[310] == 0xBB
        # Original ob byte at its recipe offset (300) must be untouched
        assert result[300] == 0x00

    def test_shifted_result_has_nonzero_shift(self):
        orig = bytearray(1024)
        orig[306:310] = b"\xca\xfe\xba\xbe"
        orig[310] = 0xAA
        orig = bytes(orig)

        inst = make_instruction(300, "AA", "BB", ctx="CAFEBABE")
        patcher = make_patcher(orig, [inst])
        patcher.apply_all()

        assert patcher.results[0].shift != 0

    def test_shift_value_is_correct(self):
        orig = bytearray(1024)
        orig[306:310] = b"\xca\xfe\xba\xbe"
        orig[310] = 0xAA
        orig = bytes(orig)

        inst = make_instruction(300, "AA", "BB", ctx="CAFEBABE")
        patcher = make_patcher(orig, [inst])
        patcher.apply_all()

        # offset_found=310, offset_expected=300 → shift=+10
        assert patcher.results[0].shift == 10

    def test_exact_instruction_has_zero_shift(self):
        orig = bytearray(512)
        orig[100:104] = b"\x11\x22\x33\x44"
        orig[104] = 0xAA
        orig = bytes(orig)

        ctx = orig[100:104].hex().upper()
        inst = make_instruction(104, "AA", "BB", ctx=ctx)
        patcher = make_patcher(orig, [inst])
        patcher.apply_all()

        assert patcher.results[0].shift == 0

    def test_pattern_outside_exact_window_not_found(self):
        """
        The ctx+ob pattern is more than ±2048 bytes from the expected offset.
        The patcher must NOT find it and must raise ValueError.
        """
        from openremap.tuning.services.patcher import EXACT_WINDOW

        orig = bytearray(EXACT_WINDOW * 3)
        # Place the real pattern at expected_offset + EXACT_WINDOW + 100
        expected_offset = 100
        real_offset = expected_offset + EXACT_WINDOW + 100
        orig[real_offset - 4 : real_offset] = b"\xde\xad\xbe\xef"
        orig[real_offset] = 0xAA
        orig = bytes(orig)

        inst = make_instruction(expected_offset, "AA", "BB", ctx="DEADBEEF")
        patcher = make_patcher(orig, [inst])
        with pytest.raises(ValueError):
            patcher.apply_all()


# ---------------------------------------------------------------------------
# preflight_warnings()
# ---------------------------------------------------------------------------


class TestPreflightWarnings:
    def test_no_warnings_when_size_matches(self):
        orig = make_bin(1024)
        patcher = make_patcher(orig, [], ecu={"file_size": 1024})
        warnings = patcher.preflight_warnings()
        size_warnings = [w for w in warnings if "size" in w.lower()]
        assert size_warnings == []

    def test_size_mismatch_warning_returned(self):
        orig = make_bin(512)
        patcher = make_patcher(orig, [], ecu={"file_size": 1024})
        warnings = patcher.preflight_warnings()
        assert any("size" in w.lower() for w in warnings)

    def test_sw_version_absent_warning_returned(self):
        orig = make_bin(512)
        patcher = make_patcher(
            orig,
            [],
            ecu={"software_version": "MYSOFTWAREVERSION12345"},
        )
        warnings = patcher.preflight_warnings()
        assert any("sw" in w.lower() or "version" in w.lower() for w in warnings)

    def test_sw_version_present_no_warning(self):
        sw = "TESTVERSION"
        orig = make_bin(512) + sw.encode("latin-1")
        patcher = make_patcher(orig, [], ecu={"software_version": sw})
        warnings = patcher.preflight_warnings()
        sw_warnings = [
            w for w in warnings if "sw version" in w.lower() or "version" in w.lower()
        ]
        assert sw_warnings == []

    def test_no_ecu_block_no_warnings(self):
        orig = make_bin(512)
        patcher = make_patcher(orig, [], ecu={})
        warnings = patcher.preflight_warnings()
        assert warnings == []

    def test_returns_list(self):
        orig = make_bin(256)
        patcher = make_patcher(orig, [])
        assert isinstance(patcher.preflight_warnings(), list)

    def test_multiple_issues_all_reported(self):
        orig = make_bin(512)
        patcher = make_patcher(
            orig,
            [],
            ecu={
                "file_size": 1024,
                "software_version": "ABSENTVERSION999",
            },
        )
        warnings = patcher.preflight_warnings()
        assert len(warnings) >= 2


# ---------------------------------------------------------------------------
# score()
# ---------------------------------------------------------------------------


class TestScore:
    def test_score_after_successful_apply(self):
        orig = make_bin_with(512, {100: 0xAA})
        ctx = ctx_before(orig, 100)
        patcher = make_patcher(orig, [make_instruction(100, "AA", "BB", ctx=ctx)])
        patcher.apply_all()
        total, success, failed = patcher.score()
        assert total == 1
        assert success == 1
        assert failed == 0

    def test_score_with_two_successes(self):
        orig = make_bin_with(1024, {100: 0xAA, 600: 0xBB})
        ctx1 = ctx_before(orig, 100)
        ctx2 = ctx_before(orig, 600)
        patcher = make_patcher(
            orig,
            [
                make_instruction(100, "AA", "CC", ctx=ctx1),
                make_instruction(600, "BB", "DD", ctx=ctx2),
            ],
        )
        patcher.apply_all()
        total, success, failed = patcher.score()
        assert total == 2
        assert success == 2
        assert failed == 0

    def test_score_before_apply_returns_zeros(self):
        orig = make_bin(256)
        patcher = make_patcher(orig, [make_instruction(10, "AA", "BB")])
        total, success, failed = patcher.score()
        assert total == 0
        assert success == 0
        assert failed == 0

    def test_score_empty_instructions(self):
        orig = make_bin(256)
        patcher = make_patcher(orig, [])
        patcher.apply_all()
        total, success, failed = patcher.score()
        assert total == 0
        assert success == 0
        assert failed == 0

    def test_score_after_partial_failure(self):
        orig = make_bin_with(512, {50: 0xAA})
        ctx = ctx_before(orig, 50)
        instructions = [
            make_instruction(50, "AA", "BB", ctx=ctx),
            make_instruction(200, "FF", "00", ctx="CAFEBABE"),
        ]
        patcher = make_patcher(orig, instructions)
        try:
            patcher.apply_all()
        except ValueError:
            pass
        total, success, failed = patcher.score()
        assert total == 2
        assert success == 1
        assert failed == 1


# ---------------------------------------------------------------------------
# PatchResult fields
# ---------------------------------------------------------------------------


class TestPatchResultFields:
    def _run_single(self, orig, inst):
        patcher = make_patcher(orig, [inst])
        try:
            patcher.apply_all()
        except ValueError:
            pass
        return patcher.results[0]

    def test_success_result_status(self):
        orig = make_bin_with(256, {50: 0xAA})
        ctx = ctx_before(orig, 50)
        inst = make_instruction(50, "AA", "BB", ctx=ctx)
        r = self._run_single(orig, inst)
        assert r.status == PatchStatus.SUCCESS

    def test_failed_result_status(self):
        orig = make_bin(256)
        inst = make_instruction(100, "FF", "00", ctx="DEADBEEF")
        r = self._run_single(orig, inst)
        assert r.status == PatchStatus.FAILED

    def test_success_offset_expected(self):
        orig = make_bin_with(256, {75: 0xCC})
        ctx = ctx_before(orig, 75)
        inst = make_instruction(75, "CC", "DD", ctx=ctx)
        r = self._run_single(orig, inst)
        assert r.offset_expected == 75

    def test_success_offset_found(self):
        orig = make_bin_with(256, {75: 0xCC})
        ctx = ctx_before(orig, 75)
        inst = make_instruction(75, "CC", "DD", ctx=ctx)
        r = self._run_single(orig, inst)
        assert r.offset_found == 75

    def test_failed_offset_found_is_none(self):
        orig = make_bin(256)
        inst = make_instruction(100, "FF", "00", ctx="DEADBEEF")
        r = self._run_single(orig, inst)
        assert r.offset_found is None

    def test_failed_shift_is_none(self):
        orig = make_bin(256)
        inst = make_instruction(100, "FF", "00", ctx="DEADBEEF")
        r = self._run_single(orig, inst)
        assert r.shift is None

    def test_success_size_matches_ob_length(self):
        orig = make_bin_with(256, {50: 0xAA, 51: 0xBB})
        ctx = ctx_before(orig, 50)
        inst = make_instruction(50, "AABB", "CCDD", ctx=ctx)
        r = self._run_single(orig, inst)
        assert r.size == 2

    def test_success_message_contains_applied(self):
        orig = make_bin_with(256, {50: 0xAA})
        ctx = ctx_before(orig, 50)
        inst = make_instruction(50, "AA", "BB", ctx=ctx)
        r = self._run_single(orig, inst)
        assert "applied" in r.message.lower() or "0x" in r.message

    def test_failed_message_mentions_pattern_not_found(self):
        orig = make_bin(256)
        inst = make_instruction(100, "FF", "00", ctx="DEADBEEF")
        r = self._run_single(orig, inst)
        assert "not found" in r.message.lower() or "pattern" in r.message.lower()

    def test_result_index_is_one_based(self):
        orig = make_bin_with(512, {100: 0xAA, 200: 0xBB})
        ctx1 = ctx_before(orig, 100)
        ctx2 = ctx_before(orig, 200)
        patcher = make_patcher(
            orig,
            [
                make_instruction(100, "AA", "CC", ctx=ctx1),
                make_instruction(200, "BB", "DD", ctx=ctx2),
            ],
        )
        patcher.apply_all()
        assert patcher.results[0].index == 1
        assert patcher.results[1].index == 2


# ---------------------------------------------------------------------------
# to_dict()
# ---------------------------------------------------------------------------


class TestToDict:
    def test_top_level_keys_present(self):
        orig = make_bin(256)
        patcher = make_patcher(orig, [])
        patcher.apply_all()
        d = patcher.to_dict()
        for key in ("target_file", "recipe_file", "target_md5", "summary", "results"):
            assert key in d, f"Missing key: {key}"

    def test_target_file_and_recipe_file_correct(self):
        orig = make_bin(256)
        patcher = make_patcher(
            orig, [], target_name="myecu.bin", recipe_name="myrec.json"
        )
        patcher.apply_all()
        d = patcher.to_dict()
        assert d["target_file"] == "myecu.bin"
        assert d["recipe_file"] == "myrec.json"

    def test_target_md5_is_32_hex_chars(self):
        orig = make_bin(256)
        patcher = make_patcher(orig, [])
        patcher.apply_all()
        assert len(patcher.to_dict()["target_md5"]) == 32

    def test_summary_keys_present(self):
        orig = make_bin(256)
        patcher = make_patcher(orig, [])
        patcher.apply_all()
        summary = patcher.to_dict()["summary"]
        for key in (
            "total",
            "success",
            "failed",
            "shifted",
            "score_pct",
            "patch_applied",
        ):
            assert key in summary, f"Missing summary key: {key}"

    def test_summary_patch_applied_true_when_all_succeed(self):
        orig = make_bin_with(256, {10: 0xAA})
        ctx = ctx_before(orig, 10)
        patcher = make_patcher(orig, [make_instruction(10, "AA", "BB", ctx=ctx)])
        patcher.apply_all()
        assert patcher.to_dict()["summary"]["patch_applied"] is True

    def test_summary_patch_applied_false_after_failure(self):
        orig = make_bin_with(256, {50: 0xAA})
        ctx = ctx_before(orig, 50)
        instructions = [
            make_instruction(50, "AA", "BB", ctx=ctx),
            make_instruction(200, "FF", "00", ctx="CAFEBABE"),
        ]
        patcher = make_patcher(orig, instructions)
        try:
            patcher.apply_all()
        except ValueError:
            pass
        assert patcher.to_dict()["summary"]["patch_applied"] is False

    def test_summary_score_pct_100_when_all_succeed(self):
        orig = make_bin_with(256, {10: 0xAA})
        ctx = ctx_before(orig, 10)
        patcher = make_patcher(orig, [make_instruction(10, "AA", "BB", ctx=ctx)])
        patcher.apply_all()
        assert patcher.to_dict()["summary"]["score_pct"] == 100.0

    def test_summary_score_pct_zero_when_empty(self):
        patcher = make_patcher(make_bin(256), [])
        patcher.apply_all()
        assert patcher.to_dict()["summary"]["score_pct"] == 0.0

    def test_results_list_length_matches_instruction_count(self):
        orig = make_bin_with(512, {100: 0xAA, 200: 0xBB})
        ctx1 = ctx_before(orig, 100)
        ctx2 = ctx_before(orig, 200)
        patcher = make_patcher(
            orig,
            [
                make_instruction(100, "AA", "CC", ctx=ctx1),
                make_instruction(200, "BB", "DD", ctx=ctx2),
            ],
        )
        patcher.apply_all()
        assert len(patcher.to_dict()["results"]) == 2

    def test_result_entry_has_required_fields(self):
        orig = make_bin_with(256, {10: 0xAA})
        ctx = ctx_before(orig, 10)
        patcher = make_patcher(orig, [make_instruction(10, "AA", "BB", ctx=ctx)])
        patcher.apply_all()
        entry = patcher.to_dict()["results"][0]
        for key in (
            "index",
            "status",
            "offset_expected",
            "offset_found",
            "size",
            "shift",
            "message",
            "offset_expected_hex",
            "offset_found_hex",
        ):
            assert key in entry, f"Missing result entry key: {key}"

    def test_result_status_is_string(self):
        orig = make_bin_with(256, {10: 0xAA})
        ctx = ctx_before(orig, 10)
        patcher = make_patcher(orig, [make_instruction(10, "AA", "BB", ctx=ctx)])
        patcher.apply_all()
        status = patcher.to_dict()["results"][0]["status"]
        assert isinstance(status, str)
        assert status in ("success", "failed")

    def test_patched_md5_included_when_patched_data_provided(self):
        orig = make_bin_with(256, {10: 0xAA})
        ctx = ctx_before(orig, 10)
        patcher = make_patcher(orig, [make_instruction(10, "AA", "BB", ctx=ctx)])
        patched = patcher.apply_all()
        d = patcher.to_dict(patched_data=patched)
        assert "patched_md5" in d["summary"]
        assert len(d["summary"]["patched_md5"]) == 32

    def test_patched_md5_absent_when_not_provided(self):
        orig = make_bin(256)
        patcher = make_patcher(orig, [])
        patcher.apply_all()
        assert "patched_md5" not in patcher.to_dict()["summary"]

    def test_offset_found_hex_formatted_correctly(self):
        orig = make_bin_with(256, {0x2A: 0xAA})
        ctx = ctx_before(orig, 0x2A)
        patcher = make_patcher(orig, [make_instruction(0x2A, "AA", "BB", ctx=ctx)])
        patcher.apply_all()
        entry = patcher.to_dict()["results"][0]
        assert entry["offset_found_hex"] == "0x0000002A"

    def test_shifted_count_in_summary(self):
        orig = bytearray(1024)
        orig[106:110] = b"\xca\xfe\xba\xbe"
        orig[110] = 0xAA
        orig = bytes(orig)
        # Recipe says offset=100, real pattern at 110 (shift=+10)
        inst = make_instruction(100, "AA", "BB", ctx="CAFEBABE")
        patcher = make_patcher(orig, [inst])
        patcher.apply_all()
        assert patcher.to_dict()["summary"]["shifted"] == 1

    def test_empty_instructions_produces_empty_results_list(self):
        patcher = make_patcher(make_bin(256), [])
        patcher.apply_all()
        assert patcher.to_dict()["results"] == []
