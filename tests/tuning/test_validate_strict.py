"""
Tests for ECUStrictValidator (validate_strict.py).

Covers:
  - validate_all: exact match, wrong bytes, out-of-bounds, multiple instructions
  - score: passed / failed counts and percentage
  - to_dict: top-level shape, summary flags, failures list
  - check_file_size: mismatch warning, match, no field in recipe
  - check_match_key: no recipe key, no target key (unrecognised binary)
  - Edge cases: empty instructions, single-byte, multi-byte, zero-length ob
"""

from tests.conftest import make_bin, make_bin_with, make_recipe, make_instruction
from openremap.tuning.services.validate_strict import ECUStrictValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_validator(
    target: bytes,
    instructions: list,
    ecu: dict | None = None,
    target_name: str = "target.bin",
    recipe_name: str = "recipe.json",
) -> ECUStrictValidator:
    recipe = make_recipe(instructions, ecu=ecu)
    return ECUStrictValidator(
        target_data=target,
        recipe=recipe,
        target_name=target_name,
        recipe_name=recipe_name,
    )


# ---------------------------------------------------------------------------
# validate_all — all pass
# ---------------------------------------------------------------------------


class TestValidateAllPass:
    def test_single_instruction_exact_match(self):
        target = make_bin_with(512, {100: 0xAA, 101: 0xBB})
        v = make_validator(target, [make_instruction(100, "AABB", "CCDD")])
        v.validate_all()
        assert len(v.results) == 1
        assert v.results[0].passed is True

    def test_single_byte_instruction_passes(self):
        target = make_bin_with(256, {50: 0xFF})
        v = make_validator(target, [make_instruction(50, "FF", "00")])
        v.validate_all()
        assert v.results[0].passed is True

    def test_multiple_instructions_all_pass(self):
        target = make_bin_with(
            1024,
            {100: 0xAA, 101: 0xBB, 500: 0xCC, 501: 0xDD},
        )
        v = make_validator(
            target,
            [
                make_instruction(100, "AABB", "0000"),
                make_instruction(500, "CCDD", "0000"),
            ],
        )
        v.validate_all()
        assert all(r.passed for r in v.results)

    def test_instruction_at_offset_zero_passes(self):
        target = make_bin_with(256, {0: 0xDE, 1: 0xAD})
        v = make_validator(target, [make_instruction(0, "DEAD", "BEEF")])
        v.validate_all()
        assert v.results[0].passed is True

    def test_instruction_at_last_valid_offset_passes(self):
        # ob is 1 byte at offset 255 in a 256-byte binary
        target = make_bin_with(256, {255: 0x42})
        v = make_validator(target, [make_instruction(255, "42", "00")])
        v.validate_all()
        assert v.results[0].passed is True

    def test_all_zero_ob_passes_on_zero_filled_target(self):
        target = make_bin(256)  # all zeros
        v = make_validator(target, [make_instruction(100, "0000", "AABB")])
        v.validate_all()
        assert v.results[0].passed is True

    def test_results_list_cleared_before_each_validate_all(self):
        target = make_bin_with(256, {10: 0xAA})
        v = make_validator(target, [make_instruction(10, "AA", "BB")])
        v.validate_all()
        v.validate_all()  # second call must reset results, not append
        assert len(v.results) == 1


# ---------------------------------------------------------------------------
# validate_all — failures
# ---------------------------------------------------------------------------


class TestValidateAllFail:
    def test_wrong_byte_at_offset_fails(self):
        target = make_bin(256)  # all zeros
        v = make_validator(target, [make_instruction(100, "FF", "00")])
        v.validate_all()
        assert v.results[0].passed is False

    def test_wrong_bytes_multi_byte_fails(self):
        target = make_bin_with(256, {100: 0xAA, 101: 0x00})  # second byte is 00
        v = make_validator(target, [make_instruction(100, "AABB", "CCDD")])
        v.validate_all()
        assert v.results[0].passed is False

    def test_offset_beyond_file_length_fails(self):
        target = make_bin(10)  # tiny binary
        v = make_validator(target, [make_instruction(100, "AABB", "CCDD")])
        v.validate_all()
        assert v.results[0].passed is False
        assert "exceeds" in v.results[0].reason.lower()

    def test_ob_spans_beyond_end_of_file_fails(self):
        # Offset is valid but ob is long enough to overflow
        target = make_bin(256)
        # ob is 4 bytes but only 1 byte remains from offset 254
        v = make_validator(target, [make_instruction(254, "AABBCCDD", "00000000")])
        v.validate_all()
        assert v.results[0].passed is False

    def test_found_bytes_recorded_on_failure(self):
        target = make_bin_with(256, {50: 0xDE, 51: 0xAD})
        v = make_validator(target, [make_instruction(50, "FFFF", "0000")])
        v.validate_all()
        r = v.results[0]
        assert r.passed is False
        assert r.found_bytes == "DEAD"

    def test_expected_bytes_recorded_correctly(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(10, "AABBCC", "000000")])
        v.validate_all()
        assert v.results[0].expected_bytes == "AABBCC"

    def test_all_instructions_scanned_even_on_early_failure(self):
        # validate_all must never short-circuit on the first failure
        target = make_bin_with(1024, {500: 0xCC, 501: 0xDD})
        v = make_validator(
            target,
            [
                make_instruction(100, "FF", "00"),  # FAIL — 0x00 at 100
                make_instruction(500, "CCDD", "00"),  # PASS
                make_instruction(200, "EE", "00"),  # FAIL — 0x00 at 200
            ],
        )
        v.validate_all()
        assert len(v.results) == 3
        statuses = [r.passed for r in v.results]
        assert statuses == [False, True, False]


# ---------------------------------------------------------------------------
# validate_all — mixed results
# ---------------------------------------------------------------------------


class TestValidateAllMixed:
    def test_partial_pass_counts_correctly(self):
        target = make_bin_with(512, {100: 0xAA})
        # instruction 1 passes, instruction 2 fails
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "BB"),
                make_instruction(200, "FF", "00"),
            ],
        )
        v.validate_all()
        passed, failed, _ = v.score()
        assert passed == 1
        assert failed == 1

    def test_result_index_is_one_based(self):
        target = make_bin_with(256, {10: 0xAA, 20: 0xBB})
        v = make_validator(
            target,
            [
                make_instruction(10, "AA", "00"),
                make_instruction(20, "BB", "00"),
            ],
        )
        v.validate_all()
        assert v.results[0].instruction_index == 1
        assert v.results[1].instruction_index == 2

    def test_offset_and_offset_hex_on_result(self):
        target = make_bin_with(256, {0x1A: 0xCC})
        v = make_validator(target, [make_instruction(0x1A, "CC", "00")])
        v.validate_all()
        r = v.results[0]
        assert r.offset == 0x1A
        assert r.offset_hex == "1A"

    def test_size_derived_from_ob_length(self):
        target = make_bin_with(256, {10: 0xAA, 11: 0xBB, 12: 0xCC})
        v = make_validator(target, [make_instruction(10, "AABBCC", "000000")])
        v.validate_all()
        assert v.results[0].size == 3


# ---------------------------------------------------------------------------
# validate_all — empty instructions
# ---------------------------------------------------------------------------


class TestValidateAllEmpty:
    def test_empty_instructions_produces_empty_results(self):
        target = make_bin(256)
        v = make_validator(target, [])
        v.validate_all()
        assert v.results == []

    def test_score_on_empty_results_returns_zeros(self):
        target = make_bin(256)
        v = make_validator(target, [])
        v.validate_all()
        passed, failed, pct = v.score()
        assert passed == 0
        assert failed == 0
        assert pct == 0.0


# ---------------------------------------------------------------------------
# score()
# ---------------------------------------------------------------------------


class TestScore:
    def test_all_pass_score(self):
        target = make_bin_with(256, {10: 0xAA})
        v = make_validator(target, [make_instruction(10, "AA", "BB")])
        v.validate_all()
        passed, failed, pct = v.score()
        assert passed == 1
        assert failed == 0
        assert pct == 100.0

    def test_all_fail_score(self):
        target = make_bin(256)
        v = make_validator(
            target,
            [
                make_instruction(10, "FF", "00"),
                make_instruction(20, "EE", "00"),
            ],
        )
        v.validate_all()
        passed, failed, pct = v.score()
        assert passed == 0
        assert failed == 2
        assert pct == 0.0

    def test_half_pass_score_percentage(self):
        target = make_bin_with(256, {10: 0xAA})
        v = make_validator(
            target,
            [
                make_instruction(10, "AA", "00"),  # pass
                make_instruction(20, "FF", "00"),  # fail
            ],
        )
        v.validate_all()
        passed, failed, pct = v.score()
        assert passed == 1
        assert failed == 1
        assert pct == 50.0

    def test_score_before_validate_all_returns_zeros(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(10, "FF", "00")])
        # Do NOT call validate_all
        passed, failed, pct = v.score()
        assert passed == 0
        assert failed == 0
        assert pct == 0.0


# ---------------------------------------------------------------------------
# to_dict()
# ---------------------------------------------------------------------------


class TestToDict:
    def test_top_level_keys_present(self):
        target = make_bin(256)
        v = make_validator(target, [])
        v.validate_all()
        d = v.to_dict()
        for key in (
            "target_file",
            "recipe_file",
            "target_md5",
            "summary",
            "failures",
            "all_results",
        ):
            assert key in d, f"Missing key: {key}"

    def test_target_file_and_recipe_file_in_report(self):
        target = make_bin(256)
        v = make_validator(
            target, [], target_name="myecu.bin", recipe_name="myrec.json"
        )
        v.validate_all()
        d = v.to_dict()
        assert d["target_file"] == "myecu.bin"
        assert d["recipe_file"] == "myrec.json"

    def test_summary_safe_to_patch_true_when_all_pass(self):
        target = make_bin_with(256, {10: 0xAA})
        v = make_validator(target, [make_instruction(10, "AA", "BB")])
        v.validate_all()
        assert v.to_dict()["summary"]["safe_to_patch"] is True

    def test_summary_safe_to_patch_false_when_any_fail(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(10, "FF", "00")])
        v.validate_all()
        assert v.to_dict()["summary"]["safe_to_patch"] is False

    def test_summary_totals_correct(self):
        target = make_bin_with(512, {100: 0xAA})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "BB"),  # pass
                make_instruction(200, "FF", "00"),  # fail
            ],
        )
        v.validate_all()
        summary = v.to_dict()["summary"]
        assert summary["total"] == 2
        assert summary["passed"] == 1
        assert summary["failed"] == 1

    def test_failures_list_only_contains_failed_instructions(self):
        target = make_bin_with(512, {100: 0xAA})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "BB"),  # pass — must NOT appear in failures
                make_instruction(200, "FF", "00"),  # fail — must appear
            ],
        )
        v.validate_all()
        failures = v.to_dict()["failures"]
        assert len(failures) == 1
        assert failures[0]["ob"] == "FF"

    def test_all_results_contains_every_instruction(self):
        target = make_bin_with(512, {100: 0xAA})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "BB"),
                make_instruction(200, "FF", "00"),
            ],
        )
        v.validate_all()
        assert len(v.to_dict()["all_results"]) == 2

    def test_target_md5_is_32_chars(self):
        target = make_bin(256)
        v = make_validator(target, [])
        v.validate_all()
        assert len(v.to_dict()["target_md5"]) == 32

    def test_failure_entry_has_required_fields(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(10, "FF", "00")])
        v.validate_all()
        failure = v.to_dict()["failures"][0]
        for key in (
            "instruction_index",
            "offset",
            "offset_hex",
            "size",
            "ob",
            "found_bytes",
            "reason",
        ):
            assert key in failure, f"Missing failure key: {key}"


# ---------------------------------------------------------------------------
# check_file_size()
# ---------------------------------------------------------------------------


class TestCheckFileSize:
    def test_size_match_returns_none(self):
        target = make_bin(1024)
        v = make_validator(target, [], ecu={"file_size": 1024})
        assert v.check_file_size() is None

    def test_size_mismatch_returns_warning_string(self):
        target = make_bin(512)
        v = make_validator(target, [], ecu={"file_size": 1024})
        msg = v.check_file_size()
        assert msg is not None
        assert "512" in msg or "1,024" in msg or "mismatch" in msg.lower()

    def test_no_file_size_in_recipe_returns_none(self):
        target = make_bin(256)
        v = make_validator(target, [], ecu={})
        assert v.check_file_size() is None

    def test_no_ecu_block_in_recipe_returns_none(self):
        target = make_bin(256)
        recipe = {"metadata": {}, "instructions": []}
        v = ECUStrictValidator(target, recipe)
        assert v.check_file_size() is None

    def test_size_larger_than_expected_returns_warning(self):
        target = make_bin(2048)
        v = make_validator(target, [], ecu={"file_size": 1024})
        msg = v.check_file_size()
        assert msg is not None


# ---------------------------------------------------------------------------
# check_match_key()
# ---------------------------------------------------------------------------


class TestCheckMatchKey:
    def test_no_recipe_match_key_returns_none(self):
        # If the recipe has no match_key, the check is skipped
        target = make_bin(256)
        v = make_validator(target, [], ecu={"file_size": 256})
        assert v.check_match_key() is None

    def test_unrecognised_target_binary_returns_none(self):
        # A random binary won't be identified → target_key is None → skip
        target = make_bin(256)
        v = make_validator(
            target,
            [],
            ecu={"match_key": "EDC17::SOMEVERSION"},
        )
        # The target is all zeros — no extractor will claim it
        result = v.check_match_key()
        assert result is None

    def test_empty_recipe_ecu_block_returns_none(self):
        target = make_bin(512)
        v = make_validator(target, [], ecu={})
        assert v.check_match_key() is None


# ---------------------------------------------------------------------------
# check_match_key() — mismatch / exception branches
# ---------------------------------------------------------------------------


class TestCheckMatchKeyMismatch:
    def test_identify_ecu_raises_exception_returns_none(self):
        from unittest.mock import patch

        target = make_bin(256)
        v = make_validator(target, [], ecu={"match_key": "EDC17::SOMEVERSION"})
        with patch("openremap.tuning.services.validate_strict.identify_ecu") as mock_id:
            mock_id.side_effect = RuntimeError("identification failed")
            result = v.check_match_key()
        assert result is None

    def test_matching_key_returns_none(self):
        from unittest.mock import patch

        target = make_bin(256)
        recipe_key = "EDC17::SOMEVERSION"
        v = make_validator(target, [], ecu={"match_key": recipe_key})
        with patch("openremap.tuning.services.validate_strict.identify_ecu") as mock_id:
            mock_id.return_value = {"match_key": recipe_key}
            result = v.check_match_key()
        assert result is None

    def test_mismatched_key_returns_mismatch_string(self):
        from unittest.mock import patch

        target = make_bin(256)
        v = make_validator(target, [], ecu={"match_key": "EDC17::SOMEVERSION"})
        with patch("openremap.tuning.services.validate_strict.identify_ecu") as mock_id:
            mock_id.return_value = {"match_key": "EDC17::DIFFERENTVERSION"}
            result = v.check_match_key()
        assert result is not None
        assert "mismatch" in result.lower()
