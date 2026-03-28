"""
Tests for ECUPatchedValidator (validate_patched.py).

Covers:
  - verify_all: mb confirmed, ob still present (not patched),
                unexpected value, out-of-bounds, multiple instructions
  - score: passed / failed counts and percentage
  - to_dict: top-level shape, summary flags, failures list, all_results
  - check_file_size: mismatch, match, no field in recipe
  - check_match_key: no recipe key, unrecognised binary
  - Edge cases: empty instructions, single-byte mb, results cleared on re-run
"""

from tests.conftest import make_bin, make_bin_with, make_recipe, make_instruction
from openremap.tuning.services.validate_patched import ECUPatchedValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_validator(
    patched: bytes,
    instructions: list,
    ecu: dict | None = None,
    patched_name: str = "patched.bin",
    recipe_name: str = "recipe.json",
) -> ECUPatchedValidator:
    recipe = make_recipe(instructions, ecu=ecu)
    return ECUPatchedValidator(
        patched_data=patched,
        recipe=recipe,
        patched_name=patched_name,
        recipe_name=recipe_name,
    )


# ---------------------------------------------------------------------------
# verify_all — all pass (mb confirmed)
# ---------------------------------------------------------------------------


class TestVerifyAllPass:
    def test_single_instruction_mb_confirmed(self):
        # patched binary already has mb at the offset
        patched = make_bin_with(512, {100: 0xCC, 101: 0xDD})
        v = make_validator(patched, [make_instruction(100, "AABB", "CCDD")])
        v.verify_all()
        assert len(v.results) == 1
        assert v.results[0].passed is True

    def test_single_byte_mb_confirmed(self):
        patched = make_bin_with(256, {50: 0xFF})
        v = make_validator(patched, [make_instruction(50, "AA", "FF")])
        v.verify_all()
        assert v.results[0].passed is True

    def test_multiple_instructions_all_confirmed(self):
        patched = make_bin_with(
            1024,
            {100: 0xCC, 101: 0xDD, 500: 0xEE, 501: 0xFF},
        )
        v = make_validator(
            patched,
            [
                make_instruction(100, "AABB", "CCDD"),
                make_instruction(500, "1122", "EEFF"),
            ],
        )
        v.verify_all()
        assert all(r.passed for r in v.results)

    def test_mb_at_offset_zero_confirmed(self):
        patched = make_bin_with(256, {0: 0x42, 1: 0x43})
        v = make_validator(patched, [make_instruction(0, "0000", "4243")])
        v.verify_all()
        assert v.results[0].passed is True

    def test_mb_at_last_valid_offset_confirmed(self):
        patched = make_bin_with(256, {255: 0x99})
        v = make_validator(patched, [make_instruction(255, "00", "99")])
        v.verify_all()
        assert v.results[0].passed is True

    def test_results_list_cleared_before_each_verify_all(self):
        patched = make_bin_with(256, {10: 0xCC})
        v = make_validator(patched, [make_instruction(10, "AA", "CC")])
        v.verify_all()
        v.verify_all()  # second call must reset, not append
        assert len(v.results) == 1

    def test_mb_confirmed_reason_message(self):
        patched = make_bin_with(256, {30: 0xBB})
        v = make_validator(patched, [make_instruction(30, "AA", "BB")])
        v.verify_all()
        assert "confirmed" in v.results[0].reason.lower()


# ---------------------------------------------------------------------------
# verify_all — ob still present (patch was not applied)
# ---------------------------------------------------------------------------


class TestVerifyAllObStillPresent:
    def test_ob_still_present_fails(self):
        # The patched binary still has the original ob bytes — not patched
        patched = make_bin_with(512, {100: 0xAA, 101: 0xBB})
        v = make_validator(patched, [make_instruction(100, "AABB", "CCDD")])
        v.verify_all()
        assert v.results[0].passed is False

    def test_ob_still_present_reason_is_descriptive(self):
        patched = make_bin_with(256, {50: 0xAA})
        v = make_validator(patched, [make_instruction(50, "AA", "BB")])
        v.verify_all()
        reason = v.results[0].reason.lower()
        assert "ob still present" in reason or "not applied" in reason

    def test_ob_still_present_distinguishes_from_unexpected_value(self):
        # Two instructions: one with ob still there, one with unexpected bytes
        patched = make_bin_with(
            512,
            {
                100: 0xAA,  # ob still present (ob=AA, mb=BB)
                200: 0xEE,  # unexpected (ob=CC, mb=DD, found=EE)
            },
        )
        v = make_validator(
            patched,
            [
                make_instruction(100, "AA", "BB"),
                make_instruction(200, "CC", "DD"),
            ],
        )
        v.verify_all()
        assert v.results[0].passed is False
        assert v.results[1].passed is False
        # Different reason strings for the two failure modes
        assert v.results[0].reason != v.results[1].reason

    def test_ob_still_present_found_bytes_equals_ob(self):
        patched = make_bin_with(256, {10: 0xDE, 11: 0xAD})
        v = make_validator(patched, [make_instruction(10, "DEAD", "BEEF")])
        v.verify_all()
        r = v.results[0]
        assert r.found == "DEAD"
        assert r.expected == "BEEF"


# ---------------------------------------------------------------------------
# verify_all — unexpected value (neither ob nor mb)
# ---------------------------------------------------------------------------


class TestVerifyAllUnexpectedValue:
    def test_unexpected_value_fails(self):
        # Binary has 0xEE at offset — neither ob (AA) nor mb (BB)
        patched = make_bin_with(256, {50: 0xEE})
        v = make_validator(patched, [make_instruction(50, "AA", "BB")])
        v.verify_all()
        assert v.results[0].passed is False

    def test_unexpected_value_reason_mentions_neither(self):
        patched = make_bin_with(256, {50: 0xEE})
        v = make_validator(patched, [make_instruction(50, "AA", "BB")])
        v.verify_all()
        reason = v.results[0].reason.lower()
        assert "neither" in reason or "unexpected" in reason

    def test_unexpected_value_found_bytes_recorded_correctly(self):
        patched = make_bin_with(256, {20: 0xCA, 21: 0xFE})
        v = make_validator(patched, [make_instruction(20, "AAAA", "BBBB")])
        v.verify_all()
        assert v.results[0].found == "CAFE"

    def test_unexpected_value_expected_field_is_mb(self):
        patched = make_bin_with(256, {20: 0xFF})
        v = make_validator(patched, [make_instruction(20, "AA", "BB")])
        v.verify_all()
        assert v.results[0].expected == "BB"


# ---------------------------------------------------------------------------
# verify_all — out-of-bounds
# ---------------------------------------------------------------------------


class TestVerifyAllOutOfBounds:
    def test_offset_beyond_file_length_fails(self):
        patched = make_bin(10)
        v = make_validator(patched, [make_instruction(100, "AABB", "CCDD")])
        v.verify_all()
        assert v.results[0].passed is False

    def test_out_of_bounds_reason_mentions_exceeds(self):
        patched = make_bin(10)
        v = make_validator(patched, [make_instruction(100, "AABB", "CCDD")])
        v.verify_all()
        assert "exceeds" in v.results[0].reason.lower()

    def test_mb_spans_beyond_end_of_file_fails(self):
        # Offset 254 is valid but mb is 4 bytes — only 2 bytes remain
        patched = make_bin(256)
        v = make_validator(patched, [make_instruction(254, "AAAA", "BBBBCCCC")])
        v.verify_all()
        assert v.results[0].passed is False

    def test_out_of_bounds_found_bytes_is_empty_string(self):
        patched = make_bin(10)
        v = make_validator(patched, [make_instruction(100, "AA", "BB")])
        v.verify_all()
        assert v.results[0].found == ""


# ---------------------------------------------------------------------------
# verify_all — all instructions scanned (no short-circuit)
# ---------------------------------------------------------------------------


class TestVerifyAllNoShortCircuit:
    def test_all_instructions_scanned_even_after_first_failure(self):
        patched = make_bin_with(
            1024,
            {
                100: 0xAA,  # ob still present → fail
                500: 0xCC,  # mb confirmed → pass
                200: 0xEE,  # unexpected → fail
            },
        )
        v = make_validator(
            patched,
            [
                make_instruction(100, "AA", "BB"),  # fail: ob still present
                make_instruction(500, "00", "CC"),  # pass: mb confirmed
                make_instruction(200, "00", "DD"),  # fail: unexpected (EE)
            ],
        )
        v.verify_all()
        assert len(v.results) == 3
        assert v.results[0].passed is False
        assert v.results[1].passed is True
        assert v.results[2].passed is False

    def test_instruction_index_is_one_based(self):
        patched = make_bin_with(256, {10: 0xBB, 20: 0xDD})
        v = make_validator(
            patched,
            [
                make_instruction(10, "AA", "BB"),
                make_instruction(20, "CC", "DD"),
            ],
        )
        v.verify_all()
        assert v.results[0].instruction_index == 1
        assert v.results[1].instruction_index == 2


# ---------------------------------------------------------------------------
# verify_all — empty instructions
# ---------------------------------------------------------------------------


class TestVerifyAllEmpty:
    def test_empty_instructions_produces_empty_results(self):
        v = make_validator(make_bin(256), [])
        v.verify_all()
        assert v.results == []

    def test_score_on_empty_results(self):
        v = make_validator(make_bin(256), [])
        v.verify_all()
        passed, failed, pct = v.score()
        assert passed == 0
        assert failed == 0
        assert pct == 0.0


# ---------------------------------------------------------------------------
# score()
# ---------------------------------------------------------------------------


class TestScore:
    def test_all_pass_score(self):
        patched = make_bin_with(256, {10: 0xBB})
        v = make_validator(patched, [make_instruction(10, "AA", "BB")])
        v.verify_all()
        passed, failed, pct = v.score()
        assert passed == 1
        assert failed == 0
        assert pct == 100.0

    def test_all_fail_score(self):
        patched = make_bin(256)  # all zeros — ob still present for all
        v = make_validator(
            patched,
            [
                make_instruction(10, "00", "BB"),  # ob (00) still there → fail
                make_instruction(20, "00", "CC"),  # ob (00) still there → fail
            ],
        )
        v.verify_all()
        passed, failed, pct = v.score()
        assert passed == 0
        assert failed == 2
        assert pct == 0.0

    def test_half_pass_half_fail_percentage(self):
        patched = make_bin_with(512, {100: 0xBB})
        v = make_validator(
            patched,
            [
                make_instruction(100, "AA", "BB"),  # pass
                make_instruction(200, "AA", "CC"),  # fail: ob(AA) not there, 00 found
            ],
        )
        v.verify_all()
        passed, failed, pct = v.score()
        assert passed == 1
        assert failed == 1
        assert pct == 50.0

    def test_score_before_verify_all_returns_zeros(self):
        v = make_validator(make_bin(256), [make_instruction(10, "AA", "BB")])
        passed, failed, pct = v.score()
        assert passed == 0
        assert failed == 0
        assert pct == 0.0

    def test_score_pct_rounds_to_two_decimal_places(self):
        patched = make_bin_with(
            1024,
            {100: 0xBB, 200: 0xCC, 300: 0xDD},
        )
        v = make_validator(
            patched,
            [
                make_instruction(100, "AA", "BB"),  # pass
                make_instruction(200, "AA", "CC"),  # pass
                make_instruction(300, "AA", "DD"),  # pass
            ],
        )
        v.verify_all()
        _, _, pct = v.score()
        assert isinstance(pct, float)
        assert pct == 100.0


# ---------------------------------------------------------------------------
# to_dict()
# ---------------------------------------------------------------------------


class TestToDict:
    def test_top_level_keys_present(self):
        v = make_validator(make_bin(256), [])
        v.verify_all()
        d = v.to_dict()
        for key in (
            "patched_file",
            "recipe_file",
            "patched_md5",
            "summary",
            "failures",
            "all_results",
        ):
            assert key in d, f"Missing key: {key}"

    def test_patched_file_and_recipe_file_correct(self):
        v = make_validator(
            make_bin(256),
            [],
            patched_name="my_patched.bin",
            recipe_name="my_recipe.json",
        )
        v.verify_all()
        d = v.to_dict()
        assert d["patched_file"] == "my_patched.bin"
        assert d["recipe_file"] == "my_recipe.json"

    def test_patched_md5_is_32_hex_chars(self):
        v = make_validator(make_bin(256), [])
        v.verify_all()
        assert len(v.to_dict()["patched_md5"]) == 32

    def test_summary_has_required_keys(self):
        v = make_validator(make_bin(256), [])
        v.verify_all()
        summary = v.to_dict()["summary"]
        for key in ("total", "passed", "failed", "score_pct", "patch_confirmed"):
            assert key in summary, f"Missing summary key: {key}"

    def test_summary_patch_confirmed_true_when_all_pass(self):
        patched = make_bin_with(256, {10: 0xBB})
        v = make_validator(patched, [make_instruction(10, "AA", "BB")])
        v.verify_all()
        assert v.to_dict()["summary"]["patch_confirmed"] is True

    def test_summary_patch_confirmed_false_when_any_fail(self):
        patched = make_bin_with(256, {10: 0xAA})  # ob still present
        v = make_validator(patched, [make_instruction(10, "AA", "BB")])
        v.verify_all()
        assert v.to_dict()["summary"]["patch_confirmed"] is False

    def test_summary_totals_correct(self):
        patched = make_bin_with(512, {100: 0xBB})
        v = make_validator(
            patched,
            [
                make_instruction(100, "AA", "BB"),  # pass
                make_instruction(
                    200, "AA", "CC"
                ),  # fail (0x00 at 200 — neither ob AA nor mb CC)
            ],
        )
        v.verify_all()
        summary = v.to_dict()["summary"]
        assert summary["total"] == 2
        assert summary["passed"] == 1
        assert summary["failed"] == 1

    def test_failures_list_only_contains_failed_instructions(self):
        patched = make_bin_with(512, {100: 0xBB})
        v = make_validator(
            patched,
            [
                make_instruction(100, "AA", "BB"),  # pass — must NOT appear
                make_instruction(200, "AA", "CC"),  # fail — must appear
            ],
        )
        v.verify_all()
        failures = v.to_dict()["failures"]
        assert len(failures) == 1
        assert failures[0]["mb"] == "CC"

    def test_all_results_contains_every_instruction(self):
        patched = make_bin_with(512, {100: 0xBB})
        v = make_validator(
            patched,
            [
                make_instruction(100, "AA", "BB"),
                make_instruction(200, "AA", "CC"),
            ],
        )
        v.verify_all()
        assert len(v.to_dict()["all_results"]) == 2

    def test_failure_entry_has_required_fields(self):
        patched = make_bin_with(256, {10: 0xAA})  # ob still present
        v = make_validator(patched, [make_instruction(10, "AA", "BB")])
        v.verify_all()
        failure = v.to_dict()["failures"][0]
        for key in (
            "instruction_index",
            "offset",
            "offset_hex",
            "size",
            "mb",
            "found",
            "reason",
        ):
            assert key in failure, f"Missing failure key: {key}"

    def test_all_results_entry_has_required_fields(self):
        patched = make_bin_with(256, {10: 0xBB})
        v = make_validator(patched, [make_instruction(10, "AA", "BB")])
        v.verify_all()
        entry = v.to_dict()["all_results"][0]
        for key in (
            "instruction_index",
            "offset",
            "offset_hex",
            "size",
            "passed",
            "mb",
            "found",
            "reason",
        ):
            assert key in entry, f"Missing all_results key: {key}"

    def test_failure_entry_mb_field_is_the_expected_mb(self):
        patched = make_bin_with(256, {10: 0xAA})
        v = make_validator(patched, [make_instruction(10, "AA", "CC")])
        v.verify_all()
        assert v.to_dict()["failures"][0]["mb"] == "CC"

    def test_failure_entry_found_field_matches_actual_bytes(self):
        patched = make_bin_with(256, {10: 0xDE, 11: 0xAD})
        v = make_validator(patched, [make_instruction(10, "FFFF", "AABB")])
        v.verify_all()
        assert v.to_dict()["failures"][0]["found"] == "DEAD"

    def test_all_results_passed_field_is_bool(self):
        patched = make_bin_with(256, {10: 0xBB})
        v = make_validator(patched, [make_instruction(10, "AA", "BB")])
        v.verify_all()
        passed_field = v.to_dict()["all_results"][0]["passed"]
        assert isinstance(passed_field, bool)

    def test_offset_hex_formatted_correctly_in_failure(self):
        patched = make_bin_with(256, {0x1F: 0xAA})  # ob still present
        v = make_validator(patched, [make_instruction(0x1F, "AA", "BB")])
        v.verify_all()
        failure = v.to_dict()["failures"][0]
        assert failure["offset"] == 0x1F
        assert failure["offset_hex"] == "1F"

    def test_score_pct_in_summary_is_float(self):
        v = make_validator(make_bin(256), [])
        v.verify_all()
        assert isinstance(v.to_dict()["summary"]["score_pct"], float)

    def test_empty_instructions_produces_empty_failures_and_all_results(self):
        v = make_validator(make_bin(256), [])
        v.verify_all()
        d = v.to_dict()
        assert d["failures"] == []
        assert d["all_results"] == []


# ---------------------------------------------------------------------------
# check_file_size()
# ---------------------------------------------------------------------------


class TestCheckFileSize:
    def test_size_match_returns_none(self):
        v = make_validator(make_bin(1024), [], ecu={"file_size": 1024})
        assert v.check_file_size() is None

    def test_size_mismatch_returns_warning_string(self):
        v = make_validator(make_bin(512), [], ecu={"file_size": 1024})
        msg = v.check_file_size()
        assert msg is not None
        assert isinstance(msg, str)

    def test_size_mismatch_message_is_informative(self):
        v = make_validator(make_bin(512), [], ecu={"file_size": 1024})
        msg = v.check_file_size()
        assert msg is not None
        assert "512" in msg or "1,024" in msg or "mismatch" in msg.lower()

    def test_no_file_size_field_returns_none(self):
        v = make_validator(make_bin(256), [], ecu={})
        assert v.check_file_size() is None

    def test_no_ecu_block_in_recipe_returns_none(self):
        recipe = {"metadata": {}, "instructions": []}
        v = ECUPatchedValidator(make_bin(256), recipe)
        assert v.check_file_size() is None

    def test_larger_than_expected_returns_warning(self):
        v = make_validator(make_bin(2048), [], ecu={"file_size": 1024})
        assert v.check_file_size() is not None

    def test_smaller_than_expected_returns_warning(self):
        v = make_validator(make_bin(256), [], ecu={"file_size": 1024})
        assert v.check_file_size() is not None


# ---------------------------------------------------------------------------
# check_match_key()
# ---------------------------------------------------------------------------


class TestCheckMatchKey:
    def test_no_recipe_match_key_returns_none(self):
        v = make_validator(make_bin(256), [], ecu={"file_size": 256})
        assert v.check_match_key() is None

    def test_empty_ecu_block_returns_none(self):
        v = make_validator(make_bin(256), [], ecu={})
        assert v.check_match_key() is None

    def test_unrecognised_binary_skips_check(self):
        # All-zero binary is not recognised by any extractor → target_key is None → skip
        v = make_validator(
            make_bin(256),
            [],
            ecu={"match_key": "EDC17::SOMEVERSION"},
        )
        assert v.check_match_key() is None

    def test_no_ecu_block_in_recipe_returns_none(self):
        recipe = {"metadata": {}, "instructions": []}
        v = ECUPatchedValidator(make_bin(256), recipe)
        assert v.check_match_key() is None


# ---------------------------------------------------------------------------
# Verify VerifyResult dataclass fields via results list
# ---------------------------------------------------------------------------


class TestVerifyResultFields:
    def test_result_offset_matches_instruction(self):
        patched = make_bin_with(256, {0x3C: 0xBB})
        v = make_validator(patched, [make_instruction(0x3C, "AA", "BB")])
        v.verify_all()
        assert v.results[0].offset == 0x3C

    def test_result_offset_hex_is_uppercase_hex_string(self):
        patched = make_bin_with(256, {0x3C: 0xBB})
        v = make_validator(patched, [make_instruction(0x3C, "AA", "BB")])
        v.verify_all()
        assert v.results[0].offset_hex == "3C"

    def test_result_size_derived_from_mb_length(self):
        patched = make_bin_with(256, {10: 0xBB, 11: 0xCC, 12: 0xDD})
        v = make_validator(patched, [make_instruction(10, "AAAAAA", "BBCCDD")])
        v.verify_all()
        assert v.results[0].size == 3

    def test_result_expected_field_is_mb(self):
        patched = make_bin_with(256, {10: 0xBB})
        v = make_validator(patched, [make_instruction(10, "AA", "BB")])
        v.verify_all()
        assert v.results[0].expected == "BB"

    def test_result_found_field_matches_patched_bytes(self):
        patched = make_bin_with(256, {10: 0xBB})
        v = make_validator(patched, [make_instruction(10, "AA", "BB")])
        v.verify_all()
        assert v.results[0].found == "BB"


# ---------------------------------------------------------------------------
# check_match_key() — mismatch / exception branches
# ---------------------------------------------------------------------------


class TestCheckMatchKeyMismatch:
    def test_identify_ecu_raises_exception_returns_none(self):
        from unittest.mock import patch

        v = make_validator(make_bin(256), [], ecu={"match_key": "EDC17::SOMEVERSION"})
        with patch(
            "openremap.tuning.services.validate_patched.identify_ecu"
        ) as mock_id:
            mock_id.side_effect = RuntimeError("identification failed")
            result = v.check_match_key()
        assert result is None

    def test_matching_key_returns_none(self):
        from unittest.mock import patch

        recipe_key = "EDC17::SOMEVERSION"
        v = make_validator(make_bin(256), [], ecu={"match_key": recipe_key})
        with patch(
            "openremap.tuning.services.validate_patched.identify_ecu"
        ) as mock_id:
            mock_id.return_value = {"match_key": recipe_key}
            result = v.check_match_key()
        assert result is None

    def test_mismatched_key_returns_mismatch_string(self):
        from unittest.mock import patch

        v = make_validator(make_bin(256), [], ecu={"match_key": "EDC17::SOMEVERSION"})
        with patch(
            "openremap.tuning.services.validate_patched.identify_ecu"
        ) as mock_id:
            mock_id.return_value = {"match_key": "EDC17::DIFFERENTVERSION"}
            result = v.check_match_key()
        assert result is not None
        assert "mismatch" in result.lower()
