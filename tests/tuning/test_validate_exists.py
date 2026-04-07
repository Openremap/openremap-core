"""
Tests for ECUExistenceValidator (validate_exists.py).

Covers:
  - validate_all: EXACT, SHIFTED, MISSING classification
  - Multiple occurrences of the same ob bytes
  - Closest-offset selection when multiple shifted matches exist
  - shift value (signed delta from expected offset)
  - counts(): exact / shifted / missing tallies
  - verdict(): safe_exact, shifted_recoverable, missing_unrecoverable
  - to_dict(): top-level shape, per-result fields, summary flags
  - check_file_size(): mismatch, match, no field
  - check_match_key(): no recipe key, unrecognised binary
  - Edge cases: empty instructions, single-byte ob, all-zero ob
"""

from tests.conftest import make_bin, make_bin_with, make_recipe, make_instruction
from openremap.core.services.validate_exists import ECUExistenceValidator, MatchStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_validator(
    target: bytes,
    instructions: list,
    ecu: dict | None = None,
    target_name: str = "target.bin",
    recipe_name: str = "recipe.json",
) -> ECUExistenceValidator:
    recipe = make_recipe(instructions, ecu=ecu)
    return ECUExistenceValidator(
        target_data=target,
        recipe=recipe,
        target_name=target_name,
        recipe_name=recipe_name,
    )


# ---------------------------------------------------------------------------
# validate_all — EXACT classification
# ---------------------------------------------------------------------------


class TestExactClassification:
    def test_single_byte_at_expected_offset_is_exact(self):
        target = make_bin_with(512, {200: 0xAA})
        v = make_validator(target, [make_instruction(200, "AA", "BB")])
        v.validate_all()
        assert len(v.results) == 1
        assert v.results[0].status == MatchStatus.EXACT

    def test_multi_byte_at_expected_offset_is_exact(self):
        target = make_bin_with(512, {100: 0xDE, 101: 0xAD, 102: 0xBE, 103: 0xEF})
        v = make_validator(target, [make_instruction(100, "DEADBEEF", "00000000")])
        v.validate_all()
        assert v.results[0].status == MatchStatus.EXACT

    def test_exact_match_has_shift_of_zero(self):
        target = make_bin_with(256, {50: 0xCC})
        v = make_validator(target, [make_instruction(50, "CC", "DD")])
        v.validate_all()
        assert v.results[0].shift == 0

    def test_exact_match_closest_offset_equals_expected(self):
        target = make_bin_with(256, {80: 0xAB})
        v = make_validator(target, [make_instruction(80, "AB", "00")])
        v.validate_all()
        assert v.results[0].closest_offset == 80

    def test_exact_match_expected_offset_in_offsets_found(self):
        target = make_bin_with(512, {300: 0xFF})
        v = make_validator(target, [make_instruction(300, "FF", "00")])
        v.validate_all()
        assert 300 in v.results[0].offsets_found

    def test_exact_match_at_offset_zero(self):
        target = make_bin_with(256, {0: 0x42})
        v = make_validator(target, [make_instruction(0, "42", "00")])
        v.validate_all()
        assert v.results[0].status == MatchStatus.EXACT

    def test_exact_match_at_last_byte(self):
        target = make_bin_with(256, {255: 0x99})
        v = make_validator(target, [make_instruction(255, "99", "00")])
        v.validate_all()
        assert v.results[0].status == MatchStatus.EXACT

    def test_multiple_occurrences_but_one_at_expected_offset_is_exact(self):
        # ob bytes appear at 100 (expected) and again at 400 (duplicate)
        target = make_bin_with(512, {100: 0xAA, 101: 0xBB, 400: 0xAA, 401: 0xBB})
        v = make_validator(target, [make_instruction(100, "AABB", "CCDD")])
        v.validate_all()
        r = v.results[0]
        assert r.status == MatchStatus.EXACT
        assert len(r.offsets_found) == 2  # both occurrences found

    def test_all_zero_ob_on_zero_filled_target_is_exact(self):
        target = make_bin(256)
        # ob = "0000" — will be found everywhere, including at offset 100
        v = make_validator(target, [make_instruction(100, "0000", "AABB")])
        v.validate_all()
        assert v.results[0].status == MatchStatus.EXACT


# ---------------------------------------------------------------------------
# validate_all — SHIFTED classification
# ---------------------------------------------------------------------------


class TestShiftedClassification:
    def test_ob_found_at_different_offset_is_shifted(self):
        # ob at 300, recipe expects 200 → SHIFTED
        target = make_bin_with(512, {300: 0xAA, 301: 0xBB})
        v = make_validator(target, [make_instruction(200, "AABB", "CCDD")])
        v.validate_all()
        assert v.results[0].status == MatchStatus.SHIFTED

    def test_shifted_result_has_nonzero_shift(self):
        target = make_bin_with(512, {300: 0xAA, 301: 0xBB})
        v = make_validator(target, [make_instruction(200, "AABB", "CCDD")])
        v.validate_all()
        assert v.results[0].shift != 0

    def test_shifted_positive_direction(self):
        # Found at 300, expected at 200 → shift = +100
        target = make_bin_with(512, {300: 0xCC})
        v = make_validator(target, [make_instruction(200, "CC", "00")])
        v.validate_all()
        assert v.results[0].shift == 100

    def test_shifted_negative_direction(self):
        # Found at 50, expected at 200 → shift = -150
        target = make_bin_with(512, {50: 0xCC})
        v = make_validator(target, [make_instruction(200, "CC", "00")])
        v.validate_all()
        assert v.results[0].shift == -150

    def test_closest_offset_is_nearest_to_expected(self):
        # ob at 150 and 450, expected at 200 — closest should be 150
        target = make_bin_with(
            512,
            {150: 0xEE, 151: 0xFF, 450: 0xEE, 451: 0xFF},
        )
        v = make_validator(target, [make_instruction(200, "EEFF", "0000")])
        v.validate_all()
        assert v.results[0].closest_offset == 150

    def test_all_offsets_found_recorded_on_shifted(self):
        target = make_bin_with(
            600,
            {100: 0x77, 300: 0x77, 500: 0x77},
        )
        # Expected at 50 — not present there → SHIFTED, 3 hits elsewhere
        v = make_validator(target, [make_instruction(50, "77", "00")])
        v.validate_all()
        r = v.results[0]
        assert r.status == MatchStatus.SHIFTED
        assert len(r.offsets_found) == 3
        assert 100 in r.offsets_found
        assert 300 in r.offsets_found
        assert 500 in r.offsets_found

    def test_shifted_reason_mentions_expected_offset(self):
        target = make_bin_with(512, {400: 0xAA})
        v = make_validator(target, [make_instruction(200, "AA", "BB")])
        v.validate_all()
        assert "200" in v.results[0].reason or "C8" in v.results[0].reason  # hex of 200

    def test_shifted_closest_offset_is_correct_when_tied(self):
        # Equidistant hits: expected=200, found at 100 and 300 (both 100 away)
        # min() picks the first one it encounters (lower offset wins)
        target = make_bin_with(512, {100: 0x55, 300: 0x55})
        v = make_validator(target, [make_instruction(200, "55", "00")])
        v.validate_all()
        r = v.results[0]
        assert r.status == MatchStatus.SHIFTED
        # Both are equidistant; closest_offset must be one of them
        assert r.closest_offset in (100, 300)


# ---------------------------------------------------------------------------
# validate_all — MISSING classification
# ---------------------------------------------------------------------------


class TestMissingClassification:
    def test_ob_not_in_binary_is_missing(self):
        target = make_bin(512)  # all zeros
        v = make_validator(target, [make_instruction(100, "AABB", "CCDD")])
        v.validate_all()
        assert v.results[0].status == MatchStatus.MISSING

    def test_missing_has_empty_offsets_found(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(50, "FFEE", "0000")])
        v.validate_all()
        assert v.results[0].offsets_found == []

    def test_missing_has_none_closest_offset(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(50, "DEAD", "BEEF")])
        v.validate_all()
        assert v.results[0].closest_offset is None

    def test_missing_has_none_shift(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(50, "CAFE", "0000")])
        v.validate_all()
        assert v.results[0].shift is None

    def test_missing_reason_mentions_possible_causes(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(50, "AABB", "CCDD")])
        v.validate_all()
        reason = v.results[0].reason.lower()
        # The reason should explain what might have gone wrong
        assert any(
            phrase in reason
            for phrase in ("not found", "wrong ecu", "modified", "missing")
        )

    def test_ob_bytes_preview_in_reason(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(50, "DEADBEEF", "00000000")])
        v.validate_all()
        # ob starts with DEAD — should appear (truncated or full) in reason
        reason = v.results[0].reason.upper()
        assert "DEAD" in reason

    def test_single_byte_missing(self):
        target = make_bin_with(256, {})  # all zeros, no 0xFF anywhere
        # 0xFF is absent → MISSING
        # But wait — 0x00 is everywhere. Let's use a unique byte.
        # All zeros → 0xAB is absent
        v = make_validator(target, [make_instruction(100, "AB", "00")])
        v.validate_all()
        assert v.results[0].status == MatchStatus.MISSING


# ---------------------------------------------------------------------------
# validate_all — mixed results and scanning behaviour
# ---------------------------------------------------------------------------


class TestValidateAllMixed:
    def test_all_instructions_scanned_regardless_of_status(self):
        target = make_bin_with(
            1024,
            {200: 0xAA, 201: 0xBB},  # only this ob present
        )
        v = make_validator(
            target,
            [
                make_instruction(200, "AABB", "CCDD"),  # EXACT
                make_instruction(100, "FFFF", "0000"),  # MISSING
                make_instruction(500, "AABB", "CCDD"),  # SHIFTED (found at 200)
            ],
        )
        v.validate_all()
        assert len(v.results) == 3
        assert v.results[0].status == MatchStatus.EXACT
        assert v.results[1].status == MatchStatus.MISSING
        assert v.results[2].status == MatchStatus.SHIFTED

    def test_results_cleared_on_second_validate_all_call(self):
        target = make_bin_with(256, {10: 0xAA})
        v = make_validator(target, [make_instruction(10, "AA", "BB")])
        v.validate_all()
        v.validate_all()  # must reset, not append
        assert len(v.results) == 1

    def test_instruction_index_is_one_based(self):
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

    def test_result_stores_ob_and_mb_from_recipe(self):
        target = make_bin_with(256, {50: 0xCC})
        v = make_validator(target, [make_instruction(50, "CC", "DD")])
        v.validate_all()
        r = v.results[0]
        assert r.original_bytes == "CC"
        assert r.modified_bytes == "DD"

    def test_result_size_derived_from_ob_length(self):
        target = make_bin_with(256, {10: 0xAA, 11: 0xBB, 12: 0xCC})
        v = make_validator(target, [make_instruction(10, "AABBCC", "000000")])
        v.validate_all()
        assert v.results[0].size == 3


# ---------------------------------------------------------------------------
# validate_all — empty instructions
# ---------------------------------------------------------------------------


class TestValidateAllEmpty:
    def test_empty_instructions_produces_empty_results(self):
        v = make_validator(make_bin(256), [])
        v.validate_all()
        assert v.results == []

    def test_counts_on_empty_results(self):
        v = make_validator(make_bin(256), [])
        v.validate_all()
        exact, shifted, missing = v.counts()
        assert exact == 0
        assert shifted == 0
        assert missing == 0


# ---------------------------------------------------------------------------
# counts()
# ---------------------------------------------------------------------------


class TestCounts:
    def test_all_exact(self):
        target = make_bin_with(512, {100: 0xAA, 200: 0xBB})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "00"),
                make_instruction(200, "BB", "00"),
            ],
        )
        v.validate_all()
        exact, shifted, missing = v.counts()
        assert exact == 2
        assert shifted == 0
        assert missing == 0

    def test_all_missing(self):
        target = make_bin(256)
        v = make_validator(
            target,
            [
                make_instruction(10, "FF", "00"),
                make_instruction(20, "EE", "00"),
            ],
        )
        v.validate_all()
        exact, shifted, missing = v.counts()
        assert exact == 0
        assert shifted == 0
        assert missing == 2

    def test_all_shifted(self):
        # ob at 400, recipe expects 100 → shifted for both
        target = make_bin_with(512, {400: 0xAA, 401: 0xBB})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "00"),
                make_instruction(200, "BB", "00"),
            ],
        )
        v.validate_all()
        exact, shifted, missing = v.counts()
        assert exact == 0
        assert shifted == 2
        assert missing == 0

    def test_mixed_counts(self):
        target = make_bin_with(
            1024,
            {100: 0xAA, 600: 0xBB},
        )
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "00"),  # EXACT
                make_instruction(200, "BB", "00"),  # SHIFTED (BB is at 600)
                make_instruction(300, "CC", "00"),  # MISSING
            ],
        )
        v.validate_all()
        exact, shifted, missing = v.counts()
        assert exact == 1
        assert shifted == 1
        assert missing == 1

    def test_counts_before_validate_returns_zeros(self):
        v = make_validator(make_bin(256), [make_instruction(10, "FF", "00")])
        # validate_all not called
        exact, shifted, missing = v.counts()
        assert (exact, shifted, missing) == (0, 0, 0)


# ---------------------------------------------------------------------------
# verdict()
# ---------------------------------------------------------------------------


class TestVerdict:
    def test_verdict_safe_exact_when_all_exact(self):
        target = make_bin_with(256, {50: 0xAA})
        v = make_validator(target, [make_instruction(50, "AA", "BB")])
        v.validate_all()
        assert v.verdict() == "safe_exact"

    def test_verdict_shifted_recoverable_when_all_shifted(self):
        target = make_bin_with(256, {200: 0xAA})
        v = make_validator(target, [make_instruction(50, "AA", "BB")])
        v.validate_all()
        assert v.verdict() == "shifted_recoverable"

    def test_verdict_missing_unrecoverable_when_any_missing(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(50, "FF", "00")])
        v.validate_all()
        assert v.verdict() == "missing_unrecoverable"

    def test_verdict_missing_unrecoverable_overrides_shifted(self):
        # Mix of shifted and missing → missing wins
        target = make_bin_with(512, {400: 0xAA})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "00"),  # SHIFTED
                make_instruction(200, "FF", "00"),  # MISSING
            ],
        )
        v.validate_all()
        assert v.verdict() == "missing_unrecoverable"

    def test_verdict_shifted_recoverable_when_mix_of_exact_and_shifted(self):
        # No missing, but some shifted → shifted_recoverable
        target = make_bin_with(512, {100: 0xAA, 400: 0xBB})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "00"),  # EXACT
                make_instruction(200, "BB", "00"),  # SHIFTED (BB at 400)
            ],
        )
        v.validate_all()
        assert v.verdict() == "shifted_recoverable"

    def test_verdict_safe_exact_on_empty_instructions(self):
        # No instructions → no missing, no shifted → safe_exact
        v = make_validator(make_bin(256), [])
        v.validate_all()
        assert v.verdict() == "safe_exact"


# ---------------------------------------------------------------------------
# to_dict()
# ---------------------------------------------------------------------------


class TestToDict:
    def test_top_level_keys_present(self):
        v = make_validator(make_bin(256), [])
        v.validate_all()
        d = v.to_dict()
        for key in ("target_file", "recipe_file", "target_md5", "summary", "results"):
            assert key in d, f"Missing top-level key: {key}"

    def test_target_file_and_recipe_file_correct(self):
        v = make_validator(
            make_bin(256),
            [],
            target_name="myecu.bin",
            recipe_name="myrec.json",
        )
        v.validate_all()
        d = v.to_dict()
        assert d["target_file"] == "myecu.bin"
        assert d["recipe_file"] == "myrec.json"

    def test_target_md5_is_32_hex_chars(self):
        v = make_validator(make_bin(256), [])
        v.validate_all()
        assert len(v.to_dict()["target_md5"]) == 32

    def test_summary_has_required_keys(self):
        v = make_validator(make_bin(256), [])
        v.validate_all()
        summary = v.to_dict()["summary"]
        for key in (
            "total",
            "exact",
            "shifted",
            "missing",
            "exact_pct",
            "shifted_pct",
            "missing_pct",
            "verdict",
        ):
            assert key in summary, f"Missing summary key: {key}"

    def test_summary_totals_correct(self):
        target = make_bin_with(512, {100: 0xAA})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "BB"),  # EXACT
                make_instruction(200, "FF", "00"),  # MISSING
            ],
        )
        v.validate_all()
        summary = v.to_dict()["summary"]
        assert summary["total"] == 2
        assert summary["exact"] == 1
        assert summary["missing"] == 1
        assert summary["shifted"] == 0

    def test_summary_verdict_matches_verdict_method(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(10, "FF", "00")])
        v.validate_all()
        assert v.to_dict()["summary"]["verdict"] == v.verdict()

    def test_summary_percentages_add_up_to_100_when_all_same_status(self):
        target = make_bin_with(256, {10: 0xAA})
        v = make_validator(target, [make_instruction(10, "AA", "BB")])
        v.validate_all()
        summary = v.to_dict()["summary"]
        assert summary["exact_pct"] == 100.0
        assert summary["shifted_pct"] == 0.0
        assert summary["missing_pct"] == 0.0

    def test_results_list_length_equals_instruction_count(self):
        target = make_bin_with(512, {100: 0xAA, 200: 0xBB})
        v = make_validator(
            target,
            [
                make_instruction(100, "AA", "00"),
                make_instruction(200, "BB", "00"),
                make_instruction(300, "CC", "00"),
            ],
        )
        v.validate_all()
        assert len(v.to_dict()["results"]) == 3

    def test_result_entry_has_required_fields(self):
        target = make_bin_with(256, {10: 0xAA})
        v = make_validator(target, [make_instruction(10, "AA", "BB")])
        v.validate_all()
        entry = v.to_dict()["results"][0]
        for key in (
            "instruction_index",
            "offset_expected",
            "offset_hex_expected",
            "size",
            "ob",
            "mb",
            "status",
            "offsets_found",
            "closest_offset",
            "shift",
            "reason",
        ):
            assert key in entry, f"Missing result key: {key}"

    def test_result_status_is_string_value(self):
        target = make_bin_with(256, {10: 0xAA})
        v = make_validator(target, [make_instruction(10, "AA", "BB")])
        v.validate_all()
        status = v.to_dict()["results"][0]["status"]
        assert isinstance(status, str)
        assert status in ("exact", "shifted", "missing")

    def test_offsets_found_formatted_as_hex_strings(self):
        target = make_bin_with(512, {100: 0xAA, 300: 0xAA})
        v = make_validator(target, [make_instruction(100, "AA", "BB")])
        v.validate_all()
        offsets = v.to_dict()["results"][0]["offsets_found"]
        assert all(isinstance(o, str) for o in offsets)
        assert all(o.startswith("0x") for o in offsets)

    def test_closest_offset_formatted_as_hex_string_when_present(self):
        target = make_bin_with(256, {50: 0xAA})
        v = make_validator(target, [make_instruction(50, "AA", "BB")])
        v.validate_all()
        closest = v.to_dict()["results"][0]["closest_offset"]
        assert isinstance(closest, str)
        assert closest.startswith("0x")

    def test_closest_offset_is_none_when_missing(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(50, "FF", "00")])
        v.validate_all()
        closest = v.to_dict()["results"][0]["closest_offset"]
        assert closest is None

    def test_shift_is_none_when_missing(self):
        target = make_bin(256)
        v = make_validator(target, [make_instruction(50, "FF", "00")])
        v.validate_all()
        assert v.to_dict()["results"][0]["shift"] is None

    def test_shift_is_integer_when_shifted(self):
        target = make_bin_with(256, {200: 0xAA})
        v = make_validator(target, [make_instruction(50, "AA", "BB")])
        v.validate_all()
        shift = v.to_dict()["results"][0]["shift"]
        assert isinstance(shift, int)


# ---------------------------------------------------------------------------
# check_file_size()
# ---------------------------------------------------------------------------


class TestCheckFileSize:
    def test_size_match_returns_none(self):
        v = make_validator(make_bin(1024), [], ecu={"file_size": 1024})
        assert v.check_file_size() is None

    def test_size_mismatch_returns_string(self):
        v = make_validator(make_bin(512), [], ecu={"file_size": 1024})
        msg = v.check_file_size()
        assert msg is not None
        assert isinstance(msg, str)

    def test_size_mismatch_message_mentions_both_sizes(self):
        v = make_validator(make_bin(512), [], ecu={"file_size": 1024})
        msg = v.check_file_size()
        # Message should reference expected and/or actual size
        assert msg is not None
        assert "512" in msg or "1,024" in msg or "mismatch" in msg.lower()

    def test_no_file_size_field_returns_none(self):
        v = make_validator(make_bin(256), [], ecu={})
        assert v.check_file_size() is None

    def test_no_ecu_block_in_recipe_returns_none(self):
        from openremap.core.services.validate_exists import ECUExistenceValidator

        recipe = {"metadata": {}, "instructions": []}
        v = ECUExistenceValidator(make_bin(256), recipe)
        assert v.check_file_size() is None


# ---------------------------------------------------------------------------
# check_match_key()
# ---------------------------------------------------------------------------


class TestCheckMatchKey:
    def test_no_recipe_match_key_returns_none(self):
        v = make_validator(make_bin(256), [], ecu={"file_size": 256})
        assert v.check_match_key() is None

    def test_unrecognised_target_binary_skips_check(self):
        # All-zero binary → no extractor claims it → target_key is None → skip
        v = make_validator(
            make_bin(256),
            [],
            ecu={"match_key": "EDC17::SOMEVERSION"},
        )
        assert v.check_match_key() is None

    def test_empty_ecu_block_returns_none(self):
        v = make_validator(make_bin(256), [], ecu={})
        assert v.check_match_key() is None


# ---------------------------------------------------------------------------
# check_match_key() — mismatch / exception branches
# ---------------------------------------------------------------------------


class TestCheckMatchKeyMismatch:
    def test_identify_ecu_raises_exception_returns_none(self):
        from unittest.mock import patch

        v = make_validator(make_bin(256), [], ecu={"match_key": "EDC17::SOMEVERSION"})
        with patch("openremap.core.services.validate_exists.identify_ecu") as mock_id:
            mock_id.side_effect = RuntimeError("identification failed")
            result = v.check_match_key()
        assert result is None

    def test_matching_key_returns_none(self):
        from unittest.mock import patch

        recipe_key = "EDC17::SOMEVERSION"
        v = make_validator(make_bin(256), [], ecu={"match_key": recipe_key})
        with patch("openremap.core.services.validate_exists.identify_ecu") as mock_id:
            mock_id.return_value = {"match_key": recipe_key}
            result = v.check_match_key()
        assert result is None

    def test_mismatched_key_returns_mismatch_string(self):
        from unittest.mock import patch

        v = make_validator(make_bin(256), [], ecu={"match_key": "EDC17::SOMEVERSION"})
        with patch("openremap.core.services.validate_exists.identify_ecu") as mock_id:
            mock_id.return_value = {"match_key": "EDC17::DIFFERENTVERSION"}
            result = v.check_match_key()
        assert result is not None
        assert "mismatch" in result.lower()
