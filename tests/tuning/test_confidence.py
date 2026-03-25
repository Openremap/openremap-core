"""
Tests for score_identity() — the ECU binary confidence scorer.

Covers:
  - Unknown binary (no ecu_family) → "Unknown" tier
  - 1037-SW present → +40, "High" tier with other signals
  - Non-1037 SW present → +15 only
  - SW absent + match_key absent → -30, "Suspicious" tier, "IDENT BLOCK MISSING" for 1037-families
  - SW absent + match_key present → -10 (LH-Jetronic style)
  - Hardware number present → +25
  - ECU variant present → +10
  - Calibration ID present → +10
  - Tuning keywords in filename → -25, "TUNING KEYWORDS IN FILENAME" warning
  - Generic numbered filename → -15, "GENERIC FILENAME" warning
  - Score tiers (High/Medium/Low/Suspicious)
  - ConfidenceResult helpers (is_suspicious, has_warnings, tier_colour_hint)
  - rationale_summary formatting
  - Determinism
"""

import pytest

from openremap.tuning.services.confidence import (
    ConfidenceResult,
    ConfidenceSignal,
    _is_1037_family,
    score_identity,
)


# ---------------------------------------------------------------------------
# Helpers — build minimal identity dicts
# ---------------------------------------------------------------------------


def _identity(
    *,
    ecu_family="EDC17",
    ecu_variant="EDC17C66",
    software_version="1037541778",
    hardware_number="0261209352",
    calibration_id="1037393302",
    match_key="EDC17C66::1037541778",
) -> dict:
    """Return a fully-populated EDC17 identity dict (all fields present)."""
    return {
        "ecu_family": ecu_family,
        "ecu_variant": ecu_variant,
        "software_version": software_version,
        "hardware_number": hardware_number,
        "calibration_id": calibration_id,
        "match_key": match_key,
        "manufacturer": "Bosch",
        "file_size": 2 * 1024 * 1024,
        "sha256": "abc" * 21 + "d",
    }


def _stripped(**overrides) -> dict:
    """Return an identity dict with the given fields overridden to None."""
    base = _identity()
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Unknown binary
# ---------------------------------------------------------------------------


class TestUnknownBinary:
    def test_unknown_when_no_family(self):
        result = score_identity({"ecu_family": None}, filename="x.bin")
        assert result.tier == "Unknown"

    def test_unknown_score_is_zero(self):
        result = score_identity({"ecu_family": None}, filename="x.bin")
        assert result.score == 0

    def test_unknown_no_signals(self):
        result = score_identity({"ecu_family": None}, filename="x.bin")
        assert result.signals == []

    def test_unknown_no_warnings(self):
        result = score_identity({"ecu_family": None}, filename="x.bin")
        assert result.warnings == []

    def test_empty_dict_no_family(self):
        result = score_identity({}, filename="x.bin")
        assert result.tier == "Unknown"

    def test_is_suspicious_is_true_for_unknown(self):
        result = score_identity({"ecu_family": None})
        assert result.is_suspicious is True


# ---------------------------------------------------------------------------
# SW version — 1037-prefixed
# ---------------------------------------------------------------------------


class TestSW1037:
    def test_1037_sw_adds_40(self):
        result = score_identity(
            _stripped(
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::1037541778",
            ),
            filename="ecu.bin",
        )
        # Only SW signal present: +40
        assert result.score == 40

    def test_1037_sw_signal_label(self):
        result = score_identity(
            _stripped(
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::1037541778",
            )
        )
        assert any("1037" in s.label for s in result.signals)

    def test_1037_sw_signal_delta_is_40(self):
        result = score_identity(
            _stripped(
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::1037541778",
            )
        )
        sw_signal = next(s for s in result.signals if s.delta == 40)
        assert sw_signal is not None

    def test_non_1037_sw_adds_15(self):
        result = score_identity(
            _stripped(
                software_version="ABCDE12345",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::ABCDE12345",
            ),
            filename="ecu.bin",
        )
        assert result.score == 15

    def test_non_1037_sw_signal_delta_is_15(self):
        result = score_identity(
            _stripped(
                software_version="ABCDE12345",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::ABCDE12345",
            )
        )
        sw_signal = next(s for s in result.signals if s.delta == 15)
        assert sw_signal is not None

    def test_1037_sw_starting_with_different_prefix_is_not_canonical(self):
        result = score_identity(
            _stripped(
                software_version="2037541778",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::2037541778",
            )
        )
        assert result.score == 15  # non-canonical, +15 not +40


# ---------------------------------------------------------------------------
# SW absent — two sub-cases
# ---------------------------------------------------------------------------


class TestSWAbsent:
    def test_sw_absent_no_match_key_deducts_30(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            ),
            filename="ecu.bin",
        )
        assert result.score == -30

    def test_sw_absent_no_match_key_suspicious_tier(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert result.tier == "Suspicious"

    def test_sw_absent_no_match_key_signal_delta_is_minus30(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert any(s.delta == -30 for s in result.signals)

    def test_sw_absent_with_match_key_deducts_10(self):
        # match_key present but SW absent (LH-Jetronic style)
        result = score_identity(
            _stripped(
                software_version=None,
                match_key="LH-JETRONIC::9146179 P01",
                ecu_family="LH-JETRONIC",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            ),
            filename="ecu.bin",
        )
        assert result.score == -10

    def test_sw_absent_with_match_key_signal_delta_is_minus10(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key="LH-JETRONIC::9146179 P01",
                ecu_family="LH-JETRONIC",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert any(s.delta == -10 for s in result.signals)

    def test_ident_block_missing_warning_for_1037_family_sw_absent(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_family="EDC17",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert "IDENT BLOCK MISSING" in result.warnings

    def test_no_ident_missing_warning_for_lh_jetronic(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key="LH-JETRONIC::9146179 P01",
                ecu_family="LH-JETRONIC",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert "IDENT BLOCK MISSING" not in result.warnings

    def test_ident_block_missing_for_me9_family(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_family="ME9",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert "IDENT BLOCK MISSING" in result.warnings

    def test_ident_block_missing_for_me7_family(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_family="ME7",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert "IDENT BLOCK MISSING" in result.warnings

    def test_ident_block_missing_for_edc16_family(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_family="EDC16",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert "IDENT BLOCK MISSING" in result.warnings


# ---------------------------------------------------------------------------
# Hardware number
# ---------------------------------------------------------------------------


class TestHardwareNumber:
    def test_hw_present_adds_25(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_variant=None,
                calibration_id=None,
                hardware_number="0261209352",
            ),
            filename="ecu.bin",
        )
        # -30 (sw absent, no match_key) + 25 (hw) = -5
        assert result.score == -5

    def test_hw_signal_delta_is_25(self):
        result = score_identity(_identity())
        assert any(s.delta == 25 for s in result.signals)

    def test_hw_absent_no_hw_signal(self):
        result = score_identity(
            _stripped(
                hardware_number=None,
                ecu_variant=None,
                calibration_id=None,
                match_key="EDC17::1037541778",
            )
        )
        assert not any(s.delta == 25 for s in result.signals)

    def test_hw_label_contains_hw_number(self):
        result = score_identity(_identity())
        hw_signal = next(s for s in result.signals if s.delta == 25)
        assert "0261209352" in hw_signal.label


# ---------------------------------------------------------------------------
# ECU variant
# ---------------------------------------------------------------------------


class TestECUVariant:
    def test_variant_different_from_family_adds_10(self):
        result = score_identity(_identity())
        assert any(
            s.delta == 10 and "variant" in s.label.lower() for s in result.signals
        )

    def test_variant_same_as_family_no_extra_signal(self):
        # When variant == family, no bonus
        result = score_identity(
            _stripped(
                ecu_family="EDC17",
                ecu_variant="EDC17",
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::1037541778",
            )
        )
        assert not any(
            "variant" in s.label.lower() and s.delta == 10 for s in result.signals
        )

    def test_variant_none_no_signal(self):
        result = score_identity(
            _stripped(
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::1037541778",
            )
        )
        assert not any(
            "variant" in s.label.lower() and s.delta == 10 for s in result.signals
        )

    def test_variant_label_contains_variant_string(self):
        result = score_identity(_identity())
        variant_signal = next(
            (
                s
                for s in result.signals
                if "variant" in s.label.lower() and s.delta == 10
            ),
            None,
        )
        assert variant_signal is not None
        assert "EDC17C66" in variant_signal.label


# ---------------------------------------------------------------------------
# Calibration ID
# ---------------------------------------------------------------------------


class TestCalibrationId:
    def test_cal_id_present_adds_10(self):
        result = score_identity(_identity())
        cal_signals = [
            s
            for s in result.signals
            if "calibration" in s.label.lower() and s.delta == 10
        ]
        assert len(cal_signals) >= 1

    def test_cal_id_absent_no_cal_signal(self):
        result = score_identity(
            _stripped(
                calibration_id=None,
                ecu_variant=None,
                hardware_number=None,
                match_key="EDC17::1037541778",
            )
        )
        assert not any(
            "calibration" in s.label.lower() and s.delta == 10 for s in result.signals
        )


# ---------------------------------------------------------------------------
# Filename — tuning keywords
# ---------------------------------------------------------------------------


class TestTuningKeywords:
    _1037_EDC17 = _identity()

    def _score(self, filename: str) -> ConfidenceResult:
        return score_identity(self._1037_EDC17, filename=filename)

    def test_stage_keyword_deducts_25(self):
        result = self._score("tune stage 1.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_remap_keyword_deducts_25(self):
        result = self._score("ecu_remap.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_tuned_keyword_deducts_25(self):
        result = self._score("ECU_tuned.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_tune_keyword_deducts_25(self):
        result = self._score("tune.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_disable_in_filename_deducts_25(self):
        result = self._score("ecu-disable-P1681.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_tuning_keywords_warning_raised(self):
        result = self._score("stage1.bin")
        assert "TUNING KEYWORDS IN FILENAME" in result.warnings

    def test_patched_keyword_deducts_25(self):
        result = self._score("ecu_patched.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_custom_keyword_deducts_25(self):
        result = self._score("custom_map.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_dpf_off_keyword_deducts_25(self):
        result = self._score("ecu dpf off.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_egr_off_keyword_deducts_25(self):
        result = self._score("egr_off.bin")
        assert any(s.delta == -25 for s in result.signals)

    def test_normal_filename_no_tuning_signal(self):
        result = self._score("ecu_stock_ori.bin")
        assert not any(s.delta == -25 for s in result.signals)

    def test_manufacturer_code_filename_not_flagged(self):
        result = self._score("0261209352_1037383785.bin")
        assert not any(s.delta == -25 for s in result.signals)


# ---------------------------------------------------------------------------
# Filename — generic numbered
# ---------------------------------------------------------------------------


class TestGenericFilename:
    _1037_EDC17 = _identity()

    def _score(self, filename: str) -> ConfidenceResult:
        return score_identity(self._1037_EDC17, filename=filename)

    def test_single_digit_bin_deducts_15(self):
        assert any(s.delta == -15 for s in self._score("1.bin").signals)

    def test_two_digit_bin_deducts_15(self):
        assert any(s.delta == -15 for s in self._score("42.bin").signals)

    def test_three_digit_bin_deducts_15(self):
        assert any(s.delta == -15 for s in self._score("007.bin").signals)

    def test_four_digit_ori_deducts_15(self):
        assert any(s.delta == -15 for s in self._score("9999.ori").signals)

    def test_generic_filename_warning_raised(self):
        assert "GENERIC FILENAME" in self._score("3.bin").warnings

    def test_named_file_not_flagged_as_generic(self):
        assert not any(s.delta == -15 for s in self._score("ecu.bin").signals)

    def test_five_digit_not_flagged_as_generic(self):
        # More than 4 digits — not matched by the generic pattern
        assert not any(s.delta == -15 for s in self._score("12345.bin").signals)

    def test_tuning_keyword_takes_precedence_over_generic(self):
        # A file that matches both (very unlikely, but ensure only -25 not -40)
        result = self._score("1_tuned.bin")
        deltas = [s.delta for s in result.signals]
        assert -25 in deltas
        assert -15 not in deltas  # the elif prevents both


# ---------------------------------------------------------------------------
# Tier assignment
# ---------------------------------------------------------------------------


class TestTiers:
    def test_high_tier_full_identity(self):
        # +40 (sw) + 25 (hw) + 10 (variant) + 10 (cal_id) = 85
        result = score_identity(_identity(), filename="ecu.bin")
        assert result.tier == "High"
        assert result.score == 85

    def test_medium_tier_sw_only(self):
        # +40 (sw) only
        result = score_identity(
            _stripped(
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::1037541778",
            ),
            filename="ecu.bin",
        )
        assert result.tier == "Medium"
        assert result.score == 40

    def test_medium_tier_sw_and_hw(self):
        # +40 + 25 = 65 → High
        result = score_identity(
            _stripped(
                ecu_variant=None,
                calibration_id=None,
                match_key="EDC17::1037541778",
            ),
            filename="ecu.bin",
        )
        assert result.tier == "High"
        assert result.score == 65

    def test_low_tier_hw_only(self):
        # -30 (sw absent, no match_key) + 25 (hw) = -5 → Suspicious
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_variant=None,
                calibration_id=None,
            ),
            filename="ecu.bin",
        )
        assert result.tier == "Suspicious"

    def test_low_tier_non1037_sw_with_tuning_keyword(self):
        # +15 (non-1037 sw) - 25 (tuning kw) = -10 → Suspicious
        result = score_identity(
            _stripped(
                software_version="ABCDE12345",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17::ABCDE12345",
            ),
            filename="stage1.bin",
        )
        assert result.tier == "Suspicious"
        assert result.score == -10

    def test_suspicious_tier_wiped_ident(self):
        # sw=None, match_key=None, no hw, no variant, no cal → -30
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert result.tier == "Suspicious"

    def test_high_score_exact_boundary(self):
        # Exactly 60 → High
        # +40 (sw) + 25 (hw) = 65 → High
        # Let's engineer exactly 60: +40 (sw) + 10 (variant) + 10 (cal_id) = 60
        result = score_identity(
            _stripped(
                hardware_number=None,
                match_key="EDC17C66::1037541778",
            ),
            filename="ecu.bin",
        )
        assert result.score == 60
        assert result.tier == "High"

    def test_medium_score_exact_boundary(self):
        # Exactly 25 → Medium
        # +15 (non-1037 sw) + 10 (variant) = 25
        result = score_identity(
            _stripped(
                software_version="ABCDE12345",
                hardware_number=None,
                calibration_id=None,
                match_key="EDC17C66::ABCDE12345",
            ),
            filename="ecu.bin",
        )
        assert result.score == 25
        assert result.tier == "Medium"

    def test_low_score_exact_boundary(self):
        # Exactly 0 → Low
        # -10 (sw absent, match_key present) + 10 (cal_id) = 0
        result = score_identity(
            _stripped(
                software_version=None,
                ecu_family="LH-JETRONIC",
                match_key="LH-JETRONIC::9146179 P01",
                calibration_id="9146179 P01",
                ecu_variant=None,
                hardware_number=None,
            ),
            filename="ecu.bin",
        )
        assert result.score == 0
        assert result.tier == "Low"


# ---------------------------------------------------------------------------
# ConfidenceResult helpers
# ---------------------------------------------------------------------------


class TestConfidenceResultHelpers:
    def test_is_suspicious_true_for_suspicious_tier(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert result.is_suspicious is True

    def test_is_suspicious_true_for_unknown_tier(self):
        result = score_identity({"ecu_family": None})
        assert result.is_suspicious is True

    def test_is_suspicious_false_for_high_tier(self):
        result = score_identity(_identity())
        assert result.is_suspicious is False

    def test_has_warnings_true_when_warnings_present(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_family="EDC17",
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert result.has_warnings is True

    def test_has_warnings_false_when_no_warnings(self):
        result = score_identity(_identity(), filename="ecu.bin")
        assert result.has_warnings is False

    def test_tier_colour_hint_green_for_high(self):
        result = score_identity(_identity(), filename="ecu.bin")
        assert result.tier_colour_hint == "green"

    def test_tier_colour_hint_red_for_suspicious(self):
        result = score_identity(
            _stripped(
                software_version=None,
                match_key=None,
                ecu_variant=None,
                hardware_number=None,
                calibration_id=None,
            )
        )
        assert result.tier_colour_hint == "red"

    def test_tier_colour_hint_cyan_for_unknown(self):
        result = score_identity({"ecu_family": None})
        assert result.tier_colour_hint == "cyan"


# ---------------------------------------------------------------------------
# rationale_summary
# ---------------------------------------------------------------------------


class TestRationaleSummary:
    def test_summary_non_empty_for_identified(self):
        result = score_identity(_identity())
        assert result.rationale_summary() != ""

    def test_summary_empty_description_for_unknown(self):
        result = score_identity({"ecu_family": None})
        # "no signals" when no signals
        assert result.rationale_summary() == "no signals"

    def test_summary_contains_top_signal(self):
        result = score_identity(_identity())
        summary = result.rationale_summary()
        assert "1037" in summary or "canonical" in summary

    def test_summary_respects_max_signals(self):
        result = score_identity(_identity())
        summary1 = result.rationale_summary(max_signals=1)
        summary3 = result.rationale_summary(max_signals=3)
        # max_signals=1 should produce fewer comma-separated parts
        assert summary1.count(",") <= summary3.count(",")


# ---------------------------------------------------------------------------
# _is_1037_family helper
# ---------------------------------------------------------------------------


class TestIs1037Family:
    def test_edc17_is_1037_family(self):
        assert _is_1037_family("EDC17") is True

    def test_edc17c66_is_1037_family(self):
        assert _is_1037_family("EDC17C66") is True

    def test_medc17_is_1037_family(self):
        assert _is_1037_family("MEDC17") is True

    def test_me9_is_1037_family(self):
        assert _is_1037_family("ME9") is True

    def test_me7_is_1037_family(self):
        assert _is_1037_family("ME7") is True

    def test_edc16_is_1037_family(self):
        assert _is_1037_family("EDC16") is True

    def test_edc15_is_1037_family(self):
        assert _is_1037_family("EDC15") is True

    def test_lh_jetronic_is_not_1037_family(self):
        assert _is_1037_family("LH-JETRONIC") is False

    def test_empty_string_is_not_1037_family(self):
        assert _is_1037_family("") is False

    def test_case_insensitive_match(self):
        assert _is_1037_family("edc17") is True
        assert _is_1037_family("Me9") is True


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_identity_same_result(self):
        identity = _identity()
        r1 = score_identity(identity, filename="ecu.bin")
        r2 = score_identity(identity, filename="ecu.bin")
        assert r1.score == r2.score
        assert r1.tier == r2.tier
        assert r1.warnings == r2.warnings

    def test_different_filename_changes_result(self):
        identity = _identity()
        r_stock = score_identity(identity, filename="ecu.bin")
        r_tuned = score_identity(identity, filename="ecu_stage1.bin")
        assert r_stock.score != r_tuned.score
