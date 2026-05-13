"""
Tests for the recipe instruction annotator (annotator.py).

Covers:
  - InstructionFlag dataclass and to_dict serialisation
  - VINScanner: VIN detection, no false positive on non-VIN data,
                partial overlap, VIN outside instruction range
  - RecipeAnnotator: annotate populates flags on all instructions,
                     flagged_count, flag_summary, add_scanner,
                     empty instructions list, no flags when clean
"""

from __future__ import annotations

import pytest

from tests.conftest import make_bin, make_bin_with
from openremap.core.services.annotator import (
    InstructionFlag,
    RecipeAnnotator,
    VINScanner,
)
from openremap.core.services.recipe_builder import ECUDiffAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A valid VIN: WVWZZZ3CZWE123456  (17 chars, no I/O/Q)
SAMPLE_VIN = b"WVWZZZ3CZWE123456"
assert len(SAMPLE_VIN) == 17


def _make_recipe_with_instruction(
    offset: int, size: int, ob_hex: str, mb_hex: str
) -> dict:
    """Build a minimal recipe dict with a single instruction."""
    return {
        "instructions": [
            {
                "offset": offset,
                "offset_hex": f"{offset:X}",
                "size": size,
                "ob": ob_hex,
                "mb": mb_hex,
                "ctx": "00" * 8,
                "context_after": "00" * 8,
                "context_size": 8,
                "description": f"{size} bytes at 0x{offset:X} modified",
            }
        ]
    }


def _build_binary_with_vin(
    size: int, vin_offset: int, vin: bytes = SAMPLE_VIN
) -> bytes:
    """Create a binary with a VIN string placed at vin_offset."""
    buf = bytearray(size)
    buf[vin_offset : vin_offset + len(vin)] = vin
    return bytes(buf)


# ---------------------------------------------------------------------------
# InstructionFlag
# ---------------------------------------------------------------------------


class TestInstructionFlag:
    def test_to_dict_has_all_keys(self):
        f = InstructionFlag(kind="VIN_SUSPECT", reason="test reason", confidence="HIGH")
        d = f.to_dict()
        assert d["kind"] == "VIN_SUSPECT"
        assert d["reason"] == "test reason"
        assert d["confidence"] == "HIGH"
        assert d["action"] == "REVIEW"

    def test_default_action_is_review(self):
        f = InstructionFlag(kind="X", reason="y", confidence="LOW")
        assert f.action == "REVIEW"

    def test_frozen(self):
        f = InstructionFlag(kind="X", reason="y", confidence="LOW")
        with pytest.raises(AttributeError):
            f.kind = "changed"


# ---------------------------------------------------------------------------
# VINScanner
# ---------------------------------------------------------------------------


class TestVINScanner:
    def test_flags_instruction_overlapping_vin(self):
        """Instruction that directly changes VIN bytes should be flagged."""
        vin_offset = 0x200
        orig = _build_binary_with_vin(1024, vin_offset)
        # Instruction covers the VIN region exactly
        ob_hex = orig[vin_offset : vin_offset + 17].hex().upper()
        mb_hex = "AA" * 17
        recipe = _make_recipe_with_instruction(vin_offset, 17, ob_hex, mb_hex)

        scanner = VINScanner()
        flags = scanner.scan(recipe["instructions"][0], orig)
        assert len(flags) == 1
        assert flags[0].kind == "VIN_SUSPECT"
        assert flags[0].confidence == "HIGH"
        assert "WVWZZZ3CZWE123456" in flags[0].reason

    def test_no_flag_on_non_vin_data(self):
        """Instruction that changes zero-filled data should not be flagged."""
        orig = make_bin(1024)
        recipe = _make_recipe_with_instruction(100, 4, "00000000", "AABBCCDD")
        scanner = VINScanner()
        flags = scanner.scan(recipe["instructions"][0], orig)
        assert flags == []

    def test_no_flag_when_vin_is_far_away(self):
        """VIN exists in binary but instruction is far from it."""
        orig = _build_binary_with_vin(4096, 0x800)
        # Instruction at offset 0x100 — far from VIN at 0x800
        recipe = _make_recipe_with_instruction(0x100, 4, "00000000", "FFFFFFFF")
        scanner = VINScanner()
        flags = scanner.scan(recipe["instructions"][0], orig)
        assert flags == []

    def test_flags_partial_overlap_start(self):
        """Instruction starts before VIN and overlaps its first bytes."""
        vin_offset = 0x200
        orig = _build_binary_with_vin(1024, vin_offset)
        # Instruction covers vin_offset-4 to vin_offset+4 (8 bytes)
        inst_offset = vin_offset - 4
        ob_hex = orig[inst_offset : inst_offset + 8].hex().upper()
        recipe = _make_recipe_with_instruction(inst_offset, 8, ob_hex, "FF" * 8)
        scanner = VINScanner()
        flags = scanner.scan(recipe["instructions"][0], orig)
        assert len(flags) == 1
        assert flags[0].kind == "VIN_SUSPECT"

    def test_flags_partial_overlap_end(self):
        """Instruction starts inside VIN and extends past it."""
        vin_offset = 0x200
        orig = _build_binary_with_vin(1024, vin_offset)
        inst_offset = vin_offset + 10  # inside VIN
        ob_hex = orig[inst_offset : inst_offset + 12].hex().upper()
        recipe = _make_recipe_with_instruction(inst_offset, 12, ob_hex, "FF" * 12)
        scanner = VINScanner()
        flags = scanner.scan(recipe["instructions"][0], orig)
        assert len(flags) == 1
        assert flags[0].kind == "VIN_SUSPECT"

    def test_no_flag_instruction_adjacent_but_not_overlapping(self):
        """Instruction is immediately after VIN — no overlap."""
        vin_offset = 0x200
        orig = _build_binary_with_vin(1024, vin_offset)
        inst_offset = vin_offset + 17  # right after VIN ends
        # Make sure the bytes at inst_offset are NOT VIN chars
        # (they're 0x00 from make_bin_with)
        recipe = _make_recipe_with_instruction(inst_offset, 4, "00000000", "FFFFFFFF")
        scanner = VINScanner()
        flags = scanner.scan(recipe["instructions"][0], orig)
        assert flags == []

    def test_vin_with_lowercase_not_matched(self):
        """VIN regex requires uppercase — lowercase should not match."""
        buf = bytearray(1024)
        buf[0x200 : 0x200 + 17] = b"wvwzzz3czwe123456"  # lowercase
        orig = bytes(buf)
        recipe = _make_recipe_with_instruction(
            0x200, 17, orig[0x200:0x211].hex().upper(), "FF" * 17
        )
        scanner = VINScanner()
        flags = scanner.scan(recipe["instructions"][0], orig)
        assert flags == []

    def test_only_one_flag_per_instruction(self):
        """Even if multiple VINs overlap, only one flag is emitted."""
        buf = bytearray(1024)
        # Two VINs right next to each other (overlapping window)
        buf[0x200 : 0x200 + 17] = SAMPLE_VIN
        buf[0x211 : 0x211 + 17] = b"WDBRF61J21F123456"
        orig = bytes(buf)
        # Instruction spans both
        recipe = _make_recipe_with_instruction(
            0x200, 40, orig[0x200:0x228].hex().upper(), "FF" * 40
        )
        scanner = VINScanner()
        flags = scanner.scan(recipe["instructions"][0], orig)
        assert len(flags) == 1


# ---------------------------------------------------------------------------
# RecipeAnnotator
# ---------------------------------------------------------------------------


class TestRecipeAnnotator:
    def test_annotate_adds_flags_key_to_all_instructions(self):
        """Every instruction should get a 'flags' key, even if empty."""
        orig = make_bin(512)
        mod = bytearray(orig)
        mod[100] = 0xFF
        mod[400] = 0xAA
        mod = bytes(mod)

        analyzer = ECUDiffAnalyzer(orig, mod, "orig.bin", "mod.bin", context_size=8)
        recipe = analyzer.build_recipe()

        annotator = RecipeAnnotator()
        annotator.annotate(recipe, orig)

        for inst in recipe["instructions"]:
            assert "flags" in inst
            assert isinstance(inst["flags"], list)

    def test_flagged_count_zero_when_clean(self):
        orig = make_bin(512)
        mod = bytearray(orig)
        mod[100] = 0xFF
        mod = bytes(mod)

        analyzer = ECUDiffAnalyzer(orig, mod, "orig.bin", "mod.bin", context_size=8)
        recipe = analyzer.build_recipe()

        annotator = RecipeAnnotator()
        annotator.annotate(recipe, orig)
        assert annotator.flagged_count(recipe) == 0

    def test_flagged_count_nonzero_when_vin_present(self):
        vin_offset = 0x100
        orig = _build_binary_with_vin(512, vin_offset)
        mod = bytearray(orig)
        # Change VIN bytes
        for i in range(17):
            mod[vin_offset + i] = 0xAA
        mod = bytes(mod)

        analyzer = ECUDiffAnalyzer(orig, mod, "orig.bin", "mod.bin", context_size=8)
        recipe = analyzer.build_recipe()

        annotator = RecipeAnnotator()
        annotator.annotate(recipe, orig)
        assert annotator.flagged_count(recipe) >= 1

    def test_flag_summary_returns_strings(self):
        vin_offset = 0x100
        orig = _build_binary_with_vin(512, vin_offset)
        mod = bytearray(orig)
        for i in range(17):
            mod[vin_offset + i] = 0xAA
        mod = bytes(mod)

        analyzer = ECUDiffAnalyzer(orig, mod, "orig.bin", "mod.bin", context_size=8)
        recipe = analyzer.build_recipe()

        annotator = RecipeAnnotator()
        annotator.annotate(recipe, orig)
        summary = annotator.flag_summary(recipe)
        assert len(summary) >= 1
        assert "VIN_SUSPECT" in summary[0]

    def test_empty_instructions_list(self):
        orig = make_bin(256)
        analyzer = ECUDiffAnalyzer(orig, orig, "a.bin", "b.bin", context_size=8)
        recipe = analyzer.build_recipe()

        annotator = RecipeAnnotator()
        annotator.annotate(recipe, orig)
        assert annotator.flagged_count(recipe) == 0

    def test_add_scanner(self):
        """Custom scanner gets invoked."""

        class AlwaysFlagScanner:
            def scan(self, instruction, original_data):
                return [
                    InstructionFlag(
                        kind="TEST_FLAG",
                        reason="always flag",
                        confidence="LOW",
                    )
                ]

        orig = make_bin(256)
        mod = bytearray(orig)
        mod[50] = 0xFF
        mod = bytes(mod)

        analyzer = ECUDiffAnalyzer(orig, mod, "a.bin", "b.bin", context_size=8)
        recipe = analyzer.build_recipe()

        annotator = RecipeAnnotator()
        annotator.add_scanner(AlwaysFlagScanner())
        annotator.annotate(recipe, orig)

        assert annotator.flagged_count(recipe) == 1
        assert recipe["instructions"][0]["flags"][-1]["kind"] == "TEST_FLAG"

    def test_annotate_returns_recipe(self):
        orig = make_bin(256)
        mod = bytearray(orig)
        mod[10] = 0xFF
        mod = bytes(mod)

        analyzer = ECUDiffAnalyzer(orig, mod, "a.bin", "b.bin", context_size=8)
        recipe = analyzer.build_recipe()

        annotator = RecipeAnnotator()
        result = annotator.annotate(recipe, orig)
        assert result is recipe  # mutated in place and returned

    def test_flags_serialise_as_dicts(self):
        vin_offset = 0x100
        orig = _build_binary_with_vin(512, vin_offset)
        mod = bytearray(orig)
        for i in range(17):
            mod[vin_offset + i] = 0xAA
        mod = bytes(mod)

        analyzer = ECUDiffAnalyzer(orig, mod, "orig.bin", "mod.bin", context_size=8)
        recipe = analyzer.build_recipe()

        annotator = RecipeAnnotator()
        annotator.annotate(recipe, orig)

        for inst in recipe["instructions"]:
            for flag in inst.get("flags", []):
                assert isinstance(flag, dict)
                assert "kind" in flag
                assert "reason" in flag
                assert "confidence" in flag
                assert "action" in flag
