"""
Tests for ECUDiffAnalyzer (recipe_builder.py).

Covers:
  - find_changes: identical, single-byte, nearby merge, far separate,
                  boundary positions, custom merge_threshold
  - compute_stats: totals, percentages, single vs multi counts, empty
  - build_recipe: top-level shape, format version, instruction fields,
                  hex encoding, context capture
  - Change dataclass: offset_hex property, to_dict, description text
  - Size-mismatched binaries (only min-length compared)
"""

from tests.conftest import make_bin, make_bin_with
from openremap.core.services.recipe_builder import ECUDiffAnalyzer, Change


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_analyzer(
    orig: bytes,
    mod: bytes,
    orig_name: str = "orig.bin",
    mod_name: str = "mod.bin",
    context_size: int = 8,
) -> ECUDiffAnalyzer:
    return ECUDiffAnalyzer(orig, mod, orig_name, mod_name, context_size=context_size)


# ---------------------------------------------------------------------------
# find_changes — no differences
# ---------------------------------------------------------------------------


class TestFindChangesNoDiff:
    def test_identical_binaries_produce_no_changes(self):
        data = make_bin(1024)
        a = make_analyzer(data, data)
        a.find_changes()
        assert a.changes == []

    def test_empty_binaries_produce_no_changes(self):
        a = make_analyzer(b"", b"")
        a.find_changes()
        assert a.changes == []

    def test_find_changes_clears_previous_results(self):
        orig = make_bin_with(256, {50: 0xAA})
        mod = make_bin_with(256, {50: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes()
        assert len(a.changes) == 1
        # Second call on identical data must clear the previous result
        a.original_data = make_bin(256)
        a.modified_data = make_bin(256)
        a.find_changes()
        assert a.changes == []


# ---------------------------------------------------------------------------
# find_changes — single change
# ---------------------------------------------------------------------------


class TestFindChangesSingleByte:
    def test_single_byte_at_middle(self):
        orig = make_bin(512)
        mod = make_bin_with(512, {200: 0xFF})
        a = make_analyzer(orig, mod)
        a.find_changes()
        assert len(a.changes) == 1
        c = a.changes[0]
        assert c.offset == 200
        assert c.size == 1
        assert c.ob == "00"
        assert c.mb == "FF"

    def test_single_byte_at_offset_zero(self):
        orig = make_bin(256)
        mod = make_bin_with(256, {0: 0xAB})
        a = make_analyzer(orig, mod)
        a.find_changes()
        assert len(a.changes) == 1
        assert a.changes[0].offset == 0
        assert a.changes[0].ob == "00"
        assert a.changes[0].mb == "AB"

    def test_single_byte_at_last_position(self):
        orig = make_bin(256)
        mod = make_bin_with(256, {255: 0xCD})
        a = make_analyzer(orig, mod)
        a.find_changes()
        assert len(a.changes) == 1
        assert a.changes[0].offset == 255

    def test_two_adjacent_bytes_form_one_change(self):
        orig = make_bin(256)
        mod = make_bin_with(256, {100: 0xAA, 101: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes()
        assert len(a.changes) == 1
        c = a.changes[0]
        assert c.offset == 100
        assert c.size == 2
        assert c.ob == "0000"
        assert c.mb == "AABB"

    def test_ob_and_mb_are_uppercase_hex(self):
        orig = make_bin_with(256, {10: 0xDE, 11: 0xAD})
        mod = make_bin_with(256, {10: 0xBE, 11: 0xEF})
        a = make_analyzer(orig, mod)
        a.find_changes()
        assert len(a.changes) == 1
        c = a.changes[0]
        assert c.ob == c.ob.upper()
        assert c.mb == c.mb.upper()
        assert c.ob == "DEAD"
        assert c.mb == "BEEF"


# ---------------------------------------------------------------------------
# find_changes — merge threshold
# ---------------------------------------------------------------------------


class TestFindChangesMerge:
    def test_changes_within_threshold_merged(self):
        # 10 bytes apart, default threshold 16 → one block
        orig = make_bin(512)
        mod = make_bin_with(512, {100: 0xAA, 110: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes(merge_threshold=16)
        assert len(a.changes) == 1
        c = a.changes[0]
        assert c.offset == 100
        assert c.size == 11  # bytes 100 through 110 inclusive

    def test_changes_beyond_threshold_separate(self):
        # 400 bytes apart → two separate blocks
        orig = make_bin(512)
        mod = make_bin_with(512, {50: 0xAA, 450: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes(merge_threshold=16)
        assert len(a.changes) == 2
        assert a.changes[0].offset == 50
        assert a.changes[1].offset == 450

    def test_exactly_at_threshold_merged(self):
        # Positions 0 and 16: gap = 16, should merge (pos - end <= threshold)
        orig = make_bin(256)
        mod = make_bin_with(256, {0: 0xAA, 16: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes(merge_threshold=16)
        assert len(a.changes) == 1

    def test_one_beyond_threshold_separate(self):
        # Positions 0 and 17: gap = 17 > 16 → two blocks
        orig = make_bin(256)
        mod = make_bin_with(256, {0: 0xAA, 17: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes(merge_threshold=16)
        assert len(a.changes) == 2

    def test_custom_merge_threshold_zero_never_merges(self):
        # With threshold=0, even adjacent bytes become separate blocks
        orig = make_bin(256)
        mod = make_bin_with(256, {10: 0xAA, 11: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes(merge_threshold=0)
        assert len(a.changes) == 2

    def test_three_changes_all_within_threshold(self):
        orig = make_bin(512)
        mod = make_bin_with(512, {100: 0xAA, 108: 0xBB, 116: 0xCC})
        a = make_analyzer(orig, mod)
        a.find_changes(merge_threshold=16)
        assert len(a.changes) == 1
        c = a.changes[0]
        assert c.offset == 100
        assert c.size == 17  # 100 through 116 inclusive


# ---------------------------------------------------------------------------
# find_changes — ob and mb content correctness
# ---------------------------------------------------------------------------


class TestFindChangesContent:
    def test_ob_reflects_original_bytes(self):
        orig = make_bin_with(256, {50: 0xDE, 51: 0xAD})
        mod = make_bin_with(256, {50: 0xBE, 51: 0xEF})
        a = make_analyzer(orig, mod)
        a.find_changes()
        assert a.changes[0].ob == "DEAD"

    def test_mb_reflects_modified_bytes(self):
        orig = make_bin_with(256, {50: 0xDE, 51: 0xAD})
        mod = make_bin_with(256, {50: 0xBE, 51: 0xEF})
        a = make_analyzer(orig, mod)
        a.find_changes()
        assert a.changes[0].mb == "BEEF"

    def test_merged_block_ob_includes_unchanged_bytes_between(self):
        # Positions 100 and 110 changed, bytes 101–109 are unchanged (0x00)
        orig = make_bin(256)
        mod = make_bin_with(256, {100: 0xAA, 110: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes(merge_threshold=16)
        c = a.changes[0]
        # ob from offset 100, size 11 — original is all zeros
        assert c.ob == "00" * 11
        # mb: 0xAA, 9 zeros, 0xBB
        assert c.mb == "AA" + "00" * 9 + "BB"

    def test_mismatched_file_sizes_only_compares_up_to_min(self):
        orig = make_bin_with(512, {400: 0xFF})
        mod = make_bin(256)  # shorter — offset 400 is beyond its length
        a = make_analyzer(orig, mod)
        a.find_changes()
        # Only bytes 0..255 are compared; offset 400 is beyond min_length
        assert all(c.offset < 256 for c in a.changes)


# ---------------------------------------------------------------------------
# find_changes — context capture
# ---------------------------------------------------------------------------


class TestFindChangesContext:
    def test_context_before_captured(self):
        # Both binaries share the same known bytes at 92..99 (the ctx region).
        # Only byte 100 differs, so no merge occurs and ctx is captured correctly.
        ctx_bytes = bytes([0x11 * (i + 1) for i in range(8)])  # 11 22 33 44 55 66 77 88
        orig = bytearray(256)
        orig[92:100] = ctx_bytes
        orig = bytes(orig)
        mod = bytearray(orig)  # identical copy — same ctx region
        mod[100] = 0xFF  # only byte 100 differs
        mod = bytes(mod)
        a = make_analyzer(orig, mod, context_size=8)
        a.find_changes()
        assert len(a.changes) == 1
        c = a.changes[0]
        expected_ctx = orig[92:100].hex().upper()
        assert c.ctx == expected_ctx

    def test_context_at_offset_zero_is_empty(self):
        orig = make_bin(256)
        mod = make_bin_with(256, {0: 0xFF})
        a = make_analyzer(orig, mod, context_size=8)
        a.find_changes()
        assert a.changes[0].ctx == ""

    def test_context_after_captured(self):
        # Both binaries share the same known bytes at 101..108 (the context_after region).
        # Only byte 100 differs, so the context_after is captured from those shared bytes.
        orig = bytearray(256)
        for i in range(8):
            orig[101 + i] = 0xAA
        orig = bytes(orig)
        mod = bytearray(orig)  # identical copy — same context_after region
        mod[100] = 0xFF  # only byte 100 differs
        mod = bytes(mod)
        a = make_analyzer(orig, mod, context_size=8)
        a.find_changes()
        assert len(a.changes) == 1
        c = a.changes[0]
        expected_after = orig[101:109].hex().upper()
        assert c.context_after == expected_after

    def test_context_size_is_stored_on_change(self):
        orig = make_bin(256)
        mod = make_bin_with(256, {128: 0xFF})
        a = make_analyzer(orig, mod, context_size=16)
        a.find_changes()
        assert a.changes[0].context_size == 16


# ---------------------------------------------------------------------------
# compute_stats
# ---------------------------------------------------------------------------


class TestComputeStats:
    def test_empty_changes_returns_empty_dict(self):
        a = make_analyzer(make_bin(256), make_bin(256))
        a.find_changes()
        assert a.compute_stats() == {}

    def test_total_changes_count(self):
        orig = make_bin(1024)
        mod = make_bin_with(1024, {100: 0xAA, 600: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes()
        stats = a.compute_stats()
        assert stats["total_changes"] == 2

    def test_total_bytes_changed(self):
        orig = make_bin(512)
        mod = make_bin_with(512, {10: 0xAA, 11: 0xBB, 12: 0xCC})
        a = make_analyzer(orig, mod)
        a.find_changes()
        stats = a.compute_stats()
        assert stats["total_bytes_changed"] == 3

    def test_single_byte_change_count(self):
        orig = make_bin(512)
        mod = make_bin_with(512, {10: 0xAA, 300: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes()
        stats = a.compute_stats()
        assert stats["single_byte_changes"] == 2
        assert stats["multi_byte_changes"] == 0

    def test_multi_byte_change_count(self):
        orig = make_bin(512)
        # Two adjacent bytes → one multi-byte change
        mod = make_bin_with(512, {10: 0xAA, 11: 0xBB})
        a = make_analyzer(orig, mod)
        a.find_changes()
        stats = a.compute_stats()
        assert stats["multi_byte_changes"] == 1
        assert stats["single_byte_changes"] == 0

    def test_percentage_changed_is_correct(self):
        orig = make_bin(100)
        mod = make_bin_with(100, {0: 0xFF})  # 1 byte changed out of 100
        a = make_analyzer(orig, mod)
        a.find_changes()
        stats = a.compute_stats()
        assert stats["percentage_changed"] == 1.0

    def test_largest_and_smallest_change_size(self):
        orig = make_bin(1024)
        # One single-byte change and one 4-byte block
        mod = make_bin_with(
            1024,
            {
                10: 0xAA,  # 1 byte
                500: 0xBB,
                501: 0xCC,
                502: 0xDD,
                503: 0xEE,  # 4 bytes
            },
        )
        a = make_analyzer(orig, mod)
        a.find_changes()
        stats = a.compute_stats()
        assert stats["largest_change_size"] == 4
        assert stats["smallest_change_size"] == 1

    def test_context_size_in_stats(self):
        orig = make_bin(256)
        mod = make_bin_with(256, {50: 0xFF})
        a = make_analyzer(orig, mod, context_size=32)
        a.find_changes()
        stats = a.compute_stats()
        assert stats["context_size"] == 32


# ---------------------------------------------------------------------------
# Change dataclass
# ---------------------------------------------------------------------------


class TestChangeDataclass:
    def _make_change(self, offset=100, ob="AABB", mb="CCDD", ctx="", context_after=""):
        return Change(
            offset=offset,
            size=len(bytes.fromhex(ob)),
            ob=ob,
            mb=mb,
            ctx=ctx,
            context_after=context_after,
            context_size=len(bytes.fromhex(ctx)) if ctx else 0,
        )

    def test_offset_hex_property(self):
        c = self._make_change(offset=0x1A2B)
        assert c.offset_hex == "1A2B"

    def test_offset_hex_at_zero(self):
        c = self._make_change(offset=0)
        assert c.offset_hex == "0"

    def test_to_dict_has_all_required_keys(self):
        c = self._make_change()
        d = c.to_dict()
        for key in (
            "offset",
            "offset_hex",
            "size",
            "ob",
            "mb",
            "ctx",
            "context_after",
            "context_size",
            "description",
        ):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_values_match(self):
        c = self._make_change(offset=256, ob="DEAD", mb="BEEF")
        d = c.to_dict()
        assert d["offset"] == 256
        assert d["offset_hex"] == "100"
        assert d["ob"] == "DEAD"
        assert d["mb"] == "BEEF"
        assert d["size"] == 2

    def test_description_single_byte(self):
        c = self._make_change(offset=0x10, ob="AA", mb="BB")
        assert "Byte" in c.to_dict()["description"]
        assert "0x10" in c.to_dict()["description"]

    def test_description_multi_byte(self):
        c = self._make_change(offset=0x20, ob="AABBCC", mb="DDEEFF")
        desc = c.to_dict()["description"]
        assert "3 bytes" in desc
        assert "0x20" in desc


# ---------------------------------------------------------------------------
# build_recipe — structure and content
# ---------------------------------------------------------------------------


class TestBuildRecipe:
    def test_recipe_top_level_keys(self):
        orig = make_bin(512)
        mod = make_bin_with(512, {100: 0xFF})
        a = make_analyzer(orig, mod)
        recipe = a.build_recipe()
        assert "metadata" in recipe
        assert "ecu" in recipe
        assert "statistics" in recipe
        assert "instructions" in recipe

    def test_format_version_is_4_1(self):
        a = make_analyzer(make_bin(256), make_bin(256))
        recipe = a.build_recipe()
        assert recipe["metadata"]["format_version"] == "4.1"

    def test_openremap_envelope_present(self):
        a = make_analyzer(make_bin(256), make_bin(256))
        recipe = a.build_recipe()
        assert "openremap" in recipe
        assert recipe["openremap"]["type"] == "recipe"
        assert recipe["openremap"]["schema_version"] == "4.0"

    def test_original_and_modified_filenames_in_metadata(self):
        orig = make_bin(256)
        mod = make_bin_with(256, {10: 0xFF})
        a = make_analyzer(orig, mod, orig_name="stock.bin", mod_name="stage1.bin")
        recipe = a.build_recipe()
        assert recipe["metadata"]["original_file"] == "stock.bin"
        assert recipe["metadata"]["modified_file"] == "stage1.bin"

    def test_instruction_has_required_fields(self):
        orig = make_bin(512)
        mod = make_bin_with(512, {200: 0xAA, 201: 0xBB})
        a = make_analyzer(orig, mod)
        recipe = a.build_recipe()
        assert len(recipe["instructions"]) == 1
        inst = recipe["instructions"][0]
        for key in (
            "offset",
            "offset_hex",
            "size",
            "ob",
            "mb",
            "ctx",
            "context_after",
            "context_size",
            "description",
        ):
            assert key in inst, f"Missing instruction key: {key}"

    def test_instruction_offset_is_correct(self):
        orig = make_bin(512)
        mod = make_bin_with(512, {300: 0xFF})
        a = make_analyzer(orig, mod)
        recipe = a.build_recipe()
        assert recipe["instructions"][0]["offset"] == 300

    def test_instruction_ob_mb_are_uppercase_hex(self):
        orig = make_bin_with(256, {10: 0xDE, 11: 0xAD})
        mod = make_bin_with(256, {10: 0xBE, 11: 0xEF})
        a = make_analyzer(orig, mod)
        recipe = a.build_recipe()
        inst = recipe["instructions"][0]
        assert inst["ob"] == inst["ob"].upper()
        assert inst["mb"] == inst["mb"].upper()
        assert inst["ob"] == "DEAD"
        assert inst["mb"] == "BEEF"

    def test_no_changes_produces_empty_instructions(self):
        data = make_bin(256)
        a = make_analyzer(data, data)
        recipe = a.build_recipe()
        assert recipe["instructions"] == []
        assert recipe["statistics"] == {}

    def test_ecu_block_has_file_size(self):
        orig = make_bin(1024)
        mod = make_bin_with(1024, {50: 0xFF})
        a = make_analyzer(orig, mod)
        recipe = a.build_recipe()
        assert recipe["ecu"]["file_size"] == 1024

    def test_multiple_instructions_ordered_by_offset(self):
        orig = make_bin(1024)
        mod = make_bin_with(1024, {100: 0xAA, 800: 0xBB})
        a = make_analyzer(orig, mod)
        recipe = a.build_recipe()
        offsets = [i["offset"] for i in recipe["instructions"]]
        assert offsets == sorted(offsets)

    def test_statistics_block_is_populated_when_changes_exist(self):
        orig = make_bin(512)
        mod = make_bin_with(512, {10: 0xFF})
        a = make_analyzer(orig, mod)
        recipe = a.build_recipe()
        stats = recipe["statistics"]
        assert stats.get("total_changes", 0) >= 1
        assert "total_bytes_changed" in stats

    def test_build_recipe_calls_find_changes_implicitly(self):
        # build_recipe should work even if find_changes was never called directly
        orig = make_bin(256)
        mod = make_bin_with(256, {50: 0xCC})
        a = ECUDiffAnalyzer(orig, mod, "a.bin", "b.bin")
        # Do NOT call find_changes manually
        recipe = a.build_recipe()
        assert len(recipe["instructions"]) == 1
