"""
Nuclear collision-safety test suite for ECUPatcher.

Core question answered
----------------------
If the same byte pattern (ob) exists in an ECU binary at multiple locations —
for example, in both the engine calibration map AND an ABS / safety-control
region — will the patcher accidentally write to the wrong address?

Short answer: No.  Here is why, proved exhaustively below.

  1. Strict pre-flight validation checks ob at the EXACT recorded offset.
     Any mismatch on ANY instruction aborts the entire operation — nothing
     is ever written to the buffer.

  2. The patcher searches for ``ctx + ob`` (not ob alone) within a
     ±EXACT_WINDOW (±2 048 bytes) window around the expected offset.
     This restricts the search space and requires matching the full context
     anchor, not just the payload bytes.

  3. When multiple ctx+ob matches exist in the window, the one CLOSEST to
     the expected offset is chosen.  Because strict validation already
     confirmed ob is at the EXACT offset (distance = 0), that match always
     wins over any shifted duplicate inside the window.

  4. A frozen read-only snapshot is used for ALL searches.  Earlier writes
     to the mutable buffer cannot corrupt context windows for later
     instructions and cannot synthesise new false ctx+ob anchors.

Real gaps also covered and guarded by the updated patcher:

  5. Overlapping write regions — two instructions writing to the same bytes.
     The patcher now raises ValueError BEFORE any bytes are written.

  6. Ambiguous matches — when multiple ctx+ob patterns are found in the
     window, PatchResult.ambiguous is set to True so callers can investigate.

Test classes
------------
  TestCollisionOutsideWindow        — far-away duplicate ob is silently ignored
  TestCollisionInsideWindow         — nearby duplicate ob but exact offset wins
  TestSameObDifferentCtx            — same ob, different ctx → two safe regions
  TestEmptyCtxWithDuplicateOb       — ctx-less fallback uses exact offset only
  TestRealisticEngineVsABS          — full engine-vs-safety-system simulation
  TestOverlappingInstructions       — raises before any write; buffer stays clean
  TestAdjacentInstructions          — adjacent (non-overlapping) writes are fine
  TestSnapshotIsolationCollision    — writes cannot create false ctx+ob anchors
  TestAmbiguousMatchFlag            — PatchResult.ambiguous and ambiguous_count()
  TestExistenceValidatorAmbiguity   — ECUExistenceValidator reports all hit sites
  TestNoCollateralDamage            — bytes around each write target are untouched
  TestOverlapEdgeCases              — boundary conditions for overlap detection
  TestSkipValidationCollisionRisk   — documents the one genuinely unsafe path
"""

from __future__ import annotations

import pytest

from tests.conftest import make_recipe, make_instruction
from openremap.core.services.patcher import ECUPatcher, PatchStatus, EXACT_WINDOW
from openremap.core.services.validate_exists import ECUExistenceValidator, MatchStatus


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _build(size: int, placements: dict) -> bytes:
    """
    Zero-filled binary of *size* bytes with specific byte sequences written
    at given absolute offsets.

        placements = {offset: bytes | int}

    int values are written as a single byte; bytes values are written verbatim.
    """
    buf = bytearray(size)
    for off, data in placements.items():
        if isinstance(data, int):
            buf[off] = data
        else:
            buf[off : off + len(data)] = data
    return bytes(buf)


def _patcher(
    data: bytes,
    instructions: list,
    ecu: dict | None = None,
    skip: bool = False,
) -> ECUPatcher:
    recipe = make_recipe(instructions, ecu=ecu)
    return ECUPatcher(data, recipe, skip_validation=skip)


def _existence(data: bytes, instructions: list) -> ECUExistenceValidator:
    return ECUExistenceValidator(data, make_recipe(instructions))


def _inst(offset: int, ob: bytes, mb: bytes, ctx: bytes = b"") -> dict:
    return make_instruction(
        offset,
        ob.hex().upper(),
        mb.hex().upper(),
        ctx.hex().upper(),
    )


# ===========================================================================
# 1 — Collision outside ±EXACT_WINDOW — duplicate ob is simply not scanned
# ===========================================================================


class TestCollisionOutsideWindow:
    """
    A second occurrence of ctx+ob located beyond ±EXACT_WINDOW from the
    expected offset is never reached by the search — it cannot be written.
    """

    CTX = bytes.fromhex("DEADBEEF")
    OB = bytes.fromhex("CAFEBABE")
    MB = bytes.fromhex("CAFEDEAD")
    EXPECTED = 500
    # Place the second occurrence well outside the ±2 048-byte window.
    SECOND = EXPECTED + EXACT_WINDOW + 1_000  # 3 548

    def _data(self) -> bytes:
        return _build(
            size=8_000,
            placements={
                self.EXPECTED - 4: self.CTX,
                self.EXPECTED: self.OB,
                self.SECOND - 4: self.CTX,
                self.SECOND: self.OB,
            },
        )

    def _instructions(self) -> list:
        return [_inst(self.EXPECTED, self.OB, self.MB, self.CTX)]

    def test_correct_offset_is_patched(self):
        result = _patcher(self._data(), self._instructions()).apply_all()
        assert result[self.EXPECTED : self.EXPECTED + 4] == self.MB

    def test_outside_window_location_untouched(self):
        result = _patcher(self._data(), self._instructions()).apply_all()
        assert result[self.SECOND : self.SECOND + 4] == self.OB

    def test_ctx_bytes_at_outside_location_untouched(self):
        result = _patcher(self._data(), self._instructions()).apply_all()
        ctx_start = self.SECOND - 4
        assert result[ctx_start : self.SECOND] == self.CTX

    def test_shift_is_zero_exact_match(self):
        p = _patcher(self._data(), self._instructions())
        p.apply_all()
        assert p.results[0].shift == 0

    def test_result_is_success(self):
        p = _patcher(self._data(), self._instructions())
        p.apply_all()
        assert p.results[0].status == PatchStatus.SUCCESS

    def test_32kb_away_second_occurrence_never_touched(self):
        """32 KB distance is 16× beyond the search window — fully out of reach."""
        ctx = bytes.fromhex("11223344")
        ob = bytes.fromhex("AABBCCDD")
        mb = bytes.fromhex("EEFF0011")
        expected = 1_000
        far = expected + 32_768

        data = _build(
            size=65_536,
            placements={
                expected - 4: ctx,
                expected: ob,
                far - 4: ctx,
                far: ob,
            },
        )
        result = _patcher(data, [_inst(expected, ob, mb, ctx)]).apply_all()
        assert result[expected : expected + 4] == mb
        assert result[far : far + 4] == ob


# ===========================================================================
# 2 — Collision inside ±EXACT_WINDOW — exact offset (distance 0) always wins
# ===========================================================================


class TestCollisionInsideWindow:
    """
    Even when a second (and third) ctx+ob pattern exists within the
    ±EXACT_WINDOW search window, the one at the exact recorded offset
    (distance = 0 from expected) is chosen every time.
    """

    CTX = bytes.fromhex("AABBCCDD")
    OB = bytes.fromhex("11223344")
    MB = bytes.fromhex("EEFF0011")
    EXPECTED = 1_000
    SHIFT = 200  # second occurrence 200 bytes forward — inside window

    def _data(self) -> bytes:
        second = self.EXPECTED + self.SHIFT
        return _build(
            size=8_000,
            placements={
                self.EXPECTED - 4: self.CTX,
                self.EXPECTED: self.OB,
                second - 4: self.CTX,
                second: self.OB,
            },
        )

    def _inst_list(self) -> list:
        return [_inst(self.EXPECTED, self.OB, self.MB, self.CTX)]

    def test_exact_offset_patched(self):
        second = self.EXPECTED + self.SHIFT
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.EXPECTED : self.EXPECTED + 4] == self.MB
        assert result[second : second + 4] == self.OB  # shifted copy untouched

    def test_shift_is_zero(self):
        p = _patcher(self._data(), self._inst_list())
        p.apply_all()
        assert p.results[0].shift == 0

    def test_offset_found_equals_expected(self):
        p = _patcher(self._data(), self._inst_list())
        p.apply_all()
        assert p.results[0].offset_found == self.EXPECTED

    def test_three_copies_in_window_exact_wins(self):
        """Three copies of ctx+ob in the window — distance-0 copy still wins."""
        ctx = bytes.fromhex("CAFECAFE")
        ob = bytes.fromhex("DEADBEEF")
        mb = bytes.fromhex("FFFF0000")
        expected = 2_000
        data = _build(
            size=8_000,
            placements={
                expected - 100 - 4: ctx,
                expected - 100: ob,  # −100 bytes
                expected - 4: ctx,
                expected: ob,  # exact ← correct
                expected + 100 - 4: ctx,
                expected + 100: ob,  # +100 bytes
            },
        )
        result = _patcher(data, [_inst(expected, ob, mb, ctx)]).apply_all()
        assert result[expected : expected + 4] == mb
        assert result[expected - 100 : expected - 96] == ob
        assert result[expected + 100 : expected + 104] == ob


# ===========================================================================
# 3 — Same ob, different ctx → two separate regions each written correctly
# ===========================================================================


class TestSameObDifferentCtx:
    """
    Two instructions that share identical ob bytes but have different context
    (ctx) bytes, each pointing to a different region of the binary, must be
    applied independently without cross-contamination.

    This is the canonical 'engine map vs ABS map' scenario — same calibration
    value appearing in two different subsystems.
    """

    OB = bytes.fromhex("01020304")
    MB1 = bytes.fromhex("AABBCCDD")  # applied to region 1
    MB2 = bytes.fromhex("11223344")  # applied to region 2
    CTX1 = bytes.fromhex("DEAD0000")  # unique context for region 1
    CTX2 = bytes.fromhex("BEEF0000")  # unique context for region 2
    OFF1 = 300
    OFF2 = 4_000

    def _data(self) -> bytes:
        return _build(
            size=8_000,
            placements={
                self.OFF1 - 4: self.CTX1,
                self.OFF1: self.OB,
                self.OFF2 - 4: self.CTX2,
                self.OFF2: self.OB,
            },
        )

    def _inst_list(self) -> list:
        return [
            _inst(self.OFF1, self.OB, self.MB1, self.CTX1),
            _inst(self.OFF2, self.OB, self.MB2, self.CTX2),
        ]

    def test_region1_receives_mb1(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.OFF1 : self.OFF1 + 4] == self.MB1

    def test_region2_receives_mb2(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.OFF2 : self.OFF2 + 4] == self.MB2

    def test_ctx_bytes_of_region1_untouched(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.OFF1 - 4 : self.OFF1] == self.CTX1

    def test_ctx_bytes_of_region2_untouched(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.OFF2 - 4 : self.OFF2] == self.CTX2

    def test_no_cross_contamination_mb1_not_in_region2(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.OFF2 : self.OFF2 + 4] != self.MB1

    def test_no_cross_contamination_mb2_not_in_region1(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.OFF1 : self.OFF1 + 4] != self.MB2

    def test_both_results_are_success(self):
        p = _patcher(self._data(), self._inst_list())
        p.apply_all()
        assert all(r.status == PatchStatus.SUCCESS for r in p.results)

    def test_both_shifts_are_zero(self):
        p = _patcher(self._data(), self._inst_list())
        p.apply_all()
        assert all(r.shift == 0 for r in p.results)


# ===========================================================================
# 4 — Empty ctx with duplicate ob — exact-offset fallback is safe
# ===========================================================================


class TestEmptyCtxWithDuplicateOb:
    """
    When ctx is empty the patcher falls back to a direct snapshot read at
    the expected offset.  This is a pure address-pinned comparison — no
    searching — so duplicate ob bytes elsewhere cannot affect the result.
    """

    OB = bytes.fromhex("AABB")
    MB = bytes.fromhex("CCDD")
    OFF = 200

    def _data_with_duplicates(self) -> bytes:
        """ob exists at multiple offsets; none of the extras should be touched."""
        return _build(
            size=2_048,
            placements={
                self.OFF: self.OB,  # target
                500: self.OB,  # duplicate 1
                800: self.OB,  # duplicate 2
                1_200: self.OB,  # duplicate 3
            },
        )

    def _inst_list(self) -> list:
        return [_inst(self.OFF, self.OB, self.MB)]  # empty ctx

    def test_target_offset_written(self):
        result = _patcher(self._data_with_duplicates(), self._inst_list()).apply_all()
        assert result[self.OFF : self.OFF + 2] == self.MB

    def test_duplicate_at_500_untouched(self):
        result = _patcher(self._data_with_duplicates(), self._inst_list()).apply_all()
        assert result[500:502] == self.OB

    def test_duplicate_at_800_untouched(self):
        result = _patcher(self._data_with_duplicates(), self._inst_list()).apply_all()
        assert result[800:802] == self.OB

    def test_duplicate_at_1200_untouched(self):
        result = _patcher(self._data_with_duplicates(), self._inst_list()).apply_all()
        assert result[1_200:1_202] == self.OB

    def test_result_is_success(self):
        p = _patcher(self._data_with_duplicates(), self._inst_list())
        p.apply_all()
        assert p.results[0].status == PatchStatus.SUCCESS


# ===========================================================================
# 5 — Realistic engine vs ABS simulation
# ===========================================================================


class TestRealisticEngineVsABS:
    """
    Simulates an ECU binary where the engine tuning calibration table and a
    safety-system control block (ABS modulator gains) happen to share an
    identical byte sequence.  Proves the patcher modifies only the intended
    engine region.

    Layout (512 KB ECU binary):
        0x08000 — engine injection map    ← recipe targets this
        0x3A000 — ABS modulator gains     ← must remain untouched
    """

    # Shared byte pattern (same calibration value in two subsystems)
    SHARED_OB = bytes.fromhex("3C0000003C00000000000000")
    MODIFIED = bytes.fromhex("400000004000000000000000")

    # Unique context bytes for each region
    ENGINE_CTX = bytes.fromhex("42006F73636800000000FFFF")
    ABS_CTX = bytes.fromhex("414253436F6E74726F6C6572")

    ENGINE_OFF = 0x08010
    ABS_OFF = 0x3A010

    BIN_SIZE = 512 * 1024  # 512 KB

    def _data(self) -> bytes:
        return _build(
            size=self.BIN_SIZE,
            placements={
                self.ENGINE_OFF - len(self.ENGINE_CTX): self.ENGINE_CTX,
                self.ENGINE_OFF: self.SHARED_OB,
                self.ABS_OFF - len(self.ABS_CTX): self.ABS_CTX,
                self.ABS_OFF: self.SHARED_OB,
            },
        )

    def _inst_list(self) -> list:
        return [_inst(self.ENGINE_OFF, self.SHARED_OB, self.MODIFIED, self.ENGINE_CTX)]

    def test_engine_region_receives_modified_bytes(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.ENGINE_OFF : self.ENGINE_OFF + 12] == self.MODIFIED

    def test_abs_region_untouched(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        assert result[self.ABS_OFF : self.ABS_OFF + 12] == self.SHARED_OB

    def test_abs_context_header_untouched(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        ctx_start = self.ABS_OFF - len(self.ABS_CTX)
        assert result[ctx_start : self.ABS_OFF] == self.ABS_CTX

    def test_engine_context_header_untouched(self):
        result = _patcher(self._data(), self._inst_list()).apply_all()
        ctx_start = self.ENGINE_OFF - len(self.ENGINE_CTX)
        assert result[ctx_start : self.ENGINE_OFF] == self.ENGINE_CTX

    def test_gap_between_regions_untouched(self):
        """Every byte between the engine region and ABS region stays zero."""
        result = _patcher(self._data(), self._inst_list()).apply_all()
        mid_start = self.ENGINE_OFF + 12
        mid_end = self.ABS_OFF - len(self.ABS_CTX)
        assert result[mid_start:mid_end] == b"\x00" * (mid_end - mid_start)

    def test_result_shift_zero_and_success(self):
        p = _patcher(self._data(), self._inst_list())
        p.apply_all()
        r = p.results[0]
        assert r.status == PatchStatus.SUCCESS
        assert r.shift == 0


# ===========================================================================
# 6 — Overlapping write regions — raises BEFORE any byte is written
# ===========================================================================


class TestOverlappingInstructions:
    """
    Two instructions whose write ranges share at least one byte must be
    rejected immediately — before any write touches the buffer.

    The overlap detection runs after strict pre-flight but before the apply
    loop, so the buffer is ALWAYS clean when the ValueError is raised.
    """

    def _overlapping_data(self) -> bytes:
        """Binary where both ob patterns exist at their respective offsets."""
        buf = bytearray(1_024)
        buf[100:104] = (
            b"\xaa\xbb\x11\x00"  # inst-1 ob at [100:102], inst-2 ob at [101:103]
        )
        return bytes(buf)

    def test_raises_value_error(self):
        """Two instructions with overlapping ranges → ValueError."""
        data = self._overlapping_data()
        with pytest.raises(ValueError, match="overlapping"):
            _patcher(
                data,
                [
                    make_instruction(100, "AABB", "CCDD"),
                    make_instruction(101, "BB11", "EEFF"),
                ],
                skip=True,
            ).apply_all()

    def test_buffer_unchanged_after_rejection(self):
        """No bytes must be written to the buffer before the raise."""
        data = self._overlapping_data()
        recipe = make_recipe(
            [
                make_instruction(100, "AABB", "CCDD"),
                make_instruction(101, "BB11", "EEFF"),
            ]
        )
        patcher = ECUPatcher(data, recipe, skip_validation=True)
        with pytest.raises(ValueError):
            patcher.apply_all()
        # Buffer must still match original
        assert bytes(patcher._buffer) == data

    def test_error_message_names_both_instructions(self):
        data = self._overlapping_data()
        with pytest.raises(ValueError) as exc_info:
            _patcher(
                data,
                [
                    make_instruction(100, "AABB", "CCDD"),
                    make_instruction(101, "BB11", "EEFF"),
                ],
                skip=True,
            ).apply_all()
        msg = str(exc_info.value)
        assert "#1" in msg
        assert "#2" in msg

    def test_exact_same_offset_two_instructions_raises(self):
        """Two instructions pointing to exactly the same offset."""
        buf = bytearray(512)
        buf[200:202] = b"\xaa\xbb"
        data = bytes(buf)
        with pytest.raises(ValueError, match="overlapping"):
            _patcher(
                data,
                [
                    make_instruction(200, "AABB", "CCDD"),
                    make_instruction(200, "AABB", "EEFF"),
                ],
                skip=True,
            ).apply_all()

    def test_partial_overlap_one_byte_raises(self):
        """Even a single shared byte must trigger the error."""
        buf = bytearray(512)
        buf[100:103] = b"\xaa\xbb\xcc"
        data = bytes(buf)
        # inst-1 covers [100,101], inst-2 covers [101,102] — share byte 101
        with pytest.raises(ValueError, match="overlapping"):
            _patcher(
                data,
                [
                    make_instruction(100, "AABB", "CCDD"),
                    make_instruction(101, "BBCC", "EEFF"),
                ],
                skip=True,
            ).apply_all()

    def test_three_instructions_two_pairs_overlap_detected(self):
        """Three instructions where two distinct pairs overlap."""
        buf = bytearray(1_024)
        buf[100:106] = b"\xaa\xbb\xcc\xdd\xee\xff"
        data = bytes(buf)
        with pytest.raises(ValueError) as exc_info:
            _patcher(
                data,
                [
                    make_instruction(100, "AABB", "1122"),
                    make_instruction(101, "BBCC", "3344"),
                    make_instruction(103, "DDEEFF", "556677"),
                ],
                skip=True,
            ).apply_all()
        # At least one overlapping pair reported
        assert "overlapping" in str(exc_info.value).lower()


# ===========================================================================
# 7 — Adjacent (non-overlapping) instructions — always fine
# ===========================================================================


class TestAdjacentInstructions:
    """
    Instructions whose write ranges are immediately adjacent — end of one is
    exactly start of the next — share no bytes and must never trigger an
    overlap error.
    """

    def test_two_adjacent_instructions_both_applied(self):
        buf = bytearray(1_024)
        buf[100:102] = b"\xaa\xbb"
        buf[102:104] = b"\xcc\xdd"
        data = bytes(buf)
        result = _patcher(
            data,
            [
                make_instruction(100, "AABB", "1122"),
                make_instruction(102, "CCDD", "3344"),
            ],
            skip=True,
        ).apply_all()
        assert result[100:102] == bytes.fromhex("1122")
        assert result[102:104] == bytes.fromhex("3344")

    def test_five_adjacent_instructions_all_applied(self):
        buf = bytearray(1_024)
        for i in range(5):
            buf[200 + i] = 0xAA
        data = bytes(buf)
        instructions = [make_instruction(200 + i, "AA", "BB") for i in range(5)]
        result = _patcher(data, instructions, skip=True).apply_all()
        assert result[200:205] == b"\xbb" * 5

    def test_adjacent_does_not_raise(self):
        buf = bytearray(512)
        buf[10:12] = b"\x01\x02"
        buf[12:14] = b"\x03\x04"
        data = bytes(buf)
        # Should not raise
        _patcher(
            data,
            [
                make_instruction(10, "0102", "AABB"),
                make_instruction(12, "0304", "CCDD"),
            ],
            skip=True,
        ).apply_all()

    def test_gap_between_instructions_untouched(self):
        buf = bytearray(1_024)
        buf[100] = 0xAA
        buf[105] = 0xBB
        data = bytes(buf)
        result = _patcher(
            data,
            [
                make_instruction(100, "AA", "CC"),
                make_instruction(105, "BB", "DD"),
            ],
            skip=True,
        ).apply_all()
        assert result[101:105] == b"\x00" * 4  # gap bytes unchanged


# ===========================================================================
# 8 — Snapshot isolation: writes cannot synthesise false ctx+ob anchors
# ===========================================================================


class TestSnapshotIsolationCollision:
    """
    Instruction 1 writes bytes that — if the snapshot were mutable — would
    create a new ctx+ob match for instruction 2 at a WRONG location.
    The frozen snapshot prevents this: instruction 2 always searches the
    original bytes, never the already-modified buffer.
    """

    def test_earlier_write_does_not_create_false_anchor_for_later_instruction(self):
        """
        Layout in the original binary:
            [96:100]   = CTX_A = AABBCCDD  ← ctx anchor for instruction 1
            [100:104]  = OB_A  = 11223344  ← instruction 1 target
            [196:200]  = CTX_A = AABBCCDD  ← ctx anchor for instruction 2
            [200:204]  = OB_B  = 55667788  ← instruction 2 target

        Instruction 1 writes MB_A = AABBCCDD (= CTX_A) at [100:104].

        After that write the buffer has CTX_A at BOTH [96:100] and [100:104].
        If instruction 2 searched the buffer it would find a second CTX_A+…
        pattern starting at [100:104] — but since [104:108] is all zeros (not
        OB_B), no false anchor is created there anyway.

        The key guarantee is simpler: the frozen snapshot always finds the
        real anchor CTX_A+OB_B at [196:204] and writes OB_B→MB_B at 200.
        Neither instruction interferes with the other.
        """
        ctx_a = bytes.fromhex("AABBCCDD")
        ob_a = bytes.fromhex("11223344")
        mb_a = ctx_a  # deliberately writes CTX_A into the buffer at [100:104]

        ob_b = bytes.fromhex("55667788")
        mb_b = bytes.fromhex("FFFFFFFF")

        data = _build(
            size=1_024,
            placements={
                96: ctx_a,  # ctx for instruction 1
                100: ob_a,  # instruction 1 target
                196: ctx_a,  # ctx for instruction 2
                200: ob_b,  # instruction 2 target
            },
        )
        result = _patcher(
            data,
            [
                _inst(100, ob_a, mb_a, ctx_a),
                _inst(200, ob_b, mb_b, ctx_a),
            ],
            skip=True,
        ).apply_all()

        assert result[100:104] == mb_a  # instruction 1 wrote correctly
        assert result[200:204] == mb_b  # instruction 2 wrote correctly
        assert result[196:200] == ctx_a  # instruction 2's ctx bytes untouched

    def test_snapshot_not_affected_by_multi_instruction_pipeline(self):
        """
        After apply_all, the internal snapshot must still equal the original
        binary — the frozen snapshot is never mutated.
        """
        buf = bytearray(512)
        buf[100] = 0xAA
        buf[200] = 0xBB
        data = bytes(buf)
        p = _patcher(
            data,
            [
                make_instruction(100, "AA", "CC"),
                make_instruction(200, "BB", "DD"),
            ],
            skip=True,
        )
        p.apply_all()
        assert p._snapshot == data  # unchanged
        assert p._snapshot[100] == 0xAA
        assert p._snapshot[200] == 0xBB

    def test_write_to_ctx_region_of_instruction_does_not_invalidate_later_sibling(self):
        """
        Instruction 1 writes to a region that overlaps the ctx bytes used by
        instruction 2.  Because instruction 2 searches the frozen snapshot,
        its ctx is still found and its ob is still matched.
        """
        ctx = bytes.fromhex("CAFECAFE")
        ob1 = bytes.fromhex(
            "DEADBEEF"
        )  # instruction 1 payload — lives inside future ctx zone
        ob2 = bytes.fromhex("12345678")
        mb1 = bytes.fromhex("AAAABBBB")
        mb2 = bytes.fromhex("CCCCDDDD")

        # Layout: [0:4]=ob1  [4:8]=ctx  [8:12]=ob2
        # Instruction 1 targets offset 0 (no ctx)
        # Instruction 2 targets offset 8 with ctx at [4:8]
        data = _build(
            size=1_024,
            placements={0: ob1, 4: ctx, 8: ob2},
        )
        result = _patcher(
            data,
            [
                _inst(0, ob1, mb1),  # no ctx — direct snapshot read
                _inst(8, ob2, mb2, ctx),  # ctx at [4:8] in snapshot
            ],
            skip=True,
        ).apply_all()
        assert result[0:4] == mb1
        assert result[8:12] == mb2


# ===========================================================================
# 9 — Ambiguous match flag
# ===========================================================================


class TestAmbiguousMatchFlag:
    """
    When multiple ctx+ob patterns exist within the ±EXACT_WINDOW search window,
    the correct (closest/exact) one is still chosen, but PatchResult.ambiguous
    is set to True to alert the caller.
    """

    def _ambiguous_data(self) -> tuple[bytes, int, bytes, bytes, bytes]:
        ctx = bytes.fromhex("FACEFEED")
        ob = bytes.fromhex("BEADCAFE")
        mb = bytes.fromhex("DEADC0DE")
        expected = 1_000
        # Second copy 150 bytes away — inside the ±2 048 window
        second = expected + 150
        data = _build(
            size=8_000,
            placements={
                expected - 4: ctx,
                expected: ob,
                second - 4: ctx,
                second: ob,
            },
        )
        return data, expected, ob, mb, ctx

    def test_ambiguous_flag_set_when_multiple_matches_in_window(self):
        data, expected, ob, mb, ctx = self._ambiguous_data()
        p = _patcher(data, [_inst(expected, ob, mb, ctx)])
        p.apply_all()
        assert p.results[0].ambiguous is True

    def test_correct_offset_still_written_despite_ambiguity(self):
        data, expected, ob, mb, ctx = self._ambiguous_data()
        second = expected + 150
        result = _patcher(data, [_inst(expected, ob, mb, ctx)]).apply_all()
        assert result[expected : expected + 4] == mb
        assert result[second : second + 4] == ob  # other copy untouched

    def test_ambiguous_count_reflects_number_of_ambiguous_instructions(self):
        data, expected, ob, mb, ctx = self._ambiguous_data()
        p = _patcher(data, [_inst(expected, ob, mb, ctx)])
        p.apply_all()
        assert p.ambiguous_count() == 1

    def test_no_ambiguity_when_single_match_in_window(self):
        ctx = bytes.fromhex("11111111")
        ob = bytes.fromhex("22222222")
        mb = bytes.fromhex("33333333")
        data = _build(
            size=1_024,
            placements={96: ctx, 100: ob},
        )
        p = _patcher(data, [_inst(100, ob, mb, ctx)])
        p.apply_all()
        assert p.results[0].ambiguous is False
        assert p.ambiguous_count() == 0

    def test_ambiguous_flag_false_for_empty_ctx_path(self):
        """ctx-less fallback is a direct read — never ambiguous."""
        buf = bytearray(512)
        buf[200:202] = b"\xaa\xbb"
        buf[300:302] = b"\xaa\xbb"  # duplicate, but ctx path not taken
        data = bytes(buf)
        p = _patcher(
            data, [_inst(200, bytes.fromhex("AABB"), bytes.fromhex("CCDD"))], skip=True
        )
        p.apply_all()
        assert p.results[0].ambiguous is False

    def test_ambiguous_warning_in_message_string(self):
        data, expected, ob, mb, ctx = self._ambiguous_data()
        p = _patcher(data, [_inst(expected, ob, mb, ctx)])
        p.apply_all()
        assert "WARNING" in p.results[0].message

    def test_ambiguous_count_zero_with_empty_instructions(self):
        data = bytes(512)
        p = _patcher(data, [], skip=True)
        p.apply_all()
        assert p.ambiguous_count() == 0

    def test_to_dict_includes_ambiguous_in_summary(self):
        data, expected, ob, mb, ctx = self._ambiguous_data()
        p = _patcher(data, [_inst(expected, ob, mb, ctx)])
        patched = p.apply_all()
        report = p.to_dict(patched)
        assert "ambiguous" in report["summary"]
        assert report["summary"]["ambiguous"] == 1


# ===========================================================================
# 10 — ExistenceValidator reports all hit locations for duplicate ob
# ===========================================================================


class TestExistenceValidatorAmbiguity:
    """
    ECUExistenceValidator._find_all() searches the ENTIRE binary for ob.
    When ob appears at multiple locations, all of them are recorded in
    ExistenceResult.offsets_found so a human can review the ambiguity.
    """

    OB = bytes.fromhex("AABBCCDD")
    OFF = 500

    def _data_with_n_copies(self, n: int, spacing: int = 1_000) -> bytes:
        placements = {self.OFF + i * spacing: self.OB for i in range(n)}
        return _build(size=65_536, placements=placements)

    def test_single_occurrence_offsets_found_has_one_entry(self):
        data = _build(size=1_024, placements={self.OFF: self.OB})
        v = _existence(data, [_inst(self.OFF, self.OB, bytes.fromhex("11223344"))])
        v.validate_all()
        assert len(v.results[0].offsets_found) == 1
        assert v.results[0].offsets_found[0] == self.OFF

    def test_two_occurrences_both_in_offsets_found(self):
        second = self.OFF + 1_000
        data = _build(size=4_096, placements={self.OFF: self.OB, second: self.OB})
        v = _existence(data, [_inst(self.OFF, self.OB, bytes.fromhex("11223344"))])
        v.validate_all()
        found = v.results[0].offsets_found
        assert self.OFF in found
        assert second in found
        assert len(found) == 2

    def test_status_is_exact_when_one_of_many_matches_expected_offset(self):
        second = self.OFF + 2_000
        data = _build(size=8_192, placements={self.OFF: self.OB, second: self.OB})
        v = _existence(data, [_inst(self.OFF, self.OB, bytes.fromhex("11223344"))])
        v.validate_all()
        assert v.results[0].status == MatchStatus.EXACT

    def test_five_occurrences_all_recorded(self):
        data = self._data_with_n_copies(5)
        v = _existence(data, [_inst(self.OFF, self.OB, bytes.fromhex("11223344"))])
        v.validate_all()
        assert len(v.results[0].offsets_found) == 5

    def test_multiple_occurrences_verdict_is_safe_exact(self):
        """Multiple hits do NOT downgrade the verdict — it is still safe_exact
        because ob IS at the expected offset."""
        data = self._data_with_n_copies(3)
        v = _existence(data, [_inst(self.OFF, self.OB, bytes.fromhex("11223344"))])
        v.validate_all()
        assert v.results[0].status == MatchStatus.EXACT
        assert v.verdict() == "safe_exact"

    def test_shifted_result_has_all_offsets_in_offsets_found(self):
        """When ob is NOT at the expected offset, all actual locations are listed."""
        actual_off = 700
        data = _build(size=2_048, placements={actual_off: self.OB})
        v = _existence(data, [_inst(self.OFF, self.OB, bytes.fromhex("11223344"))])
        v.validate_all()
        assert v.results[0].status == MatchStatus.SHIFTED
        assert actual_off in v.results[0].offsets_found


# ===========================================================================
# 11 — No collateral damage — surrounding bytes are never touched
# ===========================================================================


class TestNoCollateralDamage:
    """
    Bytes immediately before and after each write target must be completely
    unchanged after patching.  This verifies the write is strictly bounded
    to the [offset : offset + len(mb)] range.
    """

    SENTINEL_BEFORE = bytes.fromhex("FEED")
    SENTINEL_AFTER = bytes.fromhex("CAFE")

    def _data_with_sentinels(self, off: int, ob: bytes) -> bytes:
        return _build(
            size=4_096,
            placements={
                off - 2: self.SENTINEL_BEFORE,
                off: ob,
                off + len(ob): self.SENTINEL_AFTER,
            },
        )

    def test_sentinel_bytes_before_target_untouched(self):
        ob = bytes.fromhex("DEADBEEF")
        mb = bytes.fromhex("CAFED00D")
        off = 200
        data = self._data_with_sentinels(off, ob)
        result = _patcher(data, [_inst(off, ob, mb)]).apply_all()
        assert result[off - 2 : off] == self.SENTINEL_BEFORE

    def test_sentinel_bytes_after_target_untouched(self):
        ob = bytes.fromhex("DEADBEEF")
        mb = bytes.fromhex("CAFED00D")
        off = 200
        data = self._data_with_sentinels(off, ob)
        result = _patcher(data, [_inst(off, ob, mb)]).apply_all()
        assert result[off + 4 : off + 6] == self.SENTINEL_AFTER

    def test_write_size_equals_ob_size(self):
        """Number of changed bytes must equal len(ob) — no bleed."""
        ob = bytes.fromhex("AABBCCDDEEFF")  # 6 bytes
        mb = bytes.fromhex("112233445566")
        off = 300
        data = _build(size=1_024, placements={off: ob})
        result = _patcher(data, [_inst(off, ob, mb)]).apply_all()
        changed = sum(1 for i in range(len(data)) if result[i] != data[i])
        assert changed == 6

    def test_large_binary_zero_bytes_outside_write_range(self):
        """In a 512 KB zero-filled binary, patching one region leaves everything
        else at zero."""
        ob = bytes.fromhex("DEADBEEF")
        mb = bytes.fromhex("CAFECAFE")
        off = 0x20000  # 128 KB into the binary

        data = _build(size=512 * 1_024, placements={off: ob})
        result = _patcher(data, [_inst(off, ob, mb)]).apply_all()

        before = result[:off]
        after = result[off + 4 :]
        assert before == b"\x00" * off
        assert after == b"\x00" * len(after)

    def test_two_instructions_each_bounded(self):
        ob = bytes.fromhex("1234")
        mb = bytes.fromhex("ABCD")
        data = _build(
            size=1_024,
            placements={
                100: bytes.fromhex("FF"),  # sentinel before inst-1
                101: ob,
                103: bytes.fromhex("FF"),  # sentinel between
                200: ob,
                202: bytes.fromhex("FF"),  # sentinel after inst-2
            },
        )
        result = _patcher(
            data,
            [
                make_instruction(101, "1234", "ABCD"),
                make_instruction(200, "1234", "ABCD"),
            ],
            skip=True,
        ).apply_all()
        assert result[100] == 0xFF
        assert result[103] == 0xFF
        assert result[202] == 0xFF


# ===========================================================================
# 12 — Overlap edge cases
# ===========================================================================


class TestOverlapEdgeCases:
    """
    Boundary conditions for _find_overlapping_instructions:
    adjacent (end+1 = start) must NOT be flagged; any shared byte must be.
    """

    def test_no_instructions_no_overlap(self):
        p = _patcher(bytes(512), [], skip=True)
        assert p._find_overlapping_instructions([]) == []

    def test_single_instruction_no_overlap(self):
        inst = [make_instruction(100, "AABB", "CCDD")]
        p = _patcher(bytes(512), inst, skip=True)
        assert p._find_overlapping_instructions(inst) == []

    def test_two_non_overlapping_instructions_no_error(self):
        insts = [
            make_instruction(100, "AABB", "CCDD"),
            make_instruction(200, "EEFF", "1122"),
        ]
        p = _patcher(bytes(512), [], skip=True)
        assert p._find_overlapping_instructions(insts) == []

    def test_adjacent_end_plus_one_is_not_overlap(self):
        # inst-1: [100, 101]  inst-2: [102, 103]  → no shared byte
        insts = [
            make_instruction(100, "AABB", "CCDD"),
            make_instruction(102, "EEFF", "1122"),
        ]
        p = _patcher(bytes(512), [], skip=True)
        assert p._find_overlapping_instructions(insts) == []

    def test_overlap_by_one_byte_detected(self):
        # inst-1: [100, 101]  inst-2: [101, 102]  → share byte 101
        insts = [
            make_instruction(100, "AABB", "CCDD"),
            make_instruction(101, "BB11", "EEFF"),
        ]
        p = _patcher(bytes(512), [], skip=True)
        errors = p._find_overlapping_instructions(insts)
        assert len(errors) == 1

    def test_fully_contained_instruction_detected(self):
        # inst-2 is fully inside inst-1's range
        insts = [
            make_instruction(100, "AABBCCDD", "11223344"),  # [100,103]
            make_instruction(101, "BBCC", "EEFF"),  # [101,102] ⊂ [100,103]
        ]
        p = _patcher(bytes(512), [], skip=True)
        errors = p._find_overlapping_instructions(insts)
        assert len(errors) >= 1

    def test_return_type_is_list(self):
        p = _patcher(bytes(512), [], skip=True)
        result = p._find_overlapping_instructions([])
        assert isinstance(result, list)


# ===========================================================================
# 13 — skip_validation=True is the one genuinely unsafe path
# ===========================================================================


class TestSkipValidationCollisionRisk:
    """
    Documents the single scenario where a wrong write CAN happen:

        skip_validation=True  +  ob is NOT at the expected offset
        +  ctx+ob found at a DIFFERENT (closer) shifted location.

    The strict pre-flight is the primary safety gate.  Bypassing it via
    skip_validation=True while ob is absent from the expected offset means
    the patcher falls back to the closest-in-window match — which might be
    wrong.

    These tests are NOT bugs in the patcher.  They document the contract:
    skip_validation=True is an advanced escape hatch for callers who have
    already validated externally.  Do not use it on real ECU data unless
    you know exactly what you are doing.
    """

    def test_with_strict_validation_wrong_offset_raises_and_does_not_write(self):
        """
        With skip_validation=False (default), strict pre-flight catches that
        ob is not at the expected offset and raises before writing anything.
        """
        ctx = bytes.fromhex("AABBCCDD")
        ob = bytes.fromhex("11223344")
        mb = bytes.fromhex("EEFF0011")

        # ob is at offset 200, recipe says expected=100 → strict validation fails
        data = _build(size=1_024, placements={200 - 4: ctx, 200: ob})
        with pytest.raises(ValueError):
            _patcher(data, [_inst(100, ob, mb, ctx)], skip=False).apply_all()

    def test_without_strict_validation_shifted_write_can_occur(self):
        """
        With skip_validation=True, the patcher uses the ctx+ob anchor search.
        If ob is not at expected but IS within the window, the shifted
        location is written.  This is the documented shift behaviour.
        """
        ctx = bytes.fromhex("AABBCCDD")
        ob = bytes.fromhex("11223344")
        mb = bytes.fromhex("EEFF0011")
        expected = 100
        actual = 150  # shifted by +50

        data = _build(size=1_024, placements={actual - 4: ctx, actual: ob})
        p = _patcher(data, [_inst(expected, ob, mb, ctx)], skip=True)
        result = p.apply_all()

        # Wrong offset written (by design of skip_validation)
        assert result[actual : actual + 4] == mb
        assert p.results[0].shift == actual - expected

    def test_closest_match_chosen_when_two_shifted_options_exist(self):
        """
        With skip_validation=True and two shifted candidates, the one
        CLOSER to expected is written — not necessarily the 'correct' one.
        This is why strict validation is mandatory in production.
        """
        ctx = bytes.fromhex("CAFEFEED")
        ob = bytes.fromhex("DEADC0DE")
        mb = bytes.fromhex("FFFFFFFF")
        expected = 500
        close = expected + 30  # distance 30 — will win
        far = expected + 200  # distance 200 — will lose

        data = _build(
            size=4_096,
            placements={
                close - 4: ctx,
                close: ob,
                far - 4: ctx,
                far: ob,
            },
        )
        p = _patcher(data, [_inst(expected, ob, mb, ctx)], skip=True)
        result = p.apply_all()

        assert result[close : close + 4] == mb  # closer match wins
        assert result[far : far + 4] == ob  # farther match untouched
        assert p.results[0].shift == 30

    def test_strict_validation_is_default(self):
        """
        Confirm that the default ECUPatcher constructor has strict validation
        enabled.  skip_validation must default to False.
        """
        p = ECUPatcher(bytes(512), make_recipe([]))
        assert p.skip_validation is False
