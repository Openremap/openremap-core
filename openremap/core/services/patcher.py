"""
ECU Patcher
============
Applies a recipe (format 4.0) to a target ECU binary entirely in memory.

Search strategy — EXACT + context anchor:
    Build the atomic pattern  ctx + ob  and scan within ±EXACT_WINDOW bytes of
    the expected offset.  Collects ALL matches in that window, picks the one
    whose data-start is closest to expected_offset.  If no match is found the
    instruction fails hard — nothing is written.

    All searches are performed against a frozen read-only snapshot of the
    original binary so earlier writes never corrupt the context window of
    later instructions.

Safety guarantees:
    1. ECUStrictValidator is run internally before any bytes are written.
       If validation fails, apply_all() raises ValueError immediately.
    2. The patched bytes are only returned if every single instruction
       succeeded.  A partial result is never handed back to the caller.

Operates entirely on in-memory bytes — no file I/O.
Can be used from the CLI, the API layer, or any other caller.
"""

import hashlib
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from openremap.core.services.validate_strict import ECUStrictValidator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXACT_WINDOW = 2_048  # ± bytes around expected offset searched for ctx+ob anchor


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


class PatchStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class PatchResult:
    index: int
    status: PatchStatus
    offset_expected: int
    offset_found: Optional[int]
    size: int
    shift: Optional[int]  # offset_found - offset_expected (0 = exact)
    message: str
    ambiguous: bool = False  # True when >1 ctx+ob match found in window


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ECUPatcher:
    """
    Applies every instruction in a recipe to a target ECU binary.

    All input is accepted as in-memory objects — the caller is responsible
    for reading files and parsing JSON before constructing this class.

    Args:
        target_data:   Raw bytes of the target ECU binary (original, unpatched).
        recipe:        Parsed recipe dict (format 4.0 — must contain an
                       ``instructions`` list with ``offset``, ``ob``, ``mb``,
                       and ``ctx`` fields, and optionally an ``ecu`` block
                       with ``file_size``, ``sw_version``, etc.).
        target_name:   Display name used in reports (e.g. original filename).
        recipe_name:   Display name used in reports (e.g. recipe filename).
        skip_validation: When True, bypass the strict pre-flight validator.
                         Only set this if the caller has already validated
                         externally. Defaults to False.
    """

    def __init__(
        self,
        target_data: bytes,
        recipe: Dict[str, Any],
        target_name: str = "target.bin",
        recipe_name: str = "recipe.json",
        skip_validation: bool = False,
    ) -> None:
        self.target_name = target_name
        self.recipe_name = recipe_name
        self.recipe = recipe
        self.skip_validation = skip_validation

        # Mutable working buffer — writes go here
        self._buffer: bytearray = bytearray(target_data)
        # Immutable snapshot — all searches use this so that earlier writes
        # never corrupt the context window of later instructions
        self._snapshot: bytes = bytes(target_data)

        self.results: List[PatchResult] = []

    # ------------------------------------------------------------------
    # Pre-flight: strict validator
    # ------------------------------------------------------------------

    def _run_strict_validation(self) -> None:
        """
        Run ECUStrictValidator against the original snapshot before touching
        any bytes.  Raises ValueError if any instruction fails, carrying a
        human-readable summary of which instructions did not match.
        """
        validator = ECUStrictValidator(
            target_data=self._snapshot,
            recipe=self.recipe,
            target_name=self.target_name,
            recipe_name=self.recipe_name,
        )
        validator.validate_all()
        _, failed, _ = validator.score()

        if failed > 0:
            failures = [
                f"  #{r.instruction_index:>3}  0x{r.offset_hex:>8}  {r.reason}"
                for r in validator.results
                if not r.passed
            ]
            detail = "\n".join(failures)
            raise ValueError(
                f"Strict pre-flight validation failed: "
                f"{failed}/{len(validator.results)} instruction(s) did not match ob.\n"
                f"{detail}"
            )

    # ------------------------------------------------------------------
    # Pre-flight: size / SW checks (informational — returned as warnings)
    # ------------------------------------------------------------------

    def preflight_warnings(self) -> List[str]:
        """
        Return a list of non-fatal warning strings about file size and SW
        version mismatches.  These are informational — the patcher does not
        abort on them (the strict validator is the gate-keeper).
        """
        warnings: List[str] = []
        ecu = self.recipe.get("ecu", {})

        expected_size = ecu.get("file_size")
        if expected_size is not None and len(self._snapshot) != expected_size:
            warnings.append(
                f"File size mismatch: expected {expected_size:,} bytes, "
                f"found {len(self._snapshot):,} bytes — possibly a different ECU model."
            )

        sw = ecu.get("software_version")
        if sw and sw.encode("latin-1", errors="ignore") not in self._snapshot:
            warnings.append(
                f"SW version '{sw}' not found in target binary — "
                "possibly a different SW revision."
            )

        return warnings

    # ------------------------------------------------------------------
    # Search — ctx+ob anchor within ±EXACT_WINDOW
    # ------------------------------------------------------------------

    def _find(self, ctx: bytes, ob: bytes, expected: int) -> tuple[int, int]:
        """
        Search for the atomic pattern ``ctx + ob`` inside a ±EXACT_WINDOW
        slice of the frozen snapshot.

        Returns ``(absolute_offset_of_ob_start, match_count)``.
        ``offset`` is -1 and ``match_count`` is 0 when nothing is found.
        When multiple hits exist the one closest to ``expected`` is returned;
        ``match_count > 1`` signals ambiguity to the caller.
        """
        anchor = ctx + ob
        ctx_len = len(ctx)

        win_start = max(0, expected - EXACT_WINDOW)
        win_end = min(len(self._snapshot), expected + EXACT_WINDOW + len(anchor))
        region = self._snapshot[win_start:win_end]

        matches: List[int] = []
        pos = 0
        while True:
            p = region.find(anchor, pos)
            if p == -1:
                break
            # Translate back to absolute offset, then skip past ctx to where ob starts
            matches.append(win_start + p + ctx_len)
            pos = p + 1

        if not matches:
            return -1, 0

        return min(matches, key=lambda o: abs(o - expected)), len(matches)

    # ------------------------------------------------------------------
    # Single instruction
    # ------------------------------------------------------------------

    def _apply_instruction(self, idx: int, inst: Dict[str, Any]) -> PatchResult:
        expected: int = inst["offset"]
        ob = bytes.fromhex(inst["ob"])
        mb = bytes.fromhex(inst["mb"])
        # ctx may be stored as "context_before" (analyzer format) or "ctx" (recipe format)
        ctx_hex: str = inst.get("ctx") or inst.get("context_before") or ""
        ctx = bytes.fromhex(ctx_hex) if ctx_hex else b""
        size = len(ob)

        # If there is no context, fall back to a direct snapshot read at the
        # expected offset — this mirrors strict-validator behaviour and is
        # safe because we have already confirmed ob is there.
        if not ctx:
            found_ob = self._snapshot[expected : expected + size]
            offset = expected if found_ob == ob else -1
            match_count = 1 if offset != -1 else 0
        else:
            offset, match_count = self._find(ctx, ob, expected)

        if offset == -1:
            return PatchResult(
                index=idx,
                status=PatchStatus.FAILED,
                offset_expected=expected,
                offset_found=None,
                size=size,
                shift=None,
                message=(
                    f"ctx+ob pattern not found near 0x{expected:X} "
                    f"(±{EXACT_WINDOW} bytes window)."
                ),
            )

        shift = offset - expected
        ambiguous = match_count > 1

        # Write modified bytes to the mutable buffer (NOT the snapshot)
        self._buffer[offset : offset + size] = mb

        msg = f"Applied at 0x{offset:X} ({'exact' if shift == 0 else f'shift={shift:+d}'})."
        if ambiguous:
            msg += (
                f" WARNING: {match_count} ctx+ob matches found in window — "
                "closest chosen. Verify recipe ctx is sufficiently unique."
            )

        return PatchResult(
            index=idx,
            status=PatchStatus.SUCCESS,
            offset_expected=expected,
            offset_found=offset,
            size=size,
            shift=shift,
            ambiguous=ambiguous,
            message=msg,
        )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Overlap detection
    # ------------------------------------------------------------------

    def _find_overlapping_instructions(
        self, instructions: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Check every pair of instructions for overlapping write regions.

        Two instructions overlap when their byte ranges intersect — i.e. at
        least one byte would be written by both.  This is always a recipe
        error: the later instruction would silently overwrite the earlier
        one's bytes, producing a result that neither instruction intended.

        Returns:
            A list of human-readable error strings, one per overlapping pair.
            An empty list means no overlaps — safe to proceed.
        """
        regions: List[tuple[int, int, int]] = []  # (1-based idx, start, end_inclusive)
        for idx, inst in enumerate(instructions, 1):
            start = inst["offset"]
            size = len(bytes.fromhex(inst["ob"]))
            regions.append((idx, start, start + size - 1))

        errors: List[str] = []
        for i in range(len(regions)):
            idx_a, start_a, end_a = regions[i]
            for j in range(i + 1, len(regions)):
                idx_b, start_b, end_b = regions[j]
                if start_a <= end_b and start_b <= end_a:
                    errors.append(
                        f"Instructions #{idx_a} (0x{start_a:X}–0x{end_a:X}) and "
                        f"#{idx_b} (0x{start_b:X}–0x{end_b:X}) have overlapping "
                        "write regions — the later write would silently corrupt "
                        "the earlier one."
                    )
        return errors

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def apply_all(self) -> bytes:
        """
        Run the full patch pipeline:

        1. Strict pre-flight validation (unless ``skip_validation=True``).
        2. Overlapping-write detection — raises immediately if any two
           instructions share byte ranges.
        3. Apply every instruction from the recipe to the in-memory buffer.
        4. If every instruction succeeded, return the patched bytes.
        5. If any instruction failed, raise ``ValueError`` with a summary —
           the partially-modified buffer is discarded.

        Returns:
            The fully patched binary as ``bytes``.

        Raises:
            ValueError: if strict validation fails, if overlapping write
                        regions are detected, or if any instruction could
                        not be applied.
        """
        self.results.clear()

        # --- 1. Strict validation pre-flight ---
        if not self.skip_validation:
            self._run_strict_validation()

        # --- 2. Overlapping-write detection ---
        instructions = self.recipe.get("instructions", [])
        overlaps = self._find_overlapping_instructions(instructions)
        if overlaps:
            detail = "\n".join(f"  {e}" for e in overlaps)
            raise ValueError(
                f"{len(overlaps)} overlapping instruction pair(s) detected — "
                f"this recipe would corrupt itself:\n{detail}"
            )

        # --- 3. Apply instructions ---
        for idx, inst in enumerate(instructions, 1):
            result = self._apply_instruction(idx, inst)
            self.results.append(result)

        # --- 4. Check for failures ---
        failed_results = [r for r in self.results if r.status == PatchStatus.FAILED]
        if failed_results:
            lines = [
                f"  #{r.index:>3}  0x{r.offset_expected:08X}  {r.message}"
                for r in failed_results
            ]
            raise ValueError(
                f"{len(failed_results)}/{len(self.results)} instruction(s) failed to apply.\n"
                + "\n".join(lines)
            )

        # --- 5. Return patched bytes ---
        return bytes(self._buffer)

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def score(self) -> tuple[int, int, int]:
        """Returns (total, success_count, failed_count)."""
        total = len(self.results)
        success = sum(1 for r in self.results if r.status == PatchStatus.SUCCESS)
        return total, success, total - success

    def ambiguous_count(self) -> int:
        """Return the number of instructions that matched ambiguously (>1 ctx+ob hit in window)."""
        return sum(1 for r in self.results if r.ambiguous)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self, patched_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Serialise the full patch report as a plain dict — ready for a
        Pydantic schema or JSON response.

        Args:
            patched_data: The bytes returned by ``apply_all()``.  When
                          provided, the MD5 of the patched binary is included
                          in the summary.
        """
        total, success, failed = self.score()
        shifted = sum(1 for r in self.results if r.shift is not None and r.shift != 0)
        ambiguous = self.ambiguous_count()

        def _serialise(r: PatchResult) -> Dict[str, Any]:
            d = asdict(r)
            d["status"] = r.status.value
            d["offset_expected_hex"] = f"0x{r.offset_expected:08X}"
            d["offset_found_hex"] = (
                f"0x{r.offset_found:08X}" if r.offset_found is not None else None
            )
            return d

        summary: Dict[str, Any] = {
            "total": total,
            "success": success,
            "failed": failed,
            "shifted": shifted,
            "ambiguous": ambiguous,
            "score_pct": round(success / total * 100, 2) if total else 0.0,
            "patch_applied": failed == 0,
        }
        if patched_data is not None:
            summary["patched_md5"] = hashlib.md5(patched_data).hexdigest()

        return {
            "target_file": self.target_name,
            "recipe_file": self.recipe_name,
            "target_md5": hashlib.md5(self._snapshot).hexdigest(),
            "summary": summary,
            "results": [_serialise(r) for r in self.results],
        }
