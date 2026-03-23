"""
ECU Existence Validator — API service
=======================================
For every instruction in a recipe, searches the ENTIRE target ECU binary
for the original bytes (ob field) and classifies each result as:

  EXACT   — found at the exact offset recorded in the recipe (perfect)
  SHIFTED — found in the file but at a different offset (map moved)
  MISSING — not found anywhere in the file (wrong ECU / already modified)

Operates entirely on in-memory bytes — no file I/O, no CLI.
Designed to be called from the FastAPI router.

Rules:
- Scans ALL instructions before reporting (never aborts early).
- Reports a score and a per-instruction breakdown.
- Does NOT modify the target binary.
- Designed to run AFTER the strict validator fails, to explain WHY it failed.
"""

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from openremap.tuning.services.identifier import identify_ecu


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class MatchStatus(Enum):
    EXACT = "exact"  # found at the recorded offset
    SHIFTED = "shifted"  # found in file but at a different offset
    MISSING = "missing"  # not found anywhere in the file


@dataclass
class ExistenceResult:
    instruction_index: int  # 1-based
    offset_expected: int  # offset from recipe
    offset_hex_expected: str  # derived: f"{offset:X}"
    size: int  # derived: len(bytes.fromhex(ob))
    original_bytes: str  # ob field from recipe (hex string, uppercase)
    modified_bytes: str  # mb field from recipe (hex string, for reference)
    status: MatchStatus
    offsets_found: List[int]  # all offsets where original_bytes was found
    closest_offset: Optional[int]  # closest found offset to expected (or None)
    shift: Optional[int]  # closest_offset - offset_expected (or None)
    reason: str  # human-readable explanation


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ECUExistenceValidator:
    """
    Searches a target ECU binary for every original_bytes value defined in
    a recipe, regardless of offset. Classifies each as EXACT / SHIFTED / MISSING.

    All input is accepted as in-memory objects — the caller is responsible
    for reading files and parsing JSON before constructing this class.

    Args:
        target_data:  Raw bytes of the target ECU binary.
        recipe:       Parsed recipe dict (format 4.0 — must contain
                      ``instructions`` list with ``offset``, ``ob``, and
                      ``mb`` fields, and optionally an ``ecu`` block with
                      ``file_size`` and ``sw_version``).
        target_name:  Display name used in reports (e.g. original filename).
        recipe_name:  Display name used in reports (e.g. recipe filename).
    """

    def __init__(
        self,
        target_data: bytes,
        recipe: Dict[str, Any],
        target_name: str = "target.bin",
        recipe_name: str = "recipe.json",
    ) -> None:
        self.target_data = target_data
        self.recipe = recipe
        self.target_name = target_name
        self.recipe_name = recipe_name
        self.results: List[ExistenceResult] = []

    # ------------------------------------------------------------------
    # Pre-flight (informational — never fatal at the service layer)
    # ------------------------------------------------------------------

    def check_file_size(self) -> Optional[str]:
        """
        Compare the target size against the recipe's declared file_size.

        Returns:
            A warning string if sizes differ, None if they match (or if the
            recipe carries no file_size field).
        """
        expected_size = self.recipe.get("ecu", {}).get("file_size")
        if expected_size is None:
            return None  # no size declared — skip

        actual_size = len(self.target_data)
        if actual_size != expected_size:
            return (
                f"File size mismatch: expected {expected_size:,} bytes, "
                f"found {actual_size:,} bytes — possibly a different ECU model."
            )
        return None

    def check_match_key(self) -> Optional[str]:
        """
        Identify the target binary and compare its match_key against the one
        recorded in the recipe.

        Returns:
            A warning string when the match keys differ, None when they match
            (or when either key is absent).
        """
        recipe_key = self.recipe.get("ecu", {}).get("match_key")
        if not recipe_key:
            return None

        try:
            target_id = identify_ecu(data=self.target_data, filename=self.target_name)
        except Exception:
            return None

        target_key = target_id.get("match_key")
        if not target_key:
            return None

        if target_key != recipe_key:
            return (
                f"Match key mismatch: recipe is for '{recipe_key}', "
                f"but this binary identifies as '{target_key}'. "
                "This is a different ECU or calibration — patching may corrupt the ECU."
            )
        return None

    # ------------------------------------------------------------------
    # Core search
    # ------------------------------------------------------------------

    def _find_all(self, pattern: bytes) -> List[int]:
        """
        Return all offsets where ``pattern`` occurs in target_data.
        Uses bytes.find() in a loop — effectively Boyer-Moore-Horspool, O(n).
        """
        offsets: List[int] = []
        pos = 0
        while True:
            p = self.target_data.find(pattern, pos)
            if p == -1:
                break
            offsets.append(p)
            pos = p + 1
        return offsets

    def validate_all(self) -> None:
        """
        For every instruction: find all occurrences of ``ob`` in the entire
        binary, then classify as EXACT / SHIFTED / MISSING.
        Populates ``self.results`` — collects ALL results before returning.
        """
        self.results.clear()

        instructions = self.recipe.get("instructions", [])

        for idx, inst in enumerate(instructions, 1):
            offset_expected: int = inst["offset"]
            original_bytes: str = inst["ob"].upper()
            modified_bytes: str = inst["mb"].upper()
            size: int = len(bytes.fromhex(original_bytes))  # derived
            offset_hex: str = f"{offset_expected:X}"  # derived
            pattern = bytes.fromhex(original_bytes)

            offsets_found = self._find_all(pattern)

            if not offsets_found:
                # ── MISSING ─────────────────────────────────────────────
                preview = original_bytes[:32] + (
                    "…" if len(original_bytes) > 32 else ""
                )
                self.results.append(
                    ExistenceResult(
                        instruction_index=idx,
                        offset_expected=offset_expected,
                        offset_hex_expected=offset_hex,
                        size=size,
                        original_bytes=original_bytes,
                        modified_bytes=modified_bytes,
                        status=MatchStatus.MISSING,
                        offsets_found=[],
                        closest_offset=None,
                        shift=None,
                        reason=(
                            f"ob {preview} not found anywhere in the file. "
                            "Possible causes: wrong ECU model, ECU already modified, "
                            "or this calibration map does not exist in this SW version."
                        ),
                    )
                )

            elif offset_expected in offsets_found:
                # ── EXACT ────────────────────────────────────────────────
                other_count = len(offsets_found) - 1
                note = (
                    f"  Also found at {other_count} other offset(s)."
                    if other_count > 0
                    else ""
                )
                self.results.append(
                    ExistenceResult(
                        instruction_index=idx,
                        offset_expected=offset_expected,
                        offset_hex_expected=offset_hex,
                        size=size,
                        original_bytes=original_bytes,
                        modified_bytes=modified_bytes,
                        status=MatchStatus.EXACT,
                        offsets_found=offsets_found,
                        closest_offset=offset_expected,
                        shift=0,
                        reason=f"Found at exact offset 0x{offset_hex}.{note}",
                    )
                )

            else:
                # ── SHIFTED ──────────────────────────────────────────────
                closest = min(offsets_found, key=lambda o: abs(o - offset_expected))
                shift = closest - offset_expected
                all_hex = [f"0x{o:08X}" for o in offsets_found]
                preview_hex = ", ".join(all_hex[:5]) + ("…" if len(all_hex) > 5 else "")
                self.results.append(
                    ExistenceResult(
                        instruction_index=idx,
                        offset_expected=offset_expected,
                        offset_hex_expected=offset_hex,
                        size=size,
                        original_bytes=original_bytes,
                        modified_bytes=modified_bytes,
                        status=MatchStatus.SHIFTED,
                        offsets_found=offsets_found,
                        closest_offset=closest,
                        shift=shift,
                        reason=(
                            f"Not at expected 0x{offset_hex}. "
                            f"Found {len(offsets_found)} occurrence(s): {preview_hex}. "
                            f"Closest is 0x{closest:08X} ({shift:+d} bytes from expected). "
                            "Possible causes: SW revision update shifted this map, "
                            "or a different calibration variant."
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def counts(self) -> tuple[int, int, int]:
        """Returns (exact, shifted, missing)."""
        exact = sum(1 for r in self.results if r.status == MatchStatus.EXACT)
        shifted = sum(1 for r in self.results if r.status == MatchStatus.SHIFTED)
        missing = sum(1 for r in self.results if r.status == MatchStatus.MISSING)
        return exact, shifted, missing

    def verdict(self) -> str:
        """
        Compute a machine-readable verdict string based on counts.

        Returns:
            ``"safe_exact"``              — all found at exact offsets.
            ``"shifted_recoverable"``     — all found but some at wrong offsets.
            ``"missing_unrecoverable"``   — one or more not found at all.
        """
        exact, shifted, missing = self.counts()
        if missing > 0:
            return "missing_unrecoverable"
        if shifted > 0:
            return "shifted_recoverable"
        return "safe_exact"

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise the full existence report as a plain dict — ready for a
        Pydantic schema or JSON response.
        """
        exact, shifted, missing = self.counts()
        total = len(self.results)

        return {
            "target_file": self.target_name,
            "recipe_file": self.recipe_name,
            "target_md5": hashlib.md5(self.target_data).hexdigest(),
            "summary": {
                "total": total,
                "exact": exact,
                "shifted": shifted,
                "missing": missing,
                "exact_pct": round(exact / total * 100, 2) if total else 0.0,
                "shifted_pct": round(shifted / total * 100, 2) if total else 0.0,
                "missing_pct": round(missing / total * 100, 2) if total else 0.0,
                "verdict": self.verdict(),
            },
            "results": [
                {
                    "instruction_index": r.instruction_index,
                    "offset_expected": r.offset_expected,
                    "offset_hex_expected": r.offset_hex_expected,
                    "size": r.size,
                    "ob": r.original_bytes,
                    "mb": r.modified_bytes,
                    "status": r.status.value,
                    "offsets_found": [f"0x{o:08X}" for o in r.offsets_found],
                    "closest_offset": (
                        f"0x{r.closest_offset:08X}"
                        if r.closest_offset is not None
                        else None
                    ),
                    "shift": r.shift,
                    "reason": r.reason,
                }
                for r in self.results
            ],
        }
