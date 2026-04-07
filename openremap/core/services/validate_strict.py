"""
ECU Strict Offset Validator
============================
Validates a target ECU binary against a recipe by reading the EXACT offset
and comparing the EXACT original bytes (ob field) for every instruction.

Operates entirely on in-memory bytes — no file I/O.
Can be used from the CLI, the API layer, or any other caller.

Rules:
- Scans ALL instructions before reporting (never aborts early).
- If ALL match  → safe to patch  (safe_to_patch=True).
- If ANY fail   → full failure report  (safe_to_patch=False). Do not patch.
"""

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from openremap.core.services.identifier import identify_ecu


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    instruction_index: int  # 1-based
    offset: int
    offset_hex: str  # derived: f"{offset:X}"
    size: int  # derived: len(bytes.fromhex(ob))
    expected_bytes: str  # hex string — ob field from recipe
    found_bytes: str  # hex string actually read from binary
    passed: bool
    reason: str


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ECUStrictValidator:
    """
    Validates a target ECU binary against a recipe by checking every
    instruction at its exact recorded offset.

    All input is accepted as in-memory objects — the caller is responsible
    for reading files and parsing JSON before constructing this class.

    Args:
        target_data:  Raw bytes of the target ECU binary.
        recipe:       Parsed recipe dict (format 4.0 — must contain
                      ``instructions`` list with ``offset`` and ``ob`` fields,
                      and optionally an ``ecu`` block with ``file_size`` and
                      ``sw_version``).
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
        self.results: List[ValidationResult] = []

    # ------------------------------------------------------------------
    # Pre-flight checks
    # ------------------------------------------------------------------

    def check_file_size(self) -> Optional[str]:
        """
        Compare the target size against the recipe's declared file_size.

        Returns:
            An error string if sizes mismatch, None if they match (or if the
            recipe carries no file_size field — treated as a warning, not fatal
            at the service layer; the caller decides how to handle it).
        """
        expected_size = self.recipe.get("ecu", {}).get("file_size")
        if expected_size is None:
            return None  # no size declared — skip

        actual_size = len(self.target_data)
        if actual_size != expected_size:
            return (
                f"File size mismatch: expected {expected_size:,} bytes, "
                f"found {actual_size:,} bytes. "
                "This ECU is likely a different model."
            )
        return None

    def check_match_key(self) -> Optional[str]:
        """
        Identify the target binary and compare its match_key against the one
        recorded in the recipe.

        Returns:
            A warning string when the match keys differ, None when they match
            (or when either key is absent — treated as unverifiable).
        """
        recipe_key = self.recipe.get("ecu", {}).get("match_key")
        if not recipe_key:
            return None

        try:
            target_id = identify_ecu(data=self.target_data, filename=self.target_name)
        except Exception:
            return None  # identification failed — do not block validation

        target_key = target_id.get("match_key")
        if not target_key:
            return None  # target unrecognised — cannot compare

        if target_key != recipe_key:
            return (
                f"Match key mismatch: recipe is for '{recipe_key}', "
                f"but this binary identifies as '{target_key}'. "
                "This is a different ECU or calibration — patching may corrupt the ECU."
            )
        return None

    # ------------------------------------------------------------------
    # Core validation
    # ------------------------------------------------------------------

    def validate_all(self) -> None:
        """
        Iterate every instruction. For each one read exactly ``size`` bytes
        at ``offset`` and compare against ``ob``.
        Populates ``self.results`` — collects ALL results before returning.
        """
        self.results.clear()

        instructions = self.recipe.get("instructions", [])
        file_len = len(self.target_data)

        for idx, inst in enumerate(instructions, 1):
            offset: int = inst["offset"]
            expected: str = inst["ob"].upper()
            size: int = len(bytes.fromhex(expected))  # derived — not stored in recipe
            offset_hex: str = f"{offset:X}"  # derived — not stored in recipe

            # --- bounds check ---
            if offset < 0 or offset + size > file_len:
                self.results.append(
                    ValidationResult(
                        instruction_index=idx,
                        offset=offset,
                        offset_hex=offset_hex,
                        size=size,
                        expected_bytes=expected,
                        found_bytes="",
                        passed=False,
                        reason=(
                            f"Offset 0x{offset_hex} + {size} bytes "
                            f"exceeds file length ({file_len:,} bytes)."
                        ),
                    )
                )
                continue

            # --- read exact bytes ---
            found = self.target_data[offset : offset + size].hex().upper()

            if found == expected:
                self.results.append(
                    ValidationResult(
                        instruction_index=idx,
                        offset=offset,
                        offset_hex=offset_hex,
                        size=size,
                        expected_bytes=expected,
                        found_bytes=found,
                        passed=True,
                        reason="Exact match.",
                    )
                )
            else:
                self.results.append(
                    ValidationResult(
                        instruction_index=idx,
                        offset=offset,
                        offset_hex=offset_hex,
                        size=size,
                        expected_bytes=expected,
                        found_bytes=found,
                        passed=False,
                        reason=(
                            f"Value mismatch at 0x{offset_hex}. "
                            f"Expected {expected}, found {found}."
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self) -> tuple[int, int, float]:
        """Returns (passed, failed, score_pct)."""
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed
        pct = (passed / len(self.results) * 100) if self.results else 0.0
        return passed, failed, pct

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise the full validation report as a plain dict — ready for a
        Pydantic schema or JSON response.
        """
        passed, failed, pct = self.score()

        return {
            "target_file": self.target_name,
            "recipe_file": self.recipe_name,
            "target_md5": hashlib.md5(self.target_data).hexdigest(),
            "summary": {
                "total": len(self.results),
                "passed": passed,
                "failed": failed,
                "score_pct": round(pct, 2),
                "safe_to_patch": failed == 0,
            },
            "failures": [
                {
                    "instruction_index": r.instruction_index,
                    "offset": r.offset,
                    "offset_hex": r.offset_hex,
                    "size": r.size,
                    "ob": r.expected_bytes,
                    "found_bytes": r.found_bytes,
                    "reason": r.reason,
                }
                for r in self.results
                if not r.passed
            ],
            "all_results": [
                {
                    "instruction_index": r.instruction_index,
                    "offset": r.offset,
                    "offset_hex": r.offset_hex,
                    "size": r.size,
                    "passed": r.passed,
                    "ob": r.expected_bytes,
                    "found_bytes": r.found_bytes,
                    "reason": r.reason,
                }
                for r in self.results
            ],
        }
