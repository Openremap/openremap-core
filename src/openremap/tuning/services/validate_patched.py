"""
ECU Patched Validator
======================
Post-patch verification service. After the patcher has produced a patched
binary, this service reads the patched bytes and confirms that every
instruction in the recipe now has its modified bytes (mb) present at the
exact offset where the patcher wrote them.

Mirror image of ecu_validate_strict:
    ECUStrictValidator   → checks ob at each offset  (before patching)
    ECUPatchedValidator  → checks mb at each offset  (after patching)

Operates entirely on in-memory bytes — no file I/O.
Can be used from the CLI, the API layer, or any other caller.

Rules:
- Scans ALL instructions before reporting (never aborts early).
- If ALL match  → patch confirmed  (patch_confirmed=True).
- If ANY fail   → one or more writes are wrong or missing  (patch_confirmed=False).
"""

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from openremap.tuning.services.identifier import identify_ecu


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    instruction_index: int  # 1-based
    offset: int
    offset_hex: str  # derived: f"{offset:X}"
    size: int  # derived: len(bytes.fromhex(mb))
    expected: str  # mb from recipe (hex, uppercase) — what should be there
    found: str  # what was actually read from the patched binary
    passed: bool
    reason: str


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ECUPatchedValidator:
    """
    Reads a patched ECU binary and verifies that every instruction's mb value
    is present at the exact offset recorded in the recipe.

    All input is accepted as in-memory objects — the caller is responsible
    for reading files and parsing JSON before constructing this class.

    Args:
        patched_data:  Raw bytes of the patched ECU binary.
        recipe:        Parsed recipe dict (format 4.0 — must contain
                       ``instructions`` list with ``offset``, ``ob``, and
                       ``mb`` fields, and optionally an ``ecu`` block with
                       ``file_size``).
        patched_name:  Display name used in reports (e.g. output filename).
        recipe_name:   Display name used in reports (e.g. recipe filename).
    """

    def __init__(
        self,
        patched_data: bytes,
        recipe: Dict[str, Any],
        patched_name: str = "patched.bin",
        recipe_name: str = "recipe.json",
    ) -> None:
        self.patched_data = patched_data
        self.recipe = recipe
        self.patched_name = patched_name
        self.recipe_name = recipe_name
        self.results: List[VerifyResult] = []

    # ------------------------------------------------------------------
    # Pre-flight
    # ------------------------------------------------------------------

    def check_file_size(self) -> Optional[str]:
        """
        Compare the patched binary size against the recipe's declared file_size.
        The patched file must be exactly the same size as the original.

        Returns:
            An error string if sizes mismatch, None if they match (or if the
            recipe carries no file_size field).
        """
        expected_size = self.recipe.get("ecu", {}).get("file_size")
        if expected_size is None:
            return None  # no size declared — skip

        actual_size = len(self.patched_data)
        if actual_size != expected_size:
            return (
                f"File size mismatch: expected {expected_size:,} bytes, "
                f"found {actual_size:,} bytes. "
                "Wrong file or truncated output."
            )
        return None

    def check_match_key(self) -> Optional[str]:
        """
        Identify the patched binary and compare its match_key against the one
        recorded in the recipe.

        Returns:
            A warning string when the match keys differ, None when they match
            (or when either key is absent).
        """
        recipe_key = self.recipe.get("ecu", {}).get("match_key")
        if not recipe_key:
            return None

        try:
            target_id = identify_ecu(data=self.patched_data, filename=self.patched_name)
        except Exception:
            return None

        target_key = target_id.get("match_key")
        if not target_key:
            return None

        if target_key != recipe_key:
            return (
                f"Match key mismatch: recipe is for '{recipe_key}', "
                f"but this binary identifies as '{target_key}'. "
                "This is a different ECU or calibration."
            )
        return None

    # ------------------------------------------------------------------
    # Core verification
    # ------------------------------------------------------------------

    def verify_all(self) -> None:
        """
        For every instruction read exactly ``len(mb)`` bytes at ``offset``
        and compare against ``mb``.
        Populates ``self.results`` — collects ALL results before returning.
        """
        self.results.clear()

        instructions = self.recipe.get("instructions", [])
        file_len = len(self.patched_data)

        for idx, inst in enumerate(instructions, 1):
            offset: int = inst["offset"]
            expected: str = inst["mb"].upper()
            size: int = len(bytes.fromhex(expected))  # derived — not stored in recipe
            offset_hex: str = f"{offset:X}"  # derived — not stored in recipe

            # --- bounds check ---
            if offset < 0 or offset + size > file_len:
                self.results.append(
                    VerifyResult(
                        instruction_index=idx,
                        offset=offset,
                        offset_hex=offset_hex,
                        size=size,
                        expected=expected,
                        found="",
                        passed=False,
                        reason=(
                            f"Offset 0x{offset_hex} + {size} bytes "
                            f"exceeds file length ({file_len:,} bytes)."
                        ),
                    )
                )
                continue

            found = self.patched_data[offset : offset + size].hex().upper()

            if found == expected:
                self.results.append(
                    VerifyResult(
                        instruction_index=idx,
                        offset=offset,
                        offset_hex=offset_hex,
                        size=size,
                        expected=expected,
                        found=found,
                        passed=True,
                        reason="mb confirmed.",
                    )
                )
            else:
                # Distinguish: ob still present (patch never ran) vs unexpected value
                ob = inst["ob"].upper()
                if found == ob:
                    detail = "ob still present — patch was not applied at this offset."
                else:
                    detail = "neither ob nor mb — unexpected value."

                self.results.append(
                    VerifyResult(
                        instruction_index=idx,
                        offset=offset,
                        offset_hex=offset_hex,
                        size=size,
                        expected=expected,
                        found=found,
                        passed=False,
                        reason=f"Mismatch at 0x{offset_hex}: {detail}",
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
        Serialise the full verification report as a plain dict — ready for a
        Pydantic schema or JSON response.
        """
        passed, failed, pct = self.score()

        return {
            "patched_file": self.patched_name,
            "recipe_file": self.recipe_name,
            "patched_md5": hashlib.md5(self.patched_data).hexdigest(),
            "summary": {
                "total": len(self.results),
                "passed": passed,
                "failed": failed,
                "score_pct": round(pct, 2),
                "patch_confirmed": failed == 0,
            },
            "failures": [
                {
                    "instruction_index": r.instruction_index,
                    "offset": r.offset,
                    "offset_hex": r.offset_hex,
                    "size": r.size,
                    "mb": r.expected,
                    "found": r.found,
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
                    "mb": r.expected,
                    "found": r.found,
                    "reason": r.reason,
                }
                for r in self.results
            ],
        }
