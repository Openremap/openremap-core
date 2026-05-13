"""
Recipe instruction annotator — flag suspicious changes.

The diff engine captures every changed byte between two ECU binaries.
That includes calibration map changes (desired) AND volatile / vehicle-
specific data like VIN numbers, checksums, IMMO blocks, etc.

This module scans instructions and attaches non-destructive flags to
anything that looks suspicious.  Nothing is removed — the user decides.

Flags
-----
Each flag is a dict with:
    kind        — tag: VIN_SUSPECT, SHORT_BLOCK_BOUNDARY, …
    reason      — human-readable explanation
    confidence  — HIGH, MEDIUM, LOW
    action      — always "REVIEW" (we never auto-remove)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Protocol


# ---------------------------------------------------------------------------
# Flag dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstructionFlag:
    """A single flag attached to a recipe instruction."""

    kind: str
    reason: str
    confidence: str  # HIGH | MEDIUM | LOW
    action: str = "REVIEW"

    def to_dict(self) -> Dict[str, str]:
        return {
            "kind": self.kind,
            "reason": self.reason,
            "confidence": self.confidence,
            "action": self.action,
        }


# ---------------------------------------------------------------------------
# Scanner protocol
# ---------------------------------------------------------------------------


class InstructionScanner(Protocol):
    """Interface for pluggable instruction scanners."""

    def scan(
        self,
        instruction: Dict,
        original_data: bytes,
    ) -> List[InstructionFlag]:
        """
        Examine one instruction and return zero or more flags.

        Args:
            instruction: Single instruction dict from the recipe
                         (has offset, size, ob, mb, ctx, etc.)
            original_data: The full original binary (for context lookups
                          beyond what's in the instruction itself).

        Returns:
            List of InstructionFlag instances.  Empty means clean.
        """
        ...


# ---------------------------------------------------------------------------
# VIN scanner
# ---------------------------------------------------------------------------

# ISO 3779 VIN: 17 characters, A-Z 0-9 excluding I, O, Q
_VIN_CHARSET = b"ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
_VIN_RE = re.compile(rb"[A-HJ-NPR-Z0-9]{17}")

# Minimum context window around instruction to search for VINs.
# A VIN is 17 bytes; the instruction might only overlap part of it.
_VIN_SCAN_MARGIN = 24


class VINScanner:
    """
    Detect instructions that overlap with a VIN-shaped byte sequence
    in the original binary.

    Strategy:
        1. Look at the region of the original binary around the
           instruction's offset (offset - margin .. offset + size + margin).
        2. Search that region for any 17-byte sequence matching the
           ISO 3779 VIN character set.
        3. If the instruction's byte range overlaps with a VIN hit,
           flag it.

    This checks the ORIGINAL binary — if there's a VIN-shaped string
    in the original at/near the instruction offset, and the instruction
    changes bytes in that region, it's suspicious.
    """

    def scan(
        self,
        instruction: Dict,
        original_data: bytes,
    ) -> List[InstructionFlag]:
        flags: List[InstructionFlag] = []

        offset = instruction["offset"]
        size = instruction["size"]
        inst_start = offset
        inst_end = offset + size

        # Widen the search window so we catch VINs that partially overlap
        scan_start = max(0, offset - _VIN_SCAN_MARGIN)
        scan_end = min(len(original_data), offset + size + _VIN_SCAN_MARGIN)
        window = original_data[scan_start:scan_end]

        for m in _VIN_RE.finditer(window):
            vin_abs_start = scan_start + m.start()
            vin_abs_end = scan_start + m.end()

            # Check overlap: instruction range [inst_start, inst_end)
            #                 VIN range [vin_abs_start, vin_abs_end)
            if inst_start < vin_abs_end and vin_abs_start < inst_end:
                try:
                    vin_str = m.group(0).decode("ascii")
                except UnicodeDecodeError:
                    vin_str = m.group(0).hex().upper()

                flags.append(
                    InstructionFlag(
                        kind="VIN_SUSPECT",
                        reason=(
                            f"Instruction overlaps with VIN-shaped string "
                            f"'{vin_str}' at 0x{vin_abs_start:X}\u20130x{vin_abs_end:X}"
                        ),
                        confidence="HIGH",
                    )
                )
                # One VIN flag per instruction is enough
                break

        return flags


# ---------------------------------------------------------------------------
# Recipe annotator — runs all scanners
# ---------------------------------------------------------------------------


class RecipeAnnotator:
    """
    Run all registered scanners over a recipe's instructions and
    attach flags.

    Usage::

        annotator = RecipeAnnotator()
        # optionally: annotator.add_scanner(MyCustomScanner())
        annotator.annotate(recipe, original_data)
        # recipe["instructions"][i]["flags"] is now populated
    """

    def __init__(self) -> None:
        self._scanners: List[InstructionScanner] = [
            VINScanner(),
        ]

    def add_scanner(self, scanner: InstructionScanner) -> None:
        """Register an additional scanner."""
        self._scanners.append(scanner)

    def annotate(
        self,
        recipe: Dict,
        original_data: bytes,
    ) -> Dict:
        """
        Annotate every instruction in the recipe with flags.

        Modifies the recipe dict in-place and returns it.
        Each instruction gets a ``flags`` key (list of flag dicts).
        Instructions with no issues get an empty list.
        """
        for instruction in recipe.get("instructions", []):
            all_flags: List[InstructionFlag] = []
            for scanner in self._scanners:
                all_flags.extend(scanner.scan(instruction, original_data))
            instruction["flags"] = [f.to_dict() for f in all_flags]

        return recipe

    def flagged_count(self, recipe: Dict) -> int:
        """Return the number of instructions that have at least one flag."""
        return sum(1 for inst in recipe.get("instructions", []) if inst.get("flags"))

    def flag_summary(self, recipe: Dict) -> List[str]:
        """
        Return a list of human-readable summary lines for all flagged
        instructions.  Empty if no flags.
        """
        lines: List[str] = []
        for inst in recipe.get("instructions", []):
            for flag in inst.get("flags", []):
                offset_hex = inst.get("offset_hex", f"{inst['offset']:X}")
                lines.append(
                    f"0x{offset_hex} — {flag['kind']} ({flag['confidence']}): "
                    f"{flag['reason']}"
                )
        return lines
