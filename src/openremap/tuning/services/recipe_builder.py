"""
ECU Recipe Builder

Accepts two ECU binary files as raw bytes (in-memory), compares them and
produces a format-4.0 recipe consumed by the patcher pipeline.

Instruction fields emitted:
    offset          — absolute byte offset in the original file (int)
    ob              — original bytes at that offset (hex, uppercase)
    mb              — modified bytes to write (hex, uppercase)
    ctx             — context_before bytes used as anchor (hex, uppercase)
    size            — number of bytes (int, derived — convenience only)
    offset_hex      — offset as hex string (derived — convenience only)
    description     — human-readable summary

ECU identification is fully delegated to identifier.py — this file
contains only the diff engine and recipe assembly.

The ecu block embedded in the recipe contains only the lean identity fields:
    manufacturer, match_key, ecu_family, ecu_variant,
    software_version, hardware_number, file_size, sha256.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple

from openremap.tuning.services.identifier import identify_ecu


# ---------------------------------------------------------------------------
# Change dataclass
# ---------------------------------------------------------------------------


@dataclass
class Change:
    """Represents a single change block between two ECU binaries."""

    offset: int
    size: int
    ob: str  # original bytes — hex, uppercase
    mb: str  # modified bytes — hex, uppercase
    ctx: str  # context_before bytes — hex, uppercase
    context_after: str
    context_size: int

    @property
    def offset_hex(self) -> str:
        return f"{self.offset:X}"

    def to_dict(self) -> Dict:
        return {
            "offset": self.offset,
            "offset_hex": self.offset_hex,
            "size": self.size,
            "ob": self.ob,
            "mb": self.mb,
            "ctx": self.ctx,
            "context_after": self.context_after,
            "context_size": self.context_size,
            "description": self._description(),
        }

    def _description(self) -> str:
        if self.size == 1:
            return f"Byte at 0x{self.offset_hex}: 0x{self.ob} -> 0x{self.mb}"
        return f"{self.size} bytes at 0x{self.offset_hex} modified"


# ---------------------------------------------------------------------------
# ECUDiffAnalyzer
# ---------------------------------------------------------------------------


class ECUDiffAnalyzer:
    """
    Analyzes differences between two ECU binary files and produces a
    format-4.0 recipe — the same format consumed by the patcher pipeline.

    Operates entirely on in-memory bytes — no file I/O.
    Manufacturer identification is delegated to the registry.
    """

    def __init__(
        self,
        original_data: bytes,
        modified_data: bytes,
        original_filename: str,
        modified_filename: str,
        context_size: int = 32,
    ) -> None:
        self.original_data = original_data
        self.modified_data = modified_data
        self.original_filename = original_filename
        self.modified_filename = modified_filename
        self.context_size = context_size
        self.changes: List[Change] = []

    # -----------------------------------------------------------------------
    # Diff engine
    # -----------------------------------------------------------------------

    def _get_context(self, offset: int, size: int) -> Tuple[bytes, bytes]:
        """Return (context_before, context_after) bytes for a change block."""
        ctx_start = max(0, offset - self.context_size)
        ctx_end = min(len(self.original_data), offset + size + self.context_size)
        before = self.original_data[ctx_start:offset]
        after = self.original_data[offset + size : ctx_end]
        return before, after

    def find_changes(self, merge_threshold: int = 16) -> None:
        """
        Find all changed byte blocks between original and modified.

        Nearby diff positions within merge_threshold bytes of each other
        are merged into a single instruction, reducing total instruction count.
        """
        self.changes.clear()

        min_length = min(len(self.original_data), len(self.modified_data))

        diff_positions = [
            i
            for i in range(min_length)
            if self.original_data[i] != self.modified_data[i]
        ]

        if not diff_positions:
            return

        # Group positions into contiguous blocks
        blocks: List[Tuple[int, int]] = []
        start = diff_positions[0]
        end = diff_positions[0]

        for pos in diff_positions[1:]:
            if pos - end <= merge_threshold:
                end = pos
            else:
                blocks.append((start, end))
                start = pos
                end = pos
        blocks.append((start, end))

        for blk_start, blk_end in blocks:
            size = blk_end - blk_start + 1
            ob = self.original_data[blk_start : blk_end + 1].hex().upper()
            mb = self.modified_data[blk_start : blk_end + 1].hex().upper()
            ctx_before, ctx_after = self._get_context(blk_start, size)

            self.changes.append(
                Change(
                    offset=blk_start,
                    size=size,
                    ob=ob,
                    mb=mb,
                    ctx=ctx_before.hex().upper(),
                    context_after=ctx_after.hex().upper(),
                    context_size=self.context_size,
                )
            )

    # -----------------------------------------------------------------------
    # Statistics
    # -----------------------------------------------------------------------

    def compute_stats(self) -> Dict:
        """Return a statistical summary of the diff."""
        if not self.changes:
            return {}

        total_changed = sum(c.size for c in self.changes)
        file_size = len(self.original_data)
        single = sum(1 for c in self.changes if c.size == 1)

        return {
            "total_changes": len(self.changes),
            "total_bytes_changed": total_changed,
            "percentage_changed": round(total_changed / file_size * 100, 4),
            "single_byte_changes": single,
            "multi_byte_changes": len(self.changes) - single,
            "largest_change_size": max(c.size for c in self.changes),
            "smallest_change_size": min(c.size for c in self.changes),
            "context_size": self.context_size,
        }

    # -----------------------------------------------------------------------
    # Identification
    # -----------------------------------------------------------------------

    def extract_ecu_identifiers(self) -> Dict:
        """
        Extract identifying information from the original binary.
        Delegates entirely to the manufacturer registry.
        """
        return identify_ecu(
            data=self.original_data,
            filename=self.original_filename,
        )

    # -----------------------------------------------------------------------
    # Recipe builder
    # -----------------------------------------------------------------------

    def build_recipe(self) -> Dict:
        """
        Build the full format-4.0 recipe dict.

        Ready to be serialised, stored, or passed directly to the patcher pipeline.
        Consumed directly by: ecu_validate_strict, ecu_validate_exists,
        ecu_validate_patched, ecu_patcher.

        Recipe shape
        ------------
        {
            "metadata": { ... },
            "ecu": {
                "file_size": int,
                "sw_version": str | None,
                "ecu_family": str | None,
                "ecu_variant": str | None,
                "match_key": str | None,
                "hardware_number": str | None,
                "calibration_id": str | None,
                ...full ecu_identification fields...
            },
            "statistics": { ... },
            "instructions": [
                {
                    "offset": int,
                    "offset_hex": str,
                    "size": int,
                    "ob": str,   # original bytes
                    "mb": str,   # modified bytes
                    "ctx": str,  # context_before anchor
                    ...
                },
                ...
            ]
        }
        """
        self.find_changes()
        ecu_id = self.extract_ecu_identifiers()

        # Build the ecu block — maps to what the patcher services expect
        # (file_size for size checks, software_version for SW revision warnings)
        ecu_block = {
            "manufacturer": ecu_id.get("manufacturer"),
            "match_key": ecu_id.get("match_key"),
            "ecu_family": ecu_id.get("ecu_family"),
            "ecu_variant": ecu_id.get("ecu_variant"),
            "software_version": ecu_id.get("software_version"),
            "hardware_number": ecu_id.get("hardware_number"),
            "calibration_id": ecu_id.get("calibration_id"),
            "file_size": ecu_id.get("file_size"),
            "sha256": ecu_id.get("sha256"),
        }

        return {
            "metadata": {
                "original_file": self.original_filename,
                "modified_file": self.modified_filename,
                "original_size": len(self.original_data),
                "modified_size": len(self.modified_data),
                "context_size": self.context_size,
                "format_version": "4.0",
                "description": "ECU patch recipe with exact-offset and context-anchor instructions",
            },
            "ecu": ecu_block,
            "statistics": self.compute_stats(),
            "instructions": [change.to_dict() for change in self.changes],
        }
