"""
ECU Recipe Builder — .openremap format

Accepts two ECU binary files as raw bytes (in-memory), compares them and
produces a .openremap recipe consumed by the patcher pipeline.

Instruction fields emitted:
    offset          — absolute byte offset in the original file (int)
    ob              — original bytes at that offset (hex, uppercase)
    mb              — modified bytes to write (hex, uppercase)
    ctx             — context_before bytes used as anchor (hex, uppercase)
    size            — number of bytes (int, derived — convenience only)
    offset_hex      — offset as hex string (derived — convenience only)
    description     — human-readable summary
    flags           — list of annotation flags (VIN_SUSPECT, etc.)

ECU identification is fully delegated to identifier.py — this file
contains only the diff engine and .openremap recipe assembly.

The ecu block embedded in the recipe contains only the lean identity fields:
    manufacturer, match_key, ecu_family, ecu_variant,
    software_version, hardware_number, file_size, sha256.

Safety guards
-------------
build_recipe() enforces two checks before diffing:

  1. SIZE MATCH (hard error)
     The original and modified binaries must be exactly the same size.
     If they differ, ValueError is raised immediately — no diff is run.
     Rationale: ECU flash images are fixed-size. A size mismatch almost
     always means two different ECU models or a corrupted file.  Diffing
     binaries of different sizes would silently discard the tail of the
     larger file, producing wrong offsets for every instruction.

  2. IDENTITY MATCH (warning, not fatal)
     Both binaries are identified independently.  If their match_keys
     differ the recipe is still built but cook_warnings() returns a
     human-readable warning string.  The recipe's ecu block contains a
     new field ``cook_warnings`` listing any issues found at build time
     so downstream tools can surface them.
     Rationale: cooking ME7.5 vs EDC17 is almost certainly a mistake,
     but there are legitimate edge cases (anonymised bins, unknown ECUs)
     where identification fails on one side — we warn rather than block.

  ⚠  RAW DIFF WARNING
     find_changes() is a raw byte comparison of the ENTIRE binary.
     It captures calibration map changes AND any other byte that differs
     between the two files, including:
       - ECU checksums corrected by WinOLS / Alientech / etc.
       - VIN numbers stored in flash
       - Immobilizer (IMMO) data
       - ECU serial numbers
       - Odometer counters
     Always review the instruction list before applying a recipe.
     Checksum instructions must be removed and the checksum recalculated
     by a professional tool (WinOLS, ECM Titanium, etc.) after patching.
Recipe provenance
-----------------
Every recipe embeds:

  - ``creator`` block — tool name, version, timestamp, optional author
  - ``fingerprint`` — SHA-256 of the instruction content (offset + ob + mb)
  - ``trust_level`` — UNSIGNED | COMMUNITY | SIGNED | VERIFIED

The fingerprint is NOT tamper protection on its own.  It is a
deduplication and corruption-detection tool.  Tamper protection
requires a digital signature (future feature).
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from openremap.core.services.identifier import identify_ecu

import hashlib
import json
from datetime import datetime, timezone

from openremap import __version__
from openremap.core.services.annotator import RecipeAnnotator


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
# Trust & fingerprint helpers
# ---------------------------------------------------------------------------


def compute_fingerprint(instructions: list[dict]) -> str:
    """
    Deterministic SHA-256 fingerprint of the instruction content.

    Computed from a canonical representation of (offset, ob, mb) tuples
    sorted by offset.  Same tune = same fingerprint, always — regardless
    of who created it, when, or what metadata they added.

    This is NOT tamper protection on its own (anyone can recompute the
    hash).  It becomes tamper-proof only when combined with a digital
    signature (future feature).

    Uses:
        - Deduplication: two recipes with the same fingerprint are the
          same tune.
        - Accidental corruption detection: if the file was garbled, the
          fingerprint won't match a recomputation.
    """
    canonical = sorted(
        (inst["offset"], inst["ob"], inst["mb"]) for inst in instructions
    )
    blob = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(blob).hexdigest()}"


def derive_trust_level(creator: dict) -> str:
    """
    Derive the trust level from the creator block.

    UNSIGNED   — no author info
    COMMUNITY  — author info present, no signature
    SIGNED     — author + valid signature (future)
    VERIFIED   — signed + platform-verified identity (future)
    """
    author = creator.get("author")
    signature = creator.get("signature")

    if signature and author and author.get("verified"):
        return "VERIFIED"
    if signature and author:
        return "SIGNED"
    if author:
        return "COMMUNITY"
    return "UNSIGNED"


def build_creator_block(author: dict | None = None) -> dict:
    """
    Build the creator metadata block.

    Args:
        author: Optional author dict with keys like name, handle, id.
                None = anonymous / UNSIGNED.

    Returns:
        Creator dict ready to embed in the recipe.
    """
    creator = {
        "tool": "openremap-core",
        "tool_version": __version__,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "author": author,
        "signature": None,
    }
    creator["trust_level"] = derive_trust_level(creator)
    return creator


# ---------------------------------------------------------------------------
# ECUDiffAnalyzer
# ---------------------------------------------------------------------------


class ECUDiffAnalyzer:
    """
    Analyzes differences between two ECU binary files and produces a
    .openremap recipe — the same format consumed by the patcher pipeline.

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
        author: dict | None = None,
    ) -> None:
        self.original_data = original_data
        self.modified_data = modified_data
        self.original_filename = original_filename
        self.modified_filename = modified_filename
        self.context_size = context_size
        self.changes: List[Change] = []
        self._cook_warnings: List[str] = []
        self.author = author

    # -----------------------------------------------------------------------
    # Pre-cook guards
    # -----------------------------------------------------------------------

    def check_size_match(self) -> Optional[str]:
        """
        Verify that both binaries are exactly the same size.

        ECU flash images are fixed-size.  A mismatch almost always means
        two different ECU models or a corrupted/truncated file.  Diffing
        binaries of different sizes silently discards the tail of the
        larger file, producing wrong offsets for every instruction.

        Returns:
            An error string if the sizes differ, None if they match.
        """
        orig_size = len(self.original_data)
        mod_size = len(self.modified_data)
        if orig_size != mod_size:
            return (
                f"File size mismatch: original is {orig_size:,} bytes, "
                f"modified is {mod_size:,} bytes. "
                "Both files must be the same size — they must be images of "
                "the same ECU model. If the sizes differ you are most likely "
                "comparing two different ECU families or a corrupted file."
            )
        return None

    def check_identity_match(self) -> Optional[str]:
        """
        Identify both binaries independently and compare their match_keys.

        A mismatch means the two files are from different ECU families or
        software revisions — cooking a recipe from them would produce
        instructions that make no sense when applied to either binary.

        Returns:
            A warning string if the identities differ or cannot be
            compared, None if both match_keys are equal.
            Returns None (silently) when identification fails on either
            side — unknown binaries cannot be compared.
        """
        try:
            orig_id = identify_ecu(
                data=self.original_data, filename=self.original_filename
            )
            mod_id = identify_ecu(
                data=self.modified_data, filename=self.modified_filename
            )
        except Exception:
            return None  # identification failed — cannot compare, do not block

        orig_key = orig_id.get("match_key")
        mod_key = mod_id.get("match_key")

        # If either side is unidentified we cannot make a meaningful comparison
        if not orig_key or not mod_key:
            return None

        if orig_key != mod_key:
            orig_family = orig_id.get("ecu_family") or "unknown"
            mod_family = mod_id.get("ecu_family") or "unknown"
            return (
                f"ECU identity mismatch: original identifies as '{orig_key}' "
                f"({orig_family}), modified identifies as '{mod_key}' "
                f"({mod_family}). "
                "You are diffing two different ECU families or SW revisions. "
                "The produced recipe will contain nonsense instructions and "
                "must NOT be applied to any vehicle."
            )
        return None

    def cook_warnings(self) -> List[str]:
        """
        Return the list of non-fatal warnings produced during the last
        build_recipe() call.

        Always call build_recipe() before reading this — the list is
        populated (and cleared) at the start of each build_recipe() call.

        Returns:
            List of human-readable warning strings.  Empty when clean.
        """
        return list(self._cook_warnings)

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
        Build the full .openremap recipe dict.

        Runs two pre-cook guards before diffing:

          1. SIZE MATCH — raises ValueError immediately if the two binaries
             are not the same size.  No diff is run, no recipe is produced.

          2. IDENTITY MATCH — identifies both binaries and compares their
             match_keys.  A mismatch is recorded as a warning (not fatal)
             accessible via cook_warnings() and embedded in the recipe's
             ecu block under ``cook_warnings``.

        Ready to be serialised, stored, or passed directly to the patcher pipeline.
        Consumed directly by: ecu_validate_strict, ecu_validate_exists,
        ecu_validate_patched, ecu_patcher.

        Recipe shape
        ------------
        {
            "openremap": { "type": "recipe", "schema_version": "4.0" },
            "metadata": { ... },
            "ecu": {
                "file_size": int,
                "sw_version": str | None,
                "ecu_family": str | None,
                "ecu_variant": str | None,
                "match_key": str | None,
                "hardware_number": str | None,
                "calibration_id": str | None,
                "cook_warnings": list[str],   # non-empty when guards triggered
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

        Raises:
            ValueError: if the two binaries are not the same size.
        """
        self._cook_warnings.clear()

        # --- Guard 1: size match (hard error) ---
        size_error = self.check_size_match()
        if size_error:
            raise ValueError(size_error)

        # --- Guard 2: identity match (warning) ---
        identity_warning = self.check_identity_match()
        if identity_warning:
            self._cook_warnings.append(identity_warning)

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
            "cook_warnings": list(self._cook_warnings),
        }

        instructions = [change.to_dict() for change in self.changes]

        # --- Annotate instructions with flags ---
        recipe = {
            "openremap": {
                "type": "recipe",
                "schema_version": "4.1",
            },
            "creator": build_creator_block(self.author),
            "fingerprint": compute_fingerprint(instructions),
            "metadata": {
                "original_file": self.original_filename,
                "modified_file": self.modified_filename,
                "original_size": len(self.original_data),
                "modified_size": len(self.modified_data),
                "context_size": self.context_size,
                "format_version": "4.1",
                "description": "OpenRemap ECU patch recipe with exact-offset and context-anchor instructions",
            },
            "ecu": ecu_block,
            "statistics": self.compute_stats(),
            "instructions": instructions,
        }

        # Run annotator — attaches flags to each instruction in-place
        annotator = RecipeAnnotator()
        annotator.annotate(recipe, self.original_data)

        return recipe
