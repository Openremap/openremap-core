"""
ECU binary confidence scorer.

Computes a numerical "originality" confidence score for an ECU binary, based
on signals derived from the extracted identity fields and from the filename.

Score signals
─────────────
  +40  software_version present and starts with "1037" (canonical Bosch format)
  +15  software_version present but not 1037-prefixed
  +25  hardware_number present (Bosch 0261/0281 part number)
  +10  ecu_variant identified (more specific than ecu_family)
  +10  calibration_id present
  -30  software_version absent AND match_key absent
        (binary cannot be looked up — strongest ident-missing signal)
  -10  software_version absent AND match_key present
        (architecture may not store SW; match key derived from calibration_id)
  -25  filename contains tuning/modification keywords
  -15  generic numbered filename (e.g. 1.bin, 42.ori)

Tiers
─────
  High       score >= 60
  Medium     score >= 25
  Low        score >= 0  (family identified but weak evidence)
  Suspicious score < 0   (family identified but red flags present)
  Unknown    ecu_family is None (no extractor matched)

Warnings (shown separately in CLI output)
─────────────────────────────────────────
  IDENT BLOCK MISSING           SW absent for a family that normally stores it
  TUNING KEYWORDS IN FILENAME   filename suggests modified content
  GENERIC FILENAME              filename gives no identifying information
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# ECU families known to embed a canonical Bosch SW version in the binary.
# "Canonical" covers both the standard "1037" prefix (VW/Audi/BMW/Alfa/Opel)
# and the PSA/Peugeot-Citroën "1039" prefix (EDC16C34 and related variants).
# When software_version is None for one of these families the "IDENT BLOCK
# MISSING" warning is raised, because absence is abnormal for that platform.
# ---------------------------------------------------------------------------

_1037_FAMILY_PREFIXES: tuple[str, ...] = (
    "EDC17",
    "MEDC17",
    "MED17",
    "ME17",
    "EDC16",
    "EDC15",
    "EDC3",
    "ME9",
    "MED9",
    "ME7",
    "ME3",
    "ME5",
    "M1X",
    "M2X",
    "M3X",
    "M5X",
)

# ---------------------------------------------------------------------------
# Filename patterns
# ---------------------------------------------------------------------------

# Keywords that strongly suggest the file has been tuned / modified.
#
# We use (?<![a-zA-Z]) / (?![a-zA-Z]) as boundaries instead of \b because
# underscores are word characters in Python regex — \b would NOT match between
# "_" and a letter, so "ecu_remap.bin" would not be caught with \bremap\b.
# Using letter-only boundaries (ignoring digits and _) lets underscore- and
# hyphen-separated tokens work naturally while still preventing "performance"
# from matching inside "superperformance" etc.
_TUNING_KEYWORDS: re.Pattern[str] = re.compile(
    r"(?:"
    r"(?<![a-zA-Z])stage\s*[1-5]?(?![a-zA-Z])"
    r"|(?<![a-zA-Z])remap(?![a-zA-Z])"
    r"|(?<![a-zA-Z])tuned?(?![a-zA-Z])"
    r"|(?<![a-zA-Z])modified?(?![a-zA-Z])"
    r"|(?<![a-zA-Z])disable(?![a-zA-Z])"
    r"|(?<![a-zA-Z])patch(?:ed)?(?![a-zA-Z])"
    r"|(?<![a-zA-Z])custom(?![a-zA-Z])"
    r"|(?<![a-zA-Z])performance(?![a-zA-Z])"
    r"|(?<![a-zA-Z])sport(?![a-zA-Z])"
    r"|(?<![a-zA-Z])pop.{0,5}bang(?![a-zA-Z])"
    r"|(?<![a-zA-Z])dpf.{0,5}off(?![a-zA-Z])"
    r"|(?<![a-zA-Z])egr.{0,5}off(?![a-zA-Z])"
    r"|(?<![a-zA-Z])opf.{0,5}off(?![a-zA-Z])"
    r")",
    re.IGNORECASE,
)

# Generic numbered filenames: "1.bin", "42.ori", "001.bin", etc.
_GENERIC_FILENAME: re.Pattern[str] = re.compile(
    r"^\d{1,4}\.(bin|ori)$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfidenceSignal:
    """A single contributing signal to the confidence score."""

    delta: int  # positive or negative points
    label: str  # human-readable description


@dataclass
class ConfidenceResult:
    """Result of a confidence scoring operation."""

    score: int
    tier: str  # "High" | "Medium" | "Low" | "Suspicious" | "Unknown"
    signals: List[ConfidenceSignal]  # all signals that contributed (in order)
    warnings: List[str]  # human-readable warnings (uppercase)

    # ------------------------------------------------------------------
    # Derived convenience helpers
    # ------------------------------------------------------------------

    @property
    def is_suspicious(self) -> bool:
        return self.tier in ("Suspicious", "Unknown")

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def tier_colour_hint(self) -> str:
        """Colour hint for CLI rendering — maps tier to a Typer colour name."""
        return {
            "High": "green",
            "Medium": "yellow",
            "Low": "magenta",
            "Suspicious": "red",
            "Unknown": "cyan",
        }.get(self.tier, "white")

    def rationale_summary(self, max_signals: int = 3) -> str:
        """
        Return a short one-line summary of the top contributing signals.

        Up to *max_signals* signals are included, starting with the most
        impactful (highest absolute delta).

        Example:
            "canonical SW version (+40), hardware number (+25), variant (+10)"
        """
        top = sorted(self.signals, key=lambda s: abs(s.delta), reverse=True)
        parts = [
            f"{s.label} ({'+' if s.delta >= 0 else ''}{s.delta})"
            for s in top[:max_signals]
        ]
        return ", ".join(parts) if parts else "no signals"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_1037_family(family: str) -> bool:
    """Return True if *family* is expected to carry a 1037-prefixed SW version."""
    if not family:
        return False
    fam_upper = family.upper()
    return any(fam_upper.startswith(prefix.upper()) for prefix in _1037_FAMILY_PREFIXES)


def _score_to_tier(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 25:
        return "Medium"
    if score >= 0:
        return "Low"
    return "Suspicious"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score_identity(identity: dict, filename: str = "unknown.bin") -> ConfidenceResult:
    """
    Compute a confidence score for an ECU binary identity.

    Args:
        identity: Dict produced by ``identify_ecu()`` or any compatible source.
                  Expected keys: ``ecu_family``, ``ecu_variant``,
                  ``software_version``, ``hardware_number``, ``calibration_id``,
                  ``match_key``.
        filename: Original filename of the binary (basename only — no path
                  components are required).  Used for filename-based signals.

    Returns:
        :class:`ConfidenceResult` with ``score``, ``tier``, ``signals``,
        and ``warnings``.
    """
    signals: List[ConfidenceSignal] = []
    warnings: List[str] = []

    family: str | None = identity.get("ecu_family")

    # --- Unrecognised binary → Unknown tier, no scoring ---
    if family is None:
        return ConfidenceResult(score=0, tier="Unknown", signals=[], warnings=[])

    sw: str | None = identity.get("software_version")
    hw: str | None = identity.get("hardware_number")
    variant: str | None = identity.get("ecu_variant")
    cal_id: str | None = identity.get("calibration_id")
    match_key: str | None = identity.get("match_key")

    score: int = 0

    # ── Software version ────────────────────────────────────────────────────
    if sw:
        if sw.startswith(("1037", "1039")):
            score += 40
            signals.append(
                ConfidenceSignal(+40, "canonical SW version (1037/1039-prefixed)")
            )
        else:
            score += 15
            signals.append(ConfidenceSignal(+15, f"SW version present ({sw[:12]})"))
    else:
        # Absence of SW is more suspicious when we also have no match_key:
        # the binary is totally unidentifiable in the database.
        if match_key is None:
            score -= 30
            signals.append(
                ConfidenceSignal(-30, "SW ident absent — no match key produced")
            )
        else:
            # match_key was built from a fallback (e.g. calibration_id for LH-Jetronic).
            # SW being absent is expected for those architectures — mild deduction only.
            score -= 10
            signals.append(
                ConfidenceSignal(
                    -10, "SW version absent (match key from fallback field)"
                )
            )

        # Raise the IDENT BLOCK MISSING warning for families that normally carry SW.
        if _is_1037_family(family):
            warnings.append("IDENT BLOCK MISSING")

    # ── Hardware number ──────────────────────────────────────────────────────
    if hw:
        score += 25
        signals.append(ConfidenceSignal(+25, f"hardware number present ({hw})"))

    # ── ECU variant ──────────────────────────────────────────────────────────
    if variant and variant != family:
        score += 10
        signals.append(ConfidenceSignal(+10, f"ECU variant identified ({variant})"))

    # ── Calibration ID ───────────────────────────────────────────────────────
    if cal_id:
        score += 10
        signals.append(ConfidenceSignal(+10, f"calibration ID present ({cal_id[:12]})"))

    # ── Filename signals ─────────────────────────────────────────────────────
    fname = Path(filename).name  # strip any leading path components defensively
    if _TUNING_KEYWORDS.search(fname):
        score -= 25
        signals.append(
            ConfidenceSignal(-25, "tuning/modification keywords in filename")
        )
        warnings.append("TUNING KEYWORDS IN FILENAME")
    elif _GENERIC_FILENAME.match(fname):
        score -= 15
        signals.append(ConfidenceSignal(-15, "generic numbered filename"))
        warnings.append("GENERIC FILENAME")

    return ConfidenceResult(
        score=score,
        tier=_score_to_tier(score),
        signals=signals,
        warnings=warnings,
    )
