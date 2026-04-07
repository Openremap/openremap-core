"""
ECU binary identification confidence scorer.

Computes a numerical identification confidence score for an ECU binary, based
on signals derived from detection quality, extracted identity fields, filename
heuristics, and map-structure analysis.  The score reflects how confidently the
system identified this binary — not whether the binary content is original or
modified.

Higher scores mean the detection cascade matched strongly and more
identity fields were successfully extracted.  Lower scores mean weaker
detection or missing fields — the identification may be incomplete or
unreliable.

The scorer also applies secondary penalties for filename signals that
suggest the binary may have been modified (tuning keywords, generic
filenames).  These reduce confidence in the identification because
modified binaries may have altered or removed identity blocks.

The scorer is **manufacturer-aware** — each manufacturer has its own
definition of a "canonical" software version format, and each ECU family
declares which fields it is architecturally capable of providing.  Fields
that a family never stores (e.g. IAW 1AP has no software_version) are not
penalised when absent.

Score signals
─────────────
  Detection strength
  ~~~~~~~~~~~~~~~~~~
  +15  extractor detection_strength is STRONG  (4+ phases, unique signatures)
  +10  extractor detection_strength is MODERATE (2–3 phases, good signatures)
   +5  extractor detection_strength is WEAK    (minimal checks, heuristic)

  Software version
  ~~~~~~~~~~~~~~~~
  +30  software_version present and matches canonical format for its manufacturer
  +15  software_version present but not in canonical format
  -15  software_version absent AND expected by family profile AND match_key absent
  -10  software_version absent AND expected by family profile AND match_key present
    0  software_version absent AND NOT expected by family profile

  Hardware number
  ~~~~~~~~~~~~~~~
  +20  hardware_number present

  ECU variant
  ~~~~~~~~~~~
  +10  ecu_variant identified (more specific than ecu_family)

  Calibration ID
  ~~~~~~~~~~~~~~
  +10  calibration_id present

  OEM part number
  ~~~~~~~~~~~~~~~
   +5  oem_part_number present

  Filename
  ~~~~~~~~
  -25  filename contains tuning/modification keywords
  -15  generic numbered filename (e.g. 1.bin, 42.ori)

Tiers
─────
  High       score >= 55
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
from typing import List, Optional, Set

# ---------------------------------------------------------------------------
# Family field profiles
# ---------------------------------------------------------------------------
# Each family declares which identity fields it is *expected* to provide when
# the binary is a complete factory dump.
#
# A field NOT listed here is "architecturally absent" for that family — the
# scorer will not penalise its absence.
#
# Lookup is prefix-based: "EDC17C66" matches the "EDC17" entry.  Entries are
# ordered from most-specific to least-specific so that e.g. "ME1.5.5" is
# tried before "ME1" (if we ever had one).
#
# Families with an empty set produce no field-based penalties at all — only
# the detection-strength baseline and filename signals apply.
# ---------------------------------------------------------------------------

_FAMILY_FIELD_PROFILES: list[tuple[str, set[str]]] = [
    # ── Bosch — modern TriCore ──────────────────────────────────────────────
    ("EDC17", {"software_version", "hardware_number", "calibration_id", "ecu_variant"}),
    (
        "MEDC17",
        {"software_version", "hardware_number", "calibration_id", "ecu_variant"},
    ),
    ("MED17", {"software_version", "hardware_number", "calibration_id", "ecu_variant"}),
    ("ME17", {"software_version", "hardware_number", "calibration_id", "ecu_variant"}),
    ("MED9", {"software_version", "hardware_number", "calibration_id", "ecu_variant"}),
    ("MD1", {"software_version", "hardware_number", "calibration_id", "ecu_variant"}),
    # ── Bosch — older families ──────────────────────────────────────────────
    ("EDC16", {"software_version", "hardware_number", "calibration_id"}),
    ("EDC15", {"software_version", "hardware_number", "calibration_id"}),
    ("EDC3", {"software_version", "hardware_number"}),
    ("EDC1", {"software_version", "hardware_number"}),
    ("ME9", {"software_version"}),
    ("ME7", {"software_version", "hardware_number", "calibration_id"}),
    ("ME1.5.5", {"software_version", "hardware_number"}),
    ("M5.", {"software_version", "hardware_number"}),
    ("M4.", {"software_version", "hardware_number", "calibration_id"}),
    ("MP3.", {"software_version", "hardware_number"}),
    ("MP7.", {"software_version", "hardware_number"}),
    ("M3.", {"software_version", "hardware_number", "calibration_id"}),
    ("M2.", {"software_version", "hardware_number"}),
    ("M1.", {"software_version", "hardware_number"}),
    ("MP9", {"software_version", "hardware_number"}),
    ("LH-Jetronic", {"calibration_id"}),
    ("Mono-Motronic", set()),
    ("DME-3.2", set()),
    ("M1.x-early", set()),
    ("KE-Jetronic", set()),
    ("EZK", set()),
    # ── Siemens ─────────────────────────────────────────────────────────────
    ("SID801", {"software_version", "hardware_number", "calibration_id"}),
    ("SID803", {"software_version", "calibration_id"}),
    ("PPD", {"software_version", "hardware_number"}),
    ("SIMOS", {"software_version", "hardware_number"}),
    ("Simtec56", {"software_version", "hardware_number", "calibration_id"}),
    ("EMS2000", set()),
    # ── Delphi ──────────────────────────────────────────────────────────────
    (
        "Multec S",
        {"software_version", "calibration_id", "oem_part_number", "ecu_variant"},
    ),
    ("Multec", {"software_version", "calibration_id", "ecu_variant"}),
    # ── Magneti Marelli ─────────────────────────────────────────────────────
    (
        "MJD 6JF",
        {"software_version", "hardware_number", "calibration_id", "ecu_variant"},
    ),
    ("IAW 1AV", {"software_version", "oem_part_number"}),
    ("IAW 4LV", {"software_version", "hardware_number", "oem_part_number"}),
    ("IAW 1AP", {"calibration_id"}),
]


def _get_family_profile(family: str) -> Optional[set[str]]:
    """
    Return the expected-field set for *family*, or ``None`` if no profile
    matches.

    Matching is case-insensitive prefix-based: ``"EDC17C66"`` matches the
    ``"EDC17"`` entry.
    """
    if not family:
        return None
    fam_upper = family.upper()
    for prefix, fields in _FAMILY_FIELD_PROFILES:
        if fam_upper.startswith(prefix.upper()):
            return fields
    return None


# ---------------------------------------------------------------------------
# Manufacturer-aware canonical SW patterns
# ---------------------------------------------------------------------------
# Each manufacturer has a regex defining what a "well-formed" software version
# looks like for their platform.  A match earns +30 (canonical); a non-match
# still earns +15 (present but unrecognised format).
#
# The previous scorer hard-coded only the Bosch 1037/1039 prefixes.  Now
# every manufacturer can reach the full canonical bonus.
# ---------------------------------------------------------------------------

_CANONICAL_SW_PATTERNS: dict[str, re.Pattern[str]] = {
    # Bosch: 1037, 1039, 1267, 1277, 2227, 2537 followed by 6+ digits
    # (optionally ending with a version suffix like "V0").
    "Bosch": re.compile(r"^(?:1037|1039|1267|1277|2227|2537)\d{6}"),
    # Delphi / Delco: 8-digit GM-style SW part number.
    "Delphi": re.compile(r"^\d{8}$"),
    # Siemens: 9-digit serial, or 5WK9-prefixed part number.
    "Siemens": re.compile(r"^\d{9}$|^5WK9"),
    # Magneti Marelli: several formats depending on family —
    #   MJD 6JF:  5-digit + letter + 3-digit  (e.g. "31315X375")
    #   IAW 1AV:  letter + 3-digit            (e.g. "F012")
    #   IAW 4LV:  4-digit                     (e.g. "3335")
    "Magneti Marelli": re.compile(r"^\d{4,5}[A-Z]\d{3}$|^\d{4}$|^[A-Z]\d{3}$"),
}


def _is_canonical_sw(manufacturer: Optional[str], sw: str) -> bool:
    """Return True if *sw* matches the canonical format for *manufacturer*."""
    if not manufacturer or not sw:
        return False
    pattern = _CANONICAL_SW_PATTERNS.get(manufacturer)
    if pattern is None:
        # Unknown manufacturer — any SW present is treated as canonical so
        # that new manufacturers don't start at a disadvantage.
        return True
    return bool(pattern.search(sw))


# ---------------------------------------------------------------------------
# Detection strength → baseline bonus
# ---------------------------------------------------------------------------

_DETECTION_BONUS: dict[Optional[str], int] = {
    "strong": 15,
    "moderate": 10,
    "weak": 5,
    None: 0,  # backward compat: extractor didn't declare strength
}


def _detection_strength_bonus(detection_strength: Optional[str]) -> int:
    """Map a detection_strength value to its baseline score bonus."""
    if detection_strength is None:
        return _DETECTION_BONUS[None]
    # Accept both enum values and raw strings (e.g. "strong",
    # DetectionStrength.STRONG).
    key = str(detection_strength).lower()
    # Handle DetectionStrength enum .value and .name
    # DetectionStrength.STRONG -> "DetectionStrength.STRONG" via str() on enum
    # but .value -> "strong".  Try both.
    if key in _DETECTION_BONUS:
        return _DETECTION_BONUS[key]
    # Enum __str__ gives "DetectionStrength.STRONG" — extract the value.
    if "." in key:
        key = key.rsplit(".", 1)[-1]
    return _DETECTION_BONUS.get(key, _DETECTION_BONUS[None])


# ---------------------------------------------------------------------------
# Backward-compatible helper — families that should store a SW version
# ---------------------------------------------------------------------------
# This remains as a public function because it is imported by the test suite
# and is a useful diagnostic predicate in its own right.  Internally the
# scorer now uses _get_family_profile() which is strictly more powerful.
# ---------------------------------------------------------------------------

# Prefixes of families whose profile includes "software_version".
_SW_EXPECTED_FAMILY_PREFIXES: tuple[str, ...] = (
    "EDC17",
    "MEDC17",
    "MED17",
    "ME17",
    "MED9",
    "MD1",
    "EDC16",
    "EDC15",
    "EDC3",
    "EDC1",
    "ME9",
    "ME7",
    "ME1.5.5",
    "M5.",
    "M4.",
    "M3.",
    "M2.",
    "M1.",
    "MP3.",
    "MP7.",
    "MP9",
    # Siemens
    "SID801",
    "SID803",
    "PPD",
    "SIMOS",
    "Simtec56",
    # Delphi
    "Multec",  # covers both "Multec" and "Multec S"
    # Marelli (those that store SW)
    "MJD 6JF",
    "IAW 1AV",
    "IAW 4LV",
)


def _is_1037_family(family: str) -> bool:
    """
    Return True if *family* is expected to carry a software version.

    .. deprecated::
        Use ``_family_expects_field(family, "software_version")`` instead.
        Retained for backward compatibility with existing tests and external
        callers.

    Despite its name this function now covers **all** manufacturers, not
    just Bosch 1037-prefixed families.
    """
    if not family:
        return False
    fam_upper = family.upper()
    return any(fam_upper.startswith(p.upper()) for p in _SW_EXPECTED_FAMILY_PREFIXES)


def _family_expects_field(family: str, field_name: str) -> bool:
    """Return True if *family*'s profile includes *field_name*."""
    profile = _get_family_profile(family)
    if profile is None:
        # No profile registered — be conservative and assume the field is
        # expected (so absence is flagged rather than silently ignored).
        return True
    return field_name in profile


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
            "canonical SW version (+30), hardware number (+20), variant (+10)"
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


def _score_to_tier(score: int) -> str:
    if score >= 55:
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
    Compute an identification confidence score for an ECU binary.

    Args:
        identity: Dict produced by ``identify_ecu()`` or any compatible source.
                  Expected keys: ``ecu_family``, ``ecu_variant``,
                  ``software_version``, ``hardware_number``, ``calibration_id``,
                  ``match_key``, ``manufacturer``, ``oem_part_number``,
                  ``detection_strength``.
        filename: Original filename of the binary (basename only — no path
                  components are required).  Used for filename-based signals.

    Returns:
        :class:`ConfidenceResult` with ``score`` (identification confidence),
        ``tier``, ``signals`` (individual contributing factors), and
        ``warnings``.
    """
    signals: List[ConfidenceSignal] = []
    warnings: List[str] = []

    family: str | None = identity.get("ecu_family")

    # --- Unrecognised binary → Unknown tier, no scoring ---
    if family is None:
        return ConfidenceResult(score=0, tier="Unknown", signals=[], warnings=[])

    manufacturer: str | None = identity.get("manufacturer")
    sw: str | None = identity.get("software_version")
    hw: str | None = identity.get("hardware_number")
    variant: str | None = identity.get("ecu_variant")
    cal_id: str | None = identity.get("calibration_id")
    match_key: str | None = identity.get("match_key")
    oem_pn: str | None = identity.get("oem_part_number")
    det_strength = identity.get("detection_strength")

    profile: set[str] | None = _get_family_profile(family)

    score: int = 0

    # ── Detection strength baseline ─────────────────────────────────────────
    ds_bonus = _detection_strength_bonus(det_strength)
    if ds_bonus > 0:
        score += ds_bonus
        # Normalise enum to a readable label.
        ds_label = str(det_strength)
        if "." in ds_label:
            ds_label = ds_label.rsplit(".", 1)[-1]
        signals.append(
            ConfidenceSignal(+ds_bonus, f"detection strength {ds_label.lower()}")
        )

    # ── Software version ────────────────────────────────────────────────────
    sw_expected = _family_expects_field(family, "software_version")

    if sw:
        if _is_canonical_sw(manufacturer, sw):
            score += 30
            signals.append(ConfidenceSignal(+30, "canonical SW version"))
        else:
            score += 15
            signals.append(ConfidenceSignal(+15, f"SW version present ({sw[:12]})"))
    else:
        if sw_expected:
            # SW is expected but absent — how bad depends on match_key.
            if match_key is not None:
                score -= 10
                signals.append(
                    ConfidenceSignal(
                        -10,
                        "SW version absent (match key from fallback field)",
                    )
                )
            else:
                score -= 15
                signals.append(
                    ConfidenceSignal(
                        -15,
                        "SW ident absent — no match key produced",
                    )
                )
            # Raise the IDENT BLOCK MISSING warning for families that
            # normally carry a software version.
            warnings.append("IDENT BLOCK MISSING")
        # else: SW not expected → no penalty, no signal.

    # ── Hardware number ──────────────────────────────────────────────────────
    if hw:
        score += 20
        signals.append(ConfidenceSignal(+20, f"hardware number present ({hw})"))

    # ── ECU variant ──────────────────────────────────────────────────────────
    if variant and variant != family:
        score += 10
        signals.append(ConfidenceSignal(+10, f"ECU variant identified ({variant})"))

    # ── Calibration ID ───────────────────────────────────────────────────────
    if cal_id:
        score += 10
        signals.append(ConfidenceSignal(+10, f"calibration ID present ({cal_id[:12]})"))

    # ── OEM part number ──────────────────────────────────────────────────────
    if oem_pn:
        score += 5
        signals.append(ConfidenceSignal(+5, f"OEM part number present ({oem_pn[:16]})"))

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
