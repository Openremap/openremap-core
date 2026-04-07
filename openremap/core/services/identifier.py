"""
ECU Identifier

Identifies a single ECU binary by iterating the manufacturer registry
and delegating to the first extractor that claims the binary.

Falls back to a generic response (unknown manufacturer) when no extractor
matches.

Returns the lean identity fields:
    manufacturer, match_key, ecu_family, ecu_variant,
    software_version, hardware_number, calibration_id,
    oem_part_number, detection_strength, detection_evidence,
    file_size, sha256 (full file).

Full rich-extraction logic is preserved cold in the legacy/ reference folder.
"""

import hashlib
from typing import Dict, Optional, Tuple

from openremap.core.manufacturers import get_extractors


def identify_ecu(data: bytes, filename: str = "unknown.bin") -> Dict:
    """
    Identify a single ECU binary.

    Iterates the manufacturer registry and delegates to the first extractor
    that can handle the binary. Falls back to a generic response when nothing
    matches.

    Args:
        data:     Raw bytes of the ECU binary.
        filename: Original filename — used for display only.

    Returns:
        Dict compatible with ECUIdentitySchema.
    """
    sha256 = hashlib.sha256(data).hexdigest()
    file_size = len(data)

    for extractor in get_extractors():
        if extractor.can_handle(data):
            rich = extractor.extract(data, filename)
            detection_strength = getattr(extractor, "detection_strength", None)
            detection_evidence = getattr(extractor, "last_detection_evidence", ())
            return _to_identity(
                rich, file_size, sha256, detection_strength, detection_evidence
            )

    return _unknown_identity(file_size, sha256)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _to_identity(
    rich: Dict,
    file_size: int,
    sha256: str,
    detection_strength: Optional[str] = None,
    detection_evidence: Tuple[str, ...] = (),
) -> Dict:
    """
    Map the rich extractor output down to the lean identity fields.

    All other fields (md5, sha256_first_64kb, calibration_version,
    sw_base_version, serial_number, dataset_number, raw_strings)
    are intentionally dropped.

    ``oem_part_number`` is now included — Marelli and Delphi families
    use it as a primary identifier and the confidence scorer awards
    points for its presence.

    ``detection_strength`` is injected from the extractor class attribute
    rather than from the rich dict (it is a property of the extractor,
    not of a particular extraction result).

    ``detection_evidence`` is the tuple of evidence tags collected by the
    extractor's ``can_handle()`` method.  The confidence scorer uses the
    evidence count and composition to compute a dynamic detection-quality
    bonus that supersedes the static ``detection_strength`` value.
    """
    return {
        "manufacturer": rich.get("manufacturer"),
        "match_key": rich.get("match_key"),
        "ecu_family": rich.get("ecu_family"),
        "ecu_variant": rich.get("ecu_variant"),
        "software_version": rich.get("software_version"),
        "hardware_number": rich.get("hardware_number"),
        "calibration_id": rich.get("calibration_id"),
        "oem_part_number": rich.get("oem_part_number"),
        "detection_strength": detection_strength,
        "detection_evidence": detection_evidence,
        "file_size": file_size,
        "sha256": sha256,
    }


def _unknown_identity(file_size: int, sha256: str) -> Dict:
    """
    Fallback identity for unrecognised binaries.
    All identification fields are None.
    """
    return {
        "manufacturer": None,
        "match_key": None,
        "ecu_family": None,
        "ecu_variant": None,
        "software_version": None,
        "hardware_number": None,
        "calibration_id": None,
        "oem_part_number": None,
        "detection_strength": None,
        "detection_evidence": (),
        "file_size": file_size,
        "sha256": sha256,
    }
