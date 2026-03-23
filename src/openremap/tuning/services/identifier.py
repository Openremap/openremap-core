"""
ECU Identifier

Identifies a single ECU binary by iterating the manufacturer registry
and delegating to the first extractor that claims the binary.

Falls back to a generic response (unknown manufacturer) when no extractor
matches.

Returns the lean identity fields:
    manufacturer, match_key, ecu_family, ecu_variant,
    software_version, hardware_number, calibration_id, file_size, sha256 (full file).

Full rich-extraction logic is preserved cold in the legacy/ reference folder.
"""

import hashlib
from typing import Dict, Optional

from openremap.tuning.manufacturers import EXTRACTORS


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

    for extractor in EXTRACTORS:
        if extractor.can_handle(data):
            rich = extractor.extract(data, filename)
            return _to_identity(rich, file_size, sha256)

    return _unknown_identity(file_size, sha256)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _to_identity(rich: Dict, file_size: int, sha256: str) -> Dict:
    """
    Map the rich extractor output down to the lean identity fields.

    All other fields (md5, sha256_first_64kb, calibration_version,
    sw_base_version, serial_number, dataset_number, oem_part_number,
    raw_strings) are intentionally dropped.
    """
    return {
        "manufacturer": rich.get("manufacturer"),
        "match_key": rich.get("match_key"),
        "ecu_family": rich.get("ecu_family"),
        "ecu_variant": rich.get("ecu_variant"),
        "software_version": rich.get("software_version"),
        "hardware_number": rich.get("hardware_number"),
        "calibration_id": rich.get("calibration_id"),
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
        "file_size": file_size,
        "sha256": sha256,
    }
