"""
Magneti Marelli MJD 6JF ECU family package.

This package implements the binary extractor for the Magneti Marelli MJD 6JF
diesel ECU family, used in GM/Opel/Vauxhall diesel applications (e.g. Corsa
D/E 1.3 CDTI with UZ13DT engine).

Two binary layouts are supported:

  462848 bytes (0x71000) — Calibration-only dump
    16-byte ASCII header "C M D - M C D   " followed by 0xFF padding,
    then calibration data from 0x60000 onward.

  458752 bytes (0x70000) — Full flash dump
    PowerPC executable code from 0x00000, calibration data from 0x60000.
    Contains PPCCMFPE300/PPCCMFPI300 CPU identifiers and Italian dev
    comments ("Progetto SW 6JF") in the code section.

Modules:
    patterns  — Regex patterns, search regions, detection/exclusion signatures
    extractor — MarelliMJD6JFExtractor (BaseManufacturerExtractor subclass)
"""

from openremap.core.manufacturers.marelli.mjd6jf.extractor import (
    MarelliMJD6JFExtractor,
)

__all__ = ["MarelliMJD6JFExtractor"]
