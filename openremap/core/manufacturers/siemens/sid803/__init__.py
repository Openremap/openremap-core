"""
Siemens SID803 / SID803A ECU family package.

This package implements the binary extractor for the Siemens SID803 and
SID803A diesel ECU families, used in PSA (Peugeot/Citroën), Ford, and
Jaguar/Land Rover diesel applications from the mid-2000s onward.

Two sub-groups are supported:

  SID803  (458–462 KB)
    - PO project references (PO011, PO220, PO320)
    - T5_AA0Y1PO0AA00 records
    - 111PO repeated blocks
    - S120 S-record references
    - No embedded 5WS4 hardware part in some files

  SID803A (2 MB / 2097152 bytes)
    - 5WS4 hardware part numbers (5WS40262B-T, 5WS40612B-T)
    - S122 S-record references (higher series than SID801)
    - PO220, PO320 project codes
    - 111PO blocks
    - FOIX references (FOIXS160001225B0)
    - CAPO calibration datasets

Modules:
    patterns  — Regex patterns, search regions, detection/exclusion signatures
    extractor — SiemensSID803Extractor (BaseManufacturerExtractor subclass)
"""
