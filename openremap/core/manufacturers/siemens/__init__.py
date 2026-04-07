from openremap.core.manufacturers.siemens.sid801.extractor import (
    SiemensSID801Extractor,
)
from openremap.core.manufacturers.siemens.sid803.extractor import (
    SiemensSID803Extractor,
)
from openremap.core.manufacturers.siemens.simtec56.extractor import (
    SiemensSimtec56Extractor,
)
from openremap.core.manufacturers.siemens.simos.extractor import (
    SiemensSimosExtractor,
)
from openremap.core.manufacturers.siemens.ppd.extractor import SiemensPPDExtractor
from openremap.core.manufacturers.siemens.ems2000.extractor import (
    SiemensEMS2000Extractor,
)
from openremap.core.manufacturers.base import BaseManufacturerExtractor

# ---------------------------------------------------------------------------
# Siemens extractor registry — order matters, most specific first.
#
# SiemensSimtec56Extractor — Simtec 56 family (1995–2000): Opel/Vauxhall
#                            X18XE and X20XEV petrol ECUs (Vectra B, Astra,
#                            Omega B, Calibra).  128 KB (131 072 bytes) bins
#                            identified by the RS/RT ident record containing
#                            an 8-digit GM part number and Siemens 5WK9 part
#                            number, combined with the 8051 LJMP header magic
#                            (\x02\x00\xb0).  Strong positive detection —
#                            fully disjoint from SIMOS (SIMOS excludes 5WK9
#                            in its exclusion list) and from EMS2000 (different
#                            file size: 128 KB vs 256 KB).
#                            Must come FIRST — strongest positive signatures
#                            of all Siemens extractors at this size.
#
# SiemensSimosExtractor  — SIMOS family (late 1990s–mid 2000s): VAG petrol
#                          ECUs (VW/Audi/Skoda/Seat).  Three sub-types by
#                          size: 131KB EEPROM, 262KB SIMOS 2.x EEPROM, and
#                          524KB SIMOS 3.x full flash.  Detection uses a
#                          layered strategy: positive keyword signatures
#                          (b"SIMOS", b"5WP4", b"111s21", b"s21_", b"cas21"),
#                          falling back to header magic + size gate with
#                          explicit exclusion of all Bosch/SID/PPD families.
#                          Must come BEFORE EMS2000 — SIMOS has positive
#                          detection signatures and should be tried first.
#
# SiemensPPDExtractor    — PPD1.x family (2003–2008): Siemens/VDO diesel ECUs
#                          for VAG 2.0 TDI PD (Pumpe-Düse) engines.
#                          Three sub-variants: PPD1.1, PPD1.2, PPD1.5.
#                          Identified by the "PPD1." ASCII string anywhere in
#                          the binary, combined with "111SN" SN project codes
#                          and "CASN" calibration dataset references.
#                          File sizes range from 250 KB to 2 MB.
#                          Bosch signatures are explicitly excluded.
#                          Must come AFTER SIMOS (disjoint families, but SIMOS
#                          excludes PPD signatures so ordering is unambiguous)
#                          and BEFORE EMS2000 (PPD has strong positive
#                          detection signatures; EMS2000 detects by exclusion).
#
# SiemensEMS2000Extractor — EMS2000 family (1996–2004): Volvo S40/V40/S60/
#                           S70/V70 T4/T5 turbo petrol ECUs.  256KB "dark"
#                           bins with virtually no embedded ASCII metadata.
#                           Detection is by exclusion: exact 256KB size gate,
#                           reject if ANY known manufacturer signature is
#                           found, accept only if the 4-byte header magic
#                           matches the single known EMS2000 sample.
#                           Lowest confidence of all Siemens extractors.
#
# SiemensSID803Extractor — SID803 / SID803A family (mid-2000s onward):
#                          PSA (Peugeot/Citroën), Ford, Jaguar/Land Rover
#                          diesel ECUs.  Two sub-groups by file size:
#                            - SID803  (458–462 KB): PO project codes,
#                              111PO blocks, S120 S-records.
#                            - SID803A (2 MB): 5WS4 hardware idents,
#                              S122 S-records, CAPO calibration datasets,
#                              FOIX references.
#                          Detection: size gate (458752 / 462848 / 2097152)
#                          + PO/111PO/S122 positive signatures with PM3
#                          exclusion (PM3 → SID801, never SID803).
#                          Must come AFTER PPDExtractor — PPD1.x files can
#                          overlap in the 2 MB size range and have stronger
#                          positive signatures (b"PPD1.").  Must come BEFORE
#                          EMS2000 — SID803 has strong positive detection
#                          (PO blocks, S-records) while EMS2000 detects by
#                          exclusion.
#
# SiemensSID801Extractor — SID801 / SID801A family (2001–2006): PSA and Ford
#                          HDi diesel ECUs (DW10/DW12 engines, 2.0 HDi and
#                          2.2 HDi).  Exactly 512 KB (524288 bytes) bins
#                          identified by 5WS4 hardware part number prefix
#                          and/or PM3 project codes in the first 128 KB.
#                          Detection: exact 524288-byte size gate + positive
#                          5WS4/PM3 signatures with Bosch and SID803
#                          exclusion.  Must come BEFORE SID803 — SID803
#                          explicitly excludes PM3 signatures (PM3 → SID801,
#                          never SID803) and SID801 explicitly excludes
#                          SID803, making the two fully disjoint.  Must come
#                          AFTER PPD — PPD1.x files never overlap at 512 KB
#                          but ordering after PPD keeps the strongest-first
#                          convention.
# ---------------------------------------------------------------------------

EXTRACTORS: list[BaseManufacturerExtractor] = [
    SiemensSimtec56Extractor(),
    SiemensSimosExtractor(),
    SiemensPPDExtractor(),
    SiemensSID801Extractor(),
    SiemensSID803Extractor(),
    SiemensEMS2000Extractor(),
]

__all__ = [
    "EXTRACTORS",
    "SiemensSID801Extractor",
    "SiemensSID803Extractor",
    "SiemensSimtec56Extractor",
    "SiemensSimosExtractor",
    "SiemensPPDExtractor",
    "SiemensEMS2000Extractor",
]
