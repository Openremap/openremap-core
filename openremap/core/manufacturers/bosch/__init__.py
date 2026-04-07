from openremap.core.manufacturers.bosch.edc1.extractor import BoschEDC1Extractor
from openremap.core.manufacturers.bosch.motronic_legacy.extractor import (
    BoschMotronicLegacyExtractor,
)
from openremap.core.manufacturers.bosch.mono.extractor import BoschMonoExtractor
from openremap.core.manufacturers.bosch.edc3x.extractor import BoschEDC3xExtractor
from openremap.core.manufacturers.bosch.edc17.extractor import BoschExtractor
from openremap.core.manufacturers.bosch.edc16.extractor import BoschEDC16Extractor
from openremap.core.manufacturers.bosch.edc15.extractor import BoschEDC15Extractor
from openremap.core.manufacturers.bosch.lh.extractor import BoschLHExtractor
from openremap.core.manufacturers.bosch.m1x.extractor import BoschM1xExtractor
from openremap.core.manufacturers.bosch.m1x55.extractor import BoschM1x55Extractor
from openremap.core.manufacturers.bosch.m2x.extractor import BoschM2xExtractor
from openremap.core.manufacturers.bosch.m3x.extractor import BoschM3xExtractor
from openremap.core.manufacturers.bosch.m4x.extractor import BoschM4xExtractor
from openremap.core.manufacturers.bosch.m5x.extractor import BoschM5xExtractor
from openremap.core.manufacturers.bosch.mp9.extractor import BoschMP9Extractor
from openremap.core.manufacturers.bosch.me155.extractor import BoschME155Extractor
from openremap.core.manufacturers.bosch.me7.extractor import BoschME7Extractor
from openremap.core.manufacturers.bosch.me9.extractor import BoschME9Extractor
from openremap.core.manufacturers.base import BaseManufacturerExtractor

# ---------------------------------------------------------------------------
# Bosch extractor registry — order matters, most specific first.
#
# BoschEDC1Extractor  — EDC1/EDC2 family (1990–1997): tiny 32KB/64KB Audi 80
#                       and A6 TDI bins. Identified by file size (32KB or 64KB
#                       exactly) and the HW.SW dot-delimited ASCII ident record
#                       in the last 256 bytes. SW prefix is 2287, 2537, or 1037.
#                       Must come FIRST — its 32KB/64KB size gate makes it
#                       completely disjoint from every other Bosch extractor,
#                       but placing it first makes the intent unambiguous.
#
# BoschEDC3xExtractor — EDC 3.x family (1993–2000): VAG TDI diesel ECUs bridging
#                       EDC1/EDC2 and EDC15. Two sub-groups: 256KB "VV33" bins
#                       (028906021xx, 038906018xx) and 128KB/512KB c3-fill bins
#                       (038906018AH, 4B0907401AA/AC). Identified by file size in
#                       {128KB, 256KB, 512KB}, absence of all later-family
#                       signatures (TSW, EDC15, EDC16, EDC17, ME7., MOTR, etc.),
#                       and the distinctive ASCII ident block containing the OEM
#                       part, displacement, "EDC SG/AG", Bosch HW number, and a
#                       dataset code immediately followed by "HEX". Must come
#                       AFTER BoschEDC1Extractor (disjoint by size) and BEFORE
#                       BoschM1xExtractor — the 256KB size overlaps with several
#                       other Bosch families, so the exclusion set must fire
#                       before the ident check for correctness.
#
# BoschEDC16Extractor — EDC16 family (2003–2008): identified by the unique
#                       \xde\xca\xfe header magic at a fixed offset within
#                       the active flash section, and/or the "EDC16Cxx/..."
#                       slash-delimited family string in the cal area.
#                       File size is always exactly 256KB, 1MB or 2MB.
#                       Must come before BoschEDC15Extractor (both share the
#                       1037 SW prefix) and before BoschExtractor (which has
#                       b"EDC16" in its detection signatures).
#
# BoschM1xExtractor  — M1.x (1987–1996): unique 4-byte ROM header magic,
#                      never overlaps with any modern Bosch family.
#
# BoschMotronicLegacyExtractor — Legacy 6802-era Bosch bins (≤ 32KB, no ASCII
#                      ident block): Bosch DME-3.2 (Porsche 911 3.2, 2KB–4KB),
#                      M1.x-early small ROMs (BMW E30/M3, Porsche 951, early
#                      Mercedes, 4KB–16KB), KE-Jetronic (028080/028090 trailer,
#                      up to 32KB), and EZK standalone ignition (32KB, 0x815C
#                      header).  Must come AFTER BoschM1xExtractor because the
#                      M1xExtractor exclusion set includes the \\x85\\x0a\\xf0\\x30
#                      magic which disjoints the two cleanly.  Must come BEFORE
#                      BoschMonoExtractor and BoschM3xExtractor.
#
# BoschMonoExtractor — Mono-Motronic (MA1.2 / MA1.2.3, ~1989–1997): VW/Audi/
#                      Seat single-point injection ECUs.  8051 CPU, 32KB or
#                      64KB dumps.  Detected by 8051 LJMP header (\x02\x05)
#                      + PMC keyword.  Disjoint from M1.x (different reset
#                      vector, no reversed-digit ident), M2.x/M5.x (no
#                      '"0000000M' marker, no MOTRONIC label), and legacy
#                      (different header bytes).  Must come AFTER
#                      BoschMotronicLegacyExtractor (legacy exclusion set
#                      includes '"0000000M' which is absent from Mono bins,
#                      so there is no collision — but ordering after legacy
#                      makes the intent clear).  Must come BEFORE
#                      BoschM3xExtractor — M3.x bins carry the "1350000M3" /
#                      "1530000M3" marker which is in the legacy exclusion set,
#                      so no overlap is possible.
#
# BoschM1x55Extractor — M1.55 (1994–2002): Alfa Romeo 128KB petrol ECU bins
#                       (Alfa 155/156/GT/Spider 2.0TS, 1.8TS, 2.5V6).
#                       Motorola 68K-derivative CPU, 128KB size gate, detected
#                       by the b"M1.55" family token at 0x08005. Disjoint from
#                       M1.x (different size and ROM header magic), M5.x (no
#                       MOTR ident block, SW prefix 1037 is shared but M5x
#                       explicitly excludes it), and all EDC families.
#                       Must come AFTER M1x (M1x is 32KB only, no size overlap)
#                       and BEFORE M5x (M5x also handles 128KB but excludes
#                       b"1037" SW prefix which M1.55 has).
#
# BoschM3xExtractor  — M3.x (1989–1999): no ME7/EDC17 signatures at all,
#                      must be confirmed before the broader extractors run.
#
# BoschM4xExtractor  — M4.x (Volvo, 1994–2002): Volvo 850 / 960 / S70 / V70
#                      / S60 / S80 petrol ECUs.  M4.3 at 64KB, M4.4 at 128KB.
#                      Identified by DAMOS "/M4.3/" or "/M4.4/" slash-delimited
#                      family marker and/or a sequential-digit ident block
#                      (HW+SW in direct order, NOT reversed) in the last 2KB.
#                      Must come AFTER BoschM3xExtractor (M3.x uses reversed
#                      digits and different family markers — completely disjoint)
#                      and BEFORE BoschM2xExtractor (M2.x uses different markers
#                      and is in the same size range at 128KB).
#
# BoschM2xExtractor  — M2.x (1993–1999): identified by the unique
#                      '"0000000M2.' family marker. Placed before ME7 to
#                      correctly handle the Porsche 964 (M2.3) 32 KB bin.
#
# BoschLHExtractor   — LH-Jetronic (1982–1995): unique \xd5\x28 anchor or
#                      explicit 'LH-JET'/'LH24x'/'LH22x' string.
#
# BoschM5xExtractor  — M5.x / M3.8x (1997–2004): VW/Audi 1.8T petrol ECUs
#                      (AGU, AUM, APX engine codes). 128KB or 256KB bins.
#                      Identified by M5./M3.8 family string and MOTR+HW+SW
#                      ident block in the first 64KB. Must come before
#                      BoschME7Extractor — same CPU generation, overlapping
#                      HW prefix (0261), but no ZZ\xff\xff marker at 0x10000.
#                      The ZZ\xff\xff exclusion in EXCLUSION_SIGNATURES
#                      prevents ME7 from stealing these bins; the size gate
#                      (128KB / 256KB only) prevents M5x from stealing any
#                      larger ME7 bin.
#
# BoschMP9Extractor  — MP 9.0 (1996–2002): VW/Seat/Skoda 1.0–1.6L petrol
#                      ECUs. 64KB dumps only. Detected by "MOTRONIC MP 9"
#                      label in the last 1 KB and/or "MP9" + "0261xxxxxx"
#                      HW pattern. Must come before BoschME7Extractor —
#                      b"MOTRONIC" alone was previously a false-positive
#                      trigger for ME7. The 64KB size gate is completely
#                      disjoint from M5x (128/256KB) and ME7 (512KB+).
#                      Must come after BoschM5xExtractor for clarity.
#
# BoschME155Extractor — ME1.5.5 (1999–2005): Opel/Vauxhall petrol ECUs
#                       (Astra-G Z20LET, Corsa-C Z12XE/Z12XEP).
#                       C167CR CPU, 512KB flash — same size and ZZ ident
#                       offset (0x10000) as ME7, but the ZZ descriptor has
#                       a printable ASCII byte at 0x10002 (0x34 = '4')
#                       whereas ME7 has non-printable bytes (0xFF/0x00/0x01).
#                       Family anchor "/ME1.5.5/" in the ident window
#                       confirms the match.  Must come BEFORE
#                       BoschME7Extractor — ME7 already rejects these via
#                       its Phase 3 guard, but placing ME1.5.5 first makes
#                       detection order explicit and avoids any ambiguity.
#
# BoschME7Extractor  — ME7 family: no EDC17/MEDC17 signatures, must be
#                      confirmed before the broad BoschExtractor runs.
#
# BoschME9Extractor   — ME9 family (2000–2005): Bosch Motronic ME9 full 2 MB
#                       flash dumps. Detected by the unique
#                       "Bosch.Common.RamLoader.Me9" string (absent from all
#                       other Bosch families). MED9 bins are explicitly
#                       excluded so this extractor never conflicts with
#                       BoschExtractor. Must come before BoschExtractor
#                       (which rejects ME9 via Guard 3 but runs last anyway).
#
# BoschEDC15Extractor — EDC15 family (1997–2004): identified by TSW string
#                       at 0x8000 (Format A) or 0xC3 fill + 1037 SW (Format B).
#                       Must come before BoschExtractor to avoid the broad
#                       extractor stealing bins via the BOSCH string.
#
# BoschExtractor     — Modern Bosch (EDC17, MEDC17, MED17, EDC16, …):
#                      broadest match, always last.
# ---------------------------------------------------------------------------

EXTRACTORS: list[BaseManufacturerExtractor] = [
    BoschEDC1Extractor(),
    BoschEDC3xExtractor(),
    BoschM1xExtractor(),
    BoschMotronicLegacyExtractor(),
    BoschMonoExtractor(),
    BoschM1x55Extractor(),
    BoschM3xExtractor(),
    BoschM4xExtractor(),
    BoschM2xExtractor(),
    BoschLHExtractor(),
    BoschM5xExtractor(),
    BoschMP9Extractor(),
    BoschME155Extractor(),
    BoschME7Extractor(),
    BoschME9Extractor(),
    BoschEDC16Extractor(),
    BoschEDC15Extractor(),
    BoschExtractor(),
]

__all__ = [
    "EXTRACTORS",
    "BoschEDC1Extractor",
    "BoschEDC3xExtractor",
    "BoschExtractor",
    "BoschEDC16Extractor",
    "BoschEDC15Extractor",
    "BoschLHExtractor",
    "BoschM1xExtractor",
    "BoschMonoExtractor",
    "BoschMotronicLegacyExtractor",
    "BoschM1x55Extractor",
    "BoschM2xExtractor",
    "BoschM3xExtractor",
    "BoschM4xExtractor",
    "BoschM5xExtractor",
    "BoschMP9Extractor",
    "BoschME155Extractor",
    "BoschME7Extractor",
    "BoschME9Extractor",
]
