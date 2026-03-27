# Bosch ECU Families

All currently supported ECU families are Bosch. The extractor registry is designed to be extended to any manufacturer — see [CONTRIBUTING.md](../../CONTRIBUTING.md) for how to add a new family.

---

## Supported families

| Family | Era | Typical file size | Notes |
|---|---|---|---|
| **EDC1 / EDC2** | 1990–1997 | 32 KB / 64 KB | Audi 80 / A6 TDI, early common-rail diesel. Fixed-size ROM. |
| **EDC 3.x** | 1993–2000 | 128 KB / 256 KB / 512 KB | VAG TDI diesel, BMW diesel, and Opel diesel bridge generation. Three ident formats: VAG HEX block, BMW numeric block (5331xx/3150), and Opel cal block. |
| **EDC15** | 1997–2004 | 512 KB | Two sub-formats: Format A (TSW header) and Format B (C3-fill). Widely used across VAG, Fiat, Volvo, and BMW diesel. |
| **EDC16** | 2003–2008 | 256 KB / 1 MB / 2 MB | Identified by the `0xDECAFE` magic at fixed bank boundaries. Covers VAG PD TDI and CR TDI, BMW diesel (C31/C35), and Opel/GM diesel (C9). SW version is normally `1037`-prefixed decimal; Opel EDC16C9 uses alphanumeric suffixes (e.g. `1037A50286`). |
| **EDC16C9** | 2004–2006 | 1 MB | Opel/GM Vectra-C, Signum, Astra-H diesel. Active section at `0xC0000`; `0xDECAFE` at `0xC003D`. HW number stored as plain ASCII in cal area (unlike VAG EDC16). |
| **EDC17 / MEDC17 / MED17 / ME17** | 2008–present | 2 MB / 4 MB / 8 MB | The dominant modern platform. PSA (Peugeot/Citroën), VAG, BMW, Mercedes diesel and petrol. SW version format: `1037XXXXXXXXX`. |
| **ME9** | 2001–2006 | 2 MB | Full flash dumps for VW / Audi 1.8T 20v (AGU, AEB, APU, AWM and related). Identified by the `Bosch.Common.RamLoader.Me9` RAM-loader anchor. |
| **ME7 / ME7.x** | 1997–2008 | 64 KB – 1 MB | VAG 1.8T (AGU, ARJ, AWP), Porsche, Ferrari, Opel Corsa D. Sub-families ME7.1, ME7.1.1, ME7.5, ME7.5.5, ME7.5.10, ME7.6.2 identified from the ZZ ident block. Earliest pre-production variant (ME7early, ERCOS V2.x RTOS) identified by ERCOS string at 0x200. Minimum full-dump size 64 KB — the ZZ ident block is anchored at offset 0x10000. Also handles two PSA sector-dump formats: **64 KB** (Peugeot 206 1.6i 16v — cal sector only, ZZ at offset 0 instead of 0x10000) and **256 KB** (Peugeot 207 THP 1.6 150HP — ME7.4.x PSA variant, no ZZ block, SW at fixed offset `0x1A`). |
| **MED9 / MED9.x** | 2002–2008 | 512 KB – 2 MB | VAG FSI and TFSI petrol direct injection (AXX, BWA, BYD, CAWB, …). Shares the ME9 RAM-loader but detected by the `MED9` marker. |
| **M1.x** | 1987–1996 | 32 KB – 64 KB | BMW E28/E30/E34/E36, Opel petrol. Unique ROM header magic `\x85\x0a\xf0\x30`; sub-variants M1.3 and M1.7 identified by family marker. Opel M1.x and some BMW M1.7 variants lack the header magic and are identified by a valid reversed-digit ident (`0261`/`1267` prefixes) in the standard ident region. |
| **M1.55 / M1.5.5** | 1994–2002 | 128 KB | Alfa Romeo 155 / 156 / GT (`M1.55`, token at `0x8005`, slash-delimited descriptor). Opel Corsa C / Astra G petrol (`M1.5.5`, token at `~0x0D82F`, GM-style ident block at `~0xD801` — SW is an 8-digit GM number, e.g. `90532609`). Both variants are always exactly 128 KB. |
| **M2.x** | 1993–1999 | 32 KB – 128 KB | VW/Audi M2.9, Porsche 964 (M2.3), and Opel M2.7/M2.8/M2.81. Four ident formats: VAG `MOTOR PMC` label (Format A), Porsche `MOTRONIC` label (Format B), Opel 0xFF-padded space-delimited block (Format C), and Opel reversed-string encoding (Format D, 32 KB M2.7 bins). SW prefix is `1267` or `2227` (never `1037`). |
| **M3.x** | 1989–1999 | 32 KB – 256 KB | BMW E30/E36 petrol (M3.1, M3.3) and PSA/Citroën petrol (MP3.2, MP3.x-PSA, MP7.2). HW and SW are stored in reversed-digit order in the ident block — `hw = digits[0:10][::-1]`, `sw = digits[10:20][::-1]`. Sub-family resolution: `1350000M3` marker → M3.1; `1530000M3` → M3.3 or MP7.2 (256 KB PSA variant); `0000000M3` → MP3.2 or MP3.x-PSA (PSA/Citroën, always 32 KB). SW prefix is `1267` or `2227`. |
| **M5.x / M3.8x** | 1997–2004 | 128 KB – 256 KB | VW / Audi 1.8T (AGU, AUM, APX). Overlaps with ME7 era; distinguished by ident string. |
| **LH-Jetronic** | 1982–1995 | 8 KB – 64 KB | Volvo, early BMW and Mercedes fuel injection. No `1037`-prefixed SW; identification is driven by `calibration_id`. |
| **Motronic Legacy** | various | 2 KB – 32 KB | Early 6802-era Bosch DME-3.2 (Porsche 911 Carrera 3.2), M1.x-early (BMW E30/M3, Porsche 951, early Mercedes), KE-Jetronic (Bosch electronic fuel injection, HW prefix `02808`), and EZK standalone ignition controllers. No ASCII SW version is embedded in most variants; `match_key` is `None` except for KE-Jetronic. |

---

## Confidence scoring for Bosch files

### Software version bonus

The `+40` canonical SW bonus is awarded when `software_version` starts with `"1037"` **or** `"1039"`:

```
+40  software_version starts with "1037" or "1039"   (EDC15, EDC16, EDC17, ME7, ME9, …)
+15  software_version present but non-1037/1039       (M2.x uses 1267/2227; M3.x uses 1267/2227; EDC3x uses cal numbers)
```

The `1039` prefix is used by PSA/Peugeot-Citroën EDC16C34 variants (e.g. Peugeot 3008 1.6 HDI, SW `1039398238`). It is treated as equally canonical as `1037`.

M2.x, M3.x, and EDC 3.x families always produce the `+15` signal — their SW versions never begin with `1037`/`1039` and that is expected, not a defect.

### IDENT BLOCK MISSING warning

A separate concept from the bonus above. The warning fires when `software_version` is `None` for any family listed below, because absence is abnormal for those platforms regardless of their SW prefix format:

`EDC15` · `EDC16` · `EDC17` · `MEDC17` · `MED17` · `ME17` · `ME9` · `MED9` · `ME7` · `ME3` · `ME5` · `M1X` · `M2X` · `M3X` · `M5X` · `EDC3`

Families where SW absence is normal (no `IDENT BLOCK MISSING` warning):

`LH-Jetronic` · `Motronic Legacy`

### Score tiers

| Tier | Score |
|---|---|
| High | ≥ 60 |
| Medium | ≥ 25 |
| Low | ≥ 0 |
| Suspicious | < 0 |
| Unknown | `ecu_family` is `None` — no extractor matched |

---

## How Bosch extractors are structured

Each Bosch family lives in its own package under `src/openremap/tuning/manufacturers/bosch/<family>/`:

```
bosch/
├── edc1/          ← EDC1 / EDC2
├── edc15/         ← EDC15 (Format A + B)
├── edc16/         ← EDC16 (VAG C8/C39/PD, BMW C31/C35, Opel C9)
├── edc17/         ← EDC17 / MEDC17 / MED17 / ME17
├── edc3x/         ← EDC 3.x (VAG HEX, BMW numeric, Opel cal block)
├── lh/            ← LH-Jetronic
├── m1x/           ← M1.x (BMW E28/E30/E34/E36, Opel petrol)
├── m1x55/         ← M1.55 (Alfa Romeo)
├── m2x/           ← M2.x (VW/Audi M2.9, Porsche M2.3, Opel M2.7/M2.8/M2.81)
├── m3x/           ← M3.x (BMW M3.1/M3.3 and PSA/Citroën MP3.2/MP7.2)
├── m5x/           ← M5.x / M3.8x
├── me7/           ← ME7 / ME7.x (including ME7.6.2 for Opel Corsa D)
├── me9/           ← ME9 (full flash, RamLoader)
└── motronic_legacy/  ← DME-3.2, M1.x-early, KE-Jetronic, EZK
```

The registry in `bosch/__init__.py` lists all extractors in priority order — most specific first. When a new binary is submitted, the first extractor whose `can_handle()` returns `True` wins.

---

## Opel/GM notes

Opel ECUs from this era span multiple Bosch families and each uses a distinct ident layout:

| ECU | Family | SW format | HW in binary? |
|---|---|---|---|
| Astra 2.0 DTI / Vectra 1.9 TDI | EDC3 | 7-digit cal number (e.g. `0770164`) | No — filename only |
| Vectra-C / Signum / Astra-H CDTI | EDC16C9 | Alphanumeric `1037` (e.g. `1037A50286`) | Yes — plain ASCII in cal area |
| Calibra 2.0T / Astra C20XE / Calibra 2.5 V6 / Omega 3.0 V6 | M2.7 / M2.8 / M2.81 | `1267xxxxxx` or `2227xxxxxx` | Yes — embedded in ident block |
| Corsa D 1.6T (ME7.6.2) | ME7.6.2 | `1037xxxxxx` | Yes — ZZ ident block (may be past 512 KB mark) |
| Corsa C 1.0 12V / Astra G petrol | M1.5.5 | 8-digit GM number (e.g. `90532609`) | Yes — GM ident block at `~0xD801` (`"<sw8> <prefix2><hw10>..."`) |

For split-ROM EDC3 chips (HHH / LLL or h / l suffix pairs), both physical chips store the **same** 7-digit calibration ID. The byte immediately following the cal number (`H` = 0x48, `L` = 0x4C) is Bosch's built-in chip discriminator.

---

## PSA/Citroën notes

PSA (Peugeot, Citroën) petrol ECUs from the early 1990s use the **M3.x** family, specifically the MP3.2 and MP7.2 sub-variants. These are completely distinct from modern PSA EDC17 diesel bins.

| Vehicle | ECU sub-family | SW format | Calibration ID |
|---|---|---|---|
| Citroën ZX 2.0 16V (0261200218) | MP3.2 | `1267xxxxxx` or `2227xxxxxx` | DAMOS block, e.g. `57/1/MP3.2/14/115.0/DAMOS20/...` |
| Citroën Saxo 1.6i VTS | MP7.2 | `1037xxxxxx` | DAMOS block, e.g. `xx/1/MP7.2/...` |
| Other PSA petrol (`0000000M3` marker, no explicit sub-tag) | MP3.x-PSA | `1267xxxxxx` or `2227xxxxxx` | DAMOS block when present |
| Peugeot 106 1.4 / early PSA petrol (HW `0261200203`) | MP3.1 / MP3.x-PSA | `1267xxxxxx` or `2227xxxxxx` | DAMOS block — **Layout B**: 20-digit ident stored far from the `0000000M3` marker, separated by non-ASCII opcode bytes; requires whole-file digit-run scan |

Key identification details for MP3.2 (32 KB bins):

- Family marker `0000000M3` is embedded at approximately offset `0x1FF2`, overlapping with the trailing zeros of the ident digit string.
- The ident digit string immediately precedes the marker: `digits[0:10][::-1]` → HW (starts `0261`), `digits[10:20][::-1]` → SW (starts `1267` or `2227`).
- The `M3.X` label visible in the ident region (e.g. `...0000000M3.X `) uses `X` as a literal sub-variant character, not a placeholder.
- A DAMOS calibration block in the format `revision/unknown/MP3.2/dataset/...` is stored elsewhere in the binary and is used as `calibration_id`.

> **Important:** PSA MP3.2 bins share the same reversed-digit ident encoding as BMW M1.x and M3.x, and they fall in the same `0261`/`1267` HW/SW prefix range. The `0000000M3` family marker is the definitive discriminator — it is listed as an exclusion in the M1.x extractor to prevent mis-identification.

---

## PSA ME7 sector dump formats

PSA (Peugeot, Citroën) ME7 ECUs appear in two non-standard dump formats in addition to the full 128 KB – 1 MB images described in the main ME7 row. Both are accepted by the ME7 extractor.

### 64 KB PSA calibration sector (Phase 4)

These are standalone exports of the calibration sector that normally lives at offset `0x10000` in a full ME7 dump. When extracted on its own the file is exactly 64 KB and starts with the ZZ marker at offset `0x0` rather than `0x10000`.

| Detail | Value |
|---|---|
| Size | 64 KB (0x10000 bytes) |
| ZZ marker | Offset `0x0` (non-printable third byte) |
| HW + SW | `\xC8`-prefixed ASCII block anywhere in the file |
| Example | Peugeot 206 1.6i 16v — HW `0261206942`, SW `1037353507` |

Extraction uses the standard ME7 production path — the `hw_sw_combined` pattern covers the full 64 KB file.

### 256 KB PSA ME7.4.x calibration sector (Phase 5)

Bosch ME7.4.x PSA-variant ECUs (e.g. Peugeot 207 THP engines) use a compact PowerPC-style header with no ZZ block, no MOTRONIC label, and no embedded HW number. The SW version is at a fixed offset.

| Detail | Value |
|---|---|
| Size | 256 KB (0x40000 bytes) |
| Record marker | `\x02\x00` at offset `0x18` |
| SW version | Plain ASCII `1037xxxxxx` at offset `0x1A` |
| HW number | Not present — filename only |
| Example | Peugeot 207 THP 1.6 150HP — SW `1037394738` |

> These 256 KB PSA ME7.4.x files must not be confused with M5.x / M3.8x (also 256 KB, but identified by a `MOTR`-style ident) or with EDC16 sector dumps (256 KB, identified by `\xDE\xCA\xFE` at `0x3D`).

---

← [Back to README](../../README.md)