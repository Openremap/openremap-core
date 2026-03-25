# Bosch ECU Families

All currently supported ECU families are Bosch. The extractor registry is designed to be extended to any manufacturer — see [CONTRIBUTING.md](../../CONTRIBUTING.md) for how to add a new family.

---

## Supported families

| Family | Era | Typical file size | Notes |
|---|---|---|---|
| **EDC1 / EDC2** | 1990–1997 | 32 KB / 64 KB | Audi 80 / A6 TDI, early common-rail diesel. Fixed-size ROM. |
| **EDC 3.x** | 1993–2000 | 128 KB | VAG TDI diesel bridge generation. Identified by VV33 / HEX ident blocks. |
| **EDC15** | 1997–2004 | 512 KB | Two sub-formats: Format A (TSW header) and Format B (C3-fill). Widely used across VAG, Fiat, Volvo, and BMW diesel. |
| **EDC16** | 2003–2008 | 256 KB / 1 MB / 2 MB | Identified by the `0xDECAFE` magic at fixed bank boundaries. Covers VAG PD TDI and CR TDI. |
| **EDC17 / MEDC17 / MED17 / ME17** | 2008–present | 2 MB / 4 MB / 8 MB | The dominant modern platform. PSA (Peugeot/Citroën), VAG, BMW, Mercedes diesel and petrol. SW version format: `1037XXXXXXXXX`. |
| **ME9** | 2001–2006 | 2 MB | Full flash dumps for VW / Audi 1.8T 20v (AGU, AEB, APU, AWM and related). Identified by the `Bosch.Common.RamLoader.Me9` RAM-loader anchor. |
| **ME7 / ME7.x** | 1999–2006 | 128 KB – 512 KB | VAG 1.8T (AGU, ARJ, AWP), Porsche, Ferrari. Sub-families ME7.1, ME7.1.1, ME7.5, ME7.5.10 identified from the ident block. |
| **MED9 / MED9.x** | 2002–2008 | 512 KB – 2 MB | VAG FSI and TFSI petrol direct injection (AXX, BWA, BYD, CAWB, …). Shares the ME9 RAM-loader but detected by the `MED9` marker. |
| **M1.x** | 1987–1996 | 32 KB – 64 KB | BMW E28/E30/E34, early VAG. Unique ROM header; identified by `M1.x` ident block. |
| **M1.55** | 1994–2002 | 128 KB | Alfa Romeo 155 / 156 / GT. Fixed 128 KB; identified by the `M1.55` string and ECU part number. |
| **M2.x** | 1993–1999 | 32 KB | Porsche 964 (M2.3) and related. Very compact binaries; identified by `M2.x` ident pattern. |
| **M3.x** | 1989–1999 | 32 KB – 128 KB | BMW E30 / E36 petrol (M3.1, M3.3). Identified by part-number prefix and ident block. |
| **M5.x / M3.8x** | 1997–2004 | 128 KB – 256 KB | VW / Audi 1.8T (AGU, AUM, APX). Overlaps with ME7 era; distinguished by ident string. |
| **LH-Jetronic** | 1982–1995 | 8 KB – 64 KB | Volvo, early BMW and Mercedes fuel injection. No `1037`-prefixed SW; identification is driven by `calibration_id`. |
| **Motronic Legacy** | various | 16 KB – 64 KB | Early 6802-era Bosch DME / KE-Motronic / EZK ignition units. Identified by legacy ident strings. |

---

## Confidence scoring for Bosch files

The confidence system is Bosch-aware for one specific signal: Bosch ECUs from the EDC15 era onwards embed a **`1037`-prefixed software version** (e.g. `1037541778`) in the binary. When this is present, the scorer awards a larger bonus (+40) than for a generic SW version (+15). When it is absent for a family that normally carries it, the `IDENT BLOCK MISSING` warning is raised.

Families expected to carry a `1037`-prefixed SW version:

`EDC15` · `EDC16` · `EDC17` · `MEDC17` · `MED17` · `ME17` · `ME9` · `MED9` · `ME7` · `M5.x` · `EDC3x` · `M1x` · `M2x` · `M3x`

Families where SW absence is normal (no `IDENT BLOCK MISSING` warning):

`LH-Jetronic` · `Motronic Legacy`

---

## How Bosch extractors are structured

Each Bosch family lives in its own package under `src/openremap/tuning/manufacturers/bosch/<family>/`:

```
bosch/
├── edc1/          ← EDC1 / EDC2
├── edc15/         ← EDC15 (Format A + B)
├── edc16/         ← EDC16
├── edc17/         ← EDC17 / MEDC17 / MED17 / ME17
├── edc3x/         ← EDC 3.x
├── lh/            ← LH-Jetronic
├── m1x/           ← M1.x
├── m1x55/         ← M1.55 (Alfa Romeo)
├── m2x/           ← M2.x (Porsche)
├── m3x/           ← M3.x (BMW)
├── m5x/           ← M5.x / M3.8x
├── me7/           ← ME7 / ME7.x
├── me9/           ← ME9 (full flash, RamLoader)
└── motronic_legacy/
```

The registry in `bosch/__init__.py` lists all extractors in priority order — most specific first. When a new binary is submitted, the first extractor whose `can_handle()` returns `True` wins.

---

← [Back to README](../../README.md)