# `openremap families`

List all supported ECU families, or show expanded detail for a specific family.

---

## Usage

```bash
openremap families [OPTIONS]
```

---

## Options

| Option | Short | Description |
|---|---|---|
| `--family NAME` | `-f` | Show expanded detail for one family. Accepts the canonical name or any known alias (e.g. `EDC16`, `ME7`, `mp3.2`, `m3x`, `lh-jetronic`). |
| `--help` | | Show help and exit. |

---

## Examples

```bash
# Print the full table of all supported families
openremap families

# Show detailed information for a specific family
openremap families --family EDC16
openremap families --family ME7
openremap families -f mp3.2
openremap families -f edc3
openremap families -f lh-jetronic
```

---

## Example output

### Full table

```
  Supported ECU Families

  ─────────────────────────────────────────────────────────────────────────────
  FAMILY                  ERA             SIZE              NOTES
  ─────────────────────────────────────────────────────────────────────────────
  EDC1 / EDC2             1990–1997       32–64 KB          Audi 80 / A6 TDI, early diesel ROMs.
  EDC 3.x                 1993–2000       128–512 KB        VAG TDI, BMW diesel, Opel diesel. Three ident formats.
  EDC15                   1997–2004       512 KB            TSW/C3-fill. VAG/Fiat/Volvo/BMW diesel.
  EDC16                   2003–2008       256 KB–2 MB       DECAFE magic. VAG PD, BMW, Opel CDTI.
  EDC17 / MEDC17 / …      2008–present    2–8 MB            Modern platform. PSA/VAG/BMW/Mercedes.
  ME7 / ME7.x             1997–2008       64 KB–1 MB        VAG 1.8T, Porsche, Ferrari, Opel Corsa D.
  ME9                     2001–2006       2 MB              VW/Audi 1.8T 20v full flash.
  MED9 / MED9.x           2002–2008       512 KB–2 MB       VAG FSI/TFSI direct injection.
  M1.x                    1987–1996       32–64 KB          BMW E28/E30/E34/E36, Opel petrol.
  M1.55 / M1.5.5          1994–2002       128 KB            Alfa Romeo (M1.55) / Opel Corsa C (M1.5.5).
  M2.x                    1993–1999       32–128 KB         VW/Audi M2.9, Porsche M2.3, Opel M2.7/8/81.
  M3.x                    1989–1999       32–256 KB         BMW M3.1/M3.3, PSA/Citroën MP3.2/MP7.2.
  M5.x / M3.8x            1997–2004       128–256 KB        VW/Audi 1.8T AGU/AUM/APX.
  LH-Jetronic             1982–1995       8–64 KB           Volvo, BMW, Mercedes fuel injection.
  Motronic Legacy         various         2–32 KB           DME-3.2, M1.x-early, KE-Jetronic, EZK.
  ─────────────────────────────────────────────────────────────────────────────

  openremap families --family <NAME>   show full detail for one family
  openremap identify <FILE>            identify an ECU binary
```

### Detail view (`--family EDC16`)

```
  EDC16
  ─────────────────────────────────────────────────────────────────────────────

  Era             2003–2008
  File size       256 KB / 1 MB / 2 MB

  Sub-families    EDC16C8
                  EDC16C9
                  EDC16C31
                  EDC16C34
                  EDC16C35
                  EDC16C36
                  EDC16C39
                  EDC16CP33
                  EDC16CP34
                  EDC16CP35
                  EDC16U1
                  EDC16U31

  Identifier      \xDE\xCA\xFE (DECAFE) magic at bank-boundary offsets

  SW format       1037xxxxxx (standard); 1037A50286 (alphanumeric, Opel C9);
                  1039xxxxxx (PSA/Peugeot-Citroën EDC16C34)

  HW in binary    Opel EDC16C9 only — plain ASCII null-terminated in cal area

  Vehicles        Audi A3/A4 1.9 TDI BKC/BKE (VAG PD, EDC16U/C8)
                  BMW 320D/520D/120D 163HP E46/E60/E87 (EDC16C31)
                  BMW X6 30sd (EDC16CP35)
                  Opel Vectra-C / Signum / Astra-H CDTI (EDC16C9)
                  Alfa 147/156 1.9 JTDM (EDC16C8)
                  Alfa 159 2.4 JTDM (EDC16C39)
                  Peugeot 3008 1.6 HDI (EDC16C34, SW prefix 1039)

  Notes           BMW C31/C35 2 MB bins store the family string near the
                  0xC0000 mirror section (~0x0C06F3), not at the end of
                  file. BMW E46 320D early 1 MB layout has
                  active_start=0x20000 (non-standard).

  ─────────────────────────────────────────────────────────────────────────────

  openremap families             show all families
  openremap identify <FILE>      identify an ECU binary
```

---

## Supported family names and aliases

The `--family` option accepts the canonical name or any of the listed aliases
(case-insensitive, dashes and dots are flexible):

| Canonical name | Accepted aliases |
|---|---|
| EDC1 / EDC2 | `edc1`, `edc2` |
| EDC 3.x | `edc3`, `edc3x`, `edc3.x` |
| EDC15 | `edc15` |
| EDC16 | `edc16` |
| EDC17 / MEDC17 / MED17 / ME17 | `edc17`, `medc17`, `med17`, `me17` |
| ME7 / ME7.x | `me7`, `me7.1`, `me7.5`, `me7.6` |
| ME9 | `me9` |
| MED9 / MED9.x | `med9`, `med9.x` |
| M1.x | `m1x`, `m1.x`, `m1.3`, `m1.7` |
| M1.55 / M1.5.5 | `m1.55`, `m1.5.5`, `m155`, `m1x55` |
| M2.x | `m2x`, `m2.x`, `m2.3`, `m2.7`, `m2.8`, `m2.9` |
| M3.x | `m3x`, `m3.x`, `m3.1`, `m3.3`, `mp3.2`, `mp7.2` |
| M5.x / M3.8x | `m5x`, `m5.x`, `m3.8x`, `m3.8` |
| LH-Jetronic | `lh`, `lh-jetronic`, `lhjetronic` |
| Motronic Legacy | `motronic`, `motronic_legacy`, `ke-jetronic`, `ezk`, `dme` |

---

## Notes

- `openremap families` shows the same families that `openremap identify`
  recognises. If a binary is classified as `unknown`, its ECU family is not
  yet supported — see `CONTRIBUTING.md` to add support.
- For the complete technical detail on ident formats, file sizes, and binary
  layouts for Bosch ECUs, see
  [`docs/manufacturers/bosch.md`](../manufacturers/bosch.md).

---

← [Back to CLI reference](../cli.md)