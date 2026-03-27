# Confidence Scoring

Every `openremap identify` result and every `openremap scan` line includes a
confidence assessment — a quick read on how likely a binary is to be an
unmodified factory file, based on signals read directly from the binary and
from the filename.

---

## Tiers

| Tier | What it means |
|---|---|
| **HIGH** | All key identifiers present and consistent — looks like an unmodified factory file |
| **MEDIUM** | Most identifiers present, minor concerns only |
| **LOW** | Some identifiers missing, or a mild filename signal |
| **SUSPICIOUS** | Strong modification signals — inspect before use |
| **UNKNOWN** | No extractor matched the binary — family not supported |

---

## Example output

### HIGH — looks factory-fresh

```
  ── Confidence ─────────────────────────────────────
  Tier   HIGH
  Signal  +  canonical SW version (1037-prefixed)
  Signal  +  hardware number present (0261209352)
  Signal  +  ECU variant identified (EDC17C66)
```

### SUSPICIOUS — stop and check

```
  ── Confidence ─────────────────────────────────────
  Tier   SUSPICIOUS
  Signal  -  SW ident absent — no match key produced
  Signal  -  tuning/modification keywords in filename
  ⚠  IDENT BLOCK MISSING
  ⚠  TUNING KEYWORDS IN FILENAME
```

---

## Signals

Each signal line shows what contributed to the tier. A `+` prefix raised
confidence; a `-` prefix lowered it.

| Signal | Direction |
|---|---|
| SW version present and canonical (`1037`-prefixed for Bosch) | `+` |
| Hardware number present | `+` |
| ECU variant identified | `+` |
| Calibration ID present | `+` |
| SW version absent for a family that normally stores it | `-` |
| Tuning keywords in filename (`stage`, `remap`, `tuned`, `disable`, …) | `-` |
| Generic numbered filename (`1.bin`, `42.bin`, …) | `-` |

---

## Warnings

Warnings flag specific red flags, independent of the tier score:

| Warning | What it means |
|---|---|
| `⚠ IDENT BLOCK MISSING` | SW version absent for a family that always stores one — strong signal of a wiped or tampered ident block |
| `⚠ TUNING KEYWORDS IN FILENAME` | Filename contains words associated with modified files (`stage`, `remap`, `tuned`, `evc`, `disable`, …) |
| `⚠ GENERIC FILENAME` | Bare numbered filename (`1.bin`, `42.bin`) provides no identifying context |

---

## How the score is calculated

Each signal carries a positive or negative delta. The deltas are summed into a
raw numeric score, which is then mapped to a tier:

| Score range | Tier |
|---|---|
| ≥ 60 | HIGH |
| 30 – 59 | MEDIUM |
| 0 – 29 | LOW |
| < 0 | SUSPICIOUS |
| no extractor matched | UNKNOWN |

The raw score is available in JSON output (`openremap identify --json`) under
`confidence.score`, alongside the `tier` string and the full `signals` array.

---

## Manufacturer-agnostic design

The confidence system is **manufacturer-agnostic** — any extractor registered
in the system gets scoring automatically. The `1037`-prefix check is
Bosch-specific; for all other manufacturers, any software version present earns
the canonical SW version signal. All other signals apply equally across every
supported family.

---

## Using confidence in practice

```bash
# Full per-signal breakdown for a single file
openremap identify ecu.bin

# Confidence as JSON — score, tier, signals array, warnings
openremap identify ecu.bin --json

# Triage an entire folder — confidence tag on every line
openremap scan ./my_bins/

# Export confidence scores and warnings for every file to CSV
openremap scan ./my_bins/ --report report.csv
```

A `SUSPICIOUS` result is not a verdict — it is a prompt to look closer.
Run `openremap identify` on any flagged file for the full signal breakdown
before deciding whether to use it.

---

← [Back to CLI reference](cli.md)