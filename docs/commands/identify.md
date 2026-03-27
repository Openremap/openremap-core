# `openremap identify`

Read an ECU binary and print everything that can be extracted from it:
manufacturer, ECU family, software version, hardware number, calibration ID,
match key, file size, SHA-256 hash, and a **confidence assessment** of how
likely the binary is to be an unmodified factory file.

Use this to confirm what a binary is before doing anything else with it.

---

## Usage

```bash
openremap identify <FILE> [OPTIONS]
```

---

## Arguments

| Argument | Required | Description |
|---|---|---|
| `FILE` | Yes | ECU binary to read. Must end in `.bin` or `.ori`. |

---

## Options

| Option | Short | Description |
|---|---|---|
| `--json` | | Output as JSON instead of a human-readable table. |
| `--output PATH` | `-o` | Save the result to a file instead of printing to the screen. |
| `--help` | | Show help and exit. |

---

## Examples

```bash
# Print a human-readable table
openremap identify ecu.bin

# Print JSON to the screen
openremap identify ecu.bin --json

# Save the result as a JSON file
openremap identify ecu.bin --json --output result.json

# Save the table output to a text file
openremap identify ecu.bin --output result.txt
```

---

## Example output

### Table (default)

```
  ecu.bin
  Bosch · EDC17

  Manufacturer      Bosch
  ECU Family        EDC17
  ECU Variant       EDC17C66
  Software Version  1037541778
  Hardware Number   0261209352
  Calibration ID    unknown
  Match Key         EDC17C66::1037541778
  File Size         2,097,152 bytes
  SHA-256           3dc19aa03f3293bac4d27f28a22a073c...

  ── Confidence ─────────────────────────────────────────────────────────────
  Tier   HIGH
  Signal  +  canonical SW version (1037-prefixed)
  Signal  +  hardware number present (0261209352)
  Signal  +  ECU variant identified (EDC17C66)
```

### With warnings (wiped ident block)

```
  1.bin
  Bosch · EDC17

  Manufacturer      Bosch
  ECU Family        EDC17
  ECU Variant       EDC17C60
  Software Version  unknown
  Hardware Number   unknown
  Calibration ID    08001508446612B
  Match Key         EDC17C60::08001508446612B
  File Size         4,194,304 bytes
  SHA-256           ...

  ── Confidence ─────────────────────────────────────────────────────────────
  Tier   SUSPICIOUS
  Signal  -  SW ident absent — no match key produced
  Signal  +  ECU variant identified (EDC17C60)
  Signal  +  calibration ID present (080015084466)
  Signal  -  generic numbered filename
  ⚠  IDENT BLOCK MISSING
  ⚠  GENERIC FILENAME
```

### JSON (`--json`)

```json
{
  "manufacturer": "Bosch",
  "ecu_family": "EDC17",
  "ecu_variant": "EDC17C66",
  "software_version": "1037541778",
  "hardware_number": "0261209352",
  "calibration_id": null,
  "match_key": "EDC17C66::1037541778",
  "file_size": 2097152,
  "sha256": "3dc19aa03f3293bac4d27f28a22a073c...",
  "confidence": {
    "score": 75,
    "tier": "High",
    "signals": [
      { "delta": 40, "label": "canonical SW version (1037-prefixed)" },
      { "delta": 25, "label": "hardware number present (0261209352)" },
      { "delta": 10, "label": "ECU variant identified (EDC17C66)" }
    ],
    "warnings": []
  }
}
```

### Unrecognised ECU

If no extractor matches the binary, every field other than `file_size` and
`sha256` will show as `unknown`. This means the ECU family is not yet
supported — see [CONTRIBUTING.md](../../CONTRIBUTING.md) for how to add one.

```
  mystery.bin
  Unknown ECU — no extractor matched this binary

  Manufacturer      unknown
  ECU Family        unknown
  ECU Variant       unknown
  Software Version  unknown
  Hardware Number   unknown
  Calibration ID    unknown
  Match Key         unknown
  File Size         524,288 bytes
  SHA-256           3f9a21c7d84b...

  ── Confidence ─────────────────────────────────────────────────────────────
  Tier   UNKNOWN
```

---

## What to look for

### Identity fields

| Field | What it tells you |
|---|---|
| **Manufacturer** | Who made the ECU hardware (Bosch, Siemens, Delphi, …) |
| **ECU Family** | The ECU line (EDC17, ME7, SID206, …) |
| **ECU Variant** | The specific hardware variant within the family (EDC17C66, …) |
| **Software Version** | The calibration version string — the primary part of the match key |
| **Hardware Number** | The physical hardware part number, if readable from the binary |
| **Calibration ID** | A secondary calibration identifier, present on some families |
| **Match Key** | The compound identifier used to match recipes to ECUs — must match between the binary and any recipe you intend to apply |
| **File Size** | Total size in bytes — a quick sanity check |
| **SHA-256** | Cryptographic hash of the file — use this to confirm a file has not changed |

### Confidence section

| Tier | Meaning |
|---|---|
| **HIGH** | All key identifiers present and consistent — binary looks like an unmodified factory file |
| **MEDIUM** | Most identifiers present, minor concerns only |
| **LOW** | Some identifiers missing or a mild filename signal — usable, but inspect manually |
| **SUSPICIOUS** | Strong signals of modification, wiped ident, or file tampering — treat with caution |
| **UNKNOWN** | No extractor matched the binary — family not supported |

Each `Signal` line shows what contributed to the tier. A `+` prefix means the signal increased confidence; a `-` prefix means it reduced it.

Warnings (prefixed with `⚠`) are raised when specific red flags are detected — for example, when a software version is absent for a family that normally stores one.

### Good result

All of the following should be filled in for a fully supported, original binary:

- `Manufacturer` is a known name
- `ECU Family` is populated
- `Match Key` is populated
- `Confidence` tier is **HIGH** or **MEDIUM**

### Needs attention

- **`Software Version` is `unknown` but `Match Key` is populated** — the ECU architecture uses a different field (e.g. calibration ID) as the version component. This is by design for some families (e.g. LH-Jetronic). The binary is still usable.
- **`Match Key` is `unknown`** — the extractor matched the file but could not build a version identifier. You can still cook a recipe from this binary, but applying it to other ECUs will not be possible without a match key.
- **Confidence is `SUSPICIOUS` with `⚠ IDENT BLOCK MISSING`** — the software version field is absent for a family that normally stores it. This is a strong signal of a wiped or tampered ident block.
- **Confidence is `SUSPICIOUS` with `⚠ TUNING KEYWORDS IN FILENAME`** — the filename suggests this is a modified file. Inspect the binary before using it as a base for a recipe.
- **Everything is `unknown`** — the ECU family is not yet supported. See [CONTRIBUTING.md](../../CONTRIBUTING.md).

---

## Notes

- `openremap identify` is completely read-only. It never modifies the file.
- Only `.bin` and `.ori` files are accepted. Passing any other extension prints a warning and proceeds anyway — it does not exit with an error.
- The `--output` flag strips terminal colour codes automatically when writing to a file, so the saved text is clean and readable in any editor.
- The confidence score in the JSON output is a raw numeric value for programmatic use. The `tier` field is the human-readable label.

---

← [Back to CLI reference](../cli.md)