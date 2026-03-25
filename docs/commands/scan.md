# `openremap scan`

Sort a folder of ECU binaries by classification result. Every file is read and
run through all registered extractors. The result is printed to the screen and,
when you are ready, files are moved into sub-folders automatically.

Running without any flags is always a safe preview — nothing is moved until you
explicitly pass `--move`.

---

## Usage

```bash
openremap scan [DIRECTORY] [OPTIONS]
```

---

## Arguments

| Argument | Default | Description |
|---|---|---|
| `DIRECTORY` | `.` (current folder) | Folder containing the `.bin` / `.ori` files to scan |

---

## Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--dry-run` / `--move` | | `--dry-run` | Preview mode is the default — nothing is moved. Pass `--move` to actually sort files into their destination folders. |
| `--create-dirs` | | off | Create the five flat destination folders inside the scan directory if they do not already exist. |
| `--organize` | `-O` | off | Sort identified files into `manufacturer/family` sub-folders (e.g. `scanned/Bosch/EDC17/`). Creates all required folders automatically — no need to pass `--create-dirs` separately. |
| `--report PATH` | `-r` | — | Write a structured report to a file. Format is detected from the extension: `.json` → JSON array, `.csv` → CSV table. Includes identification fields, confidence score, tier, and warnings for every file. |
| `--help` | | | Show help and exit. |

---

## How files are classified

Every file is tested against every registered extractor and placed into exactly
one of five outcomes:

| Outcome | Folder | What it means |
|---|---|---|
| **SCANNED** | `scanned/` | One extractor matched and a full calibration identity (match key) was extracted. Fully identified and ready to use. |
| **SW MISSING** | `sw_missing/` | One extractor matched and identified the ECU family, but the calibration version could not be read from the binary (e.g. the binary was wiped or the pattern is missing). |
| **CONTESTED** | `contested/` | More than one extractor matched. Signals a detection overlap that needs investigation. |
| **UNKNOWN** | `unknown/` | No extractor matched. The ECU family is not yet supported, or the file is not a valid ECU binary. |
| **TRASH** | `trash/` | The file does not have a `.bin` or `.ori` extension. Moved aside without being read. |

Files are never overwritten. If a file with the same name already exists in the
destination folder, a counter is appended automatically (`file__1.bin`,
`file__2.bin`, …).

---

## Confidence tags

Every `SCANNED` and `SW MISSING` result includes a confidence tag at the end of
the detail line — a quick read on how likely the binary is to be an unmodified
factory file:

| Tag | Meaning |
|---|---|
| `[HIGH]` | All key identifiers present — looks like an original factory file |
| `[MEDIUM]` | Most identifiers present, minor concerns |
| `[LOW]` | Some identifiers missing, or mild filename signal |
| `[SUSPICIOUS]` | Strong modification signals — inspect before use |

Warnings appear inline after the tag:

```
⚠ IDENT BLOCK MISSING       — SW version absent for a family that normally stores it
⚠ TUNING KEYWORDS IN FILENAME — filename contains stage / remap / tuned / disable / etc.
⚠ GENERIC FILENAME           — filename is a bare number (1.bin, 42.bin) with no context
```

Use `openremap identify` on any flagged file for the full breakdown of what
contributed to the confidence tier.

---

## Destination folder layouts

### Flat layout (default, or `--create-dirs`)

```
my_bins/
├── scanned/        ← fully identified
├── sw_missing/     ← family known, calibration unknown
├── contested/      ← matched by more than one extractor
├── unknown/        ← no extractor matched
└── trash/          ← wrong file extension
```

### Organised layout (`--organize`)

`SCANNED` and `SW MISSING` files are further sorted into
`manufacturer/family` sub-folders. `CONTESTED`, `UNKNOWN`, and `TRASH`
remain flat because no single extractor was confirmed for them.

```
my_bins/
├── scanned/
│   ├── Bosch/
│   │   ├── EDC17/          ← ecu1.bin, ecu2.bin …
│   │   ├── MEDC17/         ← ecu3.bin …
│   │   └── ME7.5/          ← ecu4.bin …
│   └── Siemens/
│       └── SIM2K/          ← ecu5.bin …
├── sw_missing/
│   └── Bosch/
│       └── unknown_family/ ← ecu6.bin …
├── contested/              ← flat
├── unknown/                ← flat
└── trash/                  ← flat
```

---

## Examples

```bash
# Preview results — nothing moves (this is the default, no flag needed)
openremap scan ./my_bins/

# Preview the current folder
openremap scan

# Preview what --organize would do, without moving anything
openremap scan ./my_bins/ --organize

# Sort files into flat folders — create them first if they do not exist
openremap scan ./my_bins/ --move --create-dirs

# Sort files into flat folders that already exist
openremap scan ./my_bins/ --move

# Sort into a manufacturer/family tree — creates all folders automatically
openremap scan ./my_bins/ --move --organize

# Dry-run + save a JSON report of every file with confidence scores
openremap scan ./my_bins/ --report report.json

# Save a CSV report instead
openremap scan ./my_bins/ --report report.csv

# Combine: sort files and save a report in one pass
openremap scan ./my_bins/ --move --organize --report report.json
```

---

## Example output

### Default (dry-run, flat preview)

```
  OpenRemap — Batch ECU Scanner  [dry run — pass --move to sort files]
  5 file(s)  •  14 extractor(s)  •  /home/user/my_bins

[1/5]  SCANNED     006410010A0.bin          63.8 ms
                └─ extractor: BoschME7Extractor  family: ME7.1.1  sw: 1037371702  hw: 0261208771  key: ME7.1.1::1037371702  [HIGH]
[2/5]  SCANNED     0280-000-560.bin           4.4 ms
                └─ extractor: BoschLHExtractor  family: LH-Jetronic  cal_id: 1012621LH241RP (sw absent by architecture)  key: LH-JETRONIC::1012621LH241RP  [LOW]
[3/5]  SCANNED     stage1_custom.bin         12.1 ms
                └─ extractor: BoschEDC17Extractor  family: EDC17  sw: 1037541778  hw: 0261209352  key: EDC17C66::1037541778  [SUSPICIOUS]  ⚠ TUNING KEYWORDS IN FILENAME
[4/5]  SCANNED     1.bin                    635.6 ms
                └─ extractor: BoschExtractor  family: EDC17  variant: EDC17C60  cal_id: 08001508446612B  key: EDC17C60::08001508446612B  [SUSPICIOUS]  ⚠ IDENT BLOCK MISSING  ⚠ GENERIC FILENAME
[5/5]  UNKNOWN     mystery.bin               0.4 ms
                └─ no extractor matched

  ── Summary ──────────────────────────────────────────────────
  Scanned       4
  SW Missing    0
  Contested     0
  Unknown       1
  Trash         0

  Total: 5  •  0.72s  (dry run — nothing moved)

  Tip: run with --move to sort files into flat folders, or add --organize
  to sort by manufacturer/family (e.g. scanned/Bosch/EDC17/).
```

### `--report` output (JSON)

```json
[
  {
    "filename": "006410010A0.bin",
    "destination": "scanned",
    "manufacturer": "Bosch",
    "ecu_family": "ME7.1.1",
    "ecu_variant": null,
    "software_version": "1037371702",
    "hardware_number": "0261208771",
    "calibration_id": null,
    "match_key": "ME7.1.1::1037371702",
    "file_size": 524288,
    "sha256": "ca366c08cb0c7d5c...",
    "elapsed_ms": 63.8,
    "confidence_score": 65,
    "confidence_tier": "High",
    "confidence_warnings": ""
  },
  {
    "filename": "1.bin",
    "destination": "scanned",
    "manufacturer": "Bosch",
    "ecu_family": "EDC17",
    "ecu_variant": "EDC17C60",
    "software_version": null,
    "hardware_number": null,
    "calibration_id": "08001508446612B",
    "match_key": "EDC17C60::08001508446612B",
    "file_size": 4194304,
    "sha256": "...",
    "elapsed_ms": 635.6,
    "confidence_score": -15,
    "confidence_tier": "Suspicious",
    "confidence_warnings": "IDENT BLOCK MISSING; GENERIC FILENAME"
  }
]
```

---

## Recommended workflow

```bash
# 1. Preview — nothing moves
openremap scan ./my_bins/

# 2. Save a report for triage
openremap scan ./my_bins/ --report report.json

# 3. If the results look right, sort into a manufacturer/family tree
openremap scan ./my_bins/ --move --organize

# 4. Investigate anything flagged SUSPICIOUS or SW MISSING
openremap identify my_bins/sw_missing/Bosch/unknown_family/some_file.bin
openremap identify my_bins/scanned/Bosch/EDC17/1.bin
```

---

## Tips

- **Always preview first.** Dry-run is the default for exactly this reason — you
  can see what will happen before anything is moved.
- **`--organize` is the recommended mode for large collections.** Finding a
  specific ECU is much easier when files are already grouped by manufacturer and
  family.
- **Use `--report` for batch triage.** The JSON/CSV output can be filtered or
  sorted in any spreadsheet or script to surface all `Suspicious` files at once.
- **`contested` files need manual attention.** Run `openremap identify` on them
  and check which result looks correct. If two extractors genuinely overlap,
  open an issue.
- **`sw_missing` files are not broken.** The ECU family was recognised. The
  binary may have had its calibration string wiped, or the extractor's pattern
  needs improvement. Run `openremap identify` for the full detail.
- **`[SUSPICIOUS]` does not mean the file is useless.** It means something
  about the binary or filename raised a red flag. Run `openremap identify` to
  see exactly what triggered the warning and decide yourself.

---

← [Back to CLI reference](../cli.md)