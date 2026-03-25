# OpenRemap

[![CI](https://github.com/Pinelo92/openremap/actions/workflows/ci.yml/badge.svg)](https://github.com/Pinelo92/openremap/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/openremap.svg)](https://pypi.org/project/openremap/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

Know what any ECU binary is. Spot a modified file before it causes damage. Apply tunes with a recipe you can read in any text editor.

**Identify** — drop any `.bin` and get manufacturer, ECU family, software version, and hardware number back in under a second. Works offline, no cloud, no subscriptions.

**Check originality** — the confidence system reads signals straight from the binary: canonical software version, hardware part number, ident block integrity. Modified files, wiped idents, and tuned-but-relabelled dumps are flagged automatically, before you've done anything with them.

**Tune with human-readable recipes** — diff a stock and a modified binary into a portable JSON recipe. Validate it against any target before touching it. Apply it byte-by-byte. Verify every write landed. The full audit trail sits in a file you can open in Notepad.

Built for tuners who want to understand what they're writing to an ECU, and for developers who want an open, scriptable alternative to closed toolchains. → [How it works in detail](docs/about.md)

---

## Install

- 🪟 **Windows** — [Step-by-step guide](docs/install/windows.md) · written for people who rarely use a terminal
- 🍎 **macOS / 🐧 Linux** — [One-command install](docs/install/macos-linux.md)
- 🛠️ **Contributing / development** — [Clone and run from source](docs/install/developers.md)

---

## Supported ECU Families

15 Bosch families supported — spanning 1982 to the present, from 8 KB LH-Jetronic ROMs to 8 MB EDC17 flash dumps. The registry is designed to be extended to any manufacturer without touching existing code.

→ **[Full family reference](docs/manufacturers/bosch.md)** — era, file sizes, vehicle applications, and notes for every supported family.

Adding a new manufacturer? → [CONTRIBUTING.md](CONTRIBUTING.md)

---

## CLI Quickstart

> **New here?** Run `openremap workflow` first — it prints a complete plain-English guide with every step, the exact commands to type, and what to do when something goes wrong. No reading required.

Full CLI reference → [`docs/cli.md`](docs/cli.md)

```bash
# New users: print the full step-by-step workflow guide
openremap workflow

# Identify an ECU binary — family, SW version, hardware number, and confidence
openremap identify ecu.bin

# Batch-scan a folder — dry-run preview, nothing moves
openremap scan ./my_bins/

# Sort files into a manufacturer/family tree once you're happy with the preview
openremap scan ./my_bins/ --move --organize

# Save a report with confidence scores for every file in the folder
openremap scan ./my_bins/ --report report.json

# Extract the tune — diff a stock and a modified binary into a recipe
openremap cook stock.bin stage1.bin --output recipe.json

# Validate the target before touching it (run this first — always)
openremap validate strict target.bin recipe.json

# Apply the tune
openremap tune target.bin recipe.json --output target_tuned.bin

# Confirm every byte landed correctly
openremap validate tuned target_tuned.bin recipe.json
```

> 🔴 **CHECKSUM VERIFICATION IS MANDATORY**
> Before flashing any tuned binary to a vehicle, you **must** run it through a
> dedicated checksum correction tool (ECM Titanium, WinOLS, or equivalent).
> `openremap validate tuned` confirms the recipe was applied — it does **not**
> correct or validate ECU checksums. Flashing a binary with an incorrect checksum
> **will brick your ECU.** No exceptions.

---

## Confidence Scoring

Every `identify` result and every `scan` line includes a confidence assessment — a quick read on how likely a binary is to be an unmodified factory file, based on signals read directly from the binary and from the filename.

```
  ── Confidence ─────────────────────────────────────
  Tier   HIGH
  Signal  +  canonical SW version (1037-prefixed)
  Signal  +  hardware number present (0261209352)
  Signal  +  ECU variant identified (EDC17C66)
```

```
  ── Confidence ─────────────────────────────────────
  Tier   SUSPICIOUS
  Signal  -  SW ident absent — no match key produced
  Signal  -  tuning/modification keywords in filename
  ⚠  IDENT BLOCK MISSING
  ⚠  TUNING KEYWORDS IN FILENAME
```

| Tier | What it means |
|---|---|
| **HIGH** | All key identifiers present — looks like an unmodified factory file |
| **MEDIUM** | Most identifiers present, minor concerns only |
| **LOW** | Some identifiers missing, or a mild filename signal |
| **SUSPICIOUS** | Strong modification signals — inspect before use |
| **UNKNOWN** | No extractor matched the binary |

Signals that raise or lower confidence:

| Signal | Direction |
|---|---|
| SW version present and canonical (`1037`-prefixed for Bosch) | `+` |
| Hardware number present | `+` |
| ECU variant identified | `+` |
| Calibration ID present | `+` |
| SW version absent for a family that normally stores it | `-` |
| Tuning keywords in filename (`stage`, `remap`, `tuned`, `disable`, …) | `-` |
| Generic numbered filename (`1.bin`, `42.bin`, …) | `-` |

Warnings flag specific red flags:

- `⚠ IDENT BLOCK MISSING` — software version absent for a family that always stores one; strong signal of a wiped or tampered ident block
- `⚠ TUNING KEYWORDS IN FILENAME` — filename suggests the file has been modified
- `⚠ GENERIC FILENAME` — bare numbered filename provides no identifying context

The system is **manufacturer-agnostic** — any extractor registered in the system gets confidence scoring automatically. The `1037` prefix check is Bosch-specific; for other manufacturers, any software version present earns the positive signal. All other signals apply equally across all families.

Use `openremap identify` for the full per-signal breakdown on a single file, or `openremap scan --report report.json` to triage an entire folder at once.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/install/windows.md`](docs/install/windows.md) | Windows install — step-by-step for first-time terminal users |
| [`docs/install/macos-linux.md`](docs/install/macos-linux.md) | macOS / Linux install — uv, pip, shell completion, troubleshooting |
| [`docs/install/developers.md`](docs/install/developers.md) | Developer setup — clone, test suite, project structure, publishing |
| [`docs/cli.md`](docs/cli.md) | Commands overview — what each command does, with links to full per-command pages |
| [`docs/manufacturers/bosch.md`](docs/manufacturers/bosch.md) | Supported Bosch ECU families — era, file sizes, vehicle applications, confidence notes |
| [`docs/recipe-format.md`](docs/recipe-format.md) | The recipe JSON spec — fields, structure, versioning |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to add a new ECU extractor, code style, submitting a PR, contributor safety notice |
| [`DISCLAIMER.md`](DISCLAIMER.md) | Liability, intended use, professional review requirements, legal notice |

---

## Contributing

Contributions are welcome — especially new ECU family extractors. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

---

> ⚠️ **Research and educational use only.** Any output produced by this software must be reviewed by a qualified professional before being flashed to a vehicle. The authors accept no liability for damage, loss, or legal consequences arising from its use. Read the full [DISCLAIMER](DISCLAIMER.md) before proceeding.
