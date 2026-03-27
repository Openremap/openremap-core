# OpenRemap

[![CI](https://github.com/Pinelo92/openremap/actions/workflows/ci.yml/badge.svg)](https://github.com/Pinelo92/openremap/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Pinelo92/openremap/branch/main/graph/badge.svg)](https://codecov.io/gh/Pinelo92/openremap)
[![PyPI](https://img.shields.io/pypi/v/openremap.svg)](https://pypi.org/project/openremap/)
[![Changelog](https://img.shields.io/badge/-Changelog-blue.svg)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

> **CLI tool. Runs on your machine. No internet. No account. No data leaves your hands — ever.**

Drop a `.bin`, know exactly what it is. Triage a folder of hundreds. Apply a tune you can read in any text editor.

**Identify** — manufacturer, ECU family, software version, hardware number, and a confidence verdict in under a second. Works on anything from an 8 KB LH-Jetronic ROM to an 8 MB EDC17 dump.

**Confidence scoring** — signals read straight from the binary: SW version integrity, hardware part number, ident block presence. Wiped idents, tuned-but-relabelled dumps, and modified files are flagged before you've touched anything. `HIGH` means it looks factory-fresh. `SUSPICIOUS` means stop and check.

**Scan and organise** — point `scan` at a folder of hundreds of mixed binaries and get them sorted into `Bosch/EDC17/`, `Bosch/ME7/`, etc. in one command. Every file classified, confidence-tagged, and optionally exported to JSON or CSV.

**Tune with a recipe you can read** — diff a stock and a modified binary into a portable JSON file. Inspect every changed byte offset before applying anything. `tune` validates, patches, and verifies in one shot. The full audit trail is a file you can open in Notepad.

→ [How it works in detail](docs/about.md)

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
# New here? Print the full step-by-step guide
openremap workflow

# Quick reminder of every command and its syntax
openremap commands

# List every supported ECU family (add --family EDC16 for full detail)
openremap families

# Identify a binary — manufacturer, family, SW version, hardware number, confidence
openremap identify ecu.bin

# Batch-scan a folder — dry-run preview, nothing moves
openremap scan ./my_bins/

# Sort into a manufacturer/family tree when you're happy with the preview
openremap scan ./my_bins/ --move --organize

# Diff a stock and a tuned binary into a portable recipe
openremap cook stock.bin stage1.bin --output recipe.json

# One-shot: validate before → apply → validate after  (writes target_tuned.bin)
openremap tune target.bin recipe.json

# Phase 1 failed? Diagnose why — searches the whole binary for shifted or missing maps
openremap validate check target.bin recipe.json
```

> 🔴 **CHECKSUM VERIFICATION IS MANDATORY**
> Before flashing any tuned binary to a vehicle, you **must** run it through a
> dedicated checksum correction tool (ECM Titanium, WinOLS, or equivalent).
> `openremap tune` Phase 3 confirms the recipe was applied correctly — it does **not**
> correct or validate ECU checksums. Flashing a binary with an incorrect checksum
> **will brick your ECU.** No exceptions.

---

## Confidence Scoring

Every `identify` result and every `scan` line includes a confidence tier — `HIGH`, `MEDIUM`, `LOW`, `SUSPICIOUS`, or `UNKNOWN` — based on signals read directly from the binary: SW version integrity, hardware part number, ident block presence, and filename. `SUSPICIOUS` is not a verdict; it is a prompt to look closer.

→ **[Full reference: tiers, signals, warnings, and score breakdown](docs/confidence.md)**

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/install/windows.md`](docs/install/windows.md) | Windows install — step-by-step for first-time terminal users |
| [`docs/install/macos-linux.md`](docs/install/macos-linux.md) | macOS / Linux install — uv, pip, shell completion, troubleshooting |
| [`docs/install/developers.md`](docs/install/developers.md) | Developer setup — clone, test suite, project structure, publishing |
| [`docs/cli.md`](docs/cli.md) | Commands overview — what each command does, with links to full per-command pages |
| [`docs/confidence.md`](docs/confidence.md) | Confidence scoring — tiers, signals, warnings, and score breakdown |
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
