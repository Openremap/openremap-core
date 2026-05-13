# OpenRemap

[![CI](https://github.com/v-arapidis/openremap-core/actions/workflows/ci.yml/badge.svg)](https://github.com/v-arapidis/openremap-core/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/v-arapidis/openremap-core/branch/main/graph/badge.svg)](https://codecov.io/gh/v-arapidis/openremap-core)
[![PyPI](https://img.shields.io/pypi/v/openremap.svg)](https://pypi.org/project/openremap/)
[![Changelog](https://img.shields.io/badge/-Changelog-blue.svg)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

**Python library and CLI for ECU binary identification, diffing, and patching.**
Embed it in your application, automate it in a pipeline, or run it from the terminal.

🌐 **[openremap.com](https://www.openremap.com)** — full documentation, guides, and changelog.

> Runs on your machine. No internet. No account. No data leaves your hands — ever.

<p align="center">
  <img src="docs/images/tui-scan.png" alt="OpenRemap TUI — Scan panel" width="820">
</p>

**Ready to try it?** Jump to [Install](#install) — one command on any platform.

---

## What it is

OpenRemap is a **Python library first, CLI second**. The same pipeline that powers the command-line tool is fully available as importable services — no subprocess, no parsing stdout.

```python
from openremap.core.services.identifier import identify_ecu
from openremap.core.services.confidence import score_identity
from openremap.core.services.patcher    import ECUPatcher

data     = open("ecu.bin", "rb").read()
identity = identify_ecu(data, filename="ecu.bin")
result   = score_identity(identity)

print(f"{identity['ecu_family']}  {result.tier}")  # EDC17  High
```

All services accept `bytes` and `dict` — no file paths, no hidden state, trivial to test and wrap in an API endpoint or a desktop app.

→ [Full integration guide](docs/integration.md)

---

## The problem

ECU work revolves around three tasks that today require expensive commercial software (€2,500–€8,000+) or manual hex-editor work with no audit trail:

1. **Identify a binary** — manufacturer, ECU family, software revision, confidence score
2. **Diff two binaries** — what changed between a stock file and a tuned file, captured as a portable recipe
3. **Apply a recipe to another binary** — validate, patch, and verify — all-or-nothing

Whether you are building a tuning application, automating a workflow, or just need a reliable offline tool — OpenRemap gives you a clean Python API and a full CLI for all three.

## What OpenRemap does

OpenRemap is a **free, offline, open-source toolkit** that handles the binary analysis and patching pipeline:

| Step | Command | What happens |
|---|---|---|
| **Identify** | `openremap identify ecu.bin` | Reads the binary and tells you: manufacturer, ECU family, software version, hardware number, calibration ID — plus a confidence score rating how likely the file is unmodified |
| **Scan** | `openremap scan ./bins/` | Batch-identifies every binary in a folder. Sorts them into `Bosch/EDC17/`, `Siemens/PPD/`, etc. Flags suspicious files before you touch them |
| **Cook** | `openremap cook stock.bin tuned.bin` | Diffs two binaries byte-by-byte and produces a `.remap` recipe — a portable JSON file listing every changed byte with context anchors. Readable in any text editor, diffable in Git |
| **Tune** | `openremap tune target.bin recipe.remap` | Validates the recipe against the target binary, applies the patch, then verifies every byte landed correctly. All-or-nothing — partial patches never happen |

### What it does NOT do

- **Map editing** — OpenRemap works at the byte level, not the map level. Use WinOLS or ECM Titanium to find and edit maps. Use OpenRemap to capture, share, and reapply those edits.
- **Checksum correction** — you must run the output through WinOLS, ECM Titanium, or equivalent before flashing. Always.
- **ECU reading/writing** — it operates on `.bin` files you already have.

---

## Coverage

30 extractors across 4 manufacturers, covering ECUs from 1982 to present:

| Manufacturer | Families | Examples |
|---|---|---|
| **Bosch** (18) | EDC17, EDC16, EDC15, ME7, ME9, M5.x, M4.x, M3.x, M2.x, M1.x, MP9, ME1.5.5, LH-Jetronic, Mono-Motronic, and more | VAG TDI, BMW, Volvo, PSA, Porsche, Alfa Romeo |
| **Siemens** (6) | SIMOS, PPD, SID 801/803, Simtec 56, EMS2000 | VAG petrol, PSA/Ford diesel, Volvo turbo |
| **Delphi** (2) | Multec, Multec S | Opel/Vauxhall diesel and petrol |
| **Marelli** (4) | IAW 1AV, IAW 1AP, IAW 4LV, MJD 6JF | Fiat, PSA, GM/Opel |

→ Full reference: [Bosch](docs/manufacturers/bosch.md) · [Siemens](docs/manufacturers/siemens.md) · [Delphi](docs/manufacturers/delphi.md) · [Marelli](docs/manufacturers/marelli.md)

---

## Confidence scoring

Every identification includes a confidence verdict — `HIGH`, `MEDIUM`, `LOW`, `SUSPICIOUS`, or `UNKNOWN` — built from multiple signals:

- **Detection strength** — how rigorous the extractor's matching cascade is
- **Software version format** — manufacturer-aware canonical format checking (Bosch `1037`-prefixed, Delphi 8-digit GM-style, etc.)
- **Identity fields present** — hardware number, calibration ID, ECU variant
- **Filename analysis** — tuning keywords (`stage2`, `dpf_off`, `egr_off`) and generic names (`1.bin`) flag suspicious files
- **Family-aware scoring** — ECU families that architecturally lack certain fields are never penalised for their absence

→ [Full scoring breakdown](docs/confidence.md)

---

## The recipe format

The `.remap` recipe is a self-contained JSON file. Every changed byte is listed with its offset, original value, modified value, and a context anchor — 32 bytes of surrounding data that let the patcher find the right location even if the binary has shifted slightly between software revisions.

Recipes are human-readable, Git-diffable, and shareable. No proprietary format, no binary blobs.

→ [Recipe format specification](docs/recipe-format.md)

---

## Install

Works on Windows, macOS, and Linux. One command to get started:

```bash
pip install openremap
```

Or with [uv](https://github.com/astral-sh/uv) (recommended):

```bash
uv tool install openremap
```

Detailed guides:

- 🪟 **Windows** — [Step-by-step guide](docs/install/windows.md) · written for people who rarely use a terminal
- 🍎 **macOS / 🐧 Linux** — [One-command install](docs/install/macos-linux.md)
- 🛠️ **Contributing / development** — [Clone and run from source](docs/install/developers.md)

---

## Get started

```bash
openremap
```

That's it. The full terminal UI launches — identify files, scan folders, cook recipes, and apply tunes, all from one interface. No flags to memorise.

The complete CLI is still there when you need it:

```bash
openremap workflow    # Prints a plain-English guide with every step and command
openremap commands    # Quick reference for all available commands
```

→ [Full CLI reference](docs/cli.md)

---

## Documentation

- 🌐 [openremap.com](https://www.openremap.com) — website with full guides and changelog
- [Integration guide — using OpenRemap as a Python library](docs/integration.md)
- [How it all works](docs/about.md)
- [CLI commands overview](docs/cli.md)
- [Confidence scoring — tiers, signals, and breakdown](docs/confidence.md)
- [Recipe format (.remap)](docs/recipe-format.md)
- Supported families: [Bosch](docs/manufacturers/bosch.md) · [Siemens](docs/manufacturers/siemens.md) · [Delphi](docs/manufacturers/delphi.md) · [Marelli](docs/manufacturers/marelli.md)
- [Contributing — adding extractors, code style, PRs](CONTRIBUTING.md)

---

## Contributing

Contributions are welcome — especially new ECU family extractors. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

---

> ⚠️ **Checksum verification is mandatory.** Before flashing any tuned binary to a vehicle, you **must** run it through a dedicated checksum correction tool (ECM Titanium, WinOLS, or equivalent). `openremap tune` confirms the recipe was applied correctly — it does **not** correct or validate ECU checksums. Flashing a binary with an incorrect checksum **will brick your ECU.**

> ⚠️ **Research and educational use only.** Any output produced by this software must be reviewed by a qualified professional before being flashed to a vehicle. The authors accept no liability for damage, loss, or legal consequences arising from its use. Read the full [DISCLAIMER](DISCLAIMER.md).