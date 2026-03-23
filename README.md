# OpenRemap

[![CI](https://github.com/Pinelo92/openremap/actions/workflows/ci.yml/badge.svg)](https://github.com/Pinelo92/openremap/actions/workflows/ci.yml)

> ⚠️ **Research and educational use only.** Any output produced by this software must be reviewed by a qualified professional before being flashed to a vehicle. The authors accept no liability for damage, loss, or legal consequences arising from its use. Read the full [DISCLAIMER](DISCLAIMER.md) before proceeding.

Open-source ECU binary analysis and patching toolkit. Diff a stock and a tuned binary to produce a portable JSON **recipe**, then validate and apply that recipe to any compatible ECU — with strict pre- and post-patch verification at every step.

---

## Supported ECU Families

All current extractors are Bosch. The registry is built to be extended to any manufacturer without touching existing code.

| Family | Era | Notes |
|---|---|---|
| EDC1 / EDC2 | 1990–1997 | Audi 80/A6 TDI, 32 KB / 64 KB |
| EDC 3.x | 1993–2000 | VAG TDI diesel bridge generation |
| EDC15 | 1997–2004 | Format A (TSW) and Format B (C3-fill) |
| EDC16 | 2003–2008 | `0xDECAFE` magic, 256 KB / 1 MB / 2 MB |
| EDC17 / MEDC17 / MED17 / ME17 | 2008+ | PSA, VAG, BMW diesel and petrol |
| ME7 | 1999–2006 | VAG 1.8T, Porsche, Ferrari |
| M1.x | 1987–1996 | BMW, early VAG, unique ROM header |
| M1.55 | 1994–2002 | Alfa Romeo 155/156/GT, 128 KB |
| M2.x | 1993–1999 | Porsche 964 (M2.3) and related |
| M3.x | 1989–1999 | BMW E30/E36 petrol |
| M5.x / M3.8x | 1997–2004 | VW/Audi 1.8T (AGU, AUM, APX) |
| LH-Jetronic | 1982–1995 | Volvo, early BMW/Mercedes |
| Motronic Legacy | various | Early 6802-era Bosch DME / KE / EZK |

---

## Install

Requires Python 3.14+ and [uv](https://github.com/astral-sh/uv).

```bash
git clone https://github.com/Pinelo92/openremap.git
cd openremap
uv sync
```

`uv sync` installs all dependencies and registers the `openremap` command in your shell.

---

## CLI Quickstart

```bash
# Identify an ECU binary
openremap identify ecu.bin

# Cook a recipe from a stock and a tuned binary
openremap cook stock.bin stage1.bin --output recipe.json

# Validate the target before patching
openremap validate strict target.bin recipe.json

# Apply the patch
openremap patch apply target.bin recipe.json --output patched.bin

# Verify the patch was written correctly
openremap validate patched patched.bin recipe.json

# Batch-scan a directory of binaries through all extractors
openremap scan ./my_bins/ --dry-run
```

> 🔴 **CHECKSUM VERIFICATION IS MANDATORY**
> Before flashing any patched binary to a vehicle, you **must** run it through a
> dedicated checksum correction tool (ECM Titanium, WinOLS, or equivalent).
> `openremap validate patched` confirms the recipe was applied — it does **not**
> correct or validate ECU checksums. Flashing a binary with an incorrect checksum
> **will brick your ECU.** No exceptions.

Full CLI reference → [`docs/cli.md`](docs/cli.md)

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/cli.md`](docs/cli.md) | Full CLI reference — every command, every flag, scan deep-dive |
| [`docs/recipe-format.md`](docs/recipe-format.md) | The recipe JSON spec — fields, structure, versioning |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to add a new ECU extractor, code style, submitting a PR, contributor safety notice |
| [`DISCLAIMER.md`](DISCLAIMER.md) | Liability, intended use, professional review requirements, legal notice |

---

## Contributing

Contributions are welcome — especially new ECU family extractors. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
