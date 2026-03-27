# CLI Reference

Full reference for the `openremap` command-line tool. No server, no database,
no internet connection required — install and run anywhere.

> **New to the terminal?** Run `openremap workflow` first. It prints a complete
> plain-English walkthrough with the exact commands to type and what to look for
> at each step. No reading required.
>
> **Know the commands already?** Run `openremap commands` for a one-line-per-command
> cheat-sheet.

---

## Installation

See the full setup guide → [`docs/setup.md`](setup.md)

Quick start for most users — `openremap` is on [PyPI](https://pypi.org/project/openremap/):

```bash
uv tool install openremap
```

Prefer plain pip?

```bash
pip install openremap
```

`openremap` is then available from any folder, no activation required.
Shell completion, development setup, updating, and troubleshooting are all
covered in [`docs/setup.md`](setup.md).

---

## Commands

Every command supports `--help` for a quick reminder of its arguments and options.

| Command | What it does | Reference |
|---|---|---|
| `commands` | Compact cheat-sheet — all commands at a glance | [→ commands.md](commands/commands.md) |
| `workflow` | Step-by-step guide — start here if you are new | [→ workflow.md](commands/workflow.md) |
| `families` | List every supported ECU family with era, size, and notes | [→ families.md](commands/families.md) |
| `families --family <NAME>` | Full detail for one ECU family | [→ families.md](commands/families.md) |
| `scan` | Sort a folder of ECU files by manufacturer and family | [→ scan.md](commands/scan.md) |
| `identify` | Read an ECU binary and print everything extracted from it | [→ identify.md](commands/identify.md) |
| `cook` | Compare a stock and a tuned binary and save the difference as a recipe | [→ cook.md](commands/cook.md) |
| `tune` | **One-shot:** validate before → apply → validate after | [→ tune.md](commands/tune.md) |
| `validate before` | Pre-flight check — run before tuning (or use `tune`) | [→ validate.md#before](commands/validate.md#before) |
| `validate check` | Diagnostic — run when `validate before` fails | [→ validate.md#check](commands/validate.md#check) |
| `validate after` | Post-tune confirmation — run after tuning (or use `tune`) | [→ validate.md#after](commands/validate.md#after) |

> **`validate strict` / `validate exists` / `validate tuned`** are deprecated aliases
> for `validate before` / `validate check` / `validate after`. They still work but
> print a rename notice. Update your scripts when convenient.

---

## Quick-start example

```bash
# New here? Print the full step-by-step guide first
openremap workflow

# Need a quick reminder of all commands?
openremap commands

# Not sure if your ECU is supported?
openremap families
openremap families --family EDC16

# (Optional) Sort a folder of binaries into a tidy library
openremap scan ./my_bins/                    # preview — nothing moves
openremap scan ./my_bins/ --move --organize  # sort into Bosch/EDC17/ etc.

# 1. Read the stock binary — confirm it is a supported ECU
openremap identify stock.bin

# 2. Extract the tune — diff stock vs tuned and save as a recipe
openremap cook stock.bin stage1.bin --output recipe.json

# 3. One-shot: validate before → apply → validate after
openremap tune target.bin recipe.json

# If tune fails at Phase 1 — diagnose why
openremap validate check target.bin recipe.json

# 4. MANDATORY — correct checksums with ECM Titanium, WinOLS, or equivalent
#    before flashing the tuned binary to any vehicle
```

---

## Other documentation

| Document | Contents |
|---|---|
| [`docs/commands/`](commands/) | Per-command reference — arguments, options, examples, example output |
| [`docs/confidence.md`](confidence.md) | Confidence scoring — tiers, signals, warnings, and score breakdown |
| [`docs/manufacturers/bosch.md`](manufacturers/bosch.md) | Supported ECU families in detail — ident formats, file sizes, SW/HW layout |
| [`docs/about.md`](about.md) | How it works — the recipe format, the match key, use cases, FAQ |
| [`docs/recipe-format.md`](recipe-format.md) | The recipe JSON spec — fields, structure, versioning |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | How to add a new ECU extractor, code style, submitting a PR |
| [`DISCLAIMER.md`](../DISCLAIMER.md) | Liability, intended use, professional review requirements |