# `openremap workflow`

Print a complete step-by-step guide through the entire tuning workflow — plain English, exact commands to type, and what to look for (or do) when something goes wrong.

Designed for anyone who is new to OpenRemap or to the terminal.

---

## Usage

```bash
openremap workflow
```

No arguments. No options. Just run it and read.

---

## What it covers

| Step | Description |
|---|---|
| **0** | Sort a folder of ECU binaries into a tidy library (optional) |
| **1** | Read a stock binary — confirm it is a supported ECU |
| **2** | Cook a recipe by comparing the stock and tuned binary |
| **3** | Apply the recipe — validate before → apply → validate after in one shot (`openremap tune`) |
| **4** | Validate individually (advanced — only when Step 3 fails) |
| **⚠ 5** | **MANDATORY** — correct checksums before flashing to any vehicle |

---

## Example output

```
  OpenRemap — Workflow Guide
  ─────────────────────────────────────────────────────────────────────────────
  A complete walkthrough from raw binary to verified tuned file.
  Run  openremap <command> --help  at any time for full options.
  ─────────────────────────────────────────────────────────────────────────────

  ─────────────────────────────────────────────────────────────────────────────

  STEP 1 — Identify your stock binary

  What:  Read the binary and extract manufacturer, ECU family,
         software version, hardware number, calibration ID, and
         the match key that uniquely identifies this file.

  Why:   Confirms the file is a supported ECU and gives you the
         information you need before touching anything.

    openremap identify stock.bin

  What to look for:
    ✓  Manufacturer, ECU Family, and Match Key are all filled in.
    ✓  Software Version is present — it is the primary matching key.
    ✗  Any field showing "unknown" — the ECU family may not be supported yet.
       Open an issue or check CONTRIBUTING.md to add support for it.
    ✗  File reads as empty or the command errors — check the path and extension.
       Only .bin and .ori files are accepted.

  ─────────────────────────────────────────────────────────────────────────────

  STEP 2 — Cook a recipe

  What:  Compare your stock (unmodified) binary and a tuned binary.
  ...
```

The full output continues through all six steps with the same format.

---

## Notes

- The guide is read-only — running `openremap workflow` never touches any file.
- At any point you can run `openremap <command> --help` for a quick reminder of the flags for that specific command.
- The full per-command reference is in [`docs/commands/`](.).