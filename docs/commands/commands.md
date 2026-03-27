# `openremap commands`

Print a compact one-line-per-command cheat-sheet of every available command.
Designed for returning users who know the workflow and just need a quick
reminder of the exact syntax.

---

## Usage

```bash
openremap commands
```

No arguments. No options. Just the cheat-sheet.

---

## Example output

```
  OpenRemap — Command Reference
  ─────────────────────────────────────────────────────────────────────────
  Run  openremap <command> --help  for full options on any command.
  Run  openremap workflow           for the complete step-by-step guide.
  ─────────────────────────────────────────────────────────────────────────

  openremap commands                              This cheat-sheet — all commands at a glance.
  openremap workflow                              Full step-by-step guide with explanations. Start here if you are new.
  openremap families                              List every supported ECU family with era, size, and vehicle notes.
  openremap families --family <NAME>              Detailed view for one family (e.g. --family EDC16).
  openremap scan <DIR>                            Classify a folder of ECU binaries — preview mode, nothing moves.
  openremap scan <DIR> --move --organize          Sort classified binaries into Bosch/EDC17/ sub-folders.
  openremap scan <DIR> --report report.json       Write a full scan report (JSON or CSV) alongside the classification.
  openremap identify <FILE>                       Read an ECU binary and print manufacturer, family, SW, HW, confidence.
  openremap identify <FILE> --json                Same as above but output raw JSON — useful for scripting.
  openremap cook <STOCK> <TUNED> --output recipe.json  Diff two binaries and save every changed byte block as a recipe.
  openremap tune <TARGET> <RECIPE>                One-shot: validate → apply → verify. Writes <target>_tuned<ext>.
  openremap tune <TARGET> <RECIPE> --output <OUT> Same, with an explicit output path.
  openremap tune <TARGET> <RECIPE> --report r.json Save the full three-phase tune report as JSON.
  openremap validate before <TARGET> <RECIPE>     Pre-flight check — are the original bytes at every expected offset?
  openremap validate check  <TARGET> <RECIPE>     Diagnostic — why did 'validate before' fail? (searches whole binary)
  openremap validate after  <TUNED>  <RECIPE>     Post-tune confirmation — are the new bytes written correctly?

  ─────────────────────────────────────────────────────────────────────────
  Tip: new user? Run  openremap workflow  — it walks you through every step.
  ─────────────────────────────────────────────────────────────────────────
```

---

## Notes

- Every command shown here also accepts `--help` for a full explanation of
  its arguments and options. For example: `openremap tune --help`.
- `validate before`, `validate check`, and `validate after` are the current
  names. The old names `validate strict`, `validate exists`, and
  `validate tuned` still work but print a deprecation notice.
- `openremap tune` is the recommended way to apply a recipe — it runs all
  three validation and apply phases in one shot. The individual `validate`
  sub-commands exist for diagnostics and scripting.

---

## Related commands

| Command | Reference |
|---|---|
| `openremap workflow` | [→ workflow.md](workflow.md) — full step-by-step guide |
| `openremap families` | [→ families.md](families.md) — list supported ECU families |

---

← [Back to CLI reference](../cli.md)