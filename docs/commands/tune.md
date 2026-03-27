# `openremap tune`

Apply a tuning recipe to a target ECU binary in a single command.

`openremap tune` runs three phases automatically:

| Phase | What it does |
|---|---|
| **1 — validate before** | Strict pre-flight check: are the original bytes at every expected offset? |
| **2 — apply** | Write the tuned bytes with a ±2 KB anchor search for shifted maps |
| **3 — validate after** | Confirm every tuned byte was written correctly |

The original file is **never modified**. The tuned binary is written only when
all three phases pass. Exit code `0` = success, `1` = any phase failed.

> 🔴 **CHECKSUM VERIFICATION IS MANDATORY**
>
> `openremap tune` does NOT calculate or correct ECU checksums.
>
> Before flashing any tuned binary to a vehicle you **must** run it through a
> dedicated checksum correction tool — ECM Titanium, WinOLS, Checksum Fix Pro,
> or equivalent. Phase 3 (`validate after`) confirms the recipe was applied
> correctly. It does **not** replace a checksum tool. These are two different
> things.
>
> **Flashing a binary with an incorrect checksum will brick your ECU.**
> No exceptions. No recovery without a bench flash or JTAG setup.

---

## Usage

```bash
openremap tune <TARGET> <RECIPE> [OPTIONS]
```

---

## Arguments

| Argument | Required | Description |
|---|---|---|
| `TARGET` | Yes | The untuned ECU binary to apply the recipe to. Must end in `.bin` or `.ori`. |
| `RECIPE` | Yes | The recipe `.json` file produced by `openremap cook`. |

---

## Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--output PATH` | `-o` | `<target_stem>_tuned<ext>` | Path to write the tuned binary. Defaults to the same folder as the target with `_tuned` appended to the stem. |
| `--report PATH` | `-r` | | Save the combined three-phase report as a JSON file. Includes Phase 1, Phase 2, and Phase 3 results in a single document. |
| `--skip-validation` | | off | Skip Phases 1 and 3 (pre-flight and post-tune validation) and apply the recipe directly. Use only in scripted pipelines where you have already validated separately. |
| `--json` | | off | Print the combined three-phase report as JSON instead of the human-readable output. |
| `--help` | | | Show help and exit. |

---

## Examples

```bash
# Apply a tune — all three phases run automatically
openremap tune target.bin recipe.json

# Specify where to write the tuned binary
openremap tune target.bin recipe.json --output my_tuned.bin

# Save the combined three-phase report as JSON
openremap tune target.bin recipe.json --report tune_report.json

# Save both the tuned binary and the report
openremap tune target.bin recipe.json --output my_tuned.bin --report my_report.json

# Skip Phases 1 and 3 (scripted pipelines only)
openremap tune target.bin recipe.json --skip-validation

# Print the full three-phase report as JSON to the screen
openremap tune target.bin recipe.json --json
```

---

## Example output

### All three phases passed

```
  openremap tune  target.bin  +  recipe.json

  ──────────────────────────────────────────────────────────
  Phase 1 — Pre-flight check  (validate before)

  Target                   target.bin
  MD5                      abc2e7d4610bfda5619951e015566e8d
  Instructions             277
  Passed                   277

  ✅ Target matches recipe — safe to apply

  ──────────────────────────────────────────────────────────
  Phase 2 — Applying tune

  Instructions             277
  Applied                  275
  Shifted                    2
     Shifted instructions were recovered via ±2 KB anchor search.

  ✅ Recipe applied — 275/277 instructions written

  ──────────────────────────────────────────────────────────
  Phase 3 — Post-tune verification  (validate after)

  Instructions             277
  Confirmed                277

  ✅ All mb bytes confirmed in tuned binary

  ──────────────────────────────────────────────────────────
  ✅ Tune complete

  Target MD5               abc2e7d4610bfda5619951e015566e8d
  Tuned MD5                f3c1a9b2d8e7041256ff34c2ab987d31
  Tuned binary             target_tuned.bin

  ⚠  MANDATORY: correct checksums with ECM Titanium, WinOLS, or
     a similar tool before flashing the tuned binary to a vehicle.
     Flashing without checksum correction will brick the ECU.
  ──────────────────────────────────────────────────────────
```

### Phase 1 failed — nothing written

```
  openremap tune  target.bin  +  recipe.json

  ──────────────────────────────────────────────────────────
  Phase 1 — Pre-flight check  (validate before)

  ⚠  Match key mismatch:
     recipe : EDC17C66::1037541778
     target : EDC17C66::1037541779

  Target                   target.bin
  MD5                      ff3a91b2...
  Instructions             277
  Passed                   261
  Failed                    16

  Failed instructions:
     #  12  offset 0x0012A4F0  — ob not found at offset
     #  13  offset 0x0012A510  — ob not found at offset
     …

  Tip: run  openremap validate check  to find out why.

  ❌ NOT safe to apply — 16 instruction(s) failed.
     Run  openremap validate check  to diagnose.
```

Phase 2 and Phase 3 do not run. The tuned binary is not written.

### Phase 2 applied with shifted instructions

```
  Phase 2 — Applying tune

  Instructions             180
  Applied                  173
  Shifted                    7
     Shifted instructions were recovered via ±2 KB anchor search.

  ✅ Recipe applied — 173/180 instructions written
```

Shifted instructions were found at a nearby offset using the `ctx + ob` anchor
search. Phase 3 still runs to confirm every byte landed correctly.

---

## What to look for

| Result | What to do |
|---|---|
| `✅ Tune complete` — all three phases green | Correct checksums, then flash. |
| `Shifted` count in Phase 2 | Maps recovered via ±2 KB search — inspect the tuned binary carefully before flashing. |
| Phase 1 fails: `❌ NOT safe to apply` | Run `openremap validate check target.bin recipe.json` to find out whether the maps shifted or you have the wrong ECU. |
| Phase 2 fails: apply error | Run `openremap validate check` to diagnose. Do not flash the output. |
| Phase 3 fails: `❌ Post-tune verification failed` | Do not flash. Re-run `openremap tune` or investigate with `openremap validate check`. |

---

## How it works

1. The target binary and recipe are loaded and the output path is resolved
   (defaults to `<target_stem>_tuned<ext>` in the same directory).

2. **Phase 1 — validate before** (`ECUStrictValidator`): reads the exact
   offset of every recipe instruction and checks that the original bytes (`ob`)
   are present there. Reports a `match_key` or size warning if the target
   appears to be a different SW version. If any instruction fails, the command
   exits here — nothing is written.

3. **Phase 2 — apply** (`ECUPatcher`): for each instruction, looks for the
   `ctx + ob` anchor at the expected offset. If found, replaces `ob` with `mb`.
   If the anchor is not at the expected offset, searches within ±2 KB. If still
   not found, the instruction is marked as failed. If all instructions are
   applied (with or without shifting), the tuned bytes are held in memory.
   If any instruction failed, the command exits here — nothing is written.

4. **Phase 3 — validate after** (`ECUPatchedValidator`): reads the exact offset
   of every instruction in the in-memory tuned binary and confirms the modified
   bytes (`mb`) are now present there. If all pass, the tuned binary is written
   to disk.

5. A unified summary and (optionally) a combined JSON report covering all three
   phases are printed / saved.

---

## Running phases individually

`openremap tune` is the recommended path for interactive use. If you need to
inspect a specific phase in isolation — to save a report, integrate into a
script, or diagnose a failure — the individual `validate` sub-commands run the
same underlying logic:

```bash
# Phase 1 only — pre-flight check
openremap validate before target.bin recipe.json

# Diagnostic — why did Phase 1 fail?
openremap validate check target.bin recipe.json

# Phase 3 only — post-tune confirmation
openremap validate after target_tuned.bin recipe.json --json --output verify.json
```

See [validate.md](validate.md) for the full reference.

---

## After tuning — required next step

```bash
# MANDATORY — correct checksums before flashing
# Use ECM Titanium, WinOLS, Checksum Fix Pro, or equivalent.
# Skipping this step will brick the ECU.
```

---

## Notes

- The original `TARGET` file is never modified. The tuned result is always
  written to a separate output file.
- If the output file path already exists it will be overwritten. Use `--output`
  to choose a specific path if you want to preserve the previous version.
- `--skip-validation` bypasses Phases 1 and 3. The recipe is applied directly
  without pre-flight or post-tune checks. Use only in scripted pipelines where
  you have already validated separately.
- The `--report` JSON document contains the results of all three phases in a
  single file under the keys `phase_1_validate_before`, `phase_2_apply`, and
  `phase_3_validate_after`, plus a top-level `success` boolean. Useful for
  CI, auditing, and sharing results.
- If `--skip-validation` is passed, the `phase_1_validate_before` and
  `phase_3_validate_after` objects in the report carry `"skipped": true`.

---

← [Back to CLI reference](../cli.md)