# CLI Reference

Full reference for the `openremap` command-line tool. No server or database required — install and run anywhere.

---

## Installation

```bash
git clone https://github.com/your-username/openremap.git
cd openremap
uv sync
```

`uv sync` installs all dependencies and registers the `openremap` command in your shell.

---

## Commands

| Command | Description |
|---|---|
| [`identify`](#identify) | Identify a single ECU binary |
| [`cook`](#cook) | Cook a recipe by diffing two ECU binaries |
| [`validate strict`](#validate-strict) | Verify ob bytes before patching |
| [`validate exists`](#validate-exists) | Search entire binary for ob bytes |
| [`validate patched`](#validate-patched) | Confirm mb bytes were written correctly |
| [`patch apply`](#patch-apply) | Apply a recipe to a target binary |
| [`scan`](#scan) | Batch-classify a directory of binaries |

---

## `identify`

Identify a single ECU binary. Prints manufacturer, ECU family, software version, hardware number, calibration ID, match key, file size, and SHA-256.

```bash
openremap identify <file>
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `file` | Yes | ECU binary to identify (`.bin` or `.ori`) |

**Options**

| Option | Short | Description |
|---|---|---|
| `--json` | | Output result as JSON instead of a table |
| `--output PATH` | `-o` | Save the result to a file |
| `--help` | | Show help |

**Examples**

```bash
# Human-readable table
openremap identify ecu.bin

# JSON output to stdout
openremap identify ecu.bin --json

# Save JSON result to a file
openremap identify ecu.bin --json --output result.json
```

**Example output**

```
  ecu.bin
  Bosch · MEDC17

  Manufacturer      Bosch
  ECU Family        MEDC17
  ECU Variant       EDC17C66
  Software Version  1037541778126241V0
  Hardware Number   unknown
  Calibration ID    unknown
  Match Key         EDC17C66::1037541778126241V0
  File Size         4,194,304 bytes
  SHA-256           00f727e8abf62d384acc4420b08fe8e...
```

---

## `cook`

Cook a recipe by diffing an original (stock) and a modified (tuned) ECU binary. Produces a JSON recipe file containing every changed byte block, its offset, original bytes (`ob`), modified bytes (`mb`), and a context anchor (`ctx`).

The recipe is the input for all `validate` and `patch` commands.

```bash
openremap cook <original> <modified> [options]
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `original` | Yes | The unmodified (stock) ECU binary (`.bin` or `.ori`) |
| `modified` | Yes | The tuned ECU binary (`.bin` or `.ori`) |

**Options**

| Option | Short | Default | Description |
|---|---|---|---|
| `--output PATH` | `-o` | stdout | File path to write the recipe JSON |
| `--context-size N` | `-c` | `32` | Bytes of context to capture before each changed block (8–128) |
| `--pretty / --compact` | | `--pretty` | Pretty-print or compact JSON output |
| `--help` | | | Show help |

**Examples**

```bash
# Cook a recipe and save it
openremap cook stock.bin stage1.bin --output recipe.json

# Wider context window (better anchor matching on shifted binaries)
openremap cook stock.bin stage1.bin --context-size 64 --output recipe.json

# Print the recipe to stdout
openremap cook stock.bin stage1.bin

# Compact JSON (smaller file, harder to read)
openremap cook stock.bin stage1.bin --compact --output recipe.json
```

**Example output**

```
  Cooking recipe from stock.bin vs stage1.bin …

  ✅ Recipe built successfully

  ECU                    Bosch · EDC17
  Match Key              EDC17::08001505827522B
  Format Version         4.0
  Instructions           277
  Bytes Changed          43,577
  Original               stock.bin
  Modified               stage1.bin

  Recipe saved to recipe.json
```

---

## `validate strict`

Verify that the exact original bytes (`ob`) are present at every recorded offset in a target binary. Run this **before** patching.

Returns `safe_to_patch: true` only when every instruction passes. A `match_key_mismatch` warning means the target binary is a different ECU or calibration from the one the recipe was built for — do not patch.

```bash
openremap validate strict <target> <recipe>
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `target` | Yes | The unpatched ECU binary (`.bin` or `.ori`) |
| `recipe` | Yes | The recipe `.json` file |

**Options**

| Option | Short | Description |
|---|---|---|
| `--json` | | Output the full report as JSON |
| `--output PATH` | `-o` | Save the report to a file |
| `--help` | | Show help |

**Examples**

```bash
openremap validate strict target.bin recipe.json
openremap validate strict target.bin recipe.json --json
openremap validate strict target.bin recipe.json --json --output report.json
```

**Example output**

```
  Validating target.bin against recipe.json …

  ✅ Safe to patch

  Target               target.bin
  MD5                  abc2e7d4610bfda5619951e015566e8d
  Instructions         277
  Passed               277
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | All instructions passed — safe to patch |
| `1` | One or more instructions failed, or a mismatch warning was raised |

---

## `validate exists`

Search the **entire** binary for the `ob` bytes of every instruction. Use this to diagnose a `validate strict` failure — it tells you whether maps have shifted (different SW revision) or are completely absent (wrong ECU).

```bash
openremap validate exists <target> <recipe>
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `target` | Yes | The target ECU binary (`.bin` or `.ori`) |
| `recipe` | Yes | The recipe `.json` file |

**Options**

| Option | Short | Description |
|---|---|---|
| `--json` | | Output the full report as JSON |
| `--output PATH` | `-o` | Save the report to a file |
| `--help` | | Show help |

**Verdicts**

| Verdict | Meaning |
|---|---|
| `SAFE EXACT` | All `ob` bytes found at their exact expected offsets |
| `SHIFTED RECOVERABLE` | Some `ob` bytes found elsewhere in the binary — a SW revision likely shifted the maps. The patcher's ±2 KB anchor search may still recover these. |
| `MISSING UNRECOVERABLE` | Some `ob` bytes are nowhere in the binary — this is the wrong ECU. Do not attempt to patch. |

**Examples**

```bash
openremap validate exists target.bin recipe.json
openremap validate exists target.bin recipe.json --json --output exists_report.json
```

---

## `validate patched`

After patching, confirm that every instruction's modified bytes (`mb`) are now present at the correct offset. The mirror image of `validate strict`: strict checks `ob` before patching; this checks `mb` after.

```bash
openremap validate patched <patched> <recipe>
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `patched` | Yes | The patched ECU binary (`.bin` or `.ori`) |
| `recipe` | Yes | The recipe `.json` file used during patching |

**Options**

| Option | Short | Description |
|---|---|---|
| `--json` | | Output the full report as JSON |
| `--output PATH` | `-o` | Save the report to a file |
| `--help` | | Show help |

**Examples**

```bash
openremap validate patched patched.bin recipe.json
openremap validate patched patched.bin recipe.json --json --output verify.json
```

---

## `patch apply`

Apply a recipe to a target binary. Internally runs `validate strict` before writing anything. Uses a `ctx + ob` anchor search within ±2 KB of the expected offset to tolerate minor SW revision shifts.

On success, writes the patched binary and prints a summary. On failure, exits with code 1 and prints which instructions failed — nothing is written.

> 🔴 **CHECKSUM VERIFICATION IS MANDATORY**
> Before flashing any patched binary, you **must** run it through a dedicated checksum correction tool (ECM Titanium, WinOLS, or equivalent). `openremap validate patched` confirms the recipe was applied correctly — it does **not** calculate or correct ECU checksums. Flashing a binary with an incorrect checksum **will brick your ECU.** No exceptions.

```bash
openremap patch apply <target> <recipe> [options]
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `target` | Yes | The unpatched ECU binary (`.bin` or `.ori`) |
| `recipe` | Yes | The recipe `.json` file |

**Options**

| Option | Short | Default | Description |
|---|---|---|---|
| `--output PATH` | `-o` | `<target_stem>_patched<ext>` | Path to write the patched binary |
| `--report PATH` | `-r` | | Save the patch report as a JSON file |
| `--skip-validation` | | `false` | Skip strict pre-flight validation (use with caution) |
| `--json` | | | Print the full patch report as JSON to stdout |
| `--help` | | | Show help |

**Examples**

```bash
# Patch with default output name (target_patched.bin)
openremap patch apply target.bin recipe.json

# Specify output path
openremap patch apply target.bin recipe.json --output my_patched.bin

# Save a JSON patch report alongside the patched binary
openremap patch apply target.bin recipe.json --report patch_report.json

# Skip pre-flight validation (only if you have already run validate strict)
openremap patch apply target.bin recipe.json --skip-validation
```

**Example output**

```
  Patching target.bin with recipe.json …

  ✅ Patch applied successfully

  Target                 target.bin
  Target MD5             abc2e7d4610bfda5619951e015566e8d
  Patched MD5            f3c1a9b2d8e7041256ff34c2ab987d31
  Instructions           277
  Applied                275
  Applied (shifted)      2

  Patched binary saved to target_patched.bin

  ⚠  Always verify checksums with ECM Titanium, WinOLS, or a similar
     tool before flashing the patched binary to a vehicle.
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Patch applied successfully |
| `1` | Pre-flight validation failed or patch could not be applied — nothing written |

---

## `scan`

Batch-classify an entire directory of ECU binaries through all registered extractors. Each file is classified into one of five outcomes and optionally moved into a corresponding sub-folder.

This is the primary tool for testing new extractors and auditing coverage across a large collection.

```bash
openremap scan [directory] [options]
```

**Arguments**

| Argument | Required | Default | Description |
|---|---|---|---|
| `directory` | No | `.` (current directory) | Directory containing the raw `.bin` / `.ori` files |

**Options**

| Option | Short | Description |
|---|---|---|
| `--dry-run` | `-n` | Classify every file and print results without moving anything. Destination folders are not required. |
| `--create-dirs` | | Create the five destination sub-folders automatically if they do not exist. |
| `--help` | | Show help |

### How classification works

Unlike `identify`, which stops at the first matching extractor, `scan` runs **every registered extractor** against every file. This makes contested files visible — `identify` would silently hide them.

Each file is classified into exactly one outcome:

| Outcome | Meaning |
|---|---|
| **SCANNED** | Exactly one extractor claimed the file and a `match_key` was successfully extracted. Fully identified. |
| **SW MISSING** | Exactly one extractor claimed the file, but `match_key` could not be extracted. Family is known; calibration is not. |
| **CONTESTED** | More than one extractor returned `True` from `can_handle()`. Signals a pattern overlap that must be resolved. |
| **UNKNOWN** | No extractor matched. Family is not yet supported, or the file is corrupt / not an ECU binary. |
| **TRASH** | File does not have a `.bin` or `.ori` extension. Moved aside without being read. |

### Classification routing: `match_key` not `software_version`

The routing signal is `match_key`, not `software_version` directly. This matters because some ECU architectures have no software version by design:

- **Normal ECUs** (EDC15, EDC16, ME7 …) — `match_key` is `family::software_version`
- **LH-Jetronic Format A** — no software version in the binary; `match_key` is `family::calibration_id` instead
- **WinOLS-erased binaries** — identifying bytes wiped; `match_key` is `None` → `sw_missing`
- **Pattern gap** — extractor matched but could not parse a version string; `match_key` is `None` → `sw_missing`, flagging the extractor for improvement

### Destination folder layout

When moving files (without `--dry-run`), the scanner expects five sub-folders inside the target directory. Use `--create-dirs` to create them automatically:

```
my_bins/
├── scanned/        ← fully identified
├── sw_missing/     ← family known, calibration unknown
├── contested/      ← claimed by more than one extractor
├── unknown/        ← no extractor matched
└── trash/          ← wrong file extension
```

Files are never overwritten. Filename collisions are resolved by appending a counter (`file__1.bin`, `file__2.bin`, …).

### Examples

```bash
# Preview without moving anything (no sub-folders needed)
openremap scan ./my_bins/ --dry-run

# Scan and sort, creating sub-folders automatically
openremap scan ./my_bins/ --create-dirs

# Scan a directory where sub-folders already exist
openremap scan ./my_bins/

# Scan the current directory
openremap scan --dry-run
```

### Example output

```
  OpenRemap — Batch ECU Scanner
  336 file(s)  •  13 extractor(s)  •  /path/to/my_bins

[  1/336]  SCANNED    006410010A0.bin    63.8 ms
                  └─ extractor: BoschME7Extractor  family: ME7.1.1  sw: 1037371702  hw: 0261208771  key: ME7.1.1::1037371702
[  2/336]  SCANNED    0280-000-560.BIN    4.4 ms
                  └─ extractor: BoschLHExtractor  family: LH-Jetronic  cal_id: 1012621LH241rp (sw absent by architecture)  key: LH-JETRONIC::1012621LH241RP
[  3/336]  SW MISSING  anonymous_dump.bin   12.1 ms
                  └─ extractor: BoschMotronicLegacyExtractor  family: DME-3.2  sw: None
[  4/336]  CONTESTED   edge_case.bin   48.3 ms
                  └─ claimed by: BoschEDC15Extractor(Bosch), BoschEDC16Extractor(Bosch)
[  5/336]  UNKNOWN     mystery.bin    0.4 ms
                  └─ no extractor matched

  ── Summary ────────────────────────────────────────
  Scanned       331
  SW Missing      2
  Contested       1
  Unknown         1
  Trash           1

  Total: 336  •  19.6s
```

### Recommended workflow

```bash
# 1. Always dry-run first
openremap scan ./my_bins/ --dry-run

# 2. If the results look right, sort for real
openremap scan ./my_bins/ --create-dirs

# 3. Investigate sw_missing and contested folders
openremap identify my_bins/sw_missing/some_file.bin
openremap identify my_bins/contested/some_file.bin
```

---

## Typical end-to-end workflow

```bash
# 1. Identify your stock binary
openremap identify stock.bin

# 2. Cook a recipe from stock vs tuned
openremap cook stock.bin stage1.bin --output recipe.json

# 3. Validate the recipe against the target before patching
openremap validate strict target.bin recipe.json

# 4. Apply the patch
openremap patch apply target.bin recipe.json --output target_patched.bin

# 5. Confirm the patch was written correctly
openremap validate patched target_patched.bin recipe.json

# 6. MANDATORY — run the patched binary through WinOLS, ECM Titanium, or
#    equivalent to correct checksums before flashing to any vehicle
```
