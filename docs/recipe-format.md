# Recipe Format

A recipe is a plain JSON file that captures every byte-level change between an original and a modified ECU binary. It is the central data structure of the entire OpenRemap pipeline — produced by `openremap cook`, consumed by every validate and patch command.

Recipes are fully portable between the CLI and the API. A recipe cooked on the command line can be applied through the API and vice versa.

---

## Format Version

The current format version is **4.0**, recorded in `metadata.format_version`.

The version is checked during validation and patching. A recipe with an unrecognised format version will be rejected before any instructions are read.

---

## Top-level Structure

```json
{
  "metadata": { ... },
  "ecu":      { ... },
  "statistics": { ... },
  "instructions": [ ... ]
}
```

---

## `metadata`

Information about the files the recipe was built from and the format itself.

| Field | Type | Description |
|---|---|---|
| `original_file` | `string` | Filename of the unmodified (stock) binary |
| `modified_file` | `string` | Filename of the tuned binary |
| `format_version` | `string` | Recipe format version — currently `"4.0"` |

```json
"metadata": {
  "original_file": "stock.bin",
  "modified_file": "stage1.bin",
  "format_version": "4.0"
}
```

---

## `ecu`

The identity of the ECU the recipe was built for. Every validation and patch operation checks this block against the target binary before touching a single byte.

| Field | Type | Description |
|---|---|---|
| `manufacturer` | `string \| null` | ECU manufacturer (e.g. `"Bosch"`) |
| `match_key` | `string \| null` | Compound identity key used to detect incompatible binaries — see below |
| `ecu_family` | `string \| null` | ECU family (e.g. `"EDC17"`, `"ME7.5"`) |
| `ecu_variant` | `string \| null` | Variant within the family, if distinguishable |
| `software_version` | `string \| null` | Software version string extracted from the binary |
| `hardware_number` | `string \| null` | Hardware part number extracted from the binary |
| `calibration_id` | `string \| null` | Calibration identifier extracted from the binary |
| `file_size` | `integer` | Exact byte size of the original binary |
| `sha256` | `string` | SHA-256 hash of the original binary |

```json
"ecu": {
  "manufacturer": "Bosch",
  "match_key": "EDC17C66::1037541778126241V0",
  "ecu_family": "EDC17",
  "ecu_variant": "EDC17C66",
  "software_version": "1037541778126241V0",
  "hardware_number": null,
  "calibration_id": null,
  "file_size": 4194304,
  "sha256": "00f727e8abf62d384acc4420b08fe8e5477f9d004c8d3a697bbaaa08fe2149f5"
}
```

### The `match_key`

`match_key` is the primary compatibility gate. It is a compound string in the form `FAMILY::VERSION` and is compared against the target binary's own `match_key` before any validation or patching begins.

How it is built depends on the ECU architecture:

| Case | `match_key` form | Example |
|---|---|---|
| Normal ECU with software version | `FAMILY::SOFTWARE_VERSION` | `ME7.5::1037354003` |
| LH-Jetronic Format A (no SW version by design) | `FAMILY::CALIBRATION_ID` | `LH-JETRONIC::1012621LH241RP` |
| Unknown or anonymised binary | `null` | — |

If the target binary's `match_key` does not match the recipe's `match_key`, the operation is rejected immediately with a clear mismatch message. A `null` `match_key` in the recipe disables this check and falls through to byte-level validation.

---

## `statistics`

A summary of the diff. Informational only — not used during patching.

| Field | Type | Description |
|---|---|---|
| `total_changes` | `integer` | Number of instructions in the recipe |
| `total_bytes_changed` | `integer` | Total number of bytes that differ between the two binaries |

```json
"statistics": {
  "total_changes": 277,
  "total_bytes_changed": 43577
}
```

---

## `instructions`

An array of patch instructions. Each instruction describes one contiguous block of bytes that differs between the original and modified binary.

```json
"instructions": [
  {
    "offset": 139264,
    "offset_hex": "22000",
    "size": 4,
    "ob": "AABBCCDD",
    "mb": "AABBCC00",
    "ctx": "DEADBEEF112233445566778899AABBCCDDEEFF00112233445566778899AABBCC",
    "context_after": "CAFEBABE112233445566778899AABBCCDDEEFF00112233445566778899AABBCC",
    "context_size": 32,
    "description": "4 bytes at 0x22000 modified"
  }
]
```

### Instruction fields

| Field | Type | Description |
|---|---|---|
| `offset` | `integer` | Absolute byte offset of the change in the binary |
| `offset_hex` | `string` | Same offset in uppercase hex, without `0x` prefix |
| `size` | `integer` | Number of bytes in this instruction |
| `ob` | `string` | **Original bytes** — uppercase hex. What must be present at `offset` before patching |
| `mb` | `string` | **Modified bytes** — uppercase hex. What is written to `offset` when patching |
| `ctx` | `string` | Context window of `context_size` bytes immediately **before** the change — used as an anchor |
| `context_after` | `string` | Context window of `context_size` bytes immediately **after** the change |
| `context_size` | `integer` | Length of `ctx` and `context_after` in bytes (default: 32) |
| `description` | `string` | Human-readable summary of the instruction |

### `ob` and `mb`

All byte strings are uppercase hex with no separators. A 4-byte value is represented as 8 hex characters: `"AABBCCDD"`.

`ob` (original bytes) is what the strict validator checks before patching. If the bytes at `offset` do not match `ob` exactly, the instruction fails validation and the patch is rejected.

`mb` (modified bytes) is what the patcher writes. The post-patch validator checks that `mb` is present at `offset` after the patch is applied.

### `ctx` — the anchor

`ctx` is the 32-byte (by default) window of bytes that immediately precedes the changed block in the **original** binary. During patching, the patcher uses `ctx + ob` as an anchor to locate the correct position within ±2 KB of `offset`. This allows the patcher to tolerate minor SW revision shifts where maps have moved by a small number of bytes.

The anchor search works as follows:
1. Read `ob` bytes at the exact `offset` recorded in the instruction.
2. If they match — apply the patch immediately.
3. If they do not match — search the region `[offset - 2048, offset + 2048]` for the pattern `ctx + ob`.
4. If found at a new offset — apply the patch at the shifted position.
5. If not found — the instruction fails.

The `context_size` used during cooking can be increased with `--context-size` for binaries where 32 bytes is insufficient to uniquely anchor a pattern. Values between 8 and 128 are accepted.

---

## Safety Properties

- **No blind writes.** The patcher never writes `mb` without first confirming `ob` is present — either at the recorded offset or at a shifted position found via the anchor search.
- **All-or-nothing validation.** The strict validator checks every instruction before the patcher writes a single byte. A single failure aborts the entire operation.
- **Identity gate.** `match_key` and `file_size` are verified against the target binary before any instruction is read. A wrong ECU is rejected before any byte-level work begins.
- **Portable.** Recipes contain no absolute paths, no machine-specific data, and no binary blobs. They are plain JSON and can be stored, versioned, shared, and diffed like any other text file.