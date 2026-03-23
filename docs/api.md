# API Reference

Base URL for all endpoints: `/api/v1`

Run the server with:

```bash
uv run uvicorn main:app --reload --port 8000
```

Interactive Swagger UI is available at `http://localhost:8000/docs`.

---

## System

### `GET /api/v1/system/status`

Health check.

**Response**
```json
{ "status": "ok", "message": "System is running smoothly." }
```

---

## Tuning

All tuning endpoints live under `/api/v1/tuning`.

---

### `GET /api/v1/tuning/supported-families`

Returns every ECU family the system can currently identify.

**Response**
```json
{
  "total": 13,
  "families": [
    {
      "manufacturer": "Bosch",
      "family": "EDC17",
      "extractor": "BoschEDC17Extractor"
    }
  ]
}
```

Use this to check coverage before submitting a binary. Families not in this list will be returned as unknown.

---

### `POST /api/v1/tuning/identify`

Identify a single ECU binary.

**Request** — `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | `.bin` / `.ori` | ✅ | The ECU binary to identify |

**Response**
```json
{
  "manufacturer": "Bosch",
  "match_key": "EDC17::08001505827522B",
  "ecu_family": "EDC17",
  "ecu_variant": null,
  "software_version": null,
  "hardware_number": null,
  "calibration_id": "08001505827522B",
  "file_size": 4194304,
  "sha256": "33c981..."
}
```

| Field | Description |
|---|---|
| `match_key` | Compound identity key used to match a binary to a recipe. `null` if the ECU could not be fully identified. |
| `ecu_variant` | Sub-variant within the family (e.g. `EDC17C66`). `null` if not extracted. |
| `software_version` | SW version string extracted from the binary. `null` if absent or unreadable. |
| `calibration_id` | Calibration identifier. For some families (e.g. LH-Jetronic) this drives `match_key` instead of `software_version`. |

**Errors**

| Status | Reason |
|---|---|
| `422` | File is not a `.bin` or `.ori`, or is empty |
| `413` | File exceeds the 10 MB limit |
| `500` | Identification failed unexpectedly |

---

### `POST /api/v1/tuning/cook`

Cook a recipe by diffing an original and a modified ECU binary.

**Request** — `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `original` | `.bin` / `.ori` | ✅ | The unmodified (stock) ECU binary |
| `modified` | `.bin` / `.ori` | ✅ | The tuned ECU binary |

**Response** — a format-4.0 recipe JSON object.

```json
{
  "metadata": {
    "original_file": "stock.bin",
    "modified_file": "stage1.bin",
    "format_version": "4.0"
  },
  "ecu": {
    "manufacturer": "Bosch",
    "match_key": "EDC17::08001505827522B",
    "ecu_family": "EDC17",
    "ecu_variant": null,
    "calibration_id": "08001505827522B",
    "file_size": 4194304,
    "sha256": "33c981..."
  },
  "statistics": {
    "total_changes": 277,
    "total_bytes_changed": 43577
  },
  "instructions": [
    {
      "offset": 139264,
      "offset_hex": "22000",
      "size": 4,
      "ob": "AABBCCDD",
      "mb": "AABBCC00",
      "ctx": "DEADBEEF...",
      "context_after": "CAFEBABE...",
      "context_size": 32,
      "description": "4 bytes at 0x22000 modified"
    }
  ]
}
```

Save this JSON — it is the input to every validate and patch endpoint.

See [recipe-format.md](recipe-format.md) for the full field reference.

**Errors**

| Status | Reason |
|---|---|
| `422` | Either file is not a `.bin` or `.ori`, or is empty |
| `413` | Either file exceeds the 10 MB limit |
| `500` | Cook failed unexpectedly |

---

## Patch

All patch endpoints live under `/api/v1/tuning/patch`.

### Recommended workflow

```
cook → validate/strict → patch/apply → validate/patched
```

If `validate/strict` fails, run `validate/exists` to understand why before deciding whether to proceed.

---

### `POST /api/v1/tuning/patch/validate/strict`

Verify that the exact original bytes (`ob`) are present at every recorded offset. Run this **before** patching.

Reads every instruction offset directly and compares `ob` against the bytes at that position. All instructions are checked before reporting — the response always contains a full picture.

**Request** — `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `target` | `.bin` / `.ori` | ✅ | The unpatched ECU binary |
| `recipe` | `.json` | ✅ | The recipe file |

**Response**
```json
{
  "target_file": "my_ecu.bin",
  "target_md5": "d41d8cd9...",
  "warnings": {
    "size_mismatch": false,
    "match_key_mismatch": false
  },
  "summary": {
    "total": 277,
    "passed": 277,
    "failed": 0,
    "safe_to_patch": true
  }
}
```

| Field | Description |
|---|---|
| `warnings.size_mismatch` | The target binary is a different size from the one used to cook the recipe. |
| `warnings.match_key_mismatch` | The target binary identifies as a different ECU or calibration from the one in the recipe. Do not patch. |
| `summary.safe_to_patch` | `true` only when every instruction passed. Safe to call `/patch/apply`. |

**Errors**

| Status | Reason |
|---|---|
| `422` | Target is not a `.bin` or `.ori`, recipe is not `.json`, or either is empty |
| `413` | Target exceeds the 10 MB limit |
| `500` | Validation failed unexpectedly |

---

### `POST /api/v1/tuning/patch/validate/exists`

Search the entire binary for the `ob` bytes of every instruction. Use this to diagnose a strict validation failure.

Unlike strict validation (which checks a fixed offset), this scans the whole binary for each instruction's `ob` bytes and classifies the result:

| Classification | Meaning |
|---|---|
| `EXACT` | Found at the expected offset — identical to a strict pass |
| `SHIFTED` | Found, but at a different offset — a SW revision likely moved this map |
| `MISSING` | Not found anywhere in the binary — this is the wrong ECU |

**Request** — `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `target` | `.bin` / `.ori` | ✅ | The target ECU binary |
| `recipe` | `.json` | ✅ | The recipe file |

**Response**
```json
{
  "target_file": "my_ecu.bin",
  "target_md5": "d41d8cd9...",
  "warnings": {
    "size_mismatch": false,
    "match_key_mismatch": true
  },
  "summary": {
    "total": 277,
    "exact": 270,
    "shifted": 7,
    "missing": 0,
    "verdict": "shifted_recoverable"
  },
  "shifted": [
    {
      "index": 14,
      "expected_offset": "0x22000",
      "found_offset": "0x22400",
      "shift": 1024,
      "match_count": 1
    }
  ],
  "missing": []
}
```

| Verdict | Meaning |
|---|---|
| `safe_exact` | All instructions found at their exact offsets |
| `shifted_recoverable` | Some instructions shifted — the patcher's ±2 KB anchor search may recover them |
| `missing_unrecoverable` | One or more instructions not found anywhere — wrong ECU, do not patch |

**Errors**

| Status | Reason |
|---|---|
| `422` | Target is not a `.bin` or `.ori`, recipe is not `.json`, or either is empty |
| `413` | Target exceeds the 10 MB limit |
| `500` | Validation failed unexpectedly |

---

### `POST /api/v1/tuning/patch/validate/patched`

Confirm that the modified bytes (`mb`) are now present at every recorded offset. Run this **after** patching.

This is the mirror image of `validate/strict`: strict checks `ob` before writing; this checks `mb` after.

**Request** — `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `patched` | `.bin` / `.ori` | ✅ | The patched ECU binary |
| `recipe` | `.json` | ✅ | The recipe file used during patching |

**Response**
```json
{
  "patched_file": "my_ecu_patched.bin",
  "patched_md5": "a1b2c3d4...",
  "warnings": {
    "size_mismatch": false,
    "match_key_mismatch": false
  },
  "summary": {
    "total": 277,
    "confirmed": 277,
    "failed": 0,
    "patch_confirmed": true
  },
  "failures": []
}
```

| Field | Description |
|---|---|
| `summary.patch_confirmed` | `true` only when every instruction's `mb` bytes are present at the correct offset. |
| `failures` | List of instructions that failed, each with `index`, `offset`, `size`, and `reason`. |

**Errors**

| Status | Reason |
|---|---|
| `422` | Patched file is not a `.bin` or `.ori`, recipe is not `.json`, or either is empty |
| `413` | Patched file exceeds the 10 MB limit |
| `500` | Verification failed unexpectedly |

---

### `POST /api/v1/tuning/patch/apply`

Apply a recipe to a target binary and return the patched file.

Internally runs strict pre-flight validation before writing a single byte. Uses a `ctx + ob` anchor search within ±2 KB of the expected offset to tolerate minor SW revision shifts.

**Request** — `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `target` | `.bin` / `.ori` | ✅ | The unpatched ECU binary |
| `recipe` | `.json` | ✅ | The recipe file |

**Response (success)** — `application/octet-stream`

The patched binary is returned as a downloadable file named `<original_stem>_patched.bin`.

A compact patch report is attached as a base64-encoded JSON string in the `X-Patch-Report` response header. Decode and parse it to get the full summary including `applied`, `failed`, `shifted`, and `patched_md5`.

```python
import base64, json, httpx

response = httpx.post(...)
report = json.loads(base64.b64decode(response.headers["X-Patch-Report"]))
```

**Response (failure)** — `422`

```json
{
  "detail": "Pre-flight validation failed: 3 instruction(s) did not match..."
}
```

> 🔴 **CHECKSUM VERIFICATION IS MANDATORY**
> Before flashing any patched binary to a vehicle, you **must** run it through a dedicated checksum correction tool (ECM Titanium, WinOLS, or equivalent). This endpoint confirms the recipe was applied correctly — it does **not** calculate or correct ECU checksums. Flashing a binary with an incorrect checksum **will brick your ECU.** No exceptions.

**Errors**

| Status | Reason |
|---|---|
| `422` | Pre-flight validation failed, or target/recipe files are invalid |
| `413` | Target exceeds the 10 MB limit |
| `500` | Patch failed unexpectedly |

---

## File Constraints

These limits apply to all endpoints that accept file uploads.

| Constraint | Value |
|---|---|
| Allowed binary extensions | `.bin`, `.ori` |
| Allowed recipe extension | `.json` |
| Maximum file size | 10 MB per file |

---

## Rate Limits

Default limits are applied globally. These can be adjusted in `src/api/core/limiter.py`.

| Scope | Limit |
|---|---|
| Global default | 200 requests / hour |
| Read endpoints | 100 requests / minute |
| Write endpoints | 30 requests / minute |