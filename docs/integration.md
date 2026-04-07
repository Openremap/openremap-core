# Integrating OpenRemap as a Library

A practical guide for developers who want to embed the OpenRemap engine into
their own application — desktop GUI, web service, automation script, or anything
else.

---

## Installation

```bash
pip install openremap
```

Or with uv:

```bash
uv add openremap
```

Requires Python 3.10+.

---

## How the Pipeline Works

OpenRemap exposes five independent services that map to the five stages of the
ECU tuning workflow. You can use any subset — they have no shared state and no
hidden singletons.

```
        bytes                    dict                   bytes
ECU binary ──► identify_ecu() ──► score_identity()       │
                                                          │
original + modified ──► ECUDiffAnalyzer ──► recipe dict ──┤
                                                          │
                              ECUStrictValidator ◄────────┤
                                    │                     │
                              safe_to_patch?              │
                                    │ yes                 │
                              ECUPatcher ─────────────────┘
                                    │
                              patched bytes
                                    │
                          ECUPatchedValidator
```

All services operate **entirely in memory** — they accept `bytes` and `dict`,
never file paths. Your application owns all file I/O. This makes them trivial
to wrap in an API endpoint, a background thread, or a test.

---

## Import Map

```python
from openremap.core.services.identifier    import identify_ecu
from openremap.core.services.confidence    import score_identity, ConfidenceResult
from openremap.core.services.recipe_builder import ECUDiffAnalyzer
from openremap.core.services.validate_strict import ECUStrictValidator
from openremap.core.services.validate_exists import ECUExistenceValidator, MatchStatus
from openremap.core.services.validate_patched import ECUPatchedValidator
from openremap.core.services.patcher        import ECUPatcher, PatchStatus
from openremap.core.manufacturers           import get_extractors, EXTRACTORS
```

---

## 1. Identifying an ECU Binary

### `identify_ecu(data, filename) → dict`

Pass raw bytes. Get back an identity dict.

```python
from openremap.core.services.identifier import identify_ecu

with open("ecu.bin", "rb") as f:
    data = f.read()

identity = identify_ecu(data, filename="ecu.bin")

print(identity["manufacturer"])       # "Bosch"
print(identity["ecu_family"])         # "EDC17"
print(identity["ecu_variant"])        # "EDC17C66"
print(identity["software_version"])   # "1037541778126241V0"
print(identity["match_key"])          # "EDC17C66::1037541778126241V0"
print(identity["hardware_number"])    # "0281034921" or None
print(identity["calibration_id"])     # "CAL_1234" or None
print(identity["oem_part_number"])    # "55263462" or None
print(identity["file_size"])          # 4194304
print(identity["sha256"])             # "00f727e8..."
print(identity["detection_strength"]) # "STRONG" | "MEDIUM" | "WEAK" | None
print(identity["detection_evidence"]) # tuple of evidence tag strings
```

When no extractor recognises the binary all identification fields are `None` —
the function never raises. Check `identity["manufacturer"] is None` to detect
an unrecognised binary.

---

### `score_identity(identity, filename) → ConfidenceResult`

Pass the dict returned by `identify_ecu`. Get back a structured confidence result.

```python
from openremap.core.services.confidence import score_identity

result = score_identity(identity, filename="ecu.bin")

print(result.score)              # integer — higher is better
print(result.tier)               # "High" | "Medium" | "Low" | "Suspicious" | "Unknown"
print(result.tier_colour_hint)   # "green" | "yellow" | "magenta" | "red" | "cyan"
print(result.is_suspicious)      # True if tier is Suspicious or Unknown
print(result.has_warnings)       # True if any warnings were raised
print(result.warnings)           # list of warning strings

# Top contributing signals, human-readable
print(result.rationale_summary())
# e.g. "canonical SW version (+30), hardware number (+20), variant (+10)"

# Full signal breakdown
for signal in result.signals:
    print(f"  {signal.label:40s}  {signal.delta:+d}")
```

**Tier thresholds:**

| Score  | Tier       | Meaning                                      |
|--------|------------|----------------------------------------------|
| ≥ 55   | High       | Strong identification — safe to proceed      |
| 25–54  | Medium     | Probable match — review warnings before use  |
| 0–24   | Low        | Weak match — manual verification recommended |
| < 0    | Suspicious | Contradictory signals — do not proceed       |
| N/A    | Unknown    | No manufacturer matched                      |

---

## 2. Building a Recipe

A recipe captures the diff between a stock and a modified ECU binary. It is the
portable, human-readable representation of a tune.

### `ECUDiffAnalyzer`

```python
from openremap.core.services.recipe_builder import ECUDiffAnalyzer

with open("stock.bin", "rb") as f:
    original = f.read()

with open("modified.bin", "rb") as f:
    modified = f.read()

analyzer = ECUDiffAnalyzer(
    original_data=original,
    modified_data=modified,
    original_filename="stock.bin",
    modified_filename="modified.bin",
    context_size=32,          # bytes of context captured around each change
)

recipe = analyzer.build_recipe()
```

`build_recipe()` calls `find_changes()` and `identify_ecu()` internally. The
returned `recipe` dict is ready to be serialised, stored, or passed directly
to the validation and patching pipeline.

**Saving the recipe:**

```python
import json

with open("tune.remap", "w") as f:
    json.dump(recipe, f, indent=2)
```

**Inspecting the diff stats:**

```python
analyzer.find_changes()
stats = analyzer.compute_stats()

print(stats["total_changes"])        # 79
print(stats["total_bytes_changed"])  # 7828
print(stats["percentage_changed"])   # 0.1866
print(stats["largest_change_size"])  # 1024
```

**Recipe shape (summary):**

```python
{
    "openremap": { "type": "recipe", "schema_version": "4.0" },
    "metadata":  { "original_file": ..., "modified_file": ..., ... },
    "ecu":       { "manufacturer": ..., "match_key": ..., "ecu_family": ..., ... },
    "statistics": { ... },
    "instructions": [
        {
            "offset":     3145728,          # absolute byte offset (int)
            "offset_hex": "300000",
            "size":       4,
            "ob":         "0A141E28",        # original bytes (hex)
            "mb":         "0F1E2D3C",        # modified bytes (hex)
            "ctx":        "DEADBEEF...",     # context anchor before the change
            "description": "4 bytes at 0x300000 modified"
        },
        ...
    ]
}
```

---

## 3. Validating Before Patching

Always validate before patching. The strict validator checks that every
instruction's original bytes (`ob`) are present at the exact recorded offset
in the target binary.

### `ECUStrictValidator`

```python
import json
from openremap.core.services.validate_strict import ECUStrictValidator

with open("target.bin", "rb") as f:
    target_data = f.read()

with open("tune.remap") as f:
    recipe = json.load(f)

validator = ECUStrictValidator(
    target_data=target_data,
    recipe=recipe,
    target_name="target.bin",
    recipe_name="tune.remap",
)

# Optional pre-flight checks (informational — never fatal on their own)
size_warning = validator.check_file_size()
key_warning  = validator.check_match_key()

if size_warning:
    print(f"WARNING: {size_warning}")
if key_warning:
    print(f"WARNING: {key_warning}")

# Core validation
validator.validate_all()
passed, failed, score_pct = validator.score()

print(f"Validation: {passed}/{passed + failed} passed ({score_pct:.1f}%)")

if failed == 0:
    print("Safe to patch.")
else:
    print(f"{failed} instruction(s) failed — do not patch.")
    for r in validator.results:
        if not r.passed:
            print(f"  #{r.instruction_index:>3}  0x{r.offset_hex:<10}  {r.reason}")
```

**Getting a full report dict** (ready for a JSON API response or a UI):

```python
report = validator.to_dict()
# {
#   "target_file": "target.bin",
#   "recipe_file":  "tune.remap",
#   "target_md5":   "...",
#   "summary": {
#       "total": 79, "passed": 79, "failed": 0,
#       "score_pct": 100.0, "safe_to_patch": True
#   },
#   "failures": [],
#   "all_results": [...]
# }
```

---

## 4. Diagnosing Failures (Existence Validator)

When strict validation fails, the existence validator explains *why* — it
searches the entire binary for each `ob` pattern, not just at the recorded
offset. This distinguishes three cases:

| Status     | Meaning                                              |
|------------|------------------------------------------------------|
| `EXACT`    | Found at the recorded offset — validation should pass |
| `SHIFTED`  | Found but at a different offset — SW revision mismatch |
| `MISSING`  | Not found anywhere — wrong ECU model or already patched |

```python
from openremap.core.services.validate_exists import ECUExistenceValidator, MatchStatus

existence = ECUExistenceValidator(
    target_data=target_data,
    recipe=recipe,
    target_name="target.bin",
    recipe_name="tune.remap",
)

existence.validate_all()
exact, shifted, missing = existence.counts()
verdict = existence.verdict()
# "safe_exact" | "shifted_recoverable" | "missing_unrecoverable"

print(f"Exact: {exact}  Shifted: {shifted}  Missing: {missing}")
print(f"Verdict: {verdict}")

# Inspect shifted instructions — recipe may work with a SW revision update
for r in existence.results:
    if r.status == MatchStatus.SHIFTED:
        print(f"  #{r.instruction_index}  shift={r.shift:+d}  closest=0x{r.closest_offset:08X}")
    elif r.status == MatchStatus.MISSING:
        print(f"  #{r.instruction_index}  NOT FOUND — {r.reason}")
```

---

## 5. Applying the Patch

`ECUPatcher` runs strict validation internally before writing a single byte.
If validation passes, it applies every instruction and returns the patched bytes.

```python
from openremap.core.services.patcher import ECUPatcher, PatchStatus

patcher = ECUPatcher(
    target_data=target_data,
    recipe=recipe,
    target_name="target.bin",
    recipe_name="tune.remap",
    skip_validation=False,    # always validate unless you already did externally
)

# Optional: surface non-fatal warnings before committing
for warning in patcher.preflight_warnings():
    print(f"WARNING: {warning}")

try:
    patched_data = patcher.apply_all()
except ValueError as e:
    print(f"Patch failed: {e}")
    raise

# Write the result
with open("patched.bin", "wb") as f:
    f.write(patched_data)

total, success, failed = patcher.score()
print(f"Applied {success}/{total} instructions.")
```

**Getting the full patch report:**

```python
report = patcher.to_dict(patched_data=patched_data)
# {
#   "target_file": "target.bin",
#   "recipe_file":  "tune.remap",
#   "target_md5":   "...",
#   "summary": {
#       "total": 79, "success": 79, "failed": 0,
#       "shifted": 3,             ← instructions found at shifted offsets
#       "score_pct": 100.0,
#       "patch_applied": True,
#       "patched_md5": "..."
#   },
#   "results": [...]
# }
```

**Inspecting per-instruction results:**

```python
for r in patcher.results:
    status = r.status.value   # "success" | "failed"
    shift  = r.shift          # 0 = exact offset, non-zero = context-anchored shift
    print(f"  #{r.index:>3}  {status}  offset=0x{r.offset_expected:08X}  shift={shift:+d}")
```

---

## 6. Verifying After Patching

After writing the patched binary, run the post-patch validator to confirm that
every modified byte (`mb`) is now present at the expected offset.

```python
from openremap.core.services.validate_patched import ECUPatchedValidator

with open("patched.bin", "rb") as f:
    patched_data = f.read()

verifier = ECUPatchedValidator(
    patched_data=patched_data,
    recipe=recipe,
    patched_name="patched.bin",
    recipe_name="tune.remap",
)

verifier.verify_all()
passed, failed, score_pct = verifier.score()

if failed == 0:
    print(f"Patch confirmed — all {passed} instructions verified.")
else:
    print(f"Verification failed — {failed} instruction(s) not confirmed.")
    for r in verifier.results:
        if not r.passed:
            print(f"  #{r.instruction_index}  0x{r.offset_hex}  {r.reason}")
```

---

## 7. Working with the Manufacturer Registry

You can access the extractor registry directly — useful for building custom
scanners, batch processors, or UI components that need to list supported families.

```python
from openremap.core.manufacturers import get_extractors, EXTRACTORS

extractors = get_extractors()

print(f"{len(extractors)} extractors registered")

for ext in extractors:
    print(ext.__class__.__name__)
    # BoschEDC1Extractor
    # BoschEDC15Extractor
    # BoschEDC16Extractor
    # BoschEDC17Extractor
    # ... (18 Bosch + 6 Siemens + 4 Delphi + 4 Marelli)
```

**Checking if a binary is supported without full identification:**

```python
data = open("unknown.bin", "rb").read()

for extractor in get_extractors():
    if extractor.can_handle(data):
        print(f"Handled by: {extractor.__class__.__name__}")
        break
else:
    print("No matching extractor found.")
```

---

## 8. Error Handling

```python
# identify_ecu never raises — check for None fields instead
identity = identify_ecu(data)
if identity["manufacturer"] is None:
    # unrecognised binary — show error in UI, do not proceed to build recipe

# score_identity never raises
result = score_identity(identity)
if result.is_suspicious:
    # show warning — low confidence identification

# ECUStrictValidator.validate_all() never raises — check .score()
validator.validate_all()
_, failed, _ = validator.score()
if failed > 0:
    # validation failed — do not patch, show per-instruction breakdown

# ECUPatcher.apply_all() raises ValueError on:
#   - strict validation failure (pre-flight)
#   - any instruction failing to apply (pattern not found)
try:
    patched = patcher.apply_all()
except ValueError as e:
    # e contains a human-readable summary of every failed instruction
    print(str(e))
```

---

## 9. Full Pipeline Example

A complete end-to-end implementation — identify, build recipe, validate, patch,
verify.

```python
import json
from openremap.core.services.identifier      import identify_ecu
from openremap.core.services.confidence      import score_identity
from openremap.core.services.recipe_builder  import ECUDiffAnalyzer
from openremap.core.services.validate_strict import ECUStrictValidator
from openremap.core.services.validate_exists import ECUExistenceValidator
from openremap.core.services.patcher         import ECUPatcher
from openremap.core.services.validate_patched import ECUPatchedValidator


def build_recipe(stock_path: str, modified_path: str, out_path: str) -> dict:
    """Diff two binaries and save a recipe file."""
    original = open(stock_path,   "rb").read()
    modified = open(modified_path, "rb").read()

    analyzer = ECUDiffAnalyzer(
        original_data=original,
        modified_data=modified,
        original_filename=stock_path,
        modified_filename=modified_path,
    )
    recipe = analyzer.build_recipe()

    with open(out_path, "w") as f:
        json.dump(recipe, f, indent=2)

    stats = recipe["statistics"]
    print(f"Recipe built: {stats['total_changes']} instructions, "
          f"{stats['total_bytes_changed']} bytes changed "
          f"({stats['percentage_changed']}%)")
    return recipe


def apply_recipe(target_path: str, recipe_path: str, out_path: str) -> None:
    """Validate and apply a recipe to a target binary."""
    target_data = open(target_path, "rb").read()
    recipe      = json.load(open(recipe_path))

    # ── Step 1: Identify target ──────────────────────────────────────────
    identity = identify_ecu(target_data, filename=target_path)
    result   = score_identity(identity, filename=target_path)

    print(f"Identified: {identity['ecu_family']} / {identity['ecu_variant']}")
    print(f"Confidence: {result.tier} ({result.score})  —  {result.rationale_summary()}")

    if result.is_suspicious:
        raise ValueError(f"Identification confidence too low: {result.tier}")

    for warning in result.warnings:
        print(f"  WARNING: {warning}")

    # ── Step 2: Strict validation ────────────────────────────────────────
    validator = ECUStrictValidator(target_data, recipe, target_path, recipe_path)

    if w := validator.check_file_size():
        print(f"  WARNING: {w}")
    if w := validator.check_match_key():
        print(f"  WARNING: {w}")

    validator.validate_all()
    passed, failed, pct = validator.score()
    print(f"Strict validation: {passed}/{passed + failed} passed ({pct:.1f}%)")

    if failed > 0:
        # Diagnose with existence validator before giving up
        existence = ECUExistenceValidator(target_data, recipe, target_path, recipe_path)
        existence.validate_all()
        exact, shifted, missing = existence.counts()
        print(f"Existence scan — exact: {exact}  shifted: {shifted}  missing: {missing}")
        print(f"Verdict: {existence.verdict()}")
        raise ValueError(f"Strict validation failed: {failed} instruction(s) did not match.")

    # ── Step 3: Patch ────────────────────────────────────────────────────
    patcher = ECUPatcher(
        target_data=target_data,
        recipe=recipe,
        target_name=target_path,
        recipe_name=recipe_path,
        skip_validation=True,   # already validated above
    )

    for warning in patcher.preflight_warnings():
        print(f"  WARNING: {warning}")

    patched_data = patcher.apply_all()   # raises ValueError if any instruction fails
    total, success, _ = patcher.score()
    print(f"Patch applied: {success}/{total} instructions.")

    with open(out_path, "wb") as f:
        f.write(patched_data)

    # ── Step 4: Post-patch verification ──────────────────────────────────
    verifier = ECUPatchedValidator(patched_data, recipe, out_path, recipe_path)
    verifier.verify_all()
    passed, failed, pct = verifier.score()

    if failed > 0:
        raise ValueError(f"Post-patch verification failed: {failed} instruction(s) not confirmed.")

    print(f"Verification passed — {passed}/{passed} instructions confirmed.")
    print(f"Output written to: {out_path}")


# ── Usage ─────────────────────────────────────────────────────────────────────

# Build a recipe from a stock/modified pair
recipe = build_recipe("stock.bin", "modified.bin", "tune.remap")

# Apply the recipe to a target binary
apply_recipe("target.bin", "tune.remap", "target_patched.bin")
```

---

## 10. Using via CLI (subprocess)

If you only need a thin integration — calling openremap from a shell script or
spawning it as a subprocess — every pipeline stage is available as a CLI command.

```bash
# Identify a binary
openremap identify ecu.bin

# Scan a folder
openremap scan ./bins/ --dest ./sorted/

# Build a recipe from a diff
openremap cook stock.bin modified.bin --out tune.remap

# Validate a binary against a recipe
openremap validate target.bin tune.remap

# Apply a recipe
openremap tune target.bin tune.remap --out patched.bin
```

**From Python via subprocess:**

```python
import subprocess
import json

result = subprocess.run(
    ["openremap", "identify", "ecu.bin", "--json"],
    capture_output=True,
    text=True,
    check=True,
)
identity = json.loads(result.stdout)
```

---

## Summary

| Task                        | Class / function           | Key method          |
|-----------------------------|----------------------------|---------------------|
| Identify a binary           | `identify_ecu()`           | —                   |
| Score identification        | `score_identity()`         | —                   |
| Build a recipe from diff    | `ECUDiffAnalyzer`          | `.build_recipe()`   |
| Validate before patching    | `ECUStrictValidator`       | `.validate_all()`   |
| Diagnose validation failure | `ECUExistenceValidator`    | `.validate_all()`   |
| Apply a recipe              | `ECUPatcher`               | `.apply_all()`      |
| Verify after patching       | `ECUPatchedValidator`      | `.verify_all()`     |
| List registered extractors  | `get_extractors()`         | —                   |