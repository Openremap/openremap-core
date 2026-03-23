# Contributing to OpenRemap

First off, thank you for taking the time to contribute. This project is designed from the ground up to be extended — especially by people who have hands-on experience with ECU families that are not yet supported.

Every part of the codebase that matters for contributors is covered below.

---

## 🛡️ Contributor Safety Notice

**Please read this before contributing anything.** To keep OpenRemap sustainable, legally sound, and trustworthy as an open-source project, all contributors must follow these rules.

### No Binary Distribution

Never upload, attach, or link to ECU binary files (`.bin`, `.ori`, `.kp`, `.ols`) in pull requests, issues, or any other part of this repository. ECU firmware is proprietary intellectual property. Do not add any binary files to this repository.

### Original Heuristics Only

All extraction patterns, byte sequences, and regex logic you contribute must be the result of your own independent research or derived from publicly available documentation. Do not copy detection logic, offsets, or patterns from other tools without verifying they are openly licensed.

### No Reverse-Engineered Commercial Logic

Do not submit code, offsets, or algorithms that have been reverse-engineered from commercial or closed-source tuning software (WinOLS, ECM Titanium, Alientech, KESS, and similar). If you are unsure whether your source is acceptable, open an issue and ask before submitting.

### No Damos or A2L Derived Logic

Damos (`.dam`) and A2L files are proprietary Bosch calibration data formats that describe the exact memory layout, addresses, and scaling of ECU parameters. They are not publicly available and are covered by strict NDAs and licensing agreements.

All extraction patterns, byte offsets, and detection logic contributed to this project must be derived from **your own independent analysis of binary files** — not from Damos, A2L, or any other proprietary calibration data source. If anyone asks, and they may, your patterns came from staring at hex dumps, not from a calibration file someone emailed you.

This is not a technicality. Submitting logic derived from proprietary calibration data exposes both you and the project to serious intellectual property claims.

### Research Focus — No Emissions Delete Tools

This project is strictly for research and educational purposes. Pull requests that implement or enable the bypassing of emissions systems, DPF/EGR delete functionality, or any other modification that is illegal under environmental regulations will not be accepted.

### Independent Verification Reminder

Any output produced by this tool — recipes, patched binaries, or identification results — must be verified by a qualified professional and run through a standalone checksum corrector before being flashed to any vehicle. If your contribution changes patch behaviour or output format, update the documentation accordingly.

---

## Table of Contents

- [🛡️ Contributor Safety Notice](#️-contributor-safety-notice)
- [Ways to Contribute](#ways-to-contribute)
- [Getting the Project Running Locally](#getting-the-project-running-locally)
- [The Most Valuable Contribution: Adding a New ECU Extractor](#the-most-valuable-contribution-adding-a-new-ecu-extractor)
- [Other Contributions](#other-contributions)
- [Code Style](#code-style)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting a Bug or Wrong Identification](#reporting-a-bug-or-wrong-identification)
- [A Note on ECU Binary Files](#a-note-on-ecu-binary-files)

---

## Ways to Contribute

| Type | Examples |
|---|---|
| **New extractor** | Add support for Siemens SID, Delphi DCM, Marelli MJD, Denso, Continental |
| **Improve an existing extractor** | Fix a wrong pattern, handle an edge-case variant, improve the match key |
| **Bug fix** | Fix a crash, a wrong identification result, a validation logic error |
| **Tests** | Write `pytest` tests for any extractor or service |
| **Documentation** | Improve the README, add docstrings, fix typos |
| **Recipe format** | Propose and implement improvements to the recipe JSON structure |

---

## Getting the Project Running Locally

### Prerequisites

- Python 3.14+
- [uv](https://github.com/astral-sh/uv)

### Steps

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/your-username/openremap.git
cd openremap

# 2. Install all dependencies
uv sync

# 3. Run the test suite to confirm everything works
uv run pytest
```

That's all that is needed to work on the engine and CLI. No server, no database, no environment file required.

---

## The Most Valuable Contribution: Adding a New ECU Extractor

This is the single most impactful thing you can contribute. The entire pipeline — identification, recipe building, validation, patching — is manufacturer-agnostic. Adding a new extractor makes all of it work for a new family automatically.

### How the extractor system works

Every extractor lives in `src/openremap/tuning/manufacturers/<brand>/<family>/extractor.py` and subclasses `BaseManufacturerExtractor`. When a binary is submitted, the registry calls `can_handle()` on each extractor in priority order and delegates all extraction to the first one that returns `True`.

The base class (`src/openremap/tuning/manufacturers/base.py`) is well-documented. Read it before you start — it explains `can_handle()`, `extract()`, `build_match_key()`, and the opt-in fallback mechanism in detail.

### Step-by-step guide

**1. Create the package directory**

```
src/openremap/tuning/manufacturers/<brand>/<family>/
├── __init__.py      (empty)
├── extractor.py     (your implementation)
└── patterns.py      (regex patterns and search regions — optional but recommended)
```

For example, a Siemens SID206 extractor would live at:
```
src/openremap/tuning/manufacturers/siemens/sid206/extractor.py
```

**2. Implement the extractor**

```python
from openremap.tuning.manufacturers.base import BaseManufacturerExtractor
from typing import Dict, List

class SiemensSID206Extractor(BaseManufacturerExtractor):

    @property
    def name(self) -> str:
        return "Siemens"

    @property
    def supported_families(self) -> List[str]:
        return ["SID206"]

    def can_handle(self, data: bytes) -> bool:
        # Fast, bounded check only — this is called on every binary.
        # Scan only the first few KB unless you have a strong reason not to.
        # Return True if you are confident this binary belongs to your family.
        return b"SID206" in data[:0x10000]

    def extract(self, data: bytes, filename: str = "unknown.bin") -> Dict:
        # Return a dict compatible with ECUIdentitySchema.
        # Required: file_size, md5, sha256_first_64kb
        # Optional but valuable: manufacturer, ecu_family, ecu_variant,
        #   software_version, hardware_number, calibration_id, match_key
        import hashlib
        return {
            "manufacturer": self.name,
            "file_size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256_first_64kb": hashlib.sha256(data[:0x10000]).hexdigest(),
            "ecu_family": "SID206",
            "ecu_variant": None,
            "software_version": None,   # extract from binary
            "hardware_number": None,    # extract from binary
            "calibration_id": None,     # extract from binary
            "match_key": self.build_match_key(
                ecu_family="SID206",
                software_version=None,  # pass what you extracted
            ),
        }
```

**3. Register your extractor in the brand `__init__.py`**

If the brand already exists (e.g. Bosch), open `src/openremap/tuning/manufacturers/bosch/__init__.py` and add your extractor to the `EXTRACTORS` list in the correct priority position (most specific first).

If it is a new brand, create `src/openremap/tuning/manufacturers/<brand>/__init__.py`:

```python
from openremap.tuning.manufacturers.siemens.sid206.extractor import SiemensSID206Extractor
from openremap.tuning.manufacturers.base import BaseManufacturerExtractor

EXTRACTORS: list[BaseManufacturerExtractor] = [
    SiemensSID206Extractor(),
]
```

**4. Register the brand in the top-level registry**

Open `src/openremap/tuning/manufacturers/__init__.py` and add your brand:

```python
from openremap.tuning.manufacturers import bosch, siemens  # add your brand here

EXTRACTORS: list[BaseManufacturerExtractor] = [
    *bosch.EXTRACTORS,
    *siemens.EXTRACTORS,   # add your brand here
]
```

**5. Verify it works**

Run the CLI against a binary of the target family and confirm the correct `manufacturer`, `ecu_family`, and `match_key` come back:

```bash
uv run openremap identify your_binary.bin
```

Then cook a recipe from a stock and a modified binary to verify the `ecu` block is populated correctly:

```bash
uv run openremap cook stock.bin modified.bin --output recipe.json
```

### Tips for writing a good `can_handle()`

- **Keep it fast.** `can_handle()` is called on every uploaded binary for every registered extractor. Scan bounded regions (`data[:0x10000]`) rather than the full file where possible.
- **Be exclusive, not just inclusive.** If your family shares signatures with another (e.g. both have a `b"Bosch"` string), add explicit guards to reject the other family's binaries. Look at `BoschExtractor.can_handle()` for a worked example of layered exclusion guards.
- **File size is a strong discriminator.** Many older ECU families have a fixed, known file size (32 KB, 64 KB, 256 KB, etc.). Use it as a fast pre-filter.

### Tips for writing a good `extract()`

- **Extract `software_version` if at all possible.** It is the primary component of `match_key`. Without it, recipe matching relies on the fallback field, which is less reliable.
- **Use `_run_all_patterns()` and `_search()` from the base class.** They handle region slicing, regex iteration, error suppression, and deduplication for you.
- **Separate patterns into `patterns.py`.** Keeping regex byte patterns in a dedicated file makes the extractor logic easier to read and the patterns easier to update independently.
- **Use `build_match_key()` from the base class.** Don't construct the key string manually — the base method normalises whitespace and handles the `ecu_variant` vs `ecu_family` priority for you.

---

## Other Contributions

### Fixing an existing extractor

If an extractor identifies a binary incorrectly (wrong family, wrong software version, wrong match key), please open an issue first describing the binary (file size, any visible ASCII strings near offset 0) and what the extractor returns vs. what it should return. If you can share the binary privately, that will speed things up significantly.

### Writing tests

Tests live in `tests/` and are run with `uv run pytest`. Good test targets:

- `ECUStrictValidator` — feed it a recipe and a matching vs. non-matching binary and assert the warnings and summary.
- `ECUDiffAnalyzer` — feed it two known binaries and assert the instruction count and a few specific offsets.
- Individual extractor `can_handle()` — assert it returns `True` for correct family bytes and `False` for bytes from other families.

New test files belong under:

```
tests/
├── conftest.py
├── tuning/
│   ├── test_validate_strict.py
│   ├── test_recipe_builder.py
│   └── manufacturers/
│       └── bosch/
│           └── test_edc17_extractor.py
```

Run tests with:

```bash
uv run pytest
```

---

## Code Style

- **Python 3.14+ type hints everywhere.** Use `str | None` rather than `Optional[str]` for new code.
- **Docstrings on all public methods.** Follow the style already present in `base.py` and the validator services — short summary line, then `Args:` / `Returns:` blocks where the function is non-trivial.
- **No bare `except`.** Catch specific exceptions or use `except Exception` with a comment explaining why.
- **No abbreviations in variable names** unless they are universally understood in the domain (`ob`, `mb`, `ctx`, `ecu`, `sw`).
- **Hex strings are always uppercase.** Use `.hex().upper()` and uppercase literals (`"AABBCCDD"`, not `"aabbccdd"`).

---

## Submitting a Pull Request

1. **Fork** the repository and create a branch from `master`:
   ```bash
   git checkout -b feat/siemens-sid206-extractor
   ```

2. **Make your changes.** Keep each PR focused on one thing — one extractor, one bug fix, one feature. Mixed PRs are harder to review and slower to merge.

3. **Test your changes** manually against at least one real binary of the target family, or write automated tests if you can.

4. **Write a clear PR description** that answers:
   - What does this PR do?
   - Which ECU families / binaries does it affect?
   - How did you test it?
   - Any known limitations or edge cases?

5. **Open the PR** against the `master` branch.

---

## Reporting a Bug or Wrong Identification

Open a GitHub Issue and include:

- The CLI command you ran or the endpoint you called
- The output you got
- What you expected instead
- The file size of the binary (do **not** attach the binary itself — see below)
- Any printable ASCII strings visible near the start of the file, if you are comfortable sharing them

For identification bugs, the file size and the first few readable strings from the binary header are usually enough to diagnose the problem without needing the file.

---

## A Note on ECU Binary Files

**Do not attach ECU binary files to issues or pull requests.**

ECU firmware is proprietary. The binaries contain intellectual property belonging to the ECU manufacturer (Bosch, Siemens, Delphi, etc.) and potentially the vehicle OEM. Distributing them publicly — even for debugging — is legally risky for you and for this project.

If you need to share a binary to reproduce a bug, do so privately (e.g. via a direct message to a maintainer) and only after confirming you are the legal owner of the data.

There are no binary files in this repository. All tests use synthetic in-memory data generated by the test helpers in `tests/conftest.py`.