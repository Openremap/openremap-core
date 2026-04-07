# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.3] — 2026-04-07

Flat package layout, Python 3.10 minimum compatibility, README and docs refresh,
TUI syntax fix, and test reliability fix.

### Changed — Package Layout

- **Flat package layout** — source tree moved from `src/openremap/` to `openremap/`
  (standard flat layout). Build target in `pyproject.toml` updated accordingly
  (`packages = ["openremap"]`). No public API changes.

### Changed — Python Compatibility

- **Minimum Python lowered from 3.14 to 3.10** — the codebase uses no Python 3.11+
  features; the prior floor was unnecessarily restrictive. `pyproject.toml`
  `requires-python` set to `>=3.10`; classifiers expanded to cover 3.10–3.14.
- All documentation, badges, and install guides updated to reflect `>=3.10`:
  `README.md`, `CONTRIBUTING.md`, `docs/install/developers.md`,
  `docs/install/windows.md`, `docs/integration.md`, `docs/setup.md`.

### Fixed — TUI (`openremap/tui/app.py`)

- **Python 2-style multi-exception syntax** — 8 occurrences of `except A, B:`
  replaced with the correct Python 3 form `except (A, B):`. This caused a
  `SyntaxError` on any Python < 3.14 when the TUI module was imported.

### Fixed — Test Suite (`tests/cli/test_cli_main.py`)

- **`TestMainBlock::test_main_block_invokes_app` hanging** — the test exec'd
  `cli/main.py` with `__name__ == "__main__"`. When pytest is invoked with no
  extra arguments, `sys.argv` has length 1, causing `main()` to take the TUI
  branch and hang indefinitely. Fixed by pinning `sys.argv` to
  `["openremap", "--help"]` inside the test so the CLI branch is always exercised.

### Changed — README

- Rewrote introduction to emphasise the library-first design; added a Python code
  example showing the public API (`identify_ecu`, `score_identity`, `ECUPatcher`).
- Added `openremap.com` website link and integration guide cross-reference.
- Updated all GitHub badge and link URLs from `Pinelo92/openremap` to
  `Openremap/openremap-core`.

### Changed — Documentation

- CHANGELOG comparison links updated from `Pinelo92/openremap` to
  `Openremap/openremap-core`.

### Tests

- 4,763 tests passing — all green on Python 3.10.

---

## [0.4.2] — 2026-04-03

EDC16 hardware-number extraction fix, evidence-based detection system,
confidence scoring reframed as identification quality, and documentation
consistency pass.

### Fixed — EDC16 Extractor

- **Hardware number extraction** — `_resolve_hardware_number()` was too narrow (only searched the calibration area for `0281xxxxxx`). BMW EDC16C31/C35 and some VAG PD bins store the HW number in the boot sector or active header and were missed entirely. The method now searches five regions in priority order: active header → calibration area → extended active window → boot sector → full-binary fallback. Supports spaced/dotted variants (`0.281.xxx.xxx`) with normalisation.
- **OEM part number extraction** — new `_resolve_oem_part_number()` method extracts vehicle-manufacturer part numbers (VAG format `03G906016J`, BMW format `12 14 7 626 350`). Previously hardcoded to `None`.
- **`ecu_family` vs `ecu_variant` classify bug** — `ecu_family` was set to the variant string (e.g. `EDC16C8`) instead of the canonical `EDC16`, causing `--organize` to create a folder per variant instead of a single `scanned/Bosch/EDC16/` directory. Now `ecu_family` is always `"EDC16"`; the specific sub-variant is stored only in `ecu_variant`.

### Added — Evidence-Based Detection

- **Evidence tag system** in `BaseManufacturerExtractor` — 16 standard evidence-tag constants across three categories: structural (`SIZE_MATCH`, `MAGIC_MATCH`, `HEADER_MATCH`, `POINTER_TABLE`, `LAYOUT_FINGERPRINT`, `BOOT_BLOCK`), identity (`FAMILY_STRING`, `DETECTION_SIGNATURE`, `IDENT_BLOCK`, `FAMILY_ANCHOR`), and cross-check (`EXCLUSION_CLEAR`, `FILL_PATTERN`, `SYNC_MARKER`, `MANUFACTURER_CONFIRM`).
- **`DetectionResult` dataclass** — rich return type wrapping `matched: bool` and `evidence: Tuple[str, ...]` for future migration of `can_handle()`.
- **Instance plumbing** — `_last_evidence` attribute, `_set_evidence()` helper, and `last_detection_evidence` property on the base class.
- **`detection_evidence` field** added to the identity dict in `identifier.py` — the service reads evidence tags after `can_handle()` and passes them through to the result.
- **Scan CLI** now injects `detection_evidence` and `detection_strength` from the extractor instance into the identity dict before scoring, ensuring evidence-based scoring works in batch mode.

### Changed — Confidence Scoring

- **Reframed as identification quality** — the score measures how reliably the system detected and extracted identity fields, **not** whether the binary content is unmodified. A tuned file with intact ident blocks scores identically to a stock file. All docstrings, CLI help text, and documentation updated to reflect this.
- **`DetectionStrength` enum deprecated** — retained as a fallback for extractors not yet upgraded to evidence tags; marked with `.. deprecated::` docstring.
- No scoring weights or tier thresholds were changed.

### Changed — Documentation

- `confidence.md` rewritten around the identification framing; tier descriptions, signal explanations, and filename-penalty rationale all updated.
- `about.md` — added "Learn more" cross-reference section linking to CLI ref, recipe format, confidence, contributing, and disclaimer.
- `commands/identify.md` — tier descriptions aligned with new confidence framing; added "See also" section.
- `commands/cook.md` — `validate strict` → `validate before`; added "See also" links.
- `commands/families.md` — `CONTRIBUTING.md` plain text → proper markdown link.
- `recipe-format.md` — added "See also" section and back-navigation link.
- `bosch-internals.md` — tier thresholds updated (Medium 25–54, Low 0–24, Suspicious < 0); added link to `confidence.md`.

### Tests

- 4,751 tests passing (up from 4,734 in 0.4.1).
- **18 new EDC16 test methods** across two new test classes: `TestExtractHardwareNumberExpanded` (11 tests — active header, boot region, mirror region, petrol format, spaced/dotted normalisation, region priority, 2 MB extended window) and `TestExtractOemPartNumber` (6 tests — absent OEM, key presence, VAG detection, suffix letters, space normalisation, type checking).

---

## [0.4.1] — 2026-04-02

Siemens, Delphi, and Magneti Marelli manufacturer support; Bosch ME1.5.5;
manufacturer-aware confidence scoring; README rewrite; `.remap` recipe
extension; TUI-first documentation.

### Added — Manufacturers

- **Siemens extractors** (6 families): Simtec 56, SIMOS 2.x/3.x, PPD1.x, SID 801/801A, SID 803/803A, EMS2000. Full detection cascades with manufacturer-aware confidence scoring.
- **Delphi extractors** (2 families): Multec (diesel, Motorola 68k), Multec S (petrol, HCS12). Opel/Vauxhall coverage.
- **Magneti Marelli extractors** (4 families): IAW 1AV, IAW 1AP, IAW 4LV, MJD 6JF. Fiat/PSA/GM coverage including byte-swapped M68K architectures.
- **Bosch ME1.5.5** — Opel Astra-G/Corsa-C petrol (ZZ ident + `/ME1.5.5/` family token).
- **Manufacturer documentation** — new docs for Siemens (`siemens.md`, `siemens-internals.md`), Delphi (`delphi.md`), and Marelli (`marelli.md`). Bosch docs updated with ME1.5.5 and Mono-Motronic entries.

### Changed — Confidence Scoring

- Manufacturer-aware canonical SW version patterns — each manufacturer (Bosch, Delphi, Siemens, Marelli) now has its own regex for the +30 canonical SW bonus.
- Family field profiles — ECU families that architecturally lack certain identity fields (e.g. IAW 1AP has no SW/HW) are never penalised for their absence.
- Detection strength baselines — extractors self-declare STRONG/MODERATE/WEAK, setting a +15/+10/+5 baseline before field scoring.
- HIGH tier threshold adjusted to ≥55 (was ≥60).

### Changed — Documentation

- README rewritten with problem/solution framing, coverage table, dedicated confidence and recipe sections, inline install commands, and "What it does NOT do" section.
- Recipe file extension updated from `.openremap` to `.remap` across all docs.
- TUI promoted as primary interface in install and setup guides; CLI documented as scripting alternative.
- All command docs updated with `.remap` extension and TUI-first guidance.

### Changed — Extractors (base)

- `BaseManufacturerExtractor` updated with `detection_strength` enum and `match_key_fallback_field` support.
- All existing Bosch extractors updated to declare `detection_strength` and integrate with the reworked confidence scorer.

### Tests

- 4,734 tests passing (up from 3,880 in 0.4.0).
- New test suites for all Siemens extractors (Simtec 56, SIMOS, PPD, SID 801, SID 803, EMS2000).
- Confidence scoring tests updated for manufacturer-aware and family-profile logic.

---

## [0.4.0] — 2026-04-01

Terminal User Interface, smart entry-point dispatch, scan improvements,
new Bosch M4.x / MP9 extractors, and extractor hardening across the board.

### Added — TUI

- **Full Textual-based Terminal UI** (`openremap.tui`) with seven panels:
  Identify, Scan, Cook, Tune, Validate, Families, About — all backed by the
  real engine (no logic duplication).
- **Smart entry point** — bare `openremap` launches the TUI; any argument
  (`--help`, `--version`, subcommands) falls through to the CLI unchanged.
  `openremap-tui` remains as an explicit alternative.
- **Native file/folder pickers** — zenity/kdialog (Linux), osascript (macOS),
  tkinter (Windows); cross-platform save dialog.
- **Default workspace** — `~/Documents/OpenRemap/` (Linux fallback `~/OpenRemap/`)
  with `recipes/`, `tunes/`, `ECUs/` sub-folders; outputs auto-populate there.
- **Scan → Organise workflow** — scan results table with category column
  (scanned, review, contested, unknown, unsupported), then one-click
  ORGANISE into `OpenRemap/ECUs/` with two modes:
  - *By Manufacturer* — `ECUs/<Manufacturer>/`
  - *Detailed* — `ECUs/<Manufacturer>/<Family>/`
  - Special folders: `Review` (sw_missing), `Contested`, `Unknown`, `Unsupported`.
- **Compact scan layout** — scan + organise controls share a single action row;
  mode toggles and ORGANISE button sit inline with SCAN/Browse; the results
  table fills all remaining vertical space.
- **Tune checksum warning** — prominent boxed yellow warning shown above
  phase details after a successful tune.

### Added — Extractors

- **Bosch M4.x** — Volvo 850/960/S70/V70/S60/S80 petrol (M4.3 64 KB, M4.4
  128 KB). DAMOS token + sequential ident digit detection; `calibration_id`
  match-key fallback. 203 tests.
- **Bosch MP9** — 64 KB petrol (Motorola 68HC11). `MOTRONIC MP 9` label
  detection. 125 tests.
- **EDC15C3 Format C** — Volvo diesel calibration-ID extraction from structured
  ident block at `0x7EC10`; `calibration_id` match-key fallback. 37 tests.

### Fixed

- **M5.x** — accept non-`D` revision codes (`V04`, etc.) in ident block.
- **EDC16** — 512 KB half-flash dump support.
- **ME7** — tightened `MOTRONIC` detection (prevents MP9/M1.5.4/M3.8.x false
  positives); tolerate space separator in HW+SW combined block; accept `1277`
  SW prefix (Italian-market ME7.3).
- **EDC3x** — split-ROM chip detection (HI/LO 128 KB paired chips).
- **TUI scan** — case-insensitive extension matching (`.BIN`/`.ORI` accepted);
  files with unsupported extensions are now collected, shown in the results
  table, and organised into `ECUs/Unsupported/` instead of being left behind.

### Tests

- 3,880 tests passing (up from 842 in 0.3.0).

---

## [0.3.1] — 2026-03-27

Patch release with two main areas of work: extractor correctness for Opel,
PSA/Citroën, and Porsche binaries discovered during a corpus audit; and a
rework of the CLI commands including two new commands (`commands`, `families`),
renamed `validate` sub-commands, and a rebuilt one-shot `tune` workflow.

### Fixed

#### M1.x extractor (`bosch/m1x/extractor.py`)

- **PSA MP3.2 mis-identification** — added `b"0000000M3"` to `EXCLUSION_SIGNATURES`.

  Citroën ZX 2.0 16V (HW `0261200218`) and any other PSA vehicle using the
  Bosch MP3.2 ECU were being returned as `family=M1.x` instead of `family=MP3.2`.

  Root cause: the M1.x fallback path (Phase 2c — Opel-style ident) decoded the
  reversed-digit string embedded in the MP3.2 family marker block
  (`...0000000M3.X`) and validated the `0261`/`1267` prefixes, claiming the file
  before `BoschM3xExtractor` could run. The M3.x markers `1350000M3` (M3.1) and
  `1530000M3` (M3.3) were already excluded; the PSA-specific `0000000M3` marker
  was missing from the exclusion list.

- **Opel M2.x capture** — added `b'"0000000M2'` to `EXCLUSION_SIGNATURES`.

  Opel Calibra 2.0T M2.7 (HW `0261203014`) was being claimed by the M1.x
  fallback instead of `BoschM2xExtractor`. The M2.x family marker now causes
  immediate rejection.

#### ME7 extractor (`bosch/me7/extractor.py`, `bosch/me7/patterns.py`)

- **Porsche 964 Carrera 2 false positive** — added Phase 0 minimum size gate
  (`len(data) < 0x10000` → reject).

  The 32 KB Porsche 964 Carrera 2 binary (M2.x, HW `0261200473`) was accepted by
  `BoschME7Extractor.can_handle()` because Phase 2 scans the full binary for
  `b"MOTRONIC"` with no size guard, and the M2.x Porsche ident block contains
  that string. ME7 then extracted `hw=None, sw=None, match_key=None`, a silent
  data loss if the extractor order ever changed or the extractor was queried
  directly.

  The ME7 ZZ ident block is anchored at offset `0x10000`; no genuine ME7 binary
  can be smaller than 64 KB. The size gate is placed before Phase 2 (string
  signature scan) so all pre-ME7 legacy binaries (M1.x 32 KB, M2.x 32 KB,
  M3.x 32 KB, KE-Jetronic ≤ 32 KB) are rejected unconditionally.

- **ME7.6.2 support** — extended family detection to search the full binary for
  ME7 family signatures.

  Large ME7 variants (Opel Corsa D, 832 KB) store the family identifier past the
  512 KB mark. The previous 512 KB search bound caused `family=None` on these
  bins.  Added `ME7.6.2` to `supported_families` and to `FAMILY_RESOLUTION_ORDER`.

- **Magneti Marelli ZZ false positive** — tightened the Phase 3 ZZ anchor check.

  Magneti Marelli ME1.5.5 ECUs place a `ZZ` block at `0x10000` in the format
  `ZZ43/1/ME1.5.5/...`, where the third byte is a printable ASCII digit (`0x34`).
  All genuine ME7 variants use a non-printable byte at that position (`\xff`,
  `\x00`, or `\x01`). The guard `not (0x20 <= byte3 <= 0x7E)` now rejects the
  Marelli format while accepting all known ME7 sub-variants.

#### EDC3x extractor (`bosch/edc3x/extractor.py`)

- **Opel 256 KB doubled-char ident corruption** — `IDENT_PATTERN_OPEL_256` now
  accepts both sentinels (`\x55\xaa` and `\xaa\x55`).

  The Opel Astra 2.0 DTI (HW `0281001874`) ident was decoded as `0077770`
  (corrupted) because the `\xaa\x55` sentinel variant was not matched. Added the
  alternative sentinel and reordered parsing to try Format 4 (doubled-char)
  before Format 3 (plain-text) to prevent Format 3 from misreading doubled bytes.

#### EDC17 extractor (`bosch/edc17/extractor.py`)

- **Magneti Marelli false positive** — added explicit rejection of the Magneti
  Marelli `ZZ`-printable variant at `0x10000` (`ZZ` followed by a printable byte).

- **ME7 family strings false positive** — added a guard to reject files containing
  ME7 family strings (`ME7.`, `ME71`, `ME731`, `MOTRONIC`) so `BoschExtractor`
  (EDC17) does not accidentally claim ME7 binaries when the ZZ block offset check
  coincidentally passes.

### Changed

#### Documentation (`core/docs/manufacturers/bosch.md`)

- **M3.x table entry** — updated to cover all sub-families: M3.1, M3.3 (BMW) and
  MP3.2, MP3.x-PSA, MP7.2 (PSA/Citroën). Previous text listed only BMW E30/E36.
  Added reversed-digit ident encoding description and file size range (up to 256 KB
  for MP7.2).

- **ME7 table entry** — updated file size range from `128 KB – 512 KB` to
  `128 KB – 1 MB` to reflect ME7.6.2 (Opel Corsa D, 832 KB). Added ME7.6.2 and
  ME7.5.5 to the sub-family list. Added note about the 64 KB minimum size floor.

- **M1.x table entry** — expanded to mention Opel petrol ECUs and BMW M1.7 fallback
  path (no header magic, identified by reversed-digit ident).

- **Motronic Legacy table entry** — corrected file size range from `16 KB – 64 KB`
  to `2 KB – 32 KB` and expanded the vehicle/sub-family list (DME-3.2, M1.x-early,
  KE-Jetronic, EZK).

- **Confidence scoring note** — M3.x added alongside M2.x as a family that
  produces the `+15` (non-`1037` SW) signal; this is expected and not a defect.

- **Opel/GM notes table** — added Opel Corsa D ME7.6.2 row.

- **PSA/Citroën notes section** — new section documenting MP3.2 / MP7.2 /
  MP3.x-PSA identification details, the shared reversed-digit ident encoding,
  and the role of `0000000M3` as the definitive discriminator vs M1.x.

- **Extractor directory tree** — updated inline comments for `m1x/`, `m3x/`,
  `me7/`, and `motronic_legacy/` to reflect actual vehicle and sub-family coverage.

### Internal

- All 842 unit tests pass with zero regressions after each individual fix.
- Full scan of 430-file Bosch binary corpus after all fixes: 409 OK, 0 unknown,
  0 SW mismatches, 1 known HW filename typo (Opel Kadet `0261200186` filename vs
  `0261200185` in binary — pre-existing, not introduced by this release).

---

### Additional extractor fixes — 2026-03-27

Second round of extractor corrections discovered during a corpus re-scan.

#### EDC16 extractor (`bosch/edc16/extractor.py`, `bosch/edc16/patterns.py`)

- **BMW EDC16C31/C35 2 MB binaries mis-labelled as generic `EDC16`** — fixed
  `_resolve_ecu_variant()` to search the active-section neighbourhood in addition
  to the last 256 KB of the binary.

  BMW diesel ECUs using EDC16C31/C35 in 2 MB images (E46/E60/E87/E90 320d, 520d,
  120d, X6 30sd) store their slash-delimited family string
  (`EDC16C31/999/X000/...`) near the 0xC0000 mirror section (~offset `0x0C06F3`).
  This is outside the `slice(-0x40000, None)` last-256 KB window used by the
  previous implementation, so the extractor returned `ecu_variant=None` and fell
  back to the generic label `EDC16`.

  Fix: added **Priority 2b** to `_resolve_ecu_variant()` — after failing the
  last-256 KB search the method now searches `data[active_start : active_start +
  0x100000]` (1 MB window from the detected active start), wide enough to reach
  the C31/C35 family string for all known BMW layouts. A final **Priority 3**
  full-file bare-token scan is added as a last-resort fallback so no file returns
  `None` when the string is at an atypical offset.

  Affected variants now correctly resolved: `EDC16C31` (E46 320d, E60 520d,
  E87 120d, E90 318d, E53 X3) and `EDC16CP35` (E60 335d, X6 30sd).

- **BMW E46 320D early 1 MB layout missing from `ACTIVE_STARTS_BY_SIZE`** —
  spurious SW number `10373618301974` caused by absent layout entry.

  The BMW E46 320D M47TU (2003–2005, 1 MB, HW `0281010565`) places its active
  calibration section at `0x020000` (DECAFE at `0x2003D`), not at the standard
  `0x040000` used by all other 1 MB EDC16 variants. Because `0x20000` was absent
  from `ACTIVE_STARTS_BY_SIZE[0x100000]`, `_detect_active_start()` returned
  `None`. The SW resolver then fell back to the greedy cal-area regex
  `1037[\dA-Fa-f]{6,10}`, which matched `10373618301974` — SW `1037361830`
  followed immediately in flash by the literal digits `1974` — producing a
  14-character false SW and the wrong match key `EDC16C31::10373618301974`.

  Fix: added `0x20000` to `ACTIVE_STARTS_BY_SIZE[0x100000]` and `0x2003D` to
  `MAGIC_OFFSETS_BY_SIZE[0x100000]`. Active-start detection now confirms DECAFE at
  `0x2003D` and reads SW `1037361830` from `0x20010` via the strict 6-character
  pattern in `_read_sw_at()`.

- **`supported_families` expanded** — added `EDC16C31`, `EDC16C35`, `EDC16C36`,
  `EDC16CP33`, `EDC16CP34`, `EDC16CP35` so that these variants are returned as
  first-class family labels rather than undeclared strings.

---

### Opel/PSA extractor additions and further fixes — 2026-03-27

Third round of extractor work, extending coverage to Opel petrol/diesel families
and PSA sector-dump formats discovered during a full corpus re-scan.

**Added**

#### M1.55 extractor (`bosch/m1x55/extractor.py`)

- **Opel M1.5.5 support** — new variant detected via `b"M1.5.5"` signature and
  extracted via a dedicated `_parse_opel_m155_ident()` method.

  Opel Corsa C / Astra G petrol ECUs (e.g. HW `0261204058`, `90532609`) use
  the Bosch Motronic 1.5.5 hardware platform but write a different family token
  (`M1.5.5` at `~0x0D82F`) and store HW + SW in a GM-style ident block near
  `0xD801` (`"<sw8> <prefix2><hw10><checksum><variant>  <build>"`), rather than
  the Alfa M1.55 slash-delimited descriptor at `0x8005`.

  Detection: `Phase 3` now accepts `b"M1.55"` (first 64 KB, Alfa path) **or**
  `b"M1.5.5"` anywhere in the binary (Opel path). Extraction dispatches on the
  `is_opel` flag: Opel bins call `_parse_opel_m155_ident()` while Alfa bins
  continue to use the existing `_parse_hw_sw()` / `_parse_descriptor()` path.

  `supported_families` expanded to include `"M1.5.5"`.

#### M2.x extractor (`bosch/m2x/extractor.py`)

- **Opel M2.8/M2.81 support — Format C** (`0xFF`-padded ident block).

  Opel Astra GSi C20XE (M2.8, HW `0261203017`), Opel Calibra V6 (M2.8, HW
  `0261203080`), and Opel Omega 3.0 V6 (M2.81, HW `0261203589`) store HW and
  SW as plain ASCII decimal strings delimited by spaces inside a `0xFF`-padded
  region near the end of ROM:
  `b'\xff{3+} <HW_10> <SW_10> ...'`.
  No OEM part number is present in this format.

- **Opel M2.7 support — Format D** (reversed-string ident, 32 KB bins).

  Opel Calibra 2.0T (M2.7, HW `0261203014`, SW `1267357220`) stores the ident
  with each 10-digit number reversed character-by-character, prefixed by the
  two-byte marker `dx`:
  `b'dx4103021620022753762121132409JP'`
  → `hw = group1[::-1]`, `sw = group2[::-1]`.
  Reversed values are validated against expected `0261`/`1267`/`2227` prefixes.

- **DAMOS-style family fallback for M2.81** — when the primary marker regex
  (`b"0000000M2"` family suffix) contains a non-digit byte (e.g. `0x71 = 'q'`)
  the extractor now falls back to a `/M2.<digits>/` DAMOS ident scan and returns
  `M2.8` (first digit only) to normalise sub-variants.

  `supported_families` expanded to include `"M2.7"`, `"M2.8"`, `"M2.81"`.

#### EDC3x extractor (`bosch/edc3x/extractor.py`)

- **Opel calibration block — Format 3** (`IDENT_PATTERN_OPEL`, 128 KB split-ROM
  chips).

  Opel diesel ECUs using split-ROM chip pairs (e.g. HW `0281001634` LLL/HHH
  chips, `001632h`/`001632l` from BDM reads) embed a 7-digit calibration number
  anchored by a `0xFF` run or `0xAA` byte followed by the ASCII `U` (0x55)
  sentinel:

  ```
  \xff{4+}U <SW_code_1-2> <cal_7digits>   (LLL / LO-chip)
  \xaaU?    <SW_code_1-2> <cal_7digits>   (HHH / HI-chip)
  ```

  Pattern: `rb"(?:\xff{4,}U|\xaaU?)([A-Z]{1,2})(\d{7})"`.
  `HW` is recovered by scanning the whole binary for `b"0281\d{6}"`.

- **Phase 6 detection for Opel 256 KB bins** — `can_handle()` now accepts
  256 KB files with a `TSW` marker in the `0xBFC0–0xC040` region (Opel
  pre-EDC15 toolchain), in addition to the existing Phase 5 `0xC3`-fill ratio
  check. This prevents the `TSW`-at-`0x7FC0–0x8060` guard (which rejects
  EDC15 Format-A bins) from also rejecting valid Opel EDC3 256 KB files.

#### ME7 extractor (`bosch/me7/extractor.py`)

- **PSA ME7 calibration sector — 64 KB (Phase 4)**.

  Standalone 64 KB calibration-sector extracts from PSA (Peugeot–Citroën) ME7
  ECUs (e.g. Peugeot 206 1.6i 16v, HW `0261206942`, SW `1037353507`) where
  only the sector normally at `0x10000` in a full dump is captured. These files
  begin with the ZZ marker at offset `0x0` (instead of `0x10000`) and contain
  the `\xC8`-prefixed HW + SW ident block.

  Fingerprint: size = 64 KB **and** `ZZ` at offset 0 with non-printable third
  byte **and** `\xC8(0261\d{6})\x00(1037\d{6})` anywhere in the file.

  Extraction uses the existing production path — the `hw_sw_combined` pattern
  in the extended region already covers the full 64 KB file.

- **PSA ME7.4.x calibration sector — 256 KB (Phase 5 + `_extract_psa_sector_256kb()`)**.

  Calibration-only sector dumps from Bosch ME7.4.x PSA-variant ECUs (e.g.
  Peugeot 207 THP 1.6 150HP, SW `1037394738`) where no ZZ block, no MOTRONIC
  label, and no HW number are present. SW is stored as plain ASCII at the fixed
  offset `0x1A`, preceded by the two-byte record marker `\x02\x00` at `0x18`.

  Fingerprint: size = 256 KB **and** `\x02\x00` at `0x18` **and** `1037\d{6}`
  at `0x1A`. Dispatched before the early-ME7 path. Returns
  `ecu_family="ME7"`, `hardware_number=None`, `software_version` from `0x1A`.

#### EDC16 extractor (`bosch/edc16/extractor.py`, `bosch/edc16/patterns.py`)

- **EDC16C9 support — Opel Vectra-C / Signum / Astra-H** (1 MB, active section
  at `0xC0000`).

  Opel/GM common-rail ECUs (e.g. HW `0281013409`, SW `1037A50286`) place their
  active section at `0xC0000` with DECAFE at `0xC003D`. The SW suffix may
  contain uppercase hex digits A–F (`"1037A50286"`) — this is an Opel-specific
  alphanumeric SW numbering scheme.

  - `ACTIVE_STARTS_BY_SIZE[0x100000]` extended with `0xC0000` as the C9 candidate.
  - `MAGIC_OFFSETS_BY_SIZE[0x100000]` extended with `0xC003D`.
  - SW pattern updated from `rb"1037\d{6}"` to `rb"103[79][\dA-Fa-f]{6}"` to
    accept both standard numeric and alphanumeric suffixes.
  - New `_resolve_hardware_number()` scans the last 256 KB for
    `rb"(?<!\d)(0281\d{6})(?!\d)"` — Opel bins embed the HW number as a
    null-terminated ASCII string in the calibration data area.

- **PSA `1039` SW prefix support** — `_detect_active_start()` and `_read_sw_at()`
  now accept the `1039` prefix (PSA/Peugeot-Citroën EDC16C34 variant, e.g.
  Peugeot 3008 1.6 HDI SW `1039398238`) alongside the standard `1037` prefix.
  SW pattern updated to `rb"103[79][\dA-Fa-f]{6}"`.

- **Non-standard-size raw active-section dumps accepted** — Phase 2 of
  `can_handle()` now skips the strict size rejection when DECAFE is present at
  `0x3D` (indicating a raw sector dump whose size fell outside `SUPPORTED_SIZES`
  due to extra appended data or a non-standard read length). `_detect_active_start()`
  falls back to `active_start = 0x0` for unrecognised sizes.

- `supported_families` further expanded with `"EDC16C9"` and `"EDC16C34"`.

#### Confidence scoring (`tuning/services/confidence.py`)

- **`1039` prefix treated as canonical** — the `+40` SW confidence bonus
  previously gated on `sw.startswith("1037")` now also fires for `"1039"`-prefixed
  SW versions (`sw.startswith(("1037", "1039"))`). PSA EDC16C34 bins that carry
  a `1039`-prefixed SW therefore reach the same confidence tier as equivalent
  `1037`-prefix bins.

#### Scanner CLI (`cli/commands/scan.py`)

- **Zero-byte files routed to `trash`** — an explicit size check before the
  classify loop short-circuits empty files directly to the `DEST_TRASH` bucket
  (with a `"(empty file)"` label in the report row), rather than feeding them
  to every extractor and reporting `UNKNOWN`. This covers stub files created by
  failed archive extraction (e.g. password-protected RAR entries).

**Fixed**

#### M3.x extractor (`bosch/m3x/extractor.py`)

- **Layout B fallback for early MP3.1 PSA bins** (e.g. Peugeot 106 1.4, HW
  `0261200203`).

  In early PSA bins the 20-digit ident run is stored at a fixed file offset
  separated from the `0000000M3` marker by non-ASCII opcode bytes. The backward
  walk from the marker stops at the first non-digit byte (`0x22 = '"'`), yielding
  only the 7 zeros embedded in the marker — fewer than the 20 required. Previously
  this caused `_extract_psa()` to return `hw=None, sw=None`.

  Fix: when `len(digit_run) < 20` after the backward walk, the extractor now
  scans the whole binary for runs of **exactly** 20 consecutive ASCII digits
  (not preceded or followed by another digit), decodes `hw = digits[0:10][::-1]`
  and `sw = digits[10:20][::-1]`, and accepts the first run where `hw` starts
  with `"0261"` and `sw` starts with `"1267"` or `"2227"`.

#### ME7 extractor (`bosch/me7/extractor.py`)

- **Extraction-level full-file fallback for large/atypical binaries** — after
  `_run_patterns()` completes, if both `hw_sw_combined` and `hardware_number`
  hits are absent the extractor retries those two patterns across the full binary
  (Step 2b). This is the extraction-side complement to the detection-level
  full-binary search already added for ME7.6.2, and ensures large binaries
  (e.g. Opel Corsa D 832 KB) return correct `hw`, `sw`, and `ecu_family` values
  even when the ident block sits beyond the normal extended search window.

#### EDC3x extractor (`bosch/edc3x/extractor.py`)

- **Format 4 parser — back-reference de-doubling validation** — `IDENT_PATTERN_OPEL_256`
  was updated from a simple sentinel + digit capture to a full back-reference
  regex that enforces the doubled-char encoding per position:
  `([A-Z])\1 ([A-Z0-9])\2 ([A-Z0-9])\3 ...` (8 groups, one per ident character).
  This prevents `IDENT_PATTERN_OPEL` (Format 3) from accidentally matching the
  raw doubled bytes before Format 4 can run, which previously returned a
  corrupted SW such as `"0077770"` instead of the correct de-doubled `"0770173"`.
  Format 4 is now tried **before** Format 3 in the extraction dispatch for all
  files where VAG and BMW parsers find nothing.

**Internal**

- All 842 unit tests pass with zero regressions after these additions.
- Full corpus re-scan (511 files): 511 SCANNED, 0 unknown, 0 SW missing,
  0 contested.
- New verified corpus entries:
  - `0281001634 LLL/HHH` → EDC3 Format 3, `sw=0770164`
  - `0261204058` Opel Corsa 1.0 12V → M1.5.5, `sw=90532609`
  - `0261203014` Opel Calibra 2.0T → M2.7 Format D, `sw=1267357220`
  - `0261203080` Opel Calibra V6 → M2.8 Format C, `sw=1267358003`
  - `0261203589` Opel Omega 3.0 V6 → M2.81 DAMOS fallback, `sw=1267358933`
  - Peugeot 206 1.6i 16v sector dumps → ME7 Phase 4 (64 KB PSA sector)
  - Peugeot 207 THP 1.6 150HP → ME7 Phase 5 (256 KB PSA sector), `sw=1037394738`
  - `0281013409` Opel Vectra CDTI 120PS → EDC16C9, `hw=0281013409`, `sw=1037A50286`

---

### CLI rework — 2026-03-27

#### New commands

- **`openremap commands`** (`cli/commands/cmds.py`) — compact one-line-per-command
  cheat-sheet for returning users. Replaces the need to memorise syntax.
- **`openremap families`** (`cli/commands/families.py`) — list every supported ECU
  family with era, typical file size, and vehicle notes. Accepts `--family <NAME>`
  (short `-f`) to show full detail for a single family including sub-variants,
  fingerprint method, SW/HW format, representative vehicles, and notes.

#### Changed commands

- **`openremap tune`** (`cli/commands/tune.py`) — rebuilt as a true one-shot
  three-phase command: Phase 1 (validate before) → Phase 2 (apply) → Phase 3
  (validate after). The original target is never modified; the tuned binary is
  written only when all three phases pass. Adds `--skip-validation` escape hatch
  for scripted pipelines, `--report` for a combined JSON report of all three
  phases, and `--json` for machine-readable output.
- **`openremap validate`** (`cli/commands/validate.py`) — sub-commands renamed for
  clarity. Old names kept as hidden deprecated aliases with a yellow rename notice:
  - `validate strict` → **`validate before`** (pre-flight ob-byte check)
  - `validate exists` → **`validate check`** (whole-binary diagnostic search)
  - `validate tuned`  → **`validate after`** (post-tune mb-byte confirmation)
- **`openremap identify`** (`cli/commands/identify.py`) — non-`.bin`/`.ori`
  extensions now emit a warning and continue rather than exiting with an error,
  matching actual field use where `.rom` and other extensions appear.
- **`openremap workflow`** (`cli/commands/workflow.py`) — step structure updated to
  reflect the consolidated `tune` command: Step 3 is now the one-shot
  validate→apply→verify flow; Step 4 covers individual `validate` sub-commands for
  advanced diagnostics; the mandatory checksum step is now Step 5.

#### Removed

- `cli/commands/patch.py` — superseded by the reworked `openremap tune` command,
  which now covers the full validate-apply-verify lifecycle in one shot.

#### Documentation

- `docs/commands/commands.md` — corrected cook cheat-sheet example (`r.json` →
  `recipe.json`) to match the actual `cmds.py` string.
- `docs/commands/identify.md` — corrected Notes section: unrecognised extensions
  print a warning and proceed; they do not exit with an error.
- `docs/commands/workflow.md` — "What it covers" table updated to match the new
  step structure (Steps 0–5; Step 3 is the one-shot `tune`, Step 4 is individual
  `validate` for diagnostics, ⚠ Step 5 is the mandatory checksum step).
- `docs/confidence.md` — new standalone reference for the confidence scoring
  system: tiers, signals table, warnings table, score-to-tier mapping, and
  manufacturer-agnostic design note.
- `README.md` — reworked intro (offline/local/CLI callout, tighter feature
  descriptions); CLI Quickstart updated to the new command set; Confidence
  Scoring section replaced with a two-sentence summary linking to
  `docs/confidence.md`.
- `docs/cli.md` — `docs/confidence.md` added to the Other documentation table.

---

## [0.3.0] — 2026-02-14

Initial public release of the `openremap` core library.

### Added

- ECU binary identifier service (`identify_ecu`) with extractor registry.
- Bosch extractor suite: EDC1, EDC3x, EDC15, EDC16, EDC17/MEDC17/MED17/ME17,
  ME7, ME9, M1.x, M1.55, M2.x, M3.x, M5.x, LH-Jetronic, Motronic Legacy.
- CLI commands: `identify`, `scan`, `tune`, `cook`, `validate`.
- Recipe format v1 with diff-based patch application and strict/lenient validation.
- Confidence scoring system for identification results.
- Full test suite (842 tests).

---

[0.4.3]: https://github.com/Openremap/openremap-core/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/Openremap/openremap-core/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Openremap/openremap-core/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Openremap/openremap-core/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Openremap/openremap-core/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Openremap/openremap-core/releases/tag/v0.3.0