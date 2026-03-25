# Developer Setup

For contributors, extractor authors, and anyone who wants to run OpenRemap from source, modify the code, or run the test suite.

---

## Prerequisites

| Tool | Required version | Check |
|---|---|---|
| Python | 3.14+ | `python --version` |
| uv | latest | `uv --version` |
| git | any | `git --version` |

### Install uv

uv manages the virtual environment, dependencies, and Python version automatically.

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
winget install astral-sh.uv
```

Full documentation: [docs.astral.sh/uv](https://docs.astral.sh/uv/)

### Install git

Download from [git-scm.com](https://git-scm.com/downloads) or use your system package manager.

---

## Clone and set up

```bash
git clone https://github.com/Pinelo92/openremap.git
cd openremap
uv sync
```

`uv sync` creates a virtual environment at `.venv/` inside the project folder, installs all dependencies, and pins them to the exact versions in `uv.lock`. It does not affect anything outside the project folder.

---

## Running commands

You have two options after `uv sync`.

### Option A — prefix with `uv run` (no activation needed)

```bash
uv run openremap identify ecu.bin
uv run openremap scan ./my_bins/
uv run pytest
```

`uv run` automatically activates the project environment for that single call. This works from anywhere inside the project folder and requires no setup step.

### Option B — activate the environment once per session

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (Command Prompt)
.venv\Scripts\activate.bat

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

After activation, the bare command works for the rest of the terminal session:

```bash
openremap identify ecu.bin
pytest
```

Run `deactivate` to leave the environment, or just close the terminal.

---

## Running the test suite

```bash
uv run pytest core/tests/ -q
```

All tests must pass before submitting a pull request. Expected output on a clean install:

```
842 passed in X.XXs
```

To run a specific test file:

```bash
uv run pytest core/tests/tuning/manufacturers/test_edc17_extractor.py -v
```

---

## Project structure

```
openremap/
├── core/
│   ├── src/openremap/
│   │   ├── cli/
│   │   │   └── commands/       ← identify.py, scan.py, cook.py, etc.
│   │   └── tuning/
│   │       ├── manufacturers/
│   │       │   └── bosch/      ← one sub-package per ECU family
│   │       └── services/       ← identifier.py, confidence.py, patcher.py, etc.
│   └── tests/
│       └── tuning/
│           └── manufacturers/  ← per-extractor test files
├── pyproject.toml
└── uv.lock
```

The most impactful contribution is adding a new ECU extractor — every new family added makes the full pipeline (identify, scan, recipe, validate, patch) work for that family automatically. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for a full step-by-step guide.

---

## Shell completion (development install)

```bash
uv run openremap --install-completion
```

Restart your terminal after running this.

---

## Updating dependencies

```bash
git pull
uv sync
```

`uv sync` installs any new or changed dependencies automatically.

---

## Publishing a release

Releases are built and published from the `api/` workspace root (not from `core/` directly):

```bash
cd api
uv build
uv publish
```

Artifacts appear in `api/dist/`.

---

← [Back to README](../../README.md)