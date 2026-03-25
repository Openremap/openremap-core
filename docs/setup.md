# Setup Reference

Full installation guides by platform:

- 🪟 [Windows](install/windows.md)
- 🍎 / 🐧 [macOS / Linux](install/macos-linux.md)
- 🛠️ [Developers / contributors](install/developers.md)

---

## Shell completion

Tab-complete command names and flags without reading the docs.

```bash
openremap --install-completion
```

Restart your terminal after running this. Then:

```bash
openremap i<Tab>          # → openremap identify
openremap scan --<Tab>    # → shows all --flags
```

Supported shells: bash, zsh, fish, PowerShell.

If installed via `uv tool install`, run the completion install once and it persists permanently. If installed via `uv sync` (development), run it inside the project:

```bash
uv run openremap --install-completion
```

---

## Updating

```bash
# uv tool install
uv tool upgrade openremap

# pip
pip install --upgrade openremap

# development clone
git pull && uv sync
```

---

## Uninstalling

```bash
# uv tool install
uv tool uninstall openremap

# pip
pip uninstall openremap
```

For a development clone, delete the project folder — the virtual environment is self-contained inside `.venv/`.

---

## Verifying the install

Run these three commands in order. All three must succeed.

```bash
openremap --version    # prints the version number
openremap workflow     # prints the step-by-step guide without errors
openremap scan .       # dry-run scan of the current folder, nothing moves
```

---

## Troubleshooting

### `openremap: command not found` after `uv tool install`

uv installs tools into a platform-specific directory that must be on your PATH:

| Platform | Directory |
|---|---|
| Linux / macOS | `~/.local/bin` |
| Windows | `%APPDATA%\Local\uv\bin` |

**Linux / macOS** — add to your shell profile and reload:

```bash
# bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

# zsh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc

# fish
fish_add_path ~/.local/bin
```

**Windows** — open a new PowerShell window and run the uv installer again; it sets the PATH automatically. Or add `%APPDATA%\Local\uv\bin` to your user PATH manually via System Properties → Environment Variables.

---

### `openremap: command not found` after `uv sync`

Expected. After `uv sync` the command only exists inside the virtual environment, not on your global PATH. Use `uv run openremap` or activate the environment first:

```bash
source .venv/bin/activate      # macOS / Linux
.venv\Scripts\activate.bat     # Windows Command Prompt
.venv\Scripts\Activate.ps1     # Windows PowerShell
```

---

### `uv: command not found`

uv is not installed or not on your PATH. Follow the install guide for your platform:
[Windows](install/windows.md) · [macOS / Linux](install/macos-linux.md)

---

### `python: command not found` or wrong Python version

uv manages its own Python and does not depend on the system Python. Let uv install the required version:

```bash
uv python install 3.14
uv sync
```

---

### `Permission denied` on Linux / macOS

Do not use `sudo` with uv. Fix ownership of `~/.local` and retry without `sudo`:

```bash
sudo chown -R $USER ~/.local
uv tool install openremap
```

---

### Windows: `running scripts is disabled`

PowerShell's default execution policy blocks unsigned scripts. Run once:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then retry.

---

### Tests failing after `uv sync`

```bash
uv run pytest core/tests/ -q
```

The test suite must be fully green on a clean install. If tests fail immediately after cloning, open an issue with the full output.

---

## Quick-reference table

| Goal | Command |
|---|---|
| Install (uv) | `uv tool install openremap` |
| Install (pip) | `pip install openremap` |
| Check version | `openremap --version` |
| Update (uv) | `uv tool upgrade openremap` |
| Update (pip) | `pip install --upgrade openremap` |
| Uninstall (uv) | `uv tool uninstall openremap` |
| Install shell completion | `openremap --install-completion` |
| Clone for development | `git clone … && cd openremap && uv sync` |
| Run a command (dev) | `uv run openremap <command>` |
| Run tests | `uv run pytest core/tests/ -q` |

---

← [Back to README](../README.md)