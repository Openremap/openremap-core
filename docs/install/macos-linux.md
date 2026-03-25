# Installing OpenRemap on macOS / Linux

---

## What you are installing

**OpenRemap** is a command-line tool — you run it by typing short commands in a terminal.

One piece of software is needed first:

- **uv** — a free, open-source package manager made by [Astral](https://astral.sh). Think of it as a clean App Store for command-line tools: it downloads OpenRemap, installs it in an isolated space, and puts the `openremap` command on your PATH so it works from any folder. Nothing else on your system is touched. Source and documentation at [github.com/astral-sh/uv](https://github.com/astral-sh/uv).

Python does **not** need to be installed separately — uv manages its own Python installation automatically.

---

## Step 1 — Open a terminal

**macOS:** press **⌘ Space**, type **Terminal**, press Enter.

**Linux:** depends on your desktop environment — look for **Terminal**, **Konsole**, or **GNOME Terminal** in your application menu, or press **Ctrl+Alt+T** on most distributions.

---

## Step 2 — Install uv

### macOS

```bash
brew install uv
```

Don't have Homebrew? Install it first from [brew.sh](https://brew.sh) (one command, free, widely used), or use the curl installer below.

### macOS / Linux (curl installer)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

This runs the official uv installer from [astral.sh](https://astral.sh/uv/install.sh) — the same one linked on [the uv GitHub page](https://github.com/astral-sh/uv#installation). The script downloads the correct uv binary for your platform, puts it in `~/.local/bin`, and adds that folder to your shell's PATH.

### Linux — package managers

Many Linux distributions package uv directly:

```bash
# Arch / Manjaro
pacman -S uv

# Nix
nix-env -iA nixpkgs.uv
```

For all other distributions, use the curl installer above.

---

## Step 3 — Reload your shell

After installing uv for the first time, reload your shell so the new PATH entry takes effect:

```bash
source ~/.bashrc      # bash
source ~/.zshrc       # zsh (macOS default since Catalina)
source ~/.config/fish/config.fish   # fish
```

Or just close the terminal and open a new one.

Verify uv is ready:

```bash
uv --version
```

You should see something like `uv 0.x.x`.

---

## Step 4 — Install OpenRemap

```bash
uv tool install openremap
```

uv downloads OpenRemap from [PyPI](https://pypi.org/project/openremap/) — Python's official public package index — into an isolated environment. Nothing else on your system is affected.

---

## Step 5 — Verify it worked

```bash
openremap --version
openremap --help
```

Both commands should work from any directory. If `openremap` is not found, see [Troubleshooting](#troubleshooting) below.

---

## Your first command

```bash
openremap workflow
```

This prints a complete plain-English walkthrough — what each step does, the exact commands to type, and what to look for at each stage. Start here.

---

## Shell completion (optional but recommended)

Tab-complete command names and flags without reading the docs:

```bash
openremap --install-completion
```

Restart your terminal. Then:

```bash
openremap i<Tab>          # → openremap identify
openremap scan --<Tab>    # → shows all --flags
```

Supported: bash, zsh, fish.

---

## Updating

```bash
uv tool upgrade openremap
```

---

## Uninstalling

```bash
uv tool uninstall openremap
```

---

## Prefer plain pip?

If you already have Python and prefer not to use uv:

```bash
pip install openremap
```

`pip` is Python's built-in package installer — it comes with every Python installation. Note that pip does not isolate tools from each other, so if you have many Python tools installed, version conflicts are possible. `uv tool install` avoids this entirely.

---

## Troubleshooting

### `openremap: command not found` after `uv tool install`

uv installs tools into `~/.local/bin`. This directory must be on your PATH.

Check:

```bash
echo $PATH | tr ':' '\n' | grep -i local
```

If `~/.local/bin` is missing, add it to your shell profile:

```bash
# bash — add to ~/.bashrc or ~/.bash_profile
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# zsh — add to ~/.zshrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# fish
fish_add_path ~/.local/bin
```

### `uv: command not found`

The uv installer ran but the PATH was not updated in the current session. Run `source ~/.bashrc` (or equivalent for your shell), or open a new terminal.

### `Permission denied` during install

Do not use `sudo` with uv. If you see a permission error:

```bash
sudo chown -R $USER ~/.local
```

Then retry the install without `sudo`.

### macOS: `curl: (60) SSL certificate problem`

Your system certificates may be out of date. Update macOS (System Settings → General → Software Update), then retry.

---

← [Back to README](../../README.md)