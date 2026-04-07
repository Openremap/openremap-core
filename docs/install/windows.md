# Installing OpenRemap on Windows

> Written for people who rarely or never use a terminal. Every step is one command — paste it and press Enter.

---

## What you are installing

**OpenRemap** is a terminal application with a full interactive interface (TUI). Once installed, just type `openremap` and everything is at your fingertips — no commands to memorise. A full CLI is also available for scripting and automation.

Two pieces of software are needed:

- **Python** — the programming language OpenRemap is written in. Free, from [python.org](https://www.python.org). You may already have it — Step 2 will check.
- **uv** — a free, open-source package manager made by [Astral](https://astral.sh). Think of it like an App Store for command-line tools: it downloads OpenRemap, installs it cleanly in its own isolated space, and puts the `openremap` command on your system so it works from any folder. Source code and documentation at [github.com/astral-sh/uv](https://github.com/astral-sh/uv).

> 💡 uv can manage Python on its own for running OpenRemap — but having Python installed on your system is good practice if you use it for anything else, and some users prefer `pip` over `uv`. This guide installs both.

Neither tool collects data or requires an account.

---

## Step 1 — Open PowerShell

Press the **Windows key**, type **PowerShell**, and click **Windows PowerShell** or **PowerShell** in the search results.

A blue or black window with a blinking cursor will appear. That is your terminal. All the commands below are typed (or pasted) there.

> 💡 **Tip:** You can paste into PowerShell with **right-click** (not Ctrl+V).

---

## Step 2 — Install Python

First, check whether Python is already installed:

```powershell
python --version
```

- If you see `Python 3.10` or higher — you are good. Skip to Step 3.
- If you see an older version, or `python: command not found` — install Python now.

### Option A — via winget (recommended, Windows 10 and later)

```powershell
winget install Python.Python.3
```

If winget asks you to agree to terms, press **Y** and Enter. When the installer finishes, Python is ready and on your PATH — no further action needed.

### Option B — download the installer from python.org

1. Go to [python.org/downloads](https://www.python.org/downloads/) and click the big **Download Python** button.
2. Run the downloaded `.exe` file.
3. On the first screen of the installer, tick **"Add Python to PATH"** before clicking Install.

> ⚠️ **The "Add Python to PATH" checkbox is easy to miss and hard to fix later.** Make sure it is ticked before you click anything else.

4. Click **Install Now** and wait for it to finish.
5. Click **Close**.

After installation, open a **new** PowerShell window and verify:

```powershell
python --version
```

You should see `Python 3.x.x`.

---

## Step 3 — Install uv

### Option A — via winget (recommended, Windows 10 and later)

`winget` is Microsoft's built-in package manager, available on Windows 10 (version 1809 or later) and all Windows 11 versions.

```powershell
winget install astral-sh.uv
```

If winget asks you to agree to terms, press **Y** and Enter.

### Option B — direct installer (if winget is not available)

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

This downloads and runs the official uv installer from Astral's website — the same installer linked from [the uv GitHub page](https://github.com/astral-sh/uv#installation).

> ⚠️ If PowerShell says *"running scripts is disabled"*, run this first, then retry:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

---

## Step 4 — Close PowerShell and open it again

**This step is important.** After installing uv, Windows needs a fresh terminal session to find the new command. Close the PowerShell window and open a new one (Windows key → PowerShell).

Verify both tools are ready:

```powershell
python --version
uv --version
```

You should see a version number for each. If either says `command not found`, see [Troubleshooting](#troubleshooting) below.

---

## Step 5 — Install OpenRemap

```powershell
uv tool install openremap
```

uv downloads OpenRemap from [PyPI](https://pypi.org/project/openremap/) — Python's official public package index — and installs it into an isolated environment. Nothing else on your system is affected.

---

## Step 6 — Verify it worked

```powershell
openremap --version
```

You should see the version number printed. Then try:

```powershell
openremap --help
```

If both commands work, you are done. `openremap` is now permanently available from any folder on your system, in any terminal, without any activation step.

---

## Your first command

```powershell
openremap
```

This launches the full interactive interface — identify files, scan folders, cook recipes, and apply tunes, all from one screen. No commands to memorise.

Prefer the command line? Run `openremap workflow` for a plain-English walkthrough of all available CLI commands.

---

## Updating

When a new version is released:

```powershell
uv tool upgrade openremap
```

---

## Uninstalling

```powershell
uv tool uninstall openremap
```

The command is removed from your system. Nothing else is affected.

---

## Troubleshooting

### `python: command not found` after installing Python

The installer did not add Python to your PATH. This usually means the **"Add Python to PATH"** checkbox was not ticked during installation.

The quickest fix is to uninstall Python and reinstall it — this time making sure the checkbox is ticked. To uninstall: press the Windows key, search **Add or remove programs**, find Python in the list, and click Uninstall. Then repeat Option B of Step 2.

Alternatively, add Python to PATH manually:
1. Press the Windows key → search **Environment Variables** → click **Edit the system environment variables**
2. Click **Environment Variables**
3. Under **User variables**, find **Path**, click **Edit**
4. Click **New** and add the path to your Python installation, typically:
   - `C:\Users\<YourName>\AppData\Local\Programs\Python\Python3x\`
   - `C:\Users\<YourName>\AppData\Local\Programs\Python\Python3x\Scripts\`
5. Click OK, close all dialogs, open a new terminal

### `openremap: command not found` after installation

uv installs tools into `%APPDATA%\Local\uv\bin`. This folder must be on your system PATH.

Open a **new** PowerShell window and check:

```powershell
$env:PATH -split ';' | Select-String 'uv'
```

If nothing appears, the uv installer did not add itself to your PATH automatically. Run the Option B installer again — it sets the PATH via the system environment variables dialog.

If it still does not work, add the folder manually:
1. Press Windows key → search **Environment Variables** → click **Edit the system environment variables**
2. Click **Environment Variables**
3. Under **User variables**, find **Path**, click **Edit**
4. Click **New** and add: `%APPDATA%\Local\uv\bin`
5. Click OK, close all dialogs, open a new terminal

### `running scripts is disabled`

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Run this once, then retry the uv installer.

### `winget: command not found`

`winget` requires Windows 10 version 1809 or later. If you are on an older version, use the Option B installers for both Python and uv, or update Windows first.

### `uv tool install` fails with a network error

Check your internet connection. If you are behind a corporate proxy or firewall, ask your IT department to allow access to `pypi.org` and `astral.sh`.

---

← [Back to README](../../README.md)