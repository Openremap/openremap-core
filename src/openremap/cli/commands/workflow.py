"""
openremap workflow

Prints a complete, plain-English step-by-step guide to the full patching
workflow — from organising a binary collection all the way to verifying the
patched file before flashing.

Designed for users who are new to OpenRemap or to the terminal.

Examples:
    openremap workflow
"""

from __future__ import annotations

import typer

# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------

_WIDTH = 73  # separator line width (fits comfortably in an 80-column terminal)

# ---------------------------------------------------------------------------
# Low-level formatting helpers
# ---------------------------------------------------------------------------


def _sep() -> None:
    """Print a full-width dim separator line."""
    typer.echo(typer.style("  " + "─" * _WIDTH, dim=True))


def _blank() -> None:
    """Print a blank line."""
    typer.echo("")


def _body(*lines: str) -> None:
    """Print one or more plain body lines with two-space indent."""
    for line in lines:
        typer.echo(f"  {line}")


def _cmd(*commands: str) -> None:
    """
    Print one or more example commands in bold green, each indented by four
    spaces. A blank line is printed after the block so the following
    'What to look for' label stands out visually.
    """
    for command in commands:
        typer.echo("    " + typer.style(command, fg=typer.colors.GREEN, bold=True))
    _blank()


def _ok(text: str) -> None:
    """Print a green ✓ success hint."""
    typer.echo("    " + typer.style("✓  ", fg=typer.colors.GREEN, bold=True) + text)


def _fail(text: str) -> None:
    """Print a red ✗ failure hint."""
    typer.echo("    " + typer.style("✗  ", fg=typer.colors.RED, bold=True) + text)


def _note(text: str) -> None:
    """Print a dim indented note — used under ✗ hints to elaborate."""
    typer.echo("       " + typer.style(text, dim=True))


# ---------------------------------------------------------------------------
# High-level section helpers
# ---------------------------------------------------------------------------


def _step(number: str, title: str, warning: bool = False) -> None:
    """
    Print a step header — blank line, separator, blank line, then the title.

    Args:
        number:  Step number string, e.g. "0", "1", "6".
        title:   Human-readable step title.
        warning: When True, renders the header in yellow instead of cyan
                 (used for the mandatory checksum step).
    """
    _blank()
    _sep()
    _blank()
    colour = typer.colors.YELLOW if warning else typer.colors.CYAN
    typer.echo(typer.style(f"  STEP {number} — {title}", fg=colour, bold=True))
    _blank()


def _what_to_look_for() -> None:
    """Print the 'What to look for:' sub-header."""
    _body("What to look for:")


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


def workflow() -> None:
    """
    Print a complete step-by-step workflow guide.

    Walks through every stage from organising a binary collection through to
    verifying a patched file — with plain-English explanations of what each
    command does, what to look for in the output, and what to do when
    something goes wrong.

    Designed for users who are new to OpenRemap or to the terminal.
    Run  openremap <command> --help  at any time for the full options of any
    individual command.
    Run  openremap commands  for a compact one-line-per-command cheat-sheet.
    """

    # ── Header ───────────────────────────────────────────────────────────────
    _blank()
    typer.echo(typer.style("  OpenRemap — Workflow Guide", bold=True))
    _sep()
    _body(
        "A complete walkthrough from raw binary to verified patched file.",
        "Run  openremap <command> --help  at any time for full options.",
        "Run  openremap commands           for a compact command cheat-sheet.",
        "Run  openremap families           to see every supported ECU family.",
    )
    _sep()

    # ── STEP 0 — Scan / organise a collection (optional) ─────────────────────
    _step("0", "Organise a collection  (optional — skip if you have your files ready)")

    _body(
        "What:  Sort a folder of ECU binaries by manufacturer and family.",
        "       Each file is classified and moved into a sub-folder like",
        "       scanned/Bosch/EDC17/ so you can find the right one easily.",
        "",
        "Why:   If you collected binaries from multiple sources and they are",
        "       all in one flat folder, this step tidies them up before you",
        "       start working on any individual file.",
        "",
        "Tip:   Not sure if your ECU is supported? Run  openremap families",
        "       to see every supported family with era, size, and vehicle notes.",
        "       Use  openremap families --family EDC16  for full detail on one.",
    )
    _blank()
    _cmd(
        "openremap families                           # list all supported ECU families",
        "openremap families --family EDC16            # detail for one family",
        "openremap scan ./my_bins/                    # preview — nothing moves",
        "openremap scan ./my_bins/ --move --organize  # sort into Bosch/EDC17/ etc.",
    )
    _what_to_look_for()
    _ok("Files in  scanned/<Manufacturer>/<Family>/  are fully identified and ready.")
    _ok("Files in  sw_missing/  were identified by family but not by calibration.")
    _note("Inspect them with  openremap identify <file>  before using them.")
    _fail("Files in  contested/  matched more than one extractor — investigate.")
    _note("Run  openremap identify <file>  and check which result looks correct.")
    _fail("Files in  unknown/  are not supported yet or are not ECU binaries.")
    _note("Run  openremap families  to check if the ECU family is supported.")

    # ── STEP 1 — Identify ─────────────────────────────────────────────────────
    _step("1", "Identify your stock binary")

    _body(
        "What:  Read the binary and extract manufacturer, ECU family,",
        "       software version, hardware number, calibration ID, and",
        "       the match key that uniquely identifies this file.",
        "",
        "Why:   Confirms the file is a supported ECU and gives you the",
        "       information you need before touching anything.",
    )
    _blank()
    _cmd("openremap identify stock.bin")
    _what_to_look_for()
    _ok("Manufacturer, ECU Family, and Match Key are all filled in.")
    _ok("Software Version is present — it is the primary matching key.")
    _fail('Any field showing "unknown" — the ECU family may not be supported yet.')
    _note("Open an issue or check CONTRIBUTING.md to add support for it.")
    _fail("File reads as empty or the command errors — check the path and extension.")
    _note("Only .bin and .ori files are accepted.")

    # ── STEP 2 — Cook ─────────────────────────────────────────────────────────
    _step("2", "Cook a recipe")

    _body(
        "What:  Compare your stock (unmodified) binary and a tuned binary.",
        "       Every changed byte block is recorded — its offset, original",
        "       bytes (ob), new bytes (mb), and a context anchor (ctx).",
        "       The result is saved as a JSON recipe file.",
        "",
        "Why:   The recipe is a portable, human-readable record of exactly",
        "       what the tune changes. You can inspect it, share it, and",
        "       replay it on any matching ECU.",
    )
    _blank()
    _cmd("openremap cook stock.bin stage1.bin --output recipe.json")
    _what_to_look_for()
    _ok('"Recipe built successfully" with an instruction count greater than 0.')
    _ok("The ECU block shows the correct Manufacturer · Family and Match Key.")
    _fail("Zero instructions — the two files are identical.")
    _note("Check you passed the stock file first and the tuned file second.")
    _fail("A read error — check that both paths exist and end in .bin or .ori.")

    # ── STEP 3 — Validate strict ──────────────────────────────────────────────
    _step("3", "Apply the recipe  (validate → apply → verify in one shot)")

    _body(
        "What:  openremap tune runs three phases automatically:",
        "         Phase 1 — validate before : checks that the original bytes",
        "                   from the recipe are at their expected offsets.",
        "         Phase 2 — apply           : writes the tuned bytes with a",
        "                   ±2 KB anchor search for shifted maps.",
        "         Phase 3 — validate after  : confirms every tuned byte was",
        "                   written correctly.",
        "",
        "Why:   One command does the full safe workflow. The original file is",
        "       never modified — the tuned result is written separately.",
        "       Nothing is written unless all three phases pass.",
    )
    _blank()
    _cmd(
        "openremap tune target.bin recipe.json",
        "openremap tune target.bin recipe.json --output my_tuned.bin",
        "openremap tune target.bin recipe.json --report tune_report.json",
    )
    _what_to_look_for()
    _ok('"Tune complete" with all three phases green — file is ready for checksum.')
    _ok('"Shifted" count in Phase 2 — maps recovered via ±2 KB anchor search.')
    _note("Verify the shifted instructions carefully before flashing.")
    _fail("Phase 1 fails — target does not match the recipe.")
    _note("Run the command below to diagnose why:")
    _note("  openremap validate check target.bin recipe.json")
    _note("")
    _note("  EXACT    → bytes at exact offsets (unusual — re-check the file).")
    _note("  SHIFTED  → bytes at a different offset (different SW revision).")
    _note("             tune may still recover them via its ±2 KB anchor search.")
    _note("  MISSING  → bytes not found anywhere. This is the wrong ECU.")
    _fail('"match_key mismatch" warning — the target is a different SW version.')
    _note("Run  openremap validate check  and review the verdict before continuing.")
    _fail("Phase 2 or Phase 3 fails — do not flash the output binary.")
    _note("Run  openremap validate check target.bin recipe.json  to diagnose.")

    # ── STEP 4 — Validate individually (advanced / when tune fails) ───────────
    _step("4", "Validate individually  (advanced — only when Step 3 fails)")

    _body(
        "What:  The three validate sub-commands let you run each phase of",
        "       openremap tune individually for detailed diagnostics.",
        "",
        "       validate before  — same as Phase 1 of tune (pre-flight check).",
        "       validate check   — whole-binary search; run when before fails.",
        "       validate after   — same as Phase 3 of tune (post-tune confirm).",
        "",
        "Why:   Use these when you need to inspect a specific phase in isolation,",
        "       save an individual JSON report, or diagnose a failure.",
    )
    _blank()
    _cmd(
        "openremap validate before target.bin recipe.json",
        "openremap validate check  target.bin recipe.json",
        "openremap validate after  target_tuned.bin recipe.json",
        "openremap validate after  target_tuned.bin recipe.json --json --output verify.json",
    )
    _what_to_look_for()
    _ok('"Safe to tune" from validate before — Phase 1 would pass inside tune.')
    _ok('"Tune confirmed" from validate after — every byte written correctly.')
    _fail('"MISSING" verdict from validate check — this is the wrong ECU.')
    _fail('"SHIFTED" verdict from validate check — SW revision mismatch.')
    _note("tune will still attempt recovery via its ±2 KB anchor search.")

    # ── STEP 5 — Checksum (MANDATORY) ─────────────────────────────────────────
    _blank()
    _sep()
    _blank()
    typer.echo(
        typer.style(
            "  ⚠  STEP 5 — MANDATORY: correct checksums before flashing",
            fg=typer.colors.YELLOW,
            bold=True,
        )
    )
    _blank()
    _body(
        "OpenRemap does NOT calculate or correct ECU checksums.",
        "",
        "Before flashing any tuned binary to a vehicle you MUST run it",
        "through a dedicated checksum correction tool:",
        "",
        "    ECM Titanium  •  WinOLS  •  Checksum Fix Pro  •  or equivalent",
        "",
        "openremap tune Phase 3 (validate after) confirms the recipe was",
        "applied correctly. It does NOT replace a checksum tool.",
        "These are two different things.",
        "",
        "Flashing a tuned binary with an incorrect checksum WILL brick your ECU.",
        "No exceptions. No recovery without a bench flash or JTAG setup.",
    )

    # ── Footer ────────────────────────────────────────────────────────────────
    _blank()
    _sep()
    _body(
        "Quick reference:  openremap commands",
        "Full reference:   openremap <command> --help   or   docs/cli.md",
    )
    _sep()
    _blank()
