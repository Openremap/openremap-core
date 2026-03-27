"""
openremap families

List all supported ECU families, or show expanded detail for one family.

Examples:
    openremap families
    openremap families --family EDC16
    openremap families --family ME7
"""

from __future__ import annotations

from typing import Optional

import typer

# ---------------------------------------------------------------------------
# Embedded family data
# ---------------------------------------------------------------------------
# Each entry is a dict with:
#   name        — canonical display name (also used for --family matching)
#   aliases     — alternative names accepted by --family
#   era         — production era
#   size        — typical file size(s)
#   summary     — one-line description shown in the table
#   vehicles    — representative vehicle / engine list
#   sub_families — list of known sub-variant identifiers
#   identifier  — key fingerprint used by the extractor
#   sw_format   — software version format / prefix
#   hw_in_bin   — whether HW number is embedded in the binary
#   notes       — any extra detail worth calling out
# ---------------------------------------------------------------------------

_FAMILIES: list[dict] = [
    {
        "name": "EDC1 / EDC2",
        "aliases": ["edc1", "edc2"],
        "era": "1990–1997",
        "size": "32–64 KB",
        "summary": "Audi 80 / A6 TDI, BMW 525 TDS, early diesel ROMs.",
        "vehicles": [
            "Audi 80 1.9 TDI (1Z/AFN)",
            "Audi A6 2.5 TDI (AEL)",
            "BMW 318 TDS / 525 TDS",
        ],
        "sub_families": ["EDC1", "EDC2"],
        "identifier": "Fixed-offset ident block; SW prefix 2287 or 2537",
        "sw_format": "2287xxxxxx / 2537xxxxxx",
        "hw_in_bin": "Yes — ident block",
        "notes": "Fixed ROM size; one of the earliest Bosch diesel ECU platforms.",
    },
    {
        "name": "EDC 3.x",
        "aliases": ["edc3", "edc3x", "edc3.x"],
        "era": "1993–2000",
        "size": "128–512 KB",
        "summary": "VAG TDI, BMW diesel, Opel diesel bridge generation. Three ident formats.",
        "vehicles": [
            "Audi A3/A4/A6 1.9 TDI (AHU/AFN/1Z/AVB)",
            "BMW 320D / 520D 136HP (EDC3 BMW numeric block)",
            "Opel Astra/Vectra/Frontera 2.0 DTI",
        ],
        "sub_families": ["EDC3 VAG", "EDC3 BMW", "EDC3 Opel (Format 3/4)"],
        "identifier": (
            "Three ident formats: VAG HEX block, BMW numeric block (5331xx/3150), "
            "Opel cal block (0xFF/0xAA sentinel + 7-digit number)"
        ),
        "sw_format": "7-digit cal number (e.g. 0770173 / 1880150) or VAG hex string",
        "hw_in_bin": "Yes — VAG and BMW; Opel: scanned separately",
        "notes": (
            "Split-ROM Opel chips (LLL/HHH or h/l pairs) contain the same 7-digit "
            "cal ID on both chips. The byte after the cal number (H/L) is Bosch's "
            "built-in chip discriminator."
        ),
    },
    {
        "name": "EDC15",
        "aliases": ["edc15"],
        "era": "1997–2004",
        "size": "512 KB",
        "summary": "Two sub-formats: Format A (TSW header) and Format B (C3-fill).",
        "vehicles": [
            "VAG 1.9 TDI / 2.0 TDI (widespread)",
            "Fiat / Alfa Romeo 1.9 JTD",
            "Volvo / BMW diesel",
        ],
        "sub_families": ["EDC15 Format A (TSW)", "EDC15 Format B (C3-fill)"],
        "identifier": "TSW toolchain marker (Format A) or 0xC3 fill ratio > 15% (Format B)",
        "sw_format": "1037xxxxxx",
        "hw_in_bin": "No — filename / label only",
        "notes": "Widely used across VAG, Fiat, Volvo, and BMW diesel. Always 512 KB.",
    },
    {
        "name": "EDC16",
        "aliases": ["edc16"],
        "era": "2003–2008",
        "size": "256 KB / 1 MB / 2 MB",
        "summary": "DECAFE magic at fixed offsets. VAG PD TDI, BMW diesel, Opel CDTI.",
        "vehicles": [
            "Audi A3/A4 1.9 TDI BKC/BKE (VAG PD, EDC16U/C8)",
            "BMW 320D/520D/120D 163HP E46/E60/E87 (EDC16C31)",
            "BMW X6 30sd (EDC16CP35)",
            "Opel Vectra-C / Signum / Astra-H CDTI (EDC16C9)",
            "Alfa 147/156 1.9 JTDM (EDC16C8)",
            "Alfa 159 2.4 JTDM (EDC16C39)",
            "Peugeot 3008 1.6 HDI (EDC16C34, SW prefix 1039)",
        ],
        "sub_families": [
            "EDC16C8",
            "EDC16C9",
            "EDC16C31",
            "EDC16C34",
            "EDC16C35",
            "EDC16C36",
            "EDC16C39",
            "EDC16CP33",
            "EDC16CP34",
            "EDC16CP35",
            "EDC16U1",
            "EDC16U31",
        ],
        "identifier": r"\xDE\xCA\xFE (DECAFE) magic at bank-boundary offsets",
        "sw_format": (
            "1037xxxxxx (standard); 1037A50286 (alphanumeric, Opel C9); "
            "1039xxxxxx (PSA/Peugeot-Citroën EDC16C34)"
        ),
        "hw_in_bin": "Opel EDC16C9 only — plain ASCII null-terminated in cal area",
        "notes": (
            "BMW C31/C35 2 MB bins store the family string near the 0xC0000 mirror "
            "section (~0x0C06F3), not at the end of file. "
            "BMW E46 320D early 1 MB layout has active_start=0x20000 (non-standard)."
        ),
    },
    {
        "name": "EDC17 / MEDC17 / MED17 / ME17",
        "aliases": ["edc17", "medc17", "med17", "me17"],
        "era": "2008–present",
        "size": "2–8 MB",
        "summary": "The dominant modern platform. PSA, VAG, BMW, Mercedes — diesel and petrol.",
        "vehicles": [
            "VAG 2.0 TDI CR (widespread, 2008–)",
            "BMW diesel 2008–",
            "Mercedes diesel 2008–",
            "PSA / Peugeot / Citroën diesel 2008–",
        ],
        "sub_families": ["EDC17C", "EDC17CP", "MEDC17", "MED17", "ME17"],
        "identifier": "SB_V / NR000 / Customer. markers; no DECAFE; no TSW; no 0xC3 fill",
        "sw_format": "1037xxxxxxxxx (extended, may include suffix letters)",
        "hw_in_bin": "No — not stored as plain ASCII",
        "notes": (
            "Some 4 MB internal-flash BDM reads lack the calibration ident block "
            "(IDENT BLOCK MISSING warning). These cannot be identified by SW number alone."
        ),
    },
    {
        "name": "ME7 / ME7.x",
        "aliases": ["me7", "me7.1", "me7.5", "me7.6"],
        "era": "1997–2008",
        "size": "64 KB–1 MB",
        "summary": "VAG 1.8T, Porsche, Ferrari, Opel Corsa D. ZZ ident block at 0x10000.",
        "vehicles": [
            "Audi S4 2.7T biturbo (ME7.1)",
            "Audi A3 1.8T / VW Golf 1.8T (ME7.5)",
            "Opel Corsa D 1.6T (ME7.6.2, 832 KB)",
            "Porsche 996 / Ferrari 360",
            "Peugeot 206 1.6i 16v (64 KB PSA cal-sector dump)",
            "Peugeot 207 THP 1.6 150HP (256 KB PSA ME7.4.x cal-sector dump)",
        ],
        "sub_families": [
            "ME7.1",
            "ME7.1.1",
            "ME7.5",
            "ME7.5.5",
            "ME7.5.10",
            "ME7.6.2",
            "ME7early (ERCOS V2.x)",
        ],
        "identifier": (
            "ZZ ident block at offset 0x10000 (non-printable third byte). "
            "Also: MOTRONIC / ME7. string in binary. "
            "PSA 64 KB sector: ZZ at offset 0. "
            "PSA ME7.4.x 256 KB: \\x02\\x00 at 0x18, SW at 0x1A."
        ),
        "sw_format": "1037xxxxxx",
        "hw_in_bin": "Yes — ZZ ident block (HW absent in PSA 256 KB sector format)",
        "notes": (
            "Minimum full-dump size: 64 KB. "
            "ME7.6.2 (Opel Corsa D, 832 KB) stores family string past 512 KB. "
            "Magneti Marelli ME1.5.5 ECUs also place ZZ at 0x10000 but with a "
            "printable third byte — rejected by the extractor."
        ),
    },
    {
        "name": "ME9",
        "aliases": ["me9"],
        "era": "2001–2006",
        "size": "2 MB",
        "summary": "VW / Audi 1.8T 20v full flash. Identified by RamLoader anchor.",
        "vehicles": [
            "VW Golf / Bora 1.8T 20v (AGU, AEB, APU, AWM)",
            "Audi A4 / TT 1.8T 20v",
        ],
        "sub_families": ["ME9"],
        "identifier": "Bosch.Common.RamLoader.Me9 ASCII string",
        "sw_format": "1037xxxxxx",
        "hw_in_bin": "Yes",
        "notes": "Full flash dumps. Shares RAM-loader pattern with MED9.",
    },
    {
        "name": "MED9 / MED9.x",
        "aliases": ["med9", "med9.x"],
        "era": "2002–2008",
        "size": "512 KB–2 MB",
        "summary": "VAG FSI and TFSI petrol direct injection.",
        "vehicles": [
            "Audi A3 1.6 FSI / 2.0 TFSI (AXX, BWA, BYD, CAWB)",
            "VW Golf V GTI 2.0 TFSI",
            "Audi TTS 2.0 TFSI",
        ],
        "sub_families": ["MED9", "MED9.1", "MED9.5"],
        "identifier": "MED9 marker; shares RamLoader with ME9",
        "sw_format": "1037xxxxxx",
        "hw_in_bin": "Yes",
        "notes": "Distinct from ME9 by the MED9 family marker.",
    },
    {
        "name": "M1.x",
        "aliases": ["m1x", "m1.x", "m1.3", "m1.7"],
        "era": "1987–1996",
        "size": "32–64 KB",
        "summary": "BMW E28/E30/E34/E36, Opel petrol. Header magic or reversed-digit ident.",
        "vehicles": [
            "BMW 320i / 325i / 525i (M1.3 / M1.7)",
            "Opel Kadett / Astra / Calibra (no header magic, reversed-digit ident)",
        ],
        "sub_families": ["M1.3", "M1.7", "M1.x (Opel fallback)"],
        "identifier": r"\x85\x0a\xf0\x30 header magic (BMW); reversed-digit ident fallback (Opel)",
        "sw_format": "1267xxxxxx",
        "hw_in_bin": "Yes — reversed-digit ident block",
        "notes": (
            "Opel M1.x and some BMW M1.7 variants lack the header magic and are "
            "identified purely by a valid 0261/1267-prefixed reversed-digit ident."
        ),
    },
    {
        "name": "M1.55 / M1.5.5",
        "aliases": ["m1.55", "m1.5.5", "m155", "m1x55"],
        "era": "1994–2002",
        "size": "128 KB",
        "summary": "Alfa Romeo (M1.55) and Opel Corsa C / Astra G (M1.5.5) petrol.",
        "vehicles": [
            "Alfa Romeo 155 / 156 / GT 2.0 TS (M1.55)",
            "Opel Corsa C 1.0 12V / Astra G petrol (M1.5.5)",
        ],
        "sub_families": ["M1.55 (Alfa)", "M1.5.5 (Opel)"],
        "identifier": (
            'b"M1.55" at ~0x8005 (Alfa); b"M1.5.5" at ~0x0D82F (Opel). Always 128 KB.'
        ),
        "sw_format": "Alfa: 1267xxxxxx via slash descriptor. Opel: 8-digit GM number (e.g. 90532609)",
        "hw_in_bin": (
            "Alfa: ident block near end of file. "
            'Opel: GM ident block at ~0xD801 (format: "<sw8> <prefix2><hw10>...")'
        ),
        "notes": (
            "Opel M1.5.5 uses a GM-internal software numbering scheme — the SW is "
            "an 8-digit GM part number, not a 1037-prefixed Bosch calibration number."
        ),
    },
    {
        "name": "M2.x",
        "aliases": ["m2x", "m2.x", "m2.3", "m2.7", "m2.8", "m2.9"],
        "era": "1993–1999",
        "size": "32–128 KB",
        "summary": "VW/Audi M2.9, Porsche 964 (M2.3), Opel M2.7/M2.8/M2.81.",
        "vehicles": [
            "VW Corrado / Golf VR6 (M2.9)",
            "Porsche 964 Carrera 2/4 (M2.3)",
            "Opel Calibra 2.0T (M2.7, 32 KB reversed-string)",
            "Opel Astra GSi C20XE / Calibra V6 (M2.8, 0xFF-padded block)",
            "Opel Omega 3.0 V6 (M2.81, DAMOS fallback)",
        ],
        "sub_families": ["M2.3", "M2.7", "M2.8", "M2.81", "M2.9"],
        "identifier": (
            "Format A: MOTOR PMC label (VAG). "
            "Format B: MOTRONIC label (Porsche). "
            "Format C: 0xFF-padded space-delimited HW+SW (Opel 2.8/2.81). "
            "Format D: dx-prefixed reversed-string (Opel 2.7, 32 KB)."
        ),
        "sw_format": "1267xxxxxx or 2227xxxxxx (never 1037)",
        "hw_in_bin": "Yes in all formats",
        "notes": "SW prefix is always 1267 or 2227 — this is expected and not a defect.",
    },
    {
        "name": "M3.x",
        "aliases": ["m3x", "m3.x", "m3.1", "m3.3", "mp3.2", "mp7.2"],
        "era": "1989–1999",
        "size": "32–256 KB",
        "summary": "BMW M3.1/M3.3 and PSA/Citroën MP3.2/MP3.x-PSA/MP7.2. Reversed-digit ident.",
        "vehicles": [
            "BMW E30 M3 / E36 (M3.1, M3.3)",
            "Citroën ZX 2.0 16V (MP3.2, HW 0261200218)",
            "Peugeot 106 1.4 / early PSA petrol (MP3.1 Layout B)",
            "Citroën Saxo 1.6i VTS (MP7.2, 256 KB)",
        ],
        "sub_families": ["M3.1", "M3.3", "MP3.2", "MP3.x-PSA", "MP7.2"],
        "identifier": (
            "1350000M3 → M3.1 / M3.3; 1530000M3 → M3.3 / MP7.2; "
            "0000000M3 → MP3.2 / MP3.x-PSA. "
            "HW/SW in reversed-digit order: hw=digits[0:10][::-1], sw=digits[10:20][::-1]."
        ),
        "sw_format": "1267xxxxxx or 2227xxxxxx",
        "hw_in_bin": "Yes — reversed-digit ident block",
        "notes": (
            "Early PSA MP3.1 bins (Layout B) store the 20-digit ident far from the "
            "0000000M3 marker, separated by non-ASCII bytes. A whole-file digit-run "
            "scan is used as fallback."
        ),
    },
    {
        "name": "M5.x / M3.8x",
        "aliases": ["m5x", "m5.x", "m3.8x", "m3.8"],
        "era": "1997–2004",
        "size": "128–256 KB",
        "summary": "VW / Audi 1.8T (AGU, AUM, APX). Overlaps with ME7 era.",
        "vehicles": [
            "VW Golf IV / Bora 1.8T (AGU, AUM)",
            "Audi A3 / TT 1.8T (APX)",
        ],
        "sub_families": ["M5.x", "M3.8x"],
        "identifier": "MOTR-style ident string with slash descriptor",
        "sw_format": "1037xxxxxx",
        "hw_in_bin": "Yes",
        "notes": "Distinguished from ME7 by ident string content despite overlapping era.",
    },
    {
        "name": "LH-Jetronic",
        "aliases": ["lh", "lh-jetronic", "lhjetronic"],
        "era": "1982–1995",
        "size": "8–64 KB",
        "summary": "Volvo, early BMW and Mercedes fuel injection. No 1037 SW.",
        "vehicles": [
            "Volvo 240 / 740 / 940",
            "BMW E28 / E30 (early)",
            "Mercedes W124 / W201",
        ],
        "sub_families": ["LH-Jetronic"],
        "identifier": "Calibration ID pattern; no 1037-prefixed SW",
        "sw_format": "No numeric SW — identified by calibration_id only",
        "hw_in_bin": "Sometimes — HW prefix 0280xxxxxx",
        "notes": (
            "SW absence is normal for LH-Jetronic — no IDENT BLOCK MISSING warning "
            "is raised for this family."
        ),
    },
    {
        "name": "Motronic Legacy",
        "aliases": [
            "motronic",
            "motronic_legacy",
            "motroniclegacy",
            "ke-jetronic",
            "ezk",
            "dme",
        ],
        "era": "various",
        "size": "2–32 KB",
        "summary": "DME-3.2, M1.x-early, KE-Jetronic, EZK. No ASCII SW in most variants.",
        "vehicles": [
            "Porsche 911 Carrera 3.2 (DME-3.2)",
            "BMW E30 M3 early / Porsche 951 (M1.x-early)",
            "Mercedes / Volvo KE-Jetronic (HW prefix 02808)",
            "EZK standalone ignition controllers",
        ],
        "sub_families": ["DME-3.2", "M1.x-early", "KE-Jetronic", "EZK"],
        "identifier": "Size ≤ 32 KB; era-specific magic bytes; no modern Bosch markers",
        "sw_format": "No ASCII SW (KE-Jetronic has match_key via HW; others have None)",
        "hw_in_bin": "KE-Jetronic only (02808-prefixed)",
        "notes": (
            "SW absence is normal — no IDENT BLOCK MISSING warning for this family. "
            "match_key is None for all variants except KE-Jetronic."
        ),
    },
]

# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

_WIDTH = 73
_COL_FAMILY = 22
_COL_ERA = 12
_COL_SIZE = 16


def _sep(dim: bool = True) -> None:
    line = "  " + "─" * _WIDTH
    typer.echo(typer.style(line, dim=dim) if dim else line)


def _blank() -> None:
    typer.echo("")


def _header(text: str) -> None:
    typer.echo(typer.style(f"  {text}", bold=True))


def _row(family: str, era: str, size: str, summary: str) -> None:
    fam_col = typer.style(f"{family:<{_COL_FAMILY}}", fg=typer.colors.CYAN)
    era_col = f"{era:<{_COL_ERA}}"
    size_col = f"{size:<{_COL_SIZE}}"
    typer.echo(f"  {fam_col}  {era_col}  {size_col}  {summary}")


def _kv(key: str, value: str, key_width: int = 14) -> None:
    k = typer.style(f"  {key:<{key_width}}", dim=True)
    typer.echo(f"{k}  {value}")


def _lookup(name: str) -> dict | None:
    """Find a family entry by name or alias (case-insensitive)."""
    needle = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    for fam in _FAMILIES:
        if needle == fam["name"].lower().replace(" ", "").replace("-", "").replace(
            "/", ""
        ):
            return fam
        for alias in fam["aliases"]:
            if needle == alias.replace("-", "").replace("_", "").replace(".", ""):
                return fam
    return None


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


def _print_table() -> None:
    """Print all families as a compact aligned table."""
    _blank()
    _header("Supported ECU Families")
    _blank()
    _sep()

    # Column headers
    fam_hdr = typer.style(f"  {'FAMILY':<{_COL_FAMILY}}", bold=True)
    era_hdr = typer.style(f"{'ERA':<{_COL_ERA}}", bold=True)
    siz_hdr = typer.style(f"{'SIZE':<{_COL_SIZE}}", bold=True)
    dsc_hdr = typer.style("NOTES", bold=True)
    typer.echo(f"{fam_hdr}  {era_hdr}  {siz_hdr}  {dsc_hdr}")
    _sep()

    for fam in _FAMILIES:
        _row(fam["name"], fam["era"], fam["size"], fam["summary"])

    _sep()
    _blank()
    typer.echo(
        "  "
        + typer.style(
            "openremap families --family <NAME>", fg=typer.colors.GREEN, bold=True
        )
        + typer.style("   show full detail for one family", dim=True)
    )
    typer.echo(
        "  "
        + typer.style(
            "openremap identify <FILE>          ", fg=typer.colors.GREEN, bold=True
        )
        + typer.style("   identify an ECU binary", dim=True)
    )
    _blank()


def _print_detail(fam: dict) -> None:
    """Print full detail for a single family."""
    _blank()
    typer.echo(typer.style(f"  {fam['name']}", fg=typer.colors.CYAN, bold=True))
    _sep()
    _blank()

    _kv("Era", fam["era"])
    _kv("File size", fam["size"])
    _blank()

    _kv("Sub-families", fam["sub_families"][0])
    for sf in fam["sub_families"][1:]:
        typer.echo(f"  {'':14}  {sf}")
    _blank()

    _kv("Identifier", fam["identifier"])
    _blank()

    _kv("SW format", fam["sw_format"])
    _kv("HW in binary", fam["hw_in_bin"])
    _blank()

    _kv("Vehicles", fam["vehicles"][0])
    for v in fam["vehicles"][1:]:
        typer.echo(f"  {'':14}  {v}")
    _blank()

    if fam.get("notes"):
        _kv("Notes", "")
        # Wrap notes at ~58 chars for readability
        words = fam["notes"].split()
        line: list[str] = []
        line_len = 0
        first = True
        for word in words:
            if line_len + len(word) + 1 > 56 and line:
                prefix = "  " + " " * 16 if not first else "  " + " " * 16
                typer.echo(f"{prefix}{' '.join(line)}")
                line = [word]
                line_len = len(word)
                first = False
            else:
                line.append(word)
                line_len += len(word) + 1
        if line:
            typer.echo(f"  {'':16}{' '.join(line)}")
        _blank()

    _sep()
    _blank()
    typer.echo(
        "  "
        + typer.style(
            "openremap families             ", fg=typer.colors.GREEN, bold=True
        )
        + typer.style("show all families", dim=True)
    )
    typer.echo(
        "  "
        + typer.style(
            "openremap identify <FILE>      ", fg=typer.colors.GREEN, bold=True
        )
        + typer.style("identify an ECU binary", dim=True)
    )
    _blank()


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


def families(
    family: Optional[str] = typer.Option(
        None,
        "--family",
        "-f",
        help=(
            "Show expanded detail for a specific ECU family. "
            "Accepts the family name or any known alias "
            "(e.g. EDC16, ME7, M3x, mp3.2, edc3, lh-jetronic)."
        ),
        metavar="NAME",
    ),
) -> None:
    """
    List all supported ECU families.

    Without --family, prints a compact table of every supported ECU family
    with era, typical file size, and a one-line description.

    With --family <NAME>, prints full detail for that family — sub-variants,
    fingerprint method, SW format, HW availability, representative vehicles,
    and any relevant notes.

    \b
    Examples:
        openremap families
        openremap families --family EDC16
        openremap families --family ME7
        openremap families -f mp3.2
    """
    if family is None:
        _print_table()
        return

    entry = _lookup(family)
    if entry is None:
        typer.echo(
            typer.style(
                f"\n  Error: unknown family '{family}'.\n",
                fg=typer.colors.RED,
                bold=True,
            ),
            err=True,
        )
        typer.echo(
            "  Run "
            + typer.style("openremap families", fg=typer.colors.GREEN, bold=True)
            + " to see all supported families.\n",
            err=True,
        )
        raise typer.Exit(code=1)

    _print_detail(entry)
