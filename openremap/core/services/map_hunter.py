"""
Generic calibration map axis scanner — the 'bullshit detector'.

Scans ECU binaries for monotonically increasing 16-bit axis sequences that
indicate genuine calibration map structures.  Used as a confidence signal:
if an extractor identifies a binary as a modern ECU but zero map axes are
found, the file may be encrypted, corrupted, or misidentified.

ECU calibration maps store data in 2D tables with monotonically increasing
axes (e.g. RPM breakpoints, load breakpoints).  The axes are typically
stored as sequences of 16-bit unsigned integers in either little-endian or
big-endian byte order.

The scanner is intentionally conservative — it looks for *plausible* axes
rather than trying to parse any specific map format.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------


class MapAxis(NamedTuple):
    """A single plausible calibration map axis found in the binary."""

    offset: int
    """Byte offset (within the scanned region) where the axis starts."""

    length: int
    """Number of 16-bit values in the axis."""

    byte_order: str
    """Either ``'little'`` or ``'big'``."""

    values: tuple[int, ...]
    """The decoded 16-bit values forming the axis."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# struct format characters for 16-bit unsigned, by byte order.
_FMT: dict[str, str] = {"little": "<H", "big": ">H"}

# Minimum number of consecutive bytes that must be non-trivial (not all
# 0x00 or all 0xFF) before we bother decoding.  Set to 8 so that we need
# at least 4 × u16 values worth of non-trivial data.
_SKIP_WINDOW = 8


def _is_trivial_block(data: bytes, start: int, length: int) -> bool:
    """Return *True* if the *length*-byte block at *start* is all-zero or
    all-0xFF.  Used to skip erased flash / empty regions quickly."""
    end = min(start + length, len(data))
    if end <= start:
        return True
    block = data[start:end]
    first = block[0]
    if first not in (0x00, 0xFF):
        return False
    # Fast path: compare against a single-byte fill.
    return block == bytes([first]) * len(block)


def _try_axis_at(
    data: bytes,
    offset: int,
    fmt: str,
    min_axis_length: int,
    max_axis_length: int,
    min_step: int,
    max_step: int,
) -> int:
    """Starting at *offset*, try to read the longest strictly-increasing
    run of 16-bit values using *fmt* (a ``struct`` format character).

    Returns the number of consecutive increasing values found (≥ 1), or 0
    if even the first value cannot be read.
    """
    data_len = len(data)
    if offset + 2 > data_len:
        return 0

    count = 1
    prev: int = struct.unpack_from(fmt, data, offset)[0]
    pos = offset + 2
    limit = min(offset + max_axis_length * 2, data_len)

    while pos + 1 < limit:
        cur: int = struct.unpack_from(fmt, data, pos)[0]
        diff = cur - prev
        if diff < min_step or diff > max_step:
            break
        prev = cur
        pos += 2
        count += 1

    return count


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------


def scan_map_axes(
    data: bytes,
    region: slice | None = None,
    min_axis_length: int = 4,
    max_axis_length: int = 32,
    min_step: int = 1,
    max_step: int = 10000,
) -> list[MapAxis]:
    """Scan *data* for plausible 16-bit calibration map axes.

    Parameters
    ----------
    data:
        Raw ECU binary content.
    region:
        Optional ``slice`` to restrict scanning to a sub-region of *data*.
        When *None*, the entire buffer is scanned.
    min_axis_length:
        Minimum number of consecutive strictly-increasing 16-bit values
        required to consider a run a plausible axis (default **4**, i.e.
        8 bytes).
    max_axis_length:
        Maximum axis length to consider (default **32**).  Axes longer than
        this are unlikely in real ECU calibrations and may indicate
        coincidental data.
    min_step:
        Minimum allowed difference between consecutive axis values
        (default **1**).  A step of 0 would mean duplicate values.
    max_step:
        Maximum allowed difference between consecutive axis values
        (default **10 000**).  Very large jumps are unlikely in real
        breakpoint tables.

    Returns
    -------
    list[MapAxis]
        All plausible axes found, deduplicated across byte orders.  Each
        axis is reported only once even if both endianness interpretations
        would qualify (the first match wins, little-endian is tried first).
    """
    if region is not None:
        buf = data[region]
        # Work on the sliced copy; offsets are relative to the region.
    else:
        buf = data

    buf_len = len(buf)
    if buf_len < min_axis_length * 2:
        return []

    # We track which byte offsets have already been claimed by a found axis
    # so that overlapping / duplicate detections across byte orders are
    # suppressed.
    claimed_offsets: set[int] = set()
    results: list[MapAxis] = []

    # Try little-endian first, then big-endian.
    for byte_order in ("little", "big"):
        fmt = _FMT[byte_order]
        offset = 0

        while offset + min_axis_length * 2 <= buf_len:
            # --- fast skip: trivial (all-zero / all-0xFF) regions ---------
            if _is_trivial_block(buf, offset, _SKIP_WINDOW):
                # Jump forward in larger strides to leave the trivial zone.
                offset += _SKIP_WINDOW
                continue

            # --- check if this offset is already claimed ------------------
            if offset in claimed_offsets:
                offset += 2
                continue

            # --- attempt to read an axis ----------------------------------
            run_len = _try_axis_at(
                buf,
                offset,
                fmt,
                min_axis_length,
                max_axis_length,
                min_step,
                max_step,
            )

            if run_len >= min_axis_length:
                # Decode the full axis values for the result.
                values = tuple(
                    struct.unpack_from(fmt, buf, offset + i * 2)[0]
                    for i in range(run_len)
                )
                axis = MapAxis(
                    offset=offset,
                    length=run_len,
                    byte_order=byte_order,
                    values=values,
                )
                results.append(axis)

                # Claim every byte offset covered by this axis so the
                # other-endianness pass won't double-count it.
                for i in range(run_len):
                    claimed_offsets.add(offset + i * 2)

                # Skip past the axis before continuing.
                offset += run_len * 2
            else:
                offset += 2

    return results


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------


def count_map_axes(
    data: bytes,
    region: slice | None = None,
    min_axis_length: int = 4,
    max_axis_length: int = 32,
    min_step: int = 1,
    max_step: int = 10000,
) -> int:
    """Return the number of plausible calibration map axes in *data*.

    This is a thin convenience wrapper around :func:`scan_map_axes` — see
    that function's docstring for parameter details.
    """
    return len(
        scan_map_axes(
            data,
            region=region,
            min_axis_length=min_axis_length,
            max_axis_length=max_axis_length,
            min_step=min_step,
            max_step=max_step,
        )
    )
