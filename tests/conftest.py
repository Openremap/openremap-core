"""
Shared test helpers and fixtures for the tuning pipeline test suite.

All helpers are plain functions (not pytest fixtures) so tests can
compose them freely without fixture dependency injection overhead.
"""


# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------


def make_bin(size: int = 1024, fill: int = 0x00) -> bytes:
    """Return a bytes object of `size` bytes all set to `fill`."""
    return bytes([fill] * size)


def make_bin_with(size: int, patches: dict) -> bytes:
    """
    Build a zero-filled binary of `size` bytes and write specific values.

    Args:
        size:    Total size in bytes.
        patches: Dict of {offset: value_bytes} where value_bytes is bytes or int.
                 An int value is written as a single byte.

    Example:
        make_bin_with(1024, {100: b"\\xAA\\xBB", 200: 0xFF})
    """
    buf = bytearray(size)
    for offset, value in patches.items():
        if isinstance(value, int):
            buf[offset] = value
        else:
            buf[offset : offset + len(value)] = value
    return bytes(buf)


# ---------------------------------------------------------------------------
# Recipe helpers
# ---------------------------------------------------------------------------


def make_recipe(instructions: list, ecu: dict | None = None) -> dict:
    """
    Build a minimal format-4.0 recipe dict.

    Args:
        instructions: List of instruction dicts (use make_instruction()).
        ecu:          Optional ecu block. Defaults to an empty dict.
    """
    return {
        "metadata": {"format_version": "4.0"},
        "ecu": ecu or {},
        "statistics": {"total_changes": len(instructions)},
        "instructions": instructions,
    }


def make_instruction(
    offset: int,
    ob: str,
    mb: str,
    ctx: str = "",
) -> dict:
    """
    Build a single recipe instruction dict.

    Args:
        offset: Absolute byte offset in the binary.
        ob:     Original bytes as uppercase hex string (e.g. "AABB").
        mb:     Modified bytes as uppercase hex string (e.g. "CCDD").
        ctx:    Context-before bytes as uppercase hex string. Default empty.
    """
    ob = ob.upper()
    mb = mb.upper()
    ctx = ctx.upper()
    return {
        "offset": offset,
        "offset_hex": f"{offset:X}",
        "size": len(bytes.fromhex(ob)),
        "ob": ob,
        "mb": mb,
        "ctx": ctx,
        "context_after": "",
        "context_size": len(bytes.fromhex(ctx)) if ctx else 0,
        "description": f"{len(bytes.fromhex(ob))} bytes at 0x{offset:X} modified",
    }


def ctx_hex(data: bytes, offset: int, size: int = 8) -> str:
    """
    Extract `size` bytes immediately before `offset` from `data` as uppercase hex.
    Returns an empty string if offset is 0 or data is too short.
    """
    start = max(0, offset - size)
    return data[start:offset].hex().upper()
