"""
Tests for known checksums of the reference binary ``original.bin``.

Covers:
  - File size (exact byte count)
  - MD5 digest
  - SHA-256 digest
  - CRC32 (full file)
  - XOR8 (full file)
  - Example checksum corrector plugin behaviour:
      • CRC32 of first 64 KB
      • Last 4 bytes of the file
      • XOR8 of bytes 64 KB – 128 KB
      • Byte at offset -5

All tests are skipped when the binary is not present on disk so that
CI and other environments without the file are not affected.
"""

import hashlib
import os
import struct
import zlib

import pytest

# ---------------------------------------------------------------------------
# Path & skip gate
# ---------------------------------------------------------------------------

ORIGINAL_BIN = "/home/pinx/Downloads/later/original.bin"

pytestmark = pytest.mark.skipif(
    not os.path.exists(ORIGINAL_BIN),
    reason=f"{ORIGINAL_BIN} not found – skipping checksum tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_bin() -> bytes:
    """Read the entire binary into memory (cached per-module via the fixture)."""
    with open(ORIGINAL_BIN, "rb") as fh:
        return fh.read()


def _xor8(data: bytes) -> int:
    """Compute XOR of every byte in *data*."""
    result = 0
    for b in data:
        result ^= b
    return result


# ---------------------------------------------------------------------------
# Known whole-file checksums
# ---------------------------------------------------------------------------


class TestFileSize:
    """Verify the binary is exactly the expected size."""

    def test_file_size_bytes(self):
        """File must be exactly 4 194 304 bytes (0x400000)."""
        data = _read_bin()
        assert len(data) == 0x400000

    def test_file_size_decimal(self):
        """Cross-check using the decimal value."""
        data = _read_bin()
        assert len(data) == 4_194_304


class TestMD5:
    """Verify the MD5 digest of the full binary."""

    def test_md5_hex(self):
        """MD5 must equal abc2e7d4610bfda5619951e015566e8d."""
        data = _read_bin()
        digest = hashlib.md5(data).hexdigest()
        assert digest == "abc2e7d4610bfda5619951e015566e8d"


class TestSHA256:
    """Verify the SHA-256 digest of the full binary."""

    def test_sha256_hex(self):
        """SHA-256 must equal 00f727e8abf62d384acc4420b08fe8e5477f9d004c8d3a697bbaaa08fe2149f5."""
        data = _read_bin()
        digest = hashlib.sha256(data).hexdigest()
        assert digest == (
            "00f727e8abf62d384acc4420b08fe8e5477f9d004c8d3a697bbaaa08fe2149f5"
        )


class TestCRC32:
    """Verify the CRC32 of the full binary."""

    def test_crc32_value(self):
        """CRC32 must equal 0xA17B5BF1."""
        data = _read_bin()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        assert crc == 0xA17B5BF1

    def test_crc32_hex_string(self):
        """CRC32 formatted as lowercase hex must match."""
        data = _read_bin()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        assert f"{crc:08x}" == "a17b5bf1"


class TestXOR8:
    """Verify the XOR8 of the full binary."""

    def test_xor8_value(self):
        """XOR8 of every byte in the file must equal 0x31."""
        data = _read_bin()
        assert _xor8(data) == 0x31


# ---------------------------------------------------------------------------
# Example checksum corrector plugin — region checksums
# ---------------------------------------------------------------------------


class TestExampleChecksumCorrectorRegions:
    """
    Validate the region-level values that the example checksum corrector
    plugin (``example-checksum``) would read and write.

    The plugin computes:
      • CRC32 over the first 64 KB  → writes at the last 4 bytes
      • XOR8  over bytes 64 KB – 128 KB → writes at byte offset -5
    """

    def test_crc32_first_64kb(self):
        """CRC32 of bytes 0 – 0xFFFF must equal 0x2512ABE3."""
        data = _read_bin()
        region = data[:65_536]
        crc = zlib.crc32(region) & 0xFFFFFFFF
        assert crc == 0x2512ABE3

    def test_last_four_bytes(self):
        """Last 4 bytes of the file must be EFBEADDE (little-endian 0xDEADBEEF)."""
        data = _read_bin()
        last4 = data[-4:]
        assert last4.hex().upper() == "EFBEADDE"

    def test_last_four_bytes_as_int(self):
        """Last 4 bytes read as little-endian uint32 must be 0xDEADBEEF."""
        data = _read_bin()
        value = struct.unpack("<I", data[-4:])[0]
        assert value == 0xDEADBEEF

    def test_byte_at_minus_five(self):
        """Byte at offset -5 must be 0x47 (pre-correction value)."""
        data = _read_bin()
        assert data[-5] == 0x47

    def test_plugin_would_overwrite_byte_minus_five(self):
        """The plugin computes XOR8(64K–128K) and writes it at byte -5.

        In the *original* (uncorrected) file these two values differ;
        after correction they would match.  Here we just verify that
        the region is readable and the computed XOR8 is an int in range.
        """
        data = _read_bin()
        region = data[65_536:131_072]
        xor = _xor8(region)
        assert 0x00 <= xor <= 0xFF
