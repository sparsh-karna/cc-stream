"""Tests for Module 7: Encryption (XOR)."""

import pytest
from cc_stream.encryption import xor_bytes


class TestXorBytes:
    def test_basic(self):
        assert xor_bytes(b"\x00\x00", b"\xff\xff") == b"\xff\xff"

    def test_identity(self):
        data = b"Hello"
        assert xor_bytes(data, b"\x00" * len(data)) == data

    def test_self_inverse(self):
        data = b"Secret message"
        ks = b"\xab" * len(data)
        encrypted = xor_bytes(data, ks)
        decrypted = xor_bytes(encrypted, ks)
        assert decrypted == data

    def test_keystream_too_short(self):
        with pytest.raises(ValueError, match="Keystream too short"):
            xor_bytes(b"AAAA", b"BB")

    def test_empty(self):
        assert xor_bytes(b"", b"") == b""
        assert xor_bytes(b"", b"extra") == b""
