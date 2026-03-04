"""Tests for Module 6: ChaCha20 Core."""

import struct
import pytest
from cc_stream.chacha20_core import (
    _quarter_round,
    block,
    initialize_state,
    keystream,
    _MASK32,
)


class TestQuarterRound:
    def test_rfc8439_test_vector(self):
        """RFC 8439 Section 2.1.1 test vector."""
        a, b, c, d = 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567
        a, b, c, d = _quarter_round(a, b, c, d)
        assert a == 0xea2a92f4
        assert b == 0xcb1cf8ce
        assert c == 0x4581472e
        assert d == 0x5881c4bb


class TestBlock:
    def test_output_length(self):
        state = [0] * 16
        result = block(state)
        assert len(result) == 64

    def test_nonzero_state_nonzero_output(self):
        """A non-trivial state should produce a non-zero block."""
        state = list(range(16))
        result = block(state)
        assert result != b"\x00" * 64

    def test_deterministic(self):
        state = list(range(16))
        assert block(state) == block(state)

    def test_state_not_mutated(self):
        state = list(range(16))
        original = list(state)
        block(state)
        assert state == original


class TestInitializeState:
    def test_layout(self):
        constants = [0xAA] * 4
        key_words = [0xBB] * 8
        nonce_words = [0xCC] * 4
        state = initialize_state(constants, key_words, nonce_words)
        assert len(state) == 16
        assert state[:4] == [0xAA] * 4
        assert state[4:12] == [0xBB] * 8
        assert state[12:] == [0xCC] * 4

    def test_wrong_constant_length(self):
        with pytest.raises(ValueError):
            initialize_state([1, 2, 3], [0] * 8, [0] * 4)

    def test_wrong_key_length(self):
        with pytest.raises(ValueError):
            initialize_state([0] * 4, [0] * 7, [0] * 4)

    def test_wrong_nonce_length(self):
        with pytest.raises(ValueError):
            initialize_state([0] * 4, [0] * 8, [0] * 3)


class TestKeystream:
    def test_exact_64_bytes(self):
        state = list(range(16))
        ks = keystream(state, 64)
        assert len(ks) == 64

    def test_partial_block(self):
        state = list(range(16))
        ks = keystream(state, 30)
        assert len(ks) == 30
        # First 30 bytes should match a full block truncated
        full = keystream(state, 64)
        assert ks == full[:30]

    def test_multi_block(self):
        state = list(range(16))
        ks = keystream(state, 128)
        assert len(ks) == 128
        # First 64 bytes = first block
        b1 = keystream(state, 64)
        assert ks[:64] == b1
        # Second 64 bytes should differ (counter increments)
        assert ks[64:] != ks[:64]

    def test_zero_length(self):
        state = list(range(16))
        assert keystream(state, 0) == b""

    def test_negative_length(self):
        state = list(range(16))
        assert keystream(state, -1) == b""

    def test_rfc8439_full_block(self):
        """RFC 8439 Section 2.3.2 test vector for ChaCha20 block function."""
        # Standard ChaCha20 constants
        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        key_words = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ]
        nonce_words = [0x00000001, 0x09000000, 0x4a000000, 0x00000000]
        state = initialize_state(constants, key_words, nonce_words)
        result = block(state)

        # Expected first 16 bytes from RFC 8439
        expected_words = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        ]
        actual_words = list(struct.unpack('<4I', result[:16]))
        assert actual_words == expected_words
