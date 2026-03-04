"""Tests for Module 8: CCStream main API (integration tests)."""

import os
import pytest
from cc_stream.cipher import CCStream


class TestRoundTrip:
    def test_basic_roundtrip(self, fixed_key, fixed_nonce):
        pt = b"HELLO WORLD - CC-Stream Hybrid Cipher Test!"
        ct = CCStream(fixed_key, fixed_nonce).encrypt(pt)
        recovered = CCStream(fixed_key, fixed_nonce).decrypt(ct)
        assert recovered == pt

    def test_empty_message(self, fixed_key, fixed_nonce):
        ct = CCStream(fixed_key, fixed_nonce).encrypt(b"")
        assert ct == b""

    def test_single_byte(self, fixed_key, fixed_nonce):
        pt = b"\x42"
        ct = CCStream(fixed_key, fixed_nonce).encrypt(pt)
        assert len(ct) == 1
        recovered = CCStream(fixed_key, fixed_nonce).decrypt(ct)
        assert recovered == pt

    def test_exactly_one_block(self, fixed_key, fixed_nonce):
        pt = os.urandom(64)
        ct = CCStream(fixed_key, fixed_nonce).encrypt(pt)
        recovered = CCStream(fixed_key, fixed_nonce).decrypt(ct)
        assert recovered == pt

    def test_multi_block(self, fixed_key, fixed_nonce):
        pt = os.urandom(1000)
        ct = CCStream(fixed_key, fixed_nonce).encrypt(pt)
        recovered = CCStream(fixed_key, fixed_nonce).decrypt(ct)
        assert recovered == pt

    def test_large_message(self, fixed_key, fixed_nonce):
        pt = os.urandom(100_000)
        ct = CCStream(fixed_key, fixed_nonce).encrypt(pt)
        recovered = CCStream(fixed_key, fixed_nonce).decrypt(ct)
        assert recovered == pt


class TestDeterminism:
    def test_same_key_nonce_same_output(self, fixed_key, fixed_nonce):
        pt = b"Determinism test"
        c1 = CCStream(fixed_key, fixed_nonce).encrypt(pt)
        c2 = CCStream(fixed_key, fixed_nonce).encrypt(pt)
        assert c1 == c2

    def test_same_keystream(self, fixed_key, fixed_nonce):
        ks1 = CCStream(fixed_key, fixed_nonce).keystream(256)
        ks2 = CCStream(fixed_key, fixed_nonce).keystream(256)
        assert ks1 == ks2


class TestDifferentiation:
    def test_different_keys(self, fixed_nonce):
        pt = b"Same plaintext"
        c1 = CCStream(os.urandom(32), fixed_nonce).encrypt(pt)
        c2 = CCStream(os.urandom(32), fixed_nonce).encrypt(pt)
        assert c1 != c2

    def test_different_nonces(self, fixed_key):
        pt = b"Same plaintext"
        c1 = CCStream(fixed_key, os.urandom(12)).encrypt(pt)
        c2 = CCStream(fixed_key, os.urandom(12)).encrypt(pt)
        assert c1 != c2

    def test_ciphertext_differs_from_plaintext(self, fixed_key, fixed_nonce):
        pt = b"A" * 100
        ct = CCStream(fixed_key, fixed_nonce).encrypt(pt)
        assert ct != pt

    def test_ciphertext_length_equals_plaintext(self, fixed_key, fixed_nonce):
        for length in [1, 13, 64, 65, 128, 255, 1000]:
            pt = os.urandom(length)
            ct = CCStream(fixed_key, fixed_nonce).encrypt(pt)
            assert len(ct) == length


class TestStreamingEncryption:
    """Verify the BUG FIX: successive encrypt() calls advance the counter."""

    def test_streaming_matches_single_shot(self, fixed_key, fixed_nonce):
        part_a = b"First half of the message..."
        part_b = b"Second half of the message!"
        full = part_a + part_b

        # Single-shot
        ct_full = CCStream(fixed_key, fixed_nonce).encrypt(full)

        # Streaming
        enc = CCStream(fixed_key, fixed_nonce)
        ct_a = enc.encrypt(part_a)
        ct_b = enc.encrypt(part_b)

        assert ct_a + ct_b == ct_full

    def test_streaming_decrypt(self, fixed_key, fixed_nonce):
        part_a = b"AAAA"
        part_b = b"BBBB"

        enc = CCStream(fixed_key, fixed_nonce)
        ct_a = enc.encrypt(part_a)
        ct_b = enc.encrypt(part_b)

        dec = CCStream(fixed_key, fixed_nonce)
        rec_a = dec.decrypt(ct_a)
        rec_b = dec.decrypt(ct_b)

        assert rec_a == part_a
        assert rec_b == part_b

    def test_no_keystream_reuse(self, fixed_key, fixed_nonce):
        """Two consecutive encrypt calls must NOT produce the same keystream."""
        enc = CCStream(fixed_key, fixed_nonce)
        ct1 = enc.encrypt(b"\x00" * 64)
        ct2 = enc.encrypt(b"\x00" * 64)
        # ct1 and ct2 are the raw keystream bytes (XOR with zeros).
        # They MUST differ.
        assert ct1 != ct2

    def test_streaming_across_block_boundary(self, fixed_key, fixed_nonce):
        """Streaming with chunks that don't align to 64-byte blocks."""
        full_pt = os.urandom(200)

        ct_full = CCStream(fixed_key, fixed_nonce).encrypt(full_pt)

        enc = CCStream(fixed_key, fixed_nonce)
        ct_parts = b""
        for chunk_size in [10, 50, 7, 64, 33, 36]:
            offset = len(ct_parts)
            ct_parts += enc.encrypt(full_pt[offset : offset + chunk_size])

        assert ct_parts == ct_full


class TestReset:
    def test_reset_restarts_keystream(self, fixed_key, fixed_nonce):
        enc = CCStream(fixed_key, fixed_nonce)
        ct1 = enc.encrypt(b"Hello")

        enc.reset()
        ct2 = enc.encrypt(b"Hello")

        assert ct1 == ct2


class TestKeyNonceGeneration:
    def test_generate_key_length(self):
        assert len(CCStream.generate_key()) == 32

    def test_generate_nonce_length(self):
        assert len(CCStream.generate_nonce()) == 12

    def test_keys_unique(self):
        k1 = CCStream.generate_key()
        k2 = CCStream.generate_key()
        assert k1 != k2

    def test_nonces_unique(self):
        n1 = CCStream.generate_nonce()
        n2 = CCStream.generate_nonce()
        assert n1 != n2


class TestBitFrequency:
    def test_keystream_bit_balance(self, fixed_key, fixed_nonce):
        """Keystream bits should be roughly 50% ones."""
        ks = CCStream(fixed_key, fixed_nonce).keystream(4096)
        ones = sum(bin(b).count('1') for b in ks)
        total = len(ks) * 8
        ratio = ones / total
        assert 0.45 < ratio < 0.55, f"Bit ratio {ratio:.4f} outside [0.45, 0.55]"


class TestEdgeCases:
    def test_counter_zero(self, fixed_key, fixed_nonce):
        # Should work without error
        CCStream(fixed_key, fixed_nonce, counter=0)

    def test_counter_nonzero(self, fixed_key, fixed_nonce):
        c0 = CCStream(fixed_key, fixed_nonce, counter=0).keystream(64)
        c1 = CCStream(fixed_key, fixed_nonce, counter=1).keystream(64)
        assert c0 != c1

    def test_invalid_key(self, fixed_nonce):
        with pytest.raises((TypeError, ValueError)):
            CCStream(b"short", fixed_nonce)

    def test_invalid_nonce(self, fixed_key):
        with pytest.raises((TypeError, ValueError)):
            CCStream(fixed_key, b"short")
