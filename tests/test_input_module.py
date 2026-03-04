"""Tests for Module 1: Key and Nonce Input."""

import pytest
from cc_stream.input_module import validate, key_to_words, nonce_to_words


class TestValidate:
    def test_valid_inputs(self, fixed_key, fixed_nonce):
        validate(fixed_key, fixed_nonce)  # should not raise

    def test_valid_with_counter(self, fixed_key, fixed_nonce):
        validate(fixed_key, fixed_nonce, 42)

    def test_key_wrong_type(self, fixed_nonce):
        with pytest.raises(TypeError, match="Key must be bytes"):
            validate("not bytes", fixed_nonce)

    def test_key_wrong_length(self, fixed_nonce):
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            validate(b"\x00" * 16, fixed_nonce)

    def test_nonce_wrong_type(self, fixed_key):
        with pytest.raises(TypeError, match="Nonce must be bytes"):
            validate(fixed_key, "not bytes")

    def test_nonce_wrong_length(self, fixed_key):
        with pytest.raises(ValueError, match="exactly 12 bytes"):
            validate(fixed_key, b"\x00" * 8)

    def test_counter_negative(self, fixed_key, fixed_nonce):
        with pytest.raises(ValueError, match="32-bit unsigned"):
            validate(fixed_key, fixed_nonce, -1)

    def test_counter_overflow(self, fixed_key, fixed_nonce):
        with pytest.raises(ValueError, match="32-bit unsigned"):
            validate(fixed_key, fixed_nonce, 2**32)

    def test_counter_bool_rejected(self, fixed_key, fixed_nonce):
        with pytest.raises(TypeError, match="Counter must be int"):
            validate(fixed_key, fixed_nonce, True)

    def test_counter_max(self, fixed_key, fixed_nonce):
        validate(fixed_key, fixed_nonce, 2**32 - 1)  # should not raise


class TestConversions:
    def test_key_to_words_length(self, fixed_key):
        words = key_to_words(fixed_key)
        assert len(words) == 8
        assert all(isinstance(w, int) for w in words)
        assert all(0 <= w < 2**32 for w in words)

    def test_nonce_to_words_length(self, fixed_nonce):
        words = nonce_to_words(fixed_nonce)
        assert len(words) == 3
        assert all(isinstance(w, int) for w in words)
        assert all(0 <= w < 2**32 for w in words)

    def test_key_round_trip(self, fixed_key):
        """key -> words -> bytes should reconstruct the original key."""
        import struct
        words = key_to_words(fixed_key)
        rebuilt = struct.pack('<8I', *words)
        assert rebuilt == fixed_key

    def test_nonce_round_trip(self, fixed_nonce):
        import struct
        words = nonce_to_words(fixed_nonce)
        rebuilt = struct.pack('<3I', *words)
        assert rebuilt == fixed_nonce
