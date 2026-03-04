"""Tests for Module 2: Salt Generator."""

import pytest
from cc_stream.salt_generator import generate, T_DEFAULT, M_DEFAULT


class TestSaltGenerator:
    def test_output_types(self, fixed_key, fixed_nonce):
        salt, T, m = generate(fixed_key, fixed_nonce)
        assert isinstance(salt, bytes)
        assert isinstance(T, int)
        assert isinstance(m, int)

    def test_salt_length(self, fixed_key, fixed_nonce):
        salt, _, _ = generate(fixed_key, fixed_nonce)
        assert len(salt) == 64

    def test_default_parameters(self, fixed_key, fixed_nonce):
        _, T, m = generate(fixed_key, fixed_nonce)
        assert T == T_DEFAULT == 384
        assert m == M_DEFAULT == 128

    def test_deterministic(self, fixed_key, fixed_nonce):
        r1 = generate(fixed_key, fixed_nonce)
        r2 = generate(fixed_key, fixed_nonce)
        assert r1 == r2

    def test_different_keys_different_salt(self, fixed_nonce):
        import os
        s1, _, _ = generate(os.urandom(32), fixed_nonce)
        s2, _, _ = generate(os.urandom(32), fixed_nonce)
        assert s1 != s2

    def test_different_counters_different_salt(self, fixed_key, fixed_nonce):
        s1, _, _ = generate(fixed_key, fixed_nonce, counter=0)
        s2, _, _ = generate(fixed_key, fixed_nonce, counter=1)
        assert s1 != s2

    def test_custom_T_m(self, fixed_key, fixed_nonce):
        _, T, m = generate(fixed_key, fixed_nonce, T=512, m=128)
        assert T == 512
        assert m == 128

    def test_security_margin_violation(self, fixed_key, fixed_nonce):
        with pytest.raises(ValueError, match="Security parameter violation"):
            generate(fixed_key, fixed_nonce, T=300, m=128)
