"""Tests for Module 3: Collatz Iteration Engine."""

import os
import pytest
from cc_stream.collatz_engine import iterate


class TestCollatzEngine:
    def test_output_types(self):
        seed = os.urandom(32)
        salt = os.urandom(64)
        x_T, parity = iterate(seed, salt, T=100)
        assert isinstance(x_T, int)
        assert isinstance(parity, list)

    def test_parity_length(self):
        seed = os.urandom(32)
        salt = os.urandom(64)
        _, parity = iterate(seed, salt, T=384)
        assert len(parity) == 384

    def test_parity_values_binary(self):
        seed = os.urandom(32)
        salt = os.urandom(64)
        _, parity = iterate(seed, salt, T=384)
        assert all(b in (0, 1) for b in parity)

    def test_deterministic(self):
        seed = os.urandom(32)
        salt = os.urandom(64)
        r1 = iterate(seed, salt, T=384)
        r2 = iterate(seed, salt, T=384)
        assert r1 == r2

    def test_seed_forced_odd(self):
        """Even seed bytes should still produce a trajectory starting odd."""
        seed = b"\x00" * 32
        salt = os.urandom(64)
        _, parity = iterate(seed, salt, T=10)
        # x starts as seed | 1, so first bit must be 1 (odd)
        assert parity[0] == 1

    def test_bounded_512_bits(self):
        seed = os.urandom(32)
        salt = os.urandom(64)
        x_T, _ = iterate(seed, salt, T=384)
        assert x_T < 2**512

    def test_different_salts_different_trajectories(self):
        seed = os.urandom(32)
        s1 = os.urandom(64)
        s2 = os.urandom(64)
        _, p1 = iterate(seed, s1, T=384)
        _, p2 = iterate(seed, s2, T=384)
        # Extremely unlikely to collide
        assert p1 != p2
