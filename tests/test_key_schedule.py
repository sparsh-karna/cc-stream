"""Tests for Module 5: Collatz-Based Key Schedule Generator."""

import os
import pytest
from cc_stream.key_schedule import build, trajectory_to_words, augment_key


class TestKeyScheduleBuild:
    def test_output_shapes(self, fixed_key, fixed_nonce):
        cc, ck, nw = build(fixed_key, fixed_nonce)
        assert len(cc) == 4   # constants
        assert len(ck) == 8   # augmented key
        assert len(nw) == 4   # counter + nonce

    def test_all_32bit_words(self, fixed_key, fixed_nonce):
        cc, ck, nw = build(fixed_key, fixed_nonce)
        for w in cc + ck + nw:
            assert 0 <= w < 2**32

    def test_deterministic(self, fixed_key, fixed_nonce):
        r1 = build(fixed_key, fixed_nonce)
        r2 = build(fixed_key, fixed_nonce)
        assert r1 == r2

    def test_different_keys(self, fixed_nonce):
        r1 = build(os.urandom(32), fixed_nonce)
        r2 = build(os.urandom(32), fixed_nonce)
        assert r1[0] != r2[0]  # constants differ

    def test_different_nonces(self, fixed_key):
        r1 = build(fixed_key, os.urandom(12))
        r2 = build(fixed_key, os.urandom(12))
        assert r1[0] != r2[0]

    def test_counter_in_nonce_words(self, fixed_key, fixed_nonce):
        _, _, nw = build(fixed_key, fixed_nonce, counter=42)
        assert nw[0] == 42  # first word is the counter

    def test_counter_affects_output(self, fixed_key, fixed_nonce):
        r1 = build(fixed_key, fixed_nonce, counter=0)
        r2 = build(fixed_key, fixed_nonce, counter=1)
        # Constants or key should differ because counter is in seed+salt
        assert r1[0] != r2[0] or r1[1] != r2[1]

    def test_constants_not_standard_chacha(self, fixed_key, fixed_nonce):
        """CC-Stream constants must differ from ChaCha20's fixed constants."""
        CHACHA_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        cc, _, _ = build(fixed_key, fixed_nonce)
        assert cc != CHACHA_CONSTANTS


class TestTrajectoryToWords:
    def test_uses_x_T(self):
        """Changing x_T should change the constants."""
        parity = [1, 0] * 192
        pi = [0] * 128
        c1, _ = trajectory_to_words(parity, x_T=12345, pi=pi)
        c2, _ = trajectory_to_words(parity, x_T=99999, pi=pi)
        assert c1 != c2

    def test_uses_pi(self):
        """Changing pi should change the round keys."""
        parity = [1, 0] * 192
        pi_a = [0] * 128
        pi_b = [1] * 128
        _, rk1 = trajectory_to_words(parity, x_T=1, pi=pi_a)
        _, rk2 = trajectory_to_words(parity, x_T=1, pi=pi_b)
        assert rk1 != rk2


class TestAugmentKey:
    def test_xor_identity(self):
        key_words = [0] * 8
        rk = [0xDEADBEEF] * 8
        result = augment_key(key_words, rk)
        assert result == rk

    def test_xor_round_trip(self):
        key_words = [0x12345678] * 8
        rk = [0xDEADBEEF] * 8
        augmented = augment_key(key_words, rk)
        # XOR again with rk should recover original key words
        recovered = [a ^ r for a, r in zip(augmented, rk)]
        assert recovered == key_words
