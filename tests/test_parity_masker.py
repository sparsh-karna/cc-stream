"""Tests for Module 4: Parity Extraction and Masking."""

import os
import pytest
from cc_stream.parity_masker import generate_matrix, mask


class TestParityMasker:
    def test_matrix_dimensions(self):
        seed = os.urandom(32)
        R = generate_matrix(seed, m=128, T=384)
        assert len(R) == 128
        row_bytes = (384 + 7) // 8  # 48 bytes per row
        assert all(len(row) == row_bytes for row in R)

    def test_matrix_deterministic(self):
        seed = os.urandom(32)
        R1 = generate_matrix(seed, m=128, T=384)
        R2 = generate_matrix(seed, m=128, T=384)
        assert R1 == R2

    def test_mask_output_length(self):
        seed = os.urandom(32)
        R = generate_matrix(seed, m=128, T=384)
        parity = [1, 0] * 192  # 384 bits
        pi = mask(parity, R, m=128)
        assert len(pi) == 128

    def test_mask_output_binary(self):
        seed = os.urandom(32)
        R = generate_matrix(seed, m=128, T=384)
        parity = [1, 0, 1, 1] * 96  # 384 bits
        pi = mask(parity, R, m=128)
        assert all(b in (0, 1) for b in pi)

    def test_mask_deterministic(self):
        seed = os.urandom(32)
        R = generate_matrix(seed, m=128, T=384)
        parity = [1, 0, 1] * 128  # 384 bits
        pi1 = mask(parity, R, m=128)
        pi2 = mask(parity, R, m=128)
        assert pi1 == pi2

    def test_different_parity_different_mask(self):
        seed = os.urandom(32)
        R = generate_matrix(seed, m=128, T=384)
        p1 = [1] * 384
        p2 = [0] * 384
        pi1 = mask(p1, R, m=128)
        pi2 = mask(p2, R, m=128)
        # All-zero parity should produce all-zero pi (no bits set in AND)
        assert pi2 == [0] * 128
        assert pi1 != pi2
