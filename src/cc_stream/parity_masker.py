"""
Module 4: Parity Extraction and Masking Module
================================================
Transforms the raw parity sequence b into a compressed, masked
representation inspired by PSC-QOWF:

    pi = R . b  (mod 2)

where R is an m x T binary matrix derived from the seed.

Security:
    Inverting pi requires an unstructured search over 2^(T-m) candidates
    classically, or 2^((T-m)/2) quantum Grover queries.

    With T=384, m=128: classical 2^256, quantum 2^128.

IMPORTANT: The raw parity sequence b is NEVER exposed directly.
Only the compressed sketch pi and the final value x_T leave this module.
"""

import hashlib
from typing import List

# Domain separation tag for matrix derivation
_MATRIX_DOMAIN_SEP = b"parity_matrix_v1"


def generate_matrix(seed: bytes, m: int, T: int) -> List[bytes]:
    """
    Generate a high-density m x T binary matrix R from seed.

    Each row is stored as a bytes object of length ceil(T/8) for
    efficient bit-level access during masking.

    Args:
        seed: 32-byte derivation seed.
        m:    number of rows (parity constraints).
        T:    number of columns (Collatz iterations).

    Returns:
        R: list of m byte-strings, each encoding T bits.
    """
    # Derive PRNG material via SHAKE-256
    prng_seed = hashlib.sha3_256(_MATRIX_DOMAIN_SEP + seed).digest()
    row_bytes = (T + 7) // 8
    total_bytes = m * row_bytes
    random_data = hashlib.shake_256(prng_seed).digest(total_bytes)

    # Slice into rows
    R: List[bytes] = []
    for i in range(m):
        start = i * row_bytes
        R.append(random_data[start : start + row_bytes])

    return R


def mask(parity_seq: List[int], R: List[bytes], m: int) -> List[int]:
    """
    Compute the compressed parity sketch: pi = R . b  (mod 2).

    Uses popcount on the AND of each row with the packed parity vector
    for efficiency instead of element-wise multiplication.

    Args:
        parity_seq: T-element list of {0, 1} parity bits.
        R:          m rows, each a bytes object of ceil(T/8) bytes.
        m:          number of constraints (rows).

    Returns:
        pi: m-element list of {0, 1} constraint bits.
    """
    # Pack parity_seq into a single integer for fast bitwise AND
    b_int = 0
    for i, bit in enumerate(parity_seq):
        if bit:
            b_int |= (1 << i)

    pi: List[int] = []
    for i in range(m):
        # Convert row bytes to integer (little-endian bit ordering)
        row_int = int.from_bytes(R[i], 'little')
        # Constraint = popcount(row AND b) mod 2
        pi.append(bin(row_int & b_int).count('1') % 2)

    return pi
