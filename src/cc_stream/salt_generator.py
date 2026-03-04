"""
Module 2: Collatz Parameter and Salt Generator
================================================
Derives the internal salt vector and iteration parameters that control
the Collatz engine.

Uses SHA3-256 on (key || nonce || counter) for the base hash, then
extends via SHAKE-128 to produce a 64-byte salt vector controlling
per-step multiplier selection {3, 5}.

Security parameters (defaults):
    T = 384  Collatz iterations
    m = 128  parity constraints
    T - m = 256  ->  >=128-bit quantum security via Grover bound
"""

import hashlib
import struct
from typing import Tuple

T_DEFAULT: int = 384   # total Collatz iterations
M_DEFAULT: int = 128   # masked parity constraints
MIN_SECURITY_MARGIN: int = 256  # T - m must be >= this


def generate(
    key: bytes,
    nonce: bytes,
    counter: int = 0,
    T: int = T_DEFAULT,
    m: int = M_DEFAULT,
) -> Tuple[bytes, int, int]:
    """
    Derive salt and control parameters.

    Args:
        key:     32-byte secret key.
        nonce:   12-byte nonce.
        counter: 32-bit block counter.
        T:       number of Collatz iterations.
        m:       number of parity constraints.

    Returns:
        salt: 64-byte salt vector (controls multiplier selection).
        T:    iteration count.
        m:    constraint count.

    Raises:
        ValueError: if security margin T - m < 256.
    """
    if (T - m) < MIN_SECURITY_MARGIN:
        raise ValueError(
            f"Security parameter violation: T - m = {T - m}, "
            f"must be >= {MIN_SECURITY_MARGIN}"
        )

    # Deterministic constant-time derivation: SHA3-256(key || nonce || counter)
    ctr_bytes = struct.pack('<I', counter)
    base_hash = hashlib.sha3_256(key + nonce + ctr_bytes).digest()

    # Extend to 64 bytes via SHAKE-128 for per-step multiplier control
    salt = hashlib.shake_128(base_hash).digest(64)

    return salt, T, m
