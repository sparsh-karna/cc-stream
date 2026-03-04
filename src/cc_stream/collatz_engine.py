"""
Module 3: Collatz Iteration Engine
====================================
Performs a fixed number (T) of salted Collatz-style iterations and
records the full parity sequence.

Iteration rule:
    Even:  x_{i+1} = x_i >> 1
    Odd:   x_{i+1} = (a * x_i + 1) >> 1
           where a in {3, 5} is selected by the secret salt bit for step i.

Design invariants:
    - Exactly T iterations are always performed (no early exit) to
      prevent timing side-channels.
    - Intermediate values are bounded to 512-bit integers to avoid
      unbounded growth.
    - The seed is forced odd to guarantee a non-trivial first step.
"""

from typing import List, Tuple

_MAX_BITS: int = 512
_BOUND: int = 2 ** _MAX_BITS


def iterate(seed: bytes, salt: bytes, T: int) -> Tuple[int, List[int]]:
    """
    Run T salted Collatz iterations.

    Args:
        seed: 32-byte initial value (derived from key + nonce + counter).
        salt: 64-byte salt controlling multiplier selection.
        T:    exact number of iterations.

    Returns:
        x_T:        final integer value after T steps.
        parity_seq: list of T parity bits [b_0, b_1, ..., b_{T-1}].
    """
    # Convert seed to a large integer; force odd for richer trajectory
    x = int.from_bytes(seed, 'big') | 1

    parity_seq: List[int] = []
    salt_len = len(salt)

    for i in range(T):
        parity_bit = x & 1
        parity_seq.append(parity_bit)

        if parity_bit == 0:
            x = x >> 1
        else:
            # Salt-controlled multiplier selection {3, 5}
            salt_byte = salt[i % salt_len]
            salt_bit = (salt_byte >> (i % 8)) & 1
            multiplier = 5 if salt_bit else 3
            x = (multiplier * x + 1) >> 1

        # Bound to 512 bits to prevent unbounded growth
        x = x % _BOUND

    return x, parity_seq
