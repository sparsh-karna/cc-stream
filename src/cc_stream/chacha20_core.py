"""
Module 6: ChaCha20 Core Stream Cipher Module
==============================================
Standard ChaCha20 core -- 20 rounds of ARX (Add-Rotate-XOR) operations
as specified in RFC 8439.

The round function is UNCHANGED from the standard; only the initial
state fed into it differs (Collatz-derived constants and augmented key
instead of the fixed "expand 32-byte k" constants).

This preserves 18 years of ChaCha20 cryptanalysis.
"""

import struct
from typing import List, Tuple

_MASK32: int = 0xFFFFFFFF
_COUNTER_IDX: int = 12  # position of block counter in 16-word state
_BLOCK_BYTES: int = 64  # 16 words x 4 bytes
_ROUNDS: int = 20       # 20 rounds (10 double-rounds)


def _rotate_left(v: int, n: int) -> int:
    """32-bit left rotation."""
    return ((v << n) | (v >> (32 - n))) & _MASK32


def _quarter_round(
    a: int, b: int, c: int, d: int
) -> Tuple[int, int, int, int]:
    """
    ChaCha20 quarter-round (RFC 8439 section 2.1):

        a += b;  d ^= a;  d <<<= 16
        c += d;  b ^= c;  b <<<= 12
        a += b;  d ^= a;  d <<<= 8
        c += d;  b ^= c;  b <<<= 7
    """
    a = (a + b) & _MASK32; d ^= a; d = _rotate_left(d, 16)
    c = (c + d) & _MASK32; b ^= c; b = _rotate_left(b, 12)
    a = (a + b) & _MASK32; d ^= a; d = _rotate_left(d, 8)
    c = (c + d) & _MASK32; b ^= c; b = _rotate_left(b, 7)
    return a, b, c, d


def block(state: List[int]) -> bytes:
    """
    Compute one 64-byte ChaCha20 keystream block.

    Performs 10 double-rounds (= 20 rounds), then adds the original
    state back (mod 2^32) and serialises as little-endian bytes.

    Args:
        state: 16-element list of 32-bit words (not mutated).

    Returns:
        64-byte keystream block.
    """
    s = list(state)  # working copy

    for _ in range(_ROUNDS // 2):
        # Column rounds
        s[0], s[4], s[8],  s[12] = _quarter_round(s[0], s[4], s[8],  s[12])
        s[1], s[5], s[9],  s[13] = _quarter_round(s[1], s[5], s[9],  s[13])
        s[2], s[6], s[10], s[14] = _quarter_round(s[2], s[6], s[10], s[14])
        s[3], s[7], s[11], s[15] = _quarter_round(s[3], s[7], s[11], s[15])

        # Diagonal rounds
        s[0], s[5], s[10], s[15] = _quarter_round(s[0], s[5], s[10], s[15])
        s[1], s[6], s[11], s[12] = _quarter_round(s[1], s[6], s[11], s[12])
        s[2], s[7], s[8],  s[13] = _quarter_round(s[2], s[7], s[8],  s[13])
        s[3], s[4], s[9],  s[14] = _quarter_round(s[3], s[4], s[9],  s[14])

    # Add initial state back (mod 2^32)
    output = [(s[i] + state[i]) & _MASK32 for i in range(16)]

    return struct.pack('<16I', *output)


def initialize_state(
    constants: List[int],
    key_words: List[int],
    nonce_words: List[int],
) -> List[int]:
    """
    Build the 4x4 ChaCha20 initial state (16 words):

        +----------------------------------+
        | cc0   cc1   cc2   cc3            |  Row 0: constants
        | ck0   ck1   ck2   ck3            |  Row 1: augmented key
        | ck4   ck5   ck6   ck7            |  Row 2: augmented key
        | ctr   n0    n1    n2             |  Row 3: counter + nonce
        +----------------------------------+

    Args:
        constants:   4 words (Collatz-derived).
        key_words:   8 words (augmented key).
        nonce_words: 4 words [counter, n0, n1, n2].

    Returns:
        16-element list of 32-bit words.
    """
    if len(constants) != 4:
        raise ValueError(f"Expected 4 constant words, got {len(constants)}")
    if len(key_words) != 8:
        raise ValueError(f"Expected 8 key words, got {len(key_words)}")
    if len(nonce_words) != 4:
        raise ValueError(f"Expected 4 nonce words, got {len(nonce_words)}")

    return list(constants) + list(key_words) + list(nonce_words)


def keystream(state: List[int], length: int) -> bytes:
    """
    Generate ``length`` bytes of keystream.

    Increments the block counter (state[12]) for each successive
    64-byte block.

    Args:
        state:  16-word initial state (NOT mutated; a copy is used).
        length: desired keystream length in bytes.

    Returns:
        Exactly ``length`` bytes of keystream.
    """
    if length <= 0:
        return b''

    ks = bytearray()
    s = list(state)

    while len(ks) < length:
        ks.extend(block(s))
        s[_COUNTER_IDX] = (s[_COUNTER_IDX] + 1) & _MASK32

    return bytes(ks[:length])
