"""
Module 5: Collatz-Based Key Schedule Generator
================================================
Converts the outputs of the Collatz subsystem -- final state x_T and
masked parity vector pi -- into a modified ChaCha20 initial state.

Derivation pipeline:
    1. Extract 4 constants + 8 round-key words from the raw parity
       sequence (trajectory partitioning).
    2. Mix x_T into the constants via SHA3 hashing (final-state hardening).
    3. Mix pi  into the round keys via SHA3 hashing (PSC-QOWF hardening).
    4. Augment original key: ck_i = k_i XOR rk_i.

This ensures BOTH the Collatz trajectory structure AND the PSC-QOWF
masked sketch contribute to the ChaCha20 state, matching the design
specification.

BUG FIXES applied vs. original implementation:
    - x_T is now mixed into constants (was accepted but unused).
    - pi is now mixed into round keys (was computed but discarded).
    - Counter is included in the Collatz seed derivation.
    - T and m parameters are properly forwarded.
"""

import hashlib
import struct
from typing import List, Tuple

from cc_stream.input_module import validate, key_to_words, nonce_to_words
from cc_stream.salt_generator import generate as generate_salt, T_DEFAULT, M_DEFAULT
from cc_stream.collatz_engine import iterate as collatz_iterate
from cc_stream.parity_masker import generate_matrix, mask


def _parity_to_bytes(parity_seq: List[int]) -> bytes:
    """Pack a parity bit sequence into bytes (LSB-first within each byte)."""
    num_bytes = (len(parity_seq) + 7) // 8
    buf = bytearray(num_bytes)
    for i, bit in enumerate(parity_seq):
        if bit:
            buf[i // 8] |= (1 << (i % 8))
    return bytes(buf)


def trajectory_to_words(
    parity_seq: List[int],
    x_T: int,
    pi: List[int],
) -> Tuple[List[int], List[int]]:
    """
    Convert Collatz outputs into 32-bit words for ChaCha20 state.

    Trajectory partitioning:
        Bits   0-127 (128 bits) -> 4 base constant words
        Bits 128-383 (256 bits) -> 8 base round-key words

    Then:
        constants  ^= SHA3-256(x_T) unpacked as 4 words
        round_keys ^= SHA3-256(pi)  unpacked as 8 words

    Args:
        parity_seq: T-element parity bit sequence.
        x_T:        final Collatz value after T iterations.
        pi:         m-element masked parity sketch.

    Returns:
        constants:  4 x 32-bit words (replace ChaCha20 "expand 32-byte k").
        round_keys: 8 x 32-bit words (for key augmentation).
    """
    traj_bytes = _parity_to_bytes(parity_seq)

    # --- Base extraction from trajectory ---
    # Bits 0-127 -> 4 constant words (16 bytes)
    constants = list(struct.unpack('<4I', traj_bytes[0:16]))

    # Bits 128-383 -> 8 round-key words (32 bytes)
    round_keys = list(struct.unpack('<8I', traj_bytes[16:48]))

    # --- Mix in x_T (final Collatz state) ---
    # Hash x_T to 16 bytes -> 4 words, XOR into constants
    x_T_byte_len = max((x_T.bit_length() + 7) // 8, 1)
    x_T_bytes = x_T.to_bytes(x_T_byte_len, 'big')
    x_T_hash = hashlib.sha3_256(b"collatz_final_v1" + x_T_bytes).digest()
    x_T_words = list(struct.unpack('<4I', x_T_hash[:16]))
    constants = [c ^ xw for c, xw in zip(constants, x_T_words)]

    # --- Mix in pi (masked parity sketch, PSC-QOWF output) ---
    # Pack pi bits, hash to 32 bytes -> 8 words, XOR into round keys
    pi_bytes = _parity_to_bytes(pi)
    pi_hash = hashlib.sha3_256(b"parity_mask_v1" + pi_bytes).digest()
    pi_words = list(struct.unpack('<8I', pi_hash[:32]))
    round_keys = [rk ^ pw for rk, pw in zip(round_keys, pi_words)]

    return constants, round_keys


def augment_key(key_words: List[int], round_keys: List[int]) -> List[int]:
    """
    XOR original key words with Collatz-derived round keys.

        ck_i = k_i XOR rk_i   for i = 0..7
    """
    return [k ^ rk for k, rk in zip(key_words, round_keys)]


def build(
    key: bytes,
    nonce: bytes,
    counter: int = 0,
    T: int = T_DEFAULT,
    m: int = M_DEFAULT,
) -> Tuple[List[int], List[int], List[int]]:
    """
    Full Collatz key schedule pipeline.

    Args:
        key:     32-byte secret key.
        nonce:   12-byte nonce.
        counter: 32-bit block counter.
        T:       Collatz iteration count.
        m:       parity constraint count.

    Returns:
        cc_constants: 4 Collatz-derived constant words.
        ck_augmented: 8 augmented key words.
        nonce_words:  [counter, n0, n1, n2] (4 words).
    """
    # Step 1: Validate inputs
    validate(key, nonce, counter)

    # Step 2: Generate salt and parameters
    salt, T, m = generate_salt(key, nonce, counter, T, m)

    # Step 3: Derive Collatz seed via SHA3-256(key || nonce || counter)
    # BUG FIX: counter is now included in seed derivation
    ctr_bytes = struct.pack('<I', counter)
    collatz_seed = hashlib.sha3_256(key + nonce + ctr_bytes).digest()

    # Step 4: Run Collatz iteration engine
    x_T, parity_seq = collatz_iterate(collatz_seed, salt, T)

    # Step 5: Parity masking (PSC-QOWF layer)
    R = generate_matrix(collatz_seed, m, T)
    pi = mask(parity_seq, R, m)

    # Step 6: Extract constants and round keys from trajectory + x_T + pi
    # BUG FIX: x_T and pi are now mixed into the key schedule
    cc_constants, rk_words = trajectory_to_words(parity_seq, x_T, pi)

    # Step 7: Augment original key: ck_i = k_i XOR rk_i
    kw = key_to_words(key)
    ck_augmented = augment_key(kw, rk_words)

    # Step 8: Prepare nonce + counter words
    nw = [counter] + nonce_to_words(nonce)

    return cc_constants, ck_augmented, nw
