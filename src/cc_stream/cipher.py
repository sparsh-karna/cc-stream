"""
Module 8: Initialization and Control Module (Main API)
=======================================================
CC-Stream: Collatz-ChaCha Hybrid Stream Cipher

API-compatible with ChaCha20 (RFC 8439).
Drop-in replacement for ChaCha20 in TLS, SSH, VPN deployments.

Usage:
    cipher = CCStream(key, nonce)
    ciphertext = cipher.encrypt(plaintext)
    plaintext  = cipher.decrypt(ciphertext)

Streaming usage (counter advances between calls):
    cipher = CCStream(key, nonce)
    c1 = cipher.encrypt(part1)
    c2 = cipher.encrypt(part2)   # continues from where c1 left off
"""

import os
from typing import List

from cc_stream.input_module import validate
from cc_stream.key_schedule import build as build_key_schedule
from cc_stream.chacha20_core import (
    initialize_state,
    keystream as chacha_keystream,
    _COUNTER_IDX,
    _MASK32,
)
from cc_stream.encryption import xor_bytes
from cc_stream.salt_generator import T_DEFAULT, M_DEFAULT


class CCStream:
    """
    CC-Stream: Collatz-ChaCha Hybrid Stream Cipher.

    Combines a Collatz-based key schedule with a standard ChaCha20 core
    for defense-in-depth post-quantum security.

    Args:
        key:     32-byte (256-bit) secret key.
        nonce:   12-byte (96-bit) unique nonce.
        counter: initial 32-bit block counter (default 0).
        T:       Collatz iteration count (default 384).
        m:       parity constraint count (default 128).
    """

    BLOCK_SIZE = 64  # ChaCha20 block size in bytes

    def __init__(
        self,
        key: bytes,
        nonce: bytes,
        counter: int = 0,
        T: int = T_DEFAULT,
        m: int = M_DEFAULT,
    ):
        validate(key, nonce, counter)

        self._key = key
        self._nonce = nonce
        self._initial_counter = counter
        self._T = T
        self._m = m

        # Build the Collatz-derived ChaCha20 initial state
        cc_constants, ck_augmented, nonce_words = build_key_schedule(
            key, nonce, counter, T, m
        )
        self._state = initialize_state(cc_constants, ck_augmented, nonce_words)

        # Track how many keystream bytes have been consumed so the counter
        # advances correctly across multiple encrypt()/decrypt() calls.
        # BUG FIX: original implementation restarted from counter 0 on
        # every call, causing keystream reuse.
        self._bytes_used = 0

    @property
    def state(self) -> List[int]:
        """Return a copy of the current internal state (for inspection)."""
        return list(self._state)

    def _current_state(self) -> List[int]:
        """
        Return a state copy with counter advanced by the number of
        64-byte blocks already consumed.
        """
        blocks_used = self._bytes_used // self.BLOCK_SIZE
        s = list(self._state)
        s[_COUNTER_IDX] = (s[_COUNTER_IDX] + blocks_used) & _MASK32
        return s

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext.

        Successive calls continue the keystream (counter advances).
        """
        if not plaintext:
            return b''

        # Determine offset within the current 64-byte block
        block_offset = self._bytes_used % self.BLOCK_SIZE
        needed = len(plaintext) + block_offset

        # Generate keystream from current position
        ks_full = chacha_keystream(self._current_state(), needed)

        # Slice off the already-consumed prefix within the partial block
        ks = ks_full[block_offset : block_offset + len(plaintext)]

        self._bytes_used += len(plaintext)

        return xor_bytes(plaintext, ks)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext.

        Identical to encrypt() (stream cipher XOR property).
        """
        return self.encrypt(ciphertext)

    def keystream(self, length: int) -> bytes:
        """
        Generate raw keystream bytes (advances internal counter).
        """
        if length <= 0:
            return b''

        block_offset = self._bytes_used % self.BLOCK_SIZE
        needed = length + block_offset
        ks_full = chacha_keystream(self._current_state(), needed)
        ks = ks_full[block_offset : block_offset + length]
        self._bytes_used += length
        return ks

    def reset(self) -> None:
        """Reset to initial state (counter = 0, no bytes consumed)."""
        self._bytes_used = 0

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically random 256-bit key."""
        return os.urandom(32)

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a cryptographically random 96-bit nonce."""
        return os.urandom(12)
