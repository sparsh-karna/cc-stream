"""
Module 1: Key and Nonce Input Module
=====================================
Validates and converts external inputs (key, nonce, counter) into the
internal word representations used by CC-Stream.

Ensures API compatibility with ChaCha20 (RFC 8439):
  - Key:   256-bit (32 bytes)
  - Nonce:  96-bit (12 bytes)
  - Counter: 32-bit unsigned integer
"""

import struct
from typing import List

KEY_SIZE: int = 32       # 256 bits
NONCE_SIZE: int = 12     # 96 bits
MAX_COUNTER: int = 2**32 - 1


def validate(key: bytes, nonce: bytes, counter: int = 0) -> None:
    """
    Validate key, nonce, and counter formats.

    Raises:
        TypeError:  if key or nonce is not bytes.
        ValueError: if lengths or counter range are wrong.
    """
    if not isinstance(key, bytes):
        raise TypeError(f"Key must be bytes, got {type(key).__name__}")
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"Key must be exactly {KEY_SIZE} bytes (256-bit), got {len(key)}"
        )
    if not isinstance(nonce, bytes):
        raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"Nonce must be exactly {NONCE_SIZE} bytes (96-bit), got {len(nonce)}"
        )
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise TypeError(f"Counter must be int, got {type(counter).__name__}")
    if not (0 <= counter <= MAX_COUNTER):
        raise ValueError(
            f"Counter must be a 32-bit unsigned integer [0, {MAX_COUNTER}], "
            f"got {counter}"
        )


def key_to_words(key: bytes) -> List[int]:
    """Convert 32-byte key into 8 little-endian 32-bit words."""
    return list(struct.unpack('<8I', key))


def nonce_to_words(nonce: bytes) -> List[int]:
    """Convert 12-byte nonce into 3 little-endian 32-bit words."""
    return list(struct.unpack('<3I', nonce))
