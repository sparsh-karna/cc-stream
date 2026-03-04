"""
CC-Stream: Collatz-ChaCha Hybrid Stream Cipher
================================================
A defense-in-depth post-quantum stream cipher combining:
  - Collatz-based key schedule (quantum-resistant layer)
  - ChaCha20 core (classical security layer)

Architecture:
  Key + Nonce -> SHA3-256 Seed -> Salted Collatz (384 iterations)
              -> Trajectory + x_T + pi Extraction
              -> Modified ChaCha20 State -> Keystream -> XOR -> Ciphertext

Quick start:
    from cc_stream import CCStream

    key   = CCStream.generate_key()
    nonce = CCStream.generate_nonce()

    cipher = CCStream(key, nonce)
    ciphertext = cipher.encrypt(b"Hello, world!")

    decipher = CCStream(key, nonce)
    plaintext = decipher.decrypt(ciphertext)
"""

__version__ = "1.0.0"

from cc_stream.cipher import CCStream
from cc_stream.input_module import validate, key_to_words, nonce_to_words
from cc_stream.salt_generator import generate as generate_salt, T_DEFAULT, M_DEFAULT
from cc_stream.collatz_engine import iterate as collatz_iterate
from cc_stream.parity_masker import generate_matrix, mask as parity_mask
from cc_stream.key_schedule import build as build_key_schedule
from cc_stream.chacha20_core import (
    block as chacha_block,
    keystream as chacha_keystream,
    initialize_state,
)
from cc_stream.encryption import xor_bytes

__all__ = [
    "CCStream",
    "__version__",
    # Module-level functions for advanced usage / testing
    "validate",
    "key_to_words",
    "nonce_to_words",
    "generate_salt",
    "collatz_iterate",
    "generate_matrix",
    "parity_mask",
    "build_key_schedule",
    "chacha_block",
    "chacha_keystream",
    "initialize_state",
    "xor_bytes",
    "T_DEFAULT",
    "M_DEFAULT",
]
