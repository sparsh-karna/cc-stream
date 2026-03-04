"""
Module 7: Keystream Mixing and Encryption Module
==================================================
XOR-based stream encryption / decryption.

    C[i] = P[i] XOR Keystream[i]    for each byte i

Since XOR is its own inverse, the same function handles both
encryption and decryption.
"""


def xor_bytes(data: bytes, keystream: bytes) -> bytes:
    """
    Bitwise XOR of *data* with *keystream*, byte by byte.

    Args:
        data:      plaintext or ciphertext bytes.
        keystream: keystream bytes (must be >= len(data)).

    Returns:
        XOR result, same length as *data*.

    Raises:
        ValueError: if keystream is shorter than data.
    """
    if len(keystream) < len(data):
        raise ValueError(
            f"Keystream too short: need {len(data)} bytes, got {len(keystream)}"
        )
    return bytes(d ^ k for d, k in zip(data, keystream))
