"""Shared fixtures for CC-Stream tests."""

import os
import pytest


@pytest.fixture
def fixed_key() -> bytes:
    """A deterministic 256-bit key for reproducible tests."""
    return bytes.fromhex(
        "1a2b3c4d5e6f70819a0b1c2d3e4f5061"
        "71829304a5b6c7d8e9f0011223344556"
    )


@pytest.fixture
def fixed_nonce() -> bytes:
    """A deterministic 96-bit nonce for reproducible tests."""
    return bytes.fromhex("a1b2c3d4e5f60718293a4b5c")


@pytest.fixture
def random_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def random_nonce() -> bytes:
    return os.urandom(12)
