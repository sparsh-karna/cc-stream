# Module 7 — Encryption

Stateless XOR mixing of plaintext or ciphertext with the keystream.

```
C[i] = P[i] ⊕ Keystream[i]
```

Because XOR is its own inverse, the same function handles both
encryption and decryption — a fundamental property of stream ciphers.

---

## Usage

```python
from cc_stream.encryption import xor_bytes

keystream  = b"\x39\x59\xc4\xce..."
plaintext  = b"HELLO WORLD"
ciphertext = xor_bytes(plaintext, keystream)

recovered  = xor_bytes(ciphertext, keystream)
assert recovered == plaintext
```

---

## API Reference

::: cc_stream.encryption
    options:
      show_source: true
      heading_level: 3
