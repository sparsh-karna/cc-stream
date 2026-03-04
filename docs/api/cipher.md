# CCStream — Main API

`CCStream` is the top-level cipher class and the only symbol most
application code needs to import.

---

## Overview

```python
from cc_stream import CCStream

key   = CCStream.generate_key()    # 32 random bytes
nonce = CCStream.generate_nonce()  # 12 random bytes

# Encrypt
enc = CCStream(key, nonce)
ct  = enc.encrypt(b"Hello, World!")

# Decrypt
dec = CCStream(key, nonce)
pt  = dec.decrypt(ct)             # → b"Hello, World!"
```

---

## Encryption is Streaming

Multiple calls to `encrypt()` on the **same instance** continue from
where the previous call left off — the block counter advances
automatically:

```python
enc = CCStream(key, nonce)
c1  = enc.encrypt(b"Part A ")
c2  = enc.encrypt(b"Part B")

# Identical to:
ref = CCStream(key, nonce)
assert c1 + c2 == ref.encrypt(b"Part A Part B")
```

This is safe because the internal `_bytes_used` counter prevents any
keystream byte from being reused across calls.

---

## Class Reference

::: cc_stream.cipher.CCStream
    options:
      show_source: true
      heading_level: 3
      members:
        - __init__
        - encrypt
        - decrypt
        - keystream
        - reset
        - state
        - generate_key
        - generate_nonce
