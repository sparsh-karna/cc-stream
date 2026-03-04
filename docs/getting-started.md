# Getting Started

## Installation

CC-Stream requires **Python 3.9+** and has no third-party runtime dependencies
(only the standard library `hashlib`, `struct`, and `os` modules).

=== "From source (editable)"

    ```bash
    git clone https://github.com/sparshkarna/cc-stream.git
    cd cc-stream
    pip install -e ".[dev]"
    ```

=== "Direct pip install"

    ```bash
    pip install cc-stream
    ```

---

## Key & Nonce Generation

Always generate cryptographically random keys and nonces:

```python
from cc_stream import CCStream

key   = CCStream.generate_key()    # os.urandom(32) — 256-bit
nonce = CCStream.generate_nonce()  # os.urandom(12) — 96-bit
```

!!! warning "Nonce reuse"
    Reusing the same `(key, nonce)` pair for two different plaintexts
    is a critical error in any stream cipher.  
    Always generate a **fresh nonce per message**.

---

## Encrypting a Message

```python
from cc_stream import CCStream

key   = CCStream.generate_key()
nonce = CCStream.generate_nonce()

cipher     = CCStream(key, nonce)
ciphertext = cipher.encrypt(b"Secret message")

print(ciphertext.hex())
# e.g. → 3a8fbc04e1d7a2...
```

---

## Decrypting

Create a **new** `CCStream` instance with the same key and nonce:

```python
decipher  = CCStream(key, nonce)
plaintext = decipher.decrypt(ciphertext)

print(plaintext)
# → b'Secret message'
```

---

## Streaming Encryption

For large data or incremental writes, call `encrypt()` multiple times on
the same instance. The internal block counter advances automatically:

```python
cipher = CCStream(key, nonce)

c1 = cipher.encrypt(b"chunk one ")
c2 = cipher.encrypt(b"chunk two ")
c3 = cipher.encrypt(b"chunk three")

# c1 + c2 + c3 is identical to encrypting the concatenation in one shot
```

!!! tip
    This is crucial for streaming protocols (e.g. TLS record layer) where
    the plaintext arrives in fragments.

---

## Custom Security Parameters

Increase `T` to raise the Collatz iteration count (and computational cost):

```python
# T=512, m=128 → T - m = 384 → 192-bit quantum security
cipher = CCStream(key, nonce, T=512, m=128)
```

The constraint `T - m >= 256` is enforced; violating it raises a
`ValueError`.

---

## Resetting a Cipher Instance

```python
cipher = CCStream(key, nonce)
ct1 = cipher.encrypt(b"first pass")

cipher.reset()            # rewind counter to 0
ct2 = cipher.encrypt(b"first pass")

assert ct1 == ct2         # same keystream from position 0
```

---

## Running the Test Suite

```bash
pytest tests/ -v
# 93 passed
```

---

## CLI Quick Reference

```bash
# Generate key + nonce
python -m cc_stream keygen

# Encrypt plain text inline
python -m cc_stream encrypt -k $KEY -n $NONCE --text "Hello"

# Decrypt from hex
python -m cc_stream decrypt -k $KEY -n $NONCE <hex_ciphertext>

# File mode
python -m cc_stream encrypt -k $KEY -n $NONCE -i msg.txt -o msg.enc
python -m cc_stream decrypt -k $KEY -n $NONCE -i msg.enc -o msg.txt

# Self-tests & benchmark
python -m cc_stream test
python -m cc_stream benchmark
```
