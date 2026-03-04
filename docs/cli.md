# CLI Reference

CC-Stream ships a command-line interface accessible as:

```bash
python -m cc_stream <command> [options]
# or, if installed via pip:
cc-stream <command> [options]
```

---

## `keygen`

Generate a cryptographically random 256-bit key and 96-bit nonce.

```bash
python -m cc_stream keygen
```

**Output:**

```
Key   : 81e97342fa5ec9bd59a25ba19eb5aa9538fb4a2d48154ade9087d7130ee80f0e
Nonce : f7caef249f76bdb8bb356a5d
```

Store these securely.  Never reuse a nonce with the same key.

---

## `encrypt`

Three input modes are supported.  Exactly one must be provided.

### Inline — plain text string

```bash
python -m cc_stream encrypt -k $KEY -n $NONCE --text "Hello, World!"
```

**Output** (hex-encoded ciphertext printed to stdout):

```
3a8fbc04e1d7a29c...
```

### Inline — hex-encoded plaintext

```bash
python -m cc_stream encrypt -k $KEY -n $NONCE 48656c6c6f
```

### File mode

```bash
python -m cc_stream encrypt -k $KEY -n $NONCE -i plaintext.txt -o cipher.enc
# Encrypted 13 bytes -> cipher.enc
```

Output file is optional; omit `-o` to print hex ciphertext to stdout:

```bash
python -m cc_stream encrypt -k $KEY -n $NONCE -i plaintext.txt
```

### Options

| Flag | Description |
|------|-------------|
| `-k` / `--key` | **Required.** Hex-encoded 256-bit (64 hex chars) key |
| `-n` / `--nonce` | **Required.** Hex-encoded 96-bit (24 hex chars) nonce |
| `HEX_DATA` | Positional hex-encoded plaintext (inline mode) |
| `--text STRING` | UTF-8 plaintext string (inline mode) |
| `-i` / `--input FILE` | Input file path (file mode) |
| `-o` / `--output FILE` | Output file path (optional; stdout if omitted) |

---

## `decrypt`

Mirrors `encrypt`.  Output is decoded as UTF-8 if valid, otherwise
printed as hex.

### Inline — from hex ciphertext

```bash
python -m cc_stream decrypt -k $KEY -n $NONCE 3a8fbc04e1d7a29c...
```

**Output:**

```
Hello, World!
```

### File mode

```bash
python -m cc_stream decrypt -k $KEY -n $NONCE -i cipher.enc -o recovered.txt
# Decrypted 13 bytes -> recovered.txt
```

---

## `test`

Run the built-in self-test suite (8 functional checks):

```bash
python -m cc_stream test
```

```
CC-Stream Self-Tests
==================================================
  PASS: Round-trip correctness
  PASS: Different keys produce different output
  PASS: Different nonces produce different output
  PASS: Determinism (same key+nonce)
  PASS: Multi-block (1000 bytes) round-trip
  PASS: Streaming encrypt matches single-shot
  PASS: Bit frequency ratio=0.4987 (near 0.5)
  PASS: Empty input returns empty output
==================================================
Results: 8 passed, 0 failed
```

---

## `benchmark`

Measure encryption throughput across message sizes:

```bash
python -m cc_stream benchmark
```

```
      Size   Init (ms)  Encrypt (ms)      MB/s
------------------------------------------------
      1024        0.36          1.39      0.70
      4096        0.34          5.52      0.71
     16384        0.34         22.72      0.69
     65536        0.41         89.32      0.70
    262144        0.38        337.61      0.74
   1048576        0.36       1331.78      0.75
```

`Init (ms)` is the one-time Collatz key schedule cost.
`Encrypt (ms)` is the ChaCha20 keystream + XOR cost.

---

## Complete Example

```bash
# 1. Generate fresh credentials
KEY=`python -m cc_stream keygen | grep Key | awk '{print $3}'`
NONCE=`python -m cc_stream keygen | grep Nonce | awk '{print $3}'`

# 2. Encrypt a file
python -m cc_stream encrypt -k $KEY -n $NONCE -i secret.txt -o secret.enc

# 3. Decrypt
python -m cc_stream decrypt -k $KEY -n $NONCE -i secret.enc -o recovered.txt

# 4. Verify
diff secret.txt recovered.txt && echo "Match!"
```
