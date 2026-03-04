# Module 6 — ChaCha20 Core

Standard ChaCha20 round function and keystream generator, unchanged from
**RFC 8439**.  Only the initial state fed into it differs (Collatz-derived
constants instead of the fixed `"expand 32-byte k"`).

!!! success "No modifications to the round function"
    The quarter-round, double-round structure, and serialisation are
    byte-for-byte identical to the RFC 8439 specification.  All existing
    ChaCha20 security analysis fully applies.

---

## Quarter-Round

The fundamental building block (RFC 8439 §2.1):

```
QR(a, b, c, d):
    a += b;  d ^= a;  d <<<= 16
    c += d;  b ^= c;  b <<<= 12
    a += b;  d ^= a;  d <<<= 8
    c += d;  b ^= c;  b <<<= 7
```

---

## Double-Round Structure

One double-round applies QR to four columns then four diagonals:

```
Column rounds:    QR(0,4,8,12)   QR(1,5,9,13)   QR(2,6,10,14)  QR(3,7,11,15)
Diagonal rounds:  QR(0,5,10,15)  QR(1,6,11,12)  QR(2,7,8,13)   QR(3,4,9,14)
```

Ten double-rounds = 20 total rounds per 64-byte block.

---

## State Finalisation

After 20 rounds the working copy is added back to the original state
(mod 2³²) and serialised as 16 little-endian 32-bit words:

```python
output[i] = (working[i] + state[i]) & 0xFFFFFFFF
```

---

## Internal Constants

| Name | Value | Description |
|------|-------|-------------|
| `_MASK32` | `0xFFFFFFFF` | 32-bit modular mask |
| `_COUNTER_IDX` | `12` | Index of block counter in state |
| `_BLOCK_BYTES` | `64` | Bytes per keystream block |
| `_ROUNDS` | `20` | Total ARX rounds |

---

## API Reference

::: cc_stream.chacha20_core
    options:
      show_source: true
      heading_level: 3
      filters:
        - "!^_[^_]"
        - "^__"
        - "^block$"
        - "^initialize_state$"
        - "^keystream$"
