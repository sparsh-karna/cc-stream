# Security

## Security Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Key size | 256 bits | ChaCha20-compatible |
| Nonce size | 96 bits | RFC 8439 IETF variant |
| `T` | 384 | Collatz iterations |
| `m` | 128 | Parity constraint count |
| `T - m` | 256 | Security margin |
| Classical security | ≥ 2²⁵⁶ | Combined Collatz + ChaCha20 |
| Quantum security | ≥ 2¹²⁸ | Grover bound on both layers |

---

## Two-Layer Security Argument

CC-Stream is designed so that an attacker must defeat **two independent
hardness assumptions simultaneously**.

### Layer 1: Collatz Parity-Search Hardness

The PSC-QOWF analysis (Kelekhsaevi 2025) shows that recovering the
Collatz seed from the masked sketch `π` requires searching a space of
size:

$$|\mathcal{S}| \approx 2^{T - m}$$

With default parameters `T = 384`, `m = 128`:

- **Classical**: \(2^{256}\) operations (Collatz parity search)
- **Quantum (Grover)**: \(2^{128}\) oracle calls

No polynomial-time algorithm is known for this search, and it is
believed to be algebraically unrelated to lattice problems or
factoring.

### Layer 2: ChaCha20 ARX Hardness

The ChaCha20 core inherits 18 years of public cryptanalysis.  The best
known distinguishing attack on reduced-round ChaCha requires
\(\approx 2^{232}\) operations against 7 rounds; the full 20-round
design has not been broken classically.

Against a quantum adversary, Grover's algorithm yields a generic
\(2^{128}\) key search, which is why CC-Stream targets 256-bit keys.

### Combined Defense

Because both layers are **independently constructed**:

- Breaking ChaCha20 alone requires recovering the augmented key `ck`,
  which is `k ⊕ rk` — but `rk` depends on the Collatz trajectory.
- Breaking the Collatz layer alone reveals `rk`, but the attacker still
  needs to invert the ChaCha20 keystream.

An attacker with quantum hardware who solves both Grover instances
independently still needs \(2^{128}\) operations per layer.

---

## Threat Model

### What CC-Stream Protects Against

| Threat | Protection |
|--------|-----------|
| Classic brute-force key search | 2²⁵⁶ keyspace |
| Quantum Grover search | 2¹²⁸ per layer |
| Known-plaintext → key recovery | Both ARX + Collatz must be inverted |
| Nonce-reuse under *different* keys | Independent Collatz seeds per key |
| Timing side-channels | Fixed-T Collatz; constant-time XOR |
| Keystream reuse (two-time pad) | Counter advances on every encrypt() call |

### What CC-Stream Does NOT Protect Against

!!! danger "No authentication"
    CC-Stream is a **stream cipher only** — it provides **confidentiality**
    but **not integrity or authenticity**.  
    To prevent ciphertext tampering, combine it with a MAC such as
    **Poly1305** (forming CC-Stream-Poly1305 analogous to ChaCha20-Poly1305).

!!! danger "Nonce misuse"
    If the same `(key, nonce)` pair is used to encrypt two different
    messages, the XOR of the two ciphertexts equals the XOR of the
    two plaintexts — the same catastrophic failure as any stream cipher.
    Always use a fresh nonce per message.

---

## Known Limitations and Caveats

### Performance

The Collatz key schedule runs once per `CCStream` initialisation and
takes ~0.35 ms on a typical laptop.  This is a fixed **one-time cost**
independent of message length.  Encryption throughput is ~0.7 MB/s in
pure Python (dominated by the ChaCha20 core loop, not the Collatz
schedule).

### No Formal Security Proof

CC-Stream does not have a formal reduction to a well-studied
computational problem in the way that some lattice-based schemes do.
The security argument is:

1. The Collatz hardness assumption is **heuristic** but has resisted
   decades of attack.
2. ChaCha20 has a strong empirical track record.
3. Their combination (defense in depth) requires breaking both.

### Python Reference Implementation

This implementation is a **research prototype and reference design**,
not a production-grade, constant-time, side-channel-hardened library.
In particular:

- Python integer arithmetic is not constant-time.
- The PSC-QOWF paper's exact hardness bounds are an active area of
  research.

---

## Security Margin Configuration

The constraint `T - m >= 256` is enforced at runtime to ensure the
default security margin:

```python
# Raises ValueError: T - m = 192, must be >= 256
cipher = CCStream(key, nonce, T=320, m=128)

# Valid — larger T increases both security and cost
cipher = CCStream(key, nonce, T=512, m=128)   # T - m = 384
```

Increasing `T` linearly increases the cost of one Collatz key schedule
computation for both the legitimate party and the attacker.
