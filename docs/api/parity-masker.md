# Module 4 — Parity Masker

Transforms the raw parity sequence `b` into a compressed, masked sketch
`π` using the PSC-QOWF construction.

---

## The Masking Operation

Given:
- `b ∈ {0,1}^T` — the raw Collatz parity sequence  
- `R ∈ {0,1}^{m×T}` — a pseudo-random binary matrix derived from the seed

The masked output is:

$$\pi = R \cdot b \pmod{2} \in \{0,1\}^m$$

!!! warning "Raw trajectory is never exposed"
    Only `π` and the final value `x_T` leave this module.
    `b` must remain internal to the key schedule.

---

## Security

| Scenario | Complexity |
|----------|-----------|
| Classical inversion of `π` | \(2^{T-m} = 2^{256}\) |
| Quantum Grover inversion   | \(2^{(T-m)/2} = 2^{128}\) |

This bound holds when `R` has full rank (or nearly so), which is
guaranteed with overwhelming probability for a random `m × T` matrix
with `m < T`.

---

## Matrix Derivation

The matrix `R` is derived deterministically from the Collatz seed:

```
prng_seed = SHA3-256("parity_matrix_v1" ‖ seed)
raw       = SHAKE-256(prng_seed)            [m × ⌈T/8⌉ bytes]
R[i]      = raw[i·⌈T/8⌉ : (i+1)·⌈T/8⌉]    (row i as bytes)
```

Using a domain-separation tag (`"parity_matrix_v1"`) ensures R is
independent of other SHA3 uses in the key schedule.

---

## API Reference

::: cc_stream.parity_masker
    options:
      show_source: true
      heading_level: 3
