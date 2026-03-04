# Module 2 — Salt Generator

Derives the 64-byte salt vector and iteration parameters `(T, m)` that
control the Collatz engine.

The derivation is:

```
base  = SHA3-256( K ‖ N ‖ ctr )          [32 bytes]
salt  = SHAKE-128( base )                 [64 bytes]
```

Including the **block counter** in the hash ensures that different counter
values produce different Collatz trajectories.

---

## Security Parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `T_DEFAULT` | 384 | Collatz iterations per key schedule |
| `M_DEFAULT` | 128 | Number of compressed parity constraints |
| `MIN_SECURITY_MARGIN` | 256 | Minimum `T - m`; enforced at runtime |

The constraint `T - m ≥ 256` guarantees at least 2²⁵⁶ classical and
2¹²⁸ quantum Grover operations for the parity-search problem.

---

## API Reference

::: cc_stream.salt_generator
    options:
      show_source: true
      heading_level: 3
