# Module 3 — Collatz Engine

Performs exactly **T** salted Collatz-style iterations starting from the
SHA3-256 seed and records the full parity sequence.

---

## Iteration Rule

| Parity of `x` | Rule | Parity bit recorded |
|---------------|------|---------------------|
| Even | `x = x >> 1` | 0 |
| Odd  | `a = 5 if salt_bit else 3` → `x = (a·x + 1) >> 1` | 1 |

The salt bit at step `i` is `(salt[i % 64] >> (i % 8)) & 1`.

## Design Invariants

- **Fixed iteration count.** Always runs exactly `T` steps (no early
  termination when `x` reaches 1), eliminating timing side-channels.
- **Forced odd start.** The seed integer has its lowest bit forced to 1
  (`x = seed_int | 1`) for a richer initial trajectory.
- **Bounded arithmetic.** All values are kept within 512 bits via
  `x = x % 2⁵¹²`, preventing unbounded growth.

---

## API Reference

::: cc_stream.collatz_engine
    options:
      show_source: true
      heading_level: 3
