# Module 5 — Key Schedule

The key schedule is the bridge between the Collatz subsystem and the
ChaCha20 core.  It converts `(parity_seq, x_T, π)` into a 512-bit
modified ChaCha20 initial state.

---

## Derivation Pipeline

```
parity_seq  ─── traj_bytes[0:16]  ────────────┐
                                               ├─ XOR ─► constants[0:4]
x_T ─── SHA3-256("collatz_final_v1" ‖ x_T) ──┘

parity_seq  ─── traj_bytes[16:48] ────────────┐
                                               ├─ XOR ─► round_keys[0:8]
π  ─── SHA3-256("parity_mask_v1" ‖ π) ────────┘

ck_i = k_i ⊕ round_keys[i]          (key augmentation)
```

Three independent sources of entropy contribute to each output word,
so compromising any one source alone does not recover the state.

---

## Initial State Layout

```
┌──────────────────────────────────────────┐
│  cc0    cc1    cc2    cc3                 │  ← Collatz constants
│  ck0    ck1    ck2    ck3                 │  ← Augmented key (low)
│  ck4    ck5    ck6    ck7                 │  ← Augmented key (high)
│  ctr    n0     n1     n2                  │  ← Counter + Nonce
└──────────────────────────────────────────┘
```

Standard ChaCha20 uses fixed ASCII constants `"expand 32-byte k"` in
row 0.  CC-Stream replaces them with the Collatz-derived `cc0..cc3`.

---

## API Reference

::: cc_stream.key_schedule
    options:
      show_source: true
      heading_level: 3
