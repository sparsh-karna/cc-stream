# Module 1 — Input

Validates and converts the external inputs (key, nonce, block counter)
into the internal 32-bit word representations used by the rest of CC-Stream.

All size and type invariants required by ChaCha20 (RFC 8439) are
enforced here so that downstream modules can assume valid input.

---

## Constants

| Name | Value | Description |
|------|-------|-------------|
| `KEY_SIZE` | 32 | Required key length in bytes (256-bit) |
| `NONCE_SIZE` | 12 | Required nonce length in bytes (96-bit) |
| `MAX_COUNTER` | 2³² − 1 | Maximum block counter value |

---

## API Reference

::: cc_stream.input_module
    options:
      show_source: true
      heading_level: 3
