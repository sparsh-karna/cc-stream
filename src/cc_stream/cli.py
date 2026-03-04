"""
CC-Stream Command-Line Interface
==================================
Provides encrypt, decrypt, keygen, benchmark, and test sub-commands.

Inline mode (hex in → hex out, printed to stdout):
    python -m cc_stream encrypt -k <hex_key> -n <hex_nonce> <hex_plaintext>
    python -m cc_stream decrypt -k <hex_key> -n <hex_nonce> <hex_ciphertext>

Plain-text shorthand (UTF-8 string → hex ciphertext):
    python -m cc_stream encrypt -k <hex_key> -n <hex_nonce> --text "HELLO WORLD"
    python -m cc_stream decrypt -k <hex_key> -n <hex_nonce> --text <hex_ciphertext>

File mode:
    python -m cc_stream encrypt -k <hex_key> -n <hex_nonce> -i input.txt -o output.enc
    python -m cc_stream decrypt -k <hex_key> -n <hex_nonce> -i output.enc -o recovered.txt

Other:
    python -m cc_stream keygen
    python -m cc_stream benchmark
    python -m cc_stream test
"""

import argparse
import os
import sys
import time

from cc_stream.cipher import CCStream


def _keygen(args: argparse.Namespace) -> None:
    """Generate and print a random key and nonce."""
    key = CCStream.generate_key()
    nonce = CCStream.generate_nonce()
    print(f"Key   : {key.hex()}")
    print(f"Nonce : {nonce.hex()}")


def _resolve_input(args: argparse.Namespace, mode: str) -> bytes:
    """
    Resolve plaintext / ciphertext from one of three sources:
      1. Positional hex string  (args.data)
      2. --text UTF-8 string    (args.text)  [encrypt only: treated as raw bytes]
      3. -i / --input file      (args.input)
    Exactly one must be provided.
    """
    sources = [
        args.data is not None,
        getattr(args, 'text', None) is not None,
        args.input is not None,
    ]
    if sum(sources) != 1:
        print(
            "error: provide exactly one of: positional hex data, --text, or -i/--input",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.data is not None:
        try:
            return bytes.fromhex(args.data)
        except ValueError:
            print("error: positional data must be a valid hex string", file=sys.stderr)
            sys.exit(1)

    if getattr(args, 'text', None) is not None:
        if mode == 'encrypt':
            return args.text.encode('utf-8')
        else:
            # For decrypt --text is still expected to be hex ciphertext
            try:
                return bytes.fromhex(args.text)
            except ValueError:
                print("error: --text for decrypt must be a valid hex string", file=sys.stderr)
                sys.exit(1)

    with open(args.input, 'rb') as f:
        return f.read()


def _write_output(args: argparse.Namespace, data: bytes, label: str) -> None:
    """Write result to file (-o) or print hex to stdout."""
    if args.output:
        with open(args.output, 'wb') as f:
            f.write(data)
        print(f"{label} {len(data)} bytes -> {args.output}")
    else:
        print(data.hex())


def _encrypt(args: argparse.Namespace) -> None:
    """Encrypt inline hex / --text string / file."""
    try:
        key   = bytes.fromhex(args.key)
        nonce = bytes.fromhex(args.nonce)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    plaintext  = _resolve_input(args, 'encrypt')
    ciphertext = CCStream(key, nonce).encrypt(plaintext)
    _write_output(args, ciphertext, "Encrypted")


def _decrypt(args: argparse.Namespace) -> None:
    """Decrypt inline hex / --text string / file."""
    try:
        key   = bytes.fromhex(args.key)
        nonce = bytes.fromhex(args.nonce)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    ciphertext = _resolve_input(args, 'decrypt')
    plaintext  = CCStream(key, nonce).decrypt(ciphertext)

    if args.output:
        _write_output(args, plaintext, "Decrypted")
    else:
        # Try to display as UTF-8; fall back to hex
        try:
            print(plaintext.decode('utf-8'))
        except UnicodeDecodeError:
            print(plaintext.hex())


def _benchmark(args: argparse.Namespace) -> None:
    """Run performance benchmarks."""
    sizes = [1024, 4096, 16384, 65536, 262144, 1048576]
    key = CCStream.generate_key()
    nonce = CCStream.generate_nonce()

    print(f"{'Size':>10s}  {'Init (ms)':>10s}  {'Encrypt (ms)':>12s}  {'MB/s':>8s}")
    print("-" * 48)

    for size in sizes:
        plaintext = os.urandom(size)

        # Measure init
        t0 = time.perf_counter()
        cipher = CCStream(key, nonce)
        t_init = time.perf_counter() - t0

        # Measure encrypt
        t0 = time.perf_counter()
        cipher.encrypt(plaintext)
        t_enc = time.perf_counter() - t0

        mb_s = (size / 1_048_576) / t_enc if t_enc > 0 else float('inf')
        print(f"{size:>10d}  {t_init*1000:>10.2f}  {t_enc*1000:>12.2f}  {mb_s:>8.2f}")


def _test(args: argparse.Namespace) -> None:
    """Run built-in self-tests."""
    passed = 0
    failed = 0

    def check(name: str, condition: bool) -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  PASS: {name}")
        else:
            failed += 1
            print(f"  FAIL: {name}")

    print("CC-Stream Self-Tests")
    print("=" * 50)

    # 1. Round-trip correctness
    key = CCStream.generate_key()
    nonce = CCStream.generate_nonce()
    pt = b"HELLO WORLD - CC-Stream Hybrid Cipher Test!"
    ct = CCStream(key, nonce).encrypt(pt)
    recovered = CCStream(key, nonce).decrypt(ct)
    check("Round-trip correctness", pt == recovered)

    # 2. Different keys -> different ciphertexts
    pt2 = b"Same plaintext"
    nonce2 = CCStream.generate_nonce()
    c1 = CCStream(CCStream.generate_key(), nonce2).encrypt(pt2)
    c2 = CCStream(CCStream.generate_key(), nonce2).encrypt(pt2)
    check("Different keys produce different output", c1 != c2)

    # 3. Different nonces -> different ciphertexts
    key3 = CCStream.generate_key()
    c3 = CCStream(key3, CCStream.generate_nonce()).encrypt(pt2)
    c4 = CCStream(key3, CCStream.generate_nonce()).encrypt(pt2)
    check("Different nonces produce different output", c3 != c4)

    # 4. Determinism
    key4 = CCStream.generate_key()
    nonce4 = CCStream.generate_nonce()
    d1 = CCStream(key4, nonce4).encrypt(pt2)
    d2 = CCStream(key4, nonce4).encrypt(pt2)
    check("Determinism (same key+nonce)", d1 == d2)

    # 5. Multi-block round-trip
    key5 = CCStream.generate_key()
    nonce5 = CCStream.generate_nonce()
    big_pt = os.urandom(1000)
    big_ct = CCStream(key5, nonce5).encrypt(big_pt)
    big_rec = CCStream(key5, nonce5).decrypt(big_ct)
    check("Multi-block (1000 bytes) round-trip", big_pt == big_rec)

    # 6. Streaming correctness
    key6 = CCStream.generate_key()
    nonce6 = CCStream.generate_nonce()
    pt_a, pt_b = b"First part...", b"Second part!"
    enc = CCStream(key6, nonce6)
    ct_a = enc.encrypt(pt_a)
    ct_b = enc.encrypt(pt_b)
    # Single-shot
    full_ct = CCStream(key6, nonce6).encrypt(pt_a + pt_b)
    check("Streaming encrypt matches single-shot", ct_a + ct_b == full_ct)

    # 7. Bit frequency
    ks = CCStream(CCStream.generate_key(), CCStream.generate_nonce()).keystream(1024)
    ones = sum(bin(b).count('1') for b in ks)
    ratio = ones / (len(ks) * 8)
    check(f"Bit frequency ratio={ratio:.4f} (near 0.5)", abs(ratio - 0.5) < 0.05)

    # 8. Empty input
    empty_ct = CCStream(key, nonce).encrypt(b"")
    check("Empty input returns empty output", empty_ct == b"")

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cc-stream",
        description="CC-Stream: Collatz-ChaCha Hybrid Stream Cipher",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # keygen
    sub.add_parser("keygen", help="Generate a random key and nonce")

    # shared encrypt / decrypt argument builder
    def _add_crypto_args(p: argparse.ArgumentParser, verb: str) -> None:
        p.add_argument("-k", "--key",   required=True, help="Hex-encoded 256-bit key")
        p.add_argument("-n", "--nonce", required=True, help="Hex-encoded 96-bit nonce")
        # Input: exactly one of positional hex, --text, or -i file
        p.add_argument(
            "data", nargs="?", default=None,
            metavar="HEX_DATA",
            help=f"Hex-encoded {'plaintext' if verb == 'encrypt' else 'ciphertext'} (inline mode)",
        )
        p.add_argument(
            "--text", default=None,
            metavar="STRING",
            help=(
                "UTF-8 plaintext string to encrypt (encrypt mode), "
                "or hex ciphertext string to decrypt (decrypt mode)"
            ),
        )
        p.add_argument("-i", "--input",  default=None, help="Input file path (file mode)")
        p.add_argument("-o", "--output", default=None, help="Output file path (file mode, optional)")

    enc_p = sub.add_parser(
        "encrypt",
        help="Encrypt: inline hex, --text string, or -i/-o file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Encrypt data using CC-Stream.\n\n"
            "Examples:\n"
            "  Inline hex:  cc-stream encrypt -k KEY -n NONCE 48454c4c4f\n"
            "  Plain text:  cc-stream encrypt -k KEY -n NONCE --text 'HELLO'\n"
            "  File:        cc-stream encrypt -k KEY -n NONCE -i msg.txt -o msg.enc"
        ),
    )
    _add_crypto_args(enc_p, "encrypt")

    dec_p = sub.add_parser(
        "decrypt",
        help="Decrypt: inline hex, --text hex string, or -i/-o file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Decrypt data using CC-Stream.\n\n"
            "Examples:\n"
            "  Inline hex:  cc-stream decrypt -k KEY -n NONCE <hex_ct>\n"
            "  File:        cc-stream decrypt -k KEY -n NONCE -i msg.enc -o msg.txt"
        ),
    )
    _add_crypto_args(dec_p, "decrypt")

    # benchmark
    sub.add_parser("benchmark", help="Run performance benchmarks")

    # test
    sub.add_parser("test", help="Run built-in self-tests")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    dispatch = {
        "keygen": _keygen,
        "encrypt": _encrypt,
        "decrypt": _decrypt,
        "benchmark": _benchmark,
        "test": _test,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
