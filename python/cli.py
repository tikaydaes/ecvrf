#!/usr/bin/env python3
"""CLI for cross-validation: prove / verify / derive-pk."""

import sys

import ecvrf


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: cli.py prove <sk_hex> <alpha_hex> | verify <pk_hex> <pi_hex> <alpha_hex> | derive-pk <sk_hex>")
    cmd = sys.argv[1]
    if cmd == "prove":
        pi = ecvrf.prove(bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3]))
        print(pi.hex())
    elif cmd == "verify":
        ok, beta = ecvrf.verify(bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3]), bytes.fromhex(sys.argv[4]))
        if not ok or beta is None:
            sys.exit(1)
        print(beta.hex())
    elif cmd == "derive-pk":
        print(ecvrf.derive_public_key(bytes.fromhex(sys.argv[2])).hex())
    else:
        sys.exit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
