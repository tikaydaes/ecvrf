# Contributing

Contributions are welcome. This project implements RFC 9381 **ECVRF-EDWARDS25519-SHA512-TAI** (`suite_string = 0x03`) across 14 implementations, so changes need care to maintain spec compliance and cross-implementation consistency.

## Running Tests

```bash
make test          # Run all tests (all 14 implementations + cross-validation)
make test-python   # Python reference oracle only
make test-go       # Go (root module) only
make test-js       # JavaScript only
make test-ts       # TypeScript only
make test-dart     # Dart only
make test-c        # C only
make test-swift    # Swift only
make test-kotlin   # Kotlin only
make test-rust     # Rust only
make test-solana   # Solana only
make test-csharp   # C# only
make test-haskell  # Haskell only
make test-zig      # Zig only
make test-solidity # Solidity (Foundry) only
make test-cross    # Cross-implementation validation
make vectors       # Regenerate test vectors from the Python oracle
make clean         # Remove build artifacts
```

## Adding Test Vectors

1. Edit `python/generate.py` to add new vector definitions
2. Run `make vectors` to regenerate `vectors/vectors.json`
3. Run `make test` to confirm all 14 implementations pass against the updated vectors
4. Commit both `generate.py` and `vectors.json` together

## Code Style

- **Go:** `gofmt`, standard library conventions, pure Go root module (`github.com/tikaydaes/ecvrf`, `filippo.io/edwards25519` + `crypto/sha512`, no cgo)
- **Rust:** `cargo fmt`, `cargo clippy` clean (`curve25519-dalek` v4 + `sha2`)
- **Zig:** Zig standard library conventions, zero external dependencies (`std.crypto.ecc.Edwards25519` + `std.crypto.hash.sha2.Sha512`)
- **Solana:** Rust conventions, verify-only on-chain program (`curve25519-dalek` v4 + `sha2` + `solana-program`), compatible with the Solana BPF/SBF toolchain
- **Swift:** Swift API Design Guidelines, Swift 5.9+, zero external dependencies (radix-2^51 Edwards25519 + `CryptoKit` SHA-512)
- **C:** C11, consistent formatting with existing `ecvrf.c`/`ecvrf.h` style (OpenSSL `BIGNUM` + `EVP_sha512`)
- **JavaScript:** Zero-dependency ESM (`BigInt` + Web Crypto `SHA-512`)
- **TypeScript:** Strict mode, no `any` types, zero-dependency ESM (`BigInt` + Web Crypto `SHA-512`)
- **Dart:** `dart format`, `dart analyze --fatal-infos` clean (`BigInt` + `package:crypto` `sha512`)
- **Kotlin:** Kotlin coding conventions, Gradle/Kotlin DSL, zero runtime dependencies (JVM `BigInteger` + `MessageDigest` SHA-512)
- **C#:** Standard .NET 10 conventions, namespace `Ecvrf`, zero external dependencies (`BigInteger` + `SHA512`)
- **Haskell:** Consistent with existing module style, pure `Integer` + `cryptohash-sha512`, avoid unnecessary dependencies
- **Solidity:** Solidity Style Guide, Foundry project conventions, pure Solidity Edwards25519 (`modexp` `0x05`) + SHA-512
- **Python:** PEP 8, type hints where practical, pure Python 3 stdlib (`hashlib`) reference oracle

## Pull Request Requirements

- All 14 implementations must pass (`make test`)
- Cross-validation must pass (`make test-cross`)
- If adding vectors, include the regenerated `vectors/vectors.json`
- Changes must not break RFC 9381 compliance — all implementations must remain compatible with the published specification

## RFC 9381 Compliance

This project strictly follows [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381) Section 5.5 (`ECVRF-EDWARDS25519-SHA512-TAI`, suite `0x03`) and validates against the Appendix B.3 test vectors. Algorithm changes that deviate from the spec will not be accepted. If you believe an implementation diverges from the RFC, open an issue with the specific section reference.
