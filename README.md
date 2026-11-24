# ECVRF-EDWARDS25519-SHA512-TAI — RFC 9381

Reference implementations of **ECVRF-EDWARDS25519-SHA512-TAI** (`suite_string = 0x03`) as specified by [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381) Section 5.5, validated directly against the official **RFC 9381 Appendix B.3** test vectors (Examples 16, 17, and 18) plus edge-case and negative vectors (including small-order Edwards25519 torsion keys and non-canonical encodings).

## Implementations

| Language | Directory | Curve / Crypto | Constant-Time Proving |
|---|---|---|---|
| Go | `.` (module `github.com/tikaydaes/ecvrf`) | `filippo.io/edwards25519` + `crypto/sha512` (pure Go, no cgo) | Yes |
| Rust | `rust/` | `curve25519-dalek` v4 + `sha2` | Yes |
| Zig | `zig/` | `std.crypto.ecc.Edwards25519` + `std.crypto.hash.sha2.Sha512` | Yes |
| Solana | `solana/` | `curve25519-dalek` v4 + `sha2` + `solana-program` | Verify-only (on-chain program) |
| Swift | `swift/` | Zero-dependency radix-2^51 Edwards25519 + `CryptoKit` SHA-512 | Verification / reference |
| C | `c/` | OpenSSL `BIGNUM` + `EVP_sha512` | Verification / reference |
| JavaScript | `js/` | Zero-dependency ESM (`BigInt` + Web Crypto `SHA-512`) | No (verification only) |
| TypeScript | `typescript/` | Zero-dependency ESM (`BigInt` + Web Crypto `SHA-512`) | No (verification only) |
| Dart | `dart/` | Pure Dart (`BigInt` + `package:crypto` `sha512`) | No (verification only) |
| Kotlin | `kotlin/` | Zero-dependency JVM (`BigInteger` + `MessageDigest` SHA-512) | No (verification only) |
| C# | `csharp/` | Zero-dependency .NET 10 (`BigInteger` + `SHA512`) | No (verification only) |
| Haskell | `haskell/` | Pure Haskell (`Integer` + `cryptohash-sha512`) | No (verification only) |
| Solidity | `solidity/` | Pure Solidity `Edwards25519` (`modexp` `0x05`) + `SHA512` | Reference (high EVM gas; no Ed25519/SHA-512 precompiles) |
| Python | `python/` | Pure Python 3 stdlib (`hashlib`) reference oracle | Reference / vector generator |

## Parameters (RFC 9381 Section 5.5)

- **Suite**: `ECVRF-EDWARDS25519-SHA512-TAI` (`0x03`)
- **Secret key (`sk`)**: 32-byte Ed25519 seed
- **Public key (`pk`)**: 32-byte canonical RFC 8032 Edwards25519 point (small-order torsion keys rejected per Section 5.6.1)
- **Proof (`pi`)**: 80 bytes (`Gamma (32) || c (16) || s (32)`, little-endian scalars)
- **Output (`beta`)**: 64 bytes (`SHA-512(0x03 || 0x03 || point_to_string(8 * Gamma) || 0x00)`)

## Running tests

```sh
make test
```

Or run cross-validation across all locally installed toolchains:

```sh
make test-cross
```

## License

MIT (see `LICENSE`).
