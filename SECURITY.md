# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it through [GitHub Security Advisories](https://github.com/tikaydaes/ecvrf/security/advisories/new) rather than opening a public issue.

Alternatively, email security concerns to **kaity@atikayda.com** with the subject line `[ecvrf] Security Report`.

We will acknowledge reports within 72 hours and provide a timeline for resolution.

## Security Model

These are **reference implementations** of **ECVRF-EDWARDS25519-SHA512-TAI** (`suite_string = 0x03`, [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381) Section 5.5), built for correctness and cross-implementation validation. They have **not been formally audited**.

### Side-Channel Resistance

| Implementation | Crypto / Arithmetic | Constant-Time Proving |
|---|---|---|
| Go (root module) | `filippo.io/edwards25519` + `crypto/sha512` (pure Go, no cgo) | Yes |
| Rust | `curve25519-dalek` v4 + `sha2` | Yes |
| Zig | `std.crypto.ecc.Edwards25519` + `std.crypto.hash.sha2.Sha512` | Yes |
| Solana (SVM) | `curve25519-dalek` v4 + `sha2` + `solana-program` | N/A (verify-only on-chain program) |
| Swift | Zero-dependency radix-2^51 Edwards25519 + `CryptoKit` SHA-512 | No (verification / reference) |
| C | OpenSSL `BIGNUM` + `EVP_sha512` | No (verification / reference) |
| JavaScript | Zero-dependency ESM (`BigInt` + Web Crypto `SHA-512`) | No (verification only) |
| TypeScript | Zero-dependency ESM (`BigInt` + Web Crypto `SHA-512`) | No (verification only) |
| Dart | Pure Dart (`BigInt` + `package:crypto` `sha512`) | No (verification only) |
| Kotlin | JVM `BigInteger` + `MessageDigest` SHA-512 | No (verification only) |
| C# | .NET 10 `BigInteger` + `SHA512` | No (verification only) |
| Haskell | Pure `Integer` + `cryptohash-sha512` | No (verification only) |
| Solidity (EVM) | Pure Solidity Edwards25519 (`modexp` `0x05`) + SHA-512 | N/A (on-chain / reference) |
| Python (oracle) | Pure Python 3 stdlib (`hashlib`) | No (reference oracle) |

**Go, Rust, Zig:** These implementations use constant-time Edwards25519 arithmetic (`filippo.io/edwards25519`, `curve25519-dalek` v4, and Zig's `std.crypto.ecc.Edwards25519`) paired with SHA-512, making them suitable for secret-key proving. However, none have undergone formal security audits; use in production at your own risk.

**Swift, C:** Swift implements zero-dependency radix-2^51 Edwards25519 arithmetic with `CryptoKit` SHA-512, and C uses OpenSSL `BIGNUM` with `EVP_sha512`. Their proving paths are **not constant-time**; use them for verification or reference rather than timing-sensitive secret-key operations.

**JavaScript, TypeScript, Dart, Kotlin, C#, Haskell:** These implementations rely on variable-time big-integer arithmetic (`BigInt`, `BigInteger`, `Integer`) paired with SHA-512 and provide **no constant-time guarantees**. They are suitable for verifying public proofs and cross-validation, not for secret-key proving in timing-sensitive environments.

**Python:** The Python implementation uses pure Python 3 stdlib (`hashlib` and arbitrary-precision integers), which is **not constant-time** and is vulnerable to timing side-channels. It exists solely as a reference oracle for generating and validating test vectors. Do not use it for production secret-key operations.

**Solana, Solidity:** On-chain execution is publicly visible and deterministic — all inputs, outputs, and execution traces are observable by design, so timing side-channels are not applicable in this context. The Solana implementation is a verify-only on-chain program (`curve25519-dalek` v4 + `sha2` + `solana-program`). The Solidity implementation performs pure-Solidity Edwards25519 (via the `modexp` `0x05` precompile) and SHA-512 arithmetic, incurring high on-chain gas costs and serving as a reference and cross-validation target.

### Suite String

The suite string `0x03` is the official suite string defined in **RFC 9381 Section 5.5** for `ECVRF-EDWARDS25519-SHA512-TAI`. All implementations validate canonical RFC 8032 point encodings, reject small-order Edwards25519 torsion public keys per RFC 9381 Section 5.6.1, and are verified against the official RFC 9381 Appendix B.3 test vectors (Examples 16, 17, and 18).

## Supported Versions

Only the latest version on the `main` branch receives security updates.
