# ECVRF-EDWARDS25519-SHA512-TAI — RFC 9381

Reference implementations of **ECVRF-EDWARDS25519-SHA512-TAI** (`suite_string = 0x03`) as specified by [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381) Section 5.5, validated directly against the official **RFC 9381 Appendix B.3** test vectors (Examples 16, 17, and 18) plus edge-case and negative vectors (including small-order Edwards25519 torsion keys).

## Implementations

| Language | Directory | Curve / Crypto | Constant-Time Proving |
|---|---|---|---|
| Go | `go/` | `filippo.io/edwards25519` + `crypto/sha512` (pure Go, no cgo) | Yes |
| JavaScript | `js/` | Zero-dependency ESM (`BigInt` + Web Crypto `SHA-512`) | Verification only (public inputs) |
| Dart | `dart/` | Pure Dart (`BigInt` + `package:crypto` `sha512`) | Verification only (public inputs) |
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

## License

MIT (see `LICENSE`).
