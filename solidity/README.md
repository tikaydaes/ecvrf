# ECVRF-EDWARDS25519-SHA512-TAI — Solidity (Foundry)

Pure Solidity implementation of RFC 9381 **ECVRF-EDWARDS25519-SHA512-TAI** (`suite_string = 0x03`).

> **Gas note:** The EVM does not provide native precompiles for Edwards25519 or SHA-512 (only `modexp` `0x05` is available). This implementation includes pure-Solidity FIPS 180-4 SHA-512 and extended twisted Edwards25519 arithmetic using `mulmod`/`addmod` and `modexp`. Because all curve and hash operations execute in EVM bytecode, on-chain gas costs are high; it is intended as a specification-compliant reference and cross-validation target.

## Usage

```sh
forge install foundry-rs/forge-std --no-git
forge test
```
