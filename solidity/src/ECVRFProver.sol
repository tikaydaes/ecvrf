// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Edwards25519} from "./Edwards25519.sol";
import {SHA512} from "./SHA512.sol";
import {ECVRFBase} from "./ECVRFBase.sol";

contract ECVRFProver is ECVRFBase {
    function _expandSecretKey(bytes32 sk) private pure returns (uint256 x, bytes32 prefix) {
        (bytes32 hi, bytes32 lo) = SHA512.digest(abi.encodePacked(sk));
        bytes memory xb = abi.encodePacked(hi);
        xb[0] = bytes1(uint8(xb[0]) & 248);
        xb[31] = bytes1((uint8(xb[31]) & 127) | 64);
        x = Edwards25519.fromLE32(bytes32(xb));
        prefix = lo;
    }

    function derivePublicKey(bytes32 sk) external view returns (bytes32) {
        (uint256 x,) = _expandSecretKey(sk);
        return Edwards25519.encodePoint(Edwards25519.mulRaw(Edwards25519.basePoint(), x));
    }

    function prove(bytes32 sk, bytes calldata alpha)
        external view returns (bytes memory pi, bytes memory beta)
    {
        (uint256 x, bytes32 prefix) = _expandSecretKey(sk);
        Edwards25519.Point memory y = Edwards25519.mulRaw(Edwards25519.basePoint(), x);
        bytes32 pk = Edwards25519.encodePoint(y);

        (Edwards25519.Point memory h, bool hOk) = _encodeToCurve(pk, alpha);
        require(hOk, "encode_to_curve failed");

        Edwards25519.Point memory gamma = Edwards25519.mulRaw(h, x);
        (bytes32 kLo, bytes32 kHi) = SHA512.digest(abi.encodePacked(prefix, Edwards25519.encodePoint(h)));
        uint256 k = Edwards25519.reduce64ModQ(kLo, kHi);

        Edwards25519.Point memory u = Edwards25519.mul(Edwards25519.basePoint(), k);
        Edwards25519.Point memory v = Edwards25519.mul(h, k);
        (uint256 c, bytes16 cBytes) = _challengeGeneration(y, h, gamma, u, v);
        uint256 s = addmod(k, mulmod(c, x % Edwards25519.Q, Edwards25519.Q), Edwards25519.Q);

        pi = abi.encodePacked(Edwards25519.encodePoint(gamma), cBytes, Edwards25519.toLE32(s));
        beta = _gammaToHash(gamma);
    }
}
