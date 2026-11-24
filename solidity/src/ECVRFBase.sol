// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Edwards25519} from "./Edwards25519.sol";
import {SHA512} from "./SHA512.sol";

abstract contract ECVRFBase {
    uint8 internal constant SUITE_BYTE = 0x03;

    function _validateKey(bytes calldata pk) internal view returns (Edwards25519.Point memory y, bool ok) {
        if (pk.length != 32) return (Edwards25519.identity(), false);
        bytes32 pk32 = bytes32(pk);
        (y, ok) = Edwards25519.decodePoint(pk32);
        if (!ok) return (Edwards25519.identity(), false);
        if (Edwards25519.isIdentity(Edwards25519.mulBy8(y))) {
            return (Edwards25519.identity(), false);
        }
        return (y, true);
    }

    function _encodeToCurve(bytes32 pkBytes, bytes calldata alpha)
        internal view returns (Edwards25519.Point memory, bool)
    {
        for (uint256 ctr = 0; ctr < 256; ctr++) {
            (bytes32 hi,) = SHA512.digest(
                abi.encodePacked(SUITE_BYTE, uint8(0x01), pkBytes, alpha, uint8(ctr), uint8(0x00))
            );
            (Edwards25519.Point memory pt, bool ok) = Edwards25519.decodePoint(hi);
            if (ok) {
                return (Edwards25519.mulBy8(pt), true);
            }
        }
        return (Edwards25519.identity(), false);
    }

    function _challengeGeneration(
        Edwards25519.Point memory y,
        Edwards25519.Point memory h,
        Edwards25519.Point memory gamma,
        Edwards25519.Point memory u,
        Edwards25519.Point memory v
    ) internal view returns (uint256 c, bytes16 cBytes) {
        (bytes32 hi,) = SHA512.digest(
            abi.encodePacked(
                SUITE_BYTE,
                uint8(0x02),
                Edwards25519.encodePoint(y),
                Edwards25519.encodePoint(h),
                Edwards25519.encodePoint(gamma),
                Edwards25519.encodePoint(u),
                Edwards25519.encodePoint(v),
                uint8(0x00)
            )
        );
        cBytes = bytes16(hi);
        c = Edwards25519.fromLE16(cBytes);
    }

    function _gammaToHash(Edwards25519.Point memory gamma) internal view returns (bytes memory) {
        bytes32 cofGamma = Edwards25519.encodePoint(Edwards25519.mulBy8(gamma));
        return SHA512.digestBytes(abi.encodePacked(SUITE_BYTE, uint8(0x03), cofGamma, uint8(0x00)));
    }
}
