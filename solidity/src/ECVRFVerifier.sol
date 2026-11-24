// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Edwards25519} from "./Edwards25519.sol";
import {ECVRFBase} from "./ECVRFBase.sol";

contract ECVRFVerifier is ECVRFBase {
    function verify(bytes calldata pk, bytes calldata pi, bytes calldata alpha)
        external view returns (bool valid, bytes memory beta)
    {
        if (pi.length != 80) return (false, "");

        (Edwards25519.Point memory y, bool pkOk) = _validateKey(pk);
        if (!pkOk) return (false, "");

        (Edwards25519.Point memory gamma, bool gOk) = Edwards25519.decodePoint(bytes32(pi[0:32]));
        if (!gOk) return (false, "");

        bytes16 cBytes = bytes16(pi[32:48]);
        uint256 c = Edwards25519.fromLE16(cBytes);
        uint256 s = Edwards25519.fromLE32(bytes32(pi[48:80]));
        if (s >= Edwards25519.Q) return (false, "");

        (Edwards25519.Point memory h, bool hOk) = _encodeToCurve(bytes32(pk), alpha);
        if (!hOk) return (false, "");

        uint256 negC = c == 0 ? 0 : Edwards25519.Q - c;
        Edwards25519.Point memory u = Edwards25519.add(
            Edwards25519.mul(Edwards25519.basePoint(), s),
            Edwards25519.mul(y, negC)
        );
        Edwards25519.Point memory v = Edwards25519.add(
            Edwards25519.mul(h, s),
            Edwards25519.mul(gamma, negC)
        );

        (, bytes16 cPrimeBytes) = _challengeGeneration(y, h, gamma, u, v);
        if (cBytes != cPrimeBytes) return (false, "");

        return (true, _gammaToHash(gamma));
    }

    function proofToHash(bytes calldata pi) external view returns (bytes memory) {
        require(pi.length == 80, "invalid proof length");
        (Edwards25519.Point memory gamma, bool ok) = Edwards25519.decodePoint(bytes32(pi[0:32]));
        require(ok, "invalid Gamma");
        uint256 s = Edwards25519.fromLE32(bytes32(pi[48:80]));
        require(s < Edwards25519.Q, "invalid scalar s");
        return _gammaToHash(gamma);
    }
}
