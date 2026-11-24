// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import {ECVRFVerifier} from "../src/ECVRFVerifier.sol";
import {ECVRFProver} from "../src/ECVRFProver.sol";

contract Cli is Script {
    function proveCmd(bytes32 sk, bytes calldata alpha) external returns (bytes memory pi) {
        ECVRFProver prover = new ECVRFProver();
        (pi,) = prover.prove(sk, alpha);
    }

    function verifyCmd(bytes calldata pk, bytes calldata pi, bytes calldata alpha)
        external returns (bool valid, bytes memory beta)
    {
        ECVRFVerifier verifier = new ECVRFVerifier();
        return verifier.verify(pk, pi, alpha);
    }

    function derivePkCmd(bytes32 sk) external returns (bytes32) {
        ECVRFProver prover = new ECVRFProver();
        return prover.derivePublicKey(sk);
    }
}
