// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {ECVRFVerifier} from "../src/ECVRFVerifier.sol";
import {ECVRFProver} from "../src/ECVRFProver.sol";

contract ECVRFTest is Test {
    ECVRFVerifier verifier;
    ECVRFProver prover;

    function setUp() public {
        verifier = new ECVRFVerifier();
        prover = new ECVRFProver();
    }

    // --- RFC 9381 Appendix B.3 Official Test Vectors ---

    function test_rfc9381_example16() public view {
        bytes32 sk = hex"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        bytes memory pk = hex"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        bytes memory alpha = hex"";
        bytes memory expectedPi = hex"8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805";
        bytes memory expectedBeta = hex"90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae";

        assertEq(prover.derivePublicKey(sk), bytes32(pk), "pk mismatch");
        (bytes memory pi, bytes memory beta) = prover.prove(sk, alpha);
        assertEq(pi, expectedPi, "pi mismatch");
        assertEq(beta, expectedBeta, "prove beta mismatch");
        assertEq(verifier.proofToHash(pi), expectedBeta, "proofToHash mismatch");

        (bool valid, bytes memory vbeta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "verify failed");
        assertEq(vbeta, expectedBeta, "verify beta mismatch");
    }

    function test_rfc9381_example17() public view {
        bytes32 sk = hex"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        bytes memory pk = hex"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        bytes memory alpha = hex"72";
        bytes memory expectedPi = hex"f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02";
        bytes memory expectedBeta = hex"eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031";

        assertEq(prover.derivePublicKey(sk), bytes32(pk), "pk mismatch");
        (bytes memory pi, bytes memory beta) = prover.prove(sk, alpha);
        assertEq(pi, expectedPi, "pi mismatch");
        assertEq(beta, expectedBeta, "beta mismatch");

        (bool valid, bytes memory vbeta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "verify failed");
        assertEq(vbeta, expectedBeta, "verify beta mismatch");
    }

    function test_rfc9381_example18() public view {
        bytes32 sk = hex"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
        bytes memory pk = hex"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
        bytes memory alpha = hex"af82";
        bytes memory expectedPi = hex"9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e";
        bytes memory expectedBeta = hex"645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f";

        assertEq(prover.derivePublicKey(sk), bytes32(pk), "pk mismatch");
        (bytes memory pi, bytes memory beta) = prover.prove(sk, alpha);
        assertEq(pi, expectedPi, "pi mismatch");
        assertEq(beta, expectedBeta, "beta mismatch");

        (bool valid, bytes memory vbeta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "verify failed");
        assertEq(vbeta, expectedBeta, "verify beta mismatch");
    }

    // --- All shared JSON vectors (positive + negative) ---

    function test_allJsonVectors() public view {
        string memory json = vm.readFile("../vectors/vectors.json");
        assertEq(vm.parseJsonString(json, ".suite"), "ECVRF-EDWARDS25519-SHA512-TAI");

        for (uint256 i = 0; i < 12; i++) {
            string memory base = string.concat(".vectors[", vm.toString(i), "]");
            bytes32 sk = bytes32(vm.parseBytes(string.concat("0x", vm.parseJsonString(json, string.concat(base, ".sk")))));
            bytes memory pk = vm.parseBytes(string.concat("0x", vm.parseJsonString(json, string.concat(base, ".pk"))));
            bytes memory alpha = vm.parseBytes(string.concat("0x", vm.parseJsonString(json, string.concat(base, ".alpha"))));
            bytes memory wantPi = vm.parseBytes(string.concat("0x", vm.parseJsonString(json, string.concat(base, ".pi"))));
            bytes memory wantBeta = vm.parseBytes(string.concat("0x", vm.parseJsonString(json, string.concat(base, ".beta"))));

            assertEq(prover.derivePublicKey(sk), bytes32(pk), "pk mismatch");
            (bytes memory pi, bytes memory beta) = prover.prove(sk, alpha);
            assertEq(pi, wantPi, "pi mismatch");
            assertEq(beta, wantBeta, "beta mismatch");

            (bool valid, bytes memory vbeta) = verifier.verify(pk, pi, alpha);
            assertTrue(valid, "verify rejected valid proof");
            assertEq(vbeta, wantBeta, "verify beta mismatch");
        }

        for (uint256 i = 0; i < 19; i++) {
            string memory base = string.concat(".negative_vectors[", vm.toString(i), "]");
            bytes memory pk = vm.parseBytes(string.concat("0x", vm.parseJsonString(json, string.concat(base, ".pk"))));
            bytes memory alpha = vm.parseBytes(string.concat("0x", vm.parseJsonString(json, string.concat(base, ".alpha"))));
            bytes memory pi = vm.parseBytes(string.concat("0x", vm.parseJsonString(json, string.concat(base, ".pi"))));
            bool expected = vm.parseJsonBool(json, string.concat(base, ".expected_verify"));

            (bool valid, bytes memory vbeta) = verifier.verify(pk, pi, alpha);
            assertEq(valid, expected, "negative vector unexpected result");
            assertEq(vbeta.length, 0, "negative vector non-empty beta");
        }
    }

    function test_sha512PaddingAlphaLen80() public view {
        // alpha.length == 80 produces SHA-512 input length 36 + 80 = 116
        // ((116 + 1) % 128 == 117 > 112), exercising the two-block padding path.
        bytes32 sk = hex"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        bytes memory pk = hex"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        bytes memory alpha = hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
        bytes memory expectedPi = hex"764a438cc9b0902d133469057c75e2fc9f4dabf0828c138cf1ba7f3aa139f96b791a3bed1f1e7432d3029b6e808bc043a689fe9c2e7beba547bfcf4d13477fd61e5554c6284e619288a97db07e88f902";
        bytes memory expectedBeta = hex"9f430049f61a60cdfe0142e22fd3591a83579e907aec589b07951e8ff512654ce8e64b570672235f9d6c25fcc66ef525960be544a13ffdab8ae5db0ddc498265";

        assertEq(alpha.length, 80, "alpha length");
        (bytes memory pi, bytes memory beta) = prover.prove(sk, alpha);
        assertEq(pi, expectedPi, "pi mismatch");
        assertEq(beta, expectedBeta, "prove beta mismatch");
        assertEq(verifier.proofToHash(pi), expectedBeta, "proofToHash mismatch");

        (bool valid, bytes memory vbeta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "verify failed");
        assertEq(vbeta, expectedBeta, "verify beta mismatch");
    }
}
