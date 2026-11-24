// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Pure Solidity FIPS 180-4 SHA-512
library SHA512 {
    bytes private constant K_BYTES =
        hex"428a2f98d728ae227137449123ef65cdb5c0fbcfec4d3b2fe9b5dba58189dbbc"
        hex"3956c25bf348b53859f111f1b605d019923f82a4af194f9bab1c5ed5da6d8118"
        hex"d807aa98a303024212835b0145706fbe243185be4ee4b28c550c7dc3d5ffb4e2"
        hex"72be5d74f27b896f80deb1fe3b1696b19bdc06a725c71235c19bf174cf692694"
        hex"e49b69c19ef14ad2efbe4786384f25e30fc19dc68b8cd5b5240ca1cc77ac9c65"
        hex"2de92c6f592b02754a7484aa6ea6e4835cb0a9dcbd41fbd476f988da831153b5"
        hex"983e5152ee66dfaba831c66d2db43210b00327c898fb213fbf597fc7beef0ee4"
        hex"c6e00bf33da88fc2d5a79147930aa72506ca6351e003826f142929670a0e6e70"
        hex"27b70a8546d22ffc2e1b21385c26c9264d2c6dfc5ac42aed53380d139d95b3df"
        hex"650a73548baf63de766a0abb3c77b2a881c2c92e47edaee692722c851482353b"
        hex"a2bfe8a14cf10364a81a664bbc423001c24b8b70d0f89791c76c51a30654be30"
        hex"d192e819d6ef5218d69906245565a910f40e35855771202a106aa07032bbd1b8"
        hex"19a4c116b8d2d0c81e376c085141ab532748774cdf8eeb9934b0bcb5e19b48a8"
        hex"391c0cb3c5c95a634ed8aa4ae3418acb5b9cca4f7763e373682e6ff3d6b2b8a3"
        hex"748f82ee5defb2fc78a5636f43172f6084c87814a1f0ab728cc702081a6439ec"
        hex"90befffa23631e28a4506cebde82bde9bef9a3f7b2c67915c67178f2e372532b"
        hex"ca273eceea26619cd186b8c721c0c207eada7dd6cde0eb1ef57d4f7fee6ed178"
        hex"06f067aa72176fba0a637dc5a2c898a6113f9804bef90dae1b710b35131c471b"
        hex"28db77f523047d8432caab7b40c724933c9ebe0a15c9bebc431d67c49c100d4c"
        hex"4cc5d4becb3e42b6597f299cfc657e2a5fcb6fab3ad6faec6c44198c4a475817";

    function _rotr(uint64 x, uint64 n) private pure returns (uint64) {
        unchecked {
            return (x >> n) | (x << (64 - n));
        }
    }

    function _loadK(bytes memory kMem, uint256 i) private pure returns (uint64 val) {
        assembly ("memory-safe") {
            val := shr(192, mload(add(add(kMem, 32), shl(3, i))))
        }
    }

    function _loadWord(bytes memory padded, uint256 offset) private pure returns (uint64 val) {
        assembly ("memory-safe") {
            val := shr(192, mload(add(add(padded, 32), offset)))
        }
    }

    function _compress(
        uint64[8] memory h,
        bytes memory padded,
        uint256 blockOff,
        bytes memory kMem,
        uint64[80] memory w
    ) private pure {
        unchecked {
            for (uint256 i = 0; i < 16; i++) {
                w[i] = _loadWord(padded, blockOff + i * 8);
            }
            for (uint256 i = 16; i < 80; i++) {
                uint64 w15 = w[i - 15];
                uint64 w2 = w[i - 2];
                uint64 s0 = _rotr(w15, 1) ^ _rotr(w15, 8) ^ (w15 >> 7);
                uint64 s1 = _rotr(w2, 19) ^ _rotr(w2, 61) ^ (w2 >> 6);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            uint64[8] memory v;
            for (uint256 i = 0; i < 8; i++) {
                v[i] = h[i];
            }

            for (uint256 i = 0; i < 80; i++) {
                uint64 temp1;
                uint64 temp2;
                {
                    uint64 s1 = _rotr(v[4], 14) ^ _rotr(v[4], 18) ^ _rotr(v[4], 41);
                    uint64 ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
                    temp1 = v[7] + s1 + ch + _loadK(kMem, i) + w[i];
                }
                {
                    uint64 s0 = _rotr(v[0], 28) ^ _rotr(v[0], 34) ^ _rotr(v[0], 39);
                    uint64 maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                    temp2 = s0 + maj;
                }

                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3] + temp1;
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = temp1 + temp2;
            }

            for (uint256 i = 0; i < 8; i++) {
                h[i] += v[i];
            }
        }
    }

    function digest(bytes memory message) internal pure returns (bytes32 hi, bytes32 lo) {
        uint256 msgLen = message.length;
        uint256 padLen = (240 - ((msgLen + 1) % 128)) % 128;
        uint256 totalLen = msgLen + 1 + padLen + 16;
        bytes memory padded = new bytes(totalLen);

        for (uint256 i = 0; i < msgLen; i++) {
            padded[i] = message[i];
        }
        padded[msgLen] = 0x80;

        uint64 bitLen = uint64(msgLen * 8);
        for (uint256 i = 0; i < 8; i++) {
            padded[totalLen - 1 - i] = bytes1(uint8(bitLen >> (i * 8)));
        }

        uint64[8] memory h = [
            uint64(0x6a09e667f3bcc908),
            uint64(0xbb67ae8584caa73b),
            uint64(0x3c6ef372fe94f82b),
            uint64(0xa54ff53a5f1d36f1),
            uint64(0x510e527fade682d1),
            uint64(0x9b05688c2b3e6c1f),
            uint64(0x1f83d9abfb41bd6b),
            uint64(0x5be0cd19137e2179)
        ];

        bytes memory kMem = K_BYTES;
        uint64[80] memory w;

        unchecked {
            for (uint256 blockOff = 0; blockOff < totalLen; blockOff += 128) {
                _compress(h, padded, blockOff, kMem, w);
            }
        }

        uint256 hiVal = (uint256(h[0]) << 192) | (uint256(h[1]) << 128) | (uint256(h[2]) << 64) | uint256(h[3]);
        uint256 loVal = (uint256(h[4]) << 192) | (uint256(h[5]) << 128) | (uint256(h[6]) << 64) | uint256(h[7]);
        hi = bytes32(hiVal);
        lo = bytes32(loVal);
    }

    function digestBytes(bytes memory message) internal pure returns (bytes memory) {
        (bytes32 hi, bytes32 lo) = digest(message);
        return abi.encodePacked(hi, lo);
    }
}
