// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Edwards25519 Curve Arithmetic for RFC 9381 ECVRF
library Edwards25519 {
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    uint256 internal constant Q = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
    uint256 internal constant D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;
    uint256 internal constant SQRT_M1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0;
    uint256 internal constant BX = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a;
    uint256 internal constant BY = 0x6666666666666666666666666666666666666666666666666666666666666658;
    uint256 internal constant BT = 0x67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3;
    uint256 internal constant P_MINUS_2 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb;
    uint256 internal constant P_PLUS_3_DIV_8 = 0x0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe;

    struct Point {
        uint256 x;
        uint256 y;
        uint256 z;
        uint256 t;
    }

    function identity() internal pure returns (Point memory) {
        return Point(0, 1, 1, 0);
    }

    function basePoint() internal pure returns (Point memory) {
        return Point(BX, BY, 1, BT);
    }

    function _subModP(uint256 a, uint256 b) private pure returns (uint256) {
        uint256 bm = b % P;
        return addmod(a % P, bm == 0 ? 0 : P - bm, P);
    }

    function modExp(uint256 base, uint256 exp, uint256 modulus) internal view returns (uint256 result) {
        bytes memory input = abi.encode(uint256(32), uint256(32), uint256(32), base, exp, modulus);
        bool ok;
        assembly ("memory-safe") {
            ok := and(staticcall(gas(), 0x05, add(input, 32), 192, 0x00, 32), eq(returndatasize(), 32))
            result := mload(0x00)
        }
        require(ok, "modexp failed");
    }

    function invP(uint256 a) internal view returns (uint256) {
        return modExp(a % P, P_MINUS_2, P);
    }

    function fromLE32(bytes32 b) internal pure returns (uint256 r) {
        for (uint256 i = 0; i < 32; i++) {
            r |= uint256(uint8(b[i])) << (i * 8);
        }
    }

    function toLE32(uint256 v) internal pure returns (bytes32) {
        uint256 out = 0;
        for (uint256 i = 0; i < 32; i++) {
            out |= ((v >> (i * 8)) & 0xff) << ((31 - i) * 8);
        }
        return bytes32(out);
    }

    function fromLE16(bytes16 b) internal pure returns (uint256 r) {
        for (uint256 i = 0; i < 16; i++) {
            r |= uint256(uint8(b[i])) << (i * 8);
        }
    }

    /// @notice Reduces a 64-byte little-endian integer (loBytes || hiBytes) modulo Q.
    function reduce64ModQ(bytes32 loBytes, bytes32 hiBytes) internal pure returns (uint256) {
        uint256 lo = fromLE32(loBytes);
        uint256 hi = fromLE32(hiBytes);
        // 2^256 mod Q = 2^256 - 16 * Q
        uint256 two256ModQ = mulmod(1 << 128, 1 << 128, Q);
        return addmod(lo % Q, mulmod(hi % Q, two256ModQ, Q), Q);
    }

    function xRecover(uint256 y) internal view returns (uint256 x, bool ok) {
        uint256 yy = mulmod(y, y, P);
        uint256 u = _subModP(yy, 1);
        uint256 v = addmod(mulmod(D, yy, P), 1, P);
        uint256 xx = mulmod(u, invP(v), P);
        x = modExp(xx, P_PLUS_3_DIV_8, P);
        if (mulmod(x, x, P) != xx) {
            x = mulmod(x, SQRT_M1, P);
        }
        if (mulmod(x, x, P) != xx) {
            return (0, false);
        }
        if ((x & 1) != 0) {
            x = P - x;
        }
        return (x, true);
    }

    function isIdentity(Point memory pt) internal pure returns (bool) {
        return (pt.x % P) == 0 && _subModP(pt.y, pt.z) == 0;
    }

    function encodePoint(Point memory pt) internal view returns (bytes32) {
        uint256 zi = invP(pt.z);
        uint256 ax = mulmod(pt.x, zi, P);
        uint256 ay = mulmod(pt.y, zi, P);
        bytes32 out = toLE32(ay);
        if ((ax & 1) == 1) {
            out |= bytes32(uint256(0x80));
        }
        return out;
    }

    function decodePoint(bytes32 b) internal view returns (Point memory pt, bool ok) {
        uint256 sign = uint8(b[31]) >> 7;
        bytes32 yBytes = b & ~bytes32(uint256(0x80));
        uint256 y = fromLE32(yBytes);
        if (y >= P) return (identity(), false);
        (uint256 x, bool recovered) = xRecover(y);
        if (!recovered) return (identity(), false);
        if (x == 0 && sign == 1) return (identity(), false);
        if ((x & 1) != sign) {
            x = P - x;
        }
        return (Point(x, y, 1, mulmod(x, y, P)), true);
    }

    function add(Point memory p1, Point memory p2) internal pure returns (Point memory) {
        uint256 a = mulmod(_subModP(p1.y, p1.x), _subModP(p2.y, p2.x), P);
        uint256 b = mulmod(addmod(p1.y, p1.x, P), addmod(p2.y, p2.x, P), P);
        uint256 c = mulmod(mulmod(2, mulmod(p1.t, p2.t, P), P), D, P);
        uint256 dd = mulmod(2, mulmod(p1.z, p2.z, P), P);
        uint256 e = _subModP(b, a);
        uint256 f = _subModP(dd, c);
        uint256 g = addmod(dd, c, P);
        uint256 h = addmod(b, a, P);
        return Point(
            mulmod(e, f, P),
            mulmod(g, h, P),
            mulmod(f, g, P),
            mulmod(e, h, P)
        );
    }

    function mulBy8(Point memory pt) internal pure returns (Point memory) {
        Point memory p2 = add(pt, pt);
        Point memory p4 = add(p2, p2);
        return add(p4, p4);
    }

    function mulRaw(Point memory pt, uint256 k) internal pure returns (Point memory) {
        Point memory acc = identity();
        Point memory addend = pt;
        uint256 cur = k;
        while (cur > 0) {
            if ((cur & 1) == 1) {
                acc = add(acc, addend);
            }
            addend = add(addend, addend);
            cur >>= 1;
        }
        return acc;
    }

    function mul(Point memory pt, uint256 k) internal pure returns (Point memory) {
        return mulRaw(pt, k % Q);
    }
}
