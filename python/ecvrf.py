"""RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI reference implementation (pure Python).

Implements RFC 9381 Section 5.5 (suite 0x03) using only Python's standard
library (`hashlib`). Validated directly against RFC 9381 Appendix B.3
(Examples 16, 17, 18).
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

SUITE_BYTE = 0x03
SECRET_KEY_LEN = 32
PUBLIC_KEY_LEN = 32
PROOF_LEN = 80
BETA_LEN = 64
CHALLENGE_LEN = 16

P = (1 << 255) - 19
Q = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _x_recover(y: int) -> Optional[int]:
    yy = (y * y) % P
    u = (yy - 1) % P
    v = (D * yy + 1) % P
    xx = (u * pow(v, -1, P)) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * SQRT_M1) % P
    if (x * x - xx) % P != 0:
        return None
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * pow(5, -1, P)) % P
_BX = _x_recover(_BY)
assert _BX is not None
BASE_POINT = (_BX, _BY, 1, (_BX * _BY) % P)
IDENTITY = (0, 1, 1, 0)


Point = Tuple[int, int, int, int]


def point_add(p1: Point, p2: Point) -> Point:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * t1 * t2 * D) % P
    dd = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (dd - c) % P
    g = (dd + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def point_mul(pt: Point, k: int) -> Point:
    k = k % Q
    acc = IDENTITY
    addend = pt
    while k > 0:
        if k & 1:
            acc = point_add(acc, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return acc


def point_mul_raw(pt: Point, k: int) -> Point:
    acc = IDENTITY
    addend = pt
    while k > 0:
        if k & 1:
            acc = point_add(acc, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return acc


def point_to_bytes(pt: Point) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, -1, P)
    ax = (x * zi) % P
    ay = (y * zi) % P
    b = bytearray(ay.to_bytes(32, "little"))
    b[31] |= (ax & 1) << 7
    return bytes(b)


def bytes_to_point(b: bytes) -> Optional[Point]:
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= P:
        return None
    sign = (b[31] >> 7) & 1
    x = _x_recover(y)
    if x is None:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)


def is_identity(pt: Point) -> bool:
    x, y, z, _ = pt
    return (x % P) == 0 and ((y - z) % P) == 0


def _expand_sk(sk: bytes) -> Tuple[int, bytes]:
    if len(sk) != SECRET_KEY_LEN:
        raise ValueError(f"secret key must be {SECRET_KEY_LEN} bytes")
    h = hashlib.sha512(sk).digest()
    xb = bytearray(h[:32])
    xb[0] &= 248
    xb[31] &= 127
    xb[31] |= 64
    return int.from_bytes(xb, "little"), h[32:]


def derive_public_key(sk: bytes) -> bytes:
    x, _ = _expand_sk(sk)
    return point_to_bytes(point_mul_raw(BASE_POINT, x))


def validate_key(pk: bytes) -> Optional[Point]:
    """RFC 9381 Section 5.6.1: decode point and reject small-order keys."""
    y = bytes_to_point(pk)
    if y is None:
        return None
    if is_identity(point_mul_raw(y, 8)):
        return None
    return y


def encode_to_curve_tai(pk: bytes, alpha: bytes) -> Tuple[Point, int]:
    """RFC 9381 Section 5.4.1.1: try_and_increment with cofactor clearing."""
    prefix = bytes([SUITE_BYTE, 0x01]) + pk + alpha
    for ctr in range(256):
        h_str = hashlib.sha512(prefix + bytes([ctr, 0x00])).digest()
        pt = bytes_to_point(h_str[:32])
        if pt is not None:
            return point_mul_raw(pt, 8), ctr
    raise RuntimeError("encode_to_curve failed after 256 iterations")


def nonce_generation(sk: bytes, h_point: Point) -> Tuple[int, bytes]:
    """RFC 9381 Section 5.4.2.2: deterministic nonce from SHA-512."""
    _, prefix = _expand_sk(sk)
    k_string = hashlib.sha512(prefix + point_to_bytes(h_point)).digest()
    return int.from_bytes(k_string, "little") % Q, k_string


def challenge_generation(y: Point, h: Point, gamma: Point, u: Point, v: Point) -> Tuple[int, bytes]:
    """RFC 9381 Section 5.4.3: 5-point challenge hash truncated to 16 bytes."""
    h_in = (
        bytes([SUITE_BYTE, 0x02])
        + point_to_bytes(y)
        + point_to_bytes(h)
        + point_to_bytes(gamma)
        + point_to_bytes(u)
        + point_to_bytes(v)
        + bytes([0x00])
    )
    c_str = hashlib.sha512(h_in).digest()[:CHALLENGE_LEN]
    return int.from_bytes(c_str, "little"), c_str


def proof_to_hash(pi: bytes) -> bytes:
    """RFC 9381 Section 5.2: 64-byte VRF output beta."""
    gamma, _, _ = decode_proof(pi)
    cofactor_gamma = point_mul_raw(gamma, 8)
    return hashlib.sha512(
        bytes([SUITE_BYTE, 0x03]) + point_to_bytes(cofactor_gamma) + bytes([0x00])
    ).digest()


def decode_proof(pi: bytes) -> Tuple[Point, int, int]:
    if len(pi) != PROOF_LEN:
        raise ValueError(f"proof must be {PROOF_LEN} bytes")
    gamma = bytes_to_point(pi[:32])
    if gamma is None:
        raise ValueError("invalid Gamma point")
    c = int.from_bytes(pi[32:48], "little")
    s = int.from_bytes(pi[48:80], "little")
    if s >= Q:
        raise ValueError("scalar s >= group order")
    return gamma, c, s


def prove_verbose(sk: bytes, alpha: bytes) -> dict:
    x, _ = _expand_sk(sk)
    y = point_mul_raw(BASE_POINT, x)
    pk = point_to_bytes(y)
    h_point, ctr = encode_to_curve_tai(pk, alpha)
    gamma = point_mul_raw(h_point, x)
    k, k_string = nonce_generation(sk, h_point)
    u = point_mul(BASE_POINT, k)
    v = point_mul(h_point, k)
    c, c_str = challenge_generation(y, h_point, gamma, u, v)
    s = (k + c * x) % Q
    pi = point_to_bytes(gamma) + c_str + s.to_bytes(32, "little")
    beta = proof_to_hash(pi)
    return {
        "sk": sk.hex(),
        "pk": pk.hex(),
        "alpha": alpha.hex(),
        "h": point_to_bytes(h_point).hex(),
        "h_ctr": ctr,
        "k": k.to_bytes(32, "little").hex(),
        "gamma": point_to_bytes(gamma).hex(),
        "u": point_to_bytes(u).hex(),
        "v": point_to_bytes(v).hex(),
        "c": c_str.hex(),
        "s": s.to_bytes(32, "little").hex(),
        "pi": pi.hex(),
        "beta": beta.hex(),
    }


def prove(sk: bytes, alpha: bytes) -> bytes:
    return bytes.fromhex(prove_verbose(sk, alpha)["pi"])


def verify(pk: bytes, pi: bytes, alpha: bytes) -> Tuple[bool, Optional[bytes]]:
    """RFC 9381 Section 5.3: verify proof and return (valid, beta)."""
    y = validate_key(pk)
    if y is None:
        return False, None
    try:
        gamma, c, s = decode_proof(pi)
    except ValueError:
        return False, None
    h_point, _ = encode_to_curve_tai(pk, alpha)
    neg_c = (Q - c) % Q
    u = point_add(point_mul(BASE_POINT, s), point_mul(y, neg_c))
    v = point_add(point_mul(h_point, s), point_mul(gamma, neg_c))
    c_prime, _ = challenge_generation(y, h_point, gamma, u, v)
    if c_prime != c:
        return False, None
    return True, proof_to_hash(pi)


def _self_test() -> None:
    rfc_vectors = [
        (
            "RFC 9381 Appendix B.3 Example 16",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        ),
        (
            "RFC 9381 Appendix B.3 Example 17",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        ),
        (
            "RFC 9381 Appendix B.3 Example 18",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        ),
    ]
    for label, sk_hex, pk_hex, alpha_hex, pi_hex, beta_hex in rfc_vectors:
        sk = bytes.fromhex(sk_hex)
        alpha = bytes.fromhex(alpha_hex)
        pk = derive_public_key(sk)
        assert pk.hex() == pk_hex, f"{label}: pk mismatch"
        pi = prove(sk, alpha)
        assert pi.hex() == pi_hex, f"{label}: pi mismatch"
        beta = proof_to_hash(pi)
        assert beta.hex() == beta_hex, f"{label}: beta mismatch"
        ok, vbeta = verify(pk, pi, alpha)
        assert ok and vbeta == beta, f"{label}: verify failed"
    print("RFC 9381 Appendix B.3 self-test passed (3/3 official vectors).")


if __name__ == "__main__":
    _self_test()
