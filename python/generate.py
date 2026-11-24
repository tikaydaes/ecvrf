"""Generate vectors/vectors.json for ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381)."""

from __future__ import annotations

import json
import pathlib

import ecvrf

KEY_16 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
KEY_17 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
KEY_18 = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
KEY_ZERO = "00" * 32
KEY_FF = "ff" * 32

POSITIVE_CASES = [
    ("RFC 9381 Appendix B.3 Example 16 (empty alpha)", KEY_16, b"", ""),
    ("RFC 9381 Appendix B.3 Example 17 (0x72, ctr=1)", KEY_17, bytes.fromhex("72"), "r"),
    ("RFC 9381 Appendix B.3 Example 18 (0xaf82)", KEY_18, bytes.fromhex("af82"), None),
    ("all-zero seed, empty alpha", KEY_ZERO, b"", ""),
    ("all-0xff seed, single null byte", KEY_FF, b"\x00", "\u0000"),
    ("single byte 0x41, Example 16 key", KEY_16, b"A", "A"),
    ("single byte 0xff, Example 16 key", KEY_16, b"\xff", None),
    ("ASCII text alpha, Example 16 key", KEY_16, b"sample", "sample"),
    (
        "Churr draw alpha format",
        KEY_17,
        b"1763456789|0193a8ff-7c2e-7b1a-9f3e-2d4c5b6a7e80",
        "1763456789|0193a8ff-7c2e-7b1a-9f3e-2d4c5b6a7e80",
    ),
    (
        "UTF-8 multi-byte alpha",
        KEY_18,
        "churr-🎲-é".encode("utf-8"),
        "churr-🎲-é",
    ),
    ("128-byte alpha (multi-block SHA-512)", KEY_16, bytes(range(128)), None),
    ("512-byte alpha", KEY_17, bytes((i * 37) % 256 for i in range(512)), None),
]


def build_vectors() -> dict:
    vectors = []
    for label, sk_hex, alpha, alpha_str in POSITIVE_CASES:
        entry = ecvrf.prove_verbose(bytes.fromhex(sk_hex), alpha)
        entry["label"] = label
        entry["alpha_string"] = alpha_str
        vectors.append(entry)

    v0 = vectors[0]
    v1 = vectors[1]
    pi0 = bytearray(bytes.fromhex(v0["pi"]))

    def flip(idx: int, mask: int = 0x01) -> str:
        b = bytearray(pi0)
        b[idx] ^= mask
        return bytes(b).hex()

    # Exact group order q and q+1 in little-endian
    q_bytes = ecvrf.Q.to_bytes(32, "little")
    q_plus_1_bytes = (ecvrf.Q + 1).to_bytes(32, "little")

    # Known small-order Edwards25519 points (order 1, 2, 4, 8)
    small_order_pks = [
        ("identity point (order 1)", "01" + "00" * 31),
        ("order-2 torsion point (0, -1)", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ("order-4 torsion point", "0000000000000000000000000000000000000000000000000000000000000000"),
        ("order-8 torsion point", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    ]

    # Non-canonical y = p (2^255 - 19)
    y_eq_p = ecvrf.P.to_bytes(32, "little").hex()
    # Non-canonical x = 0 with sign bit 1: (0, 1) with high bit set
    non_canon_zero = ("01" + "00" * 30 + "80")

    negatives = [
        {
            "description": "wrong alpha for valid proof",
            "pk": v0["pk"],
            "alpha": "00",
            "pi": v0["pi"],
            "expected_verify": False,
        },
        {
            "description": "wrong public key for valid proof",
            "pk": v1["pk"],
            "alpha": v0["alpha"],
            "pi": v0["pi"],
            "expected_verify": False,
        },
        {
            "description": "flipped bit in Gamma",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": flip(0, 0x01),
            "expected_verify": False,
        },
        {
            "description": "flipped bit in challenge c",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": flip(32, 0x01),
            "expected_verify": False,
        },
        {
            "description": "flipped bit in scalar s",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": flip(48, 0x01),
            "expected_verify": False,
        },
        {
            "description": "proof too short (79 bytes)",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": v0["pi"][:-2],
            "expected_verify": False,
        },
        {
            "description": "proof too long (81 bytes)",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": v0["pi"] + "00",
            "expected_verify": False,
        },
        {
            "description": "empty proof",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": "",
            "expected_verify": False,
        },
        {
            "description": "s equals group order q (non-canonical)",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": bytes(pi0[:48]).hex() + q_bytes.hex(),
            "expected_verify": False,
        },
        {
            "description": "s equals q + 1 (overflow)",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": bytes(pi0[:48]).hex() + q_plus_1_bytes.hex(),
            "expected_verify": False,
        },
        {
            "description": "Gamma with non-canonical y = p",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": y_eq_p + bytes(pi0[32:]).hex(),
            "expected_verify": False,
        },
        {
            "description": "Gamma with non-canonical x = 0, sign = 1",
            "pk": v0["pk"],
            "alpha": v0["alpha"],
            "pi": non_canon_zero + bytes(pi0[32:]).hex(),
            "expected_verify": False,
        },
        {
            "description": "public key with non-canonical y = p",
            "pk": y_eq_p,
            "alpha": v0["alpha"],
            "pi": v0["pi"],
            "expected_verify": False,
        },
        {
            "description": "public key too short (31 bytes)",
            "pk": v0["pk"][:-2],
            "alpha": v0["alpha"],
            "pi": v0["pi"],
            "expected_verify": False,
        },
        {
            "description": "public key too long (33 bytes)",
            "pk": v0["pk"] + "00",
            "alpha": v0["alpha"],
            "pi": v0["pi"],
            "expected_verify": False,
        },
    ]

    for desc, pk_hex in small_order_pks:
        negatives.append(
            {
                "description": f"small-order public key: {desc}",
                "pk": pk_hex,
                "alpha": v0["alpha"],
                "pi": v0["pi"],
                "expected_verify": False,
            }
        )

    # Sanity-check every generated positive and negative vector
    for vec in vectors:
        ok, beta = ecvrf.verify(
            bytes.fromhex(vec["pk"]),
            bytes.fromhex(vec["pi"]),
            bytes.fromhex(vec["alpha"]),
        )
        assert ok and beta is not None and beta.hex() == vec["beta"], vec["label"]
    for neg in negatives:
        ok, _ = ecvrf.verify(
            bytes.fromhex(neg["pk"]),
            bytes.fromhex(neg["pi"]),
            bytes.fromhex(neg["alpha"]),
        )
        assert ok is False, neg["description"]

    return {
        "suite": "ECVRF-EDWARDS25519-SHA512-TAI",
        "spec": "RFC 9381",
        "suite_byte": "0x03",
        "vectors": vectors,
        "negative_vectors": negatives,
    }


def main() -> None:
    out_path = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "vectors.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc = build_vectors()
    out_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(doc['vectors'])} positive and {len(doc['negative_vectors'])} negative vectors to {out_path}")


if __name__ == "__main__":
    main()
