/// RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite byte 0x03).
///
/// Pure Dart implementation using only `package:crypto` for SHA-512.
/// Cross-checked against RFC 9381 Appendix B.3 and shared test vectors.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'edwards25519.dart';

const int _suiteByte = 0x03;
const int _challengeLength = 16;

/// Length in bytes of a secret key seed.
const int secretKeyLength = 32;

/// Length in bytes of a compressed Ed25519 public key.
const int publicKeyLength = 32;

/// Length in bytes of a proof: Gamma (32) || c (16) || s (32).
const int proofLength = 80;

/// Length in bytes of the VRF output beta (SHA-512).
const int betaLength = 64;

/// The result of [verify]: whether the proof is valid and, if so, beta.
final class VerifyResult {
  /// True if the proof is valid for the public key and alpha.
  final bool valid;

  /// The 64-byte VRF output when [valid]; null otherwise.
  final Uint8List? beta;

  const VerifyResult._(this.valid, this.beta);

  static const VerifyResult _invalid = VerifyResult._(false, null);
}

/// A decoded proof.
typedef DecodedProof = ({Point gamma, BigInt c, Uint8List cBytes, BigInt s});

Uint8List _sha512(List<int> data) =>
    Uint8List.fromList(sha512.convert(data).bytes);

Uint8List _concat(List<List<int>> parts) {
  final builder = BytesBuilder(copy: false);
  for (final part in parts) {
    builder.add(part);
  }
  return builder.takeBytes();
}

({BigInt x, Uint8List prefix}) _expandSecretKey(Uint8List sk) {
  if (sk.length != secretKeyLength) {
    throw ArgumentError.value(
      sk.length,
      'sk',
      'secret key must be $secretKeyLength bytes',
    );
  }
  final h = _sha512(sk);
  final xb = Uint8List.fromList(h.sublist(0, 32));
  xb[0] &= 248;
  xb[31] &= 127;
  xb[31] |= 64;
  return (x: bytesToBigIntLE(xb), prefix: Uint8List.sublistView(h, 32));
}

/// RFC 9381 Section 5.6.1: decodes [pk] and rejects small-order torsion keys.
Point? validateKey(Uint8List pk) {
  final y = Point.fromBytes(pk);
  if (y == null) return null;
  if (y.multiplyRaw(BigInt.from(8)).isIdentity) return null;
  return y;
}

/// Reports whether [pk] is a valid non-small-order 32-byte Ed25519 public key.
bool isPublicKey(Uint8List pk) => validateKey(pk) != null;

/// RFC 9381 Section 5.4.1.1: try_and_increment with cofactor clearing (8 * pt).
({Point h, int ctr}) encodeToCurve(Uint8List pkBytes, Uint8List alpha) {
  for (var ctr = 0; ctr < 256; ctr++) {
    final hash = _sha512(
      _concat([
        [_suiteByte, 0x01],
        pkBytes,
        alpha,
        [ctr, 0x00],
      ]),
    );
    final pt = Point.fromBytes(Uint8List.sublistView(hash, 0, 32));
    if (pt != null) {
      return (h: pt.multiplyRaw(BigInt.from(8)), ctr: ctr);
    }
  }
  throw StateError('encode_to_curve: no valid point found in 256 iterations');
}

/// RFC 9381 Section 5.4.3: challenge over the five points (Y, H, Gamma, U, V).
({BigInt c, Uint8List cBytes}) challengeGeneration(
  Point y,
  Point h,
  Point gamma,
  Point u,
  Point v,
) {
  final hash = _sha512(
    _concat([
      [_suiteByte, 0x02],
      y.toBytes(),
      h.toBytes(),
      gamma.toBytes(),
      u.toBytes(),
      v.toBytes(),
      [0x00],
    ]),
  );
  final cBytes = Uint8List.fromList(hash.sublist(0, _challengeLength));
  return (c: bytesToBigIntLE(cBytes), cBytes: cBytes);
}

Uint8List _gammaToHash(Point gamma) => _sha512(
  _concat([
    [_suiteByte, 0x03],
    gamma.multiplyRaw(BigInt.from(8)).toBytes(),
    [0x00],
  ]),
);

/// Decodes an 80-byte proof into (Gamma, c, cBytes, s).
DecodedProof decodeProof(Uint8List pi) {
  if (pi.length != proofLength) {
    throw ArgumentError.value(
      pi.length,
      'pi',
      'proof must be $proofLength bytes',
    );
  }
  final gamma = Point.fromBytes(Uint8List.sublistView(pi, 0, 32));
  if (gamma == null) {
    throw ArgumentError('proof Gamma is not a valid compressed point');
  }
  final cBytes = Uint8List.fromList(pi.sublist(32, 32 + _challengeLength));
  final c = bytesToBigIntLE(cBytes);
  final s = bytesToBigIntLE(pi.sublist(32 + _challengeLength, proofLength));
  if (s >= groupOrder) {
    throw ArgumentError('proof s must be less than the group order');
  }
  return (gamma: gamma, c: c, cBytes: cBytes, s: s);
}

/// Derives the 32-byte Ed25519 public key for a 32-byte secret key seed.
Uint8List derivePublicKey(Uint8List sk) {
  final (:x, prefix: _) = _expandSecretKey(sk);
  return Point.basePoint.multiplyRaw(x).toBytes();
}

/// RFC 9381 Section 5.1: generates an 80-byte proof Gamma || c || s.
Uint8List prove(Uint8List sk, Uint8List alpha) {
  final (:x, :prefix) = _expandSecretKey(sk);
  final y = Point.basePoint.multiplyRaw(x);
  final pkBytes = y.toBytes();
  final h = encodeToCurve(pkBytes, alpha).h;
  final gamma = h.multiplyRaw(x);
  final kHash = _sha512(_concat([prefix, h.toBytes()]));
  final k = bytesToBigIntLE(kHash) % groupOrder;
  final u = Point.basePoint.multiply(k);
  final v = h.multiply(k);
  final (:c, :cBytes) = challengeGeneration(y, h, gamma, u, v);
  final s = (k + c * x) % groupOrder;
  return _concat([
    gamma.toBytes(),
    cBytes,
    bigIntToBytesLE(s, 32),
  ]);
}

/// RFC 9381 Section 5.3: verifies [pi] for the 32-byte public key [pk] and
/// [alpha]. Never throws: any malformed input yields an invalid result.
VerifyResult verify(Uint8List pk, Uint8List pi, Uint8List alpha) {
  final y = validateKey(pk);
  if (y == null) return VerifyResult._invalid;

  final DecodedProof proof;
  try {
    proof = decodeProof(pi);
  } on ArgumentError {
    return VerifyResult._invalid;
  }
  final (:gamma, :c, cBytes: _, :s) = proof;

  final h = encodeToCurve(pk, alpha).h;
  final negC = (groupOrder - c) % groupOrder;

  final u = Point.basePoint.multiply(s) + y.multiply(negC);
  final v = h.multiply(s) + gamma.multiply(negC);

  final cPrime = challengeGeneration(y, h, gamma, u, v).c;
  if (c != cPrime) return VerifyResult._invalid;
  return VerifyResult._(true, _gammaToHash(gamma));
}

/// RFC 9381 Section 5.2: the 64-byte VRF output beta of a proof, without
/// verifying it. Throws [ArgumentError] if [pi] cannot be decoded.
Uint8List proofToHash(Uint8List pi) => _gammaToHash(decodeProof(pi).gamma);
