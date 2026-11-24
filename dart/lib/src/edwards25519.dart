/// Edwards25519 curve arithmetic over BigInt for ECVRF verification and
/// reference proving. Not constant-time; verification operates on public
/// inputs only.
library;

import 'dart:typed_data';

/// Prime field modulus p = 2^255 - 19.
final BigInt fieldPrime = (BigInt.one << 255) - BigInt.from(19);

/// Prime subgroup order q = 2^252 + 27742317777372353535851937790883648493.
final BigInt groupOrder =
    (BigInt.one << 252) + BigInt.parse('27742317777372353535851937790883648493');

final BigInt _pMinus2 = fieldPrime - BigInt.two;
final BigInt _pPlus3Div8 = (fieldPrime + BigInt.from(3)) >> 3;
final BigInt _sqrtM1 = BigInt.two.modPow(
  (fieldPrime - BigInt.one) >> 2,
  fieldPrime,
);
final BigInt _d = _mod(
  -BigInt.from(121665) * BigInt.from(121666).modPow(_pMinus2, fieldPrime),
);

BigInt _mod(BigInt v, [BigInt? m]) {
  final mod = m ?? fieldPrime;
  final r = v % mod;
  return r.isNegative ? r + mod : r;
}

/// Decodes unsigned little-endian bytes into a BigInt.
BigInt bytesToBigIntLE(List<int> bytes) {
  var r = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    r = (r << 8) | BigInt.from(bytes[i]);
  }
  return r;
}

/// Encodes a non-negative BigInt as fixed-length little-endian bytes.
Uint8List bigIntToBytesLE(BigInt v, int length) {
  final out = Uint8List(length);
  var cur = v;
  for (var i = 0; i < length; i++) {
    out[i] = (cur & BigInt.from(0xff)).toInt();
    cur >>= 8;
  }
  return out;
}

BigInt? _xRecover(BigInt y) {
  final yy = (y * y) % fieldPrime;
  final u = _mod(yy - BigInt.one);
  final v = _mod(_d * yy + BigInt.one);
  final xx = _mod(u * v.modPow(_pMinus2, fieldPrime));
  var x = xx.modPow(_pPlus3Div8, fieldPrime);
  if (_mod(x * x - xx) != BigInt.zero) {
    x = (x * _sqrtM1) % fieldPrime;
  }
  if (_mod(x * x - xx) != BigInt.zero) return null;
  if (x.isOdd) x = fieldPrime - x;
  return x;
}

/// A point on Edwards25519 in extended homogeneous coordinates (X : Y : Z : T).
final class Point {
  final BigInt x;
  final BigInt y;
  final BigInt z;
  final BigInt t;

  const Point._(this.x, this.y, this.z, this.t);

  /// The neutral (identity) element (0, 1).
  static final Point identity = Point._(
    BigInt.zero,
    BigInt.one,
    BigInt.one,
    BigInt.zero,
  );

  /// The Edwards25519 base point B (RFC 8032).
  static final Point basePoint = _makeBasePoint();

  static Point _makeBasePoint() {
    final by = _mod(
      BigInt.from(4) * BigInt.from(5).modPow(_pMinus2, fieldPrime),
    );
    final bx = _xRecover(by)!;
    return Point._(bx, by, BigInt.one, (bx * by) % fieldPrime);
  }

  /// True if this point is the identity element.
  bool get isIdentity =>
      _mod(x) == BigInt.zero && _mod(y - z) == BigInt.zero;

  /// Decodes a canonical 32-byte RFC 8032 compressed Edwards25519 point.
  /// Returns null if invalid or non-canonical.
  static Point? fromBytes(Uint8List data) {
    if (data.length != 32) return null;
    final sign = (data[31] >> 7) & 1;
    final yBytes = Uint8List.fromList(data);
    yBytes[31] &= 0x7f;
    final y = bytesToBigIntLE(yBytes);
    if (y >= fieldPrime) return null;
    var x = _xRecover(y);
    if (x == null) return null;
    if (x == BigInt.zero && sign == 1) return null;
    if ((x.isOdd ? 1 : 0) != sign) x = fieldPrime - x;
    return Point._(x, y, BigInt.one, (x * y) % fieldPrime);
  }

  /// Encodes this point as 32 canonical RFC 8032 bytes.
  Uint8List toBytes() {
    final zi = z.modPow(_pMinus2, fieldPrime);
    final ax = (x * zi) % fieldPrime;
    final ay = (y * zi) % fieldPrime;
    final out = bigIntToBytesLE(ay, 32);
    if (ax.isOdd) out[31] |= 0x80;
    return out;
  }

  /// Extended twisted Edwards point addition (a = -1).
  Point operator +(Point other) {
    final a = _mod((y - x) * (other.y - other.x));
    final b = _mod((y + x) * (other.y + other.x));
    final c = _mod(BigInt.two * t * other.t % fieldPrime * _d);
    final dd = _mod(BigInt.two * z * other.z);
    final e = _mod(b - a);
    final f = _mod(dd - c);
    final g = _mod(dd + c);
    final h = _mod(b + a);
    return Point._(
      (e * f) % fieldPrime,
      (g * h) % fieldPrime,
      (f * g) % fieldPrime,
      (e * h) % fieldPrime,
    );
  }

  /// Scalar multiplication by a non-negative integer without reducing mod q
  /// (used for cofactor multiplication by 8 and clamped secret scalars).
  Point multiplyRaw(BigInt k) {
    var acc = identity;
    var addend = this;
    var cur = k;
    while (cur > BigInt.zero) {
      if (cur.isOdd) acc = acc + addend;
      addend = addend + addend;
      cur >>= 1;
    }
    return acc;
  }

  /// Scalar multiplication modulo the prime subgroup order q.
  Point multiply(BigInt k) => multiplyRaw(_mod(k, groupOrder));
}
