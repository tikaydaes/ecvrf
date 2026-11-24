import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ecvrf/ecvrf.dart';
import 'package:test/test.dart';

Uint8List fromHex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final data = jsonDecode(
    File('../vectors/vectors.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final vectors = (data['vectors'] as List).cast<Map<String, dynamic>>();
  final negatives =
      (data['negative_vectors'] as List).cast<Map<String, dynamic>>();

  test('suite metadata and lengths', () {
    expect(data['suite'], 'ECVRF-EDWARDS25519-SHA512-TAI');
    expect(data['spec'], 'RFC 9381');
    expect(publicKeyLength, 32);
    expect(proofLength, 80);
    expect(betaLength, 64);
  });

  group('positive vectors', () {
    for (final v in vectors) {
      test(v['label'], () {
        final sk = fromHex(v['sk'] as String);
        final alpha = fromHex(v['alpha'] as String);
        final pk = derivePublicKey(sk);
        expect(toHex(pk), v['pk']);
        expect(isPublicKey(pk), isTrue);

        final pi = prove(sk, alpha);
        expect(toHex(pi), v['pi']);

        final beta = proofToHash(pi);
        expect(toHex(beta), v['beta']);

        final res = verify(pk, pi, alpha);
        expect(res.valid, isTrue);
        expect(toHex(res.beta!), v['beta']);
      });
    }
  });

  group('negative vectors', () {
    for (final v in negatives) {
      test(v['description'], () {
        final res = verify(
          fromHex(v['pk'] as String),
          fromHex(v['pi'] as String),
          fromHex(v['alpha'] as String),
        );
        expect(res.valid, v['expected_verify']);
        if (v['expected_verify'] == false) {
          expect(res.beta, isNull);
        }
      });
    }
  });
}
