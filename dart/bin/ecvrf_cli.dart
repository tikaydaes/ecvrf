import 'dart:io';
import 'dart:typed_data';

import 'package:ecvrf/ecvrf.dart';

Uint8List _fromHex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.writeln(
      'usage: ecvrf_cli prove <sk> <alpha> | verify <pk> <pi> <alpha> | derive-pk <sk>',
    );
    exit(2);
  }
  switch (args[0]) {
    case 'prove':
      stdout.writeln(_toHex(prove(_fromHex(args[1]), _fromHex(args[2]))));
    case 'verify':
      final res = verify(
        _fromHex(args[1]),
        _fromHex(args[2]),
        _fromHex(args[3]),
      );
      if (!res.valid) exit(1);
      stdout.writeln(_toHex(res.beta!));
    case 'derive-pk':
      stdout.writeln(_toHex(derivePublicKey(_fromHex(args[1]))));
    default:
      stderr.writeln('unknown command: ${args[0]}');
      exit(2);
  }
}
