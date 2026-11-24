import ECVRF
import Foundation

func hexToBytes(_ hex: String) -> [UInt8]? {
    let chars = Array(hex)
    guard chars.count % 2 == 0 else { return nil }
    var out = [UInt8]()
    out.reserveCapacity(chars.count / 2)
    for i in stride(from: 0, to: chars.count, by: 2) {
        guard let b = UInt8(String(chars[i...i + 1]), radix: 16) else { return nil }
        out.append(b)
    }
    return out
}

func bytesToHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    fputs("usage: ecvrf-cli prove <sk> <alpha> | verify <pk> <pi> <alpha> | derive-pk <sk>\n", stderr)
    exit(2)
}

switch args[1] {
case "prove":
    guard args.count >= 4, let sk = hexToBytes(args[2]), let alpha = hexToBytes(args[3]) else {
        exit(2)
    }
    do {
        let pi = try ECVRF.prove(sk: sk, alpha: alpha)
        print(bytesToHex(pi))
    } catch {
        fputs("\(error)\n", stderr)
        exit(1)
    }
case "verify":
    guard args.count >= 5,
          let pk = hexToBytes(args[2]),
          let pi = hexToBytes(args[3]),
          let alpha = hexToBytes(args[4]) else {
        exit(2)
    }
    let (valid, beta) = ECVRF.verify(pk: pk, pi: pi, alpha: alpha)
    guard valid, let beta else { exit(1) }
    print(bytesToHex(beta))
case "derive-pk":
    guard args.count >= 3, let sk = hexToBytes(args[2]) else { exit(2) }
    do {
        let pk = try ECVRF.derivePublicKey(sk: sk)
        print(bytesToHex(pk))
    } catch {
        fputs("\(error)\n", stderr)
        exit(1)
    }
default:
    fputs("unknown command: \(args[1])\n", stderr)
    exit(2)
}
