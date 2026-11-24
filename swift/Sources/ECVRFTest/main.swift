import ECVRF
import Foundation

struct VectorFile: Decodable {
    let suite: String
    let spec: String
    let vectors: [PositiveVector]
    let negative_vectors: [NegativeVector]
}

struct PositiveVector: Decodable {
    let label: String
    let sk: String
    let pk: String
    let alpha: String
    let pi: String
    let beta: String
}

struct NegativeVector: Decodable {
    let description: String
    let pk: String
    let alpha: String
    let pi: String
    let expected_verify: Bool
}

func hexToBytes(_ hex: String) -> [UInt8] {
    let chars = Array(hex)
    var out = [UInt8]()
    out.reserveCapacity(chars.count / 2)
    for i in stride(from: 0, to: chars.count, by: 2) {
        out.append(UInt8(String(chars[i...i + 1]), radix: 16)!)
    }
    return out
}

func bytesToHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

var passCount = 0
var failCount = 0

func check(_ cond: Bool, _ msg: String) {
    if cond {
        passCount += 1
    } else {
        failCount += 1
        fputs("FAIL: \(msg)\n", stderr)
    }
}

let vectorURL = URL(fileURLWithPath: "../vectors/vectors.json")
let data = try Data(contentsOf: vectorURL)
let vf = try JSONDecoder().decode(VectorFile.self, from: data)

check(vf.suite == "ECVRF-EDWARDS25519-SHA512-TAI", "unexpected suite \(vf.suite)")
check(vf.spec == "RFC 9381", "unexpected spec \(vf.spec)")

for vec in vf.vectors {
    let sk = hexToBytes(vec.sk)
    let alpha = hexToBytes(vec.alpha)

    do {
        let pk = try ECVRF.derivePublicKey(sk: sk)
        check(bytesToHex(pk) == vec.pk, "[\(vec.label)] pk mismatch")
        check(ECVRF.isPublicKey(pk), "[\(vec.label)] isPublicKey false")

        let pi = try ECVRF.prove(sk: sk, alpha: alpha)
        check(bytesToHex(pi) == vec.pi, "[\(vec.label)] pi mismatch")

        let beta = try ECVRF.proofToHash(pi: pi)
        check(bytesToHex(beta) == vec.beta, "[\(vec.label)] proofToHash mismatch")

        let (valid, vbeta) = ECVRF.verify(pk: pk, pi: pi, alpha: alpha)
        check(valid && vbeta.map(bytesToHex) == vec.beta, "[\(vec.label)] verify failed")
    } catch {
        check(false, "[\(vec.label)] threw \(error)")
    }
}

for neg in vf.negative_vectors {
    let (valid, beta) = ECVRF.verify(
        pk: hexToBytes(neg.pk),
        pi: hexToBytes(neg.pi),
        alpha: hexToBytes(neg.alpha)
    )
    check(valid == neg.expected_verify, "[\(neg.description)] expected \(neg.expected_verify), got \(valid)")
    if !neg.expected_verify {
        check(beta == nil, "[\(neg.description)] expected nil beta")
    }
}

print("Swift tests: \(passCount) passed, \(failCount) failed")
exit(failCount == 0 ? 0 : 1)
