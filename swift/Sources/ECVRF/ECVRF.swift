// RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite byte 0x03)
// Zero-dependency Swift implementation using radix-2^51 Edwards25519 field arithmetic
// and CryptoKit SHA-512 (with pure-Swift FIPS 180-4 fallback on non-Apple platforms).

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

public enum ECVRFError: Error, Equatable {
    case invalidSecretKey
    case invalidPublicKey
    case invalidProof
    case encodeToCurveFailed
}

public enum ECVRF {
    public static let suiteByte: UInt8 = 0x03
    public static let secretKeyLength = 32
    public static let publicKeyLength = 32
    public static let proofLength = 80
    public static let betaLength = 64
    private static let challengeLength = 16

    // MARK: - Public API

    /// Reports whether `pk` is a valid canonical non-small-order 32-byte Ed25519 public key.
    public static func isPublicKey(_ pk: [UInt8]) -> Bool {
        return validateKey(pk) != nil
    }

    /// Derives the 32-byte Ed25519 public key from a 32-byte secret key seed.
    public static func derivePublicKey(sk: [UInt8]) throws -> [UInt8] {
        let (x, _) = try expandSecretKey(sk)
        return EdPoint.basePoint.multiplyBits(x).toBytes()
    }

    /// RFC 9381 Section 5.1: Generates an 80-byte proof `Gamma (32) || c (16) || s (32)`.
    public static func prove(sk: [UInt8], alpha: [UInt8]) throws -> [UInt8] {
        let (xBytes, prefix) = try expandSecretKey(sk)
        let y = EdPoint.basePoint.multiplyBits(xBytes)
        let pk = y.toBytes()
        guard let h = encodeToCurveTAI(pk: pk, alpha: alpha) else {
            throw ECVRFError.encodeToCurveFailed
        }
        let gamma = h.multiplyBits(xBytes)

        var nonceIn = [UInt8]()
        nonceIn.reserveCapacity(64)
        nonceIn.append(contentsOf: prefix)
        nonceIn.append(contentsOf: h.toBytes())
        let kHash = sha512(nonceIn)
        let k = Scalar.reduce64(kHash)

        let u = EdPoint.basePoint.multiplyBits(k.toBytes())
        let v = h.multiplyBits(k.toBytes())
        let (c, cBytes) = challengeGeneration(y: y, h: h, gamma: gamma, u: u, v: v)

        let xScalar = Scalar.reduce32(xBytes)
        let s = Scalar.mulAdd(c, xScalar, k)

        var pi = [UInt8]()
        pi.reserveCapacity(proofLength)
        pi.append(contentsOf: gamma.toBytes())
        pi.append(contentsOf: cBytes)
        pi.append(contentsOf: s.toBytes())
        return pi
    }

    /// RFC 9381 Section 5.2: Extracts the 64-byte VRF output beta without verifying the proof.
    public static func proofToHash(pi: [UInt8]) throws -> [UInt8] {
        guard let (gamma, _, _) = decodeProof(pi) else {
            throw ECVRFError.invalidProof
        }
        return gammaToHash(gamma)
    }

    /// RFC 9381 Section 5.3: Verifies a proof and returns `(valid, beta)`.
    public static func verify(pk: [UInt8], pi: [UInt8], alpha: [UInt8]) -> (valid: Bool, beta: [UInt8]?) {
        guard let y = validateKey(pk),
              let (gamma, cBytes, s) = decodeProof(pi),
              let h = encodeToCurveTAI(pk: pk, alpha: alpha) else {
            return (false, nil)
        }
        let c = Scalar.from16Bytes(cBytes)
        let negC = Scalar.negate(c)
        let sBytes = s.toBytes()
        let negCBytes = negC.toBytes()

        let u = EdPoint.basePoint.multiplyBits(sBytes).add(y.multiplyBits(negCBytes))
        let v = h.multiplyBits(sBytes).add(gamma.multiplyBits(negCBytes))
        let (_, cPrimeBytes) = challengeGeneration(y: y, h: h, gamma: gamma, u: u, v: v)

        var diff: UInt8 = 0
        for i in 0..<challengeLength {
            diff |= cBytes[i] ^ cPrimeBytes[i]
        }
        if diff != 0 {
            return (false, nil)
        }
        return (true, gammaToHash(gamma))
    }

    // MARK: - Internal RFC 9381 Helpers

    private static func expandSecretKey(_ sk: [UInt8]) throws -> ([UInt8], [UInt8]) {
        guard sk.count == secretKeyLength else {
            throw ECVRFError.invalidSecretKey
        }
        let h = sha512(sk)
        var x = Array(h[0..<32])
        x[0] &= 248
        x[31] &= 127
        x[31] |= 64
        return (x, Array(h[32..<64]))
    }

    private static func validateKey(_ pk: [UInt8]) -> EdPoint? {
        guard pk.count == publicKeyLength, let y = EdPoint.fromBytes(pk) else {
            return nil
        }
        if y.mulByCofactor().isIdentity {
            return nil
        }
        return y
    }

    private static func encodeToCurveTAI(pk: [UInt8], alpha: [UInt8]) -> EdPoint? {
        var buf = [UInt8]()
        buf.reserveCapacity(2 + pk.count + alpha.count + 2)
        buf.append(suiteByte)
        buf.append(0x01)
        buf.append(contentsOf: pk)
        buf.append(contentsOf: alpha)
        buf.append(0x00)
        buf.append(0x00)
        let ctrIdx = buf.count - 2

        for ctr in 0..<256 {
            buf[ctrIdx] = UInt8(ctr)
            let h = sha512(buf)
            if let pt = EdPoint.fromBytes(Array(h[0..<32])) {
                return pt.mulByCofactor()
            }
        }
        return nil
    }

    private static func challengeGeneration(
        y: EdPoint, h: EdPoint, gamma: EdPoint, u: EdPoint, v: EdPoint
    ) -> (Scalar, [UInt8]) {
        var buf = [UInt8]()
        buf.reserveCapacity(2 + 5 * 32 + 1)
        buf.append(suiteByte)
        buf.append(0x02)
        buf.append(contentsOf: y.toBytes())
        buf.append(contentsOf: h.toBytes())
        buf.append(contentsOf: gamma.toBytes())
        buf.append(contentsOf: u.toBytes())
        buf.append(contentsOf: v.toBytes())
        buf.append(0x00)

        let hash = sha512(buf)
        let cBytes = Array(hash[0..<challengeLength])
        return (Scalar.from16Bytes(cBytes), cBytes)
    }

    private static func gammaToHash(_ gamma: EdPoint) -> [UInt8] {
        var buf = [UInt8]()
        buf.reserveCapacity(35)
        buf.append(suiteByte)
        buf.append(0x03)
        buf.append(contentsOf: gamma.mulByCofactor().toBytes())
        buf.append(0x00)
        return sha512(buf)
    }

    private static func decodeProof(_ pi: [UInt8]) -> (EdPoint, [UInt8], Scalar)? {
        guard pi.count == proofLength else { return nil }
        guard let gamma = EdPoint.fromBytes(Array(pi[0..<32])) else { return nil }
        let cBytes = Array(pi[32..<48])
        guard let s = Scalar.fromCanonicalBytes(Array(pi[48..<80])) else { return nil }
        return (gamma, cBytes, s)
    }
}

// MARK: - SHA-512

private func sha512(_ data: [UInt8]) -> [UInt8] {
    #if canImport(CryptoKit)
    return Array(CryptoKit.SHA512.hash(data: data))
    #else
    return pureSHA512(data)
    #endif
}

#if !canImport(CryptoKit)
private func pureSHA512(_ message: [UInt8]) -> [UInt8] {
    let k: [UInt64] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]
    var h: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]
    var msg = message
    let bitLen = UInt64(message.count) &* 8
    msg.append(0x80)
    while (msg.count % 128) != 112 {
        msg.append(0x00)
    }
    for _ in 0..<8 { msg.append(0x00) }
    for shift in stride(from: 56, through: 0, by: -8) {
        msg.append(UInt8((bitLen >> shift) & 0xff))
    }
    @inline(__always) func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 { (x >> n) | (x << (64 - n)) }

    var w = [UInt64](repeating: 0, count: 80)
    for chunkStart in stride(from: 0, to: msg.count, by: 128) {
        for i in 0..<16 {
            let off = chunkStart + i * 8
            w[i] = (UInt64(msg[off]) << 56) | (UInt64(msg[off + 1]) << 48)
                | (UInt64(msg[off + 2]) << 40) | (UInt64(msg[off + 3]) << 32)
                | (UInt64(msg[off + 4]) << 24) | (UInt64(msg[off + 5]) << 16)
                | (UInt64(msg[off + 6]) << 8) | UInt64(msg[off + 7])
        }
        for i in 16..<80 {
            let s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7)
            let s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
        }
        var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
        for i in 0..<80 {
            let s1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)
            let ch = (e & f) ^ ((~e) & g)
            let temp1 = hh &+ s1 &+ ch &+ k[i] &+ w[i]
            let s0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)
            let maj = (a & b) ^ (a & c) ^ (b & c)
            let temp2 = s0 &+ maj
            hh = g; g = f; f = e; e = d &+ temp1
            d = c; c = b; b = a; a = temp1 &+ temp2
        }
        h[0] &+= a; h[1] &+= b; h[2] &+= c; h[3] &+= d
        h[4] &+= e; h[5] &+= f; h[6] &+= g; h[7] &+= hh
    }
    var out = [UInt8](repeating: 0, count: 64)
    for i in 0..<8 {
        for j in 0..<8 {
            out[i * 8 + j] = UInt8((h[i] >> ((7 - j) * 8)) & 0xff)
        }
    }
    return out
}
#endif

// MARK: - 128-bit Unsigned Helper

private struct U128 {
    var hi: UInt64
    var lo: UInt64

    @inline(__always) init(_ v: UInt64 = 0) { self.hi = 0; self.lo = v }
    @inline(__always) init(hi: UInt64, lo: UInt64) { self.hi = hi; self.lo = lo }

    @inline(__always) static func mul(_ a: UInt64, _ b: UInt64) -> U128 {
        let p = a.multipliedFullWidth(by: b)
        return U128(hi: p.high, lo: p.low)
    }

    @inline(__always) static func += (lhs: inout U128, rhs: U128) {
        let (lo, overflow) = lhs.lo.addingReportingOverflow(rhs.lo)
        lhs.lo = lo
        lhs.hi = lhs.hi &+ rhs.hi &+ (overflow ? 1 : 0)
    }

    @inline(__always) static func += (lhs: inout U128, rhs: UInt64) {
        let (lo, overflow) = lhs.lo.addingReportingOverflow(rhs)
        lhs.lo = lo
        if overflow { lhs.hi &+= 1 }
    }

    @inline(__always) func shiftRight51() -> UInt64 {
        return (lo >> 51) | (hi << 13)
    }
}

// MARK: - Field Element GF(2^255 - 19) in radix 2^51

private struct Fe: Equatable {
    var l0: UInt64
    var l1: UInt64
    var l2: UInt64
    var l3: UInt64
    var l4: UInt64

    static let mask51: UInt64 = (1 << 51) - 1
    static let zero = Fe(0, 0, 0, 0, 0)
    static let one = Fe(1, 0, 0, 0, 0)

    // d = -121665 / 121666 mod p
    static let d: Fe = Fe.fromSmall(121665).negate().mul(Fe.fromSmall(121666).invert())
    // 2 * d mod p
    static let d2: Fe = d.add(d)
    // sqrt(-1) = 2^((p-1)/4) mod p
    static let sqrtM1: Fe = Fe.fromSmall(2).powPMinus1Div4()

    init(_ l0: UInt64, _ l1: UInt64, _ l2: UInt64, _ l3: UInt64, _ l4: UInt64) {
        self.l0 = l0; self.l1 = l1; self.l2 = l2; self.l3 = l3; self.l4 = l4
    }

    static func fromSmall(_ v: UInt64) -> Fe {
        return Fe(v, 0, 0, 0, 0)
    }

    /// Parses 32-byte little-endian canonical field element (< 2^255 - 19), ignoring bit 255.
    /// Returns nil if the 255-bit value is >= 2^255 - 19.
    static func fromCanonicalBytes(_ bytes: [UInt8]) -> Fe? {
        guard bytes.count == 32 else { return nil }
        var b = bytes
        b[31] &= 0x7f
        // Check < 2^255 - 19:
        // p = [0xed, 0xff, ..., 0xff, 0x7f]
        var allFF = (b[31] == 0x7f)
        if allFF {
            for i in 1..<31 {
                if b[i] != 0xff { allFF = false; break }
            }
            if allFF && b[0] >= 0xed {
                return nil
            }
        }
        func load64(_ off: Int) -> UInt64 {
            var v: UInt64 = 0
            for i in 0..<8 { v |= UInt64(b[off + i]) << (i * 8) }
            return v
        }
        let l0 = load64(0) & mask51
        let l1 = (load64(6) >> 3) & mask51
        let l2 = (load64(12) >> 6) & mask51
        let l3 = (load64(19) >> 1) & mask51
        let l4 = (load64(24) >> 12) & mask51
        return Fe(l0, l1, l2, l3, l4)
    }

    private mutating func carry() {
        var c = l0 >> 51; l0 &= Fe.mask51; l1 &+= c
        c = l1 >> 51; l1 &= Fe.mask51; l2 &+= c
        c = l2 >> 51; l2 &= Fe.mask51; l3 &+= c
        c = l3 >> 51; l3 &= Fe.mask51; l4 &+= c
        c = l4 >> 51; l4 &= Fe.mask51; l0 &+= c &* 19
        c = l0 >> 51; l0 &= Fe.mask51; l1 &+= c
    }

    func toBytes() -> [UInt8] {
        var t = self
        t.carry()
        t.carry()
        // Compute q = floor((t + 19) / 2^255)
        var q = (t.l0 + 19) >> 51
        q = (t.l1 + q) >> 51
        q = (t.l2 + q) >> 51
        q = (t.l3 + q) >> 51
        q = (t.l4 + q) >> 51

        // If q == 1, subtract p by adding 19 and dropping bit 255
        t.l0 += 19 * q
        var c = t.l0 >> 51; t.l0 &= Fe.mask51; t.l1 += c
        c = t.l1 >> 51; t.l1 &= Fe.mask51; t.l2 += c
        c = t.l2 >> 51; t.l2 &= Fe.mask51; t.l3 += c
        c = t.l3 >> 51; t.l3 &= Fe.mask51; t.l4 += c
        t.l4 &= Fe.mask51

        var out = [UInt8](repeating: 0, count: 32)
        // Pack 5 x 51-bit limbs into 32 LE bytes
        let limbs = [t.l0, t.l1, t.l2, t.l3, t.l4]
        var bitPos = 0
        for limb in limbs {
            var val = limb
            var remaining = 51
            while remaining > 0 {
                let byteIdx = bitPos / 8
                let bitOff = bitPos % 8
                let take = min(remaining, 8 - bitOff)
                let mask: UInt64 = (1 << take) - 1
                out[byteIdx] |= UInt8((val & mask) << bitOff)
                val >>= take
                bitPos += take
                remaining -= take
            }
        }
        return out
    }

    static func == (lhs: Fe, rhs: Fe) -> Bool {
        return lhs.toBytes() == rhs.toBytes()
    }

    var isZero: Bool {
        return toBytes().allSatisfy { $0 == 0 }
    }

    var isNegative: Bool {
        return (toBytes()[0] & 1) == 1
    }

    func add(_ b: Fe) -> Fe {
        var r = Fe(l0 + b.l0, l1 + b.l1, l2 + b.l2, l3 + b.l3, l4 + b.l4)
        r.carry()
        return r
    }

    func sub(_ b: Fe) -> Fe {
        // Add 2*p before subtracting to stay non-negative
        let p0: UInt64 = 0x000fffffffffffda
        let p1: UInt64 = 0x000ffffffffffffe
        var r = Fe(
            (l0 + p0) - b.l0,
            (l1 + p1) - b.l1,
            (l2 + p1) - b.l2,
            (l3 + p1) - b.l3,
            (l4 + p1) - b.l4
        )
        r.carry()
        return r
    }

    func negate() -> Fe {
        return Fe.zero.sub(self)
    }

    func mul(_ b: Fe) -> Fe {
        let a1_19 = l1 &* 19
        let a2_19 = l2 &* 19
        let a3_19 = l3 &* 19
        let a4_19 = l4 &* 19

        var r0 = U128.mul(l0, b.l0); r0 += U128.mul(a1_19, b.l4); r0 += U128.mul(a2_19, b.l3); r0 += U128.mul(a3_19, b.l2); r0 += U128.mul(a4_19, b.l1)
        var r1 = U128.mul(l0, b.l1); r1 += U128.mul(l1, b.l0); r1 += U128.mul(a2_19, b.l4); r1 += U128.mul(a3_19, b.l3); r1 += U128.mul(a4_19, b.l2)
        var r2 = U128.mul(l0, b.l2); r2 += U128.mul(l1, b.l1); r2 += U128.mul(l2, b.l0); r2 += U128.mul(a3_19, b.l4); r2 += U128.mul(a4_19, b.l3)
        var r3 = U128.mul(l0, b.l3); r3 += U128.mul(l1, b.l2); r3 += U128.mul(l2, b.l1); r3 += U128.mul(l3, b.l0); r3 += U128.mul(a4_19, b.l4)
        var r4 = U128.mul(l0, b.l4); r4 += U128.mul(l1, b.l3); r4 += U128.mul(l2, b.l2); r4 += U128.mul(l3, b.l1); r4 += U128.mul(l4, b.l0)

        var c = r0.shiftRight51(); var o0 = r0.lo & Fe.mask51
        r1 += c; c = r1.shiftRight51(); var o1 = r1.lo & Fe.mask51
        r2 += c; c = r2.shiftRight51(); let o2 = r2.lo & Fe.mask51
        r3 += c; c = r3.shiftRight51(); let o3 = r3.lo & Fe.mask51
        r4 += c; c = r4.shiftRight51(); let o4 = r4.lo & Fe.mask51
        o0 &+= c &* 19
        c = o0 >> 51; o0 &= Fe.mask51; o1 &+= c
        return Fe(o0, o1, o2, o3, o4)
    }

    func sqr() -> Fe {
        return mul(self)
    }

    func pow2k(_ k: Int) -> Fe {
        var r = self
        for _ in 0..<k { r = r.sqr() }
        return r
    }

    // Computes self^(2^252 - 3) mod p = self^((p - 5) / 8)
    func pow22523() -> Fe {
        let t0 = sqr()
        let t1 = t0.pow2k(2)
        let t2 = mul(t1)
        let t3 = t0.mul(t2)
        let t4 = t3.sqr()
        let t5 = t2.mul(t4)
        let t6 = t5.pow2k(5)
        let t7 = t6.mul(t5)
        let t8 = t7.pow2k(10)
        let t9 = t8.mul(t7)
        let t10 = t9.pow2k(20)
        let t11 = t10.mul(t9)
        let t12 = t11.pow2k(10)
        let t13 = t12.mul(t7)
        let t14 = t13.pow2k(50)
        let t15 = t14.mul(t13)
        let t16 = t15.pow2k(100)
        let t17 = t16.mul(t15)
        let t18 = t17.pow2k(50)
        let t19 = t18.mul(t13)
        let t20 = t19.pow2k(2)
        return t20.mul(self)
    }

    // Computes self^(p - 2) mod p
    func invert() -> Fe {
        let t0 = sqr()
        let t1 = t0.pow2k(2)
        let t2 = mul(t1)
        let t3 = t0.mul(t2)
        let t4 = t3.sqr()
        let t5 = t2.mul(t4)
        let t6 = t5.pow2k(5)
        let t7 = t6.mul(t5)
        let t8 = t7.pow2k(10)
        let t9 = t8.mul(t7)
        let t10 = t9.pow2k(20)
        let t11 = t10.mul(t9)
        let t12 = t11.pow2k(10)
        let t13 = t12.mul(t7)
        let t14 = t13.pow2k(50)
        let t15 = t14.mul(t13)
        let t16 = t15.pow2k(100)
        let t17 = t16.mul(t15)
        let t18 = t17.pow2k(50)
        let t19 = t18.mul(t13)
        let t20 = t19.pow2k(5)
        return t20.mul(t3)
    }

    // Computes self^((p - 1) / 4) = self^(2^253 - 5)
    func powPMinus1Div4() -> Fe {
        // (p - 1)/4 = 2 * ((p - 5)/8) + 1 + 1 = 2*(2^252 - 3) + 1
        return pow22523().sqr().mul(self)
    }

    // Computes self^((p + 3) / 8) = self^(2^252 - 2)
    func powPPlus3Div8() -> Fe {
        return pow22523().mul(self)
    }
}

// MARK: - Edwards25519 Point (Extended Homogeneous Coordinates X:Y:Z:T)

private struct EdPoint {
    let x: Fe
    let y: Fe
    let z: Fe
    let t: Fe

    static let identity = EdPoint(x: .zero, y: .one, z: .one, t: .zero)

    static let basePoint: EdPoint = {
        let by = Fe.fromSmall(4).mul(Fe.fromSmall(5).invert())
        let bx = xRecover(by)!
        return EdPoint(x: bx, y: by, z: .one, t: bx.mul(by))
    }()

    static func xRecover(_ y: Fe) -> Fe? {
        let yy = y.sqr()
        let u = yy.sub(.one)
        let v = Fe.d.mul(yy).add(.one)
        let xx = u.mul(v.invert())
        var x = xx.powPPlus3Div8()
        if x.sqr() != xx {
            x = x.mul(Fe.sqrtM1)
        }
        if x.sqr() != xx {
            return nil
        }
        if x.isNegative {
            x = x.negate()
        }
        return x
    }

    var isIdentity: Bool {
        return x.isZero && y == z
    }

    static func fromBytes(_ bytes: [UInt8]) -> EdPoint? {
        guard bytes.count == 32 else { return nil }
        let sign = (bytes[31] >> 7) & 1
        guard let y = Fe.fromCanonicalBytes(bytes) else { return nil }
        guard var x = xRecover(y) else { return nil }
        if x.isZero && sign == 1 { return nil }
        if (x.isNegative ? 1 : 0) != sign {
            x = x.negate()
        }
        return EdPoint(x: x, y: y, z: .one, t: x.mul(y))
    }

    func toBytes() -> [UInt8] {
        let zi = z.invert()
        let ax = x.mul(zi)
        let ay = y.mul(zi)
        var out = ay.toBytes()
        if ax.isNegative {
            out[31] |= 0x80
        }
        return out
    }

    func add(_ other: EdPoint) -> EdPoint {
        let a = y.sub(x).mul(other.y.sub(other.x))
        let b = y.add(x).mul(other.y.add(other.x))
        let c = t.mul(other.t).mul(Fe.d2)
        let dd = z.mul(other.z)
        let d2 = dd.add(dd)
        let e = b.sub(a)
        let f = d2.sub(c)
        let g = d2.add(c)
        let h = b.add(a)
        return EdPoint(x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h))
    }

    func mulByCofactor() -> EdPoint {
        let p2 = add(self)
        let p4 = p2.add(p2)
        return p4.add(p4)
    }

    /// Multiplies this point by an arbitrary 32-byte little-endian unsigned scalar.
    func multiplyBits(_ scalarLE: [UInt8]) -> EdPoint {
        var acc = EdPoint.identity
        var addend = self
        for byte in scalarLE {
            for bit in 0..<8 {
                if ((byte >> bit) & 1) == 1 {
                    acc = acc.add(addend)
                }
                addend = addend.add(addend)
            }
        }
        return acc
    }
}

// MARK: - Scalar Arithmetic mod q (2^252 + 27742317777372353535851937790883648493)

private struct Scalar {
    // Little-endian 32-bit limbs, always < q (8 limbs = 256 bits)
    private let limbs: [UInt32]

    // q in little-endian UInt32 limbs:
    // 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    private static let qLimbs: [UInt32] = [
        0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
        0x00000000, 0x00000000, 0x00000000, 0x10000000,
    ]

    private init(_ limbs: [UInt32]) {
        var padded = limbs
        while padded.count < 8 { padded.append(0) }
        self.limbs = Array(padded[0..<8])
    }

    static func from16Bytes(_ b: [UInt8]) -> Scalar {
        var padded = b
        while padded.count < 32 { padded.append(0) }
        return Scalar(bytesToLimbs(padded))
    }

    static func fromCanonicalBytes(_ b: [UInt8]) -> Scalar? {
        guard b.count == 32 else { return nil }
        let l = bytesToLimbs(b)
        if compare(l, qLimbs) >= 0 { return nil }
        return Scalar(l)
    }

    static func reduce32(_ b: [UInt8]) -> Scalar {
        return Scalar(modQ(bytesToLimbs(b)))
    }

    static func reduce64(_ b: [UInt8]) -> Scalar {
        return Scalar(modQ(bytesToLimbs(b)))
    }

    static func negate(_ a: Scalar) -> Scalar {
        if a.limbs.allSatisfy({ $0 == 0 }) {
            return a
        }
        return Scalar(subLimbs(qLimbs, a.limbs))
    }

    static func mulAdd(_ a: Scalar, _ b: Scalar, _ c: Scalar) -> Scalar {
        let prod = mulLimbs(a.limbs, b.limbs)
        let sum = addLimbs(prod, c.limbs)
        return Scalar(modQ(sum))
    }

    func toBytes() -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        for i in 0..<8 {
            let v = limbs[i]
            out[i * 4 + 0] = UInt8(v & 0xff)
            out[i * 4 + 1] = UInt8((v >> 8) & 0xff)
            out[i * 4 + 2] = UInt8((v >> 16) & 0xff)
            out[i * 4 + 3] = UInt8((v >> 24) & 0xff)
        }
        return out
    }

    // MARK: - BigUInt helpers (base 2^32, little-endian)

    private static func bytesToLimbs(_ b: [UInt8]) -> [UInt32] {
        let count = (b.count + 3) / 4
        var out = [UInt32](repeating: 0, count: count)
        for i in 0..<b.count {
            out[i / 4] |= UInt32(b[i]) << ((i % 4) * 8)
        }
        return out
    }

    private static func trim(_ a: [UInt32]) -> [UInt32] {
        var r = a
        while r.count > 1 && r.last == 0 { r.removeLast() }
        return r
    }

    private static func compare(_ a: [UInt32], _ b: [UInt32]) -> Int {
        let n = max(a.count, b.count)
        for i in stride(from: n - 1, through: 0, by: -1) {
            let ai = i < a.count ? a[i] : 0
            let bi = i < b.count ? b[i] : 0
            if ai < bi { return -1 }
            if ai > bi { return 1 }
        }
        return 0
    }

    private static func addLimbs(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let n = max(a.count, b.count)
        var out = [UInt32](repeating: 0, count: n + 1)
        var carry: UInt64 = 0
        for i in 0..<n {
            let sum = carry + UInt64(i < a.count ? a[i] : 0) + UInt64(i < b.count ? b[i] : 0)
            out[i] = UInt32(sum & 0xffffffff)
            carry = sum >> 32
        }
        out[n] = UInt32(carry)
        return trim(out)
    }

    private static func subLimbs(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let n = max(a.count, b.count)
        var out = [UInt32](repeating: 0, count: n)
        var borrow: Int64 = 0
        for i in 0..<n {
            let diff = Int64(i < a.count ? a[i] : 0) - Int64(i < b.count ? b[i] : 0) - borrow
            if diff < 0 {
                out[i] = UInt32(diff + (1 << 32))
                borrow = 1
            } else {
                out[i] = UInt32(diff)
                borrow = 0
            }
        }
        return trim(out)
    }

    private static func mulLimbs(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: a.count + b.count)
        for i in 0..<a.count {
            var carry: UInt64 = 0
            for j in 0..<b.count {
                let prod = UInt64(a[i]) * UInt64(b[j]) + UInt64(out[i + j]) + carry
                out[i + j] = UInt32(prod & 0xffffffff)
                carry = prod >> 32
            }
            out[i + b.count] = UInt32(carry)
        }
        return trim(out)
    }

    private static func bitLength(_ a: [UInt32]) -> Int {
        let t = trim(a)
        guard let top = t.last, top != 0 else { return 0 }
        return (t.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    private static func shl(_ a: [UInt32], _ bits: Int) -> [UInt32] {
        if bits == 0 { return a }
        let wordShift = bits / 32
        let bitShift = bits % 32
        var out = [UInt32](repeating: 0, count: a.count + wordShift + 1)
        for i in 0..<a.count {
            let v = UInt64(a[i]) << bitShift
            out[i + wordShift] |= UInt32(v & 0xffffffff)
            out[i + wordShift + 1] |= UInt32(v >> 32)
        }
        return trim(out)
    }

    /// Computes a mod q via shift-subtract long division.
    private static func modQ(_ a: [UInt32]) -> [UInt32] {
        var rem = trim(a)
        let qBits = bitLength(qLimbs)
        while compare(rem, qLimbs) >= 0 {
            let rBits = bitLength(rem)
            var shift = rBits - qBits
            var shifted = shl(qLimbs, shift)
            if compare(shifted, rem) > 0 {
                shift -= 1
                shifted = shl(qLimbs, shift)
            }
            rem = subLimbs(rem, shifted)
        }
        return rem
    }
}
