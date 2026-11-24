package ecvrf

import java.math.BigInteger
import java.security.MessageDigest

/**
 * RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite byte 0x03) in pure Kotlin.
 * Uses java.math.BigInteger and java.security.MessageDigest (SHA-512) with zero
 * external runtime dependencies.
 */
object EcvrfEd25519 {
    const val SUITE_BYTE: Byte = 0x03
    const val SECRET_KEY_LEN = 32
    const val PUBLIC_KEY_LEN = 32
    const val PROOF_LEN = 80
    const val BETA_LEN = 64
    private const val CHALLENGE_LEN = 16

    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val Q: BigInteger = BigInteger.ONE.shiftLeft(252)
        .add(BigInteger("27742317777372353535851937790883648493"))
    private val P_MINUS_2: BigInteger = P.subtract(BigInteger.TWO)
    private val P_PLUS_3_DIV_8: BigInteger = P.add(BigInteger.valueOf(3)).shiftRight(3)
    private val SQRT_M1: BigInteger = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)
    private val D: BigInteger = BigInteger.valueOf(-121665)
        .multiply(BigInteger.valueOf(121666).modPow(P_MINUS_2, P))
        .mod(P)

    private data class Point(
        val x: BigInteger,
        val y: BigInteger,
        val z: BigInteger,
        val t: BigInteger,
    )

    private val IDENTITY = Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)
    private val BASE_POINT: Point = run {
        val by = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modPow(P_MINUS_2, P)).mod(P)
        val bx = xRecover(by)!!
        Point(bx, by, BigInteger.ONE, bx.multiply(by).mod(P))
    }

    data class VerifyResult(val valid: Boolean, val beta: ByteArray?) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is VerifyResult) return false
            return valid == other.valid && beta.contentEquals(other.beta)
        }

        override fun hashCode(): Int = 31 * valid.hashCode() + (beta?.contentHashCode() ?: 0)
    }

    private fun sha512(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-512")
        for (part in parts) md.update(part)
        return md.digest()
    }

    private fun fromLE(bytes: ByteArray): BigInteger {
        val be = ByteArray(bytes.size)
        for (i in bytes.indices) be[i] = bytes[bytes.size - 1 - i]
        return BigInteger(1, be)
    }

    private fun toLE(v: BigInteger, len: Int): ByteArray {
        val out = ByteArray(len)
        val be = v.toByteArray()
        var dst = 0
        for (i in be.size - 1 downTo 0) {
            if (dst < len) {
                out[dst++] = be[i]
            }
        }
        return out
    }

    private fun xRecover(y: BigInteger): BigInteger? {
        val yy = y.multiply(y).mod(P)
        val u = yy.subtract(BigInteger.ONE).mod(P)
        val v = D.multiply(yy).add(BigInteger.ONE).mod(P)
        val xx = u.multiply(v.modPow(P_MINUS_2, P)).mod(P)
        var x = xx.modPow(P_PLUS_3_DIV_8, P)
        if (x.multiply(x).subtract(xx).mod(P) != BigInteger.ZERO) {
            x = x.multiply(SQRT_M1).mod(P)
        }
        if (x.multiply(x).subtract(xx).mod(P) != BigInteger.ZERO) {
            return null
        }
        if (x.testBit(0)) {
            x = P.subtract(x)
        }
        return x
    }

    private fun pointAdd(p1: Point, p2: Point): Point {
        val a = p1.y.subtract(p1.x).multiply(p2.y.subtract(p2.x)).mod(P)
        val b = p1.y.add(p1.x).multiply(p2.y.add(p2.x)).mod(P)
        val c = BigInteger.TWO.multiply(p1.t).mod(P).multiply(p2.t).mod(P).multiply(D).mod(P)
        val dd = BigInteger.TWO.multiply(p1.z).multiply(p2.z).mod(P)
        val e = b.subtract(a).mod(P)
        val f = dd.subtract(c).mod(P)
        val g = dd.add(c).mod(P)
        val h = b.add(a).mod(P)
        return Point(
            e.multiply(f).mod(P),
            g.multiply(h).mod(P),
            f.multiply(g).mod(P),
            e.multiply(h).mod(P),
        )
    }

    private fun pointMulBy8(pt: Point): Point {
        val p2 = pointAdd(pt, pt)
        val p4 = pointAdd(p2, p2)
        return pointAdd(p4, p4)
    }

    private fun pointMulRaw(pt: Point, k: BigInteger): Point {
        var acc = IDENTITY
        var addend = pt
        var cur = k
        while (cur.signum() > 0) {
            if (cur.testBit(0)) {
                acc = pointAdd(acc, addend)
            }
            addend = pointAdd(addend, addend)
            cur = cur.shiftRight(1)
        }
        return acc
    }

    private fun pointMul(pt: Point, k: BigInteger): Point = pointMulRaw(pt, k.mod(Q))

    private fun isIdentity(pt: Point): Boolean =
        pt.x.mod(P) == BigInteger.ZERO && pt.y.subtract(pt.z).mod(P) == BigInteger.ZERO

    private fun encodePoint(pt: Point): ByteArray {
        val zi = pt.z.modPow(P_MINUS_2, P)
        val ax = pt.x.multiply(zi).mod(P)
        val ay = pt.y.multiply(zi).mod(P)
        val out = toLE(ay, 32)
        if (ax.testBit(0)) {
            out[31] = (out[31].toInt() or 0x80).toByte()
        }
        return out
    }

    private fun decodePoint(b: ByteArray): Point? {
        if (b.size != 32) return null
        val sign = (b[31].toInt() ushr 7) and 1
        val yBytes = b.copyOf()
        yBytes[31] = (yBytes[31].toInt() and 0x7f).toByte()
        val y = fromLE(yBytes)
        if (y >= P) return null
        var x = xRecover(y) ?: return null
        if (x == BigInteger.ZERO && sign == 1) return null
        if ((if (x.testBit(0)) 1 else 0) != sign) {
            x = P.subtract(x)
        }
        return Point(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    private fun validateKey(pk: ByteArray): Point? {
        val y = decodePoint(pk) ?: return null
        if (isIdentity(pointMulBy8(y))) return null
        return y
    }

    fun isPublicKey(pk: ByteArray): Boolean = validateKey(pk) != null

    private fun expandSecretKey(sk: ByteArray): Pair<BigInteger, ByteArray> {
        require(sk.size == SECRET_KEY_LEN) { "secret key must be $SECRET_KEY_LEN bytes" }
        val h = sha512(sk)
        val xb = h.copyOfRange(0, 32)
        xb[0] = (xb[0].toInt() and 248).toByte()
        xb[31] = ((xb[31].toInt() and 127) or 64).toByte()
        return fromLE(xb) to h.copyOfRange(32, 64)
    }

    private fun encodeToCurve(pk: ByteArray, alpha: ByteArray): Point {
        val head = byteArrayOf(SUITE_BYTE, 0x01)
        val tail = byteArrayOf(0x00, 0x00)
        for (ctr in 0..255) {
            tail[0] = ctr.toByte()
            val h = sha512(head, pk, alpha, tail)
            val pt = decodePoint(h.copyOfRange(0, 32))
            if (pt != null) {
                return pointMulBy8(pt)
            }
        }
        throw IllegalStateException("encode_to_curve failed after 256 iterations")
    }

    private fun challenge(y: Point, h: Point, gamma: Point, u: Point, v: Point): Pair<BigInteger, ByteArray> {
        val hash = sha512(
            byteArrayOf(SUITE_BYTE, 0x02),
            encodePoint(y),
            encodePoint(h),
            encodePoint(gamma),
            encodePoint(u),
            encodePoint(v),
            byteArrayOf(0x00),
        )
        val cBytes = hash.copyOfRange(0, CHALLENGE_LEN)
        return fromLE(cBytes) to cBytes
    }

    private fun gammaToHash(gamma: Point): ByteArray = sha512(
        byteArrayOf(SUITE_BYTE, 0x03),
        encodePoint(pointMulBy8(gamma)),
        byteArrayOf(0x00),
    )

    private fun decodeProof(pi: ByteArray): Triple<Point, BigInteger, BigInteger>? {
        if (pi.size != PROOF_LEN) return null
        val gamma = decodePoint(pi.copyOfRange(0, 32)) ?: return null
        val c = fromLE(pi.copyOfRange(32, 48))
        val s = fromLE(pi.copyOfRange(48, 80))
        if (s >= Q) return null
        return Triple(gamma, c, s)
    }

    fun derivePublicKey(sk: ByteArray): ByteArray {
        val (x, _) = expandSecretKey(sk)
        return encodePoint(pointMulRaw(BASE_POINT, x))
    }

    fun prove(sk: ByteArray, alpha: ByteArray): ByteArray {
        val (x, prefix) = expandSecretKey(sk)
        val y = pointMulRaw(BASE_POINT, x)
        val pk = encodePoint(y)
        val h = encodeToCurve(pk, alpha)
        val gamma = pointMulRaw(h, x)
        val kHash = sha512(prefix, encodePoint(h))
        val k = fromLE(kHash).mod(Q)
        val u = pointMul(BASE_POINT, k)
        val v = pointMul(h, k)
        val (c, cBytes) = challenge(y, h, gamma, u, v)
        val s = k.add(c.multiply(x)).mod(Q)

        val pi = ByteArray(PROOF_LEN)
        encodePoint(gamma).copyInto(pi, 0)
        cBytes.copyInto(pi, 32)
        toLE(s, 32).copyInto(pi, 48)
        return pi
    }

    fun proofToHash(pi: ByteArray): ByteArray {
        val (gamma, _, _) = decodeProof(pi) ?: throw IllegalArgumentException("invalid proof")
        return gammaToHash(gamma)
    }

    fun verify(pk: ByteArray, pi: ByteArray, alpha: ByteArray): VerifyResult {
        val y = validateKey(pk) ?: return VerifyResult(false, null)
        val (gamma, c, s) = decodeProof(pi) ?: return VerifyResult(false, null)
        val h = encodeToCurve(pk, alpha)
        val negC = Q.subtract(c).mod(Q)
        val u = pointAdd(pointMul(BASE_POINT, s), pointMul(y, negC))
        val v = pointAdd(pointMul(h, s), pointMul(gamma, negC))
        val (cPrime, _) = challenge(y, h, gamma, u, v)
        if (cPrime != c) return VerifyResult(false, null)
        return VerifyResult(true, gammaToHash(gamma))
    }
}
