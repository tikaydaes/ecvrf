package ecvrf

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EcvrfTest {
    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    // Minimal JSON parser for vectors/vectors.json (no external test dependency needed).
    private class JsonParser(private val s: String) {
        private var pos = 0

        private fun skipWs() {
            while (pos < s.length && s[pos].isWhitespace()) pos++
        }

        fun parseValue(): Any? {
            skipWs()
            return when (s[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't' -> { pos += 4; true }
                'f' -> { pos += 5; false }
                'n' -> { pos += 4; null }
                else -> parseNumber()
            }
        }

        private fun parseObject(): Map<String, Any?> {
            pos++ // '{'
            val map = LinkedHashMap<String, Any?>()
            skipWs()
            if (s[pos] == '}') { pos++; return map }
            while (true) {
                skipWs()
                val key = parseString()
                skipWs()
                pos++ // ':'
                map[key] = parseValue()
                skipWs()
                if (s[pos] == '}') { pos++; return map }
                pos++ // ','
            }
        }

        private fun parseArray(): List<Any?> {
            pos++ // '['
            val list = ArrayList<Any?>()
            skipWs()
            if (s[pos] == ']') { pos++; return list }
            while (true) {
                list.add(parseValue())
                skipWs()
                if (s[pos] == ']') { pos++; return list }
                pos++ // ','
            }
        }

        private fun parseString(): String {
            pos++ // '"'
            val sb = StringBuilder()
            while (s[pos] != '"') {
                val c = s[pos++]
                if (c == '\\') {
                    when (val e = s[pos++]) {
                        '"', '\\', '/' -> sb.append(e)
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val code = s.substring(pos, pos + 4).toInt(16)
                            sb.append(code.toChar())
                            pos += 4
                        }
                        else -> sb.append(e)
                    }
                } else {
                    sb.append(c)
                }
            }
            pos++ // '"'
            return sb.toString()
        }

        private fun parseNumber(): Long {
            val start = pos
            if (s[pos] == '-') pos++
            while (pos < s.length && s[pos].isDigit()) pos++
            return s.substring(start, pos).toLong()
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun loadVectors(): Map<String, Any?> {
        val text = File("../vectors/vectors.json").readText(Charsets.UTF_8)
        return JsonParser(text).parseValue() as Map<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun positiveVectors() {
        val doc = loadVectors()
        assertEquals("ECVRF-EDWARDS25519-SHA512-TAI", doc["suite"])
        val vectors = doc["vectors"] as List<Map<String, Any?>>
        assertTrue(vectors.isNotEmpty())

        for (v in vectors) {
            val label = v["label"] as String
            val sk = hexToBytes(v["sk"] as String)
            val alpha = hexToBytes(v["alpha"] as String)

            val pk = EcvrfEd25519.derivePublicKey(sk)
            assertEquals(v["pk"], bytesToHex(pk), "$label: pk mismatch")
            assertTrue(EcvrfEd25519.isPublicKey(pk), "$label: isPublicKey")

            val pi = EcvrfEd25519.prove(sk, alpha)
            assertEquals(v["pi"], bytesToHex(pi), "$label: pi mismatch")

            val beta = EcvrfEd25519.proofToHash(pi)
            assertEquals(v["beta"], bytesToHex(beta), "$label: proofToHash mismatch")

            val res = EcvrfEd25519.verify(pk, pi, alpha)
            assertTrue(res.valid, "$label: verify failed")
            assertEquals(v["beta"], bytesToHex(res.beta!!), "$label: verify beta mismatch")
        }
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun negativeVectors() {
        val doc = loadVectors()
        val negatives = doc["negative_vectors"] as List<Map<String, Any?>>
        assertTrue(negatives.isNotEmpty())

        for (v in negatives) {
            val desc = v["description"] as String
            val expected = v["expected_verify"] as Boolean
            val res = EcvrfEd25519.verify(
                hexToBytes(v["pk"] as String),
                hexToBytes(v["pi"] as String),
                hexToBytes(v["alpha"] as String),
            )
            assertEquals(expected, res.valid, desc)
            if (!expected) {
                assertNull(res.beta, desc)
            }
        }
    }

    @Test
    fun rejectsInvalidSecretKeyLength() {
        assertFailsWith<IllegalArgumentException> { EcvrfEd25519.prove(ByteArray(31), ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> { EcvrfEd25519.prove(ByteArray(33), ByteArray(0)) }
    }
}
