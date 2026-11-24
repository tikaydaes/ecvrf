package ecvrf

import kotlin.system.exitProcess

private fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "odd hex length" }
    return ByteArray(hex.length / 2) { i ->
        hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

private fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it) }

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("usage: ecvrf-kotlin prove <sk> <alpha> | verify <pk> <pi> <alpha> | derive-pk <sk>")
        exitProcess(2)
    }
    when (args[0]) {
        "prove" -> {
            if (args.size < 3) exitProcess(2)
            println(bytesToHex(EcvrfEd25519.prove(hexToBytes(args[1]), hexToBytes(args[2]))))
        }
        "verify" -> {
            if (args.size < 4) exitProcess(2)
            val res = EcvrfEd25519.verify(hexToBytes(args[1]), hexToBytes(args[2]), hexToBytes(args[3]))
            if (!res.valid || res.beta == null) exitProcess(1)
            println(bytesToHex(res.beta))
        }
        "derive-pk" -> {
            if (args.size < 2) exitProcess(2)
            println(bytesToHex(EcvrfEd25519.derivePublicKey(hexToBytes(args[1]))))
        }
        else -> {
            System.err.println("unknown command: ${args[0]}")
            exitProcess(2)
        }
    }
}
