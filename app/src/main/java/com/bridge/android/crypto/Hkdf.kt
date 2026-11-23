package com.bridge.android.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 5869 HKDF-SHA256. No dependency on Android APIs, unit-testable on the JVM.
 */
object Hkdf {

    fun derive(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * 32)) { "invalid hkdf length" }
        val mac = Mac.getInstance("HmacSHA256")

        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        mac.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArray(length)
        var block = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < length) {
            mac.update(block)
            mac.update(info)
            mac.update(counter.toByte())
            block = mac.doFinal()
            val take = minOf(block.size, length - written)
            System.arraycopy(block, 0, out, written, take)
            written += take
            counter++
        }
        java.util.Arrays.fill(prk, 0)
        return out
    }

    /** Expands one 32-byte master secret into two independent directional keys. */
    fun splitKeys(master: ByteArray, transcript: ByteArray): Pair<ByteArray, ByteArray> {
        val c2s = derive(master, transcript, "bridge-v1 c2s".toByteArray(), 32)
        val s2c = derive(master, transcript, "bridge-v1 s2c".toByteArray(), 32)
        return c2s to s2c
    }

    fun sasCode(master: ByteArray, transcript: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(master, "HmacSHA256"))
        mac.update("bridge-v1 sas".toByteArray())
        mac.update(transcript)
        val digest = mac.doFinal()
        var value = 0L
        for (i in 0 until 8) value = (value shl 8) or (digest[i].toLong() and 0xFF)
        val code = Math.floorMod(value, 1_000_000L)
        return code.toString().padStart(6, '0')
    }
}
