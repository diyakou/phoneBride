package com.bridge.android.crypto

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM record layer with independent directional keys, an explicit
 * 64-bit counter in the header bound as AAD, and a 64-entry sliding replay
 * window per direction.
 *
 * Frame layout (little helper around the raw bytes):
 *   [0]      magic  0xB1
 *   [1]      version 0x01
 *   [2..9]   counter, big endian
 *   [10..]   ciphertext || 16-byte GCM tag
 *
 * The nonce is `noncePrefix (4 bytes) || counter (8 bytes)`, so the same key
 * never reuses a nonce and counters cannot be silently replayed.
 */
class SecureChannel(
    sendKey: ByteArray,
    receiveKey: ByteArray,
    sendNoncePrefix: ByteArray,
    receiveNoncePrefix: ByteArray,
) {
    private val sendCipher = SecretKeySpec(sendKey, "AES")
    private val receiveCipher = SecretKeySpec(receiveKey, "AES")
    private val sendPrefix = sendNoncePrefix.copyOf()
    private val receivePrefix = receiveNoncePrefix.copyOf()

    private var sendCounter = 0L
    private var highestSeen = -1L
    private var window = 0L

    @Synchronized
    fun seal(plaintext: ByteArray): ByteArray {
        val counter = ++sendCounter
        val header = header(counter)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, sendCipher, GCMParameterSpec(TAG_BITS, nonce(sendPrefix, counter)))
        cipher.updateAAD(header)
        val body = cipher.doFinal(plaintext)
        return header + body
    }

    /**
     * Opens a frame. Returns null on any failure: bad magic, bad version,
     * tag mismatch, or replay. Callers treat null as "drop silently".
     */
    @Synchronized
    fun open(frame: ByteArray): ByteArray? {
        if (frame.size < HEADER_BYTES + TAG_BYTES) return null
        if (frame[0] != MAGIC || frame[1] != VERSION) return null

        var counter = 0L
        for (i in 0 until 8) {
            counter = (counter shl 8) or (frame[2 + i].toLong() and 0xFF)
        }
        if (counter <= 0) return null

        // Replay check against the sliding window.
        if (counter <= highestSeen - WINDOW_BITS) return null
        if (counter <= highestSeen) {
            val shift = (highestSeen - counter).toInt()
            if (shift in 0 until WINDOW_BITS && (window shr shift) and 1L == 1L) return null
        }

        val header = frame.copyOfRange(0, HEADER_BYTES)
        val body = frame.copyOfRange(HEADER_BYTES, frame.size)
        val plaintext = runCatching {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, receiveCipher, GCMParameterSpec(TAG_BITS, nonce(receivePrefix, counter)))
            cipher.updateAAD(header)
            cipher.doFinal(body)
        }.getOrNull() ?: return null

        // Only advance the window after the tag verified: a forged high counter
        // must not be able to burn the window and lock out real traffic.
        if (counter > highestSeen) {
            val advance = counter - highestSeen
            window = if (advance >= WINDOW_BITS) 1L else (window shl advance.toInt()) or 1L
            highestSeen = counter
        } else {
            val shift = (highestSeen - counter).toInt()
            if (shift in 0 until WINDOW_BITS) window = window or (1L shl shift)
        }
        return plaintext
    }

    private fun header(counter: Long): ByteArray {
        val out = ByteArray(HEADER_BYTES)
        out[0] = MAGIC
        out[1] = VERSION
        for (i in 0 until 8) {
            out[2 + i] = ((counter shr (56 - 8 * i)) and 0xFF).toByte()
        }
        return out
    }

    private fun nonce(receivePrefix: ByteArray, counter: Long): ByteArray {
        val out = ByteArray(12)
        System.arraycopy(receivePrefix, 0, out, 0, 4)
        for (i in 0 until 8) {
            out[4 + i] = ((counter shr (56 - 8 * i)) and 0xFF).toByte()
        }
        return out
    }

    companion object {
        const val MAGIC: Byte = 0xB1.toByte()
        const val VERSION: Byte = 0x01
        const val HEADER_BYTES = 10
        private const val TAG_BITS = 128
        private const val TAG_BYTES = 16
        private const val WINDOW_BITS = 64

        /**
         * Builds both directions from the handshake master secret. Callers pass
         * the transcript hash so both sides derive identical material.
         */
        fun fromMaster(
            master: ByteArray,
            transcript: ByteArray,
            initiator: Boolean,
        ): SecureChannel {
            val (aToB, bToA) = Hkdf.splitKeys(master, transcript)
            val (aPrefix, bPrefix) = Hkdf.derive(master, transcript, "bridge-v1 nonce".toByteArray(), 8)
                .let { it.copyOfRange(0, 4) to it.copyOfRange(4, 8) }
            return if (initiator) {
                SecureChannel(aToB, bToA, aPrefix, bPrefix)
            } else {
                SecureChannel(bToA, aToB, bPrefix, aPrefix)
            }
        }
    }
}
