package com.bridge.android.transport

import android.util.Base64
import org.json.JSONObject

/**
 * Splits a JSON envelope into frames that fit inside one GATT notification and
 * rebuilds it on the far side.
 *
 * Frame (single GATT value, UTF-8 JSON, kept small so it always fits the
 * negotiated MTU):
 *
 *   {"t":"fr","i":<index>,"n":<total>,"id":"<frameId>","d":"<base64 slice>"}
 *
 * `frameId` is random per message, so two messages in flight never collide.
 * Reassembly is bounded: at most [MAX_TOTAL] bytes and at most [MAX_FRAMES]
 * frames, so a hostile peer cannot exhaust memory.
 */
object Fragmenter {

    const val MAX_FRAME_PAYLOAD = 140
    const val MAX_TOTAL = 64 * 1024
    const val MAX_FRAMES = 512

    fun fragment(message: JSONObject, frameId: String): List<JSONObject> {
        val raw = message.toString().toByteArray(Charsets.UTF_8)
        require(raw.size <= MAX_TOTAL) { "message too large" }
        val slices = raw.toList().chunked(MAX_FRAME_PAYLOAD).map { it.toByteArray() }
        require(slices.size <= MAX_FRAMES) { "too many frames" }
        return slices.mapIndexed { index, slice ->
            JSONObject()
                .put("t", "fr")
                .put("i", index)
                .put("n", slices.size)
                .put("id", frameId)
                .put("d", Base64.encodeToString(slice, Base64.NO_WRAP))
        }
    }

    /** Accumulates frames per id until the message is complete. */
    class Reassembler {
        private class Partial(val total: Int, val slices: Array<ByteArray?>, var received: Int, var bytes: Int)

        private val pending = LinkedHashMap<String, Partial>()

        /**
         * Returns the completed JSON payload, or null while more frames are
         * needed. Throws [IllegalArgumentException] on a malformed or oversized
         * frame so the caller can drop the peer.
         */
        fun push(frame: JSONObject): ByteArray? {
            val id = frame.optString("id")
            val index = frame.optInt("i", -1)
            val total = frame.optInt("n", -1)
            require(id.isNotEmpty() && index >= 0 && total in 1..MAX_FRAMES) { "bad frame header" }
            require(index < total) { "bad frame index" }
            val slice = Base64.decode(frame.optString("d"), Base64.NO_WRAP)
            require(slice.size <= MAX_FRAME_PAYLOAD) { "frame too large" }

            val partial = pending[id] ?: Partial(total, arrayOfNulls(total), 0, 0).also {
                pending[id] = it
                trim()
            }
            require(partial.total == total) { "frame count changed" }
            if (partial.slices[index] == null) {
                partial.slices[index] = slice
                partial.received++
                partial.bytes += slice.size
                require(partial.bytes <= MAX_TOTAL) { "message too large" }
            }
            if (partial.received != partial.total) return null

            pending.remove(id)
            val out = java.io.ByteArrayOutputStream(partial.bytes)
            partial.slices.forEach { out.write(it!!) }
            return out.toByteArray()
        }

        fun reset() = pending.clear()

        /** Keeps the map bounded: only the newest [MAX_IN_FLIGHT] messages survive. */
        private fun trim() {
            while (pending.size > MAX_IN_FLIGHT) {
                val oldest = pending.keys.firstOrNull() ?: return
                pending.remove(oldest)
            }
        }

        private companion object {
            const val MAX_IN_FLIGHT = 8
        }
    }
}
