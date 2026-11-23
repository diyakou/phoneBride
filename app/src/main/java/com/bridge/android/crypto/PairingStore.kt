package com.bridge.android.crypto

import android.content.Context
import android.util.Base64
import org.json.JSONObject

/**
 * Trust store for paired peers. A peer becomes trusted only after the user
 * confirms a 6-digit SAS that both devices derive from the ECDH transcript,
 * which defeats a man-in-the-middle that relays the handshake.
 */
class PairingStore(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    data class Peer(
        val fingerprint: String,
        val spki: ByteArray,
        val label: String,
        val pairedAt: Long,
    )

    fun all(): List<Peer> = prefs.all.mapNotNull { (key, value) ->
        (value as? String)?.let { raw ->
            runCatching {
                val json = JSONObject(raw)
                Peer(
                    fingerprint = key,
                    spki = Base64.decode(json.getString("spki"), Base64.NO_WRAP),
                    label = json.optString("label", ""),
                    pairedAt = json.optLong("at", 0),
                )
            }.getOrNull()
        }
    }

    fun find(fingerprint: String): Peer? = prefs.getString(fingerprint, null)?.let { raw ->
        runCatching {
            val json = JSONObject(raw)
            Peer(
                fingerprint = fingerprint,
                spki = Base64.decode(json.getString("spki"), Base64.NO_WRAP),
                label = json.optString("label", ""),
                pairedAt = json.optLong("at", 0),
            )
        }.getOrNull()
    }

    fun isTrusted(fingerprint: String): Boolean = prefs.contains(fingerprint)

    fun trust(identity: DeviceIdentity.Public, label: String) {
        val json = JSONObject()
            .put("spki", identity.spkiB64())
            .put("label", label)
            .put("at", System.currentTimeMillis())
        prefs.edit().putString(identity.fingerprint, json.toString()).apply()
    }

    fun revoke(fingerprint: String) {
        prefs.edit().remove(fingerprint).apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val PREFS = "bridge_peers"
    }
}
