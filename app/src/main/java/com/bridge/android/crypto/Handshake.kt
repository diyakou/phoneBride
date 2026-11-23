package com.bridge.android.crypto

import android.util.Base64
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Mutual ECDH handshake over an untrusted transport.
 *
 *   initiator                                responder (this phone)
 *   ---------                                -----------------------
 *   hs_hello  {spki_i, nonce_i}        ->
 *                                     <-  hs_hello  {spki_r, nonce_r}
 *   hs_confirm {sig_i(transcript)}    ->
 *                                     <-  hs_confirm {sig_r(transcript)}
 *
 * transcript = SHA256("bridge-v1 hs" || spki_i || nonce_i || spki_r || nonce_r)
 *
 * Both signatures bind the full transcript, so a relay cannot substitute either
 * party. The master secret feeds [SecureChannel]. A 6-digit SAS derived from
 * it is what the human compares out of band; until the peer's fingerprint is
 * in [PairingStore] the transport reports it as untrusted and the service
 * gates every command on trust.
 *
 * The responder only signs after verifying the initiator's signature, so an
 * unverified peer never obtains our signature to forward elsewhere.
 */
class Handshake(
    private val store: PairingStore,
    private val random: SecureRandom = SecureRandom(),
) {
    enum class Role { INITIATOR, RESPONDER }

    sealed class Outcome {
        /** Handshake advanced; send [frame] to the peer and wait for the next one. */
        data class Continue(val frame: JSONObject) : Outcome()

        /**
         * Handshake complete. [sas] must be confirmed by the user when
         * [alreadyTrusted] is false. [finalFrame], when present, is the last
         * flight this side owes the peer.
         */
        data class Established(
            val channel: SecureChannel,
            val peer: DeviceIdentity.Public,
            val sas: String,
            val alreadyTrusted: Boolean,
            val finalFrame: JSONObject? = null,
        ) : Outcome()

        /** Terminal failure. The caller drops the connection. */
        data class Failed(val reason: String) : Outcome()
    }

    private data class State(
        val role: Role,
        val localNonce: ByteArray,
        val localSpki: ByteArray,
        val transcript: ByteArray? = null,
        val peer: DeviceIdentity.Public? = null,
        val master: ByteArray? = null,
    )

    private var state: State? = null

    fun start(role: Role): JSONObject {
        val me = DeviceIdentity.publicIdentity()
        val nonce = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        state = State(
            role = role,
            localNonce = nonce,
            localSpki = me.spki,
        )
        return JSONObject()
            .put("t", "hs_hello")
            .put("role", if (role == Role.INITIATOR) "i" else "r")
            .put("spki", me.spkiB64())
            .put("nonce", b64(nonce))
    }

    fun accept(frame: JSONObject): Outcome {
        val current = state ?: return Outcome.Failed("no_handshake")
        return when (frame.optString("t")) {
            "hs_hello" -> onHello(current, frame)
            "hs_confirm" -> onConfirm(current, frame)
            else -> Outcome.Failed("unexpected_frame")
        }
    }

    private fun onHello(current: State, frame: JSONObject): Outcome {
        val peerSpki = runCatching { Base64.decode(frame.getString("spki"), Base64.NO_WRAP) }
            .getOrNull() ?: return Outcome.Failed("bad_spki")
        val peerNonce = runCatching { Base64.decode(frame.getString("nonce"), Base64.NO_WRAP) }
            .getOrNull() ?: return Outcome.Failed("bad_nonce")
        if (peerNonce.size != NONCE_BYTES) return Outcome.Failed("bad_nonce_length")
        if (peerSpki.contentEquals(current.localSpki)) return Outcome.Failed("self_connection")

        val peer = DeviceIdentity.Public(peerSpki, DeviceIdentity.fingerprintOf(peerSpki))
        val transcript = if (current.role == Role.INITIATOR) {
            transcript(current.localSpki, current.localNonce, peerSpki, peerNonce)
        } else {
            transcript(peerSpki, peerNonce, current.localSpki, current.localNonce)
        }
        val master = runCatching { DeviceIdentity.agree(peerSpki, transcript) }
            .getOrNull() ?: return Outcome.Failed("ecdh_failed")

        state = current.copy(transcript = transcript, peer = peer, master = master)

        return when (current.role) {
            // Initiator answers the responder's hello with its signed confirm.
            Role.INITIATOR -> Outcome.Continue(
                confirmFrame(current.localSpki, DeviceIdentity.sign(confirmPayload(transcript)))
            )
            // Responder answers with its hello and waits for the confirm.
            Role.RESPONDER -> Outcome.Continue(
                JSONObject()
                    .put("t", "hs_hello")
                    .put("role", "r")
                    .put("spki", Base64.encodeToString(current.localSpki, Base64.NO_WRAP))
                    .put("nonce", b64(current.localNonce))
            )
        }
    }

    private fun onConfirm(current: State, frame: JSONObject): Outcome {
        if (current.role != Role.RESPONDER) return Outcome.Failed("unexpected_confirm")
        val transcript = current.transcript ?: return Outcome.Failed("no_transcript")
        val peer = current.peer ?: return Outcome.Failed("no_peer")
        val master = current.master ?: return Outcome.Failed("no_master")

        val signature = runCatching { Base64.decode(frame.getString("sig"), Base64.NO_WRAP) }
            .getOrNull() ?: return Outcome.Failed("bad_signature")
        if (!DeviceIdentity.verify(peer.spki, confirmPayload(transcript), signature)) {
            return Outcome.Failed("signature_rejected")
        }

        val channel = SecureChannel.fromMaster(master, transcript, initiator = false)
        val finalFrame = confirmFrame(
            current.localSpki,
            DeviceIdentity.sign(confirmPayload(transcript)),
        )
        state = null
        return Outcome.Established(
            channel = channel,
            peer = peer,
            sas = Hkdf.sasCode(master, transcript),
            alreadyTrusted = store.isTrusted(peer.fingerprint),
            finalFrame = finalFrame,
        )
    }

    fun abort() {
        state = null
    }

    private fun confirmFrame(spki: ByteArray, signature: ByteArray): JSONObject = JSONObject()
        .put("t", "hs_confirm")
        .put("spki", Base64.encodeToString(spki, Base64.NO_WRAP))
        .put("sig", b64(signature))

    private fun transcript(
        initiatorSpki: ByteArray,
        initiatorNonce: ByteArray,
        responderSpki: ByteArray,
        responderNonce: ByteArray,
    ): ByteArray {
        val buffer = java.io.ByteArrayOutputStream()
        buffer.write("bridge-v1 hs".toByteArray())
        buffer.write(initiatorSpki)
        buffer.write(initiatorNonce)
        buffer.write(responderSpki)
        buffer.write(responderNonce)
        return DeviceIdentity.sha256(buffer.toByteArray())
    }

    private fun confirmPayload(transcript: ByteArray): ByteArray =
        "bridge-v1 confirm".toByteArray() + transcript

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    companion object {
        const val NONCE_BYTES = 32
    }
}
