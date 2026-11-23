package com.bridge.android.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * Long-lived device identity held in AndroidKeyStore: EC P-256 used for both
 * ECDH (session key agreement) and ECDSA (frame signatures during pairing).
 *
 * The private key never leaves the TEE/StrongBox. Only the SPKI public key is
 * ever transmitted.
 */
object DeviceIdentity {

    private const val ALIAS = "bridge_identity_v1"
    private const val PROVIDER = "AndroidKeyStore"

    data class Public(
        val spki: ByteArray,
        val fingerprint: String,
    ) {
        fun spkiB64(): String = Base64.encodeToString(spki, Base64.NO_WRAP)
    }

    @Volatile
    private var cached: KeyPair? = null

    fun keyPair(): KeyPair {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
            if (!ks.containsAlias(ALIAS)) generate()
            val priv = ks.getKey(ALIAS, null) as PrivateKey
            val pub = ks.getCertificate(ALIAS).publicKey
            return KeyPair(pub, priv).also { cached = it }
        }
    }

    private fun generate() {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_AGREE_KEY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setUserAuthenticationRequired(false)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    fun publicIdentity(): Public {
        val spki = keyPair().public.encoded
        return Public(spki, fingerprintOf(spki))
    }

    fun fingerprintOf(spki: ByteArray): String =
        Base64.encodeToString(sha256(spki), Base64.NO_WRAP or Base64.URL_SAFE)

    fun parsePublic(spki: ByteArray): PublicKey =
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))

    /** ECDH against a peer SPKI, HKDF-expanded into the session master secret. */
    fun agree(peerSpki: ByteArray, salt: ByteArray): ByteArray {
        val peer = parsePublic(peerSpki)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(keyPair().private)
        agreement.doPhase(peer, true)
        val shared = agreement.generateSecret()
        return Hkdf.derive(shared, salt, "bridge-v1 master".toByteArray(), 32)
    }

    fun sign(data: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(keyPair().private)
        signature.update(data)
        return signature.sign()
    }

    fun verify(peerSpki: ByteArray, data: ByteArray, signature: ByteArray): Boolean = runCatching {
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(parsePublic(peerSpki))
        verifier.update(data)
        verifier.verify(signature)
    }.getOrDefault(false)

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /** Wipes the identity. All pairings become invalid; peers must re-pair. */
    fun reset() {
        synchronized(this) {
            runCatching {
                KeyStore.getInstance(PROVIDER).apply { load(null) }.deleteEntry(ALIAS)
            }
            cached = null
        }
    }
}
