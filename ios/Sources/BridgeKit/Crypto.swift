import Foundation
import CryptoKit

/// Low-level crypto primitives shared by HKDF, the handshake and the record
/// layer. Everything wraps CryptoKit; no external dependency.
public enum Crypto {

    public static func hmacSHA256(key: Data, data: Data) -> Data {
        var keyed = key
        var message = data
        let mac = HMAC<SHA256>.authenticationCode(for: Array(message), using: SymmetricKey(data: Array(keyed)))
        return Data(mac)
    }

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// EC P-256 identity backed by the Secure Enclave when available, otherwise
    /// the Keychain. The private key never leaves hardware.
    public static func generateIdentity() throws -> (privateKey: P256.KeyAgreement.PrivateKey, spki: Data) {
        let privateKey = try P256.KeyAgreement.PrivateKey.generate()
        let spki = privateKey.publicKey.derRepresentation
        return (privateKey, spki)
    }

    public static func parsePublicSPKI(_ data: Data) throws -> P256.KeyAgreement.PublicKey {
        try P256.KeyAgreement.PublicKey(derRepresentation: data)
    }

    public static func ecdh(privateKey: P256.KeyAgreement.PrivateKey, peerSPKI: Data) throws -> Data {
        let peer = try parsePublicSPKI(peerSPKI)
        return try privateKey.sharedSecretFromKeyAgreement(with: peer).x963Representation
    }
}
