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
        let spki = privateKey.publicKey.x963Representation
        return (privateKey, spki)
    }

    /// X.963 = 0x04 || X || Y, which is what the Android side sends as the
    /// uncompressed EC point inside its SPKI body.
    public static func parsePublicX963(_ data: Data) throws -> P256.KeyAgreement.PublicKey {
        try P256.KeyAgreement.PublicKey(x963Representation: data)
    }

    public static func ecdh(privateKey: P256.KeyAgreement.PrivateKey, peerX963: Data) throws -> Data {
        let peer = try parsePublicX963(peerX963)
        return try privateKey.sharedSecretFromKeyAgreement(with: peer).x963Representation
    }
}
