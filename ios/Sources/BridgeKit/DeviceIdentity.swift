import Foundation
import CryptoKit

/// EC P-256 identity held in the Keychain (Secure Enclave when the device
/// supports it). The private key is generated once, persisted, and only ever
/// used through sign / agree — never exported.
public final class DeviceIdentity {

    public struct Public {
        public let spki: Data
        public let fingerprint: String
    }

    private var privateKey: P256.KeyAgreement.PrivateKey?
    private let keyTag = "com.bridge.ios.identity.v1"

    public private(set) var cached: Public?

    public init() {}

    /// Loads or generates the device identity. Call once at launch; the result
    /// is cached for the process lifetime.
    @discardableResult
    public func load() throws -> Public {
        if let cached = cached { return cached }

        let privateKey: P256.KeyAgreement.PrivateKey
        if let stored = loadFromKeychain() {
            privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: stored)
        } else {
            let generated = try Crypto.generateIdentity()
            privateKey = generated.privateKey
            try saveToKeychain(privateKey.rawRepresentation)
        }

        let spki = privateKey.publicKey.derRepresentation
        let identity = Public(spki: spki, fingerprint: Self.fingerprint(of: spki))
        self.privateKey = privateKey
        self.cached = identity
        return identity
    }

    public static func fingerprint(of spki: Data) -> String {
        Crypto.sha256(spki).base64URLEncodedString()
    }

    /// ECDH against peer SPKI, then HKDF into session master.
    public func agree(peerSPKI: Data, salt: Data) throws -> Data {
        guard let privateKey = privateKey else { throw IdentityError.notLoaded }
        let shared = try Crypto.ecdh(privateKey: privateKey, peerSPKI: peerSPKI)
        return HKDF.derive(ikm: shared, salt: salt, info: Data("bridge-v1 master".utf8), length: 32)
    }

    /// ECDSA-P256-SHA256 signature over the handshake confirm payload.
    public func sign(_ data: Data) throws -> Data {
        guard let privateKey = privateKey else { throw IdentityError.notLoaded }
        let signature = try privateKey.signature(for: data)
        return signature.derRepresentation
    }

    public static func verify(peerSPKI: Data, data: Data, signature: Data) -> Bool {
        guard
            let peer = try? Crypto.parsePublicSPKI(peerSPKI),
            let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature)
        else { return false }
        return peer.isValidSignature(sig, for: data)
    }

    /// Wipes the identity. Every paired peer becomes untrusted.
    public func reset() {
        deleteFromKeychain()
        privateKey = nil
        cached = nil
    }

    // ------------------------------------------------------------------ keychain

    private func loadFromKeychain() -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyTag,
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    private func saveToKeychain(_ data: Data) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyTag,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw IdentityError.keychainFailure(status)
        }
    }

    private func deleteFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyTag,
        ]
        SecItemDelete(query as CFDictionary)
    }

    public enum IdentityError: Error {
        case notLoaded
        case keychainFailure(OSStatus)
    }
}

extension Data {
    public func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
