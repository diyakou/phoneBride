import Foundation

/// Mutual ECDH handshake. This side is the initiator: the Android phone is
/// always the responder (it owns the GATT server and answers with its hello).
///
///   iOS (initiator)                            Android (responder)
///   ---------------                            -------------------
///   hs_hello  {spki_i, nonce_i}   ->
///                                 <-   hs_hello  {spki_r, nonce_r}
///   hs_confirm {sig_i(transcript)} ->
///                                 <-   hs_confirm {sig_r(transcript)}
///
/// transcript = SHA256("bridge-v1 hs" || spki_i || nonce_i || spki_r || nonce_r)
///
/// The 6-digit SAS from the transcript is what the human compares on both
/// screens before any command flows.
public final class Handshake {

    public enum Phase { case idle, awaitingHello, awaitingConfirm, established, failed }

    public struct Result {
        public let channel: SecureChannel
        public let peerFingerprint: String
        public let sas: String
    }

    public private(set) var phase: Phase = .idle
    public private(set) var result: Result?

    private let identity: DeviceIdentity
    private let store: PairingStore
    private let localNonce: Data
    private var localX963: Data = Data()
    private var peerX963: Data = Data()
    private var master: Data = Data()
    private var transcript: Data = Data()

    public init(identity: DeviceIdentity, store: PairingStore) {
        self.identity = identity
        self.store = store
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        self.localNonce = Data(bytes)
    }

    /// Opens the handshake: returns the hs_hello frame to send to the phone.
    public func start() throws -> Data {
        let me = try identity.load()
        localX963 = me.x963
        phase = .awaitingHello

        let frame: [String: Any] = [
            "t": "hs_hello",
            "role": "i",
            "spki": me.x963.base64EncodedString(),
            "nonce": localNonce.base64EncodedString(),
        ]
        return try JSONSerialization.data(withJSONObject: frame)
    }

    /// Feeds one plaintext frame from the phone. Returns the frame to send
    /// back, or nil when the handshake is complete or failed.
    public func accept(_ data: Data) throws -> Data? {
        guard
            let frame = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let type = frame["t"] as? String
        else {
            phase = .failed
            throw HandshakeError.badFrame
        }

        switch (type, phase) {
        case ("hs_hello", .awaitingHello):
            return try onHello(frame)
        case ("hs_confirm", .awaitingConfirm):
            return try onConfirm(frame)
        default:
            phase = .failed
            throw HandshakeError.unexpectedFrame(type)
        }
    }

    private func onHello(_ frame: [String: Any]) throws -> Data? {
        guard
            let peerSpkiB64 = frame["spki"] as? String,
            let peerSpki = Data(base64Encoded: peerSpkiB64),
            let peerNonceB64 = frame["nonce"] as? String,
            let peerNonce = Data(base64Encoded: peerNonceB64),
            peerNonce.count == 32
        else {
            phase = .failed
            throw HandshakeError.badHello
        }
        peerX963 = peerSpki

        transcript = Self.transcript(
            initiatorX963: localX963,
            initiatorNonce: localNonce,
            responderX963: peerSpki,
            responderNonce: peerNonce
        )
        master = try identity.agree(peerX963: peerSpki, salt: transcript)
        phase = .awaitingConfirm

        let payload = Self.confirmPayload(transcript)
        let signature = try identity.sign(payload)
        let reply: [String: Any] = [
            "t": "hs_confirm",
            "spki": localX963.base64EncodedString(),
            "sig": signature.base64EncodedString(),
        ]
        return try JSONSerialization.data(withJSONObject: reply)
    }

    private func onConfirm(_ frame: [String: Any]) throws -> Data? {
        guard
            let sigB64 = frame["sig"] as? String,
            let signature = Data(base64Encoded: sigB64)
        else {
            phase = .failed
            throw HandshakeError.badSignature
        }
        guard DeviceIdentity.verify(peerX963: peerX963, data: Self.confirmPayload(transcript), signature: signature) else {
            phase = .failed
            throw HandshakeError.signatureRejected
        }

        let channel = SecureChannel.fromMaster(
            master: master,
            transcript: transcript,
            initiator: true
        )
        let fingerprint = DeviceIdentity.fingerprint(of: peerX963)
        let sas = HKDF.sasCode(master: master, transcript: transcript)
        result = Result(channel: channel, peerFingerprint: fingerprint, sas: sas)
        phase = .established
        return nil
    }

    public func abort() {
        phase = .idle
        result = nil
    }

    public var isTrusted: Bool {
        guard let result = result else { return false }
        return store.isTrusted(fingerprint: result.peerFingerprint)
    }

    // ------------------------------------------------------------------ framing

    static func transcript(
        initiatorX963: Data,
        initiatorNonce: Data,
        responderX963: Data,
        responderNonce: Data
    ) -> Data {
        var buffer = Data("bridge-v1 hs".utf8)
        buffer.append(initiatorX963)
        buffer.append(initiatorNonce)
        buffer.append(responderX963)
        buffer.append(responderNonce)
        return Crypto.sha256(buffer)
    }

    static func confirmPayload(_ transcript: Data) -> Data {
        Data("bridge-v1 confirm".utf8) + transcript
    }

    public enum HandshakeError: Error {
        case badFrame
        case badHello
        case badSignature
        case signatureRejected
        case unexpectedFrame(String)
    }
}
