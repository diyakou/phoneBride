import Foundation

/// Persisted trust for paired phones, keyed by the SHA-256 fingerprint of the
/// peer's public key. Mirrors android/crypto/PairingStore.kt.
public final class PairingStore {

    public struct Peer {
        public let fingerprint: String
        public let spki: Data
        public let label: String
        public let pairedAt: Date
    }

    private let defaults: UserDefaults
    private let key = "bridge.peers.v1"

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public func all() -> [Peer] {
        guard
            let raw = defaults.array(forKey: key) as? [[String: Any]]
        else { return [] }
        return raw.compactMap { entry in
            guard
                let fingerprint = entry["fp"] as? String,
                let spkiB64 = entry["spki"] as? String,
                let spki = Data(base64Encoded: spkiB64)
            else { return nil }
            return Peer(
                fingerprint: fingerprint,
                spki: spki,
                label: entry["label"] as? String ?? "",
                pairedAt: entry["at"] as? Date ?? Date.distantPast
            )
        }
    }

    public func isTrusted(fingerprint: String) -> Bool {
        all().contains { $0.fingerprint == fingerprint }
    }

    public func trust(spki: Data, fingerprint: String, label: String) {
        var peers = all()
        peers.removeAll { $0.fingerprint == fingerprint }
        peers.append(Peer(fingerprint: fingerprint, spki: spki, label: label, pairedAt: Date()))
        persist(peers)
    }

    public func revoke(fingerprint: String) {
        var peers = all()
        peers.removeAll { $0.fingerprint == fingerprint }
        persist(peers)
    }

    public func clear() {
        defaults.removeObject(forKey: key)
    }

    private func persist(_ peers: [Peer]) {
        let raw: [[String: Any]] = peers.map {
            [
                "fp": $0.fingerprint,
                "spki": $0.spki.base64EncodedString(),
                "label": $0.label,
                "at": $0.pairedAt,
            ]
        }
        defaults.set(raw, forKey: key)
    }
}
