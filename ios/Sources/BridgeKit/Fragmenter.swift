import Foundation

/// Splits a JSON message into ≤140-byte frames and reassembles them,
/// mirroring android/transport/Fragmenter.kt.
public enum Fragmenter {

    public static let maxFramePayload = 140
    public static let maxTotal = 64 * 1024
    public static let maxFrames = 512

    public static func fragment(_ message: Data, frameId: String) throws -> [[String: Any]] {
        guard message.count <= maxTotal else { throw FragmenterError.tooLarge }
        let slices = stride(from: 0, to: message.count, by: maxFramePayload).map {
            message.subdata(in: $0..<min($0 + maxFramePayload, message.count))
        }
        guard slices.count <= maxFrames else { throw FragmenterError.tooManyFrames }
        return slices.enumerated().map { index, slice in
            [
                "t": "fr",
                "i": index,
                "n": slices.count,
                "id": frameId,
                "d": slice.base64EncodedString(),
            ]
        }
    }

    public final class Reassembler {
        private struct Partial {
            let total: Int
            var slices: [Data?]
            var received: Int
            var bytes: Int
        }

        private var pending: [String: Partial] = [:]
        private let lock = NSLock()
        private let maxInFlight = 8

        /// Returns the completed payload, or nil while more frames are needed.
        /// Throws on a malformed or oversized frame so the caller can drop the
        /// peer.
        public func push(_ frame: [String: Any]) throws -> Data? {
            lock.lock(); defer { lock.unlock() }

            guard
                let id = frame["id"] as? String, !id.isEmpty,
                let index = frame["i"] as? Int, index >= 0,
                let total = frame["n"] as? Int, total >= 1, total <= maxFrames,
                let sliceB64 = frame["d"] as? String,
                let slice = Data(base64Encoded: sliceB64)
            else { throw FragmenterError.badFrame }
            guard index < total else { throw FragmenterError.badFrame }
            guard slice.count <= maxFramePayload else { throw FragmenterError.tooLarge }

            let partial: Partial
            if let existing = pending[id] {
                guard existing.total == total else { throw FragmenterError.badFrame }
                partial = existing
            } else {
                partial = Partial(total: total, slices: [Data?](repeating: nil, count: total), received: 0, bytes: 0)
                trim()
                pending[id] = partial
            }

            var updated = partial
            if updated.slices[index] == nil {
                updated.slices[index] = slice
                updated.received += 1
                updated.bytes += slice.count
                guard updated.bytes <= maxTotal else {
                    pending.removeValue(forKey: id)
                    throw FragmenterError.tooLarge
                }
                pending[id] = updated
            }
            guard updated.received == updated.total else { return nil }

            pending.removeValue(forKey: id)
            return updated.slices.compactMap { $0 }.reduce(Data(), +)
        }

        public func reset() {
            lock.lock(); defer { lock.unlock() }
            pending.removeAll()
        }

        private func trim() {
            while pending.count >= maxInFlight {
                pending.removeValue(forKey: pending.keys.first!)
            }
        }
    }

    public enum FragmenterError: Error {
        case tooLarge
        case tooManyFrames
        case badFrame
    }
}
