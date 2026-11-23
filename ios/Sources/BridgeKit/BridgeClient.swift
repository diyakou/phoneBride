import Foundation

/// Command surface the iOS side offers to its UI. Every method maps to one
/// message the Android bridge already understands.
public final class BridgeClient {

    private let transport: BleTransport

    public init(transport: BleTransport) {
        self.transport = transport
    }

    public var isReady: Bool { transport.state == .ready }

    private func send(_ message: [String: Any]) {
        transport.send(message)
    }

    // ------------------------------------------------------------------ device

    public func ping(id: String = UUID().uuidString) {
        send(["t": "ping", "id": id])
    }

    public func deviceSnapshot(id: String = UUID().uuidString) {
        send(["t": "device", "id": id])
    }

    // ------------------------------------------------------------------ sms

    public func sendSms(to: String, body: String, sim: Int = -1, id: String = UUID().uuidString) {
        send(["t": "sms", "id": id, "to": to, "body": body, "sim": sim])
    }

    public func requestSmsLog(since: Int64 = 0, limit: Int = 200, id: String = UUID().uuidString) {
        send(["t": "smslog_req", "id": id, "since": since, "limit": limit])
    }

    // ------------------------------------------------------------------ calls

    public func dial(_ number: String, sim: Int = -1, id: String = UUID().uuidString) {
        send(["t": "dial", "id": id, "to": number, "sim": sim])
    }

    public func answer(callId: String = "", id: String = UUID().uuidString) {
        send(["t": "answer", "id": id, "callId": callId])
    }

    public func hangup(callId: String = "", id: String = UUID().uuidString) {
        send(["t": "hangup", "id": id, "callId": callId])
    }

    public func requestCallLog(since: Int64 = 0, limit: Int = 200, id: String = UUID().uuidString) {
        send(["t": "calls_req", "id": id, "since": since, "limit": limit])
    }

    public func sendDtmf(_ digit: Character, id: String = UUID().uuidString) {
        send(["t": "dtmf", "id": id, "d": String(digit)])
    }

    // ------------------------------------------------------------------ audio

    public func audioProbe(id: String = UUID().uuidString) {
        send(["t": "audio_probe", "id": id])
    }

    public func startCallAudio(id: String = UUID().uuidString) {
        send(["t": "audio_start", "id": id])
    }

    public func stopCallAudio(id: String = UUID().uuidString) {
        send(["t": "audio_stop", "id": id])
    }

    // ------------------------------------------------------------------ contacts & media

    public func requestContacts(limit: Int = 300, photos: Bool = true, id: String = UUID().uuidString) {
        send(["t": "contacts_req", "id": id, "limit": limit, "photos": photos])
    }

    public func requestMediaOffer(kind: String, limit: Int = 100, id: String = UUID().uuidString) {
        send(["t": "photos_offer", "id": id, "kind": kind, "limit": limit])
    }

    /// Requests the bytes of a specific media item, identified by the id and
    /// kind from a previous `media_offer`.
    public func requestMedia(kind: String, mediaId: Int64, id: String = UUID().uuidString) {
        send(["t": "photos_req", "id": id, "kind": kind, "media_id": mediaId])
    }
}
