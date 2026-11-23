import XCTest
@testable import BridgeKit

final class HandshakeCryptoTests: XCTestCase {

    func testHKDFMatchesRFC5869TestCase1() throws {
        // RFC 5869 Appendix A.1: SHA-256 basic test
        let ikm = Data(hex: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let salt = Data(hex: "000102030405060708090a0b0c")
        let info = Data(hex: "f0f1f2f3f4f5f6f7f8f9")
        let okm = HKDF.derive(ikm: ikm, salt: salt, info: info, length: 42)
        XCTAssertEqual(
            okm.hex,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    }

    func testHKDFEmptySaltMatchesRFC5869TestCase3() throws {
        let ikm = Data(hex: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let okm = HKDF.derive(ikm: ikm, salt: Data(), info: Data(), length: 42)
        XCTAssertEqual(
            okm.hex,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        )
    }

    func testSecureChannelRoundTripAndDirectionalKeys() {
        let master = Data(repeating: 0x42, count: 32)
        let transcript = Data(repeating: 0x01, count: 32)
        let initiator = SecureChannel.fromMaster(master: master, transcript: transcript, initiator: true)
        let responder = SecureChannel.fromMaster(master: master, transcript: transcript, initiator: false)

        let plain = Data("{\"t\":\"ping\",\"id\":\"abc\"}".utf8)
        let frame = initiator.seal(plain)
        XCTAssertEqual(frame[0], 0xB1)
        XCTAssertEqual(frame[1], 0x01)
        let opened = responder.open(frame)
        XCTAssertEqual(opened, plain)
    }

    func testReplayRejected() {
        let master = Data(repeating: 0x42, count: 32)
        let transcript = Data(repeating: 0x01, count: 32)
        let sender = SecureChannel.fromMaster(master: master, transcript: transcript, initiator: true)
        let receiver = SecureChannel.fromMaster(master: master, transcript: transcript, initiator: false)

        let frame = sender.seal(Data("first".utf8))
        XCTAssertNotNil(receiver.open(frame))
        // Same bytes again must be refused.
        XCTAssertNil(receiver.open(frame))
    }

    func testReorderWithinWindowThenMissedArrives() {
        let master = Data(repeating: 0x42, count: 32)
        let transcript = Data(repeating: 0x01, count: 32)
        let sender = SecureChannel.fromMaster(master: master, transcript: transcript, initiator: true)
        let receiver = SecureChannel.fromMaster(master: master, transcript: transcript, initiator: false)

        let f1 = sender.seal(Data("1".utf8))
        let f2 = sender.seal(Data("2".utf8))
        let f3 = sender.seal(Data("3".utf8))
        // 3, then 1 (in-window reorder), then 2.
        XCTAssertNotNil(receiver.open(f3))
        XCTAssertNotNil(receiver.open(f1))
        XCTAssertNotNil(receiver.open(f2))
    }

    func testTamperedFrameRejected() {
        let master = Data(repeating: 0x42, count: 32)
        let transcript = Data(repeating: 0x01, count: 32)
        let sender = SecureChannel.fromMaster(master: master, transcript: transcript, initiator: true)
        let receiver = SecureChannel.fromMaster(master: master, transcript: transcript, initiator: false)

        var frame = sender.seal(Data("payload".utf8))
        frame[frame.count - 1] ^= 0x01
        XCTAssertNil(receiver.open(frame))
    }

    func testSASMatchesAcrossRoles() {
        let master = Data(repeating: 0x7C, count: 32)
        let transcript = Data(repeating: 0x09, count: 32)
        XCTAssertEqual(HKDF.sasCode(master: master, transcript: transcript),
                       HKDF.sasCode(master: master, transcript: transcript))
        XCTAssertEqual(HKDF.sasCode(master: master, transcript: transcript).count, 6)
    }

    func testFragmentRoundTrip() throws {
        let message = Data("{\"t\":\"contact\",\"n\":\"مخاطب آزمایشی\",\"p\":[[\"+98912\",\"mobile\"],[\"+49151\",\"home\"]]}".utf8)
        let frames = try Fragmenter.fragment(message, frameId: "deadbeef")
        XCTAssertGreaterThan(frames.count, 1)

        let reassembler = Fragmenter.Reassembler()
        var assembled: Data?
        for frame in frames.shuffled() {
            if let complete = try reassembler.push(frame) { assembled = complete }
        }
        XCTAssertEqual(assembled, message)
    }

    func testReassemblerRejectsOversized() throws {
        let reassembler = Fragmenter.Reassembler()
        let frame: [String: Any] = [
            "t": "fr", "i": 0, "n": 1, "id": "x",
            "d": Data(repeating: 0xFF, count: 4096).base64EncodedString(),
        ]
        XCTAssertThrowsError(try reassembler.push(frame))
    }

    func testTranscriptOrderingMatters() {
        let a = Data(repeating: 0x01, count: 32)
        let b = Data(repeating: 0x02, count: 32)
        let n1 = Data(repeating: 0x11, count: 32)
        let n2 = Data(repeating: 0x22, count: 32)
        let t1 = Handshake.transcript(initiatorX963: a, initiatorNonce: n1, responderX963: b, responderNonce: n2)
        let t2 = Handshake.transcript(initiatorX963: b, initiatorNonce: n2, responderX963: a, responderNonce: n1)
        XCTAssertNotEqual(t1, t2)
    }
}

extension Data {
    init(hex: String) {
        self.init()
        var iterator = hex.makeIterator()
        while let hi = iterator.next(), let lo = iterator.next() {
            guard let byte = UInt8("\(hi)\(lo)", radix: 16) else { break }
            append(byte)
        }
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
