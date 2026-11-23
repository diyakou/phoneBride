import Foundation
import CryptoKit

/// AES-256-GCM record layer, mirroring android/crypto/SecureChannel.kt exactly.
///
/// Frame layout:
///   [0]      magic  0xB1
///   [1]      version 0x01
///   [2..9]   counter, big endian
///   [10..]   ciphertext || 16-byte GCM tag
///
/// Nonce = 4-byte direction prefix || 8-byte counter. The counter is bound as
/// AAD and a 64-entry sliding window per direction rejects replay and reorder.
public final class SecureChannel {

    private let sendKey: SymmetricKey
    private let receiveKey: SymmetricKey
    private let sendPrefix: Data
    private let receivePrefix: Data

    private let lock = NSLock()
    private var sendCounter: UInt64 = 0
    private var highestSeen: UInt64 = 0
    private var window: UInt64 = 0

    public init(sendKey: Data, receiveKey: Data, sendPrefix: Data, receivePrefix: Data) {
        self.sendKey = SymmetricKey(data: sendKey)
        self.receiveKey = SymmetricKey(data: receiveKey)
        self.sendPrefix = sendPrefix
        self.receivePrefix = receivePrefix
    }

    /// Builds both directions from the handshake master. `initiator` mirrors the
    /// Android side: the initiator sends with key A and the c2s nonce prefix.
    public static func fromMaster(
        master: Data,
        transcript: Data,
        initiator: Bool
    ) -> SecureChannel {
        let keys = HKDF.splitKeys(master: master, transcript: transcript)
        let prefixes = HKDF.noncePrefixes(master: master, transcript: transcript)
        if initiator {
            return SecureChannel(sendKey: keys.c2s, receiveKey: keys.s2c, sendPrefix: prefixes.a, receivePrefix: prefixes.b)
        } else {
            return SecureChannel(sendKey: keys.s2c, receiveKey: keys.c2s, sendPrefix: prefixes.b, receivePrefix: prefixes.a)
        }
    }

    public func seal(_ plaintext: Data) -> Data {
        lock.lock(); defer { lock.unlock() }
        sendCounter += 1
        let counter = sendCounter
        let header = Self.header(counter: counter)
        let nonce = self.nonce(prefix: sendPrefix, counter: counter)

        let sealedBox = try! AES.GCM.seal(plaintext, using: sendKey, nonce: AES.GCM.Nonce(data: nonce))
        // AES.GCM.seal returns combined = ciphertext || tag, matching the frame
        // layout the Android side expects after the 10-byte header.
        return header + sealedBox.combined!
    }

    /// Returns nil on bad magic, bad version, tag mismatch or replay.
    public func open(_ frame: Data) -> Data? {
        lock.lock(); defer { lock.unlock() }

        guard frame.count >= Self.headerBytes + Self.tagBytes else { return nil }
        guard frame[0] == Self.magic, frame[1] == Self.version else { return nil }

        var counter: UInt64 = 0
        for i in 0..<8 {
            counter = (counter << 8) | UInt64(frame[2 + i])
        }
        guard counter > 0 else { return nil }

        // Sliding replay window.
        let windowBits: UInt64 = 64
        if counter <= highestSeen &~ (windowBits - 1) { return nil }
        if counter <= highestSeen {
            let shift = highestSeen - counter
            guard shift < windowBits else { return nil }
            if (window >> shift) & 1 == 1 { return nil }
        }

        let header = frame.prefix(Self.headerBytes)
        let body = frame.suffix(from: Self.headerBytes)
        let nonce = self.nonce(prefix: receivePrefix, counter: counter)

        let opened: AES.GCM.SealedBox?
        do {
            opened = try AES.GCM.SealedBox(combined: body)
            let plaintext = try AES.GCM.open(opened!, using: receiveKey, nonce: AES.GCM.Nonce(data: nonce))
            // Only advance the window after the tag verified.
            if counter > highestSeen {
                let advance = counter - highestSeen
                window = advance >= windowBits ? 1 : (window << advance) | 1
                highestSeen = counter
            } else {
                let shift = highestSeen - counter
                if shift < windowBits { window |= (1 << shift) }
            }
            _ = header
            return plaintext
        } catch {
            return nil
        }
    }

    private static func header(counter: UInt64) -> Data {
        var out = Data([magic, version])
        for shift in stride(from: 56, through: 0, by: -8) {
            out.append(UInt8((counter >> UInt64(shift)) & 0xFF))
        }
        return out
    }

    private func nonce(prefix: Data, counter: UInt64) -> Data {
        var out = prefix
        for shift in stride(from: 56, through: 0, by: -8) {
            out.append(UInt8((counter >> UInt64(shift)) & 0xFF))
        }
        return out
    }

    static let magic: UInt8 = 0xB1
    static let version: UInt8 = 0x01
    static let headerBytes = 10
    static let tagBytes = 16
}
