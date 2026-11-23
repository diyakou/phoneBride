import Foundation

/// RFC 5869 HKDF-SHA256. Mirrors android/crypto/Hkdf.kt byte-for-byte.
public enum HKDF {

    public static func derive(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        precondition(length >= 1 && length <= 255 * 32, "invalid hkdf length")
        // Extract: PRK = HMAC-SHA256(salt, IKM). Empty salt becomes 32 zero bytes,
        // same as the Android side.
        let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
        let prk = Crypto.hmacSHA256(key: effectiveSalt, data: ikm)

        // Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        var out = Data()
        var block = Data()
        var counter: UInt8 = 1
        while out.count < length {
            block = Crypto.hmacSHA256(key: prk, data: block + info + Data([counter]))
            out.append(block)
            counter += 1
        }
        return out.prefix(length)
    }

    /// One 32-byte master into two independent directional keys.
    public static func splitKeys(master: Data, transcript: Data) -> (c2s: Data, s2c: Data) {
        let c2s = derive(ikm: master, salt: transcript, info: Data("bridge-v1 c2s".utf8), length: 32)
        let s2c = derive(ikm: master, salt: transcript, info: Data("bridge-v1 s2c".utf8), length: 32)
        return (c2s, s2c)
    }

    public static func noncePrefixes(master: Data, transcript: Data) -> (a: Data, b: Data) {
        let both = derive(ikm: master, salt: transcript, info: Data("bridge-v1 nonce".utf8), length: 8)
        return (both.prefix(4), both.suffix(4))
    }

    /// 6-digit short authentication string both devices display.
    public static func sasCode(master: Data, transcript: Data) -> String {
        let mac = Crypto.hmacSHA256(key: master, data: Data("bridge-v1 sas".utf8) + transcript)
        var value: UInt64 = 0
        for i in 0..<8 {
            value = (value << 8) | UInt64(mac[i])
        }
        let code = value % 1_000_000
        return String(format: "%06d", code)
    }
}

