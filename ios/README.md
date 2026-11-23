# Bridge iOS

Swift companion for the Android `Bridge` app. Ships as a Swift package
(`BridgeKit`) so you can drop it into an Xcode project or build/test it from
the CLI.

## Layout

```
Sources/BridgeKit/
  Crypto.swift        CryptoKit primitives (HMAC-SHA256, SHA-256, P-256)
  HKDF.swift          RFC 5869 HKDF — byte-identical to the Android side
  DeviceIdentity.swift Keychain-backed EC P-256 identity (sign / agree)
  SecureChannel.swift  AES-256-GCM record layer, counter in AAD, replay window
  Handshake.swift      Initiator side of the mutual ECDH handshake
  PairingStore.swift   Trusted-peer fingerprints in UserDefaults
  Fragmenter.swift     ≤140-byte frames with bounded reassembly
  BleTransport.swift   CoreBluetooth central, service/characteristic UUIDs match
  BridgeClient.swift   High-level command surface (dial, sms, contacts, audio…)
Tests/BridgeKitTests/
  HandshakeCryptoTests.swift  RFC vectors + round-trip + replay/tamper/reorder
```

## Protocol (matches the Android side)

```
iOS (initiator)                          Android (responder)
---------------                          -------------------
hs_hello {spki_i, nonce_i}      ->
                                <-  hs_hello {spki_r, nonce_r}
hs_confirm {sig_i(transcript)}  ->
                                <-  hs_confirm {sig_r(transcript)}
                                                      ↓ SAS 6-digit code
ready {trusted: false}          <-    (user confirms on both screens)
pair_ok {fp}                    ->
ready {trusted: true}           <-
```

After `ready {trusted: true}` every frame is `magic(1) || version(1) ||
counter(8) || AES-256-GCM(ciphertext || tag)`, AAD = header, nonce = prefix ||
counter. Both sides derive independent directional keys via HKDF over the
handshake transcript.

## Usage

```swift
let identity = DeviceIdentity()
try identity.load()
let store = PairingStore()

let transport = BleTransport(identity: identity, store: store)
transport.onPairingRequest = { sas, fingerprint in
    // show sas on screen, ask the user to confirm against the phone's screen
}
transport.onMessage = { message in
    // handle sms / call_state / media_offer / contacts / audio frames
}
transport.start()

let client = BridgeClient(transport: transport)
client.ping()
```

## Building from the CLI

```
cd ios
swift build
swift test
```

Building needs macOS with Xcode 15+ installed (CryptoKit + CoreBluetooth are
Apple-only). The package targets iOS 16 — add an Xcode app target that imports
`BridgeKit` for a real device build; BLE on the simulator is not testable.

## What is not here yet

- No UI. `BridgeClient` is the whole surface — wire it to SwiftUI views when
  the phone side is on a real device.
- No WiFi/UDP transport (Android side doesn't have one either yet).
- Audio playback of the 20 ms PCM frames (`t:"audio"` messages) needs an
  `AVAudioEngine` sink — trivial once frames arrive live.

## Security properties carried over

- Identity keys live in the Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`);
  never exported, never logged.
- A MITM that relays the handshake still fails: both signatures bind the full
  transcript, so the SAS on both screens will differ.
- Replay, reordering and bit-flips are all rejected by the record layer.
- Trust is bound to the fingerprint, revocable via `PairingStore.revoke`.
