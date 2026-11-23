# Bridge implementation status

## Security hardening (this revision)

- **Mutual ECDH pairing** (`crypto/Handshake`): both sides exchange SPKI + nonce,
  sign the transcript with their AndroidKeyStore EC P-256 identity, and derive a
  session master via ECDH → HKDF-SHA256. A relay cannot substitute either party.
- **AES-256-GCM record layer** (`crypto/SecureChannel`): independent directional
  keys, 64-bit counter bound as AAD, 4-byte nonce prefix, 64-entry sliding
  replay window. Bad tag / replay / reorder kills the session.
- **SAS out-of-band confirmation**: a 6-digit code derived from the transcript
  is surfaced to the user; an untrusted peer gets no commands until the human
  confirms (`pair_ok` with matching fingerprint, or MainActivity confirmation).
- **Pairing store** (`crypto/PairingStore`): fingerprints persisted; revocable
  from the UI; identity reset forces re-pairing everywhere.
- **Fragmentation** (`transport/Fragmenter`): JSON split into ≤140-byte frames
  with per-message id, index, total; bounded reassembly (64 KB / 512 frames /
  8 in flight) so a hostile peer cannot exhaust memory. Both directions fixed.
- **Single-thread GATT writer** (`transport/GattWriter`): all notifies
  serialised on one worker, GATT_BUSY retried with backoff, queue bounded,
  frames carry their target address. Binder-thread races eliminated.
- **Offline queue** (`transport/MessageQueue`): events arriving while the
  service is down (SMS during restart, boot) are persisted and replayed to the
  next authenticated peer. Nothing silently dropped.
- **Boot persistence** (`BootReceiver`): bridge restarts after reboot.
- **Incoming SMS survives service death** (`media/SmsReceiver`): publishes to
  the bus, which queues when no service instance exists.
- **SmsBridge fixed**: pending map actually released; monotonic request codes
  (no PendingIntent collision); delivery reports tracked per part; 90 s reaper
  fails requests whose broadcast never arrives; duplicate ids rejected.
- **Grep of static `calls` map**: removed on `callRemoved`, cleared by
  disconnect tracking; service teardown no longer leaks.
- **Call audio** (`media/AudioBridge`): real downlink capture loop (hidden
  extraction API on 13+, VOICE_DOWNLINK fallback) streaming 20 ms PCM frames;
  uplink injection track + DTMF synthesis.
- **Content** (`content/ContentReader`): paginated call log / SMS history /
  contacts (grouped, photo hashes only) streamed to the peer on request.
- **Media** (`content/MediaReader`): hash-first offer protocol; a peer gets
  metadata + SHA-256 and must request specific ids; streaming in 24 KB chunks
  through a descriptor, 192 MB per-file ceiling.
- **Lint clean**, build passes, APK produced.

## Threat model notes

- An attacker within BLE range can connect and complete the handshake, but:
  - they obtain no commands until the human confirms the SAS on the phone;
  - frames they send cannot be replayed (counter window) or forged (GCM tag);
  - a second connection evicts the first session and forces re-handshake.
- The BLE advertisement carries no device name; the target is discoverable
  only by service UUID.
- All pairing trust is bound to the AndroidKeyStore identity; wiping it
  invalidates every peer.

## Deliberate limits

- No WiFi/UDP transport yet (BLE only). The iTell original had a hotspot
  fallback; adding it means a second SecureChannel instance over the same
  handshake frames — the crypto layer is transport-agnostic already.
- No root/Wireless-ADB shell helper. Call audio uses the official hidden APIs
  and reports "unavailable" honestly on devices that reject them.
- No iOS companion app exists yet; the protocol (handshake → GCM frames →
  fragmenter → JSON commands) is documented here for the iOS side to mirror.
- SMS delivery aggregation still needs a real-device two-SIM test.

## Device test status

Previous run (2026-11-23, SM-N981B / Android 13): build, install, launch,
GATT server, advertiser all PASS. This revision adds crypto, fragmentation,
queueing, content/media/audio — needs a fresh on-device pass, in particular:

1. Two-phone pairing: SAS matches on both screens, commands only after confirm.
2. Reconnect of a revoked peer is refused.
3. Multipart SMS arrives as one settled `sms_status`.
4. Call log / contacts / SMS history stream without truncation.
5. Audio probe on a real call; downlink frames arrive at ~50/s.
6. iOS side (`ios/` Swift package): `swift test` on a Mac passes the RFC 5869
   vectors, GCM round-trip, replay/tamper/reorder and fragment-reassembly
   tests; BLE transport then needs a real iOS device against the phone.

APK:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Build: `gradlew assembleDebug` with JAVA_HOME at JDK 17.
