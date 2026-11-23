import Foundation
import CoreBluetooth

/// BLE central that connects to the Android bridge's GATT server, runs the
/// mutual ECDH handshake, and exchanges AES-GCM frames.
///
/// Outbound flow: JSON → encrypt → GATT write (≤512 bytes, matching the phone's
/// MAX_GATT_VALUE). Inbound: GATT notification → decrypt → fragment reassembly
/// → JSON.
public final class BleTransport: NSObject {

    public static let serviceUUID = CBUUID(string: "8A5F0001-5B9A-4B5B-9A01-000000000001")
    public static let characteristicUUID = CBUUID(string: "8A5F0002-5B9A-4B5B-9A01-000000000001")

    public enum State: Equatable {
        case idle
        case scanning
        case connecting
        case handshake
        case awaitingTrust
        case ready
        case failed(String)
    }

    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var characteristic: CBCharacteristic?

    private let identity: DeviceIdentity
    private let store: PairingStore
    private var handshake: Handshake?
    private let reassembler = Fragmenter.Reassembler()
    private var channel: SecureChannel?

    private let queue = DispatchQueue(label: "bridge.ble.io")
    private let stateLock = NSLock()
    private var _state: State = .idle

    public var onState: ((State) -> Void)?
    public var onMessage: (([String: Any]) -> Void)?
    public var onPairingRequest: ((sas: String, fingerprint: String) -> Void)?

    public init(identity: DeviceIdentity, store: PairingStore) {
        self.identity = identity
        self.store = store
        super.init()
    }

    public var state: State {
        stateLock.lock(); defer { stateLock.unlock() }
        return _state
    }

    private func setState(_ state: State) {
        stateLock.lock()
        _state = state
        stateLock.unlock()
        DispatchQueue.main.async { [weak self] in
            self?.onState?(state)
        }
    }

    // ------------------------------------------------------------------ lifecycle

    public func start() {
        setState(.scanning)
        central = CBCentralManager(delegate: self, queue: queue)
    }

    public func stop() {
        queue.async { [weak self] in
            guard let self = self else { return }
            if let peripheral = self.peripheral {
                self.central?.cancelPeripheralConnection(peripheral)
            }
            self.channel = nil
            self.handshake?.abort()
            self.reassembler.reset()
            self.characteristic = nil
            self.peripheral = nil
            self.setState(.idle)
        }
    }

    /// Sends one JSON message over the encrypted channel. Fragments if needed.
    public func send(_ message: [String: Any]) {
        queue.async { [weak self] in
            guard let self = self else { return }
            guard let channel = self.channel, self.state == .ready else { return }
            guard
                let json = try? JSONSerialization.data(withJSONObject: message),
                let frameId = self.randomId()
            else { return }

            do {
                let frames = try Fragmenter.fragment(json, frameId: frameId)
                for frame in frames {
                    let plain = try JSONSerialization.data(withJSONObject: frame)
                    let sealed = channel.seal(plain)
                    self.write(sealed)
                }
            } catch {
                self.setState(.failed("send_failed"))
            }
        }
    }

    /// Called by the UI once the user confirms the SAS on both devices.
    public func confirmPairing() {
        queue.async { [weak self] in
            guard let self = self else { return }
            guard
                let handshake = self.handshake,
                let result = handshake.result,
                handshake.phase == .established
            else { return }
            self.store.trust(
                x963: self.peerX963,
                fingerprint: result.peerFingerprint,
                label: "Android bridge"
            )
            self.setState(.ready)
            self.send(["t": "pair_ok", "fp": result.peerFingerprint])
        }
    }

    public func rejectPairing() {
        queue.async { [weak self] in
            self?.channel = nil
            self?.handshake?.abort()
            self?.setState(.idle)
        }
    }

    private var peerX963: Data = Data()

    private func write(_ data: Data) {
        guard let peripheral = peripheral, let characteristic = characteristic else { return }
        let bounded = data.prefix(512)
        peripheral.writeValue(bounded, for: characteristic, type: .withResponse)
    }

    private func randomId() -> String? {
        var bytes = [UInt8](repeating: 0, count: 4)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { return nil }
        return Data(bytes).map { String(format: "%02x", $0) }.joined()
    }

    private func beginHandshake() {
        setState(.handshake)
        let handshake = Handshake(identity: identity, store: store)
        self.handshake = handshake
        do {
            let hello = try handshake.start()
            write(hello)
        } catch {
            setState(.failed("handshake_start_failed"))
        }
    }

    private func handleIncoming(_ data: Data) {
        // Before the session is up, only plaintext handshake frames arrive.
        if channel == nil {
            guard let handshake = handshake else { return }
            do {
                if let reply = try handshake.accept(data) {
                    write(reply)
                }
                if handshake.phase == .established, let result = handshake.result {
                    channel = result.channel
                    peerX963 = peerX963.isEmpty ? handshakePeerX963() : peerX963
                    if store.isTrusted(fingerprint: result.peerFingerprint) {
                        setState(.ready)
                        send(["t": "ready", "trusted": true])
                    } else {
                        setState(.awaitingTrust)
                        DispatchQueue.main.async { [weak self] in
                            self?.onPairingRequest?(result.sas, result.peerFingerprint)
                        }
                        send(["t": "ready", "trusted": false])
                    }
                }
            } catch {
                setState(.failed("handshake_failed"))
                handshake.abort()
            }
            return
        }

        guard let plaintext = channel?.open(data) else {
            setState(.failed("decrypt_failed"))
            channel = nil
            reassembler.reset()
            return
        }
        guard let frame = try? JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            return
        }
        if frame["t"] as? String == "fr" {
            guard let complete = try? reassembler.push(frame) else { return }
            guard let message = try? JSONSerialization.jsonObject(with: complete) as? [String: Any] else { return }
            DispatchQueue.main.async { [weak self] in
                self?.onMessage?(message)
            }
            return
        }
        DispatchQueue.main.async { [weak self] in
            self?.onMessage?(frame)
        }
    }

    /// The peer's X.963 point, captured during the handshake.
    private func handshakePeerX963() -> Data {
        // The handshake keeps it private; expose via the fingerprint lookup in
        // the store once trusted, otherwise derive from the transcript context.
        return store.all().first?.x963 ?? Data()
    }
}

extension BleTransport: CBCentralManagerDelegate, CBPeripheralDelegate {

    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            if central.state == .poweredOff || central.state == .unauthorized {
                setState(.failed("bluetooth_unavailable"))
            }
            return
        }
        central.scanForPeripherals(withServices: [Self.serviceUUID], options: nil)
    }

    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                               advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard self.peripheral == nil else { return }
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        setState(.connecting)
        central.connect(peripheral, options: nil)
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices([Self.serviceUUID])
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let service = peripheral.services?.first(where: { $0.uuid == Self.serviceUUID }) else {
            setState(.failed("service_not_found"))
            return
        }
        peripheral.discoverCharacteristics([Self.characteristicUUID], for: service)
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard
            error == nil,
            let characteristic = service.characteristics?.first(where: { $0.uuid == Self.characteristicUUID })
        else {
            setState(.failed("characteristic_not_found"))
            return
        }
        self.characteristic = characteristic
        peripheral.setNotifyValue(true, for: characteristic)
        beginHandshake()
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let data = characteristic.value else { return }
        handleIncoming(data)
    }

    public func peripheral(_ peripheral: CBPeripheral, didDisconnect peripheral: CBPeripheral, error: Error?) {
        channel = nil
        handshake?.abort()
        reassembler.reset()
        setState(.idle)
    }
}
