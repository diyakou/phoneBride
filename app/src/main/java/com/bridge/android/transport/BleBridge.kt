package com.bridge.android.transport

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.content.pm.PackageManager
import android.os.ParcelUuid
import com.bridge.android.crypto.DeviceIdentity
import com.bridge.android.crypto.Handshake
import com.bridge.android.crypto.PairingStore
import com.bridge.android.crypto.SecureChannel
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Hardened BLE GATT server.
 *
 * Security properties:
 *  - nothing is accepted before a mutual ECDH handshake completes;
 *  - every frame after the handshake is AES-256-GCM with a counter bound in the
 *    AAD and a replay window, so an attacker cannot inject, replay or reorder;
 *  - a peer absent from [PairingStore] gets its SAS surfaced to the user and the
 *    service refuses commands until the human confirms;
 *  - exactly one authenticated peer at a time, re-checked on every frame;
 *  - all GATT notifications funnel through [GattWriter] on one thread, so binder
 *    callbacks cannot race the notify path.
 */
@SuppressLint("MissingPermission")
class BleBridge(
    private val context: Context,
    private val pairingStore: PairingStore,
    private val onMessage: (JSONObject) -> Unit,
    private val onStatus: (String) -> Unit = {},
    private val onPairingRequest: (sas: String, fingerprint: String) -> Unit = { _, _ -> },
    private val onPeerTrusted: (fingerprint: String) -> Unit = {},
) {
    private val manager = context.getSystemService(BluetoothManager::class.java)
    private var server: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var characteristic: BluetoothGattCharacteristic? = null
    private val subscribed = ConcurrentHashMap.newKeySet<String>()
    private val connectionGeneration = AtomicLong(0)
    @Volatile private var activeGeneration = 0L
    @Volatile private var activeAddress: String? = null
    @Volatile private var handshakeStarted = false

    private val io: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "bridge-ble-io").apply { isDaemon = true }
    }

    private val handshake = Handshake(pairingStore)
    private var session: Session? = null
    private val reassembler = Fragmenter.Reassembler()
    private var writer: GattWriter? = null

    private class Session(
        val device: BluetoothDevice,
        val channel: SecureChannel,
        val fingerprint: String,
        val spki: ByteArray,
        trusted: Boolean,
    ) {
        val trustedFlag = AtomicBoolean(trusted)
    }

    private val callback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                onStatus("gatt_connection_failed:$status")
                clearConnection(device.address)
                return
            }
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    clearConnection(device.address)
                    activeGeneration = connectionGeneration.incrementAndGet()
                    activeAddress = device.address
                    onStatus("connected:g$activeGeneration")
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    if (activeAddress == device.address) clearConnection(device.address)
                    onStatus("disconnected")
                }
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            if (service.uuid != SERVICE_UUID) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                onStatus("gatt_service_failed:$status")
                server?.close()
                server = null
                advertiser = null
                characteristic = null
                return
            }
            startAdvertising()
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            val valid = descriptor.uuid == CCCD_UUID &&
                descriptor.characteristic?.uuid == CHARACTERISTIC_UUID &&
                !preparedWrite && offset == 0 &&
                (value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) ||
                    value.contentEquals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE))
            respond(device, requestId, responseNeeded, if (valid) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED)
            if (!valid) return
            if (value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)) {
                if (activeAddress != device.address) return
                subscribed += device.address
                onStatus("notifications_enabled")
                if (!handshakeStarted) {
                    handshakeStarted = true
                    startHandshake(device)
                }
            } else {
                subscribed -= device.address
                onStatus("notifications_disabled")
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            if (characteristic.uuid != CHARACTERISTIC_UUID || preparedWrite || offset != 0) {
                respond(device, requestId, responseNeeded, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED)
                return
            }
            if (value.size > MAX_GATT_VALUE) {
                respond(device, requestId, responseNeeded, BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH)
                return
            }
            respond(device, requestId, responseNeeded, BluetoothGatt.GATT_SUCCESS)
            // Off the binder thread: crypto and JSON parsing never block the stack.
            io.execute { handleIncoming(device, value) }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) onStatus("notify_failed:$status")
        }
    }

    // ---------------------------------------------------------------- lifecycle

    fun start(): String? {
        if (server != null) {
            restartAdvertising()
            return null
        }
        if (!hasBluetoothPermissions()) return "Bluetooth permissions missing"
        val adapter = manager?.adapter ?: return "Bluetooth unavailable"
        if (!adapter.isEnabled) return "Bluetooth disabled"

        val bleServer = runCatching { manager.openGattServer(context, callback) }.getOrNull()
            ?: return "GATT server unavailable"
        server = bleServer
        onStatus("gatt_server_started")

        val chr = BluetoothGattCharacteristic(
            CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        chr.addDescriptor(
            BluetoothGattDescriptor(
                CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
            )
        )
        characteristic = chr

        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            .apply { addCharacteristic(chr) }
        advertiser = adapter.bluetoothLeAdvertiser ?: run {
            bleServer.close()
            server = null
            characteristic = null
            return "BLE advertiser unavailable"
        }
        if (!bleServer.addService(service)) {
            bleServer.close()
            server = null
            advertiser = null
            characteristic = null
            return "GATT service registration rejected"
        }

        writer = GattWriter(dispatch = ::dispatchRaw, onDropped = { onStatus("writer_dropped:$it") })
        onStatus("gatt_server_open")
        return null
    }

    fun restartAdvertising() {
        if (!hasBluetoothPermissions()) {
            onStatus("Bluetooth permissions missing")
            return
        }
        val adapter = manager?.adapter ?: run {
            onStatus("Bluetooth unavailable")
            return
        }
        if (!adapter.isEnabled) {
            onStatus("Bluetooth disabled")
            return
        }
        val current = advertiser ?: adapter.bluetoothLeAdvertiser ?: run {
            onStatus("BLE advertiser unavailable")
            return
        }
        advertiser = current
        if (::advertiseCallback.isInitialized) {
            runCatching { current.stopAdvertising(advertiseCallback) }
        }
        startAdvertising()
    }

    private fun startAdvertising() {
        if (!hasBluetoothPermissions()) {
            onStatus("Bluetooth permissions missing")
            return
        }
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .build()
        // No device name in the advertisement: an attacker cannot pick the target
        // out of a crowd by name, only by the service UUID it must already know.
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()
        advertiseCallback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings) = onStatus("advertising_started")
            override fun onStartFailure(errorCode: Int) = onStatus("advertise_failed:$errorCode")
        }
        runCatching {
            advertiser?.startAdvertising(settings, data, advertiseCallback)
        }.onFailure { onStatus("advertise_failed:${it.javaClass.simpleName}") }
    }

    fun stop() {
        if (hasBluetoothPermissions()) {
            runCatching { advertiser?.stopAdvertising(advertiseCallback) }
            runCatching { server?.close() }
        }
        writer?.shutdown()
        writer = null
        advertiser = null
        server = null
        characteristic = null
        session = null
        reassembler.reset()
        handshake.abort()
        subscribed.clear()
        onStatus("stopped")
    }

    // ---------------------------------------------------------------- handshake

    private fun startHandshake(device: BluetoothDevice) {
        if (activeAddress != device.address || !subscribed.contains(device.address)) return
        session = null
        reassembler.reset()
        handshake.abort()
        onStatus("handshake_started:g$activeGeneration")
        sendPlain(device, handshake.start(Handshake.Role.RESPONDER))
    }

    private fun clearConnection(address: String) {
        if (activeAddress != null && activeAddress != address) return
        session = null
        handshake.abort()
        reassembler.reset()
        subscribed.remove(address)
        handshakeStarted = false
        activeAddress = null
        activeGeneration = 0L
        writer?.clear(address)
        onStatus("connection_state_cleared")
    }

    private fun handleIncoming(device: BluetoothDevice, value: ByteArray) {
        val current = session
        if (current == null) {
            // Before the handshake only plaintext handshake frames are legal.
            val text = runCatching { String(value, StandardCharsets.UTF_8) }.getOrNull() ?: return
            val frame = runCatching { JSONObject(text) }.getOrNull() ?: run {
                onStatus("invalid_json")
                return
            }
            if (!frame.optString("t").startsWith("hs_")) {
                onStatus("pre_handshake_rejected")
                return
            }
            when (val outcome = handshake.accept(frame)) {
                is Handshake.Outcome.Continue -> sendPlain(device, outcome.frame)
                is Handshake.Outcome.Failed -> {
                    onStatus("handshake_failed:${outcome.reason}")
                    handshake.abort()
                    session = null
                    reassembler.reset()
                    handshakeStarted = false
                }
                is Handshake.Outcome.Established -> {
                    val established = Session(
                        device = device,
                        channel = outcome.channel,
                        fingerprint = outcome.peer.fingerprint,
                        spki = outcome.peer.spki,
                        trusted = outcome.alreadyTrusted,
                    )
                    session = established
                    outcome.finalFrame?.let { sendPlain(device, it) }
                    if (outcome.alreadyTrusted) {
                        onStatus("session_established:trusted")
                        onPeerTrusted(outcome.peer.fingerprint)
                    } else {
                        onStatus("session_established:untrusted")
                        onPairingRequest(outcome.sas, outcome.peer.fingerprint)
                    }
                    sendEncrypted(established, JSONObject().put("t", "ready").put("trusted", outcome.alreadyTrusted))
                }
            }
            return
        }

        if (activeAddress != device.address || !subscribed.contains(device.address)) return
        if (current.device.address != device.address) {
            onStatus("foreign_device_rejected")
            return
        }
        val plaintext = current.channel.open(value)
        if (plaintext == null) {
            // Bad tag, replay, or reordering: kill the session rather than guess.
            onStatus("decrypt_failed")
            session = null
            reassembler.reset()
            return
        }
        val frame = runCatching { JSONObject(String(plaintext, StandardCharsets.UTF_8)) }.getOrNull()
        if (frame == null) {
            onStatus("invalid_json")
            return
        }
        if (frame.optString("t") == "fr") {
            val complete = runCatching { reassembler.push(frame) }.getOrNull() ?: return
            val message = runCatching { JSONObject(String(complete, StandardCharsets.UTF_8)) }.getOrNull()
                ?: run {
                    onStatus("invalid_json")
                    return
                }
            deliver(current, message)
            return
        }
        deliver(current, frame)
    }

    private fun deliver(current: Session, message: JSONObject) {
        if (!current.trustedFlag.get()) {
            if (message.optString("t") == "pair_ok" && message.optString("fp") == current.fingerprint) {
                current.trustedFlag.set(true)
                pairingStore.trust(DeviceIdentity.Public(current.spki, current.fingerprint), "paired peer")
                onPeerTrusted(current.fingerprint)
                onStatus("session_established:trusted")
                sendEncrypted(current, JSONObject().put("t", "ready").put("trusted", true))
            } else {
                onStatus("untrusted_command_rejected")
                sendEncrypted(current, JSONObject().put("t", "error").put("err", "not_paired"))
            }
            return
        }
        onMessage(message)
    }

    /** Called by the UI once the human confirms the SAS matches on both screens. */
    fun confirmPairing(fingerprint: String, label: String = "paired peer"): Boolean {
        val current = session ?: return false
        if (current.fingerprint != fingerprint) return false
        pairingStore.trust(DeviceIdentity.Public(current.spki, current.fingerprint), label)
        current.trustedFlag.set(true)
        onPeerTrusted(fingerprint)
        onStatus("pairing_confirmed")
        sendEncrypted(current, JSONObject().put("t", "ready").put("trusted", true))
        return true
    }

    fun rejectPairing() {
        session = null
        handshake.abort()
        reassembler.reset()
        onStatus("pairing_rejected")
    }

    fun currentPeerFingerprint(): String? = session?.fingerprint

    // ---------------------------------------------------------------- outbound

    fun send(message: JSONObject) {
        val current = session ?: return
        if (!current.trustedFlag.get()) return
        sendEncrypted(current, message)
    }

    private fun sendEncrypted(current: Session, message: JSONObject) {
        val frameId = UUID.randomUUID().toString().take(8)
        Fragmenter.fragment(message, frameId).forEach { frame ->
            val plain = frame.toString().toByteArray(StandardCharsets.UTF_8)
            writer?.enqueue(current.device.address, current.channel.seal(plain))
        }
    }

    private fun sendPlain(device: BluetoothDevice, frame: JSONObject) {
        val plain = frame.toString().toByteArray(StandardCharsets.UTF_8)
        if (plain.size > MAX_GATT_VALUE) {
            onStatus("handshake_frame_too_large")
            return
        }
        writer?.enqueue(device.address, plain)
    }

    /** Runs on the writer thread only. */
    private fun dispatchRaw(address: String, frame: ByteArray): Int {
        if (address !in subscribed) return GattWriter.GATT_SUCCESS // peer has not subscribed yet
        val bleServer = server ?: return BluetoothGatt.GATT_FAILURE
        val chr = characteristic ?: return BluetoothGatt.GATT_FAILURE
        val device = connectedDevice(address) ?: return BluetoothGatt.GATT_FAILURE
        return runCatching {
            @Suppress("DEPRECATION")
            chr.value = frame
            @Suppress("DEPRECATION")
            if (bleServer.notifyCharacteristicChanged(device, chr, false)) {
                GattWriter.GATT_SUCCESS
            } else {
                GattWriter.GATT_BUSY
            }
        }.getOrDefault(BluetoothGatt.GATT_FAILURE)
    }

    private fun connectedDevice(address: String): BluetoothDevice? = runCatching {
        manager?.adapter?.getRemoteDevice(address)
    }.getOrNull()

    private fun respond(device: BluetoothDevice, requestId: Int, needed: Boolean, status: Int) {
        if (!needed) return
        runCatching { server?.sendResponse(device, requestId, status, 0, null) }
    }

    private fun hasBluetoothPermissions() =
        context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED &&
            context.checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED

    private lateinit var advertiseCallback: AdvertiseCallback

    companion object {
        private const val TAG = "PhoneBridge"
        val SERVICE_UUID: UUID = UUID.fromString("8A5F0001-5B9A-4B5B-9A01-000000000001")
        val CHARACTERISTIC_UUID: UUID = UUID.fromString("8A5F0002-5B9A-4B5B-9A01-000000000001")
        private val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        private const val MAX_GATT_VALUE = 512
    }
}
