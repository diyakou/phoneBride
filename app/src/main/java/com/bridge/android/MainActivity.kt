package com.bridge.android

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject
import com.bridge.android.crypto.DeviceIdentity
import com.bridge.android.crypto.PairingStore

/**
 * Minimal control surface: shows the device fingerprint, surfaces pairing
 * requests (SAS comparison), and exposes revoke for a lost peer.
 */
class MainActivity : Activity() {

    private lateinit var status: TextView
    private var lastBleEvent = ""
    private var pendingFingerprint = ""

    private val permissions = arrayOf(
        Manifest.permission.BLUETOOTH_SCAN,
        Manifest.permission.BLUETOOTH_CONNECT,
        Manifest.permission.BLUETOOTH_ADVERTISE,
        Manifest.permission.CALL_PHONE,
        Manifest.permission.ANSWER_PHONE_CALLS,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.READ_PHONE_NUMBERS,
        Manifest.permission.READ_CALL_LOG,
        Manifest.permission.SEND_SMS,
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.READ_SMS,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.POST_NOTIFICATIONS,
        Manifest.permission.READ_MEDIA_IMAGES,
        Manifest.permission.READ_MEDIA_VIDEO,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        BridgeServiceBus.listeners += ::showBridgeEvent
        status = TextView(this).apply {
            textSize = 14f
            setPadding(32, 48, 32, 32)
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(status)
            addView(Button(this@MainActivity).apply {
                text = "Confirm Pairing SAS"
                setOnClickListener {
                    if (pendingFingerprint.isNotEmpty()) {
                        BridgeServiceBus.confirmPairing(pendingFingerprint)
                    }
                }
            })
            addView(Button(this@MainActivity).apply {
                text = "Unpair all companions"
                setOnClickListener {
                    PairingStore(this@MainActivity).clear()
                    DeviceIdentity.reset()
                    renderStatus()
                }
            })
        })
        requestMissingPermissions()
    }

    override fun onDestroy() {
        BridgeServiceBus.listeners -= ::showBridgeEvent
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        renderStatus()
        if (bluetoothPermissionsGranted()) startBridge()
    }

    private fun showBridgeEvent(message: JSONObject) {
        runOnUiThread {
            val type = message.optString("t")
            val detail = when (type) {
                "pair_request" -> {
                    pendingFingerprint = message.optString("fp")
                    "SAS: ${message.optString("sas")}\nConfirm same code on iPhone"
                }
                "ble_status" -> message.optString("status")
                "peer_trusted" -> "trusted"
                else -> message.optString("status").ifBlank { message.optString("sas") }
            }
            lastBleEvent = detail
            status.text = "Bridge\n$lastBleEvent\n\n${status.text}"
        }
    }

    private fun renderStatus() {
        val pairing = PairingStore(this)
        val peers = pairing.all()
        status.text = buildString {
            append("Bridge\n")
            append("identity: ${DeviceIdentity.publicIdentity().fingerprint.take(12)}…\n")
            append("peers: ${peers.size}\n")
            if (lastBleEvent.isNotEmpty()) append("BLE: $lastBleEvent\n")
            peers.forEach { append("  ${it.label} (${it.fingerprint.take(12)}…)\n") }
        }
    }

    private fun requestMissingPermissions() {
        val missing = permissions.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) requestPermissions(missing.toTypedArray(), REQUEST_PERMISSIONS)
        if (bluetoothPermissionsGranted()) startBridge()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQUEST_PERMISSIONS) return
        if (bluetoothPermissionsGranted()) startBridge()
    }

    private fun bluetoothPermissionsGranted() =
        checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED &&
            checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED

    private fun startBridge() {
        BridgeServiceBus.ensureRunning(this)
    }

    companion object {
        private const val REQUEST_PERMISSIONS = 100
    }
}
