package com.bridge.android

import android.Manifest
import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.IBinder
import android.telecom.Call
import android.telecom.TelecomManager
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.util.Log
import com.bridge.android.content.ContentReader
import com.bridge.android.content.MediaReader
import com.bridge.android.crypto.PairingStore
import com.bridge.android.media.AudioBridge
import com.bridge.android.media.SmsBridge
import com.bridge.android.transport.BleBridge
import com.bridge.android.transport.MessageQueue
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground bridge service.
 *
 * Every inbound command is authenticated by [BleBridge] before it reaches this
 * class: an unpaired or unverified peer never gets a frame here. Commands that
 * touch private data additionally require the matching runtime permission, and
 * anything the transport cannot carry is answered with an explicit error rather
 * than silence.
 */
class BridgeService : Service() {

    private lateinit var smsBridge: SmsBridge
    private lateinit var audio: AudioBridge
    private lateinit var ble: BleBridge
    private lateinit var queue: MessageQueue
    private lateinit var content: ContentReader
    private lateinit var media: MediaReader
    private lateinit var pairing: PairingStore

    private val workers = Executors.newSingleThreadExecutor { r ->
        Thread(r, "bridge-worker").apply { isDaemon = true }
    }
    private val streaming = AtomicBoolean(false)

    fun smsResult(id: String, part: Int, ok: Boolean, delivered: Boolean, detail: String?): JSONObject? =
        smsBridge.onPartResult(id, part, ok, delivered, detail)

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIFICATION_ID, notification("Waiting for a paired companion"))
        instance = this

        queue = MessageQueue(this)
        BridgeServiceBus.attach(this, queue)
        content = ContentReader(this)
        media = MediaReader(this)
        pairing = PairingStore(this)
        smsBridge = SmsBridge(this)
        audio = AudioBridge(this)

        ble = BleBridge(
            context = this,
            pairingStore = pairing,
            onMessage = ::handleMessage,
            onStatus = { status ->
                Log.i(TAG, "ble: $status")
                publish(JSONObject().put("t", "ble_status").put("status", status))
                updateNotification(status)
            },
            onPairingRequest = { sas, fingerprint ->
                publish(JSONObject().put("t", "pair_request").put("sas", sas).put("fp", fingerprint))
                updateNotification("Pairing code $sas — confirm on both devices")
            },
            onPeerTrusted = { fingerprint ->
                publish(JSONObject().put("t", "peer_trusted").put("fp", fingerprint))
                drainQueue()
            },
        )
        startBle()
        if (BridgeServiceBus.consumeFlushRequest()) drainQueue()
    }

    fun startBle() {
        ble.start()?.let {
            Log.e(TAG, "BLE start failed: $it")
            publish(JSONObject().put("t", "ble_status").put("status", "start_failed").put("err", it))
        }
    }

    override fun onDestroy() {
        audio.stopCapture()
        audio.closeUplink()
        ble.stop()
        workers.shutdownNow()
        if (instance === this) {
            instance = null
            BridgeServiceBus.attach(null, null)
        }
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startBle()
        when (intent?.action) {
            ACTION_SEND_SMS -> {
                val raw = intent.getStringExtra(EXTRA_JSON).orEmpty()
                runCatching { JSONObject(raw) }
                    .onSuccess { smsBridge.send(it, ::publish) }
                    .onFailure { publish(Protocol.smsStatus("", false, "invalid request")) }
            }
            ACTION_CONFIRM_PAIRING -> {
                val fingerprint = intent.getStringExtra(EXTRA_FINGERPRINT).orEmpty()
                if (fingerprint.isNotEmpty() && ble.confirmPairing(fingerprint)) drainQueue()
            }
            ACTION_REJECT_PAIRING -> ble.rejectPairing()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ---------------------------------------------------------------- outbound

    fun publish(message: JSONObject) {
        BridgeServiceBus.listeners.forEach { runCatching { it(message) } }
        if (ble.currentPeerFingerprint() != null) {
            ble.send(message)
        } else {
            // No authenticated peer: persist so the next session receives it.
            queue.offer(message)
        }
    }

    /** Replays everything buffered while no peer was connected. */
    fun drainQueue() {
        workers.execute {
            queue.drain { entry ->
                val parsed = runCatching { JSONObject(entry.json) }.getOrNull() ?: return@drain true
                ble.send(parsed)
                ble.currentPeerFingerprint() != null
            }
            publish(JSONObject().put("t", "queue_status").put("pending", queue.size()))
        }
    }

    // ---------------------------------------------------------------- inbound

    private fun handleMessage(message: JSONObject) {
        val command = message.optString("t").ifBlank { message.optString("command") }
        val id = message.optString("id")
        val payload = message.optJSONObject("payload") ?: message
        Log.i(TAG, "command: $command")

        when (command) {
            "ping" -> publish(Protocol.commandResult(id, "ping", true, "pong"))

            "echo" -> publish(Protocol.commandResult(id, "echo", true, payload.optString("v", "echoed")))

            "device" -> publish(content.deviceSnapshot().put("id", id))

            "sms", "send_sms" -> {
                smsBridge.send(JSONObject(payload.toString()).put("id", id)) { response ->
                    publish(response)
                }
            }

            "call", "dial" -> runCommand(id, "call") {
                dial(payload.optString("to"), payload.optInt("sim", -1))
            }

            "answer" -> runCommand(id, "answer") { answer(payload.optString("callId")) }

            "hangup" -> runCommand(id, "hangup") {
                hangup(payload.optString("callId").ifBlank { activeCallId() })
            }

            "dtmf" -> {
                val digit = payload.optString("d").firstOrNull()
                val tone = digit?.let { AudioBridge.DTMF[it] }
                if (tone == null) {
                    publish(Protocol.error(id, "bad_digit"))
                } else {
                    val written = audio.injectDtmf(tone.first, tone.second)
                    publish(Protocol.commandResult(id, "dtmf", written > 0, if (written > 0) "sent" else "no_uplink", if (written > 0) null else "uplink_unavailable"))
                }
            }

            "state" -> publish(Protocol.commandResult(id, "state", true, callState()))

            "audio_probe" -> {
                val result = audio.probe()
                publish(Protocol.commandResult(id, "audio_probe", result.optBoolean("ok"), result.toString()))
            }

            "audio_start" -> runCommand(id, "audio_start") { startCallAudio(id) }

            "audio_stop" -> runCommand(id, "audio_stop") {
                audio.stopCapture()
                audio.closeUplink()
                null
            }

            "calls_req" -> streamData(id, "calls") {
                content.readCallLog(payload.optLong("since", 0), payload.optInt("limit", 200), ::emitAndContinue)
            }

            "smslog_req" -> streamData(id, "smslog") {
                content.readSms(payload.optLong("since", 0), payload.optInt("limit", 200), ::emitAndContinue)
            }

            "contacts_req" -> streamData(id, "contacts") {
                content.readContacts(
                    payload.optInt("limit", 300),
                    payload.optBoolean("photos", true),
                    ::emitAndContinue,
                )
            }

            "photos_offer" -> streamData(id, "media") {
                media.offerMedia(payload.optString("kind", "image"), payload.optInt("limit", 100), ::emitAndContinue)
            }

            "photos_req" -> {
                val kind = payload.optString("kind", "image")
                val mediaId = payload.optLong("id", -1).let { if (it < 0) payload.optLong("media_id", -1) else it }
                if (mediaId < 0) {
                    publish(Protocol.error(id, "bad_media_id"))
                } else {
                    workers.execute { streamMedia(id, kind, mediaId) }
                }
            }

            "call_log_watch", "contacts_watch", "sms_watch" -> {
                publish(Protocol.commandResult(id, command, true, "watchers_active"))
            }

            else -> publish(Protocol.error(id, "unknown_command", command))
        }
    }

    private fun emitAndContinue(record: JSONObject): Boolean {
        ble.send(record)
        return ble.currentPeerFingerprint() != null
    }

    private fun streamData(id: String, kind: String, reader: () -> Int) {
        workers.execute {
            if (streaming.compareAndSet(false, true)) {
                try {
                    val count = reader()
                    when {
                        count < 0 -> publish(Protocol.error(id, "permission_missing", kind))
                        else -> publish(Protocol.commandResult(id, "${kind}_done", true, count.toString()))
                    }
                } finally {
                    streaming.set(false)
                }
            } else {
                publish(Protocol.error(id, "busy", "another_stream_active"))
            }
        }
    }

    private fun streamMedia(id: String, kind: String, mediaId: Long) {
        val transferId = UUID.randomUUID().toString().take(8)
        val size = media.streamMedia(kind, mediaId) { index, total, data ->
            ble.send(
                JSONObject()
                    .put("t", "media_chunk")
                    .put("id", transferId)
                    .put("i", index)
                    .put("n", total)
                    .put("d", android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP))
            )
        }
        if (size < 0) {
            publish(Protocol.error(id, "media_unavailable"))
        } else {
            ble.send(JSONObject().put("t", "media_end").put("id", transferId).put("s", size))
            publish(Protocol.commandResult(id, "photos_done", true, transferId))
        }
    }

    private fun runCommand(id: String, command: String, action: () -> String?) {
        val error = runCatching { action() }.getOrElse { it.message ?: it.javaClass.simpleName }
        publish(Protocol.commandResult(id, command, error == null, if (error == null) "accepted" else "failed", error))
    }

    private fun startCallAudio(id: String): String? {
        if (audio.probe().optBoolean("ok").not()) return "no_call_audio_path"
        val captureError = audio.startCapture { pcm ->
            ble.send(
                JSONObject()
                    .put("t", "audio")
                    .put("d", android.util.Base64.encodeToString(pcm, android.util.Base64.NO_WRAP))
            )
        }
        if (captureError != null) return captureError
        audio.openUplink()?.let { Log.w(TAG, "uplink unavailable: $it") }
        publish(Protocol.commandResult(id, "audio_start", true, "streaming"))
        return null
    }

    // ---------------------------------------------------------------- calls

    private fun activeCallId(): String = synchronized(calls) {
        calls.entries.firstOrNull { it.value.state != Call.STATE_DISCONNECTED }?.key.orEmpty()
    }

    private fun callState(): String = synchronized(calls) {
        calls.values.firstOrNull { it.state != Call.STATE_DISCONNECTED }?.let { call ->
            when (call.state) {
                Call.STATE_RINGING -> "ringing"
                Call.STATE_DIALING, Call.STATE_CONNECTING -> "dialing"
                Call.STATE_ACTIVE -> "active"
                Call.STATE_DISCONNECTED -> "disconnected"
                else -> "unknown"
            }
        } ?: "idle"
    }

    private fun dial(number: String, sim: Int): String? {
        if (number.isBlank()) return "empty number"
        if (checkSelfPermission(Manifest.permission.CALL_PHONE) != PackageManager.PERMISSION_GRANTED) {
            return "CALL_PHONE permission missing"
        }
        val telecom = getSystemService(TelecomManager::class.java) ?: return "TelecomManager unavailable"
        val accounts = runCatching { telecom.callCapablePhoneAccounts }.getOrDefault(emptyList())
        val telephony = getSystemService(TelephonyManager::class.java)
        val account = if (sim < 0) {
            val default = runCatching { telecom.getDefaultOutgoingPhoneAccount("tel") }.getOrNull()
            default?.takeIf { it in accounts } ?: accounts.singleOrNull()
        } else {
            accounts.firstOrNull { handle ->
                runCatching { SubscriptionManager.getSlotIndex(telephony.getSubscriptionId(handle)) == sim }
                    .getOrDefault(false)
            }
        } ?: return if (accounts.isEmpty()) "no_call_capable_phone_account" else "call_sim_selection_required"
        if (runCatching { telephony.isEmergencyNumber(number) }.getOrDefault(false)) {
            return "emergency_number_must_be_dialed_on_device"
        }
        if (synchronized(calls) { calls.values.any { it.state != Call.STATE_DISCONNECTED } }) {
            return "another_call_active"
        }
        val extras = android.os.Bundle().apply {
            putParcelable(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE, account)
            putString(EXTRA_BRIDGE_CALL_ID, UUID.randomUUID().toString())
        }
        return runCatching {
            telecom.placeCall(android.net.Uri.fromParts("tel", number, null), extras)
        }.exceptionOrNull()?.message
    }

    private fun answer(callId: String): String? {
        if (checkSelfPermission(Manifest.permission.ANSWER_PHONE_CALLS) != PackageManager.PERMISSION_GRANTED) {
            return "ANSWER_PHONE_CALLS permission missing"
        }
        val ringing = synchronized(calls) {
            if (callId.isNotBlank()) calls[callId]?.takeIf { it.state == Call.STATE_RINGING }
            else calls.values.firstOrNull { it.state == Call.STATE_RINGING }
        }
        if (ringing != null) {
            return runCatching { ringing.answer(android.telecom.VideoProfile.STATE_AUDIO_ONLY) }
                .exceptionOrNull()?.message
        }
        return runCatching {
            @Suppress("DEPRECATION")
            getSystemService(TelecomManager::class.java).acceptRingingCall()
        }.exceptionOrNull()?.message ?: "no_ringing_call"
    }

    private fun hangup(id: String): String? = runCatching {
        val tracked = synchronized(calls) {
            if (id.isNotBlank()) calls[id]
            else calls.values.firstOrNull { it.state != Call.STATE_DISCONNECTED }
        }
        if (tracked != null) {
            tracked.disconnect()
        } else {
            if (checkSelfPermission(Manifest.permission.ANSWER_PHONE_CALLS) != PackageManager.PERMISSION_GRANTED) {
                return "ANSWER_PHONE_CALLS permission missing"
            }
            @Suppress("DEPRECATION")
            @SuppressLint("MissingPermission")
            if (!getSystemService(TelecomManager::class.java).endCall()) {
                error("no_active_call_or_end_call_rejected")
            }
            null
        }
    }.exceptionOrNull()?.message

    // ---------------------------------------------------------------- notification

    private fun createChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Bridge", NotificationManager.IMPORTANCE_LOW),
        )
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Bridge")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        runCatching {
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
        }
    }

    companion object {
        private const val TAG = "PhoneBridge"
        private const val CHANNEL_ID = "bridge"
        private const val NOTIFICATION_ID = 1
        internal const val EXTRA_BRIDGE_CALL_ID = "com.bridge.android.CALL_ID"
        const val ACTION_SEND_SMS = "com.bridge.android.SEND_SMS"
        const val ACTION_CONFIRM_PAIRING = "com.bridge.android.CONFIRM_PAIRING"
        const val ACTION_REJECT_PAIRING = "com.bridge.android.REJECT_PAIRING"
        const val EXTRA_JSON = "json"
        const val EXTRA_FINGERPRINT = "fp"

        @Volatile
        private var instance: BridgeService? = null

        internal val calls = mutableMapOf<String, Call>()

        fun publish(context: Context, message: JSONObject) {
            BridgeServiceBus.publishOrQueue(context, message)
        }

        fun ensureStarted(context: Context) {
            val running = instance
            if (running != null) running.startBle()
            else runCatching { context.startForegroundService(Intent(context, BridgeService::class.java)) }
        }

        fun callAdded(context: Context, call: Call) {
            val id = call.details?.extras?.getString(EXTRA_BRIDGE_CALL_ID)
                ?: call.details?.intentExtras?.getString(EXTRA_BRIDGE_CALL_ID)
                ?: UUID.randomUUID().toString()
            synchronized(calls) { calls[id] = call }
            publishCallState(id, call)
            runCatching {
                call.registerCallback(object : Call.Callback() {
                    override fun onStateChanged(changed: Call, state: Int) = publishCallState(id, changed)
                })
            }
        }

        private fun publishCallState(id: String, call: Call) {
            val state = when (call.state) {
                Call.STATE_RINGING -> "ringing"
                Call.STATE_DIALING, Call.STATE_CONNECTING -> "dialing"
                Call.STATE_ACTIVE -> "active"
                Call.STATE_DISCONNECTED -> "disconnected"
                else -> "unknown"
            }
            instance?.publish(Protocol.callState(id, state))
                ?: BridgeServiceBus.listeners.forEach { it(Protocol.callState(id, state)) }
        }

        fun callRemoved(call: Call) {
            val removed = synchronized(calls) {
                calls.entries.firstOrNull { it.value == call }?.also { calls.remove(it.key) }
            }
            removed?.let { instance?.publish(JSONObject().put("t", "end").put("id", it.key)) }
        }

        fun dial(context: Context, id: String, number: String, sim: Int = -1): String? =
            instance?.dial(number, sim) ?: "service_not_running"

        fun answer(context: Context, callId: String): String? =
            instance?.answer(callId) ?: "service_not_running"

        fun hangup(context: Context, id: String): String? =
            instance?.hangup(id) ?: "service_not_running"
    }
}
