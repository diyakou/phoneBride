package com.bridge.android.media

import android.Manifest
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import com.bridge.android.BridgeServiceBus
import com.bridge.android.Protocol
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Outbound SMS with per-part delivery accounting.
 *
 * Fixes from the prototype:
 *  - the pending map is actually released (it leaked one entry per message);
 *  - request codes come from a monotonic counter, so two message ids can never
 *    collide on the same PendingIntent and cross-report delivery;
 *  - a timeout reaper fails a request whose broadcast never arrives instead of
 *    leaving it pending forever.
 */
class SmsBridge(private val context: Context) {

    private class Pending(val total: Int) {
        val completed = AtomicInteger(0)
        val failed = AtomicInteger(0)
        @Volatile var error: String? = null
        @Volatile var settled = false
    }

    private val pending = ConcurrentHashMap<String, Pending>()
    private val requestCodes = AtomicInteger(1)

    fun send(request: JSONObject, reply: (JSONObject) -> Unit) {
        if (context.checkSelfPermission(Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED) {
            reply(Protocol.smsStatus(request.optString("id"), false, "SEND_SMS permission missing"))
            return
        }
        val id = request.optString("id").ifBlank { UUID.randomUUID().toString() }
        val to = request.optString("to").trim()
        val body = request.optString("body")
        if (to.isBlank() || body.isBlank()) {
            reply(Protocol.smsStatus(id, false, "to and body required"))
            return
        }
        if (pending.containsKey(id)) {
            reply(Protocol.smsStatus(id, false, "duplicate_id"))
            return
        }

        val slot = request.optInt("sim", -1)
        val subscriptionId = resolveSubscription(slot)
        if (subscriptionId == null) {
            val reason = if (activeSubscriptions().isEmpty()) "no_active_sim" else "sms_sim_selection_required"
            reply(Protocol.smsStatus(id, false, reason))
            return
        }

        runCatching {
            val manager = if (Build.VERSION.SDK_INT >= 31) {
                SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
            } else {
                @Suppress("DEPRECATION")
                SmsManager.getDefault()
            }
            val parts = manager.divideMessage(body)
            val state = Pending(parts.size)
            pending[id] = state

            val sentIntents = ArrayList<PendingIntent>(parts.size)
            val deliveredIntents = ArrayList<PendingIntent>(parts.size)
            parts.indices.forEach { index ->
                val code = requestCodes.getAndIncrement()
                sentIntents += PendingIntent.getBroadcast(
                    context,
                    code,
                    Intent(SmsSentReceiver.ACTION_SMS_SENT).setPackage(context.packageName)
                        .putExtra(SmsSentReceiver.EXTRA_ID, id)
                        .putExtra(SmsSentReceiver.EXTRA_PART, index),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                deliveredIntents += PendingIntent.getBroadcast(
                    context,
                    requestCodes.getAndIncrement(),
                    Intent(SmsSentReceiver.ACTION_SMS_DELIVERED).setPackage(context.packageName)
                        .putExtra(SmsSentReceiver.EXTRA_ID, id)
                        .putExtra(SmsSentReceiver.EXTRA_PART, index),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            }
            manager.sendMultipartTextMessage(to, null, parts, sentIntents, deliveredIntents)
            scheduleReap(id)
        }.onFailure {
            pending.remove(id)
            reply(Protocol.smsStatus(id, false, it.message ?: it.javaClass.simpleName))
        }.onSuccess {
            reply(Protocol.smsStatus(id, true))
        }
    }

    /** Called from the sent/delivered receivers. Returns true when it settled the request. */
    fun onPartResult(id: String, part: Int, ok: Boolean, delivered: Boolean, detail: String?): JSONObject? {
        val state = pending[id] ?: return null
        if (state.settled) return null
        if (ok) {
            state.completed.incrementAndGet()
        } else {
            state.failed.incrementAndGet()
            state.error = detail ?: "part $part failed"
        }
        if (state.completed.get() + state.failed.get() < state.total) return null
        state.settled = true
        pending.remove(id)
        val okAll = state.failed.get() == 0
        return Protocol.smsStatus(id, okAll, if (okAll) null else state.error)
    }

    private fun scheduleReap(id: String) {
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        handler.postDelayed({
            val state = pending.remove(id) ?: return@postDelayed
            if (state.settled) return@postDelayed
            state.settled = true
            BridgeServiceBus.publish(
                Protocol.smsStatus(id, false, "no_delivery_report_after_${TIMEOUT_MS}ms")
            )
        }, TIMEOUT_MS)
    }

    private fun resolveSubscription(slot: Int): Int? {
        val active = activeSubscriptions()
        if (active.isEmpty()) return null
        if (slot >= 0) return active.firstOrNull { it.simSlotIndex == slot }?.subscriptionId
        val defaultId = runCatching { SmsManager.getDefaultSmsSubscriptionId() }
            .getOrDefault(SubscriptionManager.INVALID_SUBSCRIPTION_ID)
        if (defaultId != SubscriptionManager.INVALID_SUBSCRIPTION_ID && active.any { it.subscriptionId == defaultId }) {
            return defaultId
        }
        return active.singleOrNull()?.subscriptionId
    }

    private fun activeSubscriptions() = runCatching {
        if (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) {
            emptyList()
        } else {
            context.getSystemService(SubscriptionManager::class.java)?.activeSubscriptionInfoList.orEmpty()
        }
    }.getOrDefault(emptyList())

    fun pendingCount(): Int = pending.size

    private companion object {
        const val TIMEOUT_MS = 90_000L
    }
}
