package com.bridge.android.media

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.bridge.android.BridgeServiceBus
import org.json.JSONObject

/**
 * Delivery accounting for outbound SMS: one broadcast per part for "sent" and
 * one for "delivered". Settles the request only when every part reported.
 */
class SmsSentReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != ACTION_SMS_SENT && action != ACTION_SMS_DELIVERED) return
        val id = intent.getStringExtra(EXTRA_ID).orEmpty()
        if (id.isEmpty()) return
        val part = intent.getIntExtra(EXTRA_PART, -1)
        val ok = resultCode == android.app.Activity.RESULT_OK
        val delivered = action == ACTION_SMS_DELIVERED
        val detail = if (ok) null else if (delivered) {
            "part $part not delivered ($resultCode)"
        } else {
            "part $part send failed ($resultCode)"
        }

        val settlement: JSONObject? = BridgeServiceBus.smsPartResult(id, part, ok, delivered, detail)
            ?: return
        BridgeServiceBus.publishOrQueue(context, settlement)
    }

    companion object {
        const val ACTION_SMS_SENT = "com.bridge.android.SMS_SENT"
        const val ACTION_SMS_DELIVERED = "com.bridge.android.SMS_DELIVERED"
        const val EXTRA_ID = "id"
        const val EXTRA_PART = "part"
    }
}
