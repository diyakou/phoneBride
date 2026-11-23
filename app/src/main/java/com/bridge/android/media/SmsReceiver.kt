package com.bridge.android.media

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.telephony.SubscriptionManager
import com.bridge.android.BridgeServiceBus
import org.json.JSONObject
import java.util.UUID

/**
 * Incoming SMS. Runs at priority 999 so it sees the message before the default
 * SMS app, and hands it straight to the service queue: if the service is not
 * running the event is persisted and replayed on the next authenticated session
 * instead of being dropped on the floor.
 */
class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val first = messages.first()
        val from = first.displayOriginatingAddress ?: first.originatingAddress ?: "?"
        val body = messages.joinToString(separator = "") { it.messageBody.orEmpty() }
        val subscriptionId = intent.getIntExtra(
            SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX,
            SubscriptionManager.INVALID_SUBSCRIPTION_ID,
        )
        val slot = if (subscriptionId != SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
            SubscriptionManager.getSlotIndex(subscriptionId)
        } else {
            -1
        }

        val event = JSONObject()
            .put("t", "sms")
            .put("id", UUID.randomUUID().toString())
            .put("from", from)
            .put("body", body)
            .put("ts", first.timestampMillis)
            .put("sim", slot)

        BridgeServiceBus.publishOrQueue(context, event)
    }
}
