package com.bridge.android

import android.content.Context
import android.content.Intent
import com.bridge.android.transport.MessageQueue
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Process-wide bus between broadcast receivers and the running [BridgeService].
 *
 * A receiver fires even when the service is dead — an SMS can land during a
 * restart — so events are queued to disk instead of being dropped. The queue is
 * flushed the moment an authenticated peer appears.
 */
object BridgeServiceBus {

    internal val listeners = CopyOnWriteArraySet<(JSONObject) -> Unit>()

    private val service = AtomicReference<BridgeService?>(null)
    private val flushPending = AtomicBoolean(false)

    @Volatile
    internal var queue: MessageQueue? = null

    fun attach(instance: BridgeService?, messageQueue: MessageQueue?) {
        service.set(instance)
        if (messageQueue != null) queue = messageQueue
    }

    fun publish(message: JSONObject) {
        listeners.forEach { runCatching { it(message) } }
    }

    /** Hands the event to the service, or persists it when the service is down. */
    fun publishOrQueue(context: Context, message: JSONObject?) {
        if (message == null) return
        val running = service.get()
        if (running != null) {
            running.publish(message)
            return
        }
        queue?.offer(message)
        flushPending.set(true)
        ensureRunning(context)
    }

    fun confirmPairing(fingerprint: String): Boolean =
        service.get()?.bleConfirmPairing(fingerprint) == true

    fun smsPartResult(id: String, part: Int, ok: Boolean, delivered: Boolean, detail: String?): JSONObject? =
        service.get()?.smsResult(id, part, ok, delivered, detail)

    fun ensureRunning(context: Context) {
        if (service.get() != null) return
        runCatching { context.startForegroundService(Intent(context, BridgeService::class.java)) }
    }

    /** Called by the service once it is ready to replay buffered events. */
    internal fun consumeFlushRequest(): Boolean = flushPending.compareAndSet(true, false)
}
