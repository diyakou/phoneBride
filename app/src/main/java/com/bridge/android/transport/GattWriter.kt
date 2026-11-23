package com.bridge.android.transport

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Serialises every GATT notify onto a single worker thread and retries when the
 * Bluetooth stack answers BUSY.
 *
 * BluetoothGattServer.notifyCharacteristicChanged() is not safe to call from
 * concurrent binder threads; without this queue a burst of publishes plus a
 * callback-driven send corrupts stack state and the characteristic goes silent
 * until the server is reopened.
 *
 * Each queued item carries its target address, so a stale frame from a previous
 * peer can never be delivered to the current one.
 */
class GattWriter(
    private val dispatch: (address: String, frame: ByteArray) -> Int,
    private val onDropped: (String) -> Unit = {},
) {
    private class Item(val address: String, val frame: ByteArray)

    private val queue = ConcurrentLinkedQueue<Item>()
    private val scheduled: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "bridge-gatt-writer").apply { isDaemon = true }
    }
    private val pumping = AtomicBoolean(false)
    private val lastDrop = AtomicLong(0)

    fun enqueue(address: String, frame: ByteArray) {
        if (queue.size >= MAX_QUEUE) {
            val now = System.currentTimeMillis()
            if (now - lastDrop.get() > 1000) {
                lastDrop.set(now)
                onDropped("queue_full")
            }
            return
        }
        queue.add(Item(address, frame))
        pump()
    }

    private fun pump() {
        if (!pumping.compareAndSet(false, true)) return
        scheduled.execute {
            try {
                while (true) {
                    val item = queue.poll() ?: break
                    if (!writeWithRetry(item)) {
                        onDropped("write_failed")
                        break
                    }
                }
            } finally {
                pumping.set(false)
            }
        }
    }

    private fun writeWithRetry(item: Item): Boolean {
        repeat(MAX_RETRIES) { attempt ->
            val result = runCatching { dispatch(item.address, item.frame) }.getOrDefault(-1)
            if (result == GATT_SUCCESS) return true
            if (result != GATT_BUSY) return false
            runCatching { Thread.sleep(RETRY_BACKOFF_MS * (attempt + 1)) }
        }
        return false
    }

    fun shutdown() {
        queue.clear()
        scheduled.shutdownNow()
    }

    companion object {
        const val GATT_SUCCESS = 0x00
        const val GATT_BUSY = 0x85
        private const val MAX_QUEUE = 256
        private const val MAX_RETRIES = 3
        private const val RETRY_BACKOFF_MS = 20L
    }
}
