package com.bridge.android.transport

import android.content.Context
import org.json.JSONObject
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong

/**
 * Offline queue for outbound messages.
 *
 * Events that arrive while no service instance is running (an SMS that lands
 * during a restart, a call state change during a crash) are buffered on disk
 * and replayed to the next peer that authenticates. Bounded so a hostile peer
 * that connects and never subscribes cannot fill storage: past the cap the
 * oldest messages are dropped.
 */
class MessageQueue(context: Context) {

    private val file = context.getFileStreamPath(FILE)
    private val entries = ConcurrentLinkedQueue<Entry>()
    private val loaded = AtomicLong(0)
    private val dropped = AtomicLong(0)

    data class Entry(val id: Long, val json: String)

    init {
        runCatching {
            if (file.exists()) {
                file.inputStream().bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        val sep = line.indexOf(' ')
                        if (sep > 0) {
                            val id = line.substring(0, sep).toLongOrNull() ?: return@forEach
                            entries.add(Entry(id, line.substring(sep + 1)))
                        }
                    }
                }
            }
        }
        loaded.set(nextId.get() - 1)
        var maxId = 0L
        entries.forEach { if (it.id > maxId) maxId = it.id }
        nextId.set(maxId + 1)
    }

    fun offer(message: JSONObject) {
        if (entries.size >= MAX_ENTRIES) {
            entries.poll()
            dropped.incrementAndGet()
        }
        val entry = Entry(nextId.getAndIncrement(), message.toString())
        entries.add(entry)
        persist()
    }

    /** Drains the queue. [sent] returns false to keep the entry for a retry. */
    fun drain(sent: (Entry) -> Boolean) {
        val iterator = entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (sent(entry)) {
                iterator.remove()
            } else {
                break
            }
        }
        persist()
    }

    fun size(): Int = entries.size

    fun stats(): Pair<Long, Long> = loaded.get() to dropped.get()

    @Synchronized
    private fun persist() {
        runCatching {
            file.outputStream().bufferedWriter().use { out ->
                entries.forEach { out.write("${it.id} ${it.json}\n") }
            }
        }
    }

    private companion object {
        const val FILE = "bridge_queue.txt"
        const val MAX_ENTRIES = 500
        val nextId = AtomicLong(1)
    }
}
