package com.bridge.android.content

import android.Manifest
import android.content.ContentUris
import android.content.Context
import android.content.pm.PackageManager
import android.provider.MediaStore
import android.util.Base64
import org.json.JSONObject
import java.io.InputStream
import java.security.MessageDigest

/**
 * Bounded media access for the gallery and Downloads folders.
 *
 * Nothing is ever pushed unsolicited. A peer must send `photos_req` with the
 * hashes it already knows about (obtained from `photos_offer`), and only those
 * exact items are streamed back. Each file is read through a descriptor and
 * hashed on the fly, so a large video never lands fully in memory.
 */
class MediaReader(private val context: Context) {

    fun canReadImages(): Boolean = when {
        android.os.Build.VERSION.SDK_INT >= 34 ->
            granted(Manifest.permission.READ_MEDIA_IMAGES) ||
                granted(Manifest.permission.READ_MEDIA_VISUAL_USER_SELECTED)
        android.os.Build.VERSION.SDK_INT >= 33 -> granted(Manifest.permission.READ_MEDIA_IMAGES)
        else -> granted(Manifest.permission.READ_EXTERNAL_STORAGE)
    }

    fun canReadVideo(): Boolean = when {
        android.os.Build.VERSION.SDK_INT >= 33 -> granted(Manifest.permission.READ_MEDIA_VIDEO)
        else -> granted(Manifest.permission.READ_EXTERNAL_STORAGE)
    }

    /**
     * Emits metadata + a content hash for each media item. The peer uses these
     * hashes to request specific files, so no image bytes move until asked.
     */
    fun offerMedia(kind: String, limit: Int, emit: (JSONObject) -> Boolean): Int {
        val uri = when (kind) {
            "video" -> {
                if (!canReadVideo()) return -1
                MediaStore.Video.Media.EXTERNAL_CONTENT_URI
            }
            "image" -> {
                if (!canReadImages()) return -1
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI
            }
            "download" -> MediaStore.Downloads.EXTERNAL_CONTENT_URI
            else -> return -2
        }
        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.MediaColumns.MIME_TYPE,
            MediaStore.MediaColumns.SIZE,
            MediaStore.MediaColumns.DATE_MODIFIED,
        )
        var count = 0
        context.contentResolver.query(uri, projection, null, null, "${MediaStore.MediaColumns.DATE_MODIFIED} DESC")
            ?.use { cursor ->
                while (cursor.moveToNext() && count < limit) {
                    val id = cursor.getLong(0)
                    val itemUri = ContentUris.withAppendedId(uri, id)
                    val hash = hashOf(itemUri) ?: continue
                    val record = JSONObject()
                        .put("t", "media_offer")
                        .put("k", kind)
                        .put("id", id)
                        .put("n", cursor.getString(1).orEmpty())
                        .put("m", cursor.getString(2).orEmpty())
                        .put("s", cursor.getLong(3))
                        .put("ts", cursor.getLong(4) * 1000)
                        .put("h", hash)
                    if (!emit(record)) return count
                    count++
                }
            }
        return count
    }

    /** Streams one requested item in [CHUNK] slices. */
    fun streamMedia(
        kind: String,
        id: Long,
        onChunk: (index: Int, total: Int, data: ByteArray) -> Unit,
    ): Long {
        val base = when (kind) {
            "video" -> MediaStore.Video.Media.EXTERNAL_CONTENT_URI
            "image" -> MediaStore.Images.Media.EXTERNAL_CONTENT_URI
            "download" -> MediaStore.Downloads.EXTERNAL_CONTENT_URI
            else -> return -1
        }
        val uri = ContentUris.withAppendedId(base, id)
        val size = runCatching {
            context.contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length }
        }.getOrNull() ?: -1L
        if (size <= 0) return -1
        val total = ((size + CHUNK - 1) / CHUNK).toInt()
        if (total > MAX_CHUNKS) return -1

        runCatching {
            context.contentResolver.openInputStream(uri)?.use { input ->
                var index = 0
                val buffer = ByteArray(CHUNK)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    onChunk(index++, total, buffer.copyOf(read))
                }
            }
        }.getOrNull() ?: return -1
        return size
    }

    private fun hashOf(uri: android.net.Uri): String? = runCatching {
        context.contentResolver.openInputStream(uri)?.use { input -> hashStream(input) }
    }.getOrNull()

    private fun hashStream(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
        return Base64.encodeToString(digest.digest(), Base64.NO_WRAP or Base64.URL_SAFE)
    }

    private fun granted(permission: String) =
        context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    companion object {
        const val CHUNK = 24 * 1024
        const val MAX_CHUNKS = 8192 // 192 MB ceiling per file
    }
}
