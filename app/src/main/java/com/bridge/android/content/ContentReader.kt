package com.bridge.android.content

import android.Manifest
import android.annotation.SuppressLint
import android.content.ContentUris
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.CallLog
import android.provider.ContactsContract
import android.provider.Telephony
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Read-only snapshot provider for call log, SMS history and contacts.
 *
 * Everything here is paginated and bounded: a peer cannot ask for "everything"
 * in one shot and stall the phone. Each record is emitted as its own JSON
 * message so the transport never has to fragment an unbounded blob.
 */
class ContentReader(private val context: Context) {

    fun canRead(permission: String): Boolean =
        context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    // ------------------------------------------------------------------ call log

    /**
     * Streams the call log newest-first. [emit] returns false to stop early,
     * which is what the caller does when the transport goes away mid-drain.
     */
    fun readCallLog(sinceMillis: Long, limit: Int, emit: (JSONObject) -> Boolean): Int {
        if (!canRead(Manifest.permission.READ_CALL_LOG)) return -1
        val projection = arrayOf(
            CallLog.Calls._ID,
            CallLog.Calls.NUMBER,
            CallLog.Calls.CACHED_NAME,
            CallLog.Calls.TYPE,
            CallLog.Calls.DATE,
            CallLog.Calls.DURATION,
        )
        var count = 0
        context.contentResolver.query(
            CallLog.Calls.CONTENT_URI,
            projection,
            "${CallLog.Calls.DATE} > ?",
            arrayOf(sinceMillis.toString()),
            "${CallLog.Calls.DATE} DESC",
        )?.use { cursor ->
            while (cursor.moveToNext() && count < limit) {
                val record = JSONObject()
                    .put("t", "call_log")
                    .put("id", cursor.getLong(0))
                    .put("num", cursor.getString(1).orEmpty())
                    .put("name", cursor.getString(2).orEmpty())
                    .put("dir", direction(cursor.getInt(3)))
                    .put("ts", cursor.getLong(4))
                    .put("dur", cursor.getLong(5))
                if (!emit(record)) return count
                count++
            }
        }
        return count
    }

    private fun direction(type: Int): String = when (type) {
        CallLog.Calls.INCOMING_TYPE -> "in"
        CallLog.Calls.OUTGOING_TYPE -> "out"
        CallLog.Calls.MISSED_TYPE -> "missed"
        CallLog.Calls.REJECTED_TYPE -> "rejected"
        CallLog.Calls.BLOCKED_TYPE -> "blocked"
        CallLog.Calls.VOICEMAIL_TYPE -> "voicemail"
        else -> "other"
    }

    // ------------------------------------------------------------------ sms

    fun readSms(sinceMillis: Long, limit: Int, emit: (JSONObject) -> Boolean): Int {
        if (!canRead(Manifest.permission.READ_SMS)) return -1
        val projection = arrayOf(
            Telephony.Sms._ID,
            Telephony.Sms.ADDRESS,
            Telephony.Sms.BODY,
            Telephony.Sms.DATE,
            Telephony.Sms.TYPE,
            Telephony.Sms.SUBSCRIPTION_ID,
        )
        var count = 0
        context.contentResolver.query(
            Telephony.Sms.CONTENT_URI,
            projection,
            "${Telephony.Sms.DATE} > ?",
            arrayOf(sinceMillis.toString()),
            "${Telephony.Sms.DATE} DESC",
        )?.use { cursor ->
            while (cursor.moveToNext() && count < limit) {
                val record = JSONObject()
                    .put("t", "sms_log")
                    .put("id", cursor.getLong(0))
                    .put("from", cursor.getString(1).orEmpty())
                    .put("body", cursor.getString(2).orEmpty())
                    .put("ts", cursor.getLong(3))
                    .put("dir", if (cursor.getInt(4) == Telephony.Sms.MESSAGE_TYPE_INBOX) "in" else "out")
                    .put("sim", cursor.getInt(5))
                if (!emit(record)) return count
                count++
            }
        }
        return count
    }

    // ------------------------------------------------------------------ contacts

    fun readContacts(limit: Int, includePhotos: Boolean, emit: (JSONObject) -> Boolean): Int {
        if (!canRead(Manifest.permission.READ_CONTACTS)) return -1
        val projection = arrayOf(
            ContactsContract.CommonDataKinds.Phone.CONTACT_ID,
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
            ContactsContract.CommonDataKinds.Phone.NUMBER,
            ContactsContract.CommonDataKinds.Phone.TYPE,
            ContactsContract.CommonDataKinds.Phone.LABEL,
            ContactsContract.CommonDataKinds.Phone.PHOTO_ID,
        )
        // Group by contact so one person with four numbers is one message.
        val grouped = LinkedHashMap<Long, JSONObject>()
        context.contentResolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            projection,
            null,
            null,
            "${ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME} COLLATE NOCASE ASC",
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val contactId = cursor.getLong(0)
                if (contactId !in grouped && grouped.size >= limit) break
                val entry = grouped.getOrPut(contactId) {
                    JSONObject()
                        .put("t", "contact")
                        .put("id", contactId.toString())
                        .put("n", cursor.getString(1).orEmpty())
                        .put("p", JSONArray())
                }
                entry.getJSONArray("p").put(
                    JSONArray()
                        .put(cursor.getString(2).orEmpty())
                        .put(labelOf(cursor.getInt(3), cursor.getString(4)))
                )
                if (includePhotos && cursor.getLong(5) != 0L && !entry.has("ph")) {
                    photoHash(contactId)?.let { entry.put("ph", it) }
                }
            }
        }
        var sent = 0
        for (entry in grouped.values) {
            if (!emit(entry)) return sent
            sent++
        }
        return sent
    }

    private fun labelOf(type: Int, label: String?): String = when (type) {
        ContactsContract.CommonDataKinds.Phone.TYPE_MOBILE -> "mobile"
        ContactsContract.CommonDataKinds.Phone.TYPE_HOME -> "home"
        ContactsContract.CommonDataKinds.Phone.TYPE_WORK -> "work"
        ContactsContract.CommonDataKinds.Phone.TYPE_MAIN -> "main"
        ContactsContract.CommonDataKinds.Phone.TYPE_FAX_WORK -> "fax"
        else -> label?.takeIf { it.isNotBlank() } ?: "other"
    }

    /** Returns a content hash of the contact photo, not the bytes themselves. */
    private fun photoHash(contactId: Long): String? = runCatching {
        val uri = ContentUris.withAppendedId(ContactsContract.Contacts.CONTENT_URI, contactId)
        ContactsContract.Contacts.openContactPhotoInputStream(context.contentResolver, uri, true)
            ?.use { stream ->
                Base64.encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(stream.readBytes()),
                    Base64.NO_WRAP or Base64.URL_SAFE,
                )
            }
    }.getOrNull()

    /** Full photo bytes, only when the peer asks for a hash it already knows. */
    fun contactPhoto(contactId: Long): ByteArray? = runCatching {
        val uri = ContentUris.withAppendedId(ContactsContract.Contacts.CONTENT_URI, contactId)
        ContactsContract.Contacts.openContactPhotoInputStream(context.contentResolver, uri, true)
            ?.use { it.readBytes() }
    }.getOrNull()

    // ------------------------------------------------------------------ phone state

    fun deviceSnapshot(): JSONObject = JSONObject()
        .put("t", "device")
        .put("model", "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
        .put("os", "Android ${android.os.Build.VERSION.RELEASE}")
        .put("sdk", android.os.Build.VERSION.SDK_INT)
        .put("sims", simSnapshot())

    private fun simSnapshot(): JSONArray {
        val out = JSONArray()
        if (!canRead(Manifest.permission.READ_PHONE_STATE)) return out
        runCatching {
            val manager = context.getSystemService(android.telephony.SubscriptionManager::class.java)
            @SuppressLint("MissingPermission")
            manager?.activeSubscriptionInfoList?.forEach { info ->
                out.put(
                    JSONObject()
                        .put("slot", info.simSlotIndex)
                        .put("carrier", info.carrierName?.toString().orEmpty())
                        .put("country", info.countryIso.orEmpty())
                )
            }
        }
        return out
    }

    fun uriForSms(id: Long): Uri = ContentUris.withAppendedId(Telephony.Sms.CONTENT_URI, id)
}
