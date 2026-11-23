package com.bridge.android

import org.json.JSONObject

object Protocol {
    fun commandResult(id: String, command: String, ok: Boolean, value: String, error: String? = null): JSONObject =
        JSONObject()
            .put("id", id)
            .put("command", "state")
            .put("payload", JSONObject().put("type", command).put("value", value).apply {
                if (error != null) put("error", error)
                put("ok", ok)
            })

    fun error(id: String, code: String, detail: String? = null): JSONObject =
        JSONObject().put("t", "error").put("id", id).put("err", code).apply {
            if (detail != null) put("detail", detail)
        }

    fun smsStatus(id: String, ok: Boolean, error: String? = null): JSONObject =
        JSONObject().put("t", "sms_status").put("id", id).put("ok", ok).apply {
            if (error != null) put("err", error)
        }

    fun incomingSms(id: String, from: String, body: String, timestamp: Long, sim: Int): JSONObject =
        JSONObject()
            .put("t", "sms")
            .put("id", id)
            .put("from", from)
            .put("body", body)
            .put("ts", timestamp)
            .put("sim", sim)

    fun callState(id: String, state: String): JSONObject =
        JSONObject().put("t", "call_state").put("id", id).put("s", state)
}
