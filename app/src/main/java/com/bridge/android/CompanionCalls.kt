package com.bridge.android

import android.telecom.Call
import android.telecom.InCallService

/**
 * Passive in-call observer. It never claims to be a dialer (no UI flag), so
 * it does not fight the real phone app; it exists purely so the bridge sees
 * ringing/active/disconnected transitions for calls it did not originate.
 */
class CompanionCalls : InCallService() {
    override fun onCallAdded(call: Call) {
        super.onCallAdded(call)
        BridgeService.callAdded(this, call)
    }

    override fun onCallRemoved(call: Call) {
        BridgeService.callRemoved(call)
        super.onCallRemoved(call)
    }
}
