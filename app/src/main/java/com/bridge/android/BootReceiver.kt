package com.bridge.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Restarts the bridge after a reboot so an incoming SMS or call still reaches
 * the paired companion without the user opening the app first.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        BridgeServiceBus.ensureRunning(context)
    }
}
