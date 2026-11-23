package com.bridge.android.media

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.os.Build
import android.os.Process
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Call audio capture and injection.
 *
 * Downlink (what the remote party says) is captured with the hidden
 * AudioManager#getCallDownlinkExtractionAudioRecord on Android 13+, falling back
 * to AudioSource.VOICE_DOWNLINK. Uplink injection uses
 * AudioManager#getCallUplinkInjectionAudioTrack, which requires the app to hold
 * CAPTURE_AUDIO_OUTPUT or to be the privileged in-call app.
 *
 * Everything is opt-in per call, gated on RECORD_AUDIO, and reports a clear
 * capability result so the companion can grey out the feature instead of
 * silently producing silence.
 */
class AudioBridge(private val context: Context) {

    private val capturing = AtomicBoolean(false)
    private val injectedSamples = AtomicLong(0)
    @Volatile
    private var captureThread: Thread? = null
    @Volatile
    private var record: AudioRecord? = null
    @Volatile
    private var track: AudioTrack? = null

    fun probe(): JSONObject {
        val result = JSONObject().put("t", "audio_probe").put("api", Build.VERSION.SDK_INT)
        if (context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            return result.put("ok", false).put("err", "RECORD_AUDIO permission missing")
        }
        result.put("downlink", probeDownlink())
        result.put("uplink", probeUplink())
        result.put("ok", result.optJSONObject("downlink")?.optBoolean("ok") == true)
        return result
    }

    private fun probeDownlink(): JSONObject {
        val hidden = if (Build.VERSION.SDK_INT >= 33) {
            runCatching {
                val method = AudioManager::class.java.getMethod(
                    "getCallDownlinkExtractionAudioRecord",
                    AudioFormat::class.java,
                )
                method.invoke(context.getSystemService(AudioManager::class.java), format()) as AudioRecord
            }.getOrNull()
        } else {
            null
        }
        if (hidden != null) {
            val initialized = hidden.state == AudioRecord.STATE_INITIALIZED
            hidden.release()
            if (initialized) return JSONObject().put("ok", true).put("path", "call_downlink_extraction")
        }
        return runCatching {
            @SuppressLint("MissingPermission")
            val record = AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.VOICE_DOWNLINK)
                .setAudioFormat(format())
                .setBufferSizeInBytes(bufferBytes())
                .build()
            val initialized = record.state == AudioRecord.STATE_INITIALIZED
            record.release()
            JSONObject().put("ok", initialized).put("path", "voice_downlink")
        }.getOrElse {
            JSONObject().put("ok", false).put("err", it.message ?: it.javaClass.simpleName)
        }
    }

    private fun probeUplink(): JSONObject {
        if (Build.VERSION.SDK_INT < 33) {
            return JSONObject().put("ok", false).put("err", "needs Android 13+")
        }
        return runCatching {
            val method = AudioManager::class.java.getMethod(
                "getCallUplinkInjectionAudioTrack",
                AudioFormat::class.java,
            )
            val track = method.invoke(context.getSystemService(AudioManager::class.java), format()) as AudioTrack
            val initialized = track.state == AudioTrack.STATE_INITIALIZED
            track.release()
            JSONObject().put("ok", initialized).put("path", "call_uplink_injection")
        }.getOrElse {
            JSONObject().put("ok", false).put("err", it.message ?: it.javaClass.simpleName)
        }
    }

    // ------------------------------------------------------------------ capture

    /** Starts the downlink capture loop. Returns null on success, else the reason. */
    fun startCapture(onFrame: (ByteArray) -> Unit): String? {
        if (context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            return "RECORD_AUDIO permission missing"
        }
        if (!capturing.compareAndSet(false, true)) return "capture already running"

        val built = openDownlink()
        if (built == null) {
            capturing.set(false)
            return "no_downlink_source"
        }
        record = built

        captureThread = Thread({
            Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO)
            val buffer = ByteArray(FRAME_BYTES)
            runCatching { built.startRecording() }
            while (capturing.get()) {
                val read = runCatching { built.read(buffer, 0, buffer.size) }.getOrDefault(-1)
                if (read <= 0) {
                    if (read < 0) break else continue
                }
                onFrame(buffer.copyOf(read))
            }
            runCatching { built.stop() }
            runCatching { built.release() }
            record = null
        }, "bridge-capture").apply {
            isDaemon = true
            start()
        }
        return null
    }

    fun stopCapture() {
        capturing.set(false)
        captureThread?.let { runCatching { it.join(500) } }
        captureThread = null
        runCatching { record?.release() }
        record = null
    }

    private fun openDownlink(): AudioRecord? {
        if (context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            return null
        }
        if (Build.VERSION.SDK_INT >= 33) {
            runCatching {
                val method = AudioManager::class.java.getMethod(
                    "getCallDownlinkExtractionAudioRecord",
                    AudioFormat::class.java,
                )
                val hidden = method.invoke(context.getSystemService(AudioManager::class.java), format()) as AudioRecord
                if (hidden.state == AudioRecord.STATE_INITIALIZED) return hidden
                hidden.release()
            }
        }
        return runCatching {
            @SuppressLint("MissingPermission")
            AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.VOICE_DOWNLINK)
                .setAudioFormat(format())
                .setBufferSizeInBytes(bufferBytes())
                .build()
                .takeIf { it.state == AudioRecord.STATE_INITIALIZED }
        }.getOrNull()
    }

    // ------------------------------------------------------------------ injection

    /** Opens the uplink track. Returns null on success, else the reason. */
    fun openUplink(): String? {
        if (Build.VERSION.SDK_INT < 33) return "needs Android 13+"
        val built = runCatching {
            val method = AudioManager::class.java.getMethod(
                "getCallUplinkInjectionAudioTrack",
                AudioFormat::class.java,
            )
            method.invoke(context.getSystemService(AudioManager::class.java), format()) as AudioTrack
        }.getOrNull() ?: return "uplink_track_unavailable"
        if (built.state != AudioTrack.STATE_INITIALIZED) {
            built.release()
            return "uplink_track_not_initialized"
        }
        track = built
        runCatching { built.play() }
        return null
    }

    /** Writes PCM16 mono into the call uplink. Returns bytes accepted. */
    fun inject(pcm: ByteArray): Int {
        val target = track ?: return -1
        val written = runCatching { target.write(pcm, 0, pcm.size) }.getOrDefault(-1)
        if (written > 0) injectedSamples.addAndGet(written.toLong())
        return written
    }

    /** Plays a short dual-tone DTMF burst into the uplink. */
    fun injectDtmf(lowHz: Int, highHz: Int, durationMs: Int = 120): Int {
        val samples = (SAMPLE_RATE * durationMs) / 1000
        val pcm = ByteArray(samples * 2)
        for (i in 0 until samples) {
            val t = i.toDouble() / SAMPLE_RATE
            val envelope = minOf(1.0, minOf(i / 80.0, (samples - i) / 80.0))
            val value = ((kotlin.math.sin(2 * Math.PI * lowHz * t) * 0.25 +
                kotlin.math.sin(2 * Math.PI * highHz * t) * 0.25) * envelope * 32767).toInt()
            pcm[i * 2] = (value and 0xFF).toByte()
            pcm[i * 2 + 1] = ((value shr 8) and 0xFF).toByte()
        }
        return inject(pcm)
    }

    fun closeUplink() {
        runCatching { track?.stop() }
        runCatching { track?.release() }
        track = null
    }

    fun stats(): JSONObject = JSONObject()
        .put("capturing", capturing.get())
        .put("injected_bytes", injectedSamples.get())

    private fun format() = AudioFormat.Builder()
        .setSampleRate(SAMPLE_RATE)
        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
        .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
        .build()

    private fun bufferBytes(): Int = maxOf(
        AudioRecord.getMinBufferSize(SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT),
        FRAME_BYTES * 4,
    )

    companion object {
        const val SAMPLE_RATE = 16000
        const val FRAME_BYTES = 640 // 20 ms of PCM16 mono at 16 kHz
        val DTMF: Map<Char, Pair<Int, Int>> = mapOf(
            '1' to (697 to 1209), '2' to (697 to 1336), '3' to (697 to 1477),
            '4' to (770 to 1209), '5' to (770 to 1336), '6' to (770 to 1477),
            '7' to (852 to 1209), '8' to (852 to 1336), '9' to (852 to 1477),
            '*' to (941 to 1209), '0' to (941 to 1336), '#' to (941 to 1477),
        )
    }
}
