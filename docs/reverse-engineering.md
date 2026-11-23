# iTell APK reverse-engineering report

Input: `itell-1.4-47.apk`

## APK facts

- Package: `com.itellapp.android`
- Version: `1.4` (`versionCode` `47`)
- Min SDK: `31` (Android 12)
- Target SDK: `36`
- Native libraries:
  - `lib/arm64-v8a/libitellpcm.so`
  - `lib/armeabi-v7a/libitellpcm.so`

## Android components

- `com.itellapp.android.MainActivity`
- `com.itellapp.android.BridgeService`
- `com.itellapp.android.call.CompanionCalls`
  - exported `InCallService`
- `com.itellapp.android.adb.GuidePip`
- `com.itellapp.android.adb.SetupGuide$Receiver`
- `com.itellapp.android.adb.UsbSetup$Receiver`
- `com.itellapp.android.shell.ShellBinderProvider`
- `com.itellapp.android.BootReceiver`
- `com.itellapp.android.ui.TestCallPip`

## Bridge layers

```text
iPhone companion
      |
      | BLE GATT: discovery, pairing, control, key exchange
      |
Note20 BridgeService
      |
      +-- local Wi-Fi socket path: voice/data after pairing
      +-- Android Telecom / InCallService: call state and controls
      +-- SmsManager / SMS_RECEIVED: SMS relay
      +-- shell or native audio path: cellular call audio
```

Observed BLE UUIDs:

- `7e1a0001-5b8f-4c2a-9d3e-2f6a1b0c9d01`
- `7e1a0002-5b8f-4c2a-9d3e-2f6a1b0c9d01`
- `7e1a0003-5b8f-4c2a-9d3e-2f6a1b0c9d01`
- `7e1a0f01-0000-4000-8000-00000000f00d`
- CCCD: `00002902-0000-1000-8000-00805f9b34fb`

String evidence shows encrypted link setup using challenge/key-pair material. Exact message framing is not recoverable from strings alone.

## Call path

Call control uses public Android Telecom APIs:

- `android.telecom.InCallService`
- `android.telecom.Call`
- `TelecomManager`
- `TelephonyManager`
- `SubscriptionManager`
- `PhoneAccountHandle`
- `CALL_PHONE`
- `ANSWER_PHONE_CALLS`

Audio is not generic Bluetooth audio. APK probes device-specific paths:

- `AUDIO_DEVICE_IN_TELEPHONY_RX`
- `AUDIO_DEVICE_OUT_TELEPHONY_TX`
- `VOICE_UPLINK`
- `VOICE_DOWNLINK`
- `VOICE_TX`
- `AUDIO_OUTPUT_FLAG_INCALL_MUSIC`
- `AudioRecord`
- `AudioTrack`
- `AudioSystem.setParameters`
- `/dev/snd/*`
- `/proc/asound/*`

Native library references Qualcomm, MediaTek, VoLTE, VoWiFi, `VOICE_TX`, and `Incall_Music` paths. This confirms device and firmware-specific audio handling.

Likely fallback order:

1. Public Android audio APIs.
2. Vendor telephony routing.
3. Wireless ADB or root helper.
4. Native ALSA/mixer access.
5. Call-forwarding or loudspeaker fallback.

## SMS path

Observed APIs and symbols:

- `SmsManager`
- `sendMultipartTextMessage`
- `Telephony.Sms`
- `Telephony.Sms.Intents`
- `SMS_RECEIVED`
- `RECEIVE_SMS`
- `READ_SMS`
- `SEND_SMS`
- `com.itellapp.android.SMS_SENT`

Likely behavior:

- Android receives SMS from Note20 SIM.
- Bridge sends SMS payload to iPhone.
- iPhone sends outgoing SMS request to Android.
- Android calls `SmsManager` using Note20 SIM subscription.
- Payload is chunked; strings mention six chunks and `pending-sms.json` retry state.

## Wireless ADB

APK contains references to:

- `_adb-tls-connect._tcp`
- `_adb-tls-pairing._tcp`
- `adb pairing_auth aes-128-gcm key`
- `/data/local/tmp/`
- `itell_shell`
- `itell_voice`

Wireless Debugging appears used for privileged audio experiments and shell helpers. It is not required for normal Android call-control APIs. Prototype must never expose ADB to iPhone or network clients.

## Backend conflict

APK contains `https://api.itellapp.com` authentication, device activation, certification, challenge, refresh, logs, and ticket endpoints. Therefore reference APK is not proof of a no-backend design.

A no-backend clone can reuse only local transport concepts. It cannot reuse cloud licensing or authentication behavior.

## What APK alone cannot reveal

- iPhone implementation.
- Exact BLE message schema.
- Exact encryption framing and key derivation.
- Local Wi-Fi port and packet format.
- Samsung audio mixer values for this Note20 variant.
- Whether iTell's server is required for pairing or activation.

## Java/Androguard results

Tools installed and used:

- Java 17: `C:\Program Files\Eclipse Adoptium\jdk-17.0.21.10002-hotspot`
- JADX 1.5.7
- Local Androguard 4.1.4

Commands:

```powershell
python reverse_apk.py itell-1.4-47.apk --out reverse-report.json
$jar = (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Skylot.jadx_Microsoft.Winget.Source_8wekyb3d8bbwe\lib\jadx-gui-1.5.7-all.jar").FullName
& 'C:\Program Files\Eclipse Adoptium\jdk-17.0.21.10002-hotspot\bin\java.exe' -cp $jar jadx.cli.JadxCLI -d reverse-jadx --decompilation-mode simple --show-bad-code itell-1.4-47.apk
```

Generated:

- `reverse-report.json`
- `reverse-jadx/`

Confirmed message types:

- Pairing: `hello`, `hello_ok`, `hello_err`, `pair`, `pair_ok`, `pair_err`
- Device: `device`, `service`, `genuine`, `unpaired`, `restart`, `pong`
- Calls: `ring`, `call_state`, `connected`, `answered`, `answer_unknown`, `end`, `call_failed`, `audio_unavailable`, `status`
- SMS: `sms`, `send_sms`, `sms_status`, `smslog_changed`
- Data: `frag`, `ft_offer`, `ft_where`, `x`, `xb`

Confirmed incoming SMS payload:

```json
{"t":"sms","id":"...","from":"...","body":"...","ts":0,"sim":0}
```

Confirmed outgoing SMS request fields:

```json
{"t":"send_sms","id":"...","to":"...","body":"...","sim":0}
```

`sim` is treated as SIM slot index. Android resolves slot index to active subscription ID, then calls `SmsManager.createForSubscriptionId(...).sendMultipartTextMessage(...)`. Delivery result returns as `sms_status`.

Confirmed fragmentation fields:

```json
{"t":"frag","k":"...","i":0,"n":2,"d":"..."}
```

Bluetooth UUIDs are now confirmed in decompiled Java, not only string extraction. Exact GATT characteristic read/write mapping still needs runtime capture.

## Safe next reverse-engineering step

Use an authorized test pair and capture only metadata:

1. Install reference APK on Note20.
2. Record package version, permissions, and granted runtime permissions.
3. Pair reference iPhone companion.
4. Capture BLE GATT UUID, characteristic properties, packet lengths, and timing.
5. Do not save audio, SMS content, keys, tokens, or personal data.
6. Compare call and SMS state transitions against acceptance tests.

Do not enable ADB over a network interface for iPhone access. If Wireless Debugging is used, keep it Note20-local and document pairing, shell commands, granted privileges, and reboot behavior.
