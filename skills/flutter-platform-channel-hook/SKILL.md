---
name: flutter-platform-channel-hook
description: Use when testing a Flutter app and you need to inspect data flowing between Dart and native code through platform channels (MethodChannel, EventChannel, BasicMessageChannel). Hook the bridge layer with Frida to see channel names, method calls, arguments, and return values crossing the Dart-native boundary. Triggers - "platform channel", "MethodChannel", "EventChannel", "BasicMessageChannel", "flutter native bridge", "flutter IPC", "handlePlatformMessage", "FlutterJNI"
platform: [android, ios]
stack: [flutter]
category: ipc
tier: B
related: [mob-flutter, flutter-aot-blutter-frida-hook]
---

# Skill: Flutter Platform Channel Hook: intercepting Dart-native data with Frida

## What it solves
Flutter apps delegate sensitive operations (biometrics, payments, keystore, device info) to
the native side via **platform channels**. The traffic crosses a binary bridge that does not
show up in HTTP proxies or in jadx's static analysis (you only see the shell). With Frida you
hook the bridge's entry/exit points to see **everything** Dart sends to native and
vice versa: channel names, invoked methods, arguments, and responses.

## When to use
- The Flutter app invokes native functionality (payments, biometrics, device-ID, crypto) and
  you need to see what data crosses the bridge.
- You want to enumerate all registered channels without static analysis of the AOT snapshot.
- You suspect sensitive data (tokens, PII, keys) passes through platform channels without
  additional protection.

## Workflow

### 1. Identify the entry vector (Android vs iOS)

**Android:** everything goes through `FlutterJNI.handlePlatformMessage` in the engine embedding.
The method receives: channel name (String), message (ByteBuffer, encoded), reply ID.

**iOS:** messages go through the `FlutterBinaryMessenger` protocol and
`FlutterMethodChannel invokeMethod:arguments:`. The concrete implementation is in
`FlutterEngine` and the channel registrations in `FlutterPluginAppLifeCycleDelegate`.

### 2. Understand the encoding

Messages are NOT plaintext. Flutter uses codecs:
- **StandardMethodCodec**: custom binary format (type-tag + serialized value). It is the
  default for `MethodChannel`. Types: null=0, true=1, false=2, int32=3, int64=4,
  float64=6, String=7, Uint8List=8, Int32List=9, Map=13, List=12.
- **JSONMethodCodec**: JSON string encoded as UTF-8 bytes.
- **StringCodec** / **BinaryCodec**: for `BasicMessageChannel`.

To see readable data, hook the **codec** level (decodeMethodCall / encodeSuccessEnvelope)
or read the payload after the codec processes it.

### 3. Android hook: FlutterJNI.handlePlatformMessage

```js
// frida -U -f com.target.app -l platform_channel_hook.js --no-pause
Java.perform(function() {
    var FlutterJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");

    FlutterJNI.handlePlatformMessage.overload(
        "java.lang.String",       // channel
        "java.nio.ByteBuffer",    // message
        "int",                    // replyId
        "long"                    // messageData
    ).implementation = function(channel, message, replyId, messageData) {
        console.log("[PlatformChannel] channel: " + channel);

        if (message !== null) {
            // Read raw bytes from the ByteBuffer
            var pos = message.position();
            var limit = message.limit();
            var size = limit - pos;
            var buf = Java.array('byte', new Array(size));
            // Duplicate so the original buffer is not consumed
            var dup = message.duplicate();
            dup.get(buf);

            // Try to decode as UTF-8 (works for JSONMethodCodec)
            try {
                var str = "";
                for (var i = 0; i < Math.min(size, 4096); i++) {
                    var b = buf[i] & 0xff;
                    if (b >= 0x20 && b < 0x7f) str += String.fromCharCode(b);
                    else str += ".";
                }
                console.log("[PlatformChannel]   size=" + size + " ascii: " + str);
            } catch(e) {}

            // For StandardMethodCodec: first byte is the method-name type tag
            if (size > 0) {
                var firstByte = buf[0] & 0xff;
                if (firstByte === 7) {
                    // Type tag 7 = String (method name in StandardMethodCodec)
                    var methodLen = 0;
                    if (size > 1) {
                        methodLen = buf[1] & 0xff;
                        if (methodLen < 254 && size >= 2 + methodLen) {
                            var methodName = "";
                            for (var j = 0; j < methodLen; j++) {
                                methodName += String.fromCharCode(buf[2+j] & 0xff);
                            }
                            console.log("[PlatformChannel]   method: " + methodName);
                        }
                    }
                }
            }
        }

        return this.handlePlatformMessage(channel, message, replyId, messageData);
    };

    console.log("[*] Platform channel hook installed");
});
```

### 4. Android hook: StandardMethodCodec.decodeMethodCall (high level)

```js
Java.perform(function() {
    var StandardMethodCodec = Java.use(
        "io.flutter.plugin.common.StandardMethodCodec"
    );
    var MethodCall = Java.use("io.flutter.plugin.common.MethodCall");

    StandardMethodCodec.decodeMethodCall.implementation = function(message) {
        var call = this.decodeMethodCall(message);
        console.log("[MethodCall] method=" + call.method.value +
                    " args=" + JSON.stringify(call.arguments.value));
        return call;
    };

    StandardMethodCodec.encodeSuccessEnvelope.implementation = function(result) {
        console.log("[MethodResult] success=" + JSON.stringify(result));
        return this.encodeSuccessEnvelope(result);
    };
});
```

### 5. iOS hook: FlutterMethodChannel

```js
// frida -U -f com.target.app -l platform_channel_ios.js --no-pause
var FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;

Interceptor.attach(
    FlutterMethodChannel["- invokeMethod:arguments:"].implementation, {
    onEnter: function(args) {
        var method = ObjC.Object(args[2]).toString();
        var arguments = ObjC.Object(args[3]);
        console.log("[FlutterChannel] invokeMethod: " + method);
        console.log("[FlutterChannel]   arguments: " + arguments.toString());
    }
});

// Hook the messenger to see ALL channels
var engine = ObjC.classes.FlutterEngine;
Interceptor.attach(
    engine["- sendOnChannel:message:"].implementation, {
    onEnter: function(args) {
        var channel = ObjC.Object(args[2]).toString();
        console.log("[FlutterBinaryMessenger] channel: " + channel);
    }
});
```

### 6. What to look for in the output

- **Sensitive channels**: names containing `payment`, `auth`, `biometric`,
  `keystore`, `crypto`, `secure`, `pin`, `otp`, `token`.
- **Sensitive data in arguments**: authentication tokens, user IDs, encryption
  keys, PII (email, phone, name), GPS coordinates.
- **Missing validation**: data going from the native side to Dart without verification
  (native responds with a status and Dart accepts it without signing it).
- **Undocumented custom channels**: proprietary channels exposing internal
  functionality (e.g.: `com.app.internal/debug`, `com.app/admin`).

## What the finding confirms
- The Frida log shows sensitive data (tokens, PII, keys) crossing a platform
  channel in the target.
- A channel exposes privileged functionality invocable without additional authentication.
- Native-side arguments are accepted without validation in Dart (e.g.: an
  `isAuthenticated` boolean that Dart trusts blindly).

## Limitations
- The `handlePlatformMessage` hook captures ALL channel traffic: it can get
  noisy. Filter by channel name.
- `StandardMethodCodec` uses a binary format: the snippet above decodes the
  method name but complex arguments (nested Maps, Lists) require full parsing
  of the wire format.
- On iOS, class names and selectors can change between engine versions.
  Verify with `frida-trace -m "*Flutter*"` first.
- In apps with multiple Flutter engines (add-to-app), there are multiple
  `FlutterJNI` instances: hook them all.
