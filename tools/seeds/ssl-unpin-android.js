/**
 * ssl-unpin-android.js: Generic Android SSL Pinning Bypass
 * MOSRAI seed script
 *
 * Hooks:
 *   1. javax.net.ssl.X509TrustManager   : checkServerTrusted / checkClientTrusted return empty
 *   2. okhttp3.CertificatePinner        : check() becomes no-op
 *   3. javax.net.ssl.SSLContext          : init() with permissive TrustManager
 *   4. TrustManagerImpl (Conscrypt)      : verifyChain returns the unmodified chain
 *
 * Usage:
 *   frida -U -f <package> -l ssl-unpin-android.js --no-pause
 *
 * Known limitations:
 *   - Does NOT bypass Flutter/BoringSSL pinning (use ssl-unpin-flutter.js).
 *   - Custom native-layer pinning (NDK, Xamarin, React-Native TurboModules
 *     that call OpenSSL directly) is not covered.
 *   - Apps that load OkHttp via a different package name or obfuscate class
 *     names may need per-app adjustments.
 *   - Certificate Transparency checks are not intercepted.
 */

"use strict";

Java.perform(function () {
    var TAG = "[ssl-unpin-android]";

    // ---------------------------------------------------------------
    // Helper: build a TrustManager[] that trusts everything
    // ---------------------------------------------------------------
    var TrustManager = Java.registerClass({
        name: "com.mosrai.PermissiveTrustManager",
        implements: [Java.use("javax.net.ssl.X509TrustManager")],
        methods: {
            checkClientTrusted: function (chain, authType) { },
            checkServerTrusted: function (chain, authType) { },
            getAcceptedIssuers: function () {
                return [];
            }
        }
    });

    // ---------------------------------------------------------------
    // 1. X509TrustManager: patch every concrete implementation
    //    already loaded by the app at hook time
    // ---------------------------------------------------------------
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        // We cannot hook an interface directly, but we CAN ensure any
        // SSLContext.init call gets our permissive TM (see section 3).
        console.log(TAG + " X509TrustManager interface located.");
    } catch (e) {
        console.log(TAG + " [!] X509TrustManager not found (unexpected): " + e);
    }

    // ---------------------------------------------------------------
    // 2. OkHttp3 CertificatePinner.check (multiple overloads)
    // ---------------------------------------------------------------
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");

        // void check(String hostname, List<Certificate> peerCertificates)
        try {
            CertificatePinner.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function (hostname, peerCerts) {
                console.log(TAG + " OkHttp3 CertificatePinner.check(String,List) bypassed for: " + hostname);
            };
        } catch (_) { /* overload may not exist */ }

        // void check(String hostname, Certificate... peerCertificates)  (varargs = array)
        try {
            CertificatePinner.check.overload(
                "java.lang.String",
                "[Ljava.security.cert.Certificate;"
            ).implementation = function (hostname, peerCerts) {
                console.log(TAG + " OkHttp3 CertificatePinner.check(String,Certificate[]) bypassed for: " + hostname);
            };
        } catch (_) { /* overload may not exist */ }

        // OkHttp 3.x: Check check(String, kotlin.jvm.functions.Function0): lazy variant
        try {
            CertificatePinner.check$okhttp.overload(
                "java.lang.String",
                "kotlin.jvm.functions.Function0"
            ).implementation = function (hostname, fn) {
                console.log(TAG + " OkHttp3 CertificatePinner.check$okhttp bypassed for: " + hostname);
            };
        } catch (_) { /* overload may not exist */ }

        console.log(TAG + " okhttp3.CertificatePinner hooked.");
    } catch (e) {
        console.log(TAG + " [i] okhttp3.CertificatePinner not found (app may not use OkHttp): " + e.message);
    }

    // ---------------------------------------------------------------
    // 3. SSLContext.init: always inject our permissive TrustManager
    // ---------------------------------------------------------------
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (keyManagers, trustManagers, secureRandom) {
            console.log(TAG + " SSLContext.init intercepted: injecting permissive TrustManager.");
            this.init(keyManagers, [TrustManager.$new()], secureRandom);
        };
        console.log(TAG + " javax.net.ssl.SSLContext.init hooked.");
    } catch (e) {
        console.log(TAG + " [!] SSLContext.init hook failed: " + e);
    }

    // ---------------------------------------------------------------
    // 4. Conscrypt TrustManagerImpl.verifyChain
    // ---------------------------------------------------------------
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        // List<X509Certificate> verifyChain(...)
        TrustManagerImpl.verifyChain.implementation = function () {
            console.log(TAG + " Conscrypt TrustManagerImpl.verifyChain bypassed.");
            // Return the untrusted chain as-is (first argument)
            return arguments[0];
        };
        console.log(TAG + " com.android.org.conscrypt.TrustManagerImpl.verifyChain hooked.");
    } catch (e) {
        console.log(TAG + " [i] Conscrypt TrustManagerImpl not found: " + e.message);
    }

    // ---------------------------------------------------------------
    // 5. Network security config: TrustManagerImpl.checkTrustedRecursive
    //    (Android 7+ network_security_config pins)
    // ---------------------------------------------------------------
    try {
        var PlatformTM = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        PlatformTM.checkTrustedRecursive.implementation = function () {
            console.log(TAG + " TrustManagerImpl.checkTrustedRecursive bypassed.");
            // Return the chain (java.util.List<X509Certificate>) from arg[0]
            return arguments[0];
        };
        console.log(TAG + " checkTrustedRecursive hooked.");
    } catch (e) {
        // Not all Android versions have this method
        console.log(TAG + " [i] checkTrustedRecursive not available: " + e.message);
    }

    // ---------------------------------------------------------------
    // 6. HttpsURLConnection: setDefaultHostnameVerifier /
    //    setSSLSocketFactory are less common but cover legacy code
    // ---------------------------------------------------------------
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            console.log(TAG + " HttpsURLConnection.setDefaultHostnameVerifier intercepted: installing permissive verifier.");
            // Create a HostnameVerifier that always returns true
            var PermissiveVerifier = Java.registerClass({
                name: "com.mosrai.PermissiveHostnameVerifier",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function (hostname, session) {
                        return true;
                    }
                }
            });
            this.setDefaultHostnameVerifier(PermissiveVerifier.$new());
        };
        console.log(TAG + " javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier hooked.");
    } catch (e) {
        console.log(TAG + " [i] HttpsURLConnection hook skipped: " + e.message);
    }

    console.log(TAG + " --- SSL unpinning hooks installed ---");
});
