/**
 * ssl-unpin-ios.js: Generic iOS SSL Pinning Bypass
 * MOSRAI seed script
 *
 * Hooks:
 *   1. SecTrustEvaluate             : returns errSecSuccess (0)
 *   2. SecTrustEvaluateWithError    : returns true, clears error
 *   3. SSLSetSessionOption          : intercepts kSSLSessionOptionBreakOnServerAuth
 *   4. SSLCreateContext / SSLHandshake: ensures custom evaluation is disabled
 *   5. NSURLSession delegate        : completionHandler with UseCredential
 *   6. AFNetworking AFSecurityPolicy: allowInvalidCertificates=YES, validatesDomainName=NO
 *   7. TrustKit (if present)        : disables pin validation
 *
 * Usage:
 *   frida -U -f <bundle-id> -l ssl-unpin-ios.js --no-pause
 *
 * Known limitations:
 *   - Does NOT bypass Flutter/BoringSSL pinning (use ssl-unpin-flutter.js).
 *   - Apps using custom C-level OpenSSL or BoringSSL linked statically need
 *     per-binary pattern hooks.
 *   - Alamofire 5+ with custom ServerTrustEvaluating may need additional hooks
 *     if it does not delegate to SecTrust* functions.
 *   - WKWebView certificate validation happens in the WebContent XPC process;
 *     this script hooks the main app process only.
 */

"use strict";

var TAG = "[ssl-unpin-ios]";

// ===================================================================
// 1. SecTrustEvaluate: OSStatus SecTrustEvaluate(SecTrustRef, SecTrustResultType *)
// ===================================================================
try {
    var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onEnter: function (args) {
                this.resultPtr = args[1];
            },
            onLeave: function (retval) {
                // kSecTrustResultProceed = 1: the trust evaluation succeeded
                if (this.resultPtr && !this.resultPtr.isNull()) {
                    this.resultPtr.writeU32(1);
                }
                // errSecSuccess = 0
                retval.replace(0);
                console.log(TAG + " SecTrustEvaluate bypassed.");
            }
        });
        console.log(TAG + " SecTrustEvaluate hooked at " + SecTrustEvaluate);
    } else {
        console.log(TAG + " [i] SecTrustEvaluate symbol not found.");
    }
} catch (e) {
    console.log(TAG + " [!] SecTrustEvaluate hook failed: " + e);
}

// ===================================================================
// 2. SecTrustEvaluateWithError: bool SecTrustEvaluateWithError(SecTrustRef, CFErrorRef *)
//    Available iOS 12+
// ===================================================================
try {
    var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.attach(SecTrustEvaluateWithError, {
            onEnter: function (args) {
                this.errorPtr = args[1];
            },
            onLeave: function (retval) {
                // Clear any error
                if (this.errorPtr && !this.errorPtr.isNull()) {
                    this.errorPtr.writePointer(NULL);
                }
                // Return true (1) = trust evaluation passed
                retval.replace(1);
                console.log(TAG + " SecTrustEvaluateWithError bypassed.");
            }
        });
        console.log(TAG + " SecTrustEvaluateWithError hooked at " + SecTrustEvaluateWithError);
    } else {
        console.log(TAG + " [i] SecTrustEvaluateWithError not found (pre-iOS 12?).");
    }
} catch (e) {
    console.log(TAG + " [!] SecTrustEvaluateWithError hook failed: " + e);
}

// ===================================================================
// 3. SSLSetSessionOption: intercept kSSLSessionOptionBreakOnServerAuth
// ===================================================================
try {
    var SSLSetSessionOption = Module.findExportByName("Security", "SSLSetSessionOption");
    if (SSLSetSessionOption) {
        Interceptor.attach(SSLSetSessionOption, {
            onEnter: function (args) {
                // kSSLSessionOptionBreakOnServerAuth = 0
                var option = args[1].toInt32();
                if (option === 0) {
                    // Force the value to false (0) so custom trust evaluation
                    // does not get triggered
                    args[2] = ptr(0);
                    console.log(TAG + " SSLSetSessionOption(BreakOnServerAuth) set to false.");
                }
            }
        });
        console.log(TAG + " SSLSetSessionOption hooked at " + SSLSetSessionOption);
    } else {
        console.log(TAG + " [i] SSLSetSessionOption not found.");
    }
} catch (e) {
    console.log(TAG + " [!] SSLSetSessionOption hook failed: " + e);
}

// ===================================================================
// 4. SSLHandshake: force noErr on custom evaluation failure
// ===================================================================
try {
    var SSLHandshake = Module.findExportByName("Security", "SSLHandshake");
    if (SSLHandshake) {
        Interceptor.attach(SSLHandshake, {
            onLeave: function (retval) {
                var status = retval.toInt32();
                // -9841 = errSSLPeerAuthCompleted (custom eval requested)
                // -9807 = errSSLXCertChainInvalid
                if (status === -9841 || status === -9807) {
                    retval.replace(0); // noErr
                    console.log(TAG + " SSLHandshake error " + status + " suppressed.");
                }
            }
        });
        console.log(TAG + " SSLHandshake hooked at " + SSLHandshake);
    }
} catch (e) {
    console.log(TAG + " [!] SSLHandshake hook failed: " + e);
}

// ===================================================================
// 5. NSURLSession delegate: completionHandler with UseCredential
// ===================================================================
if (ObjC.available) {
    try {
        // Hook the resolver that iOS calls for authentication challenges.
        // Many apps implement URLSession:didReceiveChallenge:completionHandler:
        // We swizzle it on every class that implements it.
        var dominated = {};

        function hookSessionDelegate(className) {
            if (dominated[className]) return;
            dominated[className] = true;

            var klass = ObjC.classes[className];
            if (!klass) return;

            var sel = "- URLSession:didReceiveChallenge:completionHandler:";
            if (!klass[sel]) return;

            try {
                Interceptor.attach(klass[sel].implementation, {
                    onEnter: function (args) {
                        // args[2] = self, args[3] = _cmd
                        // args[4] = NSURLSession, args[5] = NSURLAuthenticationChallenge
                        // args[6] = completionHandler (block)
                        var challenge = new ObjC.Object(args[5]);
                        var protectionSpace = challenge.protectionSpace();
                        var authMethod = protectionSpace.authenticationMethod().toString();

                        if (authMethod === "NSURLAuthenticationMethodServerTrust") {
                            var serverTrust = protectionSpace.serverTrust();
                            var credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);

                            // completionHandler disposition enum:
                            //   0 = NSURLSessionAuthChallengeUseCredential
                            var handler = new ObjC.Block(args[6]);
                            handler.implementation = function (disposition, cred) {
                                // Intentionally ignore the original handler logic
                            };
                            // Call the block ourselves with UseCredential
                            var block = new ObjC.Block(args[6]);
                            block.invoke(0, credential);
                            console.log(TAG + " NSURLSession delegate bypassed for " + className + " (host: " + protectionSpace.host() + ")");
                            // Prevent original implementation from running
                            this.shouldSkip = true;
                        }
                    }
                });
                console.log(TAG + " Hooked " + className + " URLSession:didReceiveChallenge:completionHandler:");
            } catch (e) {
                // Some classes may fail: that's OK
            }
        }

        // Enumerate all classes that respond to the selector
        var classes = ObjC.enumerateLoadedClassesSync();
        for (var moduleName in classes) {
            var moduleClasses = classes[moduleName];
            for (var i = 0; i < moduleClasses.length; i++) {
                var cls = moduleClasses[i];
                try {
                    if (ObjC.classes[cls] &&
                        ObjC.classes[cls]["- URLSession:didReceiveChallenge:completionHandler:"]) {
                        hookSessionDelegate(cls);
                    }
                } catch (_) { /* skip */ }
            }
        }
    } catch (e) {
        console.log(TAG + " [!] NSURLSession delegate hook failed: " + e);
    }

    // ===============================================================
    // 6. AFNetworking: AFSecurityPolicy
    // ===============================================================
    try {
        if (ObjC.classes.AFSecurityPolicy) {
            var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;

            // setAllowInvalidCertificates:
            Interceptor.attach(AFSecurityPolicy["- setAllowInvalidCertificates:"].implementation, {
                onEnter: function (args) {
                    args[2] = ptr(1); // YES
                    console.log(TAG + " AFSecurityPolicy.setAllowInvalidCertificates forced to YES.");
                }
            });

            // setValidatesDomainName:
            Interceptor.attach(AFSecurityPolicy["- setValidatesDomainName:"].implementation, {
                onEnter: function (args) {
                    args[2] = ptr(0); // NO
                    console.log(TAG + " AFSecurityPolicy.setValidatesDomainName forced to NO.");
                }
            });

            // evaluateServerTrust:forDomain:: always return YES
            if (AFSecurityPolicy["- evaluateServerTrust:forDomain:"]) {
                Interceptor.attach(AFSecurityPolicy["- evaluateServerTrust:forDomain:"].implementation, {
                    onLeave: function (retval) {
                        retval.replace(ptr(1));
                        console.log(TAG + " AFSecurityPolicy.evaluateServerTrust:forDomain: forced to YES.");
                    }
                });
            }

            console.log(TAG + " AFNetworking AFSecurityPolicy hooked.");
        } else {
            console.log(TAG + " [i] AFSecurityPolicy not found (app may not use AFNetworking).");
        }
    } catch (e) {
        console.log(TAG + " [!] AFSecurityPolicy hook failed: " + e);
    }

    // ===============================================================
    // 7. TrustKit: TSKPinningValidator
    // ===============================================================
    try {
        if (ObjC.classes.TSKPinningValidator) {
            var validator = ObjC.classes.TSKPinningValidator;
            if (validator["- evaluateTrust:forHostname:"]) {
                Interceptor.attach(validator["- evaluateTrust:forHostname:"].implementation, {
                    onLeave: function (retval) {
                        // 0 = TSKTrustDecisionShouldAllowConnection
                        retval.replace(ptr(0));
                        console.log(TAG + " TrustKit TSKPinningValidator bypassed.");
                    }
                });
                console.log(TAG + " TrustKit hooked.");
            }
        } else {
            console.log(TAG + " [i] TrustKit not found.");
        }
    } catch (e) {
        console.log(TAG + " [!] TrustKit hook failed: " + e);
    }
} else {
    console.log(TAG + " [!] ObjC runtime not available: are you on iOS?");
}

console.log(TAG + " --- iOS SSL unpinning hooks installed ---");
