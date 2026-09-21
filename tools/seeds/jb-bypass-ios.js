/**
 * jb-bypass-ios.js: Generic iOS Jailbreak Detection Bypass
 * MOSRAI seed script
 *
 * Hooks:
 *   1. NSFileManager fileExistsAtPath:               : NO for jailbreak paths
 *   2. NSFileManager fileExistsAtPath:isDirectory:   : NO for jailbreak paths
 *   3. UIApplication canOpenURL:                     : NO for cydia:// scheme
 *   4. fork() / popen()                              : return -1 (sandbox fakes)
 *   5. stat() / lstat()                              : return -1 for JB paths
 *   6. access()                                      : return -1 for JB paths
 *   7. dlopen()                                      : block substrate/substitute libs
 *   8. getenv("DYLD_INSERT_LIBRARIES")               : return NULL
 *   9. NSProcessInfo.environment                     : strip DYLD_INSERT_LIBRARIES
 *  10. syscall (SYS_access / SYS_stat64)             : block JB path checks
 *
 * Usage:
 *   frida -U -f <bundle-id> -l jb-bypass-ios.js --no-pause
 *
 * Known limitations:
 *   - Server-side attestation (DeviceCheck, App Attest) cannot be bypassed
 *     client-side.
 *   - IOKit-based detection (checking for unsigned kernel extensions) is
 *     not hooked.
 *   - Some apps read /etc/fstab or /proc and parse contents; those custom
 *     checks need per-app hooks.
 *   - Substrate / Substitute / ElleKit may themselves hook some of these
 *     functions, creating re-entrancy. If you see crashes, try loading
 *     this script earlier (--no-pause with spawn) or use Frida Gadget.
 *   - Does not cover sandbox_check(): rare but used by some advanced
 *     detectors.
 */

"use strict";

var TAG = "[jb-bypass-ios]";

// ===================================================================
// Path / URL lists
// ===================================================================
var JB_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/Filza.app",
    "/Applications/FlyJB.app",
    "/Applications/blackra1n.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substitute-inserter.dylib",
    "/usr/lib/TweakInject",
    "/usr/lib/libhooker.dylib",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/etc/apt/sources.list.d",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/apt/",
    "/private/var/lib/cydia",
    "/private/var/tmp/cydia.log",
    "/private/var/stash",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/mobileLibrary/SBSettingsThemes",
    "/var/lib/dpkg/info",
    "/.installed_zydia",
    "/.cydia_no_stash",
    "/var/log/syslog",
    "/var/cache/apt",
    "/jb/amfid_payload.dylib",
    "/jb/jailbreakd.plist",
    "/jb/libjailbreak.dylib",
    "/jb/lzma",
    "/jb/offsets.plist",
    "/usr/share/jailbreak/injectme.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/private/var/db/stash",
    "/usr/libexec/cydia",
    "/usr/local/bin/cycript"
];

var JB_URL_SCHEMES = [
    "cydia://",
    "sileo://",
    "zbra://",
    "filza://",
    "undecimus://"
];

// Dylibs to block in dlopen
var BLOCKED_DYLIBS = [
    "SubstrateLoader.dylib",
    "MobileSubstrate.dylib",
    "libsubstitute.dylib",
    "substitute-inserter.dylib",
    "libhooker.dylib",
    "TweakInject",
    "CydiaSubstrate",
    "SubstrateInserter.dylib"
];

function isJBPath(path) {
    if (!path) return false;
    for (var i = 0; i < JB_PATHS.length; i++) {
        if (path === JB_PATHS[i] || path.indexOf(JB_PATHS[i]) === 0) return true;
    }
    return false;
}

function isJBScheme(url) {
    if (!url) return false;
    var u = url.toString().toLowerCase();
    for (var i = 0; i < JB_URL_SCHEMES.length; i++) {
        if (u.indexOf(JB_URL_SCHEMES[i]) === 0) return true;
    }
    return false;
}

function isBlockedDylib(path) {
    if (!path) return false;
    for (var i = 0; i < BLOCKED_DYLIBS.length; i++) {
        if (path.indexOf(BLOCKED_DYLIBS[i]) !== -1) return true;
    }
    return false;
}

// ===================================================================
// ObjC hooks (require ObjC runtime)
// ===================================================================
if (ObjC.available) {

    // ---------------------------------------------------------------
    // 1. NSFileManager fileExistsAtPath:
    // ---------------------------------------------------------------
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
            onEnter: function (args) {
                this.path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                if (isJBPath(this.path)) {
                    retval.replace(ptr(0)); // NO
                    console.log(TAG + " fileExistsAtPath:\"" + this.path + "\" -> NO");
                }
            }
        });
        console.log(TAG + " NSFileManager.fileExistsAtPath: hooked.");
    } catch (e) {
        console.log(TAG + " [!] fileExistsAtPath: hook failed: " + e);
    }

    // ---------------------------------------------------------------
    // 2. NSFileManager fileExistsAtPath:isDirectory:
    // ---------------------------------------------------------------
    try {
        Interceptor.attach(ObjC.classes.NSFileManager["- fileExistsAtPath:isDirectory:"].implementation, {
            onEnter: function (args) {
                this.path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                if (isJBPath(this.path)) {
                    retval.replace(ptr(0)); // NO
                    console.log(TAG + " fileExistsAtPath:isDirectory:\"" + this.path + "\" -> NO");
                }
            }
        });
        console.log(TAG + " NSFileManager.fileExistsAtPath:isDirectory: hooked.");
    } catch (e) {
        console.log(TAG + " [!] fileExistsAtPath:isDirectory: hook failed: " + e);
    }

    // ---------------------------------------------------------------
    // 3. UIApplication canOpenURL:
    // ---------------------------------------------------------------
    try {
        if (ObjC.classes.UIApplication) {
            Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
                onEnter: function (args) {
                    this.url = new ObjC.Object(args[2]).toString();
                },
                onLeave: function (retval) {
                    if (isJBScheme(this.url)) {
                        retval.replace(ptr(0)); // NO
                        console.log(TAG + " canOpenURL:\"" + this.url + "\" -> NO");
                    }
                }
            });
            console.log(TAG + " UIApplication.canOpenURL: hooked.");
        }
    } catch (e) {
        console.log(TAG + " [!] canOpenURL: hook failed: " + e);
    }

    // ---------------------------------------------------------------
    // 9. NSProcessInfo.environment: strip DYLD_INSERT_LIBRARIES
    // ---------------------------------------------------------------
    try {
        if (ObjC.classes.NSProcessInfo) {
            Interceptor.attach(ObjC.classes.NSProcessInfo["- environment"].implementation, {
                onLeave: function (retval) {
                    var env = new ObjC.Object(retval);
                    if (env.objectForKey_("DYLD_INSERT_LIBRARIES") !== null) {
                        var mutable = env.mutableCopy();
                        mutable.removeObjectForKey_("DYLD_INSERT_LIBRARIES");
                        retval.replace(mutable.handle);
                        console.log(TAG + " NSProcessInfo.environment: stripped DYLD_INSERT_LIBRARIES.");
                    }
                }
            });
            console.log(TAG + " NSProcessInfo.environment hooked.");
        }
    } catch (e) {
        console.log(TAG + " [i] NSProcessInfo.environment hook skipped: " + e.message);
    }

} else {
    console.log(TAG + " [!] ObjC runtime not available.");
}

// ===================================================================
// Native hooks (C-level)
// ===================================================================

// ---------------------------------------------------------------
// 4. fork(): return -1 (jailbreak detection via sandbox check)
// ---------------------------------------------------------------
try {
    var forkPtr = Module.findExportByName("libSystem.B.dylib", "fork");
    if (forkPtr) {
        Interceptor.attach(forkPtr, {
            onLeave: function (retval) {
                // In a non-jailbroken sandbox, fork() fails.
                // Return -1 to simulate sandboxed behavior.
                retval.replace(-1);
                console.log(TAG + " fork() -> -1 (simulating sandbox)");
            }
        });
        console.log(TAG + " fork() hooked.");
    }
} catch (e) {
    console.log(TAG + " [i] fork() hook skipped: " + e);
}

// ---------------------------------------------------------------
// 4b. popen(): return NULL
// ---------------------------------------------------------------
try {
    var popenPtr = Module.findExportByName("libSystem.B.dylib", "popen");
    if (popenPtr) {
        Interceptor.attach(popenPtr, {
            onEnter: function (args) {
                var cmd = args[0].readUtf8String();
                if (cmd && (cmd.indexOf("which") !== -1 || cmd.indexOf("su") !== -1 ||
                            cmd.indexOf("cydia") !== -1 || cmd.indexOf("ssh") !== -1)) {
                    console.log(TAG + " popen(\"" + cmd + "\") blocked -> NULL");
                    this.blockIt = true;
                }
            },
            onLeave: function (retval) {
                if (this.blockIt) {
                    retval.replace(ptr(0)); // NULL
                }
            }
        });
        console.log(TAG + " popen() hooked.");
    }
} catch (e) {
    console.log(TAG + " [i] popen() hook skipped: " + e);
}

// ---------------------------------------------------------------
// 5. stat() / lstat(): return -1 for JB paths
// ---------------------------------------------------------------
function hookStatFamily(name) {
    try {
        var funcPtr = Module.findExportByName("libSystem.B.dylib", name);
        if (funcPtr) {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    try {
                        var path = args[0].readUtf8String();
                        if (path && isJBPath(path)) {
                            console.log(TAG + " " + name + "(\"" + path + "\") -> -1");
                            this.blockIt = true;
                        }
                    } catch (_) { }
                },
                onLeave: function (retval) {
                    if (this.blockIt) {
                        retval.replace(-1);
                    }
                }
            });
            console.log(TAG + " " + name + "() hooked.");
        }
    } catch (e) {
        console.log(TAG + " [i] " + name + "() hook skipped: " + e);
    }
}
hookStatFamily("stat");
hookStatFamily("lstat");
hookStatFamily("stat64");
hookStatFamily("lstat64");

// ---------------------------------------------------------------
// 6. access(): return -1 for JB paths
// ---------------------------------------------------------------
try {
    var accessPtr = Module.findExportByName("libSystem.B.dylib", "access");
    if (accessPtr) {
        Interceptor.attach(accessPtr, {
            onEnter: function (args) {
                try {
                    var path = args[0].readUtf8String();
                    if (path && isJBPath(path)) {
                        console.log(TAG + " access(\"" + path + "\") -> -1");
                        this.blockIt = true;
                    }
                } catch (_) { }
            },
            onLeave: function (retval) {
                if (this.blockIt) {
                    retval.replace(-1);
                }
            }
        });
        console.log(TAG + " access() hooked.");
    }
} catch (e) {
    console.log(TAG + " [i] access() hook skipped: " + e);
}

// ---------------------------------------------------------------
// 7. dlopen(): block substrate/substitute dylib loading
// ---------------------------------------------------------------
try {
    var dlopenPtr = Module.findExportByName("libSystem.B.dylib", "dlopen");
    if (!dlopenPtr) {
        dlopenPtr = Module.findExportByName(null, "dlopen");
    }
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onEnter: function (args) {
                if (args[0].isNull()) return;
                try {
                    var path = args[0].readUtf8String();
                    if (path && isBlockedDylib(path)) {
                        console.log(TAG + " dlopen(\"" + path + "\") blocked -> NULL");
                        this.blockIt = true;
                        // Redirect to a path that won't resolve
                        args[0] = Memory.allocUtf8String("/nonexistent_mosrai_blocked.dylib");
                    }
                } catch (_) { }
            },
            onLeave: function (retval) {
                if (this.blockIt) {
                    retval.replace(ptr(0));
                }
            }
        });
        console.log(TAG + " dlopen() hooked.");
    }
} catch (e) {
    console.log(TAG + " [i] dlopen() hook skipped: " + e);
}

// ---------------------------------------------------------------
// 8. getenv("DYLD_INSERT_LIBRARIES"): return NULL
// ---------------------------------------------------------------
try {
    var getenvPtr = Module.findExportByName("libSystem.B.dylib", "getenv");
    if (getenvPtr) {
        Interceptor.attach(getenvPtr, {
            onEnter: function (args) {
                try {
                    var name = args[0].readUtf8String();
                    if (name === "DYLD_INSERT_LIBRARIES") {
                        console.log(TAG + " getenv(\"DYLD_INSERT_LIBRARIES\") -> NULL");
                        this.blockIt = true;
                    }
                } catch (_) { }
            },
            onLeave: function (retval) {
                if (this.blockIt) {
                    retval.replace(ptr(0));
                }
            }
        });
        console.log(TAG + " getenv() hooked.");
    }
} catch (e) {
    console.log(TAG + " [i] getenv() hook skipped: " + e);
}

// ---------------------------------------------------------------
// 10. fopen(): block opening jailbreak-related files
// ---------------------------------------------------------------
try {
    var fopenPtr = Module.findExportByName("libSystem.B.dylib", "fopen");
    if (fopenPtr) {
        Interceptor.attach(fopenPtr, {
            onEnter: function (args) {
                try {
                    var path = args[0].readUtf8String();
                    if (path && isJBPath(path)) {
                        console.log(TAG + " fopen(\"" + path + "\") -> NULL");
                        this.blockIt = true;
                    }
                } catch (_) { }
            },
            onLeave: function (retval) {
                if (this.blockIt) {
                    retval.replace(ptr(0));
                }
            }
        });
        console.log(TAG + " fopen() hooked.");
    }
} catch (e) {
    console.log(TAG + " [i] fopen() hook skipped: " + e);
}

console.log(TAG + " --- iOS jailbreak detection bypass hooks installed ---");
