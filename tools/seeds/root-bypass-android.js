/**
 * root-bypass-android.js: Generic Android Root / Magisk Detection Bypass
 * MOSRAI seed script
 *
 * Hooks:
 *   1. java.io.File.exists()                : returns false for root indicators
 *   2. java.lang.Runtime.exec()             : blocks "su", "which su" and similar
 *   3. android.os.Build fields              : strips "test-keys" from TAGS
 *   4. ProcessBuilder                       : blocks su-related commands
 *   5. java.lang.System.getProperty         : fakes ro.debuggable=0, ro.secure=1
 *   6. android.app.ActivityManager
 *        .getRunningAppProcesses()           : filters Magisk / SuperSU processes
 *   7. java.io.File constructor monitoring  : logs every path the app checks
 *      (informational; helps identify custom detection)
 *   8. PackageManager.getPackageInfo        : hides root-related packages
 *   9. Native access()/stat()/fopen()       : blocks native file checks
 *
 * Usage:
 *   frida -U -f <package> -l root-bypass-android.js --no-pause
 *
 * Known limitations:
 *   - Apps using RootBeer, SafetyNet/Play Integrity attestation, or other
 *     server-side checks cannot be bypassed with client-side hooks alone.
 *   - Heavily obfuscated apps may access paths via reflection or JNI; those
 *     paths need per-app analysis.
 *   - Magisk's own "MagiskHide" / "Zygisk DenyList" may conflict; disable
 *     them for the target app when using this script.
 *   - Does not patch /proc/self/maps or /proc/self/mountinfo readings
 *     (some advanced detectors scan these for Magisk mount overlays).
 */

"use strict";

Java.perform(function () {
    var TAG = "[root-bypass]";

    // ---------------------------------------------------------------
    // Path lists
    // ---------------------------------------------------------------
    var ROOT_BINARIES = [
        "/system/app/Superuser.apk",
        "/system/app/Superuser",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/su/bin/su",
        "/data/local/su"
    ];

    var MAGISK_PATHS = [
        "/sbin/.magisk",
        "/sbin/.core",
        "/data/adb/magisk",
        "/data/adb/magisk.img",
        "/data/adb/magisk.db",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
        "/data/adb/modules"
    ];

    var JAILBREAK_APPS = [
        "/system/app/Superuser.apk",
        "/system/app/SuperSU",
        "/system/xbin/daemonsu"
    ];

    var ALL_ROOT_PATHS = ROOT_BINARIES.concat(MAGISK_PATHS).concat(JAILBREAK_APPS);

    // Package names that indicate root
    var ROOT_PACKAGES = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "me.phh.superuser",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclean",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot"
    ];

    // Process names to hide from getRunningAppProcesses
    var HIDDEN_PROCESSES = [
        "magisk",
        "supersu",
        "superuser",
        "daemonsu",
        "su",
        "busybox"
    ];

    function isRootPath(path) {
        if (!path) return false;
        var p = path.toString().toLowerCase();
        for (var i = 0; i < ALL_ROOT_PATHS.length; i++) {
            if (p.indexOf(ALL_ROOT_PATHS[i].toLowerCase()) !== -1) return true;
        }
        return false;
    }

    function isSuCommand(cmd) {
        if (!cmd) return false;
        var c = cmd.toString().trim();
        return (c === "su" || c === "/system/xbin/su" || c === "/system/bin/su" ||
                c === "/sbin/su" || c === "/su/bin/su" ||
                c.indexOf("which su") !== -1 || c.indexOf("which magisk") !== -1 ||
                c === "id" || c === "busybox");
    }

    // ---------------------------------------------------------------
    // 1. java.io.File.exists: hide root-indicator files
    // ---------------------------------------------------------------
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) {
                console.log(TAG + " File.exists(" + path + ") -> false (blocked)");
                return false;
            }
            return this.exists();
        };
        console.log(TAG + " java.io.File.exists hooked.");
    } catch (e) {
        console.log(TAG + " [!] File.exists hook failed: " + e);
    }

    // ---------------------------------------------------------------
    // 2. Runtime.exec: block su / which su
    // ---------------------------------------------------------------
    try {
        var Runtime = Java.use("java.lang.Runtime");

        // exec(String)
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (isSuCommand(cmd)) {
                console.log(TAG + " Runtime.exec(\"" + cmd + "\") blocked: throwing IOException.");
                throw Java.use("java.io.IOException").$new(cmd + ": not found");
            }
            return this.exec(cmd);
        };

        // exec(String[])
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
            if (cmds && cmds.length > 0 && isSuCommand(cmds[0])) {
                console.log(TAG + " Runtime.exec([\"" + cmds[0] + "\",...]) blocked.");
                throw Java.use("java.io.IOException").$new(cmds[0] + ": not found");
            }
            return this.exec(cmds);
        };

        // exec(String, String[], File) : 3-arg variant
        try {
            Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;", "java.io.File")
                .implementation = function (cmd, envp, dir) {
                    if (isSuCommand(cmd)) {
                        console.log(TAG + " Runtime.exec(\"" + cmd + "\",envp,dir) blocked.");
                        throw Java.use("java.io.IOException").$new(cmd + ": not found");
                    }
                    return this.exec(cmd, envp, dir);
                };
        } catch (_) { }

        console.log(TAG + " java.lang.Runtime.exec hooked.");
    } catch (e) {
        console.log(TAG + " [!] Runtime.exec hook failed: " + e);
    }

    // ---------------------------------------------------------------
    // 3. Build.TAGS: strip "test-keys"
    // ---------------------------------------------------------------
    try {
        var Build = Java.use("android.os.Build");
        var originalTags = Build.TAGS.value;
        if (originalTags && originalTags.toString().indexOf("test-keys") !== -1) {
            Build.TAGS.value = "release-keys";
            console.log(TAG + " Build.TAGS changed from \"" + originalTags + "\" to \"release-keys\".");
        } else {
            console.log(TAG + " Build.TAGS is already \"" + originalTags + "\": no change needed.");
        }
    } catch (e) {
        console.log(TAG + " [!] Build.TAGS patch failed: " + e);
    }

    // ---------------------------------------------------------------
    // 4. ProcessBuilder: block su commands
    // ---------------------------------------------------------------
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            var cmd = this.command();
            var cmdList = [];
            var iter = cmd.iterator();
            while (iter.hasNext()) {
                cmdList.push(iter.next().toString());
            }
            if (cmdList.length > 0 && isSuCommand(cmdList[0])) {
                console.log(TAG + " ProcessBuilder.start([\"" + cmdList.join("\",\"") + "\"]) blocked.");
                throw Java.use("java.io.IOException").$new(cmdList[0] + ": not found");
            }
            return this.start();
        };
        console.log(TAG + " ProcessBuilder.start hooked.");
    } catch (e) {
        console.log(TAG + " [!] ProcessBuilder hook failed: " + e);
    }

    // ---------------------------------------------------------------
    // 5. System.getProperty: fake ro.debuggable / ro.secure
    // ---------------------------------------------------------------
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            if (key === "ro.debuggable") {
                console.log(TAG + " SystemProperties.get(\"ro.debuggable\") -> \"0\"");
                return "0";
            }
            if (key === "ro.secure") {
                console.log(TAG + " SystemProperties.get(\"ro.secure\") -> \"1\"");
                return "1";
            }
            if (key === "ro.build.selinux") {
                console.log(TAG + " SystemProperties.get(\"ro.build.selinux\") -> \"1\"");
                return "1";
            }
            return this.get(key);
        };

        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
            if (key === "ro.debuggable") {
                console.log(TAG + " SystemProperties.get(\"ro.debuggable\",def) -> \"0\"");
                return "0";
            }
            if (key === "ro.secure") {
                console.log(TAG + " SystemProperties.get(\"ro.secure\",def) -> \"1\"");
                return "1";
            }
            return this.get(key, def);
        };
        console.log(TAG + " android.os.SystemProperties.get hooked.");
    } catch (e) {
        console.log(TAG + " [i] SystemProperties hook skipped (may not be accessible): " + e.message);
    }

    // ---------------------------------------------------------------
    // 6. ActivityManager.getRunningAppProcesses: filter root processes
    // ---------------------------------------------------------------
    try {
        var ActivityManager = Java.use("android.app.ActivityManager");
        ActivityManager.getRunningAppProcesses.implementation = function () {
            var processes = this.getRunningAppProcesses();
            if (processes === null) return processes;

            var ArrayList = Java.use("java.util.ArrayList");
            var filtered = ArrayList.$new();

            for (var i = 0; i < processes.size(); i++) {
                var procInfo = processes.get(i);
                var procName = procInfo.processName.value.toString().toLowerCase();
                var shouldHide = false;
                for (var j = 0; j < HIDDEN_PROCESSES.length; j++) {
                    if (procName.indexOf(HIDDEN_PROCESSES[j]) !== -1) {
                        shouldHide = true;
                        console.log(TAG + " Hiding process: " + procInfo.processName.value);
                        break;
                    }
                }
                if (!shouldHide) {
                    filtered.add(procInfo);
                }
            }
            return Java.cast(filtered, Java.use("java.util.List"));
        };
        console.log(TAG + " ActivityManager.getRunningAppProcesses hooked.");
    } catch (e) {
        console.log(TAG + " [i] ActivityManager hook skipped: " + e.message);
    }

    // ---------------------------------------------------------------
    // 7. PackageManager.getPackageInfo: hide root packages
    // ---------------------------------------------------------------
    try {
        var PM = Java.use("android.app.ApplicationContext") ||
                 Java.use("android.content.pm.PackageManager");
        // Hook via the abstract class method that most implementations call
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
            for (var i = 0; i < ROOT_PACKAGES.length; i++) {
                if (pkg === ROOT_PACKAGES[i]) {
                    console.log(TAG + " PackageManager.getPackageInfo(\"" + pkg + "\") blocked: throwing NameNotFoundException.");
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
                }
            }
            return this.getPackageInfo(pkg, flags);
        };
        console.log(TAG + " PackageManager.getPackageInfo hooked.");
    } catch (e) {
        console.log(TAG + " [i] PackageManager hook skipped: " + e.message);
    }

    // ---------------------------------------------------------------
    // 8. Native access(): hide root files at the native layer
    // ---------------------------------------------------------------
    try {
        var accessPtr = Module.findExportByName("libc.so", "access");
        if (accessPtr) {
            Interceptor.attach(accessPtr, {
                onEnter: function (args) {
                    var path = args[0].readUtf8String();
                    if (path && isRootPath(path)) {
                        console.log(TAG + " native access(\"" + path + "\") -> -1");
                        this.blockIt = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.blockIt) {
                        retval.replace(-1);
                    }
                }
            });
            console.log(TAG + " native access() hooked.");
        }
    } catch (e) {
        console.log(TAG + " [i] Native access() hook skipped: " + e.message);
    }

    // ---------------------------------------------------------------
    // 9. Native fopen(): block opening root-indicator files
    // ---------------------------------------------------------------
    try {
        var fopenPtr = Module.findExportByName("libc.so", "fopen");
        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function (args) {
                    var path = args[0].readUtf8String();
                    if (path && isRootPath(path)) {
                        console.log(TAG + " native fopen(\"" + path + "\") -> NULL");
                        this.blockIt = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.blockIt) {
                        retval.replace(ptr(0));
                    }
                }
            });
            console.log(TAG + " native fopen() hooked.");
        }
    } catch (e) {
        console.log(TAG + " [i] Native fopen() hook skipped: " + e.message);
    }

    console.log(TAG + " --- Root/Magisk detection bypass hooks installed ---");
});
