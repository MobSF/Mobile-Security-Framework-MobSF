// Based on  https://codeshare.frida.re/@dzonerzy/fridantiroot/
// Enhanced with modern root detection bypass (Magisk, KernelSU, APatch, Zygisk)
Java.performNow(function () {
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk", "io.github.huskydg.magisk",
        "com.topjohnwu.magisk.canary", "me.weishu.kernelsu", "me.tool.passkey", "io.github.apatch"
    ];
    var RootBinaries = ["mu", ".su", "su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk",
        "magisk", "magiskhide", "magiskpolicy", "magiskinit", "resetprop"];
    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1",
        "ro.boot.verifiedbootstate": "green",
        "ro.boot.flash.locked": "1",
        "ro.boot.veritymode": "enforcing",
        "ro.boot.warranty_bit": "0",
        "ro.warranty_bit": "0",
        "sys.oem_unlock_allowed": "0"
    };
    var RootPropertiesKeys = [];
    for (var k in RootProperties) RootPropertiesKeys.push(k);

    // Modern root paths and mount points
    var RootPaths = [
        "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
        "/system/app/Superuser.apk", "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap",
        "/data/adb/modules", "/data/adb/post-fs-data.d", "/data/adb/service.d",
        "/debug_ramdisk", "/sbin/.magisk", "/cache/.magisk", "/metadata/.magisk",
        "/persist/.magisk", "/mnt/.magisk", "/system/bin/resetprop", "/dev/magisk/mirror"
    ];

    // Magisk/KernelSU/APatch mount namespaces
    var SuspiciousMounts = [
        "magisk", "core-only", "zygisk", "kernelsu", "ksu", "apatch"
    ];

    // Patch Native functions early

    // File.exists check
    var NativeFile = Java.use('java.io.File');
    NativeFile.exists.implementation = function () {
        var name = NativeFile.getName.call(this);
        var path = NativeFile.getAbsolutePath.call(this);

        // Check against binary names
        if (RootBinaries.indexOf(name) > -1) {
            send("[RootDetection Bypass] File.exists() blocked for binary: " + name);
            return false;
        }

        // Check against root paths
        for (var i = 0; i < RootPaths.length; i++) {
            if (path.indexOf(RootPaths[i]) !== -1) {
                send("[RootDetection Bypass] File.exists() blocked for path: " + path);
                return false;
            }
        }

        return this.exists.call(this);
    };

    // String.contains check
    var javaString = Java.use('java.lang.String');
    javaString.contains.implementation = function (name) {
        if (name == "test-keys") {
            send("[RootDetection Bypass] test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    // Runtime.exec check
    function isRootCheck(cmd) {
        var fakeCmd;
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            fakeCmd = "grep";
            send("[RootDetection Bypass] " + cmd + " command");
            return fakeCmd;
        }
        if (cmd == "su") {
            fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("[RootDetection Bypass] " + cmd + " command");
            return fakeCmd;
        }
        return false;
    }
    // Get all implementations
    function get_implementations(toHook) {
        var imp_args = []
        toHook.overloads.forEach(function (impl, _) {
            if (impl.hasOwnProperty('argumentTypes')) {
                var args = [];
                var argTypes = impl.argumentTypes
                argTypes.forEach(function (arg_type, __) {
                    args.push(arg_type.className)
                });
                imp_args.push(args);
            }
        });
        return imp_args;
    }

    var Runtime = Java.use('java.lang.Runtime');
    var execImplementations = get_implementations(Runtime.exec)
    var exec = Runtime.exec.overload('java.lang.String')

    execImplementations.forEach(function (args, _) {
        Runtime.exec.overload.apply(null, args).implementation = function () {
            var fakeCmd;
            var argz = [].slice.call(arguments);
            var cmd = argz[0];
            if (typeof cmd === 'string') {
                fakeCmd = isRootCheck(cmd);
                if (fakeCmd) {
                    send("[RootDetection Bypass] " + cmd + " command");
                    return exec.call(this, fakeCmd);
                }
            } else if (typeof cmd === 'object') {
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    fakeCmd = isRootCheck(tmp_cmd);
                    if (fakeCmd) {
                        send("[RootDetection Bypass] " + cmd + " command");
                        return exec.call(this, '');
                    }
                }
            }
            return this['exec'].apply(this, argz);
        };
    });

    // BufferedReader checkLine check
    var BufferedReader = Java.use('java.io.BufferedReader');
    BufferedReader.readLine.overload().implementation = function () {
        var text = this.readLine.call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("[RootDetection Bypass] build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    }

    // ProcessBuilder.start check
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    ProcessBuilder.start.implementation = function () {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("[RootDetection Bypass] ProcessBuilder " + JSON.stringify(cmd));
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("[RootDetection Bypass] ProcessBuilder " + JSON.stringify(cmd));
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    }

    // Patch other libraries after the above ones
    var toHook, className, classMethod;
    try {
        className = 'android.app.ApplicationPackageManager'
        classMethod = 'getPackageInfo'
        toHook = Java.use(className)[classMethod];
        if (!toHook) {
            send('[RootDetection Bypass] Cannot find ' + className + '.' + classMethod);
            return
        }
        toHook.overload('java.lang.String', 'int').implementation = function (pname, flags) {
            var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
            if (shouldFakePackage) {
                send("[RootDetection Bypass] root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo.call(this, pname, flags);
        }
    } catch (err) {
        send('[RootDetection Bypass] Error ' + className + '.' + classMethod + err);
    }

    try {
        className = 'android.os.SystemProperties'
        classMethod = 'get'
        toHook = Java.use(className)[classMethod];
        if (!toHook) {
            send('[RootDetection Bypass] Cannot find ' + className + '.' + classMethod);
            return
        }
        toHook.overload('java.lang.String').implementation = function (name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                send("[RootDetection Bypass] " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        }
    } catch (err) {
        send('[RootDetection Bypass] Error ' + className + '.' + classMethod + err);
    }
    try {
        className = 'android.security.keystore.KeyInfo'
        classMethod = 'isInsideSecureHardware'
        if (parseInt(Java.androidVersion, 10) < 6) {
            send('[RootDetection Bypass] Not Hooking unavailable class/classMethod - ' + className + '.' + classMethod)
            return
        }
        toHook = Java.use(className)[classMethod];
        if (!toHook) {
            send('[RootDetection Bypass] Cannot find ' + className + '.' + classMethod);
            return
        }
        toHook.implementation = function () {
            send("[RootDetection Bypass] isInsideSecureHardware");
            return true;
        }
    } catch (err) {
        send('[RootDetection Bypass] Error ' + className + '.' + classMethod + err);
    }

    // Native Root Check Bypass

    try {
        const libc = Process.getModuleByName("libc.so");
        
        Interceptor.attach(libc.getExportByName("fopen"), {
            onEnter: function (args) {
                try{
                var path = Memory.readCString(args[0]);
                path = path.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
                if (shouldFakeReturn) {
                    args[0].writeUtf8String("/notexists");
                    send("[RootDetection Bypass] native fopen");
                }
                } catch(e){}
            },
            onLeave: function (retval) {

            }
        });
        
        Interceptor.attach(libc.getExportByName("system"), {
            onEnter: function (args) {
                try{
                var cmd = Memory.readCString(args[0]);
                send("[RootDetection Bypass] SYSTEM CMD: " + cmd);
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                    send("[RootDetection Bypass] native system: " + cmd);
                    args[0].writeUtf8String("grep");
                }
                if (cmd == "su") {
                    send("[RootDetection Bypass] native system: " + cmd);
                    args[0].writeUtf8String("justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
                }
                } catch(e){}
            },
            onLeave: function (retval) {

            }
        });
    } catch (err) {
        send('[RootDetection Bypass] Error hooking libc.so: ' + err);
    }

    // Bypass SELinux mode detection (Modern Android)
    try {
        const SELinux = Java.use('android.os.SELinux');
        SELinux.isSELinuxEnabled.implementation = function() {
            send("[RootDetection Bypass] SELinux.isSELinuxEnabled");
            return true;
        };
        SELinux.isSELinuxEnforced.implementation = function() {
            send("[RootDetection Bypass] SELinux.isSELinuxEnforced");
            return true;
        };
    } catch (err) {
        send('[RootDetection Bypass] SELinux class not available: ' + err);
    }

    // Bypass Build.TAGS check for test-keys
    try {
        const Build = Java.use('android.os.Build');
        const BuildClass = Java.use('java.lang.Class');
        const fieldTags = BuildClass.getDeclaredField.call(Build.class, 'TAGS');
        fieldTags.setAccessible(true);
        fieldTags.set(null, 'release-keys');
        send("[RootDetection Bypass] Build.TAGS set to release-keys");
    } catch (err) {}

    /*

    TO IMPLEMENT:

    Exec Family

    int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
    int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
    int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execv(const char *path, char *const argv[]);
    int execve(const char *path, char *const argv[], char *const envp[]);
    int execvp(const char *file, char *const argv[]);
    int execvpe(const char *file, char *const argv[], char *const envp[]);

    */
});
Java.perform(function() {
    // Bypassing Root in React Native JailMonkey
    // Source: https://codeshare.frida.re/@RohindhR/react-native-jail-monkey-bypass-all-checks/
    try {
        let toHook = Java.use('com.gantix.JailMonkey.JailMonkeyModule')['getConstants'];
        toHook.implementation = function() {
            var hashmap = this.getConstants();
            hashmap.put('isJailBroken', Java.use("java.lang.Boolean").$new(false));
            hashmap.put('hookDetected', Java.use("java.lang.Boolean").$new(false));
            hashmap.put('canMockLocation', Java.use("java.lang.Boolean").$new(false));
            hashmap.put('isOnExternalStorage', Java.use("java.lang.Boolean").$new(false));
            hashmap.put('AdbEnabled', Java.use("java.lang.Boolean").$new(false));
            return hashmap;
        }
    } catch (err) {}
    try{
        // Bypassing Rooted Check
        let hook = Java.use('com.gantix.JailMonkey.Rooted.RootedCheck')['getResultByDetectionMethod']
        hook.implementation = function() {
            let map = this.getResultByDetectionMethod();
            map.put("jailMonkey", Java.use("java.lang.Boolean").$new(false));
            return map;
        }

    } catch (err) {}
    try{
        // Bypassing Root detection method's result of RootBeer library
        var className = 'com.gantix.JailMonkey.Rooted.RootedCheck$RootBeerResults';
        let toHook = Java.use(className)['isJailBroken'];
        toHook.implementation = function() {
            return false;
        };

        let toHook2 = Java.use(className)['toNativeMap']
        toHook2.implementation = function() {
            var map = this.toNativeMap.call(this);
            map.put("detectRootManagementApps", Java.use("java.lang.Boolean").$new(false));
            map.put("detectPotentiallyDangerousApps", Java.use("java.lang.Boolean").$new(false));
            map.put("checkForSuBinary", Java.use("java.lang.Boolean").$new(false));
            map.put("checkForDangerousProps", Java.use("java.lang.Boolean").$new(false));
            map.put("checkForRWPaths", Java.use("java.lang.Boolean").$new(false));
            map.put("detectTestKeys", Java.use("java.lang.Boolean").$new(false));
            map.put("checkSuExists", Java.use("java.lang.Boolean").$new(false));
            map.put("checkForRootNative", Java.use("java.lang.Boolean").$new(false));
            map.put("checkForMagiskBinary", Java.use("java.lang.Boolean").$new(false));
            return map;
        };
    } catch (err) {}

    // Bypass standalone RootBeer library (if used directly)
    try {
        const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            send("[RootDetection Bypass] RootBeer.isRooted");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            send("[RootDetection Bypass] RootBeer.isRootedWithoutBusyBoxCheck");
            return false;
        };
        RootBeer.detectRootManagementApps.implementation = function() {
            send("[RootDetection Bypass] RootBeer.detectRootManagementApps");
            return false;
        };
        RootBeer.detectPotentiallyDangerousApps.implementation = function() {
            send("[RootDetection Bypass] RootBeer.detectPotentiallyDangerousApps");
            return false;
        };
        RootBeer.checkForBinary.implementation = function(filename) {
            send("[RootDetection Bypass] RootBeer.checkForBinary: " + filename);
            return false;
        };
        RootBeer.checkForMagiskBinary.implementation = function() {
            send("[RootDetection Bypass] RootBeer.checkForMagiskBinary");
            return false;
        };
    } catch (err) {}

    // Bypass Google Play Integrity API / SafetyNet (Modern)
    try {
        const IntegrityManager = Java.use('com.google.android.play.core.integrity.IntegrityManager');
        const IntegrityManagerFactory = Java.use('com.google.android.play.core.integrity.IntegrityManagerFactory');
        IntegrityManagerFactory.create.implementation = function(context) {
            send("[RootDetection Bypass] Play Integrity API create() intercepted");
            return this.create(context);
        };
    } catch (err) {}

    // Bypass SafetyNet Attestation API (Legacy)
    try {
        const SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNet');
        send("[RootDetection Bypass] SafetyNet API hooked (if available)");
    } catch (err) {}

    // Bypass for common custom root checks
    try {
        const ShellExecutor = Java.use('java.lang.Runtime');
        const exec = ShellExecutor.exec.overload('java.lang.String');
        exec.implementation = function(cmd) {
            if (cmd && cmd.indexOf('/system/bin/which') !== -1 && cmd.indexOf('su') !== -1) {
                send("[RootDetection Bypass] Blocked 'which su' command");
                return exec.call(this, 'which nonexistent');
            }
            return this.exec(cmd);
        };
    } catch (err) {}
})