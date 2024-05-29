// Based on  https://codeshare.frida.re/@dzonerzy/fridantiroot/
Java.performNow(function () {
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com"
    ];
    var RootBinaries = ["mu", ".su", "su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk"];
    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };
    var RootPropertiesKeys = [];
    for (var k in RootProperties) RootPropertiesKeys.push(k);

    // Patch Native functions early

    // File.exists check
    var NativeFile = Java.use('java.io.File');
    NativeFile.exists.implementation = function () {
        var name = NativeFile.getName.call(this);
        if (RootBinaries.indexOf(name) > -1) {
            send("[RootDetection Bypass] return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
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

    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function (args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("[RootDetection Bypass] native fopen");
            }
        },
        onLeave: function (retval) {

        }
    });
    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function (args) {
            var cmd = Memory.readCString(args[0]);
            send("[RootDetection Bypass] SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("[RootDetection Bypass] native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("[RootDetection Bypass] native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function (retval) {

        }

    });
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
})