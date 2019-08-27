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
    var String = Java.use('java.lang.String');
    String.contains.implementation = function (name) {
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
            var cmd = argz[0]
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
            send("[RootDetection Bypass] ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("[RootDetection Bypass] ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    }

    // Patch other libraries after the above ones
    var RootBypass = [{
        class: 'android.security.keystore.KeyInfo',
        method: 'isInsideSecureHardware',
        func: function () {
            send("[RootDetection Bypass] isInsideSecureHardware");
            return true;
        },
        target: 6
    }, {
        class: 'android.app.ApplicationPackageManager',
        method: 'getPackageInfo',
        arguments: ['java.lang.String', 'int'],
        func: function (pname, flags) {
            var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
            if (shouldFakePackage) {
                send("[RootDetection Bypass] root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo.call(this, pname, flags);
        }
    }, {
        class: 'android.os.SystemProperties',
        method: 'get',
        arguments: ['java.lang.String'],
        func: function (name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                send("[RootDetection Bypass] " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        }
    }
    ]

    RootBypass.forEach(function (bypass, _) {
        var toHook;
        try {
            if (bypass.target && parseInt(Java.androidVersion, 10) < bypass.target) {
                send('[RootDetection Bypass] Not Hooking unavailable class/method - ' + bypass.class + '.' + bypass.method)
                return
            }
            toHook = Java.use(bypass.class)[bypass.method];
            if (!toHook) {
                send('[RootDetection Bypass] Cannot find ' + bypass.class + '.' + bypass.method);
                return
            }
        } catch (err) {
            send('[RootDetection Bypass] Error ' + bypass.class + '.' + bypass.method + err);
            return
        }
        if (bypass.arguments) {
            toHook.overload.apply(null, bypass.arguments).implementation = bypass.func;
        } else {
            toHook.overload.implementation = bypass.func;
        }
    })

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