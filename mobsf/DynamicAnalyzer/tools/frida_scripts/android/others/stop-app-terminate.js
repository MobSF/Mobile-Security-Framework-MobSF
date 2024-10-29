/*
Made By @ApkUnpacker
Source: https://github.com/apkunpacker/FridaScripts
*/
var GlobalLogs = false;
Java.perform(function() {
    try {
        var Installer = Java.use("android.app.ApplicationPackageManager");
        Installer.getInstallerPackageName.overload('java.lang.String').implementation = function(Str) {
            console.log("Installer Name Fixed");
            if (GlobalLogs) {
                ShowLogs();
            }
            return "com.android.vending";
        }
        var Installer2 = Java.use("android.content.pm.PackageManager");
        Installer2.getInstallerPackageName.overload('java.lang.String').implementation = function(Str) {
            console.error("Installer Name Fixed 2");
            if (GlobalLogs) {
                ShowLogs();
            }
            return "com.android.vending";
        }
        var system = Java.use("java.lang.System");
        system.exit.overload("int").implementation = function(var0) {
            console.warn("[*] Exit Called");
            if (GlobalLogs) {
                ShowLogs();
            }
        }
        Java.choose("android.app.Activity", {
            onMatch: function(instance) {
                instance.onDestroy.overload().implementation = function() {
                    console.log("[*] onDestroy() Called");
                }
            },
            onComplete: function(retval) {}
        });
        var act = Java.use("android.app.Activity");
        act.finish.overload().implementation = function() {
            console.log("[*] Finish() Called");
            if (GlobalLogs) {
                ShowLogs();
            }
        }
        var secure = Java.use("android.provider.Settings$Secure");
        secure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(str1, str2, str3) {
            if (str2.indexOf("development_settings_enabled") >= 0 || str2.indexOf("adb_enabled") >= 0) {
                var fix = "bypass";
                console.log("Developer Mode & ADB Checked ");
                return this.getInt.call(this, str1, fix, str3);
            } else return this.getInt.call(this, str1, str2, str3);
        }
        var act = Java.use("android.os.Process");
        act.myPid.overload().implementation = function() {
            console.log("[*] Mypid() = ", this.myPid());
            return this.myPid();
        }
        var Debugger = Java.use("android.os.Debug");
        Debugger.isDebuggerConnected.overload().implementation = function() {
            console.log("[*] isDebuggerConnected() Called");
            return false;
        }
        var ss = Java.use("android.app.Service");
        ss.stopSelf.overload().implementation = function() {
            console.log("[*] stopSelf() called ");
        }
        var Verify = Java.use("java.security.Signature");
        Verify.verify.overload("[B").implementation = function() {
            console.warn("[*] Core Verify() called ");
            return true;
        }
        var MD = Java.use("java.security.MessageDigest");
        MD.isEqual.overload("[B", "[B").implementation = function() {
            console.log("[*] MD isEqual() called ");
            return true;
        }
        var Pm = Java.use("android.content.pm.PackageManager");
        Pm.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flag) {
            console.warn("getPackageInfo() with package", pkg, " and flag ", flag);
            return this.getPackageInfo.overload("java.lang.String", "int").call(this, pkg, flag);
        }
        var act = Java.use("android.app.Activity");
        act.finishActivity.overload('int').implementation = function(arg) {
            console.log("FinishActivity():-->>" + arg);
            console.log("[*] FinishActivity() Called");
        }
        var Proc = Java.use("android.os.Process");
        Proc.killProcess.overload('int').implementation = function(arg) {
            console.log("KillProcess():-->>" + arg);
            console.log("[*] KillProcess() Called");
            if (GlobalLogs) {
                ShowLogs();
            }
        }
        var AR = Java.use("android.app.Activity");
        AR.onActivityResult.overload('int', 'int', 'android.content.Intent').implementation = function(a, b, c) {
            console.log("onActivityResult():-->>" + a + " " + b + " " + c);
            console.log("[*] onActivityResult() Called");
        }
        var FinishAffinity = Java.use("android.app.Activity");
        FinishAffinity.finishAffinity.overload().implementation = function() {
            console.log("[*] finishAffinity() Called");
        }
        var FinishAndRemoveTask = Java.use("android.app.Activity");
        FinishAndRemoveTask.finishAndRemoveTask.overload().implementation = function() {
            console.log("[*] FinishAndRemoveTask() Called");
        }
        var StartActivity = Java.use("android.app.Activity");
        StartActivity.startActivity.overload("android.content.Intent").implementation = function(intent) {
            console.warn("[*] startActivity() Called with " + intent);
            if (GlobalLogs) {
                ShowLogs();
            }
            return this.startActivity(intent);
        }
        var ifinish = Java.use("android.app.Activity");
        ifinish.isFinishing.overload().implementation = function() {
            var ret = this.isFinishing();
            console.log("[*] isFinishing() Called");
            return this.isFinishing();
        }

        function ShowLogs() {
            Java.perform(function() {
                var jAndroidLog = Java.use("android.util.Log"),
                    jException = Java.use("java.lang.Exception");
                console.warn("##########\n", jAndroidLog.getStackTraceString(jException.$new()), "##########\n");
            });
        }
    } catch (e) {
        console.error(e);
    }
})
try {
    Interceptor.attach(Module.findExportByName(null, "exit"), {
        onEnter: function(args) {
            console.warn("Native Exit() Called :-->:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");
        },
        onLeave: function(retval) {}
    });
} catch (e) {}
try {
    Interceptor.attach(Module.findExportByName(null, "abort"), {
        onEnter: function(args) {
            console.warn("Native Abort() Called :-->:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");
        },
        onLeave: function(retval) {}
    });
} catch (e) {}
try {
    var fork = Module.findExportByName(null, "fork")
    Interceptor.attach(fork, {
        onEnter: function(args) {},
        onLeave: function(retval) {
            var pid = parseInt(retval.toString(16), 16)
            console.log("Second Process PID : ", pid)
        }
    })
} catch (e) {}
try {
    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            if (cmd.indexOf("kill") != -1) {
                console.log("Bypass native system: " + cmd);
                var NewKill = args[0].writeUtf8String("bypassed");
                args[0] = ptr(NewKill);
            }
        },
        onLeave: function(retval) {}
    });
} catch (e) {}
try {
    var abortPtr = Module.getExportByName('libc.so', 'abort');
    var abort = new NativeFunction(abortPtr, 'int', ['int']);
    var exitPtr = Module.getExportByName('libc.so', 'exit');
    var exit = new NativeFunction(exitPtr, 'int', ['int']);
    var _exitPtr = Module.getExportByName('libc.so', '_exit');
    var _exit = new NativeFunction(_exitPtr, 'int', ['int']);
    var killPtr = Module.getExportByName('libc.so', 'kill');
    var kill = new NativeFunction(killPtr, 'int', ['int', 'int']);
    var raisePtr = Module.getExportByName('libc.so', 'raise');
    var raise = new NativeFunction(raisePtr, 'int', ['int']);
    var shutdownPtr = Module.getExportByName('libc.so', 'shutdown');
    var shutdown = new NativeFunction(shutdownPtr, 'int', ['int', 'int']);
    Interceptor.replace(abortPtr, new NativeCallback(function(status) {
        console.log('Abort Replaced');
        return 0;
    }, 'int', ['int']));
    Interceptor.replace(exitPtr, new NativeCallback(function(status) {
        console.log('Exit Replaced');
        return 0;
    }, 'int', ['int']));
    Interceptor.replace(_exitPtr, new NativeCallback(function(status) {
        console.log('_exit Replaced');
        return 0;
    }, 'int', ['int']));
    Interceptor.replace(killPtr, new NativeCallback(function(pid, sig) {
        console.log('Kill Replaced');
        return 0;
    }, 'int', ['int', 'int']));
    Interceptor.replace(raisePtr, new NativeCallback(function(sig) {
        console.log('Raise Replaced');
        return 0;
    }, 'int', ['int']));
    Interceptor.replace(shutdownPtr, new NativeCallback(function(fd, how) {
        console.log('Shutdown Replaced');
        return 0;
    }, 'int', ['int', 'int']));
} catch (e) {}
