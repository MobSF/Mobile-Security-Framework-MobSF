Java.perform(function () {
    try {
        // Bypass isDebuggerConnected() check 
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            send('[Debugger Check] isDebuggerConnected() check bypassed');
            return false;
        }
    } catch(e){}
});
 // Following are based on: https://github.com/apkunpacker/FridaScripts
try {
    /* Bypass Frida Detection Based On Port Number */
    Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
        onEnter: function(args) {
            var memory = Memory.readByteArray(args[1], 64);
            var b = new Uint8Array(memory);
            if (b[2] == 0x69 && b[3] == 0xa2 && b[4] == 0x7f && b[5] == 0x00 && b[6] == 0x00 && b[7] == 0x01) {
                this.frida_detection = true;
            }
        },
        onLeave: function(retval) {
            if (this.frida_detection) {
                send("[Debugger Check] Frida Port detection bypassed");
                retval.replace(-1);
            }
        }
    });
} catch(e){}
try {
    Interceptor.attach(Module.findExportByName(null, "connect"), {
        onEnter: function(args) {
            var family = Memory.readU16(args[1]);
            if (family !== 2) {
                return
            }
            var port = Memory.readU16(args[1].add(2));
            port = ((port & 0xff) << 8) | (port >> 8);
            if (port === 27042) {
                send('[Debugger Check] Frida Port detection bypassed');
                Memory.writeU16(args[1].add(2), 0x0101);
            }
        }
    });
} catch(e){}
try {
    /* Bypass TracerPid Detection Based On Pid Status */
    var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function(buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        var bufstr = Memory.readUtf8String(buffer);
        if (bufstr.indexOf("TracerPid:") > -1) {
            Memory.writeUtf8String(buffer, "TracerPid:\t0");
            send("[Debugger Check] TracerPID check bypassed");
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']))
} catch(e){}

try {
    /* Bypass Ptrace Checks */
    Interceptor.attach(Module.findExportByName(null, "ptrace"), {
        onEnter: function(args) {},
        onLeave: function(retval) {
            send("[Debugger Check] Ptrace check bypassed");
            retval.replace(0);
        }
    })
} catch(e){}

try {
    /* Watch Child Process Forking */
    var fork = Module.findExportByName(null, "fork")
    Interceptor.attach(fork, {
        onEnter: function(args) {},
        onLeave: function(retval) {
            var pid = parseInt(retval.toString(16), 16)
            send("[Debugger Check] Hook fork child process PID: " + pid)
        }
    })
} catch(e){}


/* Xposed Detection Bypass */
Java.perform(function() {
    try {
        var cont = Java.use("java.lang.String");
        cont.contains.overload("java.lang.CharSequence").implementation = function(checks) {
            var check = checks.toString();
            if (check.indexOf("libdexposed") >= 0 || check.indexOf("libsubstrate.so") >= 0 || check.indexOf("libepic.so") >= 0 || check.indexOf("libxposed") >= 0) {
                var BypassCheck = "libpkmkb.so";
                send("[Debugger Check] Xposed library check bypassed");
                return this.contains.call(this, BypassCheck);
            }
            return this.contains.call(this, checks);
        }
    } catch (erro) {
        console.error(erro);
    }
    try {
        var StacktraceEle = Java.use("java.lang.StackTraceElement");
        StacktraceEle.getClassName.overload().implementation = function() {
            var Flag = false;
            var ClazzName = this.getClassName();
            if (ClazzName.indexOf("com.saurik.substrate.MS$2") >= 0 || ClazzName.indexOf("de.robv.android.xposed.XposedBridge") >= 0) {
                send("[Debugger Check] Debugger detection check bypassed for class: " + this.getClassName());
                Flag = true;
                if (Flag) {
                    var StacktraceEle = Java.use("java.lang.StackTraceElement");
                    StacktraceEle.getClassName.overload().implementation = function() {
                        var gMN = this.getMethodName();
                        if (gMN.indexOf("handleHookedMethod") >= 0 || gMN.indexOf("invoked") >= 0) {
                            send("[Debugger Check] Debugger detection check bypassed for method: " + this.getMethodName());
                            return "bye.pass";
                        }
                        return this.getMethodName();
                    }
                }
                return "com.android.vending"
            }
            return this.getClassName();
        }
    } catch (errr) {
        console.error(errr);
    }
})
/* VPN Related Checks */
Java.perform(function() {
    var NInterface = Java.use("java.net.NetworkInterface");
    try {
        var NInterface = Java.use("java.net.NetworkInterface");
        NInterface.getName.overload().implementation = function() {
            var IName = this.getName();
            if (IName == "tun0" || IName == "ppp0" || IName == "p2p0" || IName == "ccmni0" || IName == "tun") {
                send("[Debugger Check] Bypassed Network Interface name check: " + JSON.stringify(this.getName()));
                return "Bypass";
            }
            return this.getName();
        }
    } catch (err) {
        console.error(err);
    }
    // HTTP(s) Proxy check
    try {
        var GetProperty = Java.use("java.lang.System");
        GetProperty.getProperty.overload("java.lang.String").implementation = function(getprop) {
            if (getprop.indexOf("http.proxyHost") >= 0 || getprop.indexOf("http.proxyPort") >= 0) {
                var newprop = "CKMKB"
                send("[Debugger Check] HTTP(s) proxy check bypassed")
                return this.getProperty.call(this, newprop);
            }
            return this.getProperty(getprop);
        }
    } catch (err) {
        console.error(err);
    }
    // NetworkCapabilities check
    try {
        var NCap = Java.use("android.net.NetworkCapabilities");
        NCap.hasTransport.overload("int").implementation = function(values) {
            if (values == 4){
                send("[Debugger Check] HasTransportcheck bypassed")
                return false;
            } else
                return this.hasTransport(values);
        }
    } catch (e) {
        console.error(e);
    }
})
/* Developer Mod Check Bypass */
Java.perform(function() {
    try{
        var SSecure = Java.use("android.provider.Settings$Secure");
        SSecure.getStringForUser.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(Content, Name, Flag) {
            if (Name.indexOf("development_settings_enabled") >= 0) {
                send("[Debugger Check] Developer mode check bypassed for: " + Name)
                return this.getStringForUser.call(this, Content, "bypassed", Flag);
            }
            return this.getStringForUser(Content, Name, Flag);
        }
    } catch(e){}
})

/* Playstore install source check */
Java.perform(function() {
    try{
        var Installer = Java.use("android.app.ApplicationPackageManager");
        Installer.getInstallerPackageName.overload('java.lang.String').implementation = function(Str) {
            var playPkg = "com.android.vending";
            if (Str.toString().indexOf(playPkg) < 0) {
                send("[Debugger Check] Play Store install source check bypassed. Original value: "+ Str.toString());
                return playPkg;
            }
        }
    } catch(e){}
})

/* React Native JailMonkey Detection Bypass */

Java.perform(function() {
    try{
        let hook = Java.use("com.gantix.JailMonkey.JailMonkeyModule")['isDevelopmentSettingsMode'];
        if (hook) {
            hook.overload("com.facebook.react.bridge.Promise").implementation = function(p) {
                p.resolve(Java.use("java.lang.Boolean").$new(false));
            }
        }
        let hook2 = Java.use("com.gantix.JailMonkey.JailMonkeyModule")['isDebuggedMode'];
        if (hook2) {
            hook2.overload("com.facebook.react.bridge.Promise").implementation = function(p) {
                p.resolve(Java.use("java.lang.Boolean").$new(false));
            }
        }
    } catch(e){}
});