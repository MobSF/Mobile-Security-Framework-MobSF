// Safe Frida script: Hooks android.util.Log and liblog.so functions
function safeToString(obj) {
    return obj ? obj.toString() : "[null]";
}

function safeReadCString(ptr) {
    try {
        if (ptr.isNull()) return "[NULL]";
        return ptr.readCString();
    } catch (_) {
        return "[INVALID PTR]";
    }
}

Java.performNow(function () {
    try {
        const Log = Java.use("android.util.Log");

        Log.d.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
            console.log("[Log.d]", safeToString(a), safeToString(b));
            return this.d(a, b);
        };

        Log.d.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
            console.log("[Log.d]", safeToString(a), safeToString(b));
            return this.d(a, b, c);
        };

        Log.v.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
            console.log("[Log.v]", safeToString(a), safeToString(b));
            return this.v(a, b);
        };

        Log.v.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
            console.log("[Log.v]", safeToString(a), safeToString(b));
            return this.v(a, b, c);
        };

        Log.i.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
            console.log("[Log.i]", safeToString(a), safeToString(b));
            return this.i(a, b);
        };

        Log.i.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
            console.log("[Log.i]", safeToString(a), safeToString(b));
            return this.i(a, b, c);
        };

        Log.e.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
            console.log("[Log.e]", safeToString(a), safeToString(b));
            return this.e(a, b);
        };

        Log.e.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
            console.log("[Log.e]", safeToString(a), safeToString(b));
            return this.e(a, b, c);
        };

        Log.w.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
            console.log("[Log.w]", safeToString(a), safeToString(b));
            return this.w(a, b);
        };

        Log.w.overload("java.lang.String", "java.lang.Throwable").implementation = function (a, b) {
            console.log("[Log.w]", safeToString(a));
            return this.w(a, b);
        };

        Log.w.overload("java.lang.String", "java.lang.String", "java.lang.Throwable").implementation = function (a, b, c) {
            console.log("[Log.w]", safeToString(a), safeToString(b));
            return this.w(a, b, c);
        };

        Log.wtf.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
            console.log("[Log.wtf]", safeToString(a), safeToString(b));
            return this.wtf.overload("java.lang.String", "java.lang.String").call(this, a, b);
        };

        Log.println.overload("int", "java.lang.String", "java.lang.String").implementation = function (a, b, c) {
            console.log("[Log.println]", a.toString(), safeToString(b), safeToString(c));
            return this.println(a, b, c);
        };
    } catch (e) {
        console.error("Java hook error:", e);
    }
});

try {
    const liblog = Process.getModuleByName("liblog.so");
    const LogPrint = liblog.getExportByName("__android_log_print");
    const LogWrite = liblog.getExportByName("__android_log_write");
    const LogVPrint = liblog.getExportByName("__android_log_vprint");
    const LogAssert = liblog.getExportByName("__android_log_assert");

    Interceptor.attach(LogPrint, {
        onEnter: function (args) {
            console.log("[liblog] Print:", safeReadCString(args[1]), safeReadCString(args[2]));
        }
    });

    Interceptor.attach(LogWrite, {
        onEnter: function (args) {
            console.log("[liblog] Write:", safeReadCString(args[1]), safeReadCString(args[2]));
        }
    });

    Interceptor.attach(LogVPrint, {
        onEnter: function (args) {
            console.log("[liblog] VPrint:", safeReadCString(args[1]), safeReadCString(args[2]));
        }
    });

    Interceptor.attach(LogAssert, {
        onEnter: function (args) {
            console.log("[liblog] Assert:", safeReadCString(args[0]), safeReadCString(args[1]));
        }
    });
} catch (e) {
    console.error("Error hooking liblog.so functions:", e);
}