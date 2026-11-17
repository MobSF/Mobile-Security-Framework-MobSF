// MobSF Android API Monitor
// Inspired from: https://github.com/realgam3/ReversingAutomation/blob/master/Frida/Android-DynamicHooks/DynamicHooks.js

// [category, class, methods, options]. options.target is the minimum
// Android major version that has the API.
var API_GROUPS = [
    ['Process', 'android.app.ActivityManager', ['killBackgroundProcesses']],
    ['Process', 'android.os.Process', ['killProcess'], { early: true }],
    ['Process', 'java.lang.System', ['exit'], { early: true }],
    ['Command', 'java.lang.Runtime', ['exec']],
    ['Command', 'java.lang.ProcessBuilder', ['start']],
    // System.loadLibrary()/load() resolve the caller's class loader, which
    // breaks when invoked from a hook. The *0 variants take it explicitly.
    ['Java Native Interface', 'java.lang.Runtime', ['loadLibrary0', 'load0'], { target: 7 }],
    ['WebView', 'android.webkit.WebView', [
        'loadUrl', 'loadData', 'loadDataWithBaseURL', 'postUrl', 'evaluateJavascript',
        'addJavascriptInterface', 'removeJavascriptInterface', 'savePassword',
        'setHttpAuthUsernamePassword', 'getHttpAuthUsernamePassword',
        'setWebContentsDebuggingEnabled']],
    ['WebView', 'android.webkit.WebView', ['postWebMessage'], { target: 6 }],
    ['File IO', 'libcore.io.IoBridge', ['open']],
    ['File IO', 'android.content.ContextWrapper', ['openFileInput', 'openFileOutput', 'deleteFile']],
    ['Shared Preferences', 'android.content.ContextWrapper', ['getSharedPreferences']],
    // Hooking SharedPreferencesImpl crashes apps on Android 7.
    ['Shared Preferences', 'android.app.SharedPreferencesImpl', ['getString', 'getStringSet'], { target: 8 }],
    ['Shared Preferences', 'android.app.SharedPreferencesImpl$EditorImpl', [
        'putString', 'putStringSet', 'putInt', 'putLong', 'putFloat', 'putBoolean',
        'remove'], { target: 8 }],
    ['Database', 'android.content.ContextWrapper', ['openOrCreateDatabase', 'databaseList', 'deleteDatabase']],
    ['Database', 'android.database.sqlite.SQLiteDatabase', [
        'execSQL', 'deleteDatabase', 'insert', 'insertOrThrow', 'insertWithOnConflict',
        'openDatabase', 'openOrCreateDatabase', 'query', 'queryWithFactory', 'rawQuery',
        'rawQueryWithFactory', 'update', 'updateWithOnConflict', 'delete',
        'compileStatement', 'create']],
    ['IPC', 'android.content.ContextWrapper', [
        'sendBroadcast', 'sendOrderedBroadcast', 'sendStickyBroadcast', 'startActivity',
        'startService', 'stopService', 'bindService', 'registerReceiver']],
    ['Binder', 'android.app.ContextImpl', ['registerReceiver']],
    ['Binder', 'android.app.ActivityThread', ['handleReceiver']],
    ['Binder', 'android.app.Activity', ['startActivity', 'startActivityForResult']],
    ['Crypto', 'javax.crypto.Cipher', ['getInstance', 'init', 'doFinal']],
    ['Crypto', 'javax.crypto.spec.SecretKeySpec', ['$init']],
    ['Crypto', 'javax.crypto.spec.IvParameterSpec', ['$init']],
    ['Crypto', 'javax.crypto.spec.GCMParameterSpec', ['$init']],
    ['Crypto', 'javax.crypto.spec.PBEKeySpec', ['$init']],
    ['Crypto', 'javax.crypto.Mac', ['getInstance', 'init', 'doFinal']],
    ['Crypto', 'javax.crypto.KeyGenerator', ['getInstance', 'generateKey']],
    ['Crypto', 'java.security.KeyStore', ['getInstance', 'load', 'getKey']],
    ['Crypto - Hash', 'java.security.MessageDigest', ['getInstance', 'update', 'digest']],
    ['Device Info', 'android.telephony.TelephonyManager', [
        'getDeviceId', 'getSubscriberId', 'getLine1Number', 'getNetworkOperator',
        'getNetworkOperatorName', 'getSimOperatorName', 'getSimCountryIso',
        'getSimSerialNumber', 'getNetworkCountryIso', 'getDeviceSoftwareVersion']],
    ['Device Info', 'android.telephony.TelephonyManager', ['getImei', 'getMeid'], { target: 8 }],
    ['Device Info', 'android.net.wifi.WifiInfo', ['getMacAddress', 'getBSSID', 'getSSID', 'getIpAddress', 'getNetworkId']],
    ['Device Info', 'android.provider.Settings$Secure', ['getString']],
    ['Device Info', 'android.bluetooth.BluetoothAdapter', ['getAddress']],
    ['Device Info', 'android.os.Debug', ['isDebuggerConnected']],
    // PackageManager methods are abstract; hook the implementation.
    ['Device Info', 'android.app.ApplicationPackageManager', [
        'getInstallerPackageName', 'getInstalledApplications', 'getInstalledPackages']],
    ['Device Info', 'android.app.ApplicationPackageManager', ['getInstalledModules'], { target: 10 }],
    ['Device Info', 'android.app.ApplicationPackageManager', ['getInstallSourceInfo'], { target: 11 }],
    ['Network', 'java.net.URL', ['openConnection']],
    ['Network', 'com.android.okhttp.internal.huc.HttpURLConnectionImpl', ['getInputStream']],
    ['Network', 'javax.net.ssl.HttpsURLConnection', [
        'setDefaultHostnameVerifier', 'setHostnameVerifier',
        'setDefaultSSLSocketFactory', 'setSSLSocketFactory']],
    ['Network', 'java.net.Socket', ['connect']],
    ['Dex Class Loader', 'dalvik.system.BaseDexClassLoader', ['findResource', 'findResources', 'findLibrary']],
    ['Dex Class Loader', 'dalvik.system.DexFile', ['loadDex', 'loadClass']],
    ['Dex Class Loader', 'dalvik.system.DexClassLoader', ['$init']],
    ['Dex Class Loader', 'dalvik.system.PathClassLoader', ['$init']],
    ['Dex Class Loader', 'dalvik.system.InMemoryDexClassLoader', ['$init'], { target: 8 }],
    ['Base64', 'android.util.Base64', ['decode', 'encode', 'encodeToString']],
    ['Base64', 'java.util.Base64$Decoder', ['decode'], { target: 8 }],
    ['Base64', 'java.util.Base64$Encoder', ['encode', 'encodeToString'], { target: 8 }],
    ['System Manager', 'android.app.ApplicationPackageManager', ['setComponentEnabledSetting']],
    ['System Manager', 'android.app.NotificationManager', ['notify']],
    ['System Manager', 'android.telephony.TelephonyManager', ['listen']],
    ['System Manager', 'android.content.BroadcastReceiver', ['abortBroadcast']],
    ['SMS', 'android.telephony.SmsManager', ['sendTextMessage', 'sendMultipartTextMessage', 'sendDataMessage']],
    ['Device Data', 'android.content.ContentResolver', ['query', 'registerContentObserver', 'insert', 'update', 'delete']],
    ['Device Data', 'android.accounts.AccountManager', ['getAccountsByType', 'getAccounts']],
    ['Device Data', 'android.location.LocationManager', ['getLastKnownLocation', 'requestLocationUpdates']],
    ['Device Data', 'android.location.LocationManager', ['getCurrentLocation'], { target: 11 }],
    ['Device Data', 'android.media.AudioRecord', ['startRecording']],
    ['Device Data', 'android.media.MediaRecorder', ['start']],
    ['Device Data', 'android.hardware.camera2.CameraManager', ['openCamera']],
    ['Device Data', 'android.os.SystemProperties', ['get']]
];

// Libraries bundled inside the APK. Hooked through the app's class loader
// once it exists; absent libraries are skipped silently.
var APP_LIBRARY_GROUPS = [
    ['Network', 'okhttp3.OkHttpClient', ['newCall']],
    ['Network', 'okhttp3.CertificatePinner$Builder', ['add']],
    ['Network', 'com.squareup.okhttp.OkHttpClient', ['newCall']],
    ['Network', 'org.apache.http.impl.client.AbstractHttpClient', ['execute']],
    ['Database', 'net.sqlcipher.database.SQLiteDatabase', ['openOrCreateDatabase', 'openDatabase', 'rawQuery', 'execSQL']],
    ['Database', 'net.zetetic.database.sqlcipher.SQLiteDatabase', ['openOrCreateDatabase', 'openDatabase', 'rawQuery', 'execSQL']]
];

var WEB_SETTINGS_METHODS = [
    'setJavaScriptEnabled', 'setAllowFileAccess', 'setAllowFileAccessFromFileURLs',
    'setAllowUniversalAccessFromFileURLs', 'setAllowContentAccess', 'setMixedContentMode',
    'setSavePassword', 'setGeolocationEnabled', 'setJavaScriptCanOpenWindowsAutomatically'
];

var MAX_BYTES = 1024;
var MAX_ITEMS = 32;
var MAX_STRING = 2048;
var MAX_STACK = 12;
var MAX_BATCH = 50;
var FLUSH_MS = 250;
var INSTANCE_METHOD = 3;
// Frames from these packages are platform or runtime code, not the app.
var FRAMEWORK_PREFIXES = [
    'java.', 'javax.', 'jdk.', 'sun.', 'libcore.', 'dalvik.',
    'android.', 'androidx.', 'com.android.', 'org.apache.harmony.',
    'org.chromium.', 'WV.', 'com.google.android.webview.',
    'kotlin.', 'kotlinx.'
];
// toString() is only called on these; app-defined toString() can be slow,
// throw or have side effects.
var TRUSTED_TOSTRING_PREFIXES = FRAMEWORK_PREFIXES.concat([
    'okhttp3.', 'com.squareup.okhttp.', 'org.apache.http.',
    'net.sqlcipher.', 'net.zetetic.'
]);

var JavaObject, JavaException, JavaLog, JavaThread;
var hooked = {};
// Per-thread stack depth of the hooked calls currently executing.
var activeCalls = {};
// Threads currently formatting an event; hooks fired from toString() are skipped.
var formatting = {};
var queue = [];
var queueIndex = {};
var flushTimer = null;

function expand(groups) {
    var apis = [];
    groups.forEach(function (group) {
        var options = group[3] || {};
        group[2].forEach(function (method) {
            apis.push({
                name: group[0],
                class: group[1],
                method: method,
                target: options.target,
                early: options.early
            });
        });
    });
    return apis;
}

function clip(text) {
    text = String(text);
    return text.length > MAX_STRING ? text.slice(0, MAX_STRING) : text;
}

function hasPrefix(cls, prefixes) {
    for (var i = 0; i < prefixes.length; i++) {
        if (cls.indexOf(prefixes[i]) === 0)
            return true;
    }
    return false;
}

function isFrameworkClass(cls) {
    return hasPrefix(cls, FRAMEWORK_PREFIXES);
}

function getStack() {
    // One JNI call instead of walking StackTraceElement objects.
    var trace = JavaLog.getStackTraceString(JavaException.$new()).split('\n');
    var frames = [];
    for (var i = 0; i < trace.length; i++) {
        var line = trace[i].trim();
        if (line.indexOf('at ') !== 0)
            continue;
        var frame = line.slice(3);
        var paren = frame.indexOf('(');
        var qualified = paren >= 0 ? frame.slice(0, paren) : frame;
        frames.push({
            cls: qualified.slice(0, qualified.lastIndexOf('.')),
            str: frame
        });
    }
    return frames;
}

function shouldLog(tid, frames) {
    if (formatting[tid])
        return false;
    var calls = activeCalls[tid];
    if (!calls || !calls.length)
        return true;
    // Nested hook: log it only if app code sits between it and the outer
    // hooked call, or the outer hook is itself app code (a callback).
    var outer = calls[calls.length - 1];
    if (!frames.length || !outer)
        return false;
    for (var i = 1; i <= frames.length - outer && i < frames.length; i++) {
        if (!isFrameworkClass(frames[i].cls))
            return true;
    }
    return false;
}

function bytesValue(arr) {
    var length = arr.length;
    var count = Math.min(length, MAX_BYTES);
    var hex = '';
    for (var i = 0; i < count; i++)
        hex += ((arr[i] & 0xff) + 0x100).toString(16).slice(1);
    return { $t: 'bytes', len: length, hex: hex };
}

function describeIntentFilter(filter) {
    filter = Java.cast(filter, Java.use('android.content.IntentFilter'));
    var actions = [];
    var schemes = [];
    for (var i = 0; i < filter.countActions() && i < MAX_ITEMS; i++)
        actions.push(filter.getAction(i));
    for (var j = 0; j < filter.countDataSchemes() && j < MAX_ITEMS; j++)
        schemes.push(filter.getDataScheme(j));
    var text = 'IntentFilter { actions=[' + actions.join(', ') + ']';
    if (schemes.length)
        text += ' schemes=[' + schemes.join(', ') + ']';
    return text + ' }';
}

function describeObject(obj) {
    var cls = null;
    var str = null;
    try {
        // Cast so interface-typed wrappers dispatch to the real toString().
        var o = Java.cast(obj, JavaObject);
        cls = o.getClass().getName();
        if (cls === 'android.content.IntentFilter')
            str = describeIntentFilter(obj);
        else if (hasPrefix(cls, TRUSTED_TOSTRING_PREFIXES))
            str = o.toString();
        else
            str = cls;
    } catch (e) {
        if (cls === null) {
            try {
                str = String(obj);
            } catch (_) {}
        }
    }
    return { $t: 'object', cls: cls, str: str === null ? null : clip(str) };
}

function formatValue(value, type) {
    if (value === null || value === undefined)
        return null;
    var kind = typeof value;
    if (kind === 'string')
        return clip(value);
    if (kind === 'number' || kind === 'boolean')
        return value;
    if (type === '[B')
        return bytesValue(value);
    if (type === '[C')
        return clip([].slice.call(value, 0, MAX_STRING).join(''));
    if (type && type.charAt(0) === '[') {
        var element = type.slice(1);
        var count = Math.min(value.length, MAX_ITEMS);
        var items = [];
        for (var i = 0; i < count; i++)
            items.push(formatValue(value[i], element));
        if (value.length > count)
            items.push({ $t: 'more', count: value.length - count });
        return items;
    }
    if (kind === 'object')
        return describeObject(value);
    return clip(String(value));
}

function prefsFile(prefs) {
    var impl = Java.cast(prefs, Java.use('android.app.SharedPreferencesImpl'));
    return impl.mFile.value.getName();
}

// Describes the object an instance method was called on, keyed by hooked class.
var RECEIVERS = {
    'java.security.MessageDigest': function (o) { return o.getAlgorithm(); },
    'javax.crypto.Mac': function (o) { return o.getAlgorithm(); },
    'javax.crypto.KeyGenerator': function (o) { return o.getAlgorithm(); },
    'javax.crypto.Cipher': function (o) { return o.toString(); },
    'java.security.KeyStore': function (o) { return o.getType(); },
    'android.database.sqlite.SQLiteDatabase': function (o) { return o.getPath(); },
    'net.sqlcipher.database.SQLiteDatabase': function (o) { return o.getPath(); },
    'net.zetetic.database.sqlcipher.SQLiteDatabase': function (o) { return o.getPath(); },
    'java.net.URL': function (o) { return o.toString(); },
    'java.net.Socket': function (o) { return o.toString(); },
    'com.android.okhttp.internal.huc.HttpURLConnectionImpl': function (o) { return o.getURL().toString(); },
    'javax.net.ssl.HttpsURLConnection': function (o) { return o.getURL().toString(); },
    'android.app.SharedPreferencesImpl': function (o) { return prefsFile(o); },
    'android.app.SharedPreferencesImpl$EditorImpl': function (o) {
        var editor = Java.cast(o, Java.use('android.app.SharedPreferencesImpl$EditorImpl'));
        return prefsFile(editor.this$0.value);
    },
    'android.content.ContextWrapper': function (o) { return Java.cast(o, JavaObject).getClass().getName(); },
    'android.app.Activity': function (o) { return Java.cast(o, JavaObject).getClass().getName(); }
};

function describeReceiver(api, self) {
    var describe = RECEIVERS[api.class];
    if (!describe || !self || self.$h === null)
        return null;
    try {
        return clip(describe(Java.cast(self, api.wrapper)));
    } catch (e) {
        return null;
    }
}

function flush() {
    if (flushTimer !== null) {
        clearTimeout(flushTimer);
        flushTimer = null;
    }
    if (!queue.length)
        return;
    send('MobSF-API-Monitor: ' + JSON.stringify({ events: queue }));
    queue = [];
    queueIndex = {};
}

function enqueue(message) {
    // Identical calls within one flush window are sent once with a count.
    var key = JSON.stringify([
        message.class, message.method, message.arguments, message.returnValue,
        message.exception, message.instance, message.calledFrom
    ]);
    var index = queueIndex[key];
    if (index !== undefined) {
        queue[index].count++;
        return;
    }
    message.count = 1;
    queueIndex[key] = queue.length;
    queue.push(message);
    if (queue.length >= MAX_BATCH)
        flush();
    else if (flushTimer === null)
        flushTimer = setTimeout(flush, FLUSH_MS);
}

function report(api, overload, self, args, retval, error, frames, tid) {
    formatting[tid] = true;
    try {
        var formatted = [];
        for (var i = 0; i < args.length && i < MAX_ITEMS; i++)
            formatted.push(formatValue(args[i], overload.argTypes[i]));
        // Hooks on app classes (callbacks) are app code themselves.
        var app = !isFrameworkClass(api.class);
        var calledFrom = frames.length > 1 ? frames[1].str : '';
        for (var j = 1; j < frames.length; j++) {
            if (!isFrameworkClass(frames[j].cls)) {
                calledFrom = frames[j].str;
                app = true;
                break;
            }
        }
        var message = {
            name: api.name,
            class: api.class,
            method: api.method,
            argumentTypes: overload.argTypes,
            arguments: formatted,
            calledFrom: calledFrom,
            app: app,
            stack: frames.slice(1, 1 + MAX_STACK).map(function (f) { return f.str; }),
            thread: JavaThread.currentThread().getName(),
            timestamp: Date.now()
        };
        if (overload.isInstance) {
            var instance = describeReceiver(api, self);
            if (instance !== null)
                message.instance = instance;
        }
        if (error !== null)
            message.exception = clip(error);
        else if (overload.retType !== 'void' && !api.early)
            message.returnValue = formatValue(retval, overload.retType);
        enqueue(message);
    } finally {
        delete formatting[tid];
    }
}

function hookOverload(api, overload) {
    var info = {
        argTypes: overload.argumentTypes.map(function (t) { return t.className; }),
        retType: overload.returnType.className,
        isInstance: overload.type === INSTANCE_METHOD
    };
    // Another default script (root/SSL/debugger bypass) may already replace
    // this method; call through it so the bypass keeps working.
    var previous = overload.implementation;
    overload.implementation = function () {
        var tid = Process.getCurrentThreadId();
        var frames = [];
        var log = false;
        if (!api.silent) {
            try {
                frames = getStack();
                log = shouldLog(tid, frames);
            } catch (e) {}
        }
        if (api.before) {
            try {
                api.before(arguments);
            } catch (e) {}
        }
        if (log && api.early) {
            // The call terminates the process; report and flush first.
            try {
                report(api, info, this, arguments, undefined, null, frames, tid);
            } catch (e) {}
            flush();
            log = false;
        }
        // Silent hooks wrap app code (e.g. Application.onCreate) and must not
        // count as an outer call, or every nested app call would be dropped.
        var calls = null;
        if (!api.silent) {
            calls = activeCalls[tid] || (activeCalls[tid] = []);
            calls.push(frames.length);
        }
        var retval;
        var error = null;
        try {
            retval = previous !== null
                ? previous.apply(this, arguments)
                : overload.apply(this, arguments);
        } catch (e) {
            error = e;
        } finally {
            if (calls !== null) {
                calls.pop();
                if (!calls.length)
                    delete activeCalls[tid];
            }
        }
        if (api.after && error === null) {
            try {
                api.after(retval, arguments);
            } catch (e) {}
        }
        if (log) {
            try {
                report(api, info, this, arguments, retval, error, frames, tid);
            } catch (e) {}
        }
        if (error !== null)
            throw error;
        return retval;
    };
}

// Returns the class.method names that could not be hooked.
function installHooks(apis, factory) {
    var missing = [];
    var version = parseInt(Java.androidVersion, 10);
    apis.forEach(function (api) {
        var id = api.class + '.' + api.method;
        if (hooked[id] || (api.target && version < api.target))
            return;
        var target;
        try {
            api.wrapper = factory.use(api.class);
            target = api.wrapper[api.method];
        } catch (e) {}
        if (!target || !target.overloads) {
            missing.push(id);
            return;
        }
        try {
            target.overloads.forEach(function (overload) {
                hookOverload(api, overload);
            });
            hooked[id] = true;
        } catch (err) {
            send('[API Monitor] - ERROR: ' + id + ' ["Error"] => ' + err);
        }
    });
    return missing;
}

// Hooks methods on the runtime class of obj, e.g. the WebView provider's
// WebSettings implementation or an app's WebViewClient subclass.
function hookRuntimeClass(obj, name, methods, options) {
    if (!obj)
        return;
    var klass = Java.cast(obj, JavaObject).getClass();
    methods.forEach(function (method) {
        // Hook inherited methods on their declaring class: Frida only chains
        // replacements made through the same (cached) class wrapper, e.g. the
        // SSL bypass on WebViewClient.onReceivedSslError.
        var owner = declaringClass(klass, method);
        var loader = owner.getClassLoader();
        var api = { name: name, class: owner.getName(), method: method };
        if (options && options[method])
            api.before = options[method];
        installHooks([api], loader ? Java.ClassFactory.get(loader) : Java.classFactory);
    });
}

function declaringClass(klass, method) {
    for (var c = klass; c !== null; c = c.getSuperclass()) {
        var declared = c.getDeclaredMethods();
        for (var i = 0; i < declared.length; i++) {
            if (declared[i].getName() === method)
                return c;
        }
    }
    return klass;
}

function installAppLibraryHooks(loader) {
    if (!loader)
        return;
    try {
        installHooks(expand(APP_LIBRARY_GROUPS), Java.ClassFactory.get(loader));
    } catch (e) {}
}

function installDynamicHooks() {
    installHooks([{
        name: 'WebView',
        class: 'android.webkit.WebView',
        method: 'getSettings',
        silent: true,
        after: function (settings) {
            hookRuntimeClass(settings, 'WebView', WEB_SETTINGS_METHODS);
        }
    }, {
        name: 'WebView',
        class: 'android.webkit.WebView',
        method: 'setWebViewClient',
        after: function (retval, args) {
            hookRuntimeClass(args[0], 'WebView', ['onReceivedSslError'], {
                onReceivedSslError: function (callArgs) {
                    hookRuntimeClass(callArgs[1], 'WebView', ['proceed', 'cancel']);
                }
            });
        }
    }, {
        name: 'Process',
        class: 'android.app.Instrumentation',
        method: 'callApplicationOnCreate',
        silent: true,
        before: function (args) {
            installAppLibraryHooks(args[0].getClassLoader());
        }
    }], Java.classFactory);
}


// Pending events are sent before the host force-stops or unloads the script.
rpc.exports.flushApiMonitor = flush;
rpc.exports.dispose = flush;

// Java.perform (not performNow) queues this after the bypass scripts'
// Java.perform callbacks, so the hooks above chain to their replacements.
Java.perform(function () {
    JavaObject = Java.use('java.lang.Object');
    JavaException = Java.use('java.lang.Exception');
    JavaLog = Java.use('android.util.Log');
    JavaThread = Java.use('java.lang.Thread');
    var missing = installHooks(expand(API_GROUPS), Java.classFactory);
    if (missing.length)
        send('[API Monitor] Not available on this device: ' + missing.join(', '));
    installDynamicHooks();
    // Attached to an already running app: its class loader exists now.
    try {
        var app = Java.use('android.app.ActivityThread').currentApplication();
        if (app)
            installAppLibraryHooks(app.getClassLoader());
    } catch (e) {}
});
