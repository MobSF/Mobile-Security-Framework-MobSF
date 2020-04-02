// MobSF Android API Monitor
// Inspired from: https://github.com/realgam3/ReversingAutomation/blob/master/Frida/Android-DynamicHooks/DynamicHooks.js
var apis = [{
    class: 'android.os.Process',
    method: 'start',
    name: 'Process'
}, {
    class: 'android.app.ActivityManager',
    method: 'killBackgroundProcesses',
    name: 'Process'
}, {
    class: 'android.os.Process',
    method: 'killProcess',
    name: 'Process'
}, {
    class: 'java.lang.Runtime',
    method: 'exec',
    name: 'Command'
}, {
    class: 'java.lang.ProcessBuilder',
    method: 'start',
    name: 'Command'
}, {
    class: 'java.lang.Runtime',
    method: 'loadLibrary',
    name: 'Java Native Interface'
}, {
    class: 'java.lang.Runtime',
    method: 'load',
    name: 'Java Native Interface'
}, {
    class: 'android.webkit.WebView',
    method: 'loadUrl',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'loadData',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'loadDataWithBaseURL',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'addJavascriptInterface',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'evaluateJavascript',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'postUrl',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'postWebMessage',
    name: 'WebView',
    target: 6
}, {
    class: 'android.webkit.WebView',
    method: 'savePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'setHttpAuthUsernamePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'getHttpAuthUsernamePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'setWebContentsDebuggingEnabled',
    name: 'WebView'
}, {
    class: 'libcore.io.IoBridge',
    method: 'open',
    name: 'File IO'
},
/* {
    // so much calls
    class: 'java.io.FileOutputStream',
    method: 'write',
    name: 'File IO'
}, {
    class: 'java.io.FileInputStream',
    method: 'read',
    name: 'File IO'
}, */
{
    class: 'android.content.ContextWrapper',
    method: 'openFileInput',
    name: 'File IO'
}, {
    class: 'android.content.ContextWrapper',
    method: 'openFileOutput',
    name: 'File IO'
}, {
    class: 'android.content.ContextWrapper',
    method: 'deleteFile',
    name: 'File IO'
},
/*
// crashes app on android 7
{
    class: 'android.app.SharedPreferencesImpl',
    method: 'getString',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'contains',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getInt',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getFloat',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getLong',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getBoolean',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getStringSet',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putString',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putStringSet',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putInt',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putFloat',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putBoolean',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putLong',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'remove',
    name: 'File IO - Shared Preferences'
},
*/
{
    class: 'android.content.ContextWrapper',
    method: 'openOrCreateDatabase',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'databaseList',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'deleteDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'execSQL',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'deleteDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'getPath',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insert',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insertOrThrow',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insertWithOnConflict',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'openDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'openOrCreateDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'query',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'queryWithFactory',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'rawQuery',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'rawQueryWithFactory',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'update',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'updateWithOnConflict',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'compileStatement',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'create',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'sendBroadcast',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'sendStickyBroadcast',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'startActivity',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'startService',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'stopService',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'registerReceiver',
    name: 'IPC'
}, {
    class: 'android.app.ContextImpl',
    method: 'registerReceiver',
    name: 'Binder'
}, {
    class: 'android.app.ActivityThread',
    method: 'handleReceiver',
    name: 'Binder'
}, {
    class: 'android.app.Activity',
    method: 'startActivity',
    name: 'Binder'
}, {
    class: 'javax.crypto.spec.SecretKeySpec',
    method: '$init',
    name: 'Crypto'
}, {
    class: 'javax.crypto.Cipher',
    method: 'doFinal',
    name: 'Crypto'
}, {
    class: 'java.security.MessageDigest',
    method: 'digest',
    name: 'Crypto - Hash'
}, {
    class: 'java.security.MessageDigest',
    method: 'update',
    name: 'Crypto - Hash'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getDeviceId',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSubscriberId',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getLine1Number',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkOperator',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkOperatorName',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimOperatorName',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getMacAddress',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getBSSID',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getIpAddress',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getNetworkId',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimCountryIso',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimSerialNumber',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkCountryIso',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getDeviceSoftwareVersion',
    name: 'Device Info'
}, {
    class: 'android.os.Debug',
    method: 'isDebuggerConnected',
    name: 'Device Info'
}, {
    class: 'android.content.pm.PackageManager',
    method: 'getInstallerPackageName',
    name: 'Device Info'
}, {
    class: 'android.content.pm.PackageManager',
    method: 'getInstalledApplications',
    name: 'Device Info'
}, {
    class: 'android.content.pm.PackageManager',
    method: 'getInstalledModules',
    name: 'Device Info',
    target: 10,
}, {
    class: 'android.content.pm.PackageManager',
    method: 'getInstalledPackages',
    name: 'Device Info'
}, {
    class: 'java.net.URL',
    method: 'openConnection',
    name: 'Network'
}, {
    class: 'org.apache.http.impl.client.AbstractHttpClient',
    method: 'execute',
    name: 'Network'
}, {
    class: 'com.android.okhttp.internal.huc.HttpURLConnectionImpl',
    method: 'getInputStream',
    name: 'Network'
}, {
    class: 'com.android.okhttp.internal.http.HttpURLConnectionImpl',
    method: 'getInputStream',
    name: 'Network'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findResource',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findResources',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findLibrary',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexFile',
    method: 'loadDex',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexFile',
    method: 'loadClass',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexClassLoader',
    method: '$init',
    name: 'Dex Class Loader'
}, {
    class: 'android.util.Base64',
    method: 'decode',
    name: 'Base64'
}, {
    class: 'android.util.Base64',
    method: 'encode',
    name: 'Base64'
}, {
    class: 'android.util.Base64',
    method: 'encodeToString',
    name: 'Base64'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'setComponentEnabledSetting',
    name: 'System Manager'
}, {
    class: 'android.app.NotificationManager',
    method: 'notify',
    name: 'System Manager'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'listen',
    name: 'System Manager'
}, {
    class: 'android.content.BroadcastReceiver',
    method: 'abortBroadcast',
    name: 'System Manager'
}, {
    class: 'android.telephony.SmsManager',
    method: 'sendTextMessage',
    name: 'SMS'
}, {
    class: 'android.telephony.SmsManager',
    method: 'sendMultipartTextMessage',
    name: 'SMS'
}, {
    class: 'android.content.ContentResolver',
    method: 'query',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'registerContentObserver',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'insert',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'delete',
    name: 'Device Data'
}, {
    class: 'android.accounts.AccountManager',
    method: 'getAccountsByType',
    name: 'Device Data'
}, {
    class: 'android.accounts.AccountManager',
    method: 'getAccounts',
    name: 'Device Data'
}, {
    class: 'android.location.Location',
    method: 'getLatitude',
    name: 'Device Data'
}, {
    class: 'android.location.Location',
    method: 'getLongitude',
    name: 'Device Data'
}, {
    class: 'android.media.AudioRecord',
    method: 'startRecording',
    name: 'Device Data'
}, {
    class: 'android.media.MediaRecorder',
    method: 'start',
    name: 'Device Data'
}, {
    class: 'android.os.SystemProperties',
    method: 'get',
    name: 'Device Data'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getInstalledPackages',
    name: 'Device Data'
}
];

// Dynamic Hooks
function hook(api, callback) {
    var Exception = Java.use('java.lang.Exception');
    var toHook;
    try {
        var clazz = api.class;
        var method = api.method;
        var name = api.name;
        try {
            if (api.target && parseInt(Java.androidVersion, 10) < api.target) {
                // send('[API Monitor] Not Hooking unavailable class/method - ' + clazz + '.' + method)
                return
            }
            // Check if class and method is available
            toHook = Java.use(clazz)[method];
            if (!toHook) {
                send('[API Monitor] Cannot find ' + clazz + '.' + method);
                return
            }
        } catch (err) {
            send('[API Monitor] Cannot find ' + clazz + '.' + method);
            return
        }
        var overloadCount = toHook.overloads.length;
        for (var i = 0; i < overloadCount; i++) {
            toHook.overloads[i].implementation = function () {
                var argz = [].slice.call(arguments);
                // Call original function
                var retval = this[method].apply(this, arguments);
                if (callback) {
                    var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
                    var message = {
                        name: name,
                        class: clazz,
                        method: method,
                        arguments: argz,
                        result: retval ? retval.toString() : null,
                        calledFrom: calledFrom
                    };
                    retval = callback(retval, message);
                }
                return retval;
            }
        }
    } catch (err) {
        send('[API Monitor] - ERROR: ' + clazz + "." + method + " [\"Error\"] => " + err);
    }
}


Java.performNow(function () {
    apis.forEach(function (api, _) {
        hook(api, function (originalResult, message) {
            /*if (!message.name.includes('Database') &&
                !message.name.includes('Crypto - Hash') &&
                !message.name.includes('File IO - Shared Preferences') &&
                !message.name.includes('File IO') &&
                !message.name.includes('IPC')) {
            */
            message.returnValue = originalResult
            if (originalResult && typeof originalResult === 'object') {
                var s = [];
                for (var k = 0, l = originalResult.length; k < l; k++) {
                    s.push(originalResult[k]);
                }
                message.returnValue = '' + s.join('');
            }
            if (!message.result)
                message.result = undefined
            if (!message.returnValue)
                message.returnValue = undefined
            var msg = 'MobSF-API-Monitor: ' + JSON.stringify(message);
            send(msg + ',');
            return originalResult;
        });
    });
});
