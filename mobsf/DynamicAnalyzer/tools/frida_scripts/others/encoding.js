// Adapted from https://codeshare.frida.re/@masihyeganeh/re/

Java.perform(function() {

    // Print Initalisation
    send("[Initialised] Base64");

    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };


    // Declaring Android Objects
    var b64Def = Java.use('android.util.Base64');

    var b64DefEncode_2 = b64Def.encode.overload('[B', 'int');
    var b64DefEncode_3 = b64Def.encode.overload('[B', 'int', 'int', 'int');

    var b64DefEncodeToString_2 = b64Def.encodeToString.overload('[B', 'int');
    var b64DefEncodeToString_3 = b64Def.encodeToString.overload('[B', 'int', 'int', 'int');

    var b64DefDecode_1 = b64Def.decode.overload('java.lang.String', 'int');
    var b64DefDecode_2 = b64Def.decode.overload('[B', 'int');
    var b64DefDecode_3 = b64Def.decode.overload('[B', 'int', 'int', 'int');


    // Base64 Encoding Hooks
    b64DefEncode_2.implementation = function(arr, flag) {
        var result = b64DefEncode_2.call(this, arr, flag);
        send("[Base64] Encode: " + JSON.stringify(arr) + " | Result: " + result);
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };
    
    b64DefEncode_3.implementation = function(arr, off, len, flag) {
        var result = b64DefEncode_3.call(this, arr, off, len, flag);
        send("[Base64] Encode: [" + off + "," + len + "] " + JSON.stringify(arr) + "\n[Base64] Result: " + result);
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };


    // Base64 Encode to String Hooks
    b64DefEncodeToString_2.implementation = function(arr, flag) {
        var result = b64DefEncodeToString_2.call(this, arr, flag);
        send("[Base64] EncodeToString: " + JSON.stringify(arr) + " | Result: " + result);
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };

    b64DefEncodeToString_3.implementation = function(arr, off, len, flag) {
        var result = b64DefEncodeToString_3.call(this, arr, off, len, flag);
        send("[Base64] EncodeToString: [" + off + "," + len + "] " + JSON.stringify(arr) + " | Result: " + result);
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };


    // Base64 Decoding Hooks
    b64DefDecode_1.implementation = function(str, flag) {
        var result = b64DefDecode_1.call(this, str, flag);
        send("[Base64] Decode: " + str + " | Result : " + result + " (" + b2s(result) + ")");
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };

    b64DefDecode_2.implementation = function(arr, flag) {
        var result = b64DefDecode_2.call(this, arr, flag);
        send("[Base64] Decode: " + JSON.stringify(arr) + " | Result : " + result + " (" + b2s(result) + ")");
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };

    b64DefDecode_3.implementation = function(arr, off, len, flag) {
        var result = b64DefDecode_3.call(this, arr, off, len, flag);
        send("[Base64] Decode: [" + off + "," + len + "] " + JSON.stringify(arr) + " | Result : " + result + " (" + b2s(result) + ")");
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };


    // Formatting functions
    function b2s(array) {
        var result = "";
        for (var i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }

    function modulus(x, n) {
        return ((x % n) + n) % n;
    }
});