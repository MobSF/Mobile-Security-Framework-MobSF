Java.perform(function() {

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
        
        send("--------------------\n[Base64] Encode: " + JSON.stringify(arr));
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
        return b64DefEncode_2.call(this, arr, flag);
    };
    
    b64DefEncode_3.implementation = function(arr, off, len, flag) {
        
        send("--------------------\n[Base64] Encode: [" + off + "," + len + "] " + JSON.stringify(arr));
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
        return b64DefEncode_3.call(this, arr, off, len, flag);
    };


    // Base64 Encode to String Hooks
    b64DefEncodeToString_2.implementation = function(arr, flag) {
        
        send("--------------------\n[Base64] EncodeToString: " + JSON.stringify(arr));
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
        return b64DefEncodeToString_2.call(this, arr, flag);
    };

    b64DefEncodeToString_3.implementation = function(arr, off, len, flag) {
        
        send("--------------------\n[Base64] EncodeToString: [" + off + "," + len + "] " + JSON.stringify(arr));
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
        return b64DefEncodeToString_3.call(this, arr, off, len, flag);
    };


    // Base64 Decoding Hooks
    b64DefDecode_1.implementation = function(str, flag) {
        send("--------------------\n[Base64] Decode: " + str);
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
        return b64DefDecode_1.call(this, str, flag);
    };

    b64DefDecode_2.implementation = function(arr, flag) {
        
        send("--------------------\n[Base64] Decode: " + JSON.stringify(arr));
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
        return b64DefDecode_2.call(this, arr, flag);
    };

    b64DefDecode_3.implementation = function(arr, off, len, flag) {
        
        send("--------------------\n[Base64] Decode: [" + off + "," + len + "] " + JSON.stringify(arr));
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
        return b64DefDecode_3.call(this, arr, off, len, flag);
    };
});