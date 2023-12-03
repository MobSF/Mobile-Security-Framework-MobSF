/*

Source: https://github.com/FSecureLABS/android-keystore-audit/tree/master/frida-scripts
Cipher class hooks + utilities. 
Hooks will attempt to trace calls to Cipher class and hexdump buffer passed/returned during encryption/decryption.

All instances of Cipher class are captured by hooking any getInstance() call. You can them it in the cipherList variable.

Utilities:

ListCiphers()
* List Cipher instances collected in cipherList

GetCipher(cipherName)
* Get Cipher instance from cipherList using it's name 
* example: GetCipher("javax.crypto.Cipher@b6859ee")

doUpdate(cipherName, bytes)
* Call doUpdate on Cipher instance from cipherList using it's name
* you can pass buffer into it which will be processed.
* The bytes buffer must be Java [B
* Example: doUpdate('javax.crypto.Cipher@b6859ee', buffer)

doFinal(cipherName)
* Call doFinal on Cipher instance from cipherList using it's name
* Example: doFinal('javax.crypto.Cipher@b6859ee')

*/

send("[AUXILIARY] [TRACER CIPHER] Cipher hooks loaded!");

Java.perform(function () {
    hookCipherGetInstance();
    hookCipherGetInstance2();
    hookCipherGetInstance3();
    hookCipherInit();
    hookCipherInit2();
    hookCipherInit3();
    hookCipherInit4();
    hookCipherInit5();
    hookCipherInit6();
    hookCipherInit7();
    hookCipherInit8();
    hookDoFinal();
    hookDoFinal2();
    hookDoFinal3();
    hookDoFinal4();
    hookDoFinal5();
    hookDoFinal6();
    hookDoFinal7();
    hookUpdate();
    hookUpdate2();
    hookUpdate3();
    hookUpdate4();
    hookUpdate5();


});



var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');


});

/*
    .overload('java.lang.String')
    .overload('java.lang.String', 'java.security.Provider')
    .overload('java.lang.String', 'java.lang.String')
*/
function hookCipherGetInstance() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload("java.lang.String");
    cipherGetInstance.implementation = function (type) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.getInstance()]: type: " + type);
        var tmp = this.getInstance(type);
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.getInstance()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}


function hookCipherGetInstance2() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String', 'java.security.Provider');
    cipherGetInstance.implementation = function (transforamtion, provider) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.getInstance2()]: transforamtion: " + transforamtion + ",  provider: " + provider);
        var tmp = this.getInstance(transforamtion, provider);
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.getInstance2()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}

function hookCipherGetInstance3() {
    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String', 'java.lang.String');
    cipherGetInstance.implementation = function (transforamtion, provider) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.getInstance3()]: transforamtion: " + transforamtion + ",  provider: " + provider);
        var tmp = this.getInstance(transforamtion, provider);
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.getInstance3()]:  cipherObj: " + tmp);
        cipherList.push(tmp);
        return tmp;
    }
}


/*

    .overload('int', 'java.security.cert.Certificate')
    .overload('int', 'java.security.Key')
    .overload('int', 'java.security.Key', 'java.security.AlgorithmParameters')
    //.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
    .overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom')
    .overload('int', 'java.security.Key', 'java.security.SecureRandom')
    .overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom')
    .overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom')
*/
function hookCipherInit() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.cert.Certificate');
    cipherInit.implementation = function (mode, cert) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.init()]: mode: " + decodeMode(mode) + ", cert: " + cert + " , cipherObj: " + this);
        var tmp = this.init(mode, cert);
    }
}

function hookCipherInit2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key');
    cipherInit.implementation = function (mode, secretKey) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey);
    }
}

function hookCipherInit3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.AlgorithmParameters');
    cipherInit.implementation = function (mode, secretKey, alParam) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, alParam);
    }
}

function hookCipherInit4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
    cipherInit.implementation = function (mode, secretKey, spec) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, spec);
    }
}

function hookCipherInit5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, cert, secureRandom) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.init()]: mode: " + decodeMode(mode) + ", cert: " + cert + " secureRandom:" + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, cert, secureRandom);
    }
}

function hookCipherInit6() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, secureRandom) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " secureRandom:" + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, secureRandom);
    }
}

function hookCipherInit7() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, spec, secureRandom) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " secureRandom: " + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, spec, secureRandom);
    }
}

function hookCipherInit8() {
    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom');
    cipherInit.implementation = function (mode, secretKey, alParam, secureRandom) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " secureRandom: " + secureRandom + " , cipherObj: " + this);
        var tmp = this.init(mode, secretKey, alParam, secureRandom);
    }
}

/*
    .overload()
    .overload('[B')
    .overload('[B', 'int')
    .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
    .overload('[B', 'int', 'int')
    .overload('[B', 'int', 'int', '[B')
    .overload('[B', 'int', 'int', '[B', 'int')
*/

function hookDoFinal() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload();
    cipherInit.implementation = function () {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.doFinal()]: " + "  cipherObj: " + this);
        var tmp = this.doFinal();
        dumpByteArray('Result', tmp);
        return tmp;
    }
}

function hookDoFinal2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B');
    cipherInit.implementation = function (byteArr) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.doFinal2()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.doFinal(byteArr);
        dumpByteArray('Result', tmp);
        return tmp;
    }
}

function hookDoFinal3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int');
    cipherInit.implementation = function (byteArr, a1) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.doFinal3()]: " + "  cipherObj: " + this);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.doFinal(byteArr, a1);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        return tmp;
    }
}

function hookDoFinal4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    cipherInit.implementation = function (a1, a2) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.doFinal4()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', a1.array());
        var tmp = this.doFinal(a1, a2);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', a2.array());
        return tmp;
    }
}

function hookDoFinal5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int');
    cipherInit.implementation = function (byteArr, a1, a2) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.doFinal5()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', tmp);
        return tmp;
    }
}

function hookDoFinal6() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.doFinal6()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2, outputArr);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', outputArr);

        return tmp;
    }
}

function hookDoFinal7() {
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B', 'int');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.doFinal7()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.doFinal(byteArr, a1, a2, outputArr, a4);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', outputArr);
        return tmp;
    }
}

/*
    .overload('[B')
    .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
    .overload('[B', 'int', 'int')
    .overload('[B', 'int', 'int', '[B')
    .overload('[B', 'int', 'int', '[B', 'int')
*/
function hookUpdate() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B');
    cipherInit.implementation = function (byteArr) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.update()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.update(byteArr);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', tmp);
        return tmp;
    }
}

function hookUpdate2() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    cipherInit.implementation = function (byteArr, outputArr) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.update2()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr.array());
        var tmp = this.update(byteArr, outputArr);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', outputArr.array());
        return tmp;
    }
}

function hookUpdate3() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int');
    cipherInit.implementation = function (byteArr, a1, a2) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.update3()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.update(byteArr, a1, a2);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', tmp);
        return tmp;
    }
}

function hookUpdate4() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.update4()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.update(byteArr, a1, a2, outputArr);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', outputArr);
        return tmp;
    }
}

function hookUpdate5() {
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B', 'int');
    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
        send("[AUXILIARY] [TRACER CIPHER] [Cipher.update5()]: " + "  cipherObj: " + this);
        dumpByteArray('In buffer (cipher: ' + this.getAlgorithm() +')', byteArr);
        var tmp = this.update(byteArr, a1, a2, outputArr, a4);
        dumpByteArray('Out buffer (cipher: ' + this.getAlgorithm() +')', outputArr);
        return tmp;
    }
}

/*
* List Cipher instances collected in cipherList   
*/
function ListCiphers() {
    Java.perform(function () {
        for (var i = 0; i < cipherList.length; i++) {
            send("[AUXILIARY] [TRACER CIPHER] [" + i + "] " + cipherList[i]);
        }
    });
    return "[done]";
}

/*
* Get Cipher instance from cipherList using it's name e.g. Cipger.toString() (like: Cipher@a0b1c2)   
* Example: GetCipher('Cipher@a0b1c2')
*/
function GetCipher(cipherName) {
    var result = null;
    Java.perform(function () {
        for (var i = 0; i < cipherList.length; i++) {
            if (cipherName.localeCompare("" + cipherList[i]) == 0)
                result = cipherList[i];
        }
    });
    return result;
}

/*
* Call doUpdate on Cipher instance from cipherList using it's name e.g. Cipger.toString() (like: Cipher@a0b1c2), you can pass buffer into it which will be processed.
* The bytes buffer must be Java [B   
* Example: doUpdate('Cipher@a0b1c2', buffer)
*/
function doUpdate(cipherName, bytes) {
    Java.perform(function () {
        var cipher = GetCipher(cipherName);
        cipher.update(bytes);
        //cipher.doFinal();
    });
}

/*
* Call doFinal on Cipher instance from cipherList using it's name e.g. Cipger.toString() (like: Cipher@a0b1c2)
* Example: doFinal('Cipher@a0b1c2')
*/
function doFinal(cipherName) {
    Java.perform(function () {
        var cipher = GetCipher(cipherName);
        cipher.final(bytes);
        //cipher.doFinal();
    });
}

function decodeMode(mode) {
    if (mode == 1)
        return "Encrypt mode";
    else if (mode == 2)
        return "Decrypt mode";
    else if (mode == 3)
        return "Wrap mode";
    else if (mode == 4)
        return "Unwrap mode";
}

/* All below is hexdump implementation*/
function dumpByteArray(title, byteArr) {
    if (byteArr != null) {
        try {
            var buff = new ArrayBuffer(byteArr.length)
            var dtv = new DataView(buff)
            for (var i = 0; i < byteArr.length; i++) {
                dtv.setUint8(i, byteArr[i]); // Frida sucks sometimes and returns different byteArr.length between ArrayBuffer(byteArr.length) and for(..; i < byteArr.length;..). It occured even when Array.copyOf was done to work on copy.
            }
            send(title + ":\n");
            send(hexdumpJS(dtv.buffer, 0, byteArr.length))
        } catch (error) { send("[AUXILIARY] [TRACER CIPHER] Exception has occured in hexdump") }
    }
    else {
        send("[AUXILIARY] [TRACER CIPHER] byteArr is null!");
    }
}

function _fillUp(value, count, fillWith) {
    var l = count - value.length;
    var ret = "";
    while (--l > -1)
        ret += fillWith;
    return ret + value;
}
function hexdumpJS(arrayBuffer, offset, length) {

    var view = new DataView(arrayBuffer);
    offset = offset || 0;
    length = length || arrayBuffer.byteLength;

    var out = _fillUp("Offset", 8, " ") + "  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n";
    var row = "";
    for (var i = 0; i < length; i += 16) {
        row += _fillUp(offset.toString(16).toUpperCase(), 8, "0") + "  ";
        var n = Math.min(16, length - offset);
        var string = "";
        for (var j = 0; j < 16; ++j) {
            if (j < n) {
                var value = view.getUint8(offset);
                string += (value >= 32 && value < 128) ? String.fromCharCode(value) : ".";
                row += _fillUp(value.toString(16).toUpperCase(), 2, "0") + " ";
                offset++;
            }
            else {
                row += "   ";
                string += " ";
            }
        }
        row += " " + string + "\n";
    }
    out += row;
    return out;
};


