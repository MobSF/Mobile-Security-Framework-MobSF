/* 
    Source: https://github.com/FSecureLABS/android-keystore-audit/tree/master/frida-scripts
    PBEKeySpec tracer allows to see parameters (including password) from which PBKDF keys are generated  
*/

Java.perform(function () {
    //hookSecretKeyFactory_getInstance();
    hookPBEKeySpec();
    hookPBEKeySpec2();
    hookPBEKeySpec3();    
});

send("[AUXILIARY] [TRACER PBKDF] SecretKeyFactory hooks loaded!");


var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

function hookSecretKeyFactory_getInstance()
{
    var func = Java.use('javax.crypto.SecretKeyFactory')['getInstance'];
    func.implementation = function(flag) {
        send("[AUXILIARY] [TRACER PBKDF] [SecretKeyFactory.getInstance()]: flag: " + flag );
        return this.getInstance(flag);
    }   
}

/*
    .overload('[C')
    .overload('[C', '[B', 'int')
    .overload('[C', '[B', 'int', 'int')
*/
function hookPBEKeySpec()
{
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C');
    PBEKeySpec.implementation = function(pass) {
        send("[AUXILIARY] [TRACER PBKDF] [PBEKeySpec.PBEKeySpec()]: pass: " + charArrayToString(pass) );
        return this.$init(pass);
    }   
}

function hookPBEKeySpec2()
{
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C', '[B', 'int');
    PBEKeySpec.implementation = function(pass, salt, iter) {
        send("[AUXILIARY] [TRACER PBKDF] [PBEKeySpec.PBEKeySpec2()]: pass: " + charArrayToString(pass)  +  " iter: "+iter);
        dumpByteArray("salt",salt)
        return this.$init(pass,salt,iter);
    }   
}

function hookPBEKeySpec3()
{
    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C', '[B', 'int', 'int');
    PBEKeySpec.implementation = function(pass, salt, iter, keyLength) {
        send("[AUXILIARY] [TRACER PBKDF] [PBEKeySpec.PBEKeySpec3()]: pass: " + charArrayToString(pass)  +  " iter: "+iter + " keyLength: "+keyLength);
        dumpByteArray("salt",salt)
        return this.$init(pass,salt,iter,keyLength);
    }   
}

function charArrayToString(charArray)
{
    if(charArray == null)
        return '(null)';
    else
        return StringCls.$new(charArray); 
}

function dumpByteArray(title,byteArr)
{
    if(byteArr!=null)
    {
        try{ 
            var buff = new ArrayBuffer(byteArr.length)
            var dtv = new DataView(buff)
            for(var i = 0; i < byteArr.length; i++){
                dtv.setUint8(i,byteArr[i]); // Frida sucks sometimes and returns different byteArr.length between ArrayBuffer(byteArr.length) and for(..; i < byteArr.length;..). It occured even when Array.copyOf was done to work on copy.
            }
            send( title+":\n");
            send(hexdumpJS(dtv.buffer,0,byteArr.length))
        } catch(error){send("[AUXILIARY] [TRACER PBKDF] Exception has occured in hexdump")}
    }
    else
    {
        send("[AUXILIARY] [TRACER PBKDF] byteArr is null!");
    }
}

function _fillUp (value, count, fillWith) {
    var l = count - value.length;
    var ret = "";
    while (--l > -1)
        ret += fillWith;
    return ret + value;
}

function hexdumpJS (arrayBuffer, offset, length) {

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