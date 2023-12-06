/* Description: iOS Intercepts Crypto Operations
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/federicodotta/Brida
 * Author: @federicodotta
 */

function CCCrypt(){
    Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCrypt"),
    {
    onEnter: function(args) {

        var cccrypt = {
            'CCOperation': parseInt(args[0]),
            'CCAlgorithm': parseInt(args[1]),
            'CCOptions': parseInt(args[2]),
        }

        if(ptr(args[3]) != 0 ) {
            cccrypt['Key'] = base64ArrayBuffer(Memory.readByteArray(ptr(args[3]),parseInt(args[4])));
        } else {
            cccrypt['Key'] = 0;
        }

        if(ptr(args[5]) != 0 ) {
            cccrypt['IV'] = base64ArrayBuffer(Memory.readByteArray(ptr(args[5]),16));
        } else {
            cccrypt['IV'] = 0;
        }

        this.dataInLength = parseInt(args[7]);

        if(ptr(args[6]) != 0 ) {

            cccrypt['dataInput'] = base64ArrayBuffer(Memory.readByteArray(ptr(args[6]),this.dataInLength))

        } else {
            cccrypt['dataInput'] = null;
        }

        this.dataOut = args[8];
        this.dataOutLength = args[10];
        send(JSON.stringify({'[MBSFDUMP] crypto': cccrypt}));

    },

    onLeave: function(retval) {
        var cccrypt_re = {};
        if(ptr(this.dataOut) != 0 ) {
            cccrypt_re['dataOutput'] = base64ArrayBuffer(Memory.readByteArray(this.dataOut,parseInt(ptr(Memory.readU32(ptr(this.dataOutLength),4)))));

        } else {
            cccrypt_re['dataOutput'] = null;
        }
        send(JSON.stringify({'[MBSFDUMP] crypto': cccrypt_re}));

    }

});
}
function CCCryptorCreate(){
    Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorCreate"),
        {
        onEnter: function(args) {

            var cccryptorcreate = {
                'CCOperation': parseInt(args[0]),
                'CCAlgorithm': parseInt(args[1]),
                'CCOptions': parseInt(args[2]),
            }

            if(ptr(args[3]) != 0 ) {
                cccryptorcreate['Key'] = base64ArrayBuffer(Memory.readByteArray(ptr(args[3]),parseInt(args[4])));

            } else {
                cccryptorcreate['Key'] = 0;
            }

            if(ptr(args[5]) != 0 ) {
                cccryptorcreate['IV'] = base64ArrayBuffer(Memory.readByteArray(ptr(args[5]),16));
            } else {
                cccryptorcreate['IV'] = 0; 
            }
            send(JSON.stringify({'[MBSFDUMP] crypto': cccryptorcreate}));

        },
        onLeave: function(retval) {
        }

    });
}
function CCCryptorUpdate(){
    Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorUpdate"),
    {
    onEnter: function(args) {
        var cryptorupdate = {}
        if(ptr(args[1]) != 0) {
            cryptorupdate['dataInput'] = base64ArrayBuffer(Memory.readByteArray(ptr(args[1]),parseInt(args[2])));

        } else {
            cryptorupdate['dataInput'] = null;
        }

        //this.len = args[4];
        this.len = args[5];
        this.out = args[3];
        send(JSON.stringify({'[MBSFDUMP] crypto': cryptorupdate}));

    },

    onLeave: function(retval) {
        var cryptorupdate_re = {}
        if(ptr(this.out) != 0) {
            cryptorupdate_re['dataOutput'] = base64ArrayBuffer(Memory.readByteArray(this.out,parseInt(ptr(Memory.readU32(ptr(this.len),4)))))
        } else {
            cryptorupdate_re['dataOutput'] = null;
        }
        send(JSON.stringify({'[MBSFDUMP] crypto': cryptorupdate_re}));
    }

});
}

function CCCryptorFinal(){
    Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorFinal"),
    {
    onEnter: function(args) {
        //this.len2 = args[2];
        this.len2 = args[3];
        this.out2 = args[1];
    },
    onLeave: function(retval) {
        var cccryptorfinal_re = {}
        if(ptr(this.out2) != 0) {
            cccryptorfinal_re['dataOutput'] = base64ArrayBuffer(Memory.readByteArray(this.out2,parseInt(ptr(Memory.readU32(ptr(this.len2),4)))))
        } else {
            cccryptorfinal_re['dataOutput'] = null;
        }
        send(JSON.stringify({'[MBSFDUMP] crypto': cccryptorfinal_re}));
    }

});
}

function CC_SHA1_Init(){
    //CC_SHA1_Init(CC_SHA1_CTX *c);
    Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Init"),
    {
        onEnter: function(args) {
            send(JSON.stringify({'[MBSFDUMP] crypto': {
                'operation': 'CC_SHA1_Init',
                'contextAddress': args[0],
            }}));
        }
    });
}

function CC_SHA1_Update(){
    //CC_SHA1_Update(CC_SHA1_CTX *c, const void *data, CC_LONG len);
    Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Update"),
    {
        onEnter: function(args) {
            var ccsha1update = {
                'operation': 'CC_SHA1_Update',
                'contextAddress': args[0],
            }
            if(ptr(args[1]) != 0) {
                ccsha1update['data'] = base64ArrayBuffer(Memory.readByteArray(ptr(args[1]),parseInt(args[2])));
            } else {
                ccsha1update['data'] = null;
            }
            send(JSON.stringify({'[MBSFDUMP] crypto': ccsha1update}));
        }
    });
}

function CC_SHA1_Final(){
    //CC_SHA1_Final(unsigned char *md, CC_SHA1_CTX *c);
    Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Final"),
    {
        onEnter: function(args) {
            this.mdSha = args[0];
            this.ctxSha = args[1];
        },
        onLeave: function(retval) {
            var ccsha1final_ret = {
                'operation': 'CC_SHA1_Final',
                'contextAddress': this.ctxSha,
            }
            if(ptr(this.mdSha) != 0) {
                ccsha1final_ret['hash'] = base64ArrayBuffer(Memory.readByteArray(ptr(this.mdSha),20));

            } else {
                ccsha1final_ret['hash'] = null;
            }
            send(JSON.stringify({'[MBSFDUMP] crypto': ccsha1final_ret}));
        }
    });
}


try {
    send("Tracing Crypto Operations");
    CCCrypt();
} catch(err) {}
try {
    CCCryptorCreate();
} catch(err) {}

try {
   CCCryptorUpdate();
} catch(err) {}

try {
    CCCryptorFinal();
} catch(err) {}

try {
    CC_SHA1_Init();
} catch(err) {}

try {
    CC_SHA1_Update();
} catch(err) {}

try {
    CC_SHA1_Final();
} catch(err) {}

// Native ArrayBuffer to Base64
// https://gist.github.com/jonleighton/958841
function base64ArrayBuffer(arrayBuffer) {
    var base64    = ''
    var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    var bytes         = new Uint8Array(arrayBuffer)
    var byteLength    = bytes.byteLength
    var byteRemainder = byteLength % 3
    var mainLength    = byteLength - byteRemainder

    var a, b, c, d
    var chunk

    // Main loop deals with bytes in chunks of 3
    for (var i = 0; i < mainLength; i = i + 3) {
    // Combine the three bytes into a single integer
    chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

    // Use bitmasks to extract 6-bit segments from the triplet
    a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
    b = (chunk & 258048)   >> 12 // 258048   = (2^6 - 1) << 12
    c = (chunk & 4032)     >>  6 // 4032     = (2^6 - 1) << 6
    d = chunk & 63               // 63       = 2^6 - 1

    // Convert the raw binary segments to the appropriate ASCII encoding
    base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
    }

    // Deal with the remaining bytes and padding
    if (byteRemainder == 1) {
    chunk = bytes[mainLength]

    a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

    // Set the 4 least significant bits to zero
    b = (chunk & 3)   << 4 // 3   = 2^2 - 1

    base64 += encodings[a] + encodings[b] + '=='
    } else if (byteRemainder == 2) {
    chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

    a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
    b = (chunk & 1008)  >>  4 // 1008  = (2^6 - 1) << 4

    // Set the 2 least significant bits to zero
    c = (chunk & 15)    <<  2 // 15    = 2^4 - 1

    base64 += encodings[a] + encodings[b] + encodings[c] + '='
    }

    return base64
}
