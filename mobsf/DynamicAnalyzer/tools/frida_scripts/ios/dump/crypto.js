/* Description: iOS Intercepts Crypto Operations
 * Frida 17.x compatible
 * Credit: https://github.com/federicodotta/Brida
 * Author: @federicodotta
 */

function base64ArrayBuffer(arrayBuffer) {
    const encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let base64 = '', bytes = new Uint8Array(arrayBuffer);
    const len = bytes.length, rem = len % 3;
    for (let i = 0; i < len - rem; i += 3) {
        let chunk = (bytes[i] << 16) | (bytes[i+1] << 8) | bytes[i+2];
        base64 += encodings[(chunk >> 18) & 63] + encodings[(chunk >> 12) & 63] +
                  encodings[(chunk >> 6) & 63] + encodings[chunk & 63];
    }
    if (rem === 1) {
        let chunk = bytes[len - 1];
        base64 += encodings[(chunk >> 2) & 63] + encodings[(chunk << 4) & 63] + '==';
    } else if (rem === 2) {
        let chunk = (bytes[len - 2] << 8) | bytes[len - 1];
        base64 += encodings[(chunk >> 10) & 63] + encodings[(chunk >> 4) & 63] +
                  encodings[(chunk << 2) & 63] + '=';
    }
    return base64;
}

try {
    const libSystem = Process.getModuleByName("libSystem.B.dylib");

    function CCCrypt() {
        Interceptor.attach(libSystem.getExportByName("CCCrypt"), {
            onEnter: function(args) {
                const cccrypt = {
                    CCOperation: args[0].toInt32(),
                    CCAlgorithm: args[1].toInt32(),
                    CCOptions: args[2].toInt32(),
                    Key: !args[3].isNull() ? base64ArrayBuffer(Memory.readByteArray(args[3], args[4].toInt32())) : null,
                    IV: !args[5].isNull() ? base64ArrayBuffer(Memory.readByteArray(args[5], 16)) : null,
                    dataInput: !args[6].isNull() ? base64ArrayBuffer(Memory.readByteArray(args[6], args[7].toInt32())) : null
                };
                this.dataOut = args[8];
                this.dataOutLength = args[10];
                send(JSON.stringify({'[MBSFDUMP] crypto': cccrypt}));
            },
            onLeave: function(retval) {
                const cccrypt_re = {
                    dataOutput: !this.dataOut.isNull()
                        ? base64ArrayBuffer(Memory.readByteArray(this.dataOut, this.dataOutLength.readU32()))
                        : null
                };
                send(JSON.stringify({'[MBSFDUMP] crypto': cccrypt_re}));
            }
        });
    }

    function CCCryptorCreate() {
        Interceptor.attach(libSystem.getExportByName("CCCryptorCreate"), {
            onEnter: function(args) {
                const cccryptorcreate = {
                    CCOperation: args[0].toInt32(),
                    CCAlgorithm: args[1].toInt32(),
                    CCOptions: args[2].toInt32(),
                    Key: !args[3].isNull() ? base64ArrayBuffer(Memory.readByteArray(args[3], args[4].toInt32())) : null,
                    IV: !args[5].isNull() ? base64ArrayBuffer(Memory.readByteArray(args[5], 16)) : null
                };
                send(JSON.stringify({'[MBSFDUMP] crypto': cccryptorcreate}));
            }
        });
    }

    function CCCryptorUpdate() {
        Interceptor.attach(libSystem.getExportByName("CCCryptorUpdate"), {
            onEnter: function(args) {
                this.out = args[3];
                this.len = args[5];
                const update = {
                    dataInput: !args[1].isNull()
                        ? base64ArrayBuffer(Memory.readByteArray(args[1], args[2].toInt32()))
                        : null
                };
                send(JSON.stringify({'[MBSFDUMP] crypto': update}));
            },
            onLeave: function(retval) {
                const updateOut = {
                    dataOutput: !this.out.isNull()
                        ? base64ArrayBuffer(Memory.readByteArray(this.out, this.len.readU32()))
                        : null
                };
                send(JSON.stringify({'[MBSFDUMP] crypto': updateOut}));
            }
        });
    }

    function CCCryptorFinal() {
        Interceptor.attach(libSystem.getExportByName("CCCryptorFinal"), {
            onEnter: function(args) {
                this.out2 = args[1];
                this.len2 = args[3];
            },
            onLeave: function(retval) {
                const finalOut = {
                    dataOutput: !this.out2.isNull()
                        ? base64ArrayBuffer(Memory.readByteArray(this.out2, this.len2.readU32()))
                        : null
                };
                send(JSON.stringify({'[MBSFDUMP] crypto': finalOut}));
            }
        });
    }

    function CC_SHA1_Init() {
        Interceptor.attach(libSystem.getExportByName("CC_SHA1_Init"), {
            onEnter: function(args) {
                send(JSON.stringify({'[MBSFDUMP] crypto': {
                    operation: 'CC_SHA1_Init',
                    contextAddress: args[0]
                }}));
            }
        });
    }

    function CC_SHA1_Update() {
        Interceptor.attach(libSystem.getExportByName("CC_SHA1_Update"), {
            onEnter: function(args) {
                const update = {
                    operation: 'CC_SHA1_Update',
                    contextAddress: args[0],
                    data: !args[1].isNull()
                        ? base64ArrayBuffer(Memory.readByteArray(args[1], args[2].toInt32()))
                        : null
                };
                send(JSON.stringify({'[MBSFDUMP] crypto': update}));
            }
        });
    }

    function CC_SHA1_Final() {
        Interceptor.attach(libSystem.getExportByName("CC_SHA1_Final"), {
            onEnter: function(args) {
                this.mdSha = args[0];
                this.ctxSha = args[1];
            },
            onLeave: function(retval) {
                const shaFinal = {
                    operation: 'CC_SHA1_Final',
                    contextAddress: this.ctxSha,
                    hash: !this.mdSha.isNull()
                        ? base64ArrayBuffer(Memory.readByteArray(this.mdSha, 20))
                        : null
                };
                send(JSON.stringify({'[MBSFDUMP] crypto': shaFinal}));
            }
        });
    }

    CCCrypt();
    CCCryptorCreate();
    CCCryptorUpdate();
    CCCryptorFinal();
    CC_SHA1_Init();
    CC_SHA1_Update();
    CC_SHA1_Final();

    send("iOS crypto dumper loaded successfully");
} catch (e) {
    send("Error loading iOS crypto dumper: " + e);
}