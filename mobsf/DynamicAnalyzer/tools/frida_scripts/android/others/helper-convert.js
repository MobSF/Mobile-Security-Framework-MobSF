// Android: Java bytearray dumping
// https://awakened1712.github.io/hacking/hacking-frida/
function bytes2hex(array) {
    var result = '';
    for (var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    result += ' (' + array.length + ' bytes)'
    return result;
}

function jhexdump(array) {
    var ptr = Memory.alloc(array.length);
    for (var i = 0; i < array.length; ++i)
        ptr.add(i).writeS8(array[i]);
    send(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false }));
}

// Helper functions for converting array to C char array pointer
// Source: https://github.com/interference-security/frida-scripts

function arrayToC(array) {
    var cPtr = Memory.alloc(array.length);
    for (var i = 0; i < array.length; i++) {
        cPtr.add(i).writeS8(array[i]);
    }
    return cPtr;
}

// Usage: arrayToC([65, 66, 67, 68, 0]);  // "ABCD\0"