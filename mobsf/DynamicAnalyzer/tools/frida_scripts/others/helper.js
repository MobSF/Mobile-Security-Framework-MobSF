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
        Memory.writeS8(ptr.add(i), array[i]);
    send(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false }));
}