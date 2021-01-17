function binaryToHexToAscii(array, readLimit) {
    var result = [];
    // read 100 bytes #performance
    readLimit = readLimit || 100;
    for (var i = 0; i < readLimit; ++i) {
        result.push(String.fromCharCode( // hex2ascii part
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
                16
            )
        ));
    }
    return result.join('');
}

function hookInputStream() {
    Java.use('java.io.InputStream')['read'].overload('[B').implementation = function (b) {
        // execute original and save return value
        var retval = this.read(b);
        var resp = binaryToHexToAscii(b);
        // conditions to not print garbage packets
        var reExcludeList = new RegExp(['Mmm'/*, 'Ping' /*, ' Yo'*/].join('|'));
        if (!reExcludeList.test(resp)) {
            send(resp);
        }
        var reIncludeList = new RegExp(['AAA', 'BBB', 'CCC'].join('|'));
        if (reIncludeList.test(resp)) {
            send(binaryToHexToAscii(b, 1200));
        }
        return retval;
    };
}

Java.perform(hookInputStream);