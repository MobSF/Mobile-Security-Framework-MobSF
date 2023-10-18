Java.perform(function() {
    var SocketInputStream = Java.use('java.net.SocketInputStream');
    var SocketOutputStream = Java.use('java.net.SocketOutputStream');

    var totalPacketsSent = 0;
    var totalPacketsReceived = 0;

    function byteArrayToAscii(byteArr, off, len) {
        var asciiString = '';
        for (var i = off; i < off + len; i++) {
            var decimal = byteArr[i];
            asciiString += String.fromCharCode(decimal);
        }
        return asciiString;
    }

    SocketInputStream.socketRead0.implementation = function(fd, byteArr, off, len, timeout) {
        var result = this.socketRead0(fd, byteArr, off, len, timeout);

        if (result > 0) {
            totalPacketsReceived++;
            var asciiData = byteArrayToAscii(byteArr, off, result);
            var logMessage = 'Received data:\nASCII: ' + asciiData;
            send(logMessage);
        }
        return result;
    };

    SocketOutputStream.socketWrite0.implementation = function(fd, byteArr, off, len) {
        var result = this.socketWrite0(fd, byteArr, off, len);

        if (len > 0) {
            totalPacketsSent++;
            var asciiData = byteArrayToAscii(byteArr, off, len);
            var logMessage = 'Sent data:\nASCII: ' + asciiData;
            send(logMessage);
        }
        return result;
    };

    function trackPackets() {
        send("Total Packets Sent: " + totalPacketsSent);
        send("Total Packets Received: " + totalPacketsReceived);
    }

    setInterval(trackPackets, 3000);
});
