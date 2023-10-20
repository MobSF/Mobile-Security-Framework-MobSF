Java.perform(function() {

    // Config
    var CONFIG = {
        // if TRUE monitor network packets metric
        networkPacketsMetric: false,
        // if TRUE monitor network bytes metric
        networkBytesMetric: false,
        // polling interval for network metrics in milliseconds (checks will only run if networkPacketsMetric or networkBytesMetric is set to true)
        metricPollingInterval: 1000,
    };



    // Network Sockets
    var SocketOutputStream = Java.use('java.net.SocketOutputStream');
    var SocketInputStream = Java.use('java.net.SocketInputStream');

    // Network bytes
    var totalBytesSent = 0;
    var totalBytesReceived = 0;

    function trackBytes() {
        return("Total Bytes Sent: " + totalBytesSent + "\nTotal Bytes Received: " + totalBytesReceived);
    }

    SocketOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, byteOffset, byteCount) {
        totalBytesSent += byteCount;
        this.write.call(this, buffer, byteOffset, byteCount);
    };

    SocketInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, byteOffset, byteCount) {
        var result = this.read.call(this, buffer, byteOffset, byteCount);
        if(result > 0) {
            totalBytesReceived += result;
        }
        return result;
    };



    // Network Packets
    var totalPacketsSent = 0;
    var totalPacketsReceived = 0;

    function trackPackets() {
        return("Total Packets Sent: " + totalPacketsSent + "\nTotal Packets Received: " + totalPacketsReceived);
    }

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
            var logMessage = '--------------------\nReceived data:\nASCII: ' + asciiData;
            send(logMessage);
        }
        return result;
    };

    SocketOutputStream.socketWrite0.implementation = function(fd, byteArr, off, len) {
        var result = this.socketWrite0(fd, byteArr, off, len);

        if (len > 0) {
            totalPacketsSent++;
            var asciiData = byteArrayToAscii(byteArr, off, len);
            var logMessage = '--------------------\nSent data:\nASCII: ' + asciiData;
            send(logMessage);
        }
        return result;
    };



    // Monitor Network Metrics every second
    setInterval(function() {
        if (CONFIG.networkBytesMetric || CONFIG.networkPacketsMetric) {
            send('--------------------\n' + (CONFIG.networkBytesMetric ? (trackBytes() + '\n') : '') + (CONFIG.networkPacketsMetric ? trackPackets() : ''));
        }
    }, CONFIG.metricPollingInterval);
});