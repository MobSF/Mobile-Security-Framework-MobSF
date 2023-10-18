Java.perform(function() {
    var totalBytesSent = 0;
    var totalBytesReceived = 0;
    
    function trackBytes() {
        send("Total Bytes Sent: " + totalBytesSent);
        send("Total Bytes Received: " + totalBytesReceived);
    }

    var SocketOutputStream = Java.use('java.net.SocketOutputStream');
    SocketOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, byteOffset, byteCount) {
        totalBytesSent += byteCount;
        this.write.call(this, buffer, byteOffset, byteCount);
    };

    var SocketInputStream = Java.use('java.net.SocketInputStream');
    SocketInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, byteOffset, byteCount) {
        var result = this.read.call(this, buffer, byteOffset, byteCount);
        if(result > 0) {
            totalBytesReceived += result;
        }
        return result;
    };

    // Execute every second
    setInterval(trackBytes, 3000);
});
