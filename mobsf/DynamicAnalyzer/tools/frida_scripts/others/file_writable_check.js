var fileMap = {}; // A map to store file paths for each instance

Java.perform(function() {
    var File = Java.use('java.io.File');
    var FileInputStream = Java.use('java.io.FileInputStream');
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var StringCls = Java.use('java.lang.String'); // Add this line

    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        send('FileInputStream was created for: ' + file.getAbsolutePath());
        fileMap[this.hashCode()] = file.getAbsolutePath(); // Store file path
        return this.$init(file);
    };

    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        send('FileOutputStream was created for: ' + file.getAbsolutePath());
        fileMap[this.hashCode()] = file.getAbsolutePath(); // Store file path
        return this.$init(file);
    };

    // Hook write(int b) method
    FileOutputStream.write.overload('int').implementation = function(b) {
        var filePath = fileMap[this.hashCode()];  // Get the file path

        // Create a byte array from the int and convert to a string
        var singleByteArray = Java.array('byte', [b]);
        var str = StringCls.$new(singleByteArray, 0, 1, "UTF-8");

        send('Warning: Data(int) being written: ' + str + ' at filepath: ' + filePath);

        return FileOutputStream.write.overload('int').call(this, b);
    };


// Hook write(byte[] b) method
FileOutputStream.write.overload('[B').implementation = function(b) {
    var filePath = fileMap[this.hashCode()];  // Get the file path

    // Convert the byte array to a human-readable string
    var byteArray = Java.array('byte', b);
    var humanReadableString = StringCls.$new(byteArray, "UTF-8");

    send('Warning: Data(bytes) being written in human-readable form: ' + humanReadableString + ' at filepath: ' + filePath);

    // Check for large write
    if (b.length > 1024 * 1024) {
        send('WARNING: Large write operation: ' + b.length + ' bytes');
    } else {
        send('No large write operations detected')
    }
    return FileOutputStream.write.overload('[B').call(this, b);
};

// Hook write(byte[] b, int off, int len) method
FileOutputStream.write.overload('[B', 'int', 'int').implementation = function(b, off, len) {
    var filePath = fileMap[this.hashCode()];  // Get the file path

    // Convert the part of the byte array to a human-readable string
    var partByteArray = Java.array('byte', Array.from(b).slice(off, off + len));
    var humanReadableString = StringCls.$new(partByteArray, "UTF-8");

    send('Warning: Data(bytes and int) being written in human-readable form: ' + humanReadableString + ' at filepath: ' + filePath);

    // Check for large write
    if (len > 1024 * 1024) {
        send('WARNING: Large write operation: ' + len + ' bytes');
    } else {
        send('No large write operations detected')
    }
    return FileOutputStream.write.overload('[B', 'int', 'int').call(this, b, off, len);
};
    File.setWritable.overload('boolean', 'boolean').implementation = function(writable, ownerOnly) {
        // If the file is being set as writable, warn the user
        if (writable) {
            send('WARNING: Attempt to set file as writable: ' + this.getAbsolutePath());
        }
        // If the file is not being set as writable, also log this info
        else {
            send('setWritable called, but file is not being set as writable: ' + this.getAbsolutePath());
        }
        return this.setWritable(writable, ownerOnly);
    };
});