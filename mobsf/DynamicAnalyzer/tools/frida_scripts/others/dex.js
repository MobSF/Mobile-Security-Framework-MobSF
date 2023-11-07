Java.perform(function() {

    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false,
        // if TRUE print dex file contents
        dump_files: true,
    };



    // Declaring Android Objects
    var dalvikDexClassLoader = Java.use("dalvik.system.DexClassLoader");



    dalvikDexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        send("[DexClassLoader] DexClassLoader Catched -> " + dexPath + "," + optimizedDirectory + "," + librarySearchPath + "," + parent);
        //if (CONFIG.dump_files) {b2s(buffer);}
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };



    // helper functions
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    };

    function prettyPrint(path, buffer) {
        if (CONFIG.printEnable === false) return "";

        if (contains(path, CONFIG.dump_ascii_If_Path_contains)) {
            return b2s(buffer);
        } else if (!contains(path, CONFIG.dump_hex_If_Path_NOT_contains)) {
            return b2s(buffer);
        }
        return "[dump skipped by config]";
    }

    function b2s(array) {
        var result = "";
        for (var i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }

    function modulus(x, n) {
        return ((x % n) + n) % n;
    }
});
