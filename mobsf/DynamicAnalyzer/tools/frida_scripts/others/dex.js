Java.perform(function() {

    // Print Initalisation
    send("[Initialised] DexClassLoader");

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
        send("[DexClassLoader] Loaded Classes From: " + dexPath);
        //if (CONFIG.dump_files) {b2s(buffer);}
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };



    // helper functions
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    }
});
