/*
 * raptor_frida_android_*.js - Frida snippets for Android
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 * Modified to support Frida 17.0.0+
 */
Java.perform(function () {
    try {
        // Get the libc module and the 'open' function export
        const libc = Process.getModuleByName("libc.so");
        const openPtr = libc.getExportByName("open");

        // Attach interceptor to libc open()
        Interceptor.attach(openPtr, {
            onEnter: function (args) {
                this.flag = false;

                try {
                    // Read filename argument safely
                    const filename = args[0].readCString();

                    // Uncomment and adjust filtering logic as needed
                    // if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) return;
                    // if (filename.indexOf("my.interesting.file") !== -1)

                    this.flag = true;

                    if (this.flag) {
                        send("\n[open] file name: " + filename);

                        // Print backtrace
                        const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress)
                            .join("\n");
                        send("\nBacktrace:\n" + backtrace);
                    }
                } catch (e) {
                    send("[!] Error in onEnter: " + e);
                }
            },
            onLeave: function (retval) {
                if (this.flag) {
                    send("[open] retval: " + retval);
                }
            }
        });

        send("[✔] Hook installed on libc open()");
    } catch (e) {
        send("[✘] Error hooking libc open: " + e);
    }
});
