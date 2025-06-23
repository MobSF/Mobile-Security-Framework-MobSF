// https://github.com/iddoeldor/frida-snippets#reveal-native-methods
// Modified to support Frida 17.0.0+
// Hook JNI by address
// Hook native method by module name and method address and print arguments.
const moduleName = "libGLESv2.so";
const nativeFuncOffset = 0x1234; // Use `nm -D --demangle libGLESv2.so | grep Class::method` to get this offset

try {
    Interceptor.attach(Module.getGlobalExportByName("dlopen"), {
        onEnter(args) {
            this.lib = args[0].readUtf8String();
            send("[dlopen] called with: " + this.lib);
        },
        onLeave(retval) {
            if (!this.lib || !this.lib.endsWith(moduleName)) return;

            send("[dlopen] loaded target module: " + this.lib + " => " + retval);

            try {
                const module = Process.getModuleByName(moduleName);
                const hookAddress = module.base.add(nativeFuncOffset);

                send("[+] Hooking native method at " + hookAddress + " (" + moduleName + "+0x" + nativeFuncOffset.toString(16) + ")");

                Interceptor.attach(hookAddress, {
                    onEnter(args) {
                        try {
                            send("[-] Hook invoked");
                            send(JSON.stringify({
                                a1: args[1].toInt32(),
                                a2: args[2] && args[2].readPointer() ? args[2].readPointer().readUtf8String() : null,
                                a3: Boolean(args[3].toInt32())
                            }, null, 2));
                        } catch (err) {
                            send("[!] Error reading arguments: " + err);
                        }
                    }
                });

            } catch (e) {
                send("[!] Error hooking " + moduleName + ": " + e);
            }
        }
    });

} catch (e) {
    send("[!] Error hooking dlopen: " + e);
}
