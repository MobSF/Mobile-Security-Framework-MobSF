/* Description: Replace a module's exported function
 * Mode: S
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security

//How to identify exports
//Get a list of all modules: Process.enumerateModules()
//Get a list of export for a module: Module.enumerateExports()

// Helper Functions to replace an exported function with our own
// Source: https://github.com/interference-security/frida-scripts
// Modified to support Frida 17.0.0+

if (ObjC.available) {
    try {
        //Disable the ptrace jailbreak detection
        var ptracePtr = Module.getGlobalExportByName("ptrace"); //null can be replaced with libsystem_kernel.dylib which exports ptrace
        Interceptor.replace(ptracePtr, new NativeCallback(function (request, pid, addr, data) {
            send("[PTRACE-BYPASS] Process tried to call ptrace(" + request + ", " + pid + ", " + addr + ", " + data + ")");
            return 0;
        }, 'int', ['int', 'int', 'pointer', 'pointer']));

        //Disable the __sysctl jailbreak detection
        var sysctlPtr = Module.getGlobalExportByName("__sysctl"); //null can be replaced with libsystem_kernel.dylib which exports sysctl
        Interceptor.replace(sysctlPtr, new NativeCallback(function (name, namelen, oldp, oldlenp, newp, newlen) {
            send("[SYSCTL-BYPASS] Process tried to call __sysctl()");
            return 0;
        }, 'int', ['pointer', 'int', 'pointer', 'pointer', 'pointer', 'int']));
        
        send("Helper exported method replacement loaded successfully");
    } catch (e) {
        send("Error loading helper exported method replacement: " + e);
    }
} else {
    send("Objective-C Runtime is not available!");
}
