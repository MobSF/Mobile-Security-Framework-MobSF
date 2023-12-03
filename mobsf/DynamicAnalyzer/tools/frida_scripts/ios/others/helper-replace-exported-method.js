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

//replace a function. In this example we are replacing ptrace
var ptracePtr = Module.findExportByName(null, "ptrace"); //null can be replaced with libsystem_kernel.dylib which exports ptrace
Interceptor.replace(ptracePtr, new NativeCallback(function () {
	send("[*] Ptrace called and replaced")
}, "int", []));

//replace a function. In this example we are replacing sysctl
var sysctlPtr = Module.findExportByName(null, "__sysctl"); //null can be replaced with libsystem_kernel.dylib which exports sysctl
Interceptor.replace(sysctlPtr, new NativeCallback(function () {
	send("[*] Sysctl called and replaced")
}, "int", []));
