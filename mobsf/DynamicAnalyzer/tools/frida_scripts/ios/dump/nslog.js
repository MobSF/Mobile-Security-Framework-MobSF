/* Description: Intercept calls to Apple's NSLog logging function
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
// Modified for MobSF
// Modified to support Frida 17.0.0+
// NSLog Dumper
// Author : @apps3c
// Capture NSLog and NSLogv traces

try {
	const foundation = Process.getModuleByName("Foundation");
	
	Interceptor.attach(foundation.getExportByName("NSLog"), {
		onEnter: function(args) {
			send(JSON.stringify({'[MBSFDUMP] nslog': 'NSLog -> ' + ObjC.Object(ptr(args[0])).toString() + ', ' + Memory.readCString(ptr(args[1]))}));
		},
		onLeave: function(retval) {
		}
	});

	Interceptor.attach(foundation.getExportByName("NSLogv"), {
		onEnter: function(args) {
			send(JSON.stringify({'[MBSFDUMP] nslog': 'NSLogv -> ' + ObjC.Object(ptr(args[0])).toString()+ ', ' + Memory.readCString(ptr(args[1]))}));
		},
		onLeave: function(retval) {
		}
	});
	
	send("NSLog dumper loaded successfully");
} catch (e) {
	send("Error loading NSLog dumper: " + e);
}