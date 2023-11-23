/* Description: Intercept calls to Apple's NSLog logging function
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
//Note: This interception does not print the string interpolation (or formatting) values such as %s, %ld, %f, %a. Still working on a fix.

Interceptor.attach(Module.findExportByName("Foundation", "NSLog"), {
	onEnter: function(args) {
		send(JSON.stringify({'[MBSFDUMP] nslog': 'NSLog -> ' + ObjC.Object(ptr(args[0])).toString()}));
		//send((ObjC.Object(ptr(args[0]))).toString())
		//send((ObjC.Object(args[0])).toString())
	}
});
//As per the Apple documentation NSLog calls NSLogv in the background but for some reason it is not working. Still working on a fix.
Interceptor.attach(Module.findExportByName("Foundation", "NSLogv"), {
	onEnter: function(args) {
		send(JSON.stringify({'[MBSFDUMP] nslog': 'NSLogv -> ' + ObjC.Object(ptr(args[0])).toString()}));
	}
});
send('Tracing all NSLog calls');