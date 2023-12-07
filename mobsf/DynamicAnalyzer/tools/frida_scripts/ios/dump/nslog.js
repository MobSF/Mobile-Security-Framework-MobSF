/* Description: Intercept calls to Apple's NSLog logging function
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
// Modified for MobSF
function NSlog(){
	send('Tracing NSLog Calls');
	Interceptor.attach(Module.findExportByName("Foundation", "NSLog"), {
		onEnter: function(args) {
			send(JSON.stringify({'[MBSFDUMP] nslog': 'NSLog -> ' + ObjC.Object(ptr(args[0])).toString() + ', ' + Memory.readCString(ptr(args[1]))}));
		}
	});
}

function NSLogv(){
	//As per the Apple documentation NSLog calls NSLogv in the background but for some reason it is not working. Still working on a fix.
	Interceptor.attach(Module.findExportByName("Foundation", "NSLogv"), {
		onEnter: function(args) {
			send(JSON.stringify({'[MBSFDUMP] nslog': 'NSLogv -> ' + ObjC.Object(ptr(args[0])).toString()+ ', ' + Memory.readCString(ptr(args[1]))}));
		}
	});
}

try {
	setTimeout(() => {
		NSlog();
	}, 1000);

} catch(err) {}
try {
	setTimeout(() => {
		NSLogv();
	}, 1000);
} catch(err) {}