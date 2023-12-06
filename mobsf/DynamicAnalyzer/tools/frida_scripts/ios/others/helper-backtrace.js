// Get caller of the function using backtrace

// From: https://node-security.com/posts/frida-for-ios/
function getBacktrace(){
	send('Get the caller of the function using backtrace');
	Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
		onEnter: function (args) {
			const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
			console.log(backtrace + "\n");
			console.log(ObjC.Object(args[2]).toString());
		}
	});
}
try {
	getBacktrace();
} catch(err) {}