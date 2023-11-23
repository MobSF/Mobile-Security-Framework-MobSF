// From: https://node-security.com/posts/frida-for-ios/
send('Tracing all file access calls');
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
	onEnter: function (args) {
        var filename = ObjC.Object(args[2]).toString();
		send(JSON.stringify({'[MBSFDUMP] filename': filename}));
	}
});