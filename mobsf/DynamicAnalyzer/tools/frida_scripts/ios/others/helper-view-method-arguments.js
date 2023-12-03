// From: https://node-security.com/posts/frida-for-ios/
let className = `SCDiscoverFeedRanker`;
let methodName = `- addListener:`;

let address = ObjC.classes[className][methodName].implementation;

Interceptor.attach(address, {
	onEnter: function(args) {
		send('arg[0]:', args[0]);
		send('arg[1]:', args[1]);
		send('arg[2]:', args[2]);
	}
});