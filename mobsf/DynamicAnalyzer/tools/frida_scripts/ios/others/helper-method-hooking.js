// From: https://node-security.com/posts/frida-for-ios/
let className = `SCDiscoverFeedRanker`;
let methodName = `- addListener:`;

let address = ObjC.classes[className][methodName].implementation;

Interceptor.attach(address, {
	onEnter: function(args) {
		send(`Function Called`);
	},
	onLeave: function(returnValue) {
		send(`\nReturn Value: ${returnValue}`);
	}
});