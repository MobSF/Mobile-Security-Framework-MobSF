// From: https://node-security.com/posts/frida-for-ios/#view-and-modify-registers
let className = `SCDiscoverFeedRanker`;
let methodName = `- addListener:`;

let address = ObjC.classes[className][methodName].implementation;

Interceptor.attach(address, {
	onEnter: function(args) {
		// Print ALL Registers
		send(JSON.stringify(this.context, null, 4), '\n');

		// View Register Value
		send(`Register (x14): ${this.context.x14}`);
		send(`Register (x14): ${this.context.x14.toInt32()}\n`);

		// Update Register Value
		this.context.x14 = 64;
		this.context.x14 = 0x44; // Same as the previous line

		// View Register Value
		send(`Register (x14): ${this.context.x14}`);
		send(`Register (x14): ${this.context.x14.toInt32()}`);
	},
});