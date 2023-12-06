// From: https://node-security.com/posts/frida-for-ios/
const className	= `FFJpegFrame`;
const methodToHook	= `- setData:`;
let address = ObjC.classes[className][methodToHook].implementation;

let hexData = hexdump(address, {
	offset: 0,
	length: 64,
});

send(hexData);