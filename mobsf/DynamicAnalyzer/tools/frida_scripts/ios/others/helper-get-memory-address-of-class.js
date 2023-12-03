// From: https://node-security.com/posts/frida-for-ios/
let className = `FFJpegFrame`;
let methodName = `- setData:`;

let address = ObjC.classes[className][methodName].implementation;

send(`Address: ${address}`);