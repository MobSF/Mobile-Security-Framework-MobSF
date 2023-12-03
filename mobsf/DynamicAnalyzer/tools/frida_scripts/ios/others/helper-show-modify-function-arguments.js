/* Description: Show and modify arguments of a function inside a class
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security

function show_modify_function_args(className, funcName)
{
  var hook = ObjC.classes[className][funcName];
  Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
      // args[0] is self
      // args[1] is selector (SEL "sendMessageWithText:")
      // args[2] holds the first function argument, an NSString
      console.log("\n[*] Detected call to: " + className + " -> " + funcName);
      console.log("\t[-] Argument Value: "+args[2]);
      //your new argument value here
      var newargval = ptr("0x0")
      args[2] = newargval
      console.log("\t[-] New Argument Value: " + args[2])
    }
  });
}


//Your class name and function name here
show_modify_function_args("className", "funcName")