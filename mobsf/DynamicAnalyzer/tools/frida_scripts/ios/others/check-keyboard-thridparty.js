  // Use send() for logging
/********************************************************************************
 * Name: iOS Custom Keyboard Support Check
 * OS: iOS
 * Author: @ay-kay
 * Source: https://codeshare.frida.re/@ay-kay/ios-custom-keyboard-support/
 *********************************************************************************/

var UIApplication = ObjC.classes.UIApplication.sharedApplication();
var shouldAllowKeyboardExtension = true;
var isDelegateImplemented = false;
try {
    shouldAllowKeyboardExtension = UIApplication.delegate().application_shouldAllowExtensionPointIdentifier_(UIApplication, "com.apple.keyboard-service");
    isDelegateImplemented = true;
    send("App delegate implements application:shouldAllowExtensionPointIdentifier:");
} catch (e) {
    if (e instanceof TypeError) {
        send("App delegate has no application:shouldAllowExtensionPointIdentifier:, default behaviour applies:");
    }
}

if (shouldAllowKeyboardExtension) {
    send("-> Third-party keyboards are allowed.")
} else {
    send("-> Third-party keyboards are NOT allowed.")
}

if (shouldAllowKeyboardExtension && isDelegateImplemented) {
    send("Note: App delegate is implemented but is configured to allow third-party keyboards.");
    send("Review the implementation to check if third-party keyboard support is configurable.");
}