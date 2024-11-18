Java.perform(function () {
   send("Starting JavaScript bridge enumeration...");

    // Hook the WebView class
    const WebView = Java.use('android.webkit.WebView');

    // Hook the addJavascriptInterface method
    WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function (obj, interfaceName) {
       send("[+] addJavascriptInterface called");
       send("    Interface Name: " + interfaceName);
       send("    Methods exposed:");

        // Reflect on the object to enumerate methods
        const objectClass = obj.getClass();
        const methods = objectClass.getDeclaredMethods();
        for (let i = 0; i < methods.length; i++) {
           send("      - " + methods[i].getName());
        }

        // Call the original method
        this.addJavascriptInterface(obj, interfaceName);
    };

   send("Hook installed for WebView.addJavascriptInterface.");
});
