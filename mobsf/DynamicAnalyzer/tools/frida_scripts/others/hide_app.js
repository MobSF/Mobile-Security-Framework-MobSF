Java.perform(function() {

    // Print Initalisation
    send("[Initialised] HideApp");

    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false,
    };



    // Declaring Android Objects
    var applicationPackageManager = Java.use("android.app.ApplicationPackageManager");
    var packageManager = Java.use("android.content.pm.PackageManager")



    // Hide Application (Application Pacakge Manager)
    applicationPackageManager.setComponentEnabledSetting.overload('android.content.ComponentName', 'int', 'int').implementation = function (componentName, newState, flags) {
        if (newState === 2 && flags === 1) {
            send("[HideApp] Hidding Application");
            if (CONFIG.printStackTrace) {stackTrace();}
        }
        return this.setComponentEnabledSetting(componentName, newState, flags);
    };

    // Hide Application (Package Manager)
    packageManager.setComponentEnabledSetting.overload('android.content.ComponentName', 'int', 'int').implementation = function (componentName, newState, flags) {
        if (newState === 2 && flags === 1) {
            send("[HideApp] Hidding Application");
            if (CONFIG.printStackTrace) {stackTrace();}
        }
        return this.setComponentEnabledSetting(componentName, newState, flags);
    };



    // helper functions
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    };
});
