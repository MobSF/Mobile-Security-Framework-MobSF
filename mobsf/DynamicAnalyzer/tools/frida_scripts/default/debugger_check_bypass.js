Java.perform(function () {

    // Print Initalisation
    send("[Initialised] DebuggerCheck Bypass");

    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
        send('[Debugger Check Bypass] isDebuggerConnected() bypassed');
        return false;
    }
});
