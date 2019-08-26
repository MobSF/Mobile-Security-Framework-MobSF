Java.perform(function () {
        // send("[Debugger Check Bypass]  Activated");
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            send('[Debugger Check Bypass] isDebuggerConnected() bypassed');
            return false;
        }
});
