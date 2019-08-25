Java.perform(function () {
        send("Debugger Check Bypass: active");
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            // console.log('isDebuggerConnected Bypassed !');
            return false;
        }
});
