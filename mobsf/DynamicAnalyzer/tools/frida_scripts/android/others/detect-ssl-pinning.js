try {
    var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
    UnverifiedCertError.$init.implementation = function(str) {
        send('Unexpected SSLPeerUnverifiedException occurred');
        try {
            var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
            var exceptionStackIndex = stackTrace.findIndex(stack => stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException");
            var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
            var className = callingFunctionStack.getClassName();
            var methodName = callingFunctionStack.getMethodName();
            var callingClass = Java.use(className);
            var callingMethod = callingClass[methodName];
            send('SSL exception caused: ' + className + '.' + methodName + '. Patch this method to bypass pinning.');
            if (callingMethod.implementation) {
                return;
            }
        } catch (e) {}
        return this.$init(str);
    };
} catch (err) {}
