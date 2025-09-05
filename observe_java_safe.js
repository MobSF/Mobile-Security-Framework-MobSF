// observe_java_safe.js
function hookJava() {
    try {
        var Build = Java.use("android.os.Build");
        console.log("[observe_java] Build.MODEL=" + Build.MODEL.value + " PRODUCT=" + Build.PRODUCT.value);
    } catch(e){}

    try {
        var System = Java.use("java.lang.System");
        System.getProperty.overload('java.lang.String').implementation = function(key){
            var ret = this.getProperty(key);
            console.log("[observe_java] System.getProperty(" + key + ") -> " + ret);
            return ret;
        };
    } catch(e){}

    try {
        var SP = Java.use("android.os.SystemProperties");
        SP.get.overload('java.lang.String').implementation = function(k){
            var ret = this.get(k);
            console.log("[observe_java] SystemProperties.get(" + k + ") -> " + ret);
            return ret;
        };
    } catch(e){}

    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function(){
            var r = this.isDebuggerConnected();
            console.log("[observe_java] Debug.isDebuggerConnected() -> " + r);
            return r;
        };
    } catch(e){}

    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function(){
            var path = this.getPath();
            var r = this.exists();
            console.log("[observe_java] File.exists(" + path + ") -> " + r);
            return r;
        };
    } catch(e){}
}

// Java VM 준비될 때까지 500ms마다 반복 후킹
function tryHook() {
    if (Java.available) {
        Java.perform(hookJava);
        console.log("[observe_java] Hooks applied");
    } else {
        setTimeout(tryHook, 500);
    }
}

tryHook();
