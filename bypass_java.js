// bypass_java.js
Java.perform(function(){
  try {
    var Build = Java.use("android.os.Build");
    Build.MODEL.value = "Pixel 7";
    Build.PRODUCT.value = "cheetah";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "cheetah";
    console.log("[bypass_java] Build spoofed");
  } catch(e){}

  var PROP = {
    "ro.kernel.qemu": "0",
    "ro.debuggable": "0",
    "ro.product.model": "Pixel 7"
  };

  try {
    var System = Java.use("java.lang.System");
    var origGet = System.getProperty.overload('java.lang.String');
    origGet.implementation = function(k){
      if (PROP.hasOwnProperty(k)){
        console.log("[bypass_java] System.getProperty(" + k + ") -> " + PROP[k]);
        return PROP[k];
      }
      return origGet.call(this,k);
    };
  } catch(e){}

  try {
    var SP = Java.use("android.os.SystemProperties");
    var g1 = SP.get.overload('java.lang.String');
    g1.implementation = function(k){
      if (PROP.hasOwnProperty(k)) return PROP[k];
      return g1.call(this,k);
    };
  } catch(e){}

  try {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function(){ return false; };
  } catch(e){}

  try {
    var File = Java.use("java.io.File");
    var origExists = File.exists;
    File.exists.implementation = function(){
      var p = this.getPath();
      if (p.indexOf("su")>=0 || p.indexOf("magisk")>=0){
        console.log("[bypass_java] hide " + p);
        return false;
      }
      return origExists.call(this);
    };
  } catch(e){}
});
