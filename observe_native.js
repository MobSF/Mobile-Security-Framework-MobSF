// observe_native.js
setTimeout(function(){
  var funcs = ["open","openat","access","__system_property_get","ptrace"];
  funcs.forEach(function(fn){
    var addr = Module.findExportByName("libc.so", fn);
    if (addr) {
      Interceptor.attach(addr, {
        onEnter: function(args){
          try {
            if (fn.indexOf("property")>=0) {
              console.log("[observe_native] " + fn + "(" + Memory.readUtf8String(args[0]) + ")");
            } else {
              console.log("[observe_native] " + fn + "(" + Memory.readUtf8String(args[0]) + ")");
            }
          } catch(e){}
        }
      });
      console.log("[observe_native] hooked " + fn);
    }
  });
},0);
