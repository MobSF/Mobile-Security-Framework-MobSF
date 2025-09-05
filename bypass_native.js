// bypass_native.js
setTimeout(function(){
  var prop_map = {
    "ro.kernel.qemu": "0",
    "ro.debuggable": "0",
    "ro.product.model": "Pixel 7"
  };

  var addr = Module.findExportByName("libc.so", "__system_property_get");
  if (addr) {
    Interceptor.attach(addr, {
      onEnter: function(args){ this.k = Memory.readUtf8String(args[0]); this.buf=args[1]; },
      onLeave: function(ret){
        if (this.k && prop_map[this.k]){
          Memory.writeUtf8String(this.buf, prop_map[this.k]);
          retval.replace(ptr(prop_map[this.k].length));
          console.log("[bypass_native] __system_property_get(" + this.k + ")");
        }
      }
    });
  }

  var paddr = Module.findExportByName("libc.so","ptrace");
  if (paddr) {
    Interceptor.attach(paddr, {
      onEnter: function(args){ this.req=args[0].toInt32(); },
      onLeave: function(ret){ if (this.req===0) ret.replace(0); }
    });
  }

  ["open","access"].forEach(function(fn){
    var f=Module.findExportByName("libc.so",fn);
    if(f){
      Interceptor.attach(f,{
        onEnter:function(args){ this.p=Memory.readUtf8String(args[0]); },
        onLeave:function(ret){ if(this.p && (this.p.indexOf("su")>=0||this.p.indexOf("magisk")>=0)){ ret.replace(-1); console.log("[bypass_native] "+fn+" hide "+this.p);} }
      });
    }
  });
},0);
