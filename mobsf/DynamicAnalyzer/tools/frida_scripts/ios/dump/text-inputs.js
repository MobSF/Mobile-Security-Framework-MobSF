// Based on https://codeshare.frida.re/@lichao890427/ios-utils/
function dump_inputs() {
    send("Tracing all Text inputs to the device");
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication["- sendAction:to:from:forEvent:"].implementation, {
        onEnter:function(args) {
          var fromObj = ObjC.Object(args[4]);
          try{
            send(JSON.stringify({'[MBSFDUMP] textinput':fromObj.text().toString()}));
          }catch(e){}
        }
    });
}
try {
  dump_inputs();
} catch(err) {}