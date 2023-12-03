// From https://codeshare.frida.re/@lichao890427/ios-utils/
function trace_view() {
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication["- sendAction:to:from:forEvent:"].implementation, {
        onEnter:function(args) {
            var action = Memory.readUtf8String(args[2]);
            var toobj = ObjC.Object(args[3]);
            var fromobj = ObjC.Object(args[4]);
            var event = ObjC.Object(args[5]);
            send('SendAction:' + action + ' to:' + toobj.toString() + 
          ' from:' + fromobj.toString() + ' forEvent:' + event.toString() + ']');
        }
    });
}
trace_view();