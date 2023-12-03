function traceJSON(){
    send('Tracing JSON Data');
    var jsonHook =  ObjC.classes.NSJSONSerialization["+ JSONObjectWithData:options:error:"];
    Interceptor.attach(jsonHook.implementation,
    {
        onEnter: function(args) {
            var jsonData = ObjC.Object(args[2]);
            var jsonStr = Memory.readUtf8String(jsonData.bytes(), jsonData.length());
            send(JSON.stringify({'[MBSFDUMP] json': jsonStr}));
        }
    });
}
try {
    traceJSON();
} catch(err) {} 