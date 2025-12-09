function traceJSON(){
    send('Tracing JSON Data');
    var jsonHook =  ObjC.classes.NSJSONSerialization["+ JSONObjectWithData:options:error:"];
    Interceptor.attach(jsonHook.implementation,
    {
        onEnter: function(args) {
            var jsonData = ObjC.Object(args[2]);
            var jsonStr = jsonData.bytes().readUtf8String(jsonData.length());
            send(JSON.stringify({'[MBSFDUMP] json': jsonStr}));
        }
    });
}
try {
    traceJSON();
} catch(err) {} 