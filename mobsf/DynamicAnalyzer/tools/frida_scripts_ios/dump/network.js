send('Tracing Network calls');
// NSURLSession
try {
    var hook = ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            send(JSON.stringify({'[MBSFDUMP] network': {'source': 'NSURLSession', 'url': ObjC.Object(args[2]).URL().absoluteString().toString()}}));
        }
    });

}
catch(error){}
// NSURLRequest
try {
    var hook =  ObjC.classes.NSURLRequest["- initWithURL:"];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            send(JSON.stringify({'[MBSFDUMP] network': {'source': 'NSURLRequest', 'url': ObjC.Object(args[2]).toString()}}));
        },
    });

} catch (error) {}
// LGSRWebSocket
try {
    var hook = ObjC.classes.SRWebSocket["- send:"];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            var socketURL = ObjC.Object(args[0]).url().absoluteString().toString();
            send(JSON.stringify({'[MBSFDUMP] network': {'source': 'SRWebSocket', 'url': socketURL}}));
        },

    });

} catch (error) {}
// Cordova
try {
    var hook = ObjC.classes.CDVInvokedUrlCommand["+ commandFromJson:"];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            send(JSON.stringify({'[MBSFDUMP] network': {'source': 'Cordova', 'url': ObjC.Object(args[2]).toString()}}));
        },
    });

} catch (error) {}