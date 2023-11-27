send('Tracing Network Calls');
// NSURLSession
try {
    var NSURLSession = ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"];
    Interceptor.attach(NSURLSession.implementation, {
        onEnter: function(args) {
            send(JSON.stringify({'[MBSFDUMP] network': {'source': 'NSURLSession', 'url': ObjC.Object(args[2]).URL().absoluteString().toString()}}));
        }
    });

}
catch(error){}
// NSURLRequest
try {
    var NSURLRequest =  ObjC.classes.NSURLRequest["- initWithURL:"];
    Interceptor.attach(NSURLRequest.implementation, {
        onEnter: function(args) {
            send(JSON.stringify({'[MBSFDUMP] network': {'source': 'NSURLRequest', 'url': ObjC.Object(args[2]).toString()}}));
        },
    });

} catch (error) {}
// LGSRWebSocket
try {
    var SRWebSocket = ObjC.classes.SRWebSocket["- send:"];
    Interceptor.attach(SRWebSocket.implementation, {
        onEnter: function(args) {
            var socketURL = ObjC.Object(args[0]).url().absoluteString().toString();
            send(JSON.stringify({'[MBSFDUMP] network': {'source': 'SRWebSocket', 'url': socketURL}}));
        },

    });

} catch (error) {}
// Cordova
try {
    var CDVInvokedUrlCommand = ObjC.classes.CDVInvokedUrlCommand["+ commandFromJson:"];
    Interceptor.attach(CDVInvokedUrlCommand.implementation, {
        onEnter: function(args) {
            send(JSON.stringify({'[MBSFDUMP] network': {'source': 'Cordova', 'url': ObjC.Object(args[2]).toString()}}));
        },
    });

} catch (error) {}