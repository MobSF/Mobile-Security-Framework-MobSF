Java.perform(function() {

    // Print Initalisation
    send("[Initialised] SensitiveDataAccess");

    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };



    // Declaring Android Objects
    var ContentResolver = Java.use("android.content.ContentResolver");



    // Content Resolver Query
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function (uri, projection, queryArgs, cancellationSignal) {
        ContentType(uri.toString());
        return this.query(uri, projection, queryArgs, cancellationSignal);
    };
    // ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function (uri, projection, selection, selectionArgs, sortOrder, cancellationSignal) {
    //     send("[Dump Call Logs] Dumping Call Logs from URI -> " + uri);
    //     //if (CONFIG.dump_files) {b2s(buffer);}
    //     if (CONFIG.printStackTrace) {stackTrace();}
    //     return this.query(uri, projection, selection, selectionArgs, sortOrder, cancellationSignal);
    // };
    // ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal').implementation = function (uri, projection, selection, selectionArgs, cancellationSignal) {
    //     send("[Dump Call Logs] Dumping Call Logs from URI -> " + uri);
    //     //if (CONFIG.dump_files) {b2s(buffer);}
    //     if (CONFIG.printStackTrace) {stackTrace();}
    //     return this.query(uri, projection, selection, selectionArgs, cancellationSignal);
    // };



    // helper functions
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    }
    function ContentType(uri) {
        if (uri === 'content://com.android.contacts/contacts') {
            send("[Access.Contacts] Application Accessing Contacts from -> content://com.android.contacts/contacts");
            if (CONFIG.printStackTrace) {stackTrace();}
        } else if (uri === 'content://call_log/calls') {
            send("[Access.CallLogs] Application Accessing Call Logs from -> content://call_log/calls");
            if (CONFIG.printStackTrace) {stackTrace();}
        } else if (uri === 'content://sms/') {
            send("[Access.SMS] Application Accessing Call Logs from -> content://sms/");
            if (CONFIG.printStackTrace) {stackTrace();}
        }
    }
});