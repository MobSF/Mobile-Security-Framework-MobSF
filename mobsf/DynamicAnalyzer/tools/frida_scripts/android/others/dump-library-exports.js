/* 
    Description: Android Library Observer
    Usage: frida -U -f XXX -l android-library-observer2.js
    Credit: @mobilesecurity_

    Link:
        https://developer.android.com/reference/java/io/File
*/

Java.perform(function () 
{
    console.log("Enumerate ALL Native Libs Exports - started")
    const ActivityThread = Java.use('android.app.ActivityThread');
    const file = Java.use("java.io.File");

    var targetApp = ActivityThread.currentApplication();
    var context = targetApp.getApplicationContext();
    var libFolder = context.getFilesDir().getParent() + "/lib"
    var currentPath = file.$new(libFolder);
    var nativelibs = currentPath.listFiles();

    nativelibs.forEach(function (f) 
    {
        var libName = f.getName()
        console.log("Native lib name: " + libName)
 
        var exports = Module.enumerateExportsSync(libName)
        console.log("Exported methods:")

        if (exports === undefined || exports.length == 0) 
        {
            console.log("No exported methods for " + libName)
        }

        for (var i = 0; i < exports.length; i++) 
        {
            var current_export = 
            {
                name: exports[i].name,
                address: exports[i].address
            };
            console.log(JSON.stringify(current_export, null, 1))
        }
    });
    console.log("Enumerate ALL Native Libs Exports - completed")
});