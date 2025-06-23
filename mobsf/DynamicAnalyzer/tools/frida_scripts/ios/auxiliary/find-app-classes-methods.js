/* Description: Dump all methods inside classes owned by the app only
 * Mode: S+A
 * Version: 1.0
 * Credit: PassionFruit (https://github.com/chaitin/passionfruit/blob/master/agent/app/classdump.js) & https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
// Modified to support Frida 17.0.0+

function run_show_app_classes_methods_only()
{
    send("Started: Find App's Classes and Methods")
    var free = new NativeFunction(Module.getGlobalExportByName('free'), 'void', ['pointer'])
    var copyClassNamesForImage = new NativeFunction(Module.getGlobalExportByName('objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
    var p = Memory.alloc(Process.pointerSize)
    p.writeUInt(0)
    var path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
    var pPath = Memory.allocUtf8String(path)
    var pClasses = copyClassNamesForImage(pPath, p)
    var count = p.readUInt()
    var classesArray = new Array(count)
    for (var i = 0; i < count; i++)
    {
        var pClassName = pClasses.add(i * Process.pointerSize).readPointer()
        classesArray[i] = pClassName.readUtf8String()
        var className = classesArray[i]
        send("[AUXILIARY] Class: " + className);
        //var methods = ObjC.classes[className].$methods;
        var methods = ObjC.classes[className].$ownMethods;
        for (var j = 0; j < methods.length; j++)
        {
            send("[AUXILIARY] \t[-] Method: " + methods[j]);
            try
            {
                send("[AUXILIARY] \t\t[-] Arguments Type: " + ObjC.classes[className][methods[j]].argumentTypes);
                send("[AUXILIARY] \t\t[-] Return Type: " + ObjC.classes[className][methods[j]].returnType);
            }
            catch(err) {}
        }
    }
    free(pClasses)
    send("App Classes found: " + count);
    send("Completed: Find App's Classes")
}

function show_app_classes_methods_only()
{
    try {
        setImmediate(run_show_app_classes_methods_only)
    } catch(err) {}
}

show_app_classes_methods_only()
