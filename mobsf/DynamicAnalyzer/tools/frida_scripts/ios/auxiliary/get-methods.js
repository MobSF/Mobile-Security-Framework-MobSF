/* Description: Get all methods of the class
 * Modified for MobSF 
 * Mode: S+A
 * Version: 1.0
 * Credit: PassionFruit (https://github.com/chaitin/passionfruit/blob/master/agent/app/classdump.js) & https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_get_app_methods_in_class()
{
    var targetClass = '{{CLASS}}';
    var found = false;
    send("Looking for methods in: " + targetClass)

    var free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer'])
    var copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, 'objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
    var p = Memory.alloc(Process.pointerSize)
    Memory.writeUInt(p, 0)
    var path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
    var pPath = Memory.allocUtf8String(path)
    var pClasses = copyClassNamesForImage(pPath, p)
    var count = Memory.readUInt(p)
    var classesArray = new Array(count)
    for (var i = 0; i < count; i++)
    {
        var pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
        classesArray[i] = Memory.readUtf8String(pClassName)
		var className = classesArray[i]
        if (className === targetClass)
        {
            found = true;
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
    }
    free(pClasses)
    if (!found)
    {
        send("Class not found: " + targetClass)
    } else 
    {
	    send("Completed Enumerating Methods in Class: " + targetClass)
    }
}


try {
    run_get_app_methods_in_class()
} catch(err) {}