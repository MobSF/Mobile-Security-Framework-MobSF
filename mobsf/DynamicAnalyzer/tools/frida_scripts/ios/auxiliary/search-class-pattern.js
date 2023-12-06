/* Description: Find classes matching a pattern
 * Modified for MobSF
 * Mode: S+A
 * Version: 1.0
 * Credit: PassionFruit (https://github.com/chaitin/passionfruit/blob/master/agent/app/classdump.js) & https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function findClasses(pattern)
{
    var foundClasses = [];
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
        if (classesArray[i].match(pattern)) {
            foundClasses.push( classesArray[i]);
        }
    }
    free(pClasses)
    return foundClasses;
}


function getMatches(){
	var matches;
	try{
		var pattern = /{{PATTERN}}/i;
		send('Class search for pattern: ' + pattern)
		matches = findClasses(pattern);
	}catch (err){
		send('Class pattern match [\"Error\"] => ' + err);
		return;
	}
	if (matches.length>0)
		send('Found [' + matches.length +  '] matches')
	else
		send('No matches found')
	matches.forEach(function(clz) { 
		send('[AUXILIARY] ' + clz)
	});
}


try {
    getMatches();
} catch(err) {}