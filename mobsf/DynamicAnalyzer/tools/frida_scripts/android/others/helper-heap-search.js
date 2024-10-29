/************************************************************************
 * Name: Heap Search and method call
 * OS: Android
 * Author: @mobilesecurity_
 * Source: https://github.com/m0bilesecurity
 * Info: make sure to replace placeholders
        * {className}
        * {classMethod}
        * {args}
*************************************************************************/


Java.performNow(function () {
    var classname = "{className}"
    var classmethod = "{classMethod}";
  
    Java.choose(classname, {
        onMatch: function (instance) {
            try 
            {
                var returnValue;
                //{methodSignature}
                returnValue = instance.{classMethod}({args}); //<-- replace v[i] with the value that you want to pass
  
                //Output
                var s = "";
                s=s + "[*] Heap Search - START\\n"
  
                s=s + "Instance Found: " + instance.toString() + "\\n";
                s=s + "Calling method: \\n";
                s=s + "   Class: " + classname + "\\n"
                s=s + "   Method: " + classmethod + "\\n"
                s=s + "-->Output: " + returnValue + "\\n";
  
                s = s + "[*] Heap Search - END\\n"
  
                send(s);
            } 
            catch (err) 
            {
                var s = "";
                s=s + "[*] Heap Search - START\\n"
                s=s + "Instance NOT Found or Exception while calling the method\\n";
                s=s + "   Class: " + classname + "\\n"
                s=s + "   Method: " + classmethod + "\\n"
                s=s + "-->Exception: " + err + "\\n"
                s=s + "[*] Heap Search - END\\n"
                send(s)
            }
  
        }
    });
  
});