/* Description: Dump all methods inside all classes
 * Mode: S+A
 * Version: 1.0
 * Credit: https://github.com/interference-security/frida-scripts/blob/master/iOS
 * Author: @interference-security
 */
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
function run_show_classes_methods_of_app()
{
    send("Enumerating Classes and Methods")
	for (var className in ObjC.classes)
	{
		if (ObjC.classes.hasOwnProperty(className))
		{
			send("[AUXILIARY] Class: " + className);
			//var methods = ObjC.classes[className].$methods;
			var methods = ObjC.classes[className].$ownMethods;
			for (var i = 0; i < methods.length; i++)
			{
				send("[AUXILIARY] \t Method: " + methods[i]);
				try
				{
					send("[AUXILIARY] \t\tArguments Type: " + ObjC.classes[className][methods[i]].argumentTypes);
					send("[AUXILIARY] \t\tReturn Type: " + ObjC.classes[className][methods[i]].returnType);
				}
				catch(err) {}
			}
		}
	}
	send("Completed Enumerating Methods of All Classes")
}

function show_classes_methods_of_app()
{
	setImmediate(run_show_classes_methods_of_app)
}
show_classes_methods_of_app()