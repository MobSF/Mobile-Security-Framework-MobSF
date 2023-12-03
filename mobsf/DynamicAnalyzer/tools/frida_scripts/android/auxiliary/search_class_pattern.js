/*
 * raptor_frida_android_enum.js - Java class/method enumerator
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
*/	
function enumAllClasses()
{
	var allClasses = [];
	var classes = Java.enumerateLoadedClassesSync();
	classes.forEach(function(aClass) {
		try {
			var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
		}
		catch(err) {}
		allClasses.push(className);
	});
	return allClasses;
}

function findClasses(pattern)
{
	var allClasses = enumAllClasses();
	var foundClasses = [];
	allClasses.forEach(function(aClass) {
		try {
			if (aClass.match(pattern)) {
				foundClasses.push(aClass);
			}
		}
		catch(err) {}
	});
	return foundClasses;
}


Java.perform(function() {
	
	
	var matches;
	try{
		var pattern = /{{PATTERN}}/i;
		send('[AUXILIARY] Class search for pattern: ' + pattern)
		matches = findClasses(pattern);
	}catch (err){
		send('[AUXILIARY] Class pattern match [\"Error\"] => ' + err);
		return;
	}
	if (matches.length>0)
		send('[AUXILIARY] Pattern matches found')
	else
		send('[AUXILIARY] No matches found')
	matches.forEach(function(clz) { 
		send('[AUXILIARY] ' + clz)
	});
});
