/*
 * raptor_frida_android_enum.js - Java class/method enumerator
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
*/
Java.perform(function() {
	var classes = Java.enumerateLoadedClassesSync();
	classes.forEach(function(aClass) {
		try{
			var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
			send('[AUXILIARY] ' + className);
		}
		catch(err){}
	});
});