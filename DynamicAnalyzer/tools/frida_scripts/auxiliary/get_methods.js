/*
 * raptor_frida_android_enum.js - Java class/method enumerator
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
*/
Java.perform(function() {
	var hook;
	var targetClass = '{{CLASS}}';
	try{
		send('[AUXILIARY] Getting Methods and Implementations of Class: ' + targetClass)
		hook = Java.use(targetClass);
	} catch (err){
		send('[AUXILIARY] Hooking ' + targetClass + ' [\"Error\"] => ' + err);
		return;
	}
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose;
	methods.forEach(function(method) { 
		send('[AUXILIARY] ' + method)
	});
	
});