 /*
    * Based on raptor_frida_android_enum.js
    * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
    *
    */
 Java.perform(function() {
    var classes = Java.enumerateLoadedClassesSync();
    classes.forEach(function(aClass) {
        try{
            var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
            send('[RUNTIME-DEPS] ' + className);
        }
        catch(err){}
    });
});