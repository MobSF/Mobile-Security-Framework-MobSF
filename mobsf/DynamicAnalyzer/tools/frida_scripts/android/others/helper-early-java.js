// Source: https://github.com/apkunpacker/FridaScripts
var Duplicate = [];
Module.enumerateExportsSync("libart.so").forEach(function(exp) {
    if (exp.name.indexOf("ClassLinker") != -1 && exp.name.indexOf("FindClassE") != -1) {
        Interceptor.attach(exp.address, {
            onEnter: function(args) {
                this.name = Memory.readCString(args[2]);
            },
            onLeave: function(retval) {
                if (Duplicate.indexOf(this.name) >= 0) return;
                if (retval.toInt32() !== 0) {
                    Duplicate.push(this.name);
                    let MClass = this.name.match(/^L(.*);$/);
                    if (MClass !== null && MClass.length > 1) {
                        const clearName = MClass[1].replace(/\//g, ".")
                        HookClass(clearName);
                        //console.log(clearName);  //Print all loaded class                   
                    }
                }
            }
        })
    }
})

function HookClass(ClassName) {
    if (ClassName.indexOf("com.loaded.class.name.here") >= 0) {
        console.log("Hooking : ", ClassName);
        try {
            Java.perform(function() {
                var Cls = Java.use("com.loaded.class");
                Cls.a.overload("java.lang.String").implementation = function(str) {
                    console.warn("Ret : ", str);
                    return this.a(str);
                }
            })
        } catch (e) {
            console.error(e);
        }
    }
}