

getLoadedClasses: function(pattern=null) {
    // Get all loaded classes or those matching a pattern
    var all = [];
    try {
        var classes = Java.enumerateLoadedClassesSync();
        classes.forEach(function(aClass) {
                var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
                if (!pattern)
                    all.push(aClass);
                else if (className.match(pattern))
                    all.push(aClass);
        });
    } catch(err) {}
    return all
},
getAllMethods: function(className, pattern=null) {
    // Get all methods of all loaded classes or those matching a pattern
    var classAndMethods = {};
    var all = [];
    function uniqBy(array, key) {
        // Remove duplicates from array
        var seen = {};
        return array.filter(function (item) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    }
    try {
        var c = Java.use(className);
        var methods = c.class.getDeclaredMethods();
        c.$dispose;
        methods.forEach(function(method) {
            method = method.toString();
            var methodReplace = method.replace(className + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
            if (!pattern){
                all.push(methodReplace);
            }
            else if (methodReplace.match(pattern))
                all.push(methodReplace);
        });
    } catch(err) {}
    uniqBy(all, JSON.stringify).forEach(function (targetMethod) {
        if (targetClass in classAndMethods){
            classAndMethods[targetClass].push(targetMethod)
        } else {
            classAndMethods[targetClass] = [targetMethod]
        }
    });
    return classAndMethods
},
getAllImplementations: function(className, methodName) {
    // Get all implementations of a method of a class
    var all = [];
    try {
        var hook = Java.use(className);
        var overloadCount = hook[methodName].overloads.length;

        for (var i = 0; i < overloadCount; i++) {
            all.push(hook[methodName].overloads[i].implementation);
        }
        hook.$dispose;
    } catch(err) {}
    return all
}