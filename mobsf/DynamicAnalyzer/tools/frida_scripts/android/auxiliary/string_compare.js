//String comparison
Java.perform(function () {
    send('[AUXILIARY] [String Compare] capturing all string comparisons')
    let Exception = Java.use('java.lang.Exception');
    let javaString = Java.use('java.lang.String')
    let objectClass = 'java.lang.Object';
    var skiplist = ['android.app.SystemServiceRegistry.getSystemService']
    javaString.equals.overload(objectClass).implementation = function (obj) {
        var response = javaString.equals.overload(objectClass).call(this, obj);
        if (obj && obj.toString().length > 5) {
           var stack = [];
           var calledFrom = Exception.$new().getStackTrace().toString().split(',');
           // Otherwise capture string comparisons
           let i = 0;
           do {
                i = i + 1;
                stack.push(calledFrom[i]);
            } while (i <= 5);
            var skipClass, skipMethod = false;
            skiplist.forEach(function (toSkip) {
                if (calledFrom[4].includes(toSkip))
                    skipClass = true;
           });
           if (!skipClass) {
                var data = {
                caller: stack,
                string1: javaString.toString.call(this),
                string2: obj.toString(),
                return: response,
                }
                send('[AUXILIARY] [String Compare] ' + JSON.stringify(data, null, 2));
           }
        }
        return response;
    }
 });
 