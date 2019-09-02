//https://github.com/iddoeldor/frida-snippets#reveal-native-methods
//String comparison
Java.perform(function () {
    send('[AUXILIARY] [String Compare] capturing all string comparisons')
    var str = Java.use('java.lang.String'), objectClass = 'java.lang.Object';
    str.equals.overload(objectClass).implementation = function (obj) {
        var response = str.equals.overload(objectClass).call(this, obj);
        if (obj) {
            if (obj.toString().length > 5) {
                send('[AUXILIARY] [String Compare] ' + str.toString.call(this) + ' == ' + obj.toString() + ' ? ' + response);
            }
        }
        return response;
    }
});