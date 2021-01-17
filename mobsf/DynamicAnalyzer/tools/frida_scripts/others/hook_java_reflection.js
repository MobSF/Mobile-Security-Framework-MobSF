// https://github.com/iddoeldor/frida-snippets
Java.performNow(function () {
    Java.use('java.lang.reflect.Method').invoke.overload('java.lang.Object', '[Ljava.lang.Object;').implementation = function (a, b) {
        send('hooked ' + a + ' ' + b);
        return this.invoke(a, b);
    };
});