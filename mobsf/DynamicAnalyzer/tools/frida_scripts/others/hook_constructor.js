// https://github.com/iddoeldor/frida-snippets#hook-constructor
Java.performNow(function () {
    Java.use('java.lang.StringBuilder').$init.overload('java.lang.String').implementation = function (stringArgument) {
        send("c'tor");
        return this.$init(stringArgument);
    };
});