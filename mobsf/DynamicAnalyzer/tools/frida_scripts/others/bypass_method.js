Java.perform(function () {
    send('Installing Bypass');
    var hook = Java.use('some.package.Activity');
    hook.someMethod.overload().implementation = function () {
        send('--------------Bypassed!-------');
        return false;
    };
});