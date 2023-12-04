// https://github.com/iddoeldor/frida-snippets
// Bypass FLAG_SECURE or screenshot prevention

Java.perform(function () {
    Java.use('android.view.SurfaceView').setSecure.overload('boolean').implementation = function (flag) {
        send('[1] flag:' + flag);
        this.call(false);
    };
    var LayoutParams = Java.use('android.view.WindowManager$LayoutParams');
    Java.use('android.view.Window').setFlags.overload('int', 'int').implementation = function (flags, mask) {
        send('flag secure: ' + LayoutParams.FLAG_SECURE.value);
        send('before:' + flags);
        flags = (flags.value & ~LayoutParams.FLAG_SECURE.value);
        send('after:' + flags);
        this.call(this, flags, mask);
    };
});