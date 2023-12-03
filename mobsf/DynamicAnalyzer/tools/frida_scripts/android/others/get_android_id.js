
// https://github.com/iddoeldor/frida-snippets
// The ANDROID_ID is unique in each application in Android.
Java.perform(function () {
    function getContext() {
        return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver();
    }
    send('[-]' + Java.use('android.provider.Settings$Secure').getString(getContext(), 'android_id'));
});