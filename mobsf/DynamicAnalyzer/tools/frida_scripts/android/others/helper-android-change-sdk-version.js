/* 
    Description: Android SDK version changer frida script
    Credit: Unknown
    Src: https://github.com/rsenet/FriList/blob/main/02_SecurityBypass/android-sdk-version-change.js
    https://developer.android.com/reference/android/os/Build.VERSION
*/

Java.perform(function() 
{
      var ver = Java.use('android.os.Build$VERSION');
      ver.SDK_INT.value = 15;
});