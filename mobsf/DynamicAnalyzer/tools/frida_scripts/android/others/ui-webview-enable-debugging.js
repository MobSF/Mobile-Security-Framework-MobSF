//From: https://blog.compass-security.com/2019/10/introducing-web-vulnerabilities-into-native-apps/
Java.perform(function() {
    var Webview = Java.use("android.webkit.WebView")
    Webview.onTouchEvent.overload("android.view.MotionEvent").implementation = 
    function(touchEvent) {
      send("Hooking WebView onTouchEvent");
      send("[+]Setting setWebContentsDebuggingEnabled() to TRUE");
      this.setWebContentsDebuggingEnabled(true);
      this.onTouchEvent.overload("android.view.MotionEvent").call(this, touchEvent);
    }
 });
 