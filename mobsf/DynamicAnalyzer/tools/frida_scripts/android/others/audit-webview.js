Java.perform(function () {
   send("Starting WebView configuration dump...");

    const WebView = Java.use('android.webkit.WebView');

    // Hook the first overload: loadUrl(String)
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
       send("[+] WebView.loadUrl(String) called: " + url);

        // Dump WebSettings after loading a URL
        dumpWebSettingsSafely(this);

        // Call the original method
        this.loadUrl(url);
    };

    // Hook the second overload: loadUrl(String, Map)
    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, additionalHttpHeaders) {
       send("[+] WebView.loadUrl(String, Map) called: " + url);
       send("    Additional HTTP Headers: " + additionalHttpHeaders);

        // Dump WebSettings after loading a URL
        dumpWebSettingsSafely(this);

        // Call the original method
        this.loadUrl(url, additionalHttpHeaders);
    };

    function dumpWebSettingsSafely(webView) {
        try {
            const webSettings = webView.getSettings();
           send("\n[+] Dumping WebSettings:");

            // Security-sensitive settings
           send("    JavaScript Enabled: " + webSettings.getJavaScriptEnabled());
           send("    Allow File Access: " + webSettings.getAllowFileAccess());
           send("    Allow Content Access: " + webSettings.getAllowContentAccess());
           send("    Mixed Content Mode: " + webSettings.getMixedContentMode());
           send("    Safe Browsing Enabled: " + webSettings.getSafeBrowsingEnabled());
           send("    Dom Storage Enabled: " + webSettings.getDomStorageEnabled());
           send("    Allow Universal Access From File URLs: " + webSettings.getAllowUniversalAccessFromFileURLs());
           send("    Allow File Access From File URLs: " + webSettings.getAllowFileAccessFromFileURLs());
            // Caching and storage
           send("    Cache Mode: " + webSettings.getCacheMode());
            // User agent and other information
           send("    User Agent String: " + webSettings.getUserAgentString());
        } catch (err) {
            send("Error while dumping WebView configuration: " + err);
        }
    }

   send("Hooks installed for WebView.");
});
